import { CustomJwtPayload } from '@/custom';
import { ConversationType } from '@/entity/Conversation';
import { conversationService } from '@/services/conversationService';
import { AccessToken } from 'livekit-server-sdk';
import { Server, Socket } from 'socket.io';

const createLiveKitToken = async (roomeId: string, userId: string, name: string) => {
    const token = new AccessToken(process.env.LIVEKIT_API_KEY, process.env.LIVEKIT_API_SECRET, {
        identity: userId,
        name,
    });

    token.addGrant({
        roomJoin: true,
        room: roomeId,
        canPublish: true,
        canSubscribe: true,
    });

    return await token.toJwt();
};

const conversationEvent = (socket: Socket, io: Server, userToken: CustomJwtPayload) => {
    socket.on(
        'call:start',
        async ({
            conversationId,
            conversationType,
            callerInfo,
            friendId,
            conversationName,
        }: {
            conversationId: string;
            conversationType: ConversationType;
            callerInfo: {
                userId: string;
                firstName: string;
                lastName: string;
                avatar: string | null;
            };
            friendId: string;
            conversationName: string;
        }) => {
            const roomId = `conversation-${conversationId}`;
            const token = await createLiveKitToken(
                roomId,
                userToken.id,
                `${callerInfo.lastName} ${callerInfo.firstName}`,
            );

            if (conversationId) {
                const conversationMembers = await conversationService.getGroupMembers({ conversationId });

                conversationMembers.map((m) => {
                    if (m.userId !== callerInfo.userId) {
                        io.to(`user-${m.userId}`).emit('call:incoming', {
                            roomId,
                            conversationType,
                            callerInfo,
                            ...(conversationType === ConversationType.GROUP && {
                                conversationName,
                            }),
                        });
                    }
                });
            } else if (friendId) {
                io.to(`user-${friendId}`).emit('call:incoming', {
                    roomId,
                    conversationType,
                    callerInfo,
                });
            }

            io.to(`user-${callerInfo.userId}`).emit('callerToken', { roomId, token });
        },
    );

    socket.on('call:answer', async (roomId: string) => {
        const token = await createLiveKitToken(roomId, userToken.id, `${userToken.lastName} ${userToken.firstName}`);

        io.to(`user-${userToken.id}`).emit('call:join', token);
    });

    socket.on('call:refuse', (callerId: string) => {
        io.to(`user-${callerId}`).emit('call:end');
    });

    socket.on('call:end', (userId: string) => {
        io.to(`user-${userId}`).emit('call:end');
    });

    socket.on('call:busy', (callerId) => {
        setTimeout(() => {
            io.to(`user-${callerId}`).emit('call:end');
        }, 10000);
    });
};

export default conversationEvent;
