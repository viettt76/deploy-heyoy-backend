import { Server, Socket } from 'socket.io';
import { parse } from 'cookie';
import { verify } from 'jsonwebtoken';
import postEvent from './postEvent';
import { addOnlineFriends, addUserOnline, removeUserOnline } from '@/services/redisService';
import { CustomJwtPayload } from '@/custom';
import conversationEvent from './conversationEvent';

const events = (io: Server) => {
    io.on('connect', async (socket: Socket) => {
        try {
            const authHeader = socket.handshake.headers['authorization'];
            const token = authHeader?.split(' ')[1];
            if (!token) return socket.disconnect();

            const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
            if (!JWT_ACCESS_SECRET) throw new Error('JWT secret is missing!');

            const userToken = verify(token, JWT_ACCESS_SECRET) as CustomJwtPayload;
            const userId = userToken.id;
            if (!userId) return socket.disconnect();

            socket.join(`user-${userToken.id}`);

            await addUserOnline(userId);
            await addOnlineFriends(userId);

            postEvent(socket);
            conversationEvent(socket, io, userToken);

            socket.on('disconnect', async () => {
                socket.leave(`user-${userToken.id}`);
                await removeUserOnline(userId);
            });
        } catch (error) {
            console.error('Socket connection error:', error);
            socket.disconnect();
        }
    });
};

export default events;
