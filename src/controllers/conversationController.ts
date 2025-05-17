import { Request, Response } from 'express';
import { CustomJwtPayload, IoRequest } from '@/custom';
import { httpStatusCode } from '@/constants/httpStatusCode';
import { conversationService } from '@/services/conversationService';
import { userService } from '@/services/userService';
import ApiError from '@/utils/ApiError';
import conversationResponse from '@/constants/conversationResponse';
import { ConversationType } from '@/entity/Conversation';
import { ConversationRole } from '@/entity/ConversationParticipant';
import { MessageType } from '@/entity/Message';

class ConversationController {
    // [GET] /conversations/friends/:friendId
    async getConversationWithFriend(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { friendId } = req.params;

        const conversation = await conversationService.getConversationPrivate({ userId: id, friendId });

        return res.status(httpStatusCode.OK).json(conversation);
    }

    // [GET] /conversations/groups
    async getGroupConversations(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;

        const groupConversations = await conversationService.getGroupConversations(id);

        return res.status(httpStatusCode.OK).json(groupConversations);
    }

    // [POST] /conversations
    async createConversation(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { type, name, avatar, participants } = req.body;
        const { io } = req as IoRequest;

        const newConversation = await conversationService.createConversation({
            type,
            name,
            avatar,
            participants: [
                ...participants.map((p: string) => ({
                    userId: p,
                    role: type === ConversationType.PRIVATE ? null : ConversationRole.MEMBER,
                })),
                { userId: id, role: type === ConversationType.PRIVATE ? null : ConversationRole.ADMIN },
            ],
            ...(type === ConversationType.PRIVATE ? { creatorId: id } : {}),
        });

        if (newConversation.type === ConversationType.GROUP) {
            const newMessage = await conversationService.createMessage({
                senderId: id,
                conversationId: newConversation.id,
                content: `${lastName} ${firstName} vừa tạo nhóm`,
                type: MessageType.NOTIFICATION,
            });

            const creatorInfo = await userService.getUserFields({ userId: id, fields: ['avatar'] });
            const newConversationGroupData = {
                conversationId: newConversation.id,
                conversationName: name,
                conversationAvatar: avatar,
                creator: {
                    userId: id,
                    firstName,
                    lastName,
                    avatar: creatorInfo?.avatar,
                },
                lastUpdated: newConversation.createdAt,
                lastMessage: {
                    messageId: newMessage.id,
                    content: newMessage.content,
                    messageType: newMessage.messageType,
                    createdAt: newMessage.createdAt,
                },
            };
            participants.map((p: string) => {
                io.to(`user-${p}`).emit('newConversationGroup', newConversationGroupData);
            });
            io.to(`user-${id}`).emit('newConversationGroup', newConversationGroupData);
        }

        return res.status(httpStatusCode.CREATED).json(newConversation);
    }

    // [POST] /conversations/messages
    async sendMessage(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { conversationId, content, type, image, fileName } = req.body;
        const { io } = req as IoRequest;

        const conversation = await conversationService.getConversationById(conversationId);

        if (!conversation) {
            throw new ApiError(
                conversationResponse.CONVERSATION_NOT_FOUND.status,
                conversationResponse.CONVERSATION_NOT_FOUND.message,
            );
        }

        const newMessage = await conversationService.createMessage({
            senderId: id,
            conversationId,
            content: content || image,
            type,
            fileName,
        });

        const sender = await userService.getUserFields({ userId: id, fields: ['avatar'] });

        const participants = await conversationService.getParticipants(conversationId);

        const baseMessage: any = {
            messageId: newMessage.id,
            conversationType: conversation.type,
            conversationName: conversation.name,
            conversationAvatar: conversation.avatar,
            conversationId,
            content: newMessage.content,
            messageType: type,
            fileName: newMessage.fileName,
            sender: {
                userId: id,
                firstName,
                lastName,
                avatar: sender?.avatar,
            },
            lastUpdated: newMessage.createdAt,
        };

        if (conversation.type === ConversationType.PRIVATE) {
            const friend = participants.find((p) => p.userId !== id);

            if (friend) {
                baseMessage.friend = {
                    userId: friend.user.id,
                    firstName: friend.user.firstName,
                    lastName: friend.user.lastName,
                    avatar: friend.user.avatar,
                };
            }
        }

        participants.forEach((participant) => {
            io.to(`user-${participant.userId}`).emit('newMessage', baseMessage);
        });

        return res.status(httpStatusCode.CREATED).json();
    }

    // [GET] /conversations/messages/:conversationId
    async getMessages(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { conversationId } = req.params;
        const { page } = req.query;

        const messages = await conversationService.getMessages({ conversationId, userId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json(messages);
    }

    // [GET] /conversations/recent
    async getRecentConversations(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;

        const recentConversations = await conversationService.getRecentConversations({
            userId: id,
            page: Number(page),
        });

        const _recentConversations = recentConversations.map((c) => {
            return {
                conversationId: c.conversationId,
                conversationType: c.conversationType,
                conversationCreatedAt: c.conversationCreatedAt,
                senderId: c.senderId,
                senderFirstName: c.senderFirstName,
                senderLastName: c.senderLastName,
                senderAvatar: c.senderAvatar,
                lastMessageId: c.lastMessageId,
                lastMessageContent: c.lastMessageContent,
                lastMessageType: c.lastMessageType,
                lastUpdated: c.lastUpdated,
                ...(c.conversationType === ConversationType.PRIVATE
                    ? {
                          friendId: c.friendId,
                          conversationName: `${c.friendLastName} ${c.friendFirstName}`,
                          conversationAvatar: c.friendAvatar,
                      }
                    : {
                          conversationName: c.conversationName,
                          conversationAvatar: c.conversationAvatar,
                      }),
            };
        });

        return res.status(httpStatusCode.OK).json(_recentConversations);
    }

    // [GET] /conversations/unread
    async getConversationsUnread(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;

        const conversationsUnread = await conversationService.getConversationsUnread(id);

        return res.status(httpStatusCode.OK).json(conversationsUnread);
    }

    // [GET] /conversations/groups/members/:conversationId
    async getGroupMembers(req: Request, res: Response): Promise<any> {
        const { conversationId } = req.params;
        const { page } = req.query;

        const conversationParticipants = await conversationService.getGroupMembers({
            conversationId,
            page: Number(page),
        });

        return res.status(httpStatusCode.OK).json(conversationParticipants);
    }

    // [PUT] /conversations/reactions/:messageId
    async reactToMessage(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { messageId } = req.params;
        const { conversationId, reactionType } = req.body;
        const { io } = req as IoRequest;

        const participants = await conversationService.getParticipants(conversationId);

        if (!reactionType) {
            await conversationService.deleteMessageReaction({
                messageId,
                userId: id,
            });

            participants.forEach((participant) => {
                io.to(`user-${participant.userId}`).emit('removeReactToMessage', {
                    messageId,
                    userId: id,
                });
            });
        } else {
            await conversationService.upsertMessageReaction({
                messageId,
                userId: id,
                reactionType,
            });

            const sender = await userService.getUserFields({ userId: id, fields: ['avatar'] });

            participants.forEach((participant) => {
                io.to(`user-${participant.userId}`).emit('reactToMessage', {
                    messageId,
                    reactionType,
                    sender: {
                        userId: id,
                        firstName,
                        lastName,
                        avatar: sender?.avatar,
                    },
                });
            });
        }

        return res.status(httpStatusCode.OK).json();
    }

    // [POST] /conversations/members/:conversationId
    async addGroupMembers(req: Request, res: Response): Promise<any> {
        const { conversationId } = req.params;
        const { participants } = req.body;
        const { io } = req as IoRequest;

        const prevMembers = await conversationService.getParticipants(conversationId);

        const participantIds = participants.map((p: any) => p.userId);
        await conversationService.addGroupMembers({ conversationId, participantIds });

        participantIds.map((p: any) => {
            io.to(`user-${p}`).emit('addedToGroup');
        });
        prevMembers.map((m) => {
            io.to(`user-${m.userId}`).emit(
                'moreMemberToGroup',
                participants.map((p: any) => ({
                    ...p,
                    role: ConversationRole.MEMBER,
                })),
            );
        });

        return res.status(httpStatusCode.CREATED).json();
    }

    // [DELETE] /conversations/members/:conversationId
    async outGroup(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { conversationId } = req.params;
        const { io } = req as IoRequest;

        await conversationService.deleteGroupMember({ conversationId, userId: id });

        const prevMembers = await conversationService.getParticipants(conversationId);
        prevMembers.map((p) => {
            io.to(`user-${p.userId}`).emit('reduceMemberToGroup', id);
        });
        io.to(`user-${id}`).emit('outGroupChat', conversationId);

        return res.status(httpStatusCode.OK).json();
    }

    // [POST] /conversations/messages/read/:conversationId'
    async readMessage(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { conversationId } = req.params;

        await conversationService.readMessage({ userId: id, conversationId });

        return res.status(httpStatusCode.CREATED).json();
    }
}

export const conversationController = new ConversationController();
