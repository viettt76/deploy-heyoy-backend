import { pageSize } from '@/constants';
import conversationResponse from '@/constants/conversationResponse';
import { AppDataSource } from '@/data-source';
import { Conversation, ConversationType } from '@/entity/Conversation';
import { ConversationHistory } from '@/entity/ConversationHistory';
import { ConversationParticipant, ConversationRole } from '@/entity/ConversationParticipant';
import { Message, MessageType } from '@/entity/Message';
import { MessageReaction, MessageReactionType } from '@/entity/MessageReaction';
import { MessageRead } from '@/entity/MessageRead';
import ApiError from '@/utils/ApiError';

const conversationRepository = AppDataSource.getRepository(Conversation);
const conversationParticipantRepository = AppDataSource.getRepository(ConversationParticipant);
const conversationHistoryRepository = AppDataSource.getRepository(ConversationHistory);
const messageRepository = AppDataSource.getRepository(Message);
const messageReactionRepository = AppDataSource.getRepository(MessageReaction);
const messageReadRepository = AppDataSource.getRepository(MessageRead);

class ConversationService {
    async getConversationById(conversationId: string): Promise<Conversation | null> {
        return conversationRepository.findOneBy({ id: conversationId });
    }

    async getConversationPrivate({
        userId,
        friendId,
    }: {
        userId: string;
        friendId: string;
    }): Promise<Conversation | null | undefined> {
        return await conversationRepository
            .createQueryBuilder('conversation')
            .innerJoin(ConversationParticipant, 'cp1', 'cp1.conversationId = conversation.id')
            .innerJoin(ConversationParticipant, 'cp2', 'cp2.conversationId = conversation.id')
            .select(['conversation.id as conversationId'])
            .where('cp1.userId = :userId', { userId })
            .andWhere('cp2.userId = :friendId', { friendId })
            .andWhere('conversation.type = :conversationType', { conversationType: ConversationType.PRIVATE })
            .getRawOne();
    }

    async getGroupConversations(userId: string): Promise<Conversation[]> {
        return await conversationRepository
            .createQueryBuilder('conversation')
            .innerJoin(ConversationParticipant, 'cp', 'cp.conversationId = conversation.id')
            .select([
                'conversation.id as conversationId',
                'conversation.type as type',
                'conversation.name as name',
                'conversation.avatar as avatar',
            ])
            .where('cp.userId = :userId', { userId })
            .andWhere('conversation.type = :conversationType', { conversationType: ConversationType.GROUP })
            .getRawMany();
    }

    async createConversation({
        type,
        name,
        avatar,
        participants,
    }: {
        type: ConversationType;
        name: string;
        avatar: string;
        participants: {
            userId: string;
            role: ConversationRole;
        }[];
    }): Promise<Conversation> {
        const newConversation = await conversationRepository.save({
            type,
            ...(type === ConversationType.GROUP && {
                name,
                avatar,
            }),
        });

        await Promise.all(
            participants.map(async (participant) => {
                await conversationParticipantRepository.save({
                    userId: participant.userId,
                    conversationId: newConversation.id,
                    role: participant.role,
                });
            }),
        );
        return newConversation;
    }

    async createMessage({
        senderId,
        conversationId,
        content,
        type,
        fileName,
    }: {
        senderId: string;
        conversationId: string;
        content: string;
        type: MessageType;
        fileName?: string;
    }): Promise<Message> {
        const newMessage = await messageRepository.save({
            senderId,
            conversationId,
            content,
            messageType: type,
            fileName,
        });

        await conversationHistoryRepository.upsert(
            {
                userId: senderId,
                conversationId,
                lastMessageId: newMessage.id,
            },
            ['conversationId'],
        );

        return newMessage;
    }

    async getMessages({
        conversationId,
        userId,
        page,
    }: {
        conversationId: string;
        userId: string;
        page: number;
    }): Promise<any[]> {
        const messages = await messageRepository
            .createQueryBuilder('message')
            .leftJoinAndSelect('message.sender', 'sender')
            .where('message.conversationId = :conversationId', { conversationId })
            .select([
                'message.id as id',
                'message.conversationId as conversationId',
                'message.content as content',
                'message.fileName as fileName',
                'message.messageType as messageType',
                'message.createdAt as createdAt',
                'sender.id as senderId',
                'sender.firstName as senderFirstName',
                'sender.lastName as senderLastName',
                'sender.avatar as senderAvatar',
            ])
            .orderBy('message.createdAt', 'DESC')
            .limit(pageSize.messages)
            .offset((page - 1) * pageSize.messages)
            .getRawMany();

        messages.reverse();

        const result = await Promise.all(
            messages.map(async (m) => {
                const reactions = await messageReactionRepository.find({
                    relations: ['user'],
                    where: { messageId: m.id },
                    select: {
                        id: true,
                        reactionType: true,
                        user: {
                            id: true,
                            firstName: true,
                            lastName: true,
                            avatar: true,
                        },
                    },
                });
                return {
                    id: m.id,
                    conversationId: m.conversationId,
                    content: m.content,
                    fileName: m.fileName,
                    messageType: m.messageType,
                    createdAt: m.createdAt,
                    sender: {
                        id: m.senderId,
                        firstName: m.senderFirstName,
                        lastName: m.senderLastName,
                        avatar: m.senderAvatar,
                    },
                    reactions,
                    currentReaction: reactions.find((r) => r.user.id === userId)?.reactionType,
                };
            }),
        );
        return result;
    }

    async getParticipants(conversationId: string): Promise<ConversationParticipant[]> {
        return await conversationParticipantRepository.find({
            relations: ['user'],
            where: { conversationId },
            select: {
                userId: true,
                user: {
                    firstName: true,
                    lastName: true,
                    avatar: true,
                },
            },
        });
    }

    async getRecentConversations({ userId, page }: { userId: string; page: number }): Promise<any[]> {
        return await conversationRepository
            .createQueryBuilder('conversation')
            .innerJoin(ConversationParticipant, 'cp1', 'cp1.conversationId = conversation.id')
            .leftJoinAndSelect(
                ConversationParticipant,
                'otherCp',
                'otherCp.userId != :userId AND otherCp.conversationId = conversation.id AND conversation.type = :privateType',
                { userId, privateType: ConversationType.PRIVATE },
            )
            .leftJoinAndSelect('otherCp.user', 'friend')
            .where('cp1.userId = :userId', { userId })
            .leftJoinAndSelect('conversation.history', 'history')
            .leftJoinAndSelect('history.user', 'sender')
            .leftJoinAndSelect('history.lastMessage', 'lastMessage')
            .select([
                'conversation.id as conversationId',
                'conversation.name as conversationName',
                'conversation.type as conversationType',
                'conversation.avatar as conversationAvatar',
                'conversation.createdAt as conversationCreatedAt',
                'sender.id as senderId',
                'sender.firstName as senderFirstName',
                'sender.lastName as senderLastName',
                'sender.avatar as senderAvatar',
                'lastMessage.id as lastMessageId',
                'lastMessage.content as lastMessageContent',
                'lastMessage.messageType as lastMessageType',
                'history.createdAt as lastUpdated',
                'friend.id as friendId',
                'friend.firstName as friendFirstName',
                'friend.lastName as friendLastName',
                'friend.avatar as friendAvatar',
            ])
            .setParameter('userId', userId)
            .offset((page - 1) * pageSize.recentConversations)
            .limit(pageSize.recentConversations)
            .orderBy('COALESCE(history.updatedAt, conversation.createdAt)', 'DESC')
            .groupBy('history.id')
            .getRawMany();
    }

    async getConversationsUnread(userId: string): Promise<string[]> {
        const conversations = await conversationRepository
            .createQueryBuilder('conversation')
            .innerJoin(ConversationParticipant, 'cp1', 'cp1.conversationId = conversation.id')
            .leftJoinAndSelect('conversation.history', 'history')
            .leftJoinAndSelect('history.lastMessage', 'lastMessage')
            .leftJoin('lastMessage.reads', 'myRead', 'myRead.userId = :userId', { userId })
            .where('cp1.userId = :userId', { userId })
            .andWhere('myRead.id IS NULL')
            .andWhere('lastMessage.senderId != :userId', { userId })
            .select('conversation.id as conversationId')
            .getRawMany();

        return conversations.map((c) => c.conversationId);
    }

    async getGroupMembers({
        conversationId,
        page,
    }: {
        conversationId: string;
        page?: number;
    }): Promise<ConversationParticipant[]> {
        const query = conversationParticipantRepository
            .createQueryBuilder('cp')
            .innerJoinAndSelect('cp.user', 'userInfo')
            .where('cp.conversationId = :conversationId', { conversationId })
            .select([
                'cp.role as role',
                'cp.nickname as nickname',
                'userInfo.id as userId',
                'userInfo.firstName as userFirstName',
                'userInfo.lastName as userLastName',
                'userInfo.avatar as userAvatar',
            ])
            .orderBy('cp.role', 'DESC');

        if (page) {
            query.limit(pageSize.groupConversationMembers).offset((page - 1) * pageSize.groupConversationMembers);
        }

        return await query.getRawMany();
    }

    async upsertMessageReaction({
        messageId,
        userId,
        reactionType,
    }: {
        messageId: string;
        userId: string;
        reactionType: MessageReactionType;
    }): Promise<void> {
        await messageReactionRepository.upsert(
            {
                messageId,
                userId,
                reactionType,
            },
            ['messageId', 'userId'],
        );
    }

    async deleteMessageReaction({ messageId, userId }: { messageId: string; userId: string }): Promise<void> {
        await messageReactionRepository.delete({
            messageId,
            userId,
        });
    }

    async addGroupMembers({
        conversationId,
        participantIds,
    }: {
        conversationId: string;
        participantIds: string[];
    }): Promise<void> {
        await conversationParticipantRepository.insert(
            participantIds.map((p) => ({
                userId: p,
                conversationId,
                role: ConversationRole.MEMBER,
            })),
        );
    }

    async getLastMessage(conversationId: string): Promise<any> {
        return await conversationRepository
            .createQueryBuilder('conversation')
            .select('history.lastMessageId as messageId')
            .leftJoin('conversation.history', 'history')
            .where('conversation.id = :conversationId', { conversationId })
            .getRawOne();
    }

    async readMessage({ userId, conversationId }: { userId: string; conversationId: string }): Promise<void> {
        const message = await conversationRepository
            .createQueryBuilder('conversation')
            .select('history.lastMessageId as messageId')
            .leftJoin('conversation.history', 'history')
            .leftJoin('history.lastMessage', 'lastMessage')
            .where('conversation.id = :conversationId', { conversationId })
            .andWhere('lastMessage.senderId != :userId', { userId })
            .getRawOne();

        if (message) {
            await messageReadRepository
                .createQueryBuilder()
                .insert()
                .values({ userId, messageId: message.messageId })
                .orIgnore()
                .execute();
        }
    }
}

export const conversationService = new ConversationService();
