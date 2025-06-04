import { pageSize } from '@/constants';
import { AppDataSource } from '@/data-source';
import { FriendRequest } from '@/entity/FriendRequest';
import { Notification, NotificationType } from '@/entity/Notification';
import { Relationship } from '@/entity/Relationship';
import { Role, User } from '@/entity/User';

const friendRequestRepository = AppDataSource.getRepository(FriendRequest);
const relationshipRepository = AppDataSource.getRepository(Relationship);
const userRepository = AppDataSource.getRepository(User);
const notificationRepository = AppDataSource.getRepository(Notification);

class RelationshipService {
    async getFriends(userId: string): Promise<User[]> {
        const relationships = await relationshipRepository.find({
            relations: ['user1', 'user2'],
            select: {
                user1: {
                    id: true,
                    firstName: true,
                    lastName: true,
                    avatar: true,
                },
                user2: {
                    id: true,
                    firstName: true,
                    lastName: true,
                    avatar: true,
                },
            },
            where: [{ user1Id: userId }, { user2Id: userId }],
        });
        return relationships.map((relationship) =>
            relationship.user1.id === userId ? relationship.user2 : relationship.user1,
        );
    }

    async getFriendRequestById(friendRequestId: string): Promise<FriendRequest | null> {
        return await friendRequestRepository.findOneBy({ id: friendRequestId });
    }

    async getFriendRequestByUserId({
        userId,
        receiverId,
    }: {
        userId: string;
        receiverId: string;
    }): Promise<FriendRequest | null> {
        return await friendRequestRepository.findOne({
            where: [
                {
                    senderId: userId,
                    receiverId,
                },
                { senderId: receiverId, receiverId: userId },
            ],
        });
    }

    async getFriendRequests({ receiverId, page }: { receiverId: string; page: number }): Promise<{
        friendRequests: any[];
        totalPages: number;
    }> {
        const friendRequests = await friendRequestRepository
            .createQueryBuilder('fr')
            .innerJoinAndSelect('fr.sender', 'sender')
            .select(['fr.id', 'sender.id', 'sender.firstName', 'sender.lastName', 'sender.avatar'])
            .where('fr.receiverId = :receiverId', { receiverId })
            .offset((page - 1) * pageSize.friendRequests)
            .limit(pageSize.friendRequests)
            .getManyAndCount();

        return {
            friendRequests: friendRequests[0].map((fq) => ({
                friendRequestId: fq.id,
                userId: fq.sender.id,
                firstName: fq.sender.firstName,
                lastName: fq.sender.lastName,
                avatar: fq.sender.avatar,
            })),
            totalPages: Math.ceil(friendRequests[1] / pageSize.friendRequests),
        };
    }

    async getFriendRequestCount(receiverId: string): Promise<number> {
        return await friendRequestRepository
            .createQueryBuilder('fr')
            .where('fr.receiverId = :receiverId', { receiverId })
            .getCount();
    }

    async createFriendRequest({ userId, receiverId }: { userId: string; receiverId: string }): Promise<FriendRequest> {
        return await friendRequestRepository.save({
            senderId: userId,
            receiverId,
        });
    }

    async getSuggestions({ userId, keyword, page }: { userId: string; keyword?: string; page: number }): Promise<any> {
        const queryBuilder = userRepository
            .createQueryBuilder('user')
            .select(['user.id', 'user.firstName', 'user.lastName', 'user.avatar'])
            .where('user.id != :userId AND user.role != :adminRole', { adminRole: Role.ADMIN });

        if (keyword) {
            const keywords = keyword.split(' ');
            const keywordConditions = keywords.map(
                (word, index) => `(user.firstName LIKE :keyword${index} OR user.lastName LIKE :keyword${index})`,
            );
            const keywordParams = Object.fromEntries(keywords.map((word, index) => [`keyword${index}`, `%${word}%`]));

            queryBuilder.andWhere(`(${keywordConditions.join(' OR ')})`, keywordParams);
        }

        queryBuilder.andWhere((qb) => {
            const relationshipAsUser1 = qb
                .subQuery()
                .select('relationship.user1Id')
                .from(Relationship, 'relationship')
                .where('relationship.user2Id = :userId')
                .getQuery();

            const relationshipAsUser2 = qb
                .subQuery()
                .select('relationship.user2Id')
                .from(Relationship, 'relationship')
                .where('relationship.user1Id = :userId')
                .getQuery();

            const friendRequestAsSender = qb
                .subQuery()
                .select('friendRequest.senderId')
                .from(FriendRequest, 'friendRequest')
                .where('friendRequest.receiverId = :userId')
                .getQuery();

            const friendRequestAsReceiver = qb
                .subQuery()
                .select('friendRequest.receiverId')
                .from(FriendRequest, 'friendRequest')
                .where('friendRequest.senderId = :userId')
                .getQuery();

            return `user.id NOT IN (${relationshipAsUser1}) AND user.id NOT IN (${relationshipAsUser2}) AND user.id NOT IN (${friendRequestAsSender}) AND user.id NOT IN (${friendRequestAsReceiver})`;
        });

        queryBuilder.offset((page - 1) * pageSize.suggestionsMakeFriend);
        queryBuilder.limit(pageSize.suggestionsMakeFriend);
        queryBuilder.setParameter('userId', userId);

        const suggestions = await queryBuilder.getManyAndCount();

        return {
            suggestions: suggestions[0].map((s) => ({
                userId: s.id,
                firstName: s.firstName,
                lastName: s.lastName,
                avatar: s.avatar,
            })),
            totalPages: Math.ceil(suggestions[1] / pageSize.suggestionsMakeFriend),
        };
    }

    async addFriend({
        userId,
        senderId,
        friendRequestId,
    }: {
        userId: string;
        senderId: string;
        friendRequestId: string;
    }): Promise<any> {
        await friendRequestRepository.delete({ id: friendRequestId });
        await notificationRepository.delete({
            userId,
            actorId: senderId,
            type: NotificationType.FRIEND_REQUEST,
            referenceId: friendRequestId,
        });
        return await relationshipRepository.save({
            user1Id: senderId,
            user2Id: userId,
        });
    }

    async deleteFriendRequest(friendRequestId: string): Promise<any> {
        await friendRequestRepository.delete({ id: friendRequestId });
        await notificationRepository.delete({
            type: NotificationType.FRIEND_REQUEST,
            referenceId: friendRequestId,
        });
    }

    async unfriend({ userId, friendId }: { userId: string; friendId: string }): Promise<any> {
        await relationshipRepository
            .createQueryBuilder()
            .delete()
            .where(
                `(user1Id = :userId AND user2Id = :friendId) 
                OR (user1Id = :friendId AND user2Id = :userId)`,
                { userId, friendId },
            )
            .execute();
    }

    async getSentFriendRequests({ senderId, page }: { senderId: string; page: number }): Promise<any> {
        const sentFriendRequests = await friendRequestRepository
            .createQueryBuilder('fr')
            .innerJoinAndSelect('fr.receiver', 'receiver')
            .select(['fr.id', 'receiver.id', 'receiver.firstName', 'receiver.lastName', 'receiver.avatar'])
            .where('fr.senderId = :senderId', { senderId })
            .offset((page - 1) * pageSize.friendRequests)
            .limit(pageSize.friendRequests)
            .getManyAndCount();

        return {
            sentFriendRequests: sentFriendRequests[0].map((fq) => ({
                friendRequestId: fq.id,
                userId: fq.receiver.id,
                firstName: fq.receiver.firstName,
                lastName: fq.receiver.lastName,
                avatar: fq.receiver.avatar,
            })),
            totalPages: Math.ceil(sentFriendRequests[1] / pageSize.friendRequests),
        };
    }

    async getRelationship({
        currentUserId,
        targetUserId,
    }: {
        currentUserId: string;
        targetUserId: string;
    }): Promise<string | null> {
        const fq = await friendRequestRepository
            .createQueryBuilder('fq')
            .select(
                `CASE WHEN fq.senderId = :currentUserId THEN 'FRIEND_REQUEST_AS_SENDER' ELSE 'FRIEND_REQUEST_AS_RECEIVER' END`,
                'friendRequest',
            )
            .where('fq.senderId = :currentUserId AND fq.receiverId = :targetUserId')
            .orWhere('fq.senderId = :targetUserId AND fq.receiverId = :currentUserId')
            .setParameters({
                currentUserId,
                targetUserId,
            })
            .getRawOne();

        if (fq) return fq.friendRequest;

        const friend = await relationshipRepository.findOne({
            where: [
                { user1Id: currentUserId, user2Id: targetUserId },
                { user1Id: targetUserId, user2Id: currentUserId },
            ],
        });

        if (friend) return 'FRIEND';

        return null;
    }
}

export const relationshipService = new RelationshipService();
