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

    async getFriendRequests({
        receiverId,
        page,
    }: {
        receiverId: string;
        page: number;
    }): Promise<FriendRequest[] | null> {
        return await friendRequestRepository
            .createQueryBuilder('fr')
            .innerJoin(User, 'sender', 'fr.senderId = sender.id')
            .select([
                'fr.id as friendRequestId',
                'sender.id as userId',
                'sender.firstName as firstName',
                'sender.lastName as lastName',
                'sender.avatar as avatar',
            ])
            .where('fr.receiverId = :receiverId', { receiverId })
            .offset((page - 1) * pageSize.friendRequests)
            .limit(pageSize.friendRequests)
            .getRawMany();
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

    async getSuggestions({ userId, page }: { userId: string; page: number }): Promise<any> {
        const suggestions = await userRepository
            .createQueryBuilder('user')
            .select([
                'user.id as userId',
                'user.firstName as firstName',
                'user.lastName as lastName',
                'user.avatar as avatar',
            ])
            .where('user.id != :userId AND user.role != :adminRole', { userId, adminRole: Role.ADMIN })
            .andWhere((qb) => {
                const relationshipAsUser1 = qb
                    .subQuery()
                    .select('relationship.user1Id')
                    .from(Relationship, 'relationship')
                    .where('relationship.user2Id = :userId', { userId })
                    .getQuery();

                const relationshipAsUser2 = qb
                    .subQuery()
                    .select('relationship.user2Id')
                    .from(Relationship, 'relationship')
                    .where('relationship.user1Id = :userId', { userId })
                    .getQuery();

                const friendRequestAsSender = qb
                    .subQuery()
                    .select('friendRequest.senderId')
                    .from(FriendRequest, 'friendRequest')
                    .where('friendRequest.receiverId = :userId', { userId })
                    .getQuery();

                const friendRequestAsReceiver = qb
                    .subQuery()
                    .select('friendRequest.receiverId')
                    .from(FriendRequest, 'friendRequest')
                    .where('friendRequest.senderId = :userId', { userId })
                    .getQuery();

                return `user.id NOT IN (${relationshipAsUser1}) AND user.id NOT IN (${relationshipAsUser2}) AND user.id NOT IN (${friendRequestAsSender}) AND user.id NOT IN (${friendRequestAsReceiver})`;
            })
            .offset((page - 1) * pageSize.suggestionsMakeFriend)
            .limit(pageSize.suggestionsMakeFriend)
            .getRawMany();

        return suggestions;
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
        await relationshipRepository.insert({
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

    async getSentFriendRequests({ senderId, page }: { senderId: string; page: number }): Promise<FriendRequest[]> {
        return await friendRequestRepository
            .createQueryBuilder('fr')
            .innerJoinAndSelect('fr.receiver', 'receiver')
            .select([
                'fr.id as friendRequestId',
                'receiver.id as userId',
                'receiver.firstName as firstName',
                'receiver.lastName as lastName',
                'receiver.avatar as avatar',
            ])
            .where('fr.senderId = :senderId', { senderId })
            .offset((page - 1) * pageSize.friendRequests)
            .limit(pageSize.friendRequests)
            .getRawMany();
    }

    async getRelationship({
        currentUserId,
        targetUserId,
    }: {
        currentUserId: string;
        targetUserId: string;
    }): Promise<string | null> {
        const fq = await friendRequestRepository.findOne({
            where: [
                { senderId: currentUserId, receiverId: targetUserId },
                { senderId: targetUserId, receiverId: currentUserId },
            ],
        });

        if (fq) return 'FRIEND_REQUEST';

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
