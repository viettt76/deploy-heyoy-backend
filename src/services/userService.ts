import { AppDataSource } from '@/data-source';
import { FriendRequest } from '@/entity/FriendRequest';
import { ImageOfPost } from '@/entity/ImageOfPost';
import { Relationship } from '@/entity/Relationship';
import { Gender, User } from '@/entity/User';

const userRepository = AppDataSource.getRepository(User);
const imageOfPostRepository = AppDataSource.getRepository(ImageOfPost);

class UserService {
    async findUserById(id: string): Promise<User | null> {
        return await userRepository.findOneBy({
            id,
        });
    }

    async getUserFields({ userId, fields }: { userId: string; fields: string[] }): Promise<User | null> {
        const obj = Object.fromEntries(fields.map((field) => [field, true]));
        return await userRepository.findOne({
            where: { id: userId },
            select: obj,
        });
    }

    async changeInformation({
        userId,
        userInfo,
    }: {
        userId: string;
        userInfo: {
            firstName?: string;
            lastName?: string;
            birthday?: Date;
            gender?: Gender;
            hometown?: string;
            school?: string;
            workplace?: string;
            avatar?: string;
            isPrivate?: boolean;
        };
    }): Promise<void> {
        await userRepository.update(
            {
                id: userId,
            },
            {
                firstName: userInfo.firstName,
                lastName: userInfo.lastName,
                birthday: userInfo.birthday,
                gender: userInfo.gender,
                hometown: userInfo.hometown,
                school: userInfo.school,
                workplace: userInfo.workplace,
                avatar: userInfo.avatar,
                isPrivate: userInfo.isPrivate,
            },
        );
    }

    async getUserImages(userId: string): Promise<any> {
        return await imageOfPostRepository
            .createQueryBuilder('image')
            .select(['image.postId as postId', 'image.imageUrl as imageUrl'])
            .innerJoin('image.post', 'post')
            .where('post.posterId = :userId', { userId })
            .groupBy('image.imageUrl')
            .addGroupBy('image.postId')
            .getRawMany();
    }

    async search({ keyword, userId }: { keyword: string; userId: string }): Promise<any> {
        const queryBuilder = userRepository
            .createQueryBuilder('user')
            .leftJoinAndSelect(
                Relationship,
                'relationship',
                `(user.id = relationship.user1Id AND :userId = relationship.user2Id) 
                    OR (user.id = relationship.user2Id AND :userId = relationship.user1Id)`,
            )
            .leftJoinAndSelect(
                FriendRequest,
                'friendRequestAsSender',
                `user.id = friendRequestAsSender.receiverId AND :userId = friendRequestAsSender.senderId`,
            )
            .leftJoinAndSelect(
                FriendRequest,
                'friendRequestAsReceiver',
                `user.id = friendRequestAsReceiver.senderId AND :userId = friendRequestAsReceiver.receiverId`,
            )
            .select([
                'user.id as userId',
                'user.firstName as firstName',
                'user.lastName as lastName',
                'user.avatar as avatar',
                'relationship.id as relationshipId',
                'friendRequestAsSender.id as friendRequestAsSenderId',
                'friendRequestAsReceiver.id as friendRequestAsReceiverId',
            ]);

        const keywords = keyword.split(' ');

        keywords.forEach((word, index) => {
            const condition = `(user.firstName like :keyword${index} OR user.lastName like :keyword${index})`;

            if (index === 0) {
                queryBuilder.where(condition, { keyword0: `%${word}%` });
            } else {
                queryBuilder.orWhere(condition, { [`keyword${index}`]: `%${word}%` });
            }
        });
        queryBuilder.andWhere('user.id != :userId', { userId });
        queryBuilder.setParameter('userId', userId);

        return await queryBuilder.getRawMany();
    }
}

export const userService = new UserService();
