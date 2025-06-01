import { pageSize } from '@/constants';
import { postResponse } from '@/constants/postResponse';
import userResponse from '@/constants/userResponse';
import { AppDataSource } from '@/data-source';
import { ImageOfPost } from '@/entity/ImageOfPost';
import { Post, PostStatus } from '@/entity/Post';
import { Role, User } from '@/entity/User';
import ApiError from '@/utils/ApiError';
import { Not } from 'typeorm';
import bcrypt from 'bcrypt';

const saltRounds = 10;

const postRepository = AppDataSource.getRepository(Post);
const userRepository = AppDataSource.getRepository(User);

class AdminService {
    async getPostsNotCensored(page: number): Promise<any[]> {
        const posts = await postRepository
            .createQueryBuilder('post')
            .leftJoinAndSelect(ImageOfPost, 'image', 'image.postId = post.id')
            .innerJoin(User, 'poster', 'poster.id = post.poster')
            .select([
                'post.id as postId',
                'post.posterId as posterId',
                'poster.firstName as posterFirstName',
                'poster.lastName as posterLastName',
                'poster.avatar as posterAvatar',
                'post.visibilityType as visibilityType',
                'post.content as content',
                'post.createdAt as createdAt',
                "CONCAT('[', GROUP_CONCAT(JSON_OBJECT('id', image.id, 'imageUrl', image.imageUrl)), ']') as images",
            ])
            .where('post.status != :postStatus', { postStatus: PostStatus.INVALID })
            .offset((page - 1) * pageSize.posts)
            .limit(pageSize.posts)
            .groupBy('post.id')
            .orderBy('post.createdAt', 'DESC')
            .getRawMany();

        const result = posts.map((post) => ({
            postId: post.postId,
            visibilityType: post.visibilityType,
            content: post.content,
            createdAt: post.createdAt,
            posterInfo: {
                userId: post.posterId,
                firstName: post.posterFirstName,
                lastName: post.posterLastName,
                avatar: post.posterAvatar,
            },
            images: JSON.parse(post.images)[0]?.id === null ? [] : JSON.parse(post.images),
        }));

        return result;
    }

    async getRejectedPosts(page: number): Promise<any[]> {
        const posts = await postRepository
            .createQueryBuilder('post')
            .leftJoinAndSelect(ImageOfPost, 'image', 'image.postId = post.id')
            .innerJoin(User, 'poster', 'poster.id = post.poster')
            .select([
                'post.id as postId',
                'post.posterId as posterId',
                'poster.firstName as posterFirstName',
                'poster.lastName as posterLastName',
                'poster.avatar as posterAvatar',
                'post.visibilityType as visibilityType',
                'post.content as content',
                'post.createdAt as createdAt',
                "CONCAT('[', GROUP_CONCAT(JSON_OBJECT('id', image.id, 'imageUrl', image.imageUrl)), ']') as images",
            ])
            .where('post.status = :postStatus', { postStatus: PostStatus.INVALID })
            .offset((page - 1) * pageSize.posts)
            .limit(pageSize.posts)
            .groupBy('post.id')
            .orderBy('post.createdAt', 'DESC')
            .getRawMany();

        const result = posts.map((post) => ({
            postId: post.postId,
            visibilityType: post.visibilityType,
            content: post.content,
            createdAt: post.createdAt,
            posterInfo: {
                userId: post.posterId,
                firstName: post.posterFirstName,
                lastName: post.posterLastName,
                avatar: post.posterAvatar,
            },
            images: JSON.parse(post.images)[0]?.id === null ? [] : JSON.parse(post.images),
        }));

        return result;
    }

    async updatePostStatus({ postId, status }: { postId: string; status: PostStatus }): Promise<void> {
        const post = await postRepository.findOneBy({ id: postId });

        if (!post) {
            throw new ApiError(postResponse.POST_NOT_FOUND.status, postResponse.POST_NOT_FOUND.message);
        }

        post.status = status;

        await postRepository.save(post);
    }

    async getUsers({ page, keyword }: { page: number; keyword?: string }): Promise<{
        users: any[];
        totalPages: number;
    }> {
        const queryBuilder = userRepository
            .createQueryBuilder('user')
            .select(['user.id', 'user.username', 'user.firstName', 'user.lastName', 'user.role', 'user.isActive'])
            .where('user.role != :adminRole', { adminRole: Role.ADMIN });

        if (keyword) {
            const keywords = keyword.split(' ');
            const keywordConditions = keywords.map(
                (word, index) => `(user.firstName LIKE :keyword${index} OR user.lastName LIKE :keyword${index})`,
            );
            const keywordParams = Object.fromEntries(keywords.map((word, index) => [`keyword${index}`, `%${word}%`]));

            queryBuilder.andWhere(`(${keywordConditions.join(' OR ')})`, keywordParams);
        }

        queryBuilder.offset((page - 1) * pageSize.manageUser);
        queryBuilder.limit(pageSize.manageUser);

        const users = await queryBuilder.getManyAndCount();

        return {
            users: users[0].map((u) => ({
                id: u.id,
                username: u.username,
                firstName: u.firstName,
                lastName: u.lastName,
                role: u.role,
                isActive: u.isActive,
            })),
            totalPages: Math.ceil(users[1] / pageSize.manageUser),
        };
    }

    async setActiveUser({ userId, isActive }: { userId: string; isActive: boolean }): Promise<void> {
        const user = await userRepository.findOneBy({ id: userId });
        if (!user) throw new ApiError(userResponse.USER_NOT_FOUND.status, userResponse.USER_NOT_FOUND.message);

        user.isActive = isActive;
        await userRepository.save(user);
    }

    async createUser(userInfo: {
        firstName: string;
        lastName: string;
        username: string;
        password: string;
        role: Role;
    }): Promise<void> {
        const { firstName, lastName, username, password, role } = userInfo;

        const hashPassword = bcrypt.hashSync(password, saltRounds);

        await userRepository.insert({
            firstName,
            lastName,
            username,
            password: hashPassword,
            role,
        });
    }
}

export const adminService = new AdminService();
