import { authResponse } from '@/constants/authResponse';
import { AppDataSource } from '@/data-source';
import ApiError from '@/utils/ApiError';
import { Not, IsNull } from 'typeorm';
import bcrypt from 'bcrypt';

import { Gender, User } from '@/entity/User';
import { Comment } from '@/entity/Comment';
import { CommentReaction } from '@/entity/CommentReaction';
import { ConversationParticipant } from '@/entity/ConversationParticipant';
import { FriendRequest } from '@/entity/FriendRequest';
import { MessageReaction } from '@/entity/MessageReaction';
import { Post } from '@/entity/Post';
import { PostReaction } from '@/entity/PostReaction';
import { Relationship } from '@/entity/Relationship';

const saltRounds = 10;

const userRepository = AppDataSource.getRepository(User);
const commentRepository = AppDataSource.getRepository(Comment);
const commentReactionRepository = AppDataSource.getRepository(CommentReaction);
const conversationParticipantRepository = AppDataSource.getRepository(ConversationParticipant);
const friendRequestRepository = AppDataSource.getRepository(FriendRequest);
const messageReactionRepository = AppDataSource.getRepository(MessageReaction);
const postRepository = AppDataSource.getRepository(Post);
const postReactionRepository = AppDataSource.getRepository(PostReaction);
const relationshipRepository = AppDataSource.getRepository(Relationship);

class AuthService {
    async findUserByUsername(username: string): Promise<User | null> {
        return await userRepository.findOne({
            where: { username },
        });
    }

    async findUserEvenDeleted(username: string): Promise<User | null> {
        return await userRepository.findOne({
            where: {
                username,
                deletedAt: Not(IsNull()),
            },
            withDeleted: true,
        });
    }

    async createUser(userData: {
        firstName: string;
        lastName: string;
        username: string;
        gender: Gender;
        password: string;
    }): Promise<void> {
        const { firstName, lastName, username, password, gender } = userData;

        const hashPassword = bcrypt.hashSync(password, saltRounds);

        await userRepository.insert({
            firstName,
            lastName,
            username,
            gender,
            password: hashPassword,
        });
    }

    async changePassword({
        userId,
        oldPassword,
        newPassword,
    }: {
        userId: string;
        oldPassword: string;
        newPassword: string;
    }): Promise<void> {
        const user = await userRepository.findOneBy({ id: userId });

        if (!user) {
            throw new ApiError(authResponse.USER_NOT_FOUND.status, authResponse.USER_NOT_FOUND.message);
        }

        const checkPassword = bcrypt.compareSync(oldPassword, user.password);

        if (!checkPassword) {
            throw new ApiError(authResponse.CHANGE_PASSWORD_FAIL.status, authResponse.CHANGE_PASSWORD_FAIL.message);
        }

        const newHashPassword = bcrypt.hashSync(newPassword, saltRounds);

        user.password = newHashPassword;

        userRepository.save(user);
    }

    async deleteAccount({ userId, password }: { userId: string; password: string }): Promise<void> {
        const user = await userRepository.findOneBy({ id: userId });

        if (!user) {
            throw new ApiError(authResponse.USER_NOT_FOUND.status, authResponse.USER_NOT_FOUND.message);
        }

        const checkPassword = bcrypt.compareSync(password, user.password);

        if (!checkPassword) {
            throw new ApiError(authResponse.CHANGE_PASSWORD_FAIL.status, authResponse.CHANGE_PASSWORD_FAIL.message);
        }

        await userRepository.softRemove(user);

        const comments = await commentRepository.find({
            where: {
                commentatorId: userId,
            },
        });
        await commentRepository.softRemove(comments);

        const commentReactions = await commentReactionRepository.find({
            where: {
                userId,
            },
        });
        await commentReactionRepository.softRemove(commentReactions);

        const conversationParticipants = await conversationParticipantRepository.find({
            where: {
                userId,
            },
        });
        await conversationParticipantRepository.softRemove(conversationParticipants);

        const friendRequests = await friendRequestRepository.find({
            where: [{ senderId: userId }, { receiverId: userId }],
        });
        await friendRequestRepository.softRemove(friendRequests);

        const messageReactions = await messageReactionRepository.find({
            where: { userId },
        });
        await messageReactionRepository.softRemove(messageReactions);

        const posts = await postRepository.find({
            where: { posterId: userId },
        });
        await postRepository.softRemove(posts);

        const postReactions = await postReactionRepository.find({
            where: { userId },
        });
        await postReactionRepository.softRemove(postReactions);

        const relationships = await relationshipRepository.find({
            where: [{ user1Id: userId }, { user2Id: userId }],
        });
        await relationshipRepository.softRemove(relationships);
    }

    async recoverAccount({ username, password }: { username: string; password: string }): Promise<void> {
        const user = await userRepository.findOne({ where: { username }, withDeleted: true });

        if (!user) {
            throw new ApiError(authResponse.USER_NOT_FOUND.status, authResponse.USER_NOT_FOUND.message);
        }

        const checkPassword = bcrypt.compareSync(password, user.password);

        if (!checkPassword) {
            throw new ApiError(
                authResponse.RECOVER_ACCOUNT_PASSWORD_INCORRECT.status,
                authResponse.RECOVER_ACCOUNT_PASSWORD_INCORRECT.message,
            );
        }

        await userRepository.recover(user);

        const userId = user.id;

        const comments = await commentRepository.find({
            where: {
                commentatorId: userId,
            },
            withDeleted: true,
        });
        await commentRepository.recover(comments);

        const commentReactions = await commentReactionRepository.find({
            where: {
                userId,
            },
            withDeleted: true,
        });
        await commentReactionRepository.recover(commentReactions);

        const conversationParticipants = await conversationParticipantRepository.find({
            where: {
                userId,
            },
            withDeleted: true,
        });
        await conversationParticipantRepository.recover(conversationParticipants);

        const friendRequests = await friendRequestRepository.find({
            where: [{ senderId: userId }, { receiverId: userId }],
            withDeleted: true,
        });
        await friendRequestRepository.recover(friendRequests);

        const messageReactions = await messageReactionRepository.find({
            where: { userId },
            withDeleted: true,
        });
        await messageReactionRepository.recover(messageReactions);

        const posts = await postRepository.find({
            where: { posterId: userId },
            withDeleted: true,
        });
        await postRepository.recover(posts);

        const postReactions = await postReactionRepository.find({
            where: { userId },
            withDeleted: true,
        });
        await postReactionRepository.recover(postReactions);

        const relationships = await relationshipRepository.find({
            where: [{ user1Id: userId }, { user2Id: userId }],
            withDeleted: true,
        });
        await relationshipRepository.recover(relationships);
    }
}

export const authService = new AuthService();
