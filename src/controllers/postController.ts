import { Request, Response } from 'express';
import { postService } from '@/services/postService';
import { httpStatusCode } from '@/constants/httpStatusCode';
import { PostReactionType } from '@/entity/PostReaction';
import { CustomJwtPayload, IoRequest } from '@/custom';
import { userService } from '@/services/userService';
import { getOnlineFriendsFromRedis } from '@/services/redisService';

class PostController {
    // [POST] /posts
    async createPost(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { content, images } = req.body;
        const { io } = req as IoRequest;

        const newPost = await postService.createPost({ posterId: id, content, images });

        const creator = await userService.getUserFields({ userId: id, fields: ['avatar'] });

        const friendIds = await getOnlineFriendsFromRedis(id);
        friendIds.forEach((friendId) => {
            io.to(`user-${friendId}`).emit('newPost', {
                postId: newPost.id,
                creatorId: id,
                creatorFirstName: firstName,
                creatorLastName: lastName,
                creatorAvatar: creator?.avatar,
                content,
                images,
                createdAt: newPost.createdAt,
            });
        });

        io.to(`user-${id}`).emit('myNewPost', {
            postId: newPost.id,
            creatorId: id,
            creatorFirstName: firstName,
            creatorLastName: lastName,
            creatorAvatar: creator?.avatar,
            content,
            images,
            createdAt: newPost.createdAt,
        });

        return res.status(httpStatusCode.CREATED).json();
    }

    // [GET] /posts
    async getPosts(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;
        const posts = await postService.getPosts({ userId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json(posts);
    }

    // [GET] /posts/user/:userId
    async getPostsByUserId(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { userId, page } = req.query as Record<string, string>;

        const posts = await postService.getPostsByUserId({ currentUserId: id, userId, page: Number(page) });

        return res.status(httpStatusCode.OK).json(posts);
    }

    // [GET] /posts/reactionTypes
    async getReactionTypes(req: Request, res: Response): Promise<any> {
        const reactionTypes = PostReactionType;

        return res.status(httpStatusCode.OK).json(reactionTypes);
    }

    // [PUT] /posts/reactions/:postId
    async reactToPost(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { io } = req as IoRequest;
        const { postId } = req.params;
        const { posterId, reactionType } = req.body;

        const postReaction = await postService.getPostReaction({ postId, userId: id });

        const onlineFriends = await getOnlineFriendsFromRedis(posterId);

        if (!postReaction) {
            const newReaction = await postService.addPostReaction({ postId, userId: id, reactionType });
            const reactor = await userService.getUserFields({ userId: id, fields: ['avatar'] });

            const _newReaction = {
                postReactionId: newReaction.id,
                reactionType: newReaction.reactionType,
                user: {
                    userId: id,
                    firstName,
                    lastName,
                    avatar: reactor?.avatar,
                },
            };

            // Send all the online friends of the poster
            onlineFriends.forEach((friendId: string) => {
                io.to(`user-${friendId}`).emit('reactToPost', { postId, newReaction: _newReaction });
            });

            // If the current user is not on the list of friends of the poster
            if (!onlineFriends.includes(id))
                io.to(`user-${id}`).emit('reactToPost', { postId, newReaction: _newReaction });

            // If the current user is not the poster
            if (id !== posterId) io.to(`user-${posterId}`).emit('reactToPost', { postId, newReaction: _newReaction });
        } else if (reactionType) {
            await postService.updatePostReaction({ postReaction, reactionType });

            // Send all the online friends of the poster
            onlineFriends.forEach((friendId: string) => {
                io.to(`user-${friendId}`).emit('updateReactToPost', {
                    postId,
                    postReactionId: postReaction.id,
                    reactionType,
                });
            });

            // If the current user is not on the list of friends of the poster
            if (!onlineFriends.includes(id))
                io.to(`user-${id}`).emit('updateReactToPost', {
                    postId,
                    postReactionId: postReaction.id,
                    reactionType,
                });

            // If the current user is not the poster
            if (id !== posterId)
                io.to(`user-${posterId}`).emit('updateReactToPost', {
                    postId,
                    postReactionId: postReaction.id,
                    reactionType,
                });
        } else {
            await postService.deletePostReaction(postReaction.id);

            // Send all the online friends of the poster
            onlineFriends.forEach((friendId: string) => {
                io.to(`user-${friendId}`).emit('deleteReactToPost', {
                    postId,
                    postReactionId: postReaction.id,
                });
            });

            // If the current user is not on the list of friends of the poster
            if (!onlineFriends.includes(id))
                io.to(`user-${id}`).emit('deleteReactToPost', { postId, postReactionId: postReaction.id });

            // If the current user is not the poster
            if (id !== posterId)
                io.to(`user-${posterId}`).emit('deleteReactToPost', { postId, postReactionId: postReaction.id });
        }

        return res.status(httpStatusCode.OK).json();
    }

    // [POST] /posts/comments
    async sendComment(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { io } = req as IoRequest;
        const { postId, parentCommentId, content, image } = req.body;

        const newComment = await postService.createComment({ postId, userId: id, parentCommentId, content, image });
        const commentator = await userService.getUserFields({ userId: id, fields: ['avatar'] });

        if (parentCommentId) {
            io.to(`post-${postId}`).emit('newReply', {
                id: newComment.id,
                postId,
                parentCommentId: newComment.parentCommentId,
                content: newComment.content,
                image: newComment.image,
                commentatorId: id,
                commentatorFirstName: firstName,
                commentatorLastName: lastName,
                commentatorAvatar: commentator?.avatar,
            });
        } else {
            io.to(`post-${postId}`).emit('newComment', {
                id: newComment.id,
                postId,
                content: newComment.content,
                image: newComment.image,
                commentatorId: id,
                commentatorFirstName: firstName,
                commentatorLastName: lastName,
                commentatorAvatar: commentator?.avatar,
            });
        }

        return res.status(httpStatusCode.CREATED).json();
    }

    // [GET] /posts/comments
    async getComments(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { postId } = req.params;
        const { page, sortField, sortType } = req.query as { page: string; sortField: string; sortType: string };

        const comments = await postService.getComments({
            userId: id,
            page: Number(page),
            postId,
            sortField,
            sortType: (sortType as 'DESC' | 'ASC') || 'DESC',
        });
        return res.status(httpStatusCode.OK).json(comments);
    }

    // [GET] /posts/comments/:commentId/replies
    async getCommentReplies(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { commentId } = req.params;
        const { page, sortField, sortType } = req.query as { page: string; sortField: string; sortType: string };

        const replies = await postService.getCommentReplies({
            userId: id,
            page: Number(page),
            parentCommentId: commentId,
            sortField,
            sortType: (sortType as 'DESC' | 'ASC') || 'DESC',
        });
        return res.status(httpStatusCode.OK).json(replies);
    }

    // [PUT] /posts/comments/reactions/:commentId
    async reactToComment(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { io } = req as IoRequest;
        const { commentId } = req.params;
        const { postId, reactionType } = req.body;

        const commentReaction = await postService.getCommentReaction({ userId: id, commentId });

        if (!commentReaction) {
            const newReaction = await postService.addCommentReaction({ commentId, userId: id, reactionType });
            const reactor = await userService.getUserFields({ userId: id, fields: ['avatar'] });

            io.to(`post-${postId}`).emit('reactToComment', {
                commentId,
                commentReactionId: newReaction.id,
                reactionType,
                user: {
                    userId: id,
                    firstName,
                    lastName,
                    avatar: reactor?.avatar,
                },
            });
        } else if (reactionType) {
            await postService.updateCommentReaction({ commentReaction, reactionType });

            io.to(`post-${postId}`).emit('updateReactToComment', {
                commentId,
                commentReactionId: commentReaction.id,
                reactionType,
            });
        } else {
            await postService.deleteCommentReaction(commentReaction.id);

            io.to(`post-${postId}`).emit('deleteReactToComment', {
                commentId,
                commentReactionId: commentReaction.id,
            });
        }

        return res.status(httpStatusCode.OK).json();
    }

    // [POST] /posts/bookmark
    async bookmark(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { postId } = req.body;

        await postService.bookmark({ postId, userId: id });

        return res.status(httpStatusCode.OK).json();
    }

    // [DELETE] /posts/bookmark/:id
    async unbookmark(req: Request, res: Response): Promise<any> {
        const { id: userId } = req.userToken as CustomJwtPayload;
        const { id: postId } = req.params;

        await postService.unbookmark({ postId, userId });

        return res.status(httpStatusCode.OK).json();
    }

    // [DELETE] /posts/:id
    async deletePost(req: Request, res: Response): Promise<any> {
        const { id: userId } = req.userToken as CustomJwtPayload;
        const { id: postId } = req.params;
        const { io } = req as IoRequest;

        await postService.deletePost({ postId, userId });

        io.to(`user-${userId}`).emit('deletePost', postId);

        return res.status(httpStatusCode.OK).json();
    }

    // [GET] /posts/deleted
    async getDeletedPosts(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;

        const posts = await postService.getDeletedPosts({ userId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json(posts);
    }

    // [PATCH] /posts/recover/:id
    async recoverPost(req: Request, res: Response): Promise<any> {
        const { id: userId } = req.userToken as CustomJwtPayload;
        const { id: postId } = req.params;

        const posts = await postService.recoverPost({ postId, userId });

        return res.status(httpStatusCode.OK).json(posts);
    }

    // [GET] /posts/bookmark
    async getBookmarkPosts(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;

        const posts = await postService.getBookmarkPosts({ userId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json(posts);
    }
}

export const postController = new PostController();
