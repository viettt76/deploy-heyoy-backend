import express from 'express';
import { postController } from '@/controllers/postController';
import { postValidation } from '@/validations/postValidation';
import { Server } from 'socket.io';
import ioMiddleware from '@/middlewares/ioMiddleware';

const postRouter = (io: Server) => {
    const router = express.Router();

    router.use(ioMiddleware(io));

    router.post('/', postValidation.createPost, postController.createPost);
    router.get('/', postValidation.getPosts, postController.getPosts);
    router.get('/user', postValidation.getPostsByUserId, postController.getPostsByUserId);
    router.get('/reactionTypes', postController.getReactionTypes);
    router.put('/reactions/:postId', postValidation.reactToPost, postController.reactToPost);
    router.post('/comments', postValidation.sendComment, postController.sendComment);
    router.get('/comments/:postId', postValidation.getComments, postController.getComments);
    router.get('/comments/:commentId/replies', postValidation.getCommentReplies, postController.getCommentReplies);
    router.put('/comments/reactions/:commentId', postValidation.reactToComment, postController.reactToComment);
    router.post('/bookmark', postValidation.bookmark, postController.bookmark);
    router.delete('/bookmark/:id', postValidation.unbookmark, postController.unbookmark);
    router.delete('/:id', postValidation.deletePost, postController.deletePost);
    router.get('/deleted', postValidation.getDeletedPosts, postController.getDeletedPosts);
    router.patch('/recover/:id', postValidation.recoverPost, postController.recoverPost);
    router.get('/bookmark', postValidation.getBookmarkPosts, postController.getBookmarkPosts);

    return router;
};

export default postRouter;
