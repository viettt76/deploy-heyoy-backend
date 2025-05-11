import { relationshipController } from '@/controllers/relationshipController';
import ioMiddleware from '@/middlewares/ioMiddleware';
import { relationshipValidation } from '@/validations/relationshipValidation';
import express from 'express';
import { Server } from 'socket.io';

const relationshipRouter = (io: Server) => {
    const router = express.Router();

    router.use(ioMiddleware(io));

    router.get('/suggestions', relationshipValidation.getSuggestions, relationshipController.getSuggestions);
    router.post('/friend-requests', relationshipValidation.sendFriendRequest, relationshipController.sendFriendRequest);
    router.get('/friend-requests', relationshipValidation.getFriendRequests, relationshipController.getFriendRequests);
    router.get('/friend-requests/count', relationshipController.getFriendRequestCount);
    router.get(
        '/sent-requests',
        relationshipValidation.getSentFriendRequests,
        relationshipController.getSentFriendRequests,
    );
    router.post(
        '/friend-requests/:friendRequestId/acceptance',
        relationshipValidation.acceptFriendRequest,
        relationshipController.acceptFriendRequest,
    );
    router.delete(
        '/friend-requests/:friendRequestId',
        relationshipValidation.deleteFriendRequest,
        relationshipController.deleteFriendRequest,
    );
    router.delete(
        '/friend-requests/:userId/user',
        relationshipValidation.deleteFriendRequestByUserId,
        relationshipController.deleteFriendRequestByUserId,
    );
    router.get('/friends', relationshipValidation.getFriends, relationshipController.getFriends);
    router.delete('/friends/:friendId', relationshipValidation.unfriend, relationshipController.unfriend);

    return router;
};

export default relationshipRouter;
