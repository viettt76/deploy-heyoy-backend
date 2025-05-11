import { Server } from 'socket.io';
import express from 'express';
import { userController } from '@/controllers/userController';
import { userValidation } from '@/validations/userValidation';

const userRouter = (io: Server) => {
    const router = express.Router();

    router.get('/me', userController.getMyInfo);
    router.get('/information/:userId', userValidation.getUserInfo, userController.getUserInfo);
    router.put('/information', userValidation.changeInformation, userController.changeInformation);
    router.get('/images/:userId', userValidation.getUserImages, userController.getUserImages);
    router.get('/search', userValidation.search, userController.search);

    return router;
};

export default userRouter;
