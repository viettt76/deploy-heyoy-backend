import { notificationController } from '@/controllers/notificationController';
import express from 'express';

const notificationRouter = express.Router();

notificationRouter.get('/', notificationController.getNotifications);

export default notificationRouter;
