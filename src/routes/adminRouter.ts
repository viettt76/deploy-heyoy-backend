import express from 'express';
import { adminController } from '@/controllers/adminController';
import { adminValidation } from '@/validations/adminValidation';

const adminRouter = express.Router();

adminRouter.get('/posts-not-censored', adminValidation.getPostsNotCensored, adminController.getPostsNotCensored);
adminRouter.get('/rejected-posts', adminValidation.getRejectedPosts, adminController.getRejectedPosts);
adminRouter.patch('/approve-post/:id', adminValidation.approvePost, adminController.approvePost);
adminRouter.patch('/reject-post/:id', adminValidation.rejectPost, adminController.rejectPost);
adminRouter.get('/users', adminValidation.getUsers, adminController.getUsers);
adminRouter.patch('/users/:userId/lock', adminValidation.lockUser, adminController.lockUser);
adminRouter.patch('/users/:userId/unlock', adminValidation.unlockUser, adminController.unlockUser);
adminRouter.post('/users', adminValidation.createUser, adminController.createUser);

export default adminRouter;
