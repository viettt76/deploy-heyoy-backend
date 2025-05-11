import express from 'express';
import { authController } from '@/controllers/authController';
import { authValidation } from '@/validations/authValidation';

const authRouter = express.Router();

authRouter.post('/users', authValidation.signup, authController.signup);
authRouter.post('/token', authValidation.login, authController.login);
authRouter.delete('/token', authController.logout);
authRouter.patch('/password', authValidation.changePassword, authController.changePassword);
authRouter.delete('/account', authValidation.deleteAccount, authController.deleteAccount);
authRouter.post('/recover-account', authValidation.recoverAccount, authController.recoverAccount);

export default authRouter;
