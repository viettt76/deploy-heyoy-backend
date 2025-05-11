import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { authResponse } from '@/constants/authResponse';
import { httpStatusCode } from '@/constants/httpStatusCode';
import { authService } from '@/services/authService';
import ApiError from '@/utils/ApiError';
import { CustomJwtPayload } from '@/custom';

class AuthController {
    // [POST] /auth/signup
    async signup(req: Request, res: Response): Promise<any> {
        const { firstName, lastName, username, password, gender } = req.body;

        const user = await authService.findUserByUsername(username);

        if (user) {
            throw new ApiError(authResponse.USERNAME_EXIST.status, authResponse.USERNAME_EXIST.message);
        }

        await authService.createUser({ firstName, lastName, username, password, gender });

        return res.status(httpStatusCode.CREATED).json();
    }

    // [POST] /auth/login
    async login(req: Request, res: Response): Promise<any> {
        const { username, password } = req.body;

        const user = await authService.findUserByUsername(username);

        if (!user) {
            const userIsDeleted = await authService.findUserEvenDeleted(username);

            if (userIsDeleted) {
                const checkPassword = bcrypt.compareSync(password, userIsDeleted.password);
                if (checkPassword) {
                    return res.status(authResponse.ACCOUNT_DELETED.status).json({
                        message: authResponse.ACCOUNT_DELETED.message,
                        code: authResponse.ACCOUNT_DELETED.code,
                    });
                }
            }
            return res.status(authResponse.LOGIN_INCORRECT.status).json({
                message: authResponse.LOGIN_INCORRECT.message,
            });
        }

        const checkPassword = bcrypt.compareSync(password, user.password);

        if (checkPassword) {
            if (!user?.isActive) {
                return res.status(authResponse.ACCOUNT_LOCKED.status).json({
                    message: authResponse.ACCOUNT_LOCKED.message,
                    code: authResponse.ACCOUNT_LOCKED.code,
                });
            }

            const jwtAccessSecret = process.env.JWT_ACCESS_SECRET;
            const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
            const tokenMaxAge = process.env.TOKEN_MAX_AGE;
            const refreshTokenMaxAge = process.env.REFRESH_TOKEN_MAX_AGE;
            const frontendUrl = process.env.FRONTEND_URL;

            if (!jwtAccessSecret || !jwtRefreshSecret || !tokenMaxAge || !refreshTokenMaxAge || !frontendUrl) {
                throw new Error('Missing JWT secrets or jwt max age');
            }

            const payload = {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
            };

            const token = jwt.sign(payload, jwtAccessSecret);
            const refreshToken = jwt.sign(payload, jwtRefreshSecret);

            // res.cookie('token', token, {
            //     domain: '.onrender.com',
            //     httpOnly: true,
            //     sameSite: 'none',
            //     secure: true,
            //     maxAge: eval(tokenMaxAge),
            //     path: '/',
            // });
            // res.cookie('refreshToken', refreshToken, {
            //     domain: '.onrender.com',
            //     httpOnly: true,
            //     sameSite: 'none',
            //     secure: true,
            //     maxAge: eval(refreshTokenMaxAge),
            //     path: '/',
            // });
            return res.status(httpStatusCode.OK).json({
                token,
            });
        } else {
            return res.status(authResponse.LOGIN_INCORRECT.status).json({
                message: authResponse.LOGIN_INCORRECT.message,
            });
        }
    }

    // [POST] /auth/logout
    logout(req: Request, res: Response) {
        res.clearCookie('token');
        res.clearCookie('refreshToken');
        res.status(httpStatusCode.OK).json();
    }

    // [PATCH] /auth/password
    async changePassword(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { oldPassword, newPassword } = req.body;

        await authService.changePassword({ userId: id, oldPassword, newPassword });

        res.clearCookie('token');
        res.clearCookie('refreshToken');
        return res.status(httpStatusCode.OK).json();
    }

    // [DELETE] /auth/account
    async deleteAccount(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { password } = req.body;

        await authService.deleteAccount({ userId: id, password });

        res.clearCookie('token');
        res.clearCookie('refreshToken');
        return res.status(httpStatusCode.NO_CONTENT).json();
    }

    // [POST] /auth/recover-account
    async recoverAccount(req: Request, res: Response): Promise<any> {
        const { username, password } = req.body;

        await authService.recoverAccount({ username, password });

        return res.status(httpStatusCode.OK).json();
    }
}

export const authController = new AuthController();
