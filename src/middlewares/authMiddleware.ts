import { authResponse } from '@/constants/authResponse';
import { CustomJwtPayload } from '@/custom';
import { userService } from '@/services/userService';
import { NextFunction, Request, Response } from 'express';
import { verify, sign, JwtPayload, VerifyErrors } from 'jsonwebtoken';

const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const nonSecurePaths = ['/auth/users', '/auth/token', '/auth/recover-account'];
    if (nonSecurePaths.includes(req.path)) return next();

    const jwtAccessSecret = process.env.JWT_ACCESS_SECRET;
    const tokenMaxAge = process.env.TOKEN_MAX_AGE;

    if (!jwtAccessSecret || !tokenMaxAge) {
        throw new Error('Missing JWT secrets or token max age');
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token)
        return res.status(authResponse.INVALID_TOKEN.status).json({ message: authResponse.INVALID_TOKEN.message });

    verify(token, jwtAccessSecret, async (err: VerifyErrors | null, userToken: JwtPayload | string | undefined) => {
        if (err) return res.sendStatus(403);

        if (userToken && typeof userToken !== 'string') {
            const user = await userService.getUserFields({ userId: userToken.id, fields: ['isActive'] });

            if (!user?.isActive) {
                return res.status(authResponse.ACCOUNT_LOCKED.status).json({
                    message: authResponse.ACCOUNT_LOCKED.message,
                    code: authResponse.ACCOUNT_LOCKED.code,
                });
            }

            req.userToken = userToken;
            return next();
        }
    });
};

export default authMiddleware;
