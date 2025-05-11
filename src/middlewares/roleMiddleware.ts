import { httpStatusCode } from '@/constants/httpStatusCode';
import { CustomJwtPayload } from '@/custom';
import { Role } from '@/entity/User';
import { NextFunction, Request, Response } from 'express';

export const adminMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const { role } = req.userToken as CustomJwtPayload;

    if (role === Role.ADMIN) {
        return next();
    }

    res.status(httpStatusCode.UNAUTHORIZED).json();
};
