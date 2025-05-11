import { Request, Response } from 'express';
import { CustomJwtPayload } from '@/custom';
import { httpStatusCode } from '@/constants/httpStatusCode';
import userResponse from '@/constants/userResponse';
import { userService } from '@/services/userService';
import { relationshipService } from '@/services/relationshipService';

class UserController {
    // [GET] /users/me
    async getMyInfo(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;

        const user = await userService.findUserById(id);

        if (user) {
            return res.status(httpStatusCode.OK).json({
                id: user.id,
                lastName: user.lastName,
                firstName: user.firstName,
                birthday: user.birthday,
                gender: user.gender,
                hometown: user.hometown,
                school: user.school,
                workplace: user.workplace,
                avatar: user.avatar,
                isPrivate: user.isPrivate,
                role: user.role,
            });
        } else {
            res.clearCookie('token');
            res.clearCookie('refreshToken');
            return res.status(userResponse.USER_NOT_FOUND.status).json({
                message: userResponse.USER_NOT_FOUND.message,
            });
        }
    }

    // [GET] /users/information/:userId
    async getUserInfo(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { userId } = req.params;

        const user = await userService.findUserById(userId);

        if (user) {
            const relationship = await relationshipService.getRelationship({
                currentUserId: id,
                targetUserId: userId,
            });

            return res.status(httpStatusCode.OK).json({
                lastName: user.lastName,
                firstName: user.firstName,
                avatar: user.avatar,
                isPrivate: user.isPrivate,
                relationship,
                ...(!user.isPrivate && {
                    birthday: user.birthday,
                    gender: user.gender,
                    hometown: user.hometown,
                    school: user.school,
                    workplace: user.workplace,
                }),
            });
        } else {
            return res.status(userResponse.USER_NOT_FOUND.status).json({
                message: userResponse.USER_NOT_FOUND.message,
            });
        }
    }

    // [PUT] /users/information
    async changeInformation(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { firstName, lastName, birthday, gender, hometown, school, workplace, avatar, isPrivate } = req.body;

        await userService.changeInformation({
            userId: id,
            userInfo: { firstName, lastName, birthday, gender, hometown, school, workplace, avatar, isPrivate },
        });

        return res.status(httpStatusCode.NO_CONTENT).json();
    }

    // [GET] /users/images/:userId
    async getUserImages(req: Request, res: Response): Promise<any> {
        const { userId } = req.params;

        const images = await userService.getUserImages(userId);

        return res.status(httpStatusCode.OK).json(images);
    }

    // [GET] /users/search
    async search(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { keyword } = req.query as Record<string, string>;

        const users = await userService.search({ keyword, userId: id });

        return res.status(httpStatusCode.OK).json(users);
    }
}

export const userController = new UserController();
