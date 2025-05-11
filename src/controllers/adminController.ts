import { Request, Response } from 'express';
import { httpStatusCode } from '@/constants/httpStatusCode';
import { adminService } from '@/services/adminService';
import { PostStatus } from '@/entity/Post';
import { pageSize } from '@/constants';
import { CustomJwtPayload } from '@/custom';
import ApiError from '@/utils/ApiError';
import { authResponse } from '@/constants/authResponse';
import { authService } from '@/services/authService';

class AdminController {
    // [GET] /admin/posts-not-censored
    async getPostsNotCensored(req: Request, res: Response): Promise<any> {
        const { page } = req.query;

        const posts = await adminService.getPostsNotCensored(Number(page));

        return res.status(httpStatusCode.OK).json(posts);
    }

    // [GET] /admin/rejected-posts
    async getRejectedPosts(req: Request, res: Response): Promise<any> {
        const { page } = req.query;

        const posts = await adminService.getRejectedPosts(Number(page));

        return res.status(httpStatusCode.OK).json(posts);
    }

    // [PATCH] /admin/approve-post/:id
    async approvePost(req: Request, res: Response): Promise<any> {
        const { id } = req.params;

        await adminService.updatePostStatus({ postId: id, status: PostStatus.APPROVED });

        return res.status(httpStatusCode.OK).json();
    }

    // [PATCH] /admin/reject-post/:id
    async rejectPost(req: Request, res: Response): Promise<any> {
        const { id } = req.params;

        await adminService.updatePostStatus({ postId: id, status: PostStatus.INVALID });

        return res.status(httpStatusCode.OK).json();
    }

    // [GET] /admin/users
    async getUsers(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;

        const [users, totalUsers] = await adminService.getUsers({ adminId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json({
            users,
            totalUsers,
            totalPages: Math.ceil(totalUsers / pageSize.manageUser),
        });
    }

    // [PATCH] /admin/users/:userId/lock
    async lockUser(req: Request, res: Response): Promise<any> {
        const { userId } = req.params;

        await adminService.setActiveUser({ userId, isActive: false });

        return res.status(httpStatusCode.OK).json();
    }

    // [PATCH] /admin/users/:userId/unlock
    async unlockUser(req: Request, res: Response): Promise<any> {
        const { userId } = req.params;

        await adminService.setActiveUser({ userId, isActive: true });

        return res.status(httpStatusCode.OK).json();
    }

    // [POST] /admin/users
    async createUser(req: Request, res: Response): Promise<any> {
        const { firstName, lastName, username, password, role } = req.body;

        const user = await authService.findUserByUsername(username);

        if (user) {
            throw new ApiError(authResponse.USERNAME_EXIST.status, authResponse.USERNAME_EXIST.message);
        }

        await adminService.createUser({ firstName, lastName, username, password, role });

        return res.status(httpStatusCode.OK).json();
    }
}

export const adminController = new AdminController();
