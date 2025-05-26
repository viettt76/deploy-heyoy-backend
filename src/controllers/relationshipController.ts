import { httpStatusCode } from '@/constants/httpStatusCode';
import relationshipResponse from '@/constants/relationshipResponse';
import { CustomJwtPayload, IoRequest } from '@/custom';
import { NotificationType } from '@/entity/Notification';
import { notificationService } from '@/services/notificationService';
import { relationshipService } from '@/services/relationshipService';
import { userService } from '@/services/userService';
import ApiError from '@/utils/ApiError';
import { Request, Response } from 'express';

class RelationshipController {
    // [GET] /relationships/suggestions
    async getSuggestions(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { keyword, page } = req.query;
        const suggestions = await relationshipService.getSuggestions({
            userId: id,
            keyword: keyword?.toString(),
            page: Number(page),
        });

        return res.status(httpStatusCode.OK).json(suggestions);
    }

    // [POST] /relationships/friend-requests
    async sendFriendRequest(req: Request, res: Response): Promise<any> {
        const { id, firstName, lastName } = req.userToken as CustomJwtPayload;
        const { receiverId } = req.body;
        const { io } = req as IoRequest;

        const fq = await relationshipService.getFriendRequestByUserId({ userId: id, receiverId });

        if (fq)
            throw new ApiError(
                relationshipResponse.FRIEND_REQUEST_EXISTS.status,
                relationshipResponse.FRIEND_REQUEST_EXISTS.message,
            );

        const friendRequest = await relationshipService.createFriendRequest({ userId: id, receiverId });
        const newFriendRequestNotification = await notificationService.createNotification({
            userId: receiverId,
            actorId: id,
            type: NotificationType.FRIEND_REQUEST,
            referenceId: friendRequest.id,
            content: `<b>${lastName} ${firstName}</b> đã gửi lời mời kết bạn cho bạn`,
        });
        const user = await userService.getUserFields({ userId: id, fields: ['avatar'] });

        io.to(`user-${receiverId}`).emit('newFriendRequest', {
            friendRequestId: friendRequest.id,
            userId: id,
            firstName: firstName,
            lastName: lastName,
            avatar: user?.avatar,
            notificationId: newFriendRequestNotification.id,
            content: newFriendRequestNotification.content,
            createdAt: newFriendRequestNotification.createdAt,
        });

        return res.status(httpStatusCode.CREATED).json({
            friendRequestId: friendRequest.id,
        });
    }

    // [GET] /relationships/friend-requests
    async getFriendRequests(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;

        const friendRequests = await relationshipService.getFriendRequests({ receiverId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json(friendRequests);
    }

    // [GET] /relationships/friend-requests/count
    async getFriendRequestCount(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;

        const friendRequestCount = await relationshipService.getFriendRequestCount(id);

        return res.status(httpStatusCode.OK).json(friendRequestCount);
    }

    // [GET] /relationships/sent-requests
    async getSentFriendRequests(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { page } = req.query;

        const sentRequests = await relationshipService.getSentFriendRequests({ senderId: id, page: Number(page) });

        return res.status(httpStatusCode.OK).json(sentRequests);
    }

    // [POST] /relationships/friend-requests/:friendRequestId/acceptance
    async acceptFriendRequest(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { friendRequestId } = req.params;
        const { senderId } = req.body;

        const friendRequest = await relationshipService.getFriendRequestById(friendRequestId);

        if (!friendRequest) {
            const sender = await userService.findUserById(senderId);
            return res.status(relationshipResponse.FRIEND_REQUEST_NOT_FOUND.status).json({
                message: relationshipResponse.FRIEND_REQUEST_NOT_FOUND.message.replace(
                    '{name}',
                    `${sender?.lastName} ${sender?.firstName}`,
                ),
            });
        }

        const newRelationship = await relationshipService.addFriend({
            userId: id,
            senderId,
            friendRequestId,
        });

        return res.status(httpStatusCode.CREATED).json({
            relationshipId: newRelationship.id,
        });
    }

    // [DELETE] /relationships/friend-requests/:friendRequestId
    async deleteFriendRequest(req: Request, res: Response): Promise<any> {
        const { friendRequestId } = req.params;

        const friendRequest = await relationshipService.getFriendRequestById(friendRequestId);

        if (!friendRequest) {
            return res.status(relationshipResponse.ALREADY_FRIENDS.status).json({
                message: relationshipResponse.ALREADY_FRIENDS.message,
            });
        }

        await relationshipService.deleteFriendRequest(friendRequestId);

        return res.status(httpStatusCode.NO_CONTENT).json();
    }

    // [DELETE] /relationships/friend-requests/:userId/user
    async deleteFriendRequestByUserId(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { userId } = req.params;

        const friendRequest = await relationshipService.getFriendRequestByUserId({ userId: id, receiverId: userId });

        if (!friendRequest) {
            return res.status(relationshipResponse.ALREADY_FRIENDS.status).json({
                message: relationshipResponse.ALREADY_FRIENDS.message,
            });
        }

        await relationshipService.deleteFriendRequest(friendRequest.id);

        return res.status(httpStatusCode.NO_CONTENT).json();
    }

    // [GET] /relationships/friends
    async getFriends(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { userId } = req.query as Record<string, string>;

        const friends = await relationshipService.getFriends(userId || id);

        return res.status(httpStatusCode.OK).json(friends);
    }

    // [DELETE] /relationships/:friendId
    async unfriend(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { friendId } = req.params;

        await relationshipService.unfriend({ userId: id, friendId });

        return res.status(httpStatusCode.NO_CONTENT).json();
    }
}

export const relationshipController = new RelationshipController();
