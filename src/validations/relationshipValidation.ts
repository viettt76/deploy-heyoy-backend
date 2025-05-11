import { NextFunction, Request, Response } from 'express';
import Joi from 'joi';
import validationHandler from '@/utils/validationHandler';

class RelationshipValidation {
    getSuggestions(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    sendFriendRequest(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            receiverId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.body, res, next);
    }

    getFriendRequests(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    getSentFriendRequests(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    acceptFriendRequest(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            friendRequestId: Joi.string().uuid().required(),
            senderId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, { ...req.params, ...req.body }, res, next);
    }

    deleteFriendRequest(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            friendRequestId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    deleteFriendRequestByUserId(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            userId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    getFriends(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            userId: Joi.string().uuid().allow(null),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    unfriend(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            friendId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }
}

export const relationshipValidation = new RelationshipValidation();
