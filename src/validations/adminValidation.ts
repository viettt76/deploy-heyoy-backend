import { NextFunction, Request, Response } from 'express';
import Joi from 'joi';
import validationHandler from '@/utils/validationHandler';
import { Role } from '@/entity/User';

class AdminValidation {
    getPostsNotCensored(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    getRejectedPosts(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    approvePost(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            id: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    rejectPost(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            id: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    getUsers(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    lockUser(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            userId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    unlockUser(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            userId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    createUser(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            firstName: Joi.string().max(30).required().trim().strict(),
            lastName: Joi.string().max(30).required().trim().strict(),
            username: Joi.string().min(6).max(30).required().trim().strict(),
            password: Joi.string()
                .min(8)
                .max(32)
                .regex(/\w/)
                .regex(/[@$!%*?&]/)
                .required()
                .trim()
                .strict(),
            role: Joi.string().valid(...Object.values(Role)),
        });

        validationHandler(correctValidation, req.body, res, next);
    }
}

export const adminValidation = new AdminValidation();
