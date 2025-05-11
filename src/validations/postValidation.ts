import { NextFunction, Request, Response } from 'express';
import Joi from 'joi';
import validationHandler from '@/utils/validationHandler';
import { PostReactionType } from '@/entity/PostReaction';

class PostValidation {
    createPost(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            content: Joi.string().allow('').trim(),
            images: Joi.array()
                .items(
                    Joi.string().uri().messages({
                        'string.uri': 'Each image must be a valid URL.',
                    }),
                )
                .when('content', {
                    is: '',
                    then: Joi.array().min(1).required().messages({
                        'array.min': 'At least one image is required if content is empty.',
                        'any.required': 'Images are required when content is empty.',
                    }),
                    otherwise: Joi.array().optional(),
                }),
        });

        validationHandler(correctValidation, req.body, res, next);
    }

    getPosts(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    getPostsByUserId(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            userId: Joi.string().uuid().required(),
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    reactToPost(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            postId: Joi.string().uuid().required(),
            posterId: Joi.string().uuid().required(),
            reactionType: Joi.string()
                .valid(...Object.values(PostReactionType))
                .allow(null),
        });

        validationHandler(correctValidation, { ...req.params, ...req.body }, res, next);
    }

    sendComment(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            postId: Joi.string().uuid().required(),
            parentCommentId: Joi.string().uuid().optional(),
            content: Joi.string().allow('').trim(),
            image: Joi.string()
                .uri()
                .messages({
                    'string.uri': 'Each image must be a valid URL.',
                })
                .when('content', {
                    is: '',
                    then: Joi.required().messages({
                        'any.required': 'Image are required when content is empty.',
                    }),
                    otherwise: Joi.optional(),
                }),
        });

        validationHandler(correctValidation, req.body, res, next);
    }

    getComments(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            postId: Joi.string().uuid().required(),
            page: Joi.number().min(1),
            sortField: Joi.string().required(),
            sortType: Joi.string().valid('DESC', 'ASC'),
        });

        validationHandler(correctValidation, { ...req.params, ...req.query }, res, next);
    }

    getCommentReplies(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            commentId: Joi.string().uuid().required(),
            page: Joi.number().min(1),
            sortField: Joi.string().required(),
            sortType: Joi.string().valid('DESC', 'ASC'),
        });

        validationHandler(correctValidation, { ...req.params, ...req.query }, res, next);
    }

    reactToComment(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            commentId: Joi.string().uuid().required(),
            postId: Joi.string().uuid().required(),
            reactionType: Joi.string()
                .valid(...Object.values(PostReactionType))
                .allow(null),
        });

        validationHandler(correctValidation, { ...req.params, ...req.body }, res, next);
    }

    bookmark(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            postId: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.body, res, next);
    }

    unbookmark(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            id: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    deletePost(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            id: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    getDeletedPosts(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }

    recoverPost(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            id: Joi.string().uuid().required(),
        });

        validationHandler(correctValidation, req.params, res, next);
    }

    getBookmarkPosts(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            page: Joi.number().min(1),
        });

        validationHandler(correctValidation, req.query, res, next);
    }
}

export const postValidation = new PostValidation();
