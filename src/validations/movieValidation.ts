import { NextFunction, Request, Response } from 'express';
import Joi from 'joi';
import validationHandler from '@/utils/validationHandler';
import { MovieType, MovieSource } from '@/entity/FavoriteMovie';

class MovieValidation {
    addFavoriteMovie(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            movieId: Joi.string().required().trim().strict(),
            name: Joi.string().required().trim().strict(),
            slug: Joi.string().required().trim().strict(),
            thumbUrl: Joi.string().required(),
            type: Joi.string().valid(...Object.values(MovieType)),
            source: Joi.number().valid(...Object.values(MovieSource)),
        });

        validationHandler(correctValidation, req.body, res, next);
    }

    removeFavoriteMovie(req: Request, res: Response, next: NextFunction) {
        const correctValidation = Joi.object({
            movieId: Joi.string().required().trim().strict(),
            source: Joi.number().valid(...Object.values(MovieSource)),
        });

        validationHandler(correctValidation, { ...req.params, ...req.query }, res, next);
    }
}

export const movieValidation = new MovieValidation();
