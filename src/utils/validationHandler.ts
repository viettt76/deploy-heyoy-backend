import { NextFunction, Response } from 'express';
import { ObjectSchema } from 'joi';

const validationHandler = async (schema: ObjectSchema, data: any, res: Response, next: NextFunction) => {
    try {
        await schema.validateAsync(data, { abortEarly: false });
        next();
    } catch (error: unknown) {
        if (error instanceof Error) {
            res.status(422).json({
                message: error.message,
            });
        } else {
            res.status(422).json({
                message: 'Validation error occurred',
            });
        }
    }
};

export default validationHandler;
