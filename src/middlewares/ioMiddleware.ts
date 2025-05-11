import { IoRequest } from '@/custom';
import { NextFunction, Request, Response } from 'express';
import { Server } from 'socket.io';

const ioMiddleware = (io: Server) => (req: Request, res: Response, next: NextFunction) => {
    (req as IoRequest).io = io;
    next();
};

export default ioMiddleware;
