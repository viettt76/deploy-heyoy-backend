import 'tsconfig-paths/register';
import dotenv from 'dotenv';
import express, { NextFunction, Request, RequestHandler, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { Server } from 'socket.io';
import http from 'http';
import 'express-async-errors';
import routes from '@/routes';
import { AppDataSource } from '@/data-source';
import { errorHandler } from '@/utils/errorHandler';
import authMiddleware from '@/middlewares/authMiddleware';
import events from '@/events';
import { getRedisClient } from '@/lib/redisClient';

dotenv.config();

AppDataSource.initialize()
    .then(async () => {
        const port = process.env.PORT || 8080;
        const app = express();

        app.use(express.json());
        app.use(
            cors({
                origin: process.env.FRONTEND_URL,
                credentials: true,
            }),
        );
        app.use(cookieParser());

        const server = http.createServer(app);
        const io = new Server(server, {
            cors: {
                origin: process.env.FRONTEND_URL,
                credentials: true,
            },
        });

        getRedisClient();

        const wrapAsync =
            (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>): RequestHandler =>
            (req, res, next) => {
                fn(req, res, next).catch(next);
            };

        app.use(wrapAsync(authMiddleware));

        events(io);
        routes(app, io);

        app.use(errorHandler);

        server.listen(port, () => {
            console.log('Server running on port ' + port);
        });
    })
    .catch((error) => console.log(error));
