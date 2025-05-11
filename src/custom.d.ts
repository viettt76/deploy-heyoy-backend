import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { Server } from 'socket.io';

export interface CustomJwtPayload extends JwtPayload {
    id: string;
    firstName: string;
    lastName: string;
    role: string;
}

export interface IoRequest extends Request {
    io: Server;
}

declare global {
    namespace Express {
        interface Request {
            userToken?: JwtPayload | CustomJwtPayload;
        }
    }
}
