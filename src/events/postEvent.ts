import { Socket } from 'socket.io';

const postEvent = (socket: Socket) => {
    socket.on('joinPost', (postId: string) => {
        socket.join(`post-${postId}`);
    });

    socket.on('leavePost', (postId: string) => {
        socket.leave(`post-${postId}`);
    });
};

export default postEvent;
