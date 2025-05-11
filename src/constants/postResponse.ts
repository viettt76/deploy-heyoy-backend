import { httpStatusCode } from './httpStatusCode';

export const postResponse = {
    POST_NOT_FOUND: {
        status: httpStatusCode.BAD_REQUEST,
        message: 'Post not found',
    },
    BOOKMARK_POST_NOT_FOUND: {
        status: httpStatusCode.BAD_REQUEST,
        message: 'Bookmark post not found',
    },
};
