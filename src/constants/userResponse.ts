import { httpStatusCode } from './httpStatusCode';

const userResponse = {
    USER_NOT_FOUND: {
        status: httpStatusCode.BAD_REQUEST,
        message: 'The user does not exist',
    },
};

export default userResponse;
