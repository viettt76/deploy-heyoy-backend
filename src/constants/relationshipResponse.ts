import { httpStatusCode } from './httpStatusCode';

const relationshipResponse = {
    FRIEND_REQUEST_EXISTS: {
        status: httpStatusCode.BAD_REQUEST,
        message: 'There has been an invitation to make this friend',
    },
    FRIEND_REQUEST_NOT_FOUND: {
        status: httpStatusCode.NOT_FOUND,
        message: 'The friend request from {name} no longer exists',
    },
    ALREADY_FRIENDS: {
        status: httpStatusCode.NOT_FOUND,
        message: 'You are already friends',
    },
};

export default relationshipResponse;
