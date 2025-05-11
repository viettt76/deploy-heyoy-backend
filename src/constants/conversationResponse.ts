import { httpStatusCode } from './httpStatusCode';

const conversationResponse = {
    CONVERSATION_NOT_FOUND: {
        status: httpStatusCode.BAD_REQUEST,
        message: 'Conversation not found',
    },
    READ_MESSAGE_NOT_FOUND: {
        status: httpStatusCode.BAD_REQUEST,
        message: 'Message not found',
    },
};

export default conversationResponse;
