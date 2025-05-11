class ApiError extends Error {
    public statusCode: number;

    constructor(statusCode: number, message: string) {
        super(message);

        this.name = 'ApiError';
        this.statusCode = statusCode;

        Error.captureStackTrace(this, this.constructor);
    }
}

export default ApiError;
