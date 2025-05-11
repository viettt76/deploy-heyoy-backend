import { createClient, RedisClientType } from 'redis';

let client: RedisClientType | null = null;

const getRedisClient = (): RedisClientType => {
    if (!client) {
        client = createClient({
            url: process.env.REDIS_URL,
        });

        client.on('connect', async () => {
            console.log('Redis client connected successfully');
        });

        client.on('error', (err) => {
            console.error('Redis client connection error:', err);
        });
        client.connect().catch((error) => console.error('Redis client connection failed', error));
    }

    return client;
};

export { getRedisClient };
