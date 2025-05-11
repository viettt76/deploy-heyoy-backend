import bcrypt from 'bcrypt';
import { AppDataSource } from '../data-source';
import { User, Role } from '../entity/User';
import { Relationship } from '../entity/Relationship';
import { Post } from '../entity/Post';
import { ImageOfPost } from '../entity/ImageOfPost';
import users from './users.json';
import posts from './posts.json';

async function seed() {
    await AppDataSource.initialize();

    const hashPassword = bcrypt.hashSync('Abcd123!', 10);

    const userRepository = AppDataSource.getRepository(User);
    const relationshipRepository = AppDataSource.getRepository(Relationship);
    const postRepository = AppDataSource.getRepository(Post);
    const imageOfPostRepository = AppDataSource.getRepository(ImageOfPost);

    const userIds = [];
    for (const user of users) {
        const existingUser = await userRepository.findOne({
            where: { username: user.username },
        });
        if (!existingUser) {
            const newUser = await userRepository.save({
                firstName: user.firstName,
                lastName: user.lastName,
                username: user.username,
                password: hashPassword,
                role: user.role ? (user.role as Role) : Role.USER,
            });

            if (user.role !== Role.ADMIN) userIds.push(newUser.id);
        }
    }

    for (const user1Id of userIds) {
        for (const user2Id of userIds) {
            const existingRelationship = await relationshipRepository.findOne({
                where: [
                    { user1Id, user2Id },
                    { user1Id: user2Id, user2Id: user1Id },
                ],
            });
            if (!existingRelationship && user1Id !== user2Id) {
                await relationshipRepository.insert({
                    user1Id,
                    user2Id,
                });
            }
        }
    }

    for (const post of posts) {
        const newPost = await postRepository.save({
            posterId: userIds[0],
            content: post.content,
        });

        if (post.images.length > 0) {
            await Promise.all(
                post.images.map(async (image) => {
                    await imageOfPostRepository.insert({
                        postId: newPost.id,
                        imageUrl: image,
                    });
                }),
            );
        }
    }

    await AppDataSource.destroy();
}

seed()
    .then(() => {
        console.log('Seed completed!');
    })
    .catch((error) => {
        console.error('Error seeding data:', error);
    });
