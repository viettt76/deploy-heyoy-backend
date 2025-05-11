import { Entity, Column, Unique, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Base } from './Base';
import { User } from './User';
import { Post } from './Post';

export enum PostReactionType {
    LIKE = 'LIKE',
    LOVE = 'LOVE',
    LOVE_LOVE = 'LOVE_LOVE',
    HAHA = 'HAHA',
    WOW = 'WOW',
    SAD = 'SAD',
    ANGRY = 'ANGRY',
}

@Entity('post_reactions')
@Unique(['postId', 'userId'])
export class PostReaction extends Base {
    @Column({ type: 'uuid' })
    @Index()
    postId!: string;

    @Column({ type: 'uuid' })
    userId!: string;

    @Column({ type: 'enum', enum: PostReactionType, nullable: true })
    reactionType: PostReactionType | null;

    @ManyToOne(() => User, (user) => user.postReactions)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;

    @ManyToOne(() => Post, (post) => post.reactions)
    @JoinColumn({ name: 'post', referencedColumnName: 'id' })
    post: Post;
}
