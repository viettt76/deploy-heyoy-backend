import { Entity, Column, ManyToOne, JoinColumn, OneToMany, Index } from 'typeorm';
import { Base } from './Base';
import { User } from './User';
import { Comment } from './Comment';
import { PostReaction } from './PostReaction';
import { ImageOfPost } from './ImageOfPost';
import { BookmarkPost } from './BookmarkPost';

export enum PostVisibility {
    FRIEND = 'FRIEND',
    PUBLIC = 'PUBLIC',
    PRIVATE = 'PRIVATE',
}

export enum PostStatus {
    PENDING = 'PENDING',
    APPROVED = 'APPROVED',
    INVALID = 'INVALID',
}

@Entity({ name: 'posts' })
export class Post extends Base {
    @Column({ type: 'uuid' })
    @Index()
    posterId!: string;

    @Column({ type: 'enum', enum: PostVisibility, default: PostVisibility.FRIEND })
    visibilityType!: PostVisibility;

    @Column({ type: 'text', nullable: true })
    content?: string;

    @Column({ type: 'enum', enum: PostStatus, default: PostStatus.PENDING })
    @Index()
    status!: PostStatus;

    @ManyToOne(() => User, (user) => user.posts)
    @JoinColumn({ name: 'posterId', referencedColumnName: 'id' })
    poster: User;

    @OneToMany(() => Comment, (comment) => comment.post)
    comments: Comment[];

    @OneToMany(() => PostReaction, (reactionPost) => reactionPost.post)
    reactions: PostReaction[];

    @OneToMany(() => ImageOfPost, (imageOfPost) => imageOfPost.post)
    images: ImageOfPost[];

    @OneToMany(() => BookmarkPost, (bookmarkPost) => bookmarkPost.post)
    bookmarks: BookmarkPost[];
}
