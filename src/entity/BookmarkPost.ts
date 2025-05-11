import { Entity, Column, Index, ManyToOne, JoinColumn, PrimaryColumn } from 'typeorm';
import { Base } from './Base';
import { Post } from './Post';
import { User } from './User';

@Entity({ name: 'bookmark_posts' })
export class BookmarkPost extends Base {
    @PrimaryColumn({ type: 'uuid' })
    postId!: string;

    @PrimaryColumn({ type: 'uuid' })
    @Index()
    userId!: string;

    @ManyToOne(() => Post, (Post) => Post.bookmarks, {
        onDelete: 'CASCADE',
    })
    @JoinColumn({ name: 'postId', referencedColumnName: 'id' })
    post: Post;

    @ManyToOne(() => User, (user) => user.bookmarks)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;
}
