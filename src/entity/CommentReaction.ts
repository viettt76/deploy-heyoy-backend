import { Entity, Column, Unique, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Base } from './Base';
import { User } from './User';
import { Comment } from './Comment';

export enum CommentReactionType {
    LIKE = 'LIKE',
    LOVE = 'LOVE',
    LOVE_LOVE = 'LOVE_LOVE',
    HAHA = 'HAHA',
    WOW = 'WOW',
    SAD = 'SAD',
    ANGRY = 'ANGRY',
}

@Entity('comment_reactions')
@Unique(['commentId', 'userId'])
export class CommentReaction extends Base {
    @Column({ type: 'uuid' })
    @Index()
    commentId!: string;

    @Column({ type: 'uuid' })
    userId!: string;

    @Column({ type: 'enum', enum: CommentReactionType })
    reactionType!: CommentReactionType | null;

    @ManyToOne(() => User, (user) => user.commentReactions)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;

    @ManyToOne(() => Comment, (comment) => comment.reactions)
    @JoinColumn({ name: 'commentId', referencedColumnName: 'id' })
    comment: Comment;
}
