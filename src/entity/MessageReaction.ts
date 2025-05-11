import { Entity, Column, Unique, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Base } from './Base';
import { User } from './User';
import { Message } from './Message';

export enum MessageReactionType {
    LIKE = 'LIKE',
    LOVE = 'LOVE',
    LOVE_LOVE = 'LOVE_LOVE',
    HAHA = 'HAHA',
    WOW = 'WOW',
    SAD = 'SAD',
    ANGRY = 'ANGRY',
}

@Entity({ name: 'message_reactions' })
@Unique(['messageId', 'userId'])
export class MessageReaction extends Base {
    @Column({ type: 'uuid' })
    @Index()
    messageId!: string;

    @Column({ type: 'uuid' })
    userId!: string;

    @Column({ type: 'enum', enum: MessageReactionType })
    reactionType!: MessageReactionType;

    @ManyToOne(() => User, (user) => user.messageReactions)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;

    @ManyToOne(() => Message, (message) => message.reactions)
    @JoinColumn({ name: 'messageId', referencedColumnName: 'id' })
    message: Message;
}
