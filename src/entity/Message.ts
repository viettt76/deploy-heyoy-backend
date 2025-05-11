import { Entity, Column, Index, ManyToOne, JoinColumn, OneToMany } from 'typeorm';
import { Base } from './Base';
import { User } from './User';
import { MessageReaction } from './MessageReaction';
import { MessageRead } from './MessageRead';
import { Conversation } from './Conversation';

export enum MessageType {
    TEXT = 'TEXT',
    IMAGE = 'IMAGE',
    FILE = 'FILE',
    VIDEO = 'VIDEO',
    NOTIFICATION = 'NOTIFICATION',
}

@Entity({ name: 'messages' })
export class Message extends Base {
    @Column({ type: 'uuid' })
    senderId!: string;

    @Column({ type: 'uuid' })
    @Index()
    conversationId!: string;

    @Column({ type: 'text', nullable: true })
    content?: string;

    @Column({ type: 'text', nullable: true })
    fileName?: string;

    @Column({
        type: 'enum',
        enum: MessageType,
        default: MessageType.TEXT,
    })
    messageType: MessageType;

    @OneToMany(() => MessageRead, (messageRead) => messageRead.message)
    reads: MessageRead[];

    @ManyToOne(() => User, (user) => user.message)
    @JoinColumn({ name: 'senderId', referencedColumnName: 'id' })
    sender: User;

    @ManyToOne(() => Conversation, (conversation) => conversation.messages)
    @JoinColumn({ name: 'conversationId', referencedColumnName: 'id' })
    conversation: Conversation;

    @OneToMany(() => MessageReaction, (messageReaction) => messageReaction.message)
    reactions: MessageReaction[];
}
