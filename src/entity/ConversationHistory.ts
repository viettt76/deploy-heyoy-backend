import { Entity, Column, ManyToOne, OneToOne, JoinColumn, Unique } from 'typeorm';
import { Conversation } from './Conversation';
import { User } from './User';
import { Message } from './Message';
import { Base } from './Base';

@Entity('conversation_histories')
@Unique(['userId', 'conversationId', 'lastMessageId'])
export class ConversationHistory extends Base {
    @Column({ type: 'uuid' })
    userId!: string;

    @Column({ type: 'uuid' })
    conversationId!: string;

    @Column({ type: 'uuid' })
    lastMessageId!: string;

    @OneToOne(() => Conversation, (conversation) => conversation.id)
    @JoinColumn({ name: 'conversationId', referencedColumnName: 'id' })
    conversation: Conversation;

    @ManyToOne(() => User, (user) => user.id)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;

    @OneToOne(() => Message, (message) => message.id)
    @JoinColumn({ name: 'lastMessageId', referencedColumnName: 'id' })
    lastMessage: Message;
}
