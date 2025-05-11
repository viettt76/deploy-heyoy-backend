import { Entity, Column, ManyToOne, JoinColumn, Unique } from 'typeorm';
import { Base } from './Base';
import { Conversation } from './Conversation';
import { User } from './User';

export enum ConversationRole {
    MEMBER = 'MEMBER',
    ADMIN = 'ADMIN',
}

@Entity({ name: 'conversation_participants' })
@Unique(['userId', 'conversationId'])
export class ConversationParticipant extends Base {
    @Column({ type: 'uuid' })
    userId!: string;

    @Column({ type: 'uuid' })
    conversationId!: string;

    @Column({ nullable: true })
    nickname?: string;

    @Column({ type: 'enum', enum: ConversationRole, default: null })
    role?: ConversationRole;

    @ManyToOne(() => Conversation, (conversation) => conversation.conversationParticipants)
    @JoinColumn({ name: 'conversationId', referencedColumnName: 'id' })
    conversation: Conversation;

    @ManyToOne(() => User, (user) => user.conversationParticipant)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;
}
