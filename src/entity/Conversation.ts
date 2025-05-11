import { Entity, Column, OneToMany, OneToOne, Index } from 'typeorm';
import { Base } from './Base';
import { ConversationParticipant } from './ConversationParticipant';
import { Message } from './Message';
import { ConversationHistory } from './ConversationHistory';

export enum ConversationType {
    PRIVATE = 'PRIVATE',
    GROUP = 'GROUP',
}

@Entity({ name: 'conversations' })
export class Conversation extends Base {
    @Column({ type: 'enum', enum: ConversationType })
    type!: ConversationType;

    @Column({ nullable: true })
    @Index()
    name?: string;

    @Column({ nullable: true })
    avatar?: string;

    @OneToMany(() => ConversationParticipant, (conversationParticipant) => conversationParticipant.conversationId)
    conversationParticipants: ConversationParticipant[];

    @OneToMany(() => Message, (message) => message.conversationId)
    messages: Message[];

    @OneToOne(() => ConversationHistory, (history) => history.conversation)
    history: ConversationHistory;
}
