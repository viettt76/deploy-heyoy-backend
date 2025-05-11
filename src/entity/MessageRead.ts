import { Entity, Column, ManyToOne, JoinColumn, Unique } from 'typeorm';
import { Base } from './Base';
import { Message } from './Message';
import { User } from './User';

@Entity('message_reads')
@Unique(['messageId', 'userId'])
export class MessageRead extends Base {
    @Column({ type: 'uuid' })
    messageId!: string;

    @Column({ type: 'uuid' })
    userId!: string;

    @Column({ default: true })
    isRead: boolean;

    @ManyToOne(() => Message, (message) => message.reads)
    @JoinColumn({ name: 'messageId', referencedColumnName: 'id' })
    message: Message;

    @ManyToOne(() => User, (user) => user.messageReads)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;
}
