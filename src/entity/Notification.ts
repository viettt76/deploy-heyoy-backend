import { Entity, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { Base } from './Base';
import { User } from './User';

export enum NotificationType {
    LIKE_POST = 'LIKE_POST',
    LIKE_COMMENT = 'LIKE_COMMENT',
    COMMENT = 'COMMENT',
    FRIEND_REQUEST = 'FRIEND_REQUEST',
}

@Entity({ name: 'notifications' })
@Index(['userId', 'isRead'])
export class Notification extends Base {
    @Column({ type: 'uuid' })
    @Index()
    userId!: string;

    @Column({ type: 'uuid' })
    actorId!: string;

    @Column({ type: 'enum', enum: NotificationType })
    type!: NotificationType;

    @Column({ type: 'uuid' })
    referenceId!: string;

    @Column()
    content: string;

    @Column({ default: false })
    isRead!: boolean;

    @Column({ default: false })
    isOpenMenu!: boolean;

    @ManyToOne(() => User, (user) => user.notifications)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;

    @ManyToOne(() => User, (user) => user.notifications)
    @JoinColumn({ name: 'actorId', referencedColumnName: 'id' })
    actor: User;
}
