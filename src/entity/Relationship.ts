import { Entity, Column, Index, Unique, ManyToOne, JoinColumn, BeforeInsert } from 'typeorm';
import { Base } from './Base';
import { User } from './User';

export enum RelationshipType {
    FRIEND = 'FRIEND',
    LOVE = 'LOVE',
    SIBLING = 'SIBLING',
    BEST_FRIEND = 'BEST_FRIEND',
}

@Entity({ name: 'relationships' })
@Unique(['user1Id', 'user2Id'])
export class Relationship extends Base {
    @Column({ type: 'uuid' })
    @Index()
    user1Id!: string;

    @Column({ type: 'uuid' })
    @Index()
    user2Id!: string;

    @Column({ type: 'enum', enum: RelationshipType, default: RelationshipType.FRIEND })
    relationshipType!: RelationshipType;

    @ManyToOne(() => User, (user) => user.relationshipAsUser1)
    @JoinColumn({ name: 'user1Id', referencedColumnName: 'id' })
    user1: User;

    @ManyToOne(() => User, (user) => user.relationshipAsUser2)
    @JoinColumn({ name: 'user2Id', referencedColumnName: 'id' })
    user2: User;

    @BeforeInsert()
    sortUserIds() {
        if (this.user1 > this.user2) {
            [this.user1, this.user2] = [this.user2, this.user1];
        }
    }
}
