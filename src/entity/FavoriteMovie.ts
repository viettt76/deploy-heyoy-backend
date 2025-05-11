import { Entity, Column, Index, Unique, ManyToOne, JoinColumn } from 'typeorm';
import { Base } from './Base';
import { User } from './User';

export enum MovieType {
    MOVIE = 'MOVIE',
    TV = 'TV',
}

export enum MovieSource {
    OPHIM = 1,
    KKPHIM = 2,
}

@Entity({ name: 'favorite_movies' })
@Unique(['userId', 'movieId', 'source'])
export class FavoriteMovie extends Base {
    @Column({ type: 'uuid' })
    @Index()
    userId!: string;

    @Column()
    movieId!: string;

    @Column()
    name!: string;

    @Column()
    slug!: string;

    @Column()
    thumbUrl!: string;

    @Column({ type: 'enum', enum: MovieType })
    type!: MovieType;

    @Column({ type: 'enum', enum: MovieSource })
    source!: MovieSource;

    @ManyToOne(() => User, (user) => user.favoriteMovies)
    @JoinColumn({ name: 'userId', referencedColumnName: 'id' })
    user: User;
}
