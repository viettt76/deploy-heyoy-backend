import { AppDataSource } from '@/data-source';
import { FavoriteMovie, MovieType, MovieSource } from '@/entity/FavoriteMovie';

const favoriteMovieRepository = AppDataSource.getRepository(FavoriteMovie);

class MovieService {
    async createFavoriteMovie(favoriteMovieData: {
        userId: string;
        movieId: string;
        name: string;
        slug: string;
        thumbUrl: string;
        type: MovieType;
        source: MovieSource;
    }): Promise<void> {
        const { userId, movieId, name, slug, thumbUrl, type, source } = favoriteMovieData;
        await favoriteMovieRepository.insert({
            userId,
            movieId,
            name,
            slug,
            thumbUrl,
            type,
            source,
        });
    }

    async removeFavoriteMovie({ movieId, source }: { movieId: string; source: MovieSource }): Promise<void> {
        await favoriteMovieRepository.delete({
            movieId,
            source,
        });
    }

    async getFavoriteMovies(userId: string): Promise<FavoriteMovie[]> {
        return favoriteMovieRepository.find({
            where: {
                userId,
            },
            select: {
                movieId: true,
                name: true,
                slug: true,
                thumbUrl: true,
                type: true,
                source: true,
            },
            order: { createdAt: 'ASC' },
        });
    }

    async getFavoriteMovieById({
        userId,
        movieId,
        source,
    }: {
        userId: string;
        movieId: string;
        source: MovieSource;
    }): Promise<FavoriteMovie | null> {
        return favoriteMovieRepository.findOneBy({
            userId,
            movieId,
            source,
        });
    }
}

export const movieService = new MovieService();
