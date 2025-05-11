import { Request, Response } from 'express';
import { httpStatusCode } from '@/constants/httpStatusCode';
import { CustomJwtPayload } from '@/custom';
import { movieService } from '@/services/movieService';

class MovieController {
    // [POST] /movies/favorites
    async addFavoriteMovie(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { movieId, name, slug, thumbUrl, type, source } = req.body;

        const favoriteMovie = await movieService.getFavoriteMovieById({ userId: id, movieId, source });
        if (favoriteMovie) {
            return res.status(httpStatusCode.BAD_REQUEST).json();
        }

        await movieService.createFavoriteMovie({
            userId: id,
            movieId,
            name,
            slug,
            thumbUrl,
            type,
            source,
        });

        return res.status(httpStatusCode.CREATED).json();
    }

    // [DELETE] /movies/favorites/:movieId
    async removeFavoriteMovie(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;
        const { movieId } = req.params;
        const { source } = req.query;

        const favoriteMovie = await movieService.getFavoriteMovieById({
            userId: id,
            movieId,
            source: Number(source),
        });

        if (!favoriteMovie) {
            return res.status(httpStatusCode.NOT_FOUND).json();
        }

        await movieService.removeFavoriteMovie({
            movieId,
            source: Number(source),
        });

        return res.status(httpStatusCode.NO_CONTENT).json();
    }

    // [GET] /movies/favorites
    async getFavoriteMovies(req: Request, res: Response): Promise<any> {
        const { id } = req.userToken as CustomJwtPayload;

        const favoriteMovies = await movieService.getFavoriteMovies(id);

        return res.status(httpStatusCode.OK).json(favoriteMovies);
    }
}

export const movieController = new MovieController();
