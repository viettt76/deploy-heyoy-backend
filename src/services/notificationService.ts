import { AppDataSource } from '@/data-source';
import { Notification, NotificationType } from '@/entity/Notification';

const notificationRepository = AppDataSource.getRepository(Notification);

class NotificationService {
    async createNotification(notificationInfo: {
        userId: string;
        actorId: string;
        type: NotificationType;
        referenceId: string;
        content: string;
    }): Promise<Notification> {
        const { userId, actorId, type, referenceId, content } = notificationInfo;
        return await notificationRepository.save({
            userId,
            actorId,
            type,
            referenceId,
            content,
        });
    }

    async getNotifications(userId: string): Promise<Notification[]> {
        return await notificationRepository
            .createQueryBuilder('notification')
            .leftJoinAndSelect('notification.actor', 'actor')
            .select([
                'notification.id as notificationId',
                'notification.referenceId as referenceId',
                'notification.content as content',
                'notification.type as type',
                'notification.isRead as isRead',
                'notification.isOpenMenu as isOpenMenu',
                'notification.createdAt as createdAt',
                'actor.id as actorId',
                'actor.firstName as actorFirstName',
                'actor.lastName as actorLastName',
                'actor.avatar as actorAvatar',
            ])
            .where('notification.userId = :userId', { userId })
            .orderBy('notification.createdAt', 'DESC')
            .getRawMany();
    }
}

export const notificationService = new NotificationService();
