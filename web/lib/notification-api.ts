import apiClient from './api-client';
import type {
  Notification,
  NotificationsResponse,
  UnreadCountResponse,
} from "@/types/notification";

export const notificationApi = {
  // Get notifications with pagination
  getNotifications: async (params?: {
    page?: number;
    limit?: number;
    unreadOnly?: boolean;
    role?: string;
  }): Promise<NotificationsResponse> => {
    const response = await apiClient.get("/notifications", { params });
    return response.data;
  },

  // Get unread count
  getUnreadCount: async (params?: { role?: string }): Promise<UnreadCountResponse> => {
    const response = await apiClient.get("/notifications/unread-count", { params });
    return response.data;
  },

  // Mark notification as read
  markAsRead: async (notificationId: string): Promise<Notification> => {
    const response = await apiClient.patch(
      `/notifications/${notificationId}/read`
    );
    return response.data;
  },

  // Mark all notifications as read
  markAllAsRead: async (): Promise<{ success: boolean; modifiedCount: number }> => {
    const response = await apiClient.patch("/notifications/read-all");
    return response.data;
  },

  // Delete notification
  deleteNotification: async (
    notificationId: string
  ): Promise<{ success: boolean }> => {
    const response = await apiClient.delete(`/notifications/${notificationId}`);
    return response.data;
  },

  // Delete all notifications
  deleteAllNotifications: async (): Promise<{
    success: boolean;
    deletedCount: number;
  }> => {
    const response = await apiClient.delete("/notifications");
    return response.data;
  },
};
