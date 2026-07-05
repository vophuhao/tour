/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { vi } from "date-fns/locale";
import {
  Bell,
  Check,
  CheckCheck,
  Trash2,
  ShoppingCart,
  UserPlus,
  Package,
  AlertCircle,
} from "lucide-react";
import {
  useNotifications,
  useMarkAsRead,
  useMarkAllAsRead,
  useDeleteNotification,
  useDeleteAllNotifications,
} from "@/hooks/useNotification";
import type { Notification, NotificationType } from "@/types/notification";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import Link from "next/link";

// Icon mapping for admin notification types (Đơn hàng và Yêu cầu đăng ký Host)
const adminNotificationIcons: Record<string, any> = {
  order_confirmed: ShoppingCart,
  order_shipping: ShoppingCart,
  order_delivered: ShoppingCart,
  order_cancelled: ShoppingCart,
  order_return_request: Package,
  system: UserPlus, // For host registration requests
};

// Color mapping for priority
const priorityColors = {
  low: "bg-gray-100 text-gray-700 border-gray-200",
  medium: "bg-blue-50 text-blue-700 border-blue-200",
  high: "bg-red-50 text-red-700 border-red-200",
};

interface NotificationItemProps {
  notification: Notification;
  onMarkAsRead: (id: string) => void;
  onDelete: (id: string) => void;
}

function NotificationItem({
  notification,
  onMarkAsRead,
  onDelete,
}: NotificationItemProps) {
  const Icon = adminNotificationIcons[notification.type] || Bell;
  const timeAgo = formatDistanceToNow(new Date(notification.createdAt), {
    addSuffix: true,
    locale: vi,
  });

  const content = (
    <div
      className={cn(
        "flex gap-3 p-4 border rounded-lg transition-all hover:shadow-md",
        notification.isRead
          ? "bg-white border-gray-200"
          : "bg-blue-50/50 border-blue-200"
      )}
    >
      {/* Icon */}
      <div
        className={cn(
          "flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center",
          priorityColors[notification.priority]
        )}
      >
        <Icon className="w-5 h-5" />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1">
            <p className="font-medium text-sm text-gray-900">
              {notification.title}
            </p>
            <p className="text-sm text-gray-600 mt-0.5">
              {notification.message}
            </p>
            <p className="text-xs text-gray-400 mt-1">{timeAgo}</p>
          </div>

          {/* Priority badge */}
          {notification.priority === "high" && (
            <Badge variant="destructive" className="text-xs">
              Quan trọng
            </Badge>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-col gap-1">
        {!notification.isRead && (
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={(e) => {
              e.preventDefault();
              onMarkAsRead(notification._id);
            }}
            title="Đánh dấu đã đọc"
          >
            <Check className="h-4 w-4" />
          </Button>
        )}
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-red-500 hover:text-red-600"
          onClick={(e) => {
            e.preventDefault();
            onDelete(notification._id);
          }}
          title="Xóa"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );

  if (notification.link) {
    return (
      <Link href={notification.link} className="block">
        {content}
      </Link>
    );
  }

  return content;
}

export function AdminNotifications() {
  const [filter, setFilter] = useState<"all" | "unread">("all");
  const [page, setPage] = useState(1);

  const { data, isLoading } = useNotifications({
    page,
    limit: 20,
    unreadOnly: filter === "unread",
    role: "admin",
  });

  const markAsReadMutation = useMarkAsRead();
  const markAllAsReadMutation = useMarkAllAsRead();
  const deleteNotificationMutation = useDeleteNotification();
  const deleteAllMutation = useDeleteAllNotifications();

  const handleMarkAsRead = (id: string) => {
    markAsReadMutation.mutate(id);
  };

  const handleDelete = (id: string) => {
    deleteNotificationMutation.mutate(id);
  };

  const handleMarkAllAsRead = () => {
    markAllAsReadMutation.mutate();
  };

  const handleDeleteAll = () => {
    if (confirm("Bạn có chắc muốn xóa tất cả thông báo?")) {
      deleteAllMutation.mutate();
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      {/* Header */}
      <div className="bg-white rounded-lg border p-6 mb-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Thông báo quản trị</h1>
            {data && (
              <p className="text-sm text-gray-600 mt-1">
                {data.unreadCount > 0
                  ? `${data.unreadCount} thông báo chưa đọc`
                  : "Không có thông báo mới"}
              </p>
            )}
          </div>

          {/* Filter tabs */}
          <div className="flex gap-2">
            <Button
              variant={filter === "all" ? "default" : "outline"}
              size="sm"
              onClick={() => setFilter("all")}
            >
              Tất cả
            </Button>
            <Button
              variant={filter === "unread" ? "default" : "outline"}
              size="sm"
              onClick={() => setFilter("unread")}
            >
              Chưa đọc
            </Button>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleMarkAllAsRead}
            disabled={!data?.unreadCount || markAllAsReadMutation.isPending}
          >
            <CheckCheck className="w-4 h-4 mr-2" />
            Đánh dấu tất cả đã đọc
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleDeleteAll}
            disabled={!data?.total || deleteAllMutation.isPending}
            className="text-red-600 hover:text-red-700"
          >
            <Trash2 className="w-4 h-4 mr-2" />
            Xóa tất cả
          </Button>
        </div>
      </div>

      {/* Notifications list */}
      <div className="space-y-2">
        {isLoading ? (
          <div className="bg-white rounded-lg border p-12 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mx-auto"></div>
            <p className="text-gray-600 mt-4">Đang tải...</p>
          </div>
        ) : !data?.notifications.length ? (
          <div className="bg-white rounded-lg border p-12 text-center">
            <Bell className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600">
              {filter === "unread"
                ? "Không có thông báo chưa đọc"
                : "Chưa có thông báo nào"}
            </p>
          </div>
        ) : (
          <>
            {data.notifications.map((notification) => (
              <NotificationItem
                key={notification._id}
                notification={notification}
                onMarkAsRead={handleMarkAsRead}
                onDelete={handleDelete}
              />
            ))}

            {/* Pagination */}
            {data.totalPages > 1 && (
              <div className="flex items-center justify-center gap-2 mt-6">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                >
                  Trang trước
                </Button>
                <span className="text-sm text-gray-600">
                  Trang {page} / {data.totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(data.totalPages, p + 1))}
                  disabled={page === data.totalPages}
                >
                  Trang sau
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
