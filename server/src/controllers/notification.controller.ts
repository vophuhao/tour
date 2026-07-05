import { catchErrors } from "@/errors";
import NotificationService from "@/services/notification.service";
import { ResponseUtil } from "../utils";

export default class NotificationController {
  constructor(private readonly notificationService: NotificationService) { }

  // Lấy tất cả notifications của user
  getNotifications = catchErrors(async (req, res) => {
    const userId = req.userId.toString();
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const unreadOnly = req.query.unreadOnly === "true";
    const role = req.query.role as string | undefined;

    const result = await this.notificationService.getNotificationsByUser(
      userId,
      page,
      limit,
      unreadOnly,
      role
    );

    return ResponseUtil.success(res, result, "Lấy danh sách thông báo thành công");
  });

  // Lấy số lượng notifications chưa đọc
  getUnreadCount = catchErrors(async (req, res) => {
    const userId = req.userId.toString();
    const role = req.query.role as string | undefined;
    const result = await this.notificationService.getUnreadCount(userId, role);

    return ResponseUtil.success(res, result, "Lấy số lượng thông báo chưa đọc thành công");
  });

  // Đánh dấu notification đã đọc
  markAsRead = catchErrors(async (req, res) => {
    const userId = req.userId.toString();
    const { notificationId } = req.params;

    const notification = await this.notificationService.markAsRead(
      notificationId!,
      userId
    );

    return ResponseUtil.success(res, notification, "Đã đánh dấu thông báo là đã đọc");
  });

  // Đánh dấu tất cả notifications đã đọc
  markAllAsRead = catchErrors(async (req, res) => {
    const userId = req.userId.toString();
    const result = await this.notificationService.markAllAsRead(userId);

    return ResponseUtil.success(res, result, "Đã đánh dấu tất cả thông báo là đã đọc");
  });

  // Xóa notification
  deleteNotification = catchErrors(async (req, res) => {
    const userId = req.userId.toString();
    const { notificationId } = req.params;

    const result = await this.notificationService.deleteNotification(
      notificationId!,
      userId
    );

    return ResponseUtil.success(res, result, "Đã xóa thông báo thành công");
  });

  // Xóa tất cả notifications
  deleteAllNotifications = catchErrors(async (req, res) => {
    const userId = req.userId.toString();
    const result = await this.notificationService.deleteAllNotifications(userId);

    return ResponseUtil.success(res, result, "Đã xóa tất cả thông báo thành công");
  });

  // Tạo notification mới (Admin only hoặc system)
  createNotification = catchErrors(async (req, res) => {
    const notification = await this.notificationService.createNotification(req.body);
    return ResponseUtil.success(res, notification, "Tạo thông báo thành công");
  });

  // Lấy danh sách host (cho admin chọn recipient)
  getHosts = catchErrors(async (req: any, res: any) => {
    const { search } = req.query;
    const hosts = await this.notificationService.getHosts(search);
    return ResponseUtil.success(res, hosts, "Lấy danh sách host thành công");
  });

  // Gửi thông báo hàng loạt đến host
  sendBulkToHosts = catchErrors(async (req: any, res: any) => {
    const adminId = req.userId.toString();
    const { recipientIds, title, message, link, priority } = req.body;

    if (!title?.trim() || !message?.trim()) {
      return res.status(400).json({ success: false, message: 'Tiêu đề và nội dung không được để trống' });
    }

    const result = await this.notificationService.sendBulkToHosts({
      recipientIds: recipientIds ?? [],
      title,
      message,
      link,
      priority,
      senderId: adminId,
    });

    return ResponseUtil.success(res, result, `Đã gửi ${result.sent} thông báo`);
  });

  // Lấy danh sách thông báo admin đã gửi
  getAdminSentNotifications = catchErrors(async (req: any, res: any) => {
    const adminId = req.userId.toString();
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const result = await this.notificationService.getAdminSentNotifications(adminId, page, limit);
    return ResponseUtil.success(res, result, "Lấy danh sách thông báo đã gửi thành công");
  });

  // Xóa 1 thông báo admin đã gửi
  deleteAdminNotification = catchErrors(async (req: any, res: any) => {
    const adminId = req.userId.toString();
    const { notificationId } = req.params;
    const result = await this.notificationService.deleteAdminNotification(notificationId, adminId);
    return ResponseUtil.success(res, result, "Đã xóa thông báo");
  });

  // Xóa toàn bộ 1 lần broadcast
  deleteAdminBroadcast = catchErrors(async (req: any, res: any) => {
    const adminId = req.userId.toString();
    const { title, createdAt } = req.body;
    const result = await this.notificationService.deleteAdminBroadcast(adminId, title, createdAt);
    return ResponseUtil.success(res, result, `Đã xóa ${result.deletedCount} thông báo`);
  });
}
