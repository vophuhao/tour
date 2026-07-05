import NotificationModel, { NotificationDocument } from "@/models/notification.model";
import UserModel from "@/models/user.model";
import mongoose from "mongoose";
import { link } from "node:fs";


export default class NotificationService {
  // Tạo notification mới
  async createNotification(data: {
    recipient: string;
    sender?: string;
    type: NotificationDocument["type"];
    title: string;
    message: string;
    order?: string;
    booking?: string;
    product?: string;
    review?: string;
    property?: string;
    link?: string;
    actionType?: NotificationDocument["actionType"];
    priority?: NotificationDocument["priority"];
    role?: "guest" | "host" | "admin" | "all";
    metadata?: any;
  }) {
    const notification = await NotificationModel.create(data);
    return notification;
  }

  // Lấy tất cả notifications của user
  async getNotificationsByUser(
    userId: string,
    page: number = 1,
    limit: number = 20,
    unreadOnly: boolean = false,
    role?: string
  ) {
    const skip = (page - 1) * limit;
    const query: any = { recipient: userId };

    if (unreadOnly) {
      query.isRead = false;
    }

    if (role) {
      if (role === "admin") {
        query.role = { $in: ["admin", "all"] };
      } else if (role === "host") {
        query.role = { $in: ["host", "all"] };
      } else if (role === "guest") {
        query.role = { $in: ["guest", "all"] };
      } else {
        query.role = role;
      }
    }

    const [notifications, total, unreadCount] = await Promise.all([
      NotificationModel.find(query)
        .populate("sender", "username avatar email")
        .populate("order", "code orderStatus")
        .populate("booking", "code status")
        .populate("product", "name images")
        .populate("property", "name images")
        .populate("review", "rating comment")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      NotificationModel.countDocuments(query),
      NotificationModel.countDocuments({ recipient: userId, isRead: false, ...(role ? { role: query.role } : {}) }),
    ]);

    return {
      notifications,
      total,
      unreadCount,
      page,
      totalPages: Math.ceil(total / limit),
    };
  }

  // Đánh dấu notification đã đọc
  async markAsRead(notificationId: string, userId: string) {
    const notification = await NotificationModel.findOneAndUpdate(
      { _id: notificationId, recipient: userId },
      { isRead: true, readAt: new Date() },
      { new: true }
    );

    if (!notification) {
      throw new Error("Notification not found");
    }

    return notification;
  }

  // Đánh dấu tất cả notifications đã đọc
  async markAllAsRead(userId: string) {
    const result = await NotificationModel.updateMany(
      { recipient: userId, isRead: false },
      { isRead: true, readAt: new Date() }
    );

    return {
      success: true,
      modifiedCount: result.modifiedCount,
    };
  }

  // Xóa notification
  async deleteNotification(notificationId: string, userId: string) {
    const notification = await NotificationModel.findOneAndDelete({
      _id: notificationId,
      recipient: userId,
    });

    if (!notification) {
      throw new Error("Notification not found");
    }

    return { success: true };
  }

  // Xóa tất cả notifications
  async deleteAllNotifications(userId: string) {
    const result = await NotificationModel.deleteMany({ recipient: userId });

    return {
      success: true,
      deletedCount: result.deletedCount,
    };
  }

  // Lấy số lượng notifications chưa đọc
  async getUnreadCount(userId: string, role?: string) {
    const query: any = {
      recipient: userId,
      isRead: false,
    };

    if (role) {
      if (role === "admin") {
        query.role = { $in: ["admin", "all"] };
      } else if (role === "host") {
        query.role = { $in: ["host", "all"] };
      } else if (role === "guest") {
        query.role = { $in: ["guest", "all"] };
      } else {
        query.role = role;
      }
    }

    const count = await NotificationModel.countDocuments(query);

    return { unreadCount: count };
  }

  // Helper: Tạo notification cho order
  async createOrderNotification(
    userId: string,
    orderId: string,
    orderCode: string,
    type: "order_confirmed" | "order_shipping" | "order_delivered" | "order_cancelled",
    customMessage?: string
  ) {
    const messages = {
      order_confirmed: `Đơn hàng ${orderCode} đã được xác nhận`,
      order_shipping: `Đơn hàng ${orderCode} đang được vận chuyển`,
      order_delivered: `Đơn hàng ${orderCode} đã được giao thành công`,
      order_cancelled: `Đơn hàng ${orderCode} đã bị hủy`,
    };

    const titles = {
      order_confirmed: "Đơn hàng đã xác nhận",
      order_shipping: "Đơn hàng đang giao",
      order_delivered: "Đơn hàng đã giao",
      order_cancelled: "Đơn hàng đã hủy",
    };

    return this.createNotification({
      recipient: userId,
      type,
      title: titles[type],
      message: customMessage || messages[type],
      order: orderId,
      link: `/order/${orderId}`,
      role: "guest",
      actionType: "view_order",
      priority: type === "order_cancelled" ? "high" : "medium",
      metadata: {
        orderId,
        orderCode,
      },
    });
  }

  // Helper: Tạo notification cho return request
  async createReturnRequestNotification(
    adminUserId: string,
    orderId: string,
    orderCode: string,
    customerName: string
  ) {
    return this.createNotification({
      recipient: adminUserId,
      type: "order_return_request",
      title: "Yêu cầu trả hàng mới",
      message: `${customerName} đã gửi yêu cầu trả hàng cho đơn ${orderCode}`,
      order: orderId,
      link: `/admin/orders/${orderId}`,
      actionType: "view_order",
      role: "admin",
      priority: "high",
      metadata: {
        orderId,
        orderCode,
        customerName,
      },
    });
  }

  // Helper: Tạo notification cho booking
  async createBookingNotification(
    userId: string,
    bookingId: string,
    bookingCode: string,
    type: "booking_confirmed" | "booking_cancelled",
    customMessage?: string,
    link?: string
  ) {
    const messages = {
      booking_confirmed: `Đặt chỗ ${bookingCode} đã được xác nhận`,
      booking_cancelled: `Đặt chỗ ${bookingCode} đã bị hủy`,
    };

    const titles = {
      booking_confirmed: "Đặt chỗ đã xác nhận",
      booking_cancelled: "Đặt chỗ đã hủy",
    };

    return this.createNotification({
      recipient: userId,
      type,
      title: titles[type],
      message: customMessage || messages[type],
      booking: bookingId,
      link: link || `/booking/detail/${bookingCode}`,
      actionType: "view_booking",
      role: "guest",
      metadata: {
        bookingId,
        bookingCode,
      },
    });
  }

  // ==================== HOST NOTIFICATION HELPERS ====================

  // Thông báo đặt chỗ mới cho host
  async createNewBookingForHost(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    guestName: string,
    propertyName: string,
    propertyId: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "new_booking_request",
      title: "Đơn đặt chỗ mới",
      message: `${guestName} đã đặt ${propertyName}`,
      booking: bookingId,
      property: propertyId,
      link: `/host/bookings/detail/${bookingCode}`,
      actionType: "view_booking",
      priority: "high",
      role: "host",
      metadata: {
        bookingId,
        bookingCode,
        guestName,
        propertyName,
      },
    });
  }

  // Thông báo thanh toán đã nhận
  async createPaymentReceivedForHost(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    amount: number,
    propertyName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "booking_payment_received",
      title: "Thanh toán đã nhận",
      message: `Đã nhận ${amount.toLocaleString("vi-VN")}đ từ đơn ${bookingCode}`,
      booking: bookingId,
      link: `/host/bookings/detail/${bookingCode}`,
      actionType: "view_booking",
      priority: "medium",
      role: "host",
      metadata: {
        bookingId,
        bookingCode,
        amount,
        propertyName,
      },
    });
  }

  // Thông báo khách check-in
  async createGuestCheckedInForHost(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    guestName: string,
    propertyName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "guest_checked_in",
      title: "Khách đã check-in",
      message: `${guestName} đã check-in tại ${propertyName}`,
      booking: bookingId,
      link: `/host/bookings/detail/${bookingCode}`,
      actionType: "view_booking",
      priority: "medium",
      role: "host",
      metadata: {
        bookingId,
        bookingCode,
        guestName,
        propertyName,
      },
    });
  }

  // Thông báo khách check-out
  async createGuestCheckedOutForHost(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    guestName: string,
    propertyName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "guest_checked_out",
      title: "Khách đã check-out",
      message: `${guestName} đã check-out khỏi ${propertyName}`,
      booking: bookingId,
      link: `/host/bookings/detail/${bookingCode}`,
      actionType: "view_booking",
      priority: "medium",
      role: "host",
      metadata: {
        bookingId,
        bookingCode,
        guestName,
        propertyName,
      },
    });
  }

  // Thông báo khách hủy đặt chỗ
  async createGuestCancelledForHost(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    guestName: string,
    propertyName: string,
    reason?: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "guest_cancelled_booking",
      title: "Khách đã hủy đặt chỗ",
      message: `${guestName} đã hủy đặt chỗ ${propertyName}${reason ? `: ${reason}` : ""}`,
      booking: bookingId,
      link: `/host/bookings/detail/${bookingCode}`,
      actionType: "view_booking",
      priority: "high",
      role: "host",
      metadata: {
        bookingId,
        bookingCode,
        guestName,
        propertyName,
        reason,
      },
    });
  }

  // Thông báo nhận review mới
  async createNewReviewForHost(
    hostId: string,
    reviewId: string,
    propertyId: string,
    propertyName: string,
    guestName: string,
    rating: number
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "new_review_received",
      title: "Đánh giá mới",
      message: `${guestName} đã đánh giá ${rating}⭐ cho ${propertyName}`,
      review: reviewId,
      property: propertyId,
      link: `/host/properties/${propertyId}/reviews`,
      actionType: "view_review",
      priority: "medium",
      role: "host",
      metadata: {
        reviewId,
        propertyId,
        propertyName,
        guestName,
        rating,
      },
    });
  }

  // Thông báo property được duyệt
  async createPropertyApprovedForHost(
    hostId: string,
    propertyId: string,
    propertyName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_approved",
      title: "Property đã được duyệt",
      message: `${propertyName} đã được phê duyệt và hiển thị công khai`,
      property: propertyId,
      link: `/host/properties/${propertyId}`,
      actionType: "view_property",
      priority: "high",
      role: "host",
      metadata: {
        propertyId,
        propertyName,
      },
    });
  }

  // Thông báo property bị từ chối
  async createPropertyRejectedForHost(
    hostId: string,
    propertyId: string,
    propertyName: string,
    reason: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_rejected",
      title: "Property bị từ chối",
      message: `${propertyName} bị từ chối: ${reason}`,
      property: propertyId,
      link: `/host/properties/${propertyId}`,
      actionType: "view_property",
      priority: "high",
      role: "host",
      metadata: {
        propertyId,
        propertyName,
        reason,
      },
    });
  }

  // Thông báo payout đã xử lý
  async createPayoutProcessedForHost(
    hostId: string,
    payoutId: string,
    amount: number,
    period: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "payout_processed",
      title: "Thanh toán đã xử lý",
      message: `Đã chuyển ${amount.toLocaleString("vi-VN")}đ cho kỳ ${period}`,
      link: `/host/payouts/${payoutId}`,
      actionType: "none",
      priority: "high",
      role: "host",
      metadata: {
        payoutId,
        amount,
        period,
      },
    });
  }

  // Thông báo nhắc nhở booking sắp tới
  async createBookingReminderForHost(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    propertyName: string,
    checkInDate: Date,
    guestName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "booking_reminder",
      title: "Nhắc nhở đặt chỗ",
      message: `${guestName} sẽ check-in tại ${propertyName} vào ${checkInDate.toLocaleDateString("vi-VN")}`,
      booking: bookingId,
      link: `/host/bookings/${bookingId}`,
      actionType: "view_booking",
      priority: "medium",
      role: "host",
      metadata: {
        bookingId,
        bookingCode,
        propertyName,
        checkInDate,
        guestName,
      },
    });
  }

  // Thông báo tin nhắn mới từ khách
  async createGuestMessageForHost(
    hostId: string,
    guestId: string,
    guestName: string,
    messagePreview: string
  ) {
    return this.createNotification({
      recipient: hostId,
      sender: guestId,
      type: "guest_message",
      title: "Tin nhắn mới",
      message: `${guestName}: ${messagePreview}`,
      link: `/host/messages/${guestId}`,
      actionType: "view_message",
      priority: "medium",
      role: "host",
      metadata: {
        guestId,
        guestName,
        messagePreview,
      },
    });
  }

  // Thông báo báo cáo hiệu suất property
  async createPropertyPerformanceForHost(
    hostId: string,
    propertyId: string,
    propertyName: string,
    period: string,
    metrics: {
      bookings: number;
      revenue: number;
      rating: number;
    }
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_performance",
      title: "Báo cáo hiệu suất",
      message: `${propertyName} - ${period}: ${metrics.bookings} đặt chỗ, ${metrics.revenue.toLocaleString("vi-VN")}đ, ${metrics.rating}⭐`,
      property: propertyId,
      link: `/host/properties/${propertyId}/analytics`,
      actionType: "view_property",
      priority: "low",
      role: "host",
      metadata: {
        propertyId,
        propertyName,
        period,
        metrics,
      },
    });
  }

  // ==================== ADMIN NOTIFICATION HELPERS ====================

  // Thông báo đơn hàng mới cho admin
  async createNewOrderForAdmin(
    adminId: string,
    orderId: string,
    orderCode: string,
    customerName: string,
    totalAmount: number
  ) {
    return this.createNotification({
      recipient: adminId,
      type: "order_confirmed",
      title: "Đơn hàng mới",
      message: `${customerName} đã đặt đơn hàng ${orderCode} - ${totalAmount.toLocaleString("vi-VN")}đ`,
      order: orderId,
      link: `/admin/orders/detail/${orderId}`,
      actionType: "view_order",
      priority: "high",
      role: "admin",
      metadata: {
        orderId,
        orderCode,
        customerName,
        amount: totalAmount,
      },
    });
  }

  // Thông báo yêu cầu đăng ký host mới
  async createNewHostRequestForAdmin(
    adminId: string,
    userId: string,
    userName: string,
    email: string
  ) {
    return this.createNotification({
      recipient: adminId,
      type: "system",
      title: "Yêu cầu đăng ký Host mới",
      message: `${userName} (${email}) đã đăng ký trở thành Host`,
      link: `/admin/host`,
      actionType: "none",
      priority: "high",
      role: "admin",
      metadata: {
        userId,
        userName,
        email,
      },
    });
  }

  // Thông báo property bị admin khóa
  async createPropertyLockedForHost(
    hostId: string,
    propertyId: string,
    propertyName: string,
    reason: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_rejected",
      title: "🔒 Property của bạn đã bị khóa",
      message: `${propertyName} đã bị admin khóa. Lý do: ${reason}. Vui lòng chỉnh sửa lại và gửi yêu cầu mở khóa.`,
      property: propertyId,
      link: `/host/locations`,
      actionType: "view_property",
      priority: "high",
      role: "host",
      metadata: { propertyId, propertyName, reason, action: "locked" },
    });
  }

  // Thông báo property được admin mở khóa
  async createPropertyUnlockedForHost(
    hostId: string,
    propertyId: string,
    propertyName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_approved",
      title: "✅ Property của bạn đã được mở khóa",
      message: `${propertyName} đã được admin duyệt và mở khóa thành công. Property của bạn hiện đang hoạt động.`,
      property: propertyId,
      link: `/host/locations`,
      actionType: "view_property",
      priority: "high",
      role: "host",
      metadata: { propertyId, propertyName, action: "unlocked" },
    });
  }

  // Thông báo site bị admin khóa
  async createSiteLockedForHost(
    hostId: string,
    siteId: string,
    siteName: string,
    propertyName: string,
    reason: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_rejected",
      title: "🔒 Site của bạn đã bị khóa",
      message: `Site "${siteName}" tại ${propertyName} đã bị admin khóa. Lý do: ${reason}.`,
      link: `/host/locations`,
      actionType: "view_property",
      priority: "high",
      role: "host",
      metadata: { siteId, siteName, propertyName, reason, action: "site_locked" },
    });
  }

  // Thông báo site được admin mở khóa
  async createSiteUnlockedForHost(
    hostId: string,
    siteId: string,
    siteName: string,
    propertyName: string
  ) {
    return this.createNotification({
      recipient: hostId,
      type: "property_approved",
      title: "✅ Site của bạn đã được mở khóa",
      message: `Site "${siteName}" tại ${propertyName} đã được admin duyệt và mở khóa thành công.`,
      link: `/host/locations`,
      actionType: "view_property",
      priority: "high",
      role: "host",
      metadata: { siteId, siteName, propertyName, action: "site_unlocked" },
    });
  }

  // Thông báo host đã sửa property/site cần admin duyệt
  async createPendingApprovalForAdmin(
    adminId: string,
    resourceType: "property" | "site",
    resourceId: string,
    resourceName: string,
    hostName: string,
    propertyId?: string
  ) {
    return this.createNotification({
      recipient: adminId,
      type: "system",
      title: `⏳ ${resourceType === "property" ? "Property" : "Site"} cần duyệt`,
      message: `Host ${hostName} đã cập nhật "${resourceName}" (đang bị khóa) và đang chờ admin duyệt mở khóa.`,
      property: propertyId || resourceId,
      link: `/admin/hosts`,
      actionType: "view_property",
      priority: "high",
      role: "admin",
      metadata: { resourceType, resourceId, resourceName, hostName },
    });
  }

  // Thông báo property mới cần duyệt
  async createNewPropertyForAdmin(
    adminId: string,
    propertyId: string,
    propertyName: string,
    hostName: string
  ) {
    return this.createNotification({
      recipient: adminId,
      type: "system",
      title: "Property mới cần duyệt",
      message: `${hostName} đã tạo property mới: ${propertyName}`,
      property: propertyId,
      link: `/admin/properties/${propertyId}`,
      actionType: "view_property",
      priority: "high",
      role: "admin",
      metadata: {
        propertyId,
        propertyName,
        hostName,
      },
    });
  }

  // Thông báo lệnh rút tiền mới cho các Admin
  async createWithdrawalNotificationForAdmins(
    hostUserId: string,
    hostName: string,
    amount: number,
    withdrawalId: string
  ) {
    const admins = await UserModel.find({ role: "admin" }).select("_id");
    if (admins.length === 0) return;

    const notifications = admins.map((admin) => ({
      recipient: admin._id,
      sender: new mongoose.Types.ObjectId(hostUserId),
      type: "system",
      title: "Yêu cầu rút tiền mới",
      message: `Host ${hostName} vừa rút thành công số tiền ${amount.toLocaleString("vi-VN")}₫`,
      link: `/admin/payouts`,
      actionType: "none",
      role: "admin",
      priority: "high",
      metadata: {
        hostUserId,
        hostName,
        amount,
        withdrawalId,
      },
    }));

    await NotificationModel.insertMany(notifications);
  }

  // ==================== ADMIN SEND TO HOST HELPERS ====================

  // Lấy danh sách tất cả host
  async getHosts(search?: string) {
    const query: any = { role: 'host' };
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }
    const hosts = await UserModel.find(query)
      .select('_id username email avatarUrl isVerified')
      .sort({ username: 1 })
      .limit(100);
    return hosts;
  }

  // Gửi thông báo hàng loạt đến các host
  async sendBulkToHosts(data: {
    recipientIds: string[]; // rỗng = gửi tất cả host
    title: string;
    message: string;
    link?: string;
    priority?: 'low' | 'medium' | 'high';
    senderId: string;
  }) {
    let targetIds = data.recipientIds;

    // Nếu không chỉ định → gửi tất cả host
    if (!targetIds || targetIds.length === 0) {
      const allHosts = await UserModel.find({ role: 'host' }).select('_id');
      targetIds = allHosts.map((h: any) => h._id.toString());
    }

    if (targetIds.length === 0) {
      return { sent: 0, recipientCount: 0 };
    }

    const notifications = await NotificationModel.insertMany(
      targetIds.map((hostId: string) => ({
        recipient: new mongoose.Types.ObjectId(hostId),
        sender: new mongoose.Types.ObjectId(data.senderId),
        type: 'system',
        title: data.title,
        message: data.message,
        link: data.link ?? undefined,
        actionType: 'none',
        priority: data.priority ?? 'medium',
        role: 'host',
        isRead: false,
        metadata: { isBroadcast: true, sentBy: data.senderId },
      }))
    );

    return { sent: notifications.length, recipientCount: targetIds.length };
  }

  // Lấy các thông báo admin đã gửi (sender = adminId)
  async getAdminSentNotifications(adminId: string, page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    // Chỉ cần filter theo sender - không dùng metadata dot-notation
    const query: any = { sender: new mongoose.Types.ObjectId(adminId) };

    const [notifications, total] = await Promise.all([
      NotificationModel.find(query)
        .populate('recipient', 'username email avatarUrl')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      NotificationModel.countDocuments(query),
    ]);

    return { notifications, total, totalPages: Math.ceil(total / limit), page };
  }

  // Admin xóa thông báo đã gửi (theo sender)
  async deleteAdminNotification(notificationId: string, adminId: string) {
    const notification = await NotificationModel.findOneAndDelete({
      _id: notificationId,
      sender: adminId,
    });
    if (!notification) throw new Error('Không tìm thấy thông báo');
    return { success: true };
  }

  // Admin xóa toàn bộ 1 broadcast (cùng title + message + senderId)
  async deleteAdminBroadcast(adminId: string, title: string, createdAt: string) {
    const targetTime = new Date(createdAt);
    const windowStart = new Date(targetTime.getTime() - 5000); // ±5 giây
    const windowEnd = new Date(targetTime.getTime() + 5000);
    const result = await NotificationModel.deleteMany({
      sender: adminId,
      title,
      createdAt: { $gte: windowStart, $lte: windowEnd },
    });
    return { success: true, deletedCount: result.deletedCount };
  }
}
