import { catchErrors, ErrorFactory } from "@/errors";
import DirectMessageService from "@/services/directMessage.service";
import { appAssert, ResponseUtil } from "../utils";

export default class DirectMessageController {
  constructor(private readonly messageService: DirectMessageService) { }

  /**
   * POST /messages/conversations
   * Tạo hoặc lấy conversation với user khác
   */
  getOrCreateConversation = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { otherUserId, campsiteId, bookingId } = req.body;
    appAssert(otherUserId, ErrorFactory.badRequest("Thiếu otherUserId"));

    const conversation = await this.messageService.getOrCreateConversation(
      userId.toString(),
      otherUserId,
      { campsiteId, bookingId }
    );

    return ResponseUtil.success(res, conversation, "Conversation created");
  });

  /**
   * POST /messages/:conversationId
   * Gửi message
   */
  sendMessage = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { conversationId } = req.params;

    const { message, messageType, attachments, bookingRef, siteRef } = req.body.payload;

    const newMessage = await this.messageService.sendMessage(
      conversationId!,
      userId.toString(),
      { message, messageType, attachments, bookingRef, siteRef }
    );
    return ResponseUtil.created(res, newMessage, "Message sent");
  });

  /**
   * GET /messages/:conversationId
   * Lấy messages và đánh dấu đã đọc
   */
  getMessages = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { conversationId } = req.params;
    const { page = 1, limit = 50 } = req.query as any;

    const result = await this.messageService.getMessages(
      conversationId!,
      userId.toString(),
      Number(page),
      Number(limit)
    );

    // Đánh dấu đã đọc
    await this.messageService.markAsRead(conversationId!, userId.toString());

    const pagination = buildPagination(Number(page), Number(limit), result.pagination.total);
    return ResponseUtil.paginated(res, result.messages, pagination);
  });

  /**
   * GET /messages/conversations
   * Lấy danh sách conversations của user
   */
  getUserConversations = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { page = 1, limit = 20 } = req.query as any;

    const result = await this.messageService.getUserConversations(
      userId.toString(),
      Number(page),
      Number(limit)
    );

    const pagination = buildPagination(Number(page), Number(limit), result.pagination.total);
    return ResponseUtil.paginated(res, result.conversations, pagination);
  });

  /**
   * PUT /messages/:conversationId/read
   * Đánh dấu đã đọc
   */
  markAsRead = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { conversationId } = req.params;

    const conversation = await this.messageService.markAsRead(conversationId!, userId.toString());

    return ResponseUtil.success(res, conversation, "Marked as read");
  });

  /**
   * DELETE /messages/:conversationId
   * Xóa conversation
   */
  deleteConversation = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { conversationId } = req.params;

    const conversation = await this.messageService.deleteConversation(conversationId!, userId.toString());

    return ResponseUtil.success(res, conversation, "Conversation deleted");
  });

  /**
   * PUT /messages/:conversationId/archive
   * Lưu trữ conversation
   */
  archiveConversation = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const { conversationId } = req.params;

    const conversation = await this.messageService.archiveConversation(conversationId!, userId.toString());

    return ResponseUtil.success(res, conversation, "Conversation archived");
  });

  /**
   * GET /messages/unread-count
   * Lấy số lượng tin nhắn chưa đọc
   */
  getUnreadCount = catchErrors(async (req, res) => {
    const userId = req.userId;
    appAssert(userId, ErrorFactory.invalidCredentials("Người dùng chưa đăng nhập"));

    const count = await this.messageService.getUnreadCount(userId.toString());

    return ResponseUtil.success(res, { unreadCount: count }, "Unread count");
  });
}

export function buildPagination(page: number, limit: number, total: number) {
  const totalPages = Math.max(1, Math.ceil(total / limit));
  return {
    page,
    limit,
    total,
    totalPages,
    hasNext: page < totalPages,
    hasPrev: page > 1,
  };
}