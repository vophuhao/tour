import { ErrorFactory } from "@/errors";
import { Conversation, ConversationDocument, Message } from "@/models/directMessage.model";
import UserModel from "@/models/user.model";
import { getIO } from "@/socket";
import { Types } from "mongoose";
import { redisClient } from "../config/redis";
import appAssert from "../utils/app-assert";

type SendMessagePayload = {
  message: string;
  messageType?: "text" | "image" | "file" | "booking" | "campsite";
  attachments?: Array<{ url: string; type: string; name?: string; size?: number }>;
  bookingRef?: string | null;
  siteRef?: string | null;
};

export default class DirectMessageService {
  /**
   * Tạo hoặc lấy conversation giữa 2 users
   */
  async getOrCreateConversation(
    userId1: string,
    userId2: string,
    context?: { campsiteId?: string; bookingId?: string }
  ): Promise<ConversationDocument> {
    const user1Id = new Types.ObjectId(userId1);
    const user2Id = new Types.ObjectId(userId2);

    // Kiểm tra users tồn tại
    const [user1, user2] = await Promise.all([
      UserModel.findById(user1Id),
      UserModel.findById(user2Id),
    ]);
    const userO = await UserModel.findById(user1Id);
    const userT = await UserModel.findById(user2Id);

    if (!user1 || !user2) {
      throw ErrorFactory.resourceNotFound("User");
    }

    // Tìm conversation hiện có
    let conversation = await Conversation.findOne({
      status: "active",
      "participants.userId": { $all: [user1Id, user2Id] },
      $expr: { $eq: [{ $size: "$participants" }, 2] },
    });

    if (!conversation) {
      conversation = await Conversation.create({
        participants: [
          {
            userId: user1Id,
            role: "user",
            name: (user1 as any).username || (user1 as any).full_name,
            avatarUrl: userO?.avatarUrl,
          },
          {
            userId: user2Id,
            role: "host",
            name: (user2 as any).username || (user2 as any).full_name,
            avatarUrl: userT?.avatarUrl,
          },
        ],
        siteRef: context?.campsiteId ? new Types.ObjectId(context.campsiteId) : null,
        bookingRef: context?.bookingId ? new Types.ObjectId(context.bookingId) : null,
        createdBy: user1Id,
      });
    }

    return conversation;
  }

  /**
   * Gửi message
   */
  async sendMessage(conversationId: string, senderId: string, messageData: SendMessagePayload) {
    const {
      message,
      messageType = "text",
      attachments = [],
      bookingRef = null,
      siteRef = null,
    } = messageData;

    const convId = new Types.ObjectId(conversationId);
    const senderIdObj = new Types.ObjectId(senderId);

    // 1) Rate limiting: Max 30 messages per minute per user
    const rateLimitKey = `msg_rate:${senderId}`;
    const messageCount = await redisClient.incr(rateLimitKey);
    if (messageCount === 1) {
      await redisClient.expire(rateLimitKey, 60);
    }
    appAssert(
      messageCount <= 30,
      ErrorFactory.badRequest("Bạn đã gửi tin nhắn quá nhanh. Vui lòng thử lại sau.")
    );

    // 2) Attachments validation: max 5 files, max 10MB per file, allowed image formats only
    if (attachments && attachments.length > 0) {
      appAssert(
        attachments.length <= 5,
        ErrorFactory.badRequest("Tối đa 5 tệp đính kèm cho mỗi tin nhắn")
      );
      for (const att of attachments) {
        if (att.size) {
          appAssert(
            att.size <= 10 * 1024 * 1024,
            ErrorFactory.badRequest("Dung lượng tệp đính kèm tối đa là 10MB")
          );
        }
        if (att.type) {
          const allowedTypes = ["image/jpeg", "image/png", "image/webp", "image/jpg"];
          appAssert(
            allowedTypes.includes(att.type.toLowerCase()) || att.type.startsWith("image/"),
            ErrorFactory.badRequest("Định dạng tệp không được hỗ trợ (chỉ chấp nhận JPG, JPEG, PNG, WEBP)")
          );
        }
      }
    }

    // Kiểm tra conversation
    const conversation = await Conversation.findById(convId);
    if (!conversation) {
      throw ErrorFactory.resourceNotFound("Conversation");
    }

    // Kiểm tra sender có trong conversation
    const isMember = conversation.participants.some((p) => p.userId.equals(senderIdObj));
    if (!isMember) {
      throw ErrorFactory.forbidden("Bạn không có quyền gửi tin nhắn trong cuộc trò chuyện này");
    }

    // Tạo message
    const newMessage = await Message.create({
      conversationId: convId,
      senderId: senderIdObj,
      message,
      messageType,
      attachments,
      bookingRef: bookingRef ? new Types.ObjectId(bookingRef) : null,
      siteRef: siteRef ? new Types.ObjectId(siteRef) : null,
    });

    // Cập nhật conversation
    conversation.lastMessage = message;
    conversation.lastMessageAt = new Date();

    // Tăng unread count cho người nhận
    conversation.participants.forEach((p) => {
      if (!p.userId.equals(senderIdObj)) {
        p.unreadCount += 1;
      }
    });

    await conversation.save();

    // Populate references
    await newMessage.populate([
      { path: "senderId", select: "username avatar _id" },
      { path: "bookingRef", select: "code checkIn checkOut pricing" },
      { path: "siteRef", select: "name images pricing" },
    ]);

    // Emit socket events
    try {
      const io = getIO();
      const roomName = `conversation:${conversationId}`;

      io.to(roomName).emit("new_message", newMessage);

      // Thông báo cho các participants
      conversation.participants.forEach((p) => {
        io.to(`user:${p.userId.toString()}`).emit("conversation_updated", {
          conversationId,
          lastMessage: message,
          lastMessageAt: conversation.lastMessageAt,
        });
      });
    } catch (err) {
      console.warn("[DirectMessageService] emit error:", (err as Error).message);
    }

    return newMessage;
  }

  /**
   * Lấy messages
   */
  async getMessages(conversationId: string, userId: string, page = 1, limit = 50) {
    const convId = new Types.ObjectId(conversationId);
    const userIdObj = new Types.ObjectId(userId);

    // Kiểm tra quyền truy cập
    const conversation = await Conversation.findById(convId);
    if (!conversation) {
      throw ErrorFactory.resourceNotFound("Conversation");
    }

    const isMember = conversation.participants.some((p) => p.userId.equals(userIdObj));
    if (!isMember) {
      throw ErrorFactory.forbidden("Bạn không có quyền xem tin nhắn này");
    }

    const skip = (page - 1) * limit;
    const messages = await Message.find({ conversationId: convId, isDeleted: false })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate("bookingRef", "code checkIn checkOut pricing")
      .populate("siteRef", "name photos pricing")
      .populate("senderId", "username avatar");

    const total = await Message.countDocuments({ conversationId: convId, isDeleted: false });

    return {
      messages: messages.reverse(),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    };
  }

  /**
   * Đánh dấu đã đọc
   */
  async markAsRead(conversationId: string, userId: string) {
    const convId = new Types.ObjectId(conversationId);
    const userIdObj = new Types.ObjectId(userId);

    const conversation = await Conversation.findById(convId);
    if (!conversation) {
      throw ErrorFactory.resourceNotFound("Conversation");
    }

    await conversation.markAsRead(userIdObj);

    // Đánh dấu messages chưa đọc
    await Message.updateMany(
      {
        conversationId: convId,
        senderId: { $ne: userIdObj },
        isRead: false,
      },
      { isRead: true, readAt: new Date() }
    );

    // Emit socket
    try {
      const io = getIO();
      io.to(`conversation:${conversationId}`).emit("messages_read", {
        conversationId,
        userId,
        readAt: new Date(),
      });
    } catch (err) {
      console.warn("[DirectMessageService] emit read error:", (err as Error).message);
    }

    return conversation;
  }

  /**
   * Lấy danh sách conversations của user
   */
  async getUserConversations(userId: string, page = 1, limit = 20) {
    const userIdObj = new Types.ObjectId(userId);
    const skip = (page - 1) * limit;

    const conversations = await Conversation.find({
      "participants.userId": userIdObj,
      status: "active",
    })
      .sort({ lastMessageAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate("participants.userId", "username avatarUrl")
      .populate("siteRef", "name photos")
      .populate("bookingRef", "code status");

    const total = await Conversation.countDocuments({
      "participants.userId": userIdObj,
      status: "active",
    });

    // Transform data
    const transformed = conversations.map((conv) => {
      const otherParticipant = conv.getOtherParticipant(userIdObj);
      const unreadCount = conv.getUnreadCount(userIdObj);

      return {
        ...conv.toObject(),
        otherParticipant,
        unreadCount,
      };
    });

    return {
      conversations: transformed,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    };
  }

  /**
   * Xóa conversation
   */
  async deleteConversation(conversationId: string, userId: string) {
    const convId = new Types.ObjectId(conversationId);
    const userIdObj = new Types.ObjectId(userId);

    const conversation = await Conversation.findById(convId);
    if (!conversation) {
      throw ErrorFactory.resourceNotFound("Conversation");
    }

    const isMember = conversation.participants.some((p) => p.userId.equals(userIdObj));
    if (!isMember) {
      throw ErrorFactory.forbidden("Bạn không có quyền xóa cuộc trò chuyện này");
    }

    conversation.status = "deleted";
    await conversation.save();

    try {
      const io = getIO();
      io.to(`conversation:${conversationId}`).emit("conversation_deleted", {
        conversationId,
        deletedBy: userId,
      });
    } catch (err) {
      console.warn("[DirectMessageService] emit delete error:", (err as Error).message);
    }

    return conversation;
  }

  /**
   * Archive conversation
   */
  async archiveConversation(conversationId: string, userId: string) {
    const convId = new Types.ObjectId(conversationId);
    const userIdObj = new Types.ObjectId(userId);

    const conversation = await Conversation.findById(convId);
    if (!conversation) {
      throw ErrorFactory.resourceNotFound("Conversation");
    }

    const isMember = conversation.participants.some((p) => p.userId.equals(userIdObj));
    if (!isMember) {
      throw ErrorFactory.forbidden("Bạn không có quyền lưu trữ cuộc trò chuyện này");
    }

    conversation.status = "archived";
    await conversation.save();

    return conversation;
  }

  /**
   * Lấy số lượng tin nhắn chưa đọc
   */
  async getUnreadCount(userId: string): Promise<number> {
    const userIdObj = new Types.ObjectId(userId);

    const conversations = await Conversation.find({
      "participants.userId": userIdObj,
      status: "active",
    });

    let totalUnread = 0;
    conversations.forEach((conv) => {
      totalUnread += conv.getUnreadCount(userIdObj);
    });

    return totalUnread;
  }

  /**
   * React to a message (stub/skeleton implementation)
   */
  async reactToMessage(data: { messageId: string; userId: string; emoji: string }) {
    return {
      success: true,
      data: {
        messageId: data.messageId,
        userId: data.userId,
        emoji: data.emoji,
      },
    };
  }

  /**
   * Delete message (mark as deleted)
   */
  async deleteMessage(messageId: string, userId: string) {
    const msg = await Message.findById(messageId);
    if (!msg) {
      throw ErrorFactory.resourceNotFound("Message");
    }
    if (msg.senderId.toString() !== userId) {
      throw ErrorFactory.forbidden("Bạn không có quyền xóa tin nhắn này");
    }
    msg.isDeleted = true;
    msg.deletedAt = new Date();
    await msg.save();
    return { success: true, message: "Đã xóa tin nhắn" };
  }
}
