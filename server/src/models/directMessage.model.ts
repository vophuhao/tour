import mongoose, { Document, Model, Schema, Types } from "mongoose";

export type MessageType = "text" | "image" | "file" | "booking" | "campsite";
export type ConversationStatus = "active" | "archived" | "deleted";
export type ParticipantRole = "user" | "host";

export interface Attachment {
  url: string;
  type: string;
  name?: string;
  size?: number;
}

export interface IMessage {
  conversationId: Types.ObjectId;
  senderId: Types.ObjectId;
  message: string;
  messageType: MessageType;
  attachments?: Attachment[];
  bookingRef?: Types.ObjectId | null;
  siteRef?: Types.ObjectId | null;
  isRead?: boolean;
  readAt?: Date | null;
  isDeleted?: boolean;
  deletedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface Participant {
  userId: Types.ObjectId;
  role: ParticipantRole;
  name?: string;
  avatar?: string;
  joinedAt: Date;
  lastReadAt?: Date;
  unreadCount: number;
}

export interface IConversation {
  participants: Participant[];
  lastMessage?: string;
  lastMessageAt?: Date;
  status: ConversationStatus;
  siteRef?: Types.ObjectId | null; // Context: cuộc hội thoại về campsite nào
  bookingRef?: Types.ObjectId | null; // Context: cuộc hội thoại về booking nào
  createdBy: Types.ObjectId;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface MessageDocument extends IMessage, Document {}
export interface ConversationDocument extends IConversation, Document {
  getUnreadCount(userId: Types.ObjectId): number;
  markAsRead(userId: Types.ObjectId): Promise<void>;
  getOtherParticipant(userId: Types.ObjectId): Participant | null;
}

const AttachmentSchema = new Schema<Attachment>(
  {
    url: { type: String, required: true },
    type: { type: String, required: true },
    name: String,
    size: Number,
  },
  { _id: false }
);

const ParticipantSchema = new Schema<Participant>(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    role: { type: String, enum: ["user", "host"], required: true },
    name: String,
    avatar: String,
    joinedAt: { type: Date, default: Date.now },
    lastReadAt: { type: Date, default: null },
    unreadCount: { type: Number, default: 0 },
  },
  { _id: false }
);

const MessageSchema = new Schema<MessageDocument>(
  {
    conversationId: {
      type: Schema.Types.ObjectId,
      ref: "Conversation",
      required: true,
      index: true,
    },
    senderId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    message: { type: String, trim: true, default: "" },
    messageType: {
      type: String,
      enum: ["text", "image", "file", "booking", "campsite"],
      default: "text",
    },
    attachments: { type: [AttachmentSchema], default: [] },
    bookingRef: { type: Schema.Types.ObjectId, ref: "Booking", default: null },
    siteRef: { type: Schema.Types.ObjectId, ref: "Site", default: null },
    isRead: { type: Boolean, default: false, index: true },
    readAt: { type: Date, default: null },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const ConversationSchema = new Schema<ConversationDocument>(
  {
    participants: {
      type: [ParticipantSchema],
      required: true,
      validate: {
        validator: function (v: Participant[]) {
          return v.length === 2; // Chỉ cho phép 2 người trong conversation
        },
        message: "Conversation must have exactly 2 participants",
      },
    },
    lastMessage: String,
    lastMessageAt: { type: Date, default: Date.now },
    status: {
      type: String,
      enum: ["active", "archived", "deleted"],
      default: "active",
      index: true,
    },
    siteRef: { type: Schema.Types.ObjectId, ref: "Site", default: null },
    bookingRef: { type: Schema.Types.ObjectId, ref: "Booking", default: null },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true }
);

// Indexes
MessageSchema.index({ conversationId: 1, createdAt: -1 });
MessageSchema.index({ senderId: 1, createdAt: -1 });
ConversationSchema.index({ "participants.userId": 1 });
ConversationSchema.index({ status: 1, lastMessageAt: -1 });
ConversationSchema.index({ "participants.userId": 1, status: 1 });

// Methods
ConversationSchema.methods.getUnreadCount = function (userId: Types.ObjectId): number {
  const participant = this.participants.find((p: Participant) => p.userId.equals(userId));
  return participant?.unreadCount || 0;
};

ConversationSchema.methods.markAsRead = async function (userId: Types.ObjectId): Promise<void> {
  const participant = this.participants.find((p: Participant) => p.userId.equals(userId));
  if (participant) {
    participant.unreadCount = 0;
    participant.lastReadAt = new Date();
    await this.save();
  }
};

ConversationSchema.methods.getOtherParticipant = function (
  userId: Types.ObjectId
): Participant | null {
  return this.participants.find((p: Participant) => !p.userId.equals(userId)) || null;
};

// Static method: Tìm hoặc tạo conversation giữa 2 users
ConversationSchema.statics.findOrCreate = async function (
  userId1: Types.ObjectId,
  userId2: Types.ObjectId,
  context?: { siteId?: Types.ObjectId; bookingId?: Types.ObjectId }
) {
  // Tìm conversation hiện có
  let conversation = await this.findOne({
    status: "active",
    "participants.userId": { $all: [userId1, userId2] },
    $expr: { $eq: [{ $size: "$participants" }, 2] },
  });

  if (!conversation) {
    // Lấy thông tin users
    const UserModel = mongoose.model("User");
    const [user1, user2] = await Promise.all([
      UserModel.findById(userId1).select("username avatar"),
      UserModel.findById(userId2).select("username avatar"),
    ]);

    conversation = await this.create({
      participants: [
        {
          userId: userId1,
          role: "user",
          name: user1?.username,
          avatar: user1?.avatar,
        },
        {
          userId: userId2,
          role: "host",
          name: user2?.username,
          avatar: user2?.avatar,
        },
      ],
      siteRef: context?.siteId || null,
      bookingRef: context?.bookingId || null,
      createdBy: userId1,
    });
  }

  return conversation;
};

export const Message: Model<MessageDocument> = mongoose.model<MessageDocument>(
  "Message",
  MessageSchema
);
export const Conversation: Model<ConversationDocument> = mongoose.model<ConversationDocument>(
  "Conversation",
  ConversationSchema
);
