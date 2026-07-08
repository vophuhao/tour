
import mongoose from "mongoose";
import { slugify, generateUniqueSlug } from "../utils/slug";

const { Schema, Types } = mongoose;

const forumPostSchema = new Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  subject: { type: String, required: true },
  imageUrl: { type: String },
  userId: { type: Types.ObjectId, ref: 'User' },
  slug: { type: String, unique: true, sparse: true }, // Thêm slug
  summary: { type: String }, // Mô tả ngắn
  tags: [{ type: String }], // Mảng tag/chủ đề
  badge: { type: String, enum: ['featured', 'ai', 'meme', 'quote', 'hot', 'new'], required: false }, // Badge đặc biệt, optional
  images: [{ type: String }], // Mảng url ảnh nội dung
  videos: [{ type: String }], // Mảng url video nội dung
  viewCount: { type: Number, default: 0 }, // Lượt xem
  updatedAt: { type: Date }, // Ngày cập nhật cuối
  isEdited: { type: Boolean, default: false }, // Đánh dấu đã chỉnh sửa
  createdAt: { type: Date, default: Date.now },
  bestAnswer: { type: Types.ObjectId, ref: 'Comment' },
  likes: [{ type: Types.ObjectId, ref: 'User' }], // userIds who liked
  savedBy: [{ type: Types.ObjectId, ref: 'User' }], // userIds who saved
  visibility: { type: String, enum: ['public', 'private'], default: 'public' },
  status: { type: String, enum: ['active', 'pending', 'deleted', 'draft', 'archived', 'hidden'], default: 'active' }, // Trạng thái bài viết
  pinned: { type: Boolean, default: false }, // Ghim bài
  
  // Moderation
  moderationReason: { type: String },
  moderationAt: { type: Date },
  moderatedBy: { type: Types.ObjectId, ref: 'User' },
  commentCount: { type: Number, default: 0 }, // Số bình luận
  likeCount: { type: Number, default: 0 }, // Số like
  saveCount: { type: Number, default: 0 }, // Số save
  isAnonymous: { type: Boolean, default: false }, // Đăng ẩn danh
  attachments: [{ type: String }], // File đính kèm (ngoài ảnh)
  aiGenerated: { type: Boolean, default: false }, // Đánh dấu AI tạo
  reportCount: { type: Number, default: 0 }, // Số lần bị report
  lastCommentAt: { type: Date }, // Ngày bình luận cuối
});

// Auto-generate unique slug from title
forumPostSchema.pre('save', async function(this: any, next) {
  try {
    if (!this.isModified('title') && this.slug) return next();
    const base = slugify(this.title) || `post-${this._id?.toString() || Date.now()}`;
    this.slug = await generateUniqueSlug(base, this.constructor as any, this._id);
    next();
  } catch (e) {
    next(e instanceof Error ? e : new Error(String(e)));
  }
});

// Indexes for frequent queries
forumPostSchema.index({ userId: 1, createdAt: -1 });
forumPostSchema.index({ status: 1, visibility: 1 });
forumPostSchema.index({ status: 1, createdAt: -1 });
forumPostSchema.index({ createdAt: -1 });

const ForumPost = mongoose.model('ForumPost', forumPostSchema);

export default ForumPost;