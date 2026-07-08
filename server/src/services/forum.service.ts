import { v2 as cloudinary } from "cloudinary";
import sanitizeHtml from "sanitize-html";
import validator from "validator";
import streamifier from "streamifier";
import { isValidObjectId } from "mongoose";
import ForumPost from "../models/forum.post.model";
import Comment from "../models/comment.model";

type UploadedFile = {
  buffer: Buffer;
};

type UploadedFiles = {
  [key: string]: UploadedFile[];
};



export interface CreatePostInput {
  title: string;
  content: string;
  subject: string;
  summary: string | undefined;
  tags: string | string[] | undefined;
  badge: string | undefined;
  images: string[] | undefined;
  videos: string[] | undefined;
  attachments: string[] | undefined;
  visibility: "public" | "private" | undefined;
  status: string | undefined;
  pinned: boolean | undefined;
  isAnonymous: boolean | undefined;
  aiGenerated: boolean | string | undefined;
}

export interface UpdatePostInput {
  title: string | undefined;
  content: string | undefined;
  subject: string | undefined;
  summary: string | undefined;
  tags: string | string[] | undefined;
  badge: string | undefined;
  images: string[] | undefined;
  videos: string[] | undefined;
  attachments: string[] | undefined;
  visibility: string | undefined;
  status: string | undefined;
  pinned: boolean | undefined;
  isAnonymous: boolean | undefined;
}

export interface GetPostsInput {
  page: number;
  pageSize: number;
  search: string | undefined;
  category: string | undefined;
}
export interface GetUserPostsInput {
  page: number;
  pageSize: number;
  userId: string;
  isOwnProfile: boolean;
  isAdmin: boolean;
}

export class ForumService {
  /**
   * Upload buffer to Cloudinary
   */
  private uploadBufferToCloudinary = (buffer: Buffer, resourceType: "image" | "video" | "raw" = "image"): Promise<any> => {
    return new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: "forum-posts", resource_type: resourceType },
        (error: any, result: any) => {
          if (result) resolve(result);
          else reject(error);
        }
      );
      streamifier.createReadStream(buffer).pipe(stream);
    });
  };

  /**
   * Process base64 images in content and upload to Cloudinary
   */
  private processContentImages = async (content: string): Promise<string> => {
    if (!content) return "";

    let newContent = content;
    const uploadPromises = [];
    const replacements: any[] = [];

    // 1. Process base64 images
    const imgTagRegex =
      /<img[^>]+src=["'](data:image\/(?:png|jpeg|jpg|gif);base64,[^"'>]+)["'][^>]*>/gi;
    let match;
    while ((match = imgTagRegex.exec(content)) !== null) {
      const base64Data = match[1];
      if (base64Data) {
        const uploadPromise = this.uploadBufferToCloudinary(
          Buffer.from(base64Data.split(",")[1] || "", "base64"),
          "image"
        )
          .then((result: any) => {
            replacements.push({ old: base64Data, url: result.secure_url });
          })
          .catch(() => { });
        uploadPromises.push(uploadPromise);
      }
    }

    // 2. Process base64 videos
    const videoTagRegex =
      /<(?:video|source)[^>]+src=["'](data:video\/(?:mp4|webm|ogg|quicktime);base64,[^"'>]+)["'][^>]*>/gi;
    let videoMatch;
    while ((videoMatch = videoTagRegex.exec(content)) !== null) {
      const base64Data = videoMatch[1];
      if (base64Data) {
        const uploadPromise = this.uploadBufferToCloudinary(
          Buffer.from(base64Data.split(",")[1] || "", "base64"),
          "video"
        )
          .then((result: any) => {
            replacements.push({ old: base64Data, url: result.secure_url });
          })
          .catch(() => { });
        uploadPromises.push(uploadPromise);
      }
    }

    await Promise.all(uploadPromises);

    for (const { old, url } of replacements) {
      newContent = newContent.replace(old, url);
    }

    return newContent;
  };

  /**
   * Sanitize and process content
   */
  private sanitizeContent = async (content: string): Promise<string> => {
    let processedContent = await this.processContentImages(content);
    processedContent = sanitizeHtml(processedContent, {
      allowedTags: [
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
        "p",
        "a",
        "ul",
        "ol",
        "nl",
        "li",
        "b",
        "i",
        "strong",
        "em",
        "strike",
        "code",
        "hr",
        "br",
        "div",
        "span",
        "img",
        "video",
        "source",
        "pre",
        "u",
      ],
      allowedAttributes: {
        a: ["href", "name", "target"],
        img: ["src", "alt", "title", "width", "height", "style"],
        video: ["src", "controls", "width", "height", "autoplay", "loop", "muted", "style", "poster"],
        source: ["src", "type"],
        "*": ["data-*", "style"],
      },
      allowedSchemes: ["data", "http", "https"],
      allowProtocolRelative: true,
    });

    return processedContent;
  };

  /**
   * Create a new forum post
   */
  async createPost(
    userId: string,
    input: CreatePostInput,
    files?: UploadedFiles
  ): Promise<any> {
    const {
      title,
      content,
      subject,
      summary,
      tags,
      badge,
      images,
      videos,
      attachments,
      visibility = "public",
      status = "active",
      pinned = false,
      isAnonymous = false,
      aiGenerated = false,
    } = input;

    if (!title || !content || !subject) {
      throw new Error("Title, content, and subject are required.");
    }

    // Upload cover image
    let imageUrl = "";
    if (files?.coverImage?.[0]) {
      const result = await this.uploadBufferToCloudinary(files.coverImage[0].buffer);
      imageUrl = result.secure_url;
    }

    // Upload multiple images
    let imagesArr: string[] = [];
    if (files?.images) {
      for (const file of files.images) {
        const result = await this.uploadBufferToCloudinary(file.buffer);
        imagesArr.push(result.secure_url);
      }
    } else if (Array.isArray(images)) {
      imagesArr = images;
    }

    // Upload multiple videos
    let videosArr: string[] = [];
    if (files?.videos) {
      for (const file of files.videos) {
        const result = await this.uploadBufferToCloudinary(file.buffer, "video");
        videosArr.push(result.secure_url);
      }
    } else if (Array.isArray(videos)) {
      videosArr = videos;
    }

    // Upload attachments
    let attachmentsArr: string[] = [];
    if (files?.attachments) {
      for (const file of files.attachments) {
        const result = await this.uploadBufferToCloudinary(file.buffer);
        attachmentsArr.push(result.secure_url);
      }
    } else if (Array.isArray(attachments)) {
      attachmentsArr = attachments;
    }

    // Process tags
    let tagsArr: string[] = [];
    if (typeof tags === "string") {
      tagsArr = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
    } else if (Array.isArray(tags)) {
      tagsArr = tags;
    }

    // Safe content
    const safeTitle = validator.escape(title);
    const safeSummary = validator.escape(summary || "");

    // Determine AI badge
    const isAIGenerated =
      aiGenerated === true || aiGenerated === "true" || aiGenerated === "1";
    let safeBadge: string | undefined;
    if (isAIGenerated) {
      safeBadge = "ai";
    } else if (
      badge &&
      ["featured", "ai", "meme", "quote", "hot", "new"].includes(badge)
    ) {
      safeBadge = badge;
    }

    // Process content
    const processedContent = await this.sanitizeContent(content);
    const safeTagsArr = tagsArr.map((t) => validator.escape(t));

    console.log("DEBUG: ForumPost constructor:", typeof ForumPost, ForumPost);
    const post = new ForumPost({
      title: safeTitle,
      content: processedContent,
      subject,
      summary: safeSummary,
      tags: safeTagsArr,
      imageUrl,
      images: imagesArr,
      videos: videosArr,
      attachments: attachmentsArr,
      userId,
      visibility,
      status,
      pinned,
      isAnonymous,
      aiGenerated: isAIGenerated,
      ...(safeBadge && { badge: safeBadge }),
    });

    await post.save();
    await post.populate("userId", "name avatarUrl email");

    return post;
  }

  /**
   * Get all posts with pagination and filters
   */
  async getPosts(input: GetPostsInput): Promise<{
    posts: any[];
    total: number;
    currentPage: number;
    totalPages: number;
  }> {
    const { page, pageSize, search, category } = input;
    const skip = (page - 1) * pageSize;

    const conditions: any[] = [
      { status: "active" },
      { visibility: "public" },
    ];

    if (category) {
      conditions.push({ subject: category });
    }

    if (search && search.trim()) {
      conditions.push({
        $or: [
          { title: { $regex: search.trim(), $options: "i" } },
          { content: { $regex: search.trim(), $options: "i" } },
        ],
      });
    }

    const query = { $and: conditions };

    const posts = await ForumPost.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(pageSize)
      .populate("userId", "username avatarUrl email");

    const total = await ForumPost.countDocuments(query);

    const postsWithCounts = await Promise.all(
      posts.map(async (post: any) => {
        const obj = post.toObject();
        obj.likeCount = Array.isArray(obj.likes) ? obj.likes.length : 0;
        obj.saveCount = Array.isArray(obj.savedBy) ? obj.savedBy.length : 0;
        const commentCount = await Comment.countDocuments({ postId: post._id });
        obj.commentCount = commentCount;
        return obj;
      })
    );
    return {
      posts: postsWithCounts,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / pageSize),
    };
  }

  /**
   * Get a single post by ID or slug
   */
  async getPost(id: string, userId?: string): Promise<any> {
    const query = isValidObjectId(id) ? { _id: id } : { slug: id };
    const post = await ForumPost.findOne(query).populate(
      "userId",
      "username avatarUrl email _id "
    );

    if (!post) {
      throw new Error("Post not found");
    }

    if (!post.userId) {
      throw new Error("User not found for this post");
    }

    // Check access permissions
    const isAdmin = false; // This would be passed from controller
    const isOwner = userId && (post.userId as any)._id.toString() === userId.toString();

    if (post.status === "deleted") {
      throw new Error("Post not found");
    }

    if (post.status === "hidden" && !isAdmin && !isOwner) {
      throw new Error("Post not found");
    }

    if (post.visibility === "private") {
      if (!userId || (post.userId as any)._id.toString() !== userId) {
        throw new Error("Access denied");
      }
    }

    const postObj = post.toObject() as any;
    postObj.likeCount = post.likes?.length || 0;
    postObj.saveCount = post.savedBy?.length || 0;

    const commentCount = await Comment.countDocuments({ postId: post._id });
    postObj.commentCount = commentCount;

    if (userId) {
      postObj.isLiked =
        post.likes?.some((id: any) => id.equals(userId)) || false;
      postObj.isSaved =
        post.savedBy?.some((id: any) => id.equals(userId)) || false;
    }

    // Handle view count increment with deduplication
    postObj.viewCount = await this.incrementViewCount(post, userId);

    return postObj;
  }

  /**
   * Increment view count with deduplication
   */
  private async incrementViewCount(
    post: any,
    _userId?: string
  ): Promise<number> {
    try {
      const { redisClient } = await import("../config/redis");
      await redisClient.hIncrBy("post_views", post._id.toString(), 1);
      const redisViews = await redisClient.hGet("post_views", post._id.toString());
      return (post.viewCount || 0) + (redisViews ? parseInt(redisViews) : 0);
    } catch (err) {
      console.warn("Failed to increment/read post views in Redis:", err);
      return (post.viewCount || 0) + 1;
    }
  }

  /**
   * Update a post
   */
  async updatePost(
    postId: string,
    userId: string,
    input: UpdatePostInput,
    files?: UploadedFiles
  ): Promise<any> {
    const post = await ForumPost.findById(postId);
    if (!post) {
      throw new Error("Bài viết không tồn tại");
    }

    if ((post as any).userId.toString() !== userId) {
      throw new Error("Không có quyền sửa bài viết này");
    }

    const { title, content, subject, summary, tags, badge, images, videos, attachments, visibility, status, pinned, isAnonymous } = input;

    if (title) post.title = validator.escape(title);
    if (content) post.content = await this.sanitizeContent(content);
    if (subject) post.subject = subject;
    if (summary) post.summary = validator.escape(summary);
    if (badge) post.badge = validator.escape(badge);
    if (visibility) post.visibility = visibility;
    if (status) post.status = status;
    if (typeof pinned !== "undefined") post.pinned = !!pinned;
    if (typeof isAnonymous !== "undefined") post.isAnonymous = !!isAnonymous;

    // Handle tags
    if (tags) {
      if (typeof tags === "string") {
        post.tags = tags
          .split(",")
          .map((t: string) => validator.escape(t.trim()))
          .filter(Boolean);
      } else if (Array.isArray(tags)) {
        post.tags = tags.map((t: string) => validator.escape(t));
      }
    }

    // Upload cover image
    if (files?.coverImage?.[0]) {
      const result = await this.uploadBufferToCloudinary(
        files.coverImage[0].buffer
      );
      post.imageUrl = result.secure_url;
    }

    // Upload multiple images
    let updatedImages: string[] = [];
    if (images) {
      updatedImages = Array.isArray(images) ? images : [images];
    }
    if (files?.images) {
      for (const file of files.images) {
        const result = await this.uploadBufferToCloudinary(file.buffer);
        updatedImages.push(result.secure_url);
      }
      post.images = updatedImages;
    } else if (images) {
      post.images = updatedImages;
    }

    // Upload multiple videos
    let updatedVideos: string[] = [];
    if (videos) {
      updatedVideos = Array.isArray(videos) ? videos : [videos];
    }
    if (files?.videos) {
      for (const file of files.videos) {
        const result = await this.uploadBufferToCloudinary(file.buffer, "video");
        updatedVideos.push(result.secure_url);
      }
      post.videos = updatedVideos;
    } else if (videos) {
      post.videos = updatedVideos;
    }

    // Upload attachments
    let updatedAttachments: string[] = [];
    if (attachments) {
      updatedAttachments = Array.isArray(attachments) ? attachments : [attachments];
    }
    if (files?.attachments) {
      for (const file of files.attachments) {
        const result = await this.uploadBufferToCloudinary(file.buffer);
        updatedAttachments.push(result.secure_url);
      }
      post.attachments = updatedAttachments;
    } else if (attachments) {
      post.attachments = updatedAttachments;
    }

    post.isEdited = true;
    post.updatedAt = new Date();

    await post.save();
    await post.populate("userId", "name avatarUrl email");

    return post;
  }

  /**
   * Delete a post
   */
  async deletePost(postId: string, userId: string): Promise<{ message: string }> {
    const post = await ForumPost.findById(postId);
    if (!post) {
      throw new Error("Post not found");
    }

    if ((post as any).userId.toString() !== userId) {
      throw new Error("Permission denied");
    }

    await post.deleteOne();
    return { message: "Post deleted" };
  }

  /**
   * Toggle like on a post
   */
  async toggleLike(postId: string, userId: string): Promise<{
    success: boolean;
    liked: boolean;
    likeCount: number;
    post: any;
  }> {
    const post = await ForumPost.findById(postId);
    if (!post) {
      throw new Error("Post not found");
    }

    const liked = post.likes?.some(
      (id: any) => id && id.toString() === userId.toString()
    );

    let updatedPost;
    if (liked) {
      updatedPost = await ForumPost.findByIdAndUpdate(
        postId,
        { $pull: { likes: userId } },
        { new: true }
      ).populate("userId", "name avatarUrl email");
    } else {
      updatedPost = await ForumPost.findByIdAndUpdate(
        postId,
        { $addToSet: { likes: userId } },
        { new: true }
      ).populate("userId", "name avatarUrl email");
    }

    if (!updatedPost) {
      throw new Error("Post not found");
    }

    // Update likeCount after likes array changes
    const newLikeCount = Array.isArray(updatedPost.likes) ? updatedPost.likes.length : 0;
    updatedPost.likeCount = newLikeCount;
    await updatedPost.save();

    const postObj = updatedPost.toObject() as any;

    postObj.likeCount = newLikeCount;
    postObj.isLiked = updatedPost.likes?.some(
      (id: any) => id && id.toString() === userId.toString()
    ) ?? false;
    postObj.isBookmarked = (updatedPost.savedBy?.some(
      (id: any) => id && id.toString() === userId.toString()
    ) ?? false);

    return {
      success: true,
      liked: !liked,
      likeCount: newLikeCount,
      post: postObj,
    };
  }

  /**
   * Toggle save on a post
   */
  async toggleSave(postId: string, userId: string): Promise<{
    success: boolean;
    saved: boolean;
    post: any;
  }> {
    const post = await ForumPost.findById(postId);
    if (!post) {
      throw new Error("Bài viết không tồn tại");
    }

    const hasSaved =
      post.savedBy &&
      post.savedBy.some((id: any) => id.toString() === userId.toString());

    let updatedPost;
    if (hasSaved) {
      updatedPost = await ForumPost.findByIdAndUpdate(
        postId,
        { $pull: { savedBy: userId } },
        { new: true }
      ).populate("userId", "name avatarUrl email");
    } else {
      updatedPost = await ForumPost.findByIdAndUpdate(
        postId,
        { $addToSet: { savedBy: userId } },
        { new: true }
      ).populate("userId", "name avatarUrl email");
    }

    if (!updatedPost) {
      throw new Error("Bài viết không tồn tại");
    }

    // Update saveCount after savedBy array changes
    const newSaveCount = Array.isArray(updatedPost.savedBy) ? updatedPost.savedBy.length : 0;
    updatedPost.saveCount = newSaveCount;
    await updatedPost.save();

    const postObj = updatedPost.toObject() as any;

    postObj.saveCount = newSaveCount;
    postObj.likeCount = Array.isArray(updatedPost.likes) ? updatedPost.likes.length : 0;
    postObj.isBookmarked =
      Array.isArray(updatedPost.savedBy) &&
      updatedPost.savedBy.some((id: any) => id.toString() === userId.toString());
    postObj.isLiked =
      Array.isArray(updatedPost.likes) &&
      updatedPost.likes.some((id: any) => id.toString() === userId.toString());

    return {
      success: true,
      saved: !hasSaved,
      post: postObj,
    };
  }

  /**
   * Get user's posts
   */
  async getUserPosts(input: GetUserPostsInput): Promise<{
    posts: any[];
    currentPage: number;
    totalPages: number;
    totalPosts: number;
  }> {
    const { page, pageSize, userId, isOwnProfile, isAdmin } = input;

    const query: any = { userId };

    if (!isOwnProfile && !isAdmin) {
      query.visibility = "public";
      query.status = "active";
    } else if (isOwnProfile || isAdmin) {
      query.status = { $ne: "deleted" };
    }

    const total = await ForumPost.countDocuments(query);
    const posts = await ForumPost.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * pageSize)
      .limit(pageSize)
      .populate("userId", "name avatarUrl email");

    const postsWithLikeInfo = posts.map((post: any) => {
      const postObj = post.toObject();
      postObj.likeCount = post.likes?.length || 0;
      postObj.saveCount = post.savedBy?.length || 0;
      return postObj;
    });

    return {
      posts: postsWithLikeInfo,
      currentPage: page,
      totalPages: Math.ceil(total / pageSize),
      totalPosts: total,
    };
  }

  /**
   * Get saved posts
   */
  async getSavedPosts(userId: string, isAdmin: boolean): Promise<any[]> {
    const query: any = { savedBy: userId };
    if (!isAdmin) {
      query.status = "active";
    } else {
      query.status = { $ne: "deleted" };
    }

    const posts = await ForumPost.find(query)
      .sort({ createdAt: -1 })
      .populate("userId", "name avatarUrl email");

    return posts;
  }

  /**
   * Get liked posts
   */
  async getLikedPosts(userId: string, isAdmin: boolean): Promise<any[]> {
    const query: any = { likes: userId };
    if (!isAdmin) {
      query.status = "active";
    } else {
      query.status = { $ne: "deleted" };
    }

    const posts = await ForumPost.find(query)
      .sort({ createdAt: -1 })
      .populate("userId", "name avatarUrl email");

    return posts;
  }

  /**
   * Get trending posts (sorted by likes and creation date)
   */
  async getTrending(): Promise<
    Array<{
      _id: string;
      title: string;
      slug: string;
      createdAt: Date;
      author: string;
      likes: number;
    }>
  > {
    const trending = await ForumPost.aggregate([
      {
        $match: {
          visibility: "public",
          status: "active",
          userId: { $exists: true },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "userId",
          foreignField: "_id",
          as: "user",
        },
      },
      {
        $match: {
          "user.0": { $exists: true },
        },
      },
      {
        $project: {
          _id: 1,
          title: 1,
          slug: 1,
          createdAt: 1,
          author: {
            $ifNull: ["$user.0.name", "$user.0.username", "Unknown"],
          },
          likes: { $size: { $ifNull: ["$likes", []] } },
        },
      },
      {
        $sort: { likes: -1, createdAt: -1 },
      },
      {
        $limit: 5,
      },
    ]);

    return trending;
  }

  /**
   * Get forum categories (top 5 subjects by post count)
   */
  async getCategories(): Promise<
    Array<{
      name: string;
      count: number;
    }>
  > {
    const categories = await ForumPost.aggregate([
      {
        $match: {
          subject: { $exists: true, $nin: [null, ""] },
          visibility: "public",
          status: "active",
        },
      },
      {
        $group: {
          _id: "$subject",
          count: { $sum: 1 },
        },
      },
      {
        $project: {
          name: "$_id",
          count: 1,
          _id: 0,
        },
      },
      {
        $sort: { count: -1 },
      },
      {
        $limit: 5,
      },
    ]);

    return categories;
  }

  /**
   * Sync post view counts from Redis to MongoDB
   */
  async syncViewsFromRedis(): Promise<void> {
    const { redisClient } = await import("../config/redis");
    const mongoose = await import("mongoose");
    const keys = await redisClient.hKeys("post_views").catch(() => [] as string[]);
    const updateOps = [];

    for (const id of keys) {
      const countStr = await redisClient.hGet("post_views", id).catch(() => null);
      if (countStr) {
        const count = parseInt(countStr);
        await redisClient.hDel("post_views", id).catch(() => { });
        if (count > 0 && mongoose.isValidObjectId(id)) {
          updateOps.push({
            updateOne: {
              filter: { _id: id },
              update: { $inc: { viewCount: count } },
            },
          });
        }
      }
    }

    if (updateOps.length > 0) {
      await ForumPost.bulkWrite(updateOps).catch((err) => {
        console.error("Failed to sync post views bulk write:", err);
      });
    }
  }
}
