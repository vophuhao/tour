import { catchErrors } from "@/errors";
import 'multer';
import { verifyToken } from "@/utils/jwt";
import type {
  CreatePostInput,
  ForumService,
  UpdatePostInput,
} from "@/services/forum.service";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  createPostSchema,
  getPostsSchema,
  getUserPostsSchema,
  updatePostSchema,
} from "@/validators";
import type { Request } from "express";

export interface MulterRequest extends Request {
  // eslint-disable-next-line no-undef
  files?: Express.Multer.File[] | { [fieldname: string]: Express.Multer.File[] };
}

export default class ForumController {
  constructor(private readonly forumService: ForumService) { }

  /**
   * Create a new forum post
   * @route POST /api/forum/posts
   */
  createPost = catchErrors(async (req: any, res: any) => {
    console.log("=== DEBUG: Request Body ===");
    console.log("req.body:", req.body);
    console.log("req.files:", req.files);
    console.log("req.userId:", req.userId);
    console.log("===========================");

    const input = createPostSchema.parse(req.body);
    const userId = mongoIdSchema.parse(req.userId);
    const createInput: CreatePostInput = {
      title: input.title,
      content: input.content,
      subject: input.subject,
      summary: input.summary,
      tags: input.tags,
      badge: input.badge,
      images: input.images,
      videos: input.videos,
      attachments: input.attachments,
      visibility: input.visibility,
      status: input.status,
      pinned: input.pinned,
      isAnonymous: input.isAnonymous,
      aiGenerated: input.aiGenerated,
    };

    const post = await this.forumService.createPost(
      userId,
      createInput,
      req.files as any
    );

    return ResponseUtil.created(res, post, "Tạo bài viết thành công");
  });

  /**
   * Get all posts with pagination and filters
   * @route GET /api/forum/posts
   */
  getPosts = catchErrors(async (req: any, res: any) => {
    const input = getPostsSchema.parse(req.query);
    const pageSize = input.limit || input.pageSize;

    const result = await this.forumService.getPosts({
      page: input.page,
      pageSize,
      search: input.search,
      category: input.category,
    });

    const totalPages = Math.ceil(result.total / pageSize);
    const hasNext = result.currentPage < totalPages;
    const hasPrev = result.currentPage > 1;

    return ResponseUtil.paginated(
      res,
      result.posts,
      {
        page: result.currentPage,
        limit: pageSize,
        total: result.total,
        totalPages,
        hasNext,
        hasPrev,
      },
      "Lấy danh sách bài viết thành công"
    );
  });

  /**
   * Get a single post by ID or slug
   * @route GET /api/forum/posts/:id
   */
  getPost = catchErrors(async (req: any, res: any) => {
    const postId = req.params.id || "";
    const userId = req.userId ? mongoIdSchema.parse(req.userId) : undefined;

    const post = await this.forumService.getPost(postId, userId);

    return ResponseUtil.success(res, { post }, "Lấy thông tin bài viết thành công");
  });

  /**
   * Update a post
   * @route PUT /api/forum/posts/:id
   */
  updatePost = catchErrors(async (req: any, res: any) => {
    const postId = req.params.id || "";
    const userId = mongoIdSchema.parse(req.userId);
    const input = updatePostSchema.parse(req.body);
    const updateInput: UpdatePostInput = {
      title: input.title,
      content: input.content,
      subject: input.subject,
      summary: input.summary,
      tags: input.tags,
      badge: input.badge,
      images: input.images,
      videos: input.videos,
      attachments: input.attachments,
      visibility: input.visibility,
      status: input.status,
      pinned: input.pinned,
      isAnonymous: input.isAnonymous,
    };

    const post = await this.forumService.updatePost(
      postId,
      userId,
      updateInput,
      req.files as any
    );

    return ResponseUtil.success(res, post, "Cập nhật bài viết thành công");
  });

  /**
   * Delete a post
   * @route DELETE /api/forum/posts/:id
   */
  deletePost = catchErrors(async (req: any, res: any) => {
    const postId = req.params.id || "";
    const userId = mongoIdSchema.parse(req.userId);

    const result = await this.forumService.deletePost(postId, userId);

    return ResponseUtil.success(res, result, "Xóa bài viết thành công");
  });

  /**
   * Like/Unlike a post
   * @route POST /api/forum/posts/:id/like
   */
  toggleLike = catchErrors(async (req: any, res: any) => {
    const postId = req.params.id || "";
    const userId = mongoIdSchema.parse(req.userId);

    const result = await this.forumService.toggleLike(postId, userId);

    return ResponseUtil.success(res, result, "Bình chọn bài viết thành công");
  });

  /**
   * Save/Unsave a post
   * @route POST /api/forum/posts/:id/save
   */
  toggleSave = catchErrors(async (req: any, res: any) => {
    const postId = req.params.id || "";
    const userId = mongoIdSchema.parse(req.userId);

    const result = await this.forumService.toggleSave(postId, userId);

    return ResponseUtil.success(res, result, "Lưu bài viết thành công");
  });

  /**
   * Get user's posts
   * @route GET /api/forum/users/:userId/posts
   */
  getUserPosts = catchErrors(async (req: any, res: any) => {
    const userId = req.params.userId || "";
    const input = getUserPostsSchema.parse(req.query);
    
    let currentUserId: string | undefined;
    const accessToken = req.cookies?.accessToken as string | undefined;
    if (accessToken) {
      try {
        const { payload } = verifyToken(accessToken);
        if (payload) {
          currentUserId = payload.userId.toString();
        }
      } catch {}
    }

    const isOwnProfile = currentUserId?.toString() === userId;
    const isAdmin = false;

    const result = await this.forumService.getUserPosts({
      page: input.page,
      pageSize: input.pageSize,
      userId,
      isOwnProfile,
      isAdmin,
    });

    const totalPages = Math.ceil(result.totalPosts / input.pageSize);
    const hasNext = result.currentPage < totalPages;
    const hasPrev = result.currentPage > 1;

    return ResponseUtil.paginated(
      res,
      result.posts,
      {
        page: result.currentPage,
        limit: input.pageSize,
        total: result.totalPosts,
        totalPages,
        hasNext,
        hasPrev,
      },
      "Lấy bài viết của người dùng thành công"
    );
  });

  /**
   * Get saved posts
   * @route GET /api/forum/saved
   */
  getSavedPosts = catchErrors(async (req: any, res: any) => {
    const userId = mongoIdSchema.parse(req.userId);
    const isAdmin = false;

    const posts = await this.forumService.getSavedPosts(userId, isAdmin);

    return ResponseUtil.success(res, posts, "Lấy bài viết đã lưu thành công");
  });

  /**
   * Get liked posts
   * @route GET /api/forum/liked
   */
  getLikedPosts = catchErrors(async (req: any, res: any) => {
    const userId = mongoIdSchema.parse(req.userId);
    const isAdmin = false;

    const posts = await this.forumService.getLikedPosts(userId, isAdmin);

    return ResponseUtil.success(res, posts, "Lấy bài viết đã thích thành công");
  });

  /**
   * Get trending posts
   * @route GET /api/forum/trending
   */
  getTrending = catchErrors(async (_req: any, res: any) => {
    const trending = await this.forumService.getTrending();

    return ResponseUtil.success(
      res,
      trending,
      "Lấy bài viết thịnh hành thành công"
    );
  });

  /**
   * Get forum categories
   * @route GET /api/forum/categories
   */
  getCategories = catchErrors(async (_req: any, res: any) => {
    const categories = await this.forumService.getCategories();

    return ResponseUtil.success(
      res,
      categories,
      "Lấy danh mục thành công"
    );
  });
}
