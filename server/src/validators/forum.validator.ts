import { z } from "zod";

// Validator for creating a forum post
export const createPostSchema = z.object({
  title: z
    .string()
    .min(1, "Title không được để trống")
    .max(500, "Title quá dài"),
  content: z
    .string()
    .min(1, "Content không được để trống")
    .max(50000, "Content quá dài"),
  subject: z
    .string()
    .min(1, "Subject không được để trống"),
  summary: z
    .string()
    .max(1000, "Summary quá dài")
    .optional(),
  tags: z
    .union([
      z.string().max(10000),
      z.array(z.string()),
    ])
    .optional(),
  badge: z
    .enum(["featured", "ai", "meme", "quote", "hot", "new"])
    .optional(),
  images: z.array(z.string()).optional(),
  videos: z.array(z.string()).optional(),
  attachments: z.array(z.string()).optional(),
  visibility: z.enum(["public", "private"]).default("public"),
  status: z.string().default("active").optional(),
  pinned: z.boolean().default(false).optional(),
  isAnonymous: z.boolean().default(false).optional(),
  aiGenerated: z
    .union([z.boolean(), z.string()])
    .optional(),
});

// Validator for updating a forum post
export const updatePostSchema = z.object({
  title: z
    .string()
    .min(1, "Title không được để trống")
    .max(500, "Title quá dài")
    .optional(),
  content: z
    .string()
    .min(1, "Content không được để trống")
    .max(50000, "Content quá dài")
    .optional(),
  subject: z
    .string()
    .min(1, "Subject không được để trống")
    .optional(),
  summary: z
    .string()
    .max(1000, "Summary quá dài")
    .optional(),
  tags: z
    .union([
      z.string().max(10000),
      z.array(z.string()),
    ])
    .optional(),
  badge: z
    .enum(["featured", "ai", "meme", "quote", "hot", "new"])
    .optional(),
  images: z.array(z.string()).optional(),
  videos: z.array(z.string()).optional(),
  attachments: z.array(z.string()).optional(),
  visibility: z.enum(["public", "private"]).optional(),
  status: z.string().optional(),
  pinned: z.boolean().optional(),
  isAnonymous: z.boolean().optional(),
});

// Validator for getting posts
export const getPostsSchema = z.object({
  page: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .pipe(z.number().int().min(1).default(1)),
  pageSize: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .pipe(z.number().int().min(1).max(100).default(10)),
  limit: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .pipe(z.number().int().min(1).max(100).optional()),
  search: z.string().optional(),
  category: z.string().optional(),
});

// Validator for getting user posts
export const getUserPostsSchema = z.object({
  page: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .pipe(z.number().int().min(1).default(1)),
  pageSize: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .pipe(z.number().int().min(1).max(100).default(10)),
});

export type CreatePostInput = z.infer<typeof createPostSchema>;
export type UpdatePostInput = z.infer<typeof updatePostSchema>;
export type GetPostsInput = z.infer<typeof getPostsSchema>;
export type GetUserPostsInput = z.infer<typeof getUserPostsSchema>;
