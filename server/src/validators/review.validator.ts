import { z } from "zod";

// Validator cho tạo review
export const createReviewSchema = z.object({
  booking: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid booking ID"),

  // Property Ratings (1-5 stars) - property-level aspects
  propertyRatings: z.object({
    location: z.number().int().min(1).max(5),
    communication: z.number().int().min(1).max(5),
    value: z.number().int().min(1).max(5),
  }),

  // Site Ratings (1-5 stars) - site-specific aspects
  siteRatings: z.object({
    cleanliness: z.number().int().min(1).max(5),
    accuracy: z.number().int().min(1).max(5),
    amenities: z.number().int().min(1).max(5),
  }),

  // Review content
  title: z.union([z.string().min(5).max(100), z.literal("")]).optional(),
  comment: z.string().min(10).max(2000),
  pros: z.array(z.string().max(200)).max(10).optional(),
  cons: z.array(z.string().max(200)).max(10).optional(),

  // Images
  images: z.array(z.string()).max(10).optional(),
});

// Validator cho host response
export const hostResponseSchema = z.object({
  comment: z.string().min(10).max(1000),
});

// Validator cho search/filter reviews
export const searchReviewSchema = z.object({
  // Filter by property or site
  property: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),
  site: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),

  // Filter by guest
  guest: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),

  // Filter by rating
  minRating: z.number().min(1).max(5).optional(),

  // Filter by status
  isPublished: z.boolean().optional(),
  isFeatured: z.boolean().optional(),

  // Sorting
  sort: z
    .enum(["newest", "oldest", "highest-rating", "lowest-rating", "most-helpful"])
    .default("newest"),

  // Pagination
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
});

// Validator cho helpful vote
export const voteReviewSchema = z.object({
  voteType: z.enum(["helpful", "not-helpful"]),
});

// Validator cho publish/unpublish
export const reviewStatusSchema = z.object({
  isPublished: z.boolean(),
});

// Validator cho update review
export const updateReviewSchema = z.object({
  propertyRatings: z.object({
    location: z.number().int().min(1).max(5),
    communication: z.number().int().min(1).max(5),
    value: z.number().int().min(1).max(5),
  }).optional(),

  siteRatings: z.object({
    cleanliness: z.number().int().min(1).max(5),
    accuracy: z.number().int().min(1).max(5),
    amenities: z.number().int().min(1).max(5),
  }).optional(),

  title: z.union([z.string().min(5).max(100), z.literal("")]).optional(),
  comment: z.string().min(10).max(2000).optional(),
  pros: z.array(z.string().max(200)).max(10).optional(),
  cons: z.array(z.string().max(200)).max(10).optional(),
  images: z.array(z.string()).max(10).optional(),
});

export type CreateReviewInput = z.infer<typeof createReviewSchema>;
export type HostResponseInput = z.infer<typeof hostResponseSchema>;
export type SearchReviewInput = z.infer<typeof searchReviewSchema>;
export type VoteReviewInput = z.infer<typeof voteReviewSchema>;
export type ReviewStatusInput = z.infer<typeof reviewStatusSchema>;
export type UpdateReviewInput = z.infer<typeof updateReviewSchema>;
