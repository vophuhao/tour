import { catchErrors } from "@/errors";
import type { ReviewService } from "@/services/review.service";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  createReviewSchema,
  hostResponseSchema,
  reviewStatusSchema,
  searchReviewSchema,
  updateReviewSchema,
  voteReviewSchema,
} from "@/validators/review.validator";

export default class ReviewController {
  constructor(private readonly reviewService: ReviewService) { }

  /**
   * Create review (guest only, after completed booking)
   * @route POST /api/reviews
   */
  createReview = catchErrors(async (req, res) => {
    const input = createReviewSchema.parse(req.body);
    const guestId = mongoIdSchema.parse(req.userId!);

    const review = await this.reviewService.createReview(guestId, input);

    return ResponseUtil.created(res, review, "Tạo review thành công");
  });

  /**
   * Get review details
   * @route GET /api/reviews/:id
   */
  getReview = catchErrors(async (req, res) => {
    const { id } = req.params;

    const review = await this.reviewService.getReview(id || "");

    return ResponseUtil.success(res, review, "Lấy thông tin review thành công");
  });

  /**
   * Search reviews
   * @route GET /api/reviews
   */
  searchReviews = catchErrors(async (req, res) => {
    const input = searchReviewSchema.parse(req.query);

    const { data, pagination } = await this.reviewService.searchReviews(input);

    return ResponseUtil.paginated(res, data, pagination, "Tìm kiếm review thành công");
  });

  /**
   * Get recent reviews for homepage
   * @route GET /api/reviews/recent
   */
  getRecentReviews = catchErrors(async (req, res) => {
    const { limit = 6 } = req.query as { limit?: string };

    const reviews = await this.reviewService.getRecentReviews(Number(limit));

    return ResponseUtil.success(res, reviews, "Lấy review mới nhất thành công");
  });

  /**
   * Get property reviews
   * @route GET /api/properties/:propertyId/reviews
   */
  getPropertyReviews = catchErrors(async (req, res) => {
    const { propertyId } = req.params;
    const { page = 1, limit = 20 } = req.query as { page?: string; limit?: string };

    const { data, pagination } = await this.reviewService.getPropertyReviews(
      propertyId || "",
      Number(page),
      Number(limit)
    );

    return ResponseUtil.paginated(res, data, pagination, "Lấy review property thành công");
  });

  /**
   * Get site reviews
   * @route GET /api/sites/:siteId/reviews
   */
  getSiteReviews = catchErrors(async (req, res) => {
    const { siteId } = req.params;
    const { page = 1, limit = 20 } = req.query as { page?: string; limit?: string };

    const { data, pagination } = await this.reviewService.getSiteReviews(
      siteId || "",
      Number(page),
      Number(limit)
    );

    return ResponseUtil.paginated(res, data, pagination, "Lấy review site thành công");
  });

  /**
   * Get property review stats
   * @route GET /api/properties/:propertyId/reviews/stats
   */
  getPropertyReviewStats = catchErrors(async (req, res) => {
    const { propertyId } = req.params;

    const stats = await this.reviewService.getPropertyReviewStats(propertyId || "");

    return ResponseUtil.success(res, stats, "Lấy thống kê review property thành công");
  });

  /**
   * Get site review stats
   * @route GET /api/sites/:siteId/reviews/stats
   */
  getSiteReviewStats = catchErrors(async (req, res) => {
    const { siteId } = req.params;

    const stats = await this.reviewService.getSiteReviewStats(siteId || "");

    return ResponseUtil.success(res, stats, "Lấy thống kê review site thành công");
  });

  /**
   * Add host response
   * @route POST /api/reviews/:id/response
   */
  addHostResponse = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);
    const input = hostResponseSchema.parse(req.body);

    const review = await this.reviewService.addHostResponse(id || "", hostId, input);

    return ResponseUtil.success(res, review, "Phản hồi review thành công");
  });

  /**
   * Vote review as helpful/not-helpful
   * @route POST /api/reviews/:id/vote
   */
  voteReview = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { voteType } = voteReviewSchema.parse(req.body);

    const review = await this.reviewService.voteReview(id || "", voteType);

    return ResponseUtil.success(res, review, "Vote review thành công");
  });

  /**
   * Publish/unpublish review (admin)
   * @route PATCH /api/reviews/:id/publish
   */
  togglePublish = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { isPublished } = reviewStatusSchema.parse(req.body);

    const review = await this.reviewService.togglePublish(id || "", isPublished);

    return ResponseUtil.success(
      res,
      review,
      isPublished ? "Publish review thành công" : "Unpublish review thành công"
    );
  });

  /**
   * Feature/unfeature review (admin)
   * @route PATCH /api/reviews/:id/feature
   */
  toggleFeature = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { isFeatured } = req.body;

    const review = await this.reviewService.toggleFeature(id || "", isFeatured);

    return ResponseUtil.success(
      res,
      review,
      isFeatured ? "Feature review thành công" : "Unfeature review thành công"
    );
  });

  /**
   * Update review (guest only, max 1 edit)
   * @route PATCH /api/reviews/:id
   */
  updateReview = catchErrors(async (req, res) => {
    const { id } = req.params;
    const input = updateReviewSchema.parse(req.body);
    const guestId = mongoIdSchema.parse(req.userId!);

    const review = await this.reviewService.updateReview(id || "", guestId, input);

    return ResponseUtil.success(res, review, "Cập nhật review thành công");
  });

  getMyPropertiesReviews = catchErrors(async (req, res) => {
    const userId = mongoIdSchema.parse(req.userId);
    const { page = 1, limit = 20 } = req.query as { page?: string; limit?: string };
    const { data, pagination } = await this.reviewService.getMyPropertiesReviews(
      userId,
      Number(page),
      Number(limit)
    );
    return ResponseUtil.paginated(res, data, pagination, "Lấy review property của tôi thành công");
  });
}
