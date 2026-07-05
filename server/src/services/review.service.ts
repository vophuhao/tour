import { container, TOKENS } from "@/di";
import { ErrorFactory } from "@/errors";
import { BookingModel, PropertyModel, ReviewModel, SiteModel, type ReviewDocument } from "@/models";
import appAssert from "../utils/app-assert";
import type {
  CreateReviewInput,
  HostResponseInput,
  SearchReviewInput,
  UpdateReviewInput,
} from "@/validators/review.validator";
import NotificationService from "./notification.service";

export class ReviewService {
  /**
   * Create review (guest review site after stay)
   */
  async createReview(guestId: string, input: CreateReviewInput): Promise<ReviewDocument> {
    const {
      booking: bookingId,
      propertyRatings,
      siteRatings,
      title,
      comment,
      pros,
      cons,
      images,
    } = input;

    // Get booking
    const booking = await BookingModel.findById(bookingId);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking!.guest.toString() === guestId,
      ErrorFactory.forbidden("Bạn không phải guest của booking này")
    );
    appAssert(
      booking!.status === "completed",
      ErrorFactory.badRequest("Chỉ có thể review sau khi hoàn thành booking")
    );
    appAssert(!booking!.reviewed, ErrorFactory.conflict("Booking này đã được review"));

    // Create review
    const review = await ReviewModel.create({
      property: booking!.property,
      site: booking!.site,
      booking: bookingId,
      guest: guestId,
      host: booking!.host,
      propertyRatings,
      siteRatings,
      title,
      comment,
      pros,
      cons,
      images,
      isVerified: true, // verified vì có booking thật
    });

    // Mark booking as reviewed
    booking!.reviewed = true;
    booking!.review = review._id as any;
    await booking!.save();

    // Update property and site ratings
    await Promise.all([
      this.updatePropertyRating(booking!.property.toString()),
      this.updateSiteRating(booking!.site.toString()),
    ]);

    // Send notification to host about new review
    try {
      const notificationService = container.resolve<NotificationService>(TOKENS.NotificationService);
      const UserModel = (await import("@/models/user.model")).default;
      const property = await PropertyModel.findById(booking!.property);
      const guest = await UserModel.findById(guestId);

      // Calculate average rating across property and site ratings
      const avgRating = (
        (propertyRatings.location || 0) +
        (propertyRatings.communication || 0) +
        (propertyRatings.value || 0) +
        (siteRatings.cleanliness || 0) +
        (siteRatings.accuracy || 0) +
        (siteRatings.amenities || 0)
      ) / 6;

      await notificationService.createNewReviewForHost(
        booking!.host.toString(),
        review._id!.toString(),
        booking!.property.toString(),
        property?.name || "Property",
        guest?.username || "Khách",
        Math.round(avgRating * 10) / 10
      );
    } catch (error) {
      console.error("Failed to send review notification:", error);
    }

    return review;
  }

  /**
   * Get review by ID
   */
  async getReview(reviewId: string): Promise<ReviewDocument> {
    const review = await ReviewModel.findById(reviewId)
      .populate("property", "name slug location photos")
      .populate("site", "name slug accommodationType photos")
      .populate("guest", "username avatarUrl")
      .populate("host", "username");

    appAssert(review, ErrorFactory.resourceNotFound("Review"));
    return review!;
  }

  /**
   * Add host response to review
   */
  async addHostResponse(
    reviewId: string,
    hostId: string,
    input: HostResponseInput
  ): Promise<ReviewDocument> {
    const review = await ReviewModel.findById(reviewId);
    appAssert(review, ErrorFactory.resourceNotFound("Review"));
    appAssert(
      review!.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không phải host của review này")
    );

    await review!.addHostResponse(input.comment);

    // Send notification to guest about host response
    try {
      const notificationService = container.resolve<NotificationService>(TOKENS.NotificationService);
      await notificationService.createNotification({
        recipient: review!.guest.toString(),
        type: "review_reply",
        title: "Host đã phản hồi đánh giá",
        message: "Host đã phản hồi đánh giá của bạn",
        review: reviewId,
        link: `/reviews/${reviewId}`,
        actionType: "view_review",
        priority: "low",
        role: "guest",
      });
    } catch (error) {
      console.error("Failed to send review reply notification:", error);
    }
    return review!;
  }

  /**
   * Search reviews with filters
   */
  async searchReviews(input: SearchReviewInput) {
    const { property, site, guest, minRating, isPublished, isFeatured, sort, page, limit } = input;

    // Build query
    const query: any = {};

    if (property) query.property = property;
    if (site) query.site = site;
    if (guest) query.guest = guest;
    if (minRating !== undefined) query.overallRating = { $gte: minRating };
    if (isPublished !== undefined) query.isPublished = isPublished;
    if (isFeatured !== undefined) query.isFeatured = isFeatured;

    // Sorting
    let sortOption: any = {};
    switch (sort) {
      case "oldest":
        sortOption = { createdAt: 1 };
        break;
      case "highest-rating":
        sortOption = { "ratings.overall": -1, createdAt: -1 };
        break;
      case "lowest-rating":
        sortOption = { "ratings.overall": 1, createdAt: -1 };
        break;
      case "most-helpful":
        sortOption = { helpfulCount: -1, createdAt: -1 };
        break;
      case "newest":
      default:
        sortOption = { createdAt: -1 };
        break;
    }

    // Execute query with pagination
    const skip = (page - 1) * limit;
    const [reviews, total] = await Promise.all([
      ReviewModel.find(query)
        .populate("property", "name slug images")
        .populate("site", "name slug images")
        .populate("guest", "username email avatarUrl")
        .sort(sortOption)
        .skip(skip)
        .limit(limit),
      ReviewModel.countDocuments(query),
    ]);

    return {
      data: reviews as any[],
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
      },
    };
  }

  /**
   * Get reviews for specific property
   */
  async getPropertyReviews(propertyId: string, page: number = 1, limit: number = 20) {
    return this.searchReviews({
      property: propertyId,
      isPublished: true,
      sort: "newest",
      page,
      limit,
    });
  }

  /**
   * Get reviews for specific site
   */
  async getSiteReviews(siteId: string, page: number = 1, limit: number = 20) {
    return this.searchReviews({
      site: siteId,
      isPublished: true,
      sort: "newest",
      page,
      limit,
    });
  }

  /**
   * Get recent reviews for homepage
   * Returns latest published reviews across all properties
   */
  async getRecentReviews(limit: number = 6) {
    const reviews = await ReviewModel.find({ isPublished: true })
      .populate("property", "name slug images location")
      .populate("site", "name accommodationType")
      .populate("guest", "fullName avatarUrl")
      .sort({ createdAt: -1 })
      .limit(limit);

    return reviews;
  }

  /**
   * Vote review as helpful/not-helpful
   */
  async voteReview(reviewId: string, voteType: "helpful" | "not-helpful"): Promise<ReviewDocument> {
    const review = await ReviewModel.findById(reviewId);
    appAssert(review, ErrorFactory.resourceNotFound("Review"));

    if (voteType === "helpful") {
      review!.helpfulCount += 1;
    } else {
      review!.notHelpfulCount += 1;
    }

    await review!.save();
    return review!;
  }

  /**
   * Publish/unpublish review (admin only)
   */
  async togglePublish(reviewId: string, isPublished: boolean): Promise<ReviewDocument> {
    const review = await ReviewModel.findById(reviewId);
    appAssert(review, ErrorFactory.resourceNotFound("Review"));

    if (isPublished) {
      await review!.publish();
    } else {
      await review!.unpublish();
    }

    // Recalculate ratings
    if (review.property) {
      await this.updatePropertyRating(review.property.toString());
    }
    if (review.site) {
      await this.updateSiteRating(review.site.toString());
    }

    return review!;
  }

  /**
   * Feature/unfeature review (admin only)
   */
  async toggleFeature(reviewId: string, isFeatured: boolean): Promise<ReviewDocument> {
    const review = await ReviewModel.findById(reviewId);
    appAssert(review, ErrorFactory.resourceNotFound("Review"));

    review!.isFeatured = isFeatured;
    await review!.save();

    return review!;
  }

  /**
   * Update property rating based on all reviews
   * Aggregates: location, communication, value
   */
  private async updatePropertyRating(propertyId: string): Promise<void> {
    const reviews = await ReviewModel.find({
      property: propertyId,
      isPublished: true,
    });

    if (reviews.length === 0) {
      // Reset ratings if no reviews
      await PropertyModel.findByIdAndUpdate(propertyId, {
        rating: {
          average: 0,
          count: 0,
          breakdown: {
            location: 0,
            communication: 0,
            value: 0,
          },
        },
        "stats.totalReviews": 0,
        "stats.averageRating": 0,
        "stats.ratings": {
          location: 0,
          communication: 0,
          value: 0,
        },
      });
      return;
    }

    // Calculate average ratings from propertyRatings
    const totalRatings = reviews.reduce(
      (acc, review) => {
        acc.location += review.propertyRatings.location;
        acc.communication += review.propertyRatings.communication;
        acc.value += review.propertyRatings.value;
        return acc;
      },
      {
        location: 0,
        communication: 0,
        value: 0,
      }
    );

    const count = reviews.length;
    const average =
      (totalRatings.location + totalRatings.communication + totalRatings.value) / (count * 3);

    const breakdown = {
      location: totalRatings.location / count,
      communication: totalRatings.communication / count,
      value: totalRatings.value / count,
    };

    // Update property rating AND stats
    await PropertyModel.findByIdAndUpdate(propertyId, {
      rating: {
        average,
        count,
        breakdown,
      },
      "stats.totalReviews": count,
      "stats.averageRating": average,
      "stats.ratings": breakdown,
    });
  }

  /**
   * Update site rating based on all reviews
   * Aggregates: cleanliness, accuracy, amenities
   */
  private async updateSiteRating(siteId: string): Promise<void> {
    const reviews = await ReviewModel.find({
      site: siteId,
      isPublished: true,
    });

    if (reviews.length === 0) {
      // Reset ratings if no reviews
      await SiteModel.findByIdAndUpdate(siteId, {
        rating: {
          average: 0,
          count: 0,
          breakdown: {
            cleanliness: 0,
            accuracy: 0,
            amenities: 0,
          },
        },
      });
      return;
    }

    // Calculate average ratings from siteRatings
    const totalRatings = reviews.reduce(
      (acc, review) => {
        acc.cleanliness += review.siteRatings.cleanliness;
        acc.accuracy += review.siteRatings.accuracy;
        acc.amenities += review.siteRatings.amenities;
        return acc;
      },
      {
        cleanliness: 0,
        accuracy: 0,
        amenities: 0,
      }
    );

    const count = reviews.length;
    const average =
      (totalRatings.cleanliness + totalRatings.accuracy + totalRatings.amenities) / (count * 3);

    const siteRating = {
      average,
      count,
      breakdown: {
        cleanliness: totalRatings.cleanliness / count,
        accuracy: totalRatings.accuracy / count,
        amenities: totalRatings.amenities / count,
      },
    };

    // Update site
    await SiteModel.findByIdAndUpdate(siteId, {
      rating: siteRating,
    });
  }

  /**
   * Get review stats for property
   */
  async getPropertyReviewStats(propertyId: string): Promise<any> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    const reviews = await ReviewModel.find({
      property: propertyId,
      isPublished: true,
    });

    // Rating distribution (1-5 stars) based on overallRating
    const distribution = [0, 0, 0, 0, 0];
    reviews.forEach((review) => {
      const rating = Math.floor(review.overallRating);
      if (rating >= 1 && rating <= 5) {
        distribution[rating - 1]! += 1;
      }
    });

    return {
      totalReviews: reviews.length,
      averageRating: property!.rating?.average || 0,
      breakdown: property!.rating?.breakdown || {},
      distribution: {
        1: distribution[0],
        2: distribution[1],
        3: distribution[2],
        4: distribution[3],
        5: distribution[4],
      },
    };
  }

  /**
   * Get review stats for site
   */
  async getSiteReviewStats(siteId: string): Promise<any> {
    const site = await SiteModel.findById(siteId);
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const reviews = await ReviewModel.find({
      site: siteId,
      isPublished: true,
    });

    // Rating distribution (1-5 stars) based on overallRating
    const distribution = [0, 0, 0, 0, 0];
    reviews.forEach((review) => {
      const rating = Math.floor(review.overallRating);
      if (rating >= 1 && rating <= 5) {
        distribution[rating - 1]! += 1;
      }
    });

    return {
      totalReviews: reviews.length,
      averageRating: site!.rating?.average || 0,
      breakdown: site!.rating?.breakdown || {},
      distribution: {
        1: distribution[0],
        2: distribution[1],
        3: distribution[2],
        4: distribution[3],
        5: distribution[4],
      },
    };
  }

  async updateReview(
    reviewId: string,
    guestId: string,
    input: UpdateReviewInput
  ): Promise<ReviewDocument> {
    const review = await ReviewModel.findById(reviewId);
    appAssert(review, ErrorFactory.resourceNotFound("Review"));
    appAssert(
      review!.guest.toString() === guestId,
      ErrorFactory.forbidden("Bạn không phải tác giả của review này")
    );
    appAssert(
      !review!.isEdited,
      ErrorFactory.conflict("Đánh giá này đã được chỉnh sửa trước đó. Bạn chỉ có thể sửa đổi đánh giá 1 lần duy nhất.")
    );

    if (input.propertyRatings) {
      review!.propertyRatings = {
        ...review!.propertyRatings,
        ...input.propertyRatings,
      };
    }

    if (input.siteRatings) {
      review!.siteRatings = {
        ...review!.siteRatings,
        ...input.siteRatings,
      };
    }

    if (input.title !== undefined) review!.title = input.title;
    if (input.comment !== undefined) review!.comment = input.comment;
    if (input.pros !== undefined) review!.pros = input.pros;
    if (input.cons !== undefined) review!.cons = input.cons;
    if (input.images !== undefined) review!.images = input.images;

    review!.isEdited = true;

    await review!.save();

    // Trigger update of property and site stats
    try {
      const { PropertyModel, SiteModel } = await import("@/models");
      const property = await PropertyModel.findById(review!.property);
      if (property && typeof (property as any).updateStats === "function") {
        await (property as any).updateStats();
      }
      const site = await SiteModel.findById(review!.site);
      if (site && typeof (site as any).updateStats === "function") {
        await (site as any).updateStats();
      }
    } catch (e) {
      console.error("Failed to update stats after review edit:", e);
    }

    return review!;
  }

  async getMyPropertiesReviews(hostId: string, page: number = 1, limit: number = 20) {
    // Build query
    const query = { host: hostId };

    // Execute query with pagination
    const skip = (page - 1) * limit;
    const [reviews, total] = await Promise.all([
      ReviewModel.find(query)
        .populate("property", "name slug photos")
        .populate("site", "name slug accommodationType photos")
        .populate("guest", "username avatarUrl")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      ReviewModel.countDocuments(query),
    ]);

    return {
      data: reviews as any[],
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
      },
    };
  }
}
