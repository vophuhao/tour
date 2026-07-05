import ReviewController from "@/controllers/review.controller";
import { container, TOKENS } from "@/di";
import { authenticate, requireAdmin } from "@/middleware";
import type { ReviewService } from "@/services/review.service";
import { Router } from "express";

const reviewRoutes = Router();

const reviewService = container.resolve<ReviewService>(TOKENS.ReviewService);
const reviewController = new ReviewController(reviewService);

// Public routes

reviewRoutes.get("/my", authenticate, reviewController.getMyPropertiesReviews);
reviewRoutes.get("/recent", reviewController.getRecentReviews);
reviewRoutes.get("/", reviewController.searchReviews);
reviewRoutes.get("/:id", reviewController.getReview);

// Protected routes
reviewRoutes.post("/", authenticate, reviewController.createReview);
reviewRoutes.patch("/:id", authenticate, reviewController.updateReview);
reviewRoutes.post("/:id/response", authenticate, reviewController.addHostResponse);
reviewRoutes.post("/:id/vote", reviewController.voteReview); // public or authenticated

// Admin routes
reviewRoutes.patch("/:id/publish", requireAdmin, reviewController.togglePublish);
reviewRoutes.patch("/:id/feature", requireAdmin, reviewController.toggleFeature);

export default reviewRoutes;
