import ReviewController from "@/controllers/review.controller";
import SiteController from "@/controllers/site.controller";
import { container, TOKENS } from "@/di";
import { authenticate } from "@/middleware";
import type { ReviewService } from "@/services/review.service";
import type { SiteService } from "@/services/site.service";
import { Router } from "express";

const siteRoutes = Router();

const siteService = container.resolve<SiteService>(TOKENS.SiteService);
const siteController = new SiteController(siteService);

const reviewService = container.resolve<ReviewService>(TOKENS.ReviewService);
const reviewController = new ReviewController(reviewService);

// Public routes - ORDER MATTERS! Specific routes must come before dynamic params

// Search endpoint (must be first to avoid matching "search" as ID)
siteRoutes.get("/search", siteController.searchSites);
siteRoutes.get("/", siteController.searchSites); // Alias

// Sites by property (must be before /:idOrSlug to avoid matching "property" as ID)
siteRoutes.get("/property/:propertyId", siteController.getSitesByProperty);

// Site reviews routes (must be before /:idOrSlug)
siteRoutes.get("/:siteId/reviews", reviewController.getSiteReviews);
siteRoutes.get("/:siteId/reviews/stats", reviewController.getSiteReviewStats);

// Site availability and pricing (must be before /:idOrSlug)
siteRoutes.get("/:id/blocked-dates", siteController.getBlockedDates);
siteRoutes.get("/:id/availability", siteController.checkAvailability);
siteRoutes.get("/:id/available-units", siteController.getAvailableUnits);
siteRoutes.get("/:id/calculate-pricing", siteController.calculatePricing);
siteRoutes.get("/:idOrSlug/with-availability", siteController.getSiteWithAvailability);

// Site details (MUST BE LAST among GET routes)
siteRoutes.get("/:idOrSlug", siteController.getSite);

// Site availability and calendar endpoints for hosts
siteRoutes.post("/:id/block-dates", authenticate, siteController.blockSiteDates);
siteRoutes.delete("/:id/block-dates", authenticate, siteController.unblockSiteDates);
siteRoutes.put("/:id/seasonal-pricing", authenticate, siteController.updateSeasonalPricing);
siteRoutes.get("/:id/availability-calendar", authenticate, siteController.getAvailabilityCalendar);

// Protected routes (host/admin)
siteRoutes.post("/", authenticate, siteController.createSite);
siteRoutes.patch("/:id", authenticate, siteController.updateSite);
siteRoutes.delete("/:id", authenticate, siteController.deleteSite);
siteRoutes.post("/:id/activate", authenticate, siteController.activateSite);
siteRoutes.post("/:id/deactivate", authenticate, siteController.deactivateSite);

// Admin-only routes
siteRoutes.post("/:id/admin-lock", authenticate, siteController.adminLockSite);
siteRoutes.post("/:id/admin-unlock", authenticate, siteController.adminUnlockSite);

export default siteRoutes;
