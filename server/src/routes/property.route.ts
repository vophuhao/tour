import PropertyController from "@/controllers/property.controller";
import ReviewController from "@/controllers/review.controller";
import ComboController from "@/controllers/combo.controller";
import { container, TOKENS } from "@/di";
import { authenticate } from "@/middleware";
import type { PropertyService } from "@/services/property.service";
import type { ReviewService } from "@/services/review.service";
import { Router } from "express";

const propertyRoutes = Router();
const comboController = new ComboController();

const propertyService = container.resolve<PropertyService>(TOKENS.PropertyService);
const propertyController = new PropertyController(propertyService);

const reviewService = container.resolve<ReviewService>(TOKENS.ReviewService);
const reviewController = new ReviewController(reviewService);

// Public routes - ORDER MATTERS! Specific routes must come before dynamic params

// Search endpoint (must be first to avoid matching "search" as ID)
propertyRoutes.get("/search", propertyController.searchProperties);
propertyRoutes.get("/compare/list", propertyController.compareProperties);
propertyRoutes.post("/route-search", propertyController.searchPropertiesAlongRoute);
propertyRoutes.get("/", propertyController.searchProperties); // Alias

// Featured and nearby (must be before /:idOrSlug)
propertyRoutes.get("/featured/list", propertyController.getFeaturedProperties);
propertyRoutes.get("/nearby/:idOrSlug", propertyController.getNearbyProperties);

// Personalized recommendations (protected, must be before /:idOrSlug)
propertyRoutes.get("/recommendations/list", authenticate, propertyController.getRecommendations);

// My properties (must be before /:idOrSlug to avoid matching "my" as ID)
propertyRoutes.get("/my/list", authenticate, propertyController.getMyProperties);

// Service blocks (must be before /:idOrSlug)
propertyRoutes.post("/service-blocks", authenticate, propertyController.createServiceBlock);
propertyRoutes.get("/service-blocks/my", authenticate, propertyController.getMyServiceBlocks);
propertyRoutes.delete("/service-blocks/:blockId", authenticate, propertyController.deleteServiceBlock);

// Admin: get host's properties with sites (must be before /:idOrSlug)
propertyRoutes.get("/host/:hostId", authenticate, propertyController.getHostPropertiesWithSites);

// Property reviews routes (must be before /:idOrSlug)
propertyRoutes.get("/:propertyId/reviews", reviewController.getPropertyReviews);
propertyRoutes.get("/:propertyId/reviews/stats", reviewController.getPropertyReviewStats);

// Property combos route (public)
propertyRoutes.get("/:propertyId/combos", comboController.getPropertyCombos);
propertyRoutes.get("/:id/services/availability", propertyController.getPropertyServicesAvailability);

// Property stats (must be before /:idOrSlug)
propertyRoutes.get("/:id/stats", authenticate, propertyController.getPropertyStats);

// Superhost status (public — used by host dashboard and property detail page)
propertyRoutes.get("/:id/superhost-status", authenticate, async (req, res) => {
  try {
    const { SuperhostService } = await import("@/services/superhost.service");
    const property = await (await import("@/models")).PropertyModel.findOne({
      $or: [{ _id: req.params.id }, { slug: req.params.id }],
    }).select("host isSuperhost superhostSince superhostEvaluatedAt");

    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    const superhostService = new SuperhostService();
    const status = await superhostService.getSuperhostStatus(property.host.toString());

    return res.json({
      success: true,
      data: {
        isSuperhost: property.isSuperhost,
        superhostSince: property.superhostSince,
        superhostEvaluatedAt: property.superhostEvaluatedAt,
        criteria: status.criteria,
        isEligible: status.isEligible,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Property with sites (must be before /:idOrSlug)
propertyRoutes.get("/:idOrSlug/with-sites", propertyController.getPropertyWithSites);

// Property details (MUST BE LAST among GET routes)
propertyRoutes.get("/:idOrSlug", propertyController.getProperty);

// Blocked dates routes (host only)
propertyRoutes.get("/:id/blocked-dates", propertyController.getPropertyBlockedDates);
propertyRoutes.post("/:id/block-dates", authenticate, propertyController.blockPropertyDates);
propertyRoutes.delete(
  "/blocked-dates/:blockId",
  authenticate,
  propertyController.unblockPropertyDates
);

// Protected routes (host/admin)
propertyRoutes.post("/", authenticate, propertyController.createProperty);
propertyRoutes.patch("/:id", authenticate, propertyController.updateProperty);
propertyRoutes.delete("/:id", authenticate, propertyController.deleteProperty);
propertyRoutes.post("/:id/activate", authenticate, propertyController.activateProperty);
propertyRoutes.post("/:id/deactivate", authenticate, propertyController.deactivateProperty);

// Admin-only routes
propertyRoutes.post("/:id/admin-lock", authenticate, propertyController.adminLockProperty);
propertyRoutes.post("/:id/admin-unlock", authenticate, propertyController.adminUnlockProperty);
propertyRoutes.post("/:id/admin-approve", authenticate, propertyController.adminApproveProperty);

export default propertyRoutes;
