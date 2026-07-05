import BookingController from "@/controllers/booking.controller";
import PromoCodeController from "@/controllers/promo-code.controller";
import { container, TOKENS } from "@/di";
import { authenticate, requireAdmin } from "@/middleware";
import type { BookingService } from "@/services/booking.service";
import { Router } from "express";

const bookingRoutes = Router();

const bookingService = container.resolve<BookingService>(TOKENS.BookingService);
const bookingController = new BookingController(bookingService);
const promoController = new PromoCodeController();

// Webhook (MUST be first - no auth)
bookingRoutes.post("/payos/webhook", bookingController.handlePayOSWebhook);

// Validate Promo Code
bookingRoutes.post("/validate-promo", authenticate, promoController.validatePromoCode);

// Admin routes (must be before :id params)
bookingRoutes.get("/admin/all", requireAdmin, bookingController.getAdminBookings);
bookingRoutes.get("/admin/stats", requireAdmin, bookingController.getAdminBookingStats);
bookingRoutes.post("/admin/:id/refund", requireAdmin, bookingController.adminProcessRefund);
bookingRoutes.post("/admin/:id/cancel", requireAdmin, bookingController.adminCancelBooking);
bookingRoutes.post("/admin/:id/process-cannot-attend", requireAdmin, bookingController.adminProcessCannotAttend);


// Host routes
bookingRoutes.get("/host/list", authenticate, bookingController.getHostBookingsList);

// Guest routes
bookingRoutes.post("/:id/confirm-arrival", authenticate, bookingController.guestConfirmArrival);
bookingRoutes.post("/:id/cannot-attend", authenticate, bookingController.guestCannotAttend);

// Fixed routes BEFORE param routes
bookingRoutes.post("/", authenticate, bookingController.createBooking);
bookingRoutes.get("/", authenticate, bookingController.searchBookings);
bookingRoutes.get("/my/list", authenticate, bookingController.getMyBookings);

// Specific action routes (use POST with specific path segment)
bookingRoutes.post("/:id/cancel-payment", authenticate, bookingController.userCancelPayment);
bookingRoutes.post("/:id/confirm", authenticate, bookingController.confirmBooking);
bookingRoutes.post("/:id/cancel", authenticate, bookingController.cancelBooking);
bookingRoutes.post("/:id/complete", authenticate, bookingController.completeBooking);
bookingRoutes.post("/:id/refund", authenticate, bookingController.refundBooking);
bookingRoutes.post("/:id/request-refund", authenticate, bookingController.requestRefund);
bookingRoutes.post("/:id/dissatisfaction", authenticate, bookingController.requestDissatisfaction);
bookingRoutes.post("/:id/dissatisfaction/process", requireAdmin, bookingController.processDissatisfaction);
bookingRoutes.post("/:code/code", authenticate, bookingController.getBookingByCode);
bookingRoutes.patch("/:id/payment", authenticate, requireAdmin, bookingController.updatePayment);

// Generic GET by ID (LAST)
bookingRoutes.get("/:id", authenticate, bookingController.getBooking);

export default bookingRoutes;