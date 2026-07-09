import { catchErrors } from "@/errors";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  cancelBookingSchema,
  confirmBookingSchema,
  createBookingSchema,
  refundBookingSchema,
  searchBookingSchema,
  updatePaymentSchema,
  requestDissatisfactionSchema,
  processDissatisfactionSchema,
} from "@/validators/booking.validator";
import mongoose from "mongoose";
import { container, TOKENS } from "@/di";
import type { BookingService } from "@/services/booking.service";
import type { BookingQueryService } from "@/services/booking-query.service";
import PayOSService from "@/services/payos.service";
import { BookingDTO } from "../dtos/booking.dto";

export default class BookingController {
  constructor(private readonly _bookingService?: BookingService) { }

  private get bookingService(): BookingService {
    return this._bookingService || container.resolve<BookingService>(TOKENS.BookingService);
  }

  private get bookingQueryService(): BookingQueryService {
    return container.resolve<BookingQueryService>(TOKENS.BookingQueryService);
  }

  /**
   * Create booking (guest)
   * @route POST /api/bookings
   */
  createBooking = catchErrors(async (req, res) => {
    const input = createBookingSchema.parse(req.body);
    const guestId = mongoIdSchema.parse(req.userId);

    const booking = await this.bookingService.createBooking(guestId, input);
    return ResponseUtil.created(res, BookingDTO.toResponse(booking), "Đặt chỗ thành công");
  });

  /**
   * Get booking details
   * @route GET /api/bookings/:id
   */
  getBooking = catchErrors(async (req, res) => {
    const { id } = req.params;
    const userId = mongoIdSchema.parse(req.userId);

    const booking = await this.bookingQueryService.getBooking(id || "", userId);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Lấy thông tin booking thành công");
  });

  /**
   * Search my bookings
   * @route GET /api/bookings
   */
  searchBookings = catchErrors(async (req, res) => {
    const input = searchBookingSchema.parse(req.query);
    const userId = mongoIdSchema.parse(req.userId);

    const { data, pagination } = await this.bookingQueryService.searchBookings(userId, input);
    return ResponseUtil.paginated(res, BookingDTO.toResponseList(data), pagination, "Lấy danh sách booking thành công");
  });

  /**
   * Confirm booking (host)
   * @route POST /api/bookings/:id/confirm
   */
  confirmBooking = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);
    const { hostMessage } = confirmBookingSchema.parse(req.body);

    const booking = await this.bookingService.confirmBooking(id || "", hostId, hostMessage);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Xác nhận booking thành công");
  });

  /**
   * Cancel booking (guest or host)
   * @route POST /api/bookings/:id/cancel
   */
  cancelBooking = catchErrors(async (req, res) => {
    const { id } = req.params;
    const userId = mongoIdSchema.parse(req.userId);
    const input = cancelBookingSchema.parse(req.body);

    const booking = await this.bookingService.cancelBooking(
      id || "",
      userId as unknown as mongoose.Types.ObjectId,
      input
    );
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Hủy booking thành công");
  });

  /**
   * Complete booking (system - called after checkout date)
   * @route POST /api/bookings/:id/complete
   */
  completeBooking = catchErrors(async (req, res) => {
    const { id } = req.params;

    const booking = await this.bookingService.completeBooking(id || "");
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Hoàn thành booking thành công");
  });

  /**
   * Refund booking (host or admin)
   * @route POST /api/bookings/:id/refund
   */
  refundBooking = catchErrors(async (req, res) => {
    const { id } = req.params;
    const userId = mongoIdSchema.parse(req.userId);
    const { refundAmount } = refundBookingSchema.parse(req.body);

    const booking = await this.bookingService.refundBooking(id || "", userId, refundAmount);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Hoàn tiền booking thành công");
  });

  /**
   * Update payment status (admin)
   * @route PATCH /api/bookings/:id/payment
   */
  updatePayment = catchErrors(async (req, res) => {
    const { id } = req.params;
    updatePaymentSchema.parse(req.body);

    const booking = await this.bookingQueryService.getBooking(id || "", mongoIdSchema.parse(req.userId));
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Cập nhật thanh toán thành công");
  });

  getMyBookings = catchErrors(async (req, res) => {
    const userId = mongoIdSchema.parse(req.userId);
    const page = req.query.page ? Number(req.query.page) : 1;
    const limit = req.query.limit ? Number(req.query.limit) : 20;

    const { data, pagination } = await this.bookingQueryService.getMyBookings(userId, page, limit);
    return ResponseUtil.paginated(
      res,
      BookingDTO.toResponseList(data),
      pagination,
      "Lấy danh sách booking của tôi thành công"
    );
  });

  getBookingByCode = catchErrors(async (req, res) => {
    const { code } = req.params;

    const booking = await this.bookingQueryService.getBookingByCode(code || "");
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Lấy thông tin booking thành công");
  });

  handlePayOSWebhook = catchErrors(async (req, res) => {
    const payOSService = new PayOSService();
    const signature = req.headers["x-payos-signature"] as string | undefined;
    const result = await payOSService.handlePayOS(req.body, signature);
    return res.status(200).json(result);
  });

  userCancelPayment = catchErrors(async (req, res) => {
    const { id } = req.params;
    console.log("BookingController: userCancelPayment called with id:", id);
    const result = await this.bookingService.userCancelPayment(id || "");
    return ResponseUtil.success(res, result, "Hủy thanh toán booking thành công");
  });

  // ==================== ADMIN MANAGED METHODS ====================

  // Khách xác nhận đã đến
  guestConfirmArrival = catchErrors(async (req, res) => {
    const { id } = req.params;
    const guestId = mongoIdSchema.parse(req.userId);

    const booking = await this.bookingService.guestConfirmArrival(id || "", guestId);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Xác nhận đã đến thành công! Tiền đã được cộng vào ví host");
  });

  // Khách báo không thể đến
  guestCannotAttend = catchErrors(async (req, res) => {
    const { id } = req.params;
    const guestId = mongoIdSchema.parse(req.userId);
    const { reason, bankAccountName, bankAccountNumber, bankName, evidenceImages } = req.body;

    const booking = await this.bookingService.guestCannotAttend(
      id || "",
      guestId,
      { reason, bankAccountName, bankAccountNumber, bankName, evidenceImages }
    );
    return ResponseUtil.success(
      res,
      BookingDTO.toResponse(booking),
      "Đã ghi nhận yêu cầu không đến. Admin sẽ xét duyệt hoàn tiền 50% cho bạn"
    );
  });

  // User yêu cầu hoàn tiền
  requestRefund = catchErrors(async (req, res) => {
    const { id } = req.params;
    const userId = mongoIdSchema.parse(req.userId);
    const { reason } = req.body;

    const booking = await this.bookingService.requestRefund(id || "", userId, reason || "");
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Đã gửi yêu cầu hoàn tiền");
  });

  // Admin xử lý refund
  adminProcessRefund = catchErrors(async (req, res) => {
    const { id } = req.params;
    const adminId = req.userId.toString();
    const { approved, adminNote, refundAmount } = req.body;

    const booking = await this.bookingService.adminProcessRefund(
      id || "",
      adminId,
      approved,
      adminNote,
      refundAmount
    );
    return ResponseUtil.success(
      res,
      BookingDTO.toResponse(booking),
      approved ? "Đã duyệt hoàn tiền" : "Đã từ chối hoàn tiền"
    );
  });

  // Admin xem tất cả booking
  getAdminBookings = catchErrors(async (req, res) => {
    const { status, paymentStatus, hostId, search, startDate, endDate, page, limit, cannotAttendStatus } = req.query;
    const result = await this.bookingQueryService.getAdminBookings({
      status: status as string,
      paymentStatus: paymentStatus as string,
      hostId: hostId as string,
      search: search as string,
      startDate: startDate as string,
      endDate: endDate as string,
      cannotAttendStatus: cannotAttendStatus as string,
      page: parseInt(page as string) || 1,
      limit: parseInt(limit as string) || 20,
    });
    return ResponseUtil.paginated(
      res,
      BookingDTO.toResponseList(result.data),
      result.pagination,
      "Lấy danh sách booking thành công"
    );
  });

  // Admin thống kê
  getAdminBookingStats = catchErrors(async (_req, res) => {
    const stats = await this.bookingQueryService.getAdminBookingStats();
    return ResponseUtil.success(res, stats, "Lấy thống kê thành công");
  });

  // Admin hủy booking
  adminCancelBooking = catchErrors(async (req, res) => {
    const { id } = req.params;
    const adminId = req.userId.toString();
    const { reason } = req.body;

    const booking = await this.bookingService.adminCancelBooking(id || "", adminId, reason);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Đã hủy booking");
  });

  // Admin xử lý yêu cầu khách không đến (cannot attend)
  adminProcessCannotAttend = catchErrors(async (req, res) => {
    const { id } = req.params;
    const adminId = req.userId.toString();
    const { approved, adminNote } = req.body;

    const booking = await this.bookingService.adminProcessCannotAttend(
      id || "",
      adminId,
      Boolean(approved),
      adminNote
    );
    return ResponseUtil.success(
      res,
      BookingDTO.toResponse(booking),
      approved ? "Đã xác nhận hoàn tiền, ví host đã được cộng 20%" : "Đã từ chối yêu cầu"
    );
  });

  // Host xem booking của mình (read-only)
  getHostBookingsList = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const { status, page, limit } = req.query;

    const result = await this.bookingQueryService.getHostBookings(hostId, {
      status: status as string,
      page: parseInt(page as string) || 1,
      limit: parseInt(limit as string) || 20,
    });
    return ResponseUtil.paginated(
      res,
      BookingDTO.toResponseList(result.data),
      result.pagination,
      "Lấy danh sách booking thành công"
    );
  });

  /**
   * Khách gửi yêu cầu hoàn tiền do không hài lòng
   */
  requestDissatisfaction = catchErrors(async (req, res) => {
    const { id } = req.params;
    const guestId = mongoIdSchema.parse(req.userId);
    const input = requestDissatisfactionSchema.parse(req.body);

    const booking = await this.bookingService.requestDissatisfaction(guestId, id || "", input);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Đã gửi yêu cầu hoàn tiền không hài lòng");
  });

  /**
   * Admin xử lý yêu cầu hoàn tiền không hài lòng
   */
  processDissatisfaction = catchErrors(async (req, res) => {
    const { id } = req.params;
    const adminId = mongoIdSchema.parse(req.userId);
    const input = processDissatisfactionSchema.parse(req.body);

    const booking = await this.bookingService.processDissatisfaction(adminId, id || "", input);
    return ResponseUtil.success(res, BookingDTO.toResponse(booking), "Đã xử lý yêu cầu hoàn tiền");
  });

  cleanupCheckoutDiagnostics = catchErrors(async (req, res) => {
    const { BookingModel, AvailabilityModel } = await import("@/models");
    const blockedRecords = await AvailabilityModel.find({ blockType: "booked" });
    let deletedCount = 0;
    const deletedDetails: any[] = [];

    for (const record of blockedRecords) {
      const recordDate = new Date(record.date);
      recordDate.setHours(0, 0, 0, 0);

      const bookings = await BookingModel.find({
        site: record.site,
        status: { $in: ["pending", "confirmed", "completed", "refund_requested"] },
      });

      const isStillBooked = bookings.some(booking => {
        const ci = new Date(booking.checkIn);
        ci.setHours(0, 0, 0, 0);
        const co = new Date(booking.checkOut);
        co.setHours(0, 0, 0, 0);

        return recordDate >= ci && recordDate < co;
      });

      if (!isStillBooked) {
        await AvailabilityModel.deleteOne({ _id: record._id });
        deletedCount++;
        deletedDetails.push({
          site: record.site,
          date: record.date,
        });
      }
    }

    return res.status(200).json({
      success: true,
      deletedCount,
      deletedDetails,
    });
  });

  submitRefundBankDetails = catchErrors(async (req, res) => {
    const { id } = req.params;
    const userId = req.userId.toString();
    const { cancellInformation } = req.body;

    if (!cancellInformation || !cancellInformation.fullnameGuest || !cancellInformation.bankCode || !cancellInformation.bankType) {
      return res.status(400).json({
        success: false,
        message: "Thiếu thông tin nhận hoàn tiền (Tên, mã ngân hàng hoặc số tài khoản)",
      });
    }

    const booking = await this.bookingService.submitRefundBankDetails(
      id || "",
      userId,
      cancellInformation
    );

    return ResponseUtil.success(
      res,
      BookingDTO.toResponse(booking),
      "Gửi thông tin hoàn tiền thành công"
    );
  });
}
