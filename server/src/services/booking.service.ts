import { CLIENT_URL, PAYOS_API_KEY, PAYOS_CHECKSUM_KEY, PAYOS_CLIENT_ID } from "../constants";
import { container, TOKENS } from "@/di";
import { ErrorFactory } from "@/errors";
import {
  AvailabilityModel,
  BookingModel,
  PropertyModel,
  SiteModel,
  type BookingDocument,
} from "@/models";
import appAssert from "../utils/app-assert";
import mongoose from "mongoose";
import type { BookingQueryService } from "./booking-query.service";
import type { BookingNotificationService } from "./booking-notification.service";
import type { CancelBookingInput, CreateBookingInput, RequestDissatisfactionInput, ProcessDissatisfactionInput } from "@/validators/booking.validator";
import { sendMail } from "../utils/send-mail";
import WalletService from "./wallet.service";

const { PayOS } = require("@payos/node");

const payos = new PayOS({
  clientId: PAYOS_CLIENT_ID,
  apiKey: PAYOS_API_KEY,
  checksumKey: PAYOS_CHECKSUM_KEY,
});

export class BookingService {
  private get bookingQueryService() {
    return container.resolve<BookingQueryService>(TOKENS.BookingQueryService);
  }

  private get bookingNotificationService() {
    return container.resolve<BookingNotificationService>(TOKENS.BookingNotificationService);
  }

  /**
   * Create booking (guest book site)
   */
  async createBooking(guestId: string, input: CreateBookingInput): Promise<BookingDocument> {
    const {
      property: propertyId,
      site: siteId,
      campsite: campsiteId,
      checkIn,
      checkOut,
      numberOfGuests,
      numberOfPets,
      numberOfVehicles,
      guestMessage,
      fullnameGuest,
      phone,
      email,
      paymentMethod,
    } = input;

    appAssert(
      siteId || campsiteId,
      ErrorFactory.badRequest("Either site or campsite must be provided")
    );

    const [property, site] = await Promise.all([
      PropertyModel.findById(propertyId),
      siteId ? SiteModel.findById(siteId) : Promise.resolve(null),
    ]);

    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(site, ErrorFactory.resourceNotFound("Site"));
    appAssert(property.isActive, ErrorFactory.badRequest("Property không còn hoạt động"));
    appAssert(site!.isActive, ErrorFactory.badRequest("Site không còn hoạt động"));

    appAssert(
      site!.property.toString() === propertyId,
      ErrorFactory.badRequest("Site không thuộc property này")
    );

    appAssert(
      numberOfGuests <= site.capacity.maxGuests,
      ErrorFactory.badRequest(`Số khách tối đa: ${site.capacity.maxGuests}`)
    );
    if (site.capacity.maxPets !== undefined) {
      appAssert(
        numberOfPets <= site.capacity.maxPets,
        ErrorFactory.badRequest(`Số thú cưng tối đa: ${site.capacity.maxPets}`)
      );
    }
    if (site.capacity.maxVehicles !== undefined) {
      appAssert(
        numberOfVehicles <= site.capacity.maxVehicles,
        ErrorFactory.badRequest(`Số xe tối đa: ${site.capacity.maxVehicles}`)
      );
    }

    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);
    const nights = Math.ceil(
      (checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24)
    );

    checkInDate.setHours(12, 0, 0, 0);
    checkOutDate.setHours(10, 0, 0, 0);

    appAssert(
      nights >= site.bookingSettings.minimumNights,
      ErrorFactory.badRequest(`Tối thiểu ${site.bookingSettings.minimumNights} đêm`)
    );

    if (site.bookingSettings.maximumNights) {
      appAssert(
        nights <= site.bookingSettings.maximumNights,
        ErrorFactory.badRequest(`Tối đa ${site.bookingSettings.maximumNights} đêm`)
      );
    }

    const pricing = this.bookingQueryService.calculatePricing(
      site,
      nights,
      numberOfGuests,
      numberOfPets,
      numberOfVehicles || 0,
      checkInDate,
      checkOutDate
    );

    let payOSOrderCode: number | null = null;
    let payOSCheckoutUrl: string | null = null;
    const code = this.generateBookingCode();
    payOSOrderCode = Math.floor(Date.now() / 1000);
    const amount = 2000;

    try {
      const paymentLink = await payos.paymentRequests.create({
        orderCode: payOSOrderCode,
        amount,
        description: `BOOKING ${code}`,
        returnUrl: `${CLIENT_URL}/bookings/${code}/confirmation`,
        cancelUrl: `${CLIENT_URL}/bookings/cancel`,
      });

      payOSCheckoutUrl =
        paymentLink?.checkoutUrl ||
        paymentLink?.url ||
        paymentLink?.redirectUrl ||
        paymentLink?.data?.checkoutUrl ||
        null;
    } catch (err: any) {
      console.error("Error creating PayOS payment link:", err.message);
    }

    const session = await mongoose.startSession();
    let booking: BookingDocument;

    try {
      await session.withTransaction(async () => {
        const isAvailable = await this.bookingQueryService.checkAvailabilityInSession(
          siteId,
          checkIn,
          checkOut,
          session
        );
        appAssert(isAvailable, ErrorFactory.conflict("Site không có sẵn trong thời gian này (đã được đặt trước)"));

        const [newBooking] = await BookingModel.create(
          [
            {
              code,
              payOSOrderCode,
              payOSCheckoutUrl,
              property: propertyId,
              site: siteId,
              guest: guestId,
              host: property.host,
              checkIn: checkInDate,
              checkOut: checkOutDate,
              nights,
              numberOfGuests,
              numberOfPets,
              numberOfVehicles,
              pricing,
              guestMessage,
              fullnameGuest,
              phone,
              email,
              paymentMethod,
              paymentStatus: "pending",
            },
          ],
          { session }
        );

        appAssert(newBooking, ErrorFactory.internalError("Không thể tạo booking"));
        booking = newBooking;

        await booking.calculateTotal(session);

        if (siteId) {
          const maxConcurrent = site!.capacity.maxConcurrentBookings || 1;
          if (maxConcurrent === 1) {
            await this.blockDatesForBooking(siteId, checkInDate, checkOutDate, session);
          }
        }

        if (site!.bookingSettings.instantBook) {
          await booking.confirm(session);
        }
      });
    } finally {
      await session.endSession();
    }

    try {
      const UserModel = (await import("@/models/user.model")).default;
      const guest = await UserModel.findById(guestId);

      await this.bookingNotificationService.notifyNewBooking(
        property.host.toString(),
        booking!._id!.toString(),
        booking!.code!,
        guest?.username || fullnameGuest || "Khách",
        property.name,
        property._id!.toString(),
        !!site!.bookingSettings.instantBook,
        guestId
      );
    } catch (error) {
      console.error("Failed to send booking notification:", error);
    }

    return booking!;
  }

  private generateBookingCode(): string {
    const now = new Date();
    const day = String(now.getDate()).padStart(2, "0");
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const year = String(now.getFullYear()).slice(-2);
    const random = Math.floor(10000 + Math.random() * 90000);
    return `HDB${day}${month}${year}${random}`;
  }

  /**
   * Confirm booking (host accept)
   */
  async confirmBooking(
    bookingId: string,
    hostId: string,
    hostMessage?: string
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không phải host của booking này")
    );
    appAssert(
      booking.status === "pending",
      ErrorFactory.badRequest("Booking không ở trạng thái pending")
    );

    if (hostMessage) {
      booking.hostMessage = hostMessage;
    }

    await booking.confirm();

    await this.bookingNotificationService.notifyBookingConfirmed(
      booking.guest.toString(),
      bookingId,
      booking.code!,
      hostMessage
    );

    return booking;
  }

  /**
   * Cancel booking (guest or host)
   */
  async cancelBooking(
    bookingId: string,
    userId: mongoose.Types.ObjectId,
    input: CancelBookingInput
  ): Promise<BookingDocument> {
    const booking = await BookingModel.findOne({ code: bookingId });
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));

    const isGuest = booking.guest.toString() === userId.toString();
    const isHost = booking.host.toString() === userId.toString();
    appAssert(isGuest || isHost, ErrorFactory.forbidden("Bạn không có quyền hủy booking này"));

    appAssert(
      booking.status === "pending" || booking.status === "confirmed",
      ErrorFactory.badRequest("Không thể hủy booking này")
    );
    if (input.cancellInformation) {
      booking.cancellInformation = input.cancellInformation;
      await booking.save();
    }

    if (isGuest && booking.paymentStatus === "paid" && input.cancellInformation) {
      const now = new Date();
      const checkIn = new Date(booking.checkIn);
      const diffMs = checkIn.getTime() - now.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);

      let refundRate = 0.5;
      let hostRate = 0.3;
      if (diffDays >= 2) {
        refundRate = 0.7;
        hostRate = 0.2;
      }
      const refundAmount = Math.round(booking.pricing.total * refundRate);
      const hostAmount = Math.round(booking.pricing.total * hostRate);

      booking.cannotAttendRequest = {
        requestedAt: now,
        reason: input.cancellationReason || "Khách yêu cầu hủy đặt chỗ",
        bankAccountName: input.cancellInformation.fullnameGuest || booking.fullnameGuest || "",
        bankAccountNumber: input.cancellInformation.bankType || "",
        bankName: input.cancellInformation.bankCode || "",
        status: "pending",
        refundAmount,
        evidenceImages: [],
      };

      (booking.cannotAttendRequest as any).refundRate = refundRate;
      (booking.cannotAttendRequest as any).hostAmount = hostAmount;
    }

    const session = await mongoose.startSession();
    try {
      await session.withTransaction(async () => {
        await booking.cancel(userId, input.cancellationReason, session);
        await this.unblockDatesForBooking(booking.site.toString(), booking.checkIn, booking.checkOut, session);
      });
    } finally {
      await session.endSession();
    }

    await this.bookingNotificationService.notifyBookingCancelled(
      isGuest,
      booking.host.toString(),
      booking.guest.toString(),
      booking._id.toString(),
      booking.code!,
      booking.property.toString(),
      userId.toString(),
      input.cancellationReason
    );

    return booking;
  }

  /**
   * Complete booking
   */
  async completeBooking(bookingId: string): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(booking.status === "confirmed", ErrorFactory.badRequest("Booking chưa được confirm"));

    if (!booking.walletCredited) {
      const walletService = new WalletService();
      await walletService.creditHostWallet(
        booking.host.toString(),
        booking._id.toString(),
        booking.pricing.total
      );

      const updated = await BookingModel.findById(booking._id);
      if (updated) {
        Object.assign(booking, updated.toObject());
      }
    } else {
      await booking.complete();
    }

    await this.unblockDatesForBooking(booking.site.toString(), booking.checkIn, booking.checkOut);

    await this.bookingNotificationService.notifyGuestCheckedOut(
      booking.host.toString(),
      booking._id.toString(),
      booking.code!,
      booking.fullnameGuest || "Khách",
      booking.property.toString()
    );

    return booking;
  }

  /**
   * Refund booking (admin only)
   */
  async refundBooking(
    bookingId: string,
    userId: string,
    refundAmount?: number
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));

    const UserModel = (await import("@/models/user.model")).default;
    const user = await UserModel.findById(userId).select("role");
    appAssert(
      user?.role === "admin",
      ErrorFactory.forbidden("Chỉ admin mới có quyền refund booking")
    );

    appAssert(
      booking.status === "confirmed" || booking.status === "cancelled" || booking.status === "refund_requested",
      ErrorFactory.badRequest("Không thể refund booking này")
    );

    appAssert(
      booking.paymentStatus === "paid",
      ErrorFactory.badRequest("Booking chưa được thanh toán")
    );

    booking.status = "refunded";
    booking.refundAmount = refundAmount || booking.pricing.total;
    if (booking.refundRequest) {
      booking.refundRequest.status = "approved";
      booking.refundRequest.processedAt = new Date();
      booking.refundRequest.processedBy = new mongoose.Types.ObjectId(userId);
    }
    await booking.save();

    await this.unblockDatesForBooking(booking.site.toString(), booking.checkIn, booking.checkOut);

    return booking;
  }

  /**
   * User cancel payment
   */
  async userCancelPayment(orderCode: string) {
    console.log("User cancel payment for orderCode:", orderCode);
    const booking = await BookingModel.findOne({ payOSOrderCode: orderCode });
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));

    if (!booking.code) {
      console.log("No booking found for orderCode:", orderCode);
      return {
        success: false,
        message: "No booking found for the provided order code",
      };
    }
    const bookingId = booking.code.toString();
    await this.cancelBooking(bookingId, booking.guest as mongoose.Types.ObjectId, {
      cancellationReason: "User cancelled payment",
    });
    await booking.deleteOne();
    return {
      success: true,
      message: "Booking payment cancelled and booking removed",
    };
  }

  /**
   * Guest confirm arrival
   */
  async guestConfirmArrival(
    bookingId: string,
    guestId: string
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query)
      .populate("property", "name")
      .lean();
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.guest.toString() === guestId,
      ErrorFactory.forbidden("Bạn không phải khách của booking này")
    );
    appAssert(
      booking.status === "confirmed",
      ErrorFactory.badRequest("Booking phải ở trạng thái đã xác nhận")
    );
    appAssert(
      booking.paymentStatus === "paid",
      ErrorFactory.badRequest("Booking chưa được thanh toán")
    );
    appAssert(
      !booking.guestConfirmedAttendance,
      ErrorFactory.badRequest("Đã xác nhận đến rồi")
    );
    appAssert(
      !booking.walletCredited,
      ErrorFactory.badRequest("Tiền đã được chuyển vào ví")
    );

    const now = new Date();
    const checkIn = new Date(booking.checkIn);
    const checkOut = new Date(booking.checkOut);
    const deadline = new Date(checkOut.getTime() + 5 * 24 * 60 * 60 * 1000);

    appAssert(
      now >= checkIn,
      ErrorFactory.badRequest(
        `Chưa đến thời gian check-in (${checkIn.toLocaleDateString("vi-VN")})`
      )
    );
    appAssert(
      now <= deadline,
      ErrorFactory.badRequest("Thời gian xác nhận đã hết hạn")
    );

    const walletService = new WalletService();
    await walletService.creditHostWallet(
      booking.host.toString(),
      booking._id.toString(),
      booking.pricing.total
    );

    const updated = await BookingModel.findByIdAndUpdate(
      booking._id,
      { guestConfirmedAttendance: true, guestConfirmedAt: now },
      { new: true }
    );

    return updated!;
  }

  /**
   * Guest cannot attend
   */
  async guestCannotAttend(
    bookingId: string,
    guestId: string,
    input: {
      reason: string;
      bankAccountName: string;
      bankAccountNumber: string;
      bankName: string;
      evidenceImages?: string[];
    }
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.guest.toString() === guestId,
      ErrorFactory.forbidden("Bạn không phải khách của booking này")
    );
    appAssert(
      booking.status === "confirmed",
      ErrorFactory.badRequest("Booking phải ở trạng thái đã xác nhận")
    );
    appAssert(
      booking.paymentStatus === "paid",
      ErrorFactory.badRequest("Booking chưa được thanh toán")
    );
    appAssert(
      !booking.cannotAttendRequest,
      ErrorFactory.badRequest("Đã gửi yêu cầu không đến trước đó rồi")
    );
    appAssert(
      !booking.walletCredited,
      ErrorFactory.badRequest("Tiền đã được xử lý")
    );

    const now = new Date();
    const checkIn = new Date(booking.checkIn);
    const diffMs = checkIn.getTime() - now.getTime();
    const diffDays = diffMs / (1000 * 60 * 60 * 24);

    let refundRate = 0.5;
    let hostRate = 0.3;
    if (diffDays >= 2) {
      refundRate = 0.7;
      hostRate = 0.2;
    }
    const refundAmount = Math.round(booking.pricing.total * refundRate);
    const hostAmount = Math.round(booking.pricing.total * hostRate);

    booking.cannotAttendRequest = {
      requestedAt: now,
      reason: input.reason,
      bankAccountName: input.bankAccountName,
      bankAccountNumber: input.bankAccountNumber,
      bankName: input.bankName,
      evidenceImages: input.evidenceImages ?? [],
      status: "pending",
      refundAmount,
    };
    (booking.cannotAttendRequest as any).refundRate = refundRate;
    (booking.cannotAttendRequest as any).hostAmount = hostAmount;

    booking.status = "cancelled";

    await AvailabilityModel.deleteMany({ booking: booking._id });

    try {
      const UserModel = (await import("@/models/user.model")).default;
      const guest = await UserModel.findById(guestId);
      const property = await PropertyModel.findById(booking.property);

      await this.bookingNotificationService.notifyBookingCancelled(
        true,
        booking.host.toString(),
        booking.guest.toString(),
        booking._id.toString(),
        booking.code!,
        booking.property.toString(),
        guestId,
        input.reason
      );
    } catch (error) {
      console.error("Failed to send cancellation notification to host:", error);
    }

    await booking.save();
    return booking;
  }

  /**
   * Admin process cannot attend
   */
  async adminProcessCannotAttend(
    bookingId: string,
    adminId: string,
    approved: boolean,
    adminNote?: string
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.cannotAttendRequest,
      ErrorFactory.badRequest("Booking này chưa có yêu cầu không đến")
    );
    appAssert(
      booking.cannotAttendRequest!.status === "pending",
      ErrorFactory.badRequest("Yêu cầu này đã được xử lý rồi")
    );

    const now = new Date();

    if (approved) {
      const requestedAt = new Date(booking.cannotAttendRequest!.requestedAt);
      const checkIn = new Date(booking.checkIn);
      const diffMs = checkIn.getTime() - requestedAt.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);

      let refundRate = 0.5;
      let hostRate = 0.3;
      if (diffDays >= 2) {
        refundRate = 0.7;
        hostRate = 0.2;
      }
      const refundAmount = Math.round(booking.pricing.total * refundRate);
      const hostAmount = Math.round(booking.pricing.total * hostRate);

      const walletService = new WalletService();
      await walletService.creditHostWalletCannotAttend(
        booking.host.toString(),
        booking._id.toString(),
        booking.pricing.total,
        hostRate
      );

      booking.cannotAttendRequest!.status = "approved";
      booking.cannotAttendRequest!.refundAmount = refundAmount;
      booking.cannotAttendRequest!.processedAt = now;
      booking.cannotAttendRequest!.processedBy = new mongoose.Types.ObjectId(adminId);
      if (adminNote) booking.cannotAttendRequest!.adminNote = adminNote;
      booking.refundAmount = refundAmount;
      booking.status = "refunded";

      try {
        const property = await PropertyModel.findById(booking.property);
        await this.bookingNotificationService.notifyCannotAttendApproved(
          booking.host.toString(),
          booking._id.toString(),
          booking.code!,
          property?.name || "",
          hostAmount,
          hostRate,
          refundAmount,
          refundRate
        );
      } catch (err) {
        console.error("Failed to send cannot-attend notification to host:", err);
      }
    } else {
      const walletService = new WalletService();
      await walletService.creditHostWalletCannotAttend(
        booking.host.toString(),
        booking._id.toString(),
        booking.pricing.total,
        0.8 // Host receives 80%, platform retains 20% as per user request
      );

      booking.cannotAttendRequest!.status = "rejected";
      booking.cannotAttendRequest!.processedAt = now;
      booking.cannotAttendRequest!.processedBy = new mongoose.Types.ObjectId(adminId);
      if (adminNote) booking.cannotAttendRequest!.adminNote = adminNote;
      booking.status = "cancelled";
    }

    await booking.save();
    return booking;
  }

  /**
   * Khách gửi yêu cầu hoàn tiền do không hài lòng với cơ sở vật chất (12 tiếng sau check-in)
   */
  async requestRefund(
    bookingId: string,
    userId: string,
    reason: string
  ): Promise<BookingDocument> {
    const booking = await BookingModel.findOne({ code: bookingId });
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.guest.toString() === userId,
      ErrorFactory.forbidden("Bạn không có quyền yêu cầu hoàn tiền")
    );
    appAssert(
      booking.status === "confirmed" || booking.status === "completed",
      ErrorFactory.badRequest("Không thể yêu cầu hoàn tiền cho booking này")
    );
    appAssert(
      booking.paymentStatus === "paid",
      ErrorFactory.badRequest("Booking chưa được thanh toán")
    );
    appAssert(
      !booking.refundRequest || booking.refundRequest.status === "rejected",
      ErrorFactory.badRequest("Đã có yêu cầu hoàn tiền đang chờ xử lý")
    );

    booking.status = "refund_requested";
    booking.refundRequest = {
      requestedAt: new Date(),
      reason,
      requestedBy: new mongoose.Types.ObjectId(userId),
      status: "pending",
    };
    await booking.save();

    return booking;
  }

  /**
   * Admin xử lý yêu cầu hoàn tiền
   */
  async adminProcessRefund(
    bookingId: string,
    adminId: string,
    approved: boolean,
    adminNote?: string,
    refundAmount?: number
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.refundRequest?.status === "pending",
      ErrorFactory.badRequest("Không có yêu cầu hoàn tiền đang chờ")
    );

    if (approved) {
      booking.status = "refunded";
      booking.refundAmount = refundAmount || booking.pricing.total;
      booking.refundRequest!.status = "approved";
      await this.unblockDatesForBooking(booking.site.toString(), booking.checkIn, booking.checkOut);
    } else {
      booking.status = "confirmed";
      booking.refundRequest!.status = "rejected";
    }

    booking.refundRequest!.processedAt = new Date();
    booking.refundRequest!.processedBy = new mongoose.Types.ObjectId(adminId);
    if (adminNote) booking.refundRequest!.adminNote = adminNote;

    await booking.save();
    return booking;
  }

  /**
   * Admin hủy booking
   */
  async adminCancelBooking(
    bookingId: string,
    adminId: string,
    reason?: string
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.status === "pending" || booking.status === "confirmed",
      ErrorFactory.badRequest("Không thể hủy booking này")
    );

    booking.status = "cancelled";
    booking.cancelledBy = new mongoose.Types.ObjectId(adminId);
    booking.cancelledAt = new Date();
    if (reason) booking.cancellationReason = reason;
    await booking.save();

    await this.unblockDatesForBooking(booking.site.toString(), booking.checkIn, booking.checkOut);

    return booking;
  }

  /**
   * Guest dissatisfied check-in request
   */
  async requestDissatisfaction(
    guestId: string,
    bookingId: string,
    input: RequestDissatisfactionInput
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query);
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.guest.toString() === guestId,
      ErrorFactory.forbidden("Bạn không phải khách của booking này")
    );
    appAssert(
      booking.status === "confirmed",
      ErrorFactory.badRequest("Booking phải ở trạng thái đã xác nhận")
    );
    appAssert(
      booking.paymentStatus === "paid",
      ErrorFactory.badRequest("Booking chưa được thanh toán")
    );
    appAssert(
      !booking.dissatisfactionRequest,
      ErrorFactory.badRequest("Bạn đã gửi yêu cầu hoàn tiền không hài lòng trước đó rồi")
    );

    const now = new Date();
    const checkInTime = new Date(booking.checkIn);
    const windowEnd = new Date(checkInTime.getTime() + 12 * 60 * 60 * 1000);
    appAssert(
      now >= checkInTime && now <= windowEnd,
      ErrorFactory.badRequest(
        "Yêu cầu hoàn tiền không hài lòng chỉ được gửi trong vòng 12 tiếng sau khi check-in"
      )
    );

    booking.dissatisfactionRequest = {
      requestedAt: now,
      reason: input.reason,
      phone: input.phone,
      email: input.email,
      bankAccountName: input.bankAccountName,
      bankAccountNumber: input.bankAccountNumber,
      bankName: input.bankName,
      evidenceImages: input.evidenceImages,
      status: "pending",
    };
    booking.status = "refund_requested";
    await booking.save();

    return booking;
  }

  /**
   * Process dissatisfaction
   */
  async processDissatisfaction(
    adminId: string,
    bookingId: string,
    input: ProcessDissatisfactionInput
  ): Promise<BookingDocument> {
    const query = mongoose.Types.ObjectId.isValid(bookingId)
      ? { $or: [{ _id: bookingId }, { code: bookingId }] }
      : { code: bookingId };
    const booking = await BookingModel.findOne(query).populate("guest", "name email");
    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));
    appAssert(
      booking.dissatisfactionRequest,
      ErrorFactory.badRequest("Booking này chưa có yêu cầu hoàn tiền không hài lòng")
    );
    appAssert(
      booking.dissatisfactionRequest!.status === "pending",
      ErrorFactory.badRequest("Yêu cầu này đã được xử lý rồi")
    );

    const now = new Date();
    const guest = booking.guest as any;
    const refundAmount = booking.pricing.total;

    booking.dissatisfactionRequest!.status = input.status;
    booking.dissatisfactionRequest!.adminNote = input.adminNote;
    booking.dissatisfactionRequest!.processedAt = now;
    booking.dissatisfactionRequest!.processedBy = new mongoose.Types.ObjectId(adminId);

    if (input.status === "approved") {
      booking.dissatisfactionRequest!.refundAmount = refundAmount;
      booking.status = "refunded";
      booking.paymentStatus = "refunded";
      booking.refundAmount = refundAmount;

      try {
        await sendMail({
          to: booking.dissatisfactionRequest!.email || guest?.email,
          subject: "[Cam Trại] Yêu cầu hoàn tiền đã được chấp nhận",
          html: `
            <div style="font-family:sans-serif;max-width:600px;margin:auto;padding:24px;background:#f9fafb;border-radius:12px">
              <h2 style="color:#059669">✅ Yêu cầu hoàn tiền đã được chấp nhận</h2>
              <p>Xin chào <strong>${guest?.name || booking.fullnameGuest || "Quý khách"}</strong>,</p>
              <p>Chúng tôi đã xem xét và <strong>chấp nhận</strong> yêu cầu hoàn tiền do không hài lòng của bạn đối với booking <strong>#${booking.code}</strong>.</p>
              <div style="background:#ecfdf5;border-radius:8px;padding:16px;margin:16px 0">
                <p style="margin:0">💰 <strong>Số tiền hoàn:</strong> ${new Intl.NumberFormat("vi-VN", { style: "currency", currency: "VND" }).format(refundAmount)}</p>
                <p style="margin:4px 0 0">🏦 <strong>Tài khoản nhận:</strong> ${booking.dissatisfactionRequest!.bankAccountNumber} - ${booking.dissatisfactionRequest!.bankName}</p>
                <p style="margin:4px 0 0">👤 <strong>Chủ tài khoản:</strong> ${booking.dissatisfactionRequest!.bankAccountName}</p>
              </div>
              ${input.adminNote ? `<p><strong>Ghi chú từ admin:</strong> ${input.adminNote}</p>` : ""}
              <p>Tiền sẽ được chuyển về tài khoản của bạn trong vòng 3-5 ngày làm việc.</p>
              <p style="color:#6b7280;font-size:14px">Cảm ơn bạn đã sử dụng dịch vụ của chúng tôi!</p>
            </div>
          `,
        });
      } catch (e) {
        console.error("Lỗi gửi mail chấp nhận hoàn tiền:", e);
      }
    } else {
      booking.status = "confirmed";

      try {
        await sendMail({
          to: booking.dissatisfactionRequest!.email || guest?.email,
          subject: "[Cam Trại] Yêu cầu hoàn tiền không được chấp nhận",
          html: `
            <div style="font-family:sans-serif;max-width:600px;margin:auto;padding:24px;background:#f9fafb;border-radius:12px">
              <h2 style="color:#dc2626">❌ Yêu cầu hoàn tiền không được chấp nhận</h2>
              <p>Xin chào <strong>${guest?.name || booking.fullnameGuest || "Quý khách"}</strong>,</p>
              <p>Rất tiếc, sau khi xem xét, chúng tôi <strong>không thể chấp nhận</strong> yêu cầu hoàn tiền của bạn đối với booking <strong>#${booking.code}</strong>.</p>
              ${input.adminNote ? `<div style="background:#fef2f2;border-radius:8px;padding:16px;margin:16px 0"><p style="margin:0"><strong>Lý do:</strong> ${input.adminNote}</p></div>` : ""}
              <p>Nếu bạn có thắc mắc, vui lòng liên hệ bộ phận hỗ trợ của chúng tôi.</p>
              <p style="color:#6b7280;font-size:14px">Cảm ơn bạn đã sử dụng dịch vụ của chúng tôi!</p>
            </div>
          `,
        });
      } catch (e) {
        console.error("Lỗi gửi mail từ chối hoàn tiền:", e);
      }
    }

    await booking.save();
    return booking;
  }

  /**
   * Block dates in availability calendar when booking is created
   */
  private async blockDatesForBooking(
    siteId: string,
    checkIn: Date,
    checkOut: Date,
    session: mongoose.ClientSession | null = null
  ): Promise<void> {
    const dates: Date[] = [];
    const currentDate = new Date(checkIn);

    while (currentDate <= checkOut) {
      dates.push(new Date(currentDate));
      currentDate.setDate(currentDate.getDate() + 1);
    }

    const availabilityRecords = dates.map((date) => ({
      site: new mongoose.Types.ObjectId(siteId),
      date,
      isAvailable: false,
      blockType: "booked" as const,
      reason: "Đã được đặt",
    }));

    const bulkOps = availabilityRecords.map((record) => ({
      updateOne: {
        filter: { site: record.site, date: record.date },
        update: { $set: record },
        upsert: true,
      },
    }));

    if (bulkOps.length > 0) {
      const options = session ? { session } : {};
      await AvailabilityModel.bulkWrite(bulkOps, options);
    }
  }

  /**
   * Unblock dates when booking is cancelled/completed
   */
  private async unblockDatesForBooking(
    siteId: string,
    checkIn: Date,
    checkOut: Date,
    session: mongoose.ClientSession | null = null
  ): Promise<void> {
    const options = session ? { session } : {};
    await AvailabilityModel.deleteMany({
      site: siteId,
      date: { $gte: checkIn, $lte: checkOut },
      blockType: "booked",
    }, options);
  }
}
