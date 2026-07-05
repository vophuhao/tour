import { BookingModel, AvailabilityModel, SiteModel } from "@/models";
import { sendMail } from "../utils/send-mail";
import { CLIENT_URL } from "../constants";
import { container, TOKENS } from "@/di";
import type { BookingService } from "./booking.service";
import type { EmailTemplateService } from "./email-template.service";
import mongoose from "mongoose";

export class BookingLifecycleService {
  private get emailTemplateService(): EmailTemplateService {
    return container.resolve<EmailTemplateService>(TOKENS.EmailTemplateService);
  }

  /**
   * Auto cancel expired pending bookings and send reminder emails
   */
  async cancelExpiredPendingBookings() {
    const REMINDER_HOURS = 6;
    const CANCEL_HOURS = 12;

    const now = new Date();
    const reminderTime = new Date(now.getTime() - REMINDER_HOURS * 60 * 60 * 1000);
    const cancelTime = new Date(now.getTime() - CANCEL_HOURS * 60 * 60 * 1000);

    // 1) REMINDER EMAIL
    const bookingsNeedReminder = await BookingModel.find({
      paymentStatus: "pending",
      createdAt: { $lt: reminderTime, $gte: cancelTime },
      reminderSent: { $ne: true },
    })
      .populate("guest", "username email fullName")
      .populate("site", "name")
      .populate("property", "name");

    for (const booking of bookingsNeedReminder) {
      try {
        const guestEmail = booking.email || (booking.guest as any)?.email;
        const guestName =
          booking.fullnameGuest ||
          (booking.guest as any)?.fullName ||
          (booking.guest as any)?.username ||
          "Quý khách";
        const propertyName = (booking.property as any)?.name || "Khu cắm trại";
        const siteName = (booking.site as any)?.name || "Site";
        const totalAmount = (booking.pricing?.total || 0).toLocaleString("vi-VN");
        const checkoutUrl =
          booking.payOSCheckoutUrl || `${CLIENT_URL}/bookings/${booking.code}/confirmation`;

        if (!booking.isSentMail) {
          const html = this.emailTemplateService.render("booking-reminder", {
            guestName,
            code: booking.code,
            siteName,
            propertyName,
            checkInStr: new Date(booking.checkIn).toLocaleDateString("vi-VN"),
            checkOutStr: new Date(booking.checkOut).toLocaleDateString("vi-VN"),
            nights: booking.nights,
            numberOfGuests: booking.numberOfGuests,
            totalAmount,
            checkoutUrl,
            currentYear: new Date().getFullYear(),
          });

          await sendMail({
            to: guestEmail,
            subject: "⏰ Nhắc nhở hoàn tất thanh toán booking",
            html,
          });
          booking.isSentMail = true;
          await booking.save();
        }

        await BookingModel.updateOne({ _id: booking._id }, { $set: { reminderSent: true } });
        console.log(`📧 Đã gửi email nhắc nhở thanh toán: Booking ${booking.code} đến ${guestEmail}`);
      } catch (err) {
        console.error(`❌ Lỗi gửi email nhắc nhở Booking ${booking.code}:`, err);
      }
    }

    // 2) CANCEL EXPIRED
    const expiredBookings = await BookingModel.find({
      paymentStatus: "pending",
      status: { $in: ["pending", "confirmed"] },
      createdAt: { $lt: cancelTime },
    })
      .populate("guest", "username email fullName")
      .populate("site", "name")
      .populate("property", "name");

    const bookingService = container.resolve<BookingService>(TOKENS.BookingService);

    for (const booking of expiredBookings) {
      try {
        await bookingService.cancelBooking(
          booking.code!,
          (booking.guest as any)?._id || booking.guest,
          { cancellationReason: "Auto-cancelled: Payment timeout after 12 hours" }
        );

        console.log(`⛔ Đã tự động hủy booking quá hạn 12h: ${booking.code}`);

        try {
          const guestEmail = booking.email || (booking.guest as any)?.email;
          const guestName =
            booking.fullnameGuest ||
            (booking.guest as any)?.fullName ||
            (booking.guest as any)?.username ||
            "Quý khách";
          const propertyName = (booking.property as any)?.name || "Khu cắm trại";
          const siteName = (booking.site as any)?.name || "Site";

          const html = this.emailTemplateService.render("booking-cancelled", {
            guestName,
            code: booking.code,
            siteName,
            propertyName,
            checkInStr: new Date(booking.checkIn).toLocaleDateString("vi-VN"),
            checkOutStr: new Date(booking.checkOut).toLocaleDateString("vi-VN"),
            clientUrl: CLIENT_URL,
            currentYear: new Date().getFullYear(),
          });

          await sendMail({
            to: guestEmail,
            subject: "❌ Booking đã bị hủy do quá thời gian thanh toán",
            html,
          });
          console.log(`📧 Đã gửi email thông báo hủy booking: ${booking.code} đến ${guestEmail}`);
        } catch (emailErr) {
          console.error(`❌ Lỗi gửi email thông báo hủy Booking ${booking.code}:`, emailErr);
        }
      } catch (err) {
        console.error(`❌ Lỗi khi tự động hủy booking ${booking.code}:`, err);
      }
    }

    return {
      remindersSent: bookingsNeedReminder.length,
      bookingsCancelled: expiredBookings.length,
    };
  }

  /**
   * Auto complete bookings after checkout date or 3 days after check-in
   */
  async autoCompleteBooking() {
    try {
      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);

      const bookingsToComplete = await BookingModel.find({
        status: "confirmed",
        paymentStatus: "paid",
        checkIn: { $lte: threeDaysAgo },
      })
        .populate("guest", "username email fullName")
        .populate("site", "name")
        .populate("property", "name");

      if (bookingsToComplete.length === 0) {
        console.log("✅ Không có booking nào cần hoàn thành");
        return { completed: 0 };
      }

      let completedCount = 0;
      const bookingService = container.resolve<BookingService>(TOKENS.BookingService);

      for (const booking of bookingsToComplete) {
        try {
          await bookingService.completeBooking(booking._id.toString());
          completedCount++;
          console.log(`✅ Đã tự động hoàn thành booking: ${booking.code}`);

          try {
            const guestEmail = booking.email || (booking.guest as any)?.email;
            const guestName =
              booking.fullnameGuest ||
              (booking.guest as any)?.fullName ||
              (booking.guest as any)?.username ||
              "Quý khách";
            const propertyName = (booking.property as any)?.name || "Khu cắm trại";
            const siteName = (booking.site as any)?.name || "Site";

            const html = this.emailTemplateService.render("booking-completed", {
              guestName,
              siteName,
              propertyName,
              code: booking.code,
              checkInStr: new Date(booking.checkIn).toLocaleDateString("vi-VN"),
              checkOutStr: new Date(booking.checkOut).toLocaleDateString("vi-VN"),
              nights: booking.nights,
              numberOfGuests: booking.numberOfGuests,
              clientUrl: CLIENT_URL,
              currentYear: new Date().getFullYear(),
            });

            await sendMail({
              to: guestEmail,
              subject: "🎉 Chuyến đi của bạn đã hoàn thành - Cảm ơn bạn!",
              html,
            });
            console.log(`📧 Đã gửi email hoàn thành booking: ${booking.code} đến ${guestEmail}`);
          } catch (emailErr) {
            console.error(`❌ Lỗi gửi email hoàn thành Booking ${booking.code}:`, emailErr);
          }
        } catch (err) {
          console.error(`❌ Lỗi khi tự động hoàn thành booking ${booking.code}:`, err);
        }
      }

      return {
        completed: completedCount,
        total: bookingsToComplete.length,
      };
    } catch (error) {
      console.error("❌ Lỗi trong autoCompleteBooking:", error);
      throw error;
    }
  }

  /**
   * Auto settle payments to Host wallet after 5 days without guest confirmation
   */
  async autoSettleExpiredBookings() {
    const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);

    const expiredBookings = await BookingModel.find({
      status: "confirmed",
      paymentStatus: "paid",
      guestConfirmedAttendance: { $ne: true },
      walletCredited: { $ne: true },
      cannotAttendRequest: { $exists: false },
      checkIn: { $lte: fiveDaysAgo },
    });

    const WalletService = (await import("./wallet.service")).default;
    const walletService = new WalletService();
    let settled = 0;

    for (const booking of expiredBookings) {
      try {
        await walletService.creditHostWalletAutoSettle(
          booking.host.toString(),
          (booking._id as mongoose.Types.ObjectId).toString(),
          booking.pricing.total
        );
        await BookingModel.findByIdAndUpdate(booking._id, {
          guestConfirmedAttendance: false,
          walletCredited: true,
          status: "completed",
        });
        settled++;
      } catch (err) {
        console.error(`❌ Lỗi auto-settle booking ${booking._id}:`, err);
      }
    }

    return { settled, total: expiredBookings.length };
  }

  /**
   * Auto cancel unpaid bookings on checking day
   */
  async cancelUnpaidBookingsOnCheckinDay() {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const endOfDay = new Date(today);
    endOfDay.setHours(23, 59, 59, 999);

    const unpaidBookings = await BookingModel.find({
      paymentStatus: { $ne: "paid" },
      checkIn: { $lte: endOfDay },
      status: { $nin: ["cancelled", "completed", "refunded"] },
    });

    let cancelled = 0;
    for (const booking of unpaidBookings) {
      try {
        const site = await SiteModel.findById(booking.site);
        const maxConcurrent = site?.capacity?.maxConcurrentBookings || 1;

        if (maxConcurrent === 1) {
          const start = new Date(booking.checkIn);
          start.setHours(0, 0, 0, 0);
          const end = new Date(booking.checkOut);
          end.setHours(0, 0, 0, 0);

          await AvailabilityModel.deleteMany({
            site: booking.site,
            date: { $gte: start, $lt: end },
            blockType: "booked",
          });
        }

        booking.status = "cancelled";
        booking.cancellationReason = "Auto-cancelled: Unpaid booking on check-in day";
        booking.cancelledAt = new Date();
        await booking.save();
        cancelled++;
      } catch (err) {
        console.error(`❌ Lỗi hủy booking chưa thanh toán ${booking._id}:`, err);
      }
    }

    return { cancelled, total: unpaidBookings.length };
  }
}
