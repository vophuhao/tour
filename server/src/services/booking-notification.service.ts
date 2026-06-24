import { container, TOKENS } from "@/di";
import NotificationService from "./notification.service";
import { PropertyModel } from "@/models";
import mongoose from "mongoose";

export class BookingNotificationService {
  private get notificationService() {
    return container.resolve<NotificationService>(TOKENS.NotificationService);
  }

  async notifyNewBooking(
    hostId: string,
    bookingId: string,
    bookingCode: string,
    guestName: string,
    propertyName: string,
    propertyId: string,
    instantBook: boolean,
    guestId: string
  ) {
    try {
      await this.notificationService.createNewBookingForHost(
        hostId,
        bookingId,
        bookingCode,
        guestName,
        propertyName,
        propertyId
      );

      if (instantBook) {
        await this.notificationService.createBookingNotification(
          guestId,
          bookingId,
          bookingCode,
          "booking_confirmed"
        );
      }
    } catch (error) {
      console.error("Failed to send new booking notification:", error);
    }
  }

  async notifyBookingConfirmed(bookingGuestId: string, bookingId: string, bookingCode: string, hostMessage?: string) {
    try {
      await this.notificationService.createBookingNotification(
        bookingGuestId,
        bookingId,
        bookingCode,
        "booking_confirmed",
        hostMessage
      );
    } catch (error) {
      console.error("Failed to send booking confirmation notification:", error);
    }
  }

  async notifyBookingCancelled(
    isGuest: boolean,
    bookingHostId: string,
    bookingGuestId: string,
    bookingId: string,
    bookingCode: string,
    propertyId: string,
    userId: string,
    cancellationReason?: string
  ) {
    try {
      const UserModel = (await import("@/models/user.model")).default;
      const property = await PropertyModel.findById(propertyId);

      if (isGuest) {
        const guest = await UserModel.findById(userId);
        await this.notificationService.createGuestCancelledForHost(
          bookingHostId,
          bookingId,
          bookingCode,
          guest?.username || "Khách",
          property?.name || "Khu cắm trại",
          cancellationReason
        );
      } else {
        await this.notificationService.createBookingNotification(
          bookingGuestId,
          bookingId,
          bookingCode,
          "booking_cancelled",
          `Booking đã bị hủy bởi host${cancellationReason ? `: ${cancellationReason}` : ""}`
        );
      }
    } catch (error) {
      console.error("Failed to send cancellation notification:", error);
    }
  }

  async notifyGuestCheckedOut(bookingHostId: string, bookingId: string, bookingCode: string, guestName: string, propertyId: string) {
    try {
      const property = await PropertyModel.findById(propertyId);
      await this.notificationService.createGuestCheckedOutForHost(
        bookingHostId,
        bookingId,
        bookingCode,
        guestName,
        property?.name || "Khu cắm trại"
      );
    } catch (error) {
      console.error("Failed to send check-out notification to host:", error);
    }
  }

  async notifyCannotAttendApproved(bookingHostId: string, bookingId: string, bookingCode: string, propertyName: string, hostAmount: number, hostRate: number, refundAmount: number, refundRate: number) {
    try {
      await this.notificationService.createNotification({
        recipient: bookingHostId,
        type: "booking_cancelled",
        title: "Khách không đến — Đã xác nhận hoàn tiền",
        message: `Booking #${bookingCode} (${propertyName}): Khách không đến, bạn đã nhận ${hostAmount.toLocaleString("vi-VN")}₫ (${Math.round(hostRate * 100)}%) vào ví.`,
        booking: bookingId,
        link: `/host/bookings/${bookingId}`,
        actionType: "view_booking",
        priority: "high",
        role: "host",
        metadata: { bookingCode, hostAmount, refundAmount, refundRate },
      });
    } catch (err) {
      console.error("Failed to send cannot-attend notification to host:", err);
    }
  }
}
