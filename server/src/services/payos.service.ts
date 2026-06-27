import { createHmac } from "crypto";
import { ErrorFactory } from "@/errors";
import { BookingModel } from "@/models";
import appAssert from "../utils/app-assert";
import { sendBookingSuccessEmail } from "../utils/send-booking-email";
import { PAYOS_CHECKSUM_KEY } from "../constants";
import { notifyPropertyChange } from "../socket";

/**
 * Verify PayOS webhook signature using HMAC-SHA256
 * Tài liệu: https://payos.vn/docs/webhook
 */
export function verifyPayOSSignature(data: Record<string, any>, receivedSignature: string): boolean {
  try {
    // Sắp xếp keys theo alphabet và tạo chuỗi key=value&...
    const sortedKeys = Object.keys(data).sort();
    const dataString = sortedKeys
      .map((key) => `${key}=${data[key]}`)
      .join("&");

    const expectedSignature = createHmac("sha256", PAYOS_CHECKSUM_KEY)
      .update(dataString)
      .digest("hex");

    return expectedSignature === receivedSignature;
  } catch {
    return false;
  }
}

export default class PayOSService {
  constructor() {}

  async handlePayOS(rawBody: any, signature?: string) {
    // ============================================================
    // SECURITY: Verify webhook signature trước khi xử lý
    // Ngăn chặn kẻ tấn công fake webhook PAID
    // ============================================================
    appAssert(signature, ErrorFactory.forbidden("Missing PayOS webhook signature"));

    const webhookData = rawBody.data || {};
    const isValid = verifyPayOSSignature(webhookData, signature);
    appAssert(isValid, ErrorFactory.forbidden("Invalid PayOS webhook signature"));

    const description: string = rawBody.data?.description || "";
    const isBooking = description.includes("BOOKING");

    if (isBooking) {
      return this.handleBookingWebhook(rawBody);
    }

    // Có thể mở rộng thêm các loại webhook khác ở đây
    return { success: true, code: "UNHANDLED_TYPE", message: "Webhook type not handled" };
  }

  /**
   * Xử lý webhook cho booking thanh toán
   */
  private async handleBookingWebhook(data: any) {
    try {
      const orderCode = data.data?.orderCode;
      const status = data.data?.status;
      const success = status === "PAID" || data.success === true;

      appAssert(orderCode, ErrorFactory.badRequest("Thiếu orderCode trong webhook"));

      const booking = await BookingModel.findOne({ payOSOrderCode: orderCode })
        .populate("property", "name location")
        .populate("site", "name")
        .populate("guest", "username email fullName name");

      appAssert(booking, ErrorFactory.resourceNotFound("Booking"));

      if (success) {
        booking.paymentStatus = "paid";
        booking.paidAt = new Date(); // Set đúng thời điểm thanh toán thành công
        await booking.save();

        // Gửi email xác nhận đặt chỗ cho khách hàng
        try {
          await sendBookingSuccessEmail(booking);
        } catch (mailErr) {
          console.error("Lỗi khi gửi email xác nhận đặt chỗ:", mailErr);
        }

        notifyPropertyChange(booking.property._id.toString());

        return {
          success: true,
          code: "PAYMENT_SUCCESS",
          message: "Thanh toán thành công",
          bookingCode: booking.code,
        };
      } else {
        booking.paymentStatus = "failed";
        await booking.save();

        notifyPropertyChange(booking.property._id.toString());

        return {
          success: false,
          code: "PAYMENT_FAILED",
          message: "Thanh toán thất bại",
          bookingCode: booking.code,
        };
      }
    } catch (err: any) {
      console.error("Error handling PayOS booking webhook:", err.message);
      return { success: false, code: "WEBHOOK_ERROR", message: err.message };
    }
  }
}