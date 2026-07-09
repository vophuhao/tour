import { sendMail } from "./send-mail";
import { container, TOKENS } from "@/di";
import type { EmailTemplateService } from "@/services/email-template.service";

/**
 * Gửi email xác nhận đặt chỗ thành công cho khách hàng
 */
export const sendBookingSuccessEmail = async (booking: any) => {
  const guestEmail = booking.email || booking.guest?.email;
  if (!guestEmail) {
    console.error("Không tìm thấy email người nhận cho booking confirmation:", booking.code);
    return { error: "Không tìm thấy email người nhận" };
  }

  const guestName =
    booking.fullnameGuest ||
    booking.guest?.fullName ||
    booking.guest?.name ||
    booking.guest?.username ||
    "Quý khách";

  const propertyName = booking.property?.name || "Khu cắm trại";
  const siteName = booking.site?.name || "Vị trí cắm trại";

  const checkInStr = new Date(booking.checkIn).toLocaleDateString("vi-VN", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const checkOutStr = new Date(booking.checkOut).toLocaleDateString("vi-VN", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const totalAmount = new Intl.NumberFormat("vi-VN", {
    style: "currency",
    currency: "VND",
  }).format(booking.pricing?.total || 0);

  try {
    const emailTemplateService = container.resolve<EmailTemplateService>(TOKENS.EmailTemplateService);
    const html = emailTemplateService.render("booking-success", {
      code: booking.code,
      guestName,
      propertyName,
      siteName,
      checkInStr,
      checkOutStr,
      nights: booking.nights,
      numberOfGuests: booking.numberOfGuests,
      totalAmount,
      currentYear: new Date().getFullYear(),
    });

    return sendMail({
      to: guestEmail,
      subject: `🏕️ Xác nhận đặt chỗ thành công - Mã đặt chỗ #${booking.code}`,
      html,
    });
  } catch (err: any) {
    console.error("Failed to render and send booking success email:", err.message);
    return { error: err.message };
  }
};

/**
 * Gửi email thông báo hủy đặt chỗ cho khách hàng
 */
export const sendBookingCancelledEmail = async (booking: any, reason?: string) => {
  const guestEmail = booking.email || booking.guest?.email;
  if (!guestEmail) {
    console.error("Không tìm thấy email người nhận cho booking cancellation:", booking.code);
    return { error: "Không tìm thấy email người nhận" };
  }

  const guestName =
    booking.fullnameGuest ||
    booking.guest?.fullName ||
    booking.guest?.name ||
    booking.guest?.username ||
    "Quý khách";

  const propertyName = booking.property?.name || "Khu cắm trại";
  const siteName = booking.site?.name || "Vị trí cắm trại";

  const checkInStr = new Date(booking.checkIn).toLocaleDateString("vi-VN", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const checkOutStr = new Date(booking.checkOut).toLocaleDateString("vi-VN", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  try {
    const isPaid = booking.paymentStatus === "paid";
    const cancelSubtitle = isPaid ? "Đã hủy - Chờ thông tin hoàn tiền 100%" : "Hủy bởi đối tác/Chủ trang trại";
    const cancelMessage = isPaid
      ? `Chúng tôi rất tiếc phải thông báo rằng đơn đặt chỗ #${booking.code} của bạn đã bị hủy bởi chủ trang trại/đối tác. Do bạn đã thanh toán trước đó, vui lòng nhấn nút bên dưới hoặc truy cập website của chúng tôi để điền thông tin tài khoản ngân hàng nhận lại tiền hoàn trả 100% tự động.`
      : `Chúng tôi rất tiếc phải thông báo rằng chủ trang trại/đối tác đã hủy đơn đặt chỗ #${booking.code} của bạn.`;

    const emailTemplateService = container.resolve<EmailTemplateService>(TOKENS.EmailTemplateService);
    const html = emailTemplateService.render("booking-cancelled", {
      code: booking.code,
      guestName,
      propertyName,
      siteName,
      checkInStr,
      checkOutStr,
      clientUrl: process.env.CLIENT_URL || "http://localhost:3000",
      currentYear: new Date().getFullYear(),
      cancelSubtitle,
      cancelMessage,
      cancellationReason: reason || "Yêu cầu từ phía đối tác hoặc sự cố bất khả kháng",
    });

    return sendMail({
      to: guestEmail,
      subject: `❌ Thông báo hủy đơn đặt chỗ - Mã đặt chỗ #${booking.code}`,
      html,
    });
  } catch (err: any) {
    console.error("Failed to render and send booking cancellation email:", err.message);
    return { error: err.message };
  }
};

/**
 * Gửi email thông báo hoàn tiền thành công cho khách hàng
 */
export const sendBookingRefundedEmail = async (booking: any) => {
  const guestEmail = booking.email || booking.guest?.email;
  if (!guestEmail) {
    console.error("Không tìm thấy email người nhận cho booking refund:", booking.code);
    return { error: "Không tìm thấy email người nhận" };
  }

  const guestName =
    booking.fullnameGuest ||
    booking.guest?.fullName ||
    booking.guest?.name ||
    booking.guest?.username ||
    "Quý khách";

  const propertyName = booking.property?.name || "Khu cắm trại";
  
  // Extract bank details
  let bankName = "";
  let bankAccountNumber = "";
  let bankAccountName = "";

  if (booking.cancellInformation) {
    bankName = booking.cancellInformation.bankCode || "";
    bankAccountNumber = booking.cancellInformation.bankType || "";
    bankAccountName = booking.cancellInformation.fullnameGuest || "";
  } else if (booking.cannotAttendRequest) {
    bankName = booking.cannotAttendRequest.bankName || "";
    bankAccountNumber = booking.cannotAttendRequest.bankAccountNumber || "";
    bankAccountName = booking.cannotAttendRequest.bankAccountName || "";
  }

  const refundAmountStr = new Intl.NumberFormat("vi-VN", {
    style: "currency",
    currency: "VND",
  }).format(booking.refundAmount || booking.pricing?.total || 0);

  const processedAtStr = new Date().toLocaleDateString("vi-VN", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  try {
    const emailTemplateService = container.resolve<EmailTemplateService>(TOKENS.EmailTemplateService);
    const html = emailTemplateService.render("booking-refunded", {
      code: booking.code,
      guestName,
      propertyName,
      refundAmountStr,
      bankName,
      bankAccountNumber,
      bankAccountName,
      processedAtStr,
      currentYear: new Date().getFullYear(),
    });

    return sendMail({
      to: guestEmail,
      subject: `💸 Xác nhận hoàn tiền thành công - Mã đặt chỗ #${booking.code}`,
      html,
    });
  } catch (err: any) {
    console.error("Failed to render and send booking refunded email:", err.message);
    return { error: err.message };
  }
};

