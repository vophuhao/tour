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
