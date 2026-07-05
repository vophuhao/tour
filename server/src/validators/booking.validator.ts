import { z } from "zod";

// Validator cho tạo booking
export const createBookingSchema = z
  .object({
    property: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid property ID"),

    // Site ID (required)
    site: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid site ID"),

    // Legacy support
    campsite: z
      .string()
      .regex(/^[0-9a-fA-F]{24}$/, "Invalid campsite ID")
      .optional(),

    // Dates
    checkIn: z.string().refine((date) => !isNaN(Date.parse(date)), {
      message: "Invalid check-in date",
    }),
    checkOut: z.string().refine((date) => !isNaN(Date.parse(date)), {
      message: "Invalid check-out date",
    }),

    // Guest details
    numberOfGuests: z.number().int().min(1).max(50),
    numberOfPets: z.number().int().min(0).max(10).default(0),
    numberOfVehicles: z.number().int().min(0).max(20).default(1),
    numberOfUnits: z.number().int().min(1).optional(),

    // Optional message to host
    guestMessage: z.string().max(1000).optional(),

    // Payment method
    paymentMethod: z.enum(["deposit", "full"]),
    fullnameGuest: z.string().max(200),
    phone: z.string().max(20).optional(),
    email: z.string().max(100).optional(),
    promoCodeId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid promoCodeId").optional(),
    comboId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid comboId").optional(),
    services: z
      .array(
        z.object({
          name: z.string(),
          price: z.number().min(0),
          unit: z.string(),
          quantity: z.number().int().min(1),
        })
      )
      .optional(),
  })
  .refine(
    (data) => {
      const checkIn = new Date(data.checkIn);
      const checkOut = new Date(data.checkOut);
      return checkOut > checkIn;
    },
    {
      message: "Check-out date must be after check-in date",
      path: ["checkOut"],
    }
  );

// Validator cho confirm booking (host)
export const confirmBookingSchema = z.object({
  hostMessage: z.string().max(1000).optional(),
});

// Validator cho cancel booking
export const cancelBookingSchema = z.object({
  cancellationReason: z.string().min(0).max(500),
  cancellInformation: z.object({
    fullnameGuest: z.string().max(200),
    bankCode: z.string().max(50),
    bankType: z.string().max(50),
  }).optional(),
});

// Validator cho search bookings
export const searchBookingSchema = z.object({
  // Filter by status
  status: z.enum(["pending", "confirmed", "cancelled", "completed", "refunded"]).optional(),

  // Filter by dates
  checkInFrom: z.string().optional(),
  checkInTo: z.string().optional(),

  // Filter by user role
  role: z.enum(["guest", "host"]).optional(), // xem booking as guest hay host

  // Sorting
  sort: z.enum(["newest", "oldest", "check-in"]).default("newest"),

  // Pagination (coerce string to number for query params)
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

// Validator cho update payment
export const updatePaymentSchema = z.object({
  paymentStatus: z.enum(["pending", "paid", "refunded", "failed"]),
  transactionId: z.string().optional(),
});

// Validator cho refund booking
export const refundBookingSchema = z.object({
  refundAmount: z.number().min(0).optional(), // If not provided, refund full amount
});

export type CreateBookingInput = z.infer<typeof createBookingSchema>;
export type ConfirmBookingInput = z.infer<typeof confirmBookingSchema>;
export type CancelBookingInput = z.infer<typeof cancelBookingSchema>;
export type SearchBookingInput = z.infer<typeof searchBookingSchema>;
export type UpdatePaymentInput = z.infer<typeof updatePaymentSchema>;
export type RefundBookingInput = z.infer<typeof refundBookingSchema>;

// Validator cho yêu cầu hoàn tiền do không hài lòng
export const requestDissatisfactionSchema = z.object({
  reason: z.string().min(10, "Lý do phải tối thiểu 10 ký tự").max(2000),
  phone: z.string().min(1, "Số điện thoại là bắt buộc").max(20),
  email: z.string().email("Email không hợp lệ").max(100),
  bankAccountName: z.string().min(1, "Tên tài khoản là bắt buộc").max(200),
  bankAccountNumber: z.string().min(1, "Số tài khoản là bắt buộc").max(50),
  bankName: z.string().min(1, "Tên ngân hàng là bắt buộc").max(100),
  evidenceImages: z
    .array(z.string().url("Ảnh minh chứng không hợp lệ"))
    .min(5, "Phải cung cấp tối thiểu 5 ảnh minh chứng"),
});

// Validator để admin xử lý yêu cầu không hài lòng
export const processDissatisfactionSchema = z.object({
  status: z.enum(["approved", "rejected"]),
  adminNote: z.string().max(1000).optional(),
});

export type RequestDissatisfactionInput = z.infer<typeof requestDissatisfactionSchema>;
export type ProcessDissatisfactionInput = z.infer<typeof processDissatisfactionSchema>;

