import mongoose from "mongoose";

// Booking/Reservation model
export interface BookingDocument extends mongoose.Document {
  // Reference
  code?: string; // mã đặt chỗ
  property: mongoose.Types.ObjectId; // Reference to Property
  site: mongoose.Types.ObjectId; // Reference to Site (specific site booked)
  guest: mongoose.Types.ObjectId; // user đặt chỗ
  host: mongoose.Types.ObjectId; // chủ property

  // Booking Details
  checkIn: Date;
  checkOut: Date;
  nights: number;

  // Guest Info
  numberOfGuests: number;
  numberOfPets?: number;
  numberOfVehicles?: number;

  // Pricing Breakdown
  pricing: {
    basePrice: number; // giá cơ bản
    weekendPrice?: number; // giá cuối tuần
    totalNights: number;
    weekdayNights?: number;
    weekendNights?: number;
    subtotal: number; // basePrice * nights
    cleaningFee: number;
    petFee: number;
    extraGuestFee: number;
    vehicleFee?: number;
    serviceFee: number; // phí dịch vụ platform
    tax: number; // thuế
    total: number; // tổng cuối
  };

  // Status
  status: "pending" | "confirmed" | "cancelled" | "completed" | "refunded" | "refund_requested";

  // Payment
  paymentStatus: "pending" | "paid" | "failed" | "refunded";
  paymentMethod?: "deposit" | "full";
  transactionId?: string;
  paidAt?: Date;

  // Communication
  guestMessage?: string; // lời nhắn của khách
  hostMessage?: string; // phản hồi của host

  // Cancellation
  cancelledBy?: mongoose.Types.ObjectId; // user hủy
  cancelledAt?: Date;
  cancellationReason?: string;
  refundAmount?: number;
  cancellInformation?: {
    fullnameGuest?: string | undefined;
    bankCode?: string | undefined;
    bankType?: string | undefined;
  };
  // Review
  reviewed: boolean;
  review?: mongoose.Types.ObjectId; // ref Review

  // Guest arrival confirmation (khách xác nhận đã đến, thay vì host)
  guestConfirmedAttendance?: boolean;
  guestConfirmedAt?: Date;

  // Cannot attend request (khách báo không thể đến)
  cannotAttendRequest?: {
    requestedAt: Date;
    reason: string;
    bankAccountName: string;
    bankAccountNumber: string;
    bankName: string;
    evidenceImages?: string[];
    status: "pending" | "approved" | "rejected";
    adminNote?: string | undefined;
    processedAt?: Date;
    processedBy?: mongoose.Types.ObjectId;
    refundAmount?: number;
  };

  // Wallet credit tracking
  walletCredited?: boolean;
  walletCreditedAt?: Date;
  platformFee?: number;
  hostNetAmount?: number;

  // Payout tracking
  payoutId?: mongoose.Types.ObjectId;
  payoutStatus: "pending" | "settled";

  // Refund request (admin-managed)
  refundRequest?: {
    requestedAt: Date;
    reason: string;
    requestedBy: mongoose.Types.ObjectId;
    status: "pending" | "approved" | "rejected";
    processedAt?: Date;
    processedBy?: mongoose.Types.ObjectId;
    adminNote?: string | undefined;
  };

  // Dissatisfaction request (khách không hài lòng sau khi đến nơi)
  dissatisfactionRequest?: {
    requestedAt: Date;
    reason: string;
    phone: string;
    email: string;
    bankAccountName: string;
    bankAccountNumber: string;
    bankName: string;
    evidenceImages: string[];
    status: "pending" | "approved" | "rejected";
    adminNote?: string | undefined;
    processedAt?: Date;
    processedBy?: mongoose.Types.ObjectId;
    refundAmount?: number;
  };

  // Timestamps
  createdAt: Date;
  updatedAt: Date;

  payOSOrderCode?: Number;
  payOSCheckoutUrl?: String;

  fullnameGuest?: string;
  phone?: string;
  email?: string;
  isSentMail?: boolean;
  reminderSent?: boolean;

  // Methods
  confirm(session?: mongoose.ClientSession): Promise<BookingDocument>;
  cancel(
    userId: mongoose.Types.ObjectId,
    reason?: string,
    session?: mongoose.ClientSession
  ): Promise<BookingDocument>;
  complete(session?: mongoose.ClientSession): Promise<BookingDocument>;
  calculateTotal(session?: mongoose.ClientSession): Promise<BookingDocument>;
}

const bookingSchema = new mongoose.Schema<BookingDocument>(
  {
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
      index: true,
    },
    site: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Site",
      required: true,
      index: true,
    },
    code: { type: String, index: true, unique: true },
    guest: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    host: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    checkIn: { type: Date, required: true, index: true },
    checkOut: { type: Date, required: true, index: true },
    nights: { type: Number, required: true, min: 1 },

    numberOfGuests: { type: Number, required: true, min: 1 },
    numberOfPets: { type: Number, min: 0, default: 0 },
    numberOfVehicles: { type: Number, min: 0, default: 0 },
    isSentMail: { type: Boolean, default: false },
    reminderSent: { type: Boolean, default: false },
    pricing: {
      basePrice: { type: Number, required: true, min: 0 },
      weekendPrice: { type: Number, min: 0 },
      totalNights: { type: Number, required: true, min: 1 },
      weekdayNights: { type: Number, min: 0 },
      weekendNights: { type: Number, min: 0 },
      subtotal: { type: Number, required: true, min: 0 },
      cleaningFee: { type: Number, default: 0, min: 0 },
      petFee: { type: Number, default: 0, min: 0 },
      extraGuestFee: { type: Number, default: 0, min: 0 },
      vehicleFee: { type: Number, default: 0, min: 0 },
      serviceFee: { type: Number, default: 0, min: 0 },
      tax: { type: Number, default: 0, min: 0 },
      total: { type: Number, required: true, min: 0 },
    },

    status: {
      type: String,
      enum: ["pending", "confirmed", "cancelled", "completed", "refunded", "refund_requested"],
      default: "confirmed",
      index: true,
    },

    paymentStatus: {
      type: String,
      // IMPORTANT: Keep in sync with BookingDocument interface above
      enum: ["pending", "paid", "failed", "refunded"],
      default: "pending",
      index: true,
    },
    paymentMethod: {
      type: String,
      enum: ["deposit", "full"],
    },
    fullnameGuest: { type: String, maxlength: 200 },
    phone: { type: String, maxlength: 20 },
    email: { type: String, maxlength: 100 },
    payOSOrderCode: { type: Number },
    payOSCheckoutUrl: { type: String },

    transactionId: { type: String, index: true },
    paidAt: { type: Date },

    guestMessage: { type: String, maxlength: 1000 },
    hostMessage: { type: String, maxlength: 1000 },

    cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    cancelledAt: { type: Date },
    cancellationReason: { type: String, maxlength: 500 },
    cancellInformation: {
      fullnameGuest: { type: String, maxlength: 200 },
      bankCode: { type: String, maxlength: 20 },
      bankType: { type: String, maxlength: 100 },
    },
    refundAmount: { type: Number, min: 0 },

    reviewed: { type: Boolean, default: false },
    review: { type: mongoose.Schema.Types.ObjectId, ref: "Review" },

    // Guest arrival confirmation
    guestConfirmedAttendance: { type: Boolean, default: false },
    guestConfirmedAt: { type: Date },

    // Cannot attend request
    cannotAttendRequest: {
      requestedAt: { type: Date },
      reason: { type: String, maxlength: 1000 },
      bankAccountName: { type: String, maxlength: 200 },
      bankAccountNumber: { type: String, maxlength: 50 },
      bankName: { type: String, maxlength: 100 },
      evidenceImages: [{ type: String }],
      status: { type: String, enum: ["pending", "approved", "rejected"] },
      adminNote: { type: String, maxlength: 500 },
      processedAt: { type: Date },
      processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      refundAmount: { type: Number, min: 0 },
    },

    // Wallet credit tracking
    walletCredited: { type: Boolean, default: false },
    walletCreditedAt: { type: Date },
    platformFee: { type: Number, min: 0 },
    hostNetAmount: { type: Number, min: 0 },

    // Payout tracking
    payoutId: { type: mongoose.Schema.Types.ObjectId, ref: "Payout" },
    payoutStatus: {
      type: String,
      enum: ["pending", "settled"],
      default: "pending",
      index: true,
    },

    // Refund request (admin-managed)
    refundRequest: {
      requestedAt: { type: Date },
      reason: { type: String, maxlength: 1000 },
      requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      status: {
        type: String,
        enum: ["pending", "approved", "rejected"],
      },
      processedAt: { type: Date },
      processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      adminNote: { type: String, maxlength: 500 },
    },

    // Dissatisfaction request (khách không hài lòng)
    dissatisfactionRequest: {
      requestedAt: { type: Date },
      reason: { type: String, maxlength: 2000 },
      phone: { type: String, maxlength: 20 },
      email: { type: String, maxlength: 100 },
      bankAccountName: { type: String, maxlength: 200 },
      bankAccountNumber: { type: String, maxlength: 50 },
      bankName: { type: String, maxlength: 100 },
      evidenceImages: [{ type: String }],
      status: { type: String, enum: ["pending", "approved", "rejected"] },
      adminNote: { type: String, maxlength: 1000 },
      processedAt: { type: Date },
      processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      refundAmount: { type: Number, min: 0 },
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
bookingSchema.index({ property: 1 });
bookingSchema.index({ site: 1 });
bookingSchema.index({ code: 1 }, { unique: true });
bookingSchema.index({ guest: 1 });
bookingSchema.index({ host: 1 });
bookingSchema.index({ checkIn: 1 });
bookingSchema.index({ checkOut: 1 });
bookingSchema.index({ status: 1 });
bookingSchema.index({ paymentStatus: 1 });
bookingSchema.index({ transactionId: 1 });
bookingSchema.index({ status: 1, checkIn: 1 });
bookingSchema.index({ status: 1, checkOut: 1 });
bookingSchema.index({ guest: 1, status: 1, createdAt: -1 });
bookingSchema.index({ host: 1, status: 1, createdAt: -1 });
bookingSchema.index({ site: 1, checkIn: 1, checkOut: 1 });

// NOTE: Removed unique index on { site, checkIn, checkOut, status }
// This index prevented undesignated sites (maxConcurrentBookings > 1) from accepting
// multiple concurrent bookings for the same dates.
// Overlapping booking prevention is now handled by:
// - For designated sites (maxConcurrentBookings = 1): checkAvailability() in SiteService
// - For undesignated sites (maxConcurrentBookings > 1): Count-based capacity check
// The non-unique index above (site + checkIn + checkOut) is sufficient for query performance.

// Methods
bookingSchema.methods.confirm = async function (this: BookingDocument, session?: mongoose.ClientSession) {
  this.status = "confirmed";
  // NOTE: paidAt KHÔNG được set ở đây
  // paidAt chỉ được set khi PayOS webhook báo PAID (trong payos.service.ts)
  // confirm() là hành động của HOST, không liên quan đến thanh toán
  return this.save(session ? { session } : undefined);
};

bookingSchema.methods.cancel = async function (
  this: BookingDocument,
  userId: mongoose.Types.ObjectId,
  reason?: string,
  session?: mongoose.ClientSession
) {
  this.status = "cancelled";
  this.cancelledBy = userId;
  this.cancelledAt = new Date();
  if (reason) this.cancellationReason = reason;
  return this.save(session ? { session } : undefined);
};

bookingSchema.methods.complete = async function (this: BookingDocument, session?: mongoose.ClientSession) {
  this.status = "completed";
  return this.save(session ? { session } : undefined);
};

bookingSchema.methods.calculateTotal = async function (
  this: BookingDocument,
  session?: mongoose.ClientSession
): Promise<BookingDocument> {
  const { subtotal, cleaningFee, petFee, extraGuestFee, serviceFee, tax, vehicleFee = 0 } = this.pricing;
  this.pricing.total = subtotal + cleaningFee + petFee + extraGuestFee + serviceFee + tax + vehicleFee;
  return this.save(session ? { session } : undefined);
};

export const BookingModel = mongoose.model<BookingDocument>("Booking", bookingSchema);
