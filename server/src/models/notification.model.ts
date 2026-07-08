import mongoose from "mongoose";

export interface NotificationDocument extends mongoose.Document {
  recipient: mongoose.Types.ObjectId;
  sender?: mongoose.Types.ObjectId;
  type:
    // Guest/Customer notifications
    | "order_confirmed"
    | "order_shipping"
    | "order_delivered"
    | "order_cancelled"
    | "order_return_request"
    | "booking_confirmed"
    | "booking_cancelled"
    | "review_reply"
    | "product_available"
    | "promotion"
    | "system"
    // Host notifications
    | "new_booking_request"
    | "booking_payment_received"
    | "guest_checked_in"
    | "guest_checked_out"
    | "guest_cancelled_booking"
    | "new_review_received"
    | "property_approved"
    | "property_rejected"
    | "payout_processed"
    | "booking_reminder"
    | "guest_message"
    | "property_performance";
  title: string;
  message: string;

  // Reference to related content
  order?: mongoose.Types.ObjectId;
  booking?: mongoose.Types.ObjectId;
  product?: mongoose.Types.ObjectId;
  review?: mongoose.Types.ObjectId;
  property?: mongoose.Types.ObjectId;

  // Notification status
  isRead: boolean;
  readAt?: Date;

  // Link/Action
  link?: string;
  actionType?:
    | "view_order"
    | "view_booking"
    | "view_product"
    | "view_review"
    | "view_property"
    | "view_message"
    | "none";

  // Priority
  priority: "low" | "medium" | "high";

  // Additional metadata
  metadata?: {
    orderId?: string;
    orderCode?: string;
    bookingCode?: string;
    productName?: string;
    propertyName?: string;
    guestName?: string;
    amount?: number;
    rating?: number;
    [key: string]: any;
  };

  // Role-based filtering
  role: "guest" | "host" | "admin" | "all";

  createdAt: Date;
  updatedAt: Date;
}

const notificationSchema = new mongoose.Schema<NotificationDocument>(
  {
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    type: {
      type: String,
      enum: [
        // Guest/Customer notifications
        "order_confirmed",
        "order_shipping",
        "order_delivered",
        "order_cancelled",
        "order_return_request",
        "booking_confirmed",
        "booking_cancelled",
        "review_reply",
        "product_available",
        "promotion",
        "system",
        // Host notifications
        "new_booking_request",
        "booking_payment_received",
        "guest_checked_in",
        "guest_checked_out",
        "guest_cancelled_booking",
        "new_review_received",
        "property_approved",
        "property_rejected",
        "payout_processed",
        "booking_reminder",
        "guest_message",
        "property_performance",
      ],
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      maxlength: 100,
    },
    message: {
      type: String,
      required: true,
      maxlength: 500,
    },

    // References
    order: { type: mongoose.Schema.Types.ObjectId, ref: "Order" },
    booking: { type: mongoose.Schema.Types.ObjectId, ref: "Booking" },
    product: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    review: { type: mongoose.Schema.Types.ObjectId, ref: "Review" },
    property: { type: mongoose.Schema.Types.ObjectId, ref: "Property" },

    // Status
    isRead: { type: Boolean, default: false, index: true },
    readAt: Date,

    // Action
    link: { type: String },
    actionType: {
        type: String,
      enum: ["view_order", "view_booking", "view_product", "view_review", "view_property", "view_message", "none"],
      default: "none",
    },

    // Priority
    priority: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },

    // Additional metadata
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // Role-based filtering
    role: {
      type: String,
      enum: ["guest", "host", "admin", "all"],
      default: "guest",
      index: true,
    },
  },
  { timestamps: true }
);

// Indexes
notificationSchema.index({ recipient: 1, createdAt: -1 });
notificationSchema.index({ recipient: 1, isRead: 1 });
notificationSchema.index({ createdAt: -1 });

// TTL index to auto-delete old notifications after 90 days
notificationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

const NotificationModel = mongoose.model<NotificationDocument>("Notification", notificationSchema);
export default NotificationModel;