import mongoose from "mongoose";

export interface PromoCodeDocument extends mongoose.Document {
  code: string;
  description: string;
  scope: "global" | "host";
  host?: mongoose.Types.ObjectId;
  discountType: "percentage" | "flat";
  discountValue: number;
  maxDiscountAmount?: number;
  minSubtotal?: number;
  applicableProperties: mongoose.Types.ObjectId[];
  startDate: Date;
  endDate: Date;
  usageLimit?: number;
  usageCount: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const promoCodeSchema = new mongoose.Schema<PromoCodeDocument>(
  {
    code: {
      type: String,
      required: true,
      unique: true,
      uppercase: true,
      trim: true,
      index: true,
    },
    description: {
      type: String,
      default: "",
    },
    scope: {
      type: String,
      enum: ["global", "host"],
      required: true,
      default: "host",
    },
    host: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      index: true,
    },
    discountType: {
      type: String,
      enum: ["percentage", "flat"],
      required: true,
    },
    discountValue: {
      type: Number,
      required: true,
      min: 0,
    },
    maxDiscountAmount: {
      type: Number,
      min: 0,
    },
    minSubtotal: {
      type: Number,
      min: 0,
      default: 0,
    },
    applicableProperties: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Property",
      },
    ],
    startDate: {
      type: Date,
      required: true,
    },
    endDate: {
      type: Date,
      required: true,
    },
    usageLimit: {
      type: Number,
      min: 1,
    },
    usageCount: {
      type: Number,
      required: true,
      default: 0,
      min: 0,
    },
    isActive: {
      type: Boolean,
      required: true,
      default: true,
    },
  },
  {
    timestamps: true,
  }
);

// Compound Index for speed
promoCodeSchema.index({ code: 1, isActive: 1 });

export const PromoCodeModel = mongoose.model<PromoCodeDocument>(
  "PromoCode",
  promoCodeSchema
);
export default PromoCodeModel;
