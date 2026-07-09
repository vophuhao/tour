import mongoose from "mongoose";

export interface ISystemSetting extends mongoose.Document {
  platformFeeRate: number; // e.g. 0.05
  cancellationPolicy: {
    diffDaysThreshold: number; // e.g. 2
    refundRateAboveThreshold: number; // e.g. 0.7
    hostRateAboveThreshold: number; // e.g. 0.2
    refundRateBelowThreshold: number; // e.g. 0.5
    hostRateBelowThreshold: number; // e.g. 0.3
    rejectedRequestHostRate: number; // e.g. 0.8
  };
  popupBanner?: {
    imageUrl: string;
    linkUrl?: string;
    isActive: boolean;
  };
  popupBanners?: Array<{
    imageUrl: string;
    linkUrl?: string;
    isActive: boolean;
  }>;
  createdAt: Date;
  updatedAt: Date;
}

const systemSettingSchema = new mongoose.Schema<ISystemSetting>(
  {
    platformFeeRate: { type: Number, required: true, default: 0.05, min: 0, max: 1 },
    cancellationPolicy: {
      diffDaysThreshold: { type: Number, required: true, default: 2, min: 0 },
      refundRateAboveThreshold: { type: Number, required: true, default: 0.7, min: 0, max: 1 },
      hostRateAboveThreshold: { type: Number, required: true, default: 0.2, min: 0, max: 1 },
      refundRateBelowThreshold: { type: Number, required: true, default: 0.5, min: 0, max: 1 },
      hostRateBelowThreshold: { type: Number, required: true, default: 0.3, min: 0, max: 1 },
      rejectedRequestHostRate: { type: Number, required: true, default: 0.8, min: 0, max: 1 },
    },
    popupBanner: {
      imageUrl: { type: String, default: "" },
      linkUrl: { type: String, default: "" },
      isActive: { type: Boolean, default: false },
    },
    popupBanners: [
      {
        imageUrl: { type: String, required: true },
        linkUrl: { type: String, default: "" },
        isActive: { type: Boolean, default: true },
      },
    ],
  },
  {
    timestamps: true,
  }
);

export const SystemSettingModel = mongoose.model<ISystemSetting>("SystemSetting", systemSettingSchema);
