import mongoose from "mongoose";

export interface IServicePricing {
  price: number;
  unit: string;
  timeValue?: number | undefined;
  timeUnit?: string | undefined;
}

export interface IService {
  name: string;
  description?: string | undefined;
  pricing: IServicePricing[];
}

export interface ServicePackageDocument extends mongoose.Document {
  name: string;
  host: mongoose.Types.ObjectId;
  services: IService[];
  createdAt: Date;
  updatedAt: Date;
}

const servicePricingSchema = new mongoose.Schema({
  price: { type: Number, required: true, min: 0 },
  unit: { type: String, required: true, default: "cai" },
  timeValue: { type: Number, default: 1 },
  timeUnit: { type: String, default: "luot" },
});

const serviceSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, trim: true, default: "" },
  pricing: [servicePricingSchema],
});

const servicePackageSchema = new mongoose.Schema<ServicePackageDocument>(
  {
    name: { type: String, required: true, trim: true },
    host: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    services: [serviceSchema],
  },
  {
    timestamps: true,
  }
);

// Indexes
servicePackageSchema.index({ host: 1 });

export const ServicePackageModel = mongoose.model<ServicePackageDocument>(
  "ServicePackage",
  servicePackageSchema
);
