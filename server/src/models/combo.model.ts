import mongoose from "mongoose";

export interface IComboService {
  name: string;
  quantity: number;
}

export interface ComboDocument extends mongoose.Document {
  name: string;
  description: string;
  propertyId: mongoose.Types.ObjectId;
  applicableSites: mongoose.Types.ObjectId[];
  servicesIncluded: IComboService[];
  discountType: "percentage" | "fixed_price";
  discountValue: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const comboServiceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  quantity: { type: Number, required: true, default: 1, min: 1 },
});

const comboSchema = new mongoose.Schema<ComboDocument>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      default: "",
    },
    propertyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
      index: true,
    },
    applicableSites: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Site",
      },
    ],
    servicesIncluded: [comboServiceSchema],
    discountType: {
      type: String,
      enum: ["percentage", "fixed_price"],
      required: true,
      default: "percentage",
    },
    discountValue: {
      type: Number,
      required: true,
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

comboSchema.index({ propertyId: 1, isActive: 1 });

export const ComboModel = mongoose.model<ComboDocument>("Combo", comboSchema);
export default ComboModel;
