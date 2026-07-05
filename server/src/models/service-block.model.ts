import mongoose from "mongoose";

export interface ServiceBlockDocument extends mongoose.Document {
  property: mongoose.Types.ObjectId;
  serviceName: string;
  checkIn: Date;
  checkOut: Date;
  quantity: number;
  note?: string;
  createdAt: Date;
  updatedAt: Date;
}

const serviceBlockSchema = new mongoose.Schema<ServiceBlockDocument>(
  {
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
      index: true,
    },
    serviceName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    checkIn: {
      type: Date,
      required: true,
      index: true,
    },
    checkOut: {
      type: Date,
      required: true,
      index: true,
    },
    quantity: {
      type: Number,
      required: true,
      min: 1,
    },
    note: {
      type: String,
      trim: true,
      default: "",
      maxlength: 1000,
    },
  },
  {
    timestamps: true,
  }
);

// Compound index for performance in availability queries
serviceBlockSchema.index({ property: 1, serviceName: 1, checkIn: 1, checkOut: 1 });

const ServiceBlockModel = mongoose.model<ServiceBlockDocument>("ServiceBlock", serviceBlockSchema);
export default ServiceBlockModel;
