import mongoose from "mongoose";

export interface HostDocument extends mongoose.Document {
  name: string;
  user ?: mongoose.Types.ObjectId;
  gmail : string;
  phone ?: string;
  status : "pending" | "approved" | "rejected";
  bankInfo?: {
    bankName: string;
    accountNumber: string;
    accountHolderName: string;
  };
  walletBalance: number;
  pendingWithdrawalAmount: number;
  createdAt: Date;
  updatedAt: Date;
}
const hostSchema = new mongoose.Schema<HostDocument>(
  {
    name: { type: String, required: true, trim: true, maxlength: 255 },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    phone: { type: String, trim: true, maxlength: 20 },
    gmail: { type: String, required: true, trim: true, maxlength: 255 },
    status: { type: String, enum: ["pending", "approved", "rejected"], required: true ,default:"pending"},
    bankInfo: {
      bankName: { type: String, trim: true, maxlength: 100 },
      accountNumber: { type: String, trim: true, maxlength: 30 },
      accountHolderName: { type: String, trim: true, maxlength: 100 },
    },
    walletBalance: { type: Number, default: 0, min: 0 },
    pendingWithdrawalAmount: { type: Number, default: 0, min: 0 },
  },
  { timestamps: true }
);

const HostModel = mongoose.model<HostDocument>("Host", hostSchema);
export default HostModel;
