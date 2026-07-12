import mongoose from "mongoose";



// Property-level Availability - Block dates cho toàn bộ property (all sites)
export interface PropertyAvailabilityDocument extends mongoose.Document {
  property: mongoose.Types.ObjectId;
  startDate: Date; // ngày bắt đầu block
  endDate: Date; // ngày kết thúc block
  reason?: string; // lý do block
  createdBy: mongoose.Types.ObjectId; // host đã tạo block
  createdAt: Date;
  updatedAt: Date;
}

const availabilitySchema = new mongoose.Schema<AvailabilityDocument>(
  {
    site: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Site",
      required: true,
    },

    date: { type: Date, required: true },
    isAvailable: { type: Boolean, default: true },

    blockType: {
      type: String,
      enum: ["booked", "blocked", "maintenance", "seasonal"],
    },
    reason: { type: String, trim: true, maxlength: 500 },
    blockedSlots: { type: Number, min: 0, default: 0 }, // số chỗ partial block
  },
  {
    timestamps: true,
  }
);

// Availability model - Quản lý lịch trống/đã book của site
export interface AvailabilityDocument extends mongoose.Document {
  site: mongoose.Types.ObjectId;

  // Date range
  date: Date; // ngày cụ thể
  isAvailable: boolean; // có sẵn hay không

  // Block types
  blockType?: "booked" | "blocked" | "maintenance" | "seasonal"; // loại block
  reason?: string; // lý do block
  blockedSlots?: number; // số chỗ bị khóa thủ công (partial block, 0 = không khóa)

  // Timestamps
  createdAt: Date;
  updatedAt: Date;
}

// Indexes
availabilitySchema.index({ site: 1 });
availabilitySchema.index({ date: 1 });
availabilitySchema.index({ isAvailable: 1 });
availabilitySchema.index({ site: 1, date: 1 }, { unique: true }); // mỗi site chỉ có 1 record cho 1 ngày
// Compound index cho query: checkAvailabilityInSession() — hot path
availabilitySchema.index({ site: 1, date: 1, isAvailable: 1 });
// Compound index cho query: unblockDatesForBooking() — {site, date, blockType: "booked"}
availabilitySchema.index({ site: 1, date: 1, blockType: 1 });

export const AvailabilityModel = mongoose.model<AvailabilityDocument>(
  "Availability",
  availabilitySchema
);

// Property Availability Schema - Block dates for entire property
const propertyAvailabilitySchema = new mongoose.Schema<PropertyAvailabilityDocument>(
  {
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
    },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    reason: { type: String, trim: true, maxlength: 500 },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for efficient date range queries
propertyAvailabilitySchema.index({ property: 1 });
propertyAvailabilitySchema.index({ startDate: 1 });
propertyAvailabilitySchema.index({ endDate: 1 });
propertyAvailabilitySchema.index({ property: 1, startDate: 1, endDate: 1 });
propertyAvailabilitySchema.index({ property: 1, startDate: -1 }); // For sorting by date

export const PropertyAvailabilityModel = mongoose.model<PropertyAvailabilityDocument>(
  "PropertyAvailability",
  propertyAvailabilitySchema
);

// Favorite model - Wishlist property/site của user
export interface FavoriteDocument extends mongoose.Document {
  user: mongoose.Types.ObjectId;
  property?: mongoose.Types.ObjectId; // favorite whole property
  site?: mongoose.Types.ObjectId; // or favorite specific site
  notes?: string; // ghi chú cá nhân
  createdAt: Date;
  updatedAt: Date;
}

const favoriteSchema = new mongoose.Schema<FavoriteDocument>(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
    },
    site: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Site",
    },
    notes: { type: String, trim: true, maxlength: 500 },
  },
  {
    timestamps: true,
  }
);

// Validation: must have either property OR site (not both, not neither)
favoriteSchema.pre("validate", function (next) {
  const hasProperty = !!this.property;
  const hasSite = !!this.site;

  if (hasProperty && hasSite) {
    return next(new Error("Cannot favorite both property and site - choose one"));
  }
  if (!hasProperty && !hasSite) {
    return next(new Error("Must favorite either a property or a site"));
  }
  next();
});

// Indexes
favoriteSchema.index({ user: 1, property: 1 }, { unique: true, sparse: true }); // user can favorite property once
// favoriteSchema.index({ user: 1, site: 1 }, { unique: true, sparse: true }); // user can favorite site once
favoriteSchema.index({ user: 1, createdAt: -1 }); // list favorites của user

export const FavoriteModel = mongoose.model<FavoriteDocument>("Favorite", favoriteSchema);
