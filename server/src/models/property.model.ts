import mongoose from "mongoose";

// Property Model - Tài sản/khu đất tổng thể của host
export interface PropertyDocument extends mongoose.Document {
  // Ownership
  host: mongoose.Types.ObjectId; // Reference to User (role: host)

  // Basic Info
  name: string;
  slug: string; // URL-friendly, unique
  tagline?: string;
  description: string;

  // Location (Property-level)
  location: {
    address: string;
    city: string;
    state: string; // tỉnh/thành
    country: string;
    zipCode?: string;
    coordinates: {
      type: "Point";
      coordinates: [number, number]; // [lng, lat] - property center
    };
    directions?: string; // Hướng dẫn đến property
    parkingInstructions?: string;
  };

  // Property Details
  landSize?: {
    value: number;
    unit: "acres" | "hectares" | "square_meters";
  };
  propertyType: string; // "private_land", "farm", "ranch", "campground"

  // Property-wide Photos
  photos: Array<{
    url: string;
    caption?: string;
    isCover: boolean;
    order: number;
    uploadedAt?: Date;
  }>;

  nearbyAttractions?: Array<{
    name: string;
    distance: number; // km
    type: string; // "national_park", "lake", "town", "restaurant"
  }>;

  rules?: Array<{
    text: string;
    category: "pets" | "noise" | "fire" | "general";
    order: number;
  }>;

  checkInInstructions?: string;
  checkOutInstructions?: string;

  // Policies
  cancellationPolicy: {
    type: "flexible" | "moderate" | "strict";
    description?: string;
    refundRules: Array<{
      daysBeforeCheckIn: number;
      refundPercentage: number; // 0-100
    }>;
  };

  // Stats (aggregated from sites)
  stats: {
    totalSites: number;
    activeSites: number;
    totalBookings: number;
    totalReviews: number;
    averageRating: number;
    ratings: {
      location: number;
      communication: number;
      value: number;
    };
    responseRate?: number; // 0-100
    responseTime?: number; // minutes
    viewCount: number;
  };

  // Rating (for compatibility with review aggregation)
  rating?: {
    average: number;
    count: number;
    breakdown: {
      location: number;
      communication: number;
      value: number;
    };
  };

  // Status
  status: "active" | "inactive" | "blocked";
  isActive: boolean;
  isFeatured: boolean;
  featuredUntil?: Date;
  isVerified: boolean;
  verifiedAt?: Date;

  // Superhost
  isSuperhost: boolean;
  superhostSince?: Date;
  superhostEvaluatedAt?: Date;

  // Settings
  settings: {
    instantBookEnabled: boolean; // Apply to all sites
    requireApproval: boolean;
    minimumAdvanceNotice: number; // hours
    bookingWindow: number; // days in advance
    allowWholePropertyBooking: boolean;
  };

  // Extra Services
  services?: Array<{
    name: string;
    description?: string;
    pricing: Array<{
      price: number;
      unit: "cai" | "chiec" | "nguoi_lon" | "tre_em" | "khach" | string;
      timeValue: number;
      timeUnit: "gio" | "ngay" | "dem" | "luot" | string;
    }>;
    isInventoryTracked?: boolean;
    totalInventory?: number;
  }>;

  // Timestamps
  createdAt: Date;
  updatedAt: Date;
  publishedAt?: Date;
  lastBookedAt?: Date;

  // Methods
  activate(): Promise<PropertyDocument>;
  deactivate(): Promise<PropertyDocument>;
  incrementViews(): Promise<PropertyDocument>;
  updateStats(): Promise<PropertyDocument>;
}

const propertySchema = new mongoose.Schema<PropertyDocument>(
  {
    // Ownership
    host: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    // Basic Info
    name: { type: String, required: true, trim: true, maxlength: 200 },
    slug: { type: String, required: true, unique: true, index: true },
    tagline: { type: String, trim: true, maxlength: 150 },
    description: { type: String, required: true, maxlength: 5000 },

    // Location
    location: {
      address: { type: String, required: true },
      city: { type: String, required: true, index: true },
      state: { type: String, required: true, index: true },
      country: { type: String, required: true, default: "Vietnam" },
      zipCode: { type: String },
      coordinates: {
        type: { type: String, enum: ["Point"], required: true, default: "Point" },
        coordinates: { type: [Number], required: true }, // [lng, lat]
      },
      directions: { type: String, maxlength: 1000 },
      parkingInstructions: { type: String, maxlength: 500 },
    },

    // Property Details
    landSize: {
      value: { type: Number, min: 0 },
      unit: { type: String, enum: ["acres", "hectares", "square_meters"] },
    },

    propertyType: {
      type: String,
      required: true,
      index: true,
      enum: ["private_land", "farm", "ranch", "campground"],
    },

    // Photos
    photos: [
      {
        url: { type: String, required: true },
        caption: { type: String, maxlength: 200 },
        isCover: { type: Boolean, default: false },
        order: { type: Number, default: 0 },
        uploadedAt: { type: Date, default: Date.now },
      },
    ],

    nearbyAttractions: [
      {
        name: { type: String, required: true },
        distance: { type: Number, required: true, min: 0 },
        type: { type: String, required: true },
      },
    ],

    // Rules
    rules: [
      {
        text: { type: String, required: true, maxlength: 500 },
        category: { type: String, enum: ["pets", "noise", "fire", "general"], default: "general" },
        order: { type: Number, default: 0 },
      },
    ],

    checkInInstructions: { type: String, maxlength: 2000 },
    checkOutInstructions: { type: String, maxlength: 2000 },

    // Policies
    cancellationPolicy: {
      type: {
        type: String,
        enum: ["flexible", "moderate", "strict"],
        default: "moderate",
      },
      description: { type: String, maxlength: 1000 },
      refundRules: [
        {
          daysBeforeCheckIn: { type: Number, required: true, min: 0 },
          refundPercentage: { type: Number, required: true, min: 0, max: 100 },
        },
      ],
    },

    // Stats
    stats: {
      totalSites: { type: Number, default: 0, min: 0 },
      activeSites: { type: Number, default: 0, min: 0 },
      totalBookings: { type: Number, default: 0, min: 0 },
      totalReviews: { type: Number, default: 0, min: 0 },
      averageRating: { type: Number, default: 0, min: 0, max: 5 },
      ratings: {
        location: { type: Number, default: 0, min: 0, max: 5 },
        communication: { type: Number, default: 0, min: 0, max: 5 },
        value: { type: Number, default: 0, min: 0, max: 5 },
      },
      responseRate: { type: Number, min: 0, max: 100 },
      responseTime: { type: Number, min: 0 },
      viewCount: { type: Number, default: 0, min: 0 },
    },

    // Rating (for review aggregation compatibility)
    rating: {
      average: { type: Number, default: 0, min: 0, max: 5 },
      count: { type: Number, default: 0, min: 0 },
      breakdown: {
        location: { type: Number, default: 0, min: 0, max: 5 },
        communication: { type: Number, default: 0, min: 0, max: 5 },
        value: { type: Number, default: 0, min: 0, max: 5 },
      },
    },

    // Status
    status: {
      type: String,
      enum: ["active", "inactive", "blocked"],
      default: "active",
      index: true,
    },
    isActive: { type: Boolean, default: true, index: true },
    isFeatured: { type: Boolean, default: false, index: true },
    featuredUntil: { type: Date },
    isVerified: { type: Boolean, default: false },
    verifiedAt: { type: Date },

    // Superhost
    isSuperhost: { type: Boolean, default: false, index: true },
    superhostSince: { type: Date },
    superhostEvaluatedAt: { type: Date },

    // Settings
    settings: {
      instantBookEnabled: { type: Boolean, default: false },
      requireApproval: { type: Boolean, default: true },
      minimumAdvanceNotice: { type: Number, default: 24, min: 0 }, // hours
      bookingWindow: { type: Number, default: 365, min: 1 }, // days
      allowWholePropertyBooking: { type: Boolean, default: false },
    },

    // Timestamps
    publishedAt: { type: Date },
    lastBookedAt: { type: Date },

    // Extra Services
    services: [
      {
        name: { type: String, required: true, trim: true },
        description: { type: String, trim: true, default: "" },
        pricing: [
          {
            price: { type: Number, required: true, min: 0 },
            unit: {
              type: String,
              required: true,
              enum: ["cai", "chiec", "nguoi_lon", "tre_em", "khach"],
              default: "cai"
            },
            timeValue: {
              type: Number,
              required: true,
              min: 1,
              default: 1
            },
            timeUnit: {
              type: String,
              required: true,
              enum: ["gio", "ngay", "dem", "luot"],
              default: "luot"
            },
          },
        ],
        isInventoryTracked: { type: Boolean, default: false },
        totalInventory: { type: Number, default: 0, min: 0 },
      },
    ],
  },
  {
    timestamps: true,
  }
);

// Indexes for performance
propertySchema.index({ host: 1, isActive: 1 });
propertySchema.index({ "location.coordinates": "2dsphere" }); // Geospatial index
propertySchema.index({ propertyType: 1, isActive: 1 });
propertySchema.index({ isFeatured: 1, "stats.averageRating": -1 });
propertySchema.index({ createdAt: -1 });

// Text search index
propertySchema.index({
  name: "text",
  description: "text",
  tagline: "text",
  "location.city": "text",
  "location.state": "text",
});

// Methods
propertySchema.methods.activate = async function (this: PropertyDocument) {
  this.status = "active";
  this.isActive = true;
  return this.save();
};

propertySchema.methods.deactivate = async function (this: PropertyDocument) {
  this.status = "inactive";
  this.isActive = false;
  return this.save();
};

propertySchema.methods.incrementViews = async function (this: PropertyDocument) {
  this.stats.viewCount += 1;
  return this.save();
};

propertySchema.methods.updateStats = async function (this: PropertyDocument) {
  // This will be implemented to aggregate stats from sites
  // For now, just save
  return this.save();
};

export const PropertyModel = mongoose.model<PropertyDocument>("Property", propertySchema);
