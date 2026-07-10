import mongoose from "mongoose";

// Site Model - Vị trí cắm trại cụ thể trong property (new Campsite)
export interface SiteDocument extends mongoose.Document {
  // Reference to Property (CRITICAL!)
  property: mongoose.Types.ObjectId; // Reference to Property

  // Site Identification
  name: string; // "Riverside Tent Site", "RV Spot #3"
  slug: string; // property-slug + site-slug
  description?: string;

  // Accommodation Type
  accommodationType:
    | "tent"
    | "rv"
    | "cabin"
    | "yurt"
    | "treehouse"
    | "tiny_home"
    | "safari_tent"
    | "bell_tent"
    | "glamping_pod"
    | "dome"
    | "airstream"
    | "vintage_trailer"
    | "van";

  lodgingProvided?: "bring_your_own" | "structure_provided" | "vehicle_provided";

  siteClass?: "basic" | "vip";

  // Site-specific Location
  siteLocation?: {
    coordinates?: {
      type: "Point";
      coordinates: [number, number]; // [lng, lat] - specific site location
    };
    mapPinLabel?: string; // "Site A", "1"
    relativeDescription?: string; // "Near the river", "In the meadow"
  };
  terrain?: "forest" | "beach" | "mountain" | "desert" | "farm";

  // Capacity
  capacity: {
    maxGuests: number;
    maxAdults?: number;
    maxChildren?: number;
    maxInfants?: number;
    maxPets?: number;
    maxVehicles?: number;
    maxTents?: number;
    maxRVs?: number;
    rvMaxLength?: number; // feet

    // Concurrent Bookings (Hipcamp-style designated/undesignated)
    // maxConcurrentBookings = 1 → designated (chỉ 1 booking tại 1 thời điểm)
    // maxConcurrentBookings > 1 → undesignated (nhiều bookings đồng thời, "X sites left")
    maxConcurrentBookings: number;
  };

  // Pricing (per-site)
  pricing: {
    rateType?: "site" | "person";
    basePrice: number; // Per night
    weekendPrice?: number;
    weeklyDiscount?: number; // percentage
    monthlyDiscount?: number;
    additionalGuestFee?: number; // Per guest over base
    petFee?: number;
    vehicleFee?: number;
    cleaningFee?: number;
    depositAmount?: number;
    currency: string;

    // Seasonal pricing
    seasonalPricing?: Array<{
      name: string; // "Summer", "Winter"
      startDate: Date;
      endDate: Date;
      price: number;
    }>;
  };

  // Booking Settings
  bookingSettings: {
    minimumNights: number;
    maximumNights?: number;
    checkInTime: string; // "14:00"
    checkOutTime: string; // "11:00"
    instantBook: boolean;
    advanceNotice: number; // hours
    preparationTime?: number; // days between bookings
    allowSameDayBooking: boolean;
  };

  // Site-specific Photos
  photos: Array<{
    url: string;
    caption?: string;
    isCover: boolean;
    order: number;
    uploadedAt?: Date;
  }>;

  amenities: mongoose.Types.ObjectId[];

  // What to bring
  guestsShouldBring?: string[]; // ["sleeping_bag", "tent", "cooking_equipment"]

  // Site-specific Rules
  siteSpecificRules?: string[];

  // Stats
  stats: {
    totalBookings: number;
    totalReviews: number;
    averageRating: number;
    ratings: {
      cleanliness: number;
      accuracy: number;
    };
    occupancyRate?: number;
    viewCount: number;
  };

  // Rating (for review aggregation compatibility)
  rating?: {
    average: number;
    count: number;
    breakdown: {
      cleanliness: number;
      accuracy: number;
      amenities: number;
    };
  };

  // Status
  status: "active" | "inactive" | "blocked";
  isActive: boolean;
  isAvailableForBooking: boolean;
  unavailableReason?: string;

  // Extra Services
  services?: Array<{
    name: string;
    description?: string;
    pricing: Array<{
      price: number;
      unit: string;
    }>;
  }>;

  unitNames?: string[];

  // Timestamps
  createdAt: Date;
  updatedAt: Date;
  lastBookedAt?: Date;

  // Methods
  activate(): Promise<SiteDocument>;
  deactivate(): Promise<SiteDocument>;
  incrementViews(): Promise<SiteDocument>;
  updateStats(): Promise<SiteDocument>;
}

const siteSchema = new mongoose.Schema<SiteDocument>(
  {
    // Reference to Property
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
      index: true,
    },

    // Site Identification
    name: { type: String, required: true, trim: true, maxlength: 200 },
    slug: { type: String, required: true, index: true },
    description: { type: String, maxlength: 2000 },

    // Accommodation Type
    accommodationType: {
      type: String,
      required: true,
      enum: [
        "tent",
        "rv",
        "cabin",
        "yurt",
        "treehouse",
        "tiny_home",
        "safari_tent",
        "bell_tent",
        "glamping_pod",
        "dome",
        "airstream",
        "vintage_trailer",
        "van",
      ],
      index: true,
    },

    lodgingProvided: {
      type: String,
      enum: ["bring_your_own", "structure_provided", "vehicle_provided"],
      required: false,
    },

    siteClass: {
      type: String,
      enum: ["basic", "vip"],
      default: "basic",
      index: true,
    },

    // Site Location
    siteLocation: {
      coordinates: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number] }, // [lng, lat]
      },
      mapPinLabel: { type: String, maxlength: 50 },
      relativeDescription: { type: String, maxlength: 200 },
    },
    
    terrain: { type: String, enum: ["forest", "beach", "mountain", "desert", "farm"] },

    // Capacity
    capacity: {
      maxGuests: { type: Number, required: true, min: 1 },
      maxAdults: { type: Number, min: 0 },
      maxChildren: { type: Number, min: 0 },
      maxInfants: { type: Number, min: 0 },
      maxPets: { type: Number, min: 0, default: 0 },
      maxVehicles: { type: Number, min: 0 },
      maxTents: { type: Number, min: 0 },
      maxRVs: { type: Number, min: 0 },
      rvMaxLength: { type: Number, min: 0 }, // feet

      // Concurrent Bookings (designated vs undesignated)
      maxConcurrentBookings: {
        type: Number,
        required: true,
        default: 1,
        min: 1,
        max: 100,
        index: true,
      },
    },

     // Pricing
    pricing: {
      rateType: { type: String, enum: ["site", "person"], default: "site" },
      basePrice: { type: Number, required: true, min: 0, index: true },
      weekendPrice: { type: Number, min: 0 },
      weeklyDiscount: { type: Number, min: 0, max: 100 }, // percentage
      monthlyDiscount: { type: Number, min: 0, max: 100 },
      additionalGuestFee: { type: Number, min: 0, default: 0 },
      petFee: { type: Number, min: 0, default: 0 },
      vehicleFee: { type: Number, min: 0, default: 0 },
      cleaningFee: { type: Number, min: 0, default: 0 },
      depositAmount: { type: Number, min: 0, default: 0 },
      currency: { type: String, default: "VND" },

      seasonalPricing: [
        {
          name: { type: String, required: true },
          startDate: { type: Date, required: true },
          endDate: { type: Date, required: true },
          price: { type: Number, required: true, min: 0 },
        },
      ],
    },

    // Booking Settings
    bookingSettings: {
      minimumNights: { type: Number, required: true, default: 1, min: 1 },
      maximumNights: { type: Number, min: 1 },
      checkInTime: { type: String, required: true, default: "14:00" },
      checkOutTime: { type: String, required: true, default: "11:00" },
      instantBook: { type: Boolean, default: false },
      advanceNotice: { type: Number, default: 24, min: 0 }, // hours
      preparationTime: { type: Number, min: 0, default: 0 }, // days
      allowSameDayBooking: { type: Boolean, default: false },
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

    // Site Amenities
    amenities: [{ type: mongoose.Schema.Types.ObjectId, ref: "Amenity" }],

    // What to bring
    guestsShouldBring: [{ type: String }],
    unitNames: { type: [String], default: [] },

    // Site-specific Rules
    siteSpecificRules: [{ type: String, maxlength: 500 }],

    // Stats
    stats: {
      totalBookings: { type: Number, default: 0, min: 0 },
      totalReviews: { type: Number, default: 0, min: 0 },
      averageRating: { type: Number, default: 0, min: 0, max: 5 },
      ratings: {
        cleanliness: { type: Number, default: 0, min: 0, max: 5 },
        accuracy: { type: Number, default: 0, min: 0, max: 5 },
      },
      occupancyRate: { type: Number, min: 0, max: 100 },
      viewCount: { type: Number, default: 0, min: 0 },
    },

    // Rating (for review aggregation compatibility)
    rating: {
      average: { type: Number, default: 0, min: 0, max: 5 },
      count: { type: Number, default: 0, min: 0 },
      breakdown: {
        cleanliness: { type: Number, default: 0, min: 0, max: 5 },
        accuracy: { type: Number, default: 0, min: 0, max: 5 },
        amenities: { type: Number, default: 0, min: 0, max: 5 },
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
    isAvailableForBooking: { type: Boolean, default: true },
    unavailableReason: { type: String, maxlength: 500 },

    // Timestamps
    lastBookedAt: { type: Date },

    // Extra Services
    services: [
      {
        name: { type: String, required: true, trim: true },
        description: { type: String, trim: true, default: "" },
        pricing: [
          {
            price: { type: Number, required: true, min: 0 },
            unit: { type: String, required: true, default: "lượt" },
          },
        ],
      },
    ],
  },
  {
    timestamps: true,
  }
);

// Indexes for performance
siteSchema.index({ property: 1, isActive: 1 });
siteSchema.index({ "siteLocation.coordinates": "2dsphere" }); // Geospatial index
siteSchema.index({ accommodationType: 1, isActive: 1 });
siteSchema.index({ "stats.averageRating": -1 });
siteSchema.index({ createdAt: -1 });

// Compound index for property + slug uniqueness
siteSchema.index({ property: 1, slug: 1 }, { unique: true });

// Methods
siteSchema.methods.activate = async function (this: SiteDocument) {
  this.status = "active";
  this.isActive = true;
  this.isAvailableForBooking = true;
  return this.save();
};

siteSchema.methods.deactivate = async function (this: SiteDocument) {
  this.status = "inactive";
  this.isActive = false;
  this.isAvailableForBooking = false;
  return this.save();
};

siteSchema.methods.incrementViews = async function (this: SiteDocument) {
  this.stats.viewCount += 1;
  return this.save();
};

siteSchema.methods.updateStats = async function (this: SiteDocument) {
  // This will be implemented to aggregate stats from bookings and reviews
  // For now, just save
  return this.save();
};

export const SiteModel = mongoose.model<SiteDocument>("Site", siteSchema);
