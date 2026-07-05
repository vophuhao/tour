import mongoose from "mongoose";

// Review model - đánh giá property và site
export interface ReviewDocument extends mongoose.Document {
  // References
  property: mongoose.Types.ObjectId; // property being reviewed
  site: mongoose.Types.ObjectId; // specific site being reviewed
  booking: mongoose.Types.ObjectId;
  guest: mongoose.Types.ObjectId; // người đánh giá
  host: mongoose.Types.ObjectId; // chủ property

  // Property Ratings (1-5 stars) - property-level aspects
  propertyRatings: {
    location: number; // vị trí property
    communication: number; // giao tiếp với host
    value: number; // giá trị
  };

  // Site Ratings (1-5 stars) - site-specific aspects
  siteRatings: {
    cleanliness: number; // vệ sinh site
    accuracy: number; // đúng mô tả site
    amenities: number; // tiện nghi site
  };

  // Overall rating (calculated from property + site ratings)
  overallRating: number;

  // Review Content
  title?: string;
  comment: string;
  pros?: string[]; // điểm tốt
  cons?: string[]; // điểm chưa tốt

  // Media
  images?: string[];

  // Host Response
  hostResponse?: {
    comment: string;
    respondedAt: Date;
  };

  // Status
  isPublished: boolean;
  isFeatured: boolean; // review nổi bật
  isVerified: boolean; // đã xác minh đặt chỗ
  isEdited: boolean; // đã được sửa đổi

  // Helpful votes
  helpfulCount: number;
  notHelpfulCount: number;

  // Timestamps
  createdAt: Date;
  updatedAt: Date;

  // Methods
  publish(): Promise<ReviewDocument>;
  unpublish(): Promise<ReviewDocument>;
  addHostResponse(response: string): Promise<ReviewDocument>;
  calculateOverallRating(): number;
}

const reviewSchema = new mongoose.Schema<ReviewDocument>(
  {
    property: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Property",
      required: true,
      index: true,
    },
    site: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Site",
      required: true,
      index: true,
    },
    booking: { type: mongoose.Schema.Types.ObjectId, ref: "Booking", required: true, unique: true },
    guest: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    host: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    propertyRatings: {
      location: { type: Number, required: true, min: 1, max: 5 },
      communication: { type: Number, required: true, min: 1, max: 5 },
      value: { type: Number, required: true, min: 1, max: 5 },
    },

    siteRatings: {
      cleanliness: { type: Number, required: true, min: 1, max: 5 },
      accuracy: { type: Number, required: true, min: 1, max: 5 },
      amenities: { type: Number, required: true, min: 1, max: 5 },
    },

    // overallRating is calculated automatically in pre-save hook, so not required in schema
    overallRating: { type: Number, min: 1, max: 5 },

    title: { type: String, trim: true, maxlength: 100 },
    comment: { type: String, required: true, trim: true, maxlength: 2000 },
    pros: [{ type: String, maxlength: 200 }],
    cons: [{ type: String, maxlength: 200 }],

    images: [{ type: String }],

    hostResponse: {
      comment: { type: String, trim: true, maxlength: 1000 },
      respondedAt: { type: Date },
    },

    isPublished: { type: Boolean, default: true, index: true },
    isFeatured: { type: Boolean, default: false, index: true },
    isVerified: { type: Boolean, default: true }, // auto true nếu có booking
    isEdited: { type: Boolean, default: false },

    helpfulCount: { type: Number, default: 0, min: 0 },
    notHelpfulCount: { type: Number, default: 0, min: 0 },
  },
  {
    timestamps: true,
  }
);

// Indexes
reviewSchema.index({ property: 1, isPublished: 1, createdAt: -1 });
reviewSchema.index({ site: 1, isPublished: 1, createdAt: -1 });
reviewSchema.index({ guest: 1, createdAt: -1 });
reviewSchema.index({ overallRating: -1, isPublished: 1 });
reviewSchema.index({ isFeatured: 1, isPublished: 1 });

// Methods
reviewSchema.methods.publish = async function (this: ReviewDocument) {
  this.isPublished = true;
  return this.save();
};

reviewSchema.methods.unpublish = async function (this: ReviewDocument) {
  this.isPublished = false;
  return this.save();
};

reviewSchema.methods.addHostResponse = async function (this: ReviewDocument, response: string) {
  this.hostResponse = {
    comment: response,
    respondedAt: new Date(),
  };
  return this.save();
};

reviewSchema.methods.calculateOverallRating = function (this: ReviewDocument): number {
  const { location, communication, value } = this.propertyRatings;
  const { cleanliness, accuracy, amenities } = this.siteRatings;
  return (
    Math.round(((location + communication + value + cleanliness + accuracy + amenities) / 6) * 10) /
    10
  );
};

// Auto-calculate overall rating before validation
reviewSchema.pre("validate", function (next) {
  // Always calculate overallRating if propertyRatings and siteRatings are present
  if (this.propertyRatings && this.siteRatings) {
    this.overallRating = this.calculateOverallRating();
  }
  next();
});

export const ReviewModel = mongoose.model<ReviewDocument>("Review", reviewSchema);
