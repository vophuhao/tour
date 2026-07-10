import { z } from "zod";

// Capacity sub-schema
// const capacitySchema = z.object({
//   maxGuests: z.number().int().min(1).max(100),
//   maxAdults: z.number().int().min(0).optional(),
//   maxChildren: z.number().int().min(0).optional(),
//   maxInfants: z.number().int().min(0).optional(),
//   maxPets: z.number().int().min(0).optional(),
//   maxVehicles: z.number().int().min(0).optional(),
//   maxTents: z.number().int().min(0).optional(),
//   maxRVs: z.number().int().min(0).optional(),
//   rvMaxLength: z.number().min(0).optional(), // feet

//   // Concurrent Bookings (designated vs undesignated)
//   // 1 = designated (only 1 booking at a time)
//   // 2+ = undesignated (multiple concurrent bookings, "X sites left")
//   maxConcurrentBookings: z.number().int().min(1).max(100).default(1),
// });

// Pricing sub-schema
// const pricingSchema = z.object({
//   basePrice: z.number().min(0),
//   weekendPrice: z.number().min(0).optional(),
//   currency: z.string().default("VND"),
//   seasonalPricing: z
//     .array(
//       z.object({
//         name: z.string().max(100),
//         startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/), // YYYY-MM-DD
//         endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
//         price: z.number().min(0),
//       })
//     )
//     .optional(),
//   discounts: z
//     .object({
//       weekly: z.number().min(0).max(100).optional(), // percentage
//       monthly: z.number().min(0).max(100).optional(),
//     })
//     .optional(),
//   fees: z
//     .object({
//       cleaningFee: z.number().min(0).optional(),
//       petFee: z.number().min(0).optional(),
//       extraGuestFee: z.number().min(0).optional(),
//       extraVehicleFee: z.number().min(0).optional(),
//     })
//     .optional(),
// });

// Booking settings sub-schema
// const bookingSettingsSchema = z.object({
//   minimumNights: z.number().int().min(1).default(1),
//   maximumNights: z.number().int().min(1).optional(),
//   checkInTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/), // HH:MM format
//   checkOutTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
//   allowInstantBook: z.boolean().default(false),
//   requireApproval: z.boolean().default(true),
// });

// Validator cho tạo site
export const createSiteSchema = z.object({
  // Property reference (required)
  property: z.string(),

  // Basic Info
  name: z.string().min(2).max(200),
  slug: z.string().min(2).max(200).optional(),
  description: z.string().max(2000).optional(),

  // Accommodation Type
  accommodationType: z.enum([
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
  ]),

  lodgingProvided: z.enum(["bring_your_own", "structure_provided", "vehicle_provided"]).optional(),

  // Site Location (within property)
  siteLocation: z
    .object({
      coordinates: z
        .object({
          type: z.literal("Point").default("Point"),
          coordinates: z.tuple([
            z.number().min(-180, "Longitude must be >= -180").max(180, "Longitude must be <= 180"),
            z.number().min(-90, "Latitude must be >= -90").max(90, "Latitude must be <= 90"),
          ]), // [lng, lat]
        })
        .optional(),
      mapPinLabel: z.string().max(50).optional(),
      relativeDescription: z.string().max(200).optional(),
    })
    .optional(),

  terrain: z.enum(["forest", "beach", "mountain", "desert", "farm"]).optional(),

  // Capacity
  capacity: z.object({
    maxGuests: z.number().int().min(1),
    maxAdults: z.number().int().min(0).optional(),
    maxChildren: z.number().int().min(0).optional(),
    maxInfants: z.number().int().min(0).optional(),
    maxPets: z.number().int().min(0).optional(),
    maxVehicles: z.number().int().min(0).optional(),
    maxTents: z.number().int().min(0).optional(),
    maxRVs: z.number().int().min(0).optional(),
    rvMaxLength: z.number().min(0).optional(),
    maxConcurrentBookings: z.number().int().min(1).max(100).default(1),
  }),

  // Pricing
  pricing: z.object({
    rateType: z.enum(["site", "person"]).default("site").optional(),
    basePrice: z.number().min(0),
    weekendPrice: z.number().min(0).optional(),
    weeklyDiscount: z.number().min(0).max(100).optional(),
    monthlyDiscount: z.number().min(0).max(100).optional(),
    additionalGuestFee: z.number().min(0).optional(),
    petFee: z.number().min(0).optional(),
    vehicleFee: z.number().min(0).optional(),
    cleaningFee: z.number().min(0).optional(),
    depositAmount: z.number().min(0).optional(),
    currency: z.string().default("VND"),
    seasonalPricing: z
      .array(
        z.object({
          name: z.string(),
          startDate: z.coerce.date(),
          endDate: z.coerce.date(),
          price: z.number().min(0),
        })
      )
      .optional(),
  }),

  // Booking Settings
  bookingSettings: z.object({
    minimumNights: z.number().int().min(1).default(1),
    maximumNights: z.number().int().min(1).optional(),
    checkInTime: z.string().default("14:00"),
    checkOutTime: z.string().default("11:00"),
    instantBook: z.boolean().default(false),
    advanceNotice: z.number().min(0).default(24),
    preparationTime: z.number().min(0).optional(),
    allowSameDayBooking: z.boolean().default(false),
  }),

  // Photos
  photos: z
    .array(
      z.object({
        url: z.string().url(),
        caption: z.string().max(200).optional(),
        isCover: z.boolean().default(false),
        order: z.number().int().min(0).default(0),
      })
    )
    .optional(),

  // Amenities (array of Amenity IDs)
  amenities: z.array(z.string()).optional(),

  // What to bring
  guestsShouldBring: z.array(z.string()).optional(),

  // Site-specific rules
  siteSpecificRules: z.array(z.string().max(500)).optional(),

  // Status
  status: z.enum(["active", "inactive", "blocked"]).default("active"),
  isActive: z.boolean().default(true),
  isAvailableForBooking: z.boolean().default(true),
  unavailableReason: z.string().max(500).optional(),
  siteClass: z.enum(["basic", "vip"]).default("basic").optional(),
  services: z
    .array(
      z.object({
        name: z.string().min(1).max(200),
        description: z.string().max(1000).optional(),
        pricing: z
          .array(
            z.object({
              price: z.number().min(0),
              unit: z.string().max(100).default("lượt"),
              timeValue: z.number().min(1).default(1).optional(),
              timeUnit: z.string().max(100).default("luot").optional(),
            })
          )
          .min(1),
        isInventoryTracked: z.boolean().optional(),
        totalInventory: z.number().min(0).optional(),
      })
    )
    .optional(),
  unitNames: z.array(z.string()).optional(),
});


export const updateSiteSchema = createSiteSchema.partial();

// Validator cho search/filter sites
export const searchSiteSchema = z.object({
  // Property filter (required for listing sites within a property)
  property: z.string().optional(),

  // Search
  search: z.string().optional(),

  // Accommodation type filter
  accommodationType: z
    .union([
      z.enum([
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
      ]),
      z.array(
        z.enum([
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
        ])
      ),
    ])
    .optional()
    .transform((val) => {
      if (typeof val === "string") return [val];
      return val;
    }),

  // Capacity filters
  minGuests: z.coerce.number().int().min(1).optional(),
  maxGuests: z.coerce.number().int().min(1).optional(),
  allowPets: z.coerce.boolean().optional(),
  allowRVs: z.coerce.boolean().optional(),

  // Price range
  minPrice: z.coerce.number().min(0).optional(),
  maxPrice: z.coerce.number().min(0).optional(),

  // Amenity filters (array of amenity IDs)
  // Deprecated individual amenity filters removed (hasElectrical, hasWaterHookup, etc.)
  // Use amenities array instead
  amenities: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((val) => {
      if (typeof val === "string") return val.split(",").map((v) => v.trim());
      return val;
    }),

  // Availability filters
  checkIn: z.string().optional(), // ISO date
  checkOut: z.string().optional(),

  // Booking settings
  instantBookOnly: z.coerce.boolean().optional(),

  // Status filters
  isActive: z.coerce.boolean().optional(),
  isAvailable: z.coerce.boolean().optional(),

  // Rating filter
  minRating: z.coerce.number().min(0).max(5).optional(),

  // Sorting
  sortBy: z
    .enum(["newest", "oldest", "price-low", "price-high", "rating", "name", "capacity"])
    .optional()
    .default("newest"),

  // Pagination
  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(20),
});

// Validator cho query single site
export const getSiteSchema = z.object({
  id: z.string().optional(),
  slug: z.string().optional(),
  property: z.string().optional(), // property ID for slug lookup
});

// Type exports
export type CreateSiteInput = z.infer<typeof createSiteSchema>;
export type UpdateSiteInput = z.infer<typeof updateSiteSchema>;
export type SearchSiteInput = z.infer<typeof searchSiteSchema>;
export type GetSiteInput = z.infer<typeof getSiteSchema>;
