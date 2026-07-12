import { z } from "zod";



// Validator cho tạo property
export const createPropertySchema = z.object({
  // Ownership
  host: z.string().optional(), // Will be set from auth context

  // Basic Info
  name: z.string().min(3).max(200),
  slug: z.string().min(3).max(200).optional(),
  tagline: z.string().min(10).max(200).optional(),
  description: z.string().min(0).max(5000),

  // Location
  location: z.object({
    address: z.string().min(5).max(500),
    city: z.string().min(2).max(100),
    state: z.string().min(2).max(100),
    zipCode: z.string().max(20).optional(),
    country: z.string().default("Vietnam"),
    coordinates: z.object({
      type: z.literal("Point").default("Point"),
      coordinates: z.tuple([
        z.number().min(-180, "Longitude must be >= -180").max(180, "Longitude must be <= 180"),
        z.number().min(-90, "Latitude must be >= -90").max(90, "Latitude must be <= 90"),
      ]), // [lng, lat]
    }),
    directions: z.string().max(1000).optional(),
    parkingInstructions: z.string().max(500).optional(),
  }),

  // Property Details
  landSize: z
    .object({
      value: z.number().min(0),
      unit: z.enum(["acres", "hectares", "square_meters"]),
    })
    .optional(),
  propertyType: z.enum(["private_land", "farm", "ranch", "campground"]),

  // Media
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

  nearbyAttractions: z
    .array(
      z.object({
        name: z.string().min(1),
        distance: z.number().min(0), // km
        type: z.string(),
      })
    )
    .optional(),

  // Property Rules
  rules: z
    .array(
      z.object({
        text: z.string().min(1).max(500),
        category: z.enum(["pets", "noise", "fire", "general"]).default("general"),
        order: z.number().int().min(0).default(0),
      })
    )
    .optional(),

  checkInInstructions: z.string().max(2000).optional(),
  checkOutInstructions: z.string().max(2000).optional(),



  // Property Settings
  settings: z
    .object({
      instantBookEnabled: z.boolean().default(false),
      requireApproval: z.boolean().default(true),
      minimumAdvanceNotice: z.number().int().min(0).default(24), // hours
      bookingWindow: z.number().int().min(1).default(365), // days
      allowWholePropertyBooking: z.boolean().default(false),
    })
    .optional(),
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
  status: z.enum(["active", "inactive", "blocked"]).default("active"),

  // Status
  isActive: z.boolean().default(true),
  isFeatured: z.boolean().default(false),
  isVerified: z.boolean().default(false),
});

export const updatePropertySchema = createPropertySchema.partial();

// Validator cho search/filter properties
export const searchPropertySchema = z.object({
  // Search
  search: z.string().optional(),

  // Location filters
  city: z.string().optional(),
  state: z.string().optional(),
  country: z.string().optional(),

  // Date range filters - for availability checking
  checkIn: z.string().optional(), // ISO date string (YYYY-MM-DD)
  checkOut: z.string().optional(), // ISO date string (YYYY-MM-DD)

  // Capacity filters
  guests: z.coerce.number().int().min(1).optional(), // Total guests
  pets: z.coerce.number().int().min(0).optional(), // Number of pets

  // Geospatial search
  lat: z.coerce.number().min(-90).max(90).optional(),
  lng: z.coerce.number().min(-180).max(180).optional(),
  radius: z.coerce.number().min(0).max(500).optional(), // km

  // Property type filter
  propertyType: z
    .union([
      z.enum(["private_land", "farm", "ranch", "campground"]),
      z.array(z.enum(["private_land", "farm", "ranch", "campground"])),
    ])
    .optional()
    .transform((val) => {
      if (typeof val === "string") return [val];
      return val;
    }),

  // Accommodation filter (accepts simplified types: tent, rv, glamping)
  // "glamping" will be expanded to all glamping accommodation types in service
  campingStyle: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((val) => {
      if (!val) return undefined;
      if (Array.isArray(val)) return val;
      // Handle comma-separated string from URL query params
      return val
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);
    })
    .refine(
      (val) => {
        if (!val) return true;
        return val.every((v) => ["tent", "rv", "glamping"].includes(v));
      },
      { message: "Invalid accommodation filter. Expected 'tent', 'rv', or 'glamping'" }
    ),

  // Amenities (comma-separated string or array of amenity IDs)
  // Note: Property-level amenity filters removed (hasToilets, hasShowers, hasParking, etc.)
  // Use amenities array to filter by Site amenities
  amenities: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((val) => {
      if (typeof val === "string") return val.split(",").map((v) => v.trim());
      return val;
    }),

  // Policy filters - deprecated, kept for backward compatibility but not used
  allowPets: z.coerce.boolean().optional(),
  allowChildren: z.coerce.boolean().optional(),
  instantBooking: z.coerce.boolean().optional(),
  instantBook: z.coerce.boolean().optional(), // Alias for instantBooking (from frontend)

  // Status filters
  isActive: z.coerce.boolean().optional(),
  isFeatured: z.coerce.boolean().optional(),
  isVerified: z.coerce.boolean().optional(),

  // Host filter
  host: z.string().optional(), // host user ID

  // Rating filter
  minRating: z.coerce.number().min(0).max(5).optional(),

  // Sorting
  sortBy: z
    .enum([
      "newest",
      "oldest",
      "rating",
      "reviewCount",
      "minPrice-asc",
      "minPrice-desc",
      "name",
      "totalSites",
      "nearestFirst", // requires lat/lng
    ])
    .optional()
    .default("reviewCount"),

  // Pagination
  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(20),
});

// Validator cho query single property
export const getPropertySchema = z.object({
  id: z.string().optional(),
  slug: z.string().optional(),
});

// Type exports
export type CreatePropertyInput = z.infer<typeof createPropertySchema>;
export type UpdatePropertyInput = z.infer<typeof updatePropertySchema>;
export type SearchPropertyInput = z.infer<typeof searchPropertySchema>;
export type GetPropertyInput = z.infer<typeof getPropertySchema>;
