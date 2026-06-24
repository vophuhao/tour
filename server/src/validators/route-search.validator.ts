import { z } from "zod";

export const routeSearchSchema = z.object({
  points: z.array(z.tuple([z.number().min(-180).max(180), z.number().min(-90).max(90)])).min(1),
  radius: z.coerce.number().min(0).max(100).default(10), // Bán kính tìm kiếm (km)
  
  // Các bộ lọc bổ sung
  guests: z.coerce.number().int().min(1).optional(),
  pets: z.coerce.number().int().min(0).optional(),
  
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

  campingStyle: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((val) => {
      if (!val) return undefined;
      if (Array.isArray(val)) return val;
      return val.split(",").map((v) => v.trim()).filter(Boolean);
    }),

  amenities: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((val) => {
      if (typeof val === "string") return val.split(",").map((v) => v.trim());
      return val;
    }),

  checkIn: z.string().optional(),
  checkOut: z.string().optional(),

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
    ])
    .optional()
    .default("reviewCount"),

  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(20),
});

export type RouteSearchInput = z.infer<typeof routeSearchSchema>;
