import { ErrorFactory } from "@/errors";
import {
  BookingModel,
  PropertyAvailabilityModel,
  PropertyModel,
  ReviewModel,
  SiteModel,
  UserModel,
  AvailabilityModel,
  type PropertyAvailabilityDocument,
  type PropertyDocument,
} from "@/models";
import appAssert from "../utils/app-assert";
import type {
  CreatePropertyInput,
  SearchPropertyInput,
  UpdatePropertyInput,
} from "@/validators/property.validator";
import type { RouteSearchInput } from "../validators/route-search.validator";
import mongoose, { isValidObjectId } from "mongoose";
import { notifyPropertyChange } from "../socket";

export class PropertyService {
  /**
   * Create new property (host or admin only)
   */
  async createProperty(hostId: string, input: CreatePropertyInput): Promise<PropertyDocument> {
    // Auto-generate slug if not provided
    const slug = input.slug || this.generateSlug(input.name);

    // Check duplicate slug
    const existingProperty = await PropertyModel.findOne({ slug });
    appAssert(!existingProperty, ErrorFactory.conflict("Slug đã tồn tại"));

    const property = await PropertyModel.create({
      ...input,
      slug,
      host: hostId,
      isActive: true,
      status: "active",
    });

    return property;
  }

  /**
   * Get property by ID or slug
   */
  async getProperty(idOrSlug: string): Promise<PropertyDocument> {
    const query = isValidObjectId(idOrSlug) ? { _id: idOrSlug } : { slug: idOrSlug };

    const property = await PropertyModel.findOne(query).populate(
      "host",
      "username email avatarUrl phoneNumber bio"
    );

    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    // Increment view count in Redis
    try {
      const { redisClient } = require("../config/redis");
      redisClient.hIncrBy("property_views", property._id.toString(), 1).catch(() => {});
      
      const redisViews = await redisClient.hGet("property_views", property._id.toString());
      if (redisViews && property.stats) {
        property.stats.viewCount += parseInt(redisViews);
      }
    } catch (err) {
      console.warn("Failed to increment/read property views in Redis:", err);
    }

    return property!;
  }

  /**
   * Get property with sites
   */
  async getPropertyWithSites(idOrSlug: string) {
    const property = await this.getProperty(idOrSlug);

    // Get all active sites for this property with populated amenities
    const sites = await SiteModel.find({
      property: property._id,
      isActive: true,
    })
      .populate("amenities", "name icon category description")
      .sort({ createdAt: -1 });

    return {
      property,
      sites,
      siteCount: sites.length,
    };
  }

  /**
   * Update property (host or admin only)
   */
  async updateProperty(
    propertyId: string,
    hostId: string,
    input: UpdatePropertyInput,
    isAdmin = false
  ): Promise<PropertyDocument> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    // Check ownership unless admin
    if (!isAdmin) {
      appAssert(
        property!.host.toString() === hostId,
        ErrorFactory.forbidden("Bạn không có quyền chỉnh sửa property này")
      );

      if (property!.status === "blocked") {
        input.status = "blocked";
        input.isActive = false;
      } else if (input.isActive !== undefined) {
        input.status = input.isActive ? "active" : "inactive";
      }
    } else {
      if (input.isActive !== undefined && input.status === undefined) {
        input.status = input.isActive ? "active" : "inactive";
      }
    }

    // Update slug if name changed
    if (input.name && input.name !== property!.name) {
      (input as any).slug = this.generateSlug(input.name);
    }

    Object.assign(property, input);
    await property!.save();

    notifyPropertyChange(propertyId);

    return property;
  }

  /**
   * Admin lock property (blocked)
   */
  async adminLockProperty(propertyId: string, reason: string): Promise<PropertyDocument> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    property.status = "blocked";
    property.isActive = false;
    await property.save();

    notifyPropertyChange(propertyId);

    // Notify host
    try {
      const NotificationServiceClass = (await import("@/services/notification.service")).default;
      const notificationService = new NotificationServiceClass();
      const hostId = property.host.toString();
      await notificationService.createPropertyLockedForHost(hostId, propertyId, property.name, reason);
    } catch (err) {
      console.error("Failed to notify host about property lock:", err);
    }

    return property;
  }

  /**
   * Admin unlock property (active)
   */
  async adminUnlockProperty(propertyId: string): Promise<PropertyDocument> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    property.status = "active";
    property.isActive = true;
    await property.save();

    notifyPropertyChange(propertyId);

    // Notify host
    try {
      const NotificationServiceClass = (await import("@/services/notification.service")).default;
      const notificationService = new NotificationServiceClass();
      const hostId = property.host.toString();
      await notificationService.createPropertyUnlockedForHost(hostId, propertyId, property.name);
    } catch (err) {
      console.error("Failed to notify host about property unlock:", err);
    }

    return property;
  }

  /**
   * Admin approve property update (blocked → active)
   */
  async adminApproveProperty(propertyId: string): Promise<PropertyDocument> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(
      property.status === "blocked",
      ErrorFactory.badRequest("Property không ở trạng thái bị khóa")
    );

    property.status = "active";
    property.isActive = true;
    await property.save();

    notifyPropertyChange(propertyId);

    // Notify host
    try {
      const NotificationServiceClass = (await import("@/services/notification.service")).default;
      const notificationService = new NotificationServiceClass();
      const hostId = property.host.toString();
      await notificationService.createPropertyUnlockedForHost(hostId, propertyId, property.name);
    } catch (err) {
      console.error("Failed to notify host about property approval:", err);
    }

    return property;
  }

  /**
   * Get properties and sites of a host (for admin view)
   */
  async getHostPropertiesWithSites(hostId: string): Promise<any[]> {
    const properties = await PropertyModel.find({ host: hostId })
      .sort({ createdAt: -1 })
      .lean();

    const propertiesWithSites = await Promise.all(
      properties.map(async (property) => {
        const sites = await SiteModel.find({ property: property._id })
          .populate("amenities", "name icon category description")
          .sort({ createdAt: -1 })
          .lean();
        return { ...property, sites };
      })
    );

    return propertiesWithSites;
  }

  /**
   * Delete property (soft delete - deactivate only)
   */
  async deleteProperty(propertyId: string, hostId: string, isAdmin = false): Promise<void> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    // Check ownership unless admin
    if (!isAdmin) {
      appAssert(
        property.host.toString() === hostId,
        ErrorFactory.forbidden("Bạn không có quyền xóa property này")
      );
    }

    // Deactivate property and all its sites
    await property.deactivate();
    await SiteModel.updateMany({ property: propertyId }, { isActive: false });

    notifyPropertyChange(propertyId);
  }

  /**
   * Activate property
   */
  async activateProperty(
    propertyId: string,
    hostId: string,
    isAdmin = false
  ): Promise<PropertyDocument> {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    // Check ownership unless admin
    if (!isAdmin) {
      appAssert(
        property.host.toString() === hostId,
        ErrorFactory.forbidden("Bạn không có quyền kích hoạt property này")
      );
      appAssert(
        property.status !== "blocked",
        ErrorFactory.forbidden("Property đang bị khóa bởi Admin. Vui lòng liên hệ Admin để mở khóa.")
      );
    }

    // Check if property has at least one active site
    const siteCount = await SiteModel.countDocuments({ property: propertyId, isActive: true });
    appAssert(siteCount > 0, ErrorFactory.badRequest("Property phải có ít nhất 1 site hoạt động"));

    await property.activate();
    notifyPropertyChange(propertyId);
    return property;
  }

  /**
   * Search and filter properties with pagination
   */
  async searchProperties(input: SearchPropertyInput) {
    const {
      search,
      city,
      state,
      country,
      checkIn,
      checkOut,
      guests,
      pets,
      lat,
      lng,
      radius,
      propertyType,
      campingStyle,
      amenities,
      instantBooking,
      instantBook, // Alias from frontend
      isActive,
      isFeatured,
      isVerified,
      host,
      minRating,
      sortBy,
      page,
      limit,
    } = input;

    // Use instantBook if instantBooking not provided (frontend sends instantBook)
    const shouldFilterInstantBook = instantBook ?? instantBooking;

    const query: any = {};

    // Filter out properties from blocked hosts
    const blockedHosts = await UserModel.find({ isBlocked: true }).distinct("_id");
    if (blockedHosts.length > 0) {
      query.host = { $nin: blockedHosts };
    }

    // Text search
    if (search) {
      query.$text = { $search: search };
    }

    // Location filters
    if (city) query["location.city"] = new RegExp(city, "i");
    if (state) query["location.state"] = new RegExp(state, "i");
    if (country) query["location.country"] = country;

    // Geospatial search (near location)
    // Use $near ONLY when sorting by distance (or no sort)
    // Use $geoWithin when sorting by other fields (MongoDB restriction)
    if (lat && lng && radius) {
      const useNearSort = !sortBy || sortBy === "nearestFirst";

      if (useNearSort) {
        query["location.coordinates"] = {
          $near: {
            $geometry: {
              type: "Point",
              coordinates: [lng, lat], // [lng, lat]
            },
            $maxDistance: radius * 1000, // convert km to meters
          },
        };
      } else {
        // Use $geoWithin for filtering without geospatial sort
        query["location.coordinates"] = {
          $geoWithin: {
            $centerSphere: [[lng, lat], radius / 6378.1], // radius in km, Earth radius in km
          },
        };
      }
    }

    // Property type filter
    if (propertyType && propertyType.length > 0) {
      query.propertyType = { $in: propertyType };
    }

    // Note: Amenity filters like hasToilets, hasShowers, hasParking, hasWifi, hasElectricity, hasWater
    // are no longer applicable at Property level since sharedAmenities field was removed.
    // These filters should be handled at Site level instead.

    // Amenities filter - CRITICAL ARCHITECTURE NOTE:
    // - Property model has NO 'amenities' field
    // - Amenities are stored at Site level as ObjectId[] refs to Amenity model
    // - Strategy: Query Sites with matching amenity IDs, get Property IDs
    let amenityPropertyIds: mongoose.Types.ObjectId[] | undefined;
    if (amenities && amenities.length > 0) {
      // Query sites that have any of the requested amenities
      const sitesWithAmenities = await SiteModel.find({
        amenities: { $in: amenities.filter((id) => isValidObjectId(id)) },
        isActive: true,
      })
        .select("property")
        .lean();

      amenityPropertyIds = [...new Set(sitesWithAmenities.map((s) => s.property))];

      // If no sites match, return empty results
      if (amenityPropertyIds.length === 0) {
        return {
          properties: [],
          pagination: {
            page,
            limit,
            total: 0,
            pages: 0,
          },
        };
      }

      // Add to query - merge with existing _id filter if present
      if (query._id) {
        // Merge with existing filters
        const existingIds = query._id.$in || [];
        query._id = { $in: existingIds.filter((id: any) => amenityPropertyIds!.includes(id)) };

        // If no overlap, return empty
        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: {
              page,
              limit,
              total: 0,
              pages: 0,
            },
          };
        }
      } else {
        query._id = { $in: amenityPropertyIds };
      }
    }

    // Date range & capacity availability filter
    // Strategy: Query sites that are available and have sufficient capacity,
    // then filter properties that have those sites
    let availabilityPropertyIds: mongoose.Types.ObjectId[] | undefined;
    if (checkIn && checkOut) {
      const checkInDate = new Date(checkIn);
      const checkOutDate = new Date(checkOut);

      // Validate dates
      if (checkInDate >= checkOutDate) {
        return {
          properties: [],
          pagination: {
            page,
            limit,
            total: 0,
            pages: 0,
          },
        };
      }

      // Calculate number of nights
      const nights = Math.ceil(
        (checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24)
      );

      // Build site query for availability
      const siteQuery: any = { isActive: true };

      // Capacity filters
      if (guests) {
        siteQuery["capacity.maxGuests"] = { $gte: guests };
      }
      if (pets && pets > 0) {
        siteQuery["capacity.maxPets"] = { $gte: pets };
      }

      // Booking settings filters - nights must be within min/max range
      siteQuery["bookingSettings.minimumNights"] = { $lte: nights };
      // maximumNights is optional, so only filter if it exists and is set
      siteQuery.$or = [
        { "bookingSettings.maximumNights": { $exists: false } },
        { "bookingSettings.maximumNights": null },
        { "bookingSettings.maximumNights": { $gte: nights } },
      ];

      // Find all potentially available sites
      const candidateSites = await SiteModel.find(siteQuery).select("_id property").lean();

      if (candidateSites.length === 0) {
        return {
          properties: [],
          pagination: {
            page,
            limit,
            total: 0,
            pages: 0,
          },
        };
      }

      const candidateSiteIds = candidateSites.map((s) => s._id);

      // Find conflicting bookings for these sites
      const conflictingBookings = await BookingModel.find({
        site: { $in: candidateSiteIds },
        status: { $in: ["pending", "confirmed"] }, // Only active bookings
        $or: [
          // Booking starts during search period
          { checkIn: { $gte: checkInDate, $lt: checkOutDate } },
          // Booking ends during search period
          { checkOut: { $gt: checkInDate, $lte: checkOutDate } },
          // Booking spans entire search period
          { checkIn: { $lte: checkInDate }, checkOut: { $gte: checkOutDate } },
        ],
      })
        .select("site")
        .lean();

      const bookedSiteIds = new Set(conflictingBookings.map((b) => b.site.toString()));

      // Filter out booked sites
      const availableSites = candidateSites.filter((s) => !bookedSiteIds.has(s._id.toString()));

      if (availableSites.length === 0) {
        return {
          properties: [],
          pagination: {
            page,
            limit,
            total: 0,
            pages: 0,
          },
        };
      }

      availabilityPropertyIds = [...new Set(availableSites.map((s) => s.property))];

      // Merge with existing filters
      if (query._id) {
        const existingIds = query._id.$in || [];
        query._id = { $in: existingIds.filter((id: any) => availabilityPropertyIds!.includes(id)) };

        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: {
              page,
              limit,
              total: 0,
              pages: 0,
            },
          };
        }
      } else {
        query._id = { $in: availabilityPropertyIds };
      }
    } else if (guests || (pets && pets > 0)) {
      // No date range but have capacity requirements
      // Query sites with sufficient capacity
      const capacityQuery: any = { isActive: true };

      if (guests) {
        capacityQuery["capacity.maxGuests"] = { $gte: guests };
      }
      if (pets && pets > 0) {
        capacityQuery["capacity.maxPets"] = { $gte: pets };
      }

      const sitesWithCapacity = await SiteModel.find(capacityQuery).select("property").lean();

      if (sitesWithCapacity.length === 0) {
        return {
          properties: [],
          pagination: {
            page,
            limit,
            total: 0,
            pages: 0,
          },
        };
      }

      const capacityPropertyIds = [...new Set(sitesWithCapacity.map((s) => s.property))];

      // Merge with existing filters
      if (query._id) {
        const existingIds = query._id.$in || [];
        query._id = { $in: existingIds.filter((id: any) => capacityPropertyIds.includes(id)) };

        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: {
              page,
              limit,
              total: 0,
              pages: 0,
            },
          };
        }
      } else {
        query._id = { $in: capacityPropertyIds };
      }
    }

    // AccommodationType filter - query sites and get matching property IDs
    // Frontend sends: "tent", "rv", or "glamping"
    // "glamping" expands to all glamping accommodation types
    let accommodationPropertyIds: mongoose.Types.ObjectId[] | undefined;
    if (campingStyle && campingStyle.length > 0) {
      // Map simplified types to actual accommodationTypes
      const glampingTypes = [
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
      ];

      const accommodationTypes: string[] = [];
      campingStyle.forEach((style) => {
        if (style === "tent") {
          accommodationTypes.push("tent");
        } else if (style === "rv") {
          accommodationTypes.push("rv");
        } else if (style === "glamping") {
          accommodationTypes.push(...glampingTypes);
        }
      });

      const sitesWithAccommodation = await SiteModel.find({
        accommodationType: { $in: accommodationTypes },
        isActive: true,
      })
        .select("property")
        .lean();

      accommodationPropertyIds = [...new Set(sitesWithAccommodation.map((s) => s.property))];

      // If no sites match, return empty results
      if (accommodationPropertyIds.length === 0) {
        return {
          properties: [],
          pagination: {
            page,
            limit,
            total: 0,
            pages: 0,
          },
        };
      }

      // Merge with existing filters
      if (query._id) {
        const existingIds = query._id.$in || [];
        query._id = {
          $in: existingIds.filter((id: any) => accommodationPropertyIds!.includes(id)),
        };

        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: {
              page,
              limit,
              total: 0,
              pages: 0,
            },
          };
        }
      } else {
        query._id = { $in: accommodationPropertyIds };
      }
    }

    // Note: Pet and children policies removed from Property model
    // These filters are no longer applicable at property level

    // InstantBooking filter - check if property has instant booking enabled
    // OR if it has at least one site with instant booking
    if (shouldFilterInstantBook === true) {
      // Properties with instant booking enabled at property level
      query["settings.instantBookEnabled"] = true;
    }

    // Status filters
    if (isActive !== undefined) query.isActive = isActive;
    if (isFeatured !== undefined) query.isFeatured = isFeatured;
    if (isVerified !== undefined) query.isVerified = isVerified;

    // Host filter
    if (host) {
      // Merge with existing host filter if exists (blocked hosts)
      if (query.host && query.host.$nin) {
        query.host = { _id: host, $nin: query.host.$nin };
      } else {
        query.host = host;
      }
    }

    // Rating filter
    if (minRating) query["rating.average"] = { $gte: minRating };

    // Sorting
    let sort: any = {};
    switch (sortBy) {
      case "newest":
        sort = { createdAt: -1 };
        break;
      case "oldest":
        sort = { createdAt: 1 };
        break;
      case "rating":
        sort = { "rating.average": -1, "rating.count": -1 };
        break;
      case "reviewCount":
        sort = { "stats.totalReviews": -1 };
        break;
      case "minPrice-asc":
        sort = { minPrice: 1 };
        break;
      case "minPrice-desc":
        sort = { minPrice: -1 };
        break;
      case "name":
        sort = { name: 1 };
        break;
      case "totalSites":
        sort = { totalSites: -1 };
        break;
      case "nearestFirst":
        // Geospatial sort already handled by $near
        break;
      default:
        sort = { "stats.totalReviews": -1 }; // Default to popular
    }

    // Pagination
    const skip = (page - 1) * limit;

    // Check if we need to sort by minPrice - requires aggregation pipeline
    const needsMinPriceSort = sortBy === "minPrice-asc" || sortBy === "minPrice-desc";

    if (needsMinPriceSort) {
      // Use aggregation pipeline to join with sites and calculate minPrice
      const pipeline: any[] = [
        { $match: query },
        {
          $lookup: {
            from: "sites",
            localField: "_id",
            foreignField: "property",
            as: "sites",
          },
        },
        {
          $addFields: {
            minPrice: {
              $ifNull: [
                {
                  $min: {
                    $map: {
                      input: {
                        $filter: {
                          input: "$sites",
                          as: "site",
                          cond: { $eq: ["$$site.isActive", true] },
                        },
                      },
                      as: "site",
                      in: "$$site.pricing.basePrice",
                    },
                  },
                },
                999999999, // Default high value if no active sites
              ],
            },
          },
        },
        { $sort: sortBy === "minPrice-asc" ? { minPrice: 1 } : { minPrice: -1 } },
        { $skip: skip },
        { $limit: limit },
        {
          $lookup: {
            from: "users",
            localField: "host",
            foreignField: "_id",
            as: "host",
          },
        },
        { $unwind: { path: "$host", preserveNullAndEmptyArrays: true } },
        {
          $project: {
            sites: 0, // Remove sites array to avoid bloat
            "host.password": 0,
            "host.email": 0,
          },
        },
      ];

      const [properties, totalResult] = await Promise.all([
        PropertyModel.aggregate(pipeline),
        PropertyModel.countDocuments(query),
      ]);

      return {
        properties,
        pagination: {
          page,
          limit,
          total: totalResult,
          pages: Math.ceil(totalResult / limit),
        },
      };
    }

    // Standard query for non-price sorts
    // Dùng aggregation $lookup để lấy minPrice trong 1 query (tránh N+1)
    const pipeline: any[] = [
      { $match: { ...query, isActive: true } },
      {
        $lookup: {
          from: "sites",
          let: { propertyId: "$_id" },
          pipeline: [
            {
              $match: {
                $expr: { $eq: ["$property", "$$propertyId"] },
                isActive: true,
              },
            },
            { $sort: { "pricing.basePrice": 1 } },
            { $limit: 1 },
            { $project: { "pricing.basePrice": 1 } },
          ],
          as: "cheapestSite",
        },
      },
      {
        $addFields: {
          minPrice: {
            $ifNull: [
              { $arrayElemAt: ["$cheapestSite.pricing.basePrice", 0] },
              0,
            ],
          },
        },
      },
      { $project: { cheapestSite: 0 } }, // Xóa field tạm
      { $sort: Object.keys(sort).length > 0 ? sort : { "stats.totalReviews": -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $lookup: {
          from: "users",
          localField: "host",
          foreignField: "_id",
          as: "hostData",
        },
      },
      {
        $addFields: {
          host: { $arrayElemAt: ["$hostData", 0] },
        },
      },
      { $project: { hostData: 0, "host.password": 0, "host.email": 0 } },
    ];

    const [properties, total] = await Promise.all([
      PropertyModel.aggregate(pipeline),
      PropertyModel.countDocuments({ ...query, isActive: true }),
    ]);

    return {
      properties,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get properties by host
   */
  async getPropertiesByHost(hostId: string, page = 1, limit = 20) {
    const skip = (page - 1) * limit;

    const [properties, total] = await Promise.all([
      PropertyModel.find({ host: hostId }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      PropertyModel.countDocuments({ host: hostId }),
    ]);

    return {
      properties,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get property statistics for host dashboard
   */
  async getPropertyStats(propertyId: string, hostId: string) {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền xem thống kê property này")
    );

    // Get site statistics
    const sites = await SiteModel.find({ property: propertyId });
    const activeSites = sites.filter((s) => s.isActive);

    return {
      property: {
        name: property.name,
        totalSites: property.stats.totalSites,
        activeSites: activeSites.length,
        rating: property.rating,
        stats: property.stats,
      },
      sites: sites.map((s) => ({
        id: s._id,
        name: s.name,
        accommodationType: s.accommodationType,
        isActive: s.isActive,
        rating: s.rating,
        stats: s.stats,
      })),
    };
  }

  /**
   * Update property stats (called when booking/review created)
   */
  async updatePropertyStats(propertyId: string): Promise<void> {
    const property = await PropertyModel.findById(propertyId);
    if (!property) return;

    await property.updateStats();
  }

  /**
   * Update property rating based on reviews
   */
  async updatePropertyRating(propertyId: string): Promise<void> {
    const reviews = await ReviewModel.find({
      property: propertyId,
      isPublished: true,
    });

    if (reviews.length === 0) {
      await PropertyModel.findByIdAndUpdate(propertyId, {
        rating: {
          average: 0,
          count: 0,
          breakdown: {
            location: 0,
            communication: 0,
            value: 0,
          },
        },
      });
      return;
    }

    // Calculate averages
    const totals = reviews.reduce(
      (acc, review) => {
        acc.overall += review.overallRating;
        acc.location += review.propertyRatings.location;
        acc.communication += review.propertyRatings.communication;
        acc.value += review.propertyRatings.value;
        return acc;
      },
      { overall: 0, location: 0, communication: 0, value: 0 }
    );

    const count = reviews.length;
    const rating = {
      average: Math.round((totals.overall / count) * 10) / 10,
      count,
      breakdown: {
        location: Math.round((totals.location / count) * 10) / 10,
        communication: Math.round((totals.communication / count) * 10) / 10,
        value: Math.round((totals.value / count) * 10) / 10,
      },
    };

    await PropertyModel.findByIdAndUpdate(propertyId, { rating });
  }

  /**
   * Generate slug from name
   */
  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "") // Remove diacritics
      .replace(/đ/g, "d")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .substring(0, 200);
  }

  /**
   * Get featured properties
   */
  async getFeaturedProperties(limit = 10) {
    return PropertyModel.find({
      isFeatured: true,
      isActive: true,
    })
      .sort({ "rating.average": -1 })
      .limit(limit)
      .populate("host", "name avatar")
      .lean();
  }

  /**
   * Get nearby properties
   */
  async getNearbyProperties(propertyId: string, radius = 50, limit = 10) {
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));

    const [lng, lat] = property!.location.coordinates.coordinates;

    return PropertyModel.find({
      _id: { $ne: propertyId },
      isActive: true,
      "location.coordinates": {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [lng, lat],
          },
          $maxDistance: radius * 1000,
        },
      },
    })
      .limit(limit)
      .populate("host", "name avatar")
      .lean();
  }

  /**
   * Get personalized property recommendations based on user booking history
   * Strategy:
   * 1. Get user's booking history
   * 2. Extract properties/sites booked (locations, accommodation types)
   * 3. Find similar properties with:
   *    - Same state/region
   *    - Similar accommodation types from sites
   *    - Highly rated (avgRating >= 4.0)
   *    - Active and has active sites
   * 4. Return 8-12 properties excluding already booked ones
   *
   * IMPORTANT: Returns EMPTY ARRAY if user has no booking history
   * This is intentional - "Có thể bạn cũng thích" should ONLY show for users with bookings
   */
  async getPersonalizedRecommendations(userId: string, limit = 8) {
    // Get user's bookings (all statuses except cancelled/refunded)
    // Include pending/confirmed for users who just booked
    const userBookings = await BookingModel.find({
      guest: userId,
      status: { $nin: ["cancelled", "refunded"] }, // Exclude only cancelled/refunded
    })
      .populate("property", "location propertyType")
      .populate("site", "accommodationType")
      .sort({ createdAt: -1 }) // Sort by creation date (most recent first)
      .limit(10) // Analyze last 10 bookings
      .lean();

    // CRITICAL: Return empty array if no booking history
    // Frontend will hide section completely for users without bookings
    if (userBookings.length === 0) {
      console.log(`[Recommendations] User ${userId} has no booking history`);
      return [];
    }

    console.log(`[Recommendations] User ${userId} has ${userBookings.length} bookings`);

    // Extract preferences from booking history
    const bookedPropertyIds = new Set(userBookings.map((b: any) => b.property._id.toString()));
    const preferredStates = new Set(
      userBookings.map((b: any) => b.property?.location?.state).filter(Boolean)
    );
    const preferredAccommodationTypes = new Set(
      userBookings.map((b: any) => b.site?.accommodationType).filter(Boolean)
    );

    // Build query for similar properties
    const query: any = {
      _id: { $nin: Array.from(bookedPropertyIds).map((id) => new mongoose.Types.ObjectId(id)) },
      isActive: true,
      // RELAXED: Remove avgRating requirement - many properties might not have ratings yet
      // We'll sort by rating anyway, so good ones will appear first
    };

    // Prefer same state/region (optional - don't make it required)
    if (preferredStates.size > 0) {
      query["location.state"] = { $in: Array.from(preferredStates) };
    }

    // Find properties that have sites with preferred accommodation types
    let propertiesWithMatchingSites: string[] = [];
    if (preferredAccommodationTypes.size > 0) {
      const matchingSites = await SiteModel.find({
        accommodationType: { $in: Array.from(preferredAccommodationTypes) },
        isActive: true,
      })
        .select("property")
        .lean();

      propertiesWithMatchingSites = [...new Set(matchingSites.map((s) => s.property.toString()))];

      console.log(
        `[Recommendations] Found ${propertiesWithMatchingSites.length} properties with matching accommodation types`
      );

      if (propertiesWithMatchingSites.length > 0) {
        // Add to query if we found matching sites
        if (query._id) {
          query._id = {
            $nin: Array.from(bookedPropertyIds).map((id) => new mongoose.Types.ObjectId(id)),
            $in: propertiesWithMatchingSites.map((id) => new mongoose.Types.ObjectId(id)),
          };
        } else {
          query._id = {
            $in: propertiesWithMatchingSites.map((id) => new mongoose.Types.ObjectId(id)),
          };
        }
      }
    }

    const recommendations = await PropertyModel.find(query)
      .sort({
        avgRating: -1,
        totalReviews: -1,
        createdAt: -1, // Also sort by newest if no ratings
      })
      .limit(limit)
      .populate("host", "fullName avatar")
      .select("name slug location photos propertyType avgRating totalReviews lowestPrice")
      .lean();

    console.log(
      `[Recommendations] Returning ${recommendations.length} recommendations for user ${userId}`
    );

    // IMPORTANT: DO NOT fill with popular properties if not enough recommendations
    // We want to show ONLY truly personalized recommendations, not generic popular ones
    // If user doesn't have enough similar preferences, show fewer recommendations

    // However, if query is too restrictive and returns 0, try a broader query
    if (
      recommendations.length === 0 &&
      (preferredStates.size > 0 || preferredAccommodationTypes.size > 0)
    ) {
      console.log(`[Recommendations] No strict matches, trying broader query...`);

      // Try without state restriction, only accommodation type
      const broaderQuery: any = {
        _id: { $nin: Array.from(bookedPropertyIds).map((id) => new mongoose.Types.ObjectId(id)) },
        isActive: true,
      };

      if (propertiesWithMatchingSites.length > 0) {
        broaderQuery._id = {
          $nin: Array.from(bookedPropertyIds).map((id) => new mongoose.Types.ObjectId(id)),
          $in: propertiesWithMatchingSites.map((id) => new mongoose.Types.ObjectId(id)),
        };
      }

      const broaderRecommendations = await PropertyModel.find(broaderQuery)
        .sort({ avgRating: -1, totalReviews: -1, createdAt: -1 })
        .limit(limit)
        .populate("host", "fullName avatar")
        .select("name slug location photos propertyType avgRating totalReviews lowestPrice")
        .lean();

      console.log(
        `[Recommendations] Broader query returned ${broaderRecommendations.length} recommendations`
      );
      return broaderRecommendations;
    }

    return recommendations;
  }

  /**
   * Get popular properties (for separate "Popular" section, NOT for recommendations fallback)
   */
  async getPopularProperties(limit = 8) {
    return PropertyModel.find({ isActive: true })
      .sort({ totalReviews: -1, avgRating: -1 })
      .limit(limit)
      .populate("host", "fullName avatar")
      .select("name slug location photos propertyType avgRating totalReviews lowestPrice")
      .lean();
  }

  /**
   * Block dates for a property (host only)
   */
  async blockPropertyDates(
    propertyId: string,
    hostId: string,
    startDate: Date,
    endDate: Date,
    reason?: string
  ): Promise<PropertyAvailabilityDocument> {
    // Verify property exists and user is the host
    const property = await PropertyModel.findById(propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(
      property!.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền block property này")
    );

    // Validate dates
    appAssert(
      startDate < endDate,
      ErrorFactory.badRequest("Ngày bắt đầu phải trước ngày kết thúc")
    );

    // Create blocked date range
    const blocked = await PropertyAvailabilityModel.create({
      property: propertyId,
      startDate,
      endDate,
      reason,
      createdBy: hostId,
    });

    notifyPropertyChange(propertyId.toString());

    return blocked;
  }

  /**
   * Unblock dates for a property (host only)
   */
  async unblockPropertyDates(blockId: string, hostId: string): Promise<void> {
    const block = await PropertyAvailabilityModel.findById(blockId).populate("property");
    appAssert(block, ErrorFactory.resourceNotFound("Blocked dates"));

    // Verify ownership
    const property = block!.property as any;
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền unblock property này")
    );

    await PropertyAvailabilityModel.findByIdAndDelete(blockId);
    notifyPropertyChange(property._id.toString());
  }

  /**
   * Get all blocked dates for a property
   */
  async getPropertyBlockedDates(propertyId: string) {
    const propertyBlocks = await PropertyAvailabilityModel.find({
      property: propertyId,
      endDate: { $gte: new Date() }, // Only future/active blocks
    })
      .populate("property", "name")
      .sort({ startDate: 1 })
      .lean();

    // Get all sites for this property
    const sites = await SiteModel.find({ property: propertyId }).select("_id name");
    const siteIds = sites.map(s => s._id);

    // Get all manual/maintenance site blocks (not "booked" blocks)
    const siteBlocks = await AvailabilityModel.find({
      site: { $in: siteIds },
      date: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }, // Only future/active blocks
      isAvailable: false,
      blockType: { $ne: "booked" }
    })
      .sort({ site: 1, date: 1 })
      .lean();

    // Group consecutive daily blocks for each site into date ranges
    const siteRanges: any[] = [];
    const blocksBySite: Record<string, typeof siteBlocks> = {};

    siteBlocks.forEach((block) => {
      const siteIdStr = block.site.toString();
      if (!blocksBySite[siteIdStr]) {
        blocksBySite[siteIdStr] = [];
      }
      blocksBySite[siteIdStr].push(block);
    });

    for (const siteIdStr of Object.keys(blocksBySite)) {
      const siteName = sites.find(s => s._id.toString() === siteIdStr)?.name || "Site";
      const blocks = blocksBySite[siteIdStr];
      if (!blocks || blocks.length === 0) continue;

      let currentRange: any = null;

      blocks.forEach((block) => {
        const currentDate = new Date(block.date);
        currentDate.setHours(0, 0, 0, 0);

        if (!currentRange) {
          currentRange = {
            _id: `site-block-${siteIdStr}-${block.date.toISOString()}`,
            isSiteBlock: true,
            siteId: siteIdStr,
            siteName,
            startDate: block.date,
            endDate: block.date,
            reason: block.reason || "Bảo trì / Khóa lịch site",
            dates: [block.date.toISOString().split('T')[0]]
          };
        } else {
          // Check if block is the consecutive day
          const prevEnd = new Date(currentRange.endDate);
          prevEnd.setDate(prevEnd.getDate() + 1);
          prevEnd.setHours(0, 0, 0, 0);

          if (currentDate.getTime() === prevEnd.getTime()) {
            currentRange.endDate = block.date;
            currentRange.dates.push(block.date.toISOString().split('T')[0]);
          } else {
            siteRanges.push(currentRange);
            currentRange = {
              _id: `site-block-${siteIdStr}-${block.date.toISOString()}`,
              isSiteBlock: true,
              siteId: siteIdStr,
              siteName,
              startDate: block.date,
              endDate: block.date,
              reason: block.reason || "Bảo trì / Khóa lịch site",
              dates: [block.date.toISOString().split('T')[0]]
            };
          }
        }
      });

      if (currentRange) {
        siteRanges.push(currentRange);
      }
    }

    return [...propertyBlocks, ...siteRanges];
  }

  /**
   * Check if property has any blocked dates in range
   */
  async isPropertyBlocked(propertyId: string, checkIn: Date, checkOut: Date): Promise<boolean> {
    const blockedDates = await PropertyAvailabilityModel.findOne({
      property: propertyId,
      $or: [
        // Block starts before checkOut and ends after checkIn (overlap)
        {
          startDate: { $lt: checkOut },
          endDate: { $gt: checkIn },
        },
      ],
    });

    return !!blockedDates;
  }

  /**
   * Sync property view counts from Redis to MongoDB
   */
  async syncViewsFromRedis(): Promise<void> {
    const { redisClient } = await import("../config/redis");
    const keys = await redisClient.hKeys("property_views").catch(() => [] as string[]);
    const updateOps = [];

    for (const id of keys) {
      const countStr = await redisClient.hGet("property_views", id).catch(() => null);
      if (countStr) {
        const count = parseInt(countStr);
        await redisClient.hDel("property_views", id).catch(() => {});
        if (count > 0 && mongoose.isValidObjectId(id)) {
          updateOps.push({
            updateOne: {
              filter: { _id: id },
              update: { $inc: { "stats.viewCount": count } },
            },
          });
        }
      }
    }

    if (updateOps.length > 0) {
      await PropertyModel.bulkWrite(updateOps).catch((err) => {
        console.error("Failed to sync property views bulk write:", err);
      });
    }
  }

  /**
   * Search properties along a specific roadtrip route
   */
  async searchPropertiesAlongRoute(input: RouteSearchInput) {
    const {
      points,
      radius,
      guests,
      pets,
      propertyType,
      campingStyle,
      amenities,
      checkIn,
      checkOut,
      sortBy,
      page,
      limit,
    } = input;

    const query: any = {};

    // Filter out blocked hosts
    const blockedHosts = await UserModel.find({ isBlocked: true }).distinct("_id");
    if (blockedHosts.length > 0) {
      query.host = { $nin: blockedHosts };
    }

    // Geospatial filter: points along route
    if (points && points.length > 0) {
      query.$or = points.map(([lng, lat]) => ({
        "location.coordinates": {
          $geoWithin: {
            $centerSphere: [[lng, lat], radius / 6378.1],
          },
        },
      }));
    }

    // Property type
    if (propertyType && propertyType.length > 0) {
      query.propertyType = { $in: propertyType };
    }

    // Amenities (Site level)
    let amenityPropertyIds: mongoose.Types.ObjectId[] | undefined;
    if (amenities && amenities.length > 0) {
      const sitesWithAmenities = await SiteModel.find({
        amenities: { $in: amenities.filter((id) => isValidObjectId(id)) },
        isActive: true,
      })
        .select("property")
        .lean();

      amenityPropertyIds = [...new Set(sitesWithAmenities.map((s) => s.property))];
      if (amenityPropertyIds.length === 0) {
        return {
          properties: [],
          pagination: { page, limit, total: 0, pages: 0 },
        };
      }
      query._id = { $in: amenityPropertyIds };
    }

    // Availability & Capacity
    let availabilityPropertyIds: mongoose.Types.ObjectId[] | undefined;
    if (checkIn && checkOut) {
      const checkInDate = new Date(checkIn);
      const checkOutDate = new Date(checkOut);

      if (checkInDate >= checkOutDate) {
        return {
          properties: [],
          pagination: { page, limit, total: 0, pages: 0 },
        };
      }

      const nights = Math.ceil(
        (checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24)
      );

      const siteQuery: any = { isActive: true };
      if (guests) {
        siteQuery["capacity.maxGuests"] = { $gte: guests };
      }
      if (pets && pets > 0) {
        siteQuery["capacity.maxPets"] = { $gte: pets };
      }
      siteQuery["bookingSettings.minimumNights"] = { $lte: nights };
      siteQuery.$or = [
        { "bookingSettings.maximumNights": { $exists: false } },
        { "bookingSettings.maximumNights": null },
        { "bookingSettings.maximumNights": { $gte: nights } },
      ];

      const candidateSites = await SiteModel.find(siteQuery).select("_id property").lean();

      if (candidateSites.length === 0) {
        return {
          properties: [],
          pagination: { page, limit, total: 0, pages: 0 },
        };
      }

      const candidateSiteIds = candidateSites.map((s) => s._id);
      const conflictingBookings = await BookingModel.find({
        site: { $in: candidateSiteIds },
        status: { $in: ["pending", "confirmed"] },
        $or: [
          { checkIn: { $gte: checkInDate, $lt: checkOutDate } },
          { checkOut: { $gt: checkInDate, $lte: checkOutDate } },
          { checkIn: { $lte: checkInDate }, checkOut: { $gte: checkOutDate } },
        ],
      })
        .select("site")
        .lean();

      const bookedSiteIds = new Set(conflictingBookings.map((b) => b.site.toString()));
      const availableSites = candidateSites.filter((s) => !bookedSiteIds.has(s._id.toString()));

      if (availableSites.length === 0) {
        return {
          properties: [],
          pagination: { page, limit, total: 0, pages: 0 },
        };
      }

      availabilityPropertyIds = [...new Set(availableSites.map((s) => s.property))];

      if (query._id) {
        const existingIds = query._id.$in || [];
        query._id = { $in: existingIds.filter((id: any) => availabilityPropertyIds!.includes(id)) };
        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: { page, limit, total: 0, pages: 0 },
          };
        }
      } else {
        query._id = { $in: availabilityPropertyIds };
      }
    } else if (guests || (pets && pets > 0)) {
      const capacityQuery: any = { isActive: true };
      if (guests) {
        capacityQuery["capacity.maxGuests"] = { $gte: guests };
      }
      if (pets && pets > 0) {
        capacityQuery["capacity.maxPets"] = { $gte: pets };
      }

      const sitesWithCapacity = await SiteModel.find(capacityQuery).select("property").lean();

      if (sitesWithCapacity.length === 0) {
        return {
          properties: [],
          pagination: { page, limit, total: 0, pages: 0 },
        };
      }

      const capacityPropertyIds = [...new Set(sitesWithCapacity.map((s) => s.property))];

      if (query._id) {
        const existingIds = query._id.$in || [];
        query._id = { $in: existingIds.filter((id: any) => capacityPropertyIds.includes(id)) };
        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: { page, limit, total: 0, pages: 0 },
          };
        }
      } else {
        query._id = { $in: capacityPropertyIds };
      }
    }

    // campingStyle filter
    if (campingStyle && campingStyle.length > 0) {
      const glampingTypes = [
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
      ];

      const accommodationTypes: string[] = [];
      campingStyle.forEach((style) => {
        if (style === "tent") {
          accommodationTypes.push("tent");
        } else if (style === "rv") {
          accommodationTypes.push("rv");
        } else if (style === "glamping") {
          accommodationTypes.push(...glampingTypes);
        }
      });

      const sitesWithAccommodation = await SiteModel.find({
        accommodationType: { $in: accommodationTypes },
        isActive: true,
      })
        .select("property")
        .lean();

      const accommodationPropertyIds = [...new Set(sitesWithAccommodation.map((s) => s.property))];

      if (accommodationPropertyIds.length === 0) {
        return {
          properties: [],
          pagination: { page, limit, total: 0, pages: 0 },
        };
      }

      if (query._id) {
        const existingIds = query._id.$in || [];
        query._id = {
          $in: existingIds.filter((id: any) => accommodationPropertyIds.includes(id)),
        };
        if (query._id.$in.length === 0) {
          return {
            properties: [],
            pagination: { page, limit, total: 0, pages: 0 },
          };
        }
      } else {
        query._id = { $in: accommodationPropertyIds };
      }
    }

    // Sorting
    let sort: any = {};
    switch (sortBy) {
      case "newest":
        sort = { createdAt: -1 };
        break;
      case "oldest":
        sort = { createdAt: 1 };
        break;
      case "rating":
        sort = { "rating.average": -1, "rating.count": -1 };
        break;
      case "reviewCount":
        sort = { "stats.totalReviews": -1 };
        break;
      case "minPrice-asc":
        sort = { minPrice: 1 };
        break;
      case "minPrice-desc":
        sort = { minPrice: -1 };
        break;
      case "name":
        sort = { name: 1 };
        break;
      case "totalSites":
        sort = { totalSites: -1 };
        break;
      default:
        sort = { "stats.totalReviews": -1 };
    }

    const skip = (page - 1) * limit;
    const needsMinPriceSort = sortBy === "minPrice-asc" || sortBy === "minPrice-desc";

    if (needsMinPriceSort) {
      const pipeline: any[] = [
        { $match: { ...query, isActive: true } },
        {
          $lookup: {
            from: "sites",
            localField: "_id",
            foreignField: "property",
            as: "sites",
          },
        },
        {
          $addFields: {
            minPrice: {
              $ifNull: [
                {
                  $min: {
                    $map: {
                      input: {
                        $filter: {
                          input: "$sites",
                          as: "site",
                          cond: { $eq: ["$$site.isActive", true] },
                        },
                      },
                      as: "site",
                      in: "$$site.pricing.basePrice",
                    },
                  },
                },
                999999999,
              ],
            },
          },
        },
        { $sort: sortBy === "minPrice-asc" ? { minPrice: 1 } : { minPrice: -1 } },
        { $skip: skip },
        { $limit: limit },
        {
          $lookup: {
            from: "users",
            localField: "host",
            foreignField: "_id",
            as: "host",
          },
        },
        { $unwind: { path: "$host", preserveNullAndEmptyArrays: true } },
        {
          $project: {
            sites: 0,
            "host.password": 0,
            "host.email": 0,
          },
        },
      ];

      const [properties, totalResult] = await Promise.all([
        PropertyModel.aggregate(pipeline),
        PropertyModel.countDocuments({ ...query, isActive: true }),
      ]);

      return {
        properties,
        pagination: {
          page,
          limit,
          total: totalResult,
          pages: Math.ceil(totalResult / limit),
        },
      };
    }

    // Standard query for non-price sorts
    const pipeline: any[] = [
      { $match: { ...query, isActive: true } },
      {
        $lookup: {
          from: "sites",
          let: { propertyId: "$_id" },
          pipeline: [
            {
              $match: {
                $expr: { $eq: ["$property", "$$propertyId"] },
                isActive: true,
              },
            },
            { $sort: { "pricing.basePrice": 1 } },
            { $limit: 1 },
            { $project: { "pricing.basePrice": 1 } },
          ],
          as: "cheapestSite",
        },
      },
      {
        $addFields: {
          minPrice: {
            $ifNull: [
              { $arrayElemAt: ["$cheapestSite.pricing.basePrice", 0] },
              0,
            ],
          },
        },
      },
      { $project: { cheapestSite: 0 } },
      { $sort: Object.keys(sort).length > 0 ? sort : { "stats.totalReviews": -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $lookup: {
          from: "users",
          localField: "host",
          foreignField: "_id",
          as: "hostData",
        },
      },
      {
        $addFields: {
          host: { $arrayElemAt: ["$hostData", 0] },
        },
      },
      { $project: { hostData: 0, "host.password": 0, "host.email": 0 } },
    ];

    const [properties, total] = await Promise.all([
      PropertyModel.aggregate(pipeline),
      PropertyModel.countDocuments({ ...query, isActive: true }),
    ]);

    return {
      properties,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Aggregate data of multiple properties for comparison
   */
  async compareProperties(ids: string[]) {
    const validIds = ids.filter((id) => isValidObjectId(id));
    if (validIds.length === 0) {
      return [];
    }

    const properties = await PropertyModel.find({
      _id: { $in: validIds },
      isActive: true,
    }).populate("host", "username avatarUrl");

    const compareList = [];
    for (const property of properties) {
      const sites = await SiteModel.find({
        property: property._id,
        isActive: true,
      }).populate("amenities", "name icon category");

      const terrains = [...new Set(sites.map((s) => s.terrain).filter(Boolean))];
      const accommodationTypes = [...new Set(sites.map((s) => s.accommodationType).filter(Boolean))];

      const uniqueAmenitiesMap = new Map<string, any>();
      sites.forEach((s) => {
        if (s.amenities) {
          s.amenities.forEach((a: any) => {
            uniqueAmenitiesMap.set(a._id.toString(), {
              _id: a._id,
              name: a.name,
              icon: a.icon,
              category: a.category,
            });
          });
        }
      });
      const amenities = Array.from(uniqueAmenitiesMap.values());

      const basePrices = sites
        .map((s) => s.pricing?.basePrice)
        .filter((p) => p !== undefined && p !== null);
      const minPrice = basePrices.length > 0 ? Math.min(...basePrices) : 0;

      const maxGuestsList = sites.map((s) => s.capacity?.maxGuests || 0);
      const maxGuests = maxGuestsList.length > 0 ? Math.max(...maxGuestsList) : 0;

      compareList.push({
        _id: property._id,
        name: property.name,
        slug: property.slug,
        photos: property.photos || [],
        propertyType: property.propertyType,
        rating: property.rating,
        stats: property.stats,
        location: property.location,
        host: property.host,
        landSize: property.landSize,
        minPrice,
        maxGuests,
        terrains,
        accommodationTypes,
        amenities,
        totalSites: sites.length,
      });
    }

    return compareList;
  }
}

export default new PropertyService();
// trigger reload
