import { ErrorFactory } from "@/errors";
import {
  AvailabilityModel,
  BookingModel,
  PropertyModel,
  ReviewModel,
  SiteModel,

  type SiteDocument,
} from "@/models";
import appAssert from "../utils/app-assert";
import type {
  CreateSiteInput,
  SearchSiteInput,
  UpdateSiteInput,
} from "@/validators/site.validator";
import { isValidObjectId } from "mongoose";
import { notifyPropertyChange } from "../socket";

export class SiteService {
  /**
   * Create new site (host or admin only)
   */
  async createSite(hostId: string, input: CreateSiteInput): Promise<SiteDocument> {
    // Verify property exists and belongs to host
    const property = await PropertyModel.findById(input.property);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền thêm site vào property này")
    );

    // Auto-generate slug if not provided
    const slug = input.slug || this.generateSlug(input.name);

    // Check duplicate slug within property
    const existingSite = await SiteModel.findOne({ property: input.property, slug });
    appAssert(!existingSite, ErrorFactory.conflict("Slug đã tồn tại trong property này"));

    const site = await SiteModel.create({
      ...input,
      slug,
    });

    // Update property's totalSites count
    await PropertyModel.findByIdAndUpdate(input.property, {
      $inc: { totalSites: 1 },
    });

    notifyPropertyChange(input.property.toString());

    return site;
  }

  /**
   * Get site by ID or slug
   */
  async getSite(idOrSlug: string, propertyId?: string): Promise<SiteDocument> {
    let query: any;

    if (isValidObjectId(idOrSlug)) {
      query = { _id: idOrSlug };
    } else {
      // Slug lookup requires property ID
      appAssert(propertyId, ErrorFactory.badRequest("Property ID required for slug lookup"));
      query = { slug: idOrSlug, property: propertyId };
    }

    const site = await SiteModel.findOne(query).populate("property", "name host location");

    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    // Increment view count
    await SiteModel.findByIdAndUpdate(site._id, { $inc: { "stats.viewCount": 1 } });

    return site;
  }

  /**
   * Get site with availability
   */
  async getSiteWithAvailability(siteId: string, checkIn?: string, checkOut?: string) {
    const site = await this.getSite(siteId);

    let availability: any = null;
    if (checkIn && checkOut) {
      availability = await this.checkAvailability(siteId, checkIn, checkOut);
    }

    return {
      site,
      availability,
    };
  }

  /**
   * Update site (host or admin only)
   */
  async updateSite(
    siteId: string,
    hostId: string,
    input: UpdateSiteInput,
    isAdmin = false
  ): Promise<SiteDocument> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const property = site.property as any;

    // Check ownership unless admin
    if (!isAdmin) {
      appAssert(
        property.host.toString() === hostId,
        ErrorFactory.forbidden("Bạn không có quyền chỉnh sửa site này")
      );

      if (site.status === "blocked") {
        input.status = "blocked";
        input.isActive = false;
        input.isAvailableForBooking = false;
      } else if (input.isActive !== undefined) {
        input.status = input.isActive ? "active" : "inactive";
        input.isAvailableForBooking = input.isActive;
      }
    } else {
      if (input.isActive !== undefined && input.status === undefined) {
        input.status = input.isActive ? "active" : "inactive";
        input.isAvailableForBooking = input.isActive;
      }
    }

    // Update slug if name changed
    if (input.name && input.name !== site.name) {
      input.slug = this.generateSlug(input.name);
    }
    Object.assign(site, input);
    await site.save();

    notifyPropertyChange(site.property.toString());

    return site;
  }

  /**
   * Admin lock site (blocked)
   */
  async adminLockSite(siteId: string, reason: string, propertyName?: string): Promise<SiteDocument> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const property = site.property as any;
    site.status = "blocked";
    site.isActive = false;
    site.isAvailableForBooking = false;
    await site.save();

    notifyPropertyChange(property._id.toString());

    // Notify host
    try {
      const NotificationServiceClass = (await import("@/services/notification.service")).default;
      const notificationService = new NotificationServiceClass();
      const hostId = property.host.toString();
      await notificationService.createSiteLockedForHost(
        hostId, siteId, site.name, propertyName || property.name || "Property", reason
      );
    } catch (err) {
      console.error("Failed to notify host about site lock:", err);
    }

    return site;
  }

  /**
   * Admin unlock site (active)
   */
  async adminUnlockSite(siteId: string, propertyName?: string): Promise<SiteDocument> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const property = site.property as any;
    site.status = "active";
    site.isActive = true;
    site.isAvailableForBooking = true;
    await site.save();

    notifyPropertyChange(property._id.toString());

    // Notify host
    try {
      const NotificationServiceClass = (await import("@/services/notification.service")).default;
      const notificationService = new NotificationServiceClass();
      const hostId = property.host.toString();
      await notificationService.createSiteUnlockedForHost(
        hostId, siteId, site.name, propertyName || property.name || "Property"
      );
    } catch (err) {
      console.error("Failed to notify host about site unlock:", err);
    }

    return site;
  }

  /**
   * Delete site (soft delete - deactivate only)
   */
  async deleteSite(siteId: string, hostId: string, isAdmin = false): Promise<void> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const property = site.property as any;

    // Check ownership unless admin
    if (!isAdmin) {
      appAssert(
        property.host.toString() === hostId,
        ErrorFactory.forbidden("Bạn không có quyền xóa site này")
      );
    }

    await site.deactivate();

    // Decrement property's totalSites count
    await PropertyModel.findByIdAndUpdate(site.property, {
      $inc: { totalSites: -1 },
    });

    notifyPropertyChange(site.property.toString());
  }

  /**
   * Activate site
   */
  async activateSite(siteId: string, hostId: string, isAdmin = false): Promise<SiteDocument> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const property = site.property as any;

    // Check ownership unless admin
    if (!isAdmin) {
      appAssert(
        property.host.toString() === hostId,
        ErrorFactory.forbidden("Bạn không có quyền kích hoạt site này")
      );
      appAssert(
        site.status !== "blocked",
        ErrorFactory.forbidden("Site đang bị khóa bởi Admin. Vui lòng liên hệ Admin để mở khóa.")
      );
    }

    await site.activate();
    notifyPropertyChange(site.property.toString());
    return site;
  }

  /**
   * Search and filter sites with pagination
   */
  async searchSites(input: SearchSiteInput) {
    const {
      property,
      search,
      accommodationType,
      minGuests,
      maxGuests,
      allowPets,
      allowRVs,
      minPrice,
      maxPrice,
      amenities, // Now expects array of amenity IDs
      checkIn,
      checkOut,
      instantBookOnly,
      isActive,
      isAvailable,
      minRating,
      sortBy,
      page,
      limit,
    } = input;

    const query: any = {};

    // Property filter (required for listing sites within a property)
    if (property) query.property = property;

    // Text search
    if (search) {
      query.$or = [{ name: new RegExp(search, "i") }, { description: new RegExp(search, "i") }];
    }

    // Accommodation type filter
    if (accommodationType && accommodationType.length > 0) {
      query.accommodationType = { $in: accommodationType };
    }

    // Capacity filters
    if (minGuests) query["capacity.maxGuests"] = { $gte: minGuests };
    if (maxGuests) query["capacity.maxGuests"] = { $lte: maxGuests };
    if (allowPets) query["capacity.maxPets"] = { $gt: 0 };
    if (allowRVs) query["capacity.maxRVs"] = { $gt: 0 };

    // Price range
    if (minPrice) query["pricing.basePrice"] = { $gte: minPrice };
    if (maxPrice) {
      query["pricing.basePrice"] = {
        ...query["pricing.basePrice"],
        $lte: maxPrice,
      };
    }

    // Amenity filters - Now uses ObjectId[] refs to Amenity model
    // Filter by amenity IDs array
    if (amenities && amenities.length > 0) {
      query.amenities = { $in: amenities };
    }

    // Booking settings
    if (instantBookOnly) query["bookingSettings.instantBook"] = true;

    // Status filters
    if (isActive !== undefined) query.isActive = isActive;
    if (isAvailable !== undefined) query.isAvailableForBooking = isAvailable;

    // Rating filter
    if (minRating) query["rating.average"] = { $gte: minRating };

    // Availability check
    if (checkIn && checkOut) {
      const unavailableSiteIds = await this.getUnavailableSites(checkIn, checkOut);
      query._id = { $nin: unavailableSiteIds };
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
      case "price-low":
        sort = { "pricing.basePrice": 1 };
        break;
      case "price-high":
        sort = { "pricing.basePrice": -1 };
        break;
      case "rating":
        sort = { "rating.average": -1, "rating.count": -1 };
        break;
      case "name":
        sort = { name: 1 };
        break;
      case "capacity":
        sort = { "capacity.maxGuests": -1 };
        break;
      default:
        sort = { createdAt: -1 };
    }

    // Pagination
    const skip = (page - 1) * limit;

    const [sites, total] = await Promise.all([
      SiteModel.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .populate("property", "name host location")
        .populate("amenities", "name icon category")
        .lean(),
      SiteModel.countDocuments(query),
    ]);

    return {
      sites,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get all blocked dates for a site (for calendar display)
   * Now supports maxConcurrentBookings - only blocks when capacity is full
   */
  async getBlockedDates(siteId: string, startDate: string, endDate: string) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    // Get site with capacity info
    const site = await SiteModel.findById(siteId);
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const maxConcurrent = site.capacity.maxConcurrentBookings || 1;
    const isUndesignated = maxConcurrent > 1;

    // Get all availability records where isAvailable = false
    // NOTE: For UNDESIGNATED sites, we IGNORE these records as they shouldn't exist
    // Only DESIGNATED sites use Availability records for blocking
    const blockedRecords = await AvailabilityModel.find({
      site: siteId,
      date: { $gte: start, $lte: end },
      isAvailable: false,
    }).lean();

    // Get all bookings that overlap with the date range
    const bookings = await BookingModel.find({
      site: siteId,
      status: { $in: ["pending", "confirmed"] },
      checkIn: { $lte: end },
      checkOut: { $gte: start },
    }).lean();

    const allBlockedDates = new Set<string>();

    // Add dates from availability records (ONLY for designated sites)
    // For undesignated sites, ignore availability records
    if (!isUndesignated) {
      blockedRecords.forEach((record) => {
        allBlockedDates.add(record.date.toISOString());
      });
    } else {
      // Log warning if undesignated site has availability blocks (shouldn't happen)
      if (blockedRecords.length > 0) {
        console.log(
          `[getBlockedDates] WARNING: Undesignated site ${site.name} has ${blockedRecords.length} availability blocks - these will be IGNORED`
        );
      }
    }

    // For bookings, only block dates when capacity is FULL
    if (maxConcurrent === 1) {
      // Designated site (capacity = 1): Block all booked dates INCLUDING checkout day
      bookings.forEach((booking) => {
        const bookingStart = new Date(booking.checkIn);
        const bookingEnd = new Date(booking.checkOut);
        const currentDate = new Date(bookingStart);

        // Include checkout day by using <= instead of <
        while (currentDate <= bookingEnd) {
          if (currentDate >= start && currentDate <= end) {
            allBlockedDates.add(currentDate.toISOString());
          }
          currentDate.setDate(currentDate.getDate() + 1);
        }
      });
    } else {
      // Undesignated site (capacity > 1): Only block dates when concurrent bookings >= maxConcurrent
      // Build a map of date -> booking count
      const dateBookingCount = new Map<string, number>();

      bookings.forEach((booking) => {
        const bookingStart = new Date(booking.checkIn);
        const bookingEnd = new Date(booking.checkOut);
        const currentDate = new Date(bookingStart);

        // Include checkout day by using <= instead of <
        while (currentDate <= bookingEnd) {
          if (currentDate >= start && currentDate <= end) {
            const dateKey = currentDate.toISOString();
            dateBookingCount.set(dateKey, (dateBookingCount.get(dateKey) || 0) + 1);
          }
          currentDate.setDate(currentDate.getDate() + 1);
        }
      });

      // Only block dates where booking count >= maxConcurrent
      dateBookingCount.forEach((count, dateKey) => {
        if (count >= maxConcurrent) {
          allBlockedDates.add(dateKey);
        }
      });
    }

    return {
      blockedDates: Array.from(allBlockedDates),
      totalBlocked: allBlockedDates.size,
    };
  }

  /**
   * Check site availability for date range
   * Now supports maxConcurrentBookings (designated vs undesignated)
   */
  async checkAvailability(
    siteId: string,
    checkIn: string,
    checkOut: string
  ): Promise<{
    isAvailable: boolean;
    reason?: string;
    blockedDates?: Date[];
    spotsLeft?: number; // How many concurrent bookings are still available
  }> {
    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    // Get site with capacity.maxConcurrentBookings
    const site = await SiteModel.findById(siteId);
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const maxConcurrent = site.capacity.maxConcurrentBookings || 1;

    // Count existing bookings for this date range
    const existingBookingsCount = await BookingModel.countDocuments({
      site: siteId,
      status: { $in: ["pending", "confirmed"] },
      $or: [
        {
          checkIn: { $lte: checkOutDate },
          checkOut: { $gte: checkInDate },
        },
      ],
    });

    // Check if capacity is full
    if (existingBookingsCount >= maxConcurrent) {
      return {
        isAvailable: false,
        reason:
          maxConcurrent === 1
            ? "Site already booked for these dates"
            : `All ${maxConcurrent} spots are booked for these dates`,
        spotsLeft: 0,
      };
    }

    // Check availability records (blocked dates)
    const blockedDates = await AvailabilityModel.find({
      site: siteId,
      date: { $gte: checkInDate, $lt: checkOutDate },
      isAvailable: false,
    });

    if (blockedDates.length > 0) {
      return {
        isAvailable: false,
        reason: "Site is blocked for some dates in this range",
        blockedDates: blockedDates.map((d) => d.date),
        spotsLeft: 0,
      };
    }

    return {
      isAvailable: true,
      spotsLeft: maxConcurrent - existingBookingsCount,
    };
  }

  /**
   * Get unavailable site IDs for date range
   */
  private async getUnavailableSites(checkIn: string, checkOut: string): Promise<string[]> {
    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    // Get sites with existing bookings
    const bookedSites = await BookingModel.find({
      status: { $in: ["pending", "confirmed"] },
      $or: [
        {
          checkIn: { $lte: checkOutDate },
          checkOut: { $gte: checkInDate },
        },
      ],
    }).distinct("site");

    // Get sites with blocked dates
    const blockedSites = await AvailabilityModel.find({
      date: { $gte: checkInDate, $lt: checkOutDate },
      isAvailable: false,
    }).distinct("site");

    // Combine and deduplicate
    return Array.from(new Set([...bookedSites, ...blockedSites].map((id) => id.toString())));
  }

  /**
   * Calculate pricing for date range
   */
  async calculatePricing(siteId: string, checkIn: string, checkOut: string, guestCount: number) {
    const site = await SiteModel.findById(siteId);
    appAssert(site, ErrorFactory.resourceNotFound("Site"));

    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);
    const nights = Math.ceil(
      (checkOutDate.getTime() - checkInDate.getTime()) / (1000 * 60 * 60 * 24)
    );

    const basePrice = site!.pricing.basePrice;
    const weekendPrice = site!.pricing.weekendPrice;
    let subtotal = 0;

    // Calculate nightly rates (can be weekend/seasonal pricing)
    for (let i = 0; i < nights; i++) {
      const currentDate = new Date(checkInDate);
      currentDate.setDate(currentDate.getDate() + i);

      const dayOfWeek = currentDate.getDay();
      const isWeekend = dayOfWeek === 5 || dayOfWeek === 6; // Friday or Saturday

      let nightPrice = basePrice;
      let isSeasonal = false;

      // Seasonal price has highest priority
      if (site!.pricing.seasonalPricing && site!.pricing.seasonalPricing.length > 0) {
        const seasonalRate = site!.pricing.seasonalPricing.find((season: any) => {
          const seasonStart = new Date(season.startDate);
          const seasonEnd = new Date(season.endDate);

          // Compare dates without time
          const currentZero = new Date(currentDate);
          currentZero.setHours(0, 0, 0, 0);
          const startZero = new Date(seasonStart);
          startZero.setHours(0, 0, 0, 0);
          const endZero = new Date(seasonEnd);
          endZero.setHours(0, 0, 0, 0);

          return currentZero >= startZero && currentZero <= endZero;
        });

        if (seasonalRate) {
          nightPrice = seasonalRate.price;
          isSeasonal = true;
        }
      }

      // Weekend price applied if not overridden by seasonal price
      if (!isSeasonal && isWeekend && weekendPrice && weekendPrice > 0) {
        nightPrice = weekendPrice;
      }

      subtotal += nightPrice;
    }

    // Apply discounts
    let discount = 0;
    if (nights >= 28 && site!.pricing.monthlyDiscount) {
      discount = (subtotal * site!.pricing.monthlyDiscount) / 100;
    } else if (nights >= 7 && site!.pricing.weeklyDiscount) {
      discount = (subtotal * site!.pricing.weeklyDiscount) / 100;
    }

    // Calculate fees
    const cleaningFee = site!.pricing.cleaningFee || 0;
    const petFee = site!.pricing.petFee || 0;
    const additionalGuestFee = site!.pricing.additionalGuestFee || 0;
    const extraGuestFee =
      guestCount > site!.capacity.maxGuests
        ? (guestCount - site!.capacity.maxGuests) * additionalGuestFee
        : 0;

    const total = subtotal - discount + cleaningFee + petFee + extraGuestFee;

    return {
      nights,
      basePrice,
      subtotal,
      discount,
      fees: {
        cleaning: cleaningFee,
        pet: petFee,
        extraGuest: extraGuestFee,
      },
      total,
    };
  }

  /**
   * Update site stats (called when booking/review created)
   */
  async updateSiteStats(siteId: string): Promise<void> {
    const site = await SiteModel.findById(siteId);
    if (!site) return;

    await site.updateStats();
  }

  /**
   * Update site rating based on reviews
   */
  async updateSiteRating(siteId: string): Promise<void> {
    const reviews = await ReviewModel.find({
      site: siteId,
      isPublished: true,
    });

    if (reviews.length === 0) {
      await SiteModel.findByIdAndUpdate(siteId, {
        rating: {
          average: 0,
          count: 0,
          breakdown: {
            cleanliness: 0,
            accuracy: 0,
            amenities: 0,
          },
        },
      });
      return;
    }

    // Calculate averages
    const totals = reviews.reduce(
      (acc, review) => {
        acc.overall += review.overallRating;
        acc.cleanliness += review.siteRatings.cleanliness;
        acc.accuracy += review.siteRatings.accuracy;
        acc.amenities += review.siteRatings.amenities;
        return acc;
      },
      { overall: 0, cleanliness: 0, accuracy: 0, amenities: 0 }
    );

    const count = reviews.length;
    const rating = {
      average: Math.round((totals.overall / count) * 10) / 10,
      count,
      breakdown: {
        cleanliness: Math.round((totals.cleanliness / count) * 10) / 10,
        accuracy: Math.round((totals.accuracy / count) * 10) / 10,
        amenities: Math.round((totals.amenities / count) * 10) / 10,
      },
    };

    await SiteModel.findByIdAndUpdate(siteId, { rating });
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
   * Get sites by property
   */
  async getSitesByProperty(propertyId: string, page = 1, limit = 20) {
    const skip = (page - 1) * limit;

    const [sites, total] = await Promise.all([
      SiteModel.find({ property: propertyId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      SiteModel.countDocuments({ property: propertyId }),
    ]);

    return {
      sites,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Block multiple dates for a site
   */
  async blockSiteDates(siteId: string, hostId: string, dates: string[], reason?: string): Promise<void> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));
    const property = site.property as any;
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền chỉnh sửa site này")
    );

    // Create bulk operations to write to AvailabilityModel
    const ops = dates.map((dateStr) => {
      const date = new Date(dateStr);
      // set to midnight UTC for clean matching
      date.setUTCHours(0, 0, 0, 0);

      return {
        updateOne: {
          filter: { site: siteId, date },
          update: {
            $set: {
              isAvailable: false,
              blockType: "blocked" as const,
              reason: reason || "Manual block",
            },
          },
          upsert: true,
        },
      };
    });

    if (ops.length > 0) {
      await AvailabilityModel.bulkWrite(ops);
    }

    notifyPropertyChange(property._id.toString());
  }

  /**
   * Unblock multiple dates for a site
   */
  async unblockSiteDates(siteId: string, hostId: string, dates: string[]): Promise<void> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));
    const property = site.property as any;
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền chỉnh sửa site này")
    );

    const dateObjects = dates.map((d) => {
      const date = new Date(d);
      date.setUTCHours(0, 0, 0, 0);
      return date;
    });

    // Delete or update Availability records to be isAvailable = true
    await AvailabilityModel.deleteMany({
      site: siteId,
      date: { $in: dateObjects },
      blockType: { $ne: "booked" }, // Do not delete actual guest bookings!
    });

    notifyPropertyChange(property._id.toString());
  }

  /**
   * Update seasonal pricing for a site
   */
  async updateSeasonalPricing(
    siteId: string,
    hostId: string,
    seasonalPricing: Array<{ name: string; startDate: string; endDate: string; price: number }>
  ): Promise<SiteDocument> {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));
    const property = site.property as any;
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền chỉnh sửa site này")
    );

    // Validate date formatting and map
    const formattedSeasonalPricing = seasonalPricing.map((item) => ({
      name: item.name,
      startDate: new Date(item.startDate),
      endDate: new Date(item.endDate),
      price: item.price,
    }));

    site.pricing.seasonalPricing = formattedSeasonalPricing as any;
    await site.save();

    notifyPropertyChange(property._id.toString());

    return site;
  }

  /**
   * Get availability status of all dates in a month (blocked/booked/available)
   */
  async getAvailabilityCalendar(siteId: string, hostId: string, monthStr: string) {
    const site = await SiteModel.findById(siteId).populate("property");
    appAssert(site, ErrorFactory.resourceNotFound("Site"));
    const property = site.property as any;
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền xem thông tin site này")
    );

    // Parse month date range
    const parts = monthStr.split("-").map(Number); // e.g. "2026-06"
    const year = parts[0] ?? new Date().getFullYear();
    const month = parts[1] ?? (new Date().getMonth() + 1);
    const startDate = new Date(Date.UTC(year, month - 1, 1));
    const endDate = new Date(Date.UTC(year, month, 0, 23, 59, 59, 999));

    // Get bookings
    const bookings = await BookingModel.find({
      site: siteId,
      status: { $in: ["pending", "confirmed", "completed"] },
      checkIn: { $lte: endDate },
      checkOut: { $gte: startDate },
    }).populate("guest", "username email");

    // Get manual availability blocks
    const blocks = await AvailabilityModel.find({
      site: siteId,
      date: { $gte: startDate, $lte: endDate },
    }).lean();

    return {
      siteId,
      startDate,
      endDate,
      bookings: bookings.map((b) => ({
        id: b._id,
        checkIn: b.checkIn,
        checkOut: b.checkOut,
        status: b.status,
        guestName: (b.guest as any)?.username || "Guest",
        totalPrice: b.pricing.total,
      })),
      blocks: blocks.map((bl) => ({
        date: bl.date,
        isAvailable: bl.isAvailable,
        blockType: bl.blockType,
        reason: bl.reason,
        price: bl.price,
      })),
    };
  }
}

export default new SiteService();
