import { container, TOKENS } from "@/di";
import { ErrorFactory } from "@/errors";
import {
  AvailabilityModel,
  BookingModel,
  SiteModel,
  type BookingDocument,
} from "@/models";
import appAssert from "../utils/app-assert";
import { buildSafeSearchRegex } from "../utils/regex";
import type { SearchBookingInput } from "@/validators/booking.validator";
import mongoose from "mongoose";

export class BookingQueryService {
  /**
   * Get booking by Code (basic info)
   */
  async getBookingByCode(code: string): Promise<BookingDocument> {
    const booking = await BookingModel.findOne({ code })
      .populate("site", "name accommodationType photos pricing location")
      .populate("guest", "username email avatarUrl")
      .populate("property", "name location photos slug")
      .populate("host", "username email avatarUrl");

    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));

    return booking;
  }

  /**
   * Get booking by ID/Code with permission check
   */
  async getBooking(bookingId: string, userId: string): Promise<BookingDocument> {
    const booking = await BookingModel.findOne({ code: bookingId })
      .populate("property", "name location photos cancellationPolicy slug")
      .populate({
        path: "site",
        select: "name accommodationType photos pricing slug",
        populate: {
          path: "property",
          select: "name location photos slug host cancellationPolicy",
          populate: {
            path: "host",
            select: "fullName username avatarUrl",
          },
        },
      })
      .populate("guest", "username email avatarUrl")
      .populate("host", "username email avatarUrl");

    appAssert(booking, ErrorFactory.resourceNotFound("Booking"));

    const UserModel = (await import("@/models/user.model")).default;
    const user = await UserModel.findById(userId).select("role");
    const isAdmin = user?.role === "admin";
    appAssert(
      booking.guest._id.toString() === userId || booking.host._id.toString() === userId || isAdmin,
      ErrorFactory.forbidden("Bạn không quyền xem booking này")
    );

    return booking;
  }

  /**
   * Search bookings with filters
   */
  async searchBookings(userId: string, input: SearchBookingInput) {
    const { status, checkInFrom, checkInTo, role, sort, page, limit } = input;
    const query: any = {};

    if (role === "guest") {
      query.guest = userId;
    } else if (role === "host") {
      query.host = userId;
    } else {
      query.$or = [{ guest: userId }, { host: userId }];
    }

    if (status) {
      query.status = status;
    }

    if (checkInFrom || checkInTo) {
      query.checkIn = {};
      if (checkInFrom) query.checkIn.$gte = new Date(checkInFrom);
      if (checkInTo) query.checkIn.$lte = new Date(checkInTo);
    }

    let sortOption: any = {};
    switch (sort) {
      case "oldest":
        sortOption = { createdAt: 1 };
        break;
      case "check-in":
        sortOption = { checkIn: 1 };
        break;
      case "newest":
      default:
        sortOption = { createdAt: -1 };
        break;
    }

    const skip = (page - 1) * limit;
    const [bookings, total] = await Promise.all([
      BookingModel.find(query)
        .populate({
          path: "site",
          select: "name slug photos accommodationType pricing",
          populate: {
            path: "property",
            select: "name location photos slug host",
            populate: {
              path: "host",
              select: "fullName username",
            },
          },
        })
        .populate("guest", "username email avatarUrl")
        .populate("host", "username email avatarUrl")
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .lean(),
      BookingModel.countDocuments(query),
    ]);

    return {
      data: bookings,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
      },
    };
  }

  /**
   * Get my bookings (guest or host)
   */
  async getMyBookings(userId: string, page: number = 1, limit: number = 20, role?: "host" | "guest") {
    const query = role === "host"
      ? { host: userId }
      : role === "guest"
        ? { guest: userId }
        : { $or: [{ host: userId }, { guest: userId }] };

    const safeLimit = Math.min(Math.max(1, limit), 100);
    const skip = (page - 1) * safeLimit;

    const [bookings, total] = await Promise.all([
      BookingModel.find(query)
        .populate("property", "name slug location photos")
        .populate("site", "name slug accommodationType photos pricing location")
        .populate("guest", "username email avatarUrl")
        .populate("host", "username email avatarUrl")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(safeLimit)
        .lean(),
      BookingModel.countDocuments(query),
    ]);

    return {
      data: bookings,
      pagination: {
        page,
        limit: safeLimit,
        total,
        totalPages: Math.ceil(total / safeLimit),
        hasNext: page < Math.ceil(total / safeLimit),
        hasPrev: page > 1,
      },
    };
  }

  /**
   * Host gets bookings
   */
  async getHostBookings(
    hostId: string,
    filters: { status?: string; page?: number; limit?: number } = {}
  ) {
    const { status, page = 1, limit = 20 } = filters;
    const query: any = { host: new mongoose.Types.ObjectId(hostId) };
    if (status) query.status = status;

    const skip = (page - 1) * limit;
    const [bookings, total] = await Promise.all([
      BookingModel.find(query)
        .populate("property", "name location photos slug")
        .populate("site", "name accommodationType photos pricing")
        .populate("guest", "username email avatarUrl")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      BookingModel.countDocuments(query),
    ]);

    return {
      data: bookings,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
      },
    };
  }

  /**
   * Admin view all bookings
   */
  async getAdminBookings(filters: {
    status?: string;
    paymentStatus?: string;
    hostId?: string;
    search?: string;
    startDate?: string;
    endDate?: string;
    cannotAttendStatus?: string;
    page?: number;
    limit?: number;
  }) {
    const {
      status,
      paymentStatus,
      hostId,
      search,
      startDate,
      endDate,
      cannotAttendStatus,
      page = 1,
      limit = 20,
    } = filters;
    const query: any = {};

    if (cannotAttendStatus) {
      query["cannotAttendRequest.status"] = cannotAttendStatus;
    } else {
      if (status) query.status = status;
    }

    if (paymentStatus) query.paymentStatus = paymentStatus;
    if (hostId) query.host = new mongoose.Types.ObjectId(hostId);

    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }

    if (search) {
      const safeSearch = buildSafeSearchRegex(search);
      query.$or = [
        { code: { $regex: safeSearch } },
        { fullnameGuest: { $regex: safeSearch } },
        { email: { $regex: safeSearch } },
      ];
    }

    const skip = (page - 1) * limit;
    const [bookings, total] = await Promise.all([
      BookingModel.find(query)
        .populate("property", "name location photos slug")
        .populate("site", "name accommodationType photos pricing")
        .populate("guest", "username email avatarUrl")
        .populate("host", "username email avatarUrl")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      BookingModel.countDocuments(query),
    ]);

    return {
      data: bookings,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
      },
    };
  }

  /**
   * Admin booking stats
   */
  async getAdminBookingStats() {
    const [statusStats, paymentStats, monthlyStats, refundRequests, cannotAttendRequests] =
      await Promise.all([
        BookingModel.aggregate([
          { $group: { _id: "$status", count: { $sum: 1 }, revenue: { $sum: "$pricing.total" } } },
        ]),
        BookingModel.aggregate([
          { $group: { _id: "$paymentStatus", count: { $sum: 1 } } },
        ]),
        BookingModel.aggregate([
          { $match: { paymentStatus: "paid" } },
          {
            $group: {
              _id: { year: { $year: "$createdAt" }, month: { $month: "$createdAt" } },
              revenue: { $sum: "$pricing.total" },
              count: { $sum: 1 },
            },
          },
          { $sort: { "_id.year": -1, "_id.month": -1 } },
          { $limit: 12 },
        ]),
        BookingModel.countDocuments({ "refundRequest.status": "pending" }),
        BookingModel.countDocuments({ "cannotAttendRequest.status": "pending" }),
      ]);

    const totalRevenue = statusStats
      .filter((s: any) => s._id === "completed")
      .reduce((sum: number, s: any) => sum + s.revenue, 0);

    return {
      statusStats,
      paymentStats,
      monthlyStats: monthlyStats.reverse(),
      totalRevenue,
      platformFee: Math.round(totalRevenue * 0.05),
      pendingRefunds: refundRequests,
      pendingCannotAttend: cannotAttendRequests,
    };
  }

  /**
   * Check availability (with optional session)
   */
  async checkAvailabilityInSession(
    siteId: string,
    checkIn: string,
    checkOut: string,
    session: mongoose.ClientSession | null
  ): Promise<boolean> {
    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    const blockedDatesQuery = AvailabilityModel.countDocuments({
      site: siteId,
      date: { $gte: checkInDate, $lt: checkOutDate },
      isAvailable: false,
    });
    if (session) blockedDatesQuery.session(session);
    const blockedDates = await blockedDatesQuery;

    if (blockedDates > 0) return false;

    const siteQuery = SiteModel.findById(siteId).select("capacity");
    if (session) siteQuery.session(session);
    const site = await siteQuery;
    const maxConcurrent = (site && site.capacity && site.capacity.maxConcurrentBookings) || 1;

    if (maxConcurrent === 1) {
      const overlapQuery = BookingModel.findOne({
        site: siteId,
        status: { $in: ["pending", "confirmed"] },
        $or: [
          {
            checkIn: { $lt: checkOutDate },
            checkOut: { $gt: checkInDate },
          },
        ],
      });
      if (session) overlapQuery.session(session);
      const overlappingBooking = await overlapQuery;

      return !overlappingBooking;
    }

    const countQuery = BookingModel.countDocuments({
      site: siteId,
      status: { $in: ["pending", "confirmed"] },
      $or: [
        {
          checkIn: { $lt: checkOutDate },
          checkOut: { $gt: checkInDate },
        },
      ],
    });
    if (session) countQuery.session(session);
    const overlappingCount = await countQuery;

    return overlappingCount < maxConcurrent;
  }

  /**
   * Calculate pricing breakdown
   */
  calculatePricing(
    site: any,
    nights: number,
    numberOfGuests: number,
    numberOfPets: number,
    numberOfVehicles: number,
    checkIn: Date,
    checkOut: Date
  ): any {
    const {
      basePrice,
      weekendPrice = null,
      cleaningFee = 0,
      petFee = 0,
      additionalGuestFee = 0,
      vehicleFee = 0,
    } = site.pricing;

    let subtotal = 0;
    let weekdayNights = 0;
    let weekendNights = 0;
    let seasonalNights = 0;

    const currentDate = new Date(checkIn);
    while (currentDate < checkOut) {
      const dayOfWeek = currentDate.getDay();
      const isWeekend = dayOfWeek === 5 || dayOfWeek === 6;

      let nightPrice = basePrice;
      let isSeasonal = false;

      if (site.pricing.seasonalPricing && site.pricing.seasonalPricing.length > 0) {
        const seasonalRate = site.pricing.seasonalPricing.find((season: any) => {
          const seasonStart = new Date(season.startDate);
          const seasonEnd = new Date(season.endDate);

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

      if (!isSeasonal && isWeekend && weekendPrice !== null && weekendPrice > 0) {
        nightPrice = weekendPrice;
        weekendNights++;
      } else if (isSeasonal) {
        seasonalNights++;
      } else {
        weekdayNights++;
      }

      subtotal += nightPrice;
      currentDate.setDate(currentDate.getDate() + 1);
    }

    // Apply long-stay discount on subtotal
    let discountPercent = 0;
    if (nights >= 28 && site.pricing.monthlyDiscount) {
      discountPercent = site.pricing.monthlyDiscount;
    } else if (nights >= 7 && site.pricing.weeklyDiscount) {
      discountPercent = site.pricing.weeklyDiscount;
    }
    if (discountPercent > 0) {
      subtotal = Math.round(subtotal * (1 - discountPercent / 100));
    }

    const cleaning = cleaningFee;
    const pet = numberOfPets > 0 ? petFee * numberOfPets : 0;
    const extraGuest =
      numberOfGuests > site.capacity.maxGuests
        ? additionalGuestFee * (numberOfGuests - site.capacity.maxGuests) * nights
        : 0;
    const vehicle = numberOfVehicles > 0 ? vehicleFee * numberOfVehicles * nights : 0;

    // Platform service fee for camper is 5%
    const serviceFee = Math.round((subtotal + cleaning + pet + extraGuest + vehicle) * 0.05);

    return {
      basePrice,
      weekendPrice: weekendPrice || basePrice,
      totalNights: nights,
      weekdayNights,
      weekendNights,
      subtotal,
      cleaningFee: cleaning,
      petFee: pet,
      extraGuestFee: extraGuest,
      vehicleFee: vehicle,
      serviceFee,
      tax: 0,
      total: subtotal + cleaning + pet + extraGuest + vehicle + serviceFee,
    };
  }
}
