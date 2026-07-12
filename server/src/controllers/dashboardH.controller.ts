/* eslint-disable no-case-declarations */
import { Request, Response } from "express";
import { PropertyModel } from "../models/property.model";
import { BookingModel } from "../models/booking.model";
import { ReviewModel } from "../models/review.model";
import { SiteModel } from "../models/site.model";
import { catchErrors } from "@/errors";
import { mongoIdSchema } from "@/validators";

/**
 * Helper to extract total amount from booking.pricing.total
 */
function getBookingAmount(b: any): number {
  if (!b) return 0;

  // BookingModel stores price in pricing.total
  if (b.pricing?.total != null) {
    const val = Number(b.pricing.total);
    if (!isNaN(val) && val >= 0) return val;
  }

  // Fallback: try other common fields if pricing.total missing
  const candidates = ["totalPrice", "totalAmount", "amount", "total"];
  for (const k of candidates) {
    const v = b[k];
    if (v != null) {
      const n = Number(v);
      if (!isNaN(n) && n >= 0) return n;
    }
  }

  return 0;
}

/**
 * GET /api/dashboardH/stats
 * Overall host dashboard metrics
 */
export const getHostStats = catchErrors(async (req: Request, res: Response) => {
  const hostId = mongoIdSchema.parse(req.userId);
  if (!hostId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  // Load host properties
  const properties = await PropertyModel.find({ host: hostId })
    .select("_id name status stats")
    .lean();

  const propertyIds = properties.map((p) => p._id);

  // Load bookings for these properties
  const bookings = await BookingModel.find({ property: { $in: propertyIds } })
    .select("status createdAt checkIn checkOut pricing guest property site")
    .populate("guest", "username avatarUrl")
    .populate("property", "name photos")
    .lean();

  // Load reviews
  const reviews = await ReviewModel.find({ property: { $in: propertyIds } })
    .select("rating")
    .lean();

  // Properties stats
  const propertiesStats = {
    total: properties.length,
    active: properties.filter((p) => p.status === "active").length,
    inactive: properties.filter((p) => p.status === "inactive").length,
    pending_approval: 0,
    suspended: properties.filter((p) => p.status === "blocked").length,
  };

  // Bookings stats
  const bookingsStats = {
    total: bookings.length,
    pending: bookings.filter((b) => b.status === "pending").length,
    confirmed: bookings.filter((b) => b.status === "confirmed" && new Date(b.checkOut) >= new Date()).length,
    cancelled: bookings.filter((b) => b.status === "cancelled").length,
    completed: bookings.filter((b) => b.status === "completed" || (b.status === "confirmed" && new Date(b.checkOut) < new Date())).length,
  };

  // Calculate current month vs last month stats
  const now = new Date();
  const startOfThisMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59, 999);

  const thisMonthBookings = bookings.filter((b) => new Date(b.createdAt) >= startOfThisMonth);
  const lastMonthBookings = bookings.filter((b) => {
    const date = new Date(b.createdAt);
    return date >= startOfLastMonth && date <= endOfLastMonth;
  });

  const thisMonthBookingsCount = thisMonthBookings.length;
  const thisMonthRevenue = thisMonthBookings
    .filter((b) => b.status === "confirmed" || b.status === "completed")
    .reduce((sum, b) => sum + getBookingAmount(b), 0);

  const lastMonthBookingsCount = lastMonthBookings.length;
  const lastMonthRevenue = lastMonthBookings
    .filter((b) => b.status === "confirmed" || b.status === "completed")
    .reduce((sum, b) => sum + getBookingAmount(b), 0);

  const revenueGrowth = lastMonthRevenue > 0
    ? Number((((thisMonthRevenue - lastMonthRevenue) / lastMonthRevenue) * 100).toFixed(1))
    : 0;

  const bookingsGrowth = lastMonthBookingsCount > 0
    ? Number((((thisMonthBookingsCount - lastMonthBookingsCount) / lastMonthBookingsCount) * 100).toFixed(1))
    : 0;

  // Calculate total revenue (confirmed + completed)
  const revenueBookings = bookings.filter(
    (b) => b.status === "confirmed" || b.status === "completed"
  );
  const totalRevenue = revenueBookings.reduce((sum, b) => sum + getBookingAmount(b), 0);

  // Average rating
  const averageRating =
    reviews.length > 0
      ? reviews.reduce((sum, r) => sum + ((r as any).rating || 0), 0) / reviews.length
      : 0;

  // Recent bookings (last 5)
  const recentBookings = bookings
    .slice()
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 5)
    .map((b) => ({
      _id: b._id,
      status: b.status,
      checkIn: b.checkIn,
      checkOut: b.checkOut,
      totalPrice: getBookingAmount(b),
      guest: b.guest,
      property: b.property,
      createdAt: b.createdAt,
    }));

  // Count sites
  const sitesCount = await SiteModel.countDocuments({ property: { $in: propertyIds } });

  // Calculate real booking counts and view counts per property
  const propertyBookingCounts: Record<string, number> = {};
  const propertyViewCounts: Record<string, number> = {};

  let redisClientInstance: any = null;
  try {
    redisClientInstance = require("../config/redis").redisClient;
  } catch (err) {
    console.warn("Failed to require redisClient:", err);
  }

  for (const p of properties) {
    const pIdStr = p._id.toString();

    // Count real bookings
    propertyBookingCounts[pIdStr] = bookings.filter(
      (b) => String(b.property?._id || b.property) === pIdStr
    ).length;

    // Count real views from Redis + DB
    let redisViews = 0;
    if (redisClientInstance && redisClientInstance.isOpen) {
      try {
        const val = await redisClientInstance.hGet("property_views", pIdStr);
        if (val) redisViews = parseInt(val) || 0;
      } catch (err) {
        console.warn("Failed to get views from Redis:", err);
      }
    }
    const dbViews = p.stats?.viewCount || 0;
    propertyViewCounts[pIdStr] = dbViews + redisViews;
  }

  res.json({
    success: true,
    data: {
      properties: propertiesStats,
      bookings: {
        ...bookingsStats,
        thisMonthCount: thisMonthBookingsCount,
        thisMonthGrowth: bookingsGrowth,
      },
      totalRevenue,
      thisMonthRevenue,
      revenueGrowth,
      averageRating: Number(averageRating.toFixed(1)),
      totalReviews: reviews.length,
      recentBookings,
      sitesCount,
      propertyBookingCounts,
      propertyViewCounts,
    },
  });
});

/**
 * GET /api/dashboardH/revenue
 * Revenue analytics with date filters
 * Query: ?period=day|week|month|year or ?startDate=YYYY-MM-DD&endDate=YYYY-MM-DD
 */
export const getRevenueAnalytics = catchErrors(async (req: Request, res: Response) => {
  const hostId = mongoIdSchema.parse(req.userId);
  const { period = "month", startDate, endDate } = req.query as any;

  if (!hostId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  // Get host properties
  const properties = await PropertyModel.find({ host: hostId }).select("_id name").lean();
  const propertyIds = properties.map((p) => p._id);

  // Build date range
  let from: Date;
  let to: Date;
  const now = new Date();

  if (startDate && endDate) {
    from = new Date(startDate);
    to = new Date(endDate);
    to.setHours(23, 59, 59, 999);
  } else {
    switch (period) {
      case "day":
        from = new Date(now);
        from.setHours(0, 0, 0, 0);
        to = new Date(now);
        to.setHours(23, 59, 59, 999);
        break;
      case "week":
        from = new Date(now);
        from.setDate(now.getDate() - 6);
        from.setHours(0, 0, 0, 0);
        to = now;
        break;
      case "month":
        from = new Date(now.getFullYear(), now.getMonth(), 1);
        to = now;
        break;
      case "year":
        from = new Date(now.getFullYear(), 0, 1);
        to = now;
        break;
      default:
        from = new Date(now.getFullYear(), now.getMonth(), 1);
        to = now;
    }
  }

  // Get bookings with date filter
  const bookings = await BookingModel.find({
    property: { $in: propertyIds },
    status: { $in: ["confirmed", "completed"] },
    createdAt: { $gte: from, $lte: to },
  })
    .select("createdAt pricing property")
    .populate("property", "name")
    .lean();

  // Group by date
  const revenueByDate: Record<string, number> = {};
  const bookingsByDate: Record<string, number> = {};

  bookings.forEach((b) => {
    const dateKey = new Date(b.createdAt).toISOString().slice(0, 10); // YYYY-MM-DD
    const amount = getBookingAmount(b);

    revenueByDate[dateKey] = (revenueByDate[dateKey] || 0) + amount;
    bookingsByDate[dateKey] = (bookingsByDate[dateKey] || 0) + 1;
  });

  // Convert to chart data
  const chartData = Object.keys(revenueByDate)
    .sort()
    .map((date) => ({
      date,
      revenue: revenueByDate[date],
      bookings: bookingsByDate[date] || 0,
    }));

  // Calculate totals
  const totalRevenue = Object.values(revenueByDate).reduce((sum, val) => sum + val, 0);
  const totalBookings = bookings.length;

  // Top performing properties
  const propertyMap: Record<string, { name: string; revenue: number; bookings: number }> = {};

  bookings.forEach((b) => {
    const propId = String((b.property as any)?._id ?? b.property);
    const propName = (b.property as any)?.name ?? "Unknown";

    if (!propertyMap[propId]) {
      propertyMap[propId] = { name: propName, revenue: 0, bookings: 0 };
    }

    propertyMap[propId].revenue += getBookingAmount(b);
    propertyMap[propId].bookings += 1;
  });

  const topProperties = Object.values(propertyMap)
    .sort((a, b) => b.revenue - a.revenue)
    .slice(0, 5);

  res.json({
    success: true,
    data: {
      period,
      summary: {
        totalRevenue,
        totalBookings,
        averageBookingValue: totalBookings > 0 ? totalRevenue / totalBookings : 0,
      },
      chartData,
      topProperties,
    },
  });
});

/**
 * GET /api/dashboardH/trends
 * Booking trends grouped by month
 * Query: ?months=6
 */
export const getBookingTrends = catchErrors(async (req: Request, res: Response) => {
  const hostId = mongoIdSchema.parse(req.userId);
  const months = Number((req.query.months as any) ?? 6);

  if (!hostId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  // Get host properties
  const properties = await PropertyModel.find({ host: hostId }).select("_id").lean();
  const propertyIds = properties.map((p) => p._id);

  // Calculate date range (last N months)
  const since = new Date();
  since.setMonth(since.getMonth() - months + 1);
  since.setDate(1);
  since.setHours(0, 0, 0, 0);

  // Get bookings
  const bookings = await BookingModel.find({
    property: { $in: propertyIds },
    createdAt: { $gte: since },
  })
    .select("status createdAt")
    .lean();

  // Group by month
  const trendsByMonth: Record<
    string,
    { confirmed: number; cancelled: number; pending: number }
  > = {};

  bookings.forEach((b) => {
    const monthKey = new Date(b.createdAt).toISOString().slice(0, 7); // YYYY-MM

    if (!trendsByMonth[monthKey]) {
      trendsByMonth[monthKey] = { confirmed: 0, cancelled: 0, pending: 0 };
    }

    if (b.status === "confirmed" || b.status === "completed") {
      trendsByMonth[monthKey].confirmed++;
    } else if (b.status === "cancelled") {
      trendsByMonth[monthKey].cancelled++;
    } else if (b.status === "pending") {
      trendsByMonth[monthKey].pending++;
    }
  });

  // Convert to array
  const trends = Object.keys(trendsByMonth)
    .sort()
    .map((month) => {
      const t = trendsByMonth[month] ?? { confirmed: 0, cancelled: 0, pending: 0 };
      return {
        month,
        ...t,
        total: t.confirmed + t.cancelled + t.pending,
      };
    });

  res.json({
    success: true,
    data: trends,
  });
});