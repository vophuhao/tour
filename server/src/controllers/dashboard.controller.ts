import { catchErrors } from "@/errors";
import { BookingModel } from "@/models/booking.model";
import HostModel from "@/models/host.model";
import { PropertyModel } from "@/models/property.model";
import { ReviewModel } from "@/models/review.model";
import UserModel from "@/models/user.model";
import { ResponseUtil } from "../utils";
import mongoose from "mongoose";

export default class DashboardController {
  // Thống kê tổng quan
  getOverviewStats = catchErrors(async (_req, res) => {
    const [
      totalUsers,
      totalHosts,
      totalProperties,
      totalBookings,

    ] = await Promise.all([
      UserModel.countDocuments(),
      UserModel.countDocuments({ role: "host" }),
      PropertyModel.countDocuments({ status: "active" }),

      BookingModel.countDocuments(),

      // Booking revenue from pricing.total
      BookingModel.aggregate([
        { $match: { status: { $in: ["confirmed", "completed"] } } },
        { $group: { _id: null, total: { $sum: "$pricing.total" } } },
      ]),
      // Order revenue from grandTotal

      HostModel.countDocuments({ status: "pending" }),
      BookingModel.countDocuments({ status: "confirmed" }),
      ReviewModel.countDocuments(),
    ]);

    const stats = {
      users: {
        total: totalUsers,
        hosts: totalHosts,
        guests: totalUsers - totalHosts,
      },
      properties: {
        total: totalProperties,
      },
      bookings: {
        total: totalBookings,

      },


    };

    return ResponseUtil.success(res, stats, "Lấy thống kê tổng quan thành công");
  });

  // Thống kê doanh thu theo tháng (Booking + Order)
  getRevenueStats = catchErrors(async (req, res) => {
    const { year = new Date().getFullYear() } = req.query;

    const [bookingRevenueByMonth] = await Promise.all([
      // Booking revenue
      BookingModel.aggregate([
        {
          $match: {
            status: { $in: ["confirmed", "completed"] },
            createdAt: {
              $gte: new Date(`${year}-01-01`),
              $lte: new Date(`${year}-12-31`),
            },
          },
        },
        {
          $group: {
            _id: { $month: "$createdAt" },
            revenue: { $sum: "$pricing.total" },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ]),
      // Order revenue

    ]);

    // Merge and fill missing months
    const monthlyData = Array.from({ length: 12 }, (_, i) => {
      const bookingData = bookingRevenueByMonth.find((r: any) => r._id === i + 1);
      return {
        month: i + 1,
        bookingRevenue: bookingData?.revenue || 0,
        bookingCount: bookingData?.count || 0,

        totalRevenue: (bookingData?.revenue || 0),
        totalCount: (bookingData?.count || 0),
      };
    });

    return ResponseUtil.success(res, monthlyData, "Lấy thống kê doanh thu thành công");
  });

  // Thống kê booking theo trạng thái
  getBookingStats = catchErrors(async (_req, res) => {
    const bookingsByStatus = await BookingModel.aggregate([
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
          totalRevenue: { $sum: "$pricing.total" },
        },
      },
    ]);

    const stats = {
      byStatus: bookingsByStatus,
      total: bookingsByStatus.reduce((sum: number, item: any) => sum + item.count, 0),
      totalRevenue: bookingsByStatus.reduce((sum: number, item: any) => sum + item.totalRevenue, 0),
    };

    return ResponseUtil.success(res, stats, "Lấy thống kê booking thành công");
  });


  // Top properties (theo booking count & revenue)
  getTopProperties = catchErrors(async (req, res) => {
    const { limit = 10 } = req.query;

    const topProperties = await BookingModel.aggregate([
      { $match: { status: { $in: ["confirmed", "completed"] } } },
      {
        $group: {
          _id: "$property",
          bookingCount: { $sum: 1 },
          revenue: { $sum: "$pricing.total" },
        },
      },
      { $sort: { revenue: -1 } },
      { $limit: parseInt(limit as string) },
      {
        $lookup: {
          from: "properties",
          localField: "_id",
          foreignField: "_id",
          as: "property",
        },
      },
      { $unwind: "$property" },
      {
        $project: {
          name: "$property.name",
          location: "$property.location",
          photos: { $arrayElemAt: ["$property.photos", 0] },
          bookingCount: 1,
          revenue: 1,
        },
      },
    ]);

    return ResponseUtil.success(res, topProperties, "Lấy top properties thành công");
  });

  // Top hosts (theo booking & revenue)
  getTopHosts = catchErrors(async (req, res) => {
    const { limit = 10 } = req.query;

    const topHosts = await BookingModel.aggregate([
      { $match: { status: { $in: ["confirmed", "completed"] } } },
      {
        $group: {
          _id: "$host",
          bookingCount: { $sum: 1 },
          revenue: { $sum: "$pricing.total" },
        },
      },
      { $sort: { revenue: -1 } },
      { $limit: parseInt(limit as string) },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "host",
        },
      },
      { $unwind: "$host" },
      {
        $lookup: {
          from: "properties",
          localField: "_id",
          foreignField: "host",
          as: "properties",
        },
      },
      {
        $project: {
          username: "$host.username",
          email: "$host.email",
          avatarUrl: "$host.avatarUrl",
          propertyCount: { $size: "$properties" },
          bookingCount: 1,
          revenue: 1,
        },
      },
    ]);

    return ResponseUtil.success(res, topHosts, "Lấy top host thành công");
  });

  // Recent activities
  getRecentActivities = catchErrors(async (req, res) => {
    const { limit = 20 } = req.query;
    const limitPerType = Math.ceil(parseInt(limit as string) / 4);

    const [recentBookings, recentOrders, recentReviews] = await Promise.all([
      BookingModel.find()
        .sort({ createdAt: -1 })
        .limit(limitPerType)
        .populate("guest", "username avatarUrl")
        .populate("property", "name")
        .select("status pricing.total createdAt"),


      ReviewModel.find()
        .sort({ createdAt: -1 })
        .limit(limitPerType)
        .populate("user", "username avatarUrl")
        .populate("property", "name")
        .select("rating comment createdAt"),

      UserModel.find()
        .sort({ createdAt: -1 })
        .limit(limitPerType)
        .select("username email role createdAt"),
    ]);

    const activities = [
      ...recentBookings.map((b: any) => ({
        type: "booking",
        data: b,
        createdAt: b.createdAt,
      })),
      ...recentOrders.map((o: any) => ({
        type: "order",
        data: o,
        createdAt: o.createdAt,
      })),
      ...recentReviews.map((r: any) => ({
        type: "review",
        data: r,
        createdAt: r.createdAt,
      })),

    ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    return ResponseUtil.success(
      res,
      activities.slice(0, parseInt(limit as string)),
      "Lấy hoạt động gần đây thành công"
    );
  });

  // Growth stats (so với tháng trước)
  getGrowthStats = catchErrors(async (_req, res) => {
    const now = new Date();
    const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const thisMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const [
      usersThisMonth,
      usersLastMonth,
      bookingsThisMonth,
      bookingsLastMonth,

    ] = await Promise.all([
      UserModel.countDocuments({ createdAt: { $gte: thisMonth } }),
      UserModel.countDocuments({ createdAt: { $gte: lastMonth, $lt: thisMonth } }),

      BookingModel.countDocuments({ createdAt: { $gte: thisMonth } }),
      BookingModel.countDocuments({ createdAt: { $gte: lastMonth, $lt: thisMonth } }),



      BookingModel.aggregate([
        { $match: { status: { $in: ["confirmed", "completed"] }, createdAt: { $gte: thisMonth } } },
        { $group: { _id: null, total: { $sum: "$pricing.total" } } },
      ]),
      BookingModel.aggregate([
        {
          $match: {
            status: { $in: ["confirmed", "completed"] },
            createdAt: { $gte: lastMonth, $lt: thisMonth },
          },
        },
        { $group: { _id: null, total: { $sum: "$pricing.total" } } },
      ]),


    ]);

    const calculateGrowth = (current: number, previous: number) => {
      if (previous === 0) return current > 0 ? 100 : 0;
      return ((current - previous) / previous) * 100;
    };



    const stats = {
      users: {
        current: usersThisMonth,
        previous: usersLastMonth,
        growth: calculateGrowth(usersThisMonth, usersLastMonth),
      },
      bookings: {
        current: bookingsThisMonth,
        previous: bookingsLastMonth,
        growth: calculateGrowth(bookingsThisMonth, bookingsLastMonth),
      },


    };

    return ResponseUtil.success(res, stats, "Lấy thống kê tăng trưởng thành công");
  });



  // Thống kê properties
  getPropertyStats = catchErrors(async (_req, res) => {
    const propertiesByStatus = await PropertyModel.aggregate([
      {
        $group: {
          _id: "$status",
          count: { $sum: 1 },
        },
      },
    ]);

    const stats = {
      byStatus: propertiesByStatus,
      total: propertiesByStatus.reduce((sum: number, item: any) => sum + item.count, 0),
    };

    return ResponseUtil.success(res, stats, "Lấy thống kê properties thành công");
  });

  // Báo cáo doanh thu nâng cao (lọc theo host, ngày, tháng)
  getRevenueReport = catchErrors(async (req, res) => {
    const { hostId, startDate, endDate, year = new Date().getFullYear() } = req.query;

    const matchBase: any = {
      status: { $in: ["confirmed", "completed"] },
      paymentStatus: "paid",
    };

    if (hostId) matchBase.host = new mongoose.Types.ObjectId(hostId as string);

    if (startDate || endDate) {
      matchBase.createdAt = {};
      if (startDate) matchBase.createdAt.$gte = new Date(startDate as string);
      if (endDate) matchBase.createdAt.$lte = new Date(endDate as string);
    } else {
      matchBase.createdAt = {
        $gte: new Date(`${year}-01-01`),
        $lte: new Date(`${year}-12-31T23:59:59`),
      };
    }

    const [
      summary,
      revenueByMonth,
      revenueByHost,
      revenueByStatus,
    ] = await Promise.all([
      // Tổng quan
      BookingModel.aggregate([
        { $match: matchBase },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: "$pricing.total" },
            totalBookings: { $sum: 1 },
            avgBookingValue: { $avg: "$pricing.total" },
            totalNights: { $sum: "$nights" },
            totalGuests: { $sum: "$numberOfGuests" },
          },
        },
      ]),

      // Doanh thu theo tháng
      BookingModel.aggregate([
        { $match: matchBase },
        {
          $group: {
            _id: { $month: "$createdAt" },
            revenue: { $sum: "$pricing.total" },
            count: { $sum: 1 },
            avgValue: { $avg: "$pricing.total" },
          },
        },
        { $sort: { _id: 1 } },
      ]),

      // Doanh thu theo host (top 10)
      BookingModel.aggregate([
        { $match: matchBase },
        {
          $group: {
            _id: "$host",
            revenue: { $sum: "$pricing.total" },
            bookingCount: { $sum: 1 },
          },
        },
        { $sort: { revenue: -1 } },
        { $limit: 10 },
        {
          $lookup: {
            from: "users",
            localField: "_id",
            foreignField: "_id",
            as: "hostInfo",
          },
        },
        { $unwind: { path: "$hostInfo", preserveNullAndEmptyArrays: true } },
        {
          $project: {
            hostId: "$_id",
            hostName: "$hostInfo.username",
            hostEmail: "$hostInfo.email",
            hostAvatar: "$hostInfo.avatarUrl",
            revenue: 1,
            bookingCount: 1,
          },
        },
      ]),

      // Doanh thu theo trạng thái booking
      BookingModel.aggregate([
        {
          $match: {
            ...(hostId ? { host: new mongoose.Types.ObjectId(hostId as string) } : {}),
            ...(startDate || endDate
              ? {
                createdAt: {
                  ...(startDate ? { $gte: new Date(startDate as string) } : {}),
                  ...(endDate ? { $lte: new Date(endDate as string) } : {}),
                },
              }
              : {
                createdAt: {
                  $gte: new Date(`${year}-01-01`),
                  $lte: new Date(`${year}-12-31T23:59:59`),
                },
              }),
          },
        },
        {
          $group: {
            _id: "$status",
            count: { $sum: 1 },
            revenue: { $sum: "$pricing.total" },
          },
        },
      ]),
    ]);

    // Fill 12 months
    const monthlyData = Array.from({ length: 12 }, (_, i) => {
      const found = revenueByMonth.find((r: any) => r._id === i + 1);
      return {
        month: i + 1,
        monthLabel: `T${i + 1}`,
        revenue: found?.revenue || 0,
        count: found?.count || 0,
        avgValue: Math.round(found?.avgValue || 0),
      };
    });

    const summ = summary[0] || {};
    const totalRevenue = summ.totalRevenue || 0;
    const platformFee = Math.round(totalRevenue * 0.05);

    return ResponseUtil.success(
      res,
      {
        summary: {
          totalRevenue,
          platformFee,
          netRevenue: totalRevenue - platformFee,
          totalBookings: summ.totalBookings || 0,
          avgBookingValue: Math.round(summ.avgBookingValue || 0),
          totalNights: summ.totalNights || 0,
          totalGuests: summ.totalGuests || 0,
        },
        monthlyData,
        revenueByHost,
        revenueByStatus,
      },
      "Lấy báo cáo doanh thu thành công"
    );
  });
}
