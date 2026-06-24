import { BookingModel } from "@/models";
import PayoutModel from "@/models/payout.model";
import HostModel from "@/models/host.model";
import mongoose from "mongoose";

const PLATFORM_FEE_RATE = 0.05; // 5%

export default class PayoutService {
  /**
   * Chạy tổng kết tháng: tìm tất cả booking completed + hostConfirmedAttendance=true
   * trong kỳ, group theo host, tính gross/fee/net, tạo Payout record
   */
  async runMonthlyPayout(month: number, year: number) {
    const periodStart = new Date(year, month - 1, 1, 0, 0, 0);
    const periodEnd = new Date(year, month, 0, 23, 59, 59); // last day of month

    // Tìm booking completed + paid + host confirmed attendance + chưa settle
    const bookings = await BookingModel.find({
      status: "completed",
      paymentStatus: "paid",
      hostConfirmedAttendance: true,
      payoutStatus: "pending",
      checkOut: { $gte: periodStart, $lte: periodEnd },
    })
      .populate("host", "username email")
      .lean();

    if (bookings.length === 0) {
      return { message: "Không có booking nào cần tổng kết", payoutsCreated: 0 };
    }

    // Group bookings theo host
    const hostGroups: Record<string, typeof bookings> = {};
    for (const b of bookings) {
      const hostId = b.host._id?.toString() || b.host.toString();
      if (!hostGroups[hostId]) hostGroups[hostId] = [];
      hostGroups[hostId]!.push(b);
    }

    const payoutsCreated: any[] = [];

    for (const [hostId, hostBookings] of Object.entries(hostGroups)) {
      // Kiểm tra đã có payout cho host trong kỳ này chưa
      const existingPayout = await PayoutModel.findOne({
        host: hostId,
        periodStart,
        periodEnd,
      });

      if (existingPayout) continue; // Đã tổng kết rồi

      // Lấy thông tin bank
      const host = await HostModel.findOne({ user: hostId });
      const bankInfo = host?.bankInfo || {
        bankName: "Chưa cung cấp",
        accountNumber: "Chưa cung cấp",
        accountHolderName: "Chưa cung cấp",
      };

      // Tính tổng
      const grossAmount = hostBookings.reduce((sum, b) => sum + (b.pricing?.total || 0), 0);
      const platformFee = Math.round(grossAmount * PLATFORM_FEE_RATE);
      const netAmount = grossAmount - platformFee;

      // Tạo payout
      const payout = await PayoutModel.create({
        host: new mongoose.Types.ObjectId(hostId),
        periodStart,
        periodEnd,
        bookings: hostBookings.map((b) => b._id),
        grossAmount,
        platformFee,
        platformFeeRate: PLATFORM_FEE_RATE,
        netAmount,
        status: "pending",
        bankInfo,
      });

      // Cập nhật booking payoutStatus
      await BookingModel.updateMany(
        { _id: { $in: hostBookings.map((b) => b._id) } },
        { $set: { payoutStatus: "settled", payoutId: payout._id } }
      );

      payoutsCreated.push(payout);
    }

    return {
      message: `Đã tổng kết ${payoutsCreated.length} payout cho tháng ${month}/${year}`,
      payoutsCreated: payoutsCreated.length,
      totalAmount: payoutsCreated.reduce((s, p) => s + p.netAmount, 0),
    };
  }

  /**
   * Admin xem tất cả payout
   */
  async getAllPayouts(filters: {
    status?: string;
    hostId?: string;
    month?: number | undefined;
    year?: number | undefined;
    page?: number;
    limit?: number;
  }) {
    const { status, hostId, month, year, page = 1, limit = 20 } = filters;
    const query: any = {};

    if (status) query.status = status;
    if (hostId) query.host = new mongoose.Types.ObjectId(hostId);
    if (month && year) {
      query.periodStart = { $gte: new Date(year, month - 1, 1) };
      query.periodEnd = { $lte: new Date(year, month, 0, 23, 59, 59) };
    }

    const skip = (page - 1) * limit;
    const [payouts, total] = await Promise.all([
      PayoutModel.find(query)
        .populate("host", "username email avatarUrl")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      PayoutModel.countDocuments(query),
    ]);

    // Tổng thống kê
    const stats = await PayoutModel.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          totalGross: { $sum: "$grossAmount" },
          totalFee: { $sum: "$platformFee" },
          totalNet: { $sum: "$netAmount" },
          totalPayouts: { $sum: 1 },
        },
      },
    ]);

    return {
      payouts,
      total,
      totalPages: Math.ceil(total / limit),
      page,
      stats: stats[0] || { totalGross: 0, totalFee: 0, totalNet: 0, totalPayouts: 0 },
    };
  }

  /**
   * Admin xác nhận đã chuyển tiền
   */
  async markPayoutCompleted(payoutId: string, adminNote?: string) {
    const payout = await PayoutModel.findById(payoutId);
    if (!payout) throw new Error("Không tìm thấy payout");
    if (payout.status === "completed") throw new Error("Payout đã hoàn tất");

    payout.status = "completed";
    payout.paidAt = new Date();
    if (adminNote) payout.note = adminNote;
    await payout.save();

    return payout;
  }

  /**
   * Host xem lịch sử payout
   */
  async getPayoutsByHost(hostId: string, page = 1, limit = 20) {
    const query = { host: new mongoose.Types.ObjectId(hostId) };
    const skip = (page - 1) * limit;

    const [payouts, total] = await Promise.all([
      PayoutModel.find(query)
        .sort({ periodStart: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      PayoutModel.countDocuments(query),
    ]);

    return { payouts, total, totalPages: Math.ceil(total / limit), page };
  }

  /**
   * Host xem tổng doanh thu theo khoảng thời gian
   */
  async getHostRevenueSummary(hostId: string, startDate?: string, endDate?: string) {
    const matchStage: any = {
      host: new mongoose.Types.ObjectId(hostId),
      status: "completed",
      paymentStatus: "paid",
      hostConfirmedAttendance: true,
    };

    if (startDate || endDate) {
      matchStage.checkOut = {};
      if (startDate) matchStage.checkOut.$gte = new Date(startDate);
      if (endDate) matchStage.checkOut.$lte = new Date(endDate);
    }

    // Tổng doanh thu
    const [summary] = await BookingModel.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: "$pricing.total" },
          totalBookings: { $sum: 1 },
          avgBookingValue: { $avg: "$pricing.total" },
        },
      },
    ]);

    // Doanh thu theo tháng (12 tháng gần nhất)
    const monthlyRevenue = await BookingModel.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: {
            year: { $year: "$checkOut" },
            month: { $month: "$checkOut" },
          },
          revenue: { $sum: "$pricing.total" },
          bookings: { $sum: 1 },
        },
      },
      { $sort: { "_id.year": -1, "_id.month": -1 } },
      { $limit: 12 },
    ]);

    // Payout tổng kết
    const payoutSummary = await PayoutModel.aggregate([
      { $match: { host: new mongoose.Types.ObjectId(hostId) } },
      {
        $group: {
          _id: "$status",
          total: { $sum: "$netAmount" },
          count: { $sum: 1 },
        },
      },
    ]);

    const totalRevenue = summary?.totalRevenue || 0;
    const platformFee = Math.round(totalRevenue * PLATFORM_FEE_RATE);

    return {
      totalRevenue,
      platformFee,
      netRevenue: totalRevenue - platformFee,
      totalBookings: summary?.totalBookings || 0,
      avgBookingValue: Math.round(summary?.avgBookingValue || 0),
      monthlyRevenue: monthlyRevenue.reverse(),
      payoutSummary,
    };
  }

  /**
   * Export doanh thu host ra CSV
   */
  async exportHostRevenue(hostId: string, startDate?: string, endDate?: string): Promise<string> {
    const matchStage: any = {
      host: new mongoose.Types.ObjectId(hostId),
      status: "completed",
      paymentStatus: "paid",
    };

    if (startDate || endDate) {
      matchStage.checkOut = {};
      if (startDate) matchStage.checkOut.$gte = new Date(startDate);
      if (endDate) matchStage.checkOut.$lte = new Date(endDate);
    }

    const bookings = await BookingModel.find(matchStage)
      .populate("guest", "username email")
      .populate("site", "name")
      .populate("property", "name")
      .sort({ checkOut: -1 })
      .lean();

    // Build CSV
    const headers = [
      "Mã booking",
      "Khách hàng",
      "Email",
      "Địa điểm",
      "Property",
      "Check-in",
      "Check-out",
      "Số đêm",
      "Số khách",
      "Tổng tiền (VNĐ)",
      "Phí platform 5% (VNĐ)",
      "Số tiền nhận (VNĐ)",
      "Trạng thái",
      "Xác nhận khách đến",
    ].join(",");

    const rows = bookings.map((b: any) => {
      const total = b.pricing?.total || 0;
      const fee = Math.round(total * PLATFORM_FEE_RATE);
      return [
        b.code || "",
        `"${(b.guest as any)?.username || ""}"`,
        `"${(b.guest as any)?.email || ""}"`,
        `"${(b.site as any)?.name || ""}"`,
        `"${(b.property as any)?.name || ""}"`,
        new Date(b.checkIn).toLocaleDateString("vi-VN"),
        new Date(b.checkOut).toLocaleDateString("vi-VN"),
        b.nights || 0,
        b.numberOfGuests || 0,
        total,
        fee,
        total - fee,
        b.status,
        b.hostConfirmedAttendance ? "Có" : "Không",
      ].join(",");
    });

    return [headers, ...rows].join("\n");
  }

  /**
   * Admin: Lấy tất cả booking completed+paid nhưng chưa được tổng kết (payoutStatus=pending)
   * Group theo host để hiển thị danh sách cần thanh toán
   */
  async getUnpaidBookingsByHost() {
    const bookings = await BookingModel.find({
      status: "completed",
      paymentStatus: "paid",
      payoutStatus: "pending",
    })
      .populate("host", "username email avatarUrl")
      .populate("property", "name")
      .populate("site", "name")
      .lean();

    if (bookings.length === 0) {
      return { groups: [], totalHosts: 0, totalBookings: 0, totalAmount: 0 };
    }

    // Group by host
    const hostGroups: Record<string, { host: any; bookings: any[]; totalAmount: number }> = {};
    for (const b of bookings) {
      const hostId = (b.host as any)?._id?.toString() || b.host?.toString();
      if (!hostGroups[hostId]) {
        hostGroups[hostId] = { host: b.host, bookings: [], totalAmount: 0 };
      }
      hostGroups[hostId].bookings.push(b);
      hostGroups[hostId].totalAmount += b.pricing?.total || 0;
    }

    // Lấy thêm thông tin bank của từng host
    const groups = await Promise.all(
      Object.entries(hostGroups).map(async ([hostId, group]) => {
        const hostKyc = await HostModel.findOne({ user: hostId }).lean();
        const grossAmount = group.totalAmount;
        const platformFee = Math.round(grossAmount * PLATFORM_FEE_RATE);
        return {
          hostId,
          host: group.host,
          bookingCount: group.bookings.length,
          grossAmount,
          platformFee,
          netAmount: grossAmount - platformFee,
          bankInfo: hostKyc?.bankInfo || null,
          bookings: group.bookings.map((b: any) => ({
            _id: b._id,
            code: b.code,
            property: b.property,
            site: b.site,
            checkIn: b.checkIn,
            checkOut: b.checkOut,
            nights: b.nights,
            total: b.pricing?.total || 0,
            hostConfirmedAttendance: b.hostConfirmedAttendance,
          })),
        };
      })
    );

    // Sort by netAmount desc
    groups.sort((a, b) => b.netAmount - a.netAmount);

    return {
      groups,
      totalHosts: groups.length,
      totalBookings: bookings.length,
      totalAmount: groups.reduce((s, g) => s + g.grossAmount, 0),
    };
  }
}
