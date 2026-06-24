import { BookingModel, PropertyModel } from "@/models";

/**
 * Tiêu chí đạt Superhost:
 * - Rating trung bình ≥ 4.8
 * - Tỷ lệ phản hồi ≥ 90%
 * - ≥ 10 bookings đã hoàn thành
 * - Không có booking nào bị host chủ động hủy trong 12 tháng qua
 */
const SUPERHOST_CRITERIA = {
  minRating: 4.8,
  minResponseRate: 90,
  minCompletedBookings: 10,
};

export interface SuperhostStatus {
  isEligible: boolean;
  criteria: {
    rating: { value: number; passed: boolean; required: number };
    responseRate: { value: number; passed: boolean; required: number };
    completedBookings: { value: number; passed: boolean; required: number };
    noHostCancellations: { value: boolean; passed: boolean };
  };
}

export class SuperhostService {
  /**
   * Kiểm tra điều kiện Superhost cho một host cụ thể
   */
  async getSuperhostStatus(hostId: string): Promise<SuperhostStatus> {
    const twelveMonthsAgo = new Date();
    twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12);

    // Lấy tất cả bookings của host trong 12 tháng qua
    const [completedBookings, hostCancelledBookings, properties] = await Promise.all([
      BookingModel.countDocuments({
        host: hostId,
        status: "completed",
        createdAt: { $gte: twelveMonthsAgo },
      }),
      BookingModel.countDocuments({
        host: hostId,
        status: "cancelled",
        cancelledBy: hostId, // Host tự hủy
        cancelledAt: { $gte: twelveMonthsAgo },
      }),
      PropertyModel.find({ host: hostId, isActive: true }).select(
        "stats.averageRating stats.responseRate stats.totalReviews"
      ),
    ]);

    // Tính rating và response rate trung bình của tất cả properties
    const activeProperties = properties.filter(
      (p) => p.stats.totalReviews > 0 || p.stats.responseRate
    );
    const avgRating =
      activeProperties.length > 0
        ? activeProperties.reduce((sum, p) => sum + p.stats.averageRating, 0) /
          activeProperties.length
        : 0;
    const avgResponseRate =
      activeProperties.length > 0
        ? activeProperties.reduce((sum, p) => sum + (p.stats.responseRate || 0), 0) /
          activeProperties.length
        : 0;

    const criteria = {
      rating: {
        value: parseFloat(avgRating.toFixed(2)),
        passed: avgRating >= SUPERHOST_CRITERIA.minRating,
        required: SUPERHOST_CRITERIA.minRating,
      },
      responseRate: {
        value: parseFloat(avgResponseRate.toFixed(1)),
        passed: avgResponseRate >= SUPERHOST_CRITERIA.minResponseRate,
        required: SUPERHOST_CRITERIA.minResponseRate,
      },
      completedBookings: {
        value: completedBookings,
        passed: completedBookings >= SUPERHOST_CRITERIA.minCompletedBookings,
        required: SUPERHOST_CRITERIA.minCompletedBookings,
      },
      noHostCancellations: {
        value: hostCancelledBookings === 0,
        passed: hostCancelledBookings === 0,
      },
    };

    const isEligible = Object.values(criteria).every((c) => c.passed);

    return { isEligible, criteria };
  }

  /**
   * Đánh giá và cập nhật Superhost status cho 1 host
   */
  async evaluateHost(hostId: string): Promise<{ isSuperhost: boolean; wasChanged: boolean }> {
    const { isEligible } = await this.getSuperhostStatus(hostId);
    const now = new Date();

    // Lấy properties hiện tại của host
    const properties = await PropertyModel.find({ host: hostId });
    let wasChanged = false;

    for (const property of properties) {
      const wasAlready = property.isSuperhost;
      if (wasAlready !== isEligible) {
        wasChanged = true;
      }

      property.isSuperhost = isEligible;
      property.superhostEvaluatedAt = now;

      // Nếu vừa đạt được lần đầu → ghi lại ngày
      if (isEligible && !property.superhostSince) {
        property.superhostSince = now;
      }
      // Nếu mất Superhost → xóa ngày bắt đầu
      if (!isEligible) {
        property.superhostSince = undefined as any;
      }

      await property.save();
    }

    return { isSuperhost: isEligible, wasChanged };
  }

  /**
   * Chạy đánh giá Superhost cho tất cả hosts đang hoạt động
   * (được gọi bởi cron job hàng ngày)
   */
  async runDailyEvaluation(): Promise<void> {
    console.log("[Superhost] Starting daily evaluation...");

    // Lấy danh sách tất cả host IDs có ít nhất 1 property active
    const hostIds = await PropertyModel.distinct("host", { isActive: true });

    let evaluated = 0;
    let promoted = 0;
    let demoted = 0;

    for (const hostId of hostIds) {
      try {
        const { isSuperhost, wasChanged } = await this.evaluateHost(hostId.toString());
        evaluated++;
        if (wasChanged) {
          if (isSuperhost) promoted++;
          else demoted++;
        }
      } catch (err) {
        console.error(`[Superhost] Error evaluating host ${hostId}:`, err);
      }
    }

    console.log(
      `[Superhost] Daily evaluation complete: ${evaluated} hosts evaluated, ${promoted} promoted, ${demoted} demoted.`
    );
  }
}

export default new SuperhostService();
