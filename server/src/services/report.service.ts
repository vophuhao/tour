import Report from "../models/report.model";
import ForumPost from "../models/forum.post.model";
import FreeSpot from "../models/free-spot.model";
import { buildSafeSearchRegex } from "../utils/regex";

export interface CreateReportInput {
  targetId: string;
  targetType: "post" | "free-spot";
  reason: string;
  description?: string;
}

export interface GetReportsParams {
  page?: number;
  limit?: number;
  status?: string;
  targetType?: string;
}

export class ReportService {
  async createReport(userId: string, input: CreateReportInput): Promise<any> {
    const { targetId, targetType, reason, description } = input;

    // Check duplicate report
    const existing = await Report.findOne({
      reporterId: userId,
      targetId,
      targetType,
      status: "pending",
    });
    if (existing) {
      throw new Error("Bạn đã báo cáo nội dung này rồi");
    }

    const report = new Report({
      reporterId: userId,
      targetId,
      targetType,
      reason,
      description,
    });
    await report.save();

    // Increment reportCount on target
    if (targetType === "post") {
      await ForumPost.findByIdAndUpdate(targetId, { $inc: { reportCount: 1 } });
    } else if (targetType === "free-spot") {
      await FreeSpot.findByIdAndUpdate(targetId, { $inc: { reportCount: 1 } });
    }

    return report;
  }

  async getReports(params: GetReportsParams): Promise<{
    reports: any[];
    total: number;
    currentPage: number;
    totalPages: number;
  }> {
    const { page = 1, limit = 20, status, targetType } = params;
    const skip = (page - 1) * limit;

    const query: any = {};
    if (status) query.status = status;
    if (targetType) query.targetType = targetType;

    const [reports, total] = await Promise.all([
      Report.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate("reporterId", "username avatarUrl email")
        .populate("resolvedBy", "username avatarUrl"),
      Report.countDocuments(query),
    ]);

    // Attach target info
    const enriched = await Promise.all(
      reports.map(async (r: any) => {
        const obj = r.toObject();
        try {
          if (r.targetType === "post") {
            const post = await ForumPost.findById(r.targetId).select(
              "title slug status userId"
            ).populate("userId", "username");
            obj.target = post;
          } else if (r.targetType === "free-spot") {
            const spot = await FreeSpot.findById(r.targetId).select(
              "title slug status author"
            ).populate("author", "username");
            obj.target = spot;
          }
        } catch {}
        return obj;
      })
    );

    return {
      reports: enriched,
      total,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
    };
  }

  async updateReportStatus(
    reportId: string,
    adminId: string,
    status: "reviewed" | "resolved" | "dismissed",
    resolveNote?: string,
    action?: "hide_target" | "none"
  ): Promise<any> {
    const report = await Report.findById(reportId);
    if (!report) throw new Error("Báo cáo không tồn tại");

    report.status = status;
    report.resolvedBy = adminId as any;
    report.resolvedAt = new Date();
    if (resolveNote) report.resolveNote = resolveNote;
    await report.save();

    // Optionally hide target content
    if (action === "hide_target") {
      if (report.targetType === "post") {
        await ForumPost.findByIdAndUpdate(report.targetId, { status: "hidden" });
      } else if (report.targetType === "free-spot") {
        await FreeSpot.findByIdAndUpdate(report.targetId, { status: "hidden" });
      }
    }

    return report;
  }

  // Admin: Get all forum posts including hidden/pending
  async getAllForumPosts(params: {
    page?: number;
    limit?: number;
    status?: string;
    search?: string;
  }): Promise<{ posts: any[]; total: number; currentPage: number }> {
    const { page = 1, limit = 20, status, search } = params;
    const skip = (page - 1) * limit;
    const query: any = {};
    if (status) query.status = status;
    if (search) {
      const safeSearch = buildSafeSearchRegex(search);
      query.$or = [
        { title: { $regex: safeSearch } },
        { subject: { $regex: safeSearch } },
      ];
    }

    const [posts, total] = await Promise.all([
      ForumPost.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate("userId", "username avatarUrl email"),
      ForumPost.countDocuments(query),
    ]);

    return { posts, total, currentPage: page };
  }

  async updateForumPostStatus(
    postId: string,
    status: string,
    moderationReason?: string
  ): Promise<any> {
    const post = await ForumPost.findByIdAndUpdate(
      postId,
      {
        status,
        ...(moderationReason && { moderationReason }),
        moderationAt: new Date(),
      },
      { new: true }
    );
    if (!post) throw new Error("Bài viết không tồn tại");
    return post;
  }

  // Admin: Get all free-spots including hidden
  async getAllFreeSpots(params: {
    page?: number;
    limit?: number;
    status?: string;
    search?: string;
  }): Promise<{ spots: any[]; total: number; currentPage: number }> {
    const { page = 1, limit = 20, status, search } = params;
    const skip = (page - 1) * limit;
    const query: any = {};
    if (status) query.status = status;
    if (search) {
      const safeSearch = buildSafeSearchRegex(search);
      query.$or = [
        { title: { $regex: safeSearch } },
        { city: { $regex: safeSearch } },
        { address: { $regex: safeSearch } },
      ];
    }

    const [spots, total] = await Promise.all([
      FreeSpot.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .populate("author", "username avatarUrl email"),
      FreeSpot.countDocuments(query),
    ]);

    return { spots, total, currentPage: page };
  }

  async updateFreeSpotStatus(
    spotId: string,
    status: string,
    isVerified?: boolean
  ): Promise<any> {
    const update: any = { status };
    if (typeof isVerified === "boolean") update.isVerified = isVerified;
    const spot = await FreeSpot.findByIdAndUpdate(spotId, update, { new: true });
    if (!spot) throw new Error("Địa điểm không tồn tại");
    return spot;
  }
}
