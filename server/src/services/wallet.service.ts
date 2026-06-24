import { ErrorFactory } from "@/errors";
import { BookingModel } from "@/models";
import HostModel from "@/models/host.model";
import UserModel from "../models/user.model";
import NotificationService from "./notification.service";
import { WalletTransactionModel } from "@/models/wallet-transaction.model";
import { WithdrawalModel } from "@/models/withdrawal.model";
import appAssert from "../utils/app-assert";
import { buildSafeSearchRegex } from "../utils/regex";
import { logger } from "../utils";
import mongoose from "mongoose";

const PLATFORM_FEE_RATE = 0.05; // 5%

export default class WalletService {
  /**
   * Cộng tiền vào ví host sau khi khách xác nhận đã đến.
   * hostUserId là _id của User (không phải Host document)
   */
  async creditHostWallet(
    hostUserId: string,
    bookingId: string,
    grossAmount: number
  ) {
    const platformFee = Math.round(grossAmount * PLATFORM_FEE_RATE);
    const netAmount = grossAmount - platformFee;

    // Tìm host record theo user id (booking.host = User._id)
    let hostRecord = await HostModel.findOne({ user: hostUserId });

    // Fallback: if not found by user field, try direct _id lookup
    // (handles cases where booking.host stores the Host doc's _id instead)
    if (!hostRecord && mongoose.Types.ObjectId.isValid(hostUserId)) {
      hostRecord = await HostModel.findById(hostUserId);
    }

    appAssert(hostRecord, ErrorFactory.resourceNotFound("Host"));

    const balanceBefore = hostRecord.walletBalance;
    const balanceAfter = balanceBefore + netAmount;

    // Cộng ví
    hostRecord.walletBalance = balanceAfter;
    await hostRecord.save();

    // Ghi log giao dịch
    const tx = await WalletTransactionModel.create({
      host: hostUserId,
      type: "credit",
      amount: netAmount,
      bookingId: new mongoose.Types.ObjectId(bookingId),
      description: `Khách xác nhận đến - Booking #${bookingId.slice(-6).toUpperCase()}`,
      balanceBefore,
      balanceAfter,
    });

    // Cập nhật booking
    await BookingModel.findByIdAndUpdate(bookingId, {
      $set: {
        walletCredited: true,
        walletCreditedAt: new Date(),
        platformFee,
        hostNetAmount: netAmount,
        status: "completed",
      },
    });

    return { netAmount, platformFee, balanceAfter, txId: tx._id };
  }

  /**
   * Cộng tiền vào ví host khi hết thời hạn (khách không xác nhận sau 5 ngày)
   * Host nhận 100% net
   */
  async creditHostWalletAutoSettle(hostUserId: string, bookingId: string, grossAmount: number) {
    return this.creditHostWallet(hostUserId, bookingId, grossAmount);
  }

  /**
   * Cộng tiền vào ví host khi khách không đến (host nhận 20%)
   */
  async creditHostWalletCannotAttend(
    hostUserId: string,
    bookingId: string,
    grossAmount: number,
    hostRate: number = 0.2
  ) {
    const hostAmount = Math.round(grossAmount * hostRate);
    const platformFee = Math.round(grossAmount * PLATFORM_FEE_RATE);

    let hostRecord = await HostModel.findOne({ user: hostUserId });
    if (!hostRecord && mongoose.Types.ObjectId.isValid(hostUserId)) {
      hostRecord = await HostModel.findById(hostUserId);
    }
    appAssert(hostRecord, ErrorFactory.resourceNotFound("Host"));

    const balanceBefore = hostRecord.walletBalance;
    const balanceAfter = balanceBefore + hostAmount;

    hostRecord.walletBalance = balanceAfter;
    await hostRecord.save();

    await WalletTransactionModel.create({
      host: hostUserId,
      type: "credit",
      amount: hostAmount,
      bookingId: new mongoose.Types.ObjectId(bookingId),
      description: `Khách hủy phòng (${Math.round(hostRate * 100)}%) - Booking #${bookingId.slice(-6).toUpperCase()}`,
      balanceBefore,
      balanceAfter,
    });

    await BookingModel.findByIdAndUpdate(bookingId, {
      $set: {
        walletCredited: true,
        walletCreditedAt: new Date(),
        platformFee,
        hostNetAmount: hostAmount,
        status: "completed",
      },
    });

    return { hostAmount, platformFee, balanceAfter };
  }

  /**
   * Lấy số dư ví host
   */
  async getWalletBalance(hostUserId: string) {
    const hostRecord = await HostModel.findOne({ user: hostUserId });
    if (!hostRecord) {
      return {
        walletBalance: 0,
        pendingWithdrawalAmount: 0,
        availableBalance: 0,
        totalWithdrawn: 0,
      };
    }

    const completedWithdrawals = await WithdrawalModel.aggregate([
      { $match: { host: new mongoose.Types.ObjectId(hostUserId), status: "completed" } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);
    const totalWithdrawn = completedWithdrawals[0]?.total || 0;

    return {
      walletBalance: hostRecord.walletBalance,
      pendingWithdrawalAmount: hostRecord.pendingWithdrawalAmount,
      availableBalance:
        hostRecord.walletBalance - hostRecord.pendingWithdrawalAmount,
      bankInfo: hostRecord.bankInfo,
      totalWithdrawn,
    };
  }

  /**
   * Lịch sử giao dịch ví
   */
  async getWalletTransactions(
    hostUserId: string,
    page = 1,
    limit = 20
  ) {
    const skip = (page - 1) * limit;
    const query = { host: new mongoose.Types.ObjectId(hostUserId) };

    const [transactions, total] = await Promise.all([
      WalletTransactionModel.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      WalletTransactionModel.countDocuments(query),
    ]);

    return {
      transactions,
      total,
      totalPages: Math.ceil(total / limit),
      page,
    };
  }

  /**
   * Host tạo lệnh rút tiền (trừ tiền trực tiếp và hoàn thành ngay)
   */
  async createWithdrawalRequest(
    hostUserId: string,
    amount: number,
    bankInfo: { bankName: string; accountNumber: string; accountHolderName: string }
  ) {
    const hostRecord = await HostModel.findOne({ user: hostUserId });
    appAssert(hostRecord, ErrorFactory.resourceNotFound("Host"));
    
    appAssert(bankInfo, ErrorFactory.badRequest("Vui lòng điền thông tin ngân hàng"));
    appAssert(bankInfo.bankName?.trim(), ErrorFactory.badRequest("Tên ngân hàng là bắt buộc"));
    appAssert(bankInfo.accountNumber?.trim(), ErrorFactory.badRequest("Số tài khoản là bắt buộc"));
    appAssert(bankInfo.accountHolderName?.trim(), ErrorFactory.badRequest("Tên chủ tài khoản là bắt buộc"));

    // Số dư khả dụng trừ đi các lệnh chờ duyệt (nếu có, để đảm bảo an toàn)
    const pendingAmount = hostRecord.pendingWithdrawalAmount || 0;
    const available = hostRecord.walletBalance - pendingAmount;
    appAssert(
      amount <= available,
      ErrorFactory.badRequest(
        `Số tiền rút vượt quá số dư khả dụng (${available.toLocaleString("vi-VN")}₫)`
      )
    );
    appAssert(amount >= 50000, ErrorFactory.badRequest("Số tiền rút tối thiểu là 50,000₫"));

    // Cập nhật thông tin ngân hàng của host
    hostRecord.bankInfo = {
      bankName: bankInfo.bankName.trim(),
      accountNumber: bankInfo.accountNumber.trim(),
      accountHolderName: bankInfo.accountHolderName.trim(),
    };

    // Giả lập giao dịch chuyển tiền liên ngân hàng qua Napas/VietQR
    const napasTransId = `NPS${Date.now()}${Math.floor(1000 + Math.random() * 9000)}`;
    logger.info("=== [BANK MOCK GATEWAY] Kích hoạt chuyển khoản tự động ===");
    logger.info(`Đang kết nối tới cổng thanh toán VietQR / Napas247...`);
    logger.info(`Thông tin tài khoản nhận: ${bankInfo.bankName.trim()} - Stk: ${bankInfo.accountNumber.trim()} - Chủ TK: ${bankInfo.accountHolderName.trim()}`);
    logger.info(`Đang xử lý giao dịch chuyển tiền số lượng: ${amount.toLocaleString("vi-VN")}₫...`);
    logger.info(`[SUCCESS] Giao dịch thành công. Mã giao dịch Napas: ${napasTransId}`);
    logger.info("======================================================");

    // Trừ số dư ví ngay lập tức
    const balanceBefore = hostRecord.walletBalance;
    const balanceAfter = balanceBefore - amount;
    hostRecord.walletBalance = balanceAfter;
    await hostRecord.save();

    // Tạo lệnh rút tiền với status = "completed" (trừ tiền trực tiếp)
    const withdrawal = await WithdrawalModel.create({
      host: new mongoose.Types.ObjectId(hostUserId),
      hostRecord: hostRecord._id,
      amount,
      status: "completed",
      bankInfo: {
        bankName: bankInfo.bankName.trim(),
        accountNumber: bankInfo.accountNumber.trim(),
        accountHolderName: bankInfo.accountHolderName.trim(),
      },
      processedAt: new Date(),
    });

    // Ghi log giao dịch debit
    const tx = await WalletTransactionModel.create({
      host: hostUserId,
      type: "debit",
      amount,
      withdrawalId: withdrawal._id,
      description: `Rút tiền - Lệnh #${(withdrawal._id as mongoose.Types.ObjectId).toString().slice(-6).toUpperCase()} (Auto Payout)`,
      balanceBefore,
      balanceAfter,
    });

    withdrawal.walletTransactionId = tx._id as mongoose.Types.ObjectId;
    await withdrawal.save();

    // Gửi thông báo đến Admin
    try {
      const notificationService = new NotificationService();
      await notificationService.createWithdrawalNotificationForAdmins(
        hostUserId,
        hostRecord.name,
        amount,
        (withdrawal._id as mongoose.Types.ObjectId).toString()
      );
    } catch (error) {
      console.error("Lỗi khi gửi thông báo rút tiền cho admin:", error);
    }

    return withdrawal;
  }

  /**
   * Host xem lịch sử lệnh rút
   */
  async getWithdrawals(hostUserId: string, page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    const query = { host: new mongoose.Types.ObjectId(hostUserId) };

    const [withdrawals, total] = await Promise.all([
      WithdrawalModel.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      WithdrawalModel.countDocuments(query),
    ]);

    return { withdrawals, total, totalPages: Math.ceil(total / limit), page };
  }

  /**
   * Admin xem tất cả lệnh rút
   */
  async adminGetAllWithdrawals(filters: {
    status?: string | undefined;
    hostId?: string | undefined;
    search?: string | undefined;
    page?: number;
    limit?: number;
  }) {
    const { status, hostId, search, page = 1, limit = 20 } = filters;
    const query: Record<string, any> = {};

    if (status) query.status = status;
    if (hostId) query.host = new mongoose.Types.ObjectId(hostId);

    if (search) {
      const matchingUsers = await UserModel.find({
        $or: [
          { username: { $regex: buildSafeSearchRegex(search) } },
          { email: { $regex: buildSafeSearchRegex(search) } },
        ]
      }).select("_id");
      
      const userIds = matchingUsers.map(u => u._id);
      
      query.$or = [
        { host: { $in: userIds } },
        { "bankInfo.accountNumber": { $regex: buildSafeSearchRegex(search) } },
        { "bankInfo.bankName": { $regex: buildSafeSearchRegex(search) } },
        { "bankInfo.accountHolderName": { $regex: buildSafeSearchRegex(search) } },
      ];
    }

    const skip = (page - 1) * limit;
    const [withdrawals, total] = await Promise.all([
      WithdrawalModel.find(query)
        .populate("host", "username email avatarUrl")
        .populate("hostRecord", "bankInfo walletBalance")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      WithdrawalModel.countDocuments(query),
    ]);

    // Thống kê
    const [pendingStats] = await WithdrawalModel.aggregate([
      { $match: { status: "pending" } },
      {
        $group: {
          _id: null,
          count: { $sum: 1 },
          totalAmount: { $sum: "$amount" },
        },
      },
    ]);

    return {
      withdrawals,
      total,
      totalPages: Math.ceil(total / limit),
      page,
      pendingCount: pendingStats?.count || 0,
      pendingAmount: pendingStats?.totalAmount || 0,
    };
  }

  /**
   * Admin lấy danh sách số dư ví host và thông tin ngân hàng
   */
  async adminGetHostBalances(filters: {
    search?: string | undefined;
    page?: number;
    limit?: number;
  }) {
    const { search, page = 1, limit = 20 } = filters;
    const query: Record<string, any> = { status: "approved" };

    if (search) {
      const matchingUsers = await UserModel.find({
        $or: [
          { username: { $regex: buildSafeSearchRegex(search) } },
          { email: { $regex: buildSafeSearchRegex(search) } },
        ]
      }).select("_id");
      
      const userIds = matchingUsers.map(u => u._id);

      query.$or = [
        { name: { $regex: buildSafeSearchRegex(search) } },
        { gmail: { $regex: buildSafeSearchRegex(search) } },
        { user: { $in: userIds } },
      ];
    }

    const skip = (page - 1) * limit;
    const [hosts, total] = await Promise.all([
      HostModel.find(query)
        .populate("user", "username email avatarUrl")
        .sort({ walletBalance: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      HostModel.countDocuments(query),
    ]);

    return {
      hosts,
      total,
      totalPages: Math.ceil(total / limit),
      page,
    };
  }

  /**
   * Admin xử lý lệnh rút tiền
   */
  async adminProcessWithdrawal(
    withdrawalId: string,
    adminId: string,
    approved: boolean,
    adminNote?: string
  ) {
    const withdrawal = await WithdrawalModel.findById(withdrawalId);
    appAssert(withdrawal, ErrorFactory.resourceNotFound("Withdrawal"));
    appAssert(
      withdrawal.status === "pending" || withdrawal.status === "processing",
      ErrorFactory.badRequest("Lệnh rút này đã được xử lý")
    );

    const hostRecord = await HostModel.findOne({ user: withdrawal.host });
    appAssert(hostRecord, ErrorFactory.resourceNotFound("Host"));

    if (approved) {
      // Trừ tiền khỏi ví
      const balanceBefore = hostRecord.walletBalance;
      const balanceAfter = balanceBefore - withdrawal.amount;
      appAssert(
        balanceAfter >= 0,
        ErrorFactory.badRequest("Số dư ví không đủ")
      );

      hostRecord.walletBalance = balanceAfter;
      hostRecord.pendingWithdrawalAmount = Math.max(
        0,
        hostRecord.pendingWithdrawalAmount - withdrawal.amount
      );
      await hostRecord.save();

      // Ghi log giao dịch
      const tx = await WalletTransactionModel.create({
        host: withdrawal.host,
        type: "debit",
        amount: withdrawal.amount,
        withdrawalId: withdrawal._id,
        description: `Rút tiền - Lệnh #${(withdrawal._id as mongoose.Types.ObjectId).toString().slice(-6).toUpperCase()}`,
        balanceBefore,
        balanceAfter,
      });

      withdrawal.status = "completed";
      withdrawal.processedAt = new Date();
      withdrawal.processedBy = new mongoose.Types.ObjectId(adminId);
      withdrawal.walletTransactionId = tx._id as mongoose.Types.ObjectId;
      if (adminNote) withdrawal.adminNote = adminNote;
    } else {
      // Từ chối — hoàn lại số tiền đã khoá
      hostRecord.pendingWithdrawalAmount = Math.max(
        0,
        hostRecord.pendingWithdrawalAmount - withdrawal.amount
      );
      await hostRecord.save();

      withdrawal.status = "rejected";
      withdrawal.processedAt = new Date();
      withdrawal.processedBy = new mongoose.Types.ObjectId(adminId);
      if (adminNote) withdrawal.adminNote = adminNote;
    }

    await withdrawal.save();
    return withdrawal;
  }
}
