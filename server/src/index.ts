import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import express from "express";
import http from "http";
import cron from "node-cron";
import mongoose from "mongoose";
import { connectRedis, connectToDatabase } from "./config";
import { APP_ORIGIN, NODE_ENV, OK, PORT } from "./constants";
import { authenticate, errorHandler, globalRateLimit, authRateLimit } from "./middleware";
import {
  amenityRoutes,
  authRoutes,
  bookingRoutes,
  commentRoutes,
  forumRoutes,
  favoriteRoutes,
  mediaRoutes,
  propertyRoutes,
  reviewRoutes,
  siteRoutes,
  userRoutes,
  payoutRoutes,
  aiRoutes,
} from "./routes";

import dashboardHRoutes from "./routes/dashbardH.route";
import dashboardRoutes from "./routes/dashboard.route";
import supportRouter from "./routes/directMessage.route";
import notificationRoutes from "./routes/notification.route";
import payosRoutes from "./routes/payos.route,";
import freeSpotRoutes from "./routes/free-spot.route";
import reportRoutes from "./routes/report.route";
import walletRoutes from "./routes/wallet.route";
import mobileSelfieRoutes from "./routes/mobile-selfie.route";
import { BookingLifecycleService, PropertyService, ForumService } from "./services";
import PayoutService from "./services/payout.service";
import { initializeSocket } from "./socket";

const app = express();

// ============================================================
// Security & Performance Middleware
// ============================================================

// HTTP Security Headers (nếu helmet đã được cài)
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const helmet = require("helmet");
  app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }, // Cho phép load media từ Cloudinary
    contentSecurityPolicy: false, // Disable CSP để không ảnh hưởng API
  }));
  console.log("✅ Helmet security headers enabled");
} catch {
  console.warn("⚠️  helmet not installed, skipping security headers");
}

// Gzip/Brotli Compression — giảm response size ~70%
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const compression = require("compression");
  app.use(compression({
    level: 6, // Cân bằng giữa speed và compression ratio
    threshold: 1024, // Chỉ nén response > 1KB
    filter: (req: express.Request, res: express.Response) => {
      // Không nén nếu client không hỗ trợ
      if (req.headers["x-no-compression"]) return false;
      return compression.filter(req, res);
    },
  }));
  console.log("✅ Compression (gzip) enabled");
} catch {
  console.warn("⚠️  compression not installed, skipping gzip");
}

// ============================================================
// Standard Middleware
// ============================================================
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(
  cors({
    origin: [
      APP_ORIGIN,
      "https://www.hdcamp.id.vn",

    ],
    credentials: true,
  })
);
app.use(cookieParser());

// ============================================================
// Global Rate Limiting — 200 req/min/IP
// ============================================================
app.use(globalRateLimit);

// ============================================================
// Cron Jobs
// ============================================================
const bookingLifecycleService = new BookingLifecycleService();
const payoutService = new PayoutService();

// Cron: Tổng kết payout đầu mỗi tháng (ngày 1, 00:00)
cron.schedule("0 0 1 * *", async () => {
  if (NODE_ENV !== "production") return; // Chỉ chạy trên production
  console.log("💰 Running monthly payout job...");
  try {
    const now = new Date();
    const prevMonth = now.getMonth() === 0 ? 12 : now.getMonth();
    const prevYear = now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear();
    const result = await payoutService.runMonthlyPayout(prevMonth, prevYear);
    console.log(`✅ Payout completed: ${result.message}`);
  } catch (err) {
    console.error("❌ Monthly payout job failed:", err);
  }
});

// Cron: Tự động cộng tiền vào ví host sau 5 ngày khách không xác nhận (mỗi 6 giờ)
cron.schedule("0 */6 * * *", async () => {
  console.log("🔄 Running auto-settle expired bookings job...");
  try {
    const result = await bookingLifecycleService.autoSettleExpiredBookings();
    if (result.settled > 0) {
      console.log(`✅ Auto-settle: đã giải quyết ${result.settled}/${result.total} booking hết hạn`);
    }
  } catch (err) {
    console.error("❌ Auto-settle job failed:", err);
  }
});

// Cron: Tự động hủy/xóa các booking chưa thanh toán quá hạn 12 tiếng và giải phóng ngày (mỗi 15 phút)
cron.schedule("*/15 * * * *", async () => {
  console.log("🔄 Running cancel expired pending bookings job (12h timeout)...");
  try {
    const result = await bookingLifecycleService.cancelExpiredPendingBookings();
    if (result.remindersSent > 0 || result.bookingsCancelled > 0) {
      console.log(
        `✅ Expired bookings job: sent ${result.remindersSent} reminders, cancelled ${result.bookingsCancelled} bookings`
      );
    }
  } catch (err) {
    console.error("❌ Expired bookings job failed:", err);
  }
});

// Cron: Tự động xóa các booking chưa thanh toán có check-in bằng ngày hiện tại (mỗi ngày lúc 1:00 AM)
cron.schedule("0 1 * * *", async () => {
  console.log("🔄 Running cleanup unpaid bookings job...");
  try {
    const result = await bookingLifecycleService.cancelUnpaidBookingsOnCheckinDay();
    console.log(
      `✅ Cleanup completed: cancelled ${result.cancelled}/${result.total} unpaid bookings`
    );
  } catch (err) {
    console.error("❌ Cleanup unpaid bookings job failed:", err);
  }
});

// Cron: Đồng bộ lượt xem từ Redis sang MongoDB (mỗi 5 phút)
cron.schedule("*/5 * * * *", async () => {
  console.log("🔄 Syncing property and post views from Redis to MongoDB...");
  try {
    const propertyService = new PropertyService();
    const forumService = new ForumService();
    await Promise.all([
      propertyService.syncViewsFromRedis(),
      forumService.syncViewsFromRedis(),
    ]);
    console.log("✅ View syncing completed");
  } catch (err) {
    console.error("❌ View syncing failed:", err);
  }
});

// Cron: Đánh giá và cập nhật trạng thái Superhost cho tất cả hosts (mỗi ngày lúc 3:00 AM)
cron.schedule("0 3 * * *", async () => {
  console.log("🏅 Running Superhost daily evaluation job...");
  try {
    const { SuperhostService } = await import("@/services/superhost.service");
    const superhostService = new SuperhostService();
    await superhostService.runDailyEvaluation();
  } catch (err) {
    console.error("❌ Superhost evaluation job failed:", err);
  }
});

// ============================================================
// Health check — Readiness probe cho load balancer / k8s
// ============================================================
app.get("/health", async (_, res) => {
  const dbState = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
  const { redisClient } = await import("./config/redis");
  const redisState = redisClient.isOpen ? "connected" : "disconnected";
  const allHealthy = dbState === "connected" && redisState === "connected";

  return res.status(allHealthy ? OK : 503).json({
    status: allHealthy ? "healthy" : "degraded",
    environment: NODE_ENV,
    database: dbState,
    redis: redisState,
    uptime: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// Basic ping (always 200 — dùng để check server còn sống, không check dependencies)
app.get("/", (_, res) => {
  return res.status(OK).json({
    status: "ok",
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// Routes — Auth (với strict rate limit chống brute-force)
// ============================================================
app.use("/auth", authRateLimit, authRoutes);

// ============================================================
// Routes — Protected (require authentication)
// ============================================================
app.use("/users", authenticate, userRoutes);
app.use("/media", authenticate, mediaRoutes);
app.use("/support", authenticate, supportRouter);
app.use("/notifications", notificationRoutes);
app.use("/bookings", bookingRoutes);
app.use("/reviews", reviewRoutes);
app.use("/amenities", amenityRoutes);
app.use("/favorites", authenticate, favoriteRoutes);
app.use("/properties", propertyRoutes);
app.use("/sites", siteRoutes);
app.use("/comments", commentRoutes);
app.use("/forum", forumRoutes);
app.use("/free-spots", freeSpotRoutes);
app.use("/reports", reportRoutes);
app.use("/payos/webhook", payosRoutes);
app.use("/messages", authenticate, supportRouter);
app.use("/dashboard", authenticate, dashboardRoutes);
app.use("/dashboardH", authenticate, dashboardHRoutes);
app.use("/payouts", payoutRoutes);
app.use("/wallet", walletRoutes);
app.use("/mobile-selfie", mobileSelfieRoutes);
app.use("/ai", aiRoutes);

// ============================================================
// Global Error Handler
// ============================================================
app.use(errorHandler);

// ============================================================
// HTTP Server & Socket.IO
// ============================================================
const server = http.createServer(app);
initializeSocket(server);

server.listen(PORT, async () => {
  console.log(`🚀 Server listening on port ${PORT} in ${NODE_ENV} environment`);
  await connectToDatabase();
  await connectRedis();
});
