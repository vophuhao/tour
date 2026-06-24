import rateLimit from "express-rate-limit";
import { NODE_ENV } from "../constants/env";
import { redisClient } from "../config/redis";
import type { Request, Response } from "express";

// ==============================
// Helper — tắt rate limit ở test
// ==============================
const isTestEnv = NODE_ENV === "test";

// ==============================
// Custom Redis-backed store cho rate-limit
// Tương thích với express-rate-limit v7+
// ==============================
class RedisRateLimitStore {
  private prefix: string;
  private windowMs: number;

  constructor(prefix: string, windowMs: number) {
    this.prefix = prefix;
    this.windowMs = windowMs;
  }

  async increment(key: string): Promise<{ totalHits: number; resetTime: Date }> {
    const redisKey = `${this.prefix}:${key}`;
    const ttlSeconds = Math.ceil(this.windowMs / 1000);

    if (!redisClient.isOpen) {
      // Fallback: nếu Redis không available, không block request
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }

    try {
      const current = await redisClient.incr(redisKey);
      if (current === 1) {
        // Lần đầu — set TTL
        await redisClient.expire(redisKey, ttlSeconds);
      }
      const ttl = await redisClient.ttl(redisKey);
      const resetTime = new Date(Date.now() + ttl * 1000);
      return { totalHits: current, resetTime };
    } catch {
      // Redis lỗi → fallback, không block request
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }
  }

  async decrement(key: string): Promise<void> {
    if (!redisClient.isOpen) return;
    try {
      await redisClient.decr(`${this.prefix}:${key}`);
    } catch { /* ignore */ }
  }

  async resetKey(key: string): Promise<void> {
    if (!redisClient.isOpen) return;
    try {
      await redisClient.del(`${this.prefix}:${key}`);
    } catch { /* ignore */ }
  }
}

// ==============================
// Global rate limiter
// 200 requests / minute / IP
// ==============================
export const globalRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: isTestEnv ? 10000 : 200,
  message: {
    success: false,
    message: "Quá nhiều yêu cầu, vui lòng thử lại sau 1 phút.",
    code: "RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisRateLimitStore("rl:global", 60 * 1000) as any,
  skip: (req: Request) => req.ip === "::1" || req.ip === "127.0.0.1",
});

// ==============================
// Auth rate limiter (stricter)
// 15 requests / 15 minutes / IP — chống brute force
// Dùng Redis store để hoạt động đúng khi scale nhiều instances
// ==============================
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isTestEnv ? 10000 : 15,
  message: {
    success: false,
    message: "Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau 15 phút.",
    code: "AUTH_RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisRateLimitStore("rl:auth", 15 * 60 * 1000) as any,
});

// ==============================
// Upload rate limiter
// 10 uploads / minute / IP
// ==============================
export const uploadRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: isTestEnv ? 10000 : 10,
  message: {
    success: false,
    message: "Quá nhiều yêu cầu upload, vui lòng thử lại sau.",
    code: "UPLOAD_RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisRateLimitStore("rl:upload", 60 * 1000) as any,
});

// ==============================
// Webhook rate limiter
// 100 / minute — cho PayOS webhook
// ==============================
export const webhookRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: isTestEnv ? 10000 : 100,
  message: {
    success: false,
    message: "Too many webhook requests.",
    code: "WEBHOOK_RATE_LIMIT_EXCEEDED",
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisRateLimitStore("rl:webhook", 60 * 1000) as any,
});
