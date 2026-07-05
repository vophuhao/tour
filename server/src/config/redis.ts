import { REDIS_PASSWORD, REDIS_URL } from "../constants/env";
import { createClient } from "redis";

// Create Redis client
const redisClient = createClient({
  url: REDIS_URL,
  ...(REDIS_PASSWORD ? { password: REDIS_PASSWORD } : {}),
});
// Error handling
redisClient.on("error", (err) => {
  console.error("❌ Redis Client Error:", err);
});

redisClient.on("connect", () => {
  console.log("✅ Redis Client Connected");
});

// Connect to Redis
const connectRedis = async () => {
  if (!redisClient.isOpen) {
    await redisClient.connect();
  }
};

// Acquire a distributed lock using Redis
const acquireLock = async (key: string, ttlMs: number): Promise<string | null> => {
  if (!redisClient.isOpen) return null;
  const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
  try {
    const result = await redisClient.set(key, token, {
      NX: true,
      PX: ttlMs,
    });
    return result === "OK" ? token : null;
  } catch (err) {
    console.error("❌ Redis acquireLock error:", err);
    return null;
  }
};

// Release a distributed lock using Redis (safely via Lua script)
const releaseLock = async (key: string, token: string): Promise<boolean> => {
  if (!redisClient.isOpen) return false;
  // Lua script to make release operation atomic
  const luaScript = `
    if redis.call("get", KEYS[1]) == ARGV[1] then
      return redis.call("del", KEYS[1])
    else
      return 0
    end
  `;
  try {
    const result = await redisClient.eval(luaScript, {
      keys: [key],
      arguments: [token],
    });
    return Number(result) === 1;
  } catch (err) {
    console.error("❌ Redis releaseLock error:", err);
    return false;
  }
};

export { connectRedis, redisClient, acquireLock, releaseLock };
