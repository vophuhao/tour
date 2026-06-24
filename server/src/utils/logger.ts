import { NODE_ENV } from "../constants";

export const logger = {
  info(message: string, meta?: any) {
    this.log("info", message, meta);
  },
  warn(message: string, meta?: any) {
    this.log("warn", message, meta);
  },
  error(message: string, error?: any, meta?: any) {
    const errorMeta = error instanceof Error ? { error: error.message, stack: error.stack } : { detail: error };
    this.log("error", message, { ...meta, ...errorMeta });
  },
  debug(message: string, meta?: any) {
    if (NODE_ENV !== "production") {
      this.log("debug", message, meta);
    }
  },
  log(level: "info" | "warn" | "error" | "debug", message: string, meta?: any) {
    const timestamp = new Date().toISOString();
    const logData = {
      timestamp,
      level,
      message,
      ...(meta ? { meta } : {})
    };
    if (NODE_ENV === "production") {
      console.log(JSON.stringify(logData));
    } else {
      const color = this.getColor(level);
      const reset = "\x1b[0m";
      const metaString = meta ? ` | Meta: ${JSON.stringify(meta)}` : "";
      console.log(`[${timestamp}] ${color}${level.toUpperCase()}${reset}: ${message}${metaString}`);
    }
  },
  getColor(level: string): string {
    switch (level) {
      case "info": return "\x1b[32m";
      case "warn": return "\x1b[33m";
      case "error": return "\x1b[31m";
      case "debug": return "\x1b[36m";
      default: return "\x1b[0m";
    }
  }
};
