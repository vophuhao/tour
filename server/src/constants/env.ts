const getEnv = (key: string, defaultValue?: string): string => {
  const value = process.env[key] || defaultValue;

  if (value === undefined) {
    throw Error(`Missing String environment variable for ${key}`);
  }

  return value;
};

export const NODE_ENV = getEnv("NODE_ENV", "development");
export const PORT = getEnv("PORT", "5555");
export const MONGO_URI = getEnv("MONGO_URI");
export const APP_ORIGIN = getEnv("APP_ORIGIN");
export const JWT_SECRET = getEnv("JWT_SECRET");
export const JWT_REFRESH_SECRET = getEnv("JWT_REFRESH_SECRET");
export const EMAIL_SENDER = getEnv("EMAIL_SENDER");
export const EMAIL_PASS = getEnv("EMAIL_PASS");
export const EMAIL_PORT = getEnv("EMAIL_PORT");
export const GOOGLE_CLIENT_ID = getEnv("GOOGLE_CLIENT_ID");
export const CLOUDINARY_CLOUD_NAME = getEnv("CLOUDINARY_CLOUD_NAME");
export const CLOUDINARY_API_KEY = getEnv("CLOUDINARY_API_KEY");
export const CLOUDINARY_API_SECRET = getEnv("CLOUDINARY_API_SECRET");
export const CLARIFAI_API_KEY = getEnv("CLARIFAI_API_KEY");
export const REDIS_URL = getEnv("REDIS_URL");
export const REDIS_PASSWORD = process.env.REDIS_PASSWORD || "";
export const PAYOS_CHECKSUM_KEY = getEnv("PAYOS_CHECKSUM_KEY");
export const PAYOS_API_KEY = getEnv("PAYOS_API_KEY");
export const PAYOS_CLIENT_ID = getEnv("PAYOS_CLIENT_ID");
export const CLIENT_URL = getEnv("CLIENT_URL");