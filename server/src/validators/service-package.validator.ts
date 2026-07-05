import { z } from "zod";

const servicePricingValidator = z.object({
  price: z.number().min(0, "Giá dịch vụ không được nhỏ hơn 0"),
  unit: z.string().max(100).default("lượt"),
});

const serviceValidator = z.object({
  name: z.string().min(1, "Tên dịch vụ không được để trống").max(200),
  description: z.string().max(1000).optional().default(""),
  pricing: z.array(servicePricingValidator).min(1, "Dịch vụ phải có ít nhất 1 mức giá"),
});

export const createServicePackageSchema = z.object({
  name: z.string().min(1, "Tên gói dịch vụ không được để trống").max(200),
  services: z.array(serviceValidator).min(1, "Gói dịch vụ phải có ít nhất 1 dịch vụ"),
});

export const updateServicePackageSchema = createServicePackageSchema.partial();
