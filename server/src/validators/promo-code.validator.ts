import { z } from "zod";

export const createPromoCodeSchema = z.object({
  code: z
    .string()
    .min(3, "Mã giảm giá phải có ít nhất 3 ký tự")
    .max(30, "Mã giảm giá tối đa 30 ký tự")
    .regex(/^[A-Z0-9_-]+$/, "Mã giảm giá chỉ chứa ký tự in hoa, số, gạch ngang và gạch dưới"),
  description: z.string().max(500, "Mô tả tối đa 500 ký tự").optional().default(""),
  scope: z.enum(["global", "host"]).default("host"),
  discountType: z.enum(["percentage", "flat"]),
  discountValue: z.number().min(0, "Giá trị chiết khấu không được nhỏ hơn 0"),
  maxDiscountAmount: z.number().min(0).optional(),
  minSubtotal: z.number().min(0).optional().default(0),
  applicableProperties: z.array(z.string()).optional().default([]),
  startDate: z.coerce.date({ invalid_type_error: "Ngày bắt đầu không hợp lệ" }),
  endDate: z.coerce.date({ invalid_type_error: "Ngày kết thúc không hợp lệ" }),
  usageLimit: z.number().min(1).optional(),
  isActive: z.boolean().optional().default(true),
  minGuests: z.number().min(1).optional(),
  minBookingQuantity: z.number().min(1).optional(),
  minNights: z.number().min(1).optional(),
});

export const updatePromoCodeSchema = createPromoCodeSchema.partial().omit({ code: true });
