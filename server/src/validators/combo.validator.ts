import { z } from "zod";

const comboServiceValidator = z.object({
  name: z.string().min(1, "Tên dịch vụ không được để trống"),
  quantity: z.number().min(1, "Số lượng tối thiểu là 1").default(1),
});

export const createComboSchema = z.object({
  name: z.string().min(1, "Tên combo không được để trống").max(200),
  description: z.string().max(1000, "Mô tả tối đa 1000 ký tự").optional().default(""),
  propertyId: z.string().min(1, "Property ID không được để trống"),
  applicableSites: z.array(z.string()).optional().default([]),
  servicesIncluded: z.array(comboServiceValidator).min(1, "Combo phải chứa ít nhất 1 dịch vụ"),
  discountType: z.enum(["percentage", "fixed_price"]),
  discountValue: z.number().min(0, "Giá trị giảm không được nhỏ hơn 0"),
  isActive: z.boolean().optional().default(true),
});

export const updateComboSchema = createComboSchema.partial();
