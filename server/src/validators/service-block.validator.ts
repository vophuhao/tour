import { z } from "zod";

export const createServiceBlockSchema = z
  .object({
    propertyId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid property ID"),
    serviceName: z.string().min(1).max(200),
    checkIn: z.string().refine((date) => !isNaN(Date.parse(date)), {
      message: "Invalid check-in date",
    }),
    checkOut: z.string().refine((date) => !isNaN(Date.parse(date)), {
      message: "Invalid check-out date",
    }),
    quantity: z.number().int().min(1),
    note: z.string().max(1000).optional(),
  })
  .refine(
    (data) => {
      const checkIn = new Date(data.checkIn);
      const checkOut = new Date(data.checkOut);
      return checkOut > checkIn;
    },
    {
      message: "Check-out date must be after check-in date",
      path: ["checkOut"],
    }
  );

export type CreateServiceBlockInput = z.infer<typeof createServiceBlockSchema>;
