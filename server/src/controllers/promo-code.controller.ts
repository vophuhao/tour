import { catchErrors, ErrorFactory } from "@/errors";
import { PromoCodeModel } from "@/models";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  createPromoCodeSchema,
  updatePromoCodeSchema,
} from "@/validators/promo-code.validator";
import appAssert from "../utils/app-assert";
import { z } from "zod";
import { Types } from "mongoose";

export default class PromoCodeController {
  /**
   * Create a promo code (Host scope)
   * @route POST /api/host/promotions
   */
  createPromoCode = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const data = createPromoCodeSchema.parse(req.body);

    // Enforce host scope if created by Host
    const promoCode = await PromoCodeModel.create({
      ...data,
      scope: "host",
      host: hostId,
    });

    return ResponseUtil.created(res, promoCode, "Tạo mã giảm giá thành công");
  });

  /**
   * Get all host promo codes
   * @route GET /api/host/promotions
   */
  getMyPromoCodes = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const promoCodes = await PromoCodeModel.find({ host: hostId }).sort({ createdAt: -1 });

    return ResponseUtil.success(res, promoCodes, "Lấy danh sách mã giảm giá thành công");
  });

  /**
   * Update promo code details
   * @route PATCH /api/host/promotions/:id
   */
  updatePromoCode = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const promoId = mongoIdSchema.parse(req.params.id);
    const data = updatePromoCodeSchema.parse(req.body);

    const promoCode = await PromoCodeModel.findOne({ _id: promoId, host: hostId });
    appAssert(promoCode, ErrorFactory.resourceNotFound("Mã giảm giá không tồn tại hoặc bạn không có quyền"));

    if (data.description !== undefined) promoCode.description = data.description;
    if (data.discountType) promoCode.discountType = data.discountType;
    if (data.discountValue !== undefined) promoCode.discountValue = data.discountValue;
    if (data.maxDiscountAmount !== undefined) promoCode.maxDiscountAmount = data.maxDiscountAmount;
    if (data.minSubtotal !== undefined) promoCode.minSubtotal = data.minSubtotal;
    if (data.applicableProperties) {
      promoCode.applicableProperties = data.applicableProperties.map(
        (id) => new Types.ObjectId(mongoIdSchema.parse(id))
      );
    }
    if (data.startDate) promoCode.startDate = data.startDate;
    if (data.endDate) promoCode.endDate = data.endDate;
    if (data.usageLimit !== undefined) promoCode.usageLimit = data.usageLimit;
    if (data.isActive !== undefined) promoCode.isActive = data.isActive;

    await promoCode.save();

    return ResponseUtil.success(res, promoCode, "Cập nhật mã giảm giá thành công");
  });

  /**
   * Delete a promo code
   * @route DELETE /api/host/promotions/:id
   */
  deletePromoCode = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const promoId = mongoIdSchema.parse(req.params.id);

    const promoCode = await PromoCodeModel.findOneAndDelete({ _id: promoId, host: hostId });
    appAssert(promoCode, ErrorFactory.resourceNotFound("Mã giảm giá không tồn tại hoặc bạn không có quyền"));

    return ResponseUtil.success(res, null, "Xóa mã giảm giá thành công");
  });

  /**
   * Validate a promo code (Public/Camper)
   * @route POST /api/bookings/validate-promo
   */
  validatePromoCode = catchErrors(async (req, res) => {
    const validator = z.object({
      code: z.string().trim().toUpperCase(),
      propertyId: z.string().min(1, "Thiếu propertyId"),
      subtotal: z.number().min(0, "Tổng số tiền không hợp lệ"),
    });

    const { code, propertyId, subtotal } = validator.parse(req.body);

    const promoCode = await PromoCodeModel.findOne({ code, isActive: true });
    appAssert(promoCode, ErrorFactory.badRequest("Mã giảm giá không hợp lệ hoặc đã hết hạn"));

    const now = new Date();
    appAssert(
      now >= promoCode.startDate && now <= promoCode.endDate,
      ErrorFactory.badRequest("Mã giảm giá chưa đến hạn sử dụng hoặc đã hết hạn")
    );

    if (promoCode.usageLimit !== undefined) {
      appAssert(
        promoCode.usageCount < promoCode.usageLimit,
        ErrorFactory.badRequest("Mã giảm giá đã đạt giới hạn lượt sử dụng")
      );
    }

    appAssert(
      subtotal >= (promoCode.minSubtotal || 0),
      ErrorFactory.badRequest(`Đơn hàng tối thiểu phải đạt ${promoCode.minSubtotal?.toLocaleString()} đ để áp dụng mã này`)
    );

    if (promoCode.scope === "host") {
      // Check if property is within host applicable properties
      if (promoCode.applicableProperties && promoCode.applicableProperties.length > 0) {
        const isApplicable = promoCode.applicableProperties.some(
          (id) => id.toString() === propertyId
        );
        appAssert(
          isApplicable,
          ErrorFactory.badRequest("Mã giảm giá này không áp dụng cho khu cắm trại hiện tại")
        );
      }
    }

    // Calculate tentative discount
    let discountAmount = 0;
    if (promoCode.discountType === "percentage") {
      discountAmount = Math.round((subtotal * promoCode.discountValue) / 100);
      if (promoCode.maxDiscountAmount && discountAmount > promoCode.maxDiscountAmount) {
        discountAmount = promoCode.maxDiscountAmount;
      }
    } else {
      discountAmount = promoCode.discountValue;
    }

    // Make sure we don't discount more than the subtotal
    discountAmount = Math.min(discountAmount, subtotal);

    return ResponseUtil.success(
      res,
      {
        id: promoCode._id,
        code: promoCode.code,
        discountType: promoCode.discountType,
        discountValue: promoCode.discountValue,
        discountAmount,
      },
      "Mã giảm giá hợp lệ"
    );
  });
}
