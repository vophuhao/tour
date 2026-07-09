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
    if (data.minGuests !== undefined) promoCode.minGuests = data.minGuests;
    if (data.minBookingQuantity !== undefined) promoCode.minBookingQuantity = data.minBookingQuantity;
    if (data.minNights !== undefined) promoCode.minNights = data.minNights;

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
      guests: z.number().optional(),
      bookingQuantity: z.number().optional(),
      nights: z.number().optional(),
      checkIn: z.string().optional(),
      checkOut: z.string().optional(),
    });

    const { code, propertyId, subtotal, guests, bookingQuantity, nights, checkIn, checkOut } = validator.parse(req.body);

    const promoCode = await PromoCodeModel.findOne({ code, isActive: true });
    appAssert(promoCode, ErrorFactory.badRequest("Mã giảm giá không hợp lệ hoặc đã hết hạn"));

    if (checkIn && checkOut) {
      const checkInDate = new Date(checkIn);
      checkInDate.setHours(0, 0, 0, 0);
      const checkOutDate = new Date(checkOut);
      checkOutDate.setHours(0, 0, 0, 0);
      const promoStart = new Date(promoCode.startDate);
      promoStart.setHours(0, 0, 0, 0);
      const promoEnd = new Date(promoCode.endDate);
      promoEnd.setHours(0, 0, 0, 0);

      console.log("VALIDATE PROMO CODE [Stay Dates Check]:", {
        checkIn,
        checkOut,
        checkInParsed: checkInDate.toISOString(),
        checkOutParsed: checkOutDate.toISOString(),
        promoStartParsed: promoStart.toISOString(),
        promoEndParsed: promoEnd.toISOString(),
        isCheckInValid: checkInDate >= promoStart,
        isCheckOutValid: checkOutDate <= promoEnd,
        finalResult: checkInDate >= promoStart && checkOutDate <= promoEnd
      });

      appAssert(
        checkInDate >= promoStart && checkOutDate <= promoEnd,
        ErrorFactory.badRequest(`Mã giảm giá này chỉ áp dụng cho thời gian đi từ ${promoStart.toLocaleDateString('vi-VN')} đến ${promoEnd.toLocaleDateString('vi-VN')}`)
      );
    } else {
      const now = new Date();
      console.log("VALIDATE PROMO CODE [No Stay Dates - Fallback to Now]:", {
        now: now.toISOString(),
        promoStart: promoCode.startDate.toISOString(),
        promoEnd: promoCode.endDate.toISOString(),
        finalResult: now >= promoCode.startDate && now <= promoCode.endDate
      });
      appAssert(
        now >= promoCode.startDate && now <= promoCode.endDate,
        ErrorFactory.badRequest("Mã giảm giá chưa đến hạn sử dụng hoặc đã hết hạn")
      );
    }

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

    if (guests !== undefined && promoCode.minGuests !== undefined) {
      appAssert(
        guests >= promoCode.minGuests,
        ErrorFactory.badRequest(`Mã giảm giá này chỉ áp dụng cho nhóm từ ${promoCode.minGuests} khách trở lên`)
      );
    }

    if (bookingQuantity !== undefined && promoCode.minBookingQuantity !== undefined) {
      appAssert(
        bookingQuantity >= promoCode.minBookingQuantity,
        ErrorFactory.badRequest(`Mã giảm giá này chỉ áp dụng khi đặt từ ${promoCode.minBookingQuantity} lều/chỗ trở lên`)
      );
    }

    if (nights !== undefined && promoCode.minNights !== undefined) {
      appAssert(
        nights >= promoCode.minNights,
        ErrorFactory.badRequest(`Mã giảm giá này chỉ áp dụng cho đặt phòng từ ${promoCode.minNights} đêm trở lên`)
      );
    }

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

  /**
   * Create an admin promo code (Global scope)
   * @route POST /api/admin/promotions
   */
  createAdminPromoCode = catchErrors(async (req, res) => {
    const data = createPromoCodeSchema.parse(req.body);

    const promoCode = await PromoCodeModel.create({
      ...data,
      scope: "global",
      host: undefined,
    });

    return ResponseUtil.created(res, promoCode, "Tạo mã giảm giá Admin thành công");
  });

  /**
   * Get all promo codes for Admin management
   * @route GET /api/admin/promotions
   */
  getAllPromoCodesForAdmin = catchErrors(async (req, res) => {
    const promoCodes = await PromoCodeModel.find()
      .populate("host", "username email")
      .sort({ createdAt: -1 });

    return ResponseUtil.success(res, promoCodes, "Lấy danh sách mã giảm giá thành công");
  });

  /**
   * Update an admin global promo code
   * @route PATCH /api/admin/promotions/:id
   */
  updateAdminPromoCode = catchErrors(async (req, res) => {
    const promoId = mongoIdSchema.parse(req.params.id);
    const data = updatePromoCodeSchema.parse(req.body);

    const promoCode = await PromoCodeModel.findById(promoId);
    appAssert(promoCode, ErrorFactory.resourceNotFound("Mã giảm giá không tồn tại"));

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
    if (data.minGuests !== undefined) promoCode.minGuests = data.minGuests;
    if (data.minBookingQuantity !== undefined) promoCode.minBookingQuantity = data.minBookingQuantity;
    if (data.minNights !== undefined) promoCode.minNights = data.minNights;

    await promoCode.save();

    return ResponseUtil.success(res, promoCode, "Cập nhật mã giảm giá Admin thành công");
  });

  /**
   * Delete any promo code by admin
   * @route DELETE /api/admin/promotions/:id
   */
  deleteAdminPromoCode = catchErrors(async (req, res) => {
    const promoId = mongoIdSchema.parse(req.params.id);

    const promoCode = await PromoCodeModel.findByIdAndDelete(promoId);
    appAssert(promoCode, ErrorFactory.resourceNotFound("Mã giảm giá không tồn tại"));

    return ResponseUtil.success(res, null, "Xóa mã giảm giá thành công");
  });
}
