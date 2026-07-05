import { catchErrors } from "@/errors";
import { SettingService } from "@/services/setting.service";
import { ResponseUtil } from "../utils";
import { z } from "zod";

const updateSettingsSchema = z.object({
  platformFeeRate: z.number().min(0).max(1).optional(),
  cancellationPolicy: z.object({
    diffDaysThreshold: z.number().min(0).optional(),
    refundRateAboveThreshold: z.number().min(0).max(1).optional(),
    hostRateAboveThreshold: z.number().min(0).max(1).optional(),
    refundRateBelowThreshold: z.number().min(0).max(1).optional(),
    hostRateBelowThreshold: z.number().min(0).max(1).optional(),
    rejectedRequestHostRate: z.number().min(0).max(1).optional(),
  }).optional(),
});

export default class SettingController {
  /**
   * Get system settings
   * @route GET /api/admin/settings
   */
  getSettings = catchErrors(async (req, res) => {
    const settings = await SettingService.getSettings();
    return ResponseUtil.success(res, settings, "Lấy cấu hình hệ thống thành công");
  });

  /**
   * Update system settings
   * @route PUT /api/admin/settings
   */
  updateSettings = catchErrors(async (req, res) => {
    const data = updateSettingsSchema.parse(req.body);
    const settings = await SettingService.updateSettings(data);
    return ResponseUtil.success(res, settings, "Cập nhật cấu hình hệ thống thành công");
  });
}
