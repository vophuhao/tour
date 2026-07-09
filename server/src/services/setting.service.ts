import { SystemSettingModel } from "@/models";

export class SettingService {
  private static cachedSettings: any = null;

  static async getSettings(): Promise<any> {
    if (this.cachedSettings) {
      return this.cachedSettings;
    }

    let settings: any = await SystemSettingModel.findOne().lean();
    if (!settings) {
      // Create defaults in DB if not exists
      const newSettings = await SystemSettingModel.create({
        platformFeeRate: 0.05,
        cancellationPolicy: {
          diffDaysThreshold: 2,
          refundRateAboveThreshold: 0.7,
          hostRateAboveThreshold: 0.2,
          refundRateBelowThreshold: 0.5,
          hostRateBelowThreshold: 0.3,
          rejectedRequestHostRate: 0.8,
        },
      });
      settings = newSettings.toObject();
    }

    this.cachedSettings = settings;
    return this.cachedSettings;
  }

  static async updateSettings(data: any): Promise<any> {
    let settings = await SystemSettingModel.findOne();
    if (!settings) {
      settings = new SystemSettingModel();
    }

    if (data.platformFeeRate !== undefined) {
      settings.platformFeeRate = data.platformFeeRate;
    }

    if (data.cancellationPolicy) {
      settings.cancellationPolicy = {
        ...settings.cancellationPolicy,
        ...data.cancellationPolicy,
      };
    }

    if (data.popupBanner) {
      settings.popupBanner = {
        imageUrl: data.popupBanner.imageUrl,
        linkUrl: data.popupBanner.linkUrl || "",
        isActive: data.popupBanner.isActive,
      };
    }

    if (data.popupBanners) {
      settings.popupBanners = data.popupBanners.map((banner: any) => ({
        imageUrl: banner.imageUrl,
        linkUrl: banner.linkUrl || "",
        isActive: banner.isActive,
      }));
    }

    await settings.save();
    this.cachedSettings = settings.toObject();
    return this.cachedSettings;
  }

  static clearCache() {
    this.cachedSettings = null;
  }
}
