/**
 * Central exports for all models.
 * This provides a clean import interface for services
 */
export { default as SessionModel, type SessionDocument } from "./session.model";

export { default as UserModel, type UserDocument } from "./user.model";

// Hipcamp-style models
export { AmenityModel, type AmenityDocument } from "./amenity.model";
export {
  AvailabilityModel,
  FavoriteModel,
  PropertyAvailabilityModel,
  type AvailabilityDocument,
  type FavoriteDocument,
  type PropertyAvailabilityDocument,
} from "./availability.model";
export { BookingModel, type BookingDocument } from "./booking.model";
export { PropertyModel, type PropertyDocument } from "./property.model";
export { ReviewModel, type ReviewDocument } from "./review.model";
export { SiteModel, type SiteDocument } from "./site.model";
export { SystemSettingModel, type ISystemSetting } from "./system-setting.model";
export { ServicePackageModel, type ServicePackageDocument, type IService } from "./service-package.model";

export { PromoCodeModel, type PromoCodeDocument } from "./promo-code.model";
export { ComboModel, type ComboDocument } from "./combo.model";
export { default as ServiceBlockModel, type ServiceBlockDocument } from "./service-block.model";

