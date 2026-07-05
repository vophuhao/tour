/**
 * Services barrel export
 * Centralized entry point for all API services
 *
 * Note: property.service re-exports from lib/property-site-api which already includes
 * getPropertyReviews and getSiteReviews. review.service also exports them.
 * To avoid conflicts, import reviews directly from '@/services/review.service'.
 */

export * from './auth.service';
export * from './booking.service';
export * from './favorite.service';
export * from './forum.service';
export * from './free-spot.service';
export * from './media.service';
export * from './message.service';
export * from './notification.service';
export * from './report.service';
export * from './user.service';
export * from './wallet.service';
export * from './admin.service';
export * from './campsite.service';
export * from './product.service';
export * from './tour.service';
export * from './service-package.service';

// Property/site - exported separately to avoid conflicts with review.service
export {
  searchProperties,
  getAllProperties,
  getFeaturedProperties,
  getNearbyProperties,
  getPropertyById,
  getPropertyWithSites,
  getPropertyReviewStats,
  createProperty,
  updateProperty,
  deleteProperty,
  activateProperty,
  deactivateProperty,
  getMyProperties,
  getPropertiesForAdmin,
  searchSites,
  getAllSites,
  getSitesByProperty,
  getSiteById,
  checkSiteAvailability,
  calculateSitePricing,
  createSite,
  updateSite,
  deleteSite,
  activateSite,
  deactivateSite,
  blockSiteDates,
  unblockSiteDates,
  updateSeasonalPricing,
  getAvailabilityCalendar,
  calculateOverallRating,
  formatPropertyType,
  formatLodgingType,
  formatAccommodationType,
  getPersonalizedRecommendations,
  blockPropertyDates,
  unblockPropertyDates,
  getPropertyBlockedDates,
} from '@/lib/property-site-api';

// Review functions - canonical source
export {
  createReview,
  getPropertyReviews,
  getSiteReviews,
  addHostResponse,
  getMyCampsitesReview,
} from './review.service';
