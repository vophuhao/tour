/**
 * @deprecated
 * This file is maintained for backward compatibility.
 * All functions have been migrated to the `services/` directory.
 *
 * New code should import from the specific service:
 *   - Auth:         '@/services/auth.service'
 *   - Users:        '@/services/user.service'
 *   - Bookings:     '@/services/booking.service'
 *   - Properties:   '@/services/property.service' (or '@/lib/property-site-api')
 *   - Reviews:      '@/services/review.service'
 *   - Messages:     '@/services/message.service'
 *   - Favorites:    '@/services/favorite.service'
 *   - Media:        '@/services/media.service'
 *   - Wallet:       '@/services/wallet.service'
 *   - Admin:        '@/services/admin.service'
 */

export * from '@/services/auth.service';
export * from '@/services/user.service';
export * from '@/services/booking.service';
export * from '@/services/message.service';
export * from '@/services/favorite.service';
export * from '@/services/media.service';
export * from '@/services/wallet.service';
export * from '@/services/admin.service';
export * from '@/services/campsite.service';
export * from '@/services/product.service';
export * from '@/services/tour.service';

// Review functions
export {
  createReview,
  getPropertyReviews,
  getSiteReviews,
  addHostResponse,
  getMyCampsitesReview,
  updateReview,
} from '@/services/review.service';

// Property/Site API functions (also available from '@/lib/property-site-api')
export * from '@/lib/property-site-api';
