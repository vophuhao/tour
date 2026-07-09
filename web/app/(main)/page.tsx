import AccommodationTypes from '@/components/home/accommodation-types';
import ConditionalRecommendations from '@/components/home/conditional-recommendations';
import HeroSection from '@/components/home/hero-section';
import MarketingFeatures from '@/components/home/marketing-features';
import PopularProperties from '@/components/home/popular-properties';
import RecentReviews from '@/components/home/recent-reviews';
import TopDestinations from '@/components/home/top-destinations';
import PromoPopupBanner from '@/components/modals/promo-popup';
import {
  getFeaturedProperties,
  getRecentReviews,
  getTopDestinations,
} from '@/lib/home-api';

/**
 * HomePage - Server Component
 * Fetches all data server-side for better performance and SEO
 */
export default async function HomePage() {
  // Fetch all data in parallel for optimal performance
  const [featuredProperties, topDestinations, recentReviews] =
    await Promise.all([
      getFeaturedProperties(8),
      getTopDestinations(6),
      getRecentReviews(6),
    ]);

  return (
    <div className="min-h-screen">
      <HeroSection />

      {/* High-converting marketing & value props section */}
      <MarketingFeatures />

      {/* Personalized Recommendations - Client component for auth check */}
      <ConditionalRecommendations />

      {/* Popular/Featured Properties - Real data */}
      <PopularProperties properties={featuredProperties} />

      {/* Accommodation Types - Tent/RV/Glamping */}
      <AccommodationTypes />

      {/* Top Destinations - Real data grouped by state with geospatial query */}
      <TopDestinations destinations={topDestinations} />

      {/* Featured Products - E-commerce section */}
      {/* <FeaturedProducts /> */}

      {/* Recent Reviews - Real customer testimonials */}
      <RecentReviews reviews={recentReviews} />

      {/* Banner Popup Quảng Cáo */}
      <PromoPopupBanner />
    </div>
  );
}
