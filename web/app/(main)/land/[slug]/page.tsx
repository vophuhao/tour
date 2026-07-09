import { LocationSection } from '@/components/property/location-section';
import { NearbyAttractionsSection } from '@/components/property/nearby-attractions-section';
import { PropertyBookingCard } from '@/components/property/property-booking-card';
import { PropertyGallery } from '@/components/property/property-gallery';
import { PropertyOverview } from '@/components/property/property-overview';
import { PropertyReviewsSection } from '@/components/property/property-reviews-section';
import { PropertyRulesSection } from '@/components/property/property-rules-section';
import { SimilarProperties } from '@/components/property/similar-properties';
import { SiteAmenitiesSection } from '@/components/property/site-amenities-section';
import { SitesListSection } from '@/components/property/sites-list-section';
import { PropertyPromotions } from '@/components/property/property-promotions';
import { Separator } from '@/components/ui/separator';
import type { Property, Site } from '@/types/property-site';
import { notFound } from 'next/navigation';

interface PropertyPageProps {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{
    guests?: string;
    pets?: string;
    checkIn?: string;
    checkOut?: string;
  }>;
}

interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data: T;
}

interface PropertyWithSitesResponse {
  property: Property;
  sites: Site[];
  siteCount: number;
}

async function fetchProperty(
  slug: string,
): Promise<PropertyWithSitesResponse | null> {
  try {
    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_URL}/properties/${slug}/with-sites`,
      {
        cache: 'no-store',
      },
    );

    if (!response.ok) {
      return null;
    }

    const result: ApiResponse<PropertyWithSitesResponse> =
      await response.json();
    return result.data || null;
  } catch (error) {
    console.error('Failed to fetch property:', error);
    return null;
  }
}

async function fetchPropertyPromotions(
  propertyId: string,
): Promise<any[]> {
  try {
    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_URL}/properties/${propertyId}/promotions`,
      {
        cache: 'no-store',
      },
    );

    if (!response.ok) {
      return [];
    }

    const result = await response.json();
    return result.data || [];
  } catch (error) {
    console.error('Failed to fetch promotions:', error);
    return [];
  }
}

async function fetchSimilarProperties(
  propertyId: string,
  city: string,
): Promise<Property[]> {
  try {
    const queryParams = new URLSearchParams({
      city: city,
      limit: '4',
    });

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_URL}/properties/search?${queryParams.toString()}`,
      {
        cache: 'no-store',
      },
    );

    if (!response.ok) {
      return [];
    }

    const result = await response.json();
    const properties = result.data || [];

    // Filter out current property
    return properties.filter((p: Property) => p._id !== propertyId);
  } catch (error) {
    console.error('Failed to fetch similar properties:', error);
    return [];
  }
}

export default async function PropertyPage({
  params,
  searchParams,
}: PropertyPageProps) {
  const { slug } = await params;
  const search = await searchParams;

  const response = await fetchProperty(slug);

  if (!response) {
    notFound();
  }

  const { property, sites } = response;

  // Filter active sites only
  const activeSites = sites.filter(site => site.isActive);

  // Fetch similar properties if location available
  const similarProperties = property.location?.city
    ? await fetchSimilarProperties(property._id, property.location.city)
    : [];

  // Fetch promotions
  const promotions = await fetchPropertyPromotions(property._id);

  // Parse search params for booking
  const guests = parseInt(search.guests || '0');
  const pets = parseInt(search.pets || '0');

  return (
    <div className="bg-background container mx-auto">
      {/* Gallery */}
      <PropertyGallery
        photos={property.photos}
        sites={sites}
        name={property.name}
      />

      {/* Main Content */}
      <div className="container py-8">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
          {/* Left Column - Main Content */}
          <div className="lg:col-span-2">
            {/* Overview */}
            <PropertyOverview property={property} />

            <Separator className="my-8" />

            {/* Site Amenities - Aggregated from all sites */}
            {activeSites.length > 0 && (
              <>
                <SiteAmenitiesSection sites={activeSites} />
                <Separator className="my-8" />
              </>
            )}

            {/* Nearby Attractions */}
            {property.nearbyAttractions &&
              property.nearbyAttractions.length > 0 && (
                <>
                  <NearbyAttractionsSection
                    attractions={property.nearbyAttractions}
                  />
                  <Separator className="my-8" />
                </>
              )}

            {/* Rules & Instructions */}
            {property.rules && property.rules.length > 0 && (
              <>
                <PropertyRulesSection
                  rules={property.rules}
                  checkInInstructions={property.checkInInstructions}
                  checkOutInstructions={property.checkOutInstructions}
                />
                {/* <Separator className="my-8" /> */}
              </>
            )}
          </div>

          {/* Right Column - Quick Info / CTA */}
          <div className="lg:col-span-1">
            <div className="sticky top-24 space-y-4">
              {/* Booking Card */}
              <PropertyBookingCard
                property={property}
                sites={activeSites}
                initialGuests={guests}
                initialPets={pets}
                initialCheckIn={search.checkIn}
                initialCheckOut={search.checkOut}
              />
              <PropertyPromotions promotions={promotions} />
            </div>
          </div>
        </div>

        <Separator className="my-8" />

        {/* Available Sites - Only show if there are multiple sites */}
        {activeSites.length > 1 && (
          <>
            <SitesListSection
              sites={activeSites}
              property={property}
              propertySlug={property.slug}
              initialCheckIn={search.checkIn}
              initialCheckOut={search.checkOut}
              initialGuests={guests}
              initialPets={pets}
            />
            <Separator className="my-8" />
          </>
        )}

        {/* Reviews */}
        <PropertyReviewsSection
          propertyId={property._id}
          rating={property.rating}
        />

        <Separator className="my-8" />

        {/* Location */}
        <LocationSection location={property.location} />

        {/* Similar Properties */}
        {similarProperties.length > 0 && (
          <>
            <Separator className="my-12" />
            <SimilarProperties properties={similarProperties} />
          </>
        )}
      </div>
    </div>
  );
}
