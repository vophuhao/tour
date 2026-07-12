'use client';

import { getPersonalizedRecommendations } from '@/lib/property-site-api';
import type { Property } from '@/types/property-site';
import { useQuery } from '@tanstack/react-query';
import { Heart, HeartIcon, MapPin, Star } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import RevealOnScroll from '../reveal-on-scroll';
import { StaggerContainer, StaggerItem } from '../stagger-animation';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';
import { Skeleton } from '../ui/skeleton';

/**
 * RecommendedProperties Component
 *
 * Displays personalized property recommendations based on user's booking history.
 * Uses TanStack Query for efficient data fetching with loading and error states.
 *
 * Features:
 * - Automatic recommendations based on location, accommodation type preferences
 * - Skeleton loading states for better UX
 * - Responsive grid layout with animations
 * - Empty state when no recommendations available
 * - Refetches on mount to ensure fresh data after login
 */
export default function RecommendedProperties() {
  const {
    data: recommendations,
    isPending,
    isError,
    error,
  } = useQuery<Property[]>({
    queryKey: ['recommendations'],
    queryFn: () => getPersonalizedRecommendations(8),
    staleTime: 1000 * 60 * 5, // 5 minutes - recommendations don't change frequently
    retry: 1, // Only retry once on failure
    refetchOnMount: 'always', // CRITICAL: Always refetch when component mounts
    refetchOnWindowFocus: false, // Don't refetch on window focus to reduce API calls
  });

  // Don't render section if error or no recommendations
  if (isError) {
    console.error('Failed to load recommendations:', error);
    return null;
  }

  if (!isPending && (!recommendations || recommendations.length === 0)) {
    return null;
  }

  return (
    <section className="pb-20 bg-white">
      <div className="container-padding mx-auto max-w-7xl">
        <RevealOnScroll>
          <div className="mb-8 text-center">
            {/* <span className="mb-3 inline-block rounded-full bg-emerald-100 px-4 py-1 text-sm font-semibold text-emerald-700">
              Dành riêng cho bạn
            </span> */}
            <div className="flex items-center justify-center gap-2">
              <h2 className="mb-0 text-1xl font-bold md:text-2xl">
                Có Thể Bạn Cũng Thích
              </h2>
              <HeartIcon className="h-6 w-6 text-rose-400" />
            </div>
          </div>
        </RevealOnScroll>

        {isPending ? (
          <RecommendationsSkeleton />
        ) : (
          <StaggerContainer className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
            {recommendations?.map(property => (
              <StaggerItem key={property._id}>
                <PropertyCard property={property} />
              </StaggerItem>
            ))}
          </StaggerContainer>
        )}
      </div>
    </section>
  );
}

/**
 * PropertyCard Component
 * Individual property card with image, ratings, location, and price
 */
function PropertyCard({ property }: { property: Property }) {
  // Handle photo object structure - photos is an array of {url, caption, isCover, order}
  const mainPhoto =
    (property.photos?.[0] as { url: string })?.url ||
    '/placeholder-property.jpg';
  const displayName = property.name || 'Unnamed Property';
  const locationStr = [property.location?.city, property.location?.state]
    .filter(Boolean)
    .join(', ');

  return (
    <Link href={`/land/${property.slug}`}>
      <Card className="group cursor-pointer overflow-hidden border-0 shadow-lg transition-all hover:-translate-y-2 hover:shadow-2xl">
        <div className="relative h-64 overflow-hidden">
          <Image
            src={mainPhoto}
            alt={displayName}
            fill
            className="object-cover transition-transform duration-500 group-hover:scale-110"
            sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 25vw"
          />
          <div className="absolute inset-0 bg-linear-to-t from-black/60 via-black/20 to-transparent" />

          {/* Favorite button */}
          <button
            className="absolute top-4 right-4 flex h-10 w-10 items-center justify-center rounded-full bg-white/90 backdrop-blur-sm transition-all hover:scale-110 hover:bg-white cursor-pointer"
            onClick={e => {
              e.preventDefault();
              // TODO: Implement favorite functionality
            }}
          >
            <Heart className="h-5 w-5 text-gray-700" />
          </button>

          {/* Rating badge */}
          {property.avgRating && property.avgRating > 0 && (
            <Badge className="absolute bottom-4 left-4 flex items-center gap-1 bg-white/95 text-gray-900 backdrop-blur-sm">
              <Star className="h-3.5 w-3.5 fill-yellow-400 text-yellow-400" />
              <span className="font-semibold">
                {property.avgRating.toFixed(1)}
              </span>
              {property.totalReviews && property.totalReviews > 0 && (
                <span className="text-muted-foreground text-xs">
                  ({property.totalReviews})
                </span>
              )}
            </Badge>
          )}
        </div>

        <CardContent className="p-6">
          <h3 className="mb-2 truncate text-xl font-bold">
            {displayName}
          </h3>

          {locationStr && (
            <p className="text-muted-foreground mb-3 flex items-center gap-1.5 text-sm">
              <MapPin className="h-4 w-4 shrink-0" />
              <span className="truncate">{locationStr}</span>
            </p>
          )}

          {/* Price */}
          {property.lowestPrice && property.lowestPrice > 0 && (
            <div className="mt-4 flex items-baseline gap-1">
              <span className="text-2xl font-bold text-emerald-600">
                {property.lowestPrice.toLocaleString('vi-VN')}đ
              </span>
              <span className="text-muted-foreground text-sm">/đêm</span>
            </div>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}

/**
 * RecommendationsSkeleton Component
 * Loading skeleton with 8 cards matching the grid layout
 */
function RecommendationsSkeleton() {
  return (
    <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
      {Array.from({ length: 8 }).map((_, index) => (
        <Card
          key={index}
          className="animate-pulse overflow-hidden border-0 shadow-lg"
        >
          <Skeleton className="h-64 w-full rounded-none" />
          <CardContent className="p-6">
            <Skeleton className="mb-2 h-6 w-3/4" />
            <Skeleton className="mb-3 h-4 w-1/2" />
            <Skeleton className="mt-4 h-8 w-24" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
