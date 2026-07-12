import type { Property } from '@/types/property-site';
import { Heart, MapPin, Star } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import RevealOnScroll from '../reveal-on-scroll';
import { StaggerContainer, StaggerItem } from '../stagger-animation';
import { Badge } from '../ui/badge';
import { Card, CardContent } from '../ui/card';

interface PopularPropertiesProps {
  properties: Property[];
}

/**
 * PopularProperties Component (Server Component)
 * Displays popular camping properties based on reviews and ratings
 */
export default function PopularProperties({
  properties,
}: PopularPropertiesProps) {
  if (!properties || properties.length === 0) {
    return null;
  }

  return (
    <section className="section-padding bg-white">
      <div className="container-padding mx-auto max-w-7xl">
        <RevealOnScroll>
          <div className="mb-12 text-center">
            <span className="mb-3 inline-block rounded-full bg-emerald-100 px-4 py-1 text-sm font-semibold text-emerald-700">
              Được yêu thích nhất
            </span>
            <h2 className="mb-4 text-4xl font-bold md:text-5xl">
              Địa Điểm Phổ Biến
            </h2>
            <p className="text-muted-foreground mx-auto max-w-2xl text-lg">
              Những địa điểm cắm trại được đánh giá cao và đặt nhiều nhất
            </p>
          </div>
        </RevealOnScroll>

        <StaggerContainer className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {properties.map(property => (
            <StaggerItem key={property._id}>
              <PropertyCard property={property} />
            </StaggerItem>
          ))}
        </StaggerContainer>

        <div className="mt-12 text-center">
          <Link
            href="/search"
            className="inline-flex items-center gap-2 rounded-full bg-emerald-600 px-8 py-3 font-semibold text-white transition-all hover:bg-emerald-700 hover:shadow-lg"
          >
            Khám phá thêm
          </Link>
        </div>
      </div>
    </section>
  );
}

function PropertyCard({ property }: { property: Property }) {
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
          <h3 className="mb-2 truncate text-xl font-bold group-hover:text-emerald-600">
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
