'use client';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import type { Property } from '@/types/property-site';
import { MapPin, Star } from 'lucide-react';
import Link from 'next/link';

interface SimilarPropertiesProps {
  properties: Property[];
}

export function SimilarProperties({ properties }: SimilarPropertiesProps) {
  if (properties.length === 0) {
    return null;
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <h2 className="text-2xl font-bold">Khu đất tương tự</h2>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {properties.map(property => {
          const coverPhoto =
            property.photos?.find(p => p.isCover) || property.photos?.[0];

          return (
            <Link key={property._id} href={`/land/${property.slug}`} className="block max-w-sm w-full mx-auto">
              <Card className="h-full overflow-hidden transition-shadow hover:shadow-lg">
                {/* Property Image */}
                {coverPhoto && (
                  <div className="relative aspect-video overflow-hidden">
                    <img
                      src={coverPhoto.url}
                      alt={property.name}
                      className="h-full w-full object-cover"
                    />
                    {/* {property.stats && property.stats.totalSites && (
                      <Badge
                        className="absolute top-2 left-2"
                        variant="secondary"
                      >
                        {property.stats.totalSites} vị trí
                      </Badge>
                    )} */}
                  </div>
                )}

                <CardContent className="p-4">
                  <div className="space-y-2">
                    {/* Property Name */}
                    <h3 className="line-clamp-1 font-semibold">
                      {property.name}
                    </h3>

                    {/* Location */}
                    <div className="text-muted-foreground flex items-center gap-1 text-sm">
                      <MapPin className="h-4 w-4" />
                      <span className="line-clamp-1">
                        {property.location?.city}, {property.location?.country}
                      </span>
                    </div>

                    {/* Rating */}
                    {property.stats?.averageRating && property.stats.averageRating > 0 ? (
                      <div className="flex items-center gap-1 text-sm">
                        <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                        <span className="font-medium">
                          {property.stats.averageRating.toFixed(1)}
                        </span>
                        {property.stats.totalReviews &&
                          property.stats.totalReviews > 0 && (
                            <span className="text-muted-foreground">
                              ({property.stats.totalReviews})
                            </span>
                          )}
                      </div>
                    ) : (
                      <div className="text-xs text-muted-foreground flex items-center gap-1">
                        <Star className="h-3.5 w-3.5 text-slate-300 dark:text-slate-600" />
                        <span>Chưa có đánh giá</span>
                      </div>
                    )}

                    {/* Tagline */}
                    {property.tagline && (
                      <p className="text-muted-foreground line-clamp-2 text-xs">
                        {property.tagline}
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
