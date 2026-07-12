'use client';

import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import dynamic from 'next/dynamic';
import Image from 'next/image';
import Link from 'next/link';
import { useEffect, useState } from 'react';

// Lazy load map component to avoid SSR issues with mapbox-gl
const CampsiteMap = dynamic(
  () =>
    import('@/components/search/campsite-map').then(mod => ({
      default: mod.CampsiteMap,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-full w-full items-center justify-center bg-gray-100">
        <div className="text-center">
          <Skeleton className="mx-auto mb-4 h-12 w-12 rounded-full" />
          <p className="text-sm text-gray-500">Đang tải bản đồ...</p>
        </div>
      </div>
    ),
  },
);

interface CampsiteListProps {
  initialCampsites: Campsite[];
  totalResults?: number;
  searchCoordinates?: { lat: number; lng: number } | null;
}

export function CampsiteList({
  initialCampsites,
  totalResults = 0,
  searchCoordinates,
}: CampsiteListProps) {
  const [selectedCampsite, setSelectedCampsite] = useState<Campsite | null>(
    null,
  );
  const [hoveredCampsite, setHoveredCampsite] = useState<Campsite | null>(null);
  const [mapKey, setMapKey] = useState(0);

  // Force remount map when campsites change significantly
  useEffect(() => {
    setMapKey(prev => prev + 1);
  }, [initialCampsites.length]);

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);
  };

  return (
    <div className="flex h-[calc(100vh-64px)] gap-0">
      {/* Campsites Grid - 3 columns - Scrollable */}
      <div className="scrollbar-hide flex-1 overflow-y-auto px-6">
        {/* Results Count */}
        {totalResults > 0 && (
          <div className="pt-4">
            <p className="text-sm text-gray-700">
              <span className="font-semibold">{totalResults}</span> kết quả
            </p>
          </div>
        )}
        <div className="grid grid-cols-1 gap-4 py-6 md:grid-cols-2 lg:grid-cols-3">
          {initialCampsites.map(campsite => (
            <Card
              key={campsite._id}
              className={`cursor-pointer overflow-hidden border-none shadow-md transition-all hover:shadow-lg ${
                selectedCampsite?._id === campsite._id
                  ? 'ring-primary ring-2'
                  : ''
              }`}
              onClick={() => setSelectedCampsite(campsite)}
              onMouseEnter={() => setHoveredCampsite(campsite)}
              onMouseLeave={() => setHoveredCampsite(null)}
            >
              <Link href={`/land/${campsite.slug}`} className="block h-full">
                <div className="relative h-48 w-full">
                  <Image
                    src={campsite.images[0] || '/placeholder-campsite.jpg'}
                    alt={campsite.name}
                    fill
                    className="object-cover transition-transform hover:scale-105"
                  />
                  {campsite.rating && (
                    <div className="absolute top-3 right-3 rounded-full bg-white px-2 py-1 text-xs font-semibold shadow-md">
                      ⭐ {campsite.rating.average}
                    </div>
                  )}
                </div>

                <div className="space-y-2 p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <h3 className="line-clamp-1 font-semibold">
                        {campsite.name}
                      </h3>
                      <p className="text-muted-foreground text-sm">
                        {campsite.location.city}, {campsite.location.state}
                      </p>
                    </div>
                    <Badge variant="outline" className="shrink-0">
                      {campsite.propertyType}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-lg font-bold">
                        {formatPrice(campsite.pricing.basePrice)}
                      </span>
                      <span className="text-muted-foreground text-sm">
                        {' '}
                        / đêm
                      </span>
                    </div>
                    <p className="text-muted-foreground text-xs">
                      Tối đa {campsite.capacity.maxGuests} khách
                    </p>
                  </div>
                </div>
              </Link>
            </Card>
          ))}
        </div>

        {initialCampsites.length === 0 && (
          <div className="py-12 text-center">
            <p className="text-muted-foreground">
              Không tìm thấy campsite phù hợp
            </p>
          </div>
        )}
      </div>

      {/* Compact Map Sidebar */}
      <div className="hidden lg:block lg:w-[400px] xl:w-[500px]">
        <div className="sticky top-0 h-[calc(100vh-64px)] overflow-hidden">
          <CampsiteMap
            key={mapKey}
            campsites={initialCampsites}
            selectedCampsite={selectedCampsite}
            hoveredCampsite={hoveredCampsite}
            searchCoordinates={searchCoordinates}
            onCampsiteSelect={setSelectedCampsite}
          />
        </div>
      </div>
    </div>
  );
}
