'use client';

import type { Site } from '@/types/property-site';
import { CheckCircle2 } from 'lucide-react';
import { useMemo } from 'react';

const categoryTranslations: Record<string, string> = {
  comfort: 'Tiện nghi',
  special: 'Đặc biệt',
  basic: 'Cơ bản',
  outdoor: 'Ngoài trời',
  safety: 'An toàn',
  kitchen: 'Ăn uống & Nhà bếp',
  bathroom: 'Vệ sinh & Phòng tắm',
  general: 'Tiện ích chung',
  activities: 'Hoạt động ngoài trời',
};

const getCategoryLabel = (category: string) => {
  const normalized = category.toLowerCase();
  return categoryTranslations[normalized] || category;
};

interface Amenity {
  _id: string;
  name: string;
  icon?: string;
  category?: string;
  description?: string;
}

interface SiteAmenitiesSectionProps {
  sites: Site[];
}

export function SiteAmenitiesSection({ sites }: SiteAmenitiesSectionProps) {
  // Aggregate all unique amenities from all sites
  const allAmenities = useMemo(() => {
    const amenitiesMap = new Map<string, Amenity>();

    sites.forEach(site => {
      if (site.amenities && Array.isArray(site.amenities)) {
        site.amenities.forEach(amenity => {
          // Handle both string IDs and populated Amenity objects
          if (typeof amenity === 'object' && '_id' in amenity) {
            amenitiesMap.set(amenity._id, amenity as Amenity);
          }
        });
      }
    });

    return Array.from(amenitiesMap.values());
  }, [sites]);

  // Group amenities by category
  const groupedAmenities = useMemo(() => {
    const groups: Record<string, Amenity[]> = {};

    allAmenities.forEach(amenity => {
      const category = amenity.category || 'Khác';
      if (!groups[category]) {
        groups[category] = [];
      }
      groups[category].push(amenity);
    });

    return groups;
  }, [allAmenities]);

  if (allAmenities.length === 0) {
    return null;
  }

  return (
    <div className="space-y-6" id="amenities">
      <div>
        <h2 className="text-2xl font-bold">Tiện nghi</h2>
        <p className="text-muted-foreground mt-1 text-sm">
          Các tiện nghi có sẵn tại các vị trí cắm trại
        </p>
      </div>

      <div className="space-y-6">
        {Object.entries(groupedAmenities).map(([category, amenities]) => (
          <div key={category}>
            <h3 className="mb-3 font-semibold capitalize">{getCategoryLabel(category)}</h3>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {amenities.map(amenity => (
                <div
                  key={amenity._id}
                  className="flex items-start gap-3 rounded-lg border p-3"
                >
                  {amenity.icon ? (
                    <span className="text-2xl">{amenity.icon}</span>
                  ) : (
                    <CheckCircle2 className="h-5 w-5 text-green-600" />
                  )}
                  <div className="flex-1">
                    <p className="text-sm font-medium">{amenity.name}</p>
                    {amenity.description && (
                      <p className="text-muted-foreground text-xs">
                        {amenity.description}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
