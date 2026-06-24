'use client';

import { Button } from '@/components/ui/button';
import type { Property, Site } from '@/types/property-site';
import { Caravan, Home, Tent, TreePine } from 'lucide-react';
import 'mapbox-gl/dist/mapbox-gl.css';
import Image from 'next/image';
import { useCallback, useMemo, useRef, useState } from 'react';
import Map, { MapRef, Marker, NavigationControl, Popup } from 'react-map-gl';
import { toast } from 'sonner';

// Helper to extract lat/lng from Site siteLocation (GeoJSON format)
const getSiteCoordinates = (
  siteLocation:
    | { coordinates?: { type: 'Point'; coordinates: [number, number] } }
    | undefined,
): { lat: number; lng: number } | null => {
  if (
    siteLocation?.coordinates?.type === 'Point' &&
    Array.isArray(siteLocation.coordinates.coordinates)
  ) {
    return {
      lng: siteLocation.coordinates.coordinates[0],
      lat: siteLocation.coordinates.coordinates[1],
    };
  }
  return null;
};

// Helper to extract lat/lng from Property GeoJSON coordinates
const getPropertyCoordinates = (
  coords: Property['location']['coordinates'],
): { lat: number; lng: number } | null => {
  // GeoJSON format: { type: 'Point', coordinates: [lng, lat] }
  if (coords?.type === 'Point' && Array.isArray(coords.coordinates)) {
    return { lng: coords.coordinates[0], lat: coords.coordinates[1] };
  }
  return null;
};

// Helper to get icon for accommodation type
const getAccommodationIcon = (type: string) => {
  switch (type) {
    case 'tent':
      return <Tent className="h-3 w-3" />;
    case 'rv':
    case 'vehicle':
      return <Caravan className="h-3 w-3" />;
    case 'cabin':
      return <Home className="h-3 w-3" />;
    case 'glamping':
    case 'yurt':
    case 'treehouse':
      return <TreePine className="h-3 w-3" />;
    default:
      return <Tent className="h-3 w-3" />;
  }
};

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

interface SiteMapProps {
  sites: Site[];
  property: Property;
  selectedSite: Site | null;
  hoveredSite: Site | null;
  onSiteSelect?: (site: Site | null) => void;
}

export function SiteMap({
  sites,
  property,
  selectedSite,
  hoveredSite,
  onSiteSelect,
}: SiteMapProps) {
  const mapRef = useRef<MapRef>(null);
  const propertyCenter = getPropertyCoordinates(property.location.coordinates);

  const [viewState, setViewState] = useState({
    longitude: propertyCenter?.lng || 108.2022,
    latitude: propertyCenter?.lat || 16.0544,
    zoom: 15,
  });
  const [popupInfo, setPopupInfo] = useState<Site | null>(null);
  const [mapLoaded, setMapLoaded] = useState(false);

  const handleMarkerClick = useCallback(
    (site: Site) => {
      // Guard: don't execute if map not loaded
      if (!mapLoaded) return;

      setPopupInfo(site);
      onSiteSelect?.(site);

      const coords = getSiteCoordinates(site.siteLocation);
      if (coords && mapRef.current) {
        try {
          mapRef.current.flyTo({
            center: [coords.lng, coords.lat],
            zoom: 16,
            duration: 1000,
          });
        } catch (error) {
          console.error('Error flying to marker:', error);
        }
      }
    },
    [onSiteSelect, mapLoaded],
  );

  const formatPrice = useCallback((price: number) => {
    // Format to thousands (K) or millions (tr)
    if (price >= 1000000) {
      return `${Math.round(price / 1000000)}tr`;
    } else if (price >= 1000) {
      return `${Math.round(price / 1000)}k`;
    }
    return `${price}`;
  }, []);

  const getCoverPhoto = useCallback((site: Site) => {
    const coverPhoto = site.photos?.find(p => p.isCover);
    if (coverPhoto) return coverPhoto.url;
    return site.photos?.[0]?.url || '/placeholder-campsite.jpg';
  }, []);

  // Memoize markers to prevent unnecessary rerenders
  const markers = useMemo(() => {
    // Don't render markers until map is fully loaded
    if (!mapLoaded) return null;

    // Safely create markers with error boundary
    try {
      return sites.map(site => {
        const coords = getSiteCoordinates(site.siteLocation);
        if (!coords) return null;

        const isSelected = selectedSite?._id === site._id;
        const isHovered = hoveredSite?._id === site._id;
        const isActive = isSelected || isHovered;

        // Check if this is an undesignated site (maxConcurrentBookings > 1)
        const maxConcurrentBookings = site.capacity.maxConcurrentBookings ?? 1;
        const isUndesignated = maxConcurrentBookings > 1;

        return (
          <Marker
            key={site._id}
            longitude={coords.lng}
            latitude={coords.lat}
            anchor="bottom"
            onClick={e => {
              e.originalEvent.stopPropagation();
              handleMarkerClick(site);
            }}
          >
            <div
              className={`group relative cursor-pointer transition-all duration-200 ${
                isActive ? 'z-50 scale-125' : 'hover:scale-110'
              }`}
            >
              {/* Price Badge with Sites Info */}
              <div
                className={`flex flex-col items-center gap-0.5 rounded-full border px-3 py-1.5 text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? 'border-black bg-black text-white shadow-md'
                    : 'border-gray-300 bg-white text-gray-900 hover:border-black hover:bg-black hover:text-white hover:shadow-md'
                }`}
              >
                <div className="flex items-center gap-1">
                  {getAccommodationIcon(site.accommodationType)}
                  <span>{formatPrice(site.pricing.basePrice)}</span>
                </div>
                {isUndesignated && (
                  <span className="text-[10px] font-normal opacity-80">
                    Còn {maxConcurrentBookings} chỗ
                  </span>
                )}
              </div>
            </div>
          </Marker>
        );
      });
    } catch (error) {
      console.error('Error rendering markers:', error);
      return null;
    }
  }, [
    mapLoaded,
    sites,
    selectedSite,
    hoveredSite,
    handleMarkerClick,
    formatPrice,
  ]);

  if (!MAPBOX_TOKEN) {
    return (
      <div className="bg-muted flex h-full items-center justify-center">
        <p className="text-muted-foreground">
          Map unavailable. Please add MAPBOX_TOKEN to environment variables.
        </p>
      </div>
    );
  }

  return (
    <div translate="no" className="w-full h-full notranslate">
      <Map
        key={property._id}
        id="site-map"
        ref={mapRef}
        {...viewState}
        onMove={evt => setViewState(evt.viewState)}
        onLoad={() => {
          // Small delay to ensure DOM is fully ready before rendering markers
          setTimeout(() => {
            setMapLoaded(true);
          }, 100);
        }}
        onRemove={() => {
          // Map is being removed from DOM - clean up state
          setMapLoaded(false);
          setPopupInfo(null);
        }}
        onError={e => {
          console.error('Map error:', e);
        }}
        mapStyle="mapbox://styles/mapbox/outdoors-v12"
        mapboxAccessToken={MAPBOX_TOKEN}
        style={{ width: '100%', height: '100%' }}
        minPitch={0}
        maxPitch={0}
        projection={{ name: 'mercator' }}
        dragRotate={false}
        touchPitch={false}
      >
        {/* Navigation Controls */}
        <NavigationControl
          position="top-right"
          showCompass={true}
          showZoom={true}
        />

        {/* Site Markers - Only render when map is loaded */}
        {markers}

        {/* Popup */}
        {popupInfo &&
          (() => {
            const coords = getSiteCoordinates(popupInfo.siteLocation);
            if (!coords) return null;

            return (
              <Popup
                longitude={coords.lng}
                latitude={coords.lat}
                anchor="bottom"
                offset={20}
                onClose={() => {
                  setPopupInfo(null);
                  onSiteSelect?.(null);
                }}
                closeButton={true}
                closeOnClick={false}
                maxWidth="280px"
                className="site-popup overflow-hidden rounded-xl"
              >
                <div className="w-64 overflow-hidden">
                  {/* <Link href={`/land/${property.slug}/sites/${popupInfo.slug}`}> */}
                  <div className="relative h-40 w-full overflow-hidden rounded-lg">
                    <Image
                      src={getCoverPhoto(popupInfo)}
                      alt={popupInfo.name}
                      fill
                      className="object-cover transition-transform duration-200 hover:scale-105"
                    />
                  </div>
                  {/* </Link> */}
                  <div className="space-y-2 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <h3 className="line-clamp-2 text-sm font-semibold">
                        {popupInfo.name}
                      </h3>
                      {popupInfo.rating && popupInfo.rating.average > 0 && (
                        <div className="flex items-center gap-1 text-xs">
                          <span>⭐</span>
                          <span className="font-medium">
                            {popupInfo.rating.average.toFixed(1)}
                          </span>
                        </div>
                      )}
                    </div>

                    <p className="text-muted-foreground line-clamp-2 text-xs">
                      {popupInfo.description ||
                        `${popupInfo.accommodationType} site`}
                    </p>

                    <div className="flex items-center justify-between pt-1">
                      <div>
                        <span className="text-sm font-bold">
                          {formatPrice(popupInfo.pricing.basePrice)} ₫
                        </span>
                        <span className="text-muted-foreground text-xs">
                          {' '}
                          / đêm
                        </span>
                      </div>
                      <Button
                        onClick={() => toast('hehe')}
                        size="default"
                        asChild
                      >
                        Đặt chỗ
                      </Button>
                    </div>
                  </div>
                </div>
              </Popup>
            );
          })()}
      </Map>
    </div>
  );
}
