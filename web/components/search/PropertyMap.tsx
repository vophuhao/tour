'use client';

import { Button } from '@/components/ui/button';
import { Property } from '@/types/property-site';
import { MapPin } from 'lucide-react';
import 'mapbox-gl/dist/mapbox-gl.css';
import Image from 'next/image';
import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Map, { MapRef, Marker, NavigationControl, Popup } from 'react-map-gl';

// Helper to extract lat/lng from GeoJSON coordinates
const getCoordinates = (coords: any): { lat: number; lng: number } | null => {
  // GeoJSON format: { type: 'Point', coordinates: [lng, lat] }
  if (coords?.type === 'Point' && Array.isArray(coords.coordinates)) {
    return { lng: coords.coordinates[0], lat: coords.coordinates[1] };
  }
  return null;
};

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

interface PropertyMapProps {
  properties: Property[];
  selectedProperty?: Property | null;
  hoveredProperty?: Property | null;
  searchCoordinates?: { lat: number; lng: number } | null;
  onPropertySelect?: (property: Property | null) => void;
  onBoundsChange?: (bounds: { minLat: number; maxLat: number; minLng: number; maxLng: number }) => void;
}

export function PropertyMap({
  properties,
  selectedProperty,
  hoveredProperty,
  searchCoordinates,
  onPropertySelect,
  onBoundsChange,
}: PropertyMapProps) {
  const mapRef = useRef<MapRef>(null);
  const isMounted = useRef(false);
  const [viewState, setViewState] = useState({
    longitude: 108.2022, // Vietnam center
    latitude: 16.0544,
    zoom: 5,
  });
  const [popupInfo, setPopupInfo] = useState<Property | null>(null);
  const [mapLoaded, setMapLoaded] = useState(false);
  const [showSearchAreaButton, setShowSearchAreaButton] = useState(false);

  const handleMapMoveEnd = useCallback(() => {
    if (!mapLoaded || !onBoundsChange || !mapRef.current) return;
    
    try {
      const map = mapRef.current.getMap();
      const bounds = map.getBounds();
      const sw = bounds.getSouthWest();
      const ne = bounds.getNorthEast();
      
      // Let's show the "Search this area" button overlay
      setShowSearchAreaButton(true);
    } catch (err) {
      console.error(err);
    }
  }, [mapLoaded, onBoundsChange]);

  const triggerAreaSearch = useCallback(() => {
    if (!mapRef.current || !onBoundsChange) return;
    try {
      const map = mapRef.current.getMap();
      const bounds = map.getBounds();
      const sw = bounds.getSouthWest();
      const ne = bounds.getNorthEast();
      
      onBoundsChange({
        minLat: sw.lat,
        maxLat: ne.lat,
        minLng: sw.lng,
        maxLng: ne.lng,
      });
      setShowSearchAreaButton(false);
    } catch (err) {
      console.error(err);
    }
  }, [onBoundsChange]);

  // Initialize and cleanup map state properly
  useEffect(() => {
    let mounted = true;
    isMounted.current = true;

    const checkMapLoaded = () => {
      if (!mounted) return;

      if (mapRef.current?.getMap) {
        try {
          const map = mapRef.current.getMap();
          if (map?.loaded()) {
            setMapLoaded(true);
          }
        } catch {
          // Map not ready
        }
      }
    };

    // Check immediately
    checkMapLoaded();

    // Also check after a short delay in case map loads asynchronously
    const timer = setTimeout(checkMapLoaded, 100);

    return () => {
      mounted = false;
      isMounted.current = false;
      clearTimeout(timer);
      // Full state cleanup on unmount
      setPopupInfo(null);
      setMapLoaded(false);
    };
  }, []);

  // Fly to search coordinates when they change
  useEffect(() => {
    if (searchCoordinates && mapRef.current && mapLoaded) {
      try {
        mapRef.current.flyTo({
          center: [searchCoordinates.lng, searchCoordinates.lat],
          zoom: 8.5,
          duration: 2000,
        });
      } catch (error) {
        console.error('Error flying to coordinates:', error);
      }
    }
  }, [searchCoordinates, mapLoaded]);

  const handleMarkerClick = useCallback(
    (property: Property) => {
      // Guard: don't execute if component unmounted or map not loaded
      if (!mapLoaded || !isMounted.current) return;

      setPopupInfo(property);
      onPropertySelect?.(property);

      const coords = getCoordinates(property.location?.coordinates);
      if (coords && mapRef.current) {
        try {
          mapRef.current.flyTo({
            center: [coords.lng, coords.lat],
            zoom: 10,
            duration: 1000,
          });
        } catch (error) {
          console.error('Error flying to marker:', error);
        }
      }
    },
    [onPropertySelect, mapLoaded],
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

  const getCoverPhoto = useCallback((property: Property) => {
    const coverPhoto = property.photos?.find(p => p.isCover);
    if (coverPhoto) return coverPhoto.url;
    return property.photos?.[0]?.url || '/placeholder-campsite.jpg';
  }, []);

  // Memoize markers to prevent unnecessary rerenders
  // Only create markers when map is loaded
  const markers = useMemo(() => {
    // Don't render markers until map is fully loaded AND component is mounted
    if (!mapLoaded || !isMounted.current) return null;

    // Verify map container exists in DOM before rendering markers
    if (!mapRef.current?.getMap) return null;

    try {
      const map = mapRef.current.getMap();
      const container = map.getContainer();

      // Critical check: ensure container is still in DOM
      if (!container || !document.body.contains(container)) {
        return null;
      }
    } catch (error) {
      // Map not ready or already unmounted
      return null;
    }

    // Safely create markers with error boundary
    try {
      return properties.map(property => {
        const coords = getCoordinates(property.location?.coordinates);
        if (!coords) return null;

        const isSelected = selectedProperty?._id === property._id;
        const isHovered = hoveredProperty?._id === property._id;
        const isActive = isSelected || isHovered;

        return (
          <Marker
            key={property._id}
            longitude={coords.lng}
            latitude={coords.lat}
            anchor="bottom"
            onClick={e => {
              e.originalEvent.stopPropagation();
              handleMarkerClick(property);
            }}
          >
            <div
              className={`group relative cursor-pointer transition-all duration-200 ${
                isActive ? 'z-50 scale-125' : 'hover:scale-110'
              }`}
            >
              {/* Price Badge */}
              <div
                className={`rounded-full border px-3 py-1.5 text-sm font-medium transition-all duration-200 flex items-center gap-1 ${
                  isActive
                    ? 'border-black bg-black text-white shadow-md'
                    : 'border-gray-300 bg-white text-gray-900 hover:border-black hover:bg-black hover:text-white hover:shadow-md'
                }`}
              >
                {(property as any).isSuperhost && <span className="text-xs">🏅</span>}
                <span>
                  {property.minPrice
                    ? `${formatPrice(property.minPrice)}`
                    : '50k₫'}
                </span>
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
    properties,
    selectedProperty,
    hoveredProperty,
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
    <div translate="no" className="relative w-full h-full notranslate">
      <Map
        ref={mapRef}
        {...viewState}
        onMove={evt => setViewState(evt.viewState)}
        onMoveEnd={handleMapMoveEnd}
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
        mapStyle="mapbox://styles/mapbox/streets-v12"
        mapboxAccessToken={MAPBOX_TOKEN}
        style={{ width: '100%', height: '100%' }}
        minPitch={0}
        maxPitch={0}
        projection={{ name: 'mercator' }}
        dragRotate={false}
        touchPitch={false}
      >
        {/* Floating Search Area Button */}
        {showSearchAreaButton && onBoundsChange && (
          <div className="absolute top-4 left-1/2 -translate-x-1/2 z-30">
            <Button
              size="sm"
              onClick={triggerAreaSearch}
              className="bg-white hover:bg-slate-100 text-slate-800 border border-slate-200 shadow-xl rounded-full text-xs font-bold px-4 py-2 flex items-center gap-1.5 transition-all duration-300 transform scale-100 hover:scale-105"
            >
              <span>🔍 Tìm kiếm khu vực này</span>
            </Button>
          </div>
        )}
      {/* Navigation Controls */}
      <NavigationControl
        position="top-right"
        showCompass={true}
        showZoom={true}
      />

      {/* Property Markers - Only render when map is loaded */}
      {markers}

      {/* Popup */}
      {popupInfo &&
        (() => {
          const coords = getCoordinates(popupInfo.location?.coordinates);
          if (!coords) return null;

          return (
            <Popup
              longitude={coords.lng}
              latitude={coords.lat}
              anchor="bottom"
              offset={20}
              onClose={() => {
                setPopupInfo(null);
                onPropertySelect?.(null);
              }}
              closeButton={true}
              closeOnClick={false}
              maxWidth="280px"
              className="property-popup overflow-hidden rounded-xl"
            >
              <div className="w-64 overflow-hidden">
                <Link href={`/land/${popupInfo.slug || popupInfo._id}`}>
                  <div className="relative h-40 w-full overflow-hidden rounded-lg">
                    <Image
                      src={getCoverPhoto(popupInfo)}
                      alt={popupInfo.name}
                      fill
                      className="object-cover transition-transform duration-200 hover:scale-105"
                    />
                  </div>
                </Link>
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

                  <div className="text-muted-foreground flex items-center gap-1 text-xs">
                    <MapPin className="h-3 w-3" />
                    <span>
                      {popupInfo.location.city}, {popupInfo.location.state}
                    </span>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <div>
                      <span className="text-sm font-bold">
                        {popupInfo.minPrice
                          ? `${formatPrice(popupInfo.minPrice)} ₫`
                          : '50k₫'}
                      </span>
                      <span className="text-muted-foreground text-xs">
                        {' '}
                        / đêm
                      </span>
                    </div>
                    <Button asChild size="sm">
                      <Link href={`/land/${popupInfo.slug || popupInfo._id}`}>
                        Xem
                      </Link>
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
