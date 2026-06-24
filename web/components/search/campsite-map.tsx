'use client';

import { Button } from '@/components/ui/button';
import { MapPin } from 'lucide-react';
import 'mapbox-gl/dist/mapbox-gl.css';
import Image from 'next/image';
import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Map, { MapRef, Marker, NavigationControl, Popup } from 'react-map-gl';

// Helper to extract lat/lng from both GeoJSON and legacy format
const getCoordinates = (coords: any): { lat: number; lng: number } => {
  // GeoJSON format: { type: 'Point', coordinates: [lng, lat] }
  if (coords.type === 'Point' && Array.isArray(coords.coordinates)) {
    return { lng: coords.coordinates[0], lat: coords.coordinates[1] };
  }
  // Legacy format: { lat, lng }
  return { lat: coords.lat, lng: coords.lng };
};

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

interface CampsiteMapProps {
  campsites: Campsite[];
  selectedCampsite?: Campsite | null;
  hoveredCampsite?: Campsite | null;
  searchCoordinates?: { lat: number; lng: number } | null;
  onCampsiteSelect?: (campsite: Campsite | null) => void;
}

export function CampsiteMap({
  campsites,
  selectedCampsite,
  hoveredCampsite,
  searchCoordinates,
  onCampsiteSelect,
}: CampsiteMapProps) {
  const mapRef = useRef<MapRef>(null);
  const [viewState, setViewState] = useState({
    longitude: 108.2022, // Vietnam center
    latitude: 16.0544,
    zoom: 5,
  });
  const [popupInfo, setPopupInfo] = useState<Campsite | null>(null);
  const [mapLoaded, setMapLoaded] = useState(false);

  // Check if map is already loaded when component mounts (due to reuseMaps)
  useEffect(() => {
    const checkMapLoaded = () => {
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
      clearTimeout(timer);
      setPopupInfo(null);
    };
  }, []);

  // Fly to search coordinates when they change
  useEffect(() => {
    if (searchCoordinates && mapRef.current && mapLoaded) {
      try {
        mapRef.current.flyTo({
          center: [searchCoordinates.lng, searchCoordinates.lat],
          zoom: 10,
          duration: 2000,
        });
      } catch (error) {
        console.error('Error flying to coordinates:', error);
      }
    }
  }, [searchCoordinates, mapLoaded]);

  const handleMarkerClick = useCallback(
    (campsite: Campsite) => {
      if (!mapLoaded) return;

      setPopupInfo(campsite);
      onCampsiteSelect?.(campsite);

      const coords = getCoordinates(campsite.location.coordinates);
      // Fly to marker
      if (mapRef.current) {
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
    [onCampsiteSelect, mapLoaded],
  );

  const formatPrice = useCallback((price: number) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);
  }, []);

  // Memoize markers to prevent unnecessary rerenders
  // Only create markers when map is loaded
  const markers = useMemo(() => {
    // Don't render markers until map is fully loaded
    if (!mapLoaded) return null;

    // Safely create markers with error boundary
    try {
      return campsites.map(campsite => {
        const isSelected = selectedCampsite?._id === campsite._id;
        const isHovered = hoveredCampsite?._id === campsite._id;
        const isActive = isSelected || isHovered;
        const coords = getCoordinates(campsite.location.coordinates);

        return (
          <Marker
            key={campsite._id}
            longitude={coords.lng}
            latitude={coords.lat}
            anchor="bottom"
            onClick={e => {
              e.originalEvent.stopPropagation();
              handleMarkerClick(campsite);
            }}
          >
            <div
              className={`group relative cursor-pointer transition-all duration-200 ${
                isActive ? 'z-50 scale-125' : 'hover:scale-110'
              }`}
            >
              {/* Price Badge */}
              <div
                className={`rounded-full border px-3 py-1.5 text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? 'border-black bg-black text-white shadow-md'
                    : 'border-gray-300 bg-white text-gray-900 hover:border-black hover:bg-black hover:text-white hover:shadow-md'
                }`}
              >
                {formatPrice(campsite.pricing.basePrice).replace('₫', 'đ')}
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
    campsites,
    selectedCampsite,
    hoveredCampsite,
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
        mapStyle="mapbox://styles/mapbox/streets-v12"
        mapboxAccessToken={MAPBOX_TOKEN}
        style={{ width: '100%', height: '100%' }}
        minPitch={0}
        maxPitch={0}
        projection={{ name: 'mercator' }}
        dragRotate={false}
        touchPitch={false}
        reuseMaps
      >
        {/* Navigation Controls */}
        <NavigationControl
          position="top-right"
          showCompass={true}
          showZoom={true}
        />

        {/* Campsite Markers - Only render when map is loaded */}
        {markers}

        {/* Popup */}
        {popupInfo && (
          <Popup
            longitude={getCoordinates(popupInfo.location.coordinates).lng}
            latitude={getCoordinates(popupInfo.location.coordinates).lat}
            anchor="bottom"
            offset={20}
            onClose={() => {
              setPopupInfo(null);
              onCampsiteSelect?.(null);
            }}
            closeButton={true}
            closeOnClick={false}
            maxWidth="280px"
            className="campsite-popup overflow-hidden rounded-xl"
          >
            <div className="w-64 overflow-hidden">
              <Link href={`/land/${popupInfo.slug}`}>
                <div className="relative h-40 w-full overflow-hidden rounded-lg">
                  <Image
                    src={popupInfo.images[0] || '/placeholder.jpg'}
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
                  {popupInfo.rating && (
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
                      {formatPrice(popupInfo.pricing.basePrice)}
                    </span>
                    <span className="text-muted-foreground text-xs"> / đêm</span>
                  </div>
                  <Button asChild size="sm">
                    <Link href={`/land/${popupInfo.slug}`}>Xem</Link>
                  </Button>
                </div>
              </div>
            </div>
          </Popup>
        )}
      </Map>
    </div>
  );
}
