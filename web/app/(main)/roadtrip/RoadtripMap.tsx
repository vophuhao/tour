'use client';

import { Button } from '@/components/ui/button';
import type { Property } from '@/types/property-site';
import { MapPin } from 'lucide-react';
import 'mapbox-gl/dist/mapbox-gl.css';
import Image from 'next/image';
import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Map, { MapRef, Marker, NavigationControl, Popup, Source, Layer } from 'react-map-gl';

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

const getCoordinates = (coords: any): { lat: number; lng: number } | null => {
  if (coords?.type === 'Point' && Array.isArray(coords.coordinates)) {
    return { lng: coords.coordinates[0], lat: coords.coordinates[1] };
  }
  return null;
};

interface RoadtripMapProps {
  properties: Property[];
  selectedProperty?: Property | null;
  hoveredProperty?: Property | null;
  startCoords?: { lat: number; lng: number } | null;
  endCoords?: { lat: number; lng: number } | null;
  routeGeometry?: any | null; // GeoJSON geometry from Mapbox Directions API
  onPropertySelect?: (property: Property | null) => void;
}

export function RoadtripMap({
  properties,
  selectedProperty,
  hoveredProperty,
  startCoords,
  endCoords,
  routeGeometry,
  onPropertySelect,
}: RoadtripMapProps) {
  console.log('RoadtripMap rendering, token:', MAPBOX_TOKEN ? 'Present' : 'Empty', 'properties:', properties.length);
  const mapRef = useRef<MapRef>(null);
  const [viewState, setViewState] = useState({
    longitude: 108.2022, // Center of Vietnam
    latitude: 16.0544,
    zoom: 5,
  });
  const [popupInfo, setPopupInfo] = useState<Property | null>(null);
  const [mapLoaded, setMapLoaded] = useState(false);

  // Format price helper
  const formatPrice = useCallback((price: number) => {
    if (price >= 1000000) {
      return `${Math.round(price / 1000000)}tr`;
    } else if (price >= 1000) {
      return `${Math.round(price / 1000)}k`;
    }
    return `${price}`;
  }, []);

  const getCoverPhoto = useCallback((property: Property) => {
    const coverPhoto = property.photos?.find((p: any) => p.isCover);
    if (coverPhoto) return coverPhoto.url;
    return property.photos?.[0]?.url || '/placeholder-campsite.jpg';
  }, []);

  // Fit bounds when route geometry, start coordinates, or end coordinates change
  useEffect(() => {
    if (!mapLoaded || !mapRef.current) return;

    // Build the set of points we want to fit in the viewport
    const coordsToFit: [number, number][] = [];

    if (startCoords) {
      coordsToFit.push([startCoords.lng, startCoords.lat]);
    }
    if (endCoords) {
      coordsToFit.push([endCoords.lng, endCoords.lat]);
    }

    if (routeGeometry?.coordinates && Array.isArray(routeGeometry.coordinates)) {
      // Add a subset of route coordinates to keep bounds calculations simple
      const step = Math.max(1, Math.floor(routeGeometry.coordinates.length / 50));
      for (let i = 0; i < routeGeometry.coordinates.length; i += step) {
        coordsToFit.push(routeGeometry.coordinates[i]);
      }
    } else {
      // If no route, fit map to properties
      properties.forEach(property => {
        const c = getCoordinates(property.location?.coordinates);
        if (c) coordsToFit.push([c.lng, c.lat]);
      });
    }

    if (coordsToFit.length > 0) {
      let minLng = coordsToFit[0][0];
      let maxLng = coordsToFit[0][0];
      let minLat = coordsToFit[0][1];
      let maxLat = coordsToFit[0][1];

      coordsToFit.forEach(([lng, lat]) => {
        if (lng < minLng) minLng = lng;
        if (lng > maxLng) maxLng = lng;
        if (lat < minLat) minLat = lat;
        if (lat > maxLat) maxLat = lat;
      });

      try {
        mapRef.current.fitBounds(
          [
            [minLng, minLat],
            [maxLng, maxLat],
          ],
          {
            padding: { top: 60, bottom: 60, left: 60, right: 60 },
            duration: 1500,
          }
        );
      } catch (err) {
        console.error('Error fitting bounds:', err);
      }
    }
  }, [mapLoaded, startCoords, endCoords, routeGeometry, properties]);

  // Center on hovered property
  useEffect(() => {
    if (hoveredProperty && mapRef.current && mapLoaded) {
      const coords = getCoordinates(hoveredProperty.location?.coordinates);
      if (coords) {
        mapRef.current.easeTo({
          center: [coords.lng, coords.lat],
          duration: 500,
        });
      }
    }
  }, [hoveredProperty, mapLoaded]);

  // Center on selected property
  useEffect(() => {
    if (selectedProperty && mapRef.current && mapLoaded) {
      const coords = getCoordinates(selectedProperty.location?.coordinates);
      if (coords) {
        setPopupInfo(selectedProperty);
        mapRef.current.easeTo({
          center: [coords.lng, coords.lat],
          duration: 500,
        });
      }
    }
  }, [selectedProperty, mapLoaded]);

  // Render properties pins
  const propertyMarkers = useMemo(() => {
    if (!mapLoaded) return null;

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
            setPopupInfo(property);
            onPropertySelect?.(property);
          }}
        >
          <div
            className={`group relative cursor-pointer transition-all duration-200 ${isActive ? 'z-50 scale-125' : 'hover:scale-110'
              }`}
          >
            {/* Price Badge */}
            <div
              className={`rounded-full border px-3 py-1.5 text-sm font-semibold shadow-sm transition-all duration-200 flex items-center gap-1 ${isActive
                ? 'border-emerald-600 bg-emerald-600 text-white shadow-md'
                : 'border-gray-200 bg-white text-gray-900 hover:border-emerald-600 hover:bg-emerald-50 hover:shadow-md'
                }`}
            >
              {property.isSuperhost && <span className="text-xs">🏅</span>}
              <span>
                {property.minPrice
                  ? `${formatPrice(property.minPrice)}₫`
                  : '50k₫'}
              </span>
            </div>
          </div>
        </Marker>
      );
    });
  }, [mapLoaded, properties, selectedProperty, hoveredProperty, onPropertySelect, formatPrice]);

  // Route layer configuration
  const routeSourceData = useMemo(() => {
    if (!routeGeometry) return null;
    return {
      type: 'Feature' as const,
      properties: {},
      geometry: routeGeometry,
    };
  }, [routeGeometry]);

  if (!MAPBOX_TOKEN) {
    return (
      <div className="bg-muted flex h-full items-center justify-center rounded-xl border border-dashed border-gray-300">
        <p className="text-muted-foreground p-4 text-center">
          Không tìm thấy MAPBOX_TOKEN. Hãy cấu hình NEXT_PUBLIC_MAPBOX_TOKEN.
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
        onLoad={() => setMapLoaded(true)}
        mapStyle="mapbox://styles/mapbox/streets-v12"
        mapboxAccessToken={MAPBOX_TOKEN}
        style={{ width: '100%', height: '100%', borderRadius: '12px' }}
        minPitch={0}
        maxPitch={0}
        projection={{ name: 'mercator' }}
        dragRotate={false}
        touchPitch={false}
      >
        {/* Navigation Controls */}
        <NavigationControl position="top-right" showCompass={false} />

        {/* Route Source & Layers */}
        {routeSourceData && (
          <Source id="route-source" type="geojson" data={routeSourceData}>
            {/* Wider semi-transparent background line */}
            <Layer
              id="route-line-glow"
              type="line"
              layout={{
                'line-join': 'round',
                'line-cap': 'round',
              }}
              paint={{
                'line-color': '#d35422', // Primary theme color glow
                'line-width': 10,
                'line-opacity': 0.25,
              }}
            />
            {/* Crisp main line */}
            <Layer
              id="route-line-main"
              type="line"
              layout={{
                'line-join': 'round',
                'line-cap': 'round',
              }}
              paint={{
                'line-color': '#d35422', // Primary theme color main line
                'line-width': 5,
              }}
            />
          </Source>
        )}

        {/* Start Point Marker */}
        {startCoords && (
          <Marker longitude={startCoords.lng} latitude={startCoords.lat} anchor="bottom">
            <div className="flex flex-col items-center">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500 text-white font-bold border-2 border-white shadow-lg animate-bounce">
                A
              </div>
              <div className="h-2 w-2 bg-emerald-500 rotate-45 -mt-1 border-r border-b border-white shadow-sm" />
            </div>
          </Marker>
        )}

        {/* End Point Marker */}
        {endCoords && (
          <Marker longitude={endCoords.lng} latitude={endCoords.lat} anchor="bottom">
            <div className="flex flex-col items-center">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-rose-500 text-white font-bold border-2 border-white shadow-lg animate-bounce">
                B
              </div>
              <div className="h-2 w-2 bg-rose-500 rotate-45 -mt-1 border-r border-b border-white shadow-sm" />
            </div>
          </Marker>
        )}

        {/* Property markers */}
        {propertyMarkers}

        {/* Popup detailed property card */}
        {popupInfo && (() => {
          const coords = getCoordinates(popupInfo.location?.coordinates);
          if (!coords) return null;

          return (
            <Popup
              longitude={coords.lng}
              latitude={coords.lat}
              anchor="bottom"
              offset={24}
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
                      sizes="256px"
                    />
                  </div>
                </Link>
                <div className="space-y-2 p-3">
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="line-clamp-2 text-sm font-semibold text-gray-900 leading-tight">
                      {popupInfo.name}
                    </h3>
                  </div>

                  <div className="text-muted-foreground flex items-center gap-1 text-xs">
                    <MapPin className="h-3 w-3" />
                    <span className="truncate">
                      {popupInfo.location.city}, {popupInfo.location.state}
                    </span>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <div>
                      <span className="text-sm font-bold text-gray-950">
                        {popupInfo.minPrice
                          ? `${formatPrice(popupInfo.minPrice)} ₫`
                          : '50k ₫'}
                      </span>
                      <span className="text-muted-foreground text-xs"> / đêm</span>
                    </div>
                    <Button asChild size="sm" className="h-8 rounded-full px-3 text-xs bg-emerald-600 hover:bg-emerald-700">
                      <Link href={`/land/${popupInfo.slug || popupInfo._id}`}>
                        Chi tiết
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
