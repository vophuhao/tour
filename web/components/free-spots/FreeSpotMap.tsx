'use client';

import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import Map, { MapRef, Marker, NavigationControl, Popup, Source, Layer } from 'react-map-gl';
import mapboxgl from 'mapbox-gl';
import 'mapbox-gl/dist/mapbox-gl.css';
import type { FreeSpot } from '@/lib/free-spot-api';
import Link from 'next/link';
import { Eye, Heart, MapPin } from 'lucide-react';
import { Button } from '@/components/ui/button';

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

interface Props {
  spots: FreeSpot[];
  highlightedId?: string | null;
  onMarkerClick?: (id: string) => void;
  userLocation?: { lat: number; lng: number } | null;
  nearbyRadius?: number; // km
  center?: [number, number]; // [lng, lat]
  zoom?: number;
  height?: number | string;
  interactive?: boolean;
  onLocationChange?: (lat: number, lng: number) => void; // for create form
  singleSpot?: boolean; // show just one marker (detail page)
}

export default function FreeSpotMap({
  spots,
  highlightedId,
  onMarkerClick,
  userLocation,
  nearbyRadius,
  center,
  zoom = 6,
  height = 480,
  interactive = false,
  onLocationChange,
  singleSpot = false,
}: Props) {
  const mapRef = useRef<MapRef>(null);
  const [mapLoaded, setMapLoaded] = useState(false);
  const [popupInfo, setPopupInfo] = useState<FreeSpot | null>(null);

  const [viewState, setViewState] = useState({
    longitude: center ? center[0] : 106.6297, // default Vietnam/HCM
    latitude: center ? center[1] : 10.8231,
    zoom: zoom,
  });

  const [selectedCoords, setSelectedCoords] = useState<{ lat: number; lng: number } | null>(() => {
    if (interactive && center) {
      return { lng: center[0], lat: center[1] };
    }
    return null;
  });

  // Sync center prop
  useEffect(() => {
    if (center) {
      setViewState((prev) => ({
        ...prev,
        longitude: center[0],
        latitude: center[1],
      }));
    }
  }, [center]);

  // Click on map to select coordinates in interactive mode
  const handleMapClick = useCallback((e: any) => {
    if (!interactive) return;
    const { lng, lat } = e.lngLat;
    setSelectedCoords({ lat, lng });
    onLocationChange?.(lat, lng);
  }, [interactive, onLocationChange]);

  // Fit bounds or fly to center reactively
  useEffect(() => {
    if (!mapLoaded || !mapRef.current) return;
    const map = mapRef.current.getMap();

    if (singleSpot && spots.length > 0) {
      const [lng, lat] = spots[0].location.coordinates;
      map.flyTo({ center: [lng, lat], zoom: 13, duration: 1000 });
      return;
    }

    if (spots.length === 1) {
      const [lng, lat] = spots[0].location.coordinates;
      map.flyTo({ center: [lng, lat], zoom: 12, duration: 1000 });
      return;
    }

    if (spots.length > 1) {
      const bounds = new mapboxgl.LngLatBounds();
      spots.forEach((s) => bounds.extend(s.location.coordinates as [number, number]));
      map.fitBounds(bounds, { padding: 60, maxZoom: 13, duration: 800 });
    }
  }, [spots, mapLoaded, singleSpot]);

  // Fly to highlighted marker
  useEffect(() => {
    if (!mapLoaded || !mapRef.current || !highlightedId) return;
    const spot = spots.find((s) => s._id === highlightedId);
    if (spot) {
      setPopupInfo(spot);
      const [lng, lat] = spot.location.coordinates;
      mapRef.current.flyTo({ center: [lng, lat], zoom: 12, duration: 800 });
    }
  }, [highlightedId, mapLoaded, spots]);

  // Circle overlay GeoJSON for user range
  const circleGeoJSON = useMemo(() => {
    if (!userLocation || !nearbyRadius) return null;
    const radiusDeg = nearbyRadius / 111.32;
    const points = 64;
    const coords: [number, number][] = Array.from({ length: points + 1 }, (_, i) => {
      const angle = (i / points) * 2 * Math.PI;
      return [
        userLocation.lng + radiusDeg * Math.cos(angle),
        userLocation.lat + radiusDeg * Math.sin(angle),
      ];
    });
    return {
      type: 'Feature',
      properties: {},
      geometry: {
        type: 'Polygon',
        coordinates: [coords],
      },
    };
  }, [userLocation, nearbyRadius]);

  // Render markers memoized
  const markers = useMemo(() => {
    if (!mapLoaded) return null;
    return spots.map((spot) => {
      const [lng, lat] = spot.location.coordinates;
      const isHighlighted = spot._id === highlightedId;
      return (
        <Marker
          key={spot._id}
          longitude={lng}
          latitude={lat}
          anchor="bottom"
          onClick={(e) => {
            e.originalEvent.stopPropagation();
            if (onMarkerClick) {
              onMarkerClick(spot._id);
            } else {
              setPopupInfo(spot);
            }
          }}
        >
          <div
            className={`group flex items-center justify-center rounded-full border-3 border-white bg-primary text-sm shadow-md transition-all duration-200 cursor-pointer h-9 w-9 hover:scale-110 active:scale-95 select-none ${
              isHighlighted ? 'bg-amber-500 scale-125 z-50 border-amber-300 ring-4 ring-amber-500/20' : ''
            }`}
          >
            🏕️
          </div>
        </Marker>
      );
    });
  }, [spots, mapLoaded, highlightedId, onMarkerClick]);

  if (!MAPBOX_TOKEN) {
    return (
      <div className="bg-muted flex h-full items-center justify-center rounded-2xl border border-border">
        <p className="text-muted-foreground text-sm font-medium">
          Mapbox token is missing. Please check your environment configuration.
        </p>
      </div>
    );
  }

  return (
    <div translate="no" className="relative w-full h-full min-h-[300px] notranslate">
      <Map
        ref={mapRef}
        {...viewState}
        onMove={(evt) => setViewState(evt.viewState)}
        onLoad={() => setMapLoaded(true)}
        onClick={handleMapClick}
        mapStyle="mapbox://styles/mapbox/streets-v12"
        mapboxAccessToken={MAPBOX_TOKEN}
        style={{ width: '100%', height: height === 9999 ? '100%' : height }}
        minPitch={0}
        maxPitch={0}
        dragRotate={false}
        touchPitch={false}
      >
        {/* Navigation Controls */}
        <NavigationControl
          position="top-right"
          showCompass={true}
          showZoom={true}
        />

        {/* User radius layer */}
        {circleGeoJSON && (
          <Source id="user-radius" type="geojson" data={circleGeoJSON as any}>
            <Layer
              id="user-radius-layer"
              type="fill"
              paint={{
                'fill-color': '#3b82f6',
                'fill-opacity': 0.08,
              }}
            />
          </Source>
        )}

        {/* Spot Markers */}
        {markers}

        {/* User Location Marker */}
        {userLocation && (
          <Marker
            longitude={userLocation.lng}
            latitude={userLocation.lat}
            anchor="center"
          >
            <div className="h-5 w-5 rounded-full border-2 border-white bg-blue-500 shadow-md ring-4 ring-blue-500/20 animate-pulse-subtle" />
          </Marker>
        )}

        {/* Interactive Click Marker */}
        {interactive && selectedCoords && (
          <Marker
            longitude={selectedCoords.lng}
            latitude={selectedCoords.lat}
            anchor="bottom"
            draggable
            onDragEnd={(e) => {
              const lngLat = e.lngLat;
              setSelectedCoords({ lat: lngLat.lat, lng: lngLat.lng });
              onLocationChange?.(lngLat.lat, lngLat.lng);
            }}
          >
            <div className="flex items-center justify-center rounded-full border-3 border-white bg-primary text-base shadow-md h-9 w-9 cursor-grab active:cursor-grabbing hover:scale-105 transition-all">
              📍
            </div>
          </Marker>
        )}

        {/* Interactive Guide overlay */}
        {interactive && (
          <div className="absolute top-3 left-3 z-10 bg-white/92 dark:bg-black/92 backdrop-blur-md px-3 py-1.5 rounded-lg text-[11px] font-extrabold shadow-md text-foreground border border-border">
            💡 Click hoặc kéo ghim để chọn vị trí
          </div>
        )}

        {/* Popup info */}
        {popupInfo && (
          <Popup
            longitude={popupInfo.location.coordinates[0]}
            latitude={popupInfo.location.coordinates[1]}
            anchor="bottom"
            offset={20}
            onClose={() => setPopupInfo(null)}
            closeButton={true}
            closeOnClick={false}
            maxWidth="280px"
            className="overflow-hidden rounded-xl shadow-lg border border-border"
          >
            <div className="w-56 overflow-hidden">
              <Link href={`/free-spots/${popupInfo._id}`}>
                <div className="relative h-28 w-full overflow-hidden rounded-lg bg-muted">
                  {popupInfo.images?.[0] ? (
                    <img
                      src={popupInfo.images[0]}
                      alt={popupInfo.title}
                      width={224}
                      height={112}
                      className="object-cover w-full h-full transition-transform duration-200 hover:scale-105"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-3xl bg-muted text-muted-foreground">
                      🏕️
                    </div>
                  )}
                </div>
              </Link>
              <div className="space-y-1.5 pt-2">
                <h3 className="line-clamp-1 text-xs font-bold text-foreground">
                  {popupInfo.title}
                </h3>

                <div className="text-muted-foreground flex items-center gap-1 text-[10px]">
                  <MapPin className="h-3 w-3 text-primary/70 shrink-0" />
                  <span className="truncate">
                    {popupInfo.address}, {popupInfo.city}
                  </span>
                </div>

                <div className="flex items-center justify-between pt-1">
                  <div className="flex items-center gap-2 text-[10px] font-semibold">
                    <span className="flex items-center gap-0.5 text-rose-500">
                      <Heart size={11} fill="#ef4444" />
                      <span>{popupInfo.likeCount ?? 0}</span>
                    </span>
                    <span className="flex items-center gap-0.5 text-muted-foreground">
                      <Eye size={11} />
                      <span>{popupInfo.viewCount ?? 0}</span>
                    </span>
                  </div>
                  <Button asChild size="sm" className="h-6 text-[10px] px-2 bg-primary text-white">
                    <Link href={`/free-spots/${popupInfo._id}`}>Xem</Link>
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
