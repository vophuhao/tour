'use client';

import { MapPin } from 'lucide-react';
import 'mapbox-gl/dist/mapbox-gl.css';
import { useEffect, useRef, useState } from 'react';
import Map, { MapRef, Marker } from 'react-map-gl';

interface LocationSectionProps {
  location: {
    address: string;
    city: string;
    state: string;
    country: string;
    coordinates:
      | {
          type: 'Point';
          coordinates: [number, number];
        }
      | {
          lat: number;
          lng: number;
        };
    accessInstructions?: string;
  };
}

export function LocationSection({ location }: LocationSectionProps) {
  const mapRef = useRef<MapRef>(null);
  const [mapLoaded, setMapLoaded] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);

  // Initialize and cleanup
  useEffect(() => {
    setIsInitialized(true);

    return () => {
      setMapLoaded(false);
      setIsInitialized(false);
    };
  }, []);
  // Extract coordinates
  const coords =
    'type' in location.coordinates
      ? {
          lat: location.coordinates.coordinates[1],
          lng: location.coordinates.coordinates[0],
        }
      : location.coordinates;

  return (
    <div className="space-y-6" id="location">
      <h2 className="text-2xl font-bold">Vị trí</h2>

      <div className="space-y-4">
        <div className="flex items-start gap-3">
          <MapPin className="text-muted-foreground mt-1 h-5 w-5" />
          <div>
            <p className="font-semibold">
              {location.city}, {location.state}, {location.country}
            </p>
            <p className="text-muted-foreground text-sm">
              Địa chỉ chính xác sẽ được cung cấp sau khi đặt phòng để bảo vệ
              quyền riêng tư của chủ nhà
            </p>
          </div>
        </div>

        {/* Mapbox Map */}
        <div className="relative h-[400px] w-full overflow-hidden rounded-lg border notranslate" translate="no">
          <Map
            key={`location-${coords.lat}-${coords.lng}`}
            id="location-map"
            ref={mapRef}
            mapboxAccessToken={process.env.NEXT_PUBLIC_MAPBOX_TOKEN}
            initialViewState={{
              longitude: coords.lng,
              latitude: coords.lat,
              zoom: 12.5,
            }}
            style={{ width: '100%', height: '100%' }}
            mapStyle="mapbox://styles/mapbox/streets-v12"
            interactive={false}
            onLoad={() => {
              setTimeout(() => {
                setMapLoaded(true);
              }, 150);
            }}
            onRemove={() => {
              setMapLoaded(false);
            }}
            onError={e => {
              console.error('Location map error:', e);
            }}
          >
            {mapLoaded && isInitialized && (
              <Marker
                longitude={coords.lng}
                latitude={coords.lat}
                anchor="bottom"
              >
                <div className="flex flex-col items-center">
                  <div className="bg-primary rounded-full p-2 shadow-lg">
                    <MapPin className="text-primary-foreground h-6 w-6" />
                  </div>
                </div>
              </Marker>
            )}
          </Map>
        </div>

        {/* Access Instructions */}
        {location.accessInstructions && (
          <div className="bg-muted/50 rounded-lg border p-4">
            <h4 className="mb-2 font-semibold">Hướng dẫn đến nơi</h4>
            <p className="text-muted-foreground text-sm whitespace-pre-wrap">
              {location.accessInstructions}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
