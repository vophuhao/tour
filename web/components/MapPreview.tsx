'use client';

import { useEffect, useRef, useState } from 'react';
import mapboxgl from 'mapbox-gl';
import 'mapbox-gl/dist/mapbox-gl.css';

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

interface MapPreviewProps {
    lat: number;
    lng: number;
    zoom?: number;
    height?: number;
    interactive?: boolean;
    onLocationChange?: (lat: number, lng: number) => void;
}

export default function MapPreview({ 
    lat, 
    lng, 
    zoom = 13, 
    height = 400,
    interactive = false,
    onLocationChange
}: MapPreviewProps) {
    const mapContainer = useRef<HTMLDivElement>(null);
    const map = useRef<mapboxgl.Map | null>(null);
    const marker = useRef<mapboxgl.Marker | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [isMapLoaded, setIsMapLoaded] = useState(false);

    // Initialize map only once
    useEffect(() => {
        if (!mapContainer.current || !MAPBOX_TOKEN || map.current) return;

        mapboxgl.accessToken = MAPBOX_TOKEN;
        
        map.current = new mapboxgl.Map({
            container: mapContainer.current,
            style: 'mapbox://styles/mapbox/streets-v12',
            center: [lng, lat],
            zoom: zoom,
        });

        // Add navigation controls
        map.current.addControl(new mapboxgl.NavigationControl(), 'top-right');

        // Wait for map to load
        map.current.on('load', () => {
            setIsMapLoaded(true);
        });

        // Add marker
        marker.current = new mapboxgl.Marker({ 
            color: '#10b981',
            draggable: interactive 
        })
            .setLngLat([lng, lat])
            .addTo(map.current!);

        // Handle marker drag
        if (interactive && marker.current) {
            marker.current.on('dragstart', () => {
                setIsDragging(true);
            });

            marker.current.on('dragend', () => {
                setIsDragging(false);
                const lngLat = marker.current?.getLngLat();
                if (lngLat && onLocationChange) {
                    onLocationChange(lngLat.lat, lngLat.lng);
                }
            });
        }

        // Handle map click (if interactive)
        if (interactive && map.current) {
            map.current.on('click', (e) => {
                const { lng, lat } = e.lngLat;
                marker.current?.setLngLat([lng, lat]);
                if (onLocationChange) {
                    onLocationChange(lat, lng);
                }
            });

            // Change cursor on hover
            map.current.getCanvas().style.cursor = 'crosshair';
        }

        // Cleanup only on unmount
        return () => {
            marker.current?.remove();
            map.current?.remove();
            map.current = null;
        };
    }, []); // Empty deps - only run once

    // Update marker position when lat/lng changes
    useEffect(() => {
        if (map.current && marker.current && isMapLoaded) {
            marker.current.setLngLat([lng, lat]);
            map.current.flyTo({
                center: [lng, lat],
                zoom: zoom,
                duration: 1000
            });
        }
    }, [lat, lng, zoom, isMapLoaded]);

    // Update marker draggable state
    useEffect(() => {
        if (marker.current) {
            marker.current.setDraggable(interactive);
        }
    }, [interactive]);

    return (
        <div className="relative notranslate" translate="no">
            <div
                ref={mapContainer}
                className="w-full rounded-lg border"
                style={{ height: `${height}px` }}
            />
            {interactive && (
                <div className="absolute top-2 left-2 z-10 rounded-md bg-white/90 px-3 py-2 text-xs font-medium shadow-md backdrop-blur">
                    {isDragging ? (
                        <span className="text-emerald-600">🎯 Đang di chuyển marker...</span>
                    ) : (
                        <span className="text-gray-700">
                            💡 Click vào bản đồ hoặc kéo marker để chọn vị trí chính xác
                        </span>
                    )}
                </div>
            )}
            {!isMapLoaded && (
                <div className="absolute inset-0 flex items-center justify-center bg-gray-50">
                    <div className="text-sm text-gray-500">Đang tải bản đồ...</div>
                </div>
            )}
        </div>
    );
}