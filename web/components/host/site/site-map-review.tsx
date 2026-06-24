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
    circleCenter?: { lat: number; lng: number; km: number };
    otherMarkers?: Array<{
        lat: number;
        lng: number;
        label: string;
        siteName?: string;
        image?: string;
    }>;
    propertyCenter?: {
        lat: number;
        lng: number;
        label: string;
    };
}

export default function MapPreview({ 
    lat, 
    lng, 
    zoom = 13, 
    height = 400,
    interactive = false,
    onLocationChange,
    circleCenter,
    otherMarkers = [],
    propertyCenter
}: MapPreviewProps) {
    const mapContainer = useRef<HTMLDivElement>(null);
    const map = useRef<mapboxgl.Map | null>(null);
    const marker = useRef<mapboxgl.Marker | null>(null);
    const otherMarkersRef = useRef<mapboxgl.Marker[]>([]);
    const propertyCenterMarkerRef = useRef<mapboxgl.Marker | null>(null);
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

        // Add main marker
        marker.current = new mapboxgl.Marker({ 
            color: '#ef4444', // Red for current site
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
            otherMarkersRef.current.forEach(m => m.remove());
            propertyCenterMarkerRef.current?.remove();
            map.current?.remove();
            map.current = null;
        };
    }, []); // Empty deps - only run once

    // Draw circle radius around property center
    useEffect(() => {
        if (!isMapLoaded || !map.current || !circleCenter) return;

        const sourceId = 'circle-radius';
        const layerId = 'circle-radius-layer';
        const outlineLayerId = 'circle-radius-outline';

        // Remove existing layers and source
        if (map.current.getLayer(outlineLayerId)) {
            map.current.removeLayer(outlineLayerId);
        }
        if (map.current.getLayer(layerId)) {
            map.current.removeLayer(layerId);
        }
        if (map.current.getSource(sourceId)) {
            map.current.removeSource(sourceId);
        }

        // Calculate circle points
        const points = 64;
        const distanceKm = circleCenter.km;
        const coordinates: [number, number][] = [];

        for (let i = 0; i <= points; i++) {
            const angle = (i * 360) / points;
            const radiusInDegrees = distanceKm / 111.32;

            const dx = radiusInDegrees * Math.cos((angle * Math.PI) / 180);
            const dy = radiusInDegrees * Math.sin((angle * Math.PI) / 180);

            coordinates.push([
                circleCenter.lng + dx,
                circleCenter.lat + dy,
            ]);
        }

        // Add source
        map.current.addSource(sourceId, {
            type: 'geojson',
            data: {
                type: 'Feature',
                properties: {},
                geometry: {
                    type: 'Polygon',
                    coordinates: [coordinates],
                },
            },
        });

        // Add fill layer
        map.current.addLayer({
            id: layerId,
            type: 'fill',
            source: sourceId,
            paint: {
                'fill-color': '#10b981',
                'fill-opacity': 0.1,
            },
        });

        // Add outline layer
        map.current.addLayer({
            id: outlineLayerId,
            type: 'line',
            source: sourceId,
            paint: {
                'line-color': '#10b981',
                'line-width': 2,
                'line-dasharray': [2, 2],
            },
        });
    }, [isMapLoaded, circleCenter]);

    // Render other sites markers
    useEffect(() => {
        if (!isMapLoaded || !map.current) return;

        // Remove existing other markers
        otherMarkersRef.current.forEach(m => m.remove());
        otherMarkersRef.current = [];

        // Add new other markers
        otherMarkers.forEach(({ lat: otherLat, lng: otherLng, label, siteName, image }) => {
            // Create custom element for marker with image
            const el = document.createElement('div');
            el.style.width = '40px';
            el.style.height = '40px';
            el.style.cursor = 'pointer';
            
            if (image) {
                // Marker with image
                el.innerHTML = `
                    <div style="
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        border: 3px solid #3b82f6;
                        overflow: hidden;
                        background: white;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                    ">
                        <img 
                            src="${image}" 
                            alt="${siteName || label}"
                            style="
                                width: 100%;
                                height: 100%;
                                object-fit: cover;
                            "
                            onerror="this.style.display='none'; this.parentElement.style.background='#3b82f6'; this.parentElement.innerHTML='<div style=\\"display:flex;align-items:center;justify-content:center;height:100%;color:white;font-weight:bold;font-size:16px\\">${(siteName || label).charAt(0).toUpperCase()}</div>';"
                        />
                    </div>
                `;
            } else {
                // Fallback marker without image
                el.innerHTML = `
                    <div style="
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        border: 3px solid #3b82f6;
                        background: #3b82f6;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: white;
                        font-weight: bold;
                        font-size: 16px;
                    ">${(siteName || label).charAt(0).toUpperCase()}</div>
                `;
            }

            const newMarker = new mapboxgl.Marker({
                element: el,
                draggable: false,
            })
                .setLngLat([otherLng, otherLat])
                .setPopup(
                    new mapboxgl.Popup({ offset: 25 })
                        .setHTML(`
                            <div style="min-width: 180px;">
                                ${image ? `
                                    <img 
                                        src="${image}" 
                                        alt="${siteName || label}"
                                        style="
                                            width: 100%;
                                            height: 100px;
                                            object-fit: cover;
                                            border-radius: 4px;
                                            margin-bottom: 8px;
                                        "
                                    />
                                ` : ''}
                                <div style="padding: 4px 0;">
                                    <div style="font-weight: 600; font-size: 13px; color: #1f2937; margin-bottom: 4px;">
                                        ${siteName || label}
                                    </div>
                                    <div style="font-size: 11px; color: #6b7280; margin-bottom: 2px;">
                                        📍 ${label}
                                    </div>
                                    <div style="font-size: 10px; color: #9ca3af;">
                                        ${otherLat.toFixed(6)}, ${otherLng.toFixed(6)}
                                    </div>
                                </div>
                            </div>
                        `)
                )
                .addTo(map.current!);

            otherMarkersRef.current.push(newMarker);
        });
    }, [isMapLoaded, otherMarkers]);

    // Render property center marker
    useEffect(() => {
        if (!isMapLoaded || !map.current) return;

        // Remove existing property center marker
        if (propertyCenterMarkerRef.current) {
            propertyCenterMarkerRef.current.remove();
            propertyCenterMarkerRef.current = null;
        }

        // Add property center marker if provided
        if (propertyCenter) {
            propertyCenterMarkerRef.current = new mapboxgl.Marker({ 
                color: '#10b981', // Green for property
                draggable: false 
            })
                .setLngLat([propertyCenter.lng, propertyCenter.lat])
                .setPopup(
                    new mapboxgl.Popup({ offset: 25 })
                        .setHTML(`
                            <div style="padding: 4px;">
                                <div style="font-weight: 600; font-size: 13px; color: #10b981; margin-bottom: 4px;">
                                    🏕️ ${propertyCenter.label}
                                </div>
                                <div style="font-size: 10px; color: #6b7280;">
                                    ${propertyCenter.lat.toFixed(6)}, ${propertyCenter.lng.toFixed(6)}
                                </div>
                            </div>
                        `)
                )
                .addTo(map.current!);
        }
    }, [isMapLoaded, propertyCenter]);

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