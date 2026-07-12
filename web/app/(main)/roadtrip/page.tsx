'use client';

import React, { useState, useEffect, useRef } from 'react';
import dynamic from 'next/dynamic';
import Image from 'next/image';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import apiClient from '@/lib/api-client';
import type { Property } from '@/types/property-site';
import { FavoriteButton } from '@/components/property/FavoriteButton';
import { CompareButton } from '@/components/property/CompareButton';
import { SuperhostBadge } from '@/components/property/SuperhostBadge';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { GuestPopover } from '@/components/search/guest-popover';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { LocationSearch } from '@/components/search/location-search';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import {
  Eye,
  MapPin,
  Search,
  Route,
  Compass,
  Navigation,
  X,
  ArrowRight,
  Loader2,
  Calendar,
  Users
} from 'lucide-react';
import { format } from 'date-fns';

const MAPBOX_TOKEN = process.env.NEXT_PUBLIC_MAPBOX_TOKEN || '';

// Dynamically load Map component to prevent SSR failures
const RoadtripMap = dynamic(
  () => {
    console.log('RoadtripMap dynamic import started');
    return import('./RoadtripMap').then(mod => {
      console.log('RoadtripMap dynamic import completed, export exists:', !!mod.RoadtripMap);
      return mod.RoadtripMap;
    });
  },
  {
    ssr: false,
    loading: () => (
      <div className="flex h-full w-full items-center justify-center bg-gray-100 rounded-xl">
        <div className="text-center">
          <Loader2 className="mx-auto mb-4 h-8 w-8 animate-spin text-emerald-600" />
          <p className="text-sm text-gray-500 font-medium animate-pulse">Đang tải bản đồ...</p>
        </div>
      </div>
    ),
  },
);

interface Coordinates {
  lat: number;
  lng: number;
}

interface MapboxFeature {
  id: string;
  place_name: string;
  text: string;
  center: [number, number]; // [lng, lat]
  place_type: string[];
}

export default function RoadtripPage() {
  const searchParams = useSearchParams();

  // Route & Search state
  const [startQuery, setStartQuery] = useState('');
  const [startCoords, setStartCoords] = useState<Coordinates | null>(null);
  const [endQuery, setEndQuery] = useState('');
  const [endCoords, setEndCoords] = useState<Coordinates | null>(null);
  const [isSearchSheetOpen, setIsSearchSheetOpen] = useState(false);
  const [startOpen, setStartOpen] = useState(false);
  const [endOpen, setEndOpen] = useState(false);

  const [radius, setRadius] = useState('10'); // radius in km
  const [guests, setGuests] = useState<number>(1);
  const [childrenCount, setChildrenCount] = useState<number>(0);
  const [propertyType, setPropertyType] = useState<string>('all');

  // Loading and results states
  const [isSearchingRoute, setIsSearchingRoute] = useState(false);
  const [isSearchingProperties, setIsSearchingProperties] = useState(false);
  const [routeGeometry, setRouteGeometry] = useState<any | null>(null);
  const [routeInfo, setRouteInfo] = useState<{ distance: number; duration: number } | null>(null);
  const [properties, setProperties] = useState<Property[]>([]);
  const [searched, setSearched] = useState(false);
  const [shouldAutoSearch, setShouldAutoSearch] = useState(false);

  // Card interaction state
  const [selectedProperty, setSelectedProperty] = useState<Property | null>(null);
  const [hoveredProperty, setHoveredProperty] = useState<Property | null>(null);
  const [showMobileMap, setShowMobileMap] = useState(false);

  console.log('RoadtripPage rendering. startCoords:', startCoords, 'endCoords:', endCoords, 'showMobileMap:', showMobileMap);

  // Initialize query parameters if available
  useEffect(() => {
    const fromCity = searchParams.get('fromCity');
    const toCity = searchParams.get('toCity');
    const fromLat = searchParams.get('fromLat');
    const fromLng = searchParams.get('fromLng');
    const toLat = searchParams.get('toLat');
    const toLng = searchParams.get('toLng');
    const urlGuests = searchParams.get('guests');

    if (fromCity) setStartQuery(fromCity);
    if (toCity) setEndQuery(toCity);
    if (urlGuests) {
      const parsedGuests = parseInt(urlGuests);
      if (!isNaN(parsedGuests)) {
        setGuests(parsedGuests);
      }
    }

    if (fromLat && fromLng && toLat && toLng) {
      setStartCoords({ lat: parseFloat(fromLat), lng: parseFloat(fromLng) });
      setEndCoords({ lat: parseFloat(toLat), lng: parseFloat(toLng) });
      setShouldAutoSearch(true);
    }
  }, [searchParams]);

  useEffect(() => {
    if (shouldAutoSearch && startCoords && endCoords) {
      setShouldAutoSearch(false);
      handleSearch();
    }
  }, [shouldAutoSearch, startCoords, endCoords]);

  // Simplification helper: sample coordinates to maximum number of points
  const samplePoints = (coords: [number, number][], maxPoints = 25): [number, number][] => {
    if (coords.length <= maxPoints) return coords;
    const sampled: [number, number][] = [];
    const step = (coords.length - 1) / (maxPoints - 1);
    for (let i = 0; i < maxPoints; i++) {
      const index = Math.round(i * step);
      sampled.push(coords[index]);
    }
    return sampled;
  };

  // Run roadtrip planner search
  const handleSearch = async () => {
    if (!startCoords || !endCoords) {
      alert('Vui lòng chọn điểm bắt đầu và kết thúc từ danh sách gợi ý!');
      return;
    }

    setIsSearchingRoute(true);
    setIsSearchingProperties(true);
    setSearched(true);
    setSelectedProperty(null);

    try {
      // 1. Get driving direction from Mapbox Directions API
      const directionsUrl = `https://api.mapbox.com/directions/v5/mapbox/driving/${startCoords.lng},${startCoords.lat};${endCoords.lng},${endCoords.lat}?geometries=geojson&overview=full&access_token=${MAPBOX_TOKEN}`;
      const routeRes = await fetch(directionsUrl);
      if (!routeRes.ok) {
        throw new Error('Không thể tìm thấy tuyến đường di chuyển');
      }
      const routeData = await routeRes.json();
      if (!routeData.routes || routeData.routes.length === 0) {
        throw new Error('Không tìm thấy tuyến đường hợp lệ giữa hai điểm này');
      }

      const route = routeData.routes[0];
      setRouteGeometry(route.geometry);
      setRouteInfo({
        distance: route.distance, // in meters
        duration: route.duration, // in seconds
      });

      setIsSearchingRoute(false);

      // 2. Sample coordinates for backend post payload
      const allCoords: [number, number][] = route.geometry.coordinates;
      const sampledCoords = samplePoints(allCoords, 30);

      // 3. Post to backend `/properties/route-search` to query camping sites along the route
      const payload: any = {
        points: sampledCoords,
        radius: parseFloat(radius),
        guests: guests + childrenCount,
      };

      if (propertyType !== 'all') {
        payload.propertyType = propertyType;
      }

      const response: any = await apiClient.post('/properties/route-search', payload);

      // Filter out active properties only
      const results = response.data || [];
      const activeProperties = results.filter((p: any) => p.isActive);
      setProperties(activeProperties);
    } catch (err: any) {
      console.error(err);
      alert(err.message || 'Có lỗi xảy ra trong quá trình tìm kiếm lộ trình!');
    } finally {
      setIsSearchingRoute(false);
      setIsSearchingProperties(false);
    }
  };

  // Helper formatting styles
  const formatDistance = (m: number) => {
    return `${(m / 1000).toFixed(1)} km`;
  };

  const formatDuration = (s: number) => {
    const hrs = Math.floor(s / 3600);
    const mins = Math.round((s % 3600) / 60);
    if (hrs > 0) return `${hrs} giờ ${mins} phút`;
    return `${mins} phút`;
  };

  const getCoverPhoto = (property: Property) => {
    const coverPhoto = property.photos?.find((p: any) => p.isCover);
    if (coverPhoto) return coverPhoto.url;
    return property.photos?.[0]?.url || '/placeholder-campsite.jpg';
  };

  const formatPrice = (price: number) => {
    if (price >= 1000000) {
      return `${Math.round(price / 1000000)}tr `;
    } else if (price >= 1000) {
      return `${Math.round(price / 1000)}k `;
    }
    return `${price}`;
  };

  const getRouteDisplayText = () => {
    if (startQuery && endQuery) {
      return `${startQuery} đến ${endQuery}`;
    }
    if (startQuery) {
      return `Từ ${startQuery}...`;
    }
    if (endQuery) {
      return `Đến ${endQuery}...`;
    }
    return 'Lập lộ trình di chuyển...';
  };

  const getLandSizeDisplay = (property: Property) => {
    if (!property.landSize) return '101 acres';
    const { value, unit } = property.landSize;
    return `${value} ${unit === 'acres' ? 'acres' : unit === 'hectares' ? 'ha' : 'm²'}`;
  };

  const getPropertyTypeDisplay = (type: string) => {
    switch (type) {
      case 'private_land':
        return 'Đất tư nhân';
      case 'campground':
        return 'Khu cắm trại';
      case 'farm':
        return 'Trang trại';
      case 'ranch':
        return 'Trang trại chăn nuôi';
      default:
        return 'Khu nghỉ dưỡng';
    }
  };

  const formatViews = (n: number) => {
    if (n >= 1000000) return `${Math.floor(n / 1000000)}M`;
    if (n >= 1000) return `${Math.floor(n / 1000)}k`;
    return `${n}`;
  };

  const buildPropertyLink = (slug: string) => {
    const params = new URLSearchParams();
    const checkIn = searchParams.get('checkIn');
    const checkOut = searchParams.get('checkOut');
    const guests = searchParams.get('guests');
    const pets = searchParams.get('pets');

    if (checkIn) params.set('checkIn', checkIn);
    if (checkOut) params.set('checkOut', checkOut);
    if (guests) params.set('guests', guests);
    if (pets) params.set('pets', pets);

    const queryString = params.toString();
    return `/land/${slug}${queryString ? `?${queryString}` : ''}`;
  };

  return (
    <div className="flex flex-col min-h-[calc(100vh-64px)] bg-gray-50/50">

      {/* Premium Roadtrip Toolbar */}
      <div className="bg-white border-b border-gray-200/80 sticky top-0 z-20 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-3">
          <div className="flex flex-wrap items-center gap-3 justify-start">

            {/* Route Selector Button */}
            <button
              onClick={() => setIsSearchSheetOpen(true)}
              className="flex items-center gap-2 h-9 border border-gray-300 bg-white rounded-lg px-3 text-sm font-medium text-gray-700 hover:bg-gray-50 focus:ring-2 focus:ring-primary shadow-xs max-w-[240px] md:max-w-[280px] truncate shrink-0 cursor-pointer"
            >
              <MapPin className="h-4 w-4 text-gray-500 shrink-0" />
              <span className="truncate">{getRouteDisplayText()}</span>
            </button>

            {/* Radius Select */}
            <div className="w-full md:w-28">
              <Select value={radius} onValueChange={setRadius}>
                <SelectTrigger className="h-9 border-gray-300 bg-white rounded-lg text-sm font-medium">
                  <SelectValue placeholder="Bán kính" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">Dọc 5 km</SelectItem>
                  <SelectItem value="10">Dọc 10 km</SelectItem>
                  <SelectItem value="20">Dọc 20 km</SelectItem>
                  <SelectItem value="50">Dọc 50 km</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Property Type Filter */}
            <div className="w-full md:w-40">
              <Select value={propertyType} onValueChange={setPropertyType}>
                <SelectTrigger className="h-9 border-gray-300 bg-white rounded-lg text-sm font-medium">
                  <SelectValue placeholder="Loại hình" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tất cả loại hình</SelectItem>
                  <SelectItem value="campground">Khu cắm trại</SelectItem>
                  <SelectItem value="private_land">Đất tư nhân</SelectItem>
                  <SelectItem value="farm">Trang trại</SelectItem>
                  <SelectItem value="ranch">Trang trại vật nuôi</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Search Button */}
            <div className="w-full md:w-auto">
              <Button
                onClick={handleSearch}
                disabled={isSearchingRoute || isSearchingProperties}
                className="h-9 bg-[#d35422] hover:bg-[#be4315] text-white rounded-lg px-4 text-sm font-semibold flex items-center justify-center gap-1.5 transition-all select-none duration-150 border-none"
              >
                {isSearchingRoute || isSearchingProperties ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin text-white" />
                    <span>Đang tìm...</span>
                  </>
                ) : (
                  <>
                    <Search className="h-3.5 w-3.5" />
                    <span>Tìm</span>
                  </>
                )}
              </Button>
            </div>

          </div>
        </div>
      </div>

      {/* Top Search Drawer Sheet */}
      <Sheet open={isSearchSheetOpen} onOpenChange={setIsSearchSheetOpen}>
        <SheetContent side="top" className="h-auto py-6">
          <SheetHeader className="mb-4">
            <SheetTitle className="text-center text-lg font-bold text-gray-900">Tìm kiếm lộ trình</SheetTitle>
          </SheetHeader>

          <div className="mx-auto w-full max-w-5xl">
            <div className="flex flex-col md:flex-row w-full items-stretch gap-3 md:gap-4 bg-white p-2 rounded-xl">

              {/* Start point Autocomplete input */}
              <div className="relative flex-1">
                <Popover open={startOpen} onOpenChange={setStartOpen}>
                  <PopoverTrigger asChild>
                    <button
                      className={cn(
                        'flex h-11 w-full cursor-pointer items-center gap-3 rounded-lg border border-gray-300 bg-white px-4 text-left shadow-xs transition-all hover:bg-white',
                        startOpen && 'border-gray-900 ring-2 ring-gray-900',
                      )}
                    >
                      <MapPin className="h-4 w-4 shrink-0 text-gray-500" />
                      <span className="truncate text-sm text-gray-900 font-medium">
                        {startQuery || 'Điểm xuất phát...'}
                      </span>
                    </button>
                  </PopoverTrigger>
                  <PopoverContent
                    className="w-[var(--radix-popover-trigger-width)] md:w-[400px] p-4"
                    align="start"
                    sideOffset={8}
                  >
                    <LocationSearch
                      value={startQuery}
                      onChange={(value, coordinates) => {
                        setStartQuery(value);
                        if (coordinates) {
                          setStartCoords(coordinates);
                          setStartOpen(false);
                        }
                      }}
                      onClose={() => setStartOpen(false)}
                      placeholder="Tìm điểm xuất phát..."
                      showDropdown={false}
                      showInlineResults={true}
                    />
                  </PopoverContent>
                </Popover>
              </div>

              {/* End point Autocomplete input */}
              <div className="relative flex-1">
                <Popover open={endOpen} onOpenChange={setEndOpen}>
                  <PopoverTrigger asChild>
                    <button
                      className={cn(
                        'flex h-11 w-full cursor-pointer items-center gap-3 rounded-lg border border-gray-300 bg-white px-4 text-left shadow-xs transition-all hover:bg-white',
                        endOpen && 'border-gray-900 ring-2 ring-gray-900',
                      )}
                    >
                      <MapPin className="h-4 w-4 shrink-0 text-gray-500" />
                      <span className="truncate text-sm text-gray-900 font-medium">
                        {endQuery || 'Điểm đến...'}
                      </span>
                    </button>
                  </PopoverTrigger>
                  <PopoverContent
                    className="w-[var(--radix-popover-trigger-width)] md:w-[400px] p-4"
                    align="start"
                    sideOffset={8}
                  >
                    <LocationSearch
                      value={endQuery}
                      onChange={(value, coordinates) => {
                        setEndQuery(value);
                        if (coordinates) {
                          setEndCoords(coordinates);
                          setEndOpen(false);
                        }
                      }}
                      onClose={() => setEndOpen(false)}
                      placeholder="Tìm điểm đến..."
                      showDropdown={false}
                      showInlineResults={true}
                    />
                  </PopoverContent>
                </Popover>
              </div>

              {/* Guest Selector */}
              <div className="relative flex-1">
                <GuestPopover
                  adults={guests}
                  childrenCount={childrenCount}
                  pets={0}
                  onAdultsChange={setGuests}
                  onChildrenChange={setChildrenCount}
                  onPetsChange={() => { }}
                  buttonClassName="w-full h-11 border border-gray-300 bg-white rounded-lg px-4 flex items-center justify-start text-left text-sm font-medium text-gray-900 hover:bg-white shadow-xs focus:ring-2 focus:ring-primary cursor-pointer"
                  icon={<Users className="mr-3 h-4 w-4 text-gray-500 shrink-0" />}
                  labels={{
                    guestsText: (guests: number) => `${guests} khách`
                  }}
                  showPets={false}
                />
              </div>

              {/* Search Button */}
              <div className="shrink-0 w-full md:w-auto">
                <Button
                  onClick={() => {
                    handleSearch();
                    setIsSearchSheetOpen(false);
                  }}
                  disabled={isSearchingRoute || isSearchingProperties}
                  className="w-full md:w-auto h-11 bg-[#d35422] hover:bg-[#be4315] text-white rounded-lg px-6 text-sm font-bold shadow-md flex items-center justify-center gap-2 select-none hover:scale-[1.02] active:scale-[0.98] transition-all duration-150 border-none"
                >
                  <Search className="h-4 w-4 text-white" />
                  <span>Tìm</span>
                </Button>
              </div>

            </div>
          </div>
        </SheetContent>
      </Sheet>

      {/* Main Split View Container */}
      <div className="flex-1 flex flex-col lg:flex-row w-full items-stretch">

        {/* Left Side: Results Grid */}
        <div className={
          showMobileMap
            ? "hidden lg:flex lg:flex-1 bg-white px-6 py-4 flex-col"
            : "flex-1 bg-white px-6 py-4 flex flex-col"
        }>
          {/* Grid list of properties */}
          <div className="flex-1">
            {isSearchingProperties ? (
              // Loading skeletons
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3 py-4">
                {[...Array(6)].map((_, idx) => (
                  <div key={idx} className="border border-gray-100 rounded-2xl p-4 animate-pulse bg-gray-50/50 space-y-3">
                    <div className="w-full h-48 bg-gray-200 rounded-xl" />
                    <div className="space-y-2.5">
                      <div className="h-4 bg-gray-200 rounded w-3/4" />
                      <div className="h-3 bg-gray-200 rounded w-1/2" />
                      <div className="h-3 bg-gray-200 rounded w-5/6" />
                    </div>
                  </div>
                ))}
              </div>
            ) : properties.length > 0 ? (
              // Properties cards
              <div className="grid grid-cols-1 gap-4 py-6 md:grid-cols-2 lg:grid-cols-3">
                {properties.map(property => (
                  <Card
                    key={property._id}
                    onMouseEnter={() => setHoveredProperty(property)}
                    onMouseLeave={() => setHoveredProperty(null)}
                    onClick={() => setSelectedProperty(property)}
                    className={`relative cursor-pointer overflow-hidden border-none shadow-md transition-all hover:shadow-lg rounded-2xl flex flex-col justify-between ${selectedProperty?._id === property._id
                      ? 'ring-2 ring-primary bg-primary/[0.02]'
                      : ''
                      }`}
                  >

                    <Link href={buildPropertyLink(property.slug || property._id)} className="block h-full flex flex-col justify-between">
                      {/* Top image section */}
                      <div className="relative h-48 w-full overflow-hidden rounded-xl shrink-0">
                        <Image
                          src={getCoverPhoto(property)}
                          alt={property.name}
                          fill
                          className="object-cover transition-transform duration-300 hover:scale-105"
                          sizes="(max-width: 768px) 100vw, 33vw"
                        />

                        {/* Action buttons (top-left) */}
                        <div className="absolute top-3 left-3 z-20 flex gap-2">
                          <FavoriteButton
                            propertyId={property._id}
                            className="bg-white/90 backdrop-blur-xs hover:!bg-white h-8 w-8 p-0"
                          />
                          <CompareButton
                            propertyId={property._id}
                            className="bg-white/90 backdrop-blur-xs hover:!bg-white h-8 w-8 p-0"
                          />
                        </div>

                        {/* Views count badge */}
                        <div className="absolute top-3 right-3 z-20">
                          <Badge variant="outline" className="flex bg-white/90 backdrop-blur-xs text-gray-800 items-center gap-1.5 rounded-full px-2 py-1 text-xs shadow border-none">
                            <Eye className="h-3 w-3 text-gray-700" />
                            <span>
                              {formatViews(property.stats?.viewCount ?? property.viewCount ?? 0)}
                            </span>
                          </Badge>
                        </div>
                      </div>

                      {/* Bottom details section */}
                      <div className="space-y-1.5 p-4 flex-1 flex flex-col justify-between">
                        <div className="space-y-1.5">

                          {/* Rating + Superhost */}
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-1">
                              {property.stats?.averageRating && property.stats.averageRating > 0 ? (
                                <>
                                  <span className="text-base">👍</span>
                                  <span className="text-sm font-semibold text-gray-900">
                                    {Math.round((property.stats.averageRating / 5) * 100)}%
                                  </span>
                                  <span className="text-xs text-gray-500">
                                    ({property.stats.totalReviews || 0})
                                  </span>
                                </>
                              ) : (
                                <span className="text-xs text-gray-400">Chưa có đánh giá</span>
                              )}
                            </div>
                            {property.isSuperhost && (
                              <SuperhostBadge size="xs" showTooltip superhostSince={property.superhostSince} />
                            )}
                          </div>

                          {/* Title */}
                          <h3 className="text-base font-semibold text-gray-900 line-clamp-1">
                            {property.name}
                          </h3>

                          {/* Sites count + Property type */}
                          <p className="text-sm text-gray-600">
                            {property.stats?.totalSites || 0} địa điểm · {getPropertyTypeDisplay(property.propertyType)}
                          </p>

                          {/* Location */}
                          <p className="text-sm text-gray-500 truncate">
                            {getLandSizeDisplay(property)} · {property.location?.city}, {property.location?.state}
                          </p>

                          {/* Price */}
                          <div className="pt-0.5">
                            <span className="text-sm text-gray-500">từ </span>
                            <span className="text-base font-bold text-gray-900">
                              {property.minPrice ? formatPrice(property.minPrice) : '50k'}
                            </span>
                            <span className="text-sm text-gray-500"> / đêm</span>
                          </div>

                        </div>
                      </div>
                    </Link>
                  </Card>
                ))}
              </div>
            ) : (
              // Empty search state
              <div className="py-24 text-center space-y-4 max-w-md mx-auto">
                <div className="h-16 w-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto text-gray-400 shadow-inner">
                  <Compass className="h-8 w-8" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-base font-bold text-gray-900">
                    {searched ? 'Không tìm thấy địa điểm nào' : 'Lập kế hoạch cho chuyến đi phượt'}
                  </h3>
                  <p className="text-xs text-gray-500 leading-relaxed">
                    {searched
                      ? `Không có khu cắm trại nào trong bán kính ${radius}km dọc tuyến đường đã chọn. Hãy thử tăng bán kính tìm kiếm!`
                      : 'Chọn điểm khởi hành và điểm đến của bạn để tìm tất cả các khu cắm trại dọc theo lộ trình di chuyển.'
                    }
                  </p>
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Right Side: Compact Map Sidebar */}
        <div className={
          showMobileMap
            ? "block w-full h-[calc(100vh-145px)] relative"
            : "hidden lg:block lg:w-[400px] xl:w-[500px] shrink-0 border-l border-gray-200 bg-gray-100"
        }>
          {showMobileMap ? (
            <RoadtripMap
              properties={properties}
              selectedProperty={selectedProperty}
              hoveredProperty={hoveredProperty}
              startCoords={startCoords}
              endCoords={endCoords}
              routeGeometry={routeGeometry}
              onPropertySelect={setSelectedProperty}
            />
          ) : (
            <div className="sticky top-[61px] h-[calc(100vh-61px)] overflow-hidden">
              <RoadtripMap
                properties={properties}
                selectedProperty={selectedProperty}
                hoveredProperty={hoveredProperty}
                startCoords={startCoords}
                endCoords={endCoords}
                routeGeometry={routeGeometry}
                onPropertySelect={setSelectedProperty}
              />
            </div>
          )}
        </div>

      </div>

      {/* Floating Toggle Button for Mobile/Tablet */}
      <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-30 lg:hidden">
        <Button
          onClick={() => setShowMobileMap(!showMobileMap)}
          className="rounded-full bg-gray-900 text-white hover:bg-gray-800 shadow-lg px-5 py-6 font-semibold flex items-center gap-2 border-none cursor-pointer hover:scale-[1.02] active:scale-[0.98] transition-all"
        >
          {showMobileMap ? (
            <>
              <Eye className="h-4 w-4" />
              <span>Xem danh sách</span>
            </>
          ) : (
            <>
              <MapPin className="h-4 w-4" />
              <span>Xem bản đồ</span>
            </>
          )}
        </Button>
      </div>

    </div>
  );
}
