'use client';

import type { DateRangeType } from '@/components/search/date-range-picker';
import { LocationSearch, saveSearchToHistory } from '@/components/search/location-search';
import { SearchBar } from '@/components/search/search-bar';
import { GuestPopover } from '@/components/search/guest-popover';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';
import { Award, MapPin, Tent, Users, X, Search, Navigation, User } from 'lucide-react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { useState, useRef, useEffect } from 'react';

export default function HeroSection() {
  const router = useRouter();
  const [location, setLocation] = useState('');
  const [coordinates, setCoordinates] = useState<{
    lat: number;
    lng: number;
  }>();
  const [dateRange, setDateRange] = useState<DateRangeType>();
  const [guests, setGuests] = useState(0);
  const [childrenCount, setChildrenCount] = useState(0);
  const [pets, setPets] = useState(0);

  // Active Tab State
  const [activeTab, setActiveTab] = useState<'places' | 'roadtrip'>('places');

  // Roadtrip Search Bar States
  const [startQuery, setStartQuery] = useState('');
  const [startCoords, setStartCoords] = useState<{ lat: number; lng: number } | null>(null);
  const [startOpen, setStartOpen] = useState(false);

  const [endQuery, setEndQuery] = useState('');
  const [endCoords, setEndCoords] = useState<{ lat: number; lng: number } | null>(null);
  const [endOpen, setEndOpen] = useState(false);

  const handleRoadtripSearch = () => {
    if (!startQuery || !endQuery) {
      alert('Vui lòng nhập điểm xuất phát và điểm đến!');
      return;
    }
    const params = new URLSearchParams();
    params.set('fromCity', startQuery);
    params.set('toCity', endQuery);
    if (startCoords) {
      params.set('fromLat', startCoords.lat.toString());
      params.set('fromLng', startCoords.lng.toString());
    }
    if (endCoords) {
      params.set('toLat', endCoords.lat.toString());
      params.set('toLng', endCoords.lng.toString());
    }
    const totalGuests = guests + childrenCount;
    if (totalGuests) {
      params.set('guests', totalGuests.toString());
    }
    router.push(`/roadtrip?${params.toString()}`);
  };

  const handleSearch = () => {
    const params = new URLSearchParams();

    // Add coordinates if available (geospatial search)
    if (coordinates) {
      params.set('lat', coordinates.lat.toString());
      params.set('lng', coordinates.lng.toString());
      params.set('radius', '50'); // 50km radius
      // Save to recent searches with date and guest info
      const totalGuests = guests + childrenCount;
      saveSearchToHistory(
        location,
        coordinates,
        dateRange?.from ? format(dateRange.from, 'yyyy-MM-dd') : undefined,
        dateRange?.to ? format(dateRange.to, 'yyyy-MM-dd') : undefined,
        totalGuests || undefined,
      );
    }
    // Otherwise use city name for text-based search
    else if (location) {
      params.set('city', location);
    }

    if (dateRange?.from) {
      params.set('checkIn', format(dateRange.from, 'yyyy-MM-dd'));
    }
    if (dateRange?.to) {
      params.set('checkOut', format(dateRange.to, 'yyyy-MM-dd'));
    }
    const totalGuests = guests + childrenCount;
    if (totalGuests) params.set('minGuests', totalGuests.toString());

    router.push(`/search?${params.toString()}`);
  };

  const handleNearbyClick = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        position => {
          const { latitude, longitude } = position.coords;
          const coords = { lat: latitude, lng: longitude };
          setCoordinates(coords);
          setLocation('Vị trí hiện tại');
        },
        error => {
          console.error('Error getting location:', error);
          alert('Không thể lấy vị trí hiện tại');
        },
      );
    } else {
      alert('Trình duyệt không hỗ trợ định vị');
    }
  };

  return (
    <section className="relative min-h-[70vh] overflow-hidden">
      {/* Background Image */}
      {/* <div className="absolute inset-0">
        <Image
          src="/assets/images/landing-image-1.avif"
          alt="Camping in nature"
          fill
          sizes="100vw"
          className="object-cover"
          priority
        />
        <div className="absolute inset-0 bg-linear-to-b from-black/50 via-black/30 to-black/70" />
      </div> */}

      {/* Content */}
      <div className="relative z-10 mx-auto flex min-h-[70vh] max-w-7xl flex-col justify-center px-4">
        <div className="mb-12 text-center text-foreground">
          <h1 className="mb-6 font-bold">
            <div className="text-5xl lg:text-6xl leading-none">
              Đi đến bất cứ nơi nào bạn muốn.
            </div>

            <div className="mt-3 text-sm md:text-2xl">
              Tìm kiếm và đặt chỗ tại những địa điểm yêu thích,
            </div>

            <div className="mt-3 text-sm md:text-2xl">
              dễ dàng và thuận tiện.
            </div>
          </h1>
        </div>

        <div className="mx-10 rounded-2xl bg-white p-8 shadow-[0_12px_35px_rgba(0,0,0,0.12)] relative z-30">
          {/* Tabs */}
          <div className="mb-7 inline-flex rounded-full bg-[#efeee9] p-1">
            <button
              onClick={() => setActiveTab('places')}
              className={`rounded-full px-5 py-2 text-base font-bold transition-all duration-200 cursor-pointer ${
                activeTab === 'places'
                  ? 'bg-white text-[#2f2d24] shadow-xs'
                  : 'text-[#6b675d] hover:text-[#2f2d24]'
              }`}
            >
              Địa điểm
            </button>
            <button
              onClick={() => setActiveTab('roadtrip')}
              className={`rounded-full px-5 py-2 text-base font-bold transition-all duration-200 cursor-pointer ${
                activeTab === 'roadtrip'
                  ? 'bg-white text-[#2f2d24] shadow-xs'
                  : 'text-[#6b675d] hover:text-[#2f2d24]'
              }`}
            >
              Chuyến đi
            </button>
          </div>

          {/* Search Bar */}
          <div className="mx-auto w-full max-w-6xl">
            {activeTab === 'places' ? (
              <SearchBar
                location={location}
                onLocationChange={setLocation}
                onLocationSelect={(loc, coords) => {
                  setLocation(loc);
                  setCoordinates(coords);
                }}
                onNearbyClick={handleNearbyClick}
                dateRange={dateRange}
                onDateChange={setDateRange}
                guests={guests}
                childrenCount={childrenCount}
                pets={pets}
                onGuestsChange={setGuests}
                onChildrenChange={setChildrenCount}
                onPetsChange={setPets}
                onSearch={handleSearch}
                onRecentSearchDateSelect={(checkIn, checkOut) => {
                  setDateRange({
                    from: new Date(checkIn),
                    to: new Date(checkOut),
                  });
                }}
                onRecentSearchGuestsSelect={totalGuests => {
                  setGuests(totalGuests);
                  setChildrenCount(0);
                }}
              />
            ) : (
              <div className="flex flex-col md:flex-row w-full items-stretch gap-3 md:gap-4 bg-white md:bg-transparent rounded-xl md:border-none">
                {/* Starting location input */}
                <div className="relative flex-1">
                  <Popover open={startOpen} onOpenChange={setStartOpen}>
                    <PopoverTrigger asChild>
                      <button
                        className={cn(
                          'flex h-14 w-full cursor-pointer items-center gap-3 rounded-lg border border-gray-300 bg-white px-4 text-left shadow-xs transition-all hover:bg-white',
                          startOpen && 'border-gray-900 ring-2 ring-gray-900',
                        )}
                      >
                        <MapPin className="h-5 w-5 shrink-0 text-gray-700" />
                        <span className="truncate text-base text-gray-950 font-normal">
                          {startQuery || 'Điểm xuất phát...'}
                        </span>
                      </button>
                    </PopoverTrigger>
                    <PopoverContent
                      className="w-[var(--radix-popover-trigger-width)] md:w-[450px] p-4"
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

                {/* Where to? input */}
                <div className="relative flex-1">
                  <Popover open={endOpen} onOpenChange={setEndOpen}>
                    <PopoverTrigger asChild>
                      <button
                        className={cn(
                          'flex h-14 w-full cursor-pointer items-center gap-3 rounded-lg border border-gray-300 bg-white px-4 text-left shadow-xs transition-all hover:bg-white',
                          endOpen && 'border-gray-900 ring-2 ring-gray-900',
                        )}
                      >
                        <MapPin className="h-5 w-5 shrink-0 text-gray-700" />
                        <span className="truncate text-base text-gray-950 font-normal">
                          {endQuery || 'Điểm đến...'}
                        </span>
                      </button>
                    </PopoverTrigger>
                    <PopoverContent
                      className="w-[var(--radix-popover-trigger-width)] md:w-[450px] p-4"
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

                {/* Add guests input */}
                <div className="relative flex-1">
                  <GuestPopover
                    adults={guests || 1}
                    childrenCount={childrenCount}
                    pets={pets}
                    onAdultsChange={setGuests}
                    onChildrenChange={setChildrenCount}
                    onPetsChange={setPets}
                    buttonClassName="w-full h-14 border border-gray-300 bg-white rounded-lg px-4 flex items-center justify-start text-left text-base font-normal text-gray-900 hover:bg-white shadow-xs focus:ring-2 focus:ring-gray-900"
                    icon={<User className="mr-3 h-5 w-5 text-gray-700 shrink-0" />}
                    labels={{
                      guestsText: (guests: number) => guests > 0 ? `${guests} khách` : 'Thêm khách'
                    }}
                    showPets={false}
                  />
                </div>

                {/* Search button */}
                <div className="shrink-0 w-full md:w-auto">
                  <Button
                    onClick={handleRoadtripSearch}
                    className="w-full md:w-auto h-14 bg-[#f08569] hover:bg-[#e2765b] text-white rounded-lg px-8 text-lg font-bold shadow-md flex items-center justify-center gap-2 select-none hover:scale-[1.02] active:scale-[0.98] transition-all duration-150"
                  >
                    <Search className="h-5 w-5 text-white" />
                    <span>Tìm</span>
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
