'use client';

import type { DateRangeType } from '@/components/search/date-range-picker';
import { saveSearchToHistory } from '@/components/search/location-search';
import { SearchBar } from '@/components/search/search-bar';
import { format } from 'date-fns';
import { Award, MapPin, Tent, Users } from 'lucide-react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { useState } from 'react';

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

        <div className="mx-10 rounded-2xl bg-white p-8 shadow-[0_12px_35px_rgba(0,0,0,0.12)]">
          {/* Tabs */}
          {/* <div className="mb-7 inline-flex rounded-full bg-[#efeee9] p-1">
            <button className="rounded-full bg-white px-4 text-lg font-bold text-[#2f2d24] shadow-sm">
              Địa điểm
            </button>
            <button className="rounded-full px-4 text-lg font-bold text-[#6b675d]">
              Chuyến đi
            </button>
          </div> */}

          {/* Search Bar */}
          <div className="mx-auto w-full max-w-6xl">
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
          </div>
        </div>
      </div>
    </section>
  );
}
