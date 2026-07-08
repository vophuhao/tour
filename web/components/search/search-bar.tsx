'use client';

import { Calendar, MapPin, Search, Users } from 'lucide-react';
import { useState } from 'react';

import { Button } from '@/components/ui/button';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';

import { cn } from '@/lib/utils';
import { type DateRangeType } from './date-range-picker';
import { DateRangePopover } from './date-range-popover';
import { GuestPopover } from './guest-popover';
import { LocationSearch } from './location-search';

interface SearchBarProps {
  location: string;
  onLocationChange: (value: string) => void;
  onLocationSelect?: (
    location: string,
    coordinates?: { lat: number; lng: number },
  ) => void;
  onNearbyClick?: () => void;
  dateRange?: DateRangeType;
  onDateChange: (date?: DateRangeType) => void;
  guests: number;
  childrenCount: number;
  pets: number;
  onGuestsChange: (value: number) => void;
  onChildrenChange: (value: number) => void;
  onPetsChange: (value: number) => void;
  onSearch: () => void;
  loading?: boolean;
  onRecentSearchDateSelect?: (checkIn: string, checkOut: string) => void;
  onRecentSearchGuestsSelect?: (guests: number) => void;
}

export function SearchBar({
  location,
  onLocationChange,
  onLocationSelect,
  onNearbyClick,
  dateRange,
  onDateChange,
  guests,
  childrenCount,
  pets,
  onGuestsChange,
  onChildrenChange,
  onPetsChange,
  onSearch,
  loading = false,
  onRecentSearchDateSelect,
  onRecentSearchGuestsSelect,
}: SearchBarProps) {
  const [locationOpen, setLocationOpen] = useState(false);
  const [dateOpen, setDateOpen] = useState(false);
  const [guestOpen, setGuestOpen] = useState(false);

  return (
    <div className="w-full max-w-6xl">
      {/* Search Bar - Hipcamp Style */}
      <div className="flex flex-col md:flex-row w-full items-stretch gap-3 md:gap-4 bg-white md:bg-transparent p-4 md:p-0 rounded-xl border border-gray-200 md:border-none shadow-sm md:shadow-none">
        {/* Location Popover */}
        <Popover open={locationOpen} onOpenChange={setLocationOpen}>
          <PopoverTrigger asChild>
            <button
              className={cn(
                'flex flex-1 cursor-pointer items-center gap-3 rounded-lg border border-gray-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-3 text-left shadow-sm transition-all hover:shadow-md w-full text-gray-900 dark:text-slate-100',
                locationOpen && 'border-gray-900 dark:border-slate-100 ring-2 ring-gray-900 dark:ring-slate-100',
              )}
            >
              <MapPin className="h-5 w-5 shrink-0 text-gray-700 dark:text-slate-400" />
              <span className="truncate text-base text-gray-900 dark:text-slate-100">
                {location || 'Tìm địa điểm'}
              </span>
            </button>
          </PopoverTrigger>
          <PopoverContent
            className="w-[var(--radix-popover-trigger-width)] md:w-[500px] p-0"
            align="start"
            sideOffset={8}
          >
            {/* LocationSearch with inline results */}
            <div className="p-4">
              <LocationSearch
                value={location}
                onChange={(value, coordinates) => {
                  onLocationChange(value);
                  if (coordinates && onLocationSelect) {
                    onLocationSelect(value, coordinates);
                  }
                }}
                onNearbyClick={() => {
                  onNearbyClick?.();
                  setLocationOpen(false);
                }}
                onClose={() => setLocationOpen(false)}
                showDropdown={false}
                showInlineResults={true}
                placeholder="Tìm địa điểm"
                className="w-full"
                onDateRangeSelect={onRecentSearchDateSelect}
                onGuestsSelect={onRecentSearchGuestsSelect}
              />
            </div>
          </PopoverContent>
        </Popover>

        {/* Date Popover */}
        <DateRangePopover
          dateRange={dateRange}
          onDateChange={onDateChange}
          open={dateOpen}
          onOpenChange={setDateOpen}
          placeholder="Thêm ngày"
          buttonClassName={cn(
            'h-auto flex-1 gap-3 rounded-lg border border-gray-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-3 shadow-sm hover:shadow-md w-full text-gray-900 dark:text-slate-100',
            dateOpen && 'border-gray-900 dark:border-slate-100 ring-2 ring-gray-900 dark:ring-slate-100',
          )}
          align="center"
          dateFormat="d MMM"
          icon={<Calendar className="h-5 w-5 shrink-0 text-gray-700 dark:text-slate-400" />}
        />

        {/* Guest Popover */}
        <GuestPopover
          adults={guests}
          childrenCount={childrenCount}
          pets={pets}
          onAdultsChange={onGuestsChange}
          onChildrenChange={onChildrenChange}
          onPetsChange={onPetsChange}
          open={guestOpen}
          onOpenChange={setGuestOpen}
          buttonClassName={cn(
            'h-auto flex-1 gap-3 rounded-lg border border-gray-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-3 shadow-sm hover:shadow-md w-full text-gray-900 dark:text-slate-100',
            guestOpen && 'border-gray-900 dark:border-slate-100 ring-2 ring-gray-900 dark:ring-slate-100',
          )}
          align="end"
          icon={<Users className="h-5 w-5 shrink-0 text-gray-700 dark:text-slate-400" />}
          labels={{
            guestsText: guests => {
              const total = guests;
              if (total === 0) return 'Thêm khách';
              return `${total} khách`;
            },
          }}
        />

        {/* Search Button */}
        <Button
          size="lg"
          className="bg-primary hover:brightness-80 h-auto cursor-pointer rounded-lg px-8 py-3 text-base font-semibold w-full md:w-auto"
          onClick={onSearch}
          disabled={loading}
        >
          <Search className="h-5 w-5 text-white" />
          <span className="text-white">Tìm</span>
        </Button>
      </div>
    </div>
  );
}
