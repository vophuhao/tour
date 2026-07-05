'use client';

import { type DateRangeType } from '@/components/search/date-range-picker';
import { usePathname, useSearchParams } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';

/**
 * Custom hook to manage booking state (dates, guests, pets) synced with URL search params
 *
 * Optimized version:
 * - Uses client-side local state for instant rendering response.
 * - Syncs state across different instances of this hook on the same page using custom events.
 * - Updates the browser URL instantly using window.history.replaceState to avoid slow
 *   Next.js server-side re-renders on every click.
 * - Handles browser history navigation (back/forward) using popstate event.
 */

interface UsePropertyBookingStateOptions {
  initialGuests?: number;
  initialPets?: number;
  initialCheckIn?: string;
  initialCheckOut?: string;
}

// Custom event for cross-component hook state synchronization
const BOOKING_STATE_EVENT = 'camp-booking-state-changed';

export function usePropertyBookingState(
  options: UsePropertyBookingStateOptions = {},
) {
  const {
    initialGuests = 2,
    initialPets = 0,
    initialCheckIn,
    initialCheckOut,
  } = options;

  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Helper to parse dates from search parameters
  const parseDateRange = useCallback((params: URLSearchParams) => {
    const checkIn = params.get('checkIn') || initialCheckIn;
    const checkOut = params.get('checkOut') || initialCheckOut;

    if (checkIn && checkOut) {
      try {
        const checkInParts = checkIn.split('-').map(Number);
        const checkOutParts = checkOut.split('-').map(Number);

        if (
          checkInParts.length === 3 &&
          checkOutParts.length === 3 &&
          !checkInParts.some(isNaN) &&
          !checkOutParts.some(isNaN)
        ) {
          const [fromYear, fromMonth, fromDay] = checkInParts;
          const [toYear, toMonth, toDay] = checkOutParts;

          const fromDate = new Date(fromYear, fromMonth - 1, fromDay);
          const toDate = new Date(toYear, toMonth - 1, toDay);

          if (!isNaN(fromDate.getTime()) && !isNaN(toDate.getTime())) {
            return {
              from: fromDate,
              to: toDate,
            };
          }
        }
      } catch (error) {
        console.error('Error parsing date range:', error);
      }
    }
    return undefined;
  }, [initialCheckIn, initialCheckOut]);

  // Helper to parse guests count from search parameters
  const parseGuests = useCallback((params: URLSearchParams) => {
    const param = params.get('guests');
    return param ? parseInt(param, 10) : initialGuests;
  }, [initialGuests]);

  // Helper to parse pets count from search parameters
  const parsePets = useCallback((params: URLSearchParams) => {
    const param = params.get('pets');
    return param ? parseInt(param, 10) : initialPets;
  }, [initialPets]);

  // Get current active URL params (fallback to fallback searchParams if server-side)
  const getSearchParams = useCallback(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search);
    }
    return new URLSearchParams(searchParams.toString());
  }, [searchParams]);

  // Initialize local states from current query parameters
  const [dateRange, setLocalDateRange] = useState<DateRangeType | undefined>(() =>
    parseDateRange(getSearchParams()),
  );
  const [guests, setLocalGuests] = useState<number>(() =>
    parseGuests(getSearchParams()),
  );
  const [pets, setLocalPets] = useState<number>(() =>
    parsePets(getSearchParams()),
  );

  // Helper to update browser URL and dispatch synchronization event
  const updateUrlAndNotify = useCallback(
    (newDateRange: DateRangeType | undefined, newGuests: number, newPets: number) => {
      if (typeof window === 'undefined') return;

      const params = new URLSearchParams(window.location.search);

      // 1. Update dates
      if (newDateRange?.from && newDateRange?.to) {
        const formatLocalDate = (date: Date) => {
          const year = date.getFullYear();
          const month = String(date.getMonth() + 1).padStart(2, '0');
          const day = String(date.getDate()).padStart(2, '0');
          return `${year}-${month}-${day}`;
        };
        params.set('checkIn', formatLocalDate(newDateRange.from));
        params.set('checkOut', formatLocalDate(newDateRange.to));
      } else {
        params.delete('checkIn');
        params.delete('checkOut');
      }

      // 2. Update guests count
      if (newGuests > 0) {
        params.set('guests', newGuests.toString());
      } else {
        params.delete('guests');
      }

      // 3. Update pets count
      if (newPets > 0) {
        params.set('pets', newPets.toString());
      } else {
        params.delete('pets');
      }

      // Update browser URL bar instantly without server navigation round-trip
      const newUrl = `${pathname}${params.toString() ? '?' + params.toString() : ''}`;
      window.history.replaceState(null, '', newUrl);

      // Notify all other instances of this custom hook on the page to synchronize
      window.dispatchEvent(
        new CustomEvent(BOOKING_STATE_EVENT, {
          detail: { dateRange: newDateRange, guests: newGuests, pets: newPets },
        }),
      );
    },
    [pathname],
  );

  // Setters exposed to the consumer
  const setDateRange = useCallback(
    (newRange: DateRangeType | undefined) => {
      setLocalDateRange(newRange);
      updateUrlAndNotify(newRange, guests, pets);
    },
    [guests, pets, updateUrlAndNotify],
  );

  const setGuests = useCallback(
    (newGuests: number) => {
      setLocalGuests(newGuests);
      updateUrlAndNotify(dateRange, newGuests, pets);
    },
    [dateRange, pets, updateUrlAndNotify],
  );

  const setPets = useCallback(
    (newPets: number) => {
      setLocalPets(newPets);
      updateUrlAndNotify(dateRange, guests, newPets);
    },
    [dateRange, guests, updateUrlAndNotify],
  );

  // Synchronize state across hooks on events or browser navigation
  useEffect(() => {
    const handleSync = (event: Event) => {
      const customEvent = event as CustomEvent;
      const { dateRange: d, guests: g, pets: p } = customEvent.detail;
      setLocalDateRange(d);
      setLocalGuests(g);
      setLocalPets(p);
    };

    const handlePopState = () => {
      const params = new URLSearchParams(window.location.search);
      setLocalDateRange(parseDateRange(params));
      setLocalGuests(parseGuests(params));
      setLocalPets(parsePets(params));
    };

    window.addEventListener(BOOKING_STATE_EVENT, handleSync);
    window.addEventListener('popstate', handlePopState);

    return () => {
      window.removeEventListener(BOOKING_STATE_EVENT, handleSync);
      window.removeEventListener('popstate', handlePopState);
    };
  }, [parseDateRange, parseGuests, parsePets]);

  return {
    dateRange,
    guests,
    pets,
    setDateRange,
    setGuests,
    setPets,
    isPending: false, // Compatibility fallback
  };
}
