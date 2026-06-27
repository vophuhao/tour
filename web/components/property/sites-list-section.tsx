'use client';

import LoginPromptDialog from '@/components/auth/login-prompt-dialog';
import { useAuthStore } from '@/store/auth.store';

import { DateRangePopover } from '@/components/search/date-range-popover';
import { GuestPopover } from '@/components/search/guest-popover';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { usePropertyBookingState } from '@/hooks/usePropertyBookingState';
import { getBlockedDates } from '@/lib/client-actions';
import { getPropertyBlockedDates, getPropertyWithSites } from '@/lib/property-site-api';
import type { Property, Site } from '@/types/property-site';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSocket } from '@/provider/socketProvider';
import { differenceInDays, parseISO } from 'date-fns';
import useEmblaCarousel from 'embla-carousel-react';
import {
  CalendarIcon,
  Car,
  ChevronLeft,
  ChevronRight,
  Dog,
  Flame,
  TreePine,
  Users,
  Utensils,
  Wifi,
  Zap,
} from 'lucide-react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';

const SiteMap = dynamic(
  () => import('@/components/property/site-map').then(mod => mod.SiteMap),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-full w-full items-center justify-center bg-gray-100">
        <div className="text-center">
          <Skeleton className="mx-auto mb-4 h-12 w-12 rounded-full" />
          <p className="text-sm text-gray-500">Đang tải bản đồ...</p>
        </div>
      </div>
    ),
  },
);

interface SiteImageSliderProps {
  photos: Array<{ url: string; isCover?: boolean }>;
  name: string;
}

function SiteImageSlider({ photos, name }: SiteImageSliderProps) {
  const [currentIndex, setCurrentIndex] = useState(0);

  if (!photos || photos.length === 0) {
    return <div className="h-full w-full bg-gray-100 rounded-lg" />;
  }

  const handlePrev = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    setCurrentIndex((prev) => (prev === 0 ? photos.length - 1 : prev - 1));
  };

  const handleNext = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    setCurrentIndex((prev) => (prev === photos.length - 1 ? 0 : prev + 1));
  };

  return (
    <div className="relative h-full w-full group overflow-hidden rounded-lg">
      <img
        src={photos[currentIndex].url}
        alt={`${name} - Ảnh ${currentIndex + 1}`}
        className="h-full w-full object-cover transition-all duration-300"
        loading="lazy"
      />

      {photos.length > 1 && (
        <>
          {/* Navigation Arrows */}
          <button
            onClick={handlePrev}
            className="absolute left-2 top-1/2 -translate-y-1/2 flex h-7 w-7 items-center justify-center rounded-full bg-black/40 hover:bg-black/60 text-white opacity-0 group-hover:opacity-100 transition-all duration-200 shadow-sm"
            type="button"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button
            onClick={handleNext}
            className="absolute right-2 top-1/2 -translate-y-1/2 flex h-7 w-7 items-center justify-center rounded-full bg-black/40 hover:bg-black/60 text-white opacity-0 group-hover:opacity-100 transition-all duration-200 shadow-sm"
            type="button"
          >
            <ChevronRight className="h-4 w-4" />
          </button>

          {/* Dots Indicator */}
          <div className="absolute bottom-2 left-1/2 -translate-x-1/2 flex gap-1 rounded-full bg-black/30 px-2 py-1 backdrop-blur-sm">
            {photos.map((_, idx) => (
              <span
                key={idx}
                className={`h-1 w-1 rounded-full transition-all ${idx === currentIndex ? 'bg-white scale-125' : 'bg-white/55'
                  }`}
              />
            ))}
          </div>

          {/* Badge count */}
          <div className="absolute right-2 top-2 rounded-full bg-black/50 px-2 py-0.5 text-[9px] font-medium text-white backdrop-blur-sm">
            {currentIndex + 1}/{photos.length}
          </div>
        </>
      )}
    </div>
  );
}

function calculateSiteSubtotal(site: Site, checkIn: Date, checkOut: Date) {
  const basePrice = site.pricing.basePrice;
  const weekendPrice = site.pricing.weekendPrice ?? null;
  let subtotal = 0;
  let hasWeekendPrice = false;
  let hasSeasonalPrice = false;
  let hasLongStayDiscount = false;
  let discountPercent = 0;

  const currentDate = new Date(checkIn);
  while (currentDate < checkOut) {
    const dayOfWeek = currentDate.getDay();
    const isWeekend = dayOfWeek === 5 || dayOfWeek === 6; // Friday & Saturday

    let nightPrice = basePrice;
    let isSeasonal = false;

    // Seasonal price has highest priority
    if (site.pricing.seasonalPricing && site.pricing.seasonalPricing.length > 0) {
      const seasonalRate = site.pricing.seasonalPricing.find((season: any) => {
        const seasonStart = new Date(season.startDate);
        const seasonEnd = new Date(season.endDate);

        // Compare dates without time
        const currentZero = new Date(currentDate);
        currentZero.setHours(0, 0, 0, 0);
        const startZero = new Date(seasonStart);
        startZero.setHours(0, 0, 0, 0);
        const endZero = new Date(seasonEnd);
        endZero.setHours(0, 0, 0, 0);

        return currentZero >= startZero && currentZero <= endZero;
      });

      if (seasonalRate) {
        nightPrice = seasonalRate.price;
        isSeasonal = true;
        hasSeasonalPrice = true;
      }
    }

    // Weekend price applied if not overridden by seasonal price
    if (!isSeasonal && isWeekend && weekendPrice !== null && weekendPrice > 0) {
      nightPrice = weekendPrice;
      hasWeekendPrice = true;
    }

    subtotal += nightPrice;
    currentDate.setDate(currentDate.getDate() + 1);
  }

  // Apply discounts
  const nights = Math.round(
    (checkOut.getTime() - checkIn.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (nights >= 28 && site.pricing.monthlyDiscount) {
    discountPercent = site.pricing.monthlyDiscount;
    hasLongStayDiscount = true;
  } else if (nights >= 7 && site.pricing.weeklyDiscount) {
    discountPercent = site.pricing.weeklyDiscount;
    hasLongStayDiscount = true;
  }
  if (discountPercent > 0) {
    subtotal = Math.round(subtotal * (1 - discountPercent / 100));
  }

  return {
    subtotal,
    hasWeekendPrice,
    hasSeasonalPrice,
    hasLongStayDiscount,
    discountPercent,
  };
}

interface SitesListSectionProps {
  sites: Site[];
  property: Property;
  propertySlug?: string;
  initialCheckIn?: string;
  initialCheckOut?: string;
  initialGuests?: number;
  initialPets?: number;
}

export function SitesListSection({
  sites: initialSites,
  property: initialProperty,
  propertySlug,
  initialCheckIn,
  initialCheckOut,
  initialGuests = 2,
  initialPets = 0,
}: SitesListSectionProps) {
  const queryClient = useQueryClient();
  const { socket } = useSocket();

  // Dynamic fetch of property and sites to allow background refresh when host updates them
  const { data: propertyWithSitesData } = useQuery<{ property: Property; sites: Site[]; siteCount: number }>({
    queryKey: ['property-with-sites', initialProperty._id],
    queryFn: () => getPropertyWithSites(initialProperty._id) as any,
    initialData: { property: initialProperty, sites: initialSites, siteCount: initialSites.length },
    staleTime: 5 * 60 * 1000,
  });

  const property = propertyWithSitesData.property;
  const sites = propertyWithSitesData.sites;

  // Use shared booking state from URL
  const booking = usePropertyBookingState({
    initialGuests,
    initialPets,
    initialCheckIn,
    initialCheckOut,
  });

  // Local UI state only
  // Sync initial values from booking.guests (which comes from URL)
  const [adults, setAdults] = useState(() => Math.max(1, booking.guests));
  const [children, setChildren] = useState(0);
  const [datePopoverOpen, setDatePopoverOpen] = useState(false);
  const [guestPopoverOpen, setGuestPopoverOpen] = useState(false);
  const [showLoginPrompt, setShowLoginPrompt] = useState(false);

  // Ref for scrolling to date selector
  const dateRangeRef = useRef<HTMLDivElement>(null);

  // Embla carousel for suggested sites
  const [emblaRef, emblaApi] = useEmblaCarousel({
    align: 'start',
    slidesToScroll: 1,
    containScroll: 'trimSnaps',
  });
  const [canScrollPrev, setCanScrollPrev] = useState(false);
  const [canScrollNext, setCanScrollNext] = useState(false);

  const onSelect = useCallback(() => {
    if (!emblaApi) return;
    setCanScrollPrev(emblaApi.canScrollPrev());
    setCanScrollNext(emblaApi.canScrollNext());
  }, [emblaApi]);

  useEffect(() => {
    if (!emblaApi) return;
    onSelect();
    emblaApi.on('select', onSelect);
    emblaApi.on('reInit', onSelect);
  }, [emblaApi, onSelect]);

  // Helper to get amenity icon
  const getAmenityIcon = (amenityName: string) => {
    const name = amenityName.toLowerCase();
    if (name.includes('wifi') || name.includes('internet'))
      return <Wifi className="h-3.5 w-3.5" />;
    if (name.includes('điện') || name.includes('electric'))
      return <Zap className="h-3.5 w-3.5" />;
    if (name.includes('lửa') || name.includes('fire') || name.includes('bếp'))
      return <Flame className="h-3.5 w-3.5" />;
    if (name.includes('cây') || name.includes('tree') || name.includes('shade'))
      return <TreePine className="h-3.5 w-3.5" />;
    if (
      name.includes('ăn') ||
      name.includes('food') ||
      name.includes('kitchen')
    )
      return <Utensils className="h-3.5 w-3.5" />;
    if (
      name.includes('xe') ||
      name.includes('parking') ||
      name.includes('vehicle')
    )
      return <Car className="h-3.5 w-3.5" />;
    if (name.includes('pet') || name.includes('thú'))
      return <Dog className="h-3.5 w-3.5" />;
    return <span className="text-emerald-600">•</span>;
  };

  // Sync local adults state when booking.guests changes from URL
  useEffect(() => {
    if (booking.guests !== adults + children) {
      // Update adults only if total changed (preserve children if possible)
      const newAdults = Math.max(1, booking.guests - children);
      setAdults(newAdults);
    }
  }, [booking.guests]); // Only run when URL guests changes



  // Filter State
  const [filterType] = useState<string | null>(null);
  const [petsAllowed, setPetsAllowed] = useState(false);
  const [instantBook, setInstantBook] = useState(false);
  const [selectedSite, setSelectedSite] = useState<Site | null>(null);
  const [hoveredSite, setHoveredSite] = useState<Site | null>(null);

  // Sync adults+children to URL guests
  const handleGuestsChange = (newAdults: number, newChildren: number) => {
    setAdults(newAdults);
    setChildren(newChildren);
    booking.setGuests(newAdults + newChildren);
  };

  // Handle "Đặt ngay" click when no dates selected
  const handleBookNowClick = (e: React.MouseEvent) => {
    // If user hasn't selected dates, prompt them to pick dates
    if (!booking.dateRange?.from || !booking.dateRange?.to) {
      e.preventDefault();
      // Scroll to date selector
      dateRangeRef.current?.scrollIntoView({
        behavior: 'smooth',
        block: 'center',
      });
      // Open date popover after a brief delay for smooth UX
      setTimeout(() => {
        setDatePopoverOpen(true);
      }, 500);
      return;
    }

    // If user is not authenticated, prevent navigation and open login dialog
    const isAuthenticated = useAuthStore.getState().isAuthenticated;
    if (!isAuthenticated) {
      e.preventDefault();
      setShowLoginPrompt(true);
      return;
    }
  };

  const nights =
    booking.dateRange?.from && booking.dateRange?.to
      ? differenceInDays(booking.dateRange.to, booking.dateRange.from)
      : 1;

  // Create a map of site ID to reason why it's unavailable (if any)
  const siteUnavailableReason = useMemo(() => {
    const map = new Map<string, string>();
    if (!booking.dateRange?.from || !booking.dateRange?.to) {
      return map;
    }

    sites.forEach(site => {
      // Check booking settings
      const { minimumNights, maximumNights } = site.bookingSettings;

      if (minimumNights && nights < minimumNights) {
        map.set(site._id, `Tối thiểu ${minimumNights} đêm`);
      } else if (maximumNights && nights > maximumNights) {
        map.set(site._id, `Tối đa ${maximumNights} đêm`);
      }

      // Check advance notice requirement
      // const advanceNoticeHours = property.settings?.minimumAdvanceNotice ?? 24;
      // const now = new Date();
      // const checkInTime = new Date(booking.dateRange.from);
      // const hoursDiff =
      //   (checkInTime.getTime() - now.getTime()) / (1000 * 60 * 60);

      // if (hoursDiff < advanceNoticeHours) {
      //   const daysNotice = Math.ceil(advanceNoticeHours / 24);
      //   map.set(site._id, `Cần đặt trước ${daysNotice} ngày`);
      // }

      // // Check booking window
      // const bookingWindowDays = property.settings?.bookingWindow ?? 365;
      // const daysDiff =
      //   (checkInTime.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

      // if (daysDiff > bookingWindowDays) {
      //   map.set(site._id, `Chỉ đặt trong ${bookingWindowDays} ngày`);
      // }
    });

    return map;
  }, [sites, booking.dateRange, nights, property.settings]);

  // Accommodation type labels
  const typeLabels: Record<string, string> = {
    tent: 'Lều',
    rv: 'Xe RV / nhà di động',
    cabin: 'Nhà gỗ',
    yurt: 'Nhà lều Mông Cổ (Yurt)',
    treehouse: 'Nhà trên cây',
    tiny_home: 'Nhà tí hon',
    safari_tent: 'Lều safari',
    bell_tent: 'Lều chuông (Bell tent)',
    glamping_pod: 'Nhà glamping (Glamping pod)',
    dome: 'Nhà mái vòm',
    airstream: 'Xe kéo Airstream',
    vintage_trailer: 'Xe kéo cổ (Vintage trailer)',
    van: 'Xe van cắm trại',
  };

  // Get max capacity from sites
  const maxCapacity = useMemo(() => {
    if (sites.length === 0) return { maxGuests: 20, maxPets: 5 };
    const maxGuests = Math.max(...sites.map(s => s.capacity.maxGuests || 20));
    const maxPets = Math.max(...sites.map(s => s.capacity.maxPets || 0));
    return { maxGuests, maxPets };
  }, [sites]);

  // Auto-detect if this is undesignated property
  const isUndesignated = useMemo(() => {
    return sites.some(site => (site.capacity.maxConcurrentBookings ?? 1) > 1);
  }, [sites]);

  // Collect all site IDs to check their availability
  const siteIdsForAvailability = useMemo(() => {
    if (sites.length > 0) {
      return sites.filter(s => s.isActive).map(s => s._id);
    }
    return [];
  }, [sites]);

  // Listen for real-time changes
  useEffect(() => {
    if (!socket) return;

    const handlePropertyChange = (payload: { propertyId: string }) => {
      if (payload.propertyId === property._id) {
        if (process.env.NODE_ENV === 'development') {
          console.log(`[SOCKET] Property changed: ${payload.propertyId}. Invalidate queries...`);
        }
        queryClient.invalidateQueries({
          queryKey: ['property-with-sites', property._id],
        });
        queryClient.invalidateQueries({
          queryKey: ['property-blocked-dates', property._id],
        });
        queryClient.invalidateQueries({
          queryKey: ['site-blocked-dates', siteIdsForAvailability],
        });
        queryClient.invalidateQueries({
          queryKey: ['site-selected-dates-blocked', siteIdsForAvailability],
        });
      }
    };

    socket.on('property_data_changed', handlePropertyChange);

    return () => {
      socket.off('property_data_changed', handlePropertyChange);
    };
  }, [socket, property._id, siteIdsForAvailability, queryClient]);

  // Fetch blocked dates for a 6-month window from today (for calendar display)
  const availabilityWindow = useMemo(() => {
    const today = new Date();
    const sixMonthsLater = new Date();
    sixMonthsLater.setMonth(today.getMonth() + 6);
    return {
      checkIn: today.toISOString(),
      checkOut: sixMonthsLater.toISOString(),
    };
  }, []);

  // Fetch blocked dates for each site
  const { data: siteAvailabilities } = useQuery({
    queryKey: ['site-blocked-dates', siteIdsForAvailability],
    queryFn: async () => {
      if (siteIdsForAvailability.length === 0) return [];
      const results = await Promise.all(
        siteIdsForAvailability.map(siteId =>
          getBlockedDates(
            siteId,
            availabilityWindow.checkIn,
            availabilityWindow.checkOut,
          ),
        ),
      );
      return results;
    },
    enabled: siteIdsForAvailability.length > 0,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Fetch property-level blocked dates for THIS property only
  const { data: propertyBlockedDates = [] } = useQuery({
    queryKey: ['property-blocked-dates', property._id],
    queryFn: () => getPropertyBlockedDates(property._id),
    enabled: !!property._id,
    staleTime: 5 * 60 * 1000,
  });

  // Convert property-level blocks to disabled dates
  const propertyDisabledDates = useMemo(() => {
    const dates: Date[] = [];
    propertyBlockedDates.forEach(
      (block: { startDate: string; endDate: string }) => {
        const start = parseISO(block.startDate);
        const end = parseISO(block.endDate);
        const current = new Date(start);

        while (current <= end) {
          dates.push(new Date(current));
          current.setDate(current.getDate() + 1);
        }
      },
    );
    return dates;
  }, [propertyBlockedDates]);

  // Calculate date restrictions based on property settings
  const dateRestrictions = useMemo(() => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // minimumAdvanceNotice: hours before check-in (default 24h)
    const advanceNoticeHours = property.settings?.minimumAdvanceNotice ?? 24;
    const earliestCheckIn = new Date(today);
    earliestCheckIn.setHours(earliestCheckIn.getHours() + advanceNoticeHours);

    // bookingWindow: days in advance that bookings are allowed (default 365)
    const bookingWindowDays = property.settings?.bookingWindow ?? 365;
    const latestCheckIn = new Date(today);
    latestCheckIn.setDate(latestCheckIn.getDate() + bookingWindowDays);

    return { earliestCheckIn, latestCheckIn };
  }, [property.settings]);

  // Process blocked dates for calendar display (same logic as property-booking-card)
  const blockedDates = useMemo(() => {
    const siteBlocked: Date[] = [];

    if (siteAvailabilities && siteAvailabilities.length > 0) {
      if (isUndesignated) {
        // For UNDESIGNATED: Find undesignated sites and merge their blocked dates
        const undesignatedIndices: number[] = [];
        sites.forEach((site, index) => {
          if ((site.capacity.maxConcurrentBookings ?? 1) > 1) {
            undesignatedIndices.push(index);
          }
        });

        if (undesignatedIndices.length > 0) {
          // If only one undesignated site, use its blocked dates directly
          if (undesignatedIndices.length === 1) {
            const result = siteAvailabilities[undesignatedIndices[0]];
            if (result?.data?.blockedDates) {
              siteBlocked.push(
                ...result.data.blockedDates.map(
                  (dateStr: string) => new Date(dateStr),
                ),
              );
            }
          } else {
            // If multiple undesignated sites, block only when ALL are blocked
            const dateBlockedCount = new Map<string, number>();
            undesignatedIndices.forEach(index => {
              const result = siteAvailabilities[index];
              if (result?.data?.blockedDates) {
                result.data.blockedDates.forEach((dateStr: string) => {
                  dateBlockedCount.set(
                    dateStr,
                    (dateBlockedCount.get(dateStr) || 0) + 1,
                  );
                });
              }
            });

            const fullyBlockedDates: string[] = [];
            dateBlockedCount.forEach((count, dateStr) => {
              if (count === undesignatedIndices.length) {
                fullyBlockedDates.push(dateStr);
              }
            });

            siteBlocked.push(
              ...fullyBlockedDates.map(dateStr => new Date(dateStr)),
            );
          }
        }
      } else {
        // For DESIGNATED: Block dates only when ALL sites are blocked
        const dateBlockedCount = new Map<string, number>();

        siteAvailabilities.forEach(
          (result: { data?: { blockedDates?: string[] } }) => {
            if (result.data?.blockedDates) {
              result.data.blockedDates.forEach((dateStr: string) => {
                dateBlockedCount.set(
                  dateStr,
                  (dateBlockedCount.get(dateStr) || 0) + 1,
                );
              });
            }
          },
        );

        const fullyBlockedDates: string[] = [];
        dateBlockedCount.forEach((count, dateStr) => {
          if (count === siteAvailabilities.length) {
            fullyBlockedDates.push(dateStr);
          }
        });

        siteBlocked.push(
          ...fullyBlockedDates.map(dateStr => new Date(dateStr)),
        );
      }
    }

    // Merge property-level and site-level blocked dates
    return [...siteBlocked, ...propertyDisabledDates];
  }, [siteAvailabilities, isUndesignated, sites, propertyDisabledDates]);

  // Combine blocked dates with advance notice and booking window restrictions
  const allDisabledDates = useMemo(() => {
    const disabled = [...blockedDates];
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Disable dates before earliest check-in (advance notice)
    const current = new Date(today);
    while (current < dateRestrictions.earliestCheckIn) {
      disabled.push(new Date(current));
      current.setDate(current.getDate() + 1);
    }

    // Disable dates after latest check-in (booking window)
    const futureDate = new Date(dateRestrictions.latestCheckIn);
    futureDate.setDate(futureDate.getDate() + 1);
    const farFuture = new Date(today);
    farFuture.setFullYear(farFuture.getFullYear() + 2); // 2 years ahead

    while (futureDate < farFuture) {
      disabled.push(new Date(futureDate));
      futureDate.setDate(futureDate.getDate() + 1);
    }

    return disabled;
  }, [blockedDates, dateRestrictions]);

  // Separate query for checking site blocking in user's selected date range
  const selectedDateWindow = useMemo(() => {
    if (!booking.dateRange?.from || !booking.dateRange?.to) return null;
    return {
      checkIn: booking.dateRange.from.toISOString(),
      checkOut: booking.dateRange.to.toISOString(),
    };
  }, [booking.dateRange]);

  const { data: selectedDateAvailabilities } = useQuery({
    queryKey: [
      'site-selected-dates-blocked',
      siteIdsForAvailability,
      selectedDateWindow,
    ],
    queryFn: async () => {
      if (siteIdsForAvailability.length === 0 || !selectedDateWindow) return [];
      const results = await Promise.all(
        siteIdsForAvailability.map(siteId =>
          getBlockedDates(
            siteId,
            selectedDateWindow.checkIn,
            selectedDateWindow.checkOut,
          ),
        ),
      );
      return results;
    },
    enabled: siteIdsForAvailability.length > 0 && !!selectedDateWindow,
    staleTime: 5 * 60 * 1000,
  });

  // Create a map of site ID to blocked status (for filtering)
  const siteBlockedMap = useMemo(() => {
    const map = new Map<string, boolean>();
    if (
      !selectedDateAvailabilities ||
      !booking.dateRange?.from ||
      !booking.dateRange?.to
    ) {
      return map;
    }

    sites.forEach((site, index) => {
      const result = selectedDateAvailabilities[index];
      // If site has any blocked dates in the selected range, mark as blocked
      const hasBlockedDates =
        result?.data?.blockedDates && result.data.blockedDates.length > 0;

      // Also mark as blocked if nights exceed booking settings
      const exceedsBookingSettings = siteUnavailableReason.has(site._id);

      map.set(site._id, hasBlockedDates || exceedsBookingSettings);
    });

    return map;
  }, [
    selectedDateAvailabilities,
    sites,
    booking.dateRange,
    siteUnavailableReason,
  ]);

  // Filter sites
  const filteredSites = useMemo(() => {
    let result = sites.filter(site => site.isActive);

    // Filter by accommodation type
    if (filterType) {
      result = result.filter(s => s.accommodationType === filterType);
    }

    // Filter by capacity
    if (booking.guests) {
      result = result.filter(s => s.capacity.maxGuests >= booking.guests);
    }

    // Filter by pets
    if (petsAllowed && booking.pets > 0) {
      result = result.filter(
        s => s.capacity.maxPets && s.capacity.maxPets >= booking.pets,
      );
    }

    // Filter by instant book
    if (instantBook) {
      result = result.filter(s => s.bookingSettings.instantBook);
    }

    // Filter by availability - exclude blocked sites when dates are selected
    if (
      booking.dateRange?.from &&
      booking.dateRange?.to &&
      siteBlockedMap.size > 0
    ) {
      result = result.filter(s => !siteBlockedMap.get(s._id));
    }

    return result;
  }, [
    sites,
    filterType,
    booking.guests,
    booking.pets,
    petsAllowed,
    instantBook,
    booking.dateRange,
    siteBlockedMap,
  ]);

  // Group sites by accommodation type
  const groupedSites = useMemo(() => {
    const groups: Record<string, Site[]> = {};
    filteredSites.forEach(site => {
      const type = site.accommodationType;
      if (!groups[type]) groups[type] = [];
      groups[type].push(site);
    });
    return groups;
  }, [filteredSites]);

  const accommodationTypes = Object.keys(groupedSites);

  // Compute visible site count for a group.
  // If a site is "undesignated" (can have multiple concurrent bookings),
  // count its `maxConcurrentBookings` instead of 1 so the displayed total
  // reflects the actual number of available bookable positions.
  const getSiteCount = (sitesGroup: Site[]) => {
    return sitesGroup.reduce((sum, s) => {
      const concurrent = s.capacity?.maxConcurrentBookings ?? 1;
      return sum + Math.max(1, concurrent);
    }, 0);
  };

  return (
    <div className="relative" id="sites">
      <LoginPromptDialog
        open={showLoginPrompt}
        onOpenChange={setShowLoginPrompt}
      />
      {/* Sites List + Map Layout */}
      <div className="flex min-h-0 gap-0">
        {/* Sites List - Scrollable */}
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="flex-1 overflow-y-auto scroll-smooth pr-4 lg:pr-6">
            {/* Select a site header */}
            <h2 className="mb-6 text-xl font-bold sm:text-2xl">
              Chọn vị trí cắm trại
            </h2>

            {/* Date & Guest Selectors Row */}
            <div
              className="mb-4 flex flex-wrap items-center gap-3"
              ref={dateRangeRef}
            >
              {/* Date Range */}
              <DateRangePopover
                dateRange={booking.dateRange}
                onDateChange={booking.setDateRange}
                disabledDates={allDisabledDates}
                open={datePopoverOpen}
                onOpenChange={setDatePopoverOpen}
                placeholder="Chọn ngày"
                buttonClassName="h-11 border-gray-300 bg-white px-4"
                align="start"
                dateFormat="MMM d"
                icon={<CalendarIcon className="mr-2 h-4 w-4 text-gray-600" />}
              />

              {/* Guests */}
              <GuestPopover
                adults={adults}
                childrenCount={children}
                pets={booking.pets}
                onAdultsChange={newAdults =>
                  handleGuestsChange(newAdults, children)
                }
                onChildrenChange={newChildren =>
                  handleGuestsChange(adults, newChildren)
                }
                onPetsChange={booking.setPets}
                open={guestPopoverOpen}
                onOpenChange={setGuestPopoverOpen}
                maxGuests={maxCapacity.maxGuests}
                maxPets={maxCapacity.maxPets}
                buttonClassName="h-11 border-gray-300 bg-white px-4"
                align="start"
                icon={<Users className="mr-2 h-4 w-4 text-gray-600" />}
                labels={{
                  adults: 'Khách',
                  adultsSubtext: 'Từ 13 tuổi trở lên',
                  children: 'Trẻ em',
                  childrenSubtext: 'Dưới 13 tuổi',
                  pets: 'Thú cưng',
                  petsSubtext: `Tối đa ${maxCapacity.maxPets}`,
                  guestsText: guests => `${guests} khách`,
                  childrenText: children => `${children} trẻ em`,
                }}
              />

              <Button
                variant={instantBook ? 'default' : 'outline'}
                size="sm"
                className={`h-9 rounded-full transition-all ${instantBook
                  ? 'bg-orange-600 hover:bg-orange-700'
                  : 'border-gray-300 hover:border-orange-500 hover:bg-orange-50'
                  }`}
                onClick={() => setInstantBook(!instantBook)}
              >
                ⚡ Đặt ngay
              </Button>
            </div>

            {/* Filter Buttons Row */}
            {/* <div className="mb-6 flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-9 rounded-full border-gray-300 hover:border-orange-500 hover:bg-orange-50"
              >
                <MapPin className="mr-1 h-4 w-4" />
                Loại hình
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-9 rounded-full border-gray-300 hover:border-orange-500 hover:bg-orange-50"
              >
                Tiện nghi
              </Button>
              <Button
                variant={petsAllowed ? 'default' : 'outline'}
                size="sm"
                className={`h-9 rounded-full transition-all ${
                  petsAllowed
                    ? 'bg-orange-600 hover:bg-orange-700'
                    : 'border-gray-300 hover:border-orange-500 hover:bg-orange-50'
                }`}
                onClick={() => setPetsAllowed(!petsAllowed)}
              >
                <Dog className="mr-1 h-4 w-4" />
                Cho phép thú cưng
              </Button>
            </div> */}

            {/* Sites content */}
            {accommodationTypes.map(type => {
              const sitesInGroup = groupedSites[type];
              return (
                <div key={type} className="mb-8">
                  {/* Group Header */}
                  <div className="mb-4">
                    <h3 className="text-xl font-bold">
                      {typeLabels[type] || type}
                    </h3>
                    <p className="text-sm text-gray-600">
                      {getSiteCount(sitesInGroup)} vị trí hiện có
                    </p>
                  </div>

                  {/* Sites in Group */}
                  <div className="space-y-4">
                    {sitesInGroup.map(site => {
                      const dateRange = booking.dateRange;
                      const hasSelectedDates = !!(dateRange?.from && dateRange?.to);
                      const calculated = hasSelectedDates
                        ? calculateSiteSubtotal(site, dateRange.from!, dateRange.to!)
                        : null;
                      const totalPrice = calculated ? calculated.subtotal : site.pricing.basePrice * nights;
                      const averagePricePerNight = hasSelectedDates ? totalPrice / nights : site.pricing.basePrice;

                      return (
                        <Card
                          key={site._id}
                          className={`group cursor-pointer overflow-hidden border-0 transition-all duration-200 ${selectedSite?._id === site._id
                            ? 'shadow-md ring-2'
                            : 'hover:border-orange-200 hover:shadow-md'
                            }`}
                          onClick={() => setSelectedSite(site)}
                          onMouseEnter={() => setHoveredSite(site)}
                          onMouseLeave={() => setHoveredSite(null)}
                        >
                          <div className="flex gap-4">
                            {/* Site Image */}
                            {site.photos && site.photos.length > 0 && (
                              <div className="relative flex h-62 shrink-0 basis-[45%] overflow-hidden rounded-lg bg-gray-100">
                                <SiteImageSlider photos={site.photos} name={site.name} />
                              </div>
                            )}

                            {/* Site Info - Max height matches image */}
                            <div
                              className="flex flex-1 flex-col justify-between overflow-hidden"
                              style={{ maxHeight: '248px' }}
                            >
                              <div>
                                {/* Title & Rating */}
                                <div className="flex items-start justify-between gap-2">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2">
                                      <h4 className="text-md font-bold">
                                        {site.name}
                                      </h4>
                                      {site.siteClass === 'vip' ? (
                                        <Badge className="bg-gradient-to-r from-amber-500 to-yellow-500 text-white font-semibold text-sx uppercase shadow-sm">
                                          VIP
                                        </Badge>
                                      ) : (
                                        <Badge variant="outline" className="text-sx text-gray-600 bg-gray-100 dark:bg-slate-800">
                                          Cơ bản
                                        </Badge>
                                      )}
                                      {/* {site.bookingSettings.instantBook && (
                                        <Badge
                                          variant="outline"
                                          className="text-center text-xs"
                                        >
                                          Đặt ngay
                                        </Badge>
                                      )} */}
                                      {/* Show unavailable reason badge */}
                                      {siteUnavailableReason.has(site._id) && (
                                        <Badge
                                          variant="destructive"
                                          className="text-xs"
                                        >
                                          {siteUnavailableReason.get(site._id)}
                                        </Badge>
                                      )}
                                    </div>
                                  </div>
                                  {/* {site.stats?.averageRating &&
                                    site.stats.averageRating > 0 && (
                                      <div className="flex items-center gap-1">
                                        <span className="text-lg">👍</span>
                                        <span className="text-sm font-semibold">
                                          {Math.round(
                                            (site.stats.averageRating / 5) *
                                              100,
                                          )}
                                          %
                                        </span>
                                        <span className="text-xs text-gray-500">
                                          ({site.stats.totalReviews || 0})
                                        </span>
                                      </div>
                                    )} */}
                                </div>

                                {/* Details */}
                                <p className="mb-1 text-xs text-gray-700">
                                  {typeLabels[site.accommodationType]} · Tối đa{' '}
                                  {site.capacity.maxGuests} người
                                  {site.capacity.maxVehicles &&
                                    site.capacity.maxVehicles > 0 &&
                                    ` · Xe dưới ${site.capacity.rvMaxLength || 35} ft`}
                                </p>

                                {/* Description */}
                                {site.description && (
                                  <p className="mb-2 line-clamp-2 text-xs text-gray-600">
                                    {site.description}
                                  </p>
                                )}

                                {/* Amenities Grid - 2 columns x 3 rows */}
                                {site.amenities &&
                                  site.amenities.length > 0 && (
                                    <div className="mb-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs text-gray-600">
                                      {site.amenities
                                        .slice(0, 6)
                                        .map((amenity, idx) => {
                                          const amenityName =
                                            typeof amenity === 'string'
                                              ? amenity
                                              : amenity.name;
                                          const icon =
                                            getAmenityIcon(amenityName);
                                          return (
                                            <span
                                              key={idx}
                                              className="flex items-center gap-1.5 truncate"
                                            >
                                              {icon}
                                              <span className="truncate">
                                                {amenityName}
                                              </span>
                                            </span>
                                          );
                                        })}
                                    </div>
                                  )}
                              </div>

                              {/* Price & CTA */}
                              <div className="flex items-end justify-between">
                                <div>
                                  <div className="flex flex-col">
                                    <p className="text-md font-bold">
                                      {averagePricePerNight.toLocaleString()} VND
                                      <span className="text-sm font-normal text-gray-600"> / đêm</span>
                                    </p>
                                    {hasSelectedDates ? (
                                      <div className="flex flex-col gap-1 mt-1">
                                        <p className="text-xs text-gray-500 font-semibold">
                                          Tổng cộng: {totalPrice.toLocaleString()} ₫
                                        </p>
                                        {(calculated?.hasSeasonalPrice ||
                                          calculated?.hasWeekendPrice ||
                                          calculated?.hasLongStayDiscount) && (
                                          <div className="flex flex-wrap gap-1 mt-0.5">
                                            {calculated.hasSeasonalPrice && (
                                              <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-amber-850 bg-amber-50 border border-amber-200/60 rounded px-1.5 py-0.5 dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-900/50">
                                                <Flame className="w-2.5 h-2.5 text-amber-600" />
                                                Giá mùa vụ
                                              </span>
                                            )}
                                            {calculated.hasWeekendPrice && (
                                              <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200/60 rounded px-1.5 py-0.5 dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-900/50">
                                                <CalendarIcon className="w-2.5 h-2.5 text-emerald-600" />
                                                Giá cuối tuần
                                              </span>
                                            )}
                                            {calculated.hasLongStayDiscount && (
                                              <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-indigo-800 bg-indigo-50 border border-indigo-200/60 rounded px-1.5 py-0.5 dark:bg-indigo-950/30 dark:text-indigo-400 dark:border-indigo-900/50">
                                                ✨ Giảm dài ngày (-{calculated.discountPercent}%)
                                              </span>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    ) : (
                                      <div className="flex flex-wrap gap-1.5 mt-1">
                                        {site.pricing.weekendPrice && site.pricing.weekendPrice !== site.pricing.basePrice && (
                                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-800 bg-emerald-50 border border-emerald-200/60 rounded-md px-2 py-0.5 shadow-sm dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-900/50">
                                            <CalendarIcon className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                                            Cuối tuần: {site.pricing.weekendPrice.toLocaleString()} VND
                                          </span>
                                        )}
                                        {site.pricing.seasonalPricing && site.pricing.seasonalPricing.length > 0 && (
                                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-amber-850 bg-amber-50 border border-amber-200/60 rounded-md px-2 py-0.5 shadow-sm dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-900/50">
                                            <Flame className="w-3 h-3 text-amber-600 dark:text-amber-450" />
                                            Lễ, Tết: Có giá riêng
                                          </span>
                                        )}
                                      </div>
                                    )}
                                  </div>

                                  {site.capacity.maxConcurrentBookings > 1 && (
                                    <div className="mt-1 flex items-center gap-2">
                                      <div className="flex items-center gap-1">
                                        <div className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
                                        <span className="text-xs font-medium text-green-700">
                                          {site.capacity.maxConcurrentBookings}{' '}
                                          vị trí có sẵn
                                        </span>
                                      </div>
                                    </div>
                                  )}
                                </div>
                                <Button
                                  size="lg"
                                  className="hover:bg-primary/90 m-2 px-8"
                                  asChild={hasSelectedDates}
                                  onClick={handleBookNowClick}
                                >
                                  {hasSelectedDates ? (
                                    <Link
                                      href={
                                        `/checkouts/payment?` +
                                        new URLSearchParams({
                                          siteId: site._id,
                                          propertyId:
                                            typeof site.property === 'string'
                                              ? site.property
                                              : site.property._id,
                                          name: site.name,
                                          location: `${property.location.city}, ${property.location.state}`,
                                          image:
                                            site.photos?.find(p => p.isCover)
                                              ?.url ||
                                            site.photos?.[0]?.url ||
                                            '',
                                          checkIn:
                                            booking.dateRange!.from!.toISOString(),
                                          checkOut:
                                            booking.dateRange!.to!.toISOString(),
                                          basePrice:
                                            site.pricing.basePrice.toString(),
                                          nights: nights.toString(),
                                          cleaningFee: (
                                            site.pricing.cleaningFee || 0
                                          ).toString(),
                                          petFee: booking.pets
                                            ? (
                                              (site.pricing.petFee || 0) *
                                              booking.pets
                                            ).toString()
                                            : '0',
                                          additionalGuestFee:
                                            booking.guests >
                                              site.capacity.maxGuests
                                              ? (
                                                (site.pricing
                                                  .additionalGuestFee || 0) *
                                                (booking.guests -
                                                  site.capacity.maxGuests)
                                              ).toString()
                                              : '0',
                                          total: totalPrice.toString(),
                                          currency:
                                            site.pricing.currency || 'VND',
                                          guests: booking.guests.toString(),
                                          pets: booking.pets.toString(),
                                          vehicles: '1',
                                        }).toString()
                                      }
                                      onClick={e => {
                                        const isAuthenticated =
                                          useAuthStore.getState()
                                            .isAuthenticated;
                                        if (!isAuthenticated) {
                                          e.preventDefault();
                                          setShowLoginPrompt(true);
                                        }
                                      }}
                                    >
                                      Đặt ngay
                                    </Link>
                                  ) : (
                                    <span>Đặt ngay</span>
                                  )}
                                </Button>
                              </div>
                            </div>
                          </div>
                        </Card>
                      );
                    })}
                  </div>
                </div>
              );
            })}

            {/* No Results */}
            {accommodationTypes.length === 0 && (
              <div className="mt-20 py-12 text-center">
                <p className="text-gray-500">Không có vị trí nào phù hợp</p>
              </div>
            )}

            {/* "These aren't exact matches" section - Carousel */}
            {filteredSites.length < sites.length && (
              <div className="mt-12">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="text-xl font-bold">
                    Những vị trí này có thể phù hợp với bạn
                  </h3>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-8 w-8 rounded-full"
                      onClick={() => emblaApi?.scrollPrev()}
                      disabled={!canScrollPrev}
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      className="h-8 w-8 rounded-full"
                      onClick={() => emblaApi?.scrollNext()}
                      disabled={!canScrollNext}
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <div className="overflow-hidden" ref={emblaRef}>
                  <div className="flex gap-4">
                    {sites
                      .filter(s => !filteredSites.includes(s) && s.isActive)
                      .map(site => {
                        const isBlocked = siteBlockedMap.get(site._id);
                        const dateRange = booking.dateRange;
                        const hasSelectedDates = !!(dateRange?.from && dateRange?.to);
                        const calculated = hasSelectedDates
                          ? calculateSiteSubtotal(site, dateRange.from!, dateRange.to!)
                          : null;
                        const totalPrice = calculated ? calculated.subtotal : site.pricing.basePrice * nights;
                        const averagePricePerNight = hasSelectedDates ? totalPrice / nights : site.pricing.basePrice;
                        return (
                          <div
                            key={site._id}
                            className="max-w-60 min-w-[300px] shrink-0"
                          >
                            <Card className="h-full overflow-hidden border border-gray-200 shadow-sm transition-shadow hover:shadow-md">
                              {site.photos && site.photos.length > 0 && (
                                <div className="relative h-[220px] w-full overflow-hidden">
                                  <SiteImageSlider photos={site.photos} name={site.name} />
                                  {isBlocked &&
                                    booking.dateRange?.from &&
                                    booking.dateRange?.to && (
                                      <div className="absolute inset-0 flex items-center justify-center bg-black/50 pointer-events-none">
                                        <Badge
                                          variant="destructive"
                                          className="text-sm"
                                        >
                                          {siteUnavailableReason.get(
                                            site._id,
                                          ) || 'Không khả dụng'}
                                        </Badge>
                                      </div>
                                    )}
                                </div>
                              )}
                              <CardContent className="p-4">
                                <div className="mb-2 flex items-start justify-between gap-2">
                                  <h4 className="line-clamp-1 font-semibold">
                                    {site.name}
                                  </h4>
                                  {site.siteClass === 'vip' ? (
                                    <Badge className="bg-gradient-to-r from-amber-500 to-yellow-500 text-white font-semibold text-[10px] uppercase shadow-sm">
                                      VIP
                                    </Badge>
                                  ) : (
                                    <Badge variant="secondary" className="text-[10px] text-gray-500 bg-gray-100 dark:bg-slate-800">
                                      Cơ bản
                                    </Badge>
                                  )}
                                  {site.stats?.averageRating && (
                                    <span className="flex shrink-0 items-center gap-1 text-sm">
                                      👍
                                      <span className="font-medium">
                                        {Math.round(
                                          (site.stats.averageRating / 5) * 100,
                                        )}
                                        %
                                      </span>
                                      <span className="text-gray-400">
                                        ({site.stats.totalReviews || 0})
                                      </span>
                                    </span>
                                  )}
                                </div>
                                <p className="mb-3 text-sm text-gray-600">
                                  {typeLabels[site.accommodationType]} · Tối đa{' '}
                                  {site.capacity.maxGuests} người
                                  {site.capacity.maxVehicles &&
                                    site.capacity.maxVehicles > 0 &&
                                    ` · Xe dưới ${site.capacity.rvMaxLength || 35} ft`}
                                </p>
                                <div className="flex items-end justify-between">
                                  <div>
                                    <div className="flex flex-col">
                                      <div className="flex items-baseline gap-1">
                                        <p className="text-lg font-bold">
                                          {averagePricePerNight.toLocaleString()}{' '}
                                        </p>
                                        <span className="text-sm text-gray-500">
                                          / đêm
                                        </span>
                                      </div>
                                      {hasSelectedDates ? (
                                        <div className="flex flex-col gap-1 mt-1">
                                          <p className="text-xs text-gray-500 font-semibold">
                                            {totalPrice.toLocaleString()} ₫ tổng
                                          </p>
                                          {(calculated?.hasSeasonalPrice ||
                                            calculated?.hasWeekendPrice ||
                                            calculated?.hasLongStayDiscount) && (
                                            <div className="flex flex-wrap gap-1 mt-0.5">
                                              {calculated.hasSeasonalPrice && (
                                                <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-amber-850 bg-amber-50 border border-amber-200/60 rounded px-1 py-0.2 dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-900/50">
                                                  <Flame className="w-2.5 h-2.5 text-amber-600 animate-pulse" />
                                                  Mùa vụ
                                                </span>
                                              )}
                                              {calculated.hasWeekendPrice && (
                                                <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200/60 rounded px-1 py-0.2 dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-900/50">
                                                  <CalendarIcon className="w-2.5 h-2.5 text-emerald-600" />
                                                  Cuối tuần
                                                </span>
                                              )}
                                              {calculated.hasLongStayDiscount && (
                                                <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-indigo-800 bg-indigo-50 border border-indigo-200/60 rounded px-1 py-0.2 dark:bg-indigo-950/30 dark:text-indigo-400 dark:border-indigo-900/50">
                                                  ✨ -{calculated.discountPercent}%
                                                </span>
                                              )}
                                            </div>
                                          )}
                                        </div>
                                      ) : (
                                        <div className="flex flex-col gap-1.5 mt-1">
                                          {site.pricing.weekendPrice && site.pricing.weekendPrice !== site.pricing.basePrice && (
                                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-800 bg-emerald-50 border border-emerald-200/60 rounded px-1.5 py-0.5 w-fit shadow-xs dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-900/50">
                                              <CalendarIcon className="w-2.5 h-2.5 text-emerald-600 dark:text-emerald-400" />
                                              Cuối tuần: {site.pricing.weekendPrice.toLocaleString()} ₫
                                            </span>
                                          )}
                                          {site.pricing.seasonalPricing && site.pricing.seasonalPricing.length > 0 && (
                                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-amber-850 bg-amber-50 border border-amber-200/60 rounded px-1.5 py-0.5 w-fit shadow-xs dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-900/50">
                                              <Flame className="w-2.5 h-2.5 text-amber-600 dark:text-amber-450" />
                                              Lễ, Tết: Có giá riêng
                                            </span>
                                          )}
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                  {isBlocked &&
                                    booking.dateRange?.from &&
                                    booking.dateRange?.to ? (
                                    <Button
                                      size="default"
                                      variant="outline"
                                      disabled
                                      className="cursor-not-allowed"
                                    >
                                      Không khả dụng
                                    </Button>
                                  ) : (
                                    <Button
                                      size="default"
                                      asChild={hasSelectedDates}
                                      onClick={handleBookNowClick}
                                    >
                                      {hasSelectedDates ? (
                                        <Link
                                          href={
                                            `/checkouts/payment?` +
                                            new URLSearchParams({
                                              siteId: site._id,
                                              propertyId:
                                                typeof site.property === 'string'
                                                  ? site.property
                                                  : site.property._id,
                                              name: site.name,
                                              location: `${property.location.city}, ${property.location.state}`,
                                              image:
                                                site.photos?.find(p => p.isCover)
                                                  ?.url ||
                                                site.photos?.[0]?.url ||
                                                '',
                                              checkIn:
                                                booking.dateRange!.from!.toISOString(),
                                              checkOut:
                                                booking.dateRange!.to!.toISOString(),
                                              basePrice:
                                                site.pricing.basePrice.toString(),
                                              nights: nights.toString(),
                                              cleaningFee: (
                                                site.pricing.cleaningFee || 0
                                              ).toString(),
                                              petFee: booking.pets
                                                ? (
                                                  (site.pricing.petFee || 0) *
                                                  booking.pets
                                                ).toString()
                                                : '0',
                                              additionalGuestFee:
                                                booking.guests >
                                                  site.capacity.maxGuests
                                                  ? (
                                                    (site.pricing
                                                      .additionalGuestFee || 0) *
                                                    (booking.guests -
                                                      site.capacity.maxGuests)
                                                  ).toString()
                                                  : '0',
                                              total: totalPrice.toString(),
                                              currency:
                                                site.pricing.currency || 'VND',
                                              guests: booking.guests.toString(),
                                              pets: booking.pets.toString(),
                                              vehicles: '1',
                                            }).toString()
                                          }
                                          onClick={e => {
                                            const isAuthenticated =
                                              useAuthStore.getState()
                                                .isAuthenticated;
                                            if (!isAuthenticated) {
                                              e.preventDefault();
                                              setShowLoginPrompt(true);
                                            }
                                          }}
                                        >
                                          Đặt ngay
                                        </Link>
                                      ) : (
                                        <span>Đặt ngay</span>
                                      )}
                                    </Button>
                                  )}
                                </div>
                              </CardContent>
                            </Card>
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Map Sidebar */}
        <div className="hidden lg:block lg:w-[45%]">
          <div className="sticky top-0 h-screen overflow-hidden rounded-2xl">
            <SiteMap
              sites={filteredSites}
              property={property}
              selectedSite={selectedSite}
              hoveredSite={hoveredSite}
              onSiteSelect={setSelectedSite}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
