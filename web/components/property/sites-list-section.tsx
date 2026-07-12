'use client';

import LoginPromptDialog from '@/components/auth/login-prompt-dialog';
import { useAuthStore } from '@/store/auth.store';
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';

import { DateRangePopover } from '@/components/search/date-range-popover';
import { GuestPopover } from '@/components/search/guest-popover';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { usePropertyBookingState } from '@/hooks/usePropertyBookingState';
import { getBlockedDates, getAvailableUnits } from '@/lib/client-actions';
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
  Bed,
  Droplets,
  ShowerHead,
  Toilet,
  Tent,
  Check,
  Sparkles,
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

function calculateSiteSubtotal(site: Site, checkIn: Date, checkOut: Date, guests: number = 1) {
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
        const seasonalStart = new Date(season.startDate);
        const seasonalEnd = new Date(season.endDate);

        // Compare dates without time
        const currentZero = new Date(currentDate);
        currentZero.setHours(0, 0, 0, 0);
        const startZero = new Date(seasonalStart);
        startZero.setHours(0, 0, 0, 0);
        const endZero = new Date(seasonalEnd);
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

  // Apply rate type scaling (per person or per site)
  const isPerPerson = site.pricing.rateType === 'person';
  const requiredUnits = Math.ceil(guests / (site.capacity.maxGuests || 1)) || 1;
  const multiplier = isPerPerson ? guests : requiredUnits;
  subtotal = subtotal * multiplier;

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

const formatCapacityText = (capacity: { maxGuests: number; maxAdults?: number; maxChildren?: number }) => {
  const { maxGuests, maxAdults, maxChildren } = capacity;
  if (maxAdults !== undefined && maxAdults > 0 && maxChildren !== undefined && maxChildren > 0) {
    return `${maxAdults} người lớn, ${maxChildren} trẻ em`;
  }
  return `${maxGuests} người`;
};

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
    queryFn: async () => {
      const res = await getPropertyWithSites(initialProperty._id);
      return res.data as any;
    },
    initialData: { property: initialProperty, sites: initialSites, siteCount: initialSites.length },
    staleTime: 5 * 60 * 1000,
  });

  const property = propertyWithSitesData?.property;
  const sites = propertyWithSitesData?.sites || [];

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

  // Helper to get site unit based on accommodation type
  const getSiteUnit = (type: string) => {
    const t = type?.toLowerCase() || '';
    if (t.includes('rv') || t.includes('trailer') || t.includes('van') || t.includes('airstream')) {
      return 'xe';
    }
    if (t.includes('cabin') || t.includes('house') || t.includes('home') || t.includes('dome') || t.includes('pod')) {
      return 'căn';
    }
    return 'lều';
  };

  // Helper to render lodging provided badge or note
  const renderLodgingBadge = (
    lodgingProvided?: 'bring_your_own' | 'structure_provided' | 'vehicle_provided',
    isNoteStyle = false
  ) => {
    if (!lodgingProvided) return null;

    if (isNoteStyle) {
      switch (lodgingProvided) {
        case 'bring_your_own':
          return (
            <p className="text-1xl text-amber-600 dark:text-amber-400 italic">
              * Khách tự mang theo lều/dụng cụ cắm trại
            </p>
          );
        case 'structure_provided':
          return (
            <p className="text-1xl text-primary italic">
              * Đã trang bị sẵn lều/chỗ ở
            </p>
          );
        case 'vehicle_provided':
          return (
            <p className="text-1xl text-blue-600 dark:text-blue-400 italic">
              * Đã trang bị sẵn xe cắm trại
            </p>
          );
        default:
          return null;
      }
    }

    switch (lodgingProvided) {
      case 'bring_your_own':
        return (
          <Badge variant="outline" className="text-[10px] font-medium text-amber-700 bg-amber-50 border-amber-200 dark:bg-amber-950/20 dark:text-amber-400 dark:border-amber-900/50 shrink-0 whitespace-nowrap">
            Tự mang dụng cụ cắm trại
          </Badge>
        );
      case 'structure_provided':
        return (
          <Badge variant="outline" className="text-[10px] font-medium text-primary bg-primary/10 border-primary/20 shrink-0 whitespace-nowrap">
            Có sẵn lều
          </Badge>
        );
      case 'vehicle_provided':
        return (
          <Badge variant="outline" className="text-[10px] font-medium text-blue-700 bg-blue-50 border-blue-200 dark:bg-blue-950/20 dark:text-blue-400 dark:border-blue-900/50 shrink-0 whitespace-nowrap">
            Có sẵn xe
          </Badge>
        );
      default:
        return null;
    }
  };

  // Helper to check if today falls inside any seasonal pricing period
  const isTodayInSeason = (site: Site) => {
    if (!site.pricing.seasonalPricing || site.pricing.seasonalPricing.length === 0) return false;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return site.pricing.seasonalPricing.some((season: any) => {
      const start = new Date(season.startDate);
      start.setHours(0, 0, 0, 0);
      const end = new Date(season.endDate);
      end.setHours(0, 0, 0, 0);
      return today >= start && today <= end;
    });
  };

  // Helper to get amenity icon
  const getAmenityIcon = (amenityName: string) => {
    const name = amenityName.toLowerCase();
    if (name.includes('wifi') || name.includes('internet'))
      return <Wifi className="h-3.5 w-3.5" />;
    if (name.includes('điện') || name.includes('electric'))
      return <Zap className="h-3.5 w-3.5" />;
    if (
      name.includes('lửa') ||
      name.includes('fire') ||
      name.includes('bếp') ||
      name.includes('bbq') ||
      name.includes('nướng') ||
      name.includes('grill')
    )
      return <Flame className="h-3.5 w-3.5" />;
    if (name.includes('cây') || name.includes('tree') || name.includes('shade'))
      return <TreePine className="h-3.5 w-3.5" />;
    if (
      name.includes('nước nóng') ||
      name.includes('tắm') ||
      name.includes('shower') ||
      name.includes('vòi sen')
    )
      return <ShowerHead className="h-3.5 w-3.5" />;
    if (name.includes('nước') || name.includes('water'))
      return <Droplets className="h-3.5 w-3.5" />;
    if (name.includes('toilet') || name.includes('vệ sinh') || name.includes('wc') || name.includes('nhà tắm'))
      return <Toilet className="h-3.5 w-3.5" />;
    if (name.includes('giường') || name.includes('ngủ') || name.includes('bed') || name.includes('đệm'))
      return <Bed className="h-3.5 w-3.5" />;
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
    return <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" />;
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

  const hasSelectedDates = !!(booking.dateRange?.from && booking.dateRange?.to);

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

  // Get max capacity from sites (largest combined capacity of any single site)
  const maxCapacity = useMemo(() => {
    if (sites.length === 0) return { maxGuests: 50, maxPets: 10 };
    const maxGuests = Math.max(
      ...sites.map(s => (s.capacity.maxGuests || 0) * (s.capacity.maxConcurrentBookings || 1))
    ) || 50;
    const maxPets = Math.max(
      ...sites.map(s => (s.capacity.maxPets || 0) * (s.capacity.maxConcurrentBookings || 1))
    ) || 10;
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
  });

  // Fetch available units count for each site in the selected date range
  const { data: sitesAvailableUnits } = useQuery({
    queryKey: [
      'sites-available-units-count',
      siteIdsForAvailability,
      selectedDateWindow,
    ],
    queryFn: async () => {
      if (siteIdsForAvailability.length === 0 || !selectedDateWindow) return {};
      const results = await Promise.all(
        siteIdsForAvailability.map(async siteId => {
          try {
            const res = await getAvailableUnits(
              siteId,
              selectedDateWindow.checkIn,
              selectedDateWindow.checkOut,
            );
            return { siteId, count: res.data?.availableUnits?.length ?? 0 };
          } catch (error) {
            console.error('Failed to get available units count for site:', siteId, error);
            return { siteId, count: 0 };
          }
        }),
      );
      return results.reduce((acc, curr) => {
        acc[curr.siteId] = curr.count;
        return acc;
      }, {} as Record<string, number>);
    },
    enabled: siteIdsForAvailability.length > 0 && !!selectedDateWindow,
    staleTime: 5 * 60 * 1000,
  });

  // Check if the selected site is sold out for the current booking parameters
  const isSoldOut = useMemo(() => {
    if (!selectedSite || !hasSelectedDates || !sitesAvailableUnits) return false;
    const requiredUnits = Math.ceil(booking.guests / (selectedSite.capacity.maxGuests || 1)) || 1;
    return (
      sitesAvailableUnits[selectedSite._id] !== undefined &&
      sitesAvailableUnits[selectedSite._id] < requiredUnits
    );
  }, [selectedSite, hasSelectedDates, sitesAvailableUnits, booking.guests]);

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

  // Check if the selected site is unavailable due to capacity, pets or block restrictions
  const isSelectedSiteUnavailable = useMemo(() => {
    if (!selectedSite) return false;
    const isBlocked = siteBlockedMap.get(selectedSite._id);
    const combinedCapacity = (selectedSite.capacity.maxGuests || 0) * (selectedSite.capacity.maxConcurrentBookings || 1);
    const isCapacityExceeded = booking.guests > combinedCapacity;

    const maxAdults = (selectedSite.capacity.maxAdults !== undefined && selectedSite.capacity.maxAdults !== null && selectedSite.capacity.maxAdults > 0) ? selectedSite.capacity.maxAdults : (selectedSite.capacity.maxGuests || 0);
    const combinedAdultsCapacity = maxAdults * (selectedSite.capacity.maxConcurrentBookings || 1);
    const isAdultsExceeded = adults > combinedAdultsCapacity;

    const maxChildren = (selectedSite.capacity.maxChildren !== undefined && selectedSite.capacity.maxChildren !== null && selectedSite.capacity.maxChildren > 0) ? selectedSite.capacity.maxChildren : (selectedSite.capacity.maxGuests || 0);
    const combinedChildrenCapacity = maxChildren * (selectedSite.capacity.maxConcurrentBookings || 1);
    const isChildrenExceeded = children > combinedChildrenCapacity;

    const maxPets = selectedSite.capacity.maxPets || 0;
    const combinedPetsCapacity = maxPets * (selectedSite.capacity.maxConcurrentBookings || 1);
    const isPetsNotAllowed = booking.pets > 0 && maxPets === 0;
    const isPetsCapacityExceeded = booking.pets > 0 && booking.pets > combinedPetsCapacity;

    return isCapacityExceeded || isAdultsExceeded || isChildrenExceeded || isPetsNotAllowed || isPetsCapacityExceeded || (isBlocked && hasSelectedDates);
  }, [selectedSite, siteBlockedMap, booking.guests, booking.pets, hasSelectedDates, adults, children]);

  const selectedSiteUnavailableReasonText = useMemo(() => {
    if (!selectedSite) return '';
    const isBlocked = siteBlockedMap.get(selectedSite._id);
    const combinedCapacity = (selectedSite.capacity.maxGuests || 0) * (selectedSite.capacity.maxConcurrentBookings || 1);
    
    if (booking.guests > combinedCapacity) {
      return 'Không đáp ứng đủ số người';
    }

    const maxAdults = (selectedSite.capacity.maxAdults !== undefined && selectedSite.capacity.maxAdults !== null && selectedSite.capacity.maxAdults > 0) ? selectedSite.capacity.maxAdults : (selectedSite.capacity.maxGuests || 0);
    const combinedAdultsCapacity = maxAdults * (selectedSite.capacity.maxConcurrentBookings || 1);
    if (adults > combinedAdultsCapacity) {
      return 'Vượt quá số người lớn tối đa';
    }

    const maxChildren = (selectedSite.capacity.maxChildren !== undefined && selectedSite.capacity.maxChildren !== null && selectedSite.capacity.maxChildren > 0) ? selectedSite.capacity.maxChildren : (selectedSite.capacity.maxGuests || 0);
    const combinedChildrenCapacity = maxChildren * (selectedSite.capacity.maxConcurrentBookings || 1);
    if (children > combinedChildrenCapacity) {
      return 'Vượt quá số trẻ em tối đa';
    }
    
    const maxPets = selectedSite.capacity.maxPets || 0;
    const combinedPetsCapacity = maxPets * (selectedSite.capacity.maxConcurrentBookings || 1);
    if (booking.pets > 0 && maxPets === 0) {
      return 'Không cho phép thú cưng';
    }
    if (booking.pets > 0 && booking.pets > combinedPetsCapacity) {
      return 'Vượt quá số lượng thú cưng';
    }
    if (isBlocked && hasSelectedDates) {
      return siteUnavailableReason.get(selectedSite._id) || 'Không khả dụng vào ngày đã chọn';
    }
    return '';
  }, [selectedSite, siteBlockedMap, booking.guests, booking.pets, hasSelectedDates, siteUnavailableReason, adults, children]);

  // Filter sites
  const filteredSites = useMemo(() => {
    let result = sites.filter(site => site.isActive);

    // Filter by accommodation type
    if (filterType) {
      result = result.filter(s => s.accommodationType === filterType);
    }

    // Filter by capacity (supporting group booking via concurrent units)
    if (booking.guests) {
      result = result.filter(s => {
        const combinedCapacity = (s.capacity.maxGuests || 0) * (s.capacity.maxConcurrentBookings || 1);
        if (combinedCapacity < booking.guests) return false;

        // Enforce max adults if configured
        if (s.capacity.maxAdults !== undefined && s.capacity.maxAdults > 0) {
          const combinedAdults = s.capacity.maxAdults * (s.capacity.maxConcurrentBookings || 1);
          if (adults > combinedAdults) return false;
        }

        // Enforce max children if configured
        if (s.capacity.maxChildren !== undefined) {
          const combinedChildren = s.capacity.maxChildren * (s.capacity.maxConcurrentBookings || 1);
          if (children > combinedChildren) return false;
        }

        return true;
      });
    }

    // Filter by pets (supporting group booking via concurrent units)
    if (petsAllowed || booking.pets > 0) {
      result = result.filter(s => {
        const combinedPetsCapacity = (s.capacity.maxPets || 0) * (s.capacity.maxConcurrentBookings || 1);
        const requiredPets = booking.pets > 0 ? booking.pets : 1;
        return combinedPetsCapacity >= requiredPets;
      });
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
    sitesAvailableUnits,
    adults,
    children,
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

      {/* Details Dialog / Modal for selected site */}
      <Dialog open={!!selectedSite} onOpenChange={(open) => !open && setSelectedSite(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto p-0 gap-0 rounded-2xl border-0 shadow-2xl bg-white dark:bg-slate-900">
          <DialogTitle className="sr-only">
            Chi tiết vị trí cắm trại {selectedSite?.name}
          </DialogTitle>

          {selectedSite && (
            <div className="flex flex-col">
              {/* Image Slider at the top */}
              <div className="px-6 pt-6 md:px-8 md:pt-8">
                <div className="relative h-64 sm:h-80 w-full overflow-hidden rounded-2xl bg-gray-100 dark:bg-slate-800 shadow-md">
                  <SiteImageSlider photos={selectedSite.photos || []} name={selectedSite.name} />
                </div>
              </div>

              {/* Main Content Area */}
              <div className="p-6 md:p-8 space-y-6">

                {/* Header info */}
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    {selectedSite.siteClass === 'vip' ? (
                      <Badge className="bg-gradient-to-r from-amber-500 to-yellow-500 text-white font-semibold text-xs uppercase shadow-sm">
                        VIP
                      </Badge>
                    ) : (
                      <Badge variant="secondary" className="text-xs text-gray-500 bg-gray-100 dark:bg-slate-800">
                        Cơ bản
                      </Badge>
                    )}
                    {renderLodgingBadge(selectedSite.lodgingProvided)}
                  </div>
                  <h3 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                    {selectedSite.name}
                  </h3>
                </div>

                {/* Description */}
                {selectedSite.description && (
                  <div>
                    <h4 className="text-base font-semibold text-gray-900 dark:text-gray-100 mb-2">
                      Giới thiệu
                    </h4>
                    <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed whitespace-pre-line">
                      {selectedSite.description}
                    </p>
                  </div>
                )}

                {/* Capacity & Space Details */}
                <div className="border-t border-gray-100 dark:border-slate-800 pt-6">
                  <h4 className="text-base font-semibold text-gray-900 dark:text-gray-100 mb-3">
                    Thông tin không gian
                  </h4>
                  <div className="grid grid-cols-2 gap-y-3 gap-x-6 text-sm text-gray-700 dark:text-gray-300">
                    <div className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-1.5">
                      <span className="text-gray-500">Sức chứa tối đa:</span>
                      <span className="font-semibold">{formatCapacityText(selectedSite.capacity)}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-1.5">
                      <span className="text-gray-500">Số xe tối đa:</span>
                      <span className="font-semibold">{selectedSite.capacity.maxVehicles ?? 0} xe</span>
                    </div>
                    {selectedSite.capacity.rvMaxLength && selectedSite.capacity.rvMaxLength > 0 && (
                      <div className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-1.5 col-span-2">
                        <span className="text-gray-500">Độ dài xe RV tối đa:</span>
                        <span className="font-semibold">{selectedSite.capacity.rvMaxLength} ft (~{(selectedSite.capacity.rvMaxLength * 0.3048).toFixed(1)}m)</span>
                      </div>
                    )}
                    <div className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-1.5">
                      <span className="text-gray-500">Thú cưng:</span>
                      <span className="font-semibold">
                        {selectedSite.capacity.maxPets && selectedSite.capacity.maxPets > 0
                          ? `Tối đa ${selectedSite.capacity.maxPets} con`
                          : 'Không cho phép'}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-50 dark:border-slate-800/50 pb-1.5">
                      <span className="text-gray-500">Phân loại khu vực:</span>
                      <span className="font-semibold">
                        {selectedSite.capacity.maxConcurrentBookings > 1
                          ? `Tự do (${selectedSite.capacity.maxConcurrentBookings} chỗ)`
                          : 'Khu vực riêng tư'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Amenities */}
                <div className="border-t border-gray-100 dark:border-slate-800 pt-6">
                  <h4 className="text-base font-semibold text-gray-900 dark:text-gray-100 mb-3">
                    Tiện nghi
                  </h4>
                  {selectedSite.amenities && selectedSite.amenities.length > 0 ? (
                    <div className="grid grid-cols-2 gap-3.5">
                      {selectedSite.amenities.map((amenity: any, idx: number) => {
                        const name = typeof amenity === 'string' ? amenity : amenity.name;
                        return (
                          <div key={idx} className="flex items-center gap-2.5 text-sm text-gray-700 dark:text-gray-300">
                            <span className="flex h-6 w-6 shrink-0 items-center justify-center text-primary rounded-full bg-primary/10">
                              {getAmenityIcon(name)}
                            </span>
                            <span className="truncate">{name}</span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500 italic">Không có tiện nghi đặc biệt nào được liệt kê.</p>
                  )}
                </div>

                {/* Services section */}
                {selectedSite.services && selectedSite.services.length > 0 && (
                  <div className="border-t border-gray-100 dark:border-slate-800 pt-6">
                    <h4 className="text-base font-semibold text-gray-900 dark:text-gray-100 mb-3">
                      Dịch vụ đi kèm
                    </h4>

                    <div className="space-y-4">
                      {/* Individual Services */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {selectedSite.services.map((srv: any, idx: number) => {
                          const srvPrice = srv.pricing?.[0] || srv;
                          return (
                            <div key={idx} className="flex justify-between items-center bg-slate-50 dark:bg-slate-900/40 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800 text-sm">
                              <span className="font-medium text-gray-800 dark:text-gray-200">{srv.name}</span>
                              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                                {typeof srvPrice.price === 'number'
                                  ? srvPrice.price === 0
                                    ? 'Miễn phí'
                                    : `${srvPrice.price.toLocaleString()} ₫ / ${srvPrice.unit || 'lượt'}`
                                  : 'Liên hệ'}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}


                {/* Rules & Stay Policies */}
                <div className="border-t border-gray-100 dark:border-slate-800 pt-6">
                  <h4 className="text-base font-semibold text-gray-900 dark:text-gray-100 mb-3">
                    Quy định lưu trú & Bảng giá
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Standard Rates breakdown */}
                    <div className="bg-slate-50 dark:bg-slate-900/60 p-4 rounded-xl border border-gray-105 dark:border-slate-800 shadow-sm">
                      <h5 className="font-semibold text-xs text-gray-400 uppercase tracking-wider mb-2.5">
                        Bảng giá tiêu chuẩn
                      </h5>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-650 dark:text-gray-400">Giá ngày thường:</span>
                          <span className="font-semibold">
                            {selectedSite.pricing.basePrice.toLocaleString()} ₫ {selectedSite.pricing.rateType === 'person' ? '/ khách / đêm' : '/ đêm'}
                          </span>
                        </div>
                        {selectedSite.pricing.weekendPrice && selectedSite.pricing.weekendPrice > 0 && (
                          <div className="flex justify-between">
                            <span className="text-gray-650 dark:text-gray-400">Giá cuối tuần:</span>
                            <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                              {selectedSite.pricing.weekendPrice.toLocaleString()} ₫ {selectedSite.pricing.rateType === 'person' ? '/ khách / đêm' : '/ đêm'}
                            </span>
                          </div>
                        )}
                        {selectedSite.pricing.cleaningFee && selectedSite.pricing.cleaningFee > 0 && (
                          <div className="flex justify-between">
                            <span className="text-gray-650 dark:text-gray-400">Phí dọn dẹp:</span>
                            <span className="font-semibold">{selectedSite.pricing.cleaningFee.toLocaleString()} ₫</span>
                          </div>
                        )}
                        {selectedSite.pricing.petFee && selectedSite.pricing.petFee > 0 && (
                          <div className="flex justify-between">
                            <span className="text-gray-650 dark:text-gray-400">Phí mang thú cưng:</span>
                            <span className="font-semibold">{selectedSite.pricing.petFee.toLocaleString()} ₫ / con</span>
                          </div>
                        )}
                        {selectedSite.pricing.additionalGuestFee && selectedSite.pricing.additionalGuestFee > 0 && (
                          <div className="flex justify-between">
                            <span className="text-gray-650 dark:text-gray-400">Phí khách phát sinh:</span>
                            <span className="font-semibold">{selectedSite.pricing.additionalGuestFee.toLocaleString()} ₫ / người</span>
                          </div>
                        )}
                        {(selectedSite.pricing.weeklyDiscount || selectedSite.pricing.monthlyDiscount) && (
                          <div className="border-t border-dashed border-gray-200 dark:border-slate-800 pt-2 mt-2">
                            <div className="text-[11px] font-semibold text-primary uppercase tracking-wider mb-1">
                              Ưu đãi lưu trú dài ngày
                            </div>
                            {selectedSite.pricing.weeklyDiscount && (
                              <div className="flex justify-between text-xs text-indigo-600 dark:text-indigo-400">
                                <span>Từ 7 đêm trở lên:</span>
                                <span className="font-bold">-{selectedSite.pricing.weeklyDiscount}%</span>
                              </div>
                            )}
                            {selectedSite.pricing.monthlyDiscount && (
                              <div className="flex justify-between text-xs text-indigo-600 dark:text-indigo-400">
                                <span>Từ 28 đêm trở lên:</span>
                                <span className="font-bold">-{selectedSite.pricing.monthlyDiscount}%</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Stay Rules */}
                    <div className="bg-slate-50 dark:bg-slate-900/60 p-4 rounded-xl border border-gray-105 dark:border-slate-800 shadow-sm">
                      <h5 className="font-semibold text-xs text-gray-400 uppercase tracking-wider mb-2.5">
                        Quy định
                      </h5>
                      <div className="space-y-2 text-sm text-gray-700 dark:text-gray-300">
                        <div className="flex justify-between">
                          <span className="text-gray-500">Đêm tối thiểu:</span>
                          <span className="font-medium">{selectedSite.bookingSettings.minimumNights} đêm</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Giờ nhận/trả phòng:</span>
                          <span className="font-medium">
                            {selectedSite.bookingSettings.checkInTime} - {selectedSite.bookingSettings.checkOutTime}
                          </span>
                        </div>

                      </div>
                    </div>
                  </div>

                  {/* Seasonal Pricing list if any */}
                  {selectedSite.pricing.seasonalPricing && selectedSite.pricing.seasonalPricing.length > 0 && (
                    <div className="mt-4 bg-amber-50/40 dark:bg-amber-950/20 border border-amber-200/50 dark:border-amber-900/30 p-3.5 rounded-xl">
                      <div className="flex items-center gap-1.5 mb-2 text-amber-900 dark:text-amber-300 font-bold text-xs">
                        <Flame className="w-3.5 h-3.5 text-amber-600 animate-pulse" />
                        Giá Mùa Vụ / Lễ Tết
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-24 overflow-y-auto pr-1">
                        {selectedSite.pricing.seasonalPricing.map((season: any, idx: number) => (
                          <div key={idx} className="flex justify-between text-[11px] items-center border-b border-amber-100/30 dark:border-amber-900/20 pb-1">
                            <span className="font-medium text-amber-950 dark:text-amber-400">{season.name}</span>
                            <span className="text-gray-500 text-[10px]">
                              {new Date(season.startDate).toLocaleDateString('vi-VN', { month: 'numeric', day: 'numeric' })} - {new Date(season.endDate).toLocaleDateString('vi-VN', { month: 'numeric', day: 'numeric' })}
                            </span>
                            <span className="font-bold text-amber-800 dark:text-amber-500">{season.price.toLocaleString()}đ</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Checkout Summary Card */}
                <div className="border-t border-gray-100 dark:border-slate-800 pt-6">
                  <div className="bg-white dark:bg-slate-900/60 p-5 rounded-2xl border border-primary/10 shadow-sm">
                    {hasSelectedDates ? (
                      (() => {
                        const dateRange = booking.dateRange;
                        const calculated = hasSelectedDates
                          ? calculateSiteSubtotal(selectedSite, dateRange!.from!, dateRange!.to!, booking.guests)
                          : null;

                        const today = new Date();
                        today.setHours(0, 0, 0, 0);
                        const activeSeason = !hasSelectedDates
                          ? selectedSite.pricing.seasonalPricing?.find((season: any) => {
                            const start = new Date(season.startDate);
                            start.setHours(0, 0, 0, 0);
                            const end = new Date(season.endDate);
                            end.setHours(0, 0, 0, 0);
                            return today >= start && today <= end;
                          })
                          : null;
                        const dayOfWeek = today.getDay();
                        const isTodayWeekendDay = dayOfWeek === 5 || dayOfWeek === 6;
                        const hasWeekendPrice = selectedSite.pricing.weekendPrice && selectedSite.pricing.weekendPrice !== selectedSite.pricing.basePrice;
                        const defaultPrice = activeSeason ? activeSeason.price : (isTodayWeekendDay && hasWeekendPrice) ? selectedSite.pricing.weekendPrice! : selectedSite.pricing.basePrice;

                        const isPerPerson = selectedSite.pricing.rateType === 'person';
                        const requiredUnits = Math.ceil(booking.guests / (selectedSite.capacity.maxGuests || 1)) || 1;
                        const multiplier = isPerPerson ? booking.guests : requiredUnits;

                        const totalPrice = calculated ? calculated.subtotal : defaultPrice * nights * multiplier;
                        const averagePricePerNight = hasSelectedDates ? totalPrice / nights : defaultPrice * multiplier;

                        const cleaningFee = selectedSite.pricing.cleaningFee || 0;
                        const petFee = selectedSite.pricing.petFee && booking.pets
                          ? selectedSite.pricing.petFee * booking.pets
                          : 0;
                        const additionalGuestFee = booking.guests > selectedSite.capacity.maxGuests
                          ? (selectedSite.pricing.additionalGuestFee || 0) * (booking.guests - selectedSite.capacity.maxGuests)
                          : 0;
                        const finalTotal = totalPrice + cleaningFee + petFee + additionalGuestFee;

                        return (
                          <div className="space-y-4">
                            <div className="flex justify-between items-baseline">
                              <span className="text-sm font-semibold text-gray-500">Giá dự tính:</span>
                              <div className="text-right">
                                <span className="text-xl font-extrabold text-primary">{averagePricePerNight.toLocaleString()}₫</span>
                                <span className="text-xs text-gray-500">
                                  {isPerPerson ? ' / khách / đêm' : ' / đêm'}
                                </span>
                              </div>
                            </div>

                            <div className="border-t border-gray-100 dark:border-slate-800 pt-3 space-y-2 text-xs text-gray-600 dark:text-gray-400">
                              <div className="flex justify-between">
                                <span>Giá lưu trú ({nights} đêm):</span>
                                <span className="font-semibold">{totalPrice.toLocaleString()} ₫</span>
                              </div>
                              {cleaningFee > 0 && (
                                <div className="flex justify-between">
                                  <span>Phí dọn dẹp:</span>
                                  <span className="font-semibold">{cleaningFee.toLocaleString()} ₫</span>
                                </div>
                              )}
                              {petFee > 0 && (
                                <div className="flex justify-between">
                                  <span>Phí thú cưng ({booking.pets} con):</span>
                                  <span className="font-semibold">{petFee.toLocaleString()} ₫</span>
                                </div>
                              )}
                              {additionalGuestFee > 0 && (
                                <div className="flex justify-between">
                                  <span>Phí khách thêm:</span>
                                  <span className="font-semibold">{additionalGuestFee.toLocaleString()} ₫</span>
                                </div>
                              )}
                              <div className="flex justify-between text-sm font-bold text-gray-900 dark:text-gray-100 border-t border-gray-100 dark:border-slate-800 pt-2.5">
                                <span>Tổng thanh toán:</span>
                                <span className="text-lg text-primary">{finalTotal.toLocaleString()} ₫</span>
                              </div>
                            </div>

                             {isSelectedSiteUnavailable ? (
                               <Button
                                 className="w-full py-6 font-bold text-base rounded-xl mt-2 bg-slate-300 text-slate-500 dark:bg-slate-700 dark:text-slate-400 cursor-not-allowed border-0"
                                 disabled
                               >
                                 <span>{selectedSiteUnavailableReasonText || 'Không khả dụng'}</span>
                               </Button>
                             ) : (
                               <Button
                                 className={isSoldOut ? "w-full py-6 font-bold text-base rounded-xl mt-2 bg-slate-300 text-slate-500 dark:bg-slate-700 dark:text-slate-400 cursor-not-allowed" : "w-full py-6 font-bold text-base rounded-xl mt-2"}
                                 disabled={isSoldOut}
                                 asChild={!isSoldOut}
                               >
                                 {!isSoldOut ? (
                                   <Link
                                     href={
                                       `/checkouts/payment?` +
                                       new URLSearchParams({
                                         siteId: selectedSite._id,
                                         propertyId:
                                           typeof selectedSite.property === 'string'
                                             ? selectedSite.property
                                             : selectedSite.property._id,
                                         name: selectedSite.name,
                                         location: `${property.location.city}, ${property.location.state}`,
                                         image:
                                           selectedSite.photos?.find((p: any) => p.isCover)
                                             ?.url ||
                                           selectedSite.photos?.[0]?.url ||
                                           '',
                                         checkIn:
                                           booking.dateRange!.from!.toISOString(),
                                         checkOut:
                                           booking.dateRange!.to!.toISOString(),
                                         basePrice:
                                           selectedSite.pricing.basePrice.toString(),
                                         nights: nights.toString(),
                                         cleaningFee: cleaningFee.toString(),
                                         petFee: petFee.toString(),
                                         additionalGuestFee: additionalGuestFee.toString(),
                                         total: finalTotal.toString(),
                                         currency:
                                           selectedSite.pricing.currency || 'VND',
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
                                     ⚡ Đặt ngay
                                   </Link>
                                 ) : (
                                   <span>Hết chỗ</span>
                                 )}
                               </Button>
                             )}
                          </div>
                        );
                      })()
                    ) : (
                      <div className="text-center py-2 space-y-3">
                        <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
                          Vui lòng chọn ngày để kiểm tra giá và đặt vị trí này.
                        </p>
                        <Button
                          variant="outline"
                          className="w-full"
                          onClick={() => {
                            setSelectedSite(null);
                            // Scroll to date picker
                            dateRangeRef.current?.scrollIntoView({
                              behavior: 'smooth',
                              block: 'center',
                            });
                            setTimeout(() => {
                              setDatePopoverOpen(true);
                            }, 500);
                          }}
                        >
                          Chọn ngày cắm trại
                        </Button>
                      </div>
                    )}
                  </div>
                </div>

              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
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

              {/* <Button
                variant={instantBook ? 'default' : 'outline'}
                size="sm"
                className={`h-9 rounded-full transition-all ${instantBook
                  ? 'bg-orange-600 hover:bg-orange-700'
                  : 'border-gray-300 hover:border-orange-500 hover:bg-orange-50'
                  }`}
                onClick={() => setInstantBook(!instantBook)}
              >
                ⚡ Đặt ngay
              </Button> */}
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
                      const requiredUnits = Math.ceil(booking.guests / (site.capacity.maxGuests || 1)) || 1;
                      const isPerPerson = site.pricing.rateType === 'person';
                      const multiplier = isPerPerson ? booking.guests : requiredUnits;
                      const isSoldOut = hasSelectedDates &&
                        sitesAvailableUnits &&
                        sitesAvailableUnits[site._id] !== undefined &&
                        sitesAvailableUnits[site._id] < requiredUnits;
                      const calculated = hasSelectedDates
                        ? calculateSiteSubtotal(site, dateRange.from!, dateRange.to!, booking.guests)
                        : null;

                      // Determine if we are rendering for a holiday, weekend, etc.
                      let averagePricePerNight = site.pricing.basePrice;
                      let showHolidayLabel = false;
                      let holidayLabelText = '';
                      let showWeekendLabel = false;
                      let weekendLabelText = '';

                      if (calculated && hasSelectedDates) {
                        // Xác định giá theo ngày check-in
                        const checkInDate = new Date(dateRange.from!);
                        checkInDate.setHours(0, 0, 0, 0);

                        // Kiểm tra ngày check-in có phải ngày lễ không
                        const checkInSeason = site.pricing.seasonalPricing?.find((season: any) => {
                          const start = new Date(season.startDate);
                          start.setHours(0, 0, 0, 0);
                          const end = new Date(season.endDate);
                          end.setHours(0, 0, 0, 0);
                          return checkInDate >= start && checkInDate <= end;
                        });

                        if (checkInSeason) {
                          // Ngày lễ → chỉ hiện giá lễ, không hiện giá cuối tuần
                          showHolidayLabel = true;
                          holidayLabelText = `Giá ${checkInSeason.name}`;
                        } else {
                          // Không phải ngày lễ → luôn hiện giá ngày thường
                          // Nếu có giá cuối tuần thì hiện thêm label cuối tuần
                          const hasWeekendPricing = site.pricing.weekendPrice && site.pricing.weekendPrice !== site.pricing.basePrice && site.pricing.weekendPrice > 0;
                          if (hasWeekendPricing) {
                            showWeekendLabel = true;
                            weekendLabelText = `Cuối tuần: ${site.pricing.weekendPrice!.toLocaleString()} ₫`;
                          }
                        }
                      } else {
                        const today = new Date();
                        today.setHours(0, 0, 0, 0);
                        const activeSeason = site.pricing.seasonalPricing?.find((season: any) => {
                          const start = new Date(season.startDate);
                          start.setHours(0, 0, 0, 0);
                          const end = new Date(season.endDate);
                          end.setHours(0, 0, 0, 0);
                          return today >= start && today <= end;
                        });

                        const hasWeekendPrice = site.pricing.weekendPrice && site.pricing.weekendPrice !== site.pricing.basePrice && site.pricing.weekendPrice > 0;

                        if (activeSeason) {
                          showHolidayLabel = true;
                          holidayLabelText = `Giá ${activeSeason.name}`;
                        } else {
                          // Nếu có giá cuối tuần thì hiện thêm label cuối tuần
                          if (hasWeekendPrice) {
                            showWeekendLabel = true;
                            weekendLabelText = `Cuối tuần: ${site.pricing.weekendPrice!.toLocaleString()} ₫`;
                          }
                        }
                      }

                      const totalPrice = calculated ? calculated.subtotal : averagePricePerNight * nights;
                      const siteUnit = getSiteUnit(site.accommodationType);

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
                          <div className="flex flex-col md:flex-row gap-4">
                            {/* Site Image */}
                            {site.photos && site.photos.length > 0 && (
                              <div className="relative flex h-48 sm:h-56 md:h-62 w-full md:w-auto shrink-0 md:basis-[45%] overflow-hidden rounded-lg bg-gray-100">
                                <SiteImageSlider photos={site.photos} name={site.name} />
                                {isSoldOut && (
                                  <div className="absolute inset-0 flex items-center justify-center bg-black/50 pointer-events-none z-10">
                                    <Badge
                                      variant="destructive"
                                      className="text-sm px-3 py-1 font-semibold uppercase tracking-wider"
                                    >
                                      Hết chỗ
                                    </Badge>
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Site Info - Max height matches image */}
                            <div
                              className="flex flex-1 flex-col justify-between py-3 px-4 md:px-0 md:pr-4 md:max-h-[248px] md:overflow-hidden pb-4 md:pb-3"
                            >
                              <div>
                                {/* Title & Rating */}
                                <div className="mb-2 flex items-start justify-between gap-2">
                                  <h4 className="font-semibold flex-1 leading-snug">
                                    {site.name}
                                  </h4>
                                  <div className="flex items-center gap-1 shrink-0">
                                    {site.siteClass === 'vip' ? (
                                      <Badge className="bg-gradient-to-r from-amber-500 to-yellow-500 text-white font-semibold text-[10px] uppercase shadow-sm shrink-0 whitespace-nowrap">
                                        VIP
                                      </Badge>
                                    ) : (
                                      <Badge variant="secondary" className="text-[10px] text-gray-500 bg-gray-100 dark:bg-slate-800 shrink-0 whitespace-nowrap">
                                        Cơ bản
                                      </Badge>
                                    )}

                                  </div>
                                </div>

                                {/* Capacity & Availability Info */}
                                <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 border-b border-dashed border-slate-100 dark:border-slate-800 pb-2">
                                  <span className="flex items-center gap-1.5">
                                    <Users className="w-3.5 h-3.5 text-primary shrink-0" />
                                    Mỗi {siteUnit}: Tối đa <strong>{formatCapacityText(site.capacity)}</strong>
                                  </span>
                                  <span className="flex items-center gap-1.5">
                                    <Sparkles className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                                    {hasSelectedDates && sitesAvailableUnits && sitesAvailableUnits[site._id] !== undefined ? (
                                      <span>Còn trống: <strong className="text-emerald-600 font-bold">{sitesAvailableUnits[site._id]} / {site.capacity.maxConcurrentBookings}</strong> {siteUnit}</span>
                                    ) : (
                                      <span>Tổng số: <strong className="font-semibold">{site.capacity.maxConcurrentBookings}</strong> {siteUnit}</span>
                                    )}
                                  </span>
                                </div>


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
                                              className="flex items-center gap-2.5 truncate py-0.5"
                                            >
                                              <span className="flex h-4 w-4 shrink-0 items-center justify-center text-black dark:text-white">
                                                {icon}
                                              </span>
                                              <span className="truncate text-slate-700 dark:text-slate-350">
                                                {amenityName}
                                              </span>
                                            </span>
                                          );
                                        })}
                                    </div>
                                  )}

                                {/* Site Services */}
                                {site.services && site.services.length > 0 && (
                                  <div className="mb-2 border-t pt-2 mt-2">
                                    <p className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">Dịch vụ đi kèm tại Site:</p>
                                    <div className="flex flex-wrap gap-1">
                                      {site.services.map((srv: any, idx: number) => {
                                        if (srv.pricing && srv.pricing.length > 0) {
                                          return srv.pricing.map((pOpt: any, pIdx: number) => (
                                            <Badge
                                              key={`${idx}-${pIdx}`}
                                              variant="secondary"
                                              className="text-[10px] bg-emerald-50 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300 hover:bg-emerald-100/50 py-0.5 px-1.5 border-0"
                                            >
                                              {srv.name} ({pOpt.price === 0 ? 'Miễn phí' : `${pOpt.price.toLocaleString()} đ / ${pOpt.unit}`})
                                            </Badge>
                                          ));
                                        }
                                        return typeof srv.price === "number" ? (
                                          <Badge
                                            key={idx}
                                            variant="secondary"
                                            className="text-[10px] bg-emerald-50 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300 hover:bg-emerald-100/50 py-0.5 px-1.5 border-0"
                                          >
                                            {srv.name} ({srv.price === 0 ? 'Miễn phí' : `${srv.price.toLocaleString()} đ / ${srv.unit || "lượt"}`})
                                          </Badge>
                                        ) : null;
                                      })}
                                    </div>
                                  </div>
                                )}
                              </div>
                              <div className="space-y-1 w-full">
                                {renderLodgingBadge(site.lodgingProvided, true)}
                                {/* Price & CTA */}
                                <div className="flex items-end justify-between">
                                  <div className="flex flex-col">
                                    <div className="flex items-baseline gap-1">
                                      <p className="text-lg font-bold">
                                        {averagePricePerNight.toLocaleString()}{' '}
                                        <span className="text-sm font-normal">₫</span>
                                      </p>
                                      <span className="text-sm text-gray-500">
                                        {isPerPerson ? '/ khách / đêm' : '/ đêm'}
                                      </span>
                                    </div>
                                    {showHolidayLabel && (
                                      <p className="text-xs font-normal text-amber-600 dark:text-amber-400 mt-0.5">
                                        ({holidayLabelText})
                                      </p>
                                    )}
                                    {showWeekendLabel && (
                                      <p className="text-xs font-normal text-emerald-600 dark:text-emerald-400 mt-0.5">
                                        ({weekendLabelText})
                                      </p>
                                    )}

                                  </div>
                                  {(() => {
                                    const requiredUnits = Math.ceil(booking.guests / (site.capacity.maxGuests || 1)) || 1;
                                    const isSoldOut = hasSelectedDates &&
                                      sitesAvailableUnits &&
                                      sitesAvailableUnits[site._id] !== undefined &&
                                      sitesAvailableUnits[site._id] < requiredUnits;

                                    return (
                                      <Button
                                        size="lg"
                                        className={isSoldOut ? "px-8 bg-slate-300 text-slate-500 dark:bg-slate-700 dark:text-slate-400 cursor-not-allowed" : "hover:bg-primary/90 px-8"}
                                        disabled={isSoldOut}
                                        asChild={hasSelectedDates && !isSoldOut}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          if (!isSoldOut) {
                                            handleBookNowClick(e);
                                          }
                                        }}
                                      >
                                        {hasSelectedDates && !isSoldOut ? (
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
                                          <span>{isSoldOut ? 'Hết chỗ' : 'Đặt ngay'}</span>
                                        )}
                                      </Button>
                                    );
                                  })()}
                                </div>
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
                        const dateRange = booking.dateRange;
                        const siteUnit = getSiteUnit(site.accommodationType);
                        const hasSelectedDates = !!(dateRange?.from && dateRange?.to);
                        const isBlocked = siteBlockedMap.get(site._id);
                        const combinedCapacity = (site.capacity.maxGuests || 0) * (site.capacity.maxConcurrentBookings || 1);
                        const maxAdults = (site.capacity.maxAdults !== undefined && site.capacity.maxAdults !== null && site.capacity.maxAdults > 0) ? site.capacity.maxAdults : (site.capacity.maxGuests || 0);
                        const combinedAdultsCapacity = maxAdults * (site.capacity.maxConcurrentBookings || 1);
                        const isAdultsExceeded = adults > combinedAdultsCapacity;

                        const maxChildren = (site.capacity.maxChildren !== undefined && site.capacity.maxChildren !== null && site.capacity.maxChildren > 0) ? site.capacity.maxChildren : (site.capacity.maxGuests || 0);
                        const combinedChildrenCapacity = maxChildren * (site.capacity.maxConcurrentBookings || 1);
                        const isChildrenExceeded = children > combinedChildrenCapacity;

                        const isCapacityExceeded = booking.guests > combinedCapacity || isAdultsExceeded || isChildrenExceeded;
                        
                        // Check pets conditions
                        const maxPets = site.capacity.maxPets || 0;
                        const combinedPetsCapacity = maxPets * (site.capacity.maxConcurrentBookings || 1);
                        const isPetsNotAllowed = booking.pets > 0 && maxPets === 0;
                        const isPetsCapacityExceeded = booking.pets > 0 && booking.pets > combinedPetsCapacity;
                        
                        const isUnavailable = isCapacityExceeded || isPetsNotAllowed || isPetsCapacityExceeded || (isBlocked && hasSelectedDates);
                        const requiredUnits = Math.ceil(booking.guests / (site.capacity.maxGuests || 1)) || 1;
                        const isSoldOut = hasSelectedDates &&
                          sitesAvailableUnits &&
                          sitesAvailableUnits[site._id] !== undefined &&
                          sitesAvailableUnits[site._id] < requiredUnits;
                        const calculated = hasSelectedDates
                          ? calculateSiteSubtotal(site, dateRange.from!, dateRange.to!, booking.guests)
                          : null;

                        const hasWeekendPrice = site.pricing.weekendPrice && site.pricing.weekendPrice !== site.pricing.basePrice;
                        const isPerPerson = site.pricing.rateType === 'person';
                        const multiplier = isPerPerson ? booking.guests : requiredUnits;

                        let averagePricePerNight = site.pricing.basePrice;
                        let showHolidayLabel = false;
                        let holidayLabelText = '';
                        let showWeekendLabel = false;
                        let weekendLabelText = '';
                        let activeSeason = null;

                        if (calculated && hasSelectedDates) {
                          if (calculated.hasSeasonalPrice) {
                            showHolidayLabel = true;
                            const overlappingSeason = site.pricing.seasonalPricing?.find((season: any) => {
                              const start = new Date(season.startDate);
                              start.setHours(0, 0, 0, 0);
                              const end = new Date(season.endDate);
                              end.setHours(0, 0, 0, 0);
                              return start <= dateRange.to! && end >= dateRange.from!;
                            });
                            activeSeason = overlappingSeason;
                            holidayLabelText = overlappingSeason ? `Giá ${overlappingSeason.name}` : 'Giá lễ';
                          } else if (calculated.hasWeekendPrice) {
                            showWeekendLabel = true;
                            weekendLabelText = `Cuối tuần: ${site.pricing.weekendPrice!.toLocaleString()} ₫`;
                          }
                        } else {
                          const today = new Date();
                          today.setHours(0, 0, 0, 0);
                          activeSeason = site.pricing.seasonalPricing?.find((season: any) => {
                            const start = new Date(season.startDate);
                            start.setHours(0, 0, 0, 0);
                            const end = new Date(season.endDate);
                            end.setHours(0, 0, 0, 0);
                            return today >= start && today <= end;
                          });

                          if (activeSeason) {
                            showHolidayLabel = true;
                            holidayLabelText = `Giá ${activeSeason.name}`;
                          } else {
                            if (hasWeekendPrice) {
                              showWeekendLabel = true;
                              weekendLabelText = `Cuối tuần: ${site.pricing.weekendPrice!.toLocaleString()} ₫`;
                            }
                          }
                        }

                        const totalPrice = calculated ? calculated.subtotal : averagePricePerNight * nights;

                        return (
                          <div
                            key={site._id}
                            className="max-w-60 min-w-[300px] shrink-0"
                          >
                            <Card
                              className="h-full overflow-hidden border border-gray-200 shadow-sm transition-shadow hover:shadow-md cursor-pointer"
                              onClick={() => setSelectedSite(site)}
                            >
                              {site.photos && site.photos.length > 0 && (
                                <div className="relative h-[220px] w-full overflow-hidden">
                                  <SiteImageSlider photos={site.photos} name={site.name} />
                                  {(isUnavailable || isSoldOut) && (
                                    <div className="absolute inset-0 flex items-center justify-center bg-black/50 pointer-events-none">
                                      <Badge
                                        variant="destructive"
                                        className="text-sm text-center"
                                      >
                                        {isSoldOut
                                          ? 'Hết chỗ'
                                          : isCapacityExceeded
                                            ? 'Không đáp ứng đủ số người'
                                            : isPetsNotAllowed
                                              ? 'Không cho phép thú cưng'
                                              : isPetsCapacityExceeded
                                                ? 'Vượt quá số lượng thú cưng'
                                                : (siteUnavailableReason.get(site._id) || 'Không khả dụng')}
                                      </Badge>
                                    </div>
                                  )}
                                </div>
                              )}
                              <CardContent className="p-4">
                                <div className="mb-2 flex items-start justify-between gap-2">
                                  <h4 className="font-semibold flex-1 leading-snug">
                                    {site.name}
                                  </h4>
                                  <div className="flex items-center gap-1 shrink-0">
                                    {site.siteClass === 'vip' ? (
                                      <Badge className="bg-gradient-to-r from-amber-500 to-yellow-500 text-white font-semibold text-[10px] uppercase shadow-sm shrink-0 whitespace-nowrap">
                                        VIP
                                      </Badge>
                                    ) : (
                                      <Badge variant="secondary" className="text-[10px] text-gray-500 bg-gray-100 dark:bg-slate-800 shrink-0 whitespace-nowrap">
                                        Cơ bản
                                      </Badge>
                                    )}
                                    {renderLodgingBadge(site.lodgingProvided)}
                                  </div>
                                  {!!site.stats?.averageRating && (
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

                                {/* Capacity & Availability Info */}
                                <div className="mt-3 flex flex-col gap-1.5 text-xs text-slate-500 border-t border-dashed border-slate-100 dark:border-slate-800 pt-2 pb-0.5">
                                  <span className="flex items-center gap-1.5">
                                    <Users className="w-3.5 h-3.5 text-primary shrink-0" />
                                    Mỗi {siteUnit}: Tối đa <strong>{formatCapacityText(site.capacity)}</strong>
                                  </span>
                                  <span className="flex items-center gap-1.5">
                                    <Sparkles className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                                    {hasSelectedDates && sitesAvailableUnits && sitesAvailableUnits[site._id] !== undefined ? (
                                      <span>Còn trống: <strong className="text-emerald-600 font-bold">{sitesAvailableUnits[site._id]} / {site.capacity.maxConcurrentBookings}</strong> {siteUnit}</span>
                                    ) : (
                                      <span>Tổng số: <strong className="font-semibold">{site.capacity.maxConcurrentBookings}</strong> {siteUnit}</span>
                                    )}
                                  </span>
                                </div>

                                <div className="flex items-end justify-between mt-4">
                                  <div className="flex flex-col">
                                    <div className="flex items-baseline gap-1">
                                      <p className="text-lg font-bold">
                                        {averagePricePerNight.toLocaleString()}{' '}
                                        <span className="text-sm font-normal">₫</span>
                                      </p>
                                      <span className="text-sm text-gray-500">
                                        {isPerPerson ? '/ khách / đêm' : '/ đêm'}
                                      </span>
                                    </div>
                                    {activeSeason && (
                                      <p className="text-xs font-normal text-amber-600 dark:text-amber-400 mt-0.5">
                                        (Giá {activeSeason.name})
                                      </p>
                                    )}
                                    {hasWeekendPrice && !activeSeason && (
                                      <p className="text-xs font-normal text-emerald-600 dark:text-emerald-400 mt-0.5">
                                        (Cuối tuần: {site.pricing.weekendPrice?.toLocaleString()} ₫)
                                      </p>
                                    )}

                                  </div>
                                  {isUnavailable ? (
                                    <Button
                                      size="default"
                                      variant="outline"
                                      disabled
                                      className="cursor-not-allowed"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                      }}
                                    >
                                      Không khả dụng
                                    </Button>
                                  ) : (() => {
                                    const requiredUnits = Math.ceil(booking.guests / (site.capacity.maxGuests || 1)) || 1;
                                    const isSoldOut = hasSelectedDates &&
                                      sitesAvailableUnits &&
                                      sitesAvailableUnits[site._id] !== undefined &&
                                      sitesAvailableUnits[site._id] < requiredUnits;

                                    return (
                                      <Button
                                        size="default"
                                        className={isSoldOut ? "bg-slate-300 text-slate-500 dark:bg-slate-700 dark:text-slate-400 cursor-not-allowed" : ""}
                                        disabled={isSoldOut}
                                        asChild={hasSelectedDates && !isSoldOut}
                                        onClick={(e) => {
                                          if (!isSoldOut) {
                                            handleBookNowClick(e);
                                          }
                                        }}
                                      >
                                        {hasSelectedDates && !isSoldOut ? (
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
                                          <span>{isSoldOut ? 'Hết chỗ' : 'Đặt ngay'}</span>
                                        )}
                                      </Button>
                                    );
                                  })()}
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
