'use client';

import LoginPromptDialog from '@/components/auth/login-prompt-dialog';
import { DateRangePopover } from '@/components/search/date-range-popover';
import { GuestPopover } from '@/components/search/guest-popover';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { WeatherAdvice } from '@/components/property/weather-advice';
import { usePropertyBookingState } from '@/hooks/usePropertyBookingState';
import { getBlockedDates } from '@/lib/client-actions';
import { getPropertyBlockedDates, getPropertyWithSites } from '@/lib/property-site-api';
import { useAuthStore } from '@/store/auth.store';
import type { Property, Site } from '@/types/property-site';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { addDays, differenceInDays, parseISO } from 'date-fns';
import { Star } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { useSocket } from '@/provider/socketProvider';

interface PropertyBookingCardProps {
  property: Property;
  sites: Site[];
  initialGuests?: number;
  initialPets?: number;
  initialCheckIn?: string;
  initialCheckOut?: string;
}

export function PropertyBookingCard({
  property: initialProperty,
  sites: initialSites,
  initialGuests = 0,
  initialPets = 0,
  initialCheckIn,
  initialCheckOut,
}: PropertyBookingCardProps) {
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

  // Use shared booking state synced with URL
  const booking = usePropertyBookingState({
    initialGuests,
    initialPets,
    initialCheckIn,
    initialCheckOut,
  });

  // Auto-detect if this is undesignated property
  // Undesignated = any site with maxConcurrentBookings > 1
  const isUndesignated = useMemo(() => {
    return sites.some(site => (site.capacity.maxConcurrentBookings ?? 1) > 1);
  }, [sites]);

  // Compute total number of bookable positions for the property.
  // If a site has `maxConcurrentBookings > 1` it contributes that number,
  // otherwise it contributes 1. This ensures the displayed "total sites"
  // reflects concurrent slots for undesignated sites.
  const computedTotalSites = useMemo(() => {
    if (!sites || sites.length === 0) return property.stats?.totalSites ?? 0;
    return sites.reduce((sum, s) => {
      const concurrent = s.capacity?.maxConcurrentBookings ?? 1;
      return sum + Math.max(1, concurrent);
    }, 0);
  }, [sites, property.stats]);

  // Check if property has only one site (for maximumNights check)
  const isSingleSiteProperty = sites.length === 1;

  // Adults/children breakdown (local state, not in URL)
  // Sync initial values from booking.guests (which comes from URL)
  const [adults, setAdults] = useState(() => Math.max(1, booking.guests));
  const [children, setChildren] = useState(0);

  // Popovers open state
  const [datePopoverOpen, setDatePopoverOpen] = useState(false);
  const [guestPopoverOpen, setGuestPopoverOpen] = useState(false);

  // Sync local adults state when booking.guests changes from URL
  useEffect(() => {
    if (booking.guests !== adults + children) {
      // Update adults only if total changed (preserve children if possible)
      const newAdults = Math.max(1, booking.guests - children);
      setAdults(newAdults);
    }
  }, [booking.guests]); // Only run when URL guests changes

  const [showLoginPrompt, setShowLoginPrompt] = useState(false);

  // Sync total guests with URL when adults/children change
  const handleGuestsChange = (newAdults: number, newChildren: number) => {
    setAdults(newAdults);
    setChildren(newChildren);
    booking.setGuests(newAdults + newChildren);
  };

  // Collect all site IDs to check their availability (for both designated and undesignated)
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
      }
    };

    socket.on('property_data_changed', handlePropertyChange);

    return () => {
      socket.off('property_data_changed', handlePropertyChange);
    };
  }, [socket, property._id, siteIdsForAvailability, queryClient]);

  // Fetch blocked dates for all sites (designated) or group (undesignated)
  // We'll fetch availability for a 6-month window from today
  const availabilityWindow = useMemo(() => {
    const today = new Date();
    const sixMonthsLater = new Date();
    sixMonthsLater.setMonth(today.getMonth() + 6);
    return {
      checkIn: today.toISOString(),
      checkOut: sixMonthsLater.toISOString(),
    };
  }, []);

  // Fetch property-level blocked dates for THIS property only
  const { data: propertyBlockedDates = [] } = useQuery({
    queryKey: ['property-blocked-dates', property._id],
    queryFn: () => getPropertyBlockedDates(property._id),
    enabled: !!property._id,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Expand property-level date ranges into individual Date objects
  const propertyDisabledDates = useMemo(() => {
    const disabled: Date[] = [];
    propertyBlockedDates.forEach(
      (block: { startDate: string; endDate: string }) => {
        const start = parseISO(block.startDate);
        const end = parseISO(block.endDate);
        let current = start;
        while (current <= end) {
          disabled.push(new Date(current));
          current = addDays(current, 1);
        }
      },
    );
    return disabled;
  }, [propertyBlockedDates]);

  // For designated: fetch blocked dates for each site and merge them
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
    enabled: siteIdsForAvailability.length > 0, // Enable for both designated and undesignated
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

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

  // Process blocked dates using useMemo
  const blockedDates = useMemo(() => {
    // Start with site-level blocked dates
    const siteBlocked: Date[] = [];

    if (!siteAvailabilities || siteAvailabilities.length === 0) {
      // If no site availabilities, only return property-level blocks
      return propertyDisabledDates;
    }

    if (isUndesignated) {
      // For UNDESIGNATED: Find the undesignated site(s) and merge their blocked dates
      // An undesignated site has maxConcurrentBookings > 1
      const undesignatedIndices: number[] = [];
      sites.forEach((site, index) => {
        if ((site.capacity.maxConcurrentBookings ?? 1) > 1) {
          undesignatedIndices.push(index);
        }
      });

      if (undesignatedIndices.length === 0) {
        return propertyDisabledDates;
      }

      // If there's only one undesignated site, use its blocked dates directly
      if (undesignatedIndices.length === 1) {
        const result = siteAvailabilities[undesignatedIndices[0]];
        if (result?.data?.blockedDates) {
          result.data.blockedDates.forEach((dateStr: string) => {
            siteBlocked.push(new Date(dateStr));
          });
        }
        // Merge property and site blocks
        return [...siteBlocked, ...propertyDisabledDates];
      }

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

      // Only block dates that are blocked in ALL undesignated sites
      const fullyBlockedDates: string[] = [];
      dateBlockedCount.forEach((count, dateStr) => {
        if (count === undesignatedIndices.length) {
          fullyBlockedDates.push(dateStr);
        }
      });

      fullyBlockedDates.forEach(dateStr => {
        siteBlocked.push(new Date(dateStr));
      });

      // Merge property and site blocks
      return [...siteBlocked, ...propertyDisabledDates];
    } else {
      // For DESIGNATED (all sites with capacity = 1):
      // Block dates only when ALL sites are blocked (no availability across all sites)
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

      // Only block dates that are blocked in ALL sites
      const fullyBlockedDates: string[] = [];
      dateBlockedCount.forEach((count, dateStr) => {
        if (count === siteAvailabilities.length) {
          fullyBlockedDates.push(dateStr);
        }
      });

      fullyBlockedDates.forEach(dateStr => {
        siteBlocked.push(new Date(dateStr));
      });

      // Merge property and site blocks
      return [...siteBlocked, ...propertyDisabledDates];
    }
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

  // Calculate pricing range from available sites
  const prices = sites
    .filter(site => site.isActive)
    .map(site => site.pricing.basePrice);
  const minPrice = prices.length > 0 ? Math.min(...prices) : 0;
  const maxPrice = prices.length > 0 ? Math.max(...prices) : 0;

  // Calculate nights
  const nights =
    booking.dateRange?.from && booking.dateRange?.to
      ? differenceInDays(booking.dateRange.to, booking.dateRange.from)
      : 1;

  // Get maximumNights from sites (for single site properties)
  const maximumNights = useMemo(() => {
    if (!isSingleSiteProperty || sites.length === 0) return undefined;
    // Single site properties may have maximumNights restriction
    return sites[0]?.bookingSettings?.maximumNights;
  }, [isSingleSiteProperty, sites]);

  // Check if selected nights exceed maximum for single site properties
  const exceedsMaxNights = useMemo(() => {
    if (
      !isSingleSiteProperty ||
      !maximumNights ||
      !booking.dateRange?.from ||
      !booking.dateRange?.to
    )
      return false;
    return nights > maximumNights;
  }, [isSingleSiteProperty, maximumNights, nights, booking.dateRange]);

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);
  };

  // Get max capacity from sites
  const maxCapacity = useMemo(() => {
    if (sites.length === 0) return { maxGuests: 20, maxPets: 5 };
    const maxGuests = Math.max(...sites.map(s => s.capacity.maxGuests || 20));
    const maxPets = Math.max(...sites.map(s => s.capacity.maxPets || 5));
    return { maxGuests, maxPets };
  }, [sites]);

  const handleSearch = () => {
    // Validation: Check if dates are selected
    if (!booking.dateRange?.from || !booking.dateRange?.to) {
      setDatePopoverOpen(true);
      return;
    }

    // For undesignated properties, scroll is not needed as there's no sites list
    if (!isUndesignated) {
      // Scroll to sites section
      const sitesSection = document.getElementById('sites');
      if (sitesSection) {
        sitesSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  };

  // Build checkout URL for single site property booking
  const buildUndesignatedCheckoutUrl = () => {
    if (
      !booking.dateRange?.from ||
      !booking.dateRange?.to ||
      !isSingleSiteProperty ||
      sites.length === 0
    )
      return '#';

    // For single site properties, use the site directly
    const site = sites[0];
    const totalPrice = site.pricing.basePrice * nights;

    return (
      `/checkouts/payment?` +
      new URLSearchParams({
        siteId: site._id, // Use siteId for undesignated (single site with maxConcurrentBookings > 1)
        propertyId:
          typeof site.property === 'string' ? site.property : site.property._id,
        name: site.name || property.name, // Use site name if available, fallback to property name
        location: `${property.location.city}, ${property.location.state}`,
        image: property.photos?.[0]?.url || '',
        checkIn: booking.dateRange.from.toISOString(),
        checkOut: booking.dateRange.to.toISOString(),
        basePrice: site.pricing.basePrice.toString(),
        nights: nights.toString(),
        cleaningFee: (site.pricing.cleaningFee || 0).toString(),
        petFee: booking.pets
          ? ((site.pricing.petFee || 0) * booking.pets).toString()
          : '0',
        additionalGuestFee:
          booking.guests > site.capacity.maxGuests
            ? (
                (site.pricing.additionalGuestFee || 0) *
                (booking.guests - site.capacity.maxGuests)
              ).toString()
            : '0',
        total: totalPrice.toString(),
        currency: site.pricing.currency || 'VND',
        guests: booking.guests.toString(),
        pets: booking.pets.toString(),
        vehicles: '1',
      }).toString()
    );
  };

  return (
    <Card className="border-0 shadow-2xl">
      <LoginPromptDialog
        open={showLoginPrompt}
        onOpenChange={setShowLoginPrompt}
      />
      <CardHeader className="pb-4">
        <div className="flex items-baseline justify-between">
          <div>
            {minPrice === maxPrice ? (
              <>
                <span className="text-muted-foreground mr-2 text-sm">Từ</span>
                <span className="text-2xl font-bold">
                  {formatPrice(minPrice)}
                </span>
                <span className="text-muted-foreground text-sm"> / đêm</span>
              </>
            ) : (
              <>
                <span className="text-2xl font-bold">
                  {formatPrice(minPrice)} - {formatPrice(maxPrice)}
                </span>
                <span className="text-muted-foreground text-sm"> / đêm</span>
              </>
            )}
          </div>
          {property.rating && property.rating.average > 0 && (
            <div className="flex items-center gap-1 text-sm">
              <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
              <span className="font-semibold">
                {property.rating.average.toFixed(1)}
              </span>
              <span className="text-muted-foreground">
                ({property.rating.count})
              </span>
            </div>
          )}
        </div>
        {computedTotalSites > 0 && (
          <span
            className={`mt-2 w-fit text-xs ${computedTotalSites < 3 ? 'text-destructive' : ''} `}
          >
            Còn {computedTotalSites} vị trí cắm trại
          </span>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Date Range Popover */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Ngày</label>
          <DateRangePopover
            dateRange={booking.dateRange}
            onDateChange={booking.setDateRange}
            disabledDates={allDisabledDates}
            open={datePopoverOpen}
            onOpenChange={setDatePopoverOpen}
            placeholder="Chọn ngày"
            buttonClassName="w-full"
            align="start"
          />
          {/* Booking restrictions info */}
          <div className="text-muted-foreground space-y-0.5 text-xs">
            {property.settings?.minimumAdvanceNotice &&
              property.settings.minimumAdvanceNotice > 0 && (
                <p>
                  📅 Đặt trước tối thiểu:{' '}
                  {property.settings.minimumAdvanceNotice < 24
                    ? `${property.settings.minimumAdvanceNotice} giờ`
                    : `${Math.round(property.settings.minimumAdvanceNotice / 24)} ngày`}
                </p>
              )}
            {property.settings?.bookingWindow &&
              property.settings.bookingWindow < 365 && (
                <p>
                  🗓️ Đặt tối đa: {property.settings.bookingWindow} ngày trước
                </p>
              )}
          </div>
        </div>

        {/* Weather Advice */}
        {booking.dateRange?.from && (
          <WeatherAdvice
            latitude={property.location?.coordinates?.coordinates?.[1] ?? 0}
            longitude={property.location?.coordinates?.coordinates?.[0] ?? 0}
            checkIn={booking.dateRange.from}
            checkOut={booking.dateRange.to}
          />
        )}

        {/* Guests Popover */}
        <div className="space-y-2">
          <label className="text-sm font-medium">Khách</label>
          <GuestPopover
            adults={adults}
            childrenCount={children}
            pets={booking.pets}
            onAdultsChange={val => handleGuestsChange(val, children)}
            onChildrenChange={val => handleGuestsChange(adults, val)}
            onPetsChange={booking.setPets}
            open={guestPopoverOpen}
            onOpenChange={setGuestPopoverOpen}
            maxGuests={maxCapacity.maxGuests}
            maxPets={maxCapacity.maxPets}
            showPets={property.petPolicy?.allowed ?? false}
            buttonClassName="w-full"
            align="start"
            labels={{
              adultsSubtext: 'Từ 13 tuổi trở lên',
              childrenSubtext: 'Dưới 13 tuổi',
            }}
          />
        </div>

        {/* CTA Button - Different for designated vs undesignated */}
        {isSingleSiteProperty ? (
          // Single site property (designated or undesignated)
          <div className="space-y-2">
            {/* Maximum nights warning */}
            {exceedsMaxNights && maximumNights && (
              <p className="text-destructive text-center text-sm font-medium">
                Tối đa {maximumNights} đêm
              </p>
            )}
            <Button
              className="w-full"
              size="lg"
              disabled={
                !booking.dateRange?.from ||
                !booking.dateRange?.to ||
                exceedsMaxNights
              }
              asChild={
                !!(
                  booking.dateRange?.from &&
                  booking.dateRange?.to &&
                  !exceedsMaxNights
                )
              }
              variant={exceedsMaxNights ? 'outline' : 'default'}
            >
              {booking.dateRange?.from && booking.dateRange?.to ? (
                exceedsMaxNights ? (
                  <span>Đổi ngày</span>
                ) : (
                  <Link
                    href={buildUndesignatedCheckoutUrl()}
                    onClick={e => {
                      const isAuthenticated =
                        useAuthStore.getState().isAuthenticated;
                      if (!isAuthenticated) {
                        e.preventDefault();
                        setShowLoginPrompt(true);
                      }
                    }}
                  >
                    Đặt chỗ ngay
                  </Link>
                )
              ) : (
                <span>Chọn ngày để đặt chỗ</span>
              )}
            </Button>
          </div>
        ) : (
          // Multiple sites property: Search for available sites
          <Button className="w-full" size="lg" onClick={handleSearch}>
            Tìm vị trí cắm trại phù hợp
          </Button>
        )}

        {/* Info Text */}
        {booking.dateRange?.from &&
          booking.dateRange?.to &&
          !exceedsMaxNights && (
            <div className="text-center">
              <p className="text-muted-foreground text-sm">
                {nights} đêm · {booking.guests} khách
                {children > 0 && ` (${children} trẻ em)`}
                {booking.pets > 0 && ` · ${booking.pets} thú cưng`}
              </p>
              {isSingleSiteProperty ? (
                <p className="text-muted-foreground mt-1 text-xs">
                  {isUndesignated
                    ? 'Vị trí cụ thể sẽ được chọn khi check-in'
                    : 'Xác nhận để hoàn tất đặt chỗ'}
                </p>
              ) : (
                <p className="text-muted-foreground mt-1 text-xs">
                  Giá cụ thể sẽ hiển thị khi chọn vị trí cắm trại
                </p>
              )}
            </div>
          )}
      </CardContent>
    </Card>
  );
}
