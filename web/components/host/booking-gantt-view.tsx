'use client';

import type { DateRangeType } from '@/components/search/date-range-picker';
import { DateRangePopover } from '@/components/search/date-range-popover';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  blockPropertyDates,
  getPropertyBlockedDates,
  unblockPropertyDates,
  getSitesByProperty,
  blockSiteDates,
  unblockSiteDates,
} from '@/lib/property-site-api';
import { cn } from '@/lib/utils';
import type { Booking, PropertyBlockedDates } from '@/types/property-site';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  addDays,
  format,
  getDaysInMonth,
  isSameDay,
  isWeekend as isWeekendDate,
  isWithinInterval,
  startOfDay,
  startOfMonth,
} from 'date-fns';
import {
  Calendar as CalendarIcon,
  ChevronLeft,
  ChevronRight,
  DollarSign,
  Lock,
  X,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import { toast } from 'sonner';

interface BookingGanttViewProps {
  bookings: Booking[];
  properties: Array<{ _id: string; name: string }>; // All host properties for block selection
  onBookingClick: (booking: Booking) => void;
}

const STATUS_COLORS: Record<string, string> = {
  unpaid: 'bg-yellow-500',
  confirmed: 'bg-green-500',
  cancelled: 'bg-red-500',
  completed: 'bg-blue-500',
  refunded: 'bg-purple-500',
};

interface TimelineDay {
  date: Date;
  isToday: boolean;
  isWeekend: boolean;
  isBlocked: boolean;
  blockInfo?: PropertyBlockedDates;
}

export function BookingGanttView({
  bookings,
  properties,
  onBookingClick,
}: BookingGanttViewProps) {
  const [currentDate, setCurrentDate] = useState(new Date());
  const [blockDialogOpen, setBlockDialogOpen] = useState(false);
  const [dateRange, setDateRange] = useState<DateRangeType>();
  const [blockReason, setBlockReason] = useState('');
  const [blockScope, setBlockScope] = useState<'all' | 'specific' | 'site'>('all');
  const [selectedPropertyId, setSelectedPropertyId] = useState<string>(
    properties[0]?._id || '',
  );
  const [selectedSiteId, setSelectedSiteId] = useState<string>('');
  const [sites, setSites] = useState<any[]>([]);
  const [slotsToBlock, setSlotsToBlock] = useState<number>(0);
  const queryClient = useQueryClient();

  // Load sites when property changes
  useMemo(() => {
    async function loadSites() {
      if (!selectedPropertyId) return;
      try {
        const res = await getSitesByProperty(selectedPropertyId);
        const sitesList = res?.data?.sites || res?.sites || [];
        setSites(sitesList);
        if (sitesList.length > 0) {
          setSelectedSiteId(sitesList[0]._id);
        } else {
          setSelectedSiteId('');
        }
      } catch (err) {
        console.error('Lỗi khi tải site:', err);
      }
    }
    loadSites();
  }, [selectedPropertyId]);

  // Fetch blocked dates for all properties
  const { data: allBlockedDates = [] } = useQuery({
    queryKey: [
      'all-properties-blocked-dates',
      properties.map(p => p._id).join(','),
    ],
    queryFn: async () => {
      if (properties.length === 0) return [];
      const results = await Promise.all(
        properties.map(p => getPropertyBlockedDates(p._id)),
      );
      return results.flat();
    },
    enabled: properties.length > 0,
  });

  // Block dates mutation
  const blockMutation = useMutation({
    mutationFn: async ({
      startDate,
      endDate,
      reason,
    }: {
      startDate: string;
      endDate: string;
      reason?: string;
    }) => {
      if (blockScope === 'all') {
        // Block all properties
        await Promise.all(
          properties.map(p =>
            blockPropertyDates(p._id, startDate, endDate, reason),
          ),
        );
      } else if (blockScope === 'specific') {
        // Block specific property
        await blockPropertyDates(
          selectedPropertyId,
          startDate,
          endDate,
          reason,
        );
      } else if (blockScope === 'site') {
        // Block specific site (must construct list of dates between start and end)
        const dates: string[] = [];
        let curr = new Date(startDate);
        const end = new Date(endDate);
        while (curr <= end) {
          dates.push(curr.toISOString().split('T')[0]);
          curr.setDate(curr.getDate() + 1);
        }
        await blockSiteDates(selectedSiteId, dates, reason, slotsToBlock > 0 ? slotsToBlock : undefined);
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['all-properties-blocked-dates'],
      });
      // Invalidate calendar if exists
      queryClient.invalidateQueries({
        queryKey: ['site-availability-calendar'],
      });
      toast.success(
        blockScope === 'all'
          ? 'Đã khóa ngày cho tất cả property'
          : blockScope === 'specific'
            ? 'Đã khóa ngày cho property đã chọn'
            : 'Đã khóa ngày cho site đã chọn',
      );
      setBlockDialogOpen(false);
      setDateRange(undefined);
      setBlockReason('');
      setBlockScope('all');
      setSlotsToBlock(0);
    },
    onError: (err: any) => {
      toast.error(err?.message || 'Không thể khóa ngày');
    },
  });

  // Unblock dates mutation
  const unblockMutation = useMutation({
    mutationFn: async (data: { blockId?: string; isSiteBlock?: boolean; siteId?: string; dates?: string[] }) => {
      if (data.isSiteBlock && data.siteId && data.dates) {
        return unblockSiteDates(data.siteId, data.dates);
      } else if (data.blockId) {
        return unblockPropertyDates(data.blockId);
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['all-properties-blocked-dates'],
      });
      toast.success('Đã bỏ khóa ngày thành công');
    },
    onError: () => {
      toast.error('Không thể bỏ khóa ngày');
    },
  });

  // Generate timeline - shows current month with correct number of days
  const timeline = useMemo(() => {
    const days: TimelineDay[] = [];
    const monthStart = startOfMonth(currentDate);
    const daysInMonth = getDaysInMonth(currentDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Generate all days in the current month
    for (let i = 0; i < daysInMonth; i++) {
      const date = addDays(monthStart, i);

      // Check if this date is blocked
      const blockInfo = allBlockedDates.find(block => {
        const blockStart = startOfDay(new Date(block.startDate));
        const blockEnd = startOfDay(new Date(block.endDate));
        return isWithinInterval(date, { start: blockStart, end: blockEnd });
      });

      days.push({
        date,
        isToday: isSameDay(date, today),
        isWeekend: isWeekendDate(date),
        isBlocked: !!blockInfo,
        blockInfo,
      });
    }

    return days;
  }, [currentDate, allBlockedDates]);

  // Calculate booking positions and group by property name
  const bookingBars = useMemo(() => {
    const daysInMonth = timeline.length;

    // Map bookings to bars with positions
    const bars = bookings
      .map(booking => {
        const checkIn = new Date(booking.checkIn);
        const checkOut = new Date(booking.checkOut);
        checkIn.setHours(0, 0, 0, 0);
        checkOut.setHours(0, 0, 0, 0);

        const property =
          typeof booking.property === 'object' ? booking.property : null;
        const site = typeof booking.site === 'object' ? booking.site : null;
        const guest = typeof booking.guest === 'object' ? booking.guest : null;

        const propertyName = property?.name || 'Unknown Property';
        const guestName =
          (guest && 'fullName' in guest
            ? (guest as { fullName: string }).fullName
            : undefined) ||
          (guest && 'name' in guest
            ? (guest as { name: string }).name
            : undefined) ||
          guest?.username ||
          guest?.email ||
          'Guest';

        // Find start and end positions in timeline
        const startPos = timeline.findIndex(day =>
          isSameDay(day.date, checkIn),
        );
        const endPos = timeline.findIndex(day => isSameDay(day.date, checkOut));

        if (startPos === -1) return null; // Booking not in visible range

        const duration =
          endPos !== -1 ? endPos - startPos + 1 : booking.nights + 1;

        const getBookingDisplayStatus = (b: any) => {
          if (b.paymentStatus === 'pending') return 'unpaid';
          return b.status;
        };
        const displayStatus = getBookingDisplayStatus(booking);

        return {
          booking,
          propertyName,
          propertyId: property?._id || '',
          guestName,
          siteName: site?.name || 'Site',
          startPos,
          duration: duration > 0 ? duration : 1,
          status: displayStatus,
        };
      })
      .filter(Boolean);

    // Group bookings by property name
    const groupedByProperty = bars.reduce(
      (acc, bar) => {
        if (!bar) return acc;
        if (!acc[bar.propertyName]) {
          acc[bar.propertyName] = [];
        }
        acc[bar.propertyName].push(bar);
        return acc;
      },
      {} as Record<string, typeof bars>,
    );

    // Return grouped structure with property name and their bookings
    return Object.entries(groupedByProperty).map(
      ([propertyName, bookings]) => ({
        propertyName,
        bookings,
        daysInMonth,
      }),
    );
  }, [bookings, timeline]);

  // Blocked dates bars (shown as a separate row)
  const blockedBars = useMemo(() => {
    const daysInMonth = timeline.length;

    // Group blocked dates by date range to detect "all properties" blocks
    const blockGroups = new Map<string, typeof allBlockedDates>();

    allBlockedDates.forEach(block => {
      const key = block.isSiteBlock
        ? `site-${block.siteId}-${block.startDate}-${block.endDate}-${block.reason || ''}`
        : `${block.startDate}-${block.endDate}-${block.reason || ''}`;
      if (!blockGroups.has(key)) {
        blockGroups.set(key, []);
      }
      blockGroups.get(key)!.push(block);
    });

    // Convert groups to bars
    const bars: Array<{
      blocks: typeof allBlockedDates;
      startPos: number;
      duration: number;
      daysInMonth: number;
      isAllProperties: boolean;
    }> = [];

    blockGroups.forEach(blocks => {
      const firstBlock = blocks[0];
      const blockStart = startOfDay(new Date(firstBlock.startDate));
      const blockEnd = startOfDay(new Date(firstBlock.endDate));

      // Get month boundaries
      const monthStart = timeline[0].date;
      const monthEnd = timeline[timeline.length - 1].date;

      // Check if block overlaps with current month
      if (blockEnd < monthStart || blockStart > monthEnd) {
        return; // Block is completely outside current month
      }

      // Clamp block dates to current month
      const visibleStart = blockStart < monthStart ? monthStart : blockStart;
      const visibleEnd = blockEnd > monthEnd ? monthEnd : blockEnd;

      // Find positions in timeline
      const startPos = timeline.findIndex(day =>
        isSameDay(startOfDay(day.date), visibleStart),
      );
      const endPos = timeline.findIndex(day =>
        isSameDay(startOfDay(day.date), visibleEnd),
      );

      if (startPos === -1 || endPos === -1) return;

      const duration = endPos - startPos + 1;

      // If blocks.length equals properties.length, it's an "all properties" block
      const isAllProperties = blocks.length === properties.length;

      bars.push({
        blocks,
        startPos,
        duration: duration > 0 ? duration : 1,
        daysInMonth,
        isAllProperties,
      });
    });

    return bars;
  }, [allBlockedDates, timeline, properties.length]);

  const goToPreviousMonth = () => {
    setCurrentDate(
      new Date(currentDate.getFullYear(), currentDate.getMonth() - 1),
    );
  };

  const goToNextMonth = () => {
    setCurrentDate(
      new Date(currentDate.getFullYear(), currentDate.getMonth() + 1),
    );
  };

  const goToToday = () => {
    setCurrentDate(new Date());
  };

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN').format(price);
  };

  const monthYear = currentDate.toLocaleDateString('vi-VN', {
    month: 'long',
    year: 'numeric',
  });

  // Calculate stats
  const stats = useMemo(() => {
    return {
      total: bookings.length,
      unpaid: bookings.filter(b => b.paymentStatus === 'pending').length,
      confirmed: bookings.filter(b => b.status === 'confirmed' && b.paymentStatus === 'paid').length,
      revenue: bookings
        .filter(b => b.paymentStatus === 'paid')
        .reduce((sum, b) => sum + b.pricing.total, 0),
    };
  }, [bookings]);

  const handleBlockDates = () => {
    if (!dateRange?.from || !dateRange?.to) {
      toast.error('Vui lòng chọn ngày bắt đầu và kết thúc');
      return;
    }

    blockMutation.mutate({
      startDate: format(dateRange.from, 'yyyy-MM-dd'),
      endDate: format(dateRange.to, 'yyyy-MM-dd'),
      reason: blockReason || undefined,
    });
  };

  return (
    <div className="space-y-6">
      {/* Header with controls */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-2xl font-bold capitalize">{monthYear}</h2>
          <p className="mt-1 text-sm text-gray-500">
            {properties.length} khu cắm trại · {stats.total} booking
            {stats.total !== 1 ? 's' : ''} ·{' '}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setBlockDialogOpen(true)}
          >
            <Lock className="mr-2 h-4 w-4" />
            Khóa ngày
          </Button>

          <Button variant="outline" size="sm" onClick={goToToday}>
            <CalendarIcon className="mr-2 h-4 w-4" />
            Hôm nay
          </Button>

          <div className="flex items-center gap-1">
            <Button variant="outline" size="icon" onClick={goToPreviousMonth}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="icon" onClick={goToNextMonth}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>

      {/* Stats Overview */}
      {/* <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-100">
              <CalendarIcon className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Tổng số</p>
              <p className="text-xl font-bold">{stats.total}</p>
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-yellow-100">
              <CalendarIcon className="h-5 w-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Chưa thanh toán</p>
              <p className="text-xl font-bold">{stats.unpaid}</p>
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-100">
              <CalendarIcon className="h-5 w-5 text-green-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Đã xác nhận</p>
              <p className="text-xl font-bold">{stats.confirmed}</p>
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-100">
              <DollarSign className="h-5 w-5 text-emerald-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Doanh thu</p>
              <p className="text-lg font-bold">
                {formatPrice(stats.revenue)} ₫
              </p>
            </div>
          </div>
        </Card>
      </div> */}

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 rounded-lg border bg-white p-4">
        <span className="text-sm font-medium text-gray-700">Trạng thái:</span>
        <div className="flex items-center gap-2">
          <div className="h-3 w-8 rounded bg-gray-400" />
          <span className="text-sm text-gray-600">Khóa</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-8 rounded bg-yellow-500" />
          <span className="text-sm text-gray-600">Chưa thanh toán</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-8 rounded bg-green-500" />
          <span className="text-sm text-gray-600">Đã xác nhận</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-8 rounded bg-blue-500" />
          <span className="text-sm text-gray-600">Hoàn thành</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-8 rounded bg-red-500" />
          <span className="text-sm text-gray-600">Đã hủy</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-3 w-8 rounded bg-purple-500" />
          <span className="text-sm text-gray-600">Đã hoàn tiền</span>
        </div>
      </div>

      {/* Gantt Timeline */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          {bookingBars.length > 0 || blockedBars.length > 0 ? (
            <div className="min-w-[800px]">
              {/* Timeline header */}
              <div className="sticky top-0 z-10 flex border-b bg-gray-50">
                <div className="w-48 shrink-0 border-r p-3 font-semibold">
                  Booking
                </div>
                <div className="flex flex-1">
                  {timeline.map((day, index) => (
                    <div
                      key={index}
                      className={cn(
                        'flex flex-1 flex-col border-r p-2 text-center text-xs', // thêm flex-col
                        day.isToday && 'bg-emerald-50',
                        day.isWeekend && 'bg-gray-100',
                        day.isBlocked && 'bg-gray-200',
                      )}
                    >
                      <div className="font-medium">
                        {day.date.toLocaleDateString('vi-VN', {
                          day: '2-digit',
                        })}
                      </div>

                      <div className="text-gray-500">
                        {day.date.toLocaleDateString('vi-VN', {
                          weekday: 'short',
                        })}
                      </div>

                      {day.isBlocked && (
                        <Lock className="mx-auto mt-auto h-3 w-3 text-gray-500" />
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Blocked dates row */}
              {blockedBars.length > 0 && (
                <div
                  className="flex border-b bg-gray-50"
                  style={{
                    minHeight: `${Math.max(56, blockedBars.length * 40 + 16)}px`,
                  }}
                >
                  <div className="w-48 shrink-0 border-r p-3">
                    <div className="flex items-center gap-2 text-sm font-medium text-gray-700">
                      <Lock className="h-4 w-4" />
                      Các ngày đã khóa
                    </div>
                    <div className="text-xs text-gray-500">
                      {blockedBars.length} block
                      {blockedBars.length > 1 ? 's' : ''}
                    </div>
                  </div>
                  <div className="relative flex flex-1">
                    {/* Grid lines */}
                    {timeline.map((day, dayIndex) => (
                      <div
                        key={dayIndex}
                        className={cn(
                          'flex-1 border-r',
                          day.isWeekend && 'bg-gray-50',
                        )}
                      />
                    ))}

                    {/* Blocked bars */}
                    {blockedBars.map((bar, barIndex) => {
                      if (!bar || bar.startPos >= bar.daysInMonth) return null;

                      const displayText = bar.isAllProperties
                        ? 'Tất cả'
                        : bar.blocks[0].isSiteBlock
                          ? `${bar.blocks[0].siteName} (Khóa site)`
                          : typeof bar.blocks[0].property === 'object'
                            ? bar.blocks[0].property.name
                            : 'Unknown Property';

                      const tooltipText = bar.isAllProperties
                        ? `Tất cả property - ${bar.blocks[0].reason || 'Blocked'}`
                        : bar.blocks[0].isSiteBlock
                          ? `Site: ${bar.blocks[0].siteName} - ${bar.blocks[0].reason || 'Blocked'}`
                          : `${displayText} - ${bar.blocks[0].reason || 'Blocked'}`;

                      return (
                        <div
                          key={barIndex}
                          className="group absolute rounded bg-gray-400/90 px-2 text-xs font-medium text-white transition-all hover:z-10 hover:bg-gray-500"
                          style={{
                            top: `${8 + barIndex * 40}px`,
                            left: `${(bar.startPos / bar.daysInMonth) * 100}%`,
                            width: `${Math.min(
                              (bar.duration / bar.daysInMonth) * 100,
                              ((bar.daysInMonth - bar.startPos) /
                                bar.daysInMonth) *
                              100,
                            )}%`,
                            height: '22px',
                          }}
                          title={tooltipText}
                        >
                          <div className="flex h-full items-center justify-between rounded-2xl">
                            <span className="truncate">{displayText}</span>
                            <button
                              onClick={async () => {
                                // If blocking all properties, unblock all of them
                                if (bar.isAllProperties) {
                                  await Promise.all(
                                    bar.blocks.map(block =>
                                      unblockMutation.mutateAsync({ blockId: block._id }),
                                    ),
                                  );
                                } else if (bar.blocks[0].isSiteBlock) {
                                  const block = bar.blocks[0];
                                  unblockMutation.mutate({
                                    isSiteBlock: true,
                                    siteId: block.siteId,
                                    dates: block.dates,
                                  });
                                } else {
                                  unblockMutation.mutate({ blockId: bar.blocks[0]._id });
                                }
                              }}
                              className="ml-2 rounded p-0.5 opacity-0 transition-opacity group-hover:opacity-100 hover:bg-gray-600"
                              title="Bỏ khóa"
                            >
                              <X className="h-3 w-3" />
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Booking rows - grouped by property */}
              <div className="relative">
                {bookingBars.map((group, groupIndex) => (
                  <div
                    key={groupIndex}
                    className="flex border-b hover:bg-gray-50"
                    style={{
                      minHeight: `${Math.max(56, group.bookings.length * 40 + 16)}px`,
                    }}
                  >
                    <div className="w-48 shrink-0 border-r p-3">
                      <div className="truncate text-sm font-medium">
                        {group.propertyName}
                      </div>
                      <div className="text-xs text-gray-500">
                        {group.bookings.length} booking
                        {group.bookings.length > 1 ? 's' : ''}
                      </div>
                    </div>
                    <div className="relative flex flex-1">
                      {/* Grid lines */}
                      {timeline.map((day, dayIndex) => (
                        <div
                          key={dayIndex}
                          className={cn(
                            'flex-1 border-r',
                            day.isWeekend && 'bg-gray-50',
                            day.isBlocked && 'bg-gray-100',
                          )}
                        />
                      ))}

                      {/* Booking bars for this guest - each on separate row */}
                      {group.bookings.map((bar, barIndex) => {
                        if (!bar || bar.startPos >= group.daysInMonth)
                          return null;

                        return (
                          <div
                            key={barIndex}
                            className="absolute cursor-pointer rounded px-2 text-xs font-medium text-white transition-all hover:z-10 hover:opacity-80"
                            style={{
                              top: `${8 + barIndex * 40}px`,
                              left: `${(bar.startPos / group.daysInMonth) * 100}%`,
                              width: `${Math.min(
                                (bar.duration / group.daysInMonth) * 100,
                                ((group.daysInMonth - bar.startPos) /
                                  group.daysInMonth) *
                                100,
                              )}%`,
                              height: '22px',
                            }}
                            onClick={() => onBookingClick(bar.booking)}
                          >
                            <div
                              className={cn(
                                'flex h-full items-center justify-center rounded-2xl px-2',
                                STATUS_COLORS[bar.status],
                              )}
                            >
                              <span className="truncate text-xs">
                                {bar.guestName}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex h-64 items-center justify-center">
              <div className="text-center">
                <CalendarIcon className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-lg font-medium text-gray-900">
                  Chưa có booking nào
                </h3>
                <p className="mt-1 text-sm text-gray-500">
                  Các booking sẽ hiển thị trên timeline
                </p>
              </div>
            </div>
          )}
        </div>
      </Card>
      \
      {/* Block Dates Dialog */}
      <Dialog open={blockDialogOpen} onOpenChange={setBlockDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Khóa ngày</DialogTitle>
            <DialogDescription>
              Chọn phạm vi và khoảng ngày bạn muốn khóa ( chỉ cho phép khóa từ 2 ngày trở lên)
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Scope Selection */}
            <div className="space-y-3">
              <Label className="text-sm font-medium">Phạm vi khóa</Label>
              <RadioGroup
                value={blockScope}
                onValueChange={(value: 'all' | 'specific' | 'site') => {
                  setBlockScope(value);
                  if (
                    (value === 'specific' || value === 'site') &&
                    !selectedPropertyId &&
                    properties.length > 0
                  ) {
                    setSelectedPropertyId(properties[0]._id);
                  }
                }}
                className="space-y-2"
              >
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="all" id="block-all" />
                  <Label
                    htmlFor="block-all"
                    className="cursor-pointer font-normal"
                  >
                    Tất cả property ({properties.length})
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="specific" id="block-specific" />
                  <Label
                    htmlFor="block-specific"
                    className="cursor-pointer font-normal"
                  >
                    Property cụ thể
                  </Label>
                </div>
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="site" id="block-site" />
                  <Label
                    htmlFor="block-site"
                    className="cursor-pointer font-normal"
                  >
                    Vị trí cắm trại cụ thể (Site)
                  </Label>
                </div>
              </RadioGroup>
            </div>

            {/* Property Selection (only when specific or site is selected) */}
            {(blockScope === 'specific' || blockScope === 'site') && (
              <div className="space-y-2">
                <Label
                  htmlFor="property-select"
                  className="text-sm font-medium"
                >
                  Chọn property
                </Label>
                <select
                  id="property-select"
                  value={selectedPropertyId}
                  onChange={e => setSelectedPropertyId(e.target.value)}
                  className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 focus:outline-none"
                >
                  {properties.map(property => (
                    <option key={property._id} value={property._id}>
                      {property.name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Site Selection (only when site is selected) */}
            {blockScope === 'site' && (
              <div className="space-y-2">
                <Label
                  htmlFor="site-select"
                  className="text-sm font-medium"
                >
                  Chọn vị trí cắm trại (Site)
                </Label>
                <select
                  id="site-select"
                  value={selectedSiteId}
                  onChange={e => setSelectedSiteId(e.target.value)}
                  className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 focus:outline-none"
                  disabled={sites.length === 0}
                >
                  {sites.length === 0 ? (
                    <option value="">Khu đất chưa có site nào</option>
                  ) : (
                    sites.map(site => (
                      <option key={site._id} value={site._id}>
                        {site.name}
                      </option>
                    ))
                  )}
                </select>
              </div>
            )}

            {/* Slots to block (only when site is selected and maxConcurrent > 1) */}
            {blockScope === 'site' && selectedSiteId && (() => {
              const selectedSite = sites.find(s => s._id === selectedSiteId);
              const maxConcurrent = selectedSite?.capacity?.maxConcurrentBookings || 1;
              if (maxConcurrent <= 1) return null;
              return (
                <div className="space-y-2">
                  <Label htmlFor="slots-to-block" className="text-sm font-medium">
                    Số chỗ muốn khóa <span className="text-xs text-gray-400 font-normal">(0 = khóa toàn bộ {maxConcurrent} chỗ)</span>
                  </Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="slots-to-block"
                      type="number"
                      min={0}
                      max={maxConcurrent}
                      placeholder={`Ví dụ: 3`}
                      value={slotsToBlock || ''}
                      onChange={e => setSlotsToBlock(Number(e.target.value) || 0)}
                      className="w-24"
                    />
                    <span className="text-xs text-gray-500">/ {maxConcurrent} chỗ</span>
                  </div>
                  {slotsToBlock > 0 && slotsToBlock < maxConcurrent && (
                    <p className="text-[11px] text-amber-600 font-medium">
                      ⚠️ Khóa {slotsToBlock}/{maxConcurrent} chỗ — site vẫn nhận đặt {maxConcurrent - slotsToBlock} chỗ còn lại
                    </p>
                  )}
                  {slotsToBlock === 0 && (
                    <p className="text-[11px] text-red-650 font-medium">
                      🔒 Khóa toàn bộ {maxConcurrent} chỗ — không ai đặt được
                    </p>
                  )}
                </div>
              );
            })()}

            {/* Date Range Selection */}
            <div className="space-y-2">
              <Label className="text-sm font-medium">Chọn ngày *</Label>
              <DateRangePopover
                dateRange={dateRange}
                onDateChange={setDateRange}
                placeholder="Chọn ngày bắt đầu và kết thúc"
                buttonClassName="w-full"
              />
            </div>

            {/* Reason */}
            <div className="space-y-2">
              <Label htmlFor="block-reason" className="text-sm font-medium">
                Lý do (không bắt buộc)
              </Label>
              <Input
                id="block-reason"
                placeholder="VD: Bảo trì, sự kiện riêng..."
                value={blockReason}
                onChange={e => setBlockReason(e.target.value)}
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setBlockDialogOpen(false)}>
              Hủy
            </Button>
            <Button
              onClick={handleBlockDates}
              disabled={
                !dateRange?.from ||
                !dateRange?.to ||
                blockMutation.isPending ||
                (blockScope === 'site' && !selectedSiteId)
              }
            >
              {blockMutation.isPending ? 'Đang xử lý...' : 'Khóa ngày'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
