/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { cn } from '@/lib/utils';
import type { Booking } from '@/types/property-site';
import { Calendar as CalendarIcon, ChevronLeft, ChevronRight, DollarSign, TrendingUp, Users } from 'lucide-react';
import { useMemo, useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';

interface BookingCalendarProps {
  bookings: Booking[];
  onBookingClick: (booking: Booking) => void;
  currentDate?: Date;
  onMonthChange?: (date: Date) => void;
  maxConcurrent?: number;
  blockedSlotsByDate?: Record<string, number>;
  onBlockDate?: (date: Date, slotsToBlock: number, reason?: string) => Promise<void>;
  onUnblockDate?: (date: Date) => Promise<void>;
}

interface CalendarDay {
  date: Date;
  bookings: Booking[];
  isCurrentMonth: boolean;
  isToday: boolean;
}

const STATUS_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  unpaid: { bg: 'bg-amber-500', text: 'text-white', dot: 'bg-amber-400' },
  confirmed: { bg: 'bg-emerald-500', text: 'text-white', dot: 'bg-emerald-400' },
  cancelled: { bg: 'bg-red-500', text: 'text-white', dot: 'bg-red-400' },
  completed: { bg: 'bg-blue-500', text: 'text-white', dot: 'bg-blue-400' },
  refunded: { bg: 'bg-purple-500', text: 'text-white', dot: 'bg-purple-400' },
};

const STATUS_LABELS: Record<string, string> = {
  unpaid: 'Chưa thanh toán', confirmed: 'Đã xác nhận',
  cancelled: 'Đã hủy', completed: 'Hoàn thành', refunded: 'Đã hoàn tiền',
};

const getBookingConnectionClass = (booking: any, currentDate: Date) => {
  const d = new Date(currentDate); d.setHours(0, 0, 0, 0);
  const ci = new Date(booking.checkIn); ci.setHours(0, 0, 0, 0);
  const co = new Date(booking.checkOut); co.setHours(0, 0, 0, 0);

  const isStart = d.getTime() === ci.getTime();
  const isEnd = d.getTime() === co.getTime();

  if (isStart && isEnd) return 'rounded-md';
  if (isStart) return 'rounded-l-md rounded-r-none';
  if (isEnd) return 'rounded-r-md rounded-l-none';
  return 'rounded-none';
};

export function BookingCalendar({ 
  bookings, 
  onBookingClick,
  currentDate: propCurrentDate,
  onMonthChange,
  maxConcurrent = 1,
  blockedSlotsByDate = {},
  onBlockDate,
  onUnblockDate,
}: BookingCalendarProps) {
  const [internalCurrentDate, setInternalCurrentDate] = useState(new Date());
  const [selectedDay, setSelectedDay] = useState<CalendarDay | null>(null);
  const [hoveredBookingId, setHoveredBookingId] = useState<string | null>(null);
  const [blockSlotsInput, setBlockSlotsInput] = useState<number>(0);
  const [blockReason, setBlockReason] = useState('');
  const [blockLoading, setBlockLoading] = useState(false);

  const currentDate = propCurrentDate || internalCurrentDate;
  const setCurrentDate = (date: Date) => {
    if (onMonthChange) {
      onMonthChange(date);
    } else {
      setInternalCurrentDate(date);
    }
  };

  const calendarDays = useMemo(() => {
    const year = currentDate.getFullYear();
    const month = currentDate.getMonth();
    const firstDay = new Date(year, month, 1);
    const startDate = new Date(firstDay);
    const dow = firstDay.getDay();
    startDate.setDate(firstDay.getDate() - (dow === 0 ? 6 : dow - 1));

    const days: CalendarDay[] = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    for (let i = 0; i < 42; i++) {
      const date = new Date(startDate);
      date.setDate(startDate.getDate() + i);
      date.setHours(0, 0, 0, 0);

      const dayBookings = bookings.filter(b => {
        const ci = new Date(b.checkIn); ci.setHours(0, 0, 0, 0);
        const co = new Date(b.checkOut); co.setHours(0, 0, 0, 0);
        return date >= ci && date <= co;
      });

      days.push({ date, bookings: dayBookings, isCurrentMonth: date.getMonth() === month, isToday: date.getTime() === today.getTime() });
    }
    return days;
  }, [currentDate, bookings]);

  const bookingSlots = useMemo(() => {
    // Sort all bookings to assign slots consistently:
    // Sort by checkIn date ascending, then duration descending (longer stays get lower slots), then id
    const sorted = [...bookings].sort((a, b) => {
      const ciA = new Date(a.checkIn).getTime();
      const ciB = new Date(b.checkIn).getTime();
      if (ciA !== ciB) return ciA - ciB;
      
      const durA = new Date(a.checkOut).getTime() - ciA;
      const durB = new Date(b.checkOut).getTime() - ciB;
      if (durB !== durA) return durB - durA;

      const idA = a._id || (a as any).id || '';
      const idB = b._id || (b as any).id || '';
      return idA.localeCompare(idB);
    });

    const slots: Record<string, number> = {};
    const slotOccupied: { start: number; end: number }[][] = [];

    sorted.forEach(booking => {
      const start = new Date(booking.checkIn); start.setHours(0,0,0,0);
      const end = new Date(booking.checkOut); end.setHours(0,0,0,0);
      const startMs = start.getTime();
      const endMs = end.getTime();

      const bookingId = booking._id || (booking as any).id || '';

      let assignedSlot = 0;
      while (true) {
        if (!slotOccupied[assignedSlot]) {
          slotOccupied[assignedSlot] = [];
        }
        
        const hasOverlap = slotOccupied[assignedSlot].some(interval => {
          return startMs <= interval.end && interval.start <= endMs;
        });

        if (!hasOverlap) {
          slotOccupied[assignedSlot].push({ start: startMs, end: endMs });
          slots[bookingId] = assignedSlot;
          break;
        }
        assignedSlot++;
      }
    });

    return slots;
  }, [bookings]);

  const monthStats = useMemo(() => {
    const mb = bookings.filter(b => {
      const ci = new Date(b.checkIn);
      return ci.getMonth() === currentDate.getMonth() && ci.getFullYear() === currentDate.getFullYear();
    });
    return {
      total: mb.length,
      unpaid: mb.filter(b => b.paymentStatus === 'pending').length,
      confirmed: mb.filter(b => b.status === 'confirmed' && b.paymentStatus === 'paid').length,
      revenue: mb.filter(b => b.paymentStatus === 'paid').reduce((s, b) => s + b.pricing.total, 0),
    };
  }, [bookings, currentDate]);

  const formatPrice = (p: number) => new Intl.NumberFormat('vi-VN').format(p);
  const monthYear = currentDate.toLocaleDateString('vi-VN', { month: 'long', year: 'numeric' });

  const statCards = [
    { label: 'Tổng booking', value: monthStats.total, icon: CalendarIcon, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/30' },
    { label: 'Chưa thanh toán', value: monthStats.unpaid, icon: TrendingUp, color: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-900/30' },
    { label: 'Đã xác nhận', value: monthStats.confirmed, icon: Users, color: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-50 dark:bg-emerald-950/30' },
    { label: 'Doanh thu', value: `${formatPrice(monthStats.revenue)}₫`, icon: DollarSign, color: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-900/30', small: true },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold capitalize text-foreground">{monthYear}</h2>
          <p className="text-xs text-muted-foreground mt-0.5">{monthStats.total} booking trong tháng này</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentDate(new Date())}
            className="rounded-lg border border-border bg-card px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            Hôm nay
          </button>
          <div className="flex rounded-lg border border-border bg-card overflow-hidden">
            <button
              onClick={() => setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() - 1))}
              className="p-2 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + 1))}
              className="p-2 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors border-l border-border"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Stats */}
      {/* <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {statCards.map(s => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="flex items-center gap-3 rounded-xl border border-border bg-card p-3 shadow-sm">
              <div className={cn('flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg', s.bg)}>
                <Icon className={cn('h-4 w-4', s.color)} />
              </div>
              <div className="min-w-0">
                <p className="text-xs text-muted-foreground truncate">{s.label}</p>
                <p className={cn('font-bold', s.color, (s as any).small ? 'text-sm' : 'text-xl')}>{s.value}</p>
              </div>
            </div>
          );
        })}
      </div> */}

      {/* Calendar grid */}
      <div className="rounded-xl border border-border bg-card shadow-sm overflow-hidden">
        {/* Weekday headers */}
        <div className="grid grid-cols-7 border-b border-border bg-muted/40">
          {['T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'CN'].map((d, i) => (
            <div key={d} className={cn('py-2.5 text-center text-xs font-semibold text-muted-foreground', i === 6 && 'text-red-500 dark:text-red-400')}>
              {d}
            </div>
          ))}
        </div>

        {/* Days */}
        <div className="grid grid-cols-7 divide-x divide-y divide-border">
          {calendarDays.map((day, idx) => {
            const hasBookings = day.bookings.length > 0;
            return (
              <div
                key={idx}
                className={cn(
                  'relative min-h-[90px] p-2 transition-colors',
                  day.isCurrentMonth ? 'bg-card' : 'bg-muted/20',
                  day.isToday && 'bg-emerald-50/60 dark:bg-emerald-950/30',
                  hasBookings && 'cursor-pointer hover:bg-accent/50',
                )}
                onClick={() => {
                  if (hasBookings) {
                    setSelectedDay(day);
                  }
                }}
              >
                {/* Day number */}
                <div className={cn(
                  'inline-flex h-6 w-6 items-center justify-center rounded-full text-xs font-medium mb-1',
                  day.isToday ? 'bg-emerald-600 text-white font-bold' :
                    day.isCurrentMonth ? 'text-foreground' : 'text-muted-foreground/50',
                  idx % 7 === 6 && !day.isToday && 'text-red-500 dark:text-red-400',
                )}>
                  {day.date.getDate()}
                </div>

                {/* Slot availability badge */}
                {day.isCurrentMonth && (() => {
                  const dateStr = day.date.toISOString().split('T')[0];
                  const bookedCount = day.bookings.reduce((sum, b) => sum + ((b as any).numberOfUnits || 1), 0);
                  const manualBlocked = blockedSlotsByDate[dateStr] || 0;
                  const free = Math.max(0, maxConcurrent - bookedCount - manualBlocked);
                  const isFull = free === 0;
                  const hasPartialBlock = manualBlocked > 0 && !isFull;
                  return (
                    <div className={cn(
                      'mb-1 inline-flex items-center gap-0.5 rounded-md px-1 py-0.5 text-[9px] font-bold leading-none',
                      isFull
                        ? 'bg-rose-100 text-rose-700 dark:bg-rose-950/40 dark:text-rose-400'
                        : hasPartialBlock
                          ? 'bg-amber-100 text-amber-700 dark:bg-amber-950/40 dark:text-amber-400'
                          : free <= Math.ceil(maxConcurrent / 2)
                            ? 'bg-amber-100 text-amber-700 dark:bg-amber-950/40 dark:text-amber-400'
                            : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400'
                    )}>
                      <span className={cn('h-1.5 w-1.5 rounded-full',
                        isFull ? 'bg-rose-500' : hasPartialBlock ? 'bg-amber-500 animate-pulse' : free <= Math.ceil(maxConcurrent / 2) ? 'bg-amber-500' : 'bg-emerald-500'
                      )} />
                      {isFull ? 'Hết chỗ' : `${free}/${maxConcurrent}`}
                      {hasPartialBlock && <span className="ml-0.5 opacity-70">&#128295;</span>}
                    </div>
                  );
                })()}

                {/* Bookings */}
                <div className="space-y-0.5">
                  {(() => {
                    // Find max slot index for this day
                    let maxSlotForDay = -1;
                    day.bookings.forEach(booking => {
                      const bId = booking._id || (booking as any).id || '';
                      const slot = bookingSlots[bId] ?? 0;
                      if (slot > maxSlotForDay) {
                        maxSlotForDay = slot;
                      }
                    });

                    if (maxSlotForDay === -1) return null;

                    // Render slots from 0 to maxSlotForDay
                    return Array.from({ length: maxSlotForDay + 1 }, (_, slotIndex) => {
                      const booking = day.bookings.find(b => {
                        const bId = b._id || (b as any).id || '';
                        return bookingSlots[bId] === slotIndex;
                      });

                      if (!booking) {
                        // Render empty placeholder to keep other slots aligned vertically
                        return (
                          <button
                            key={`empty-${slotIndex}`}
                            tabIndex={-1}
                            aria-hidden="true"
                            className="w-full text-left opacity-0 pointer-events-none select-none group cursor-default"
                          >
                            <div className="h-[30px] px-1.5 py-0.5 text-[10px] leading-[14px] font-medium flex flex-col justify-center">
                              <div className="font-semibold leading-[14px]">{'\u00A0'}</div>
                              <div className="text-[9px] leading-[12px]">{'\u00A0'}</div>
                            </div>
                          </button>
                        );
                      }

                      const getBookingDisplayStatus = (b: any) => {
                        if (b.paymentStatus === 'pending') return 'unpaid';
                        return b.status;
                      };
                      const displayStatus = getBookingDisplayStatus(booking);
                      const statusColors = STATUS_COLORS[displayStatus] || STATUS_COLORS.unpaid;
                      const guest = typeof booking.guest === 'object' ? booking.guest : null;
                      const site = typeof booking.site === 'object' ? booking.site : null;
                      const connectionClass = getBookingConnectionClass(booking, day.date);

                      // Check if we should show the booking text on this day:
                      // Show text only on the actual check-in day, OR if the check-in day is before the calendar
                      // start date, show it on the first day of the calendar view so it's not completely blank.
                      const d = new Date(day.date); d.setHours(0,0,0,0);
                      const ci = new Date(booking.checkIn); ci.setHours(0,0,0,0);
                      const isStart = d.getTime() === ci.getTime();
                      
                      const firstCalendarDate = calendarDays[0].date;
                      const isPastStart = ci.getTime() < firstCalendarDate.getTime();
                      const isFirstVisibleDay = isPastStart && d.getTime() === firstCalendarDate.getTime();
                      
                      const showText = isStart || isFirstVisibleDay;
                      const bId = booking._id || (booking as any).id || '';

                      return (
                        <button
                          key={bId}
                          onMouseEnter={() => setHoveredBookingId(bId)}
                          onMouseLeave={() => setHoveredBookingId(null)}
                          onClick={(e) => {
                            e.stopPropagation();
                            onBookingClick(booking);
                          }}
                          className="w-full text-left group cursor-pointer"
                        >
                          <div className={cn(
                            'h-[30px] px-1.5 py-0.5 text-[10px] leading-[14px] font-medium group-hover:opacity-80 transition-all duration-150 flex flex-col justify-center',
                            statusColors.bg,
                            statusColors.text,
                            connectionClass,
                            hoveredBookingId === bId && 'brightness-[1.12] saturate-[1.08] shadow-sm font-semibold'
                          )}>
                            <div className="truncate font-semibold leading-[14px]">
                              {showText ? ((guest as any)?.name || 'Khách') : '\u00A0'}
                            </div>
                            {site && (
                              <div className="truncate opacity-80 text-[9px] leading-[12px]">
                                {showText ? site.name : '\u00A0'}
                              </div>
                            )}
                          </div>
                        </button>
                      );
                    });
                  })()}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border pt-4">
        <span className="text-xs font-semibold text-muted-foreground">Trạng thái:</span>
        {Object.entries(STATUS_COLORS).map(([status, colors]) => (
          <div key={status} className="flex items-center gap-1.5">
            <span className={cn('h-2.5 w-2.5 rounded-sm', colors.bg)} />
            <span className="text-xs text-muted-foreground">{STATUS_LABELS[status]}</span>
          </div>
        ))}
      </div>

      {/* Daily bookings popup dialog */}
      <Dialog open={!!selectedDay} onOpenChange={(open) => { if (!open) { setSelectedDay(null); setBlockSlotsInput(0); setBlockReason(''); } }}>
        <DialogContent className="sm:max-w-md rounded-2xl border-stone-200">
          <DialogHeader>
            <DialogTitle className="text-lg font-bold text-stone-900">
              {selectedDay?.date.toLocaleDateString('vi-VN', { weekday: 'long', day: '2-digit', month: '2-digit', year: 'numeric' })}
            </DialogTitle>
            <DialogDescription className="text-stone-500 text-xs">
              {selectedDay?.bookings.length
                ? `${selectedDay.bookings.length} lượt đặt chỗ trong ngày này`
                : 'Chưa có booking nào trong ngày này'}
            </DialogDescription>
          </DialogHeader>

          {/* Booking list */}
          {selectedDay?.bookings && selectedDay.bookings.length > 0 && (
            <div className="max-h-[200px] overflow-y-auto space-y-2 pr-1">
              {selectedDay.bookings.map((booking) => {
                const getBookingDisplayStatus = (b: any) => {
                  if (b.paymentStatus === 'pending') return 'unpaid';
                  return b.status;
                };
                const displayStatus = getBookingDisplayStatus(booking);
                const colors = STATUS_COLORS[displayStatus] || STATUS_COLORS.unpaid;
                const label = STATUS_LABELS[displayStatus] || 'Chưa thanh toán';
                const guest = typeof booking.guest === 'object' ? booking.guest : null;
                const site = typeof booking.site === 'object' ? booking.site : null;
                return (
                  <div
                    key={booking._id}
                    onClick={() => { onBookingClick(booking); setSelectedDay(null); }}
                    className="flex items-center justify-between p-3 rounded-xl border border-stone-200 hover:border-stone-300 bg-stone-50/50 hover:bg-stone-50 cursor-pointer transition-all duration-150 group"
                  >
                    <div className="min-w-0 flex-1 pr-3">
                      <p className="font-semibold text-sm text-stone-950 truncate group-hover:text-emerald-800 transition-colors">
                        {(guest as any)?.name || (booking as any).fullnameGuest || '—'}
                      </p>
                      <p className="text-xs text-stone-500 truncate mt-0.5">
                        {site?.name || 'Vị trí cắm trại'}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                      <span className={cn('inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[10px] font-semibold text-white', colors.bg)}>
                        <span className={cn('h-1.5 w-1.5 rounded-full', colors.dot)} />
                        {label}
                      </span>
                      <span className="text-[10px] text-stone-400">
                        {new Date(booking.checkIn).toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit' })} -{' '}
                        {new Date(booking.checkOut).toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit' })}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Block / Unblock section */}
          {(onBlockDate || onUnblockDate) && (
            <div className="border-t border-stone-100 pt-4 space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-extrabold uppercase tracking-wider text-stone-400">Khóa ngày này</p>
                {selectedDay && (() => {
                  const dateStr = selectedDay.date.toISOString().split('T')[0];
                  const currentBlocked = blockedSlotsByDate[dateStr] || 0;
                  return currentBlocked > 0 ? (
                    <span className="text-[10px] bg-amber-100 text-amber-700 font-semibold rounded-full px-2 py-0.5">
                      Đang khóa {currentBlocked}/{maxConcurrent} chỗ
                    </span>
                  ) : null;
                })()}
              </div>

              {maxConcurrent > 1 && (
                <div className="space-y-1">
                  <label className="text-xs text-stone-500 font-medium">
                    Số chỗ muốn khóa <span className="text-stone-400">(0 = khóa hết {maxConcurrent} chỗ)</span>
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min={0}
                      max={maxConcurrent}
                      value={blockSlotsInput || ''}
                      onChange={(e) => setBlockSlotsInput(Number(e.target.value) || 0)}
                      placeholder={`1 – ${maxConcurrent}`}
                      className="w-24 h-9 rounded-lg border border-stone-200 px-3 text-sm focus:outline-none focus:ring-2 focus:ring-rose-300"
                    />
                    <span className="text-xs text-stone-400">/ {maxConcurrent} chỗ</span>
                    {blockSlotsInput > 0 && blockSlotsInput < maxConcurrent && (
                      <span className="text-[10px] text-amber-600 font-semibold">
                        Còn {maxConcurrent - blockSlotsInput} chỗ cho khách đặt
                      </span>
                    )}
                  </div>
                </div>
              )}

              <div className="space-y-1">
                <label className="text-xs text-stone-500 font-medium">Lý do (không bắt buộc)</label>
                <input
                  type="text"
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                  placeholder="VD: Bảo trì, sự kiện riêng..."
                  className="w-full h-9 rounded-lg border border-stone-200 px-3 text-sm focus:outline-none focus:ring-2 focus:ring-rose-300"
                />
              </div>

              <div className="flex gap-2 pt-1">
                <button
                  disabled={blockLoading || !onBlockDate}
                  onClick={async () => {
                    if (!selectedDay || !onBlockDate) return;
                    setBlockLoading(true);
                    try {
                      await onBlockDate(selectedDay.date, blockSlotsInput, blockReason || undefined);
                      setSelectedDay(null);
                      setBlockSlotsInput(0);
                      setBlockReason('');
                    } finally { setBlockLoading(false); }
                  }}
                  className="flex-1 h-9 rounded-xl bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white text-xs font-bold transition-colors flex items-center justify-center gap-1.5"
                >
                  {blockLoading ? (
                    <svg className="animate-spin h-3.5 w-3.5" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                    </svg>
                  ) : (
                    <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  )}
                  Khóa ngày
                </button>
                <button
                  disabled={blockLoading || !onUnblockDate}
                  onClick={async () => {
                    if (!selectedDay || !onUnblockDate) return;
                    setBlockLoading(true);
                    try {
                      await onUnblockDate(selectedDay.date);
                      setSelectedDay(null);
                    } finally { setBlockLoading(false); }
                  }}
                  className="flex-1 h-9 rounded-xl border border-stone-300 hover:bg-stone-50 disabled:opacity-50 text-stone-700 text-xs font-bold transition-colors flex items-center justify-center gap-1.5"
                >
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
                  </svg>
                  Mở lịch
                </button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
