'use client';

import { useEffect, useState, useMemo, ReactNode } from 'react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Calendar } from '@/components/ui/calendar';
import { Separator } from '@/components/ui/separator';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Calendar as CalendarIcon, Loader2, DollarSign, CalendarCheck, Users, Tent, ArrowRight, CheckCircle2, Clock3 } from 'lucide-react';
import { toast } from 'sonner';
import { getMyProperties, getSitesByProperty } from '@/lib/property-site-api';
import { useRouter } from 'next/navigation';
import { BookingCalendar } from '@/components/host/booking-calendar';

const API = process.env.NEXT_PUBLIC_API_URL;

export default function HostCalendarPage() {
  const [mounted, setMounted] = useState(false);
  const [properties, setProperties] = useState<any[]>([]);
  const [sites, setSites] = useState<any[]>([]);
  const [selectedPropertyId, setSelectedPropertyId] = useState<string>('');
  const [selectedSiteId, setSelectedSiteId] = useState<string>('');
  const [selectedSiteDetail, setSelectedSiteDetail] = useState<any>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Availability calendar details
  const [calendarMonth, setCalendarMonth] = useState<Date>(new Date());
  const [availabilityData, setAvailabilityData] = useState<any>({ bookings: [], blocks: [] });
  const [loadingCalendar, setLoadingCalendar] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  // Seasonal pricing form
  const [seasonalPricing, setSeasonalPricing] = useState<any[]>([]);
  const [newRule, setNewRule] = useState({
    name: '',
    startDate: '',
    endDate: '',
    price: '',
  });

  const router = useRouter();

  const transformedBookings = useMemo(() => {
    if (!availabilityData.bookings) return [];
    return availabilityData.bookings.map((b: any) => ({
      ...b,
      _id: b.id || b._id,
      guest: { name: b.guestName || 'Khách' },
      pricing: { total: b.totalPrice || 0 },
      site: { name: b.unitName || 'Đã đặt' },
      status: b.status || 'confirmed',
      paymentStatus: b.paymentStatus || (b.status === 'confirmed' ? 'paid' : 'pending'),
    }));
  }, [availabilityData.bookings]);

  const maxConcurrent = selectedSiteDetail?.capacity?.maxConcurrentBookings || 1;

  // map: date string -> số chỗ bị partial block
  const blockedSlotsByDate = useMemo(() => {
    const map: Record<string, number> = {};
    if (availabilityData.blocks) {
      (availabilityData.blocks as any[]).forEach((b) => {
        if (b.blockedSlots && b.blockedSlots > 0) {
          const dateStr = new Date(b.date).toISOString().split('T')[0];
          map[dateStr] = b.blockedSlots;
        }
      });
    }
    return map;
  }, [availabilityData.blocks]);
  const handleBookingClick = (booking: any) => {
    if (booking.code) {
      router.push(`/host/bookings/detail/${booking.code}`);
    } else {
      toast.error("Không tìm thấy mã đặt chỗ");
    }
  };

  // Load properties on mount
  useEffect(() => {
    async function loadProperties() {
      try {
        const res = await getMyProperties();
        console.log('getMyProperties response:', res);

        let list: any[] = [];
        if (res && res.properties && Array.isArray(res.properties)) {
          list = res.properties;
        } else if (res && res.data?.properties && Array.isArray(res.data.properties)) {
          list = res.data.properties;
        } else if (res && Array.isArray(res.data)) {
          list = res.data;
        } else if (Array.isArray(res)) {
          list = res;
        }

        setProperties(list);
        if (list.length > 0) {
          setSelectedPropertyId(list[0]._id);
        }
      } catch (err) {
        toast.error('Lỗi khi tải danh sách khu cắm trại');
      }
    }
    loadProperties();
  }, []);

  // Load sites when property changes
  useEffect(() => {
    async function loadSites() {
      if (!selectedPropertyId) return;
      try {
        const res = await getSitesByProperty(selectedPropertyId);
        // getSitesByProperty returns the axios response.data, which is likely { success, data: { sites, pagination } } or { sites }
        const sitesList = res?.data?.sites || res?.sites || [];
        setSites(sitesList);
        if (sitesList.length > 0) {
          setSelectedSiteId(sitesList[0]._id);
        } else {
          setSelectedSiteId('');
        }
      } catch (err) {
        toast.error('Lỗi khi tải các site con');
      }
    }
    loadSites();
  }, [selectedPropertyId]);

  // Fetch calendar availability when site or month changes
  useEffect(() => {
    async function fetchCalendar() {
      if (!selectedSiteId) return;
      setLoadingCalendar(true);
      try {
        const token = localStorage.getItem('accessToken');
        const monthStr = `${calendarMonth.getFullYear()}-${String(calendarMonth.getMonth() + 1).padStart(2, '0')}`;
        const res = await fetch(`${API}/sites/${selectedSiteId}/availability-calendar?month=${monthStr}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setAvailabilityData(data.data || { bookings: [], blocks: [] });
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoadingCalendar(false);
      }
    }

    // Load site details for seasonal pricing & metadata
    async function loadSiteDetails() {
      if (!selectedSiteId) return;
      try {
        const token = localStorage.getItem('accessToken');
        const res = await fetch(`${API}/sites/${selectedSiteId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setSelectedSiteDetail(data.data || null);
          setSeasonalPricing(data.data?.pricing?.seasonalPricing || []);
        }
      } catch (err) {
        console.error(err);
      }
    }

    fetchCalendar();
    loadSiteDetails();
  }, [selectedSiteId, calendarMonth]);

  // Action: Add Seasonal Pricing Rule
  const handleAddSeasonalRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.name || !newRule.startDate || !newRule.endDate || !newRule.price || !selectedSiteId) {
      toast.error('Vui lòng nhập đầy đủ thông tin');
      return;
    }

    setActionLoading(true);
    try {
      const token = localStorage.getItem('accessToken');
      const updatedRules = [
        ...seasonalPricing.map(r => ({
          name: r.name,
          startDate: r.startDate,
          endDate: r.endDate,
          price: r.price,
        })),
        {
          name: newRule.name,
          startDate: newRule.startDate,
          endDate: newRule.endDate,
          price: Number(newRule.price),
        },
      ];

      const res = await fetch(`${API}/sites/${selectedSiteId}/seasonal-pricing`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ seasonalPricing: updatedRules }),
      });

      if (res.ok) {
        toast.success('Thêm cấu hình giá mùa vụ thành công');
        const data = await res.json();
        setSeasonalPricing(data.data?.pricing?.seasonalPricing || []);
        setNewRule({ name: '', startDate: '', endDate: '', price: '' });
      } else {
        const errData = await res.json();
        toast.error(errData.message || 'Lỗi cấu hình giá mùa vụ');
      }
    } catch (err) {
      toast.error('Lỗi kết nối máy chủ');
    } finally {
      setActionLoading(false);
    }
  };

  // Action: Delete Seasonal Rule
  const handleDeleteSeasonalRule = async (indexToDelete: number) => {
    setActionLoading(true);
    try {
      const token = localStorage.getItem('accessToken');
      const updatedRules = seasonalPricing
        .filter((_, idx) => idx !== indexToDelete)
        .map(r => ({
          name: r.name,
          startDate: r.startDate,
          endDate: r.endDate,
          price: r.price,
        }));

      const res = await fetch(`${API}/sites/${selectedSiteId}/seasonal-pricing`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ seasonalPricing: updatedRules }),
      });

      if (res.ok) {
        toast.success('Đã xoá cấu hình giá');
        const data = await res.json();
        setSeasonalPricing(data.data?.pricing?.seasonalPricing || []);
      } else {
        toast.error('Lỗi khi xoá cấu hình');
      }
    } catch (err) {
      toast.error('Có lỗi xảy ra');
    } finally {
      setActionLoading(false);
    }
  };

  // Helper to color code calendar cells
  const getDayClassName = (date: Date) => {
    // Check if is manual blocked
    const dateStr = date.toISOString().split('T')[0];
    const isManualBlock = availabilityData.blocks?.some(
      (b: any) => b.date?.split('T')[0] === dateStr && !b.isAvailable
    );
    if (isManualBlock) return 'bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-400 font-bold border border-red-300';

    // Check if booked
    const isBooked = availabilityData.bookings?.some((b: any) => {
      const checkIn = new Date(b.checkIn);
      const checkOut = new Date(b.checkOut);
      // Clean time values for exact matches
      const checkInStr = checkIn.toISOString().split('T')[0];
      const checkOutStr = checkOut.toISOString().split('T')[0];
      return dateStr >= checkInStr && dateStr <= checkOutStr;
    });

    if (isBooked) return 'bg-slate-200 text-slate-800 dark:bg-slate-800/80 dark:text-slate-400 line-through';

    return 'hover:bg-indigo-50 hover:text-indigo-900';
  };

  // Find bookings overlapping a specific date
  const getBookingsForDate = (date: Date) => {
    if (!availabilityData.bookings) return [];
    const dateStr = date.toISOString().split('T')[0];
    return availabilityData.bookings.filter((b: any) => {
      const checkInStr = new Date(b.checkIn).toISOString().split('T')[0];
      const checkOutStr = new Date(b.checkOut).toISOString().split('T')[0];
      return dateStr >= checkInStr && dateStr < checkOutStr;
    });
  };

  if (!mounted) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-12 w-12 animate-spin rounded-full border-4 border-indigo-650 border-t-transparent"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8 p-6 pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
          Quản Lý Lịch & Giá Mùa Vụ
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Thiết lập trạng thái hoạt động của bãi cắm trại và quản lý các khoảng giá đặc biệt theo các mùa trong năm.
        </p>
      </div>

      {/* Property and Site Selectors */}
      <div className="grid gap-4 md:grid-cols-2 bg-white dark:bg-slate-900/60 p-4 rounded-2xl border border-slate-200/80 dark:border-slate-850">
        <div className="space-y-1.5">
          <Label htmlFor="property" className="text-xs font-bold uppercase tracking-wider text-slate-400">Khu cắm trại chính</Label>
          <Select value={selectedPropertyId} onValueChange={setSelectedPropertyId}>
            <SelectTrigger id="property" className="bg-transparent border-slate-200 dark:border-slate-800 rounded-xl h-11">
              <SelectValue placeholder="Chọn khu cắm trại" />
            </SelectTrigger>
            <SelectContent>
              {properties.map(p => (
                <SelectItem key={p._id} value={p._id}>{p.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="site" className="text-xs font-bold uppercase tracking-wider text-slate-400">Vị trí cắm trại cụ thể (Site)</Label>
          <Select value={selectedSiteId} onValueChange={setSelectedSiteId} disabled={sites.length === 0}>
            <SelectTrigger id="site" className="bg-transparent border-slate-200 dark:border-slate-800 rounded-xl h-11">
              <SelectValue placeholder={sites.length === 0 ? 'Khu đất chưa có site nào' : 'Chọn site'} />
            </SelectTrigger>
            <SelectContent>
              {sites.map(s => (
                <SelectItem key={s._id} value={s._id}>{s.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {selectedSiteId ? (
        <Tabs defaultValue="bookings" className="space-y-6">
          <div className="flex items-center justify-between">
            <TabsList className="bg-slate-100 dark:bg-slate-800 p-1 rounded-xl">
              <TabsTrigger value="bookings" className="rounded-lg px-4 py-2 text-xs font-bold data-[state=active]:bg-white dark:data-[state=active]:bg-slate-900 data-[state=active]:shadow-sm">
                Sơ đồ đặt chỗ
              </TabsTrigger>
              <TabsTrigger value="block-dates" className="rounded-lg px-4 py-2 text-xs font-bold data-[state=active]:bg-white dark:data-[state=active]:bg-slate-900 data-[state=active]:shadow-sm">
                Đóng / Mở lịch & Giá mùa vụ
              </TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="bookings" className="space-y-6 mt-0">
            <div className="bg-white dark:bg-slate-900/60 rounded-2xl border border-slate-200/80 dark:border-slate-850 p-6">
              <BookingCalendar 
                bookings={transformedBookings} 
                onBookingClick={handleBookingClick} 
                currentDate={calendarMonth}
                onMonthChange={setCalendarMonth}
                maxConcurrent={maxConcurrent}
                blockedSlotsByDate={blockedSlotsByDate}
                blocks={availabilityData.blocks}
                showSlotsInfo={true}
              />
            </div>
          </TabsContent>

          <TabsContent value="block-dates" className="mt-0 space-y-6">
            <div className="grid gap-8 lg:grid-cols-3">
              {/* Pricing Panel */}
              <div className="lg:col-span-1 space-y-6">
                <Card className="border border-slate-200/80 dark:border-slate-850">
                  <CardHeader>
                    <CardTitle className="text-md font-extrabold text-slate-800 dark:text-white">Thiết lập giá mùa vụ</CardTitle>
                    <CardDescription className="text-xs">Cấu hình mức giá đặc biệt cho mùa cao điểm hoặc dịp lễ.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <form onSubmit={handleAddSeasonalRule} className="space-y-3.5">
                      <div className="space-y-1">
                        <Label htmlFor="rule-name" className="text-xs font-semibold text-slate-500">Tên mùa vụ / Dịp lễ</Label>
                        <Input
                          id="rule-name"
                          placeholder="Ví dụ: Lễ Tết, Mùa Hè 2026"
                          value={newRule.name}
                          onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                          className="rounded-xl h-10 text-xs"
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-2">
                        <div className="space-y-1">
                          <Label htmlFor="start" className="text-xs font-semibold text-slate-500">Bắt đầu</Label>
                          <Input
                            id="start"
                            type="date"
                            value={newRule.startDate}
                            onChange={(e) => setNewRule({ ...newRule, startDate: e.target.value })}
                            className="rounded-xl h-10 text-xs"
                          />
                        </div>
                        <div className="space-y-1">
                          <Label htmlFor="end" className="text-xs font-semibold text-slate-500">Kết thúc</Label>
                          <Input
                            id="end"
                            type="date"
                            value={newRule.endDate}
                            onChange={(e) => setNewRule({ ...newRule, endDate: e.target.value })}
                            className="rounded-xl h-10 text-xs"
                          />
                        </div>
                      </div>

                      <div className="space-y-1">
                        <Label htmlFor="price" className="text-xs font-semibold text-slate-500">Giá mới mỗi đêm (₫)</Label>
                        <div className="relative">
                          <DollarSign className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                          <Input
                            id="price"
                            type="number"
                            placeholder="Giá/đêm"
                            value={newRule.price}
                            onChange={(e) => setNewRule({ ...newRule, price: e.target.value })}
                            className="rounded-xl h-10 pl-9 text-xs"
                          />
                        </div>
                      </div>

                      <Button type="submit" className="w-full bg-slate-900 hover:bg-slate-800 text-white rounded-xl h-10 text-xs font-bold" disabled={actionLoading}>
                        {actionLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Thêm cấu hình giá'}
                      </Button>
                    </form>

                    <Separator />

                    {/* List of rules */}
                    <div className="space-y-3">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Các mùa đã cấu hình</h4>
                      {seasonalPricing.length === 0 ? (
                        <p className="text-xs text-slate-400 text-center py-4">Chưa có mức giá mùa vụ nào</p>
                      ) : (
                        <div className="space-y-3.5">
                          {seasonalPricing.map((rule, idx) => (
                            <div key={idx} className="p-3.5 bg-slate-50 dark:bg-slate-900/40 rounded-xl border border-slate-100 dark:border-slate-850 flex items-start justify-between">
                              <div className="space-y-1">
                                <p className="text-xs font-extrabold text-slate-800 dark:text-slate-200">{rule.name}</p>
                                <p className="text-[10px] text-slate-400 font-medium">
                                  {new Date(rule.startDate).toLocaleDateString('vi-VN')} - {new Date(rule.endDate).toLocaleDateString('vi-VN')}
                                </p>
                                <p className="text-xs font-black text-indigo-650 dark:text-indigo-400 mt-1.5">
                                  {new Intl.NumberFormat('vi-VN', { style: 'currency', currency: 'VND' }).format(rule.price)} / đêm
                                </p>
                              </div>
                              <Button size="icon" variant="ghost" className="h-8 w-8 text-rose-500 hover:bg-rose-50 rounded-lg" onClick={() => handleDeleteSeasonalRule(idx)}>
                                ✕
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Right Column: Month Bookings list */}
              <div className="lg:col-span-2 space-y-6">
                <Card className="border border-slate-200/80 dark:border-slate-850">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-md font-extrabold text-slate-800 dark:text-white flex items-center gap-2">
                      <CalendarCheck className="h-5 w-5 text-indigo-500" />
                      Danh sách đặt phòng trong tháng
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Danh sách các booking của site này trong tháng {calendarMonth.getMonth() + 1}/{calendarMonth.getFullYear()}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {!availabilityData.bookings || availabilityData.bookings.length === 0 ? (
                      <p className="text-xs text-slate-400 text-center py-6">Chưa có khách cắm trại trong tháng này</p>
                    ) : (
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        {availabilityData.bookings.map((b: any) => {
                          const statusConfig: Record<string, { label: string; color: string; icon: ReactNode }> = {
                            confirmed: { label: 'Đã xác nhận', color: 'text-emerald-700 bg-emerald-50 border-emerald-200 dark:bg-emerald-950/30 dark:text-emerald-400 dark:border-emerald-900/30', icon: <CheckCircle2 className="h-3 w-3" /> },
                            pending:   { label: 'Chờ xác nhận', color: 'text-amber-700 bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:text-amber-400 dark:border-amber-900/30', icon: <Clock3 className="h-3 w-3" /> },
                            completed: { label: 'Hoàn thành', color: 'text-blue-700 bg-blue-50 border-blue-200 dark:bg-blue-950/30 dark:text-blue-400 dark:border-blue-900/30', icon: <CheckCircle2 className="h-3 w-3" /> },
                            cancelled: { label: 'Đã hủy', color: 'text-red-700 bg-red-50 border-red-200 dark:bg-red-950/30 dark:text-red-400 dark:border-red-900/30', icon: null },
                          };
                          const sc = statusConfig[b.status] || statusConfig.pending;
                          return (
                            <div
                              key={b.id}
                              className="py-3 flex items-start justify-between gap-3 text-xs cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-900/40 -mx-2 px-2 rounded-lg transition-colors group"
                              onClick={() => b.code && router.push(`/host/bookings/detail/${b.code}`)}
                            >
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                  <p className="font-extrabold text-slate-900 dark:text-slate-200 truncate">
                                    {b.guestName}
                                  </p>
                                  {b.numberOfUnits > 1 && (
                                    <span className="inline-flex items-center gap-1 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-1.5 py-0.5 text-[10px] font-semibold shrink-0">
                                      {b.numberOfUnits} {selectedSiteDetail?.accommodationType === 'tent' ? 'lều' : 'đơn vị'}
                                    </span>
                                  )}
                                </div>
                                <div className="flex items-center gap-3 text-[10px] text-slate-400 flex-wrap">
                                  <span>
                                    {new Date(b.checkIn).toLocaleDateString('vi-VN')} → {new Date(b.checkOut).toLocaleDateString('vi-VN')}
                                  </span>
                                  {b.numberOfGuests && (
                                    <span className="flex items-center gap-1">
                                      <Users className="h-2.5 w-2.5" />
                                      {b.numberOfGuests} người
                                    </span>
                                  )}
                                  {b.code && (
                                    <span className="font-mono text-[9px] text-slate-300 dark:text-slate-600">#{b.code}</span>
                                  )}
                                </div>
                              </div>
                              <div className="text-right shrink-0 flex flex-col items-end gap-1">
                                <p className="font-bold text-indigo-600 dark:text-indigo-400">
                                  {new Intl.NumberFormat('vi-VN', { style: 'currency', currency: 'VND' }).format(b.totalPrice)}
                                </p>
                                <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold border ${sc.color}`}>
                                  {sc.icon}{sc.label}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>

            {/* Detailed Monthly Tent/Slot Grid */}
            <Card className="border border-slate-205 dark:border-slate-850 mt-8">
              <CardHeader className="pb-3">
                <CardTitle className="text-md font-bold text-slate-800 dark:text-white flex items-center gap-2">
                  <CalendarCheck className="h-5 w-5 text-indigo-600" />
                  Sơ đồ chi tiết & Trạng thái bãi trống trong tháng {calendarMonth.getMonth() + 1}/{calendarMonth.getFullYear()}
                </CardTitle>
                <CardDescription className="text-xs">
                  Theo dõi tình hình hoạt động, hiển thị chi tiết tên lều/vị trí cụ thể đang có khách ở hay đang trống.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {/* Status Legend */}
                <div className="flex gap-5 mb-5 text-xs font-semibold">
                  <div className="flex items-center gap-2">
                    <span className="h-3 w-3 rounded-full bg-emerald-500 inline-block"></span>
                    <span>Còn trống</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="h-3 w-3 rounded-full bg-rose-500 inline-block"></span>
                    <span>Đã bận / Có khách</span>
                  </div>
                </div>

            {/* List of Days */}
            <div className="space-y-3.5 max-h-[500px] overflow-y-auto pr-1">
              {(() => {
                const year = calendarMonth.getFullYear();
                const month = calendarMonth.getMonth();
                const daysCount = new Date(year, month + 1, 0).getDate();
                const daysList = Array.from({ length: daysCount }, (_, i) => new Date(year, month, i + 1));
                
                const maxConcurrent = selectedSiteDetail?.capacity?.maxConcurrentBookings || 1;
                const lodgingProvided = selectedSiteDetail?.lodgingProvided;
                const isBYO = lodgingProvided === "bring_your_own";
                const unitNames = selectedSiteDetail?.unitNames || [];

                return daysList.map((dayDate) => {
                  const dateStr = dayDate.toISOString().split('T')[0];
                  const dayBookings = getBookingsForDate(dayDate);
                  
                  const formattedDay = dayDate.toLocaleDateString('vi-VN', {
                    day: '2-digit',
                    month: '2-digit',
                    weekday: 'short'
                  });

                  return (
                    <div key={dateStr} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-xl border border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/30 hover:bg-slate-50 dark:hover:bg-slate-900/50 transition-colors">
                      {/* Date label */}
                      <div className="sm:w-36 shrink-0">
                        <span className="font-bold text-xs sm:text-sm text-slate-700 dark:text-slate-300">{formattedDay}</span>
                      </div>

                      {/* Capacity display — count-based only */}
                      <div className="flex-1 flex flex-wrap gap-2 justify-start items-center">
                        {maxConcurrent > 1 ? (() => {
                          const bookedCount = dayBookings.reduce((sum: number, b: any) => sum + (b.numberOfUnits || 1), 0);
                          const freeCount = Math.max(0, maxConcurrent - bookedCount);
                          return (
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge className={`border-0 rounded-lg px-2.5 py-1 text-xs font-bold ${
                                freeCount > 0
                                  ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-400"
                                  : "bg-rose-100 text-rose-800 dark:bg-rose-950/30 dark:text-rose-400"
                              }`}>
                                <span className={`h-1.5 w-1.5 rounded-full mr-1.5 inline-block ${freeCount > 0 ? 'bg-emerald-500' : 'bg-rose-500 animate-pulse'}`} />
                                {freeCount > 0 ? `Còn trống ${freeCount}/${maxConcurrent} chỗ` : `Đã đầy (${maxConcurrent}/${maxConcurrent})`}
                              </Badge>
                              {dayBookings.length > 0 && (
                                <p className="text-xs text-slate-500 dark:text-slate-400">
                                  ({dayBookings.map((b: any) => `${b.guestName}${b.numberOfUnits > 1 ? ` ×${b.numberOfUnits}` : ''}`).join(', ')})
                                </p>
                              )}
                            </div>
                          );
                        })() : (
                          <div>
                            {dayBookings.length > 0 ? (
                              <Badge className="bg-rose-50 text-rose-700 dark:bg-rose-950/20 dark:text-rose-450 border border-rose-100 dark:border-rose-900/20 rounded-md px-2 py-0.5 text-xs font-semibold">
                                <span className="h-1.5 w-1.5 rounded-full bg-rose-500 mr-1.5 inline-block" />
                                Đã bận: {dayBookings[0].guestName} ({dayBookings[0].totalPrice?.toLocaleString("vi-VN")} đ)
                              </Badge>
                            ) : (
                              <Badge className="bg-emerald-50 text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-450 border border-emerald-100 dark:border-emerald-900/20 rounded-md px-2 py-0.5 text-xs font-semibold">
                                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 mr-1.5 inline-block" />
                                Sẵn sàng / Trống
                              </Badge>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                });
              })()}
            </div>
          </CardContent>
        </Card>
          </TabsContent>
        </Tabs>
      ) : (
        <div className="flex flex-col items-center justify-center p-12 text-center bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl">
          <CalendarIcon className="h-12 w-12 text-slate-300 animate-pulse" />
          <h3 className="mt-4 text-sm font-bold text-slate-800 dark:text-slate-200">Chưa lựa chọn site</h3>
          <p className="mt-1 text-xs text-slate-400 max-w-sm">
            Vui lòng chọn khu cắm trại chính và bãi cắm chi tiết (Site) ở bộ lọc phía trên để quản lý lịch hoạt động và cấu hình giá mùa vụ.
          </p>
        </div>
      )}
    </div>
  );
}
