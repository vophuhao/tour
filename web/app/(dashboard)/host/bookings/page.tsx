/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { BookingCalendar } from '@/components/host/booking-calendar';
import { BookingDetailSheet } from '@/components/host/booking-detail-sheet';
import { BookingGanttView } from '@/components/host/booking-gantt-view';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import {
  Calendar, CheckCircle, Clock, DollarSign, Download,
  Eye, LayoutGrid, List, MessageSquare, Search, Users, XCircle,
} from 'lucide-react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { getMyBookings } from '@/lib/client-actions';
import { getMyProperties } from '@/lib/property-site-api';
import API from '@/lib/api-client';
import QRCode from 'qrcode';
import * as XLSX from 'xlsx';

const STATUS_CONFIG: Record<string, { label: string; color: string; dot: string }> = {
  unpaid: { label: 'Chưa thanh toán', color: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300', dot: 'bg-amber-500' },
  confirmed: { label: 'Đã xác nhận', color: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300', dot: 'bg-emerald-500' },
  cancelled: { label: 'Đã hủy', color: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300', dot: 'bg-red-500' },
  completed: { label: 'Hoàn thành', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300', dot: 'bg-blue-500' },
  refunded: { label: 'Đã hoàn tiền', color: 'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300', dot: 'bg-purple-500' },
};

const PAYMENT_CONFIG: Record<string, { label: string; color: string }> = {
  pending: { label: 'Chưa thanh toán', color: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300' },
  paid: { label: 'Đã thanh toán', color: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300' },
  refunded: { label: 'Đã hoàn tiền', color: 'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300' },
  failed: { label: 'Thất bại', color: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300' },
};

export default function BookingsPage() {
  const [bookings, setBookings] = useState<any[]>([]);
  const [filteredBookings, setFilteredBookings] = useState<any[]>([]);
  const [properties, setProperties] = useState<Array<{ _id: string; name: string }>>([]);
  const [activeTab, setActiveTab] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'list' | 'calendar' | 'gantt'>('gantt');
  const [selectedBooking, setSelectedBooking] = useState<any | null>(null);
  const [detailSheetOpen, setDetailSheetOpen] = useState(false);
  const router = useRouter();

  const [actionDialog, setActionDialog] = useState<{ open: boolean; type: 'confirm' | 'cancel' | 'complete' | 'attendance' | null; booking: any }>
    ({ open: false, type: null, booking: null });
  const [cancelDialog, setCancelDialog] = useState<{ open: boolean; booking: any; reason: string }>
    ({ open: false, booking: null, reason: '' });

  async function fetchBookings() {
    try {
      const res = await getMyBookings({ limit: 1000 });
      if (res.success) setBookings(res.data ?? []);
      setLoading(true);
      setTimeout(() => setLoading(false), 1000);
    } catch {
      toast.error('Có lỗi khi tải danh sách booking');
      setLoading(false);
    }
  }

  async function fetchProperties() {
    try {
      const res = await getMyProperties();
      let list: Array<{ _id: string; name: string }> = [];
      if (res.data?.properties && Array.isArray(res.data.properties)) {
        list = res.data.properties.map((p: any) => ({ _id: p._id, name: p.name }));
      } else if (res.properties && Array.isArray(res.properties)) {
        list = res.properties.map((p: any) => ({ _id: p._id, name: p.name }));
      } else if (Array.isArray(res)) {
        list = res.map((p: any) => ({ _id: p._id, name: p.name }));
      }
      setProperties(list);
    } catch {
      toast.error('Không thể tải danh sách property');
    }
  }

  useEffect(() => { fetchBookings(); fetchProperties(); }, []);

  useEffect(() => {
    let filtered = [...bookings];
    if (activeTab !== 'all') {
      if (activeTab === 'unpaid') {
        filtered = filtered.filter(b => b.paymentStatus === 'pending');
      } else if (activeTab === 'confirmed') {
        filtered = filtered.filter(b => b.status === 'confirmed' && b.paymentStatus === 'paid');
      } else {
        filtered = filtered.filter(b => b.status === activeTab);
      }
    }
    if (searchTerm) {
      const t = searchTerm.toLowerCase();
      filtered = filtered.filter(b =>
        b.guest?.name?.toLowerCase().includes(t) ||
        b.guest?.email?.toLowerCase().includes(t) ||
        b.site?.name?.toLowerCase().includes(t),
      );
    }
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'newest': return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        case 'oldest': return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
        case 'checkin-soon': return new Date(a.checkIn).getTime() - new Date(b.checkIn).getTime();
        case 'price-high': return b.pricing?.total - a.pricing?.total;
        case 'price-low': return a.pricing?.total - b.pricing?.total;
        default: return 0;
      }
    });
    setFilteredBookings(filtered);
  }, [bookings, activeTab, sortBy, searchTerm]);

  function handleAction(type: 'confirm' | 'cancel' | 'complete' | 'attendance', booking: any) {
    if (type === 'attendance') {
      setActionDialog({ open: true, type: 'attendance', booking });
    } else if (type === 'cancel') {
      setCancelDialog({ open: true, booking, reason: '' });
    } else {
      setActionDialog({ open: true, type, booking });
    }
  }

  function handleBookingClick(booking: any) { setSelectedBooking(booking); setDetailSheetOpen(true); }

  async function executeCancelWithReason() {
    try {
      const { booking, reason } = cancelDialog;
      if (!booking) return;
      const res: any = await API.post(`/bookings/${booking._id}/cancel`, {
        cancellationReason: reason
      });
      if (res?.data?.success) {
        toast.success('Đã từ chối/hủy đặt phòng!');
        setCancelDialog({ open: false, booking: null, reason: '' });
        await fetchBookings();
      } else throw new Error(res?.data?.message || 'Có lỗi xảy ra');
    } catch (error: any) {
      toast.error(error?.response?.data?.message || error?.message || 'Có lỗi xảy ra');
    }
  }

  async function executeAction() {
    try {
      const { type, booking } = actionDialog;
      if (!type || !booking) return;
      if (type === 'attendance') {
        const res: any = await API.post(`/bookings/host/${booking._id}/confirm-attendance`, { arrived: true });
        if (res?.data?.success) {
          toast.success('Đã xác nhận khách đến!');
          setActionDialog({ open: false, type: null, booking: null });
          await fetchBookings();
        } else throw new Error(res?.data?.message || 'Có lỗi xảy ra');
      } else if (type === 'confirm') {
        const res: any = await API.post(`/bookings/${booking._id}/confirm`);
        if (res?.data?.success) {
          toast.success('Đã xác nhận đặt phòng thành công!');
          setActionDialog({ open: false, type: null, booking: null });
          await fetchBookings();
        } else throw new Error(res?.data?.message || 'Có lỗi xảy ra');
      } else if (type === 'complete') {
        const res: any = await API.post(`/bookings/${booking._id}/complete`);
        if (res?.data?.success) {
          toast.success('Đã hoàn thành đặt phòng!');
          setActionDialog({ open: false, type: null, booking: null });
          await fetchBookings();
        } else throw new Error(res?.data?.message || 'Có lỗi xảy ra');
      }
    } catch (error: any) {
      toast.error(error?.response?.data?.message || error?.message || 'Có lỗi xảy ra');
    }
  }

  const formatPrice = (price: number) => new Intl.NumberFormat('vi-VN').format(price);
  const formatDate = (date: string) => new Date(date).toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });

  const handleExportReport = () => {
    try {
      if (filteredBookings.length === 0) {
        toast.error('Không có dữ liệu để xuất');
        return;
      }

      const data = filteredBookings.map((b, idx) => {
        const guestName = b.fullnameGuest || b.guest?.name || '—';
        const guestEmail = b.email || b.guest?.email || '—';
        const guestPhone = b.phone || b.guest?.phone || b.guest?.phoneNumber || '—';
        const statusText = STATUS_CONFIG[b.status]?.label || b.status;
        const paymentStatusText = PAYMENT_CONFIG[b.paymentStatus]?.label || b.paymentStatus || '—';

        return {
          'STT': idx + 1,
          'Mã đặt phòng': b.code || b._id || '',
          'Khách hàng': guestName,
          'Số điện thoại': guestPhone,
          'Email': guestEmail,
          'Khu cắm trại': b.property?.name || 'Khu cắm trại',
          'Vị trí/Site': b.site?.name || 'Vị trí',
          'Check-in': b.checkIn ? new Date(b.checkIn).toLocaleDateString('vi-VN') : '—',
          'Check-out': b.checkOut ? new Date(b.checkOut).toLocaleDateString('vi-VN') : '—',
          'Tổng tiền (VND)': b.pricing?.total || 0,
          'Tiền cọc (VND)': b.pricing?.deposit || 0,
          'Thanh toán': paymentStatusText,
          'Trạng thái': statusText,
          'Ngày đặt': b.createdAt ? new Date(b.createdAt).toLocaleDateString('vi-VN') : '—',
        };
      });

      const worksheet = XLSX.utils.json_to_sheet(data);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, 'Danh sách Booking');

      const maxLens = data.reduce((acc, row) => {
        Object.keys(row).forEach((key) => {
          const val = row[key as keyof typeof row];
          const valStr = val ? val.toString() : '';
          const len = valStr.length;
          acc[key] = Math.max(acc[key] || 0, len, key.length);
        });
        return acc;
      }, {} as Record<string, number>);

      worksheet['!cols'] = Object.keys(maxLens).map((key) => ({
        wch: maxLens[key] + 3
      }));

      XLSX.writeFile(workbook, `bao-cao-booking-host-${new Date().toISOString().slice(0, 10)}.xlsx`);
      toast.success('Đã tải xuống báo cáo booking Excel (.xlsx)');
    } catch (err) {
      console.error(err);
      toast.error('Lỗi khi xuất file báo cáo Excel');
    }
  };

  const stats = {
    total: bookings.length,
    unpaid: bookings.filter(b => b.paymentStatus === 'pending').length,
    confirmed: bookings.filter(b => b.status === 'confirmed' && b.paymentStatus === 'paid').length,
    completed: bookings.filter(b => b.status === 'completed').length,
    totalRevenue: bookings.filter(b => b.paymentStatus === 'paid' && b.status === 'completed').reduce((s, b) => s + b.pricing.total, 0),
  };

  const tabs = [
    { value: 'all', label: 'Tất cả', count: stats.total },
    { value: 'unpaid', label: 'Chưa thanh toán', count: stats.unpaid },
    { value: 'confirmed', label: 'Đã xác nhận', count: stats.confirmed },
    { value: 'completed', label: 'Hoàn thành', count: stats.completed },
    { value: 'cancelled', label: 'Đã hủy', count: bookings.filter(b => b.status === 'cancelled').length },
    { value: 'refunded', label: 'Hoàn tiền', count: bookings.filter(b => b.status === 'refunded').length },
  ];

  const statCards = [
    { label: 'Tổng booking', value: stats.total, icon: Calendar, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/30' },
    { label: 'Chưa thanh toán', value: stats.unpaid, icon: Clock, color: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-900/30' },
    { label: 'Đã xác nhận', value: stats.confirmed, icon: CheckCircle, color: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-50 dark:bg-emerald-900/30' },
    { label: 'Doanh thu', value: `${formatPrice(stats.totalRevenue)}₫`, icon: DollarSign, color: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-900/30', small: true },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="sticky top-0 z-30 bg-background/95 backdrop-blur  border-border">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-xl font-bold text-foreground">Booking & Lịch</h1>
            </div>
            <div className="flex items-center gap-2">
              {/* View toggle */}
              <div className="flex rounded-lg border border-border bg-card overflow-hidden">
                {[
                  { mode: 'gantt', icon: LayoutGrid, label: 'Timeline' },
                  { mode: 'calendar', icon: Calendar, label: 'Lịch' },
                  { mode: 'list', icon: List, label: 'Danh sách' },
                ].map(({ mode, icon: Icon, label }) => (
                  <button
                    key={mode}
                    onClick={() => setViewMode(mode as any)}
                    className={cn(
                      'flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors',
                      viewMode === mode
                        ? 'bg-primary text-white'
                        : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                    )}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span className="hidden sm:inline">{label}</span>
                  </button>
                ))}
              </div>
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-border text-xs"
                onClick={handleExportReport}
              >
                <Download className="h-3.5 w-3.5" /> Xuất báo cáo
              </Button>
            </div>
          </div>

          {/* Stats row - always visible */}
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
                    <p className={cn('font-bold', s.color, s.small ? 'text-sm' : 'text-xl')}>{s.value}</p>
                  </div>
                </div>
              );
            })}
          </div> */}
        </div>
      </div>

      {/* List view filters */}
      {viewMode === 'list' && (
        <div className="px-6 py-4 border-b border-border bg-card/50">
          {/* Tabs */}
          <div className="flex gap-1 flex-wrap mb-4">
            {tabs.map(tab => (
              <button
                key={tab.value}
                onClick={() => setActiveTab(tab.value)}
                className={cn(
                  'flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-all',
                  activeTab === tab.value
                    ? 'bg-primary text-white shadow-sm'
                    : 'bg-muted text-muted-foreground hover:bg-accent hover:text-foreground',
                )}
              >
                {tab.label}
                {tab.count > 0 && (
                  <span className={cn('rounded-full px-1.5 py-0.5 text-[10px] font-bold',
                    activeTab === tab.value ? 'bg-white/25 text-white' : 'bg-background text-foreground')}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>
          {/* Search + sort */}
          <div className="flex gap-2">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input placeholder="Tìm khách hàng, địa điểm..." value={searchTerm} onChange={e => setSearchTerm(e.target.value)} className="pl-9 h-8 text-xs bg-background border-border" />
            </div>
            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger className="w-40 h-8 text-xs bg-background border-border">
                <SelectValue placeholder="Sắp xếp" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="newest">Mới nhất</SelectItem>
                <SelectItem value="oldest">Cũ nhất</SelectItem>
                <SelectItem value="checkin-soon">Check-in sớm</SelectItem>
                <SelectItem value="price-high">Giá cao → thấp</SelectItem>
                <SelectItem value="price-low">Giá thấp → cao</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      )}

      {/* Content */}
      <div className="px-6 py-5">
        {/* Gantt */}
        {viewMode === 'gantt' && (
          loading ? <LoadingSpinner /> : (
            <BookingGanttView bookings={bookings} properties={properties} onBookingClick={handleBookingClick} />
          )
        )}

        {/* Calendar */}
        {viewMode === 'calendar' && (
          loading ? <LoadingSpinner /> : (
            <BookingCalendar bookings={bookings} onBookingClick={handleBookingClick} />
          )
        )}

        {/* List */}
        {viewMode === 'list' && (
          loading ? <LoadingSpinner /> : filteredBookings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 rounded-xl border border-border bg-card">
              <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted mb-3">
                <Calendar className="h-7 w-7 text-muted-foreground" />
              </div>
              <h3 className="text-base font-semibold text-foreground mb-1">Không có booking nào</h3>
              <p className="text-sm text-muted-foreground">{searchTerm ? 'Không tìm thấy kết quả' : 'Các booking sẽ xuất hiện ở đây'}</p>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Hiển thị <span className="font-semibold text-foreground">{filteredBookings.length}</span> booking
              </p>
              {filteredBookings.map(booking => (
                <BookingCard
                  key={booking._id}
                  booking={booking}
                  formatPrice={formatPrice}
                  formatDate={formatDate}
                  onAction={handleAction}
                  onDetail={() => router.push(`/host/bookings/detail/${booking.code}`)}
                />
              ))}
            </div>
          )
        )}
      </div>

      {/* Detail sheet */}
      <BookingDetailSheet
        booking={selectedBooking}
        open={detailSheetOpen}
        onOpenChange={setDetailSheetOpen}
        onConfirm={b => handleAction('confirm', b)}
        onCancel={b => handleAction('cancel', b)}
        onComplete={b => handleAction('complete', b)}
      />

      {/* Cancel dialog */}
      <AlertDialog open={cancelDialog.open} onOpenChange={open => !open && setCancelDialog({ open: false, booking: null, reason: '' })}>
        <AlertDialogContent className="sm:max-w-[480px]">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-600" /> Từ chối booking
            </AlertDialogTitle>
            <AlertDialogDescription>Nhập lý do từ chối. Khách hàng sẽ nhận được thông báo.</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Textarea
              value={cancelDialog.reason}
              onChange={e => setCancelDialog({ ...cancelDialog, reason: e.target.value })}
              placeholder="Ví dụ: Địa điểm đã được đặt đầy..."
              className="min-h-[100px] resize-none text-sm"
              maxLength={500}
            />
            <p className="mt-1 text-xs text-muted-foreground">{cancelDialog.reason.length}/500</p>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setCancelDialog({ open: false, booking: null, reason: '' })}>Hủy bỏ</AlertDialogCancel>
            <AlertDialogAction onClick={executeCancelWithReason} className="bg-red-600 hover:bg-red-700" disabled={!cancelDialog.reason.trim()}>
              Xác nhận từ chối
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Action dialog */}
      <AlertDialog open={actionDialog.open} onOpenChange={open => setActionDialog({ ...actionDialog, open })}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-primary" />
              {actionDialog.type === 'confirm' ? 'Xác nhận booking' : 'Hoàn thành booking'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {actionDialog.type === 'confirm' ? 'Xác nhận booking này? Khách hàng sẽ nhận email xác nhận.' : 'Đánh dấu booking này là đã hoàn thành?'}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Hủy</AlertDialogCancel>
            <AlertDialogAction onClick={executeAction} className="bg-primary hover:bg-primary/90">
              Xác nhận
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
    </div>
  );
}

function BookingCard({ booking, formatPrice, formatDate, onAction, onDetail }: any) {
  const getBookingDisplayStatus = (b: any) => {
    if (b.paymentStatus === 'pending') return 'unpaid';
    return b.status;
  };
  const displayStatus = getBookingDisplayStatus(booking);
  const status = STATUS_CONFIG[displayStatus] || STATUS_CONFIG.unpaid;
  const payment = PAYMENT_CONFIG[booking.paymentStatus] || PAYMENT_CONFIG.pending;
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [showQr, setShowQr] = useState(false);

  const guestConfirmed = booking.guestConfirmedAttendance;
  const cannotAttendPending = booking.cannotAttendRequest?.status === "pending";
  const walletCredited = booking.walletCredited;

  const confirmUrl = typeof window !== 'undefined'
    ? `${window.location.origin}/bookings/${booking._id}/confirmation`
    : `/bookings/${booking._id}/confirmation`;

  async function generateQR() {
    if (!showQr) {
      try {
        const url = await QRCode.toDataURL(confirmUrl, {
          width: 200,
          margin: 2,
          color: { dark: '#1e1b4b', light: '#ffffff' },
        });
        setQrDataUrl(url);
        setShowQr(true);
      } catch (err) {
        console.error(err);
      }
    } else {
      setShowQr(false);
    }
  }

  return (
    <div className="rounded-xl border border-border bg-card shadow-sm hover:shadow-md transition-all duration-200 overflow-hidden">
      <div className="flex flex-col lg:flex-row">
        {/* Image */}
        <div className="relative h-44 lg:h-auto lg:w-52 flex-shrink-0 bg-muted">
          <Image src={booking.site?.photos?.[0]?.url || '/placeholder.jpg'} alt={booking.site?.name || ''} fill className="object-cover" />
          <div className="absolute inset-0 bg-gradient-to-t from-black/40 to-transparent lg:bg-gradient-to-r" />
          <div className="absolute top-3 left-3 flex flex-col gap-1.5">
            <span className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold', status.color)}>
              <span className={cn('h-1.5 w-1.5 rounded-full', status.dot)} />
              {status.label}
            </span>
            <span className={cn('inline-flex rounded-full px-2 py-0.5 text-[11px] font-semibold', payment.color)}>
              {payment.label}
            </span>
          </div>
          {guestConfirmed && (
            <div className="absolute top-3 right-3">
              <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold bg-emerald-600 text-white">
                <CheckCircle className="h-3 w-3" /> Khách đã xác nhận
              </span>
            </div>
          )}
          {cannotAttendPending && (
            <div className="absolute top-3 right-3">
              <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold bg-amber-500 text-white">
                Báo không đến
              </span>
            </div>
          )}
        </div>

        {/* Content */}
        <div className="flex flex-1 flex-col p-5">
          <div className="flex items-start justify-between gap-4 mb-4">
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <h3 className="font-semibold text-foreground">{booking.guest?.name || booking.fullnameGuest || '—'}</h3>
                <span className="text-xs text-muted-foreground">• {booking.guest?.email || booking.email || ''}</span>
              </div>
              <p className="text-sm text-muted-foreground">{booking.site?.name}</p>
            </div>
            <div className="text-right flex-shrink-0">
              <p className="text-xs text-muted-foreground">Tổng tiền</p>
              <p className="text-lg font-bold text-emerald-600 dark:text-emerald-400">{formatPrice(booking.pricing?.total)} ₫</p>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 py-3 border-y border-border mb-4">
            {[
              { label: 'Check-in', value: formatDate(booking.checkIn) },
              { label: 'Check-out', value: formatDate(booking.checkOut) },
              { label: 'Số đêm', value: `${booking.nights} đêm` },
              { label: 'Khách', value: `${booking.numberOfGuests} người${booking.numberOfPets > 0 ? ` • ${booking.numberOfPets} pet` : ''}` },
            ].map(d => (
              <div key={d.label}>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{d.label}</p>
                <p className="text-sm font-semibold text-foreground mt-0.5">{d.value}</p>
              </div>
            ))}
          </div>

          {booking.guestMessage && (
            <div className="flex gap-2 rounded-lg bg-muted/50 px-3 py-2 mb-4">
              <MessageSquare className="h-3.5 w-3.5 text-muted-foreground mt-0.5 flex-shrink-0" />
              <p className="text-xs text-muted-foreground line-clamp-2">{booking.guestMessage}</p>
            </div>
          )}

          {/* QR Code section */}
          {booking.status === 'confirmed' && booking.paymentStatus === 'paid' && (
            <div className="mb-3">
              <button
                onClick={generateQR}
                className="flex items-center gap-1.5 text-xs text-primary font-medium transition-colors"
              >
                <span>{showQr ? 'Ẩn mã QR' : 'Hiển mã QR check-in'}</span>
              </button>
              {showQr && qrDataUrl && (
                <div className="mt-2 flex items-center gap-3 p-3 bg-primary/10 dark:bg-primary/20 rounded-xl border border-primary/20">
                  <img src={qrDataUrl} alt="QR check-in" className="w-24 h-24 rounded-lg" />
                  <div>
                    <p className="text-xs font-semibold text-primary">Mã QR Check-in</p>
                    <p className="text-[10px] text-primary/80 mt-0.5">Cho khách quét để xác nhận đã đến</p>
                    <p className="text-[10px] text-primary mt-1 break-all">{confirmUrl}</p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Actions: only View Detail for host now */}
          <div className="flex gap-2 mt-auto">
            <Button size="sm" variant="outline" className="flex-1 border-border gap-1.5 text-xs" onClick={onDetail}>
              <Eye className="h-3.5 w-3.5" /> Xem chi tiết
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
