'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback } from 'react';
import API from '@/lib/api-client';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  Search, RefreshCw, ChevronLeft, ChevronRight, X, Eye,
  Calendar, Users, DollarSign, AlertCircle, CheckCircle2,
  XCircle, Clock, Ban, Undo2, Filter, Info, Shield, MapPin, Tent, CreditCard, FileDown
} from 'lucide-react';
import * as XLSX from 'xlsx';

const STATUS_MAP: Record<string, { label: string; class: string }> = {
  confirmed: { label: 'Đã xác nhận', class: 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-450 border border-emerald-200/60 dark:border-emerald-900/30' },
  completed: { label: 'Hoàn thành', class: 'bg-primary/10 dark:bg-primary/20 text-primary border border-primary/20' },
  cancelled: { label: 'Đã hủy', class: 'bg-rose-50 dark:bg-rose-950/20 text-rose-700 dark:text-rose-450 border border-rose-200/60 dark:border-rose-900/30' },
  refunded: { label: 'Đã hoàn tiền', class: 'bg-purple-50 dark:bg-purple-950/20 text-purple-700 dark:text-purple-400 border border-purple-200/60 dark:border-purple-900/30' },
  refund_requested: { label: 'Yêu cầu hoàn tiền', class: 'bg-orange-50 dark:bg-orange-950/20 text-orange-700 dark:text-orange-400 border border-orange-200/60 dark:border-orange-900/30' },
};

const PAYMENT_MAP: Record<string, { label: string; class: string }> = {
  pending: { label: 'Chờ TT', class: 'bg-amber-50/80 dark:bg-amber-950/20 text-amber-700 dark:text-amber-400' },
  paid: { label: 'Đã TT', class: 'bg-emerald-50/80 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-450' },
  failed: { label: 'Thất bại', class: 'bg-rose-50/80 dark:bg-rose-950/20 text-rose-700 dark:text-rose-450' },
  processing: { label: 'Đang xử lý', class: 'bg-primary/10 dark:bg-primary/25 text-primary' },
};

const fmt = (n: number) => new Intl.NumberFormat('vi-VN').format(n);
const fmtDate = (d: string) => d ? new Date(d).toLocaleDateString('vi-VN') : '—';
const fmtDateTime = (d: string) => d ? new Date(d).toLocaleString('vi-VN') : '—';

export default function AdminBookingsPage() {
  const [tab, setTab] = useState<'all' | 'refunds' | 'cannotAttend'>('all');
  const [bookings, setBookings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<any>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [cannotAttendFilter, setCannotAttendFilter] = useState<'pending' | 'approved' | ''>('pending');
  const [detail, setDetail] = useState<any>(null);
  const [modal, setModal] = useState<{ type: string; booking: any } | null>(null);
  const [actionNote, setActionNote] = useState('');
  const [acting, setActing] = useState(false);

  // Filter states
  const [hosts, setHosts] = useState<any[]>([]);
  const [hostFilter, setHostFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [quickTime, setQuickTime] = useState('all');
  const [exporting, setExporting] = useState(false);

  // Helper for quick date ranges
  const getQuickDateRange = (range: string) => {
    const now = new Date();
    let start = '';
    let end = '';

    const formatLocalDate = (date: Date) => {
      const yyyy = date.getFullYear();
      const mm = String(date.getMonth() + 1).padStart(2, '0');
      const dd = String(date.getDate()).padStart(2, '0');
      return `${yyyy}-${mm}-${dd}`;
    };

    if (range === 'today') {
      const todayStr = formatLocalDate(now);
      start = todayStr;
      end = todayStr;
    } else if (range === 'week') {
      const day = now.getDay();
      const diffToMonday = day === 0 ? -6 : 1 - day; // Adjust for Sunday (0)
      const monday = new Date(now);
      monday.setDate(now.getDate() + diffToMonday);
      const sunday = new Date(monday);
      sunday.setDate(monday.getDate() + 6);
      
      start = formatLocalDate(monday);
      end = formatLocalDate(sunday);
    } else if (range === 'month') {
      const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
      const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      
      start = formatLocalDate(firstDay);
      end = formatLocalDate(lastDay);
    }
    return { start, end };
  };

  const fetchHosts = useCallback(async () => {
    try {
      const res: any = await API.get('/users/hosts');
      setHosts(res?.data?.data ?? res?.data ?? []);
    } catch { /* ignore */ }
  }, []);

  const fetchBookings = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = {
        page,
        limit: 15,
        search: search || undefined,
        hostId: hostFilter || undefined,
      };
      if (startDate) {
        try {
          params.startDate = new Date(`${startDate}T00:00:00`).toISOString();
        } catch {
          params.startDate = startDate;
        }
      }
      if (endDate) {
        try {
          params.endDate = new Date(`${endDate}T23:59:59.999`).toISOString();
        } catch {
          params.endDate = endDate;
        }
      }
      if (tab === 'refunds') params.status = 'refund_requested';
      else if (tab === 'cannotAttend') {
        params.cannotAttendStatus = cannotAttendFilter || 'pending';
      } else if (statusFilter) params.status = statusFilter;

      const res: any = await API.get('/bookings/admin/all', { params });
      setBookings(res?.data ?? []);
      setTotalPages(res?.pagination?.totalPages ?? 1);
      setTotal(res?.pagination?.total ?? 0);
    } catch { toast.error('Không thể tải booking'); }
    finally { setLoading(false); }
  }, [page, search, statusFilter, tab, hostFilter, startDate, endDate, cannotAttendFilter]);

  const handleExportExcel = async () => {
    if (bookings.length === 0) {
      toast.warning('Không có dữ liệu để xuất');
      return;
    }
    setExporting(true);
    try {
      const params: any = {
        page: 1,
        limit: total || 2000,
        search: search || undefined,
        hostId: hostFilter || undefined,
      };
      if (startDate) {
        try {
          params.startDate = new Date(`${startDate}T00:00:00`).toISOString();
        } catch {
          params.startDate = startDate;
        }
      }
      if (endDate) {
        try {
          params.endDate = new Date(`${endDate}T23:59:59.999`).toISOString();
        } catch {
          params.endDate = endDate;
        }
      }
      if (tab === 'refunds') params.status = 'refund_requested';
      else if (tab === 'cannotAttend') {
        params.cannotAttendStatus = cannotAttendFilter || 'pending';
      } else if (statusFilter) params.status = statusFilter;

      const res: any = await API.get('/bookings/admin/all', { params });
      const allBookings = res?.data ?? [];

      if (!allBookings.length) {
        toast.warning('Không tìm thấy dữ liệu để xuất');
        return;
      }

      const excelData = allBookings.map((b: any) => ({
        'Mã Booking': b.code || (b._id ? b._id.slice(-6).toUpperCase() : '—'),
        'Khách Hàng': b.fullnameGuest || b.guest?.username || '—',
        'Email Khách': b.email || b.guest?.email || '—',
        'Số Điện Thoại': b.phone || '—',
        'Chủ Vườn (Host)': b.host?.username || '—',
        'Khu Cắm Trại': b.property?.name || '—',
        'Vị Trí (Site)': b.site?.name || '—',
        'Ngày Check-in': b.checkIn ? new Date(b.checkIn).toLocaleDateString('vi-VN') : '—',
        'Ngày Check-out': b.checkOut ? new Date(b.checkOut).toLocaleDateString('vi-VN') : '—',
        'Số Đêm': b.nights || 0,
        'Số Khách': b.numberOfGuests || 0,
        'Tổng Tiền (VND)': b.pricing?.total || 0,
        'Trạng Thái Đơn': STATUS_MAP[b.status]?.label || b.status,
        'Thanh Toán': PAYMENT_MAP[b.paymentStatus]?.label || b.paymentStatus,
        'Phương Thức': b.paymentMethod === 'full' ? 'Trả toàn bộ' : 'Đặt cọc/Trả sau',
        'Khách Xác Nhận Đến': b.hostConfirmedAttendance === true ? 'Có' : b.hostConfirmedAttendance === false ? 'Không' : 'Chờ xác nhận',
        'Ngày Tạo Đơn': b.createdAt ? new Date(b.createdAt).toLocaleString('vi-VN') : '—'
      }));

      const ws = XLSX.utils.json_to_sheet(excelData);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Bookings');

      const fileName = `HDCamp_Bookings_${new Date().toISOString().slice(0, 10)}.xlsx`;
      XLSX.writeFile(wb, fileName);
      toast.success('Xuất file Excel thành công!');
    } catch (e: any) {
      console.error(e);
      toast.error('Lỗi khi xuất file Excel');
    } finally {
      setExporting(false);
    }
  };

  const fetchStats = useCallback(async () => {
    try {
      const res: any = await API.get('/bookings/admin/stats');
      setStats(res?.data?.data ?? res?.data);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchBookings(); }, [fetchBookings]);
  useEffect(() => { fetchStats(); }, [fetchStats]);
  useEffect(() => { fetchHosts(); }, [fetchHosts]);

  const handleAction = async (type: string, bookingId: string, body: any = {}) => {
    setActing(true);
    try {
      if (type === 'refund-approve') {
        await API.post(`/bookings/admin/${bookingId}/refund`, { approved: true, ...body });
      } else if (type === 'refund-reject') {
        await API.post(`/bookings/admin/${bookingId}/refund`, { approved: false, ...body });
      } else if (type === 'cannot-attend-approve') {
        await API.post(`/bookings/admin/${bookingId}/process-cannot-attend`, { approved: true, ...body });
      } else if (type === 'cannot-attend-reject') {
        await API.post(`/bookings/admin/${bookingId}/process-cannot-attend`, { approved: false, ...body });
      }
      toast.success('Thao tác thành công');
      setModal(null);
      setActionNote('');
      setDetail(null);
      fetchBookings();
      fetchStats();
    } catch (e: any) { toast.error(e?.response?.data?.message ?? 'Lỗi'); }
    finally { setActing(false); }
  };

  const statCards = stats ? [
    { label: 'Tổng booking', value: stats.statusStats?.reduce((s: number, x: any) => s + x.count, 0) || 0, icon: Calendar, color: 'text-primary', bg: 'bg-primary/10 dark:bg-primary/20' },
    { label: 'Doanh thu', value: `${fmt(stats.totalRevenue || 0)}₫`, icon: DollarSign, color: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-50 dark:bg-emerald-950/40' },
    { label: 'Phí platform 5%', value: `${fmt(stats.platformFee || 0)}₫`, icon: DollarSign, color: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-950/40' },
    { label: 'Chờ hoàn tiền', value: stats.pendingRefunds || 0, icon: AlertCircle, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40' },
  ] : [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Title Header */}
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
          Quản lý Booking hệ thống
        </h1>
      </div>

      {/* Stats Cards */}
      {statCards.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {statCards.map(s => {
            const Icon = s.icon;
            return (
              <div key={s.label} className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex items-center gap-4 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md shadow-xs">
                <div className={cn("w-11 h-11 rounded-xl flex items-center justify-center shadow-inner", s.bg)}>
                  <Icon className={cn("h-5.5 w-5.5", s.color)} />
                </div>
                <div>
                  <div className="text-xs text-slate-400 font-semibold">{s.label}</div>
                  <div className={cn("text-lg font-black mt-0.5", s.color)}>{s.value}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Tabs Menu */}
      <div className="flex gap-2 border-b border-slate-200 dark:border-slate-800/80">
        {[
          { key: 'all', label: 'Tất cả booking' },
          { key: 'refunds', label: `Yêu cầu hoàn tiền${stats?.pendingRefunds ? ` (${stats.pendingRefunds})` : ''}` },
          { key: 'cannotAttend', label: `Khách không đến${stats?.pendingCannotAttend ? ` (${stats.pendingCannotAttend})` : ''}` },
        ].map(t => {
          const isActive = tab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => { setTab(t.key as any); setPage(1); }}
              className={cn(
                'px-4 py-2.5 text-xs font-extrabold transition-all border-b-2 rounded-t-lg -mb-[2px]',
                isActive
                  ? 'border-primary text-primary bg-primary/10'
                  : 'border-transparent text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
              )}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Filters & Actions Bar */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3 p-4 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl shadow-xs">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          {/* Search bar */}
          <div className="relative w-full max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
              placeholder="Tìm theo mã, tên, email..."
              className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none dark:text-slate-100"
            />
          </div>

          {/* Status selector */}
          {tab === 'all' && (
            <select
              value={statusFilter}
              onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
              className="px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-650 dark:text-slate-350"
            >
              <option value="">Tất cả trạng thái</option>
              {Object.entries(STATUS_MAP).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
          )}

          {/* Cannot-attend sub-filter */}
          {tab === 'cannotAttend' && (
            <div className="flex items-center gap-1.5">
              {[{ v: 'pending', label: 'Chờ xử lý' }, { v: 'approved', label: 'Đã hoàn tiền' }].map(opt => (
                <button
                  key={opt.v}
                  onClick={() => { setCannotAttendFilter(opt.v as any); setPage(1); }}
                  className={cn(
                    'px-3 py-1.5 text-[11px] font-extrabold rounded-xl border transition-colors cursor-pointer',
                    cannotAttendFilter === opt.v
                      ? 'bg-primary border-primary text-white'
                      : 'bg-white dark:bg-slate-950 border-slate-250 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-50'
                  )}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}

          {/* Host selector */}
          <select
            value={hostFilter}
            onChange={e => { setHostFilter(e.target.value); setPage(1); }}
            className="px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-650 dark:text-slate-350 cursor-pointer"
          >
            <option value="">Tất cả Host</option>
            {hosts.map((h, index) => (
              <option key={h._id || `HOST-${index}`} value={h._id}>{h.username} ({h.email})</option>
            ))}
          </select>

          {/* Quick Time Selector */}
          <select
            value={quickTime}
            onChange={e => {
              const val = e.target.value;
              setQuickTime(val);
              const range = getQuickDateRange(val);
              setStartDate(range.start);
              setEndDate(range.end);
              setPage(1);
            }}
            className="px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-650 dark:text-slate-350 cursor-pointer"
          >
            <option value="all">Mọi lúc</option>
            <option value="today">Hôm nay</option>
            <option value="week">Tuần này</option>
            <option value="month">Tháng này</option>
          </select>

          {/* Time range picker */}
          <div className="flex items-center gap-2 bg-slate-50 dark:bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-250 dark:border-slate-800">
            <span className="text-[10px] font-bold text-slate-400 uppercase">Từ:</span>
            <input
              type="date"
              value={startDate}
              onChange={e => { setStartDate(e.target.value); setQuickTime('all'); setPage(1); }}
              className="bg-transparent border-none text-xs focus:outline-none text-slate-650 dark:text-slate-350 cursor-pointer"
            />
            <span className="text-[10px] font-bold text-slate-400 uppercase">Đến:</span>
            <input
              type="date"
              value={endDate}
              onChange={e => { setEndDate(e.target.value); setQuickTime('all'); setPage(1); }}
              className="bg-transparent border-none text-xs focus:outline-none text-slate-650 dark:text-slate-350 cursor-pointer"
            />
          </div>

          {/* Reset Filters */}
          {(hostFilter || startDate || endDate || search || statusFilter || quickTime !== 'all') && (
            <button
              onClick={() => {
                setHostFilter('');
                setStartDate('');
                setEndDate('');
                setSearch('');
                setStatusFilter('');
                setQuickTime('all');
                setPage(1);
              }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-rose-200 dark:border-rose-900/30 bg-rose-50 dark:bg-rose-955/20 text-xs font-bold text-rose-600 dark:text-rose-455 hover:bg-rose-100 transition-colors cursor-pointer"
            >
              <X className="h-3.5 w-3.5" /> Xóa lọc
            </button>
          )}

          {/* Refresh Action */}
          <button
            onClick={() => { fetchBookings(); fetchStats(); }}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 text-xs font-bold text-slate-650 dark:text-slate-350 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Làm mới
          </button>

          {/* Export Excel Action */}
          <button
            onClick={handleExportExcel}
            disabled={exporting || bookings.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-emerald-250 dark:border-emerald-900/30 bg-emerald-50 dark:bg-emerald-950/20 text-xs font-extrabold text-emerald-600 dark:text-emerald-450 hover:bg-emerald-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
          >
            {exporting ? (
              <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-emerald-600 border-t-transparent"></div>
            ) : (
              <FileDown className="h-3.5 w-3.5" />
            )}
            Xuất Excel
          </button>
        </div>
      </div>
      {loading ? (
        <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
        </div>
      ) : bookings.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl shadow-xs text-slate-400">
          <Calendar className="h-12 w-12 text-slate-200 dark:text-slate-800 mb-3" />
          <p className="text-sm font-semibold">Không tìm thấy booking nào</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-400 font-bold text-xs uppercase tracking-wider">
                  <th className="px-4 py-3.5 font-bold">Mã</th>
                  <th className="px-4 py-3.5 font-bold">Khách</th>
                  <th className="px-4 py-3.5 font-bold">Host</th>
                  <th className="px-4 py-3.5 font-bold">Site</th>
                  <th className="px-4 py-3.5 font-bold">Thời gian</th>
                  <th className="px-4 py-3.5 font-bold">Tổng tiền</th>
                  <th className="px-4 py-3.5 font-bold">Trạng thái</th>
                  <th className="px-4 py-3.5 font-bold">Thanh Toán</th>
                  <th className="px-4 py-3.5 font-bold text-center">Đã đến</th>
                  <th className="px-4 py-3.5 font-bold text-right">Hành động</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {bookings.map((b: any, index: number) => {
                  const st = STATUS_MAP[b.status] ?? { label: b.status, class: 'bg-slate-150 text-slate-700' };
                  const pt = PAYMENT_MAP[b.paymentStatus] ?? { label: b.paymentStatus, class: 'bg-slate-150 text-slate-700' };
                  return (
                    <tr key={b._id || `BKN-ROW-${index}`} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors">
                      <td className="px-4 py-3.5">
                        <span className="font-mono font-bold text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-350 px-2 py-1 rounded">
                          {b.code || b._id?.slice(-6).toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="font-bold text-slate-900 dark:text-slate-100">{b.fullnameGuest || b.guest?.username || '—'}</div>
                        <div className="text-[10px] text-slate-400">{b.email || b.guest?.email || ''}</div>
                      </td>
                      <td className="px-4 py-3.5 text-xs font-semibold text-slate-600 dark:text-slate-300">
                        {b.host?.username || '—'}
                      </td>
                      <td className="px-4 py-3.5 text-xs text-slate-600 dark:text-slate-300 max-w-[140px] truncate" title={b.site?.name}>
                        {b.site?.name || '—'}
                      </td>
                      <td className="px-4 py-3.5 text-xs text-slate-650 dark:text-slate-400">
                        <div className="font-semibold">{fmtDate(b.checkIn)} → {fmtDate(b.checkOut)}</div>
                        <div className="text-[10px] text-slate-400 mt-0.5">{b.nights} đêm</div>
                      </td>
                      <td className="px-4 py-3.5 font-extrabold text-emerald-600 dark:text-emerald-450">
                        {fmt(b.pricing?.total || 0)}₫
                      </td>
                      <td className="px-4 py-3.5">
                        <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-extrabold border', st.class)}>
                          {st.label}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-extrabold', pt.class)}>
                          {pt.label}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-center">
                        <div className="flex justify-center">
                          {b.hostConfirmedAttendance === true ? (
                            <CheckCircle2 className="h-4.5 w-4.5 text-emerald-600" />
                          ) : b.hostConfirmedAttendance === false ? (
                            <XCircle className="h-4.5 w-4.5 text-rose-600" />
                          ) : (
                            <Clock className="h-4.5 w-4.5 text-slate-300 dark:text-slate-700" />
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <div className="flex justify-end">
                          <button
                            onClick={() => setDetail(b)}
                            title="Xem chi tiết booking"
                            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-primary/20 bg-primary/10 text-primary hover:bg-primary/20 transition-colors cursor-pointer text-xs font-bold"
                          >
                            <Eye className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-4 mt-6">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <ChevronLeft className="h-4 w-4" /> Trước
          </button>
          <span className="text-xs text-slate-500 font-semibold">
            Trang <strong className="text-slate-850 dark:text-slate-200 font-black">{page}</strong> / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            Sau <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Detailed Booking Modal */}
      {detail && (
        <div
          className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-90 flex items-center justify-center p-4 overflow-y-auto"
          onClick={e => e.target === e.currentTarget && setDetail(null)}
        >
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-3xl p-6 shadow-2xl w-full max-w-3xl transform transition-all my-8">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100 dark:border-slate-800">
              <div>
                <span className="text-[10px] font-black text-primary bg-primary/10 dark:bg-primary/20 px-2.5 py-1 rounded-full uppercase tracking-wider">
                  Mã: {detail.code || detail._id?.slice(-6).toUpperCase()}
                </span>
                <h3 className="text-lg font-black text-slate-900 dark:text-white mt-1.5 flex items-center gap-2">
                  Chi Tiết Đơn Đặt Chỗ
                </h3>
              </div>
              <button onClick={() => setDetail(null)} className="p-1.5 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-h-[60vh] overflow-y-auto pr-1">
              {/* Left Column: General & Customer Info */}
              <div className="space-y-5">
                <div className="bg-slate-50 dark:bg-slate-950/40 border border-slate-100 dark:border-slate-800/80 rounded-2xl p-4">
                  <h4 className="text-xs font-black text-slate-450 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <Info className="h-3.5 w-3.5 text-primary" /> Thông tin chung
                  </h4>
                  <div className="space-y-2.5 text-xs">
                    <div className="flex justify-between"><span className="text-slate-400">Trạng thái booking:</span>
                      <span className={cn('font-extrabold px-2 py-0.5 rounded-full text-[10px]', (STATUS_MAP[detail.status] as any)?.class)}>
                        {(STATUS_MAP[detail.status] as any)?.label ?? detail.status}
                      </span>
                    </div>
                    <div className="flex justify-between"><span className="text-slate-400">Thanh toán:</span>
                      <span className={cn('font-extrabold px-2 py-0.5 rounded-full text-[10px]', (PAYMENT_MAP[detail.paymentStatus] as any)?.class)}>
                        {(PAYMENT_MAP[detail.paymentStatus] as any)?.label ?? detail.paymentStatus}
                      </span>
                    </div>
                    <div className="flex justify-between"><span className="text-slate-400">Phương thức:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-350">{detail.paymentMethod === 'full' ? 'Trả toàn bộ' : 'Đặt cọc/Trả sau'}</span>
                    </div>
                    <div className="flex justify-between"><span className="text-slate-400">Ngày tạo đơn:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-350">{fmtDateTime(detail.createdAt)}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-50 dark:bg-slate-950/40 border border-slate-100 dark:border-slate-800/80 rounded-2xl p-4">
                  <h4 className="text-xs font-black text-slate-450 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <Users className="h-3.5 w-3.5 text-primary" /> Khách hàng
                  </h4>
                  <div className="space-y-2.5 text-xs">
                    <div className="flex justify-between"><span className="text-slate-400">Họ và tên:</span> <span className="font-bold text-slate-800 dark:text-slate-200">{detail.fullnameGuest || detail.guest?.username || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Email:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.email || detail.guest?.email || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Số điện thoại:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.phone || '—'}</span></div>
                    {detail.guestMessage && (
                      <div className="pt-2 border-t border-slate-200/40 dark:border-slate-800/40">
                        <span className="text-slate-400 block mb-1">Lời nhắn của khách:</span>
                        <p className="bg-white dark:bg-slate-900 p-2 rounded-lg text-slate-600 dark:text-slate-300 text-[11px] italic">
                          "{detail.guestMessage}"
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Right Column: Campsite & Cost Breakdown */}
              <div className="space-y-5">
                <div className="bg-slate-50 dark:bg-slate-950/40 border border-slate-100 dark:border-slate-800/80 rounded-2xl p-4">
                  <h4 className="text-xs font-black text-slate-450 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <Tent className="h-3.5 w-3.5 text-primary" /> Khu cắm trại & Site
                  </h4>
                  <div className="space-y-2.5 text-xs">
                    <div className="flex justify-between"><span className="text-slate-400">Khu cắm trại:</span> <span className="font-bold text-slate-800 dark:text-slate-200">{detail.property?.name || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Vị trí (Site):</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.site?.name || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Chủ vườn (Host):</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.host?.username || '—'} ({detail.host?.email})</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Thời gian đi:</span> <span className="font-extrabold text-primary">{fmtDate(detail.checkIn)} → {fmtDate(detail.checkOut)}</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Số đêm:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.nights} đêm</span></div>
                    <div className="flex justify-between"><span className="text-slate-400">Thành viên:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.numberOfGuests} khách, {detail.numberOfPets || 0} thú cưng, {detail.numberOfVehicles || 0} xe</span></div>
                  </div>
                </div>

                <div className="bg-slate-50 dark:bg-slate-950/40 border border-slate-100 dark:border-slate-800/80 rounded-2xl p-4">
                  <h4 className="text-xs font-black text-slate-450 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                    <DollarSign className="h-3.5 w-3.5 text-primary" /> Chi tiết chi phí
                  </h4>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between"><span className="text-slate-400">Giá cơ bản:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{fmt(detail.pricing?.basePrice || 0)}₫</span></div>
                    {detail.pricing?.cleaningFee > 0 && (
                      <div className="flex justify-between"><span className="text-slate-400">Phí dọn dẹp:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{fmt(detail.pricing.cleaningFee)}₫</span></div>
                    )}
                    {detail.pricing?.petFee > 0 && (
                      <div className="flex justify-between"><span className="text-slate-400">Phí thú cưng:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{fmt(detail.pricing.petFee)}₫</span></div>
                    )}
                    {detail.pricing?.extraGuestFee > 0 && (
                      <div className="flex justify-between"><span className="text-slate-400">Phí khách thêm:</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{fmt(detail.pricing.extraGuestFee)}₫</span></div>
                    )}
                    <div className="pt-2 border-t border-slate-200/40 dark:border-slate-800/40 flex justify-between items-center">
                      <span className="font-black text-slate-900 dark:text-slate-100">Tổng chi phí:</span>
                      <span className="font-black text-md text-emerald-600 dark:text-emerald-450">{fmt(detail.pricing?.total || 0)}₫</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Cannot-attend admin panel */}
            {detail.cannotAttendRequest && detail.cannotAttendRequest.status && (
              <div className="mt-6 p-5 rounded-2xl bg-rose-50/30 dark:bg-rose-950/5 border border-rose-100 dark:border-rose-900/20 shadow-inner">
                <h4 className="text-xs font-black text-rose-700 dark:text-rose-450 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Ban className="h-4.5 w-4.5 text-rose-500" /> Yêu cầu hoàn tiền (Khách báo không thể đến / Hủy đặt)
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  {/* Left Box: Request details */}
                  <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-150 dark:border-slate-800 space-y-2 text-xs">
                    <div className="font-bold text-slate-800 dark:text-slate-200 mb-1 border-b border-slate-100 dark:border-slate-800 pb-1 flex justify-between items-center">
                      <span>Chi tiết yêu cầu</span>
                      <span className={cn('font-extrabold px-2.5 py-0.5 rounded-full text-[9px] uppercase tracking-wider border',
                        detail.cannotAttendRequest.status === 'approved' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' :
                          detail.cannotAttendRequest.status === 'rejected' ? 'bg-rose-50 border-rose-200 text-rose-700' :
                            'bg-amber-50 border-amber-200 text-amber-700'
                      )}>
                        {detail.cannotAttendRequest.status === 'approved' ? 'Đã duyệt' :
                          detail.cannotAttendRequest.status === 'rejected' ? 'Đã từ chối' : 'Đang xử lý'}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-slate-400 font-medium">Lý do khách gửi:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-200 bg-slate-50 dark:bg-slate-950 p-2 rounded-lg italic">
                        "{detail.cannotAttendRequest.reason}"
                      </span>
                    </div>
                    <div className="flex justify-between pt-1">
                      <span className="text-slate-400">Thời điểm gửi:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-350">{fmtDateTime(detail.cannotAttendRequest.requestedAt)}</span>
                    </div>
                  </div>

                  {/* Right Box: Bank Details */}
                  <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-150 dark:border-slate-800 space-y-2.5 text-xs">
                    <div className="font-bold text-slate-800 dark:text-slate-200 mb-1 border-b border-slate-100 dark:border-slate-800 pb-1">
                      Tài khoản nhận tiền hoàn
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Chủ tài khoản:</span>
                      <span className="font-bold text-slate-700 dark:text-slate-200 uppercase">{detail.cannotAttendRequest.bankAccountName || '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Số tài khoản:</span>
                      <span className="font-mono font-bold text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-slate-950 px-1.5 py-0.5 rounded">{detail.cannotAttendRequest.bankAccountNumber || '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Ngân hàng:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">{detail.cannotAttendRequest.bankName || '—'}</span>
                    </div>
                  </div>
                </div>

                {/* Refund calculation breakdown */}
                {(() => {
                  const total = detail.pricing?.total || 0;
                  const reqAt = detail.cannotAttendRequest.requestedAt ? new Date(detail.cannotAttendRequest.requestedAt) : new Date();
                  const checkIn = detail.checkIn ? new Date(detail.checkIn) : new Date();
                  const diffDays = (checkIn.getTime() - reqAt.getTime()) / (1000 * 60 * 60 * 24);

                  let refundRate = 0.5;
                  let hostRate = 0.3;
                  if (diffDays >= 2) {
                    refundRate = 0.7;
                    hostRate = 0.2;
                  }

                  const refundAmt = Math.round(total * refundRate);
                  const hostAmt = Math.round(total * hostRate);
                  const platformAmt = total - refundAmt - hostAmt;

                  return (
                    <div className="bg-gradient-to-br from-primary/5 via-slate-50/50 to-orange-50/5 dark:from-primary/5 dark:via-slate-900/10 dark:to-orange-950/5 border border-slate-200 dark:border-slate-850 rounded-xl p-4 mb-4">
                      <div className="text-xs font-black text-primary mb-3 flex items-center justify-between">
                        <span>TÍNH TOÁN PHÂN CHIA HỦY BOOKING</span>
                        <span className="text-[10px] font-bold text-slate-450 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full">
                          Khoảng cách: {diffDays.toFixed(1)} ngày
                        </span>
                      </div>

                      <div className="grid grid-cols-3 gap-4 text-center">
                        <div className="bg-white/80 dark:bg-slate-950/40 p-2.5 rounded-lg border border-slate-100 dark:border-slate-800">
                          <div className="text-[10px] text-slate-400 font-bold mb-1">HOÀN GUEST ({Math.round(refundRate * 100)}%)</div>
                          <div className="font-extrabold text-md text-emerald-600 dark:text-emerald-400">{fmt(refundAmt)}₫</div>
                          <div className="text-[9px] text-slate-450 mt-1 font-semibold">
                            {diffDays >= 2 ? '≥ 2 ngày (70%)' : '< 2 ngày (50%)'}
                          </div>
                        </div>

                        <div className="bg-white/80 dark:bg-slate-950/40 p-2.5 rounded-lg border border-slate-100 dark:border-slate-800">
                          <div className="text-[10px] text-slate-400 font-bold mb-1">HOST NHẬN ({Math.round(hostRate * 100)}%)</div>
                          <div className="font-extrabold text-md text-purple-600 dark:text-purple-400">{fmt(hostAmt)}₫</div>
                          <div className="text-[9px] text-slate-450 mt-1 font-semibold">Cộng trực tiếp vào ví</div>
                        </div>

                        <div className="bg-white/80 dark:bg-slate-950/40 p-2.5 rounded-lg border border-slate-100 dark:border-slate-800">
                          <div className="text-[10px] text-slate-400 font-bold mb-1">PLATFORM GIỮ ({Math.round((1 - refundRate - hostRate) * 100)}%)</div>
                          <div className="font-extrabold text-md text-slate-700 dark:text-slate-300">{fmt(platformAmt)}₫</div>
                          <div className="text-[9px] text-slate-450 mt-1 font-semibold">Phần còn lại</div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {detail.cannotAttendRequest.status === 'pending' && (
                  <div className="flex justify-end gap-3 border-t border-slate-200/40 dark:border-slate-800/40 pt-4 mt-1">
                    <button
                      onClick={() => setModal({ type: 'cannot-attend-reject', booking: detail })}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-rose-200 bg-rose-50 dark:bg-rose-950/20 text-rose-650 hover:bg-rose-100 transition-colors cursor-pointer text-xs font-extrabold"
                    >
                      <XCircle className="h-4 w-4" /> Từ chối hoàn tiền
                    </button>
                    <button
                      onClick={() => setModal({ type: 'cannot-attend-approve', booking: detail })}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-emerald-200 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 hover:bg-emerald-100 transition-colors cursor-pointer text-xs font-extrabold"
                    >
                      <CheckCircle2 className="h-4 w-4" /> Phê duyệt hoàn tiền
                    </button>
                  </div>
                )}

                {detail.cannotAttendRequest.adminNote && (
                  <div className="text-xs text-slate-500 mt-3 bg-slate-550/10 p-2.5 rounded-lg border border-slate-200/40 dark:border-slate-800/40">
                    <span className="font-bold text-slate-600 dark:text-slate-350 block">Phản hồi của Admin:</span>
                    <p className="mt-0.5">{detail.cannotAttendRequest.adminNote}</p>
                  </div>
                )}
              </div>
            )}

            {/* Host Cancellation Refund Panel */}
            {((detail.status === 'cancelled' || detail.status === 'refunded') && 
              !(detail.cannotAttendRequest && detail.cannotAttendRequest.status)) && (() => {
                const isCancelledByHost = !detail.cancelledBy 
                  ? (detail.cancellationReason?.toLowerCase().includes('chủ nhà') || detail.cancellationReason?.toLowerCase().includes('host'))
                  : (typeof detail.cancelledBy === 'object' ? detail.cancelledBy._id : detail.cancelledBy) === (typeof detail.host === 'object' ? detail.host._id : detail.host);

                const isPaid = detail.paymentStatus === 'paid' || detail.paymentStatus === 'refunded' || detail.status === 'refunded';

                if (!isPaid) {
                  return (
                    <div className="mt-6 p-5 rounded-2xl bg-slate-50 dark:bg-slate-950/20 border border-slate-200 dark:border-slate-800/80 shadow-inner">
                      <h4 className="text-xs font-black text-slate-700 dark:text-slate-350 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Ban className="h-4.5 w-4.5 text-slate-500" /> Thông tin hủy đặt (Đơn chưa thanh toán)
                      </h4>

                      <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-150 dark:border-slate-800 space-y-2.5 text-xs">
                        <div className="font-bold text-slate-800 dark:text-slate-200 mb-1 border-b border-slate-100 dark:border-slate-800 pb-1 flex justify-between items-center">
                          <span>Chi tiết hủy đặt chỗ</span>
                          <span className="font-extrabold px-2.5 py-0.5 rounded-full text-[9px] uppercase tracking-wider border bg-slate-50 border-slate-200 text-slate-500">
                            Không hoàn tiền
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Bên thực hiện hủy:</span>
                          <span className="font-bold text-slate-700 dark:text-slate-200">
                            {isCancelledByHost ? 'Chủ vườn (Host)' : 'Khách hàng (Guest) / Khác'}
                          </span>
                        </div>
                        <div className="flex flex-col gap-1 pt-1.5 border-t border-slate-100 dark:border-slate-850/40">
                          <span className="text-slate-400 font-medium">Lý do hủy chỗ:</span>
                          <span className="font-semibold text-slate-700 dark:text-slate-200 bg-slate-50 dark:bg-slate-950 p-2.5 rounded-lg italic">
                            "{detail.cancellationReason || 'Không cung cấp lý do'}"
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                }

                return (
                  <div className="mt-6 p-5 rounded-2xl bg-amber-50/30 dark:bg-amber-950/5 border border-amber-100 dark:border-amber-900/20 shadow-inner">
                    <h4 className="text-xs font-black text-amber-700 dark:text-orange-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                      <Ban className="h-4.5 w-4.5 text-amber-500" /> Thông tin hủy đặt & Hoàn tiền (Do Host hủy - Hoàn 100%)
                    </h4>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      {/* Left Box: Request details */}
                      <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-150 dark:border-slate-800 space-y-2 text-xs">
                        <div className="font-bold text-slate-800 dark:text-slate-200 mb-1 border-b border-slate-100 dark:border-slate-800 pb-1 flex justify-between items-center">
                          <span>Chi tiết yêu cầu</span>
                          <span className={cn('font-extrabold px-2.5 py-0.5 rounded-full text-[9px] uppercase tracking-wider border',
                            detail.status === 'refunded' || detail.paymentStatus === 'refunded' || detail.refundRequest?.status === 'approved' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' :
                              detail.refundRequest?.status === 'rejected' ? 'bg-rose-50 border-rose-200 text-rose-700' :
                                'bg-amber-50 border-amber-200 text-amber-700'
                          )}>
                            {detail.status === 'refunded' || detail.paymentStatus === 'refunded' || detail.refundRequest?.status === 'approved' ? 'Đã hoàn tiền' :
                              detail.refundRequest?.status === 'rejected' ? 'Đã từ chối' : 'Đang xử lý'}
                          </span>
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-slate-400 font-medium">Bên thực hiện hủy:</span>
                          <span className="font-semibold text-slate-800 dark:text-slate-200">
                            {isCancelledByHost ? 'Chủ vườn (Host)' : 'Khách hàng (Guest) / Khác'}
                          </span>
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-slate-400 font-medium">Lý do hủy chỗ:</span>
                          <span className="font-semibold text-slate-700 dark:text-slate-200 bg-slate-50 dark:bg-slate-950 p-2.5 rounded-lg italic">
                            "{detail.cancellationReason || detail.refundRequest?.reason || 'Chủ vườn hủy đặt chỗ'}"
                          </span>
                        </div>
                        {detail.refundRequest?.requestedAt && (
                          <div className="flex justify-between pt-1">
                            <span className="text-slate-400">Thời điểm gửi tài khoản:</span>
                            <span className="font-semibold text-slate-700 dark:text-slate-350">{fmtDateTime(detail.refundRequest.requestedAt)}</span>
                          </div>
                        )}
                      </div>

                      {/* Right Box: Bank Details */}
                      <div className="bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-150 dark:border-slate-800 space-y-2.5 text-xs">
                        <div className="font-bold text-slate-800 dark:text-slate-200 mb-1 border-b border-slate-100 dark:border-slate-800 pb-1">
                          Tài khoản nhận tiền hoàn (Guest cung cấp)
                        </div>
                        {detail.cancellInformation ? (
                          <>
                            <div className="flex justify-between">
                              <span className="text-slate-400">Chủ tài khoản:</span>
                              <span className="font-bold text-slate-700 dark:text-slate-200 uppercase">{detail.cancellInformation.fullnameGuest || '—'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-400">Số tài khoản:</span>
                              <span className="font-mono font-bold text-slate-800 dark:text-slate-100 bg-slate-50 dark:bg-slate-950 px-1.5 py-0.5 rounded">{detail.cancellInformation.bankType || '—'}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-slate-400">Ngân hàng:</span>
                              <span className="font-semibold text-slate-700 dark:text-slate-350">{detail.cancellInformation.bankCode || '—'}</span>
                            </div>
                          </>
                        ) : (
                          <div className="text-slate-400 text-center py-6 italic">
                            Khách hàng chưa điền thông tin tài khoản nhận tiền hoàn.
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Refund calculation breakdown */}
                    <div className="bg-gradient-to-br from-emerald-50/50 via-slate-50/50 to-primary/5 dark:from-emerald-950/10 dark:via-slate-900/10 dark:to-primary/5 border border-slate-200 dark:border-slate-850 rounded-xl p-4 mb-4">
                      <div className="text-xs font-black text-emerald-600 dark:text-emerald-450 mb-3 flex items-center justify-between">
                        <span>TÍNH TOÁN PHÂN CHIA HỦY BOOKING</span>
                        <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 dark:bg-emerald-950/20 px-2 py-0.5 rounded-full">
                          Hoàn trả 100%
                        </span>
                      </div>

                      <div className="grid grid-cols-1 gap-2 text-center">
                        <div className="bg-white/80 dark:bg-slate-950/40 p-3 rounded-lg border border-slate-100 dark:border-slate-800">
                          <div className="text-[10px] text-slate-400 font-bold mb-1">TỔNG SỐ TIỀN HOÀN CHO GUEST</div>
                          <div className="font-extrabold text-lg text-emerald-600 dark:text-emerald-450">{fmt(detail.pricing?.total || 0)}₫</div>
                          <div className="text-[9px] text-slate-450 mt-1 font-semibold">Do Host chủ động hủy đặt chỗ</div>
                        </div>
                      </div>
                    </div>

                    {detail.refundRequest?.adminNote && (
                      <div className="text-xs text-slate-500 mt-3 bg-slate-550/10 p-2.5 rounded-lg border border-slate-200/40 dark:border-slate-800/40">
                        <span className="font-bold text-slate-600 dark:text-slate-350 block">Phản hồi của Admin:</span>
                        <p className="mt-0.5">{detail.refundRequest.adminNote}</p>
                      </div>
                    )}
                  </div>
                );
              })()}

            {/* Refund request administrative panel */}
            {detail.status === 'refund_requested' && (
              <div className="mt-6 p-4 rounded-2xl bg-orange-50/50 dark:bg-orange-950/10 border border-orange-200/60 dark:border-orange-900/30">
                <h4 className="text-xs font-black text-orange-700 dark:text-orange-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <AlertCircle className="h-4 w-4" /> Yêu cầu hoàn tiền cần xử lý
                </h4>
                <p className="text-xs text-slate-600 dark:text-slate-350 mb-4 bg-white dark:bg-slate-900/60 p-3 rounded-xl border border-orange-200/40">
                  <span className="font-bold text-slate-700 dark:text-slate-200 block mb-0.5">Lý do hoàn tiền của khách:</span>
                  {detail.refundRequest?.reason || 'Không cung cấp lý do'}
                </p>

                <div className="flex justify-end gap-3">
                  <button
                    onClick={() => setModal({ type: 'refund-reject', booking: detail })}
                    className="flex items-center gap-1 px-4 py-2 rounded-xl border border-rose-200 bg-rose-50 dark:bg-rose-950/20 text-rose-650 hover:bg-rose-100 transition-colors cursor-pointer text-xs font-extrabold"
                  >
                    <XCircle className="h-4 w-4" /> Từ chối hoàn tiền
                  </button>
                  <button
                    onClick={() => setModal({ type: 'refund-approve', booking: detail })}
                    className="flex items-center gap-1 px-4 py-2 rounded-xl border border-emerald-200 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 hover:bg-emerald-100 transition-colors cursor-pointer text-xs font-extrabold"
                  >
                    <CheckCircle2 className="h-4 w-4" /> Phê duyệt hoàn tiền
                  </button>
                </div>
              </div>
            )}

            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                onClick={() => setDetail(null)}
                className="px-4 py-2 rounded-xl border border-slate-250 dark:border-slate-800 text-xs font-bold text-slate-650 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                Đóng
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Action Decision Modal */}
      {modal && (
        <div
          className="fixed inset-0 bg-slate-950/50 backdrop-blur-xs z-100 flex items-center justify-center p-4 transition-all duration-300"
          onClick={e => e.target === e.currentTarget && setModal(null)}
        >
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-2xl w-full max-w-md transform transition-all">
            <div className="flex items-start justify-between mb-4">
              <h3 className="text-md font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                {modal.type.includes('approve') ? (
                  <>✅ Xác nhận hoàn tiền</>
                ) : (
                  <>❌ Từ chối yêu cầu</>
                )}
              </h3>
              <button onClick={() => { setModal(null); setActionNote(''); }} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3.5">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Booking mã: <strong className="text-slate-700 dark:text-slate-200 font-bold">{modal.booking.code}</strong> — Giá trị: <strong className="text-primary font-bold">{fmt(modal.booking.pricing?.total || 0)}₫</strong>
              </p>

              {/* Cannot-attend refund summary */}
              {(modal.type === 'cannot-attend-approve') && (() => {
                const total = modal.booking.pricing?.total || 0;
                const reqAt = modal.booking.cannotAttendRequest?.requestedAt ? new Date(modal.booking.cannotAttendRequest.requestedAt) : new Date();
                const checkIn = modal.booking.checkIn ? new Date(modal.booking.checkIn) : new Date();
                const diffDays = (checkIn.getTime() - reqAt.getTime()) / (1000 * 60 * 60 * 24);
                let refundRate = 0.5;
                let hostRate = 0.3;
                if (diffDays >= 2) {
                  refundRate = 0.7;
                  hostRate = 0.2;
                }
                const refundAmt = Math.round(total * refundRate);
                const hostAmt = Math.round(total * hostRate);
                return (
                  <div className="p-3 rounded-xl bg-primary/10 dark:bg-primary/20 border border-primary/20 text-xs">
                    <div className="font-black text-primary mb-2">Tóm tắt xử lý</div>
                    <div className="space-y-1">
                      <div className="flex justify-between"><span className="text-slate-400">Hoàn cho khách ({Math.round(refundRate * 100)}%):</span> <span className="font-bold text-primary">{fmt(refundAmt)}₫</span></div>
                      <div className="flex justify-between"><span className="text-slate-400">Ví host nhận ({Math.round(hostRate * 100)}%):</span> <span className="font-bold text-purple-600">{fmt(hostAmt)}₫</span></div>
                      <div className="flex justify-between border-t border-slate-200/60 dark:border-slate-700/40 pt-1 mt-1"><span className="text-slate-400">Platform giữ ({Math.round((1 - refundRate - hostRate) * 100)}%):</span> <span className="font-bold text-slate-600">{fmt(total - refundAmt - hostAmt)}₫</span></div>
                    </div>
                  </div>
                );
              })()}

              {modal.type === 'refund-approve' && modal.booking.refundRequest?.reason && (
                <div className="p-3 rounded-xl bg-orange-50/50 dark:bg-orange-950/10 border border-orange-200/60 dark:border-orange-900/30 text-xs text-slate-700 dark:text-slate-350">
                  <span className="font-bold text-orange-700 dark:text-orange-400 block mb-0.5">Lý do hoàn tiền của khách:</span>
                  {modal.booking.refundRequest.reason}
                </div>
              )}

              {modal.type === 'cannot-attend-approve' && modal.booking.cannotAttendRequest?.reason && (
                <div className="p-3 rounded-xl bg-red-50/50 dark:bg-red-950/10 border border-red-200/60 dark:border-red-900/30 text-xs text-slate-700 dark:text-slate-350">
                  <span className="font-bold text-red-700 dark:text-red-400 block mb-0.5">Lý do khách không đến:</span>
                  {modal.booking.cannotAttendRequest.reason}
                </div>
              )}

              <div>
                <label className="block text-[11px] font-bold text-slate-400 uppercase tracking-wide mb-1">
                  Ghi chú phản hồi (tùy chọn)
                </label>
                <textarea
                  value={actionNote}
                  onChange={e => setActionNote(e.target.value)}
                  placeholder="Nhập ghi chú phản hồi..."
                  rows={3}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none dark:text-slate-200"
                />
              </div>
            </div>

            <div className="flex gap-2.5 justify-end mt-6">
              <button
                onClick={() => { setModal(null); setActionNote(''); }}
                className="px-4 py-2 rounded-xl border border-slate-250 dark:border-slate-800 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 cursor-pointer"
              >
                Đóng
              </button>
              <button
                onClick={() => handleAction(modal.type, modal.booking.id || modal.booking._id, { adminNote: actionNote })}
                disabled={acting}
                className={cn(
                  'px-4 py-2 rounded-xl text-xs font-extrabold text-white transition-all shadow-md cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed',
                  (modal.type === 'refund-reject' || modal.type === 'cannot-attend-reject')
                    ? 'bg-rose-600 hover:bg-rose-700 shadow-rose-600/10'
                    : 'bg-primary hover:bg-primary/90 shadow-primary/10'
                )}
              >
                {acting ? 'Đang xử lý...' : (modal.type.includes('reject') ? 'Từ chối' : 'Xác nhận')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
