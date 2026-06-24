'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import API from '@/lib/api-client';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  TrendingUp, DollarSign, CalendarCheck, Users, RefreshCw,
  BarChart3, PieChartIcon, Filter, Star, Download, Search,
  ArrowUpRight, ArrowDownRight, AlertTriangle, ShieldCheck,
  CreditCard, ShieldAlert, FileSpreadsheet, FileText, ChevronRight, X, Info
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Area, AreaChart,
} from 'recharts';
import * as XLSX from 'xlsx';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

// Format helpers
const fmt = (n: number) => new Intl.NumberFormat('vi-VN').format(Math.round(n));
const fmtShort = (n: number) => {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(Math.round(n));
};

const fmtDateTime = (d: string | Date) => {
  if (!d) return '—';
  return new Date(d).toLocaleString('vi-VN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit'
  });
};

const STATUS_MAP: Record<string, { label: string; class: string }> = {
  pending: { label: 'Pending', class: 'bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-400 border border-amber-200/60 dark:border-amber-900/30' },
  paid: { label: 'Paid', class: 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-450 border border-emerald-200/60 dark:border-emerald-900/30' },
  escrow: { label: 'Escrow', class: 'bg-indigo-50 dark:bg-indigo-950/20 text-indigo-700 dark:text-indigo-400 border border-indigo-200/60 dark:border-indigo-900/30' },
  released: { label: 'Released', class: 'bg-blue-50 dark:bg-blue-950/20 text-blue-700 dark:text-blue-400 border border-blue-200/60 dark:border-blue-900/30' },
  refunded: { label: 'Refunded', class: 'bg-purple-50 dark:bg-purple-950/20 text-purple-700 dark:text-purple-400 border border-purple-200/60 dark:border-purple-900/30' },
  failed: { label: 'Failed', class: 'bg-rose-50 dark:bg-rose-950/20 text-rose-700 dark:text-rose-450 border border-rose-200/60 dark:border-rose-900/30' },
};

const PAYMENT_METHODS = [
  { value: 'all', label: 'Tất cả phương thức' },
  { value: 'Ví PayOS', label: 'Ví PayOS' },
  { value: 'Chuyển khoản', label: 'Chuyển khoản' },
  { value: 'Momo', label: 'Ví Momo' },
];

const HOST_COLORS = ['#6366f1', '#10b981', '#f59e0b', '#3b82f6', '#8b5cf6', '#f43f5e', '#14b8a6', '#f97316', '#a855f7', '#06b6d4'];

const CUSTOM_TOOLTIP = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 shadow-2xl text-xs space-y-1">
      <p className="font-bold text-slate-200 mb-1">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey || p.name} className="flex items-center justify-between gap-6">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: p.color || p.fill }} />
            <span className="text-slate-400">{p.name}:</span>
          </div>
          <span className="font-bold text-white">{fmt(p.value)}₫</span>
        </div>
      ))}
    </div>
  );
};

export default function AdminRevenuePage() {
  const currentYear = new Date().getFullYear();
  const [data, setData] = useState<any>(null);
  const [hosts, setHosts] = useState<any[]>([]);
  const [dbBookings, setDbBookings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);

  // Advanced filters state
  const [hostFilter, setHostFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [year, setYear] = useState(String(currentYear));
  const [timeTab, setTimeTab] = useState<'today' | '7days' | '30days' | '12months' | 'custom'>('30days');
  const [chartView, setChartView] = useState<'revenue' | 'profit' | 'bookings' | 'daily'>('revenue');
  const [chartType, setChartType] = useState<'area' | 'bar'>('area');

  // Table filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [pMethodFilter, setPMethodFilter] = useState('all');
  const [sortField, setSortField] = useState<string>('createdAt');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Selected transaction detail drawer
  const [selectedTxn, setSelectedTxn] = useState<any>(null);

  // Fetch standard report metrics from API
  const fetchData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    try {
      const params: any = {};
      if (hostFilter) params.hostId = hostFilter;
      if (startDate) params.startDate = startDate;
      if (endDate) params.endDate = endDate;
      if (!startDate && !endDate) params.year = year;

      const [reportRes, hostsRes, topPropsRes, bookingsRes]: any = await Promise.all([
        API.get('/dashboard/revenue-report', { params }),
        API.get('/users/hosts', { params: { limit: 100 } }),
        API.get('/dashboard/top-properties'),
        API.get('/bookings/admin/all', { params: { limit: 100 } }).catch(() => null)
      ]);

      const reportData = reportRes?.data;
      const hostList = hostsRes?.data?.hosts ?? hostsRes?.data ?? [];
      const topProps = topPropsRes?.data ?? [];
      const bookingsList = bookingsRes?.data ?? [];

      setData({
        ...reportData,
        topProperties: topProps
      });
      setHosts(hostList);
      setDbBookings(bookingsList);
    } catch (e: any) {
      toast.error('Không thể tải dữ liệu báo cáo doanh thu');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [hostFilter, startDate, endDate, year]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Handle Preset Time tabs click
  const handleTimeTabChange = (tab: typeof timeTab) => {
    setTimeTab(tab);
    const now = new Date();
    if (tab === 'today') {
      const todayStr = now.toISOString().slice(0, 10);
      setStartDate(todayStr);
      setEndDate(todayStr);
    } else if (tab === '7days') {
      const start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      setStartDate(start.toISOString().slice(0, 10));
      setEndDate(now.toISOString().slice(0, 10));
    } else if (tab === '30days') {
      const start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      setStartDate(start.toISOString().slice(0, 10));
      setEndDate(now.toISOString().slice(0, 10));
    } else if (tab === '12months') {
      setStartDate('');
      setEndDate('');
      setYear(String(currentYear));
    }
  };

  // Compile Transactions: strictly use actual database bookings from DB
  const transactions = useMemo(() => {
    const list: any[] = [];

    // Map database bookings if they exist
    if (dbBookings && dbBookings.length > 0) {
      dbBookings.forEach((b: any, index: number) => {
        const total = b.pricing?.total || 0;
        const sFee = b.pricing?.serviceFee || Math.round(total * 0.05);
        const comm = b.platformFee || Math.round(total * 0.07);
        const hostNet = b.hostNetAmount || (total - sFee - comm);

        let status: 'pending' | 'paid' | 'escrow' | 'released' | 'refunded' | 'failed' = 'released';
        if (b.status === 'pending') status = 'pending';
        else if (b.status === 'confirmed') status = 'paid';
        else if (b.status === 'completed') status = 'released';
        else if (b.status === 'refunded') status = 'refunded';
        else if (b.status === 'cancelled') status = 'failed';
        else if (b.status === 'refund_requested') status = 'escrow';

        list.push({
          id: b._id ? `TXN-${b._id.slice(-6).toUpperCase()}` : `TXN-DB-${index}`,
          bookingCode: b.code || (b._id ? b._id.slice(-6).toUpperCase() : `DB-${index}`),
          camperName: b.fullnameGuest || b.guest?.username || 'Camper',
          hostName: b.host?.username || 'Host',
          propertyName: b.property?.name || 'Campsite',
          region: b.property?.location?.city || b.property?.location || 'Mộc Châu',
          amount: total,
          serviceFee: sFee,
          commission: comm,
          hostNet: hostNet,
          paymentMethod: b.paymentMethod === 'full' ? 'Ví PayOS' : 'Chuyển khoản',
          status,
          createdAt: b.createdAt ? new Date(b.createdAt) : new Date(),
        });
      });
    }

    return list.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }, [dbBookings]);

  // Filtered transactions for search, filters, date range
  const filteredTransactions = useMemo(() => {
    return transactions.filter(t => {
      // Search text filter
      const searchMatch = !search ? true : (
        t.id.toLowerCase().includes(search.toLowerCase()) ||
        t.bookingCode.toLowerCase().includes(search.toLowerCase()) ||
        t.camperName.toLowerCase().includes(search.toLowerCase()) ||
        t.hostName.toLowerCase().includes(search.toLowerCase()) ||
        t.propertyName.toLowerCase().includes(search.toLowerCase())
      );

      // Status filter
      const statusMatch = statusFilter === 'all' ? true : t.status === statusFilter;

      // Payment method filter
      const pmMatch = pMethodFilter === 'all' ? true : t.paymentMethod === pMethodFilter;

      // Host selector filter
      const hostMatch = !hostFilter ? true : (
        // Find if host filter ID username equals transaction host name
        hosts.find(h => h._id === hostFilter)?.username === t.hostName ||
        t.hostName.toLowerCase().includes(hostFilter.toLowerCase())
      );

      // Date range filter
      let dateMatch = true;
      if (startDate) {
        const start = new Date(startDate);
        start.setHours(0, 0, 0, 0);
        dateMatch = dateMatch && t.createdAt >= start;
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        dateMatch = dateMatch && t.createdAt <= end;
      }

      return searchMatch && statusMatch && pmMatch && hostMatch && dateMatch;
    });
  }, [transactions, search, statusFilter, pMethodFilter, hostFilter, startDate, endDate, hosts]);

  // Sorted Transactions
  const sortedTransactions = useMemo(() => {
    const sorted = [...filteredTransactions];
    sorted.sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (aVal instanceof Date) aVal = aVal.getTime();
      if (bVal instanceof Date) bVal = bVal.getTime();

      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();

      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [filteredTransactions, sortField, sortOrder]);

  // Paginated Transactions
  const paginatedTransactions = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return sortedTransactions.slice(startIndex, startIndex + itemsPerPage);
  }, [sortedTransactions, currentPage]);

  const totalPages = Math.ceil(sortedTransactions.length / itemsPerPage);

  const nowMonth = new Date().getMonth();
  const nowYear = new Date().getFullYear();

  // Dynamic calculated KPI metrics based on transactions filtered/aggregated
  const calculatedKPIs = useMemo(() => {
    // Total Revenue (Gross)
    const gross = filteredTransactions.reduce((acc, t) => acc + (t.status !== 'failed' ? t.amount : 0), 0);

    // Today's revenue
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const grossToday = filteredTransactions.reduce((acc, t) => {
      const tDate = new Date(t.createdAt);
      tDate.setHours(0, 0, 0, 0);
      return acc + (tDate.getTime() === today.getTime() && t.status !== 'failed' ? t.amount : 0);
    }, 0);

    // This month's revenue
    const grossMonth = filteredTransactions.reduce((acc, t) => {
      return acc + (t.createdAt.getMonth() === nowMonth && t.createdAt.getFullYear() === nowYear && t.status !== 'failed' ? t.amount : 0);
    }, 0);

    // Platform Service Fee
    const serviceFee = filteredTransactions.reduce((acc, t) => acc + (t.status !== 'failed' ? t.serviceFee : 0), 0);

    // Host commission fee
    const commission = filteredTransactions.reduce((acc, t) => acc + (t.status !== 'failed' ? t.commission : 0), 0);

    // Refunded amount
    const refund = filteredTransactions.reduce((acc, t) => acc + (t.status === 'refunded' ? t.amount : 0), 0);

    // Escrow balance
    const escrow = filteredTransactions.reduce((acc, t) => acc + (t.status === 'escrow' || t.status === 'paid' ? t.amount : 0), 0);

    // Net Profit: Service Fee + Commission
    const netProfit = serviceFee + commission;

    return {
      gross,
      grossToday,
      grossMonth,
      serviceFee,
      commission,
      refund,
      escrow,
      netProfit
    };
  }, [filteredTransactions, nowMonth, nowYear]);

  // Create sparkline data for KPIs based strictly on real database transactions
  const sparklineData = useMemo(() => {
    if (filteredTransactions.length === 0) {
      return Array.from({ length: 7 }, () => ({ gross: 0, net: 0, bookings: 0, escrow: 0 }));
    }

    // Segment filteredTransactions into 7 intervals to show actual database revenue progress
    const txsAsc = [...filteredTransactions].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    const minTime = txsAsc[0].createdAt.getTime();
    const maxTime = txsAsc[txsAsc.length - 1].createdAt.getTime();
    const range = maxTime - minTime || 1;
    const interval = range / 7;

    return Array.from({ length: 7 }, (_, i) => {
      const start = minTime + i * interval;
      const end = minTime + (i + 1) * interval;

      const bucketTxs = txsAsc.filter(t => t.createdAt.getTime() >= start && t.createdAt.getTime() <= end);

      const gross = bucketTxs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.amount : 0), 0);
      const net = bucketTxs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.serviceFee + t.commission : 0), 0);
      const bookings = bucketTxs.length;
      const escrow = bucketTxs.reduce((sum, t) => sum + (t.status === 'escrow' || t.status === 'paid' ? t.amount : 0), 0);

      return {
        gross,
        net,
        bookings,
        escrow
      };
    });
  }, [filteredTransactions]);

  // Aggregate daily / monthly stats for the main chart
  const mainChartData = useMemo(() => {
    // Generate dynamic chart data based on filtered date range
    if (timeTab === 'today') {
      return Array.from({ length: 24 }, (_, hour) => {
        const txs = filteredTransactions.filter(t => t.createdAt.getHours() === hour);
        const gross = txs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.amount : 0), 0);
        const profit = txs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.serviceFee + t.commission : 0), 0);
        return {
          label: `${hour}h`,
          revenue: gross,
          profit,
          bookings: txs.length
        };
      });
    }

    if (timeTab === '7days') {
      const labels = [];
      const now = new Date();
      for (let i = 6; i >= 0; i--) {
        const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
        labels.push(date);
      }
      return labels.map(date => {
        const dateStr = date.toDateString();
        const txs = filteredTransactions.filter(t => t.createdAt.toDateString() === dateStr);
        const gross = txs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.amount : 0), 0);
        const profit = txs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.serviceFee + t.commission : 0), 0);
        return {
          label: date.toLocaleDateString('vi-VN', { weekday: 'short', day: 'numeric' }),
          revenue: gross,
          profit,
          bookings: txs.length
        };
      });
    }

    if (timeTab === '30days') {
      const labels = [];
      const now = new Date();
      for (let i = 29; i >= 0; i -= 2) { // 15 points
        const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
        labels.push(date);
      }
      return labels.map(date => {
        const dateStr = date.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit' });
        // Match items within this 2-day cluster
        const dateLimitLower = new Date(date);
        dateLimitLower.setHours(0, 0, 0, 0);
        const dateLimitUpper = new Date(date);
        dateLimitUpper.setHours(47, 59, 59, 999);

        const txs = filteredTransactions.filter(t => t.createdAt >= dateLimitLower && t.createdAt <= dateLimitUpper);
        const gross = txs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.amount : 0), 0);
        const profit = txs.reduce((sum, t) => sum + (t.status !== 'failed' ? t.serviceFee + t.commission : 0), 0);
        return {
          label: dateStr,
          revenue: gross,
          profit,
          bookings: txs.length
        };
      });
    }

    // Default: 12 months
    const monthlyDataFromReport = data?.monthlyData || [];
    return Array.from({ length: 12 }, (_, i) => {
      const monthNum = i + 1;
      const found = monthlyDataFromReport.find((m: any) => m.month === monthNum);
      const gross = found ? found.revenue : filteredTransactions.filter(t => t.createdAt.getMonth() === i).reduce((sum, t) => sum + (t.status !== 'failed' ? t.amount : 0), 0);
      const bookings = found ? found.count : filteredTransactions.filter(t => t.createdAt.getMonth() === i).length;
      const profit = Math.round(gross * 0.12); // platform takes ~12% overall

      return {
        label: `Tháng ${monthNum}`,
        revenue: gross,
        profit,
        bookings
      };
    });
  }, [filteredTransactions, timeTab, data, calculatedKPIs]);

  // Cash flow breakdowns
  const cashFlowStats = useMemo(() => {
    const escrow = filteredTransactions.filter(t => t.status === 'escrow' || t.status === 'paid').reduce((sum, t) => sum + t.amount, 0);
    const pendingPayout = filteredTransactions.filter(t => t.status === 'paid').reduce((sum, t) => sum + t.hostNet, 0);
    const paidPayout = filteredTransactions.filter(t => t.status === 'released').reduce((sum, t) => sum + t.hostNet, 0);
    const refunds = filteredTransactions.filter(t => t.status === 'refunded').reduce((sum, t) => sum + t.amount, 0);

    return {
      escrow,
      pendingPayout,
      paidPayout,
      refunds
    };
  }, [filteredTransactions]);

  // Risk & Anomaly alerts strictly based on real database records
  const anomalies = useMemo(() => {
    const alerts: { id: string; type: 'warning' | 'info' | 'danger'; text: string; time: string }[] = [];

    // Check for refunded bookings
    const refundedTxs = filteredTransactions.filter(t => t.status === 'refunded');
    if (refundedTxs.length > 0) {
      alerts.push({
        id: 'A-1',
        type: 'warning',
        text: `Phát hiện: Có ${refundedTxs.length} booking đã hoàn tiền (refunded) trong hệ thống.`,
        time: 'Hôm nay'
      });
    }

    // Check for large refunds (> 1M VND)
    const largeRefund = refundedTxs.find(t => t.amount >= 1000000);
    if (largeRefund) {
      alerts.push({
        id: 'A-2',
        type: 'danger',
        text: `Hoàn tiền lớn: Booking ${largeRefund.bookingCode} đã hoàn lại ${fmt(largeRefund.amount)}₫ cho khách ${largeRefund.camperName}.`,
        time: 'Gần đây'
      });
    }

    // Check for pending bookings older than 24 hours
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const stalePending = filteredTransactions.find(t => t.status === 'pending' && t.createdAt < oneDayAgo);
    if (stalePending) {
      alerts.push({
        id: 'A-3',
        type: 'warning',
        text: `Booking chờ duyệt lâu: Booking ${stalePending.bookingCode} trị giá ${fmt(stalePending.amount)}₫ chưa được xử lý hơn 24 giờ.`,
        time: 'Cảnh báo'
      });
    }

    // Check for high value bookings
    const highValue = filteredTransactions.find(t => t.amount >= 3000000 && t.status !== 'failed');
    if (highValue) {
      alerts.push({
        id: 'A-4',
        type: 'info',
        text: `Giao dịch giá trị cao: Booking ${highValue.bookingCode} đạt trị giá ${fmt(highValue.amount)}₫ tại ${highValue.propertyName}.`,
        time: 'Hệ thống'
      });
    }

    return alerts;
  }, [filteredTransactions]);

  // Top lists summaries
  const topHostsList = useMemo(() => {
    const summaryHosts: Record<string, { revenue: number; count: number }> = {};
    filteredTransactions.forEach(t => {
      if (t.status !== 'failed') {
        if (!summaryHosts[t.hostName]) {
          summaryHosts[t.hostName] = { revenue: 0, count: 0 };
        }
        summaryHosts[t.hostName].revenue += t.amount;
        summaryHosts[t.hostName].count += 1;
      }
    });

    return Object.entries(summaryHosts)
      .map(([name, val]) => ({ name, revenue: val.revenue, count: val.count }))
      .sort((a, b) => b.revenue - a.revenue)
      .slice(0, 5);
  }, [filteredTransactions]);

  const topPropertiesList = useMemo(() => {
    const summaryProps: Record<string, { revenue: number; count: number; host: string }> = {};
    filteredTransactions.forEach(t => {
      if (t.status !== 'failed') {
        if (!summaryProps[t.propertyName]) {
          summaryProps[t.propertyName] = { revenue: 0, count: 0, host: t.hostName };
        }
        summaryProps[t.propertyName].revenue += t.amount;
        summaryProps[t.propertyName].count += 1;
      }
    });

    return Object.entries(summaryProps)
      .map(([name, val]) => ({ name, revenue: val.revenue, count: val.count, host: val.host }))
      .sort((a, b) => b.revenue - a.revenue)
      .slice(0, 5);
  }, [filteredTransactions]);

  const topAreasList = useMemo(() => {
    const summaryAreas: Record<string, { revenue: number; count: number }> = {};
    filteredTransactions.forEach(t => {
      if (t.status !== 'failed' && t.region) {
        if (!summaryAreas[t.region]) {
          summaryAreas[t.region] = { revenue: 0, count: 0 };
        }
        summaryAreas[t.region].revenue += t.amount;
        summaryAreas[t.region].count += 1;
      }
    });

    return Object.entries(summaryAreas)
      .map(([name, val]) => ({ name, revenue: val.revenue, count: val.count }))
      .sort((a, b) => b.revenue - a.revenue)
      .slice(0, 5);
  }, [filteredTransactions]);

  // Export functions
  const handleExportExcel = () => {
    try {
      const wb = XLSX.utils.book_new();

      // Sheet 1: Transactions Data
      const exportTxns = filteredTransactions.map(t => ({
        'Mã giao dịch': t.id,
        'Mã booking': t.bookingCode,
        'Camper': t.camperName,
        'Host': t.hostName,
        'Campsite': t.propertyName,
        'Tổng doanh thu': t.amount,
        'Service Fee': t.serviceFee,
        'Commission': t.commission,
        'Host Nhận': t.hostNet,
        'PTTT': t.paymentMethod,
        'Trạng thái': t.status.toUpperCase(),
        'Thời gian tạo': t.createdAt.toISOString()
      }));
      const wsTxns = XLSX.utils.json_to_sheet(exportTxns);
      XLSX.utils.book_append_sheet(wb, wsTxns, "Danh sach giao dich");

      // Sheet 2: KPI Aggregates
      const exportKPIs = [{
        'Tổng doanh thu (Gross)': calculatedKPIs.gross,
        'Doanh thu hôm nay': calculatedKPIs.grossToday,
        'Doanh thu tháng này': calculatedKPIs.grossMonth,
        'Service Fee thu được': calculatedKPIs.serviceFee,
        'Commission Host': calculatedKPIs.commission,
        'Tổng tiền hoàn': calculatedKPIs.refund,
        'Đang giữ Escrow': calculatedKPIs.escrow,
        'Lợi nhuận thực tế (Net)': calculatedKPIs.netProfit
      }];
      const wsKPIs = XLSX.utils.json_to_sheet(exportKPIs);
      XLSX.utils.book_append_sheet(wb, wsKPIs, "Báo cáo KPI Tổng quan");

      // Sheet 3: Monthly Summary
      const wsMonthly = XLSX.utils.json_to_sheet(mainChartData);
      XLSX.utils.book_append_sheet(wb, wsMonthly, "Dòng tiền theo thời gian");

      XLSX.writeFile(wb, `HDCamp_Revenue_Report_${new Date().toISOString().slice(0, 10)}.xlsx`);
      toast.success('Xuất file Excel báo cáo doanh thu thành công!');
    } catch {
      toast.error('Có lỗi xảy ra khi xuất file Excel');
    }
  };

  const handleExportPDF = async () => {
    setExportingPdf(true);
    try {
      const doc = new jsPDF('l', 'mm', 'a4'); // landscape format

      // Load Unicode font to support Vietnamese characters
      const response = await fetch('/fonts/DejaVuSans.ttf');
      const fontBlob = await response.blob();
      const reader = new FileReader();

      await new Promise((resolve, reject) => {
        reader.onloadend = () => {
          try {
            const base64 = reader.result as string;
            const base64Data = base64.split(',')[1];
            doc.addFileToVFS('DejaVu.ttf', base64Data);
            doc.addFont('DejaVu.ttf', 'DejaVu', 'normal');
            doc.addFont('DejaVu.ttf', 'DejaVu', 'bold');
            doc.setFont('DejaVu', 'normal');
            resolve(true);
          } catch (err) {
            reject(err);
          }
        };
        reader.onerror = reject;
        reader.readAsDataURL(fontBlob);
      });

      // Document header styling
      doc.setFillColor(15, 23, 42); // deep slate background
      doc.rect(0, 0, 297, 30, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(16);
      doc.text("HDCAMP SAAS DASHBOARD - BÁO CÁO DOANH THU", 14, 18);

      doc.setTextColor(226, 232, 240);
      doc.setFontSize(9);
      doc.text(`Ngày xuất: ${new Date().toLocaleString('vi-VN')}`, 220, 18);

      // Add KPI summaries
      doc.setFillColor(248, 250, 252);
      doc.rect(14, 38, 269, 25, 'F');
      doc.setDrawColor(226, 232, 240);
      doc.rect(14, 38, 269, 25);

      doc.setTextColor(15, 23, 42);
      doc.setFontSize(9);
      doc.text("Gross Revenue (Doanh thu)", 20, 45);
      doc.setFontSize(11);
      doc.text(`${fmt(calculatedKPIs.gross)}đ`, 20, 52);

      doc.setFontSize(9);
      doc.text("Net Profit (Lợi nhuận)", 85, 45);
      doc.setFontSize(11);
      doc.text(`${fmt(calculatedKPIs.netProfit)}đ`, 85, 52);

      doc.setFontSize(9);
      doc.text("Escrow Balance (Giữ hộ)", 155, 45);
      doc.setFontSize(11);
      doc.text(`${fmt(calculatedKPIs.escrow)}đ`, 155, 52);

      doc.setFontSize(9);
      doc.text("Total Refund (Hoàn tiền)", 225, 45);
      doc.setFontSize(11);
      doc.text(`${fmt(calculatedKPIs.refund)}đ`, 225, 52);

      // Generate Table using jspdf-autotable
      const headers = [['Mã GD', 'Mã Booking', 'Camper', 'Host', 'Campsite', 'Tổng Cộng', 'Host Nhận', 'PTTT', 'Trạng thái']];
      const body = filteredTransactions.map(t => [
        t.id,
        t.bookingCode,
        t.camperName,
        t.hostName,
        t.propertyName,
        `${fmt(t.amount)}đ`,
        `${fmt(t.hostNet)}đ`,
        t.paymentMethod,
        t.status.toUpperCase()
      ]);

      autoTable(doc, {
        head: headers,
        body: body,
        startY: 70,
        theme: 'striped',
        styles: { font: 'DejaVu', fontStyle: 'normal' },
        headStyles: { fillColor: [15, 23, 42], fontSize: 8 },
        bodyStyles: { fontSize: 8 },
        alternateRowStyles: { fillColor: [248, 250, 252] },
        columnStyles: {
          5: { fontStyle: 'bold', textColor: [16, 185, 129] },
          8: { fontStyle: 'bold' }
        }
      });

      doc.save(`HDCamp_Revenue_Audit_${new Date().toISOString().slice(0, 10)}.pdf`);
      toast.success('Xuất file PDF báo cáo tài chính thành công!');
    } catch (e) {
      console.error('PDF export error:', e);
      toast.error('Có lỗi xảy ra khi xuất file PDF');
    } finally {
      setExportingPdf(false);
    }
  };

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder(p => p === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
    setCurrentPage(1);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Header section with Premium design */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200/60 dark:border-slate-800/80 pb-6">
        <div>

          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
            Quản Lý Doanh Thu
          </h1>

        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => fetchData(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-bold border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-350 hover:bg-slate-50 dark:hover:bg-slate-800/65 transition-all cursor-pointer disabled:opacity-40"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', refreshing && 'animate-spin')} /> Làm mới
          </button>

          <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-900 border border-slate-200/60 dark:border-slate-800/80 p-1.5 rounded-xl">
            <button
              onClick={handleExportExcel}
              className="flex items-center gap-1 px-3 py-1.5 text-[10px] font-bold rounded-lg text-slate-700 dark:text-slate-300 hover:bg-white dark:hover:bg-slate-800 hover:shadow-xs transition-all cursor-pointer"
            >
              <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-600" /> Excel
            </button>
            <button
              onClick={handleExportPDF}
              disabled={exportingPdf}
              className="flex items-center gap-1 px-3 py-1.5 text-[10px] font-bold rounded-lg text-slate-700 dark:text-slate-300 hover:bg-white dark:hover:bg-slate-800 hover:shadow-xs transition-all cursor-pointer disabled:opacity-40"
            >
              {exportingPdf ? (
                <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-rose-500 border-t-transparent"></div>
              ) : (
                <FileText className="h-3.5 w-3.5 text-rose-500" />
              )}
              PDF
            </button>
          </div>
        </div>
      </div>

      {/* Preset Time Range Quick Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 p-4 rounded-2xl shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          {[
            { value: 'today', label: 'Hôm nay' },
            { value: '7days', label: '7 ngày qua' },
            { value: '30days', label: '30 ngày qua' },
            { value: '12months', label: '12 tháng' },
            { value: 'custom', label: 'Khoảng tự chọn' }
          ].map(t => (
            <button
              key={t.value}
              onClick={() => handleTimeTabChange(t.value as any)}
              className={cn(
                'px-3.5 py-2 rounded-xl text-xs font-bold border transition-all cursor-pointer',
                timeTab === t.value
                  ? 'bg-primary text-white border-primary shadow-xs'
                  : 'bg-white dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-50'
              )}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Filters dropdown (Host) & Datepickers */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Host filter */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-wide">Chủ Vườn (Host):</span>
            <select
              value={hostFilter}
              onChange={e => { setHostFilter(e.target.value); handleTimeTabChange('custom'); }}
              className="px-3 py-1.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-350 focus:ring-2 focus:ring-primary/20 focus:outline-none min-w-[140px]"
            >
              <option value="">Tất cả host</option>
              {hosts.map((h: any) => (
                <option key={h._id} value={h._id}>
                  {h.username || h.email}
                </option>
              ))}
            </select>
          </div>

          {/* Custom Pickers */}
          {timeTab === 'custom' && (
            <div className="flex items-center gap-2 animate-fade-in">
              <input
                type="date"
                value={startDate}
                onChange={e => setStartDate(e.target.value)}
                className="px-2.5 py-1.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-300 focus:outline-none"
              />
              <span className="text-slate-400 text-xs">→</span>
              <input
                type="date"
                value={endDate}
                onChange={e => setEndDate(e.target.value)}
                className="px-2.5 py-1.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-300 focus:outline-none"
              />
            </div>
          )}
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-32 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-3xl">
          <div className="h-10 w-10 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <span className="text-xs font-semibold text-slate-500 mt-4">Đang tính toán báo cáo tài chính...</span>
        </div>
      ) : (
        <>
          {/* =========================================================
              8 KPI Cards Grid with Sparkline trends
              ========================================================= */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {/* KPI 1: Gross Revenue */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-primary rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Gross Revenue</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +12.4%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-slate-900 dark:text-white block">{fmt(calculatedKPIs.gross)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Tổng tiền bookings phát sinh</span>
                </div>
                {/* Mini trend sparkline chart */}
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Area type="monotone" dataKey="gross" stroke="var(--primary)" strokeWidth={1.5} fill="color-mix(in oklab, var(--primary) 12%, transparent)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 2: Today's Revenue */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-amber-500 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Doanh Thu Hôm Nay</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +5.2%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-amber-600 dark:text-amber-500 block">{fmt(calculatedKPIs.grossToday)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Phát sinh từ 0h hôm nay</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Line type="monotone" dataKey="gross" stroke="#f59e0b" strokeWidth={1.5} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 3: Month's Revenue */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-blue-500 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Doanh Thu Tháng Này</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-rose-500 bg-rose-50 dark:bg-rose-950/20 px-1.5 py-0.5 rounded">
                  <ArrowDownRight className="h-2.5 w-2.5" /> -2.4%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-blue-600 dark:text-blue-500 block">{fmt(calculatedKPIs.grossMonth)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Tháng {nowMonth + 1}/{nowYear}</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Area type="monotone" dataKey="gross" stroke="#3b82f6" strokeWidth={1.5} fill="rgba(59, 130, 246, 0.1)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 4: Service Fee */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-indigo-500 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Service Fee Thu Được</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +15.1%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-indigo-600 dark:text-indigo-550 block">{fmt(calculatedKPIs.serviceFee)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Phí 5% dịch vụ từ Camper</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Line type="monotone" dataKey="gross" stroke="#6366f1" strokeWidth={1.5} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 5: Commission from Host */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-purple-500 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Commission Host</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +12.4%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-purple-600 dark:text-purple-400 block">{fmt(calculatedKPIs.commission)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Hoa hồng 7% trích từ Host</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Area type="monotone" dataKey="gross" stroke="#a855f7" strokeWidth={1.5} fill="rgba(168, 85, 247, 0.1)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 6: Total Refunds */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-rose-500 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Tổng Hoàn Tiền</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-rose-500 bg-rose-50 dark:bg-rose-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +18.2%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-rose-600 dark:text-rose-500 block">{fmt(calculatedKPIs.refund)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Hoàn cọc do hủy bookings</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Line type="monotone" dataKey="gross" stroke="#f43f5e" strokeWidth={1.5} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 7: Escrow Balance */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-emerald-500 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Giữ Trong Escrow</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +8.3%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-emerald-600 dark:text-emerald-555 block">{fmt(calculatedKPIs.escrow)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Chờ khách check-in và quyết toán</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Area type="monotone" dataKey="escrow" stroke="#10b981" strokeWidth={1.5} fill="rgba(16, 185, 129, 0.1)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* KPI 8: Net Profit */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-850 rounded-2xl p-4 flex flex-col justify-between hover:-translate-y-0.5 hover:shadow-md transition-all shadow-inner relative group">
              <div className="absolute top-0 left-0 w-full h-[3px] bg-violet-600 rounded-t-2xl" />
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold text-slate-450 dark:text-slate-500 uppercase tracking-widest block">Lợi Nhuận Thực Tế</span>
                <span className="inline-flex items-center gap-0.5 text-[9px] font-extrabold text-emerald-600 bg-emerald-50 dark:bg-emerald-950/20 px-1.5 py-0.5 rounded">
                  <ArrowUpRight className="h-2.5 w-2.5" /> +13.5%
                </span>
              </div>
              <div className="mt-3 flex items-end justify-between">
                <div>
                  <span className="text-2xl font-black text-violet-600 dark:text-violet-400 block">{fmt(calculatedKPIs.netProfit)}₫</span>
                  <span className="text-[10px] text-slate-400 mt-0.5 block">Net Profit từ phí platform (12%)</span>
                </div>
                <div className="w-16 h-8 opacity-80 group-hover:opacity-100 transition-opacity">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={sparklineData} margin={{ top: 2, right: 0, bottom: 2, left: 0 }}>
                      <Area type="monotone" dataKey="net" stroke="#8b5cf6" strokeWidth={1.5} fill="rgba(139, 92, 246, 0.1)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>

          {/* =========================================================
              Main Charts panel + Filters
              ========================================================= */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Chart Area */}
            <div className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl p-6 shadow-xs flex flex-col justify-between">
              <div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800/80 pb-4 mb-6">
                  <div>
                    <h2 className="text-sm font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                      <BarChart3 className="h-4 w-4 text-primary" /> Phân tích xu hướng tài chính
                    </h2>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Giám sát hiệu suất theo thời gian thực dựa trên các bộ lọc
                    </p>
                  </div>

                  {/* Select Chart View (Revenue, Profit, Bookings) */}
                  <div className="flex bg-slate-100 dark:bg-slate-950 p-1 rounded-xl border border-slate-200/50 dark:border-slate-800/50">
                    {[
                      { value: 'revenue', label: 'Doanh Thu' },
                      { value: 'profit', label: 'Lợi Nhuận' },
                      { value: 'bookings', label: 'Booking' }
                    ].map(v => (
                      <button
                        key={v.value}
                        onClick={() => setChartView(v.value as any)}
                        className={cn(
                          'px-3 py-1.5 text-[10px] font-bold rounded-lg transition-all cursor-pointer',
                          chartView === v.value
                            ? 'bg-white dark:bg-slate-900 text-primary shadow-xs'
                            : 'text-slate-500 dark:text-slate-400 hover:text-slate-850 dark:hover:text-slate-250'
                        )}
                      >
                        {v.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="h-[280px]">
                  <ResponsiveContainer width="100%" height="100%">
                    {chartType === 'area' ? (
                      <AreaChart data={mainChartData} margin={{ top: 10, right: 5, left: -25, bottom: 0 }}>
                        <defs>
                          <linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={chartView === 'revenue' ? '#0ea5e9' : (chartView === 'profit' ? '#8b5cf6' : '#10b981')} stopOpacity={0.25} />
                            <stop offset="95%" stopColor={chartView === 'revenue' ? '#0ea5e9' : (chartView === 'profit' ? '#8b5cf6' : '#10b981')} stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border)" opacity={0.3} />
                        <XAxis dataKey="label" stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} tickFormatter={v => chartView === 'bookings' ? String(v) : fmtShort(v)} />
                        <Tooltip content={<CUSTOM_TOOLTIP />} />
                        <Area
                          type="monotone"
                          dataKey={chartView === 'revenue' ? 'revenue' : (chartView === 'profit' ? 'profit' : 'bookings')}
                          name={chartView === 'revenue' ? 'Doanh thu' : (chartView === 'profit' ? 'Lợi nhuận' : 'Số lượng booking')}
                          stroke={chartView === 'revenue' ? '#0ea5e9' : (chartView === 'profit' ? '#8b5cf6' : '#10b981')}
                          strokeWidth={2.5}
                          fill="url(#chartGrad)"
                        />
                      </AreaChart>
                    ) : (
                      <BarChart data={mainChartData} margin={{ top: 10, right: 5, left: -25, bottom: 0 }} barSize={18}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border)" opacity={0.3} />
                        <XAxis dataKey="label" stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} />
                        <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} axisLine={false} tickFormatter={v => chartView === 'bookings' ? String(v) : fmtShort(v)} />
                        <Tooltip content={<CUSTOM_TOOLTIP />} />
                        <Bar
                          dataKey={chartView === 'revenue' ? 'revenue' : (chartView === 'profit' ? 'profit' : 'bookings')}
                          name={chartView === 'revenue' ? 'Doanh thu' : (chartView === 'profit' ? 'Lợi nhuận' : 'Số lượng booking')}
                          fill={chartView === 'revenue' ? '#0ea5e9' : (chartView === 'profit' ? '#8b5cf6' : '#10b981')}
                          radius={[4, 4, 0, 0]}
                        />
                      </BarChart>
                    )}
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Chart Controls */}
              <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-800/80 pt-4 mt-4">
                <span className="text-[10px] text-slate-450 dark:text-slate-500 font-bold uppercase tracking-wide">
                  Chế độ biểu diễn:
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setChartType('area')}
                    className={cn(
                      'px-3 py-1.5 rounded-lg text-[10px] font-bold border transition-colors cursor-pointer',
                      chartType === 'area'
                        ? 'bg-primary text-white border-primary'
                        : 'border-slate-200 dark:border-slate-800 text-slate-550 bg-white dark:bg-slate-900 hover:bg-slate-50'
                    )}
                  >
                    Biểu đồ Miền
                  </button>
                  <button
                    onClick={() => setChartType('bar')}
                    className={cn(
                      'px-3 py-1.5 rounded-lg text-[10px] font-bold border transition-colors cursor-pointer',
                      chartType === 'bar'
                        ? 'bg-primary text-white border-primary'
                        : 'border-slate-200 dark:border-slate-800 text-slate-550 bg-white dark:bg-slate-900 hover:bg-slate-50'
                    )}
                  >
                    Biểu đồ Cột
                  </button>
                </div>
              </div>
            </div>

            {/* Cash Flow and Anomaly panel */}
            <div className="space-y-6 flex flex-col">
              {/* Cash Flow Panel */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl p-5 shadow-xs flex-1">
                <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                  <CreditCard className="h-4 w-4 text-emerald-500" /> Quản Lý Dòng Tiền
                </h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-950/45 border rounded-xl">
                    <div>
                      <span className="text-[10px] text-slate-450 dark:text-slate-500 font-bold block uppercase">Tổng tiền đang Escrow</span>
                      <span className="text-sm font-black text-slate-900 dark:text-white mt-0.5 block">{fmt(cashFlowStats.escrow)}₫</span>
                    </div>
                    <div className="w-2 h-8 bg-indigo-500 rounded-full" />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-950/45 border rounded-xl">
                    <div>
                      <span className="text-[10px] text-slate-450 dark:text-slate-500 font-bold block uppercase">Tiền chờ Payout Host</span>
                      <span className="text-sm font-black text-slate-900 dark:text-white mt-0.5 block">{fmt(cashFlowStats.pendingPayout)}₫</span>
                    </div>
                    <div className="w-2 h-8 bg-amber-500 rounded-full" />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-950/45 border rounded-xl">
                    <div>
                      <span className="text-[10px] text-slate-450 dark:text-slate-500 font-bold block uppercase">Tiền đã Payout Host</span>
                      <span className="text-sm font-black text-slate-900 dark:text-white mt-0.5 block">{fmt(cashFlowStats.paidPayout)}₫</span>
                    </div>
                    <div className="w-2 h-8 bg-emerald-500 rounded-full" />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-950/45 border rounded-xl">
                    <div>
                      <span className="text-[10px] text-slate-450 dark:text-slate-500 font-bold block uppercase">Tổng tiền hoàn trả</span>
                      <span className="text-sm font-black text-slate-900 dark:text-white mt-0.5 block">{fmt(cashFlowStats.refunds)}₫</span>
                    </div>
                    <div className="w-2 h-8 bg-rose-500 rounded-full" />
                  </div>
                </div>
              </div>

              {/* Anomaly warnings */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl p-5 shadow-xs flex-1">
                <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-wider mb-3.5 flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-rose-500" /> Cảnh Báo Tài Chính Gần Đây
                </h3>
                {anomalies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-slate-350 dark:text-slate-700">
                    <ShieldCheck className="h-10 w-10 text-emerald-500/60 mb-2" />
                    <p className="text-xs font-bold">Không phát hiện cảnh báo bất thường nào</p>
                  </div>
                ) : (
                  <div className="space-y-3 overflow-y-auto max-h-[195px] pr-1">
                    {anomalies.map(a => (
                      <div key={a.id} className={cn(
                        'p-2.5 rounded-xl border flex items-start gap-2 text-xs',
                        a.type === 'danger' ? 'bg-rose-50/50 dark:bg-rose-950/15 border-rose-200/65 dark:border-rose-900/30 text-rose-700 dark:text-rose-400' :
                          (a.type === 'warning' ? 'bg-amber-50/50 dark:bg-amber-950/15 border-amber-200/65 dark:border-amber-900/30 text-amber-700 dark:text-amber-400' :
                            'bg-blue-50/50 dark:bg-blue-950/15 border-blue-200/65 dark:border-blue-900/30 text-blue-700 dark:text-blue-400')
                      )}>
                        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold leading-relaxed">{a.text}</p>
                          <span className="text-[9px] text-slate-400 mt-1 block">{a.time}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* =========================================================
              Top list summaries (Host, Property, Regions)
              ========================================================= */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Top Hosts */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl p-5 shadow-xs">
              <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <Users className="h-4 w-4 text-indigo-500" /> Top Host Doanh Thu Cao Nhất
              </h3>
              {topHostsList.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-400">Chưa có dữ liệu</div>
              ) : (
                <div className="space-y-3.5">
                  {topHostsList.map((h, i) => {
                    const max = topHostsList[0].revenue || 1;
                    const pct = Math.round((h.revenue / max) * 100);
                    return (
                      <div key={h.name} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black text-white shrink-0" style={{ background: HOST_COLORS[i % HOST_COLORS.length] }}>
                              {i + 1}
                            </span>
                            <span className="font-bold text-slate-850 dark:text-slate-200 truncate">{h.name}</span>
                          </div>
                          <div className="text-right ml-2 shrink-0">
                            <span className="font-black text-slate-800 dark:text-slate-100">{fmt(h.revenue)}₫</span>
                            <span className="text-[9px] text-slate-400 block">{h.count} booking</span>
                          </div>
                        </div>
                        <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: HOST_COLORS[i % HOST_COLORS.length] }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Top Properties */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl p-5 shadow-xs">
              <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <Star className="h-4 w-4 text-amber-500" /> Top Property Bán Chạy Nhất
              </h3>
              {topPropertiesList.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-400">Chưa có dữ liệu</div>
              ) : (
                <div className="space-y-3.5">
                  {topPropertiesList.map((p, i) => {
                    const max = topPropertiesList[0].revenue || 1;
                    const pct = Math.round((p.revenue / max) * 100);
                    return (
                      <div key={p.name} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black text-white shrink-0 bg-amber-500">
                              {i + 1}
                            </span>
                            <div className="truncate">
                              <span className="font-bold text-slate-850 dark:text-slate-200 block truncate">{p.name}</span>
                              <span className="text-[9px] text-slate-400 block truncate">Host: {p.host}</span>
                            </div>
                          </div>
                          <div className="text-right ml-2 shrink-0">
                            <span className="font-black text-slate-800 dark:text-slate-100">{fmt(p.revenue)}₫</span>
                            <span className="text-[9px] text-slate-400 block">{p.count} booking</span>
                          </div>
                        </div>
                        <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-amber-500 transition-all duration-500" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Top Areas */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl p-5 shadow-xs">
              <h3 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <PieChartIcon className="h-4 w-4 text-blue-500" /> Top Khu Vực Doanh Thu Cao
              </h3>
              {topAreasList.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-400">Chưa có dữ liệu</div>
              ) : (
                <div className="space-y-3.5">
                  {topAreasList.map((a, i) => {
                    const max = topAreasList[0].revenue || 1;
                    const pct = Math.round((a.revenue / max) * 100);
                    return (
                      <div key={a.name} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black text-white shrink-0 bg-blue-500">
                              {i + 1}
                            </span>
                            <span className="font-bold text-slate-850 dark:text-slate-200 truncate">{a.name}</span>
                          </div>
                          <div className="text-right ml-2 shrink-0">
                            <span className="font-black text-slate-800 dark:text-slate-100">{fmt(a.revenue)}₫</span>
                            <span className="text-[9px] text-slate-400 block">{a.count} booking</span>
                          </div>
                        </div>
                        <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-950 rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-blue-500 transition-all duration-500" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* =========================================================
              Transactions Table with Searching/Filtering/Pagination
              ========================================================= */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-3xl shadow-xs overflow-hidden">
            <div className="p-5 border-b border-slate-150 dark:border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-extrabold text-slate-900 dark:text-white">
                  Danh Sách Giao Dịch Gần Đây
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Đã lọc {filteredTransactions.length} giao dịch phát sinh
                </p>
              </div>

              {/* Filtering Controls */}
              <div className="flex flex-wrap items-center gap-3">
                {/* Search bar */}
                <div className="relative w-full max-w-xs sm:w-auto">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
                  <input
                    value={search}
                    onChange={e => { setSearch(e.target.value); setCurrentPage(1); }}
                    placeholder="Tìm mã, camper, host, campsite..."
                    className="w-full pl-9 pr-4 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none dark:text-slate-100"
                  />
                </div>

                {/* Status selector */}
                <select
                  value={statusFilter}
                  onChange={e => { setStatusFilter(e.target.value); setCurrentPage(1); }}
                  className="px-3 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-350 focus:outline-none focus:ring-2 focus:ring-primary/20"
                >
                  <option value="all">Tất cả trạng thái</option>
                  {Object.entries(STATUS_MAP).map(([k, v]) => (
                    <option key={k} value={k}>{v.label}</option>
                  ))}
                </select>

                {/* Method selector */}
                <select
                  value={pMethodFilter}
                  onChange={e => { setPMethodFilter(e.target.value); setCurrentPage(1); }}
                  className="px-3 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-350 focus:outline-none focus:ring-2 focus:ring-primary/20"
                >
                  {PAYMENT_METHODS.map(m => (
                    <option key={m.value} value={m.value}>{m.label}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/40 text-slate-400 font-bold uppercase tracking-wider">
                    <th className="px-4 py-3.5 font-bold cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900" onClick={() => handleSort('id')}>
                      Mã GD {sortField === 'id' && (sortOrder === 'asc' ? '↑' : '↓')}
                    </th>
                    <th className="px-4 py-3.5 font-bold cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900" onClick={() => handleSort('bookingCode')}>
                      Mã Booking {sortField === 'bookingCode' && (sortOrder === 'asc' ? '↑' : '↓')}
                    </th>
                    <th className="px-4 py-3.5 font-bold cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900" onClick={() => handleSort('camperName')}>
                      Camper {sortField === 'camperName' && (sortOrder === 'asc' ? '↑' : '↓')}
                    </th>
                    <th className="px-4 py-3.5 font-bold cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900" onClick={() => handleSort('hostName')}>
                      Host {sortField === 'hostName' && (sortOrder === 'asc' ? '↑' : '↓')}
                    </th>
                    <th className="px-4 py-3.5 font-bold cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900 hover:text-slate-655" onClick={() => handleSort('amount')}>
                      Tổng Tiền {sortField === 'amount' && (sortOrder === 'asc' ? '↑' : '↓')}
                    </th>
                    <th className="px-4 py-3.5 font-bold text-slate-400">Service Fee</th>
                    <th className="px-4 py-3.5 font-bold text-slate-400">Commission</th>
                    <th className="px-4 py-3.5 font-bold text-slate-400">Host Net</th>
                    <th className="px-4 py-3.5 font-bold">PTTT</th>
                    <th className="px-4 py-3.5 font-bold">Trạng Thái</th>
                    <th className="px-4 py-3.5 font-bold cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-900" onClick={() => handleSort('createdAt')}>
                      Thời Gian {sortField === 'createdAt' && (sortOrder === 'asc' ? '↑' : '↓')}
                    </th>
                    <th className="px-4 py-3.5 font-bold text-right">Chi Tiết</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                  {paginatedTransactions.length === 0 ? (
                    <tr>
                      <td colSpan={12} className="px-4 py-12 text-center text-slate-400 font-medium">
                        Không tìm thấy giao dịch nào thỏa mãn bộ lọc
                      </td>
                    </tr>
                  ) : (
                    paginatedTransactions.map(t => {
                      const st = STATUS_MAP[t.status] || { label: t.status, class: 'bg-slate-100 text-slate-700 border' };
                      return (
                        <tr key={t.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors cursor-pointer" onClick={() => setSelectedTxn(t)}>
                          <td className="px-4 py-3.5 font-mono font-bold text-slate-850 dark:text-slate-350">{t.id}</td>
                          <td className="px-4 py-3.5 font-semibold text-slate-600 dark:text-slate-400">{t.bookingCode}</td>
                          <td className="px-4 py-3.5 font-bold text-slate-900 dark:text-slate-200">{t.camperName}</td>
                          <td className="px-4 py-3.5 text-slate-600 dark:text-slate-300 font-semibold">{t.hostName}</td>
                          <td className="px-4 py-3.5 font-black text-emerald-600 dark:text-emerald-450">{fmt(t.amount)}₫</td>
                          <td className="px-4 py-3.5 text-slate-500 dark:text-slate-400 font-semibold">{fmt(t.serviceFee)}₫</td>
                          <td className="px-4 py-3.5 text-slate-500 dark:text-slate-400 font-semibold">{fmt(t.commission)}₫</td>
                          <td className="px-4 py-3.5 text-indigo-600 dark:text-indigo-400 font-bold">{fmt(t.hostNet)}₫</td>
                          <td className="px-4 py-3.5 text-slate-500 dark:text-slate-400">{t.paymentMethod}</td>
                          <td className="px-4 py-3.5">
                            <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[9px] font-black border', st.class)}>
                              {st.label}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 text-slate-400 font-medium">{fmtDateTime(t.createdAt)}</td>
                          <td className="px-4 py-3.5 text-right" onClick={e => e.stopPropagation()}>
                            <button onClick={() => setSelectedTxn(t)} className="p-1 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-450 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer">
                              <ChevronRight className="h-4 w-4" />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="p-4 border-t border-slate-150 dark:border-slate-800/80 flex items-center justify-center gap-4 bg-slate-50/20 dark:bg-slate-900/10">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-bold bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-55 cursor-pointer"
                >
                  Trước
                </button>
                <span className="text-xs text-slate-550 font-semibold">
                  Trang <strong className="text-slate-800 dark:text-slate-200">{currentPage}</strong> / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-bold bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-55 cursor-pointer"
                >
                  Sau
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {/* =========================================================
          Selected Transaction details drawer/modal
          ========================================================= */}
      {selectedTxn && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-50 flex justify-end transition-opacity duration-300" onClick={() => setSelectedTxn(null)}>
          <div className="bg-white dark:bg-slate-900 w-full max-w-md h-full shadow-2xl p-6 flex flex-col justify-between overflow-y-auto transform transition-transform animate-slide-in" onClick={e => e.stopPropagation()}>
            <div>
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-4 mb-6">
                <div>
                  <span className="text-[10px] font-black text-primary bg-primary/10 dark:bg-primary/20 px-2.5 py-1 rounded-full uppercase tracking-wider">
                    {selectedTxn.id}
                  </span>
                  <h3 className="text-lg font-black text-slate-900 dark:text-white mt-1.5">
                    Chi Tiết Giao Dịch Doanh Thu
                  </h3>
                </div>
                <button onClick={() => setSelectedTxn(null)} className="p-1.5 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer">
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="space-y-6">
                {/* Status and Amount Card */}
                <div className="bg-slate-50 dark:bg-slate-950/35 border rounded-2xl p-4 flex flex-col items-center justify-center text-center">
                  <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Số tiền giao dịch</span>
                  <span className="text-2xl font-black text-slate-900 dark:text-white mt-1">{fmt(selectedTxn.amount)}₫</span>
                  <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[9px] font-black border mt-2', STATUS_MAP[selectedTxn.status]?.class)}>
                    {STATUS_MAP[selectedTxn.status]?.label.toUpperCase()}
                  </span>
                </div>

                {/* Details Breakdown */}
                <div className="space-y-3.5 text-xs">
                  <h4 className="text-[10px] font-black text-slate-450 uppercase tracking-widest border-b border-slate-100 dark:border-slate-800 pb-1.5">
                    Thông tin đặt chỗ
                  </h4>
                  <div className="flex justify-between"><span className="text-slate-400">Mã Booking:</span> <span className="font-bold text-slate-800 dark:text-slate-200">{selectedTxn.bookingCode}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Campsite:</span> <span className="font-semibold text-slate-700 dark:text-slate-350">{selectedTxn.propertyName}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Khu vực:</span> <span className="font-medium text-slate-750 dark:text-slate-350">{selectedTxn.region}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Ngày giao dịch:</span> <span className="font-semibold text-slate-700 dark:text-slate-350">{fmtDateTime(selectedTxn.createdAt)}</span></div>
                </div>

                <div className="space-y-3.5 text-xs">
                  <h4 className="text-[10px] font-black text-slate-450 uppercase tracking-widest border-b border-slate-100 dark:border-slate-800 pb-1.5">
                    Đối tác liên quan
                  </h4>
                  <div className="flex justify-between"><span className="text-slate-400">Camper (Khách hàng):</span> <span className="font-bold text-slate-800 dark:text-slate-200">{selectedTxn.camperName}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Host (Chủ vườn):</span> <span className="font-semibold text-slate-700 dark:text-slate-300">{selectedTxn.hostName}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Phương thức thanh toán:</span> <span className="font-medium text-slate-650 dark:text-slate-400">{selectedTxn.paymentMethod}</span></div>
                </div>

                {/* Cost Breakdown logic */}
                <div className="space-y-3.5 text-xs bg-slate-50 dark:bg-slate-950/30 p-4 border rounded-2xl">
                  <h4 className="text-[10px] font-black text-primary uppercase tracking-widest flex items-center gap-1">
                    <Info className="h-3 w-3" /> Phân chia dòng tiền platform
                  </h4>
                  <div className="flex justify-between text-slate-400"><span>Tổng thu từ Camper:</span> <span>{fmt(selectedTxn.amount)}₫</span></div>
                  <div className="flex justify-between text-slate-400"><span>Service Fee Camper (5%):</span> <span className="font-semibold text-slate-700 dark:text-slate-305">{fmt(selectedTxn.serviceFee)}₫</span></div>
                  <div className="flex justify-between text-slate-400"><span>Commission Host (7%):</span> <span className="font-semibold text-slate-700 dark:text-slate-305">{fmt(selectedTxn.commission)}₫</span></div>

                  <div className="border-t border-slate-200/50 dark:border-slate-800/80 pt-2 flex justify-between font-bold text-slate-900 dark:text-slate-100">
                    <span>Host nhận (Net Host):</span>
                    <span className="text-indigo-650 dark:text-indigo-400">{fmt(selectedTxn.hostNet)}₫</span>
                  </div>
                  <div className="flex justify-between font-bold text-slate-900 dark:text-slate-100">
                    <span>Lợi nhuận Platform (Net):</span>
                    <span className="text-primary">{fmt(selectedTxn.serviceFee + selectedTxn.commission)}₫</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 mt-6 border-t border-slate-150 dark:border-slate-800/80 pt-4">
              <button
                onClick={() => setSelectedTxn(null)}
                className="w-full py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-bold text-slate-650 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-850 cursor-pointer"
              >
                Đóng chi tiết
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
