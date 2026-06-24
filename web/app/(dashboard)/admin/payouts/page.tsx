'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback } from 'react';
import API from '@/lib/api-client';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  DollarSign, RefreshCw, CheckCircle2, Clock, Play,
  ChevronLeft, ChevronRight, AlertCircle, TrendingUp, Users, Wallet,
  ChevronDown, ChevronUp, Building2, CreditCard, AlertTriangle,
  ListCheck, Search, Eye
} from 'lucide-react';
import { adminGetAllWithdrawals, adminGetHostBalances } from '@/services/wallet.service';
import { Input } from '@/components/ui/input';

const STATUS_MAP: Record<string, { label: string; class: string }> = {
  pending: { label: 'Chờ chuyển', class: 'bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-900/30' },
  processing: { label: 'Đang xử lý', class: 'bg-primary/10 dark:bg-primary/20 text-primary border border-primary/20' },
  completed: { label: 'Đã chuyển', class: 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/30' },
  failed: { label: 'Thất bại', class: 'bg-rose-50 dark:bg-rose-950/20 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-900/30' },
};

const fmt = (n: number) => new Intl.NumberFormat('vi-VN').format(Math.round(n));
const fmtDate = (d: string) => new Date(d).toLocaleDateString('vi-VN');

type UnpaidGroup = {
  hostId: string;
  host: any;
  bookingCount: number;
  grossAmount: number;
  platformFee: number;
  netAmount: number;
  bankInfo: any;
  bookings: any[];
};

export default function AdminPayoutsPage() {
  const [tab, setTab] = useState<'unpaid' | 'history' | 'withdrawals' | 'balances'>('withdrawals');

  // Unpaid bookings state
  const [unpaidData, setUnpaidData] = useState<{ groups: UnpaidGroup[]; totalHosts: number; totalBookings: number; totalAmount: number } | null>(null);
  const [unpaidLoading, setUnpaidLoading] = useState(true);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  // Payout history state
  const [payouts, setPayouts] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [stats, setStats] = useState<any>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [confirmNote, setConfirmNote] = useState('');
  const [acting, setActing] = useState(false);

  // Withdrawals tab state
  const [withdrawals, setWithdrawals] = useState<any[]>([]);
  const [withdrawalsLoading, setWithdrawalsLoading] = useState(true);
  const [withdrawalSearch, setWithdrawalSearch] = useState('');
  const [withdrawalStatus, setWithdrawalStatus] = useState('all');
  const [withdrawalPage, setWithdrawalPage] = useState(1);
  const [withdrawalTotalPages, setWithdrawalTotalPages] = useState(1);

  // Host balances tab state
  const [hostBalances, setHostBalances] = useState<any[]>([]);
  const [balancesLoading, setBalancesLoading] = useState(true);
  const [balancesSearch, setBalancesSearch] = useState('');
  const [balancesPage, setBalancesPage] = useState(1);
  const [balancesTotalPages, setBalancesTotalPages] = useState(1);

  const fetchUnpaid = useCallback(async () => {
    setUnpaidLoading(true);
    try {
      const res: any = await API.get('/payouts/admin/unpaid-bookings');
      setUnpaidData(res?.data ?? null);
    } catch { toast.error('Không thể tải dữ liệu booking chưa thanh toán'); }
    finally { setUnpaidLoading(false); }
  }, []);

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const params: any = { page, limit: 15 };
      if (statusFilter) params.status = statusFilter;
      const res: any = await API.get('/payouts/admin/all', { params });
      setPayouts(res?.data?.payouts ?? []);
      setTotalPages(res?.data?.totalPages ?? 1);
      setStats(res?.data?.stats ?? null);
    } catch { toast.error('Không thể tải lịch sử payout'); }
    finally { setHistoryLoading(false); }
  }, [page, statusFilter]);

  const fetchWithdrawals = useCallback(async () => {
    setWithdrawalsLoading(true);
    try {
      const params: any = { page: withdrawalPage, limit: 15 };
      if (withdrawalStatus !== 'all') params.status = withdrawalStatus;
      if (withdrawalSearch.trim()) params.search = withdrawalSearch.trim();
      const res: any = await adminGetAllWithdrawals(params);
      if (res.success) {
        setWithdrawals(res.data?.withdrawals || []);
        setWithdrawalTotalPages(res.data?.totalPages || 1);
      }
    } catch {
      toast.error('Không thể tải lịch sử rút tiền');
    } finally {
      setWithdrawalsLoading(false);
    }
  }, [withdrawalPage, withdrawalStatus, withdrawalSearch]);

  const fetchHostBalances = useCallback(async () => {
    setBalancesLoading(true);
    try {
      const params: any = { page: balancesPage, limit: 15 };
      if (balancesSearch.trim()) params.search = balancesSearch.trim();
      const res: any = await adminGetHostBalances(params);
      if (res.success) {
        setHostBalances(res.data?.hosts || []);
        setBalancesTotalPages(res.data?.totalPages || 1);
      }
    } catch {
      toast.error('Không thể tải số dư ví Host');
    } finally {
      setBalancesLoading(false);
    }
  }, [balancesPage, balancesSearch]);

  useEffect(() => { fetchUnpaid(); }, [fetchUnpaid]);
  useEffect(() => { if (tab === 'history') fetchHistory(); }, [tab, fetchHistory]);
  useEffect(() => { if (tab === 'withdrawals') fetchWithdrawals(); }, [tab, fetchWithdrawals]);
  useEffect(() => { if (tab === 'balances') fetchHostBalances(); }, [tab, fetchHostBalances]);

  const runMonthlyPayout = async () => {
    if (!window.confirm('Xác nhận chạy tổng kết? Hệ thống sẽ tạo payout cho tất cả host có booking chưa thanh toán.')) return;
    setRunning(true);
    try {
      const res: any = await API.post('/payouts/admin/run', {});
      toast.success(res?.data?.message || 'Đã chạy tổng kết');
      fetchUnpaid();
      if (tab === 'history') fetchHistory();
    } catch (e: any) { toast.error(e?.response?.data?.message ?? 'Lỗi'); }
    finally { setRunning(false); }
  };

  const markCompleted = async () => {
    if (!confirmId) return;
    setActing(true);
    try {
      await API.patch(`/payouts/admin/${confirmId}/complete`, { note: confirmNote });
      toast.success('Đã xác nhận chuyển tiền');
      setConfirmId(null); setConfirmNote('');
      fetchHistory();
    } catch (e: any) { toast.error(e?.response?.data?.message ?? 'Lỗi'); }
    finally { setActing(false); }
  };

  const statCards = stats ? [
    { label: 'Tổng doanh thu (gross)', value: `${fmt(stats.totalGross || 0)}₫`, icon: TrendingUp, color: 'text-primary', bg: 'bg-primary/10 dark:bg-primary/20' },
    { label: 'Phí platform', value: `${fmt(stats.totalFee || 0)}₫`, icon: DollarSign, color: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-50 dark:bg-purple-950/40' },
    { label: 'Đã chuyển cho host', value: `${fmt(stats.totalNet || 0)}₫`, icon: Wallet, color: 'text-primary', bg: 'bg-primary/10 dark:bg-primary/20' },
    { label: 'Số bản ghi payout', value: stats.totalPayouts || 0, icon: Users, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-950/40' },
  ] : [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
            Thanh toán Host
          </h1>

        </div>
        {tab === 'unpaid' && (
          <button
            onClick={runMonthlyPayout}
            disabled={running}
            className="flex items-center gap-1.5 px-4.5 py-2.5 rounded-xl text-xs font-extrabold text-white bg-primary hover:bg-primary/95 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play className="h-3.5 w-3.5 fill-white" />
            {running ? 'Đang tổng kết...' : 'Chạy tổng kết & tạo payout'}
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1.5 border-b border-slate-200 dark:border-slate-800">
        {([
          { key: 'withdrawals', label: 'Lịch sử rút tiền', icon: Clock, badge: null },
          { key: 'balances', label: 'Số dư ví Host', icon: Wallet, badge: null },
          // { key: 'unpaid', label: 'Kỳ hạn thanh toán (Chưa kết)', icon: AlertCircle, badge: unpaidData?.totalHosts },
          // { key: 'history', label: 'Lịch sử Kỳ hạn (Đã kết)', icon: DollarSign, badge: null },
        ] as const).map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              'flex items-center gap-1.5 px-4 py-2.5 text-xs font-extrabold transition-all border-b-2 rounded-t-lg -mb-[2px] cursor-pointer',
              tab === t.key
                ? 'border-primary text-primary bg-primary/10'
                : 'border-transparent text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
            )}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
            {t.badge != null && t.badge > 0 && (
              <span className="ml-1 flex h-4.5 min-w-4.5 items-center justify-center rounded-full bg-rose-500 text-[9px] font-black text-white px-1">
                {t.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ===== TAB: WITHDRAWALS (Lịch sử rút tiền) ===== */}
      {tab === 'withdrawals' && (
        <div className="space-y-4">
          {/* Filters & Search */}
          <div className="flex flex-wrap gap-3 items-center justify-between p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <Input
                placeholder="Tìm host, số TK..."
                value={withdrawalSearch}
                onChange={(e) => {
                  setWithdrawalSearch(e.target.value);
                  setWithdrawalPage(1);
                }}
                className="pl-9 text-xs rounded-xl border-slate-200 dark:border-slate-800"
              />
            </div>

            <div className="flex items-center gap-3">
              <select
                value={withdrawalStatus}
                onChange={(e) => {
                  setWithdrawalStatus(e.target.value);
                  setWithdrawalPage(1);
                }}
                className="px-3 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-700 dark:text-slate-300"
              >
                <option value="all">Tất cả trạng thái</option>
                <option value="completed">Đã chuyển tiền (Thành công)</option>
                <option value="pending">Chờ duyệt</option>
                <option value="processing">Đang xử lý</option>
                <option value="rejected">Bị từ chối</option>
              </select>

              <button
                onClick={fetchWithdrawals}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
              >
                <RefreshCw className="h-3.5 w-3.5" /> Làm mới
              </button>
            </div>
          </div>

          {/* List */}
          {withdrawalsLoading ? (
            <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
            </div>
          ) : withdrawals.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl text-slate-400 text-center space-y-2">
              <Clock className="h-12 w-12 text-slate-200 dark:text-slate-800" />
              <p className="text-sm font-semibold">Chưa có lịch sử rút tiền nào</p>
            </div>
          ) : (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-400 font-bold text-xs uppercase tracking-wider">
                      <th className="px-4 py-3.5">Host</th>
                      <th className="px-4 py-3.5">Số tiền rút</th>
                      <th className="px-4 py-3.5">Thông tin tài khoản NH</th>
                      <th className="px-4 py-3.5">Ngày thực hiện</th>
                      <th className="px-4 py-3.5">Trạng thái</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {withdrawals.map((w: any) => {
                      const periodDate = new Date(w.createdAt);
                      return (
                        <tr key={w._id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors">
                          <td className="px-4 py-3.5">
                            <div className="font-bold text-slate-900 dark:text-slate-100">{w.host?.username || '—'}</div>
                            <div className="text-[10px] text-slate-400">{w.host?.email || ''}</div>
                          </td>
                          <td className="px-4 py-3.5 font-black text-primary text-base">
                            {fmt(w.amount)}₫
                          </td>
                          <td className="px-4 py-3.5">
                            {w.bankInfo?.bankName ? (
                              <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-100 dark:border-slate-800 min-w-[160px] max-w-xs text-xs">
                                <div className="font-bold text-slate-800 dark:text-slate-200">{w.bankInfo.bankName}</div>
                                <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 mt-0.5 select-all">{w.bankInfo.accountNumber}</div>
                                <div className="text-[10px] text-slate-400 truncate mt-0.5 uppercase">{w.bankInfo.accountHolderName}</div>
                              </div>
                            ) : (
                              <span className="text-slate-300 dark:text-slate-700 italic">Không khả dụng</span>
                            )}
                          </td>
                          <td className="px-4 py-3.5 text-xs text-slate-600 dark:text-slate-400 font-medium">
                            {periodDate.toLocaleString('vi-VN')}
                          </td>
                          <td className="px-4 py-3.5">
                            <span className={cn(
                              'inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-extrabold',
                              w.status === 'completed'
                                ? 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/30'
                                : w.status === 'pending'
                                  ? 'bg-yellow-50 dark:bg-yellow-950/20 text-yellow-700 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-900/30'
                                  : 'bg-rose-50 dark:bg-rose-950/20 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-900/30'
                            )}>
                              {w.status === 'completed' ? 'Thành công (Trực tiếp)' : w.status === 'pending' ? 'Chờ duyệt' : 'Từ chối'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Pagination */}
          {withdrawalTotalPages > 1 && (
            <div className="flex items-center justify-center gap-4 mt-6">
              <button
                onClick={() => setWithdrawalPage(p => Math.max(1, p - 1))}
                disabled={withdrawalPage === 1}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors cursor-pointer"
              >
                <ChevronLeft className="h-4 w-4" /> Trước
              </button>
              <span className="text-xs text-slate-500 font-semibold">
                Trang <strong className="text-slate-800 dark:text-slate-200 font-black">{withdrawalPage}</strong> / {withdrawalTotalPages}
              </span>
              <button
                onClick={() => setWithdrawalPage(p => Math.min(withdrawalTotalPages, p + 1))}
                disabled={withdrawalPage === withdrawalTotalPages}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors cursor-pointer"
              >
                Sau <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* ===== TAB: BALANCES (Số dư ví Host) ===== */}
      {tab === 'balances' && (
        <div className="space-y-4">
          {/* Filters & Search */}
          <div className="flex flex-wrap gap-3 items-center justify-between p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <Input
                placeholder="Tìm tên host, email..."
                value={balancesSearch}
                onChange={(e) => {
                  setBalancesSearch(e.target.value);
                  setBalancesPage(1);
                }}
                className="pl-9 text-xs rounded-xl border-slate-200 dark:border-slate-800"
              />
            </div>

            <button
              onClick={fetchHostBalances}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Làm mới
            </button>
          </div>

          {/* List */}
          {balancesLoading ? (
            <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
            </div>
          ) : hostBalances.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl text-slate-400 text-center space-y-2">
              <Users className="h-12 w-12 text-slate-200 dark:text-slate-800" />
              <p className="text-sm font-semibold">Chưa có dữ liệu ví Host nào</p>
            </div>
          ) : (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-400 font-bold text-xs uppercase tracking-wider">
                      <th className="px-4 py-3.5">Host</th>
                      <th className="px-4 py-3.5">Số dư ví hiện tại</th>
                      <th className="px-4 py-3.5">Đang chờ rút</th>
                      <th className="px-4 py-3.5">Thông tin tài khoản NH</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {hostBalances.map((host: any) => {
                      return (
                        <tr key={host._id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors">
                          <td className="px-4 py-3.5">
                            <div className="font-bold text-slate-900 dark:text-slate-100">{host.name || host.user?.username || '—'}</div>
                            <div className="text-[10px] text-slate-400">{host.gmail || host.user?.email || ''}</div>
                          </td>
                          <td className="px-4 py-3.5 font-black text-emerald-600 text-base">
                            {fmt(host.walletBalance)}₫
                          </td>
                          <td className="px-4 py-3.5 font-semibold text-amber-500 text-xs">
                            {fmt(host.pendingWithdrawalAmount)}₫
                          </td>
                          <td className="px-4 py-3.5">
                            {host.bankInfo?.bankName ? (
                              <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-100 dark:border-slate-800 min-w-[160px] max-w-xs text-xs">
                                <div className="font-bold text-slate-800 dark:text-slate-200">{host.bankInfo.bankName}</div>
                                <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 mt-0.5 select-all">{host.bankInfo.accountNumber}</div>
                                <div className="text-[10px] text-slate-400 truncate mt-0.5 uppercase">{host.bankInfo.accountHolderName}</div>
                              </div>
                            ) : (
                              <span className="text-slate-300 dark:text-slate-700 italic">Chưa đăng ký</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Pagination */}
          {balancesTotalPages > 1 && (
            <div className="flex items-center justify-center gap-4 mt-6">
              <button
                onClick={() => setBalancesPage(p => Math.max(1, p - 1))}
                disabled={balancesPage === 1}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors cursor-pointer"
              >
                <ChevronLeft className="h-4 w-4" /> Trước
              </button>
              <span className="text-xs text-slate-500 font-semibold">
                Trang <strong className="text-slate-800 dark:text-slate-200 font-black">{balancesPage}</strong> / {balancesTotalPages}
              </span>
              <button
                onClick={() => setBalancesPage(p => Math.min(balancesTotalPages, p + 1))}
                disabled={balancesPage === balancesTotalPages}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors cursor-pointer"
              >
                Sau <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* ===== TAB: UNPAID ===== */}
      {tab === 'unpaid' && (
        <>
          {unpaidLoading ? (
            <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
            </div>
          ) : !unpaidData || unpaidData.groups.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl shadow-xs text-center space-y-2">
              <CheckCircle2 className="h-12 w-12 text-emerald-400 dark:text-emerald-600" />
              <p className="text-sm font-bold text-slate-700 dark:text-slate-300">Tất cả đã được thanh toán!</p>
              <p className="text-xs text-slate-400">Không có booking nào đang chờ tổng kết.</p>
            </div>
          ) : (
            <>
              {/* Summary */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                  { label: 'Số host chờ thanh toán', value: unpaidData.totalHosts, icon: Users, color: 'text-rose-600 dark:text-rose-400', bg: 'bg-rose-50 dark:bg-rose-950/40' },
                  { label: 'Tổng booking chưa kết', value: unpaidData.totalBookings, icon: ListCheck, color: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-950/40' },
                  { label: 'Tổng cần thanh toán', value: `${fmt(unpaidData.totalAmount * 0.95)}₫`, icon: Wallet, color: 'text-primary', bg: 'bg-primary/10 dark:bg-primary/20' },
                ].map(s => {
                  const Icon = s.icon;
                  return (
                    <div key={s.label} className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl p-4 flex items-center gap-4 shadow-xs">
                      <div className={cn('w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0', s.bg)}>
                        <Icon className={cn('h-5 w-5', s.color)} />
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">{s.label}</div>
                        <div className={cn('text-xl font-black mt-0.5', s.color)}>{s.value}</div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Host Groups */}
              <div className="space-y-3">
                {unpaidData.groups.map((group) => {
                  const isExpanded = expandedHost === group.hostId;
                  const hasBankInfo = !!(group.bankInfo?.bankName && group.bankInfo?.accountNumber);
                  return (
                    <div key={group.hostId} className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
                      {/* Host header row */}
                      <button
                        onClick={() => setExpandedHost(isExpanded ? null : group.hostId)}
                        className="w-full flex items-center justify-between p-5 hover:bg-slate-50/50 dark:hover:bg-slate-900/40 transition-colors cursor-pointer text-left"
                      >
                        <div className="flex items-center gap-4 min-w-0">
                          <div className="w-10 h-10 rounded-xl bg-primary/10 dark:bg-primary/20 flex items-center justify-center text-primary font-black text-sm flex-shrink-0">
                            {(group.host?.username || 'H').charAt(0).toUpperCase()}
                          </div>
                          <div className="min-w-0">
                            <div className="font-bold text-slate-900 dark:text-slate-100 text-sm">{group.host?.username || '—'}</div>
                            <div className="text-[11px] text-slate-400 truncate">{group.host?.email || ''}</div>
                          </div>
                        </div>

                        <div className="flex items-center gap-6 flex-shrink-0 ml-4">
                          <div className="text-right hidden sm:block">
                            <div className="text-[10px] text-slate-400 font-semibold">{group.bookingCount} booking</div>
                            <div className="text-xs text-slate-600 dark:text-slate-300">Gross: {fmt(group.grossAmount)}₫</div>
                          </div>
                          <div className="text-right">
                            <div className="text-[10px] text-slate-400 font-semibold">Cần chuyển</div>
                            <div className="text-base font-black text-primary">{fmt(group.netAmount)}₫</div>
                          </div>
                          {hasBankInfo ? (
                            <span title="Đã có thông tin ngân hàng"><CreditCard className="h-4 w-4 text-emerald-500 flex-shrink-0" /></span>
                          ) : (
                            <span title="Chưa có thông tin ngân hàng"><AlertTriangle className="h-4 w-4 text-amber-500 flex-shrink-0" /></span>
                          )}
                          {isExpanded ? <ChevronUp className="h-4 w-4 text-slate-400 flex-shrink-0" /> : <ChevronDown className="h-4 w-4 text-slate-400 flex-shrink-0" />}
                        </div>
                      </button>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="border-t border-slate-100 dark:border-slate-800 px-5 py-4 space-y-4">
                          {/* Bank info */}
                          <div className="flex flex-wrap gap-4">
                            <div className="flex-1 min-w-[200px] p-4 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <CreditCard className="h-3 w-3" /> Thông tin ngân hàng
                              </div>
                              {hasBankInfo ? (
                                <div className="space-y-1 text-xs">
                                  <div className="font-bold text-slate-800 dark:text-slate-200">{group.bankInfo.bankName}</div>
                                  <div className="font-mono text-slate-600 dark:text-slate-400 select-all text-sm">{group.bankInfo.accountNumber}</div>
                                  <div className="text-slate-500 uppercase tracking-wide">{group.bankInfo.accountHolderName}</div>
                                </div>
                              ) : (
                                <div className="text-xs text-amber-600 dark:text-amber-400 font-semibold flex items-center gap-1.5">
                                  <AlertTriangle className="h-3.5 w-3.5" /> Host chưa cung cấp thông tin ngân hàng
                                </div>
                              )}
                            </div>

                            <div className="flex-1 min-w-[200px] p-4 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
                              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">Tổng kết</div>
                              <div className="space-y-1.5 text-xs">
                                <div className="flex justify-between">
                                  <span className="text-slate-500">Doanh thu Gross:</span>
                                  <span className="font-bold text-slate-800 dark:text-slate-200">{fmt(group.grossAmount)}₫</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-slate-500">Phí platform (5%):</span>
                                  <span className="font-bold text-rose-600">-{fmt(group.platformFee)}₫</span>
                                </div>
                                <div className="flex justify-between border-t border-slate-200 dark:border-slate-700 pt-1.5 mt-1">
                                  <span className="text-slate-700 dark:text-slate-300 font-bold">Số tiền cần chuyển:</span>
                                  <span className="font-black text-primary text-sm">{fmt(group.netAmount)}₫</span>
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Booking table */}
                          <div>
                            <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                              <Building2 className="h-3 w-3" /> Danh sách booking ({group.bookingCount})
                            </div>
                            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                              <table className="w-full text-xs text-left">
                                <thead>
                                  <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-400 font-bold uppercase tracking-wider">
                                    <th className="px-4 py-2.5">Mã booking</th>
                                    <th className="px-4 py-2.5">Property / Site</th>
                                    <th className="px-4 py-2.5">Check-in</th>
                                    <th className="px-4 py-2.5">Check-out</th>
                                    <th className="px-4 py-2.5">Đêm</th>
                                    <th className="px-4 py-2.5 text-right">Tổng tiền</th>
                                    <th className="px-4 py-2.5 text-center">Khách đến</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                                  {group.bookings.map((b: any) => (
                                    <tr key={b._id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors">
                                      <td className="px-4 py-2.5 font-mono text-slate-600 dark:text-slate-400">{b.code || b._id?.toString().slice(-8)}</td>
                                      <td className="px-4 py-2.5">
                                        <div className="font-semibold text-slate-800 dark:text-slate-200">{b.property?.name || '—'}</div>
                                        <div className="text-[10px] text-slate-400">{b.site?.name || ''}</div>
                                      </td>
                                      <td className="px-4 py-2.5 text-slate-600 dark:text-slate-400">{new Date(b.checkIn).toLocaleDateString('vi-VN')}</td>
                                      <td className="px-4 py-2.5 text-slate-600 dark:text-slate-400">{new Date(b.checkOut).toLocaleDateString('vi-VN')}</td>
                                      <td className="px-4 py-2.5 text-center text-slate-700 dark:text-slate-300">{b.nights}</td>
                                      <td className="px-4 py-2.5 text-right font-bold text-slate-800 dark:text-slate-200">{fmt(b.total)}₫</td>
                                      <td className="px-4 py-2.5 text-center">
                                        {b.hostConfirmedAttendance ? (
                                          <span className="text-emerald-600 dark:text-emerald-400 text-[10px] font-bold">✓ Có</span>
                                        ) : (
                                          <span className="text-slate-400 text-[10px]">—</span>
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Run payout button */}
              <div className="flex justify-center pt-2">
                <button
                  onClick={runMonthlyPayout}
                  disabled={running}
                  className="flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-extrabold text-white bg-primary hover:bg-primary/95 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Play className="h-4 w-4 fill-white" />
                  {running ? 'Đang tổng kết...' : `Tạo payout cho ${unpaidData.totalHosts} host`}
                </button>
              </div>
            </>
          )}
        </>
      )}

      {/* ===== TAB: HISTORY ===== */}
      {tab === 'history' && (
        <>
          {/* Stats Cards */}
          {statCards.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {statCards.map(s => {
                const Icon = s.icon;
                return (
                  <div key={s.label} className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl p-4 flex items-center gap-4 shadow-xs transition-all hover:-translate-y-0.5 hover:shadow-md">
                    <div className={cn('w-11 h-11 rounded-xl flex items-center justify-center shadow-inner', s.bg)}>
                      <Icon className={cn('h-5.5 w-5.5', s.color)} />
                    </div>
                    <div>
                      <div className="text-xs text-slate-400 font-semibold">{s.label}</div>
                      <div className={cn('text-lg font-black mt-0.5', s.color)}>{s.value}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Filter */}
          <div className="flex items-center gap-3 p-4 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl shadow-xs">
            <select
              value={statusFilter}
              onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
              className="px-3 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-700 dark:text-slate-300"
            >
              <option value="">Tất cả trạng thái</option>
              {Object.entries(STATUS_MAP).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
            <button
              onClick={fetchHistory}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Làm mới
            </button>
          </div>

          {/* Table */}
          {historyLoading ? (
            <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
            </div>
          ) : payouts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl shadow-xs text-slate-400 text-center space-y-2">
              <DollarSign className="h-12 w-12 text-slate-200 dark:text-slate-800" />
              <p className="text-sm font-semibold">Chưa có payout nào</p>
              <p className="text-xs text-slate-400">Nhấn &quot;Chạy tổng kết&quot; ở góc trên để tạo bản ghi thanh toán.</p>
            </div>
          ) : (
            <div className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950 text-slate-400 font-bold text-xs uppercase tracking-wider">
                      <th className="px-4 py-3.5">Host</th>
                      <th className="px-4 py-3.5">Kỳ hạn</th>
                      <th className="px-4 py-3.5 text-center">Booking</th>
                      <th className="px-4 py-3.5">Gross</th>
                      <th className="px-4 py-3.5">Phí (5%)</th>
                      <th className="px-4 py-3.5">Thực nhận</th>
                      <th className="px-4 py-3.5">Tài khoản NH</th>
                      <th className="px-4 py-3.5">Trạng thái</th>
                      <th className="px-4 py-3.5 text-right">Thao tác</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {payouts.map((p: any) => {
                      const st = STATUS_MAP[p.status] ?? { label: p.status, class: 'bg-slate-100 text-slate-700' };
                      const periodDate = new Date(p.periodStart);
                      return (
                        <tr key={p._id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors">
                          <td className="px-4 py-3.5">
                            <div className="font-bold text-slate-900 dark:text-slate-100">{p.host?.username || '—'}</div>
                            <div className="text-[10px] text-slate-400">{p.host?.email || ''}</div>
                          </td>
                          <td className="px-4 py-3.5 text-xs font-bold text-slate-700 dark:text-slate-300">
                            Tháng {periodDate.getMonth() + 1}/{periodDate.getFullYear()}
                          </td>
                          <td className="px-4 py-3.5 text-center font-bold text-slate-700 dark:text-slate-300">
                            {p.bookings?.length || 0}
                          </td>
                          <td className="px-4 py-3.5 font-semibold text-slate-700 dark:text-slate-300">{fmt(p.grossAmount)}₫</td>
                          <td className="px-4 py-3.5 text-xs text-rose-600 dark:text-rose-400 font-medium">-{fmt(p.platformFee)}₫</td>
                          <td className="px-4 py-3.5 font-black text-primary">{fmt(p.netAmount)}₫</td>
                          <td className="px-4 py-3.5 text-xs text-slate-600 dark:text-slate-400">
                            {p.bankInfo?.bankName ? (
                              <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-900 border border-slate-100 dark:border-slate-800 min-w-[140px]">
                                <div className="font-bold text-slate-800 dark:text-slate-200">{p.bankInfo.bankName}</div>
                                <div className="font-mono text-[10px] text-slate-500 mt-0.5 select-all">{p.bankInfo.accountNumber}</div>
                                <div className="text-[10px] text-slate-400 truncate mt-0.5 uppercase">{p.bankInfo.accountHolderName}</div>
                              </div>
                            ) : (
                              <span className="text-slate-300 dark:text-slate-700 italic">Chưa cung cấp</span>
                            )}
                          </td>
                          <td className="px-4 py-3.5">
                            <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-extrabold', st.class)}>
                              {st.label}
                            </span>
                            {p.paidAt && (
                              <div className="text-[10px] text-slate-400 mt-1">{fmtDate(p.paidAt)}</div>
                            )}
                          </td>
                          <td className="px-4 py-3.5 text-right">
                            {p.status === 'pending' && (
                              <button
                                onClick={() => setConfirmId(p._id)}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-primary/20 bg-primary/10 text-primary hover:bg-primary/20 text-xs font-bold cursor-pointer transition-colors"
                              >
                                <CheckCircle2 className="h-3.5 w-3.5" /> Đã chuyển
                              </button>
                            )}
                            {p.status === 'completed' && (
                              <div className="flex justify-end">
                                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-4 mt-6">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors cursor-pointer"
              >
                <ChevronLeft className="h-4 w-4" /> Trước
              </button>
              <span className="text-xs text-slate-500 font-semibold">
                Trang <strong className="text-slate-800 dark:text-slate-200 font-black">{page}</strong> / {totalPages}
              </span>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-600 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 transition-colors cursor-pointer"
              >
                Sau <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </>
      )}

      {/* Confirm Modal */}
      {confirmId && (
        <div
          className="fixed inset-0 bg-slate-950/50 backdrop-blur-xs z-100 flex items-center justify-center p-4"
          onClick={e => e.target === e.currentTarget && setConfirmId(null)}
        >
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-2xl w-full max-w-md">
            <h3 className="text-md font-extrabold text-slate-900 dark:text-white flex items-center gap-2 mb-2">
              ✅ Xác nhận chuyển tiền
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              Xác nhận rằng bạn đã thực hiện chuyển tiền thành công qua ngân hàng đến tài khoản của Host.
            </p>
            <textarea
              value={confirmNote}
              onChange={e => setConfirmNote(e.target.value)}
              placeholder="Nhập mã giao dịch ngân hàng, ghi chú (tùy chọn)..."
              rows={3}
              className="w-full px-3 py-2 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none dark:text-slate-200"
            />
            <div className="flex gap-2.5 justify-end mt-5">
              <button
                onClick={() => { setConfirmId(null); setConfirmNote(''); }}
                className="px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-50 cursor-pointer"
              >
                Đóng
              </button>
              <button
                onClick={markCompleted}
                disabled={acting}
                className="px-4 py-2 rounded-xl text-xs font-extrabold text-white bg-primary hover:bg-primary/95 shadow-md cursor-pointer disabled:opacity-50"
              >
                {acting ? 'Đang xử lý...' : 'Xác nhận đã chuyển'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
