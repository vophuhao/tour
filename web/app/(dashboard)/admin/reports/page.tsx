'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback } from 'react';
import { getReports, updateReport } from '@/lib/reportApi';
import { toast } from 'sonner';
import {
  RefreshCw, ChevronLeft, ChevronRight,
  ExternalLink, CheckCircle2, XCircle, EyeOff, AlertTriangle, Flag, Info
} from 'lucide-react';
import Link from 'next/link';
import { cn } from '@/lib/utils';

const STATUS_TABS = [
  { value: '', label: 'Tất cả' },
  { value: 'pending', label: 'Chờ xử lý' },
  { value: 'reviewed', label: 'Đang xem xét' },
  { value: 'resolved', label: 'Đã xử lý' },
  { value: 'dismissed', label: 'Đã từ chối' },
];

const TYPE_OPTIONS = [
  { value: '', label: 'Tất cả loại' },
  { value: 'post', label: 'Bài viết diễn đàn' },
  { value: 'free-spot', label: 'Địa điểm chia sẻ' },
];

const REASON_LABELS: Record<string, string> = {
  spam: 'Spam',
  inappropriate_content: 'Nội dung không phù hợp',
  harassment: 'Quấy rối',
  fake_information: 'Thông tin sai lệch',
  copyright_violation: 'Vi phạm bản quyền',
  other: 'Lý do khác',
};

const STATUS_BADGE: Record<string, { label: string; class: string }> = {
  pending: { label: 'Chờ xử lý', class: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' },
  reviewed: { label: 'Đang xem xét', class: 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/20' },
  resolved: { label: 'Đã xử lý', class: 'bg-primary/10 text-primary border-primary/20' },
  dismissed: { label: 'Từ chối', class: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20' },
};

export default function AdminReportsPage() {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [typeFilter, setTypeFilter] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [noteModal, setNoteModal] = useState(false);
  const [resolveNote, setResolveNote] = useState('');
  const [pendingAction, setPendingAction] = useState<{ reportId: string; status: string; action?: string } | null>(null);

  const fetchReports = useCallback(async () => {
    setLoading(true);
    try {
      const res: any = await getReports({
        page,
        limit: 15,
        status: statusFilter || undefined,
        targetType: typeFilter || undefined
      });
      setReports(res?.data?.data ?? res?.data ?? []);
      setTotalPages(res?.data?.pagination?.totalPages ?? 1);
      setTotal(res?.data?.pagination?.total ?? 0);
    } catch {
      toast.error('Không thể tải danh sách báo cáo');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, typeFilter]);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  const openNoteModal = (reportId: string, status: string, action?: string) => {
    setPendingAction({ reportId, status, action });
    setResolveNote('');
    setNoteModal(true);
  };

  const handleConfirmAction = async () => {
    if (!pendingAction) return;
    setActionLoading(pendingAction.reportId);
    try {
      await updateReport(pendingAction.reportId, {
        status: pendingAction.status,
        resolveNote: resolveNote.trim() || undefined,
        action: pendingAction.action as any,
      });
      toast.success('Đã xử lý báo cáo thành công');
      setNoteModal(false);
      fetchReports();
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi xử lý');
    } finally {
      setActionLoading(null);
      setPendingAction(null);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">Xử lý báo cáo vi phạm</h1>

        </div>
      </div>

      {/* Status Tabs */}
      <div className="flex gap-2 border-b border-slate-200 dark:border-slate-800/80">
        {STATUS_TABS.map((tab) => {
          const isActive = statusFilter === tab.value;
          return (
            <button
              key={tab.value}
              onClick={() => { setStatusFilter(tab.value); setPage(1); }}
              className={cn(
                'px-4 py-2.5 text-xs font-extrabold transition-all border-b-2 rounded-t-lg -mb-[2px] cursor-pointer',
                isActive
                  ? 'border-primary text-primary bg-primary/5 dark:bg-primary/5'
                  : 'border-transparent text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
              )}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Filter Action Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-4 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-850 rounded-2xl shadow-xs">
        <div className="flex flex-wrap items-center gap-3 flex-1">
          {/* Type dropdown select */}
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 focus:ring-2 focus:ring-primary/20 focus:outline-none text-slate-650 dark:text-slate-350 cursor-pointer"
          >
            {TYPE_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>

          {/* Refresh Button */}
          <button
            onClick={fetchReports}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 text-xs font-bold text-slate-650 dark:text-slate-350 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Làm mới
          </button>
        </div>

        <div className="text-xs text-slate-400 font-semibold">
          Tổng số báo cáo: <strong className="text-slate-700 dark:text-slate-200 font-extrabold">{total}</strong>
        </div>
      </div>

      {/* Table Data View */}
      {loading ? (
        <div className="flex items-center justify-center py-24 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-855 rounded-2xl">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
        </div>
      ) : reports.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-855 rounded-2xl shadow-xs text-slate-400">
          <Flag className="h-12 w-12 text-slate-200 dark:text-slate-800 mb-3" />
          <p className="text-sm font-semibold">Không tìm thấy báo cáo nào</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-855 rounded-2xl shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-805 bg-slate-50/50 dark:bg-slate-950 text-slate-400 font-bold text-xs uppercase tracking-wider">
                  <th className="px-5 py-3.5 font-bold">Nội dung bị báo cáo</th>
                  <th className="px-5 py-3.5 font-bold">Loại</th>
                  <th className="px-5 py-3.5 font-bold">Lý do</th>
                  <th className="px-5 py-3.5 font-bold">Người báo cáo</th>
                  <th className="px-5 py-3.5 font-bold">Trạng thái</th>
                  <th className="px-5 py-3.5 font-bold">Ngày gửi</th>
                  <th className="px-5 py-3.5 font-bold text-right">Thao tác</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {reports.map((report) => {
                  const badge = STATUS_BADGE[report.status] ?? STATUS_BADGE.pending;
                  const target = report.target;
                  return (
                    <tr
                      key={report._id}
                      className="hover:bg-slate-50/50 dark:hover:bg-slate-900/20 transition-colors cursor-pointer"
                      onClick={() => setSelectedReport(selectedReport?._id === report._id ? null : report)}
                    >
                      {/* Reported target content description */}
                      <td className="px-5 py-3.5 max-w-[240px]">
                        <div className="font-bold text-slate-900 dark:text-slate-100 truncate">
                          {target?.title ?? report.targetId}
                        </div>
                        {report.description && (
                          <div className="text-[10px] text-slate-400 mt-1 truncate max-w-[220px]" title={report.description}>
                            "{report.description}"
                          </div>
                        )}
                      </td>

                      {/* Type Badge */}
                      <td className="px-5 py-3.5">
                        <span className={cn(
                          'inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-extrabold border uppercase tracking-wider',
                          report.targetType === 'post'
                            ? 'bg-primary/10 text-primary border-primary/20'
                            : 'bg-emerald-500/10 text-emerald-650 dark:text-emerald-400 border-emerald-500/20'
                        )}>
                          {report.targetType === 'post' ? '📝 Bài viết' : '🏕️ Địa điểm'}
                        </span>
                      </td>

                      {/* Reason */}
                      <td className="px-5 py-3.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
                        {REASON_LABELS[report.reason] ?? report.reason}
                      </td>

                      {/* Reporter */}
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2">
                          {report.reporterId?.avatarUrl ? (
                            <img
                              src={report.reporterId.avatarUrl}
                              alt=""
                              className="h-6 w-6 rounded-full object-cover ring-1 ring-slate-200 dark:ring-slate-800"
                            />
                          ) : (
                            <div className="h-6 w-6 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-[10px] font-bold text-slate-500 dark:text-slate-400">
                              {report.reporterId?.username?.charAt(0).toUpperCase() || '—'}
                            </div>
                          )}
                          <span className="text-xs font-bold text-slate-800 dark:text-slate-205">
                            {report.reporterId?.username ?? '—'}
                          </span>
                        </div>
                      </td>

                      {/* Status Badge */}
                      <td className="px-5 py-3.5">
                        <span className={cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-extrabold border uppercase tracking-wider', badge.class)}>
                          {badge.label}
                        </span>
                      </td>

                      {/* Created Date */}
                      <td className="px-5 py-3.5 text-xs text-slate-400 font-semibold">
                        {new Date(report.createdAt).toLocaleDateString('vi-VN')}
                      </td>

                      {/* Action buttons */}
                      <td className="px-5 py-3.5 text-right" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-2 flex-wrap">
                          {target?.slug && (
                            <Link
                              href={report.targetType === 'post' ? `/forum/${target.slug}` : `/free-spots/${report.targetId}`}
                              target="_blank"
                              className="inline-flex items-center justify-center p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500 hover:text-slate-800 dark:hover:text-slate-100 transition-colors shadow-xs"
                              title="Xem chi tiết"
                            >
                              <ExternalLink className="h-3.5 w-3.5" />
                            </Link>
                          )}
                          {report.status === 'pending' && (
                            <>
                              <button
                                onClick={() => openNoteModal(report._id, 'resolved', 'hide_target')}
                                disabled={!!actionLoading}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-rose-200 bg-rose-50 hover:bg-rose-100 text-rose-600 dark:text-rose-400 dark:border-rose-900/50 dark:bg-rose-950/20 dark:hover:bg-rose-950/40 text-[10px] font-extrabold uppercase transition-colors cursor-pointer"
                                title="Ẩn nội dung bị báo cáo"
                              >
                                <EyeOff className="h-3 w-3" /> Ẩn đi
                              </button>
                              <button
                                onClick={() => openNoteModal(report._id, 'dismissed', 'none')}
                                disabled={!!actionLoading}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-600 dark:text-slate-350 dark:border-slate-800 dark:bg-slate-900 dark:hover:bg-slate-800/80 text-[10px] font-extrabold uppercase transition-colors cursor-pointer"
                                title="Từ chối báo cáo này"
                              >
                                <XCircle className="h-3 w-3" /> Bỏ qua
                              </button>
                              <button
                                onClick={() => openNoteModal(report._id, 'resolved', 'none')}
                                disabled={!!actionLoading}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-primary/30 bg-primary/5 hover:bg-primary/10 text-primary dark:border-primary/30 dark:bg-primary/5 dark:hover:bg-primary/10 text-[10px] font-extrabold uppercase transition-colors cursor-pointer"
                                title="Phê duyệt không ẩn nội dung"
                              >
                                <CheckCircle2 className="h-3 w-3" /> Giải quyết
                              </button>
                            </>
                          )}
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

      {/* Pagination controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-4 mt-6">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-650 dark:text-slate-350 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <ChevronLeft className="h-4 w-4" /> Trước
          </button>
          <span className="text-xs text-slate-500 font-semibold">
            Trang <strong className="text-slate-800 dark:text-slate-200 font-black">{page}</strong> / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold text-slate-650 dark:text-slate-350 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            Sau <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Note modal */}
      {noteModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-xs p-4 animate-fade-in"
          onClick={e => e.target === e.currentTarget && setNoteModal(false)}
        >
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className={cn(
                "w-10 h-10 rounded-xl flex items-center justify-center shadow-inner",
                pendingAction?.action === 'hide_target'
                  ? "bg-rose-50 dark:bg-rose-950 text-rose-650 dark:text-rose-455"
                  : pendingAction?.status === 'dismissed'
                    ? "bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400"
                    : "bg-primary/10 dark:bg-primary/20 text-primary dark:text-primary"
              )}>
                {pendingAction?.action === 'hide_target' ? <AlertTriangle className="h-5 w-5" /> : <Info className="h-5 w-5" />}
              </div>
              <h3 className="text-md font-black text-slate-850 dark:text-slate-100">
                {pendingAction?.action === 'hide_target'
                  ? '🚫 Phê duyệt & Ẩn nội dung'
                  : pendingAction?.status === 'dismissed'
                    ? '✅ Từ chối báo cáo'
                    : '✅ Đánh dấu đã giải quyết'}
              </h3>
            </div>

            {pendingAction?.action === 'hide_target' && (
              <div className="p-3.5 rounded-xl bg-rose-50 dark:bg-rose-950/30 border border-rose-100 dark:border-rose-900/40 text-xs text-rose-600 dark:text-rose-455 font-semibold leading-relaxed">
                ⚠️ Hành động này sẽ ẩn vĩnh viễn nội dung bị báo cáo khỏi tất cả người dùng hệ thống.
              </div>
            )}

            <div className="space-y-1.5">
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider">Ghi chú xử lý (tùy chọn)</label>
              <textarea
                value={resolveNote}
                onChange={e => setResolveNote(e.target.value)}
                placeholder="Nhập lý do hoặc thông tin phản hồi bổ sung..."
                rows={3}
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-250 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-700 dark:text-slate-205 focus:ring-2 focus:ring-primary/20 focus:outline-none resize-none"
              />
            </div>

            <div className="flex justify-end gap-2.5 pt-2">
              <button
                onClick={() => setNoteModal(false)}
                className="rounded-xl border border-slate-250 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 py-2 text-xs font-bold text-slate-650 dark:text-slate-350 hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors cursor-pointer"
              >
                Hủy bỏ
              </button>
              <button
                onClick={handleConfirmAction}
                disabled={!!actionLoading}
                className={cn(
                  "rounded-xl px-4 py-2 text-xs font-bold text-white transition-colors cursor-pointer shadow-xs",
                  pendingAction?.action === 'hide_target'
                    ? "bg-rose-600 hover:bg-rose-700 dark:bg-rose-500 dark:hover:bg-rose-600"
                    : pendingAction?.status === 'dismissed'
                      ? "bg-slate-600 hover:bg-slate-700 dark:bg-slate-500 dark:hover:bg-slate-600"
                      : "bg-primary hover:bg-primary/90"
                )}
              >
                {actionLoading ? 'Đang xử lý...' : 'Xác nhận'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
