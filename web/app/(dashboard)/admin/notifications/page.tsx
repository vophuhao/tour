'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback } from 'react';
import API from '@/lib/api-client';
import { toast } from 'sonner';
import {
  Send, Bell, Users, Trash2, Search, RefreshCw,
  CheckCircle2, ChevronLeft, ChevronRight, X,
  Clock, ExternalLink, AlertCircle, Check, History
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AdminNotifications } from '@/components/admin/AdminNotifications';

const PRIORITY_OPTIONS = [
  { value: 'low', label: 'Thấp', color: 'text-slate-500 border-slate-200 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800', activeClass: 'border-slate-500 bg-slate-50 text-slate-800 dark:bg-slate-800 dark:text-slate-200 font-bold' },
  { value: 'medium', label: 'Trung bình', color: 'text-amber-600 border-slate-200 hover:bg-amber-50/30 dark:border-slate-800 dark:hover:bg-amber-950/20', activeClass: 'border-amber-500 bg-amber-50 text-amber-700 dark:bg-amber-950/30 dark:text-amber-500 font-bold' },
  { value: 'high', label: 'Cao', color: 'text-red-600 border-slate-200 hover:bg-red-50/30 dark:border-slate-800 dark:hover:bg-red-950/20', activeClass: 'border-red-500 bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-500 font-bold' },
];

// ── Compose Form ──────────────────────────────────────────────────────────────

function ComposeTab() {
  const [hosts, setHosts] = useState<any[]>([]);
  const [hostsLoading, setHostsLoading] = useState(true);
  const [hostSearch, setHostSearch] = useState('');
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [sendToAll, setSendToAll] = useState(true);
  const [form, setForm] = useState({ title: '', message: '', link: '', priority: 'medium' });
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState<{ sent: number; recipientCount: number } | null>(null);

  const fetchHosts = useCallback(async (search = '') => {
    setHostsLoading(true);
    try {
      const res: any = await API.get('/notifications/admin/hosts', { params: { search } });
      setHosts(res?.data?.data ?? res?.data ?? []);
    } catch {
      toast.error('Không thể tải danh sách host');
    } finally {
      setHostsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHosts();
  }, [fetchHosts]);

  const toggleHost = (hostId: string) => {
    setSelectedHosts(prev =>
      prev.includes(hostId) ? prev.filter(id => id !== hostId) : [...prev, hostId]
    );
  };

  const handleSend = async () => {
    if (!form.title.trim() || !form.message.trim()) {
      toast.error('Tiêu đề và nội dung là bắt buộc');
      return;
    }
    if (!sendToAll && selectedHosts.length === 0) {
      toast.error('Vui lòng chọn ít nhất 1 host');
      return;
    }

    setSending(true);
    try {
      const res: any = await API.post('/notifications/admin/send-bulk', {
        recipientIds: sendToAll ? [] : selectedHosts,
        title: form.title,
        message: form.message,
        link: form.link || undefined,
        priority: form.priority,
      });
      const data = res?.data?.data ?? res?.data;
      setResult(data);
      toast.success(`Đã gửi thành công đến ${data?.sent ?? '?'} host!`);
      setForm({ title: '', message: '', link: '', priority: 'medium' });
      setSelectedHosts([]);
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi gửi thông báo');
    } finally {
      setSending(false);
    }
  };

  const filteredHosts = hosts.filter(h =>
    h.username?.toLowerCase().includes(hostSearch.toLowerCase()) ||
    h.email?.toLowerCase().includes(hostSearch.toLowerCase())
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
      {/* Left: Compose Form */}
      <div className="lg:col-span-2 bg-white dark:bg-slate-900 rounded-2xl border border-slate-100 dark:border-slate-800 shadow-sm p-6">
        <h2 className="text-lg font-bold text-slate-800 dark:text-slate-100 mb-5 flex items-center gap-2">
          <span>✍️</span> Soạn thông báo mới
        </h2>

        {result && (
          <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/50 mb-5 flex items-center gap-3">
            <CheckCircle2 size={18} className="text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
            <div className="flex-1">
              <div className="font-semibold text-emerald-800 dark:text-emerald-400 text-sm">Gửi thành công!</div>
              <div className="text-xs text-emerald-600 dark:text-emerald-500">Đã gửi đến <strong>{result.sent}</strong> host</div>
            </div>
            <button onClick={() => setResult(null)} className="text-emerald-600 hover:text-emerald-800 dark:text-emerald-400 dark:hover:text-emerald-300">
              <X size={16} />
            </button>
          </div>
        )}

        <div className="space-y-4">
          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 block mb-1.5">
              Tiêu đề <span className="text-red-500">*</span>
            </label>
            <input
              value={form.title}
              onChange={e => setForm(p => ({ ...p, title: e.target.value }))}
              placeholder="Nhập tiêu đề thông báo..."
              maxLength={100}
              className="w-full px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
            />
            <div className="text-[11px] text-slate-400 dark:text-slate-500 text-right mt-1">{form.title.length}/100</div>
          </div>

          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 block mb-1.5">
              Nội dung <span className="text-red-500">*</span>
            </label>
            <textarea
              value={form.message}
              onChange={e => setForm(p => ({ ...p, message: e.target.value }))}
              placeholder="Nhập nội dung thông báo chi tiết..."
              rows={4}
              maxLength={500}
              className="w-full px-4 py-2.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-955 text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all resize-none"
            />
            <div className="text-[11px] text-slate-400 dark:text-slate-500 text-right mt-1">{form.message.length}/500</div>
          </div>

          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 block mb-1.5">
              Link đi kèm (tùy chọn)
            </label>
            <div className="relative">
              <ExternalLink size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                value={form.link}
                onChange={e => setForm(p => ({ ...p, link: e.target.value }))}
                placeholder="Ví dụ: /host/properties hoặc URL khác..."
                className="w-full pl-9 pr-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-sm focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
              />
            </div>
          </div>

          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 block mb-2">Mức độ ưu tiên</label>
            <div className="grid grid-cols-3 gap-2">
              {PRIORITY_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setForm(p => ({ ...p, priority: opt.value }))}
                  className={`py-2 rounded-xl border text-xs font-semibold transition-all ${
                    form.priority === opt.value
                      ? opt.activeClass
                      : `${opt.color} bg-white dark:bg-slate-900`
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={handleSend}
            disabled={sending || !form.title.trim() || !form.message.trim()}
            className={`w-full py-2.5 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all mt-6 shadow-sm ${
              sending || !form.title.trim() || !form.message.trim()
                ? 'bg-slate-300 dark:bg-slate-800 text-slate-500 cursor-not-allowed'
                : 'bg-primary hover:bg-primary/90 active:scale-[0.98]'
            }`}
          >
            {sending ? (
              <RefreshCw size={16} className="animate-spin" />
            ) : (
              <Send size={15} />
            )}
            {sending ? 'Đang gửi...' : `Gửi thông báo${sendToAll ? ' đến tất cả host' : ` (${selectedHosts.length} host được chọn)`}`}
          </button>
        </div>
      </div>

      {/* Right: Recipient Picker */}
      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-100 dark:border-slate-800 shadow-sm p-5">
        <h3 className="text-base font-bold text-slate-800 dark:text-slate-100 mb-4">Người nhận thông báo</h3>

        <div className="space-y-4">
          <label className={`flex items-center gap-3 p-3.5 rounded-xl border-2 cursor-pointer transition-all ${
            sendToAll
              ? 'border-primary bg-primary/5 dark:bg-primary/5'
              : 'border-slate-200 dark:border-slate-800 hover:border-slate-300'
          }`}>
            <input
              type="checkbox"
              checked={sendToAll}
              onChange={e => { setSendToAll(e.target.checked); setSelectedHosts([]); }}
              className="w-4 h-4 text-primary rounded focus:ring-primary cursor-pointer"
            />
            <div className="flex-1">
              <div className={`font-bold text-sm ${sendToAll ? 'text-primary' : 'text-slate-700 dark:text-slate-300'}`}>Tất cả host</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500">{hosts.length} host đang hoạt động</div>
            </div>
            {sendToAll && <Check size={16} className="text-primary ml-auto" />}
          </label>

          {!sendToAll && (
            <div className="space-y-3">
              <div className="relative">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  value={hostSearch}
                  onChange={e => setHostSearch(e.target.value)}
                  placeholder="Tìm kiếm host..."
                  className="w-full pl-9 pr-4 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-955 text-xs focus:outline-none focus:ring-1 focus:ring-primary transition-all"
                />
              </div>

              {selectedHosts.length > 0 && (
                <div className="flex items-center justify-between p-2 px-3 rounded-lg bg-primary/10 dark:bg-primary/20 text-xs text-primary font-semibold">
                  <span>Đã chọn: {selectedHosts.length} host</span>
                  <button onClick={() => setSelectedHosts([])} className="text-[10px] text-slate-500 hover:text-red-500 dark:hover:text-red-400 transition-all">
                    Bỏ chọn tất cả
                  </button>
                </div>
              )}

              <div className="max-h-[350px] overflow-y-auto space-y-1.5 pr-1 divide-y divide-slate-50 dark:divide-slate-800/50">
                {hostsLoading ? (
                  <div className="py-8 text-center text-xs text-slate-400">Đang tải danh sách...</div>
                ) : filteredHosts.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-400">Không tìm thấy host nào</div>
                ) : (
                  filteredHosts.map(host => {
                    const selected = selectedHosts.includes(host._id);
                    return (
                      <label
                        key={host._id}
                        className={`flex items-center gap-3 p-2.5 rounded-lg cursor-pointer transition-all hover:bg-slate-50 dark:hover:bg-slate-800/40 ${
                          selected ? 'bg-primary/5 dark:bg-primary/5 border-l-2 border-primary pl-2' : ''
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={() => toggleHost(host._id)}
                          className="w-3.5 h-3.5 text-primary rounded focus:ring-primary cursor-pointer"
                        />
                        {host.avatarUrl ? (
                          <img src={host.avatarUrl} alt="" className="w-8 h-8 rounded-full object-cover border border-slate-100 dark:border-slate-800" />
                        ) : (
                          <div className="w-8 h-8 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-xs font-bold text-slate-600 dark:text-slate-300">
                            {host.username?.charAt(0).toUpperCase()}
                          </div>
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-bold text-slate-700 dark:text-slate-300 truncate">{host.username}</div>
                          <div className="text-[10px] text-slate-400 truncate">{host.email}</div>
                        </div>
                        {host.isVerified && <CheckCircle2 size={13} className="text-emerald-500 ml-auto flex-shrink-0" />}
                      </label>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Sent History Tab ─────────────────────────────────────────────────────────

function SentHistoryTab() {
  const [notifications, setNotifications] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<any>(null);

  const fetchSent = useCallback(async () => {
    setLoading(true);
    try {
      const res: any = await API.get('/notifications/admin/sent', { params: { page, limit: 15 } });
      const d = res?.data?.data ?? res?.data;
      setNotifications(d?.notifications ?? d ?? []);
      setTotalPages(d?.totalPages ?? 1);
      setTotal(d?.total ?? 0);
    } catch {
      toast.error('Không thể tải lịch sử thông báo');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchSent();
  }, [fetchSent]);

  const handleDeleteOne = async (notificationId: string) => {
    setDeletingId(notificationId);
    try {
      await API.delete(`/notifications/admin/sent/${notificationId}`);
      toast.success('Đã xóa thông báo');
      fetchSent();
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi xóa');
    } finally {
      setDeletingId(null);
      setConfirmDelete(null);
    }
  };

  const handleDeleteBroadcast = async (title: string, createdAt: string) => {
    setDeletingId('bulk');
    try {
      await API.delete('/notifications/admin/broadcast', { data: { title, createdAt } });
      toast.success('Đã xóa toàn bộ thông báo broadcast này');
      fetchSent();
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi xóa');
    } finally {
      setDeletingId(null);
      setConfirmDelete(null);
    }
  };

  const PRIORITY_BADGE: Record<string, { label: string; color: string }> = {
    low: { label: 'Thấp', color: 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800/80 dark:text-slate-400 dark:border-slate-800' },
    medium: { label: 'Trung bình', color: 'bg-primary/10 text-primary border-primary/20' },
    high: { label: 'Cao', color: 'bg-red-50 text-red-600 border-red-100 dark:bg-red-950/20 dark:text-red-400 dark:border-red-900/30' },
  };

  return (
    <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-100 dark:border-slate-800 shadow-sm p-6">
      <div className="flex items-center justify-between mb-6 flex-wrap gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-800 dark:text-slate-100">Lịch sử thông báo đã gửi</h2>
          <p className="text-xs text-slate-400 mt-1">Tổng cộng {total} thông báo đã được gửi đi</p>
        </div>
        <button
          onClick={fetchSent}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-semibold hover:bg-slate-50 dark:hover:bg-slate-800 transition-all shadow-sm"
        >
          <RefreshCw size={12} /> Làm mới
        </button>
      </div>

      {loading ? (
        <div className="py-16 text-center text-slate-400 dark:text-slate-500">
          <RefreshCw size={24} className="animate-spin mx-auto mb-3" />
          <p className="text-xs">Đang tải lịch sử thông báo...</p>
        </div>
      ) : notifications.length === 0 ? (
        <div className="py-16 text-center border-2 border-dashed border-slate-100 dark:border-slate-800 rounded-xl max-w-md mx-auto">
          <Bell size={36} className="text-slate-300 dark:text-slate-700 mx-auto mb-3" />
          <h4 className="font-bold text-sm text-slate-700 dark:text-slate-300">Chưa gửi thông báo nào</h4>
          <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">Hãy soạn và phát đi thông báo đầu tiên của bạn đến các host ở tab "Gửi thông báo".</p>
        </div>
      ) : (
        <div className="space-y-3">
          {notifications.map((notif: any) => {
            const badge = PRIORITY_BADGE[notif.priority] ?? PRIORITY_BADGE.medium;
            return (
              <div
                key={notif._id}
                className="p-4 rounded-xl border border-slate-100 dark:border-slate-800 bg-white dark:bg-slate-950 flex gap-4 items-start hover:shadow-md transition-all duration-200"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <span className="font-bold text-sm text-slate-800 dark:text-slate-200">{notif.title}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${badge.color}`}>
                      {badge.label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed mb-3">{notif.message}</p>

                  <div className="flex items-center gap-4 flex-wrap text-[10px] text-slate-400 dark:text-slate-500">
                    <div className="flex items-center gap-1.5 bg-slate-50 dark:bg-slate-900 px-2 py-0.5 rounded border border-slate-100 dark:border-slate-800/80">
                      {notif.recipient?.avatarUrl && (
                        <img src={notif.recipient.avatarUrl} alt="" className="w-4.5 h-4.5 rounded-full object-cover" />
                      )}
                      <span className="font-semibold text-slate-600 dark:text-slate-400">→ {notif.recipient?.username ?? 'Tất cả host'}</span>
                    </div>

                    {notif.link && (
                      <a href={notif.link} className="flex items-center gap-1 text-primary hover:underline font-semibold">
                        <ExternalLink size={10} /> {notif.link}
                      </a>
                    )}

                    <div className="flex items-center gap-1">
                      <Clock size={10} />
                      {new Date(notif.createdAt).toLocaleString('vi-VN')}
                    </div>

                    {notif.isRead && (
                      <span className="text-emerald-500 font-bold flex items-center gap-0.5">
                        <Check size={10} /> Đã đọc
                      </span>
                    )}
                  </div>
                </div>

                <button
                  onClick={() => setConfirmDelete({ type: 'one', id: notif._id })}
                  className="p-1.5 rounded-lg border border-red-200 bg-red-50/50 hover:bg-red-50 text-red-600 transition-all dark:border-red-950/20 dark:bg-red-950/10 dark:hover:bg-red-950/30 flex-shrink-0"
                  title="Xóa thông báo này"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-3 mt-6">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold bg-white dark:bg-slate-900 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-all shadow-sm"
          >
            <ChevronLeft size={12} /> Trước
          </button>
          <span className="text-xs text-slate-500">Trang <strong>{page}</strong> / {totalPages}</span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold bg-white dark:bg-slate-900 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-all shadow-sm"
          >
            Sau <ChevronRight size={12} />
          </button>
        </div>
      )}

      {/* Confirm Delete Modal */}
      {confirmDelete && (
        <div
          className="fixed inset-0 bg-slate-950/60 dark:bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={e => e.target === e.currentTarget && setConfirmDelete(null)}
        >
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-100 dark:border-slate-800 shadow-2xl p-6 max-w-md w-full animate-in fade-in zoom-in-95 duration-200">
            <h3 className="text-base font-bold text-slate-800 dark:text-slate-100 mb-2">Xóa thông báo?</h3>
            <p className="text-xs text-slate-400 dark:text-slate-500 mb-6 leading-relaxed">
              Thông báo này sẽ bị xóa vĩnh viễn khỏi lịch sử hệ thống và hộp thư nhận của host. Hành động này không thể hoàn tác.
            </p>
            <div className="flex justify-end gap-2.5">
              <button
                onClick={() => setConfirmDelete(null)}
                className="px-4 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-bold hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition-all"
              >
                Hủy bỏ
              </button>
              <button
                onClick={() => handleDeleteOne(confirmDelete.id)}
                disabled={!!deletingId}
                className="px-4 py-1.5 rounded-xl bg-red-600 hover:bg-red-700 active:bg-red-800 text-white text-xs font-bold transition-all shadow-sm flex items-center gap-1.5 disabled:opacity-50"
              >
                {deletingId ? (
                  <RefreshCw size={12} className="animate-spin" />
                ) : (
                  <Trash2 size={12} />
                )}
                {deletingId ? 'Đang xóa...' : 'Xác nhận xóa'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AdminNotificationsPage() {
  return (
    <div className="h-[calc(100vh-2rem)] max-w-7xl mx-auto w-full flex flex-col gap-4">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
          Quản lý thông báo
        </h1>
        <p className="text-xs text-slate-400 font-semibold mt-0.5">
          Xem các thông báo nhận được từ hệ thống hoặc gửi thông báo mới cho các host.
        </p>
      </div>

      {/* Tabs Layout */}
      <Tabs defaultValue="received" className="flex-1 flex flex-col min-h-0">
        <TabsList className="w-fit mb-4">
          <TabsTrigger value="received" className="gap-1.5 text-xs">
            <Bell className="w-3.5 h-3.5" /> Thông báo nhận
          </TabsTrigger>
          <TabsTrigger value="compose" className="gap-1.5 text-xs">
            <Send className="w-3.5 h-3.5" /> Gửi thông báo
          </TabsTrigger>
          <TabsTrigger value="sent" className="gap-1.5 text-xs">
            <History className="w-3.5 h-3.5" /> Lịch sử đã gửi
          </TabsTrigger>
        </TabsList>

        <div className="flex-1 min-h-0 overflow-y-auto pr-1">
          <TabsContent value="received" className="m-0 h-full">
            <AdminNotifications />
          </TabsContent>
          <TabsContent value="compose" className="m-0">
            <ComposeTab />
          </TabsContent>
          <TabsContent value="sent" className="m-0">
            <SentHistoryTab />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
