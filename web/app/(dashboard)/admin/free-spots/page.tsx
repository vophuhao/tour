'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect, useCallback } from 'react';
import { getAdminFreeSpots, updateFreeSpotStatus } from '@/lib/reportApi';
import { toast } from 'sonner';
import {
  Search, EyeOff, Trash2, CheckCircle2, RefreshCw,
  ChevronLeft, ChevronRight, ExternalLink, Flag, ShieldCheck
} from 'lucide-react';
import Link from 'next/link';

const STATUS_OPTIONS = [
  { value: '', label: 'Tất cả trạng thái' },
  { value: 'active', label: 'Đang hoạt động' },
  { value: 'hidden', label: 'Đã ẩn' },
  { value: 'pending', label: 'Chờ duyệt' },
];

const TERRAIN_LABELS: Record<string, string> = {
  mountain: '🏔️ Núi', beach: '🏖️ Biển', forest: '🌲 Rừng',
  river: '🏞️ Sông', lake: '💧 Hồ', field: '🌾 Đồng', other: '📍 Khác',
};

const STATUS_BADGE: Record<string, { label: string; color: string; bg: string }> = {
  active: { label: 'Hoạt động', color: '#15803d', bg: '#dcfce7' },
  hidden: { label: 'Đã ẩn', color: '#c2410c', bg: '#ffedd5' },
  pending: { label: 'Chờ duyệt', color: '#b45309', bg: '#fef3c7' },
};

export default function AdminFreeSpotsPage() {
  const [spots, setSpots] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchSpots = useCallback(async () => {
    setLoading(true);
    try {
      const res: any = await getAdminFreeSpots({ page, limit: 15, status: statusFilter || undefined, search: search || undefined });
      setSpots(res?.data?.data ?? res?.data ?? []);
      setTotalPages(res?.data?.pagination?.totalPages ?? 1);
      setTotal(res?.data?.pagination?.total ?? 0);
    } catch {
      toast.error('Không thể tải danh sách địa điểm');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, search]);

  useEffect(() => { fetchSpots(); }, [fetchSpots]);

  const handleAction = async (spotId: string, data: any, label: string) => {
    setActionLoading(spotId + JSON.stringify(data));
    try {
      await updateFreeSpotStatus(spotId, data);
      toast.success(`Đã ${label} địa điểm`);
      fetchSpots();
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi cập nhật');
    } finally {
      setActionLoading(null);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearch(searchInput);
    setPage(1);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      <div>
        <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
          Quản lý địa điểm chia sẻ
        </h1>
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8, flex: 1, minWidth: 240 }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#9ca3af' }} />
            <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Tìm theo tên, thành phố..." style={{ width: '100%', padding: '9px 12px 9px 36px', borderRadius: 10, border: '1px solid var(--border)', background: 'var(--card)', fontSize: 13, outline: 'none', boxSizing: 'border-box' }} />
          </div>
          <button type="submit" style={{ padding: '9px 18px', borderRadius: 10, border: 'none', background: '#10b981', color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>Tìm</button>
        </form>
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }} style={{ padding: '9px 14px', borderRadius: 10, border: '1px solid var(--border)', background: 'var(--card)', fontSize: 13, cursor: 'pointer', outline: 'none' }}>
          {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <button onClick={fetchSpots} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '9px 14px', borderRadius: 10, border: '1px solid var(--border)', background: 'var(--card)', fontSize: 13, cursor: 'pointer' }}>
          <RefreshCw size={14} /> Làm mới
        </button>
        <span style={{ fontSize: 13, color: 'var(--muted-foreground)' }}>Tổng: <strong>{total}</strong></span>
      </div>

      <div style={{ background: 'var(--card)', borderRadius: 14, border: '1px solid var(--border)', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--muted-foreground)' }}>
            <RefreshCw size={24} style={{ animation: 'spin 1s linear infinite', marginBottom: 8 }} />
            <div>Đang tải...</div>
          </div>
        ) : spots.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', color: 'var(--muted-foreground)' }}>Không có địa điểm nào</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>
                {['Địa điểm', 'Tác giả', 'Địa hình', 'Thành phố', 'Trạng thái', 'Báo cáo', 'Ngày', 'Hành động'].map(h => (
                  <th key={h} style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, fontWeight: 700, color: 'var(--muted-foreground)', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {spots.map((spot) => {
                const badge = STATUS_BADGE[spot.status] ?? STATUS_BADGE.active;
                return (
                  <tr key={spot._id} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.15s' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--muted)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    <td style={{ padding: '12px 16px', maxWidth: 240 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {spot.images?.[0] && <img src={spot.images[0]} alt="" style={{ width: 44, height: 44, borderRadius: 8, objectFit: 'cover', flexShrink: 0 }} />}
                        <div>
                          <div style={{ fontSize: 14, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{spot.title}</div>
                          {spot.isVerified && <span style={{ fontSize: 11, color: '#059669', fontWeight: 600 }}>✓ Đã xác minh</span>}
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {spot.author?.avatarUrl && <img src={spot.author.avatarUrl} alt="" style={{ width: 26, height: 26, borderRadius: '50%', objectFit: 'cover' }} />}
                        <span style={{ fontSize: 13 }}>{spot.author?.username ?? '—'}</span>
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}><span style={{ fontSize: 12 }}>{TERRAIN_LABELS[spot.terrain] ?? spot.terrain}</span></td>
                    <td style={{ padding: '12px 16px', fontSize: 13, color: 'var(--muted-foreground)' }}>{spot.city}</td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ padding: '4px 10px', borderRadius: 99, fontSize: 12, fontWeight: 700, background: badge.bg, color: badge.color }}>{badge.label}</span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      {(spot.reportCount ?? 0) > 0 ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#dc2626', fontWeight: 700, fontSize: 13 }}><Flag size={13} /> {spot.reportCount}</span>
                      ) : <span style={{ color: '#9ca3af', fontSize: 13 }}>0</span>}
                    </td>
                    <td style={{ padding: '12px 16px', fontSize: 12, color: 'var(--muted-foreground)', whiteSpace: 'nowrap' }}>
                      {new Date(spot.createdAt).toLocaleDateString('vi-VN')}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        <Link href={`/free-spots/${spot._id}`} target="_blank" style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', borderRadius: 8, border: '1px solid var(--border)', background: 'var(--card)', color: 'var(--foreground)', fontSize: 12, textDecoration: 'none' }}>
                          <ExternalLink size={12} />
                        </Link>
                        {!spot.isVerified && (
                          <button onClick={() => handleAction(spot._id, { status: spot.status, isVerified: true }, 'xác minh')} disabled={!!actionLoading} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', borderRadius: 8, border: '1px solid #2563eb', background: '#eff6ff', color: '#1d4ed8', fontSize: 12, cursor: 'pointer' }}>
                            <ShieldCheck size={12} /> Xác minh
                          </button>
                        )}
                        {spot.status !== 'hidden' ? (
                          <button onClick={() => handleAction(spot._id, { status: 'hidden' }, 'ẩn')} disabled={!!actionLoading} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', borderRadius: 8, border: '1px solid #f59e0b', background: '#fffbeb', color: '#b45309', fontSize: 12, cursor: 'pointer' }}>
                            <EyeOff size={12} /> Ẩn
                          </button>
                        ) : (
                          <button onClick={() => handleAction(spot._id, { status: 'active' }, 'khôi phục')} disabled={!!actionLoading} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', borderRadius: 8, border: '1px solid #10b981', background: '#f0fdf4', color: '#065f46', fontSize: 12, cursor: 'pointer' }}>
                            <CheckCircle2 size={12} /> Khôi phục
                          </button>
                        )}
                        <button onClick={() => handleAction(spot._id, { status: 'hidden' }, 'ẩn/xóa')} disabled={!!actionLoading} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', borderRadius: 8, border: '1px solid #ef4444', background: '#fef2f2', color: '#dc2626', fontSize: 12, cursor: 'pointer' }}>
                          <Trash2 size={12} /> Xóa
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {totalPages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12, marginTop: 20 }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '8px 14px', borderRadius: 10, border: '1px solid var(--border)', background: 'var(--card)', cursor: page === 1 ? 'not-allowed' : 'pointer', opacity: page === 1 ? 0.5 : 1, fontSize: 13 }}>
            <ChevronLeft size={14} /> Trước
          </button>
          <span style={{ fontSize: 13 }}>Trang <strong>{page}</strong> / {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '8px 14px', borderRadius: 10, border: '1px solid var(--border)', background: 'var(--card)', cursor: page === totalPages ? 'not-allowed' : 'pointer', opacity: page === totalPages ? 0.5 : 1, fontSize: 13 }}>
            Sau <ChevronRight size={14} />
          </button>
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
