'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useAuthStore } from '@/store/auth.store';
import { getFreeSpots, deleteFreeSpot } from '@/lib/free-spot-api';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import Link from 'next/link';
import Image from 'next/image';
import { useMounted } from '@/hooks/useMounted';
import { Button } from '@/components/ui/button';
import {
  MapPin, Eye, Heart, Edit3, Trash2, Loader2,
  Plus, ChevronLeft, ChevronRight, Clock, Lock, ShieldCheck,
} from 'lucide-react';

const TERRAIN_LABELS: Record<string, string> = {
  mountain: '🏔️ Núi', beach: '🏖️ Biển', forest: '🌲 Rừng',
  river: '🏞️ Sông', lake: '💧 Hồ', field: '🌾 Đồng', other: '📍 Khác',
};

const STATUS_BADGE: Record<string, { label: string; className: string }> = {
  active: { label: 'Hoạt động', className: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-400' },
  pending: { label: 'Chờ duyệt', className: 'bg-amber-100 text-amber-800 dark:bg-amber-950/30 dark:text-amber-400' },
  hidden: { label: 'Đã ẩn', className: 'bg-orange-100 text-orange-850 dark:bg-orange-950/30 dark:text-orange-400' },
};

export default function MySpotsPage() {
  const params = useParams();
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();
  const isOwnProfile = currentUser?.username === username;
  const router = useRouter();
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const mounted = useMounted();

  const { data: mySpots, isLoading } = useQuery({
    queryKey: ['my-free-spots', currentUser?._id, page],
    queryFn: async () => {
      if (!currentUser?._id) return null;
      const res: any = await getFreeSpots({ page, limit: 12, author: currentUser._id } as any);
      return res;
    },
    enabled: isOwnProfile && !!currentUser?._id,
  });

  const spots: any[] = mySpots?.data ?? mySpots?.spots ?? [];
  const total = mySpots?.pagination?.total ?? mySpots?.total ?? spots.length;
  const totalPages = mySpots?.pagination?.totalPages ?? (Math.ceil(total / 12) || 1);

  const handleDelete = async (spotId: string) => {
    setDeletingId(spotId);
    try {
      await deleteFreeSpot(spotId);
      toast.success('Đã xóa địa điểm!');
      queryClient.invalidateQueries({ queryKey: ['my-free-spots'] });
      setConfirmDelete(null);
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi xóa địa điểm');
    } finally {
      setDeletingId(null);
    }
  };

  if (!mounted || isLoading) {
    return (
      <div className="space-y-6">
        {/* Header Skeleton */}
        <div className="animate-pulse space-y-2">
          <div className="h-8 w-48 bg-slate-200 dark:bg-slate-800 rounded" />
          <div className="h-4 w-64 bg-slate-200 dark:bg-slate-800 rounded" />
        </div>

        {/* Grid Skeleton */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm animate-pulse p-4 space-y-4">
              <div className="h-44 w-full bg-slate-200 dark:bg-slate-800 rounded-xl" />
              <div className="space-y-3">
                <div className="h-4 w-16 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-5 w-3/4 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-4 w-1/2 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="flex gap-4 pt-1">
                  <div className="h-3.5 w-10 bg-slate-200 dark:bg-slate-800 rounded" />
                  <div className="h-3.5 w-10 bg-slate-200 dark:bg-slate-800 rounded" />
                  <div className="h-3.5 w-16 bg-slate-200 dark:bg-slate-800 rounded" />
                </div>
                <div className="flex gap-2 pt-2">
                  <div className="h-8 flex-1 bg-slate-200 dark:bg-slate-800 rounded-lg" />
                  <div className="h-8 flex-1 bg-slate-200 dark:bg-slate-800 rounded-lg" />
                  <div className="h-8 flex-1 bg-slate-200 dark:bg-slate-800 rounded-lg" />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!isOwnProfile) {
    return (
      <div className="py-16 text-center">
        <Lock className="text-muted-foreground mx-auto h-10 w-10 mb-3" />
        <h2 className="text-lg font-bold text-slate-850 dark:text-white">Riêng tư</h2>
        <p className="text-sm text-muted-foreground mt-1">Bạn không thể xem địa điểm của người dùng khác</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-extrabold text-slate-900 dark:text-white">
            Địa điểm của tôi
          </h2>
          <p className="text-xs text-muted-foreground mt-1">
            {total} địa điểm đã chia sẻ
          </p>
        </div>
        <Link
          href="/free-spots/create"
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-primary text-white text-xs font-bold shadow-md hover:bg-primary/95 transition-all w-full sm:w-auto text-center"
        >
          <Plus size={15} /> Thêm địa điểm
        </Link>
      </div>

      {/* Content */}
      {spots.length === 0 ? (
        <div className="py-16 px-6 text-center bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm">
          <MapPin className="text-slate-300 dark:text-slate-700 mx-auto h-12 w-12 mb-4" />
          <h3 className="text-lg font-bold text-slate-850 dark:text-white mb-2">
            Chưa có địa điểm nào
          </h3>
          <p className="text-sm text-muted-foreground mb-6 max-w-sm mx-auto">
            Hãy chia sẻ những địa điểm cắm trại tuyệt vời bạn đã khám phá!
          </p>
          <Link
            href="/free-spots/create"
            className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-primary text-white text-sm font-bold shadow-md hover:bg-primary/95 transition-all"
          >
            <Plus size={16} /> Chia sẻ địa điểm đầu tiên
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {spots.map((spot: any) => {
            const badge = STATUS_BADGE[spot.status] ?? STATUS_BADGE.active;
            return (
              <div
                key={spot._id}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm hover:shadow-md transition-shadow flex flex-col"
              >
                {/* Image */}
                <div className="relative h-44 w-full bg-slate-100 dark:bg-slate-800">
                  {spot.images?.[0] ? (
                    <Image
                      src={spot.images[0]}
                      alt={spot.title}
                      fill
                      sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
                      className="object-cover"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-4xl select-none">
                      🏕️
                    </div>
                  )}
                  {/* Status badge overlay */}
                  <div className="absolute top-3 left-3 z-10">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold shadow-sm ${badge.className}`}>
                      {badge.label}
                    </span>
                  </div>
                  {spot.isVerified && (
                    <div className="absolute top-3 right-3 z-10">
                      <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-extrabold bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-455 shadow-sm">
                        <ShieldCheck size={10} /> Đã xác minh
                      </span>
                    </div>
                  )}
                </div>

                {/* Content */}
                <div className="p-4 flex-1 flex flex-col justify-between space-y-3">
                  <div className="space-y-2">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-450 dark:text-slate-400">
                      {TERRAIN_LABELS[spot.terrain] ?? spot.terrain}
                    </div>
                    <h3 className="text-base font-bold text-slate-850 dark:text-white line-clamp-1">
                      {spot.title}
                    </h3>
                    <div className="flex items-center gap-1 text-xs text-slate-550 dark:text-slate-400">
                      <MapPin size={12} className="text-primary/70 shrink-0" />
                      <span className="truncate">{spot.city}</span>
                    </div>
                  </div>

                  <div className="space-y-3.5 pt-1">
                    {/* Stats */}
                    <div className="flex gap-4 text-xs text-slate-500 dark:text-slate-400">
                      <span className="flex items-center gap-1">
                        <Eye size={12} /> {spot.viewCount ?? 0}
                      </span>
                      <span className="flex items-center gap-1">
                        <Heart size={12} /> {spot.likeCount ?? 0}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock size={12} /> {new Date(spot.createdAt).toLocaleDateString('vi-VN')}
                      </span>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex gap-2">
                      <Link
                        href={`/free-spots/${spot._id}`}
                        className="flex-1 flex items-center justify-center gap-1 py-2 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-bold hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-350 transition-colors"
                      >
                        <Eye size={12} /> Xem
                      </Link>
                      <Link
                        href={`/free-spots/${spot._id}/edit`}
                        className="flex-1 flex items-center justify-center gap-1 py-2 rounded-lg border border-primary/20 bg-primary/5 hover:bg-primary/10 text-primary-dark text-xs font-bold transition-colors"
                      >
                        <Edit3 size={12} /> Sửa
                      </Link>
                      <button
                        onClick={() => setConfirmDelete(spot._id)}
                        className="flex-1 flex items-center justify-center gap-1 py-2 rounded-lg border border-red-200 dark:border-red-900/30 bg-red-50 dark:bg-red-950/20 hover:bg-red-100/50 dark:hover:bg-red-950/30 text-red-650 dark:text-red-400 text-xs font-bold transition-colors cursor-pointer"
                      >
                        <Trash2 size={12} /> Xóa
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-3 mt-8">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <ChevronLeft size={14} /> Trước
          </button>
          <span className="text-xs text-slate-650 dark:text-slate-400">
            Trang <strong className="text-slate-900 dark:text-white">{page}</strong> / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-bold disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            Sau <ChevronRight size={14} />
          </button>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {confirmDelete && (
        <div
          className="fixed inset-0 bg-black/60 z-[100] flex items-center justify-center p-4 backdrop-blur-xs"
          onClick={e => e.target === e.currentTarget && setConfirmDelete(null)}
        >
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 max-w-sm w-full shadow-2xl animate-in zoom-in-95 duration-200">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Xóa địa điểm?</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
              Địa điểm sẽ bị xóa vĩnh viễn. Hành động này không thể hoàn tác.
            </p>
            <div className="flex gap-3 justify-end">
              <Button
                variant="outline"
                onClick={() => setConfirmDelete(null)}
                className="rounded-xl font-bold cursor-pointer"
              >
                Hủy
              </Button>
              <Button
                variant="destructive"
                onClick={() => handleDelete(confirmDelete)}
                disabled={!!deletingId}
                className="rounded-xl font-bold cursor-pointer bg-red-650 hover:bg-red-600"
              >
                {deletingId ? 'Đang xóa...' : 'Xóa địa điểm'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
