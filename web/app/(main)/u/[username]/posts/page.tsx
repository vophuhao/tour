'use client';
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useParams } from 'next/navigation';
import { useAuthStore } from '@/store/auth.store';
import { forumApi } from '@/lib/forumApi';
import API from '@/lib/api-client';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import Link from 'next/link';
import Image from 'next/image';
import { useMounted } from '@/hooks/useMounted';
import { Button } from '@/components/ui/button';
import {
  MessageSquare, Eye, Heart, Edit3, Trash2,
  Loader2, Plus, ChevronLeft, ChevronRight, Clock, Lock, AlertCircle,
} from 'lucide-react';

const STATUS_BADGE: Record<string, { label: string; className: string }> = {
  published: { label: 'Đã đăng', className: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-400' },
  draft: { label: 'Nháp', className: 'bg-amber-100 text-amber-800 dark:bg-amber-950/30 dark:text-amber-400' },
  archived: { label: 'Lưu trữ', className: 'bg-slate-100 text-slate-650 dark:bg-slate-800 dark:text-slate-400' },
  hidden: { label: 'Đã ẩn', className: 'bg-orange-100 text-orange-850 dark:bg-orange-950/30 dark:text-orange-400' },
  deleted: { label: 'Đã xóa', className: 'bg-red-100 text-red-800 dark:bg-red-950/30 dark:text-red-400' },
  active: { label: 'Hoạt động', className: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-400' },
};

export default function MyPostsPage() {
  const params = useParams();
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();
  const isOwnProfile = currentUser?.username === username;
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const mounted = useMounted();

  const { data: myPostsData, isLoading } = useQuery({
    queryKey: ['my-posts-by-user', currentUser?._id, page],
    queryFn: async () => {
      if (!currentUser?._id) return null;
      const res: any = await API.get(`/forum/${currentUser._id}/posts`, {
        params: { page, pageSize: 12 },
      });
      return res;
    },
    enabled: isOwnProfile && !!currentUser?._id,
  });

  const posts: any[] = myPostsData?.data ?? myPostsData?.posts ?? [];
  const total = myPostsData?.pagination?.total ?? myPostsData?.totalPosts ?? posts.length;
  const totalPages = myPostsData?.pagination?.totalPages ?? myPostsData?.totalPages ?? (Math.ceil(total / 12) || 1);

  const handleDelete = async (postId: string) => {
    setDeletingId(postId);
    try {
      await forumApi.deletePost(postId);
      toast.success('Đã xóa bài viết!');
      queryClient.invalidateQueries({ queryKey: ['my-posts-by-user'] });
      setConfirmDelete(null);
    } catch (e: any) {
      toast.error(e?.response?.data?.message ?? 'Lỗi xóa bài viết');
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

        {/* List Skeleton */}
        <div className="flex flex-col gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row gap-4 items-start shadow-sm animate-pulse">
              <div className="w-full sm:w-24 h-40 sm:h-20 bg-slate-200 dark:bg-slate-800 rounded-xl flex-shrink-0" />
              <div className="flex-1 w-full space-y-3">
                <div className="flex gap-2">
                  <div className="h-4 w-12 bg-slate-200 dark:bg-slate-800 rounded" />
                  <div className="h-4 w-16 bg-slate-200 dark:bg-slate-800 rounded" />
                </div>
                <div className="h-6 w-3/4 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="flex gap-4 pt-1">
                  <div className="h-3.5 w-10 bg-slate-200 dark:bg-slate-800 rounded" />
                  <div className="h-3.5 w-10 bg-slate-200 dark:bg-slate-800 rounded" />
                  <div className="h-3.5 w-10 bg-slate-200 dark:bg-slate-800 rounded" />
                  <div className="h-3.5 w-16 bg-slate-200 dark:bg-slate-800 rounded" />
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
        <p className="text-sm text-muted-foreground mt-1">Bạn không thể xem bài viết của người dùng khác</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-extrabold text-slate-900 dark:text-white">
            Bài viết của tôi
          </h2>
          <p className="text-xs text-muted-foreground mt-1">
            {total} bài viết đã đăng
          </p>
        </div>
        <Link
          href="/forum/create"
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-primary text-white text-xs font-bold shadow-md hover:bg-primary/95 transition-all w-full sm:w-auto text-center"
        >
          <Plus size={15} /> Tạo bài viết
        </Link>
      </div>

      {/* Content */}
      {posts.length === 0 ? (
        <div className="py-16 px-6 text-center bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm">
          <MessageSquare className="text-slate-300 dark:text-slate-700 mx-auto h-12 w-12 mb-4" />
          <h3 className="text-lg font-bold text-slate-850 dark:text-white mb-2">
            Chưa có bài viết nào
          </h3>
          <p className="text-sm text-muted-foreground mb-6 max-w-sm mx-auto">
            Hãy chia sẻ kinh nghiệm cắm trại của bạn với cộng đồng!
          </p>
          <Link
            href="/forum/create"
            className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-xl bg-primary text-white text-sm font-bold shadow-md hover:bg-primary/95 transition-all"
          >
            <Plus size={16} /> Viết bài đầu tiên
          </Link>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {posts.map((post: any) => {
            const badge = STATUS_BADGE[post.status] ?? STATUS_BADGE.published;
            const displayImage = post.imageUrl || 
                                 (post.images && post.images.length > 0 ? post.images[0] : null) ||
                                 (post.content ? post.content.match(/<img[^>]+src=["']([^"']+)["']/i)?.[1] : null) ||
                                 null;
            return (
              <div
                key={post._id}
                className={`bg-white dark:bg-slate-900 border rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row gap-4 items-start shadow-sm transition-all ${
                  post.status === 'hidden'
                    ? 'border-rose-200 dark:border-rose-900/40 bg-rose-50/5 dark:bg-rose-950/5'
                    : 'border-slate-200 dark:border-slate-800'
                }`}
              >
                {/* Cover image */}
                {displayImage && (
                  <div className="relative w-full sm:w-24 h-40 sm:h-20 flex-shrink-0 overflow-hidden rounded-xl">
                    <Image
                      src={displayImage}
                      alt={post.title || ''}
                      fill
                      sizes="(max-width: 768px) 100vw, 96px"
                      className="object-cover"
                    />
                  </div>
                )}

                <div className="flex-1 min-w-0 w-full space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold ${badge.className}`}>
                      {badge.label}
                    </span>
                    {post.subject && (
                      <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-650 dark:bg-slate-800 dark:text-slate-400 font-bold">
                        {post.subject}
                      </span>
                    )}
                  </div>

                  <h3 className="text-base font-bold text-slate-850 dark:text-white truncate">
                    {post.title}
                  </h3>

                  <div className="flex items-center gap-4 flex-wrap text-xs text-slate-500 dark:text-slate-400">
                    <span className="flex items-center gap-1">
                      <Eye size={12} /> {post.viewCount ?? 0}
                    </span>
                    <span className="flex items-center gap-1">
                      <Heart size={12} /> {post.likeCount ?? post.likes?.length ?? 0}
                    </span>
                    <span className="flex items-center gap-1">
                      <MessageSquare size={12} /> {post.commentCount ?? 0}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock size={12} /> {new Date(post.createdAt).toLocaleDateString('vi-VN')}
                    </span>
                  </div>

                  {post.status === 'hidden' && (
                    <div className="mt-2.5 flex items-start gap-2 px-3 py-2 bg-rose-50 dark:bg-rose-950/20 border border-rose-100 dark:border-rose-900/30 rounded-xl text-xs text-rose-650 dark:text-rose-400 w-full">
                      <AlertCircle className="h-4 w-4 shrink-0 text-rose-500 mt-0.5" />
                      <div>
                        <span className="font-bold text-rose-700 dark:text-rose-400">Bài viết đã bị ẩn bởi quản trị viên:</span>{' '}
                        {post.moderationReason || 'Bài viết bị báo cáo hoặc vi phạm tiêu chuẩn cộng đồng.'}
                      </div>
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex sm:flex-col gap-2 w-full sm:w-auto flex-shrink-0 border-t sm:border-t-0 pt-3 sm:pt-0 mt-2 sm:mt-0">
                  {post.slug && (
                    <Link
                      href={`/forum/${post.slug}`}
                      className="flex-1 sm:flex-initial flex items-center justify-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-bold hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-350 transition-colors text-center"
                    >
                      <Eye size={12} /> Xem
                    </Link>
                  )}
                  <Link
                    href={`/forum/${post._id}/edit`}
                    className="flex-1 sm:flex-initial flex items-center justify-center gap-1 px-3 py-2 rounded-lg border border-primary/20 bg-primary/5 hover:bg-primary/10 text-primary-dark text-xs font-bold transition-colors text-center"
                  >
                    <Edit3 size={12} /> Sửa
                  </Link>
                  <button
                    onClick={() => setConfirmDelete(post._id)}
                    className="flex-1 sm:flex-initial flex items-center justify-center gap-1 px-3 py-2 rounded-lg border border-red-200 dark:border-red-900/30 bg-red-50 dark:bg-red-950/20 hover:bg-red-100/50 dark:hover:bg-red-950/30 text-red-650 dark:text-red-400 text-xs font-bold transition-colors cursor-pointer text-center"
                  >
                    <Trash2 size={12} /> Xóa
                  </button>
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
          <span className="text-xs text-slate-655 dark:text-slate-400">
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
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Xóa bài viết?</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
              Bài viết sẽ bị xóa vĩnh viễn và không thể khôi phục.
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
                {deletingId ? 'Đang xóa...' : 'Xóa'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
