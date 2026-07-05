'use client';

import { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { getUserReviews, updateReview } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import type { Property, Site } from '@/types/property-site';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import {
  Loader2,
  MessageCircle,
  Star,
  Settings,
} from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';

interface Review {
  _id: string;
  property: Partial<Property> & { _id: string; name: string; slug: string };
  site: Partial<Site> & { _id: string; name: string };
  booking: {
    _id: string;
    checkIn: string;
    checkOut: string;
  };
  propertyRatings: {
    location: number;
    communication: number;
    value: number;
  };
  siteRatings: {
    cleanliness: number;
    accuracy: number;
    amenities: number;
  };
  overallRating: number;
  title?: string;
  comment: string;
  pros?: string[];
  cons?: string[];
  images?: string[];
  hostResponse?: {
    comment: string;
    respondedAt: string;
  };
  isEdited?: boolean;
  createdAt: string;
}

export default function UserReviewsPage() {
  const params = useParams();
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();
  const isOwnProfile = currentUser?.username === username;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['user-reviews', username],
    queryFn: () => getUserReviews(username),
    enabled: !!username,
  });

  const reviews = (data?.data || []) as Review[];

  const [editingReview, setEditingReview] = useState<Review | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [editForm, setEditForm] = useState({
    title: '',
    comment: '',
    propertyRatings: { location: 5, communication: 5, value: 5 },
    siteRatings: { cleanliness: 5, accuracy: 5, amenities: 5 },
  });

  useEffect(() => {
    if (editingReview) {
      setEditForm({
        title: editingReview.title || '',
        comment: editingReview.comment || '',
        propertyRatings: {
          location: editingReview.propertyRatings?.location ?? 5,
          communication: editingReview.propertyRatings?.communication ?? 5,
          value: editingReview.propertyRatings?.value ?? 5,
        },
        siteRatings: {
          cleanliness: editingReview.siteRatings?.cleanliness ?? 5,
          accuracy: editingReview.siteRatings?.accuracy ?? 5,
          amenities: editingReview.siteRatings?.amenities ?? 5,
        },
      });
    }
  }, [editingReview]);

  const handleUpdate = async () => {
    if (!editingReview) return;
    if (editForm.comment.length < 10) {
      toast.error('Nhận xét phải có ít nhất 10 ký tự');
      return;
    }
    setSubmitting(true);
    try {
      await updateReview(editingReview._id, editForm);
      toast.success('Cập nhật đánh giá thành công!');
      setEditingReview(null);
      refetch();
    } catch (err: any) {
      toast.error(err?.message || 'Có lỗi xảy ra khi cập nhật');
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOwnProfile) {
    return (
      <div className="py-12 text-center">
        <MessageCircle className="text-muted-foreground mx-auto h-12 w-12" />
        <h2 className="mt-4 text-lg font-semibold">Đánh giá riêng tư</h2>
        <p className="text-muted-foreground mt-2">
          Bạn không thể xem đánh giá của người dùng khác
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
      </div>
    );
  }

  if (reviews.length === 0) {
    return (
      <div className="py-12 text-center">
        <MessageCircle className="text-muted-foreground mx-auto h-12 w-12" />
        <h2 className="mt-4 text-lg font-semibold">Chưa có đánh giá</h2>
        <p className="text-muted-foreground mt-2">
          Bạn chưa viết đánh giá nào. Hãy trải nghiệm chuyến đi và chia sẻ cảm
          nhận của bạn!
        </p>
      </div>
    );
  }

  const renderStarRating = (rating: number) => {
    return (
      <div className="flex items-center gap-0.5">
        {[1, 2, 3, 4, 5].map(star => (
          <Star
            key={star}
            className={`h-4 w-4 ${
              star <= rating
                ? 'fill-yellow-400 text-yellow-400'
                : 'text-gray-300'
            }`}
          />
        ))}
        <span className="ml-1 text-sm font-semibold">{rating.toFixed(1)}</span>
      </div>
    );
  };

  const ReviewCard = ({ review }: { review: Review }) => {
    return (
      <Card className="transition-all duration-200 hover:border-stone-300 shadow-sm border border-stone-200 rounded-2xl overflow-hidden bg-white">
        <CardContent className="p-4 sm:p-5">
          <div className="flex flex-col gap-3">
            {/* Top row: Property Name & Quick Info */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-stone-100 pb-2">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs sm:text-sm">
                <Link
                  href={`/land/${review.property.slug}`}
                  className="font-semibold text-stone-850 hover:text-primary transition-colors hover:underline"
                >
                  {review.property.name}
                </Link>
                <span className="text-stone-300">•</span>
                <span className="text-stone-500 font-medium">{review.site.name}</span>
                <span className="text-stone-300">•</span>
                <span className="text-stone-400">
                  {format(new Date(review.createdAt), 'dd/MM/yyyy')}
                </span>
                {review.isEdited && (
                  <>
                    <span className="text-stone-300">•</span>
                    <span className="text-[10px] text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded font-medium">
                      Đã sửa
                    </span>
                  </>
                )}
              </div>

              <div className="flex items-center gap-3">
                {renderStarRating(review.overallRating)}
                
                {!review.isEdited && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2.5 gap-1 border border-stone-200 hover:bg-stone-50 text-stone-600 rounded-lg text-xs font-medium transition-all"
                    onClick={() => setEditingReview(review)}
                  >
                    <Settings className="h-3 w-3" />
                    Chỉnh sửa
                  </Button>
                )}
              </div>
            </div>

            {/* Comment Body */}
            <div>
              {review.title && (
                <h4 className="text-sm font-semibold text-stone-800 mb-0.5">
                  {review.title}
                </h4>
              )}
              <p className="text-stone-600 text-sm leading-relaxed">
                {review.comment}
              </p>
            </div>

            {/* Host Response (Compact) */}
            {review.hostResponse && (
              <div className="mt-1 pl-3 border-l-2 border-primary/30 py-0.5">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className="text-[11px] font-bold text-primary bg-primary/5 px-1.5 py-0.5 rounded">
                    Phản hồi từ chủ nhà
                  </span>
                  <span className="text-[10px] text-stone-400">
                    {format(new Date(review.hostResponse.respondedAt), 'dd/MM/yyyy')}
                  </span>
                </div>
                <p className="text-xs text-stone-600">
                  {review.hostResponse.comment}
                </p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-4">
      <div className="mb-6">
        <h2 className="text-2xl font-bold">Đánh giá đã gửi</h2>
        <p className="text-muted-foreground mt-1 text-sm">
          {reviews.length} đánh giá
        </p>
      </div>

      <div className="space-y-4">
        {reviews.map(review => (
          <ReviewCard key={review._id} review={review} />
        ))}
      </div>

      {/* Edit Review Dialog */}
      <Dialog open={!!editingReview} onOpenChange={(open) => !open && setEditingReview(null)}>
        <DialogContent className="sm:max-w-[480px] max-h-[90vh] overflow-y-auto rounded-3xl p-6 border-slate-100 bg-white shadow-2xl">
          <DialogHeader className="space-y-2">
            <DialogTitle className="text-xl font-bold text-slate-900 tracking-tight">Chỉnh sửa đánh giá</DialogTitle>
            <DialogDescription className="text-xs text-stone-500 leading-relaxed">
              Bạn chỉ được chỉnh sửa đánh giá này <strong className="text-primary">1 lần duy nhất</strong>. Các số liệu và nhận xét cũ sẽ bị thay thế vĩnh viễn.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* Ratings Selection Group */}
            <div className="space-y-3 rounded-2xl border border-stone-150/70 bg-stone-50/50 p-4">
              <span className="text-[10px] font-bold text-stone-400 uppercase tracking-wider">Đánh giá chung (Khu cắm trại)</span>
              
              <div className="flex items-center justify-between py-1">
                <span className="text-xs font-semibold text-stone-650">Vị trí địa lý</span>
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setEditForm(prev => ({
                        ...prev,
                        propertyRatings: { ...prev.propertyRatings, location: star }
                      }))}
                      className="hover:scale-110 active:scale-95 transition-transform focus:outline-none"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          star <= editForm.propertyRatings.location ? 'fill-yellow-400 text-yellow-400' : 'text-stone-200'
                        }`}
                      />
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-xs font-semibold text-stone-650">Hỗ trợ & Giao tiếp</span>
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setEditForm(prev => ({
                        ...prev,
                        propertyRatings: { ...prev.propertyRatings, communication: star }
                      }))}
                      className="hover:scale-110 active:scale-95 transition-transform focus:outline-none"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          star <= editForm.propertyRatings.communication ? 'fill-yellow-400 text-yellow-400' : 'text-stone-200'
                        }`}
                      />
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-xs font-semibold text-stone-650">Xứng đáng với giá tiền</span>
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setEditForm(prev => ({
                        ...prev,
                        propertyRatings: { ...prev.propertyRatings, value: star }
                      }))}
                      className="hover:scale-110 active:scale-95 transition-transform focus:outline-none"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          star <= editForm.propertyRatings.value ? 'fill-yellow-400 text-yellow-400' : 'text-stone-200'
                        }`}
                      />
                    </button>
                  ))}
                </div>
              </div>

              <div className="my-2 border-t border-stone-200/50" />

              <span className="text-[10px] font-bold text-stone-400 uppercase tracking-wider">Đánh giá vị trí (Site của bạn)</span>
              
              <div className="flex items-center justify-between py-1">
                <span className="text-xs font-semibold text-stone-650">Sạch sẽ & Vệ sinh</span>
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setEditForm(prev => ({
                        ...prev,
                        siteRatings: { ...prev.siteRatings, cleanliness: star }
                      }))}
                      className="hover:scale-110 active:scale-95 transition-transform focus:outline-none"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          star <= editForm.siteRatings.cleanliness ? 'fill-yellow-400 text-yellow-400' : 'text-stone-200'
                        }`}
                      />
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-xs font-semibold text-stone-650">Thông tin chính xác</span>
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setEditForm(prev => ({
                        ...prev,
                        siteRatings: { ...prev.siteRatings, accuracy: star }
                      }))}
                      className="hover:scale-110 active:scale-95 transition-transform focus:outline-none"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          star <= editForm.siteRatings.accuracy ? 'fill-yellow-400 text-yellow-400' : 'text-stone-200'
                        }`}
                      />
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-xs font-semibold text-stone-650">Tiện nghi có sẵn</span>
                <div className="flex gap-1">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setEditForm(prev => ({
                        ...prev,
                        siteRatings: { ...prev.siteRatings, amenities: star }
                      }))}
                      className="hover:scale-110 active:scale-95 transition-transform focus:outline-none"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          star <= editForm.siteRatings.amenities ? 'fill-yellow-400 text-yellow-400' : 'text-stone-200'
                        }`}
                      />
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Fields Text */}
            <div className="space-y-3">
              <div>
                <Label htmlFor="edit-title" className="text-xs font-semibold text-stone-700">Tiêu đề đánh giá</Label>
                <Input
                  id="edit-title"
                  placeholder="VD: Trải nghiệm tuyệt vời cùng gia đình"
                  value={editForm.title}
                  onChange={(e) => setEditForm(prev => ({ ...prev, title: e.target.value }))}
                  className="mt-1 rounded-xl border-stone-200 focus-visible:ring-primary focus-visible:border-primary h-10 text-sm"
                />
              </div>

              <div>
                <Label htmlFor="edit-comment" className="text-xs font-semibold text-stone-700">Nội dung đánh giá <span className="text-red-500">*</span></Label>
                <Textarea
                  id="edit-comment"
                  placeholder="Chia sẻ chi tiết hơn cảm nhận của bạn để cải thiện dịch vụ cắm trại..."
                  rows={4}
                  value={editForm.comment}
                  onChange={(e) => setEditForm(prev => ({ ...prev, comment: e.target.value }))}
                  className="mt-1 rounded-xl border-stone-200 focus-visible:ring-primary focus-visible:border-primary text-sm leading-relaxed"
                />
                <div className="mt-1 flex items-center justify-between text-[10px] text-stone-400">
                  <span>Tối thiểu 10 ký tự</span>
                  <span className={editForm.comment.length < 10 ? 'text-rose-500 font-medium' : 'text-stone-400'}>
                    Hiện tại: {editForm.comment.length} ký tự
                  </span>
                </div>
              </div>
            </div>
          </div>

          <DialogFooter className="gap-2 mt-4 flex sm:flex-row flex-col-reverse justify-end">
            <Button
              variant="outline"
              disabled={submitting}
              onClick={() => setEditingReview(null)}
              className="rounded-xl border-stone-250 hover:bg-stone-50 text-xs px-5 h-10"
            >
              Hủy
            </Button>
            <Button
              disabled={submitting || editForm.comment.length < 10}
              onClick={handleUpdate}
              className="bg-primary hover:bg-primary/90 text-white rounded-xl text-xs px-6 h-10 font-bold gap-1.5 transition-all shadow-md shadow-primary/10"
            >
              {submitting && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Lưu thay đổi
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
