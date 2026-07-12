'use client';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { createReview } from '@/lib/client-actions';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Loader2, Star } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';

interface ReviewDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  bookingId: string;
  bookingCode?: string;
  propertyId: string;
  siteId: string;
  propertyName: string;
  siteName: string;
}

interface RatingState {
  location: number;
  communication: number;
  value: number;
  cleanliness: number;
  accuracy: number;
  amenities: number;
}

// Rating stars component
function RatingStars({
  label,
  value,
  onChange,
  disabled,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-2">
      <Label className="text-sm font-medium">{label}</Label>
      <div className="flex gap-1">
        {[1, 2, 3, 4, 5].map(star => (
          <button
            key={star}
            type="button"
            onClick={() => onChange(star)}
            className="transition-transform hover:scale-110"
            disabled={disabled}
          >
            <Star
              className={`h-8 w-8 ${star <= value
                  ? 'fill-yellow-400 text-yellow-400'
                  : 'text-gray-300'
                }`}
            />
          </button>
        ))}
      </div>
    </div>
  );
}

export function ReviewDialog({
  open,
  onOpenChange,
  bookingId,
  bookingCode,
  propertyId,
  siteId,
  propertyName,
  siteName,
}: ReviewDialogProps) {
  const queryClient = useQueryClient();
  const [comment, setComment] = useState('');
  const [ratings, setRatings] = useState<RatingState>({
    location: 0,
    communication: 0,
    value: 0,
    cleanliness: 0,
    accuracy: 0,
    amenities: 0,
  });

  const reviewMutation = useMutation({
    mutationFn: (data: {
      booking: string;
      property: string;
      site: string;
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
      comment: string;
    }) => createReview(data),
    onSuccess: () => {
      toast.success('Đánh giá thành công', {
        description: 'Cảm ơn bạn đã chia sẻ trải nghiệm của mình!',
      });

      // Invalidate queries
      queryClient.invalidateQueries({ queryKey: ['booking', bookingId] });
      if (bookingCode) {
        queryClient.invalidateQueries({ queryKey: ['booking', bookingCode] });
      }
      queryClient.invalidateQueries({ queryKey: ['bookings'] });
      queryClient.invalidateQueries({
        queryKey: ['property-reviews', propertyId],
      });
      queryClient.invalidateQueries({ queryKey: ['site-reviews', siteId] });

      // Reset form and close
      onOpenChange(false);
      setComment('');
      setRatings({
        location: 0,
        communication: 0,
        value: 0,
        cleanliness: 0,
        accuracy: 0,
        amenities: 0,
      });
    },
    onError: (error: Error) => {
      toast.error('Không thể gửi đánh giá', {
        description: error?.message || 'Vui lòng thử lại sau.',
      });
    },
  });

  const handleSubmit = () => {
    // Validate all ratings are set
    const allRatings = Object.values(ratings);
    if (allRatings.some(r => r === 0)) {
      toast.error('Vui lòng đánh giá tất cả các tiêu chí');
      return;
    }

    // Validate comment
    if (comment.trim().length < 10) {
      toast.error('Nhận xét phải có ít nhất 10 ký tự');
      return;
    }

    if (comment.trim().length > 2000) {
      toast.error('Nhận xét không được vượt quá 2000 ký tự');
      return;
    }

    // Submit review
    reviewMutation.mutate({
      booking: bookingId,
      property: propertyId,
      site: siteId,
      propertyRatings: {
        location: ratings.location,
        communication: ratings.communication,
        value: ratings.value,
      },
      siteRatings: {
        cleanliness: ratings.cleanliness,
        accuracy: ratings.accuracy,
        amenities: ratings.amenities,
      },
      comment: comment.trim(),
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>Đánh giá chuyến đi của bạn</DialogTitle>
          <DialogDescription>
            Chia sẻ trải nghiệm của bạn tại {siteName} - {propertyName}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* Property Ratings */}
          <div className="space-y-4">
            <h3 className="font-semibold">Đánh giá về địa điểm</h3>
            <RatingStars
              label="Vị trí"
              value={ratings.location}
              onChange={value =>
                setRatings(prev => ({ ...prev, location: value }))
              }
              disabled={reviewMutation.isPending}
            />
            <RatingStars
              label="Giao tiếp với chủ nhà"
              value={ratings.communication}
              onChange={value =>
                setRatings(prev => ({ ...prev, communication: value }))
              }
              disabled={reviewMutation.isPending}
            />
            <RatingStars
              label="Giá trị"
              value={ratings.value}
              onChange={value =>
                setRatings(prev => ({ ...prev, value: value }))
              }
              disabled={reviewMutation.isPending}
            />
          </div>

          <Separator />

          {/* Site Ratings */}
          <div className="space-y-4">
            <h3 className="font-semibold">Đánh giá về vị trí cắm trại</h3>
            <RatingStars
              label="Vệ sinh"
              value={ratings.cleanliness}
              onChange={value =>
                setRatings(prev => ({ ...prev, cleanliness: value }))
              }
              disabled={reviewMutation.isPending}
            />
            <RatingStars
              label="Đúng mô tả"
              value={ratings.accuracy}
              onChange={value =>
                setRatings(prev => ({ ...prev, accuracy: value }))
              }
              disabled={reviewMutation.isPending}
            />
            <RatingStars
              label="Tiện nghi"
              value={ratings.amenities}
              onChange={value =>
                setRatings(prev => ({ ...prev, amenities: value }))
              }
              disabled={reviewMutation.isPending}
            />
          </div>

          <Separator />

          {/* Comment */}
          <div className="space-y-2">
            <Label htmlFor="review-comment">
              Nhận xét <span className="text-red-500">*</span>
            </Label>
            <Textarea
              id="review-comment"
              placeholder="Chia sẻ trải nghiệm của bạn... (tối thiểu 10 ký tự)"
              value={comment}
              onChange={e => setComment(e.target.value)}
              className="min-h-[120px] resize-none"
              disabled={reviewMutation.isPending}
              maxLength={2000}
            />
            <div className="flex items-center justify-between">
              <p className="text-muted-foreground text-xs">
                Nhận xét của bạn sẽ giúp ích cho những người khác
              </p>
              <p
                className={`text-xs ${comment.length < 10
                    ? 'text-red-600'
                    : comment.length > 1800
                      ? 'text-orange-600'
                      : 'text-muted-foreground'
                  }`}
              >
                {comment.length}/2000
              </p>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={reviewMutation.isPending}
          >
            Hủy
          </Button>
          <Button
            type="button"
            onClick={handleSubmit}
            disabled={
              reviewMutation.isPending ||
              Object.values(ratings).some(r => r === 0) ||
              comment.trim().length < 10
            }
          >
            {reviewMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Đang gửi...
              </>
            ) : (
              'Gửi đánh giá'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
