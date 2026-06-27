'use client';

import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { getPropertyReviews } from '@/lib/client-actions';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';
import { Star, ThumbsUp } from 'lucide-react';
import { useState } from 'react';

interface PropertyReviewsSectionProps {
  propertyId: string;
  rating?: {
    average: number;
    count: number;
    breakdown: {
      location: number;
      communication: number;
      value: number;
    };
  };
}

interface Review {
  _id: string;
  guest: {
    _id: string;
    username: string;
    avatarUrl?: string;
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
  comment: string;
  createdAt: string;
  hostResponse?: {
    comment: string;
    respondedAt: string;
  };
}

export function PropertyReviewsSection({
  propertyId,
  rating,
}: PropertyReviewsSectionProps) {
  const [page, setPage] = useState(1);
  const limit = 10;

  const { data, isLoading } = useQuery({
    queryKey: ['property-reviews', propertyId, page],
    queryFn: () => getPropertyReviews(propertyId, page, limit),
    enabled: !!propertyId,
  });

  const reviews = (data?.data || []) as Review[];

  if (isLoading && page === 1) {
    return (
      <div className="space-y-6" id="reviews">
        <h2 className="text-2xl font-bold">Đánh giá</h2>
        <div className="text-muted-foreground py-8 text-center">
          Đang tải...
        </div>
      </div>
    );
  }

  if (!rating || rating.count === 0) {
    return (
      <div className="space-y-6" id="reviews">
        <h2 className="text-2xl font-bold">Đánh giá</h2>
        <div className="text-muted-foreground py-8 text-center">
          Chưa có đánh giá nào
        </div>
      </div>
    );
  }

  // Calculate rating distribution from actual reviews
  const ratingDistribution = reviews.reduce(
    (acc, review) => {
      const starRating = Math.round(review.overallRating);
      if (starRating >= 1 && starRating <= 5) {
        acc[starRating - 1]++;
      }
      return acc;
    },
    [0, 0, 0, 0, 0], // [1-star, 2-star, 3-star, 4-star, 5-star]
  );

  const ratingBreakdown = [5, 4, 3, 2, 1].map(stars => {
    const count = ratingDistribution[stars - 1];
    return {
      stars,
      count,
      percentage:
        rating.count > 0 ? Math.round((count / rating.count) * 100) : 0,
    };
  });

  const recommendPercentage =
    rating.average >= 4 ? 95 : rating.average >= 3 ? 75 : 60;
  console.log('Recommend Percentage:', reviews);

  return (
    <div className="space-y-6" id="reviews">
      <h2 className="text-2xl font-bold">Đánh giá</h2>

      {rating && (
        <div className="grid gap-6 md:grid-cols-2">
          {/* Overall Rating */}
          <div className="space-y-4">
            <div className="flex items-baseline gap-2">
              <div className="flex items-center gap-1">
                <Star className="h-6 w-6 fill-yellow-400 text-yellow-400" />
                <span className="text-3xl font-bold">
                  {rating.average.toFixed(1)}
                </span>
              </div>
              <span className="text-muted-foreground">
                ({rating.count} đánh giá)
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 text-sm">
                <ThumbsUp className="h-4 w-4" />
                <span className="font-semibold">{recommendPercentage}%</span>
                <span className="text-muted-foreground">Khuyến nghị</span>
              </div>
            </div>
          </div>

          {/* Rating Breakdown */}
          <div className="space-y-2">
            {ratingBreakdown.map(({ stars, percentage }) => (
              <div key={stars} className="flex items-center gap-3">
                <span className="w-12 text-sm font-medium">{stars} sao</span>
                <Progress value={percentage} className="flex-1" />
                <span className="text-muted-foreground w-12 text-right text-sm">
                  {percentage}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <Separator />

      {/* Reviews List */}
      <div className="space-y-6">
        {reviews.map(review => (
          <div key={review._id} className="space-y-3">
            <div className="flex items-start gap-4">
              <Avatar>
                <AvatarImage src={review.guest?.avatarUrl} />
                <AvatarFallback>
                  {review.guest?.username.charAt(0).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <div className="flex-1 space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-semibold">{review.guest?.username}</p>
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.overallRating.toFixed(1)}
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 text-xs">
                  <span className="text-muted-foreground">
                    {format(new Date(review.createdAt), 'MMMM yyyy', {
                      locale: vi,
                    })}
                  </span>
                </div>

                <p className="text-sm">{review.comment}</p>

                {/* Rating Details */}
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge variant="outline">
                    Vị trí: {review.propertyRatings.location.toFixed(1)}
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                  </Badge>
                  <Badge variant="outline">
                    Giao tiếp: {review.propertyRatings.communication.toFixed(1)}
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                  </Badge>
                  <Badge variant="outline">
                    Giá trị: {review.propertyRatings.value.toFixed(1)}
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                  </Badge>
                  <Badge variant="outline">
                    Vệ sinh: {review.siteRatings.cleanliness.toFixed(1)}
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                  </Badge>
                  <Badge variant="outline">
                    Đúng mô tả: {review.siteRatings.accuracy.toFixed(1)}
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                  </Badge>
                  <Badge variant="outline">
                    Tiện nghi: {review.siteRatings.amenities.toFixed(1)}
                    <Star className="ml-1 h-3 w-3 fill-yellow-400 text-yellow-400" />
                  </Badge>
                </div>

                {/* Host Response */}
                {review.hostResponse && (
                  <div className="border-primary/20 mt-3 ml-4 border-l-2 pl-4">
                    <p className="mb-1 text-xs font-semibold">
                      Phản hồi từ chủ nhà
                    </p>
                    <p className="text-muted-foreground text-sm">
                      {review.hostResponse.comment}
                    </p>
                    <p className="text-muted-foreground mt-1 text-xs">
                      {format(
                        new Date(review.hostResponse.respondedAt),
                        'dd/MM/yyyy',
                        { locale: vi },
                      )}
                    </p>
                  </div>
                )}
              </div>
            </div>
            <Separator />
          </div>
        ))}
      </div>

      {reviews.length === 0 && (
        <div className="text-muted-foreground py-8 text-center">
          Không tìm thấy đánh giá
        </div>
      )}

      {rating.count > limit && reviews.length >= limit && (
        <Button
          variant="outline"
          className="w-full cursor-pointer"
          onClick={() => setPage(p => p + 1)}
          disabled={isLoading}
        >
          {isLoading
            ? 'Đang tải...'
            : `Xem thêm (${rating.count - reviews.length} còn lại)`}
        </Button>
      )}
    </div>
  );
}
