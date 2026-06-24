'use client';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { getUserReviews } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import type { Property, Site } from '@/types/property-site';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';
import {
  CalendarDays,
  Loader2,
  MapPin,
  MessageCircle,
  Star,
} from 'lucide-react';
import Image from 'next/image';
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
  createdAt: string;
}

export default function UserReviewsPage() {
  const params = useParams();
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();
  const isOwnProfile = currentUser?.username === username;

  const { data, isLoading } = useQuery({
    queryKey: ['user-reviews', username],
    queryFn: () => getUserReviews(username),
    enabled: !!username,
  });

  const reviews = (data?.data || []) as Review[];

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
    const propertyImageUrl =
      review.property.photos?.find(p => p.isCover)?.url ||
      review.property.photos?.[0]?.url ||
      '/placeholder-property.jpg';

    return (
      <Card className="overflow-hidden transition-shadow hover:shadow-lg">
        <CardContent className="p-0">
          <div className="grid gap-4 md:grid-cols-12">
            {/* Property Image & Info */}
            <Link
              href={`/land/${review.property.slug}`}
              className="group md:col-span-4"
            >
              <div className="relative h-48 w-full md:h-full">
                <Image
                  src={propertyImageUrl}
                  alt={review.property.name}
                  fill
                  sizes="(max-width: 768px) 100vw, 33vw"
                  className="object-cover transition-transform group-hover:scale-105"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                <div className="absolute right-0 bottom-0 left-0 p-4 text-white">
                  <h3 className="text-lg font-semibold">
                    {review.property.name}
                  </h3>
                  {review.property.location && (
                    <div className="mt-1 flex items-center gap-1 text-sm">
                      <MapPin className="h-3 w-3" />
                      <span>
                        {review.property.location.city},{' '}
                        {review.property.location.state}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </Link>

            {/* Review Content */}
            <div className="p-4 md:col-span-8">
              {/* Header */}
              <div className="mb-3 flex items-start justify-between">
                <div>
                  <div className="mb-1">
                    {renderStarRating(review.overallRating)}
                  </div>
                  {review.title && (
                    <h4 className="text-lg font-semibold">{review.title}</h4>
                  )}
                  <div className="text-muted-foreground mt-1 flex items-center gap-2 text-sm">
                    <CalendarDays className="h-3.5 w-3.5" />
                    <span>
                      {format(new Date(review.createdAt), 'dd MMMM yyyy', {
                        locale: vi,
                      })}
                    </span>
                    <Separator orientation="vertical" className="h-4" />
                    <span>Site: {review.site.name}</span>
                  </div>
                </div>
              </div>

              {/* Comment */}
              <p className="text-muted-foreground mb-3 text-sm leading-relaxed">
                {review.comment}
              </p>

              {/* Pros & Cons */}
              {(review.pros?.length || review.cons?.length) && (
                <div className="mb-3 grid gap-3 md:grid-cols-2">
                  {review.pros && review.pros.length > 0 && (
                    <div>
                      <Badge
                        variant="outline"
                        className="mb-2 border-green-200 bg-green-50 text-green-700"
                      >
                        👍 Điểm tốt
                      </Badge>
                      <ul className="text-muted-foreground space-y-1 text-sm">
                        {review.pros.map((pro, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-green-500">•</span>
                            <span>{pro}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {review.cons && review.cons.length > 0 && (
                    <div>
                      <Badge
                        variant="outline"
                        className="mb-2 border-orange-200 bg-orange-50 text-orange-700"
                      >
                        👎 Điểm chưa tốt
                      </Badge>
                      <ul className="text-muted-foreground space-y-1 text-sm">
                        {review.cons.map((con, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-orange-500">•</span>
                            <span>{con}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Rating Breakdown */}
              <div className="mb-3 grid grid-cols-2 gap-2 rounded-lg bg-gray-50 p-3 text-sm md:grid-cols-3">
                <div>
                  <div className="text-muted-foreground mb-1 text-xs">
                    Vị trí
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.propertyRatings.location}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1 text-xs">
                    Giao tiếp
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.propertyRatings.communication}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1 text-xs">
                    Giá trị
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.propertyRatings.value}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1 text-xs">
                    Vệ sinh
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.siteRatings.cleanliness}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1 text-xs">
                    Độ chính xác
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.siteRatings.accuracy}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1 text-xs">
                    Tiện nghi
                  </div>
                  <div className="flex items-center gap-1">
                    <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                    <span className="font-semibold">
                      {review.siteRatings.amenities}
                    </span>
                  </div>
                </div>
              </div>

              {/* Host Response */}
              {review.hostResponse && (
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3">
                  <div className="mb-1 flex items-center gap-2">
                    <Badge className="bg-primary text-white">
                      Phản hồi từ chủ nhà
                    </Badge>
                    <span className="text-muted-foreground text-xs">
                      {format(
                        new Date(review.hostResponse.respondedAt),
                        'dd/MM/yyyy',
                      )}
                    </span>
                  </div>
                  <p className="text-sm text-primary dark:text-primary-300">
                    {review.hostResponse.comment}
                  </p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-4">
      <div className="mb-6">
        <h2 className="text-2xl font-bold">Đánh giá của tôi</h2>
        <p className="text-muted-foreground mt-1 text-sm">
          {reviews.length} đánh giá
        </p>
      </div>

      <div className="space-y-4">
        {reviews.map(review => (
          <ReviewCard key={review._id} review={review} />
        ))}
      </div>
    </div>
  );
}
