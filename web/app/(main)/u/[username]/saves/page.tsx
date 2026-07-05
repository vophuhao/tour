'use client';

import { useMounted } from '@/hooks/useMounted';
import { FavoriteButton } from '@/components/property/FavoriteButton';
import { SiteFavoriteButton } from '@/components/site/SiteFavoriteButton';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useFavorites } from '@/hooks/useFavorite';
import { useAuthStore } from '@/store/auth.store';
import { Calendar, Heart, Loader2, MapPin, Users } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { forumApi } from '@/lib/forumApi';

export default function SavesPage() {
  const params = useParams();
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();
  const isOwnProfile = currentUser?.username === username;

  const { data: allFavorites, isLoading: isLoadingFavorites } = useFavorites('all');

  const { data: likedPosts, isLoading: isLoadingLiked } = useQuery({
    queryKey: ['my-liked-posts', currentUser?._id],
    queryFn: async () => {
      const res: any = await forumApi.getLikedPosts();
      return res?.data ?? res ?? [];
    },
    enabled: isOwnProfile && !!currentUser?._id,
  });

  const isLoading = isLoadingFavorites || isLoadingLiked;

  const mounted = useMounted();

  const propertyFavorites = allFavorites?.filter(fav => fav.property) || [];
  const siteFavorites = allFavorites?.filter(fav => fav.site) || [];
  const postFavorites = likedPosts || [];

  const formatPrice = (price: number) => {
    if (price >= 1000000) {
      return `${Math.round(price / 1000000)}tr`;
    } else if (price >= 1000) {
      return `${Math.round(price / 1000)}k`;
    }
    return `${price}`;
  };

  const getCoverPhoto = (photos: any[]) => {
    const coverPhoto = photos?.find((p: any) => p.isCover);
    if (coverPhoto) return coverPhoto.url;
    return photos?.[0]?.url || photos?.[0] || '/placeholder-campsite.jpg';
  };

  if (!mounted || isLoading) {
    return (
      <div className="space-y-6">
        {/* Header Skeleton */}
        <div className="animate-pulse space-y-2">
          <div className="h-8 w-48 bg-slate-200 dark:bg-slate-800 rounded" />
          <div className="h-4 w-64 bg-slate-200 dark:bg-slate-800 rounded" />
        </div>

        {/* Tabs Skeleton */}
        <div className="flex gap-2 pb-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-9 w-24 bg-slate-200 dark:bg-slate-800 rounded-lg animate-pulse" />
          ))}
        </div>

        {/* Grid Skeleton */}
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm animate-pulse p-4 space-y-4">
              <div className="h-48 w-full bg-slate-200 dark:bg-slate-800 rounded-xl" />
              <div className="space-y-3">
                <div className="h-4 w-12 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-6 w-3/4 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-4 w-1/2 bg-slate-200 dark:bg-slate-800 rounded" />
                <div className="h-5 w-1/3 bg-slate-200 dark:bg-slate-800 rounded" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!isOwnProfile) {
    return (
      <div className="py-12 text-center">
        <Heart className="text-muted-foreground mx-auto h-12 w-12" />
        <h2 className="mt-4 text-lg font-semibold">Danh sách riêng tư</h2>
        <p className="text-muted-foreground mt-2">
          Bạn không thể xem danh sách đã lưu của người dùng khác
        </p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="mb-2 flex items-center gap-2 text-2xl font-bold">
          Danh sách của tôi
        </h1>
      </div>

      {/* Tabs for Properties, Sites, and Liked Posts */}
      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6">
          <TabsTrigger value="all">
            Tất cả ({allFavorites?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="properties">
            Khu đất ({propertyFavorites.length})
          </TabsTrigger>
          <TabsTrigger value="sites">
            Địa điểm ({siteFavorites.length})
          </TabsTrigger>
          <TabsTrigger value="posts">
            Bài viết đã thích ({postFavorites.length})
          </TabsTrigger>
        </TabsList>

        {/* All Favorites */}
        <TabsContent value="all">
          {allFavorites && allFavorites.length > 0 ? (
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
              {allFavorites.map(favorite => {
                const item = favorite.property || favorite.site;
                const isProperty = !!favorite.property;

                return (
                  <Card
                    key={favorite._id}
                    className="group overflow-hidden transition-shadow hover:shadow-lg"
                  >
                    <Link
                      href={
                        isProperty
                          ? `/land/${item?.slug || item?._id}`
                          : `/sites/${item?.slug || item?._id}`
                      }
                    >
                      <div className="relative h-48 w-full overflow-hidden">
                        {/* Favorite Button */}
                        <div className="absolute top-3 left-3 z-10">
                          {isProperty ? (
                            <FavoriteButton
                              propertyId={item?._id || ''}
                              className="bg-white/90 backdrop-blur-sm hover:bg-white"
                            />
                          ) : (
                            <SiteFavoriteButton
                              siteId={item?._id || ''}
                              className="bg-white/90 backdrop-blur-sm hover:bg-white"
                            />
                          )}
                        </div>

                        {/* Type Badge */}
                        <div className="absolute top-3 right-3 z-10">
                          <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-bold shadow-sm backdrop-blur-sm ${isProperty
                            ? "bg-blue-600/90 text-white"
                            : "bg-white/90 text-slate-800 dark:bg-slate-900/90 dark:text-slate-200"
                            }`}>
                            {isProperty ? 'Khu đất' : 'Địa điểm'}
                          </span>
                        </div>

                        <Image
                          src={getCoverPhoto(
                            (isProperty
                              ? favorite.property?.photos
                              : [favorite.site?.photos?.[0]]) as any,
                          )}
                          alt={item?.name || ''}
                          fill
                          sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
                          className="object-cover transition-transform group-hover:scale-105"
                        />
                      </div>
                    </Link>

                    <CardContent className="space-y-2 p-4">
                      {/* Rating */}
                      {isProperty && favorite.property?.stats?.averageRating ? (
                        <div className="flex items-center gap-1">
                          <span className="text-base">👍</span>
                          <span className="text-sm font-semibold">
                            {Math.round(
                              (favorite.property.stats.averageRating / 5) * 100,
                            )}
                            %
                          </span>
                          <span className="text-muted-foreground text-xs">
                            ({favorite.property.stats.totalReviews || 0})
                          </span>
                        </div>
                      ) : null}

                      {/* Name */}
                      <h3 className="line-clamp-1 text-lg font-semibold">
                        {item?.name}
                      </h3>

                      {/* Location */}
                      <div className="text-muted-foreground flex items-center gap-1 text-sm">
                        <MapPin className="h-4 w-4" />
                        <span className="line-clamp-1">
                          {isProperty
                            ? `${favorite.property?.location?.city}, ${favorite.property?.location?.state}`
                            : `${favorite.site?.propertyRef}`}
                        </span>
                      </div>

                      {/* Capacity for Site */}
                      {!isProperty && favorite.site?.capacity && (
                        <div className="text-muted-foreground flex items-center gap-1 text-sm">
                          <Users className="h-4 w-4" />
                          <span>
                            Tối đa {favorite.site.capacity.maxGuests} khách
                          </span>
                        </div>
                      )}

                      {/* Price */}
                      <div className="pt-1">
                        <span className="text-muted-foreground text-sm">
                          từ{' '}
                        </span>
                        <span className="text-lg font-bold">
                          {isProperty
                            ? formatPrice(
                              favorite.property?.pricing?.minPrice || 0,
                            )
                            : formatPrice(
                              favorite.site?.pricing?.basePrice || 0,
                            )}
                          ₫
                        </span>
                        <span className="text-muted-foreground text-sm">
                          {' '}
                          / đêm
                        </span>
                      </div>

                      {/* Notes */}
                      {favorite.notes && (
                        <div className="mt-3 rounded-md bg-gray-50 p-3">
                          <p className="text-sm text-gray-700 italic">
                            "{favorite.notes}"
                          </p>
                        </div>
                      )}

                      {/* Saved Date */}
                      <div className="text-muted-foreground flex items-center gap-1 pt-2 text-xs">
                        <Calendar className="h-3 w-3" />
                        <span>
                          Đã lưu{' '}
                          {new Date(favorite.createdAt).toLocaleDateString(
                            'vi-VN',
                          )}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ) : (
            <EmptyState />
          )}
        </TabsContent>

        {/* Properties Only */}
        <TabsContent value="properties">
          {propertyFavorites.length > 0 ? (
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
              {propertyFavorites.map(favorite => (
                <PropertyCard
                  key={favorite._id}
                  favorite={favorite}
                  getCoverPhoto={getCoverPhoto}
                  formatPrice={formatPrice}
                />
              ))}
            </div>
          ) : (
            <EmptyState type="property" />
          )}
        </TabsContent>

        {/* Sites Only */}
        <TabsContent value="sites">
          {siteFavorites.length > 0 ? (
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
              {siteFavorites.map(favorite => (
                <SiteCard
                  key={favorite._id}
                  favorite={favorite}
                  formatPrice={formatPrice}
                />
              ))}
            </div>
          ) : (
            <EmptyState type="site" />
          )}
        </TabsContent>

        {/* Liked Posts Only */}
        <TabsContent value="posts">
          {postFavorites.length > 0 ? (
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
              {postFavorites.map((post: any) => (
                <LikedPostCard key={post._id} post={post} />
              ))}
            </div>
          ) : (
            <EmptyStatePosts />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function PropertyCard({
  favorite,
  getCoverPhoto,
  formatPrice,
}: {
  favorite: any;
  getCoverPhoto: (photos: any[]) => string;
  formatPrice: (price: number) => string;
}) {
  return (
    <Card className="group overflow-hidden transition-shadow hover:shadow-lg">
      <Link href={`/land/${favorite.property?.slug || favorite.property?._id}`}>
        <div className="relative h-48 w-full overflow-hidden">
          <div className="absolute top-3 left-3 z-10">
            <FavoriteButton
              propertyId={favorite.property?._id || ''}
              className="bg-white/90 backdrop-blur-sm hover:bg-white"
            />
          </div>
          <Image
            src={getCoverPhoto(favorite.property?.photos)}
            alt={favorite.property?.name || ''}
            fill
            sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
            className="object-cover transition-transform group-hover:scale-105"
          />
        </div>
      </Link>

      <CardContent className="space-y-2 p-4">
        {!!favorite.property?.stats?.averageRating && (
          <div className="flex items-center gap-1">
            <span className="text-base">👍</span>
            <span className="text-sm font-semibold">
              {Math.round((favorite.property.stats.averageRating / 5) * 100)}%
            </span>
            <span className="text-muted-foreground text-xs">
              ({favorite.property.stats.totalReviews || 0})
            </span>
          </div>
        )}

        <h3 className="line-clamp-1 text-lg font-semibold">
          {favorite.property?.name}
        </h3>

        <div className="text-muted-foreground flex items-center gap-1 text-sm">
          <MapPin className="h-4 w-4" />
          <span>
            {favorite.property?.location?.city},{' '}
            {favorite.property?.location?.state}
          </span>
        </div>

        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          <span>{favorite.property?.stats?.totalSites || 0} địa điểm</span>
          <span>·</span>
          <span>
            {favorite.property?.propertyType === 'private_land'
              ? 'Đất tư nhân'
              : favorite.property?.propertyType === 'campground'
                ? 'Khu cắm trại'
                : favorite.property?.propertyType === 'farm'
                  ? 'Trang trại'
                  : 'Khu nghỉ dưỡng'}
          </span>
        </div>

        <div className="pt-1">
          <span className="text-muted-foreground text-sm">từ </span>
          <span className="text-lg font-bold">
            {formatPrice(favorite.property?.pricing?.minPrice || 0)}₫
          </span>
          <span className="text-muted-foreground text-sm"> / đêm</span>
        </div>

        {favorite.notes && (
          <div className="mt-3 rounded-md bg-gray-50 p-3">
            <p className="text-sm text-gray-700 italic">"{favorite.notes}"</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SiteCard({
  favorite,
  formatPrice,
}: {
  favorite: any;
  formatPrice: (price: number) => string;
}) {
  return (
    <Card className="group overflow-hidden transition-shadow hover:shadow-lg">
      <Link href={`/sites/${favorite.site?.slug || favorite.site?._id}`}>
        <div className="relative h-48 w-full overflow-hidden">
          <div className="absolute top-3 left-3 z-10">
            <SiteFavoriteButton
              siteId={favorite.site?._id || ''}
              className="bg-white/90 backdrop-blur-sm hover:bg-white"
            />
          </div>
          <Image
            src={favorite.site?.photos?.[0] || '/placeholder-campsite.jpg'}
            alt={favorite.site?.name || ''}
            fill
            sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
            className="object-cover transition-transform group-hover:scale-105"
          />
        </div>
      </Link>

      <CardContent className="space-y-2 p-4">
        <h3 className="line-clamp-1 text-lg font-semibold">
          {favorite.site?.name}
        </h3>

        <div className="text-muted-foreground flex items-center gap-1 text-sm">
          <span>
            {favorite.site?.siteType === 'tent'
              ? 'Lều'
              : favorite.site?.siteType === 'rv'
                ? 'RV'
                : favorite.site?.siteType === 'cabin'
                  ? 'Cabin'
                  : 'Khác'}
          </span>
        </div>

        {favorite.site?.capacity && (
          <div className="text-muted-foreground flex items-center gap-1 text-sm">
            <Users className="h-4 w-4" />
            <span>Tối đa {favorite.site.capacity.maxGuests} khách</span>
          </div>
        )}

        <div className="pt-1">
          <span className="text-lg font-bold">
            {formatPrice(favorite.site?.pricing?.basePrice || 0)}₫
          </span>
          <span className="text-muted-foreground text-sm"> / đêm</span>
        </div>

        {favorite.notes && (
          <div className="mt-3 rounded-md bg-gray-50 p-3">
            <p className="text-sm text-gray-700 italic">"{favorite.notes}"</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function EmptyState({ type }: { type?: 'property' | 'site' }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <Heart className="mb-4 h-16 w-16 text-gray-300" />
        <h3 className="mb-2 text-xl font-semibold text-gray-700">
          {type === 'property'
            ? 'Chưa có khu đất yêu thích'
            : type === 'site'
              ? 'Chưa có địa điểm yêu thích'
              : 'Chưa lưu địa điểm nào'}
        </h3>
        <p className="text-muted-foreground mb-6 text-center">
          Hãy khám phá và lưu những địa điểm bạn yêu thích
          <br />
          để dễ dàng tìm lại sau này
        </p>
        <Button asChild className="bg-primary hover:bg-primary/90 cursor-pointer">
          <Link href="/search">Khám phá địa điểm</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

function EmptyStatePosts() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16">
        <Heart className="mb-4 h-16 w-16 text-gray-300" />
        <h3 className="mb-2 text-xl font-semibold text-gray-700">
          Chưa có bài viết yêu thích
        </h3>
        <p className="text-muted-foreground mb-6 text-center">
          Hãy khám phá diễn đàn và thả tim những bài viết thú vị
        </p>
        <Button asChild className="bg-primary hover:bg-primary/90 cursor-pointer">
          <Link href="/forum">Khám phá diễn đàn</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

function LikedPostCard({ post }: { post: any }) {
  const getPostImage = (p: any) => {
    if (p.imageUrl) return p.imageUrl;
    if (p.images && p.images.length > 0) return p.images[0];
    if (p.content) {
      const match = p.content.match(/<img[^>]+src=["']([^"']+)["']/i);
      if (match && match[1]) {
        return match[1];
      }
    }
    return null;
  };

  const displayImage = getPostImage(post);

  return (
    <Card className="group overflow-hidden transition-shadow hover:shadow-lg">
      <Link href={`/forum/${post.slug || post._id}`}>
        <div className="relative h-48 w-full overflow-hidden bg-muted">
          {displayImage ? (
            <Image
              src={displayImage}
              alt={post.title || ''}
              fill
              sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
              className="object-cover transition-transform group-hover:scale-105"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center text-4xl bg-orange-50 dark:bg-slate-900">
              🏕️
            </div>
          )}
          <div className="absolute top-3 left-3 z-10">
            <span className="flex items-center gap-1 rounded-full bg-white/90 px-3 py-1 text-xs font-bold text-rose-500 shadow-sm backdrop-blur-sm dark:bg-slate-900/90">
              <Heart className="h-3 w-3 fill-rose-500 text-rose-500" />
              Đã thích
            </span>
          </div>
          {post.subject && (
            <div className="absolute top-3 right-3 z-10">
              <span className="flex items-center rounded-full bg-white/90 px-3 py-1 text-xs font-bold text-slate-800 shadow-sm backdrop-blur-sm dark:bg-slate-900/90 dark:text-slate-200">
                {post.subject}
              </span>
            </div>
          )}
        </div>
      </Link>

      <CardContent className="space-y-3 p-4">
        {/* Author info */}
        <div className="flex items-center gap-2">
          {post.userId?.avatarUrl ? (
            <img
              src={post.userId.avatarUrl}
              alt={post.userId.name || ''}
              className="h-5 w-5 rounded-full object-cover"
            />
          ) : (
            <div className="flex h-5 w-5 items-center justify-center rounded-full bg-slate-200 text-[10px] dark:bg-slate-800">
              👤
            </div>
          )}
          <span className="text-xs text-muted-foreground font-medium">
            {post.userId?.name || 'Thành viên'}
          </span>
        </div>

        <h3 className="line-clamp-2 text-base font-semibold leading-snug group-hover:text-primary transition-colors min-h-[44px]">
          <Link href={`/forum/${post.slug || post._id}`}>
            {post.title}
          </Link>
        </h3>

        {/* Stats */}
        <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-850 pt-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1">
              <Heart className="h-3.5 w-3.5" />
              {post.likeCount ?? post.likes?.length ?? 0}
            </span>
            <span className="flex items-center gap-1">
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
              {post.commentCount ?? 0}
            </span>
          </div>
          <div className="flex items-center gap-1">
            <Calendar className="h-3 w-3" />
            <span>
              {new Date(post.createdAt).toLocaleDateString('vi-VN')}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
