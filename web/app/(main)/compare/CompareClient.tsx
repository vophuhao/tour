'use client';

import { useEffect, useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { getCompareProperties } from '@/lib/property-site-api';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Trash2,
  GitCompare,
  ArrowLeft,
  Star,
  Check,
  X,
  ExternalLink,
  Users,
  Maximize2,
  Compass,
  Home,
  Sparkles,
} from 'lucide-react';
import { toast } from 'sonner';

interface CompareClientProps {
  initialIds: string;
}

export function CompareClient({ initialIds }: CompareClientProps) {
  const router = useRouter();
  const [properties, setProperties] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  useEffect(() => {
    let active = true;

    const loadProperties = async (idsString: string) => {
      if (!idsString) {
        if (active) {
          setProperties([]);
          setLoading(false);
        }
        return;
      }

      try {
        if (active) {
          setLoading(true);
          setError(null);
        }
        const data = await getCompareProperties(idsString);
        if (active) {
          setProperties(data || []);
        }
      } catch (err: any) {
        console.error('Failed to load compare list:', err);
        if (active) {
          setError('Có lỗi xảy ra khi tải dữ liệu so sánh. Vui lòng thử lại.');
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    loadProperties(initialIds);

    return () => {
      active = false;
    };
  }, [initialIds]);

  // Synchronize with local storage if state updates from user removals
  const handleRemove = (id: string) => {
    if (typeof window === 'undefined') return;

    const stored = localStorage.getItem('campsite_compare_ids');
    let compareIds: string[] = stored ? JSON.parse(stored) : [];
    compareIds = compareIds.filter((item) => item !== id);
    localStorage.setItem('campsite_compare_ids', JSON.stringify(compareIds));

    // Dispatch event to update CompareDrawer
    window.dispatchEvent(new Event('compare-updated'));

    toast.success('Đã xóa địa điểm khỏi danh sách so sánh');

    // Update URL query param without full page reload
    const newIdsString = compareIds.join(',');
    startTransition(() => {
      router.replace(newIdsString ? `/compare?ids=${newIdsString}` : '/compare');
    });
  };

  const handleClearAll = () => {
    if (typeof window === 'undefined') return;

    localStorage.setItem('campsite_compare_ids', JSON.stringify([]));
    window.dispatchEvent(new Event('compare-updated'));
    toast.success('Đã xóa tất cả địa điểm so sánh');

    startTransition(() => {
      router.replace('/compare');
    });
  };

  // Helper formatting functions
  const formatPrice = (price: number) => {
    if (!price) return 'Liên hệ';
    return new Intl.NumberFormat('vi-VN').format(price) + ' ₫';
  };

  const getCoverPhoto = (property: any) => {
    const coverPhoto = property.photos?.find((p: any) => p.isCover);
    if (coverPhoto) return coverPhoto.url;
    return property.photos?.[0]?.url || '/assets/images/hero.jpg';
  };

  const getLandSizeDisplay = (property: any) => {
    if (!property.landSize || !property.landSize.value) return 'Chưa cập nhật';
    const { value, unit } = property.landSize;
    return `${value} ${unit === 'acres' ? 'acres' : unit === 'hectares' ? 'ha' : 'm²'}`;
  };

  const translatePropertyType = (type: string) => {
    const map: Record<string, string> = {
      private_land: 'Đất tư nhân',
      campground: 'Khu cắm trại',
      ranch: 'Trang trại chăn nuôi',
      farm: 'Trang trại',
      retreat_center: 'Khu nghỉ dưỡng',
    };
    return map[type] || type;
  };

  const translateAccommodationType = (type: string) => {
    const map: Record<string, string> = {
      tent: 'Lều cắm trại',
      rv: 'Xe cắm trại (RV)',
      cabin: 'Nhà gỗ (Cabin)',
      yurt: 'Lều Yurt',
      treehouse: 'Nhà trên cây',
      glamping: 'Glamping',
      vehicle: 'Xe ô tô',
    };
    return map[type.toLowerCase()] || type;
  };

  const translateTerrain = (terrain: string) => {
    const map: Record<string, string> = {
      forest: 'Rừng',
      river: 'Sông / Suối',
      beach: 'Bãi biển',
      mountain: 'Núi đồi',
      desert: 'Sa mạc',
      lake: 'Hồ nước',
      meadow: 'Đồng cỏ',
      farm: 'Trang trại',
      valley: 'Thung lũng',
    };
    return map[terrain.toLowerCase()] || terrain;
  };

  // Aggregate all unique amenities from compared properties
  const allUniqueAmenities = Array.from(
    new Map(
      properties.flatMap((p) => p.amenities || []).map((a) => [a._id?.toString() || a.name, a])
    ).values()
  ) as any[];

  // Render Loading Skeletons
  if (loading) {
    return (
      <div className="space-y-8 animate-pulse">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-2">
            <div className="h-8 w-64 rounded bg-slate-200 dark:bg-slate-800" />
            <div className="h-4 w-96 rounded bg-slate-200 dark:bg-slate-800" />
          </div>
          <div className="h-10 w-32 rounded bg-slate-200 dark:bg-slate-800" />
        </div>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
          <div className="hidden space-y-4 md:block pt-48">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-12 w-full rounded bg-slate-100 dark:bg-slate-900" />
            ))}
          </div>
          {[...Array(3)].map((_, col) => (
            <div key={col} className="space-y-6 rounded-2xl border border-slate-100 p-4 dark:border-slate-800">
              <div className="relative h-44 w-full rounded-xl bg-slate-200 dark:bg-slate-800" />
              <div className="h-6 w-3/4 rounded bg-slate-200 dark:bg-slate-800" />
              <div className="h-4 w-1/2 rounded bg-slate-200 dark:bg-slate-800" />
              <div className="space-y-3 pt-4 border-t border-slate-100 dark:border-slate-800">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-8 w-full rounded bg-slate-100 dark:bg-slate-900" />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // Render Empty State
  if (properties.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <div className="glass-card mb-6 flex h-20 w-20 items-center justify-center rounded-2xl text-primary shadow-lg">
          <GitCompare className="h-10 w-10" />
        </div>
        <h1 className="text-2xl font-extrabold text-slate-800 dark:text-slate-100 md:text-3xl">
          Chưa chọn địa điểm so sánh
        </h1>
        <p className="mt-3 max-w-md text-slate-500 dark:text-slate-400">
          Danh sách so sánh hiện đang trống. Vui lòng quay lại danh sách tìm kiếm và nhấn biểu tượng so sánh trên mỗi địa điểm.
        </p>
        <Link href="/search" className="mt-8">
          <Button className="btn-primary rounded-xl px-6 py-5 font-bold shadow-lg transition-transform hover:scale-[1.02]">
            <ArrowLeft className="mr-2 h-4 w-4" /> Quay lại tìm kiếm
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header section */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <Link
            href="/search"
            className="inline-flex items-center text-xs font-semibold text-primary hover:underline"
          >
            <ArrowLeft className="mr-1 h-3.5 w-3.5" /> Quay lại trang tìm kiếm
          </Link>
          <h1 className="text-3xl font-extrabold tracking-tight text-primary md:text-4xl">
            So sánh địa điểm cắm trại
          </h1>

        </div>

        {properties.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            id="clear-all-compare-btn"
            onClick={handleClearAll}
            className="rounded-xl border-red-200 text-red-600 hover:bg-red-50 dark:border-red-900/30 dark:text-red-400 dark:hover:bg-red-950/20 font-bold self-start sm:self-center"
          >
            <Trash2 className="mr-2 h-4 w-4" /> Xóa tất cả
          </Button>
        )}
      </div>

      {/* Comparison Grid container (Horizontal Scroll on Mobile) */}
      <div className="scrollbar-hide w-full overflow-x-auto rounded-2xl border border-slate-100 bg-white shadow-xl dark:border-slate-800/80 dark:bg-slate-900/50">
        <div className="min-w-[800px]">
          {/* Main Grid structure */}
          <div className={`grid grid-cols-${properties.length + 1} divide-x divide-slate-100 dark:divide-slate-800`}>
            {/* Header Columns: Images & Title */}
            <div className="bg-slate-50/50 p-6 flex flex-col justify-end dark:bg-slate-950/20">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Thông số so sánh
              </span>
            </div>

            {properties.map((property) => (
              <div
                key={property._id}
                className="relative p-6 flex flex-col justify-between group hover:bg-slate-50/30 dark:hover:bg-slate-950/10 transition-colors"
              >
                {/* Remove button */}
                <button
                  onClick={() => handleRemove(property._id)}
                  id={`remove-property-${property._id}`}
                  className="absolute top-4 right-4 z-10 flex h-8 w-8 items-center justify-center rounded-full bg-white/90 text-slate-400 shadow-md backdrop-blur-sm transition-all hover:bg-red-500 hover:text-white dark:bg-slate-800/90 dark:text-slate-500 dark:hover:bg-red-500 dark:hover:text-white"
                  title="Xóa khỏi so sánh"
                >
                  <X className="h-4 w-4" />
                </button>

                <div className="space-y-4">
                  <div className="relative h-44 w-full overflow-hidden rounded-xl bg-slate-100 shadow-inner group-hover:shadow-md transition-shadow dark:bg-slate-800">
                    <img
                      src={getCoverPhoto(property)}
                      alt={property.name}
                      className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Badge variant="secondary" className="rounded-md font-bold px-2 py-0.5 text-xs bg-primary/10 text-primary">
                      {translatePropertyType(property.propertyType)}
                    </Badge>
                    <h3 className="line-clamp-2 text-lg font-bold text-slate-800 dark:text-slate-200 leading-snug">
                      {property.name}
                    </h3>
                    <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                      <Compass className="h-3.5 w-3.5" />
                      <span>
                        {property.location?.city}, {property.location?.state}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Host Info */}
                {property.host && (
                  <div className="mt-4 flex items-center gap-2 border-t border-slate-100 pt-3 dark:border-slate-800/60">
                    <div className="relative h-6 w-6 overflow-hidden rounded-full bg-slate-100">
                      {property.host.avatarUrl ? (
                        <img
                          src={property.host.avatarUrl}
                          alt={property.host.username || 'Host'}
                          className="h-full w-full object-cover"
                        />
                      ) : (
                        <div className="flex h-full w-full items-center justify-center bg-slate-200 text-[10px] font-bold text-slate-600 dark:bg-slate-700 dark:text-slate-400">
                          {property.host.username?.charAt(0).toUpperCase() || 'H'}
                        </div>
                      )}
                    </div>
                    <span className="text-xs text-slate-600 dark:text-slate-400">
                      Được đăng bởi <strong className="font-semibold text-slate-700 dark:text-slate-300">{property.host.username}</strong>
                    </span>
                  </div>
                )}
              </div>
            ))}

            {/* ROW: PRICE */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Giá thấp nhất</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div>
                  <span className="text-2xl font-black text-primary">
                    {formatPrice(property.minPrice)}
                  </span>
                  <span className="text-xs text-slate-500 dark:text-slate-400"> / đêm</span>
                </div>
              </div>
            ))}

            {/* ROW: RATING */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Đánh giá</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div className="flex items-center gap-1.5">
                  {property.rating?.average || property.stats?.averageRating ? (
                    <>
                      <div className="flex items-center gap-1 rounded-lg bg-amber-50 px-2 py-1 text-amber-700 dark:bg-amber-950/20 dark:text-amber-400">
                        <Star className="h-4 w-4 fill-amber-500 text-amber-500" />
                        <span className="text-sm font-bold">
                          {property.rating?.average || property.stats?.averageRating}
                        </span>
                      </div>
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        ({property.rating?.count || property.stats?.totalReviews || 0} nhận xét)
                      </span>
                    </>
                  ) : (
                    <span className="text-xs text-slate-400">Chưa có đánh giá</span>
                  )}
                </div>
              </div>
            ))}

            {/* ROW: LAND SIZE */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Diện tích khuôn viên</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                  <Maximize2 className="h-4 w-4 text-slate-400" />
                  <span>{getLandSizeDisplay(property)}</span>
                </div>
              </div>
            ))}

            {/* ROW: TOTAL SITES */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Số điểm cắm trại (Sites)</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                  <Home className="h-4 w-4 text-slate-400" />
                  <span className="font-semibold">{property.totalSites || 0} khu vực</span>
                </div>
              </div>
            ))}

            {/* ROW: MAX GUESTS */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Sức chứa tối đa</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                  <Users className="h-4 w-4 text-slate-400" />
                  <span className="font-semibold">Lên tới {property.maxGuests || 0} người</span>
                </div>
              </div>
            ))}

            {/* ROW: TERRAIN */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Địa hình</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div className="flex flex-wrap gap-1">
                  {property.terrains && property.terrains.length > 0 ? (
                    property.terrains.map((terrain: string) => (
                      <Badge
                        key={terrain}
                        variant="outline"
                        className="rounded-md bg-slate-50 border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 text-xs px-2 py-0.5 font-medium"
                      >
                        {translateTerrain(terrain)}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-slate-400">Không có thông tin</span>
                  )}
                </div>
              </div>
            ))}

            {/* ROW: ACCOMMODATION TYPES */}
            <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">Hình thức lưu trú</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-4 flex items-center">
                <div className="flex flex-wrap gap-1">
                  {property.accommodationTypes && property.accommodationTypes.length > 0 ? (
                    property.accommodationTypes.map((type: string) => (
                      <Badge
                        key={type}
                        variant="outline"
                        className="rounded-md bg-emerald-50/30 border-emerald-100 text-emerald-700 dark:bg-emerald-950/10 dark:border-emerald-900/30 dark:text-emerald-400 text-xs px-2 py-0.5 font-medium"
                      >
                        {translateAccommodationType(type)}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-slate-400">Không có thông tin</span>
                  )}
                </div>
              </div>
            ))}

            {/* SECTION: AMENITIES */}
            <div className="col-span-full bg-slate-100/50 px-6 py-2.5 text-xs font-bold uppercase tracking-wider text-slate-500 dark:bg-slate-950/40 dark:text-slate-400">
              Tiện nghi & Dịch vụ
            </div>

            {/* Render Row for each unique amenity */}
            {allUniqueAmenities.length > 0 ? (
              allUniqueAmenities.map((amenity) => {
                const amenityId = amenity._id?.toString() || amenity.name;
                return (
                  <div key={amenityId} className="contents">
                    {/* Amenity Label Column */}
                    <div className="bg-slate-50/50 px-6 py-3.5 flex items-center gap-2 dark:bg-slate-950/20">
                      {amenity.icon ? (
                        <span className="text-base" role="img" aria-label={amenity.name}>
                          {amenity.icon.startsWith('http') ? (
                            <img src={amenity.icon} alt={amenity.name} className="h-4 w-4 object-contain inline-block" />
                          ) : (
                            <span className="text-slate-600 dark:text-slate-300">{amenity.icon}</span>
                          )}
                        </span>
                      ) : (
                        <Sparkles className="h-3.5 w-3.5 text-slate-400" />
                      )}
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                        {amenity.name}
                      </span>
                    </div>

                    {/* Property Columns - Has/HasNot check */}
                    {properties.map((property) => {
                      const hasAmenity = property.amenities?.some(
                        (a: any) => (a._id?.toString() || a.name) === amenityId
                      );
                      return (
                        <div key={property._id} className="px-6 py-3.5 flex items-center">
                          {hasAmenity ? (
                            <div className="flex items-center gap-1.5 text-sm font-medium text-emerald-600 dark:text-emerald-400">
                              <div className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/30">
                                <Check className="h-3 w-3 stroke-[3]" />
                              </div>
                              <span>Có</span>
                            </div>
                          ) : (
                            <div className="flex items-center gap-1.5 text-sm text-slate-400">
                              <div className="flex h-5 w-5 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800">
                                <X className="h-3 w-3" />
                              </div>
                              <span>Không</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                );
              })
            ) : (
              <>
                <div className="bg-slate-50/50 px-6 py-4 flex items-center dark:bg-slate-950/20">
                  <span className="text-sm font-medium text-slate-500">Tiện nghi</span>
                </div>
                {properties.map((property) => (
                  <div key={property._id} className="px-6 py-4 flex items-center text-sm text-slate-400">
                    Không có thông tin tiện nghi
                  </div>
                ))}
              </>
            )}

            {/* ROW: ACTIONS */}
            <div className="bg-slate-50/50 px-6 py-6 flex items-center dark:bg-slate-950/20">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Hành động</span>
            </div>
            {properties.map((property) => (
              <div key={property._id} className="px-6 py-6 flex items-center">
                <Link href={`/land/${property.slug || property._id}`} className="w-full">
                  <Button className="btn-primary w-full rounded-xl py-5 font-bold shadow-md hover:shadow-lg transition-all group-hover:scale-[1.01]">
                    Đặt chỗ ngay <ExternalLink className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
