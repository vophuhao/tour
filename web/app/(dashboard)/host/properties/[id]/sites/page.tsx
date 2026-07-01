/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { useEffect, useMemo, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import {
  Plus,
  ArrowLeft,
  Settings,
  Eye,
  Trash2,
  Search,
  Filter,
  MoreVertical,
  DollarSign,
  Users,
  Car,
  Calendar,
  Home,
  Tent,
  MapPin,
  Star,
  Map as MapIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from 'sonner';
import {
  getPropertyById,
  deleteSite,
  getSitesByProperty,
} from '@/lib/client-actions';
import dynamic from 'next/dynamic';
import { Skeleton } from '@/components/ui/skeleton';

// Dynamically import SiteMap
const SiteMap = dynamic(
  () => import('@/components/property/site-map').then(mod => mod.SiteMap),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-full w-full items-center justify-center bg-gray-100">
        <div className="text-center">
          <Skeleton className="mx-auto mb-4 h-12 w-12 rounded-full" />
          <p className="text-sm text-gray-500">Đang tải bản đồ...</p>
        </div>
      </div>
    ),
  },
);

export default function PropertySitesPage() {
  const params = useParams() as any;
  const router = useRouter();
  const propertyId = params?.id ?? params?.propertyId;

  const [property, setProperty] = useState<any | null>(null);
  const [sites, setSites] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [siteToDelete, setSiteToDelete] = useState<{
    id: string;
    name: string;
  } | null>(null);

  // Map states
  const [viewMode, setViewMode] = useState<'list' | 'map'>('list');
  const [selectedSite, setSelectedSite] = useState<any | null>(null);
  const [hoveredSite, setHoveredSite] = useState<any | null>(null);

  useEffect(() => {
    if (!propertyId) return;
    let mounted = true;

    setLoading(true);
    (async () => {
      try {
        const p = await getPropertyById(propertyId);
        if (mounted && p?.success) setProperty(p.data ?? null);
      } catch (err) {
        console.error(err);
      } finally {
        if (mounted) setLoading(false);
      }
    })();

    return () => {
      mounted = false;
    };
  }, [propertyId]);

  const fetchSites = async () => {
    if (!propertyId) return;
    setLoading(true);
    try {
      const res = await getSitesByProperty(propertyId);

      if (res?.success) setSites(res.data.sites ?? []);
      else setSites([]);
    } catch (err) {
      console.error(err);
      setSites([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSites();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyId]);

  const handleDeleteSite = async () => {
    if (!siteToDelete || !propertyId) return;
    try {
      await deleteSite(propertyId, siteToDelete.id);
      toast.success(`Đã xóa site "${siteToDelete.name}" thành công!`);
      setDeleteDialogOpen(false);
      setSiteToDelete(null);
      await fetchSites();
    } catch (error: any) {
      console.error(error);
      toast.error(error?.message || 'Có lỗi xảy ra khi xóa site');
    }
  };

  const filteredSites = useMemo(() => {
    if (!sites) return [];
    return sites.filter(site => {
      const matchesSearch =
        !searchQuery ||
        (site.name ?? '')
          .toString()
          .toLowerCase()
          .includes(searchQuery.toLowerCase());
      const matchesStatus =
        statusFilter === 'all' ||
        site.status === statusFilter;
      const matchesType =
        typeFilter === 'all' || site.accommodationType === typeFilter;
      return matchesSearch && matchesStatus && matchesType;
    });
  }, [sites, searchQuery, statusFilter, typeFilter]);

  const statusConfig = {
    active: {
      label: 'Sẵn sàng',
      color: 'bg-green-100 text-green-800 border-green-200',
      dot: 'bg-green-500',
    },
    inactive: {
      label: 'Tạm ẩn',
      color: 'bg-slate-100 text-slate-800 border-slate-200',
      dot: 'bg-slate-500',
    },
    blocked: {
      label: 'Bị khóa',
      color: 'bg-red-100 text-red-800 border-red-200',
      dot: 'bg-red-500',
    },
    suspended: {
      label: 'Bị khóa',
      color: 'bg-red-100 text-red-800 border-red-200',
      dot: 'bg-red-500',
    },
  };

  const siteTypeLabels: any = {
    tent: 'Tent Site',
    rv: 'RV Site',
    cabin: 'Cabin',
    glamping: 'Glamping',
    group: 'Group Site',
    yurt: 'Yurt',
    treehouse: 'Treehouse',
    vehicle: 'Vehicle',
  };

  // Calculate stats
  const stats = useMemo(() => {
    if (!sites) return null;
    const totalSites = sites.length;
    const activeSites = sites.filter(s => s.isActive).length;
    const availableSites = sites.filter(
      s => s.status === 'active',
    ).length;
    const totalRevenue = sites.reduce(
      (sum, s) => sum + (s.stats?.totalRevenue || 0),
      0,
    );
    const totalBookings = sites.reduce(
      (sum, s) => sum + (s.stats?.totalBookings || 0),
      0,
    );

    return {
      totalSites,
      activeSites,
      availableSites,
      totalRevenue,
      totalBookings,
    };
  }, [sites]);

  // Full site card for list view
  const renderFullSiteCard = (site: any) => {
    const statusKey = (site.status ?? 'active') as keyof typeof statusConfig;
    const status = statusConfig[statusKey] || statusConfig.active;

    const isVip = site.siteClass === 'vip';

    return (
      <Card
        key={site._id}
        className={`group overflow-hidden rounded-2xl transition-all duration-300 border-stone-200/80 bg-white shadow-sm hover:shadow-md flex flex-col h-full w-full max-w-[340px] mx-auto ${selectedSite?._id === site._id ? 'ring-2 ring-emerald-800 border-transparent shadow-md' : ''
          }`}
        onMouseEnter={() => setHoveredSite(site)}
        onMouseLeave={() => setHoveredSite(null)}
        onClick={() => setSelectedSite(site)}
      >
        {/* Image */}
        <div className="relative aspect-[16/9] w-full flex-shrink-0 bg-stone-100 overflow-hidden">
          <Image
            src={site.photos?.[0]?.url || '/placeholder.jpg'}
            alt={site.name}
            fill
            className="object-cover group-hover:scale-105 transition-transform duration-500 ease-out"
            unoptimized
          />

          {/* Badges on Image */}
          <div className="absolute left-2.5 top-2.5 flex flex-col gap-1.5">
            {isVip ? (
              <Badge className="bg-amber-50 border border-amber-300 text-amber-900 font-bold px-2 py-0.5 text-[10px] rounded-full shadow-sm">
                VIP
              </Badge>
            ) : (
              <Badge className="bg-stone-100/90 border border-stone-200/50 text-stone-850 font-semibold px-2 py-0.5 text-[10px] rounded-full shadow-sm backdrop-blur-sm">
                Thường
              </Badge>
            )}
          </div>

          {site.photos && site.photos.length > 1 && (
            <div className="absolute bottom-2.5 right-2.5 rounded-full bg-stone-900/75 px-2 py-0.5 text-[10px] text-white backdrop-blur-sm font-medium">
              +{site.photos.length - 1} ảnh
            </div>
          )}
        </div>

        {/* Content */}
        <div className="flex flex-1 flex-col justify-between p-5 bg-white">
          <div>
            {/* Title Row */}
            <div className="mb-2">
              <h3 className="text-lg font-bold text-stone-900 leading-snug group-hover:text-emerald-850 transition-colors line-clamp-1">
                {site.name}
              </h3>
            </div>

            {/* Description */}
            <p className="mb-4 line-clamp-2 text-xs text-stone-500 leading-relaxed min-h-[2.5rem]">
              {site.description || 'Chưa có mô tả chi tiết cho vị trí cắm trại này.'}
            </p>

            {/* Capacity Grid: 2x2 grid of soft sand/emerald colors */}
            <div className="mb-4 grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-2 bg-stone-50/70 border border-stone-200/30 p-2 rounded-xl">
                <Users className="h-3.5 w-3.5 text-emerald-700 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-[9px] text-stone-400 font-semibold uppercase tracking-wider leading-none">Khách</p>
                  <p className="font-bold text-stone-800 mt-0.5 truncate leading-none">
                    {site.capacity?.maxGuests || 0} người
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 bg-stone-50/70 border border-stone-200/30 p-2 rounded-xl">
                <Car className="h-3.5 w-3.5 text-stone-600 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-[9px] text-stone-400 font-semibold uppercase tracking-wider leading-none">Xe</p>
                  <p className="font-bold text-stone-800 mt-0.5 truncate leading-none">
                    {site.capacity?.maxVehicles || 0} xe
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 bg-stone-50/70 border border-stone-200/30 p-2 rounded-xl">
                <Tent className="h-3.5 w-3.5 text-stone-600 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-[9px] text-stone-400 font-semibold uppercase tracking-wider leading-none">Lều</p>
                  <p className="font-bold text-stone-800 mt-0.5 truncate leading-none">
                    {site.capacity?.maxTents ?? '-'} lều
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 bg-stone-50/70 border border-stone-200/30 p-2 rounded-xl">
                <Calendar className="h-3.5 w-3.5 text-blue-600 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-[9px] text-stone-400 font-semibold uppercase tracking-wider leading-none">Bookings</p>
                  <p className="font-bold text-stone-800 mt-0.5 truncate leading-none">
                    {site.stats?.totalBookings || 0} lượt
                  </p>
                </div>
              </div>
            </div>
          </div>

          <Separator className="my-2 bg-stone-100" />

          {/* Footer with Price and Exposed Buttons */}
          <div className="pt-2 flex flex-col gap-3">
            <div className="flex items-baseline justify-between">
              <span className="text-[10px] text-stone-400 uppercase tracking-wider font-semibold">Giá mỗi đêm</span>
              <p className="text-lg font-bold text-emerald-850">
                {new Intl.NumberFormat('vi-VN', {
                  style: 'currency',
                  currency: 'VND',
                }).format(site.pricing?.basePrice || 0)}
                <span className="text-xs text-stone-500 font-sans font-normal ml-1">/ đêm</span>
              </p>
            </div>

            {/* Direct buttons exposed side-by-side inside grid */}
            <div className="grid grid-cols-3 gap-1.5">
              <Button
                variant="outline"
                size="sm"
                className="border-stone-200 text-stone-700 hover:bg-stone-50 rounded-xl px-2 h-9 gap-1 text-[11px] font-medium w-full"
                onClick={(e) => {
                  e.stopPropagation();
                  router.push(`/host/properties/${propertyId}/sites/${site._id}`);
                }}
              >
                <Eye className="h-3.5 w-3.5 flex-shrink-0" />
                Chi tiết
              </Button>

              <Button
                variant="outline"
                size="sm"
                className="border-stone-200 text-stone-700 hover:bg-stone-50 rounded-xl px-2 h-9 gap-1 text-[11px] font-medium bg-stone-50/30 w-full"
                onClick={(e) => {
                  e.stopPropagation();
                  router.push(`/host/properties/${propertyId}/sites/${site._id}/edit`);
                }}
              >
                <Settings className="h-3.5 w-3.5 text-stone-500 flex-shrink-0" />
                Sửa
              </Button>

              <Button
                variant="ghost"
                size="sm"
                className="text-rose-600 hover:bg-rose-50 hover:text-rose-700 rounded-xl px-2 h-9 gap-1 text-[11px] font-medium w-full"
                onClick={(e) => {
                  e.stopPropagation();
                  setSiteToDelete({
                    id: site._id,
                    name: site.name,
                  });
                  setDeleteDialogOpen(true);
                }}
              >
                <Trash2 className="h-3.5 w-3.5 flex-shrink-0" />
                Xóa
              </Button>
            </div>
          </div>
        </div>
      </Card>
    );
  };

  // Compact site card for map view
  const renderCompactSiteCard = (site: any) => {
    const statusKey = (site.status ?? 'active') as keyof typeof statusConfig;
    const status = statusConfig[statusKey] || statusConfig.active;

    return (
      <Card
        key={site._id}
        className={`group cursor-pointer overflow-hidden rounded-2xl transition-all duration-300 border-stone-200/80 bg-white ${selectedSite?._id === site._id ? 'ring-2 ring-emerald-800 border-transparent shadow-md' : 'shadow-sm'
          }`}
        onMouseEnter={() => setHoveredSite(site)}
        onMouseLeave={() => setHoveredSite(null)}
        onClick={() => setSelectedSite(site)}
      >
        <div className="flex gap-3 p-3">
          {/* Compact Image */}
          <div className="relative h-24 w-32 flex-shrink-0 overflow-hidden rounded-xl bg-stone-100">
            <Image
              src={site.photos?.[0]?.url || '/placeholder.jpg'}
              alt={site.name}
              fill
              className="object-cover transition-transform duration-300 group-hover:scale-105"
              unoptimized
            />
            {site.photos && site.photos.length > 1 && (
              <div className="absolute bottom-1 right-1 rounded-full bg-stone-900/75 px-1.5 py-0.5 text-[10px] text-white backdrop-blur-sm font-medium">
                +{site.photos.length - 1}
              </div>
            )}
          </div>

          {/* Compact Content */}
          <div className="flex min-w-0 flex-1 flex-col justify-between py-0.5">
            <div className="min-w-0">
              <div className="flex items-start justify-between gap-1.5">
                <h4 className="truncate font-bold text-stone-900 group-hover:text-emerald-800 transition-colors text-sm">
                  {site.name}
                </h4>
                {/* Exposed quick small icon actions instead of vertical dots */}
                <div className="flex items-center gap-0.5 flex-shrink-0">
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 rounded-lg text-stone-500 hover:text-stone-900"
                    title="Chi tiết"
                    onClick={(e) => {
                      e.stopPropagation();
                      router.push(`/host/properties/${propertyId}/sites/${site._id}`);
                    }}
                  >
                    <Eye className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 rounded-lg text-stone-500 hover:text-stone-900"
                    title="Chỉnh sửa"
                    onClick={(e) => {
                      e.stopPropagation();
                      router.push(`/host/properties/${propertyId}/sites/${site._id}/edit`);
                    }}
                  >
                    <Settings className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7 rounded-lg text-rose-600 hover:bg-rose-50"
                    title="Xóa site"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSiteToDelete({
                        id: site._id,
                        name: site.name,
                      });
                      setDeleteDialogOpen(true);
                    }}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>

              <div className="mt-1 flex items-center gap-1.5 flex-wrap">
                <Badge className="bg-stone-50 border border-stone-200/50 text-stone-600 text-[10px] px-1.5 py-0 rounded-full font-medium shadow-none">
                  {siteTypeLabels[site.accommodationType] ?? site.accommodationType}
                </Badge>
                <Badge className={`${status.color} border text-[10px] px-1.5 py-0 rounded-full shadow-none`}>
                  <div className={`mr-1 h-1 w-1 rounded-full ${status.dot}`} />
                  {status.label}
                </Badge>
              </div>
            </div>

            {/* Compact Stats */}
            <div className="mt-1.5 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-stone-500">
                <span className="flex items-center gap-0.5">
                  <Users className="h-3 w-3 text-emerald-700" />
                  {site.capacity?.maxGuests || 0}
                </span>
                <span className="flex items-center gap-0.5">
                  <Car className="h-3 w-3 text-stone-400" />
                  {site.capacity?.maxVehicles || 0}
                </span>
              </div>
              <div className="font-serif font-bold text-emerald-800 text-sm">
                {new Intl.NumberFormat('vi-VN', {
                  style: 'currency',
                  currency: 'VND',
                  notation: 'compact',
                }).format(site.pricing?.basePrice || 0)}
              </div>
            </div>
          </div>
        </div>
      </Card>
    );
  };

  if (loading && sites === null) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center bg-slate-50 dark:bg-slate-950">
        <div className="text-center">
          <div className="mx-auto h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <p className="mt-4 text-stone-600 font-medium">Đang tải...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen text-stone-900 pb-12">
      {/* Header */}
      <div className=" top-0 z-10  border-stone-200/80">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1 min-w-0">
              <Link
                href="/host/properties"
                className="mb-3 inline-flex items-center text-sm font-medium text-stone-500 hover:text-stone-950 transition-colors"
              >
                <ArrowLeft className="mr-2 h-4 w-4 text-stone-400" />
                Quay lại danh sách khu cắm trại
              </Link>

              {property && (
                <div className="flex items-center gap-3 mt-1">

                  <div className="min-w-0">
                    <h1 className="text-2xl md:text-3xl font-bold text-stone-900 tracking-tight truncate">
                      {property.name}
                    </h1>
                  </div>
                </div>
              )}
            </div>

            <Button
              className="bg-primary hover:bg-primary/90 text-white font-medium rounded-xl px-5 py-5 text-sm transition-all flex-shrink-0 gap-2"
              onClick={() =>
                router.push(`/host/properties/${propertyId}/sites/new`)
              }
            >
              <Plus className="h-4 w-4" />
              Thêm Site mới
            </Button>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8 py-8">
        {/* Filters */}
        <Card className="mb-6 bg-white border-stone-200/80 rounded-2xl shadow-sm overflow-hidden">
          <CardContent className="pt-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-1 flex-wrap gap-3">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-stone-400" />
                  <Input
                    placeholder="Tìm kiếm theo tên site..."
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    className="pl-10 border-stone-200 focus:ring-2 focus:ring-primary/20 focus:border-primary rounded-xl h-10 text-sm"
                  />
                </div>

                <Select value={typeFilter} onValueChange={setTypeFilter}>
                  <SelectTrigger className="w-[160px] border-stone-200 rounded-xl h-10 text-sm focus:ring-emerald-800/20">
                    <Tent className="mr-2 h-4 w-4 text-stone-400" />
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl">
                    <SelectItem value="all">Tất cả loại</SelectItem>
                    <SelectItem value="tent">Tent Site</SelectItem>
                    <SelectItem value="rv">RV Site</SelectItem>
                    <SelectItem value="cabin">Cabin</SelectItem>
                    <SelectItem value="glamping">Glamping</SelectItem>
                    <SelectItem value="group">Group Site</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[160px] border-stone-200 rounded-xl h-10 text-sm focus:ring-emerald-800/20">
                    <Filter className="mr-2 h-4 w-4 text-stone-400" />
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl">
                    <SelectItem value="all">Tất cả trạng thái</SelectItem>
                    <SelectItem value="active">Sẵn sàng</SelectItem>
                    <SelectItem value="inactive">Tạm ẩn</SelectItem>
                    <SelectItem value="blocked">Bị khóa</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* View Mode Toggle */}
              <Tabs value={viewMode} onValueChange={(v: any) => setViewMode(v)} className="flex-shrink-0">
                <TabsList className="bg-stone-100 rounded-xl p-1">
                  <TabsTrigger value="list" className="gap-2 rounded-lg text-xs font-semibold text-stone-600 data-[state=active]:bg-white data-[state=active]:text-stone-900">
                    <Tent className="h-3.5 w-3.5" />
                    Danh sách
                  </TabsTrigger>
                  <TabsTrigger value="map" className="gap-2 rounded-lg text-xs font-semibold text-stone-600 data-[state=active]:bg-white data-[state=active]:text-stone-900">
                    <MapIcon className="h-3.5 w-3.5" />
                    Bản đồ
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
          </CardContent>
        </Card>

        {/* Content - List or Map View */}
        {viewMode === 'list' ? (
          // List View - Full cards
          filteredSites && filteredSites.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredSites.map(site => renderFullSiteCard(site))}
            </div>
          ) : (
            <Card className="bg-white border-stone-200/80 rounded-2xl shadow-sm px-6 py-16 text-center">
              <CardContent className="py-6 flex flex-col items-center">
                <div className="w-16 h-16 bg-stone-50 border border-stone-100 rounded-full flex items-center justify-center mb-4">
                  <Tent className="h-8 w-8 text-stone-400" />
                </div>
                <h3 className="mb-1 text-lg font-bold text-stone-900">
                  {searchQuery || statusFilter !== 'all' || typeFilter !== 'all'
                    ? 'Không tìm thấy site nào'
                    : 'Chưa có site nào'}
                </h3>
                <p className="mb-6 text-sm text-stone-500 max-w-sm">
                  {searchQuery || statusFilter !== 'all' || typeFilter !== 'all'
                    ? 'Thử thay đổi bộ lọc hoặc từ khóa tìm kiếm để xem các kết quả khác.'
                    : 'Bắt đầu bằng cách tạo site đầu tiên cho property này để khách hàng có thể đặt chỗ.'}
                </p>
                {!searchQuery && statusFilter === 'all' && typeFilter === 'all' && (
                  <Button
                    className="bg-primary hover:bg-primary/90 text-white font-medium rounded-xl px-5 py-5 text-sm transition-all"
                    onClick={() =>
                      router.push(`/host/properties/${propertyId}/sites/new`)
                    }
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Tạo Site mới
                  </Button>
                )}
              </CardContent>
            </Card>
          )
        ) : (
          // Map View - Split layout with compact cards
          <div className="flex flex-col lg:flex-row gap-6">
            {/* Sites List - Scrollable with compact cards */}
            <div className="w-full lg:w-2/5 min-w-0 flex flex-col">
              <div className="h-[calc(100vh-280px)] min-h-[500px] lg:h-[650px] space-y-4 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-stone-200">
                {filteredSites && filteredSites.length > 0 ? (
                  filteredSites.map(site => renderCompactSiteCard(site))
                ) : (
                  <Card className="bg-white border-stone-200/80 rounded-2xl shadow-sm py-12 px-4 text-center">
                    <CardContent className="py-6 flex flex-col items-center">
                      <Tent className="mb-3 h-8 w-8 text-stone-400" />
                      <h4 className="font-bold text-stone-850 text-sm">Không tìm thấy site nào</h4>
                      <p className="text-xs text-stone-500 mt-1">Thử thay đổi bộ lọc hoặc từ khóa tìm kiếm</p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>

            {/* Map - Fixed */}
            <div className="w-full lg:w-3/5 min-w-0">
              <div className="sticky top-28 h-[400px] lg:h-[650px] overflow-hidden rounded-2xl border border-stone-200 shadow-sm bg-stone-100">
                {property && filteredSites && (
                  <SiteMap
                    sites={filteredSites}
                    property={property}
                    selectedSite={selectedSite}
                    hoveredSite={hoveredSite}
                    onSiteSelect={setSelectedSite}
                  />
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent className="rounded-2xl border-stone-200">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-xl font-bold">Xác nhận xóa site</AlertDialogTitle>
            <AlertDialogDescription className="text-stone-500 text-sm">
              Bạn có chắc chắn muốn xóa site{' '}
              <span className="font-semibold text-stone-850">
                &quot;{siteToDelete?.name}&quot;
              </span>
              ? Hành động này không thể hoàn tác và sẽ xóa tất cả các dữ liệu liên quan (bookings, lịch sử, ...).
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="rounded-xl border-stone-200">Hủy</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteSite}
              className="bg-rose-600 hover:bg-rose-700 text-white rounded-xl"
            >
              Xóa site
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}