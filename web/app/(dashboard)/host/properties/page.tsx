/* eslint-disable @typescript-eslint/no-explicit-any */

'use client';

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
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { deleteProperty, getMyProperties, activateProperty } from '@/lib/client-actions';
import { useQuery } from '@tanstack/react-query';
import {
  Calendar,
  Eye,
  Filter,
  Grid3x3,
  Home,
  List,
  MapPin,
  Plus,
  Search,
  Settings,
  Star,
  Trash2,
  TrendingUp,
  X,
  MoreHorizontal,
  Copy,
  Heading5,
  Play,
  Power,
} from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';

export default function PropertiesPage() {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [propertyToDelete, setPropertyToDelete] = useState<string | null>(null);
  const [selectedProperties, setSelectedProperties] = useState<Set<string>>(new Set());

  const { data: properties = [], isLoading, refetch } = useQuery({
    queryKey: ['my-properties-list'],
    queryFn: async () => {
      const response = await getMyProperties();
      if (response && Array.isArray(response.properties)) {
        return response.properties;
      }
      if (response && response.data && Array.isArray(response.data.properties)) {
        return response.data.properties;
      }
      if (response && Array.isArray(response.data)) {
        return response.data;
      }
      if (Array.isArray(response)) {
        return response;
      }
      return [];
    },
  });

  const handleDeleteProperty = async () => {
    if (!propertyToDelete) return;
    try {
      await deleteProperty(propertyToDelete);
      toast.success('Tắt hoạt động khu cắm trại thành công!');
      refetch();
      setDeleteDialogOpen(false);
      setPropertyToDelete(null);
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Có lỗi xảy ra khi tắt hoạt động khu cắm trại');
    }
  };

  const handleActivateProperty = async (id: string) => {
    try {
      await activateProperty(id);
      toast.success('Kích hoạt khu cắm trại thành công!');
      refetch();
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Có lỗi xảy ra khi kích hoạt khu cắm trại');
    }
  };

  const propertiesList = Array.isArray(properties) ? properties : [];

  const filteredProperties = propertiesList.filter((property: any) => {
    const matchesSearch = property.name.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || property.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const stats = {
    total: propertiesList.length,
    active: propertiesList.filter((p: any) => p.status === 'active').length,
    totalSites: propertiesList.reduce((sum: number, p: any) => sum + (p.stats?.totalSites || 0), 0),
    totalBookings: propertiesList.reduce((sum: number, p: any) => sum + (p.stats?.totalBookings || 0), 0),
  };

  const statusConfig: any = {
    active: { label: 'Hoạt động', color: 'bg-emerald-100 text-emerald-800 border-emerald-300', icon: '✓' },
    inactive: { label: 'Không hoạt động', color: 'bg-slate-100 text-slate-800 border-slate-300', icon: '◯' },
    blocked: { label: 'Bị khóa', color: 'bg-red-100 text-red-800 border-red-200', icon: '⊗' },
    suspended: { label: 'Bị khóa', color: 'bg-red-100 text-red-800 border-red-200', icon: '⊗' },
  };

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 dark:bg-slate-950">
        <div className="text-center">
          <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent" />
          <p className="mt-4 text-stone-600 font-medium">Đang tải dữ liệu...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen text-stone-900 pb-12">
      {/* Header */}
      <div className="sticky top-0 z-40  backdrop-blur-md  border-stone-200/80">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex items-center justify-between">
          <div>
            <h1 className="text-3xl  font-bold text-stone-900 dark:text-stone-100 tracking-tight">Khu đất</h1>
          </div>
          <Button
            className="bg-primary hover:bg-primary/90 text-white shadow-md hover:shadow-lg transition-all rounded-xl px-5 py-5 text-sm font-medium gap-2"
            onClick={() => router.push('/host/properties/new')}
          >
            <Plus className="h-4 w-4" />
            Thêm khu đất mới
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col lg:flex-row gap-8">
        {/* Sidebar Filters */}
        <div className="w-full lg:w-64 flex-shrink-0">
          <div className="bg-white dark:bg-card rounded-2xl shadow-sm border border-stone-200/80 dark:border-stone-800 p-5 sticky top-28 space-y-6">
            <div>
              <h3 className="text-sm font-bold text-stone-900 dark:text-stone-200 mb-4 tracking-wider uppercase">Bộ lọc</h3>
              {/* Status Filter */}
              <div className="space-y-2">
                <label className="text-xs font-semibold text-stone-500 dark:text-stone-400 block">Trạng thái</label>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="bg-stone-50 dark:bg-stone-900 border-stone-200 dark:border-stone-800 h-10 text-sm rounded-xl focus:ring-primary/20 focus:border-primary text-stone-900 dark:text-stone-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl">
                    <SelectItem value="all">Tất cả trạng thái</SelectItem>
                    <SelectItem value="active">Đang hoạt động</SelectItem>
                    <SelectItem value="inactive">Không hoạt động</SelectItem>
                    <SelectItem value="blocked">Bị khóa</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Quick Stats list */}
            <div className="pt-5 border-t border-stone-100 dark:border-stone-800 space-y-2.5">
              <label className="text-xs font-semibold text-stone-500 dark:text-stone-400 block mb-2">Thống kê nhanh</label>
              {[
                { label: 'Tổng khu đất', count: stats.total, color: 'bg-stone-100 text-stone-700 dark:bg-stone-800 dark:text-stone-300' },
                { label: 'Khu đất đang hoạt động', count: stats.active, color: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-350' },
                { label: 'Tổng số bãi cắm', count: stats.totalSites, color: 'bg-blue-100 text-blue-800 dark:bg-blue-950/40 dark:text-blue-350' },
                { label: 'Tổng bookings', count: stats.totalBookings, color: 'bg-purple-100 text-purple-800 dark:bg-purple-950/40 dark:text-purple-350' },
              ].map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between text-sm py-1.5 px-1.5 rounded-lg"
                >
                  <span className="text-stone-600 dark:text-stone-300">{item.label}</span>
                  <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${item.color}`}>
                    {item.count}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Area */}
        <div className="flex-1 min-w-0">
          {/* Search & View Controls */}
          <div className="flex gap-4 mb-6">
            <div className="flex-1 relative">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-stone-400" />
              <Input
                placeholder="Tìm kiếm khu đất..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-11 bg-white dark:bg-card border-stone-200/80 dark:border-stone-800 h-11 rounded-xl focus:ring-2 focus:ring-primary/20 focus:border-primary text-sm text-stone-900 dark:text-stone-100"
              />
            </div>

            {/* View Mode Toggle */}
            <div className="flex bg-white dark:bg-card border border-stone-200/80 dark:border-stone-800 rounded-xl p-1 shadow-sm">
              <button
                onClick={() => setViewMode('grid')}
                className={`p-2.5 rounded-lg transition-all ${viewMode === 'grid' ? 'bg-primary/10 text-primary' : 'text-stone-500 hover:text-stone-850 dark:text-stone-400 dark:hover:text-stone-200'}`}
                title="Bố cục thẻ ngang"
              >
                <Grid3x3 className="h-4 w-4" />
              </button>
              <button
                onClick={() => setViewMode('list')}
                className={`p-2.5 rounded-lg transition-all ${viewMode === 'list' ? 'bg-primary/10 text-primary' : 'text-stone-500 hover:text-stone-850 dark:text-stone-400 dark:hover:text-stone-200'}`}
                title="Bố cục bảng danh sách"
              >
                <List className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Empty State */}
          {!filteredProperties || filteredProperties.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 bg-white rounded-2xl border border-stone-200/80 shadow-sm px-4 text-center">
              <div className="w-16 h-16 rounded-full bg-stone-50 border border-stone-100 flex items-center justify-center mb-4">
                <Home className="h-8 w-8 text-stone-400" />
              </div>
              <h3 className="text-lg  font-bold text-stone-900 mb-1">
                {searchQuery || statusFilter !== 'all' ? 'Không tìm thấy khu đất nào' : 'Chưa có khu đất nào'}
              </h3>
              <p className="text-sm text-stone-500 max-w-sm mb-6">
                {searchQuery || statusFilter !== 'all' ? 'Thử thay đổi từ khóa hoặc bộ lọc trạng thái' : 'Bắt đầu hành trình bằng cách tạo khu đất đầu tiên của bạn'}
              </p>
              {!searchQuery && statusFilter === 'all' && (
                <Button
                  className="bg-primary hover:bg-primary/90 text-white rounded-xl px-5 py-5 text-sm"
                  onClick={() => router.push('/host/properties/new')}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Tạo khu đất mới
                </Button>
              )}
            </div>
          ) : viewMode === 'grid' ? (
            /* Horizontal Cards View */
            <div className="flex flex-col gap-6">
              {filteredProperties.map((property: any) => (
                <PropertyGridCard
                  key={property._id}
                  property={property}
                  statusConfig={statusConfig}
                  onEdit={(id: string) => router.push(`/host/properties/${id}`)}
                  onViewSites={(id: string) => router.push(`/host/properties/${id}/sites`)}
                  onAddSite={(id: string) => router.push(`/host/properties/${id}/sites/new`)}
                  onDelete={(id: string) => {
                    setPropertyToDelete(id);
                    setDeleteDialogOpen(true);
                  }}
                  onActivate={handleActivateProperty}
                />
              ))}
            </div>
          ) : (
            /* List View */
            <div className="bg-white dark:bg-card rounded-2xl shadow-sm border border-stone-200/85 dark:border-stone-800 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-stone-900 dark:text-stone-100">
                  <thead className="bg-stone-50 dark:bg-stone-900 border-b border-stone-200 dark:border-stone-800">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Khu đất</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Địa điểm</th>
                      <th className="px-6 py-4 text-center text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Bãi cắm</th>
                      <th className="px-6 py-4 text-center text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Bookings</th>
                      <th className="px-6 py-4 text-center text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Đánh giá</th>
                      <th className="px-6 py-4 text-left text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Trạng thái</th>
                      <th className="px-6 py-4 text-right text-xs font-bold text-stone-500 dark:text-stone-400 uppercase tracking-wider">Hành động</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-100 dark:divide-stone-800">
                    {filteredProperties.map((property: any) => (
                      <PropertyListRow
                        key={property._id}
                        property={property}
                        statusConfig={statusConfig}
                        onEdit={(id: string) => router.push(`/host/properties/${id}`)}
                        onViewSites={(id: string) => router.push(`/host/properties/${id}/sites`)}
                        onAddSite={(id: string) => router.push(`/host/properties/${id}/sites/new`)}
                        onDelete={(id: string) => {
                          setPropertyToDelete(id);
                          setDeleteDialogOpen(true);
                        }}
                        onActivate={handleActivateProperty}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Delete Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent className="rounded-2xl border-stone-200">
          <AlertDialogHeader>
            <AlertDialogTitle className=" text-xl font-bold">Tắt hoạt động khu đất?</AlertDialogTitle>
            <AlertDialogDescription className="text-stone-500 text-sm">
              Hành động này sẽ tắt trạng thái hoạt động của khu đất và tất cả các bãi cắm thuộc khu này. Bạn có thể bật lại hoạt động bất cứ lúc nào khi có bãi cắm hoạt động.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="rounded-xl border-stone-200">Hủy</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteProperty}
              className="bg-rose-600 hover:bg-rose-700 text-white rounded-xl"
            >
              Tắt hoạt động
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// Grid Card Component formatted as horizontal layouts
function PropertyGridCard({ property, statusConfig, onEdit, onViewSites, onAddSite, onDelete, onActivate }: any) {
  const config = statusConfig[property.status] || statusConfig.inactive;

  return (
    <div className="group bg-white dark:bg-card rounded-2xl shadow-sm hover:shadow-md border border-stone-200/80 dark:border-stone-800 hover:border-stone-300 dark:hover:border-stone-700 transition-all duration-300 overflow-hidden flex flex-col md:flex-row">
      {/* Left side: Image */}
      <div className="relative w-full md:w-80 h-48 md:h-auto min-h-[220px] bg-gradient-to-br from-stone-100 to-stone-200 dark:from-stone-800 dark:to-stone-900 overflow-hidden flex-shrink-0">
        <Image
          src={property.photos?.[0]?.url || '/placeholder.jpg'}
          alt={property.name}
          fill
          className="object-cover group-hover:scale-105 transition-transform duration-500 ease-out"
          unoptimized
        />
        <div className="absolute top-3 left-3">
          <Badge className={`${config.color} border text-xs font-semibold px-2.5 py-1 rounded-full shadow-sm`}>
            {config.label}
          </Badge>
        </div>
      </div>

      {/* Middle side: Main content details */}
      <div className="flex-1 p-6 flex flex-col justify-between">
        <div>
          <p className=" text-xl md:text-1xl text-stone-900 dark:text-stone-100 group-hover:text-emerald-800 dark:group-hover:text-primary transition-colors font-semibold leading-snug line-clamp-2 mb-2">
            {property.name}
          </p>
          <div className="flex items-center gap-1.5 text-stone-500 dark:text-stone-400 mb-4">
            <MapPin className="h-4 w-4 text-emerald-750 flex-shrink-0" />
            <span className="text-sm font-medium">{property.location?.city || 'N/A'}, {property.location?.state || 'N/A'}</span>
          </div>
        </div>

        {/* Quick Stats: Rounded pills/capsules with elegant styling */}
        <div className="flex flex-wrap gap-3 mt-auto">
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-stone-50 dark:bg-stone-800/40 border border-stone-250/30 dark:border-stone-700/50">
            <Home className="h-3.5 w-3.5 text-emerald-700" />
            <span className="text-xs text-stone-500 dark:text-stone-400">Bãi cắm</span>
            <span className="text-sm font-bold text-stone-800 dark:text-stone-200">{property.stats?.totalSites || 0}</span>
          </div>
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-stone-50 dark:bg-stone-800/40 border border-stone-250/30 dark:border-stone-700/50">
            <Calendar className="h-3.5 w-3.5 text-blue-600" />
            <span className="text-xs text-stone-500 dark:text-stone-400">Bookings:</span>
            <span className="text-sm font-bold text-stone-800 dark:text-stone-200">{property.stats?.totalBookings || 0}</span>
          </div>
          <div className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-stone-50 dark:bg-stone-800/40 border border-stone-250/30 dark:border-stone-700/50">
            <Star className="h-3.5 w-3.5 text-amber-500 fill-amber-500" />
            <span className="text-xs text-stone-500 dark:text-stone-400">Đánh giá:</span>
            <span className="text-sm font-bold text-stone-800 dark:text-stone-200">{property.stats?.averageRating?.toFixed(1) || '0'}</span>
          </div>
        </div>
      </div>

      {/* Right side: Direct Action Buttons (No dropdown!) */}
      <div className="flex flex-row md:flex-col justify-center items-stretch gap-3 p-6 border-t md:border-t-0 md:border-l border-stone-200/80 dark:border-stone-800 bg-stone-50/50 dark:bg-stone-950/20 md:min-w-[220px]">
        <Button
          onClick={() => onViewSites(property._id)}
          className="flex-1 md:flex-initial bg-primary hover:bg-primary/90 text-white font-medium py-5 shadow-sm hover:shadow transition-all rounded-xl gap-2 text-sm"
        >
          <Eye className="h-4 w-4" />
          Quản lý bãi cắm
        </Button>
        <Button
          variant="outline"
          onClick={() => onEdit(property._id)}
          className="flex-1 md:flex-initial border-stone-200 dark:border-stone-850 hover:bg-stone-50 dark:hover:bg-stone-800 text-stone-700 dark:text-stone-300 hover:text-stone-900 dark:hover:text-white font-medium py-5 rounded-xl gap-2 text-sm"
        >
          <Settings className="h-4 w-4 text-stone-500" />
          Chỉnh sửa khu đất
        </Button>
        <Button
          variant="ghost"
          onClick={() => onAddSite(property._id)}
          className="flex-1 md:flex-initial text-emerald-800 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/20 font-medium py-5 rounded-xl gap-2 text-sm"
        >
          <Plus className="h-4 w-4" />
          Thêm bãi cắm mới
        </Button>
        {property.status === 'active' ? (
          <Button
            variant="ghost"
            onClick={() => onDelete(property._id)}
            className="flex-1 md:flex-initial text-rose-600 dark:text-rose-450 hover:bg-rose-50 dark:hover:bg-rose-950/20 hover:text-rose-750 dark:hover:text-rose-350 font-medium py-5 rounded-xl gap-2 text-sm"
          >
            <Power className="h-4 w-4" />
            Tắt hoạt động
          </Button>
        ) : property.status === 'inactive' ? (
          <Button
            variant="ghost"
            onClick={() => onActivate(property._id)}
            className="flex-1 md:flex-initial text-emerald-600 dark:text-emerald-450 hover:bg-emerald-50 dark:hover:bg-emerald-950/20 hover:text-emerald-750 dark:hover:text-emerald-350 font-medium py-5 rounded-xl gap-2 text-sm"
          >
            <Play className="h-4 w-4" />
            Bật hoạt động
          </Button>
        ) : (
          <Button
            variant="ghost"
            onClick={() => onDelete(property._id)}
            className="flex-1 md:flex-initial text-rose-600 dark:text-rose-450 hover:bg-rose-50 dark:hover:bg-rose-950/20 hover:text-rose-750 dark:hover:text-rose-350 font-medium py-5 rounded-xl gap-2 text-sm"
          >
            <Trash2 className="h-4 w-4" />
            Xóa khu đất
          </Button>
        )}
      </div>
    </div>
  );
}

// List Row Component
function PropertyListRow({ property, statusConfig, onEdit, onViewSites, onAddSite, onDelete, onActivate }: any) {
  const config = statusConfig[property.status] || statusConfig.inactive;

  return (
    <tr className="hover:bg-stone-50/60 dark:hover:bg-stone-850/40 transition-colors">
      <td className="px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="relative w-11 h-11 rounded-xl overflow-hidden bg-stone-100 dark:bg-stone-800 flex-shrink-0">
            <Image
              src={property.photos?.[0]?.url || '/placeholder.jpg'}
              alt={property.name}
              fill
              className="object-cover"
              unoptimized
            />
          </div>
          <div>
            <p className=" font-bold text-stone-900 dark:text-stone-100 text-sm md:text-base leading-tight">{property.name}</p>
          </div>
        </div>
      </td>
      <td className="px-6 py-4 text-sm text-stone-650 dark:text-stone-400">
        <div className="flex items-center gap-1.5">
          <MapPin className="h-3.5 w-3.5 text-emerald-700" />
          {property.location?.city || 'N/A'}
        </div>
      </td>
      <td className="px-6 py-4 text-center">
        <span className="inline-flex items-center justify-center h-8 w-8 rounded-full bg-primary/10 border border-primary/20 text-primary font-bold text-sm">
          {property.stats?.totalSites || 0}
        </span>
      </td>
      <td className="px-6 py-4 text-center">
        <span className="inline-flex items-center justify-center h-8 w-8 rounded-full bg-blue-50 dark:bg-blue-950/40 border border-blue-100 dark:border-blue-800 text-blue-750 dark:text-blue-400 font-bold text-sm">
          {property.stats?.totalBookings || 0}
        </span>
      </td>
      <td className="px-6 py-4 text-center">
        <div className="flex items-center justify-center gap-1">
          <Star className="h-3.5 w-3.5 text-amber-500 fill-amber-500" />
          <span className="font-bold text-stone-900 dark:text-stone-100 text-sm">
            {property.stats?.averageRating?.toFixed(1) || '0'}
          </span>
        </div>
      </td>
      <td className="px-6 py-4">
        <Badge className={`${config.color} border text-xs font-semibold px-2 rounded-full`}>
          {config.label}
        </Badge>
      </td>
      <td className="px-6 py-4 text-right">
        <div className="flex items-center justify-end gap-2">
          <Button
            size="sm"
            variant="outline"
            className="border-stone-200 dark:border-stone-800 text-stone-700 dark:text-stone-300 hover:bg-stone-50 dark:hover:bg-stone-800 h-9 rounded-xl px-3.5 gap-1.5"
            onClick={() => onViewSites(property._id)}
          >
            <Eye className="h-3.5 w-3.5" />
            Bãi cắm
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="ghost" className="h-9 w-9 p-0 rounded-xl">
                <MoreHorizontal className="h-4 w-4 text-stone-500" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="rounded-xl border-stone-200">
              <DropdownMenuItem onClick={() => onEdit(property._id)} className="cursor-pointer text-stone-700 rounded-lg">
                <Settings className="h-4 w-4 mr-2 text-stone-500" />
                Chỉnh sửa khu đất
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onAddSite(property._id)} className="cursor-pointer text-stone-700 rounded-lg">
                <Plus className="h-4 w-4 mr-2 text-stone-500" />
                Thêm bãi cắm mới
              </DropdownMenuItem>
              <DropdownMenuSeparator className="bg-stone-100" />
              {property.status === 'active' ? (
                <DropdownMenuItem onClick={() => onDelete(property._id)} className="cursor-pointer text-rose-600 hover:bg-rose-50 rounded-lg">
                  <Power className="h-4 w-4 mr-2" />
                  Tắt hoạt động
                </DropdownMenuItem>
              ) : property.status === 'inactive' ? (
                <DropdownMenuItem onClick={() => onActivate(property._id)} className="cursor-pointer text-emerald-600 hover:bg-emerald-50 rounded-lg">
                  <Play className="h-4 w-4 mr-2" />
                  Bật hoạt động
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem onClick={() => onDelete(property._id)} className="cursor-pointer text-rose-600 hover:bg-rose-50 rounded-lg">
                  <Trash2 className="h-4 w-4 mr-2" />
                  Xóa khu đất
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </td>
    </tr>
  );
}
