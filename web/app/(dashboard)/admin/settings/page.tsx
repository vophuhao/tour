'use client';

import { useEffect, useState } from 'react';
import {
  Settings,
  Save,
  RefreshCw,
  Percent,
  ShieldAlert,
  CheckCircle,
  HelpCircle,
  AlertTriangle,
  Info,
  Image as ImageIcon,
  Link as LinkIcon,
  Plus,
  Trash2
} from 'lucide-react';
import { toast } from 'sonner';
import { getSystemSettings, updateSystemSettings } from '@/services/admin.service';
import { uploadMedia } from '@/services/media.service';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { cn } from '@/lib/utils';

export default function AdminSettingsPage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [platformFee, setPlatformFee] = useState<number>(5);

  // Cancellation policy states
  const [diffDaysThreshold, setDiffDaysThreshold] = useState<number>(2);
  const [refundRateAbove, setRefundRateAbove] = useState<number>(70);
  const [hostRateAbove, setHostRateAbove] = useState<number>(20);
  const [refundRateBelow, setRefundRateBelow] = useState<number>(50);
  const [hostRateBelow, setHostRateBelow] = useState<number>(30);
  const [rejectedHostRate, setRejectedHostRate] = useState<number>(80);

  interface PopupBannerItem {
    id: string;
    imageUrl: string;
    linkUrl?: string;
    isActive: boolean;
    uploading?: boolean;
  }

  // Popup banner states
  const [banners, setBanners] = useState<PopupBannerItem[]>([]);
  const [activeTab, setActiveTab] = useState<'fee' | 'policy' | 'banner'>('fee');

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const res = await getSystemSettings();
      if (res.success && res.data) {
        const data = res.data;
        setPlatformFee(Math.round(data.platformFeeRate * 100));

        if (data.cancellationPolicy) {
          const policy = data.cancellationPolicy;
          setDiffDaysThreshold(policy.diffDaysThreshold);
          setRefundRateAbove(Math.round(policy.refundRateAboveThreshold * 100));
          setHostRateAbove(Math.round(policy.hostRateAboveThreshold * 100));
          setRefundRateBelow(Math.round(policy.refundRateBelowThreshold * 100));
          setHostRateBelow(Math.round(policy.hostRateBelowThreshold * 100));
          setRejectedHostRate(Math.round(policy.rejectedRequestHostRate * 100));
        }

        if (data.popupBanners && data.popupBanners.length > 0) {
          setBanners(data.popupBanners.map((b: any, idx: number) => ({
            id: b._id || `banner-${idx}-${Date.now()}`,
            imageUrl: b.imageUrl,
            linkUrl: b.linkUrl || '',
            isActive: b.isActive,
          })));
        } else if (data.popupBanner && data.popupBanner.imageUrl) {
          setBanners([{
            id: 'legacy-banner',
            imageUrl: data.popupBanner.imageUrl || '',
            linkUrl: data.popupBanner.linkUrl || '',
            isActive: data.popupBanner.isActive,
          }]);
        } else {
          setBanners([]);
        }
      }
    } catch (err) {
      console.error('Load settings error:', err);
      toast.error('Không thể tải cấu hình hệ thống');
    } finally {
      setLoading(false);
    }
  };

  const handleBannerItemUpload = async (e: React.ChangeEvent<HTMLInputElement>, id: string) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      toast.error('Vui lòng chỉ chọn tệp ảnh');
      return;
    }

    try {
      setBanners(prev => prev.map(b => b.id === id ? { ...b, uploading: true } : b));
      const formData = new FormData();
      formData.append('files', file);

      const res = await uploadMedia(formData);
      if (res.success && Array.isArray(res.data) && res.data.length > 0) {
        const uploadedUrl = res.data[0];
        setBanners(prev => prev.map(b => b.id === id ? { ...b, imageUrl: uploadedUrl, uploading: false } : b));
        toast.success('Tải ảnh banner lên thành công');
      } else {
        toast.error(res.message || 'Tải ảnh lên thất bại');
        setBanners(prev => prev.map(b => b.id === id ? { ...b, uploading: false } : b));
      }
    } catch (err) {
      console.error('Upload banner error:', err);
      toast.error('Đã xảy ra lỗi khi tải ảnh lên');
      setBanners(prev => prev.map(b => b.id === id ? { ...b, uploading: false } : b));
    }
  };

  const addBanner = () => {
    const newBanner: PopupBannerItem = {
      id: `new-${Date.now()}`,
      imageUrl: '',
      linkUrl: '',
      isActive: true,
    };
    setBanners(prev => [...prev, newBanner]);
  };

  const removeBanner = (id: string) => {
    setBanners(prev => prev.filter(b => b.id !== id));
  };

  const updateBannerField = (id: string, field: 'linkUrl' | 'isActive', value: any) => {
    setBanners(prev => prev.map(b => b.id === id ? { ...b, [field]: value } : b));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validations
    if (platformFee < 0 || platformFee > 100) {
      toast.error('Phí nền tảng phải nằm trong khoảng từ 0% đến 100%');
      return;
    }
    if (diffDaysThreshold < 0) {
      toast.error('Ngưỡng số ngày hủy không được âm');
      return;
    }

    if (refundRateAbove + hostRateAbove > 100) {
      toast.error('Tổng tỷ lệ hoàn khách và Host nhận trước ngưỡng không được vượt quá 100%');
      return;
    }
    if (refundRateBelow + hostRateBelow > 100) {
      toast.error('Tổng tỷ lệ hoàn khách và Host nhận sau ngưỡng không được vượt quá 100%');
      return;
    }
    if (rejectedHostRate < 0 || rejectedHostRate > 100) {
      toast.error('Tỷ lệ Host nhận khi bị từ chối phải từ 0% đến 100%');
      return;
    }

    const activeBannersMissingImage = banners.some(b => b.isActive && !b.imageUrl);
    if (activeBannersMissingImage) {
      toast.error('Vui lòng tải ảnh lên cho tất cả các banner được kích hoạt');
      return;
    }

    try {
      setSaving(true);
      const payload = {
        platformFeeRate: platformFee / 100,
        cancellationPolicy: {
          diffDaysThreshold,
          refundRateAboveThreshold: refundRateAbove / 100,
          hostRateAboveThreshold: hostRateAbove / 100,
          refundRateBelowThreshold: refundRateBelow / 100,
          hostRateBelowThreshold: hostRateBelow / 100,
          rejectedRequestHostRate: rejectedHostRate / 100,
        },
        popupBanners: banners.map(b => ({
          imageUrl: b.imageUrl,
          linkUrl: b.linkUrl || '',
          isActive: b.isActive,
        })),
        // Fallback for backward compatibility
        popupBanner: banners.length > 0 ? {
          imageUrl: banners[0].imageUrl,
          linkUrl: banners[0].linkUrl || '',
          isActive: banners[0].isActive,
        } : {
          imageUrl: '',
          linkUrl: '',
          isActive: false,
        }
      };

      const res = await updateSystemSettings(payload);
      if (res.success) {
        toast.success('Cập nhật cấu hình hệ thống thành công');
      } else {
        toast.error(res.message || 'Cập nhật cấu hình thất bại');
      }
    } catch (err) {
      console.error('Save settings error:', err);
      toast.error('Đã xảy ra lỗi khi lưu cấu hình');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <div className="flex flex-col items-center gap-2">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Đang tải cấu hình hệ thống...</p>
        </div>
      </div>
    );
  }

  // Calculate platform cut percentages
  const platformAbove = 100 - (refundRateAbove + hostRateAbove);
  const platformBelow = 100 - (refundRateBelow + hostRateBelow);
  const platformRejected = 100 - rejectedHostRate;

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-10">
      {/* Page Header */}
      <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">

            Cài đặt hệ thống
          </h1>

        </div>
        <Button
          onClick={loadSettings}
          variant="outline"
          size="sm"
          className="w-fit"
        >
          <RefreshCw className="mr-2 h-4 w-4" />
          Tải lại
        </Button>
      </div>

      <div className="flex flex-col md:flex-row gap-6 items-start">
        {/* Left Column: Sidebar Tabs */}
        <div className="w-full md:w-60 shrink-0 flex flex-row md:flex-col gap-1 overflow-x-auto md:overflow-visible pb-2 md:pb-0 border-b md:border-b-0 md:border-r border-slate-200 dark:border-slate-800 pr-0 md:pr-4">
          <button
            type="button"
            onClick={() => setActiveTab('fee')}
            className={cn(
              "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left whitespace-nowrap md:whitespace-normal w-full",
              activeTab === 'fee'
                ? "bg-primary text-white shadow-sm"
                : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
            )}
          >
            <Percent className="h-4 w-4 shrink-0" />
            <span>Phí dịch vụ</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('policy')}
            className={cn(
              "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left whitespace-nowrap md:whitespace-normal w-full",
              activeTab === 'policy'
                ? "bg-primary text-white shadow-sm"
                : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
            )}
          >
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>Chính sách hủy</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('banner')}
            className={cn(
              "flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left whitespace-nowrap md:whitespace-normal w-full",
              activeTab === 'banner'
                ? "bg-primary text-white shadow-sm"
                : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
            )}
          >
            <ImageIcon className="h-4 w-4 shrink-0" />
            <span>Banner quảng cáo</span>
          </button>
        </div>

        {/* Right Column: Tab Content */}
        <div className="flex-1 w-full">
          <form onSubmit={handleSave} className="space-y-6">
            {activeTab === 'fee' && (
              <div className="space-y-6 animate-in fade-in duration-200">
                {/* Card 1: Platform Fee */}
                <Card className="shadow-md border-slate-200 dark:border-slate-800">
                  <CardHeader className="bg-slate-50/50 dark:bg-slate-905/10 border-b border-slate-100 dark:border-slate-800">
                    <CardTitle className="text-lg font-semibold flex items-center gap-2">

                      Phí nền tảng (Platform Fee)
                    </CardTitle>
                    <CardDescription>
                      Cấu hình tỷ lệ phần trăm phí dịch vụ thu của khách hàng khi tạo booking mới.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-6 space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="platformFee" className="text-sm font-medium">
                        Phí dịch vụ khách hàng (%)
                      </Label>
                      <div className="relative flex items-center">
                        <Input
                          id="platformFee"
                          type="number"
                          min="0"
                          max="100"
                          value={platformFee}
                          onChange={(e) => setPlatformFee(parseFloat(e.target.value) || 0)}
                          className="pr-10"
                          required
                        />
                        <div className="absolute right-3 text-slate-400 text-sm font-medium">%</div>
                      </div>
                      <p className="text-xs text-muted-foreground leading-normal pt-1">
                        Giá trị này được tính dựa trên tổng tiền phòng (subtotal + phí dọn dẹp + phí thú cưng + khách thêm + xe thêm). Mặc định là 5%.
                      </p>
                    </div>

                    <div className="rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-100 dark:border-blue-900/30 p-3.5 mt-4 flex items-start gap-2.5">
                      <Info className="h-4 w-4 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                      <div className="text-xs text-blue-800 dark:text-blue-300 leading-normal">
                        <strong>Ví dụ minh họa:</strong>
                        <ul className="list-disc list-inside mt-1 space-y-1">
                          <li>Tổng tiền dịch vụ của campsite: 1,000,000đ</li>
                          <li>Phí nền tảng ({platformFee}%): {Math.round(1000000 * platformFee / 100).toLocaleString('vi-VN')}đ</li>
                          <li>Tổng tiền chủ đất nhận được: {Math.round(1000000 * (1 - platformFee / 100)).toLocaleString('vi-VN')}đ</li>
                        </ul>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {activeTab === 'policy' && (
              <div className="space-y-6 animate-in fade-in duration-200">
                {/* Card 2: Cancellation Policy Overview */}
                <Card className="shadow-md border-slate-200 dark:border-slate-800">
                  <CardHeader className="bg-slate-50/50 border-b border-slate-100 dark:border-slate-800">
                    <CardTitle className="text-lg font-semibold flex items-center gap-2">

                      Thông tin chính sách hủy
                    </CardTitle>
                    <CardDescription>
                      Giải thích cơ chế phân chia tài chính khi xảy ra yêu cầu hủy booking (Không thể đến).
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-6 space-y-4">
                    <div className="space-y-3 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                      <p>
                        Hệ thống phân phối số tiền booking dựa trên mốc thời gian báo hủy của khách hàng so với ngày nhận phòng (Check-in):
                      </p>
                      <div className="grid gap-3 sm:grid-cols-2">
                        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-100 dark:border-emerald-900/30 rounded-lg">
                          <p className="font-semibold text-emerald-800 dark:text-emerald-300 text-xs">
                            1. Hủy trước ngưỡng thời gian (&ge; {diffDaysThreshold} ngày)
                          </p>
                          <ul className="text-xs space-y-1 mt-1 list-disc list-inside">
                            <li>Khách hàng được hoàn trả: <strong className="text-emerald-700 dark:text-emerald-400">{refundRateAbove}%</strong></li>
                            <li>Chủ campsite (Host) nhận: <strong className="text-emerald-700 dark:text-emerald-400">{hostRateAbove}%</strong></li>
                            <li>Nền tảng (Platform) giữ lại: <strong className="text-emerald-700 dark:text-emerald-400">{platformAbove}%</strong></li>
                          </ul>
                        </div>

                        <div className="p-3 bg-rose-50 dark:bg-rose-950/20 border border-rose-100 dark:border-rose-900/30 rounded-lg">
                          <p className="font-semibold text-rose-800 dark:text-rose-300 text-xs">
                            2. Hủy sát ngày hoặc sau ngưỡng (&lt; {diffDaysThreshold} ngày)
                          </p>
                          <ul className="text-xs space-y-1 mt-1 list-disc list-inside">
                            <li>Khách hàng được hoàn trả: <strong className="text-rose-700 dark:text-rose-400">{refundRateBelow}%</strong></li>
                            <li>Chủ campsite (Host) nhận: <strong className="text-rose-700 dark:text-rose-400">{hostRateBelow}%</strong></li>
                            <li>Nền tảng (Platform) giữ lại: <strong className="text-rose-700 dark:text-rose-400">{platformBelow}%</strong></li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Card 3: Cancellation Rules Details */}
                <Card className="shadow-md border-slate-200 dark:border-slate-800">
                  <CardHeader className="bg-slate-50/50 border-b border-slate-100 dark:border-slate-800">
                    <CardTitle className="text-lg font-semibold flex items-center gap-2">
                      <ShieldAlert className="h-5 w-5 text-primary" />
                      Thiết lập chính sách chi tiết
                    </CardTitle>
                    <CardDescription>
                      Tinh chỉnh tỷ lệ phần trăm phân bổ số tiền booking khi khách báo hủy (không thể đến).
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-6 space-y-6">
                    <div className="grid gap-4 md:grid-cols-3">
                      <div className="space-y-2">
                        <Label htmlFor="diffDays" className="text-sm font-medium">
                          Ngưỡng ngày hủy phòng (ngày)
                        </Label>
                        <Input
                          id="diffDays"
                          type="number"
                          min="0"
                          value={diffDaysThreshold}
                          onChange={(e) => setDiffDaysThreshold(parseInt(e.target.value) || 0)}
                          required
                        />
                        <p className="text-xs text-muted-foreground">Mốc ngày xác định tính chất hoàn tiền. Mặc định là 2 ngày.</p>
                      </div>
                    </div>

                    <hr className="border-slate-100 dark:border-slate-800" />

                    <div>
                      <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-3">
                        Quy tắc hủy TRƯỚC NGƯỠNG (&ge; {diffDaysThreshold} ngày)
                      </h3>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label htmlFor="refundRateAbove" className="text-sm font-medium">
                            Tỷ lệ hoàn tiền cho Khách hàng (%)
                          </Label>
                          <div className="relative flex items-center">
                            <Input
                              id="refundRateAbove"
                              type="number"
                              min="0"
                              max="100"
                              value={refundRateAbove}
                              onChange={(e) => setRefundRateAbove(parseFloat(e.target.value) || 0)}
                              className="pr-10"
                              required
                            />
                            <div className="absolute right-3 text-slate-400 text-sm font-medium">%</div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="hostRateAbove" className="text-sm font-medium">
                            Tỷ lệ bồi thường cho Host (%)
                          </Label>
                          <div className="relative flex items-center">
                            <Input
                              id="hostRateAbove"
                              type="number"
                              min="0"
                              max="100"
                              value={hostRateAbove}
                              onChange={(e) => setHostRateAbove(parseFloat(e.target.value) || 0)}
                              className="pr-10"
                              required
                            />
                            <div className="absolute right-3 text-slate-400 text-sm font-medium">%</div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label className="text-sm font-medium text-slate-400">Tỷ lệ giữ lại của Nền tảng (%)</Label>
                          <div className="h-10 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md flex items-center font-bold text-slate-700 dark:text-slate-300">
                            {platformAbove}%
                          </div>
                        </div>
                      </div>
                    </div>

                    <hr className="border-slate-100 dark:border-slate-800" />

                    <div>
                      <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-3">
                        Quy tắc hủy SÁT NGÀY / SAU NGƯỠNG (&lt; {diffDaysThreshold} ngày)
                      </h3>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label htmlFor="refundRateBelow" className="text-sm font-medium">
                            Tỷ lệ hoàn tiền cho Khách hàng (%)
                          </Label>
                          <div className="relative flex items-center">
                            <Input
                              id="refundRateBelow"
                              type="number"
                              min="0"
                              max="100"
                              value={refundRateBelow}
                              onChange={(e) => setRefundRateBelow(parseFloat(e.target.value) || 0)}
                              className="pr-10"
                              required
                            />
                            <div className="absolute right-3 text-slate-400 text-sm font-medium">%</div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="hostRateBelow" className="text-sm font-medium">
                            Tỷ lệ bồi thường cho Host (%)
                          </Label>
                          <div className="relative flex items-center">
                            <Input
                              id="hostRateBelow"
                              type="number"
                              min="0"
                              max="100"
                              value={hostRateBelow}
                              onChange={(e) => setHostRateBelow(parseFloat(e.target.value) || 0)}
                              className="pr-10"
                              required
                            />
                            <div className="absolute right-3 text-slate-400 text-sm font-medium">%</div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label className="text-sm font-medium text-slate-400">Tỷ lệ giữ lại của Nền tảng (%)</Label>
                          <div className="h-10 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md flex items-center font-bold text-slate-700 dark:text-slate-300">
                            {platformBelow}%
                          </div>
                        </div>
                      </div>
                    </div>

                    <hr className="border-slate-100 dark:border-slate-800" />

                    <div>
                      <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-1">
                        Trường hợp Yêu cầu hủy bị Bác bỏ / Từ chối bởi Admin
                      </h3>
                      <p className="text-xs text-muted-foreground mb-3">
                        Khi khách hàng báo không đến nhưng Admin từ chối hoàn tiền (Guest nhận 0% hoàn tiền).
                      </p>
                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label htmlFor="rejectedHostRate" className="text-sm font-medium">
                            Tỷ lệ trả cho Host (%)
                          </Label>
                          <div className="relative flex items-center">
                            <Input
                              id="rejectedHostRate"
                              type="number"
                              min="0"
                              max="100"
                              value={rejectedHostRate}
                              onChange={(e) => setRejectedHostRate(parseFloat(e.target.value) || 0)}
                              className="pr-10"
                              required
                            />
                            <div className="absolute right-3 text-slate-400 text-sm font-medium">%</div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label className="text-sm font-medium text-slate-400">Tỷ lệ giữ lại của Nền tảng (%)</Label>
                          <div className="h-10 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md flex items-center font-bold text-slate-700 dark:text-slate-300">
                            {platformRejected}%
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {activeTab === 'banner' && (
              <div className="space-y-6 animate-in fade-in duration-200">
                {/* Banner popup settings */}
                <Card className="border-slate-100 dark:border-slate-800 shadow-sm">
                  <CardHeader className="border-b border-slate-50 dark:border-slate-800 pb-4">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <div>
                        <CardTitle className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                          Danh Sách Banner Quảng Cáo Popup Trang Chủ
                        </CardTitle>
                        <CardDescription>
                          Cấu hình các ảnh banner quảng cáo dạng popup hiển thị khi camper truy cập vào trang chủ.
                        </CardDescription>
                      </div>
                      <Button
                        type="button"
                        onClick={addBanner}
                        size="sm"
                        className="flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
                      >
                        <Plus className="h-4 w-4" />
                        Thêm Banner Mới
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-6 space-y-6">
                    {banners.length === 0 ? (
                      <div className="flex flex-col items-center justify-center border border-dashed border-slate-200 dark:border-slate-700 rounded-lg p-10 bg-slate-50/50 dark:bg-slate-900/10 min-h-[220px]">
                        <ImageIcon className="h-12 w-12 text-slate-300 dark:text-slate-700 mb-2" />
                        <p className="text-sm font-semibold text-slate-500 dark:text-slate-400">
                          Chưa có banner nào được tạo
                        </p>
                        <p className="text-xs text-slate-400 dark:text-slate-500 mb-4 text-center max-w-sm">
                          Bấm nút &quot;Thêm Banner Mới&quot; để thiết lập hình ảnh quảng cáo hiển thị khi truy cập trang chủ.
                        </p>
                        <Button
                          type="button"
                          onClick={addBanner}
                          variant="outline"
                          size="sm"
                          className="flex items-center gap-1"
                        >
                          <Plus className="h-3.5 w-3.5" />
                          Tạo banner đầu tiên
                        </Button>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {banners.map((banner, idx) => (
                          <div
                            key={banner.id}
                            className="relative flex flex-col md:flex-row gap-4 border border-slate-100 dark:border-slate-800 rounded-xl p-4 bg-white dark:bg-slate-950 shadow-sm"
                          >
                            {/* Visual index badge */}
                            <div className="absolute top-2 left-2 flex items-center justify-center h-5 w-5 rounded-full bg-slate-100 dark:bg-slate-800 text-[10px] font-bold text-slate-600 dark:text-slate-400 select-none">
                              {idx + 1}
                            </div>

                            {/* Banner Preview Block */}
                            <div className="w-full md:w-48 shrink-0 flex flex-col items-center justify-center border border-dashed border-slate-200 dark:border-slate-700 rounded-lg p-2 bg-slate-50 dark:bg-slate-900/50 min-h-[120px] max-h-[140px] overflow-hidden relative">
                              {banner.uploading ? (
                                <div className="flex flex-col items-center gap-1.5 p-2">
                                  <RefreshCw className="h-5 w-5 animate-spin text-primary" />
                                  <span className="text-[10px] text-muted-foreground">Đang tải ảnh...</span>
                                </div>
                              ) : banner.imageUrl ? (
                                <>
                                  {/* eslint-disable-next-line @next/next/no-img-element */}
                                  <img
                                    src={banner.imageUrl}
                                    alt={`Banner ${idx + 1}`}
                                    className="max-h-[120px] object-contain rounded"
                                  />
                                  <div className="absolute inset-0 bg-black/40 opacity-0 hover:opacity-100 transition-opacity flex items-center justify-center">
                                    <Label className="cursor-pointer text-[10px] font-bold text-white bg-black/60 px-2 py-1 rounded hover:bg-black/80">
                                      Thay đổi ảnh
                                      <input
                                        type="file"
                                        accept="image/*"
                                        className="hidden"
                                        onChange={(e) => handleBannerItemUpload(e, banner.id)}
                                      />
                                    </Label>
                                  </div>
                                </>
                              ) : (
                                <div className="text-center p-2 flex flex-col items-center gap-1.5 w-full">
                                  <ImageIcon className="h-6 w-6 text-slate-300 dark:text-slate-700" />
                                  <Label className="cursor-pointer text-[10px] font-bold text-primary bg-primary/10 px-2.5 py-1.5 rounded hover:bg-primary/20 transition-all">
                                    Tải ảnh lên
                                    <input
                                      type="file"
                                      accept="image/*"
                                      className="hidden"
                                      onChange={(e) => handleBannerItemUpload(e, banner.id)}
                                    />
                                  </Label>
                                </div>
                              )}
                            </div>

                            {/* Banner Fields Block */}
                            <div className="flex-1 flex flex-col justify-between gap-3 pt-4 md:pt-0">
                              <div className="grid gap-4 sm:grid-cols-3 items-start">
                                <div className="sm:col-span-2 space-y-1.5">
                                  <Label htmlFor={`bannerLink-${banner.id}`} className="text-xs font-semibold">
                                    Đường dẫn liên kết khi click (tùy chọn)
                                  </Label>
                                  <div className="relative">
                                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                      <LinkIcon className="h-3.5 w-3.5 text-slate-400" />
                                    </div>
                                    <Input
                                      id={`bannerLink-${banner.id}`}
                                      placeholder="https://example.com/promotion"
                                      value={banner.linkUrl}
                                      onChange={(e) => updateBannerField(banner.id, 'linkUrl', e.target.value)}
                                      className="pl-9 h-8 text-xs"
                                    />
                                  </div>
                                </div>

                                <div className="space-y-1.5 flex flex-col sm:items-center">
                                  <Label className="text-xs font-semibold sm:text-center">Trạng thái</Label>
                                  <div className="flex items-center gap-2 h-8 pt-1">
                                    <span className="text-[11px] text-slate-500">Hiển thị</span>
                                    <Switch
                                      checked={banner.isActive}
                                      onCheckedChange={(checked) => updateBannerField(banner.id, 'isActive', checked)}
                                    />
                                  </div>
                                </div>
                              </div>

                              <div className="flex justify-end pt-2 border-t border-slate-100 dark:border-slate-800">
                                <Button
                                  type="button"
                                  onClick={() => removeBanner(banner.id)}
                                  variant="ghost"
                                  size="sm"
                                  className="h-7 px-2 text-rose-500 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 text-xs flex items-center gap-1"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                  Xóa banner
                                </Button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Form actions */}
            <div className="flex justify-end gap-3 border-t border-slate-200 dark:border-slate-800 pt-6">
              <Button
                type="button"
                variant="outline"
                onClick={loadSettings}
                disabled={saving}
              >
                Hủy thay đổi
              </Button>
              <Button
                type="submit"
                disabled={saving}
                className="flex items-center gap-2"
              >
                {saving ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Lưu cấu hình
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
