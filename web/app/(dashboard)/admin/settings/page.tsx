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
  Info
} from 'lucide-react';
import { toast } from 'sonner';
import { getSystemSettings, updateSystemSettings } from '@/services/admin.service';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

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
      }
    } catch (err) {
      console.error('Load settings error:', err);
      toast.error('Không thể tải cấu hình hệ thống');
    } finally {
      setLoading(false);
    }
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
    <div className="space-y-6 max-w-5xl mx-auto pb-10">
      {/* Page Header */}
      <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">
            <Settings className="h-6 w-6 text-primary" />
            Cài đặt hệ thống
          </h1>
          <p className="text-sm text-muted-foreground">
            Quản lý tỷ lệ phí dịch vụ nền tảng và thiết lập chính sách hoàn tiền, hủy đặt phòng.
          </p>
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

      <form onSubmit={handleSave} className="space-y-6">
        <div className="grid gap-6 md:grid-cols-2">
          {/* Card 1: Platform Fee */}
          <Card className="shadow-md border-slate-200 dark:border-slate-800">
            <CardHeader className="bg-slate-50/50 dark:bg-slate-905/10 border-b border-slate-100 dark:border-slate-800">
              <CardTitle className="text-lg font-semibold flex items-center gap-2">
                <Percent className="h-5 w-5 text-primary" />
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

              <div className="rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-100 dark:border-blue-900/30 p-3 mt-4 flex items-start gap-2.5">
                <Info className="h-4 w-4 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                <div className="text-xs text-blue-800 dark:text-blue-300 leading-normal">
                  <strong>Ví dụ minh họa:</strong>
                  <ul className="list-disc list-inside mt-1 space-y-1">
                    <li>Tổng tiền dịch vụ của campsite: 1,000,000đ</li>
                    <li>Phí nền tảng ({platformFee}%): {Math.round(1000000 * platformFee / 100).toLocaleString('vi-VN')}đ</li>
                    <li>Tổng tiền khách thanh toán: {Math.round(1000000 * (1 + platformFee / 100)).toLocaleString('vi-VN')}đ</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Card 2: Cancellation Policy Overview */}
          <Card className="shadow-md border-slate-200 dark:border-slate-800">
            <CardHeader className="bg-slate-50/50 border-b border-slate-100 dark:border-slate-800">
              <CardTitle className="text-lg font-semibold flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-amber-500" />
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
                <div className="space-y-2.5">
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
        </div>

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
  );
}
