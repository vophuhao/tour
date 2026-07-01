/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { CheckCircle2, Clock, Calendar } from "lucide-react";

interface BookingSettings {
  minimumNights: number;
  maximumNights?: number;
  checkInTime: string;
  checkOutTime: string;
  instantBook: boolean;
  advanceNotice: number;
  preparationTime?: number;
  allowSameDayBooking: boolean;
}

interface SiteBookingSettingsProps {
  data: BookingSettings;
  onChange: (newSettings: BookingSettings) => void;
}

export function SiteBookingSettings({ data, onChange }: SiteBookingSettingsProps) {
  const settings: BookingSettings = {
    minimumNights: data?.minimumNights ?? 1,
    maximumNights: data?.maximumNights ?? undefined,
    checkInTime: data?.checkInTime ?? "14:00",
    checkOutTime: data?.checkOutTime ?? "11:00",
    instantBook: data?.instantBook ?? false,
    advanceNotice: data?.advanceNotice ?? 24,
    preparationTime: data?.preparationTime ?? undefined,
    allowSameDayBooking: data?.allowSameDayBooking ?? false,
  };

  const updateField = (field: keyof BookingSettings, value: any) => {
    onChange({ ...settings, [field]: value });
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-3xl font-semibold text-gray-900 mb-2">
          Cài đặt đặt chỗ
        </h3>
        <p className="text-sm text-gray-500 mb-6">
          Cấu hình cách khách có thể đặt site này
        </p>
      </div>

      <div className="space-y-6">
        {/* Stay Duration */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5" />
              Thời gian lưu trú
            </CardTitle>
            <CardDescription>
              Số đêm tối thiểu và tối đa
            </CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="minimumNights">Số đêm tối thiểu <span className="text-red-500">*</span></Label>
              <Input
                id="minimumNights"
                type="number"
                value={settings.minimumNights}
                onChange={(e) => updateField("minimumNights", e.target.value === "" ? 1 : Number(e.target.value))}
                min={1}
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="maximumNights">Số đêm tối đa</Label>
              <Input
                id="maximumNights"
                type="number"
                value={settings.maximumNights ?? ""}
                onChange={(e) => updateField("maximumNights", e.target.value === "" ? undefined : Number(e.target.value))}
                min={1}
                placeholder="Không giới hạn"
                className="mt-1"
              />
            </div>
          </CardContent>
        </Card>

        {/* Check-in/out Times */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Giờ check-in/check-out
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="checkInTime">Giờ check-in <span className="text-red-500">*</span></Label>
              <Input
                id="checkInTime"
                type="time"
                value={settings.checkInTime}
                onChange={(e) => updateField("checkInTime", e.target.value)}
                className="mt-1"
              />
            </div>
            <div>
              <Label htmlFor="checkOutTime">Giờ check-out <span className="text-red-500">*</span></Label>
              <Input
                id="checkOutTime"
                type="time"
                value={settings.checkOutTime}
                onChange={(e) => updateField("checkOutTime", e.target.value)}
                className="mt-1"
              />
            </div>
          </CardContent>
        </Card>

        {/* Booking Options */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5" />
              Tùy chọn đặt chỗ
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* <div className="flex items-center justify-between border-b pb-4">
              <div className="space-y-1">
                <Label htmlFor="instantBook" className="text-base">
                  Đặt chỗ ngay lập tức
                </Label>
                <p className="text-sm text-gray-500">
                  Khách có thể đặt mà không cần chờ phê duyệt
                </p>
              </div>
              <Switch
                id="instantBook"
                checked={settings.instantBook}
                onCheckedChange={(checked) => updateField("instantBook", checked)}
              />
            </div> */}

            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <Label htmlFor="allowSameDayBooking" className="text-base">
                  Cho phép đặt cùng ngày
                </Label>
                <p className="text-sm text-gray-500">
                  Khách có thể đặt và check-in trong cùng 1 ngày
                </p>
              </div>
              <Switch
                id="allowSameDayBooking"
                checked={settings.allowSameDayBooking}
                onCheckedChange={(checked) => updateField("allowSameDayBooking", checked)}
              />
            </div>
          </CardContent>
        </Card>

        {/* Timing Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Cài đặt thời gian
            </CardTitle>
            <CardDescription>
              Thời gian báo trước và chuẩn bị
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="advanceNotice">
                Thời gian báo trước tối thiểu (giờ) <span className="text-red-500">*</span>
              </Label>
              <Input
                id="advanceNotice"
                type="number"
                value={settings.advanceNotice}
                onChange={(e) => updateField("advanceNotice", e.target.value === "" ? 24 : Number(e.target.value))}
                min={0}
                step={1}
                className="mt-1"
              />
              <p className="text-xs text-gray-500 mt-1">
                Khách phải đặt trước ít nhất bao nhiêu giờ
              </p>
            </div>

            <div>
              <Label htmlFor="preparationTime">
                Thời gian chuẩn bị giữa các booking (ngày)
              </Label>
              <Input
                id="preparationTime"
                type="number"
                value={settings.preparationTime ?? ""}
                onChange={(e) => updateField("preparationTime", e.target.value === "" ? undefined : Number(e.target.value))}
                min={0}
                placeholder="0"
                className="mt-1"
              />
              <p className="text-xs text-gray-500 mt-1">
                Số ngày trống cần giữa các lượt khách để chuẩn bị site
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Summary */}
        <Card className="bg-gradient-to-r from-emerald-50 to-blue-50 border-emerald-200">
          <CardHeader>
            <CardTitle className="text-emerald-900">Tóm tắt cài đặt</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-emerald-600" />
                <span className="text-gray-700">
                  Lưu trú: <strong>{settings.minimumNights} - {settings.maximumNights ?? "∞"} đêm</strong>
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-emerald-600" />
                <span className="text-gray-700">
                  Check-in: <strong>{settings.checkInTime}</strong>, Check-out: <strong>{settings.checkOutTime}</strong>
                </span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                <span className="text-gray-700">
                  {settings.instantBook ? "Đặt ngay lập tức" : "Cần phê duyệt"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-emerald-600" />
                <span className="text-gray-700">
                  Báo trước: <strong>{settings.advanceNotice} giờ</strong>
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}