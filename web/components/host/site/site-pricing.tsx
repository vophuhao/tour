/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useMemo } from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { DollarSign, Plus, Trash } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Season {
  name: string;
  startDate: Date | string;
  endDate: Date | string;
  price: number;
}

interface Pricing {
  rateType?: "site" | "person";
  basePrice: number;
  weekendPrice?: number;
  currency: string;
  weeklyDiscount?: number;
  monthlyDiscount?: number;
  additionalGuestFee?: number;
  cleaningFee?: number;
  vehicleFee?: number;
  petFee?: number;
  seasonalPricing?: Season[];
}

interface SitePricingProps {
  data: Pricing;
  onChange: (next: Pricing) => void;
}

export function SitePricing({ data, onChange }: SitePricingProps) {
  const pricing: Pricing = useMemo(() => ({
    rateType: data?.rateType ?? "site",
    basePrice: Number(data?.basePrice ?? 0),
    weekendPrice: data?.weekendPrice === undefined ? undefined : Number(data.weekendPrice),
    currency: data?.currency ?? "VND",
    weeklyDiscount: data?.weeklyDiscount === undefined ? undefined : Number(data.weeklyDiscount),
    monthlyDiscount: data?.monthlyDiscount === undefined ? undefined : Number(data.monthlyDiscount),
    additionalGuestFee: data?.additionalGuestFee === undefined ? undefined : Number(data.additionalGuestFee),
    petFee: data?.petFee === undefined ? undefined : Number(data.petFee),
    cleaningFee: data?.cleaningFee === undefined ? undefined : Number(data.cleaningFee),
    vehicleFee: data?.vehicleFee === undefined ? undefined : Number(data.vehicleFee),
    seasonalPricing: Array.isArray(data?.seasonalPricing) ? data.seasonalPricing.map(s => ({
      name: s.name ?? "",
      startDate: s.startDate ? (s.startDate instanceof Date ? s.startDate : new Date(s.startDate)) : "",
      endDate: s.endDate ? (s.endDate instanceof Date ? s.endDate : new Date(s.endDate)) : "",
      price: Number(s.price ?? 0),
    })) : [],
  }), [data]);

  const setField = (k: keyof Pricing, v: any) => onChange({ ...pricing, [k]: v });

  const setNumeric = (k: keyof Pricing, raw: string) => {
    if (raw === "") {
      setField(k, undefined);
      return;
    }
    const val = Number(raw);
    setField(k, typeof val === "number" && !Number.isNaN(val) ? val : undefined);
  };

  const seasons = pricing.seasonalPricing ?? [];

  const setSeason = (idx: number, patch: Partial<Season>) => {
    const next = seasons.map((s, i) => i === idx ? { ...s, ...patch } : s);
    setField("seasonalPricing", next);
  };

  const addSeason = () => {
    setField("seasonalPricing", [...seasons, { name: "", startDate: new Date(), endDate: new Date(), price: 0 }]);
  };

  const removeSeason = (idx: number) => {
    setField("seasonalPricing", seasons.filter((_, i) => i !== idx));
  };

  const fmtDate = (d: Date | string) => {
    if (!d) return "";
    const dt = d instanceof Date ? d : new Date(d);
    return dt.toISOString().slice(0, 10);
  };

  return (
    <div className="space-y-6">
      <div>
        <p className="text-3xl font-semibold text-gray-900 mb-4">Giá & Chiết khấu</p>
      </div>

      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><DollarSign className="h-5 w-5" />Giá cơ bản</CardTitle>
            <CardDescription>Thiết lập giá mỗi đêm và tiền tệ</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="basePrice">Giá cơ bản (VNĐ) <span className="text-red-500">*</span></Label>
              <Input id="basePrice" type="number" value={pricing.basePrice ?? 0} onChange={(e) => setNumeric("basePrice", e.target.value)} min={0} step={1000} className="mt-1" />
            </div>

            <div>
              <Label htmlFor="currency">Tiền tệ</Label>
              <Input id="currency" value={pricing.currency} onChange={(e) => setField("currency", e.target.value || "VND")} className="mt-1" />
            </div>

            <div className="col-span-2">
              <Label htmlFor="rateType">Mô hình tính giá</Label>
              <select
                id="rateType"
                value={pricing.rateType || "site"}
                onChange={(e) => setField("rateType", e.target.value)}
                className="mt-1 flex h-10 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 border-gray-300 dark:border-slate-800 text-gray-900 dark:text-gray-100"
              >
                <option value="site" className="text-black dark:text-white bg-white dark:bg-slate-900">Tính trên 1 vị trí (Cố định theo vị trí)</option>
                <option value="person" className="text-black dark:text-white bg-white dark:bg-slate-900">Tính trên đầu người (Tính theo số lượng khách)</option>
              </select>
            </div>

            <div className="col-span-2">
              <div className="flex items-center justify-between border-t pt-4">
                <div>
                  <Label>Giá cuối tuần (tùy chọn)</Label>
                  <p className="text-xs text-gray-500">Giá áp dụng cho thứ 7 & Chủ nhật</p>
                </div>
                <Switch
                  checked={typeof pricing.weekendPrice === "number"}
                  onCheckedChange={(v) => {
                    if (!v) setField("weekendPrice", undefined);
                    else setField("weekendPrice", pricing.basePrice ?? 0);
                  }}
                />
              </div>

              {typeof pricing.weekendPrice === "number" && (
                <div className="mt-3">
                  <Input type="number" value={pricing.weekendPrice ?? 0} onChange={(e) => setNumeric("weekendPrice", e.target.value)} min={0} step={1000} />
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Chiết khấu theo thời gian lưu trú</CardTitle>
            <CardDescription>Khuyến khích khách ở lâu hơn</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="weeklyDiscount">Giảm giá theo tuần (%)</Label>
              <Input id="weeklyDiscount" type="number" value={pricing.weeklyDiscount ?? ""} onChange={(e) => setNumeric("weeklyDiscount", e.target.value)} min={0} max={100} placeholder="10" className="mt-1" />
              <p className="text-xs text-gray-500 mt-1">Cho đặt 7 đêm trở lên</p>
            </div>
            <div>
              <Label htmlFor="monthlyDiscount">Giảm giá theo tháng (%)</Label>
              <Input id="monthlyDiscount" type="number" value={pricing.monthlyDiscount ?? ""} onChange={(e) => setNumeric("monthlyDiscount", e.target.value)} min={0} max={100} placeholder="20" className="mt-1" />
              <p className="text-xs text-gray-500 mt-1">Cho đặt 30 đêm trở lên</p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Phí bổ sung</CardTitle>
            <CardDescription>Phí khách thêm, xe, dọn dẹp, deposit, thú cưng</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="additionalGuestFee">Phí khách thêm (VNĐ/người/đêm)</Label>
              <Input id="additionalGuestFee" type="number" value={pricing.additionalGuestFee ?? ""} onChange={(e) => setNumeric("additionalGuestFee", e.target.value)} min={0} className="mt-1" />
            </div>

            <div>
              <Label htmlFor="vehicleFee">Phí xe (VNĐ/xe/đêm)</Label>
              <Input id="vehicleFee" type="number" value={pricing.vehicleFee ?? ""} onChange={(e) => setNumeric("vehicleFee", e.target.value)} min={0} className="mt-1" />
            </div>

            <div>
              <Label htmlFor="cleaningFee">Phí dọn dẹp (VNĐ)</Label>
              <Input id="cleaningFee" type="number" value={pricing.cleaningFee ?? ""} onChange={(e) => setNumeric("cleaningFee", e.target.value)} min={0} className="mt-1" />
            </div>

            <div>
              <Label htmlFor="petFee">Phí thú cưng (VNĐ)</Label>
              <Input id="petFee" type="number" value={pricing.petFee ?? ""} onChange={(e) => setNumeric("petFee", e.target.value)} min={0} className="mt-1" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Giá theo mùa</CardTitle>
            <CardDescription>Thiết lập giá khác nhau cho từng mùa trong năm</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {seasons.length === 0 && <p className="text-sm text-gray-500">Chưa có mùa nào.</p>}
              {seasons.map((s, i) => (
                <div key={i} className="grid grid-cols-6 gap-2 items-end border p-2 rounded">
                  <div className="col-span-2">
                    <Label>Tên mùa</Label>
                    <Input value={s.name ?? ""} onChange={(e) => setSeason(i, { name: e.target.value })} placeholder="Mùa cao điểm" />
                  </div>
                  <div>
                    <Label>Bắt đầu</Label>
                    <Input type="date" value={fmtDate(s.startDate)} onChange={(e) => setSeason(i, { startDate: new Date(e.target.value) })} />
                  </div>
                  <div>
                    <Label>Kết thúc</Label>
                    <Input type="date" value={fmtDate(s.endDate)} onChange={(e) => setSeason(i, { endDate: new Date(e.target.value) })} />
                  </div>
                  <div>
                    <Label>Giá (VNĐ)</Label>
                    <Input type="number" value={s.price ?? 0} onChange={(e) => setSeason(i, { price: Number(e.target.value || 0) })} min={0} />
                  </div>
                  <div className="flex items-center gap-2">
                    <Button size="sm" variant="destructive" onClick={() => removeSeason(i)}><Trash className="h-4 w-4" /></Button>
                  </div>
                </div>
              ))}

              <div>
                <Button size="sm" variant="ghost" onClick={addSeason}><Plus className="h-4 w-4 mr-1" /> Thêm mùa</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}