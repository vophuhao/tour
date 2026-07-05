/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus, Trash2, Package, Sparkles, AlertCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getMyServicePackages } from "@/services/service-package.service";
import type { Service, ServicePackage } from "@/types/property-site";

interface SiteServicesStepProps {
  data: Service[];
  onChange: (services: Service[]) => void;
}

export function SiteServicesStep({ data = [], onChange }: SiteServicesStepProps) {
  const [newServiceName, setNewServiceName] = useState("");
  const [newServiceDesc, setNewServiceDesc] = useState("");
  const [newPricing, setNewPricing] = useState<Array<{ price: number; unit: string }>>([
    { price: 0, unit: "lượt" }
  ]);

  // Fetch host service packages
  const { data: response } = useQuery<any>({
    queryKey: ["service-packages"],
    queryFn: getMyServicePackages,
  });

  const packages = response?.data as ServicePackage[] || [];

  const handleAddCustomService = () => {
    if (!newServiceName.trim()) return;

    const validPricing = newPricing.filter(p => p.price >= 0);
    const newService: Service = {
      name: newServiceName.trim(),
      description: newServiceDesc.trim() || undefined,
      pricing: validPricing.length > 0 ? validPricing : [{ price: 0, unit: "lượt" }],
    };

    onChange([...data, newService]);

    // Reset fields
    setNewServiceName("");
    setNewServiceDesc("");
    setNewPricing([{ price: 0, unit: "lượt" }]);
  };

  const handleRemoveService = (index: number) => {
    const updated = data.filter((_, i) => i !== index);
    onChange(updated);
  };

  const handleAddPricingRow = () => {
    setNewPricing(prev => [...prev, { price: 0, unit: "lượt" }]);
  };

  const handleRemovePricingRow = (pIdx: number) => {
    if (newPricing.length === 1) return;
    setNewPricing(prev => prev.filter((_, i) => i !== pIdx));
  };

  const handlePricingFieldChange = (pIdx: number, field: "price" | "unit", value: any) => {
    setNewPricing(prev => {
      const updated = [...prev];
      updated[pIdx] = {
        ...updated[pIdx],
        [field]: field === "price" ? Number(value) : value
      };
      return updated;
    });
  };

  const handleImportPackage = (packageId: string) => {
    const selectedPkg = packages.find(p => p._id === packageId);
    if (!selectedPkg) return;

    const overwrite = confirm(
      `Bạn có muốn thay thế toàn bộ dịch vụ hiện tại bằng ${selectedPkg.services.length} dịch vụ từ gói "${selectedPkg.name}"? \n\n(Nhấn Cancel để Gộp chung dịch vụ)`
    );

    const newServices = selectedPkg.services.map(s => ({
      name: s.name,
      description: s.description || "",
      pricing: s.pricing && s.pricing.length > 0
        ? s.pricing.map(p => ({ price: p.price, unit: p.unit }))
        : [{ price: 0, unit: "lượt" }]
    }));

    if (overwrite) {
      onChange(newServices);
    } else {
      // Merge
      const existingNames = new Set(data.map(s => s.name.toLowerCase()));
      const merged = [...data];
      newServices.forEach(s => {
        if (!existingNames.has(s.name.toLowerCase())) {
          merged.push(s);
        }
      });
      onChange(merged);
    }
  };

  return (
    <div className="space-y-8">
      {/* Introduction */}
      <div>
        <h3 className="text-xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-emerald-600 dark:text-emerald-500 animate-pulse" />
          Dịch vụ đi kèm tại Vị trí cắm trại
        </h3>
        <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm">
          Cấu hình dịch vụ đặc thù chỉ có sẵn tại riêng vị trí cắm trại (Site) này (ví dụ: Thuê ổ điện riêng, Thuê lều ngủ cỡ lớn...).
          Những dịch vụ này hiển thị phẳng khi khách xem chi tiết Vị trí này.
        </p>
      </div>

      {/* Package Importer */}
      {packages.length > 0 && (
        <Card className="border border-emerald-100 dark:border-emerald-950 bg-emerald-50/20 dark:bg-emerald-950/10 rounded-2xl">
          <CardContent className="pt-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-3">
                <Package className="h-5 w-5 text-emerald-600 dark:text-emerald-400 mt-0.5" />
                <div>
                  <h4 className="font-semibold text-slate-800 dark:text-slate-200 text-sm">Nhập từ gói dịch vụ mẫu</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Chọn nhanh các dịch vụ từ gói mẫu của bạn.
                  </p>
                </div>
              </div>

              <div className="w-full md:w-64">
                <Select onValueChange={handleImportPackage}>
                  <SelectTrigger className="rounded-xl border-emerald-200 dark:border-emerald-900 bg-white dark:bg-slate-900">
                    <SelectValue placeholder="Chọn gói dịch vụ..." />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl border border-slate-200 dark:border-slate-800">
                    {packages.map(pkg => (
                      <SelectItem key={pkg._id} value={pkg._id} className="rounded-lg text-sm">
                        {pkg.name} ({pkg.services.length} dịch vụ)
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Form */}
        <div className="space-y-4 lg:col-span-1 border-r dark:border-slate-800 pr-0 lg:pr-8">
          <h4 className="font-bold text-sm text-slate-800 dark:text-slate-200 border-b pb-2 flex items-center gap-1.5">
            <Plus className="h-4 w-4 text-emerald-600" />
            Thêm dịch vụ đặc biệt cho Site
          </h4>

          <div className="space-y-3.5">
            <div className="space-y-1.5">
              <Label htmlFor="srvName" className="text-xs font-semibold text-slate-500">Tên dịch vụ</Label>
              <Input
                id="srvName"
                placeholder="Ví dụ: Thuê bếp nướng ga mini"
                value={newServiceName}
                onChange={(e) => setNewServiceName(e.target.value)}
                className="rounded-xl border-slate-200 dark:border-slate-800 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="srvDesc" className="text-xs font-semibold text-slate-500">Mô tả ngắn</Label>
              <Input
                id="srvDesc"
                placeholder="Mô tả dịch vụ..."
                value={newServiceDesc}
                onChange={(e) => setNewServiceDesc(e.target.value)}
                className="rounded-xl border-slate-200 dark:border-slate-800 text-sm"
              />
            </div>

            <div className="space-y-2 border-t pt-3">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-semibold text-slate-500">Cấu hình đơn giá</Label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleAddPricingRow}
                  className="h-7 text-xs text-emerald-600 hover:text-emerald-700 p-0 rounded"
                >
                  + Thêm mức giá
                </Button>
              </div>

              <div className="space-y-2">
                {newPricing.map((pricingRow, pIdx) => (
                  <div key={pIdx} className="flex items-center gap-2">
                    <Input
                      type="number"
                      min="0"
                      placeholder="Giá"
                      value={pricingRow.price || ""}
                      onChange={(e) => handlePricingFieldChange(pIdx, "price", e.target.value)}
                      className="h-9 rounded-lg text-sm border-slate-200 dark:border-slate-800 w-full"
                    />
                    <span className="text-xs text-slate-400">đ/</span>
                    <Select
                      value={pricingRow.unit}
                      onValueChange={(val) => handlePricingFieldChange(pIdx, "unit", val)}
                    >
                      <SelectTrigger className="h-9 rounded-lg text-sm border-slate-200 dark:border-slate-800 w-24 shrink-0 focus:ring-emerald-500">
                        <SelectValue placeholder="Đơn vị" />
                      </SelectTrigger>
                      <SelectContent className="rounded-lg">
                        <SelectItem value="lượt">Lượt</SelectItem>
                        <SelectItem value="giờ">Giờ</SelectItem>
                        <SelectItem value="ngày">Ngày</SelectItem>
                        <SelectItem value="đêm">Đêm</SelectItem>
                        <SelectItem value="người">Người</SelectItem>
                        <SelectItem value="khách">Khách</SelectItem>
                        <SelectItem value="chiếc">Chiếc</SelectItem>
                        <SelectItem value="cái">Cái</SelectItem>
                      </SelectContent>
                    </Select>
                    {newPricing.length > 1 && (
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => handleRemovePricingRow(pIdx)}
                        className="h-8 w-8 text-slate-400 hover:text-red-600 rounded-lg shrink-0"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <Button
              type="button"
              onClick={handleAddCustomService}
              disabled={!newServiceName.trim()}
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl shadow-md text-sm mt-3"
            >
              Thêm dịch vụ
            </Button>
          </div>
        </div>

        {/* Right List */}
        <div className="lg:col-span-2 space-y-4">
          <h4 className="font-bold text-sm text-slate-800 dark:text-slate-200 border-b pb-2 flex items-center justify-between">
            <span>Dịch vụ được hỗ trợ tại Site ({data.length})</span>
            {data.length > 0 && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => onChange([])}
                className="text-red-500 hover:text-red-700 dark:hover:text-red-400 text-xs h-7 px-2 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg"
              >
                Xóa tất cả
              </Button>
            )}
          </h4>

          {data.length === 0 ? (
            <div className="text-center py-12 border border-dashed border-slate-200 dark:border-slate-800 rounded-2xl p-6 bg-slate-50/30 dark:bg-slate-900/10">
              <AlertCircle className="h-8 w-8 text-slate-400 mx-auto mb-2" />
              <p className="text-slate-500 dark:text-slate-400 text-sm font-medium">Chưa có dịch vụ nào cho vị trí này</p>
              <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">
                Sử dụng form bên trái hoặc chọn gói mẫu của bạn để cấu hình dịch vụ.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {data.map((srv, idx) => (
                <div
                  key={idx}
                  className="flex items-start justify-between gap-4 p-4 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl shadow-sm hover:shadow-md dark:shadow-none transition-all group"
                >
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold text-sm text-slate-800 dark:text-slate-200 truncate">{srv.name}</p>
                    {srv.description && (
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                        {srv.description}
                      </p>
                    )}
                    <div className="flex flex-wrap gap-1 mt-2.5">
                      {srv.pricing?.map((pOpt, pIdx) => (
                        <Badge
                          key={pIdx}
                          className="bg-emerald-50 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300 font-semibold border border-emerald-100 dark:border-emerald-900/30 text-[10px] py-0.5 px-2 rounded-lg"
                        >
                          {pOpt.price.toLocaleString("vi-VN")} đ / {pOpt.unit}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => handleRemoveService(idx)}
                    className="h-8 w-8 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg shrink-0"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
