/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus, Trash2, Package, Sparkles, AlertCircle, Check, X } from "lucide-react";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { getMyServicePackages } from "@/services/service-package.service";
import type { Service, ServicePackage } from "@/types/property-site";

interface PropertyServicesStepProps {
  data: Service[];
  onChange: (services: Service[]) => void;
}

export function PropertyServicesStep({ data = [], onChange }: PropertyServicesStepProps) {
  const [newServiceName, setNewServiceName] = useState("");
  const [newServiceDesc, setNewServiceDesc] = useState("");
  const [newIsInventoryTracked, setNewIsInventoryTracked] = useState(false);
  const [newTotalInventory, setNewTotalInventory] = useState(0);
  const [newPricing, setNewPricing] = useState<Array<{ price: number; unit: string; timeValue: number; timeUnit: string }>>([
    { price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }
  ]);

  const [importConfirmOpen, setImportConfirmOpen] = useState(false);
  const [importPkg, setImportPkg] = useState<ServicePackage | null>(null);

  // Fetch host service packages
  const { data: response } = useQuery<any>({
    queryKey: ["service-packages"],
    queryFn: getMyServicePackages,
    staleTime: 0,
  });

  const packages = response?.data as ServicePackage[] || [];

  const handleAddCustomService = () => {
    if (!newServiceName.trim()) return;

    const validPricing = newPricing.filter(p => p.price >= 0);
    const newService: Service = {
      name: newServiceName.trim(),
      description: newServiceDesc.trim() || undefined,
      pricing: validPricing.length > 0 ? validPricing.map(p => ({ price: p.price, unit: p.unit, timeValue: p.timeValue, timeUnit: p.timeUnit })) : [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }],
      isInventoryTracked: newIsInventoryTracked,
      totalInventory: newIsInventoryTracked ? newTotalInventory : 0,
    };

    onChange([...data, newService]);

    // Reset fields
    setNewServiceName("");
    setNewServiceDesc("");
    setNewIsInventoryTracked(false);
    setNewTotalInventory(0);
    setNewPricing([{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }]);
  };

  const handleRemoveService = (index: number) => {
    const updated = data.filter((_, i) => i !== index);
    onChange(updated);
  };

  const handleAddPricingRow = () => {
    setNewPricing(prev => [...prev, { price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }]);
  };

  const handleRemovePricingRow = (pIdx: number) => {
    if (newPricing.length === 1) return;
    setNewPricing(prev => prev.filter((_, i) => i !== pIdx));
  };

  const handlePricingFieldChange = (pIdx: number, field: "price" | "unit" | "timeValue" | "timeUnit", value: any) => {
    setNewPricing(prev => {
      const updated = [...prev];
      updated[pIdx] = {
        ...updated[pIdx],
        [field]: (field === "price" || field === "timeValue")
          ? (value === "" ? "" : Number(value))
          : value
      };
      return updated;
    });
  };

  const handleImportPackage = (packageId: string) => {
    const selectedPkg = packages.find(p => p._id === packageId);
    if (!selectedPkg) return;
    setImportPkg(selectedPkg);
    setImportConfirmOpen(true);
  };

  const executeImport = (overwrite: boolean) => {
    if (!importPkg) return;
    const selectedPkg = importPkg;
    const newServices = selectedPkg.services.map(s => {
      const pricing = s.pricing && s.pricing.length > 0
        ? s.pricing.map(p => {
          const unit = p.unit || "cai";
          const timeUnit = p.timeUnit || "luot";
          const timeValue = p.timeValue ?? 1;

          const standardUnits = ["cai", "chiec", "nguoi_lon", "tre_em", "khach"];
          const standardTimeUnits = ["luot", "gio", "dem", "ngay"];

          let finalUnit = standardUnits.includes(unit) ? unit : "cai";
          let finalTimeUnit = standardTimeUnits.includes(timeUnit) ? timeUnit : "luot";

          if (!standardUnits.includes(unit)) {
            const uLower = unit.toLowerCase();
            if (uLower.includes("khách") || uLower.includes("người")) finalUnit = "khach";
            else if (uLower.includes("lớn")) finalUnit = "nguoi_lon";
            else if (uLower.includes("em")) finalUnit = "tre_em";
            else if (uLower.includes("chiếc")) finalUnit = "chiec";

            if (uLower.includes("đêm")) finalTimeUnit = "dem";
            else if (uLower.includes("ngày")) finalTimeUnit = "ngay";
            else if (uLower.includes("giờ")) finalTimeUnit = "gio";
          }

          return {
            price: typeof p.price === 'number' ? p.price : Number(p.price || 0),
            unit: finalUnit,
            timeValue,
            timeUnit: finalTimeUnit
          };
        })
        : [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }];

      return {
        name: s.name,
        description: s.description || "",
        pricing,
        isInventoryTracked: false,
        totalInventory: 0,
      };
    });

    if (overwrite) {
      onChange(newServices);
    } else {
      // Merge: avoid duplicating exact names
      const existingNames = new Set(data.map(s => s.name.toLowerCase()));
      const merged = [...data];
      newServices.forEach(s => {
        if (!existingNames.has(s.name.toLowerCase())) {
          merged.push(s);
        }
      });
      onChange(merged);
    }

    setImportConfirmOpen(false);
    setImportPkg(null);
  };

  return (
    <div className="space-y-8">
      {/* Introduction */}
      <div>
        <h3 className="text-xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">

          Dịch vụ đi kèm của khu đất
        </h3>
        <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm">
          Cấu hình các dịch vụ mà khu cắm trại của bạn hỗ trợ (ví dụ: Thuê đồ cắm trại, Bán củi đốt lều, Tổ chức BBQ...).
          Các dịch vụ này sẽ hiển thị thành một danh sách phẳng trên trang chi tiết để khách hàng tham khảo.
        </p>
      </div>

      {/* Package Importer */}
      {packages.length > 0 && (
        <Card className="border border-emerald-100 dark:border-emerald-950 bg-emerald-50/20 dark:bg-emerald-950/10 rounded-2xl">
          <CardContent className="pt-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-3">

                <div>
                  <h4 className="font-semibold text-slate-800 dark:text-slate-200 text-sm">Nhập nhanh từ gói dịch vụ mẫu</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Chọn một trong các gói dịch vụ mẫu bạn đã tạo trong Host Settings để điền nhanh.
                  </p>
                </div>
              </div>

              <div className="w-full md:w-64">
                <Select onValueChange={handleImportPackage}>
                  <SelectTrigger className="rounded-xl border-emerald-200 dark:border-emerald-900 bg-white dark:bg-slate-900 focus:ring-emerald-500">
                    <SelectValue placeholder="Chọn gói dịch vụ mẫu..." />
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

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        {/* Left: Add special service */}
        <div className="space-y-4 lg:col-span-2 border-r dark:border-slate-800 pr-0 lg:pr-8">
          <h4 className="font-bold text-sm text-slate-800 dark:text-slate-200 border-b pb-2 flex items-center gap-1.5">
            <Plus className="h-4 w-4 text-primary" />
            Thêm dịch vụ đặc biệt
          </h4>

          <div className="space-y-3.5">
            <div className="space-y-1.5">
              <Label htmlFor="srvName" className="text-xs font-semibold text-slate-500">Tên dịch vụ</Label>
              <Input
                id="srvName"
                placeholder="Ví dụ: Cho thuê SUP chèo"
                value={newServiceName}
                onChange={(e) => setNewServiceName(e.target.value)}
                className="rounded-xl border-slate-200 dark:border-slate-800 text-sm"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="srvDesc" className="text-xs font-semibold text-slate-500">Mô tả ngắn</Label>
              <Input
                id="srvDesc"
                placeholder="Ví dụ: Kèm mái chèo, phao cứu sinh..."
                value={newServiceDesc}
                onChange={(e) => setNewServiceDesc(e.target.value)}
                className="rounded-xl border-slate-200 dark:border-slate-800 text-sm"
              />
            </div>

            <div className="space-y-3 bg-slate-50/50 dark:bg-slate-900/30 p-3 rounded-2xl border border-slate-100 dark:border-slate-800/80">
              <div className="flex items-center justify-between">
                <Label htmlFor="trackInventory" className="text-xs font-semibold text-slate-600 dark:text-slate-350 cursor-pointer">Quản lý giới hạn số lượng?</Label>
                <input
                  type="checkbox"
                  id="trackInventory"
                  checked={newIsInventoryTracked}
                  onChange={(e) => setNewIsInventoryTracked(e.target.checked)}
                  className="h-4 w-4 rounded border-slate-300 dark:border-slate-800 text-emerald-600 focus:ring-emerald-500"
                />
              </div>
              {newIsInventoryTracked && (
                <div className="space-y-1">
                  <Label htmlFor="totalInv" className="text-[10px] uppercase font-bold text-slate-400">Tổng số lượng có</Label>
                  <Input
                    type="number"
                    id="totalInv"
                    min="1"
                    value={newTotalInventory || ""}
                    onChange={(e) => setNewTotalInventory(Number(e.target.value))}
                    className="h-8 rounded-lg text-sm border-slate-200 dark:border-slate-800"
                  />
                </div>
              )}
            </div>

            <div className="space-y-2 border-t pt-3">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-semibold text-slate-500">Cấu hình đơn giá</Label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleAddPricingRow}
                  className="h-7 text-xs text-primary hover:text-primary/80 p-0 rounded"
                >
                  + Thêm mức giá
                </Button>
              </div>

              <div className="space-y-2">
                {newPricing.map((pricingRow, pIdx) => (
                  <div key={pIdx} className="flex flex-wrap items-center gap-2">
                    <Input
                      type="number"
                      min="0"
                      placeholder="Giá"
                      value={pricingRow.price || ""}
                      onChange={(e) => handlePricingFieldChange(pIdx, "price", e.target.value)}
                      className="h-9 rounded-lg text-sm border-slate-200 dark:border-slate-800 flex-1 min-w-[120px]"
                    />
                    <span className="text-xs text-slate-400">đ/</span>
                    <Select
                      value={pricingRow.unit}
                      onValueChange={(val) => handlePricingFieldChange(pIdx, "unit", val)}
                    >
                      <SelectTrigger className="h-9 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-24 shrink-0 focus:ring-emerald-500 bg-white">
                        <SelectValue placeholder="Đơn vị" />
                      </SelectTrigger>
                      <SelectContent className="rounded-lg">
                        <SelectItem value="cai">cái</SelectItem>
                        <SelectItem value="chiec">chiếc</SelectItem>
                        <SelectItem value="nguoi_lon">người lớn</SelectItem>
                        <SelectItem value="tre_em">trẻ em</SelectItem>
                        <SelectItem value="khach">khách</SelectItem>
                      </SelectContent>
                    </Select>
                    <span className="text-xs text-slate-400">/</span>
                    <Input
                      type="number"
                      min="1"
                      placeholder="Số"
                      value={pricingRow.timeValue ?? ""}
                      onChange={(e) => handlePricingFieldChange(pIdx, "timeValue", e.target.value)}
                      className="h-9 rounded-lg text-sm border-slate-200 dark:border-slate-800 w-14 px-1 text-center shrink-0 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                    />
                    <Select
                      value={pricingRow.timeUnit}
                      onValueChange={(val) => handlePricingFieldChange(pIdx, "timeUnit", val)}
                    >
                      <SelectTrigger className="h-9 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-20 shrink-0 focus:ring-emerald-500 bg-white">
                        <SelectValue placeholder="Thời gian" />
                      </SelectTrigger>
                      <SelectContent className="rounded-lg">
                        <SelectItem value="luot">lượt</SelectItem>
                        <SelectItem value="gio">giờ</SelectItem>
                        <SelectItem value="dem">đêm</SelectItem>
                        <SelectItem value="ngay">ngày</SelectItem>
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
              className="w-full bg-primary hover:bg-primary/90 text-white rounded-xl shadow-md text-sm mt-3"
            >
              Thêm dịch vụ
            </Button>
          </div>
        </div>

        {/* Right: List of services in this Property */}
        <div className="lg:col-span-3 space-y-4">
          <h4 className="font-bold text-sm text-slate-800 dark:text-slate-200 border-b pb-2 flex items-center justify-between">
            <span>Dịch vụ được hỗ trợ ({data.length})</span>
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
              <p className="text-slate-500 dark:text-slate-400 text-sm font-medium">Chưa có dịch vụ nào cho khu đất này</p>
              <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">
                Nhập từ gói mẫu hoặc điền form bên trái để kích hoạt dịch vụ cho thuê tại đây.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {data.map((srv, idx) => (
                <div
                  key={idx}
                  className="flex flex-col gap-4 p-4 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl shadow-sm hover:shadow-md dark:shadow-none transition-all"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-sm text-slate-800 dark:text-slate-200 truncate">{srv.name}</p>
                      {srv.description && (
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-1 leading-relaxed">
                          {srv.description}
                        </p>
                      )}
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

                  <div className="grid grid-cols-1 gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                    {srv.pricing?.map((pOpt, pIdx) => (
                      <div key={pIdx} className="flex items-center gap-2">
                        <Label className="text-[10px] uppercase font-bold text-slate-400 w-16 shrink-0">Giá thuê</Label>
                        <Input
                          type="number"
                          min="0"
                          value={pOpt.price ?? ""}
                          onChange={(e) => {
                            const updated = [...data];
                            const updatedPricing = [...(updated[idx].pricing || [])];
                            updatedPricing[pIdx] = {
                              ...updatedPricing[pIdx],
                              price: e.target.value === "" ? "" as any : Number(e.target.value)
                            };
                            updated[idx] = {
                              ...updated[idx],
                              pricing: updatedPricing
                            };
                            onChange(updated);
                          }}
                          className="h-8 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-full"
                        />
                        <span className="text-xs text-slate-400">đ/</span>
                        <Select
                          value={pOpt.unit}
                          onValueChange={(val) => {
                            const updated = [...data];
                            const updatedPricing = [...(updated[idx].pricing || [])];
                            updatedPricing[pIdx] = {
                              ...updatedPricing[pIdx],
                              unit: val
                            };
                            updated[idx] = {
                              ...updated[idx],
                              pricing: updatedPricing
                            };
                            onChange(updated);
                          }}
                        >
                          <SelectTrigger className="h-8 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-24 shrink-0 focus:ring-emerald-500 bg-transparent">
                            <SelectValue placeholder="Đơn vị" />
                          </SelectTrigger>
                          <SelectContent className="rounded-lg">
                            <SelectItem value="cai">cái</SelectItem>
                            <SelectItem value="chiec">chiếc</SelectItem>
                            <SelectItem value="nguoi_lon">người lớn</SelectItem>
                            <SelectItem value="tre_em">trẻ em</SelectItem>
                            <SelectItem value="khach">khách</SelectItem>
                          </SelectContent>
                        </Select>
                        <span className="text-xs text-slate-400">/</span>
                        <Input
                          type="number"
                          min="1"
                          value={pOpt.timeValue ?? ""}
                          onChange={(e) => {
                            const updated = [...data];
                            const updatedPricing = [...(updated[idx].pricing || [])];
                            updatedPricing[pIdx] = {
                              ...updatedPricing[pIdx],
                              timeValue: e.target.value === "" ? "" as any : Number(e.target.value)
                            };
                            updated[idx] = {
                              ...updated[idx],
                              pricing: updatedPricing
                            };
                            onChange(updated);
                          }}
                          className="h-8 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-14 px-1 text-center shrink-0 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                        />
                        <Select
                          value={pOpt.timeUnit || "luot"}
                          onValueChange={(val) => {
                            const updated = [...data];
                            const updatedPricing = [...(updated[idx].pricing || [])];
                            updatedPricing[pIdx] = {
                              ...updatedPricing[pIdx],
                              timeUnit: val
                            };
                            updated[idx] = {
                              ...updated[idx],
                              pricing: updatedPricing
                            };
                            onChange(updated);
                          }}
                        >
                          <SelectTrigger className="h-8 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-20 shrink-0 focus:ring-emerald-500 bg-transparent">
                            <SelectValue placeholder="Thời gian" />
                          </SelectTrigger>
                          <SelectContent className="rounded-lg">
                            <SelectItem value="luot">lượt</SelectItem>
                            <SelectItem value="gio">giờ</SelectItem>
                            <SelectItem value="dem">đêm</SelectItem>
                            <SelectItem value="ngay">ngày</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    ))}

                    <div className="space-y-2 bg-slate-50/50 dark:bg-slate-900/30 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800/80 mt-1">
                      <div className="flex items-center justify-between">
                        <Label htmlFor={`track-${idx}`} className="text-xs font-semibold text-slate-500 cursor-pointer">Giới hạn số lượng?</Label>
                        <input
                          type="checkbox"
                          id={`track-${idx}`}
                          checked={srv.isInventoryTracked || false}
                          onChange={(e) => {
                            const updated = [...data];
                            updated[idx] = {
                              ...updated[idx],
                              isInventoryTracked: e.target.checked,
                              totalInventory: e.target.checked ? (updated[idx].totalInventory || 1) : 0
                            };
                            onChange(updated);
                          }}
                          className="h-3.5 w-3.5 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500"
                        />
                      </div>
                      {srv.isInventoryTracked && (
                        <div className="flex items-center justify-between gap-2 pt-1.5 border-t border-dashed border-slate-200/60 dark:border-slate-800/60">
                          <Label htmlFor={`total-${idx}`} className="text-[10px] uppercase font-bold text-slate-400">Tổng số trong kho</Label>
                          <Input
                            type="number"
                            id={`total-${idx}`}
                            min="1"
                            value={srv.totalInventory || ""}
                            onChange={(e) => {
                              const updated = [...data];
                              updated[idx] = {
                                ...updated[idx],
                                totalInventory: Number(e.target.value)
                              };
                              onChange(updated);
                            }}
                            className="h-7 w-20 rounded-lg text-xs border-slate-200 dark:border-slate-800 text-center"
                          />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <Dialog open={importConfirmOpen} onOpenChange={setImportConfirmOpen}>
        <DialogContent className="max-w-md rounded-2xl border border-slate-200 dark:border-slate-800">
          <DialogHeader>
            <DialogTitle className="text-lg font-bold text-slate-850 dark:text-slate-100">
              Nhập gói dịch vụ mẫu
            </DialogTitle>
            <DialogDescription className="text-slate-500 dark:text-slate-400 mt-2 text-sm leading-relaxed">
              Bạn có muốn **thay thế toàn bộ** danh sách dịch vụ hiện tại bằng {importPkg?.services.length} dịch vụ từ gói "{importPkg?.name}", hay muốn **gộp chung** (thêm vào cuối danh sách)?
            </DialogDescription>
          </DialogHeader>

          <DialogFooter className="mt-4 flex flex-col sm:flex-row gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => setImportConfirmOpen(false)}
              className="rounded-xl sm:flex-1"
            >
              Hủy bỏ
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => executeImport(false)}
              className="bg-slate-100 hover:bg-slate-200 text-slate-700 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-300 rounded-xl sm:flex-1"
            >
              Gộp chung
            </Button>
            <Button
              type="button"
              onClick={() => executeImport(true)}
              className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl sm:flex-1"
            >
              Thay thế tất cả
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
