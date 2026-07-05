"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Edit2, Trash2, Package, Check, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  getMyServicePackages,
  createServicePackage,
  updateServicePackage,
  deleteServicePackage,
} from "@/services/service-package.service";
import type { ServicePackage, Service } from "@/types/property-site";

export default function HostServicesPage() {
  const queryClient = useQueryClient();
  const [isOpen, setIsOpen] = useState(false);
  const [editingPackage, setEditingPackage] = useState<ServicePackage | null>(null);
  const [packageName, setPackageName] = useState("");
  const [services, setServices] = useState<Omit<Service, "_id">[]>([
    { name: "", description: "", pricing: [{ price: 0, unit: "lượt" }] }
  ]);

  // Fetch all service packages
  const { data: response, isLoading } = useQuery<any>({
    queryKey: ["service-packages"],
    queryFn: getMyServicePackages,
  });

  const packages = response?.data as ServicePackage[] || [];

  // Mutations
  const createMutation = useMutation({
    mutationFn: createServicePackage,
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Tạo gói dịch vụ thành công!");
        queryClient.invalidateQueries({ queryKey: ["service-packages"] });
        closeDialog();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
    onError: (err: any) => {
      toast.error(err.message || "Lỗi kết nối");
    }
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => updateServicePackage(id, data),
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Cập nhật gói dịch vụ thành công!");
        queryClient.invalidateQueries({ queryKey: ["service-packages"] });
        closeDialog();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
    onError: (err: any) => {
      toast.error(err.message || "Lỗi kết nối");
    }
  });

  const deleteMutation = useMutation({
    mutationFn: deleteServicePackage,
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Xóa gói dịch vụ thành công!");
        queryClient.invalidateQueries({ queryKey: ["service-packages"] });
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
    onError: (err: any) => {
      toast.error(err.message || "Lỗi kết nối");
    }
  });

  const closeDialog = () => {
    setIsOpen(false);
    setEditingPackage(null);
    setPackageName("");
    setServices([{ name: "", description: "", pricing: [{ price: 0, unit: "lượt" }] }]);
  };

  const openCreateDialog = () => {
    setEditingPackage(null);
    setPackageName("");
    setServices([{ name: "", description: "", pricing: [{ price: 0, unit: "lượt" }] }]);
    setIsOpen(true);
  };

  const openEditDialog = (pkg: ServicePackage) => {
    setEditingPackage(pkg);
    setPackageName(pkg.name);
    setServices(pkg.services.map(s => ({
      name: s.name,
      description: s.description || "",
      pricing: s.pricing && s.pricing.length > 0
        ? s.pricing.map(p => ({ price: p.price, unit: p.unit }))
        : [{ price: 0, unit: "lượt" }]
    })));
    setIsOpen(true);
  };

  const handleAddServiceRow = () => {
    setServices(prev => [...prev, { name: "", description: "", pricing: [{ price: 0, unit: "lượt" }] }]);
  };

  const handleRemoveServiceRow = (index: number) => {
    if (services.length === 1) {
      toast.error("Gói dịch vụ phải có ít nhất 1 dịch vụ");
      return;
    }
    setServices(prev => prev.filter((_, i) => i !== index));
  };

  const handleServiceFieldChange = (index: number, field: "name" | "description", value: string) => {
    setServices(prev => {
      const updated = [...prev];
      updated[index] = {
        ...updated[index],
        [field]: value
      };
      return updated;
    });
  };

  // Pricing Options handlers inside a specific service row
  const handleAddPricingOption = (serviceIdx: number) => {
    setServices(prev => {
      const updated = [...prev];
      updated[serviceIdx] = {
        ...updated[serviceIdx],
        pricing: [...(updated[serviceIdx].pricing || []), { price: 0, unit: "lượt" }]
      };
      return updated;
    });
  };

  const handleRemovePricingOption = (serviceIdx: number, pricingIdx: number) => {
    setServices(prev => {
      const updated = [...prev];
      const currentPricing = updated[serviceIdx].pricing || [];
      if (currentPricing.length === 1) {
        toast.error("Mỗi dịch vụ phải có ít nhất 1 mức giá cấu hình");
        return prev;
      }
      updated[serviceIdx] = {
        ...updated[serviceIdx],
        pricing: currentPricing.filter((_, i) => i !== pricingIdx)
      };
      return updated;
    });
  };

  const handlePricingFieldChange = (
    serviceIdx: number,
    pricingIdx: number,
    field: "price" | "unit",
    value: any
  ) => {
    setServices(prev => {
      const updated = [...prev];
      const currentPricing = [...(updated[serviceIdx].pricing || [])];
      currentPricing[pricingIdx] = {
        ...currentPricing[pricingIdx],
        [field]: field === "price" ? Number(value) : value
      };
      updated[serviceIdx] = {
        ...updated[serviceIdx],
        pricing: currentPricing
      };
      return updated;
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!packageName.trim()) {
      toast.error("Vui lòng nhập tên gói dịch vụ");
      return;
    }

    const validServices = services.filter(s => s.name.trim() !== "");
    if (validServices.length === 0) {
      toast.error("Vui lòng điền thông tin cho ít nhất 1 dịch vụ");
      return;
    }

    // Clean up empty pricing options and set defaults if missing
    const cleanedServices = validServices.map(s => {
      const pricing = s.pricing && s.pricing.length > 0
        ? s.pricing
        : [{ price: 0, unit: "lượt" }];
      return {
        ...s,
        pricing
      };
    });

    const payload = {
      name: packageName.trim(),
      services: cleanedServices
    };

    if (editingPackage) {
      updateMutation.mutate({ id: editingPackage._id, data: payload });
    } else {
      createMutation.mutate(payload);
    }
  };

  const handleDelete = (id: string) => {
    if (confirm("Bạn có chắc chắn muốn xóa gói dịch vụ này?")) {
      deleteMutation.mutate(id);
    }
  };

  return (
    <div className="container mx-auto p-6 max-w-7xl min-h-screen">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Package className="h-8 w-8 text-primary" />
            Gói dịch vụ bổ sung
          </h1>
          <p className="text-muted-foreground mt-1 text-sm max-w-2xl">
            Tạo các gói dịch vụ mẫu để áp dụng nhanh cho Khu đất (Property) và Vị trí cắm trại (Site). 
            Mỗi dịch vụ hỗ trợ thiết lập nhiều tùy chọn giá khác nhau (theo giờ, theo ngày, theo lượt...).
          </p>
        </div>

        <Button
          onClick={openCreateDialog}
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl shadow-lg shadow-primary/10 dark:shadow-none transition-all flex items-center gap-2"
        >
          <Plus className="h-5 w-5" />
          Tạo gói dịch vụ
        </Button>
      </div>

      {/* Grid Packages list */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map(i => (
            <Card key={i} className="animate-pulse border border-slate-200 dark:border-slate-800">
              <CardHeader className="h-28 bg-slate-100 dark:bg-slate-900 rounded-t-xl" />
              <CardContent className="h-40" />
            </Card>
          ))}
        </div>
      ) : packages.length === 0 ? (
        <div className="text-center py-16 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 max-w-xl mx-auto shadow-sm">
          <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-primary/20">
            <Package className="h-8 w-8 text-primary" />
          </div>
          <h3 className="text-xl font-bold text-slate-800 dark:text-slate-200">Chưa có gói dịch vụ nào</h3>
          <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
            Tạo gói dịch vụ giúp bạn lưu sẵn danh sách tên và các mức giá để gán nhanh khi cấu hình Property/Site, không cần gõ lại từ đầu.
          </p>
          <Button
            onClick={openCreateDialog}
            className="mt-6 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl"
          >
            Tạo ngay gói đầu tiên
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {packages.map(pkg => (
            <Card
              key={pkg._id}
              className="group relative overflow-hidden border-l-4 border-l-primary border-t border-r border-b border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 hover:shadow-xl hover:-translate-y-1 transition-all duration-300 rounded-2xl flex flex-col justify-between"
            >
              <div>
                <CardHeader className="pb-3 pt-5 px-5 border-b border-slate-100 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-950/20">
                  <div className="flex items-center justify-between gap-3">
                    <CardTitle className="text-lg font-bold text-slate-850 dark:text-slate-100 truncate group-hover:text-primary transition-colors">
                      {pkg.name}
                    </CardTitle>
                    <div className="flex items-center gap-1 shrink-0 opacity-80 md:opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => openEditDialog(pkg)}
                        className="h-8 w-8 text-slate-400 hover:text-primary hover:bg-primary/10 rounded-lg transition-colors"
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDelete(pkg._id)}
                        className="h-8 w-8 text-slate-400 hover:text-red-650 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-lg transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <span className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-350">
                      Gồm {pkg.services?.length || 0} dịch vụ con
                    </span>
                  </div>
                </CardHeader>
                <CardContent className="p-5 space-y-3.5 flex-1 bg-white dark:bg-slate-900">
                  {pkg.services.map((service, idx) => (
                    <div
                      key={idx}
                      className="group/item flex flex-col gap-2.5 p-4 rounded-xl border border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30 hover:bg-white dark:hover:bg-slate-950 hover:shadow-md hover:border-slate-200 dark:hover:border-slate-850 transition-all duration-200"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="font-semibold text-sm text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                          <span className="h-1.5 w-1.5 rounded-full bg-primary shrink-0 animate-pulse" />
                          {service.name}
                        </p>
                        {service.description && (
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed pl-3">
                            {service.description}
                          </p>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-1.5 mt-0.5 pl-3">
                        {service.pricing?.map((priceOpt, pIdx) => (
                          <Badge
                            key={pIdx}
                            className="bg-primary/5 hover:bg-primary/10 text-primary font-semibold border border-primary/10 text-[10px] py-0.5 px-2 rounded-lg transition-colors shadow-2xs"
                          >
                            {priceOpt.price.toLocaleString("vi-VN")} đ / {priceOpt.unit}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="max-w-5xl overflow-y-auto max-h-[85vh] rounded-2xl border border-slate-200 dark:border-slate-800">
          <DialogHeader>
            <DialogTitle className="text-xl font-bold">
              {editingPackage ? "Chỉnh sửa gói dịch vụ" : "Tạo gói dịch vụ mới"}
            </DialogTitle>
            <DialogDescription>
              Tạo gói các dịch vụ của bạn. Mỗi dịch vụ có thể thêm nhiều loại đơn giá tương ứng (ví dụ: giá thuê theo giờ, giá thuê theo ngày).
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="pkgName" className="font-semibold">Tên gói dịch vụ mẫu</Label>
              <Input
                id="pkgName"
                placeholder="Ví dụ: Gói dịch vụ cắm trại, gói ẩm thực tự chọn..."
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                className="rounded-xl border-slate-200 dark:border-slate-800 focus-visible:ring-primary"
                required
              />
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between border-b pb-2">
                <h3 className="font-semibold text-slate-800 dark:text-slate-200">Danh sách các dịch vụ</h3>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAddServiceRow}
                  className="border-primary text-primary hover:bg-primary/10 text-xs rounded-xl flex items-center gap-1"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Thêm dịch vụ
                </Button>
              </div>

              <div className="space-y-6">
                {services.map((service, index) => (
                  <div
                    key={index}
                    className="flex flex-col gap-4 p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 relative group shadow-sm"
                  >
                    {/* Upper row: Name & Description */}
                    <div className="flex flex-col md:flex-row gap-4">
                      <div className="flex-1 space-y-1.5">
                        <Label className="text-xs font-bold text-slate-500 dark:text-slate-400">Tên dịch vụ</Label>
                        <Input
                          placeholder="Ví dụ: Cho thuê SUP chèo, Đặt tiệc BBQ ngoài trời"
                          value={service.name}
                          onChange={(e) => handleServiceFieldChange(index, "name", e.target.value)}
                          className="rounded-xl text-sm border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
                          required
                        />
                      </div>

                      <div className="flex-[1.5] space-y-1.5">
                        <Label className="text-xs font-bold text-slate-500 dark:text-slate-400">Mô tả chi tiết</Label>
                        <Input
                          placeholder="Mô tả các phụ kiện đi kèm hoặc quy định dịch vụ..."
                          value={service.description}
                          onChange={(e) => handleServiceFieldChange(index, "description", e.target.value)}
                          className="rounded-xl text-sm border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
                        />
                      </div>

                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => handleRemoveServiceRow(index)}
                        className="absolute right-3 top-3 md:relative md:top-auto md:right-auto md:self-end text-slate-400 hover:text-red-650 hover:bg-red-50 dark:hover:bg-red-950/20 h-10 w-10 rounded-xl"
                      >
                        <Trash2 className="h-5 w-5" />
                      </Button>
                    </div>

                    {/* Lower block: Multi-pricing options configuration */}
                    <div className="border-t border-slate-200/60 dark:border-slate-800/60 pt-3 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-500 dark:text-slate-400">Cấu hình đơn giá dịch vụ:</span>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => handleAddPricingOption(index)}
                          className="h-8 text-primary hover:bg-primary/10 text-xs rounded-xl flex items-center gap-1.5"
                        >
                          <Plus className="h-3.5 w-3.5" />
                          Thêm đơn giá mới (vd: theo giờ, theo ngày)
                        </Button>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {service.pricing?.map((priceOpt, pIdx) => (
                          <div
                            key={pIdx}
                            className="flex items-center gap-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-2.5 rounded-xl group/price"
                          >
                            <div className="flex-1 flex items-center gap-2 min-w-0">
                              <Input
                                type="number"
                                min="0"
                                placeholder="Đơn giá"
                                value={priceOpt.price ?? ""}
                                onChange={(e) => handlePricingFieldChange(index, pIdx, "price", e.target.value)}
                                className="h-9 rounded-lg text-sm border-slate-200 dark:border-slate-800 w-full"
                                required
                              />
                              <span className="text-xs text-slate-400 shrink-0">đ /</span>
                              <Select
                                value={priceOpt.unit || "lượt"}
                                onValueChange={(val) => handlePricingFieldChange(index, pIdx, "unit", val)}
                              >
                                <SelectTrigger className="h-9 rounded-lg text-sm border-slate-200 dark:border-slate-800 w-24 shrink-0 focus:ring-primary">
                                  <SelectValue placeholder="Đơn vị..." />
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
                            </div>

                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              onClick={() => handleRemovePricingOption(index, pIdx)}
                              className="h-8 w-8 text-slate-400 hover:text-red-650 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-lg shrink-0"
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <DialogFooter className="gap-2 border-t pt-4">
              <Button type="button" variant="outline" onClick={closeDialog} className="rounded-xl">
                Hủy bỏ
              </Button>
              <Button
                type="submit"
                disabled={createMutation.isPending || updateMutation.isPending}
                className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl px-5 flex items-center gap-2"
              >
                {createMutation.isPending || updateMutation.isPending ? (
                  <>
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                    Đang lưu...
                  </>
                ) : (
                  <>
                    <Check className="h-4 w-4" />
                    Lưu gói dịch vụ
                  </>
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
