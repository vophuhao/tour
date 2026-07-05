"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  Edit2,
  Trash2,
  Ticket,
  Sparkles,
  Calendar,
  Percent,
  DollarSign,
  Check,
  X,
  PlusCircle,
  MinusCircle,
  Tag,
  Building,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getMyProperties } from "@/lib/client-actions";
import { getPropertyWithSites } from "@/lib/property-site-api";
import {
  createPromoCode,
  getMyPromoCodes,
  updatePromoCode,
  deletePromoCode,
} from "@/services/promo-code.service";
import {
  createCombo,
  getMyCombos,
  updateCombo,
  deleteCombo,
} from "@/services/combo.service";

export default function HostPromotionsPage() {
  const queryClient = queryClientHook();
  function queryClientHook() {
    try {
      return useQueryClient();
    } catch {
      return null as any;
    }
  }

  const [activeTab, setActiveTab] = useState<"promo" | "combo">("promo");
  
  // Dialog States
  const [promoDialogOpen, setPromoDialogOpen] = useState(false);
  const [editingPromo, setEditingPromo] = useState<any | null>(null);
  const [comboDialogOpen, setComboDialogOpen] = useState(false);
  const [editingCombo, setEditingCombo] = useState<any | null>(null);

  // Form states - Promo
  const [promoCode, setPromoCode] = useState("");
  const [promoDesc, setPromoDesc] = useState("");
  const [discountType, setDiscountType] = useState<"percentage" | "flat">("percentage");
  const [discountValue, setDiscountValue] = useState(0);
  const [maxDiscount, setMaxDiscount] = useState<number | undefined>(undefined);
  const [minSubtotal, setMinSubtotal] = useState(0);
  const [promoProps, setPromoProps] = useState<string[]>([]);
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [usageLimit, setUsageLimit] = useState<number | undefined>(undefined);
  const [promoActive, setPromoActive] = useState(true);

  // Form states - Combo
  const [comboName, setComboName] = useState("");
  const [comboDesc, setComboDesc] = useState("");
  const [selectedProperty, setSelectedProperty] = useState("");
  const [applicableSites, setApplicableSites] = useState<string[]>([]);
  const [servicesIncluded, setServicesIncluded] = useState<Array<{ name: string; quantity: number }>>([
    { name: "", quantity: 1 }
  ]);
  const [comboDiscountType, setComboDiscountType] = useState<"percentage" | "fixed_price">("percentage");
  const [comboDiscountValue, setComboDiscountValue] = useState(0);
  const [comboActive, setComboActive] = useState(true);

  // Queries
  const { data: propertiesResponse } = useQuery<any>({
    queryKey: ["my-properties"],
    queryFn: () => getMyProperties(),
  });
  const properties = propertiesResponse?.data?.properties || [];

  // Query sites when property is selected for combo
  const { data: propertyDetails } = useQuery<any>({
    queryKey: ["property-sites", selectedProperty],
    queryFn: () => getPropertyWithSites(selectedProperty),
    enabled: !!selectedProperty,
  });
  const propertySites = propertyDetails?.data?.sites || [];
  const propertyServices = propertyDetails?.data?.property?.services || [];

  const { data: promoCodes = [], isLoading: loadingPromos } = useQuery<any>({
    queryKey: ["promo-codes"],
    queryFn: async () => {
      const res = await getMyPromoCodes();
      return res.data || [];
    },
  });

  const { data: combos = [], isLoading: loadingCombos } = useQuery<any>({
    queryKey: ["combos"],
    queryFn: async () => {
      const res = await getMyCombos();
      return res.data || [];
    },
  });

  // Mutations - Promo
  const createPromoMutation = useMutation({
    mutationFn: createPromoCode,
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Tạo mã giảm giá thành công!");
        queryClient.invalidateQueries({ queryKey: ["promo-codes"] });
        closePromoDialog();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
  });

  const updatePromoMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => updatePromoCode(id, data),
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Cập nhật thành công!");
        queryClient.invalidateQueries({ queryKey: ["promo-codes"] });
        closePromoDialog();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
  });

  const deletePromoMutation = useMutation({
    mutationFn: deletePromoCode,
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Đã xóa mã giảm giá!");
        queryClient.invalidateQueries({ queryKey: ["promo-codes"] });
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
  });

  // Mutations - Combo
  const createComboMutation = useMutation({
    mutationFn: createCombo,
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Tạo gói combo thành công!");
        queryClient.invalidateQueries({ queryKey: ["combos"] });
        closeComboDialog();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
  });

  const updateComboMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => updateCombo(id, data),
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Cập nhật combo thành công!");
        queryClient.invalidateQueries({ queryKey: ["combos"] });
        closeComboDialog();
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
  });

  const deleteComboMutation = useMutation({
    mutationFn: deleteCombo,
    onSuccess: (res: any) => {
      if (res.success) {
        toast.success("Đã xóa gói combo!");
        queryClient.invalidateQueries({ queryKey: ["combos"] });
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    },
  });

  // Handlers - Promo Dialog
  const openCreatePromo = () => {
    setEditingPromo(null);
    setPromoCode("");
    setPromoDesc("");
    setDiscountType("percentage");
    setDiscountValue(0);
    setMaxDiscount(undefined);
    setMinSubtotal(0);
    setPromoProps([]);
    setStartDate("");
    setEndDate("");
    setUsageLimit(undefined);
    setPromoActive(true);
    setPromoDialogOpen(true);
  };

  const openEditPromo = (promo: any) => {
    setEditingPromo(promo);
    setPromoCode(promo.code);
    setPromoDesc(promo.description);
    setDiscountType(promo.discountType);
    setDiscountValue(promo.discountValue);
    setMaxDiscount(promo.maxDiscountAmount);
    setMinSubtotal(promo.minSubtotal || 0);
    setPromoProps(promo.applicableProperties || []);
    setStartDate(new Date(promo.startDate).toISOString().slice(0, 16));
    setEndDate(new Date(promo.endDate).toISOString().slice(0, 16));
    setUsageLimit(promo.usageLimit);
    setPromoActive(promo.isActive);
    setPromoDialogOpen(true);
  };

  const closePromoDialog = () => {
    setPromoDialogOpen(false);
    setEditingPromo(null);
  };

  const handlePromoSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const payload = {
      code: promoCode.trim().toUpperCase(),
      description: promoDesc,
      discountType,
      discountValue,
      maxDiscountAmount: maxDiscount || undefined,
      minSubtotal,
      applicableProperties: promoProps,
      startDate: new Date(startDate).toISOString(),
      endDate: new Date(endDate).toISOString(),
      usageLimit: usageLimit || undefined,
      isActive: promoActive,
    };

    if (editingPromo) {
      updatePromoMutation.mutate({ id: editingPromo._id, data: payload });
    } else {
      createPromoMutation.mutate(payload);
    }
  };

  // Handlers - Combo Dialog
  const openCreateCombo = () => {
    setEditingCombo(null);
    setComboName("");
    setComboDesc("");
    setSelectedProperty("");
    setApplicableSites([]);
    setServicesIncluded([{ name: "", quantity: 1 }]);
    setComboDiscountType("percentage");
    setComboDiscountValue(0);
    setComboActive(true);
    setComboDialogOpen(true);
  };

  const openEditCombo = (combo: any) => {
    setEditingCombo(combo);
    setComboName(combo.name);
    setComboDesc(combo.description);
    setSelectedProperty(combo.propertyId);
    setApplicableSites(combo.applicableSites?.map((s: any) => s._id || s) || []);
    setServicesIncluded(combo.servicesIncluded || [{ name: "", quantity: 1 }]);
    setComboDiscountType(combo.discountType);
    setComboDiscountValue(combo.discountValue);
    setComboActive(combo.isActive);
    setComboDialogOpen(true);
  };

  const closeComboDialog = () => {
    setComboDialogOpen(false);
    setEditingCombo(null);
  };

  const handleComboSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanServices = servicesIncluded.filter((s) => s.name.trim() !== "");
    if (cleanServices.length === 0) {
      toast.error("Vui lòng thêm ít nhất 1 dịch vụ vào combo");
      return;
    }

    const payload = {
      name: comboName.trim(),
      description: comboDesc,
      propertyId: selectedProperty,
      applicableSites,
      servicesIncluded: cleanServices,
      discountType: comboDiscountType,
      discountValue: comboDiscountValue,
      isActive: comboActive,
    };

    if (editingCombo) {
      updateComboMutation.mutate({ id: editingCombo._id, data: payload });
    } else {
      createComboMutation.mutate(payload);
    }
  };

  const handleAddServiceRow = () => {
    setServicesIncluded((prev) => [...prev, { name: "", quantity: 1 }]);
  };

  const handleRemoveServiceRow = (idx: number) => {
    setServicesIncluded((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleServiceChange = (idx: number, field: "name" | "quantity", value: any) => {
    setServicesIncluded((prev) => {
      const updated = [...prev];
      updated[idx] = { ...updated[idx], [field]: value };
      return updated;
    });
  };

  return (
    <div className="container mx-auto p-6 max-w-7xl min-h-screen">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Sparkles className="h-8 w-8 text-primary" />
            Ưu đãi & Combo dịch vụ
          </h1>
          <p className="text-muted-foreground mt-1 text-sm max-w-2xl">
            Tạo các chương trình khuyến mãi (coupon) hoặc các gói combo phòng kèm dịch vụ ăn uống, chèo SUP để tăng doanh thu cắm trại.
          </p>
        </div>

        <Button
          onClick={activeTab === "promo" ? openCreatePromo : openCreateCombo}
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl shadow-lg shadow-primary/10 transition-all flex items-center gap-2"
        >
          <Plus className="h-5 w-5" />
          {activeTab === "promo" ? "Tạo mã giảm giá" : "Tạo gói combo"}
        </Button>
      </div>

      {/* Tabs Toggles */}
      <div className="flex gap-2 p-1 bg-slate-100 dark:bg-slate-900 rounded-xl max-w-md mb-8 border border-slate-200/55 dark:border-slate-800">
        <button
          onClick={() => setActiveTab("promo")}
          className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-all ${
            activeTab === "promo"
              ? "bg-white dark:bg-slate-800 text-primary shadow-sm"
              : "text-slate-500 hover:text-slate-800 dark:hover:text-slate-250"
          }`}
        >
          Mã giảm giá (Coupons)
        </button>
        <button
          onClick={() => setActiveTab("combo")}
          className={`flex-1 py-2 text-sm font-semibold rounded-lg transition-all ${
            activeTab === "combo"
              ? "bg-white dark:bg-slate-800 text-primary shadow-sm"
              : "text-slate-500 hover:text-slate-800 dark:hover:text-slate-250"
          }`}
        >
          Gói Combo dịch vụ
        </button>
      </div>

      {/* Promotions Codes Tab Content */}
      {activeTab === "promo" && (
        <>
          {loadingPromos ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[1, 2, 3].map((i) => (
                <Card key={i} className="animate-pulse border border-slate-200 dark:border-slate-800">
                  <div className="h-44 bg-slate-100 dark:bg-slate-900 rounded-xl" />
                </Card>
              ))}
            </div>
          ) : promoCodes.length === 0 ? (
            <div className="text-center py-16 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 max-w-xl mx-auto shadow-sm">
              <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-primary/20">
                <Ticket className="h-8 w-8 text-primary" />
              </div>
              <h3 className="text-xl font-bold text-slate-800 dark:text-slate-200">Chưa có mã giảm giá nào</h3>
              <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
                Tạo mã coupon giảm giá (Ví dụ: `PINESUMMER`) để tặng cho khách hàng đặt phòng cắm trại tại các khu đất của bạn.
              </p>
              <Button onClick={openCreatePromo} className="mt-6 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl">
                Tạo mã đầu tiên
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {promoCodes.map((promo: any) => (
                <Card
                  key={promo._id}
                  className="group relative overflow-hidden border-l-4 border-l-primary border-t border-r border-b border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 hover:shadow-xl hover:-translate-y-1 transition-all duration-300 rounded-2xl flex flex-col justify-between"
                >
                  <CardHeader className="pb-3 pt-5 px-5 border-b border-slate-100 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-950/20">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <Tag className="h-4 w-4 text-primary" />
                        <CardTitle className="text-lg font-bold text-slate-850 dark:text-slate-100 truncate">
                          {promo.code}
                        </CardTitle>
                      </div>
                      <div className="flex items-center gap-1 shrink-0 opacity-80 md:opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openEditPromo(promo)}
                          className="h-8 w-8 text-slate-400 hover:text-primary hover:bg-primary/10 rounded-lg transition-colors"
                        >
                          <Edit2 className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            if (confirm("Bạn có chắc chắn muốn xóa mã giảm giá này?")) {
                              deletePromoMutation.mutate(promo._id);
                            }
                          }}
                          className="h-8 w-8 text-slate-400 hover:text-red-650 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-lg transition-colors"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    {promo.description && (
                      <CardDescription className="text-xs mt-1 text-slate-500 line-clamp-1">
                        {promo.description}
                      </CardDescription>
                    )}
                  </CardHeader>
                  <CardContent className="p-5 space-y-4">
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-slate-500">Giảm giá:</span>
                      <Badge className="bg-primary/10 text-primary font-bold border border-primary/20">
                        {promo.discountType === "percentage" ? `${promo.discountValue}%` : `${promo.discountValue.toLocaleString()} đ`}
                      </Badge>
                    </div>
                    {promo.maxDiscountAmount && (
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-500">Giảm tối đa:</span>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          {promo.maxDiscountAmount.toLocaleString()} đ
                        </span>
                      </div>
                    )}
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-slate-500">Đơn hàng tối thiểu:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">
                        {promo.minSubtotal ? `${promo.minSubtotal.toLocaleString()} đ` : "Không có"}
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-slate-500">Lượt sử dụng:</span>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">
                        {promo.usageCount} / {promo.usageLimit || "∞"} lượt
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-xs text-slate-400 border-t pt-3">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3.5 w-3.5" />
                        {new Date(promo.startDate).toLocaleDateString("vi-VN")} - {new Date(promo.endDate).toLocaleDateString("vi-VN")}
                      </span>
                      <Badge variant={promo.isActive ? "default" : "secondary"} className="text-[9px]">
                        {promo.isActive ? "Hoạt động" : "Tắt"}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </>
      )}

      {/* Combos Tab Content */}
      {activeTab === "combo" && (
        <>
          {loadingCombos ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[1, 2, 3].map((i) => (
                <Card key={i} className="animate-pulse border border-slate-200 dark:border-slate-800">
                  <div className="h-44 bg-slate-100 dark:bg-slate-900 rounded-xl" />
                </Card>
              ))}
            </div>
          ) : combos.length === 0 ? (
            <div className="text-center py-16 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 max-w-xl mx-auto shadow-sm">
              <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-primary/20">
                <Sparkles className="h-8 w-8 text-primary" />
              </div>
              <h3 className="text-xl font-bold text-slate-800 dark:text-slate-200">Chưa có gói combo nào</h3>
              <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
                Tạo gói combo bao gồm đêm cắm trại tại một vị trí cắm trại cụ thể và các dịch vụ đi kèm để kích thích người dùng đặt trọn gói.
              </p>
              <Button onClick={openCreateCombo} className="mt-6 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl">
                Tạo combo đầu tiên
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {combos.map((combo: any) => (
                <Card
                  key={combo._id}
                  className="group relative overflow-hidden border-l-4 border-l-primary border-t border-r border-b border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 hover:shadow-xl hover:-translate-y-1 transition-all duration-300 rounded-2xl flex flex-col justify-between"
                >
                  <CardHeader className="pb-3 pt-5 px-5 border-b border-slate-100 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-950/20">
                    <div className="flex items-center justify-between gap-3">
                      <CardTitle className="text-lg font-bold text-slate-850 dark:text-slate-100 truncate">
                        {combo.name}
                      </CardTitle>
                      <div className="flex items-center gap-1 shrink-0 opacity-80 md:opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => openEditCombo(combo)}
                          className="h-8 w-8 text-slate-400 hover:text-primary hover:bg-primary/10 rounded-lg transition-colors"
                        >
                          <Edit2 className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            if (confirm("Bạn có chắc chắn muốn xóa gói combo này?")) {
                              deleteComboMutation.mutate(combo._id);
                            }
                          }}
                          className="h-8 w-8 text-slate-400 hover:text-red-650 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-lg transition-colors"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    {combo.description && (
                      <CardDescription className="text-xs mt-1 text-slate-500 line-clamp-1">
                        {combo.description}
                      </CardDescription>
                    )}
                  </CardHeader>
                  <CardContent className="p-5 space-y-4">
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-slate-500">Mức chiết khấu combo:</span>
                      <Badge className="bg-primary/10 text-primary font-bold border border-primary/20">
                        {combo.discountType === "percentage" ? `Giảm ${combo.discountValue}%` : `Giá cố định: ${combo.discountValue.toLocaleString()} đ`}
                      </Badge>
                    </div>

                    <div className="space-y-1.5 border-t pt-3">
                      <span className="text-xs font-bold text-slate-400 block uppercase tracking-wider">Dịch vụ đi kèm:</span>
                      <div className="space-y-1">
                        {combo.servicesIncluded?.map((srv: any, idx: number) => (
                          <div key={idx} className="flex justify-between text-sm text-slate-650 dark:text-slate-350 pl-2 border-l border-slate-200">
                            <span>{srv.name}</span>
                            <span className="font-semibold text-slate-800 dark:text-slate-200">x{srv.quantity}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="flex justify-between items-center text-xs text-slate-400 border-t pt-3">
                      <span className="flex items-center gap-1">
                        <Building className="h-3.5 w-3.5" />
                        Áp dụng: {combo.applicableSites?.length || 0} vị trí (sites)
                      </span>
                      <Badge variant={combo.isActive ? "default" : "secondary"} className="text-[9px]">
                        {combo.isActive ? "Hoạt động" : "Tắt"}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </>
      )}

      {/* Promo Code Dialog */}
      <Dialog open={promoDialogOpen} onOpenChange={setPromoDialogOpen}>
        <DialogContent className="max-w-xl rounded-2xl border border-slate-200 dark:border-slate-800">
          <DialogHeader>
            <DialogTitle className="text-xl font-bold">
              {editingPromo ? "Chỉnh sửa mã giảm giá" : "Tạo mã giảm giá mới"}
            </DialogTitle>
            <DialogDescription>
              Tạo mã coupon giảm giá cho các dịch vụ cắm trại của bạn. Các mã này sẽ được khách hàng nhập tại khung thanh toán.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handlePromoSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="code" className="font-semibold">Mã giảm giá (Coupon Code)</Label>
              <Input
                id="code"
                placeholder="Ví dụ: PINELOVE20, GIAM50K..."
                value={promoCode}
                onChange={(e) => setPromoCode(e.target.value.toUpperCase())}
                disabled={!!editingPromo}
                className="rounded-xl border-slate-200 focus-visible:ring-primary uppercase font-bold"
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="description" className="font-semibold">Mô tả chương trình</Label>
              <Input
                id="description"
                placeholder="Ví dụ: Giảm giá 20% tổng đơn cắm trại dịp hè..."
                value={promoDesc}
                onChange={(e) => setPromoDesc(e.target.value)}
                className="rounded-xl border-slate-200 focus-visible:ring-primary"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label className="font-semibold">Loại giảm giá</Label>
                <Select value={discountType} onValueChange={(val: any) => setDiscountType(val)}>
                  <SelectTrigger className="rounded-xl border-slate-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl">
                    <SelectItem value="percentage">Chiết khấu (%)</SelectItem>
                    <SelectItem value="flat">Số tiền cố định (đ)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="discountValue" className="font-semibold">Giá trị giảm</Label>
                <div className="relative">
                  <Input
                    id="discountValue"
                    type="number"
                    min="0"
                    value={discountValue || ""}
                    onChange={(e) => setDiscountValue(Number(e.target.value))}
                    className="rounded-xl border-slate-200 focus-visible:ring-primary pr-8"
                    required
                  />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm">
                    {discountType === "percentage" ? "%" : "đ"}
                  </span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="maxDiscount" className="font-semibold">Giảm tối đa (đ) (Optional)</Label>
                <Input
                  id="maxDiscount"
                  type="number"
                  placeholder="Để trống nếu không giới hạn"
                  value={maxDiscount || ""}
                  onChange={(e) => setMaxDiscount(e.target.value ? Number(e.target.value) : undefined)}
                  className="rounded-xl border-slate-200 focus-visible:ring-primary"
                  disabled={discountType === "flat"}
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="minSubtotal" className="font-semibold">Đơn hàng tối thiểu (đ)</Label>
                <Input
                  id="minSubtotal"
                  type="number"
                  value={minSubtotal || ""}
                  onChange={(e) => setMinSubtotal(Number(e.target.value))}
                  className="rounded-xl border-slate-200 focus-visible:ring-primary"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="startDate" className="font-semibold">Ngày bắt đầu</Label>
                <Input
                  id="startDate"
                  type="datetime-local"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="rounded-xl border-slate-200"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="endDate" className="font-semibold">Ngày kết thúc</Label>
                <Input
                  id="endDate"
                  type="datetime-local"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="rounded-xl border-slate-200"
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 items-center">
              <div className="space-y-1.5">
                <Label htmlFor="usageLimit" className="font-semibold">Giới hạn số lượt dùng (Optional)</Label>
                <Input
                  id="usageLimit"
                  type="number"
                  placeholder="Ví dụ: 100 lượt"
                  value={usageLimit || ""}
                  onChange={(e) => setUsageLimit(e.target.value ? Number(e.target.value) : undefined)}
                  className="rounded-xl border-slate-200 focus-visible:ring-primary"
                />
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl border border-slate-200 bg-slate-50/50 mt-5">
                <Label htmlFor="isActive" className="font-semibold cursor-pointer">Trạng thái hoạt động</Label>
                <Switch
                  id="isActive"
                  checked={promoActive}
                  onCheckedChange={setPromoActive}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="font-semibold">Áp dụng cho khu cắm trại</Label>
              <div className="grid grid-cols-2 gap-2 max-h-32 overflow-y-auto p-3 rounded-xl border border-slate-200 bg-slate-50/30">
                {properties.map((prop: any) => (
                  <label key={prop._id} className="flex items-start gap-2 text-sm text-slate-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={promoProps.includes(prop._id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setPromoProps((prev) => [...prev, prop._id]);
                        } else {
                          setPromoProps((prev) => prev.filter((id) => id !== prop._id));
                        }
                      }}
                      className="rounded border-slate-300 mt-1"
                    />
                    <span className="break-words">{prop.name}</span>
                  </label>
                ))}
              </div>
              <p className="text-[10px] text-slate-400">Nếu không chọn khu nào, mã sẽ tự động áp dụng cho tất cả các khu cắm trại của bạn.</p>
            </div>

            <DialogFooter className="gap-2 border-t pt-4">
              <Button type="button" variant="outline" onClick={closePromoDialog} className="rounded-xl">
                Hủy bỏ
              </Button>
              <Button
                type="submit"
                disabled={createPromoMutation.isPending || updatePromoMutation.isPending}
                className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl px-5"
              >
                {createPromoMutation.isPending || updatePromoMutation.isPending ? "Đang lưu..." : "Lưu mã giảm giá"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Combo Dialog */}
      <Dialog open={comboDialogOpen} onOpenChange={setComboDialogOpen}>
        <DialogContent className="max-w-3xl overflow-y-auto max-h-[85vh] rounded-2xl border border-slate-200 dark:border-slate-800">
          <DialogHeader>
            <DialogTitle className="text-xl font-bold">
              {editingCombo ? "Chỉnh sửa gói combo" : "Tạo gói combo mới"}
            </DialogTitle>
            <DialogDescription>
              Tạo gói cắm trại trọn gói bao gồm giá thuê Site (phòng) và các dịch vụ ăn uống, chèo thuyền đi kèm.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleComboSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="comboName" className="font-semibold">Tên gói combo</Label>
              <Input
                id="comboName"
                placeholder="Ví dụ: Combo Cuối Tuần Vui Vẻ, Trọn Gói BBQ SUP..."
                value={comboName}
                onChange={(e) => setComboName(e.target.value)}
                className="rounded-xl border-slate-200 focus-visible:ring-primary"
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="comboDesc" className="font-semibold">Mô tả combo</Label>
              <Input
                id="comboDesc"
                placeholder="Ví dụ: Đã bao gồm lều cắm trại VIP, 1 suất BBQ tối và chèo thuyền SUP miễn phí..."
                value={comboDesc}
                onChange={(e) => setComboDesc(e.target.value)}
                className="rounded-xl border-slate-200 focus-visible:ring-primary"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label className="font-semibold">Thuộc khu cắm trại (Property)</Label>
                <Select value={selectedProperty} onValueChange={(val: any) => setSelectedProperty(val)} disabled={!!editingCombo}>
                  <SelectTrigger className="rounded-xl border-slate-200">
                    <SelectValue placeholder="Chọn khu đất..." />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl">
                    {properties.map((prop: any) => (
                      <SelectItem key={prop._id} value={prop._id}>
                        {prop.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center justify-between p-3 rounded-xl border border-slate-200 bg-slate-50/50 mt-5">
                <Label htmlFor="comboActive" className="font-semibold cursor-pointer">Trạng thái hoạt động</Label>
                <Switch
                  id="comboActive"
                  checked={comboActive}
                  onCheckedChange={setComboActive}
                />
              </div>
            </div>

            {selectedProperty && (
              <div className="space-y-1.5">
                <Label className="font-semibold">Các vị trí cắm trại áp dụng (Sites)</Label>
                <div className="grid grid-cols-3 gap-2 p-3 rounded-xl border border-slate-200 bg-slate-50/30 max-h-32 overflow-y-auto">
                  {propertySites.map((site: any) => (
                    <label key={site._id} className="flex items-start gap-2 text-sm text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={applicableSites.includes(site._id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setApplicableSites((prev) => [...prev, site._id]);
                          } else {
                            setApplicableSites((prev) => prev.filter((id) => id !== site._id));
                          }
                        }}
                        className="rounded border-slate-300 mt-1"
                      />
                      <span className="break-words">{site.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            )}

            {/* Included Services Row Editor */}
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b pb-2">
                <Label className="font-semibold">Chọn các dịch vụ đi kèm trong Combo</Label>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAddServiceRow}
                  className="border-primary text-primary hover:bg-primary/10 text-xs rounded-xl flex items-center gap-1"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Thêm dịch vụ đi kèm
                </Button>
              </div>

              <div className="space-y-2.5 max-h-48 overflow-y-auto">
                {servicesIncluded.map((item, idx) => (
                  <div key={idx} className="flex items-center gap-3">
                    <div className="flex-1">
                      {selectedProperty && propertyServices.length > 0 ? (
                        <Select
                          value={item.name}
                          onValueChange={(val) => handleServiceChange(idx, "name", val)}
                        >
                          <SelectTrigger className="rounded-xl border-slate-200">
                            <SelectValue placeholder="Chọn dịch vụ mẫu..." />
                          </SelectTrigger>
                          <SelectContent className="rounded-xl">
                            {propertyServices.map((srv: any, sIdx: number) => (
                              <SelectItem key={sIdx} value={srv.name}>
                                {srv.name}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <Input
                          placeholder="Tên dịch vụ cắm trại..."
                          value={item.name}
                          onChange={(e) => handleServiceChange(idx, "name", e.target.value)}
                          className="rounded-xl border-slate-200 focus-visible:ring-primary"
                          required
                        />
                      )}
                    </div>
                    <div className="w-28 flex items-center gap-1.5 shrink-0">
                      <Input
                        type="number"
                        min="1"
                        placeholder="SL"
                        value={item.quantity}
                        onChange={(e) => handleServiceChange(idx, "quantity", Number(e.target.value))}
                        className="rounded-xl border-slate-200 focus-visible:ring-primary text-center"
                        required
                      />
                      <span className="text-xs text-slate-400">suất</span>
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => handleRemoveServiceRow(idx)}
                      disabled={servicesIncluded.length === 1}
                      className="text-slate-400 hover:text-red-650 rounded-xl"
                    >
                      <MinusCircle className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 border-t pt-4">
              <div className="space-y-1.5">
                <Label className="font-semibold">Hình thức giảm giá combo</Label>
                <Select value={comboDiscountType} onValueChange={(val: any) => setComboDiscountType(val)}>
                  <SelectTrigger className="rounded-xl border-slate-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="rounded-xl">
                    <SelectItem value="percentage">Chiết khấu trên tổng (%)</SelectItem>
                    <SelectItem value="fixed_price">Giá combo cố định trọn gói (đ)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="comboDiscountValue" className="font-semibold">Giá trị giảm/giá bán</Label>
                <div className="relative">
                  <Input
                    id="comboDiscountValue"
                    type="number"
                    min="0"
                    value={comboDiscountValue || ""}
                    onChange={(e) => setComboDiscountValue(Number(e.target.value))}
                    className="rounded-xl border-slate-200 focus-visible:ring-primary pr-8"
                    required
                  />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm">
                    {comboDiscountType === "percentage" ? "%" : "đ"}
                  </span>
                </div>
              </div>
            </div>

            <DialogFooter className="gap-2 border-t pt-4">
              <Button type="button" variant="outline" onClick={closeComboDialog} className="rounded-xl">
                Hủy bỏ
              </Button>
              <Button
                type="submit"
                disabled={createComboMutation.isPending || updateComboMutation.isPending}
                className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl px-5"
              >
                {createComboMutation.isPending || updateComboMutation.isPending ? "Đang lưu..." : "Lưu gói combo"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
