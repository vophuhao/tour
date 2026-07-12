"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Plus,
  Edit2,
  Trash2,
  Ticket,
  Calendar,
  Tag,
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
import {
  createPromoCode,
  getMyPromoCodes,
  updatePromoCode,
  deletePromoCode,
} from "@/services/promo-code.service";

export default function HostPromotionsPage() {
  const queryClient = queryClientHook();
  function queryClientHook() {
    try {
      return useQueryClient();
    } catch {
      return null as any;
    }
  }

  // Dialog States
  const [promoDialogOpen, setPromoDialogOpen] = useState(false);
  const [editingPromo, setEditingPromo] = useState<any | null>(null);

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
  const [minGuests, setMinGuests] = useState<number | undefined>(undefined);
  const [minBookingQuantity, setMinBookingQuantity] = useState<number | undefined>(undefined);
  const [minNights, setMinNights] = useState<number | undefined>(undefined);

  // Queries
  const { data: propertiesResponse } = useQuery<any>({
    queryKey: ["my-properties"],
    queryFn: () => getMyProperties(),
  });
  const properties = propertiesResponse?.data?.properties || [];

  const { data: promoCodes = [], isLoading: loadingPromos } = useQuery<any>({
    queryKey: ["promo-codes"],
    queryFn: async () => {
      const res = await getMyPromoCodes();
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
    setMinGuests(undefined);
    setMinBookingQuantity(undefined);
    setMinNights(undefined);
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
    setMinGuests(promo.minGuests);
    setMinBookingQuantity(promo.minBookingQuantity);
    setMinNights(promo.minNights);
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
      minGuests: minGuests || undefined,
      minBookingQuantity: minBookingQuantity || undefined,
      minNights: minNights || undefined,
    };

    if (editingPromo) {
      updatePromoMutation.mutate({ id: editingPromo._id, data: payload });
    } else {
      createPromoMutation.mutate(payload);
    }
  };

  return (
    <div className="container mx-auto p-6 max-w-7xl min-h-screen">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            Ưu đãi
          </h1>
        </div>

        <Button
          onClick={openCreatePromo}
          className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl shadow-lg shadow-primary/10 transition-all flex items-center gap-2"
        >
          <Plus className="h-5 w-5" />
          Tạo mã giảm giá
        </Button>
      </div>

      {/* Promotions Codes Content */}
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
                    {promo.minGuests && (
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-500">Số khách tối thiểu:</span>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          {promo.minGuests} người
                        </span>
                      </div>
                    )}
                    {promo.minNights && (
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-500">Số đêm tối thiểu:</span>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          {promo.minNights} đêm
                        </span>
                      </div>
                    )}
                    {promo.minBookingQuantity && (
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-slate-500">Số lều tối thiểu:</span>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">
                          {promo.minBookingQuantity} lều
                        </span>
                      </div>
                    )}
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

      {/* Promo Code Dialog */}
      <Dialog open={promoDialogOpen} onOpenChange={setPromoDialogOpen}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto rounded-2xl border border-slate-200 dark:border-slate-800">
          <DialogHeader>
            <DialogTitle className="text-xl font-bold">
              {editingPromo ? "Chỉnh sửa mã giảm giá" : "Tạo mã giảm giá mới"}
            </DialogTitle>

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

            {/* Advanced Application Conditions Section */}
            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-900/30 space-y-3">
              <div className="flex items-center gap-2 pb-1 border-b border-slate-100 dark:border-slate-800">

                <h4 className="text-sm font-semibold text-slate-850 dark:text-slate-200">
                  Điều kiện áp dụng nâng cao
                </h4>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="minGuests" className="text-xs font-semibold text-slate-600 dark:text-slate-300">Số khách tối thiểu</Label>
                  <Input
                    id="minGuests"
                    type="number"
                    min="1"
                    placeholder="Ví dụ: 30"
                    value={minGuests || ""}
                    onChange={(e) => setMinGuests(e.target.value ? Number(e.target.value) : undefined)}
                    className="rounded-xl border-slate-200 focus-visible:ring-primary h-9 text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="minNights" className="text-xs font-semibold text-slate-600 dark:text-slate-300">Số đêm tối thiểu</Label>
                  <Input
                    id="minNights"
                    type="number"
                    min="1"
                    placeholder="Ví dụ: 4"
                    value={minNights || ""}
                    onChange={(e) => setMinNights(e.target.value ? Number(e.target.value) : undefined)}
                    className="rounded-xl border-slate-200 focus-visible:ring-primary h-9 text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="minBookingQty" className="text-xs font-semibold text-slate-600 dark:text-slate-300">Số lều tối thiểu</Label>
                  <Input
                    id="minBookingQty"
                    type="number"
                    min="1"
                    placeholder="Ví dụ: 2"
                    value={minBookingQuantity || ""}
                    onChange={(e) => setMinBookingQuantity(e.target.value ? Number(e.target.value) : undefined)}
                    className="rounded-xl border-slate-200 focus-visible:ring-primary h-9 text-sm"
                  />
                </div>
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
    </div>
  );
}
