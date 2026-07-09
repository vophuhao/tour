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
  Tag,
  Building,
  Shield,
  User,
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
import { getPropertiesForAdmin } from "@/lib/client-actions";
import {
  createAdminPromo,
  getAdminPromos,
  updateAdminPromo,
  deleteAdminPromo,
} from "@/services/admin.service";

export default function AdminPromotionsPage() {
  const queryClient = useQueryClient();
  const [promoDialogOpen, setPromoDialogOpen] = useState(false);
  const [editingPromo, setEditingPromo] = useState<any | null>(null);

  // Form states
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
    queryKey: ["admin-properties-list"],
    queryFn: () => getPropertiesForAdmin(),
  });
  const properties = propertiesResponse?.data || [];

  const { data: promoResponse, isLoading: loadingPromos } = useQuery<any>({
    queryKey: ["admin-promos"],
    queryFn: () => getAdminPromos(),
  });
  const promoCodes = promoResponse?.data || [];

  // Mutations
  const createMutation = useMutation({
    mutationFn: createAdminPromo,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-promos"] });
      toast.success("Tạo mã giảm giá Admin thành công");
      setPromoDialogOpen(false);
      resetForm();
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.message || "Lỗi khi tạo mã giảm giá");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => updateAdminPromo(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-promos"] });
      toast.success("Cập nhật mã giảm giá thành công");
      setPromoDialogOpen(false);
      resetForm();
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.message || "Lỗi khi cập nhật");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteAdminPromo,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-promos"] });
      toast.success("Xóa mã giảm giá thành công");
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.message || "Lỗi khi xóa");
    },
  });

  const resetForm = () => {
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
    setEditingPromo(null);
  };

  const handleOpenCreate = () => {
    resetForm();
    setPromoDialogOpen(true);
  };

  const handleOpenEdit = (promo: any) => {
    setEditingPromo(promo);
    setPromoCode(promo.code);
    setPromoDesc(promo.description || "");
    setDiscountType(promo.discountType);
    setDiscountValue(promo.discountValue);
    setMaxDiscount(promo.maxDiscountAmount);
    setMinSubtotal(promo.minSubtotal || 0);
    setPromoProps(promo.applicableProperties || []);
    setStartDate(new Date(promo.startDate).toISOString().split("T")[0]);
    setEndDate(new Date(promo.endDate).toISOString().split("T")[0]);
    setUsageLimit(promo.usageLimit);
    setPromoActive(promo.isActive);
    setMinGuests(promo.minGuests);
    setMinBookingQuantity(promo.minBookingQuantity);
    setMinNights(promo.minNights);
    setPromoDialogOpen(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!promoCode) {
      toast.error("Vui lòng nhập mã giảm giá");
      return;
    }
    if (discountValue <= 0) {
      toast.error("Giá trị chiết khấu phải lớn hơn 0");
      return;
    }
    if (!startDate || !endDate) {
      toast.error("Vui lòng chọn thời gian áp dụng");
      return;
    }

    const payload = {
      code: promoCode,
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
      updateMutation.mutate({ id: editingPromo._id, data: payload });
    } else {
      createMutation.mutate(payload);
    }
  };

  const handleDelete = (id: string) => {
    if (confirm("Bạn có chắc chắn muốn xóa mã giảm giá này?")) {
      deleteMutation.mutate(id);
    }
  };

  const handleToggleProperty = (propId: string) => {
    setPromoProps((prev) =>
      prev.includes(propId) ? prev.filter((id) => id !== propId) : [...prev, propId]
    );
  };

  const isExpired = (endDateStr: string) => {
    return new Date(endDateStr) < new Date();
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-2">

            Khuyến mãi & Mã giảm giá
          </h1>

        </div>
        <Button onClick={handleOpenCreate} className="flex items-center gap-2">
          <Plus className="h-4 w-4" />
          Tạo mã giảm giá Admin
        </Button>
      </div>

      {/* Stats Summary */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="border-slate-100 dark:border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Mã giảm giá Admin (Global)</CardTitle>
            <Shield className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {promoCodes.filter((p: any) => p.scope === "global").length}
            </div>
            <p className="text-xs text-muted-foreground">Áp dụng toàn hệ thống, sàn chịu phí.</p>
          </CardContent>
        </Card>
        <Card className="border-slate-100 dark:border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Mã của Host</CardTitle>
            <User className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {promoCodes.filter((p: any) => p.scope === "host").length}
            </div>
            <p className="text-xs text-muted-foreground">Do Host tạo, trừ vào doanh thu của Host.</p>
          </CardContent>
        </Card>
        <Card className="border-slate-100 dark:border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Đang hoạt động</CardTitle>
            <Check className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {promoCodes.filter((p: any) => p.isActive && !isExpired(p.endDate)).length}
            </div>
            <p className="text-xs text-muted-foreground">Mã đang có hiệu lực sử dụng.</p>
          </CardContent>
        </Card>
      </div>

      {/* Promotions Table */}
      <Card className="border-slate-100 dark:border-slate-800">
        <CardHeader>
          <CardTitle>Danh sách mã giảm giá</CardTitle>
          <CardDescription>Danh sách toàn bộ mã giảm giá trên toàn hệ thống.</CardDescription>
        </CardHeader>
        <CardContent>
          {loadingPromos ? (
            <div className="text-center py-10 text-muted-foreground">Đang tải danh sách mã giảm giá...</div>
          ) : promoCodes.length === 0 ? (
            <div className="text-center py-10 text-muted-foreground">Chưa có mã giảm giá nào được tạo.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-100 dark:border-slate-800 text-slate-500 font-semibold">
                    <th className="py-3 px-4">Mã Code</th>
                    <th className="py-3 px-4">Loại mã</th>
                    <th className="py-3 px-4">Mức giảm giá</th>
                    <th className="py-3 px-4">Điều kiện áp dụng</th>
                    <th className="py-3 px-4">Thời gian</th>
                    <th className="py-3 px-4">Lượt dùng</th>
                    <th className="py-3 px-4">Trạng thái</th>
                    <th className="py-3 px-4 text-right">Thao tác</th>
                  </tr>
                </thead>
                <tbody>
                  {promoCodes.map((promo: any) => {
                    const expired = isExpired(promo.endDate);
                    return (
                      <tr
                        key={promo._id}
                        className="border-b border-slate-50 dark:border-slate-900 hover:bg-slate-50/50 dark:hover:bg-slate-900/50"
                      >
                        <td className="py-3 px-4 font-mono font-bold text-slate-900 dark:text-white">
                          {promo.code}
                        </td>
                        <td className="py-3 px-4">
                          {promo.scope === "global" ? (
                            <Badge variant="default" className="gap-1">
                              <Shield className="h-3 w-3" />
                              Admin (Sàn chịu phí)
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="gap-1 border-emerald-200 text-emerald-700 bg-emerald-50">
                              <User className="h-3 w-3" />
                              Host: {promo.host?.username || "Ẩn danh"}
                            </Badge>
                          )}
                        </td>
                        <td className="py-3 px-4 font-semibold text-slate-800 dark:text-slate-200">
                          {promo.discountType === "percentage" ? (
                            <span className="flex items-center gap-1">
                              <Percent className="h-3.5 w-3.5 text-primary" />
                              {promo.discountValue}%
                              {promo.maxDiscountAmount && (
                                <span className="text-xs text-muted-foreground font-normal">
                                  (tối đa {promo.maxDiscountAmount.toLocaleString()}đ)
                                </span>
                              )}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1">
                              <DollarSign className="h-3.5 w-3.5 text-emerald-500" />
                              {promo.discountValue.toLocaleString()} đ
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400 text-xs space-y-1">
                          <div>
                            <span className="font-medium text-slate-500">Đơn từ:</span> {promo.minSubtotal ? `${promo.minSubtotal.toLocaleString()}đ` : "0đ"}
                          </div>
                          {promo.minGuests && (
                            <div>
                              <span className="font-medium text-slate-500">Khách:</span> ≥{promo.minGuests} người
                            </div>
                          )}
                          {promo.minNights && (
                            <div>
                              <span className="font-medium text-slate-500">Đêm:</span> ≥{promo.minNights} đêm
                            </div>
                          )}
                          {promo.minBookingQuantity && (
                            <div>
                              <span className="font-medium text-slate-500">Lều:</span> ≥{promo.minBookingQuantity} lều
                            </div>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400 text-xs">
                          <span className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {new Date(promo.startDate).toLocaleDateString("vi-VN")} - {new Date(promo.endDate).toLocaleDateString("vi-VN")}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400">
                          {promo.usageCount} {promo.usageLimit ? `/ ${promo.usageLimit}` : ""}
                        </td>
                        <td className="py-3 px-4">
                          {expired ? (
                            <Badge variant="secondary" className="bg-red-50 text-red-700 border-red-150">Hết hạn</Badge>
                          ) : promo.isActive ? (
                            <Badge className="bg-green-50 text-green-700 border-green-150">Đang chạy</Badge>
                          ) : (
                            <Badge variant="outline" className="text-slate-500">Tắt</Badge>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {/* Host vouchers cannot be edited by admin directly, but admin can delete them if violates terms */}
                            {promo.scope === "global" && (
                              <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => handleOpenEdit(promo)}
                                className="h-8 w-8 text-slate-600 hover:text-primary"
                              >
                                <Edit2 className="h-4 w-4" />
                              </Button>
                            )}
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleDelete(promo._id)}
                              className="h-8 w-8 text-slate-400 hover:text-red-500"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create / Edit Dialog */}
      <Dialog open={promoDialogOpen} onOpenChange={setPromoDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-primary" />
              {editingPromo ? "Cập nhật mã giảm giá Admin" : "Tạo mã giảm giá Admin mới"}
            </DialogTitle>
            <DialogDescription>
              Mã giảm giá này do Sàn chịu 100% chi phí. Host sẽ nhận đủ tiền khi khách đặt chỗ.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-6 pt-4">
            <div className="grid gap-4 md:grid-cols-2">
              {/* Code */}
              <div className="space-y-2">
                <Label htmlFor="code" className="font-semibold text-slate-700">Mã Code (In hoa, không dấu)</Label>
                <div className="relative">
                  <Tag className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
                  <Input
                    id="code"
                    placeholder="HE2026, BANMOI100K..."
                    value={promoCode}
                    onChange={(e) => setPromoCode(e.target.value.toUpperCase())}
                    className="pl-10 font-mono font-bold"
                    disabled={!!editingPromo}
                    required
                  />
                </div>
              </div>

              {/* Description */}
              <div className="space-y-2">
                <Label htmlFor="desc" className="font-semibold text-slate-700">Mô tả chương trình</Label>
                <Input
                  id="desc"
                  placeholder="Giảm giá chào mừng thành viên mới..."
                  value={promoDesc}
                  onChange={(e) => setPromoDesc(e.target.value)}
                />
              </div>

              {/* Discount Type */}
              <div className="space-y-2">
                <Label className="font-semibold text-slate-700">Loại giảm giá</Label>
                <Select
                  value={discountType}
                  onValueChange={(val: "percentage" | "flat") => setDiscountType(val)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Chọn loại giảm giá" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="percentage">Giảm theo Phần trăm (%)</SelectItem>
                    <SelectItem value="flat">Giảm số tiền cố định (đ)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Discount Value */}
              <div className="space-y-2">
                <Label htmlFor="value" className="font-semibold text-slate-700">Giá trị giảm</Label>
                <Input
                  id="value"
                  type="number"
                  min="1"
                  value={discountValue}
                  onChange={(e) => setDiscountValue(Number(e.target.value) || 0)}
                  required
                />
              </div>

              {/* Max Discount Amount */}
              {discountType === "percentage" && (
                <div className="space-y-2">
                  <Label htmlFor="maxDiscount" className="font-semibold text-slate-700">Giới hạn số tiền giảm tối đa (đ)</Label>
                  <Input
                    id="maxDiscount"
                    type="number"
                    min="1000"
                    placeholder="Không giới hạn"
                    value={maxDiscount || ""}
                    onChange={(e) => setMaxDiscount(Number(e.target.value) || undefined)}
                  />
                </div>
              )}

              {/* Min Subtotal */}
              <div className="space-y-2">
                <Label htmlFor="minSubtotal" className="font-semibold text-slate-700">Giá trị đơn hàng tối thiểu (đ)</Label>
                <Input
                  id="minSubtotal"
                  type="number"
                  min="0"
                  value={minSubtotal}
                  onChange={(e) => setMinSubtotal(Number(e.target.value) || 0)}
                />
              </div>

              {/* Start Date */}
              <div className="space-y-2">
                <Label htmlFor="startDate" className="font-semibold text-slate-700">Ngày bắt đầu</Label>
                <Input
                  id="startDate"
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  required
                />
              </div>

              {/* End Date */}
              <div className="space-y-2">
                <Label htmlFor="endDate" className="font-semibold text-slate-700">Ngày kết thúc</Label>
                <Input
                  id="endDate"
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  required
                />
              </div>

              {/* Usage Limit */}
              <div className="space-y-2">
                <Label htmlFor="usageLimit" className="font-semibold text-slate-700">Giới hạn lượt sử dụng (Toàn sàn)</Label>
                <Input
                  id="usageLimit"
                  type="number"
                  min="1"
                  placeholder="Không giới hạn"
                  value={usageLimit || ""}
                  onChange={(e) => setUsageLimit(Number(e.target.value) || undefined)}
                />
              </div>

              {/* Toggle Active */}
              <div className="flex items-center justify-between p-3 border border-slate-100 dark:border-slate-800 rounded-md">
                <div className="space-y-0.5">
                  <Label className="text-sm font-semibold">Kích hoạt mã giảm</Label>
                  <p className="text-xs text-muted-foreground">Mã sẽ khả dụng khi nằm trong thời gian áp dụng.</p>
                </div>
                <Switch checked={promoActive} onCheckedChange={setPromoActive} />
              </div>
            </div>

            {/* Advanced Application Conditions Section */}
            <div className="p-4 rounded-xl border border-slate-150 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-900/30 space-y-3">
              <div className="flex items-center gap-2 pb-1 border-b border-slate-100 dark:border-slate-800">
                <h4 className="text-sm font-semibold text-slate-850 dark:text-slate-200">
                  Điều kiện áp dụng nâng cao (Tùy chọn)
                </h4>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="minGuests" className="text-xs font-semibold text-slate-650 dark:text-slate-400">Số khách tối thiểu</Label>
                  <Input
                    id="minGuests"
                    type="number"
                    min="1"
                    placeholder="Ví dụ: 30"
                    value={minGuests || ""}
                    onChange={(e) => setMinGuests(e.target.value ? Number(e.target.value) : undefined)}
                    className="h-9 text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="minNights" className="text-xs font-semibold text-slate-650 dark:text-slate-400">Số đêm tối thiểu</Label>
                  <Input
                    id="minNights"
                    type="number"
                    min="1"
                    placeholder="Ví dụ: 4"
                    value={minNights || ""}
                    onChange={(e) => setMinNights(e.target.value ? Number(e.target.value) : undefined)}
                    className="h-9 text-sm"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="minBookingQty" className="text-xs font-semibold text-slate-650 dark:text-slate-400">Số lều tối thiểu</Label>
                  <Input
                    id="minBookingQty"
                    type="number"
                    min="1"
                    placeholder="Ví dụ: 2"
                    value={minBookingQuantity || ""}
                    onChange={(e) => setMinBookingQuantity(e.target.value ? Number(e.target.value) : undefined)}
                    className="h-9 text-sm"
                  />
                </div>
              </div>
            </div>

            {/* Applicable properties */}
            <div className="space-y-2">
              <Label className="font-semibold text-slate-700 flex items-center gap-1.5">
                <Building className="h-4 w-4 text-slate-400" />
                Áp dụng cho các khu cắm trại (Trống = Tất cả)
              </Label>
              <div className="border border-slate-150 dark:border-slate-800 rounded-lg p-4 max-h-[160px] overflow-y-auto grid gap-2 md:grid-cols-2">
                {properties.map((prop: any) => (
                  <div
                    key={prop._id}
                    onClick={() => handleToggleProperty(prop._id)}
                    className={`flex items-center gap-2 p-2 rounded cursor-pointer border transition text-xs ${promoProps.includes(prop._id)
                      ? "border-primary bg-primary/5 text-primary font-semibold"
                      : "border-slate-150 hover:bg-slate-50"
                      }`}
                  >
                    <Building className="h-3.5 w-3.5 shrink-0" />
                    <span className="truncate">{prop.name}</span>
                  </div>
                ))}
              </div>
            </div>

            <DialogFooter className="border-t border-slate-100 pt-4">
              <Button type="button" variant="outline" onClick={() => setPromoDialogOpen(false)}>
                Hủy
              </Button>
              <Button type="submit" disabled={createMutation.isPending || updateMutation.isPending}>
                {editingPromo ? "Cập nhật mã" : "Tạo mã giảm giá"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
