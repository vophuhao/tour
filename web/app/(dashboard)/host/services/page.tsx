"use client";

import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Edit2, Trash2, Package, Check, X, Calendar as CalendarIcon, Clock, ShieldAlert, ClipboardList, Layers } from "lucide-react";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  getMyServicePackages,
  createServicePackage,
  updateServicePackage,
  deleteServicePackage,
} from "@/services/service-package.service";
import {
  getMyProperties,
  createServiceBlock,
  getMyServiceBlocks,
  deleteServiceBlock,
  getPropertyServicesAvailability
} from "@/lib/property-site-api";
import type { ServicePackage, Service } from "@/types/property-site";

export default function HostServicesPage() {
  const queryClient = useQueryClient();
  const [isOpen, setIsOpen] = useState(false);
  const [editingPackage, setEditingPackage] = useState<ServicePackage | null>(null);
  const [packageName, setPackageName] = useState("");
  const [services, setServices] = useState<Omit<Service, "_id">[]>([
    { name: "", description: "", pricing: [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }] }
  ]);

  // Tabs & Service blocks states
  const [activeTab, setActiveTab] = useState("packages");

  const { data: blocksResponse, isLoading: isLoadingBlocks, refetch: refetchBlocks } = useQuery<any>({
    queryKey: ["service-blocks"],
    queryFn: getMyServiceBlocks,
  });
  const serviceBlocks = blocksResponse?.data || [];

  const { data: propertiesResponse } = useQuery<any>({
    queryKey: ["my-properties"],
    queryFn: () => getMyProperties(1, 100),
  });
  const myProperties = propertiesResponse?.properties || propertiesResponse?.data?.properties || [];

  const propertiesWithServices = useMemo(() => {
    return myProperties.filter((p: any) => p.services && p.services.length > 0);
  }, [myProperties]);

  const [isBlockOpen, setIsBlockOpen] = useState(false);
  const [blockPropertyId, setBlockPropertyId] = useState("");
  const [blockServiceName, setBlockServiceName] = useState("");
  const [blockCheckIn, setBlockCheckIn] = useState("");
  const [blockCheckOut, setBlockCheckOut] = useState("");
  const [blockQuantity, setBlockQuantity] = useState(1);
  const [blockNote, setBlockNote] = useState("");

  const selectedProperty = myProperties.find((p: any) => p._id === blockPropertyId);
  const propertyServices = selectedProperty?.services || [];

  const handleCreateBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!blockPropertyId || !blockServiceName || !blockCheckIn || !blockCheckOut || blockQuantity < 1) {
      toast.error("Vui lòng điền đầy đủ thông tin");
      return;
    }
    try {
      const res = await createServiceBlock({
        propertyId: blockPropertyId,
        serviceName: blockServiceName,
        checkIn: blockCheckIn,
        checkOut: blockCheckOut,
        quantity: Number(blockQuantity),
        note: blockNote,
      });
      if (res.success) {
        toast.success("Khóa tồn kho dịch vụ thành công!");
        setIsBlockOpen(false);
        refetchBlocks();
        setBlockPropertyId("");
        setBlockServiceName("");
        setBlockCheckIn("");
        setBlockCheckOut("");
        setBlockQuantity(1);
        setBlockNote("");
      } else {
        toast.error(res.message || "Có lỗi xảy ra");
      }
    } catch (err: any) {
      toast.error(err.response?.data?.message || err.message || "Lỗi kết nối");
    }
  };

  const handleDeleteBlock = async (id: string) => {
    if (confirm("Bạn có chắc chắn muốn giải phóng đợt khóa kho này?")) {
      try {
        const res = await deleteServiceBlock(id);
        if (res.success) {
          toast.success("Đã giải phóng tồn kho dịch vụ!");
          refetchBlocks();
        } else {
          toast.error(res.message || "Có lỗi xảy ra");
        }
      } catch (err: any) {
        toast.error(err.response?.data?.message || err.message || "Lỗi kết nối");
      }
    }
  };

  // Lookup states for inventory check widget
  const [lookupPropertyId, setLookupPropertyId] = useState("");
  const getTodayStr = () => {
    const d = new Date();
    return d.toISOString().split("T")[0];
  };
  const [lookupDate, setLookupDate] = useState(getTodayStr());

  // Compute next day dynamically
  const lookupCheckIn = lookupDate;
  const lookupCheckOut = useMemo(() => {
    if (!lookupDate) return "";
    const d = new Date(lookupDate);
    d.setDate(d.getDate() + 1);
    return d.toISOString().split("T")[0];
  }, [lookupDate]);

  // Fetch availability when lookup states change
  const { data: availabilityResponse, isLoading: isLoadingAvailability } = useQuery<any>({
    queryKey: ["lookup-availability", lookupPropertyId, lookupCheckIn, lookupCheckOut],
    queryFn: () => getPropertyServicesAvailability(lookupPropertyId, lookupCheckIn, lookupCheckOut),
    enabled: !!lookupPropertyId && !!lookupCheckIn && !!lookupCheckOut,
  });
  const availabilityData = availabilityResponse?.data || [];

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
    setServices([{ name: "", description: "", pricing: [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }] }]);
  };

  const openCreateDialog = () => {
    setEditingPackage(null);
    setPackageName("");
    setServices([{ name: "", description: "", pricing: [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }] }]);
    setIsOpen(true);
  };

  const openEditDialog = (pkg: ServicePackage) => {
    setEditingPackage(pkg);
    setPackageName(pkg.name);
    setServices(pkg.services.map(s => ({
      name: s.name,
      description: s.description || "",
      pricing: s.pricing && s.pricing.length > 0
        ? s.pricing.map((p: any) => ({ price: p.price, unit: p.unit, timeValue: p.timeValue || 1, timeUnit: p.timeUnit || "luot" }))
        : [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }]
    })));
    setIsOpen(true);
  };

  const handleAddServiceRow = () => {
    setServices(prev => [...prev, { name: "", description: "", pricing: [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }] }]);
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
        pricing: [...(updated[serviceIdx].pricing || []), { price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }]
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
    field: "price" | "unit" | "timeValue" | "timeUnit",
    value: any
  ) => {
    setServices(prev => {
      const updated = [...prev];
      const currentPricing = [...(updated[serviceIdx].pricing || [])];
      currentPricing[pricingIdx] = {
        ...currentPricing[pricingIdx],
        [field]: (field === "price" || field === "timeValue")
          ? (value === "" ? "" : Number(value))
          : value
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
        : [{ price: 0, unit: "cai", timeValue: 1, timeUnit: "luot" }];
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

            Dịch vụ & Tồn kho
          </h1>

        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-3">
          <TabsList className="bg-slate-100 dark:bg-slate-900 rounded-xl p-1">
            <TabsTrigger value="packages" className="rounded-lg text-xs font-semibold px-4 py-2 flex items-center gap-1.5 data-[state=active]:bg-white dark:data-[state=active]:bg-slate-950 data-[state=active]:shadow-xs">
              <Layers className="h-3.5 w-3.5" />
              Gói dịch vụ mẫu
            </TabsTrigger>
            <TabsTrigger value="blocks" className="rounded-lg text-xs font-semibold px-4 py-2 flex items-center gap-1.5 data-[state=active]:bg-white dark:data-[state=active]:bg-slate-950 data-[state=active]:shadow-xs">
              <ClipboardList className="h-3.5 w-3.5" />
              Cho thuê trực tiếp / Khóa kho
            </TabsTrigger>
          </TabsList>

          {activeTab === "packages" ? (
            <Button
              onClick={openCreateDialog}
              className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl shadow-lg shadow-primary/10 dark:shadow-none transition-all flex items-center gap-2 text-xs"
            >
              <Plus className="h-4 w-4" />
              Tạo gói dịch vụ mẫu
            </Button>
          ) : (
            <Button
              onClick={() => setIsBlockOpen(true)}
              className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl shadow-lg shadow-primary/10 dark:shadow-none transition-all flex items-center gap-2 text-xs"
            >
              <Plus className="h-4 w-4" />
              Khóa tồn kho / Cho thuê trực tiếp
            </Button>
          )}
        </div>

        <TabsContent value="packages" className="outline-hidden mt-0">
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
                            {service.pricing?.map((priceOpt: any, pIdx) => {
                              const getUnitFriendlyName = (u: string) => {
                                if (u === 'cai') return 'cái';
                                if (u === 'chiec') return 'chiếc';
                                if (u === 'nguoi_lon') return 'người lớn';
                                if (u === 'tre_em') return 'trẻ em';
                                if (u === 'khach') return 'khách';
                                return u;
                              };

                              const getTimeUnitFriendlyName = (t?: string) => {
                                if (!t) return '';
                                if (t === 'luot') return 'lượt';
                                if (t === 'gio') return 'giờ';
                                if (t === 'dem') return 'đêm';
                                if (t === 'ngay') return 'ngày';
                                return t;
                              };

                              const timeDisplay = priceOpt.timeUnit
                                ? ` / ${priceOpt.timeValue || 1} ${getTimeUnitFriendlyName(priceOpt.timeUnit)}`
                                : '';

                              return (
                                <Badge
                                  key={pIdx}
                                  className="bg-primary/5 hover:bg-primary/10 text-primary font-semibold border border-primary/10 text-[10px] py-0.5 px-2 rounded-lg transition-colors shadow-2xs"
                                >
                                  {priceOpt.price.toLocaleString("vi-VN")} đ / {getUnitFriendlyName(priceOpt.unit)}{timeDisplay}
                                </Badge>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </CardContent>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="blocks" className="outline-hidden mt-0">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Tra cứu tồn kho */}
            <div className="lg:col-span-1 space-y-4">
              <Card className="rounded-2xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
                <CardHeader className="pb-3 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/20">
                  <CardTitle className="text-base font-bold text-slate-800 dark:text-slate-100 flex items-center gap-1.5">
                    <CalendarIcon className="h-4.5 w-4.5 text-primary" />
                    Tồn kho khả dụng
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Tra cứu số lượng thiết bị còn trống tại khu đất theo từng ngày cụ thể.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 pt-4">
                  <div className="space-y-1.5">
                    <Label className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Khu đất</Label>
                    <Select value={lookupPropertyId} onValueChange={setLookupPropertyId}>
                      <SelectTrigger className="rounded-xl border-slate-200 dark:border-slate-800 text-xs">
                        <SelectValue placeholder="Chọn khu đất..." />
                      </SelectTrigger>
                      <SelectContent className="rounded-xl">
                        {propertiesWithServices.map((p: any) => (
                          <SelectItem key={p._id} value={p._id} className="rounded-lg text-xs">
                            {p.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-1.5">
                    <Label className="text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Chọn ngày kiểm tra</Label>
                    <Input
                      type="date"
                      value={lookupDate}
                      onChange={(e) => setLookupDate(e.target.value)}
                      className="rounded-xl text-xs h-9 border-slate-200 dark:border-slate-800"
                    />
                  </div>

                  <div className="border-t border-slate-100 dark:border-slate-800 pt-3 space-y-3">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 block">Số lượng khả dụng:</span>

                    {!lookupPropertyId ? (
                      <p className="text-xs text-slate-400 italic">Vui lòng chọn khu đất để tra cứu...</p>
                    ) : isLoadingAvailability ? (
                      <div className="flex items-center justify-center py-4">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                      </div>
                    ) : availabilityData.length === 0 ? (
                      <p className="text-xs text-slate-400 italic">Không có dịch vụ nào cần theo dõi tồn kho.</p>
                    ) : (
                      <div className="space-y-3">
                        {availabilityData.map((s: any, idx: number) => {
                          const percent = s.totalInventory > 0 ? (s.availableCount / s.totalInventory) * 100 : 100;
                          let progressColor = "bg-primary";
                          if (s.availableCount === 0) progressColor = "bg-red-500";
                          else if (percent <= 30) progressColor = "bg-amber-500";

                          return (
                            <div key={idx} className="space-y-1 text-xs">
                              <div className="flex justify-between items-center">
                                <span className="font-semibold text-slate-700 dark:text-slate-300">{s.name}</span>
                                <span className="font-bold text-slate-850 dark:text-slate-200">
                                  {s.isInventoryTracked ? (
                                    <>
                                      Còn {s.availableCount} / {s.totalInventory}
                                    </>
                                  ) : (
                                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Vô hạn</span>
                                  )}
                                </span>
                              </div>
                              {s.isInventoryTracked && (
                                <div className="w-full bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                                  <div className={`h-full ${progressColor} transition-all`} style={{ width: `${percent}%` }} />
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* List Blocks */}
            <div className="lg:col-span-2 space-y-4">
              {isLoadingBlocks ? (
                <div className="space-y-4">
                  {[1, 2].map(i => (
                    <div key={i} className="h-16 bg-slate-100 dark:bg-slate-900 rounded-xl animate-pulse" />
                  ))}
                </div>
              ) : serviceBlocks.length === 0 ? (
                <div className="text-center py-16 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 shadow-sm">
                  <div className="h-16 w-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-primary/20">
                    <CalendarIcon className="h-8 w-8 text-primary" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-800 dark:text-slate-200">Chưa có đợt khóa kho nào</h3>
                  <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm">
                    Khóa tồn kho dịch vụ (hoặc cho khách thuê trực tiếp tại bãi) giúp bạn tự động trừ đi số lượng trống của thiết bị đó trên website trong khoảng ngày chỉ định.
                  </p>
                  <Button
                    onClick={() => setIsBlockOpen(true)}
                    className="mt-6 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl"
                  >
                    Tạo đợt khóa kho đầu tiên
                  </Button>
                </div>
              ) : (
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/20 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                          <th className="px-6 py-4">Dịch vụ</th>
                          <th className="px-6 py-4">Khu đất</th>
                          <th className="px-6 py-4 text-center">Số lượng</th>
                          <th className="px-6 py-4">Thời gian khóa</th>
                          <th className="px-6 py-4">Ghi chú</th>
                          <th className="px-6 py-4 text-right">Hành động</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80 text-sm">
                        {serviceBlocks.map((block: any) => (
                          <tr key={block._id} className="hover:bg-slate-50/50 dark:hover:bg-slate-950/20 transition-colors">
                            <td className="px-6 py-4 font-semibold text-slate-800 dark:text-slate-250">
                              {block.serviceName}
                            </td>
                            <td className="px-6 py-4 text-slate-500 dark:text-slate-400">
                              {block.property?.name || "Khu đất"}
                            </td>
                            <td className="px-6 py-4 text-center">
                              <span className="inline-flex items-center justify-center h-6 min-w-6 px-1.5 rounded-full bg-slate-100 dark:bg-slate-800 text-xs font-bold text-slate-700 dark:text-slate-300">
                                {block.quantity}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-slate-600 dark:text-slate-350 font-medium">
                              {new Date(block.checkIn).toLocaleDateString("vi-VN")} - {new Date(block.checkOut).toLocaleDateString("vi-VN")}
                            </td>
                            <td className="px-6 py-4 text-xs text-slate-400 max-w-xs truncate">
                              {block.note || "—"}
                            </td>
                            <td className="px-6 py-4 text-right">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDeleteBlock(block._id)}
                                className="text-red-500 hover:text-red-650 hover:bg-red-50 dark:hover:bg-red-950/20 rounded-xl"
                              >
                                <Trash2 className="h-4 w-4 mr-1.5" />
                                Giải phóng kho
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* Create Block Dialog */}
      <Dialog open={isBlockOpen} onOpenChange={setIsBlockOpen}>
        <DialogContent className="max-w-xl rounded-2xl border border-slate-200 dark:border-slate-800 overflow-y-auto max-h-[90vh]">
          <DialogHeader>
            <DialogTitle className="text-xl font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
              <CalendarIcon className="h-5 w-5 text-primary" />
              Khóa tồn kho dịch vụ / Cho thuê trực tiếp
            </DialogTitle>
            <DialogDescription>
              Tạo đợt khóa kho cho một dịch vụ để tự động trừ đi số lượng khả dụng trên website cắm trại trong khoảng ngày cụ thể.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateBlock} className="space-y-5 mt-2">
            <div className="space-y-1.5">
              <Label htmlFor="blockProperty" className="font-semibold text-xs text-slate-600">Chọn Khu đất (Property) *</Label>
              <Select value={blockPropertyId} onValueChange={(val) => {
                setBlockPropertyId(val);
                setBlockServiceName("");
              }}>
                <SelectTrigger className="rounded-xl border-slate-200 dark:border-slate-800 focus:ring-primary">
                  <SelectValue placeholder={propertiesWithServices.length === 0 ? "Không có khu đất nào có dịch vụ..." : "Chọn khu đất..."} />
                </SelectTrigger>
                <SelectContent className="rounded-xl">
                  {propertiesWithServices.map((p: any) => (
                    <SelectItem key={p._id} value={p._id} className="rounded-lg">
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="blockService" className="font-semibold text-xs text-slate-600">Chọn Dịch vụ muốn khóa *</Label>
              <Select
                value={blockServiceName}
                onValueChange={setBlockServiceName}
                disabled={!blockPropertyId || propertyServices.length === 0}
              >
                <SelectTrigger className="rounded-xl border-slate-200 dark:border-slate-800 focus:ring-primary">
                  <SelectValue placeholder={!blockPropertyId ? "Vui lòng chọn khu đất trước..." : propertyServices.length === 0 ? "Khu đất không có dịch vụ nào" : "Chọn dịch vụ..."} />
                </SelectTrigger>
                <SelectContent className="rounded-xl">
                  {propertyServices.map((s: any, idx: number) => (
                    <SelectItem key={idx} value={s.name} className="rounded-lg">
                      {s.name} {s.isInventoryTracked ? `(Tổng kho: ${s.totalInventory || 0})` : "(Không giới hạn)"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="blockCheckIn" className="font-semibold text-xs text-slate-600">Từ ngày *</Label>
                <Input
                  type="date"
                  id="blockCheckIn"
                  value={blockCheckIn}
                  onChange={(e) => setBlockCheckIn(e.target.value)}
                  className="rounded-xl border-slate-200 dark:border-slate-800 focus-visible:ring-primary"
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="blockCheckOut" className="font-semibold text-xs text-slate-600">Đến ngày *</Label>
                <Input
                  type="date"
                  id="blockCheckOut"
                  value={blockCheckOut}
                  onChange={(e) => setBlockCheckOut(e.target.value)}
                  className="rounded-xl border-slate-200 dark:border-slate-800 focus-visible:ring-primary"
                  required
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="blockQuantity" className="font-semibold text-xs text-slate-600">Số lượng khóa *</Label>
              <Input
                type="number"
                id="blockQuantity"
                min="1"
                value={blockQuantity}
                onChange={(e) => setBlockQuantity(Number(e.target.value))}
                className="rounded-xl border-slate-200 dark:border-slate-800 focus-visible:ring-primary"
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="blockNote" className="font-semibold text-xs text-slate-600">Ghi chú khóa kho</Label>
              <Input
                type="text"
                id="blockNote"
                placeholder="Ví dụ: Cho khách thuê trực tiếp tại bãi, mang đi sửa chữa..."
                value={blockNote}
                onChange={(e) => setBlockNote(e.target.value)}
                className="rounded-xl border-slate-200 dark:border-slate-800 focus-visible:ring-primary"
              />
            </div>

            <DialogFooter className="gap-2 border-t pt-4 mt-2">
              <Button type="button" variant="outline" onClick={() => setIsBlockOpen(false)} className="rounded-xl">
                Hủy bỏ
              </Button>
              <Button
                type="submit"
                className="bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl px-5"
              >
                Xác nhận khóa kho
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

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
                                value={priceOpt.unit || "cai"}
                                onValueChange={(val) => handlePricingFieldChange(index, pIdx, "unit", val)}
                              >
                                <SelectTrigger className="h-9 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-20 shrink-0 focus:ring-primary">
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
                              <span className="text-xs text-slate-400 shrink-0">/</span>
                              <Input
                                type="number"
                                min="1"
                                value={priceOpt.timeValue ?? ""}
                                onChange={(e) => handlePricingFieldChange(index, pIdx, "timeValue", e.target.value)}
                                className="h-9 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-14 px-1 text-center shrink-0 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                                required
                              />
                              <Select
                                value={priceOpt.timeUnit || "luot"}
                                onValueChange={(val) => handlePricingFieldChange(index, pIdx, "timeUnit", val)}
                              >
                                <SelectTrigger className="h-9 rounded-lg text-xs border-slate-200 dark:border-slate-800 w-20 shrink-0 focus:ring-primary">
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
