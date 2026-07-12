/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState, useEffect, useMemo, Suspense } from "react";
import { useRouter, useParams } from "next/navigation";
import { useQuery, useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { StepIndicator } from "@/components/host/property/step-indicator";
import { PropertyBasicInfo } from "@/components/host/property/property-basic-info";
import { PropertyLocation } from "@/components/host/property/property-location";
import { PropertyPhotos } from "@/components/host/property/property-photo";
import { PropertyPolicies } from "@/components/host/property/property-policies";
import { PropertySettings } from "@/components/host/property/property-settings";
import { PropertyServicesStep } from "@/components/host/property/property-services-step";
import { Badge } from "@/components/ui/badge";

import { getPropertyById, updateProperty, uploadMedia } from "@/lib/client-actions";
import { ArrowLeft, ArrowRight, Check, Star, Trash2 } from "lucide-react";
import Image from "next/image";

const STEPS = [
  { label: "Cơ bản", description: "Thông tin property" },
  { label: "Vị trí", description: "Địa chỉ và bản đồ" },
  { label: "Hình ảnh", description: "Ảnh property" },
  { label: "Quy định", description: "Nội quy lưu trú" },
  { label: "Dịch vụ", description: "Dịch vụ đi kèm" },
];

export default function EditPropertyPage() {
  const router = useRouter();
  const params = useParams();
  const propertyId = params.id as string;

  const [currentStep, setCurrentStep] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [formData, setFormData] = useState<any>(null);

  // Fetch existing property data
  const { data: propertyData, isLoading } = useQuery<any>({
    queryKey: ["property", propertyId],
    queryFn: async () => {
      const response = await getPropertyById(propertyId);
      return response.data;
    },
  });

  // Initialize form data when property data is loaded
  useEffect(() => {
    if (propertyData) {
      setFormData({
        basicInfo: {
          name: propertyData.name || "",
          tagline: propertyData.tagline || "",
          description: propertyData.description || "",
          propertyType: propertyData.propertyType || "campground",
          terrain: propertyData.terrain || "",
          landSize: propertyData.landSize || { value: 0, unit: "square_meters" as const },
          nearbyAttractions: propertyData.nearbyAttractions || [],
          status: propertyData.status || "active",
          isActive: propertyData.isActive ?? true,
          isFeatured: propertyData.isFeatured ?? false,
        },
        location: {
          address: propertyData.location?.address || "",
          city: propertyData.location?.city || "",
          state: propertyData.location?.state || "",
          country: propertyData.location?.country || "Vietnam",
          zipCode: propertyData.location?.zipCode || "",
          coordinates: propertyData.location?.coordinates || {
            type: "Point" as const,
            coordinates: [0, 0] as [number, number],
          },
          directions: propertyData.location?.directions || "",
          parkingInstructions: propertyData.location?.parkingInstructions || "",
        },
        photos: [], // New photos to upload (File[])
        existingPhotos: propertyData.photos || [], // Keep track of existing photos
        policies: {
          depositRequired: propertyData.depositRequired ?? false,
          depositAmount: propertyData.depositAmount ?? 0,
          depositType: propertyData.depositType || "fixed",
          refundPolicy: propertyData.refundPolicy || "",
          paymentMethods: propertyData.paymentMethods || [],
          rules: propertyData.rules || [],
        },
        settings: {
          instantBookEnabled: propertyData.settings?.instantBookEnabled ?? false,
          requireApproval: propertyData.settings?.requireApproval ?? true,
          minimumAdvanceNotice: propertyData.settings?.minimumAdvanceNotice ?? 24,
          bookingWindow: propertyData.settings?.bookingWindow ?? 365,
          allowWholePropertyBooking: propertyData.settings?.allowWholePropertyBooking ?? false,
          // UI helpers
          status: "draft" as "draft" | "published" | "suspended",
          visibility: "public" as "public" | "private" | "unlisted",
          timezone: "Asia/Ho_Chi_Minh",
          checkInInstructions: propertyData.checkInInstructions || "",
          checkOutInstructions: propertyData.checkOutInstructions || "",
        },
        services: propertyData.services || [],
      });
    }
  }, [propertyData]);

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => updateProperty(id, data),
    onSuccess: () => {
      toast.success("Cập nhật property thành công!");
      router.push("/host/properties");
    },
    onError: (error: any) => {
      console.error("Update property error:", error);
      toast.error(error?.message || "Có lỗi xảy ra khi cập nhật property");
    },
  });

  const updateFormData = (step: string, data: any) => {
    setFormData((prev: any) => ({
      ...prev,
      [step]: { ...(prev?.[step] || {}), ...data },
    }));
  };

  const handleStepClick = (step: number) => {
    setCurrentStep(step);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleNext = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };

  const removeExistingPhoto = (index: number) => {
    const existingPhotos = Array.isArray(formData.existingPhotos) ? formData.existingPhotos : [];
    const newPhotos = existingPhotos.filter((_: any, i: number) => i !== index);
    setFormData((prev: any) => ({
      ...prev,
      existingPhotos: newPhotos,
    }));
    toast.success("Đã xóa ảnh");
  };

  const setExistingPhotoCover = (index: number) => {
    const existingPhotos = Array.isArray(formData.existingPhotos) ? formData.existingPhotos : [];
    const updatedPhotos = existingPhotos.map((photo: any, i: number) => ({
      ...photo,
      isCover: i === index,
    }));
    setFormData((prev: any) => ({
      ...prev,
      existingPhotos: updatedPhotos,
    }));
    toast.success("Đã đặt ảnh làm ảnh bìa");
  };
  const uploadAllPhotos = async (files: File[]) => {
    const uploaded: any[] = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const fd = new FormData();
      fd.append("files", file);
      fd.append("folder", "properties");
      const res = await uploadMedia(fd);
      const getMetadata = (window as any).__propertyPhotosMetadata;
      const metadata = getMetadata ? getMetadata() : [];
      const meta = metadata[i] ?? { caption: "", isCover: i === 0, order: i };
      const imageUrl = Array.isArray(res.data) ? res.data[0] : res.data;
      uploaded.push({
        url: imageUrl,
        caption: meta.caption || "",
        isCover: !!meta.isCover,
        order: meta.order ?? i,
        uploadedAt: new Date().toISOString(),
      });
      toast.loading(`Upload ảnh ${i + 1}/${files.length}...`, { id: "upload-progress" });
    }
    toast.dismiss("upload-progress");
    return uploaded;
  };

  const handleSubmit = async () => {
    if (!formData) return;

    try {
      setUploading(true);

      const b = formData.basicInfo;
      const l = formData.location;

      if (!b.name?.trim() || !b.description?.trim()) {
        toast.error("Vui lòng điền đầy đủ thông tin cơ bản!");
        return;
      }
      if (!l.address?.trim() || !l.city?.trim() || !l.state?.trim()) {
        toast.error("Vui lòng điền đầy đủ thông tin địa chỉ!");
        return;
      }

      // 1. Upload new photos
      let uploadedPhotos: any[] = [];
      const newPhotos = Array.isArray(formData.photos) ? formData.photos : [];
      if (newPhotos.length > 0) {
        toast.info(`Đang upload ${newPhotos.length} ảnh mới...`);
        uploadedPhotos = await uploadAllPhotos(newPhotos);
        if (uploadedPhotos.length > 0) {
          toast.success(`Đã upload ${uploadedPhotos.length} ảnh mới!`);
        }
      }

      // 2. Combine existing + new
      const existingPhotos = Array.isArray(formData.existingPhotos) ? formData.existingPhotos : [];
      const allPhotos = [...existingPhotos, ...uploadedPhotos];

      if (allPhotos.length === 0) {
        toast.error("Vui lòng thêm ít nhất 1 ảnh!");
        return;
      }

      const validPhotos = allPhotos.filter((p: any) => p?.url && p.url.trim() !== "");
      if (validPhotos.length === 0) {
        toast.error("Không có ảnh hợp lệ!");
        return;
      }

      const hasCover = validPhotos.some((p: any) => p.isCover);
      const finalPhotos = validPhotos.map((p: any, idx: number) => ({
        url: p.url,
        caption: p.caption || "",
        isCover: hasCover ? p.isCover : idx === 0,
        order: idx,
      }));

      // 3. Prepare payload
      const payload: any = {
        name: b.name.trim(),
        slug: undefined,
        tagline: b.tagline?.trim() || undefined,
        description: b.description.trim(),
        propertyType: b.propertyType,
        terrain: b.terrain || undefined,
        landSize: b.landSize && b.landSize.value > 0 ? { value: b.landSize.value, unit: b.landSize.unit } : undefined,
        location: {
          address: l.address.trim(),
          city: l.city.trim(),
          state: l.state.trim(),
          country: l.country,
          zipCode: l.zipCode?.trim() || undefined,
          coordinates: l.coordinates,
          directions: l.directions?.trim() || undefined,
          parkingInstructions: l.parkingInstructions?.trim() || undefined,
        },
        photos: finalPhotos,
        nearbyAttractions: b.nearbyAttractions ?? [],

        rules: formData.policies.rules ?? [],
        depositRequired: false,
        depositAmount: 0,
        depositType: "fixed",
        paymentMethods: [],
        refundPolicy: undefined,
        settings: {
          instantBookEnabled: false,
          requireApproval: true,
          minimumAdvanceNotice: 24,
          bookingWindow: 365,
          allowWholePropertyBooking: false,
        },
        checkInInstructions: undefined,
        checkOutInstructions: undefined,
        status: b.status ?? "active",
        isActive: b.isActive !== undefined ? !!b.isActive : true,
        isFeatured: !!b.isFeatured,
        services: formData.services ?? [],
      };

      console.log("Submitting property update:", payload);
      await updateMutation.mutateAsync({ id: propertyId, data: payload });
    } catch (error) {
      console.error("Submit error:", error);
      toast.error("Có lỗi xảy ra khi cập nhật property");
    } finally {
      setUploading(false);
    }
  };

  const renderStep = () => {
    if (!formData) return null;

    switch (currentStep) {
      case 0:
        return (
          <PropertyBasicInfo
            data={formData.basicInfo}
            onChange={(d: any) => updateFormData("basicInfo", d)}
          />
        );
      case 1:
        return (
          <PropertyLocation
            data={formData.location}
            onChange={(d: any) => updateFormData("location", d)}
          />
        );
      case 2:
        const existingPhotos = Array.isArray(formData.existingPhotos) ? formData.existingPhotos : [];
        const newPhotos = Array.isArray(formData.photos) ? formData.photos : [];

        return (
          <div className="space-y-6">
            {/* Existing Photos */}
            {existingPhotos.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">Ảnh hiện tại</h3>
                  <Badge variant="secondary">{existingPhotos.length} ảnh</Badge>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 mb-6">
                  {existingPhotos.map((photo: any, index: number) => (
                    <div key={`existing-${index}`} className="relative group rounded-lg overflow-hidden border-2 hover:border-emerald-500 transition-colors">
                      <div className="relative aspect-square bg-gray-100">
                        <Image src={photo.url} alt={photo.caption || `Photo ${index + 1}`} fill className="object-cover" unoptimized />

                        {photo.isCover && (
                          <Badge className="absolute top-2 left-2 bg-emerald-600 gap-1 z-10">
                            <Star className="h-3 w-3 fill-white" />
                            Ảnh bìa
                          </Badge>
                        )}

                        <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-2">
                          {!photo.isCover && (
                            <Button type="button" size="sm" variant="secondary" onClick={() => setExistingPhotoCover(index)} className="text-xs">
                              <Star className="h-3 w-3 mr-1" />
                              Đặt bìa
                            </Button>
                          )}
                          <Button type="button" size="sm" variant="destructive" onClick={() => removeExistingPhoto(index)}>
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>

                      {photo.caption && <div className="p-2 bg-white border-t text-xs text-gray-600 truncate">{photo.caption}</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Divider */}
            {existingPhotos.length > 0 && (
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-200" />
                </div>
                <div className="relative flex justify-center">
                  <span className="bg-white px-3 text-sm text-gray-500">Thêm ảnh mới</span>
                </div>
              </div>
            )}

            {/* Add New Photos */}
            <div>
              {existingPhotos.length === 0 && <h3 className="text-lg font-semibold text-gray-900 mb-4">Thêm ảnh property</h3>}
              <PropertyPhotos data={newPhotos} onChange={(files: File[]) => setFormData((prev: any) => ({ ...prev, photos: files }))} />
            </div>

            {/* Total Photos Count */}
            {(existingPhotos.length > 0 || newPhotos.length > 0) && (
              <div className="p-4 bg-emerald-50 rounded-lg border border-emerald-200">
                <p className="text-sm text-emerald-800">
                  📸 Tổng số ảnh: <strong>{existingPhotos.length + newPhotos.length}</strong>
                  {existingPhotos.length > 0 && ` (${existingPhotos.length} ảnh hiện tại)`}
                  {newPhotos.length > 0 && ` + ${newPhotos.length} ảnh mới`}
                </p>
              </div>
            )}
          </div>
        );
        return (
          <div className="space-y-6">
            {/* Existing Photos */}
            {formData.existingPhotos && formData.existingPhotos.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">Ảnh hiện tại</h3>
                  <Badge variant="secondary">{formData.existingPhotos.length} ảnh</Badge>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 mb-6">
                  {formData.existingPhotos.map((photo: any, index: number) => (
                    <div key={`existing-${index}`} className="relative group rounded-lg overflow-hidden border-2 hover:border-emerald-500 transition-colors">
                      <div className="relative aspect-square bg-gray-100">
                        <Image src={photo.url} alt={photo.caption || `Photo ${index + 1}`} fill className="object-cover" unoptimized />

                        {photo.isCover && (
                          <Badge className="absolute top-2 left-2 bg-emerald-600 gap-1 z-10">
                            <Star className="h-3 w-3 fill-white" />
                            Ảnh bìa
                          </Badge>
                        )}

                        <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-2">
                          {!photo.isCover && (
                            <Button type="button" size="sm" variant="secondary" onClick={() => setExistingPhotoCover(index)} className="text-xs">
                              <Star className="h-3 w-3 mr-1" />
                              Đặt bìa
                            </Button>
                          )}
                          <Button type="button" size="sm" variant="destructive" onClick={() => removeExistingPhoto(index)}>
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>

                      {photo.caption && <div className="p-2 bg-white border-t text-xs text-gray-600 truncate">{photo.caption}</div>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Divider */}
            {formData.existingPhotos && formData.existingPhotos.length > 0 && (
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-200" />
                </div>
                <div className="relative flex justify-center">
                  <span className="bg-white px-3 text-sm text-gray-500">Thêm ảnh mới</span>
                </div>
              </div>
            )}

            {/* Add New Photos */}
            <div>
              {(!formData.existingPhotos || formData.existingPhotos.length === 0) && <h3 className="text-lg font-semibold text-gray-900 mb-4">Thêm ảnh property</h3>}
              <PropertyPhotos data={formData.photos} onChange={(files: File[]) => setFormData((prev: any) => ({ ...prev, photos: files }))} />
            </div>

            {/* Total Photos Count */}
            {(formData.existingPhotos.length > 0 || formData.photos.length > 0) && (
              <div className="p-4 bg-emerald-50 rounded-lg border border-emerald-200">
                <p className="text-sm text-emerald-800">
                  📸 Tổng số ảnh: <strong>{formData.existingPhotos.length + formData.photos.length}</strong>
                  {formData.existingPhotos.length > 0 && ` (${formData.existingPhotos.length} ảnh hiện tại)`}
                  {formData.photos.length > 0 && ` + ${formData.photos.length} ảnh mới`}
                </p>
              </div>
            )}
          </div>
        );
      case 3:
        return <PropertyPolicies data={formData.policies} onChange={(d: any) => updateFormData("policies", d)} />;
      case 4:
        return (
          <PropertyServicesStep
            data={formData.services || []}
            onChange={(services: any[]) =>
              setFormData((prev: any) => ({ ...prev, services }))
            }
          />
        );
      default:
        return null;
    }
  };

  if (isLoading || !formData) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-emerald-600 border-t-transparent mx-auto" />
          <p className="mt-4 text-gray-600">Đang tải dữ liệu...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900/50 pb-12">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-between bg-white/70 dark:bg-slate-900/70 backdrop-blur-md border border-slate-200/50 dark:border-slate-800/50 rounded-2xl p-4 shadow-sm mb-8">
          <button
            type="button"
            onClick={() => router.push("/host/properties")}
            className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div className="flex-1 flex justify-center px-4">
            <StepIndicator currentStep={currentStep} steps={STEPS} onStepClick={handleStepClick} />
          </div>
          <div className="w-9" />
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-md rounded-2xl shadow-xl shadow-slate-100/40 dark:shadow-none border border-slate-200/50 dark:border-slate-800/50 p-6 sm:p-8 lg:p-10 mb-6 transition-all duration-300">
          <div className="transition-opacity duration-300 ease-in-out">
            {renderStep()}
          </div>
        </div>

        <div className="flex items-center justify-between bg-white/80 dark:bg-slate-900/80 backdrop-blur-md rounded-2xl shadow-md border border-slate-200/50 dark:border-slate-800/50 p-4">
          <Button
            variant="outline"
            onClick={handlePrevious}
            disabled={currentStep === 0}
            className="gap-2 rounded-xl px-5 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
          >
            <ArrowLeft className="h-4 w-4" />
            Quay lại
          </Button>

          {currentStep === STEPS.length - 1 ? (
            <Button
              onClick={handleSubmit}
              disabled={updateMutation.isPending || uploading}
              className="bg-primary hover:bg-primary/90 text-white font-semibold rounded-xl px-6 gap-2 shadow-md shadow-primary/10 transition-all hover:-translate-y-0.5 active:translate-y-0"
            >
              {uploading || updateMutation.isPending ? (
                <>
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  {uploading ? "Đang upload..." : "Đang lưu..."}
                </>
              ) : (
                <>
                  Cập nhật
                </>
              )}
            </Button>
          ) : (
            <Button
              onClick={handleNext}
              className="bg-primary hover:bg-primary/90 text-white font-semibold rounded-xl px-6 gap-2 shadow-md shadow-primary/10 transition-all hover:-translate-y-0.5 active:translate-y-0"
            >
              Tiếp theo
              <ArrowRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}