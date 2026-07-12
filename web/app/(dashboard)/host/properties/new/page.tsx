// ...existing code...
/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { StepIndicator } from "@/components/host/property/step-indicator";
import { PropertyBasicInfo } from "@/components/host/property/property-basic-info";
import { PropertyLocation } from "@/components/host/property/property-location";
import { PropertyPhotos } from "@/components/host/property/property-photo";
import { PropertyPolicies } from "@/components/host/property/property-policies";
import { PropertySettings } from "@/components/host/property/property-settings";

import { createProperty, uploadMedia } from "@/lib/client-actions";
import { ArrowLeft, ArrowRight, Check } from "lucide-react";

const STEPS = [
  { label: "Cơ bản", description: "Thông tin property" },
  { label: "Vị trí", description: "Địa chỉ và bản đồ" },
  { label: "Hình ảnh", description: "Ảnh property" },
];

export default function NewPropertyPage() {
  const router = useRouter();
  const [currentStep, setCurrentStep] = useState(0);
  const [uploading, setUploading] = useState(false);

  type PropertyRule = { text: string; category: "pets" | "noise" | "fire" | "general"; order: number };

  interface Policies {

    depositRequired: boolean;
    depositAmount: number;
    depositType: "fixed" | "percentage";
    refundPolicy: string;
    paymentMethods: string[];
    rules: PropertyRule[];
  }

  interface FormDataType {
    basicInfo: any;
    location: any;
    photos: File[];
    policies: Policies;
    settings: any;
  }

  const [formData, setFormData] = useState<FormDataType>({
    basicInfo: {
      name: "",
      tagline: "",
      description: "",
      propertyType: "campground" as "private_land" | "farm" | "ranch" | "campground",
      landSize: { value: 0, unit: "square_meters" as "square_meters" | "hectares" | "acres" },
      nearbyAttractions: [] as { name: string; distance?: number; type?: string }[],
      status: "active" as "active" | "inactive" | "blocked" | "suspended",
      isActive: true,
      isFeatured: false,
    },
    location: {
      address: "",
      city: "",
      state: "",
      country: "Vietnam",
      zipCode: "",
      coordinates: { type: "Point" as const, coordinates: [0, 0] as [number, number] },
      directions: "",
      parkingInstructions: "",
    },
    photos: [] as File[],
    policies: {

      depositRequired: false,
      depositAmount: 0,
      depositType: "fixed" as "fixed" | "percentage",
      refundPolicy: "",
      paymentMethods: [] as string[],
      rules: [] as PropertyRule[],
    },
    settings: {
      instantBookEnabled: false,
      requireApproval: true,
      minimumAdvanceNotice: 24,
      bookingWindow: 365,
      allowWholePropertyBooking: false,
      status: "draft" as "draft" | "published" | "suspended",
      visibility: "public" as "public" | "private" | "unlisted",
      timezone: "Asia/Ho_Chi_Minh",
    },
  });

  const createMutation = useMutation({
    mutationFn: createProperty,
    onSuccess: () => {
      toast.success("Tạo property thành công!");
      router.push("/host/properties");
    },
    onError: (err: any) => {
      console.error("Create property error:", err);
      toast.error(err?.message || "Có lỗi xảy ra khi tạo property");
    },
  });

  const updateFormData = (key: string, value: any) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
  };

  const handleStepClick = (idx: number) => {
    setCurrentStep(idx);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const next = () => setCurrentStep((s) => Math.min(s + 1, STEPS.length - 1));
  const prev = () => setCurrentStep((s) => Math.max(s - 1, 0));

  const uploadAllPhotos = async (files: File[]) => {
    const uploaded: any[] = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const fd = new FormData();
      fd.append("files", file);
      fd.append("folder", "properties");
      const res = await uploadMedia(fd);
      // read metadata from global uploader if provided by component
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
    try {
      setUploading(true);

      // basic validation
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
      if (formData.photos.length === 0) {
        toast.error("Vui lòng thêm ít nhất 1 ảnh!");
        return;
      }

      toast.info(`Đang upload ${formData.photos.length} ảnh...`);
      const uploadedPhotos = await uploadAllPhotos(formData.photos);

      if (uploadedPhotos.length === 0) {
        toast.error("Không có ảnh nào được upload thành công!");
        return;
      }

      const payload: any = {
        name: b.name.trim(),
        slug: undefined, // server should create slug if needed
        tagline: b.tagline?.trim() || undefined,
        description: b.description.trim(),
        propertyType: b.propertyType,
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
        photos: uploadedPhotos,
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
        status: formData.basicInfo.status ?? "active",
        isActive: formData.basicInfo.isActive !== undefined ? !!formData.basicInfo.isActive : true,
        isFeatured: !!formData.basicInfo.isFeatured,
        isVerified: false,
      };
      console.log("Submitting property payload:", payload);
      await createMutation.mutateAsync(payload);
    } catch (err) {
      console.error("Submit error:", err);
      toast.error("Có lỗi xảy ra khi tạo property");
    } finally {
      setUploading(false);
    }
  };

  const renderStep = () => {
    switch (currentStep) {
      case 0:
        return <PropertyBasicInfo data={formData.basicInfo} onChange={(d: any) => updateFormData("basicInfo", { ...formData.basicInfo, ...d })} />;
      case 1:
        return <PropertyLocation data={formData.location} onChange={(d: any) => updateFormData("location", { ...formData.location, ...d })} />;
      case 2:
        return <PropertyPhotos data={formData.photos} onChange={(files: File[]) => updateFormData("photos", files)} />;
      case 3:
        return <PropertyPolicies data={formData.policies} onChange={(d: any) => updateFormData("policies", { ...formData.policies, ...d })} />;
      default:
        return null;
    }
  };

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
            onClick={prev}
            disabled={currentStep === 0}
            className="gap-2 rounded-xl px-5 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
          >
            <ArrowLeft className="h-4 w-4" />
            Quay lại
          </Button>

          {currentStep === STEPS.length - 1 ? (
            <Button
              onClick={handleSubmit}
              disabled={createMutation.isPending || uploading}
              className="bg-primary hover:bg-primary/90 text-white font-semibold rounded-xl px-6 gap-2 shadow-md shadow-primary/10 transition-all hover:-translate-y-0.5 active:translate-y-0"
            >
              {uploading || createMutation.isPending ? (
                <>
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  {uploading ? "Đang upload..." : "Đang lưu..."}
                </>
              ) : (
                <>
                  Hoàn thành
                </>
              )}
            </Button>
          ) : (
            <Button
              onClick={next}
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
// ...existing code...