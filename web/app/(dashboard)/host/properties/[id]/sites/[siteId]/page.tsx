/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { ArrowLeft, Check } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { SiteDetails } from "@/components/host/site/site-details";
import { SiteAmenitiesRules } from "@/components/host/site/site-amenities-rules";
import { SiteLocation } from "@/components/host/site/site-location";
import { SitePhotos } from "@/components/host/site/site-photos";
import { SiteBookingSettings } from "@/components/host/site/site-booking-settings";
import { SiteServicesStep } from "@/components/host/site/site-services-step";
import { getPropertyById, getSiteById, getSitesByProperty, updateSite, uploadMedia } from "@/lib/client-actions";
import { useQuery } from "@tanstack/react-query";
import { StepIndicator } from "@/components/host/property/step-indicator";

const STEPS = [
    { id: "details", title: "Thông tin & Giá" },
    { id: "amenities", title: "Tiện nghi & Quy định" },
    { id: "services", title: "Dịch vụ đi kèm" },
    { id: "location", title: "Vị trí" },
    { id: "photos", title: "Hình ảnh" },
    { id: "settings", title: "Cài đặt & Đăng" },
];

export default function EditSitePage() {
  const params = useParams() as any;
  const router = useRouter();
  const propertyId = params?.id ?? params?.propertyId;
  const siteId = params?.siteId ?? params?.site ?? null;

  const defaultForm = {
    basic: { name: "", slug: "", description: "", siteClass: "basic" as "basic" | "vip" },
    accommodationType: "tent",
    lodgingProvided: undefined,
    terrain: undefined,
    capacity: { maxGuests: 1, maxConcurrentBookings: 1 },
    pricing: { basePrice: 0, currency: "VND" },
    siteLocation: null,
    amenities: [] as any[],
    rules: { guestsShouldBring: [] as string[], siteSpecificRules: [] as string[] },
    photos: [] as any[],
    unitNames: [] as string[],
    bookingSettings: { minimumNights: 1, checkInTime: "14:00", checkOutTime: "11:00", instantBook: false, advanceNotice: 24, allowSameDayBooking: false },
    services: [] as any[],
  };

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [propertyLocation, setPropertyLocation] = useState<any | null>(null);
  const [form, setForm] = useState<any>({ ...defaultForm });
  const [step, setStep] = useState(0);

  const { data: sitesData } = useQuery({
    queryKey: ['property-sites', propertyId],
    queryFn: async () => {
      const response = await getSitesByProperty(propertyId);
      return response.data;
    },
    enabled: !!propertyId,
  });


  useEffect(() => {
    if (!propertyId) return;
    let mounted = true;
    (async () => {
      try {
        const p = await getPropertyById(propertyId);
        if (mounted && p?.success) {
          // ensure we don't access 'location' on a boolean or non-object
          const loc = (p as any)?.data && typeof (p as any).data === "object" ? (p as any).data.location ?? null : null;
          setPropertyLocation(loc);
        }
      } catch (err) {
        console.error(err);
      }
    })();
    return () => { mounted = false; };
  }, [propertyId]);

  useEffect(() => {
    setForm((f: any) => ({ ...(defaultForm as any), ...(f ?? {}) }));
    if (!propertyId || !siteId) {
      setLoading(false);
      return;
    }

    let mounted = true;
    setLoading(true);

    (async () => {
      try {
        const res = await getSiteById(siteId);
        const found = res?.data;

        if (found && typeof found === "object") {
          const normalizePhoto = (p: any, idx: number) => {
            if (!p) return null;
            return {
              _id: p._id ?? `photo-${idx}`,
              url: typeof p === "string" ? p : p.url ?? "",
              caption: p.caption ?? "",
              isCover: !!p.isCover,
              order: typeof p.order === "number" ? p.order : idx,
              uploadedAt: p.uploadedAt ?? null,
              __raw: p,
            };
          };

          const photos = Array.isArray(found.photos)
            ? found.photos.map((p: any, i: number) => normalizePhoto(p, i)).filter(Boolean)
            : defaultForm.photos;

          setForm({
            basic: { name: found.name ?? "", slug: found.slug ?? "", description: found.description ?? "", siteClass: found.siteClass ?? "basic" },
            accommodationType: found.accommodationType ?? defaultForm.accommodationType,
            lodgingProvided: found.lodgingProvided ?? undefined,
            terrain: found.terrain ?? undefined,
            capacity: { ...(defaultForm.capacity as any), ...(found.capacity ?? {}) },
            pricing: { ...(defaultForm.pricing as any), ...(found.pricing ?? {}) },
            siteLocation: found.siteLocation ?? defaultForm.siteLocation,
            amenities: Array.isArray(found.amenities) ? found.amenities : defaultForm.amenities,
            rules: {
              guestsShouldBring: Array.isArray(found.guestsShouldBring) ? found.guestsShouldBring : defaultForm.rules.guestsShouldBring,
              siteSpecificRules: Array.isArray(found.siteSpecificRules) ? found.siteSpecificRules : defaultForm.rules.siteSpecificRules,
            },
            photos,
            bookingSettings: { ...(defaultForm.bookingSettings as any), ...(found.bookingSettings ?? {}) },
            unitNames: found.unitNames ?? [],
            services: found.services ?? [],
          });
        } else {
          toast.error("Không tìm thấy site để chỉnh sửa.");
        }
      } catch (err) {
        console.error(err);
        toast.error("Lỗi khi tải dữ liệu site.");
      } finally {
        if (mounted) setLoading(false);
      }
    })();

    return () => { mounted = false; };
  }, [propertyId, siteId]);

  const update = (patch: Partial<any>) => setForm((s: any) => ({ ...(s ?? {}), ...(patch ?? {}) }));

  const canNext = useMemo(() => {
    if (step === 0) return !!form.basic?.name;
    if (step === 3) return !!(form.siteLocation?.coordinates ?? form.siteLocation?.lat);
    return true;
  }, [step, form]);

  const handleSave = async (publish = false) => {
    if (!propertyId || !siteId) return;
    setSaving(true);
    try {
      const photosInput = Array.isArray(form.photos) ? form.photos : [];
      const uploadedPhotos: any[] = [];

      for (let i = 0; i < photosInput.length; i++) {
        const p = photosInput[i];
        if (p instanceof File) {
          const fd = new FormData();
          fd.append("files", p);
          fd.append("folder", "sites");
          toast.info(`Đang upload ảnh ${i + 1}/${photosInput.length}...`);
          const resp = await uploadMedia(fd);
          const url = Array.isArray(resp?.data)
            ? resp.data[0]
            : ((resp?.data as any)?.url ?? resp?.data);
          const getMeta = (window as any).__sitePhotosMetadata;
          const metaArr = typeof getMeta === "function" ? getMeta() : [];
          const meta = metaArr[i] ?? { caption: "", isCover: i === 0, order: i };
          uploadedPhotos.push({
            url,
            caption: meta.caption || "",
            isCover: meta.isCover ?? (i === 0),
            order: meta.order ?? i,
          });
        } else if (p && p.url) {
          uploadedPhotos.push(p);
        }
      }

      // serialize pricing.seasonalPricing dates
      const pricingForServer = { ...(form.pricing ?? {}) };
      if (Array.isArray(pricingForServer.seasonalPricing)) {
        pricingForServer.seasonalPricing = pricingForServer.seasonalPricing.map((s: any) => ({
          name: s.name,
          startDate: s.startDate instanceof Date ? s.startDate.toISOString() : s.startDate,
          endDate: s.endDate instanceof Date ? s.endDate.toISOString() : s.endDate,
          price: Number(s.price ?? 0),
        }));
      }

      const payload: any = {
        property: propertyId,
        name: form.basic?.name?.trim(),
        slug: form.basic?.slug?.trim() || undefined,
        description: form.basic?.description?.trim() || undefined,
        siteClass: form.basic?.siteClass || "basic",
        accommodationType: typeof form.accommodationType === "string" ? form.accommodationType : form.accommodationType?.type,
        lodgingProvided: form.lodgingProvided || undefined,
        terrain: form.terrain || undefined,
        siteLocation: form.siteLocation?.coordinates
          ? {
            coordinates: {
              type: "Point",
              coordinates: [
                form.siteLocation.coordinates.coordinates?.[0],
                form.siteLocation.coordinates.coordinates?.[1],
              ],
            },
            mapPinLabel: form.siteLocation?.mapPinLabel || undefined,
            relativeDescription: form.siteLocation?.relativeDescription || undefined,
          }
          : form.siteLocation
            ? {
              mapPinLabel: form.siteLocation?.mapPinLabel || undefined,
              relativeDescription: form.siteLocation?.relativeDescription || undefined,
            }
            : undefined,
        capacity: form.capacity,
        unitNames: form.unitNames || [],
        pricing: pricingForServer,
        bookingSettings: form.bookingSettings,
        photos: uploadedPhotos.length > 0 ? uploadedPhotos : form.photos?.filter((p: any) => p?.url) ?? undefined,
        amenities: Array.isArray(form.amenities) ? form.amenities : undefined,
        guestsShouldBring: Array.isArray(form.rules?.guestsShouldBring) ? form.rules.guestsShouldBring : undefined,
        siteSpecificRules: Array.isArray(form.rules?.siteSpecificRules) ? form.rules.siteSpecificRules : undefined,
        status: publish ? "active" : "inactive",
        isActive: publish,
        isAvailableForBooking: publish,
        publish,
        services: form.services ?? [],
      };
      const res = await updateSite(siteId, payload);
      if (!res?.success) throw new Error(res?.message || "Cập nhật thất bại");
      toast.success("Cập nhật site thành công");
      router.push(`/host/properties/${propertyId}/sites`);
    } catch (err: any) {
      console.error(err);
      toast.error(err?.message || "Lỗi khi lưu site");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-emerald-600 border-t-transparent mx-auto" />
          <p className="mt-4 text-gray-600">Đang tải dữ liệu site...</p>
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
            onClick={() => router.push(`/host/properties/${propertyId}/sites`)}
            className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div className="flex-1 flex justify-center px-4">
            <StepIndicator currentStep={step} steps={STEPS.map(s => ({ label: s.title, description: "" }))} onStepClick={setStep} />
          </div>
          <div className="w-9" />
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-md rounded-2xl shadow-xl shadow-slate-100/40 dark:shadow-none border border-slate-200/50 dark:border-slate-800/50 p-6 sm:p-8 lg:p-10 mb-6 transition-all duration-300">
          {step === 0 && (
            <SiteDetails
              data={{
                basic: form.basic,
                accommodationType: form.accommodationType,
                lodgingProvided: form.lodgingProvided,
                terrain: form.terrain,
                capacity: form.capacity,
                pricing: form.pricing,
                unitNames: form.unitNames,
              }}
              onChange={(patch) => update(patch)}
            />
          )}

          {step === 1 && (
            <SiteAmenitiesRules
              data={{ amenities: form.amenities, rules: form.rules }}
              onChange={(patch) => update(patch)}
            />
          )}

          {step === 2 && (
            <SiteServicesStep
              data={form.services ?? []}
              onChange={(services) => update({ services })}
            />
          )}

          {step === 3 && (
            <SiteLocation
              data={form.siteLocation}
              propertyLocation={propertyLocation}
              onChange={(d: any) =>
                update({ siteLocation: { ...(form.siteLocation ?? {}), ...(d ?? {}) } })
              }
              currentSiteId={siteId}
              existingSites={sitesData.sites || []}
            />
          )}

          {step === 4 && (
            <SitePhotos data={form.photos ?? []} onChange={(p: any[]) => update({ photos: p })} />
          )}

          {step === 5 && (
            <SiteBookingSettings
              data={form.bookingSettings ?? defaultForm.bookingSettings}
              onChange={(newSettings: any) => update({ bookingSettings: newSettings })}
            />
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between bg-white/80 dark:bg-slate-900/80 backdrop-blur-md rounded-2xl shadow-md border border-slate-200/50 dark:border-slate-800/50 p-4">
          <Button
            variant="outline"
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0 || saving}
            className="gap-2 rounded-xl px-5 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
          >
            <ArrowLeft className="h-4 w-4" />
            Quay lại
          </Button>

          <div className="flex-1" />

          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              disabled={!canNext || saving}
              onClick={() => handleSave(false)}
              className="rounded-xl px-5 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
            >
              Lưu nháp
            </Button>

            {step < 5 ? (
              <Button
                disabled={!canNext || saving}
                onClick={() => setStep((s) => Math.min(5, s + 1))}
                className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold rounded-xl px-6 gap-2 transition-all shadow-md shadow-primary/20 hover:-translate-y-0.5 active:translate-y-0"
              >
                Tiếp theo
                <ArrowLeft className="h-4 w-4 ml-1 rotate-180" />
              </Button>
            ) : (
              <Button
                disabled={!canNext || saving}
                onClick={() => handleSave(true)}
                className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold rounded-xl px-6 gap-2 transition-all shadow-md shadow-primary/20 hover:-translate-y-0.5 active:translate-y-0"
              >
                {siteId ? "Cập nhật & Đăng" : "Tạo & Đăng"}
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}