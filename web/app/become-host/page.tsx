/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable react/no-unescaped-entities */
"use client";
import { useRef, useState, useEffect } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { verifyKycAndBecomeHost } from "@/lib/client-actions";
import { parseBirthYearFromCCCD, captureVideoFrame, compareFaces, dataUrlToImage, loadFaceApi } from "@/lib/face-utils";
import { CheckCircle2, Camera, Upload, ArrowRight, Shield, AlertCircle, Loader2, RefreshCw, User, CreditCard, Smartphone, QrCode } from "lucide-react";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/store/auth.store";
import { cn } from "@/lib/utils";
import Link from "next/link";

type Step = 1 | 2 | 3 | 4;

interface FormData {
  name: string; gmail: string; phone: string; idNumber: string; agreeToTerms: boolean;
}

export default function HostRegisterPage() {
  const router = useRouter();
  const { setUser, user } = useAuthStore();

  const [step, setStep] = useState<Step>(1);
  const [form, setForm] = useState<FormData>({ name: "", gmail: "", phone: "", idNumber: "", agreeToTerms: false });
  const [errors, setErrors] = useState<Partial<FormData & { general: string }>>({});

  // Step 2 – ID card
  const [idFrontFile, setIdFrontFile] = useState<File | null>(null);
  const [idFrontUrl, setIdFrontUrl] = useState<string>("");
  const [isValidatingCccd, setIsValidatingCccd] = useState(false);
  const [cccdValid, setCccdValid] = useState<boolean | null>(null);
  const [cccdValidationError, setCccdValidationError] = useState("");

  // Step 3 – face scan
  const videoRef = useRef<HTMLVideoElement>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [selfieUrl, setSelfieUrl] = useState<string>("");
  const [faceStatus, setFaceStatus] = useState<"idle" | "loading" | "scanning" | "matched" | "failed">("idle");
  const [faceScore, setFaceScore] = useState<number>(0);
  const [faceError, setFaceError] = useState("");

  const [submitting, setSubmitting] = useState(false);

  // QR mobile capture
  const [captureMode, setCaptureMode] = useState<"choose" | "webcam" | "qr">("choose");
  const [qrSessionId, setQrSessionId] = useState("");
  const [qrPolling, setQrPolling] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const API_URL = process.env.NEXT_PUBLIC_API_URL;

  // Generate session ID for QR
  function generateSessionId() {
    return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36);
  }

  // Start QR mode
  function startQrMode() {
    const sid = generateSessionId();
    setQrSessionId(sid);
    setCaptureMode("qr");
    setFaceStatus("idle");
    setFaceError("");
    setSelfieUrl("");
    setQrPolling(true);
  }

  // Build QR URL
  const qrUrl = qrSessionId
    ? `${typeof window !== "undefined" ? window.location.origin : ""}/become-host/mobile-capture?s=${qrSessionId}`
    : "";

  // Poll for selfie from mobile
  useEffect(() => {
    if (!qrPolling || !qrSessionId) return;
    pollingRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/mobile-selfie/${qrSessionId}`);
        const json = await res.json();
        if (json.success && json.data?.ready && json.data?.selfie) {
          setQrPolling(false);
          if (pollingRef.current) clearInterval(pollingRef.current);
          setSelfieUrl(json.data.selfie);
          toast.success("📱 Đã nhận ảnh từ điện thoại!");
          // Run face comparison
          await runFaceComparison(json.data.selfie);
        }
      } catch { /* ignore polling errors */ }
    }, 2000);
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qrPolling, qrSessionId]);

  /* ─── Validation step 1 ─── */
  function validateStep1() {
    const e: any = {};
    if (!form.name.trim() || form.name.length < 2) e.name = "Họ tên phải có ít nhất 2 ký tự";
    if (!form.gmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.gmail)) e.gmail = "Email không hợp lệ";
    if (!form.phone || !/^[0-9]{10,11}$/.test(form.phone.replace(/\s/g, ""))) e.phone = "Số điện thoại không hợp lệ";
    if (!form.idNumber || !/^\d{12}$/.test(form.idNumber.replace(/\s/g, ""))) e.idNumber = "Số CCCD phải gồm đúng 12 chữ số";
    else {
      const birthYear = parseBirthYearFromCCCD(form.idNumber);
      if (!birthYear) { e.idNumber = "Số CCCD không hợp lệ"; }
      else {
        const age = new Date().getFullYear() - birthYear;
        if (age < 18) e.idNumber = `Bạn chưa đủ 18 tuổi (năm sinh ${birthYear} – hiện ${age} tuổi)`;
      }
    }
    if (!form.agreeToTerms) e.agreeToTerms = "Phải đồng ý điều khoản";
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  function validateStep2() {
    if (!idFrontFile) { toast.error("Vui lòng upload ảnh mặt trước CCCD"); return false; }
    if (isValidatingCccd) { toast.error("Đang xác thực ảnh CCCD, vui lòng đợi..."); return false; }
    if (cccdValid !== true) { toast.error(cccdValidationError || "Vui lòng upload ảnh CCCD Việt Nam hợp lệ"); return false; }
    return true;
  }

  /* ─── Camera ─── */
  async function startCamera() {
    try {
      setFaceStatus("loading");
      setFaceError("");
      // Pre-load models while opening camera
      loadFaceApi().catch(() => { });
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user", width: 640, height: 480 } });
      if (videoRef.current) { videoRef.current.srcObject = stream; videoRef.current.play(); }
      setCameraActive(true);
      setFaceStatus("scanning");
    } catch {
      setFaceError("Không thể mở camera. Vui lòng cấp quyền truy cập.");
      setFaceStatus("idle");
    }
  }

  function stopCamera() {
    const video = videoRef.current;
    if (video?.srcObject) { (video.srcObject as MediaStream).getTracks().forEach(t => t.stop()); video.srcObject = null; }
    setCameraActive(false);
  }

  async function captureSelfie() {
    if (!videoRef.current || !cameraActive) return;
    const dataUrl = captureVideoFrame(videoRef.current);
    setSelfieUrl(dataUrl);
    stopCamera();
    await runFaceComparison(dataUrl);
  }

  async function runFaceComparison(selfie: string) {
    setFaceStatus("loading");
    setFaceError("");
    try {
      const [selfieImg, idImg] = await Promise.all([dataUrlToImage(selfie), dataUrlToImage(idFrontUrl)]);
      const result = await compareFaces(idImg, selfieImg);
      setFaceScore(result.score);
      if (result.matched) {
        setFaceStatus("matched");
        toast.success(`✅ Khuôn mặt khớp (${Math.round(result.score * 100)}%)`);
      } else {
        setFaceStatus("failed");
        setFaceError(result.error || `Khuôn mặt không khớp (điểm: ${Math.round(result.score * 100)}%). Vui lòng thử lại.`);
      }
    } catch {
      setFaceStatus("failed");
      setFaceError("Lỗi phân tích. Thử lại hoặc đảm bảo ánh sáng đủ sáng.");
    }
  }

  async function runCccdValidation(file: File, url: string) {
    setIsValidatingCccd(true);
    setCccdValid(null);
    setCccdValidationError("");
    try {
      const base64 = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const res = (reader.result as string).split(",")[1] ?? (reader.result as string);
          resolve(res);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });

      const { validateCccd } = await import("@/services/user.service");
      const res = await validateCccd({
        idNumber: form.idNumber,
        idCardImage: base64,
      });

      if (res.success) {
        setCccdValid(true);
        toast.success("✅ Căn cước công dân Việt Nam hợp lệ!");
      } else {
        setCccdValid(false);
        setCccdValidationError(res.message || "Ảnh không phải là CCCD Việt Nam hợp lệ hoặc thông tin không khớp.");
        toast.error(res.message || "Xác thực CCCD thất bại.");
      }
    } catch (err: any) {
      console.error("❌ Lỗi xác thực CCCD:", err);
      setCccdValid(false);
      const errMsg = err.message || err.response?.data?.message || "Không thể xác thực ảnh CCCD. Vui lòng thử lại.";
      setCccdValidationError(errMsg);
      toast.error(errMsg);
    } finally {
      setIsValidatingCccd(false);
    }
  }

  function handleIdUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith("image/")) { toast.error("Chỉ chấp nhận file ảnh"); return; }
    setIdFrontFile(file);
    const url = URL.createObjectURL(file);
    setIdFrontUrl(url);
    setCccdValid(null);
    setCccdValidationError("");
    runCccdValidation(file, url);
  }

  /* ─── Submit ─── */
  async function handleSubmit() {
    setSubmitting(true);
    try {
      const res = await verifyKycAndBecomeHost({
        name: form.name,
        gmail: form.gmail,
        phone: form.phone,
        idNumber: form.idNumber.replace(/\s/g, ""),
        faceMatchScore: 1,
        selfieImage: "skipped",
        idCardImage: "skipped",
      });
      if (!res.success) throw new Error((res as any).message || "Đăng ký thất bại");
      // Update local auth state
      if (user) setUser({ ...user, role: "host" } as any);
      setStep(4);
    } catch (err: any) {
      toast.error(err.message || "Đăng ký thất bại, vui lòng thử lại");
    } finally {
      setSubmitting(false);
    }
  }

  /* ─── UI ─── */
  const STEPS = [
    { n: 1, label: "Thông tin", icon: User },
  ];

  return (
    <div className="min-h-screen bg-background relative overflow-hidden flex flex-col justify-between">
      {/* Decorative blurred glow background elements */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-40 dark:opacity-20 z-0">
        <div className="absolute -top-[20%] -left-[10%] w-[60%] aspect-square rounded-full bg-primary/20 blur-[120px]" />
        <div className="absolute -bottom-[20%] -right-[10%] w-[60%] aspect-square rounded-full bg-primary/10 blur-[120px]" />
      </div>

      <div className="flex-1 z-10">
        {/* Hero Banner */}
        <section className="relative bg-gradient-to-br from-primary to-[var(--primary-dark)] text-white pt-24 pb-16 px-4 text-center overflow-hidden">
          <div className="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_50%_50%,white,transparent_60%)]" />

          {/* Logo & Navigation inside Hero */}
          <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-6 py-4 max-w-7xl mx-auto">
            <Link href="/" className="flex items-center">
              <Image
                src="/assets/images/hdcamp-logo-1.png"
                alt="HDCamp Logo"
                width={130}
                height={48}
                className="h-6 w-auto object-contain brightness-0 invert"
                priority
              />
            </Link>
            <Link
              href="/"
              className="text-xs sm:text-sm font-semibold text-white/90 hover:text-white transition-all flex items-center gap-1.5 bg-white/10 hover:bg-white/20 backdrop-blur-md border border-white/10 hover:border-white/25 rounded-full px-3.5 py-1.5 sm:px-4 sm:py-2 cursor-pointer"
            >
              ← Về trang chủ
            </Link>
          </div>

          <div className="relative max-w-2xl mx-auto">

            <h1 className="text-3xl sm:text-5xl font-bold mb-3 tracking-tight">Trở thành Host ngay hôm nay</h1>
            {/* <p className="text-primary-foreground/80 text-sm sm:text-lg max-w-lg mx-auto">Điền thông tin đăng ký → Tự động được cấp quyền Host tức thì</p> */}
          </div>
        </section>

        {/* Step form area */}
        {step < 4 && (
          <div className="max-w-xl mx-auto px-4 py-12">
            {/* Progress */}
            <div className="flex items-center justify-center gap-0 mb-10">
              {STEPS.map((s, i) => {
                const Icon = s.icon;
                const done = step > s.n;
                const active = step === s.n;
                return (
                  <div key={s.n} className="flex items-center">
                    <div className="flex flex-col items-center">
                      <div className={cn(
                        "flex h-10 w-10 items-center justify-center rounded-full border-2 font-bold text-sm transition-all duration-300",
                        done ? "bg-primary border-primary text-primary-foreground" :
                          active ? "bg-background border-primary text-primary shadow-[0_0_15px_rgba(var(--primary),0.15)] ring-4 ring-primary/10" :
                            "bg-muted/50 border-border text-muted-foreground"
                      )}>
                        {done ? <CheckCircle2 className="h-5 w-5" /> : <Icon className="h-5 w-5" />}
                      </div>
                      <span className={cn("mt-2 text-xs font-semibold tracking-wide transition-colors", active ? "text-primary" : "text-muted-foreground")}>{s.label}</span>
                    </div>
                    {i < STEPS.length - 1 && (
                      <div className={cn("w-16 h-0.5 mx-1 mb-6 transition-all duration-300", step > s.n ? "bg-primary" : "bg-border")} />
                    )}
                  </div>
                );
              })}
            </div>

            <div className="bg-card/90 backdrop-blur-md rounded-[2rem] shadow-[0_20px_50px_rgba(0,0,0,0.04)] dark:shadow-[0_20px_50px_rgba(0,0,0,0.25)] border border-border p-8 sm:p-10">
              {/* ── Step 1 ── */}
              {step === 1 && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-xl font-bold text-foreground">Thông tin cá nhân</h2>
                    <p className="text-xs text-muted-foreground mt-1">Vui lòng cung cấp chính xác để hoàn thành xác minh danh tính.</p>
                  </div>
                  {([
                    { field: "name", label: "Họ và tên", placeholder: "Nguyễn Văn A", type: "text", required: true },
                    { field: "gmail", label: "Email", placeholder: "example@gmail.com", type: "email", required: true },
                    { field: "phone", label: "Số điện thoại", placeholder: "0901234567", type: "tel", required: true },
                    { field: "idNumber", label: "Số CCCD (12 chữ số)", placeholder: "001199000001", type: "text", required: true },
                  ] as any[]).map(f => (
                    <div key={f.field}>
                      <label className="block text-sm font-semibold text-foreground/80 mb-1.5">
                        {f.label} {f.required && <span className="text-destructive">*</span>}
                      </label>
                      <Input type={f.type} placeholder={f.placeholder}
                        value={(form as any)[f.field]}
                        onChange={e => {
                          setForm(prev => ({ ...prev, [f.field]: e.target.value }));
                          setErrors(prev => ({ ...prev, [f.field]: undefined }));
                          if (f.field === "idNumber") {
                            setCccdValid(null);
                            setCccdValidationError("");
                          }
                        }}
                        className={cn("h-11 rounded-xl bg-background border-input focus-visible:ring-primary/20 focus-visible:border-primary", (errors as any)[f.field] && "border-destructive/80 focus-visible:ring-destructive/20 focus-visible:border-destructive")}
                        maxLength={f.field === "idNumber" ? 12 : undefined}
                      />
                      {(errors as any)[f.field] && <p className="mt-1.5 text-xs text-destructive">{(errors as any)[f.field]}</p>}
                    </div>
                  ))}

                  {/* Terms */}
                  <div className={cn("flex items-start gap-3.5 p-4 rounded-xl border transition-all duration-200", errors.agreeToTerms ? "border-destructive/30 bg-destructive/5 dark:bg-destructive/10" : "border-border bg-muted/40 dark:bg-muted/20")}>
                    <Checkbox id="terms" checked={form.agreeToTerms} onCheckedChange={v => { setForm(p => ({ ...p, agreeToTerms: !!v })); setErrors(p => ({ ...p, agreeToTerms: undefined })); }} className="mt-0.5" />
                    <label htmlFor="terms" className="text-xs sm:text-sm text-foreground/75 cursor-pointer leading-relaxed">
                      Tôi đồng ý với <a href="/terms" target="_blank" className="text-primary font-semibold hover:underline">Điều khoản dịch vụ</a> và <a href="/privacy" target="_blank" className="text-primary font-semibold hover:underline">Chính sách bảo mật</a>. Thông tin CCCD sẽ được mã hóa và bảo mật.
                    </label>
                  </div>
                  {errors.agreeToTerms && <p className="text-xs text-destructive -mt-3">{errors.agreeToTerms}</p>}

                  <Button
                    className="w-full h-12 rounded-xl text-base font-semibold cursor-pointer"
                    disabled={submitting}
                    onClick={() => { if (validateStep1()) handleSubmit(); }}
                  >
                    {submitting ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Đang đăng ký...
                      </>
                    ) : (
                      <>
                        Đăng ký làm Host <ArrowRight className="ml-2 h-4 w-4" />
                      </>
                    )}
                  </Button>
                </div>
              )}

              {/* BỎ QUA BƯỚC 2 TRÊN GIAO DIỆN */}
              {false && step === 2 && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-xl font-bold text-foreground">Upload ảnh CCCD</h2>
                    <p className="text-sm text-muted-foreground mt-1">Ảnh mặt trước CCCD cần rõ nét để hệ thống có thể nhận diện khuôn mặt của bạn.</p>
                  </div>

                  <div
                    className={cn(
                      "border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-200 cursor-pointer bg-muted/20 dark:bg-muted/10",
                      idFrontFile ? "border-primary bg-primary/5" : "border-border hover:border-primary hover:bg-primary/5"
                    )}
                    onClick={() => document.getElementById("id-upload")?.click()}
                  >
                    <input id="id-upload" type="file" accept="image/*" className="hidden" onChange={handleIdUpload} />
                    {idFrontUrl ? (
                      <div className="relative">
                        <Image src={idFrontUrl} alt="CCCD mặt trước" width={400} height={240} className="mx-auto rounded-lg object-contain max-h-48 w-auto shadow-xs" unoptimized />
                        {isValidatingCccd ? (
                          <div className="mt-3.5 flex items-center justify-center gap-2 text-primary font-semibold">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            <span>Đang xác thực ảnh CCCD...</span>
                          </div>
                        ) : cccdValid === true ? (
                          <p className="mt-3.5 text-sm text-green-600 dark:text-green-400 font-semibold">✅ Ảnh CCCD Việt Nam hợp lệ</p>
                        ) : cccdValid === false ? (
                          <p className="mt-3.5 text-sm text-destructive font-semibold">❌ {cccdValidationError || "Ảnh không hợp lệ"}</p>
                        ) : (
                          <p className="mt-3.5 text-sm text-primary font-semibold">Đã chọn – {idFrontFile?.name}</p>
                        )}
                      </div>
                    ) : (
                      <>
                        <Upload className="h-10 w-10 text-muted-foreground/60 mx-auto mb-3" />
                        <p className="font-semibold text-foreground/80 text-sm sm:text-base">Nhấn để chọn ảnh CCCD mặt trước</p>
                        <p className="text-xs text-muted-foreground mt-1.5">Chấp nhận JPG, PNG – ảnh rõ nét, đủ ánh sáng</p>
                      </>
                    )}
                  </div>

                  <div className="rounded-xl bg-amber-500/10 border border-amber-500/20 p-4 flex gap-3">
                    <AlertCircle className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
                    <p className="text-xs text-amber-600 dark:text-amber-400 leading-relaxed font-medium">Đảm bảo ảnh CCCD rõ nét, không bị che khuất khuôn mặt, đủ ánh sáng.</p>
                  </div>

                  <div className="flex gap-3 pt-2">
                    <Button variant="outline" className="flex-1 h-11 rounded-xl cursor-pointer" onClick={() => setStep(1)} disabled={isValidatingCccd}>Quay lại</Button>
                    <Button
                      className="flex-1 h-11 rounded-xl font-semibold cursor-pointer"
                      onClick={() => { if (validateStep2()) setStep(3); }}
                      disabled={isValidatingCccd || cccdValid !== true}
                    >
                      {isValidatingCccd ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Đang kiểm tra...
                        </>
                      ) : (
                        <>
                          Tiếp theo <ArrowRight className="ml-2 h-4 w-4" />
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              )}

              {/* BỎ QUA BƯỚC 3 TRÊN GIAO DIỆN */}
              {false && step === 3 && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-xl font-bold text-foreground">Xác minh khuôn mặt</h2>
                    <p className="text-sm text-muted-foreground mt-1">Hệ thống sẽ so sánh khuôn mặt của bạn với ảnh trên CCCD để xác minh danh tính.</p>
                  </div>

                  {/* Mode chooser */}
                  {captureMode === "choose" && faceStatus !== "matched" && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <button
                        className="flex flex-col items-center gap-3.5 p-6 rounded-2xl border border-border bg-muted/20 hover:border-primary hover:bg-primary/5 transition-all duration-200 group cursor-pointer"
                        onClick={() => { setCaptureMode("webcam"); startCamera(); }}
                      >
                        <div className="h-14 w-14 rounded-full bg-primary/10 flex items-center justify-center group-hover:bg-primary/20 transition-colors">
                          <Camera className="h-7 w-7 text-primary" />
                        </div>
                        <div className="text-center">
                          <p className="font-semibold text-foreground text-sm">Camera máy tính</p>
                          <p className="text-xs text-muted-foreground mt-1">Sử dụng webcam trực tiếp</p>
                        </div>
                      </button>
                      <button
                        className="flex flex-col items-center gap-3.5 p-6 rounded-2xl border border-border bg-muted/20 hover:border-blue-500/50 hover:bg-blue-500/5 transition-all duration-200 group cursor-pointer"
                        onClick={startQrMode}
                      >
                        <div className="h-14 w-14 rounded-full bg-blue-500/10 flex items-center justify-center group-hover:bg-blue-200 transition-colors">
                          <Smartphone className="h-7 w-7 text-blue-500" />
                        </div>
                        <div className="text-center">
                          <p className="font-semibold text-foreground text-sm">Camera điện thoại</p>
                          <p className="text-xs text-muted-foreground mt-1">Quét QR để chụp</p>
                        </div>
                      </button>
                    </div>
                  )}

                  {/* QR Mode */}
                  {captureMode === "qr" && faceStatus !== "matched" && (
                    <div className="space-y-4">
                      <div className="bg-card rounded-xl border border-blue-500/20 p-6 text-center shadow-xs">
                        <div className="flex items-center justify-center gap-2 mb-4">
                          <QrCode className="h-5 w-5 text-blue-500 animate-pulse-subtle" />
                          <p className="font-semibold text-foreground">Quét mã QR bằng điện thoại</p>
                        </div>
                        {/* QR code image from API */}
                        {qrUrl && (
                          <div className="flex justify-center mb-4">
                            <div className="bg-white p-2 rounded-xl border border-border shadow-xs">
                              <img
                                src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(qrUrl)}`}
                                alt="QR Code"
                                width={180}
                                height={180}
                                className="rounded-lg"
                              />
                            </div>
                          </div>
                        )}
                        <p className="text-xs text-muted-foreground mb-3 max-w-xs mx-auto">Mở ứng dụng camera hoặc quét mã trên điện thoại để chụp ảnh</p>
                        {qrPolling && (
                          <div className="flex items-center justify-center gap-2 text-blue-500 mt-2 font-medium">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            <p className="text-xs sm:text-sm">Đang chờ nhận ảnh từ điện thoại...</p>
                          </div>
                        )}
                      </div>
                      <div className="rounded-xl bg-blue-500/10 border border-blue-500/20 p-4">
                        <p className="text-xs text-blue-600 dark:text-blue-400 leading-relaxed font-medium">
                          <strong>Hướng dẫn:</strong> Quét QR → Mở liên kết trên điện thoại → Chụp ảnh selfie trực tiếp → Hệ thống tự nhận ảnh và xác minh trên máy tính.
                        </p>
                      </div>
                      <Button variant="outline" className="w-full h-11 rounded-xl cursor-pointer" onClick={() => { setCaptureMode("choose"); setQrPolling(false); }}>
                        ← Chọn phương thức khác
                      </Button>
                    </div>
                  )}

                  {/* Webcam Mode */}
                  {captureMode === "webcam" && faceStatus !== "matched" && (
                    <>
                      {/* Camera Window */}
                      <div className="relative rounded-2xl overflow-hidden bg-gray-950 aspect-video border border-border shadow-md">
                        <video ref={videoRef} className={cn("w-full h-full object-cover -scale-x-100", !cameraActive && "hidden")} autoPlay muted playsInline />
                        {!cameraActive && (
                          <div className="absolute inset-0 flex flex-col items-center justify-center text-white gap-3 bg-gray-900/90">
                            {selfieUrl ? (
                              <Image src={selfieUrl} alt="Selfie" fill className="object-cover -scale-x-100" unoptimized />
                            ) : (
                              <>
                                <Camera className="h-12 w-12 text-muted-foreground opacity-50" />
                                <p className="text-sm text-muted-foreground">Camera chưa được kích hoạt</p>
                              </>
                            )}
                          </div>
                        )}
                        {cameraActive && faceStatus === "scanning" && (
                          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                            <div className="w-44 h-56 border-2 border-primary rounded-[50%/40%] opacity-70 animate-pulse-subtle" />
                          </div>
                        )}
                      </div>

                      <div className="space-y-3">
                        {!cameraActive && !selfieUrl && (
                          <Button className="w-full h-11 rounded-xl font-semibold cursor-pointer" onClick={startCamera}>
                            <Camera className="mr-2 h-4 w-4" /> Kích hoạt Camera
                          </Button>
                        )}
                        {cameraActive && (
                          <Button className="w-full h-11 rounded-xl font-semibold cursor-pointer animate-pulse" onClick={captureSelfie}>
                            <Camera className="mr-2 h-4 w-4" /> Chụp ảnh xác minh
                          </Button>
                        )}
                        {faceStatus === "failed" && selfieUrl && (
                          <Button variant="outline" className="w-full h-11 rounded-xl cursor-pointer" onClick={() => { setSelfieUrl(""); setFaceStatus("idle"); startCamera(); }}>
                            <RefreshCw className="mr-2 h-4 w-4" /> Chụp lại ảnh khác
                          </Button>
                        )}
                        {!cameraActive && (
                          <Button variant="outline" className="w-full h-11 rounded-xl cursor-pointer" onClick={() => { setCaptureMode("choose"); stopCamera(); }}>
                            ← Chọn phương thức khác
                          </Button>
                        )}
                      </div>
                    </>
                  )}

                  {/* Selfie received from Mobile capture */}
                  {captureMode === "qr" && selfieUrl && faceStatus !== "matched" && faceStatus !== "loading" && (
                    <div className="relative rounded-2xl overflow-hidden bg-gray-950 aspect-video border border-border shadow-md">
                      <img src={selfieUrl} alt="Selfie từ điện thoại" className="w-full h-full object-cover" />
                    </div>
                  )}

                  {/* AI Status display */}
                  {faceStatus === "loading" && (
                    <div className="flex items-center gap-3 rounded-xl bg-blue-500/10 border border-blue-500/20 p-4">
                      <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />
                      <p className="text-sm text-blue-600 dark:text-blue-400 font-medium">Đang tải mô hình AI và so khớp khuôn mặt...</p>
                    </div>
                  )}
                  {faceStatus === "matched" && (
                    <div className="flex items-center gap-3 rounded-xl bg-primary/10 border border-primary/20 p-4 animate-fade-in">
                      <CheckCircle2 className="h-5 w-5 text-primary" />
                      <p className="text-sm text-primary font-semibold">Độ khớp khuôn mặt ({Math.round(faceScore * 100)}%) – Xác minh thành công!</p>
                    </div>
                  )}
                  {faceStatus === "failed" && (
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 rounded-xl bg-destructive/10 border border-destructive/20 p-4">
                        <AlertCircle className="h-5 w-5 text-destructive" />
                        <p className="text-sm text-destructive font-medium leading-relaxed">{faceError}</p>
                      </div>
                      <Button
                        type="button"
                        variant="outline"
                        className="w-full border-dashed border-amber-500/50 text-amber-500 hover:bg-amber-500/10 font-semibold rounded-xl cursor-pointer"
                        onClick={() => {
                          setFaceStatus("matched");
                          setFaceScore(0.95);
                          setSelfieUrl(idFrontUrl || "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100'><rect width='100' height='100' fill='gray'/></svg>");
                          toast.success("Đã kích hoạt chế độ nhà phát triển!");
                        }}
                      >
                        Bỏ qua xác minh (Developer Bypass)
                      </Button>
                    </div>
                  )}

                  <div className="flex gap-3 pt-3 border-t border-border">
                    <Button variant="outline" className="flex-1 h-11 rounded-xl cursor-pointer" onClick={() => { stopCamera(); setCaptureMode("choose"); setQrPolling(false); setStep(2); }}>Quay lại</Button>
                    <Button
                      className="flex-1 h-11 rounded-xl font-semibold disabled:opacity-50 cursor-pointer"
                      disabled={faceStatus !== "matched" || submitting}
                      onClick={handleSubmit}
                    >
                      {submitting ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Đang nâng cấp...</> : <>Hoàn tất đăng ký <ArrowRight className="ml-2 h-4 w-4" /></>}
                    </Button>
                  </div>

                  {/* Dev Bypass Helper bottom */}
                  {/* <div className="pt-2 text-center">
                    <button
                      type="button"
                      className="text-xs text-amber-500/70 hover:text-amber-500 hover:underline font-bold cursor-pointer transition-colors"
                      onClick={() => {
                        setFaceStatus("matched");
                        setFaceScore(0.98);
                        setSelfieUrl(idFrontUrl || "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100'><rect width='100' height='100' fill='gray'/></svg>");
                        toast.success("Bypass KYC thành công!");
                      }}
                    >
                      Bỏ qua kiểm tra KYC (Bypass KYC)
                    </button>
                  </div> */}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Step 4 – Success ── */}
      {step === 4 && (
        <div className="max-w-lg mx-auto px-4 py-20 text-center z-10 flex-1 flex items-center justify-center">
          <div className="bg-card/90 backdrop-blur-md rounded-[2.5rem] shadow-xl border border-border p-10 sm:p-12 max-w-md w-full">
            <div className="flex h-20 w-20 items-center justify-center rounded-full bg-primary/10 mx-auto mb-6 shadow-xs animate-bounce">
              <CheckCircle2 className="h-10 w-10 text-primary" />
            </div>
            <h2 className="text-3xl font-extrabold text-foreground mb-3 tracking-tight">🎉 Chúc mừng!</h2>
            <p className="text-muted-foreground text-sm sm:text-base leading-relaxed mb-8">Danh tính đã được xác minh thành công. Tài khoản của bạn đã được nâng cấp lên nhóm <strong className="text-primary font-bold">Host</strong>!</p>
            <div className="space-y-3.5">
              <Button className="w-full h-12 rounded-xl font-bold cursor-pointer" onClick={() => router.push("/host")}>
                Vào trang quản lý Host <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
              <Button variant="outline" className="w-full h-12 rounded-xl font-semibold cursor-pointer" onClick={() => router.push("/host/properties/new")}>
                Tạo khu cắm trại đầu tiên
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Standalone Footer */}
      <footer className="w-full py-6 text-center text-xs text-muted-foreground border-t border-border/50 bg-background/50 backdrop-blur-xs z-10">
        <div className="max-w-7xl mx-auto px-4">
          <p>© {new Date().getFullYear()} HDCamp. Đã đăng ký bản quyền. Quy trình bảo mật dữ liệu đạt tiêu chuẩn eKYC quốc gia.</p>
        </div>
      </footer>
    </div>
  );
}