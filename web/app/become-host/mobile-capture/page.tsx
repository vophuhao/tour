"use client";
import { useRef, useState, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { Camera, CheckCircle2, Loader2, RefreshCw, Smartphone } from "lucide-react";

const API_URL = process.env.NEXT_PUBLIC_API_URL;

export default function MobileCapturePage() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("s") || "";

  const videoRef = useRef<HTMLVideoElement>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [selfieUrl, setSelfieUrl] = useState("");
  const [status, setStatus] = useState<"idle" | "camera" | "uploading" | "done" | "error">("idle");
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    if (!sessionId) {
      setStatus("error");
      setErrorMsg("Liên kết không hợp lệ. Vui lòng quét lại mã QR.");
    }
  }, [sessionId]);

  async function startCamera() {
    try {
      setErrorMsg("");
      // Use environment (rear) camera for phone
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "user", width: { ideal: 720 }, height: { ideal: 960 } },
      });
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
      }
      setCameraActive(true);
      setStatus("camera");
    } catch {
      setErrorMsg("Không thể mở camera. Vui lòng cấp quyền truy cập camera.");
      setStatus("error");
    }
  }

  function stopCamera() {
    const video = videoRef.current;
    if (video?.srcObject) {
      (video.srcObject as MediaStream).getTracks().forEach((t) => t.stop());
      video.srcObject = null;
    }
    setCameraActive(false);
  }

  async function capture() {
    if (!videoRef.current || !cameraActive) return;
    const canvas = document.createElement("canvas");
    canvas.width = videoRef.current.videoWidth;
    canvas.height = videoRef.current.videoHeight;
    canvas.getContext("2d")!.drawImage(videoRef.current, 0, 0);
    const dataUrl = canvas.toDataURL("image/jpeg", 0.85);
    setSelfieUrl(dataUrl);
    stopCamera();
    await upload(dataUrl);
  }

  async function upload(selfie: string) {
    setStatus("uploading");
    try {
      const res = await fetch(`${API_URL}/mobile-selfie/${sessionId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ selfie }),
      });
      const json = await res.json();
      if (json.success) {
        setStatus("done");
      } else {
        throw new Error(json.message || "Upload thất bại");
      }
    } catch (err: any) {
      setStatus("error");
      setErrorMsg(err?.message || "Lỗi kết nối. Vui lòng thử lại.");
    }
  }

  function retry() {
    setSelfieUrl("");
    setErrorMsg("");
    setStatus("idle");
    startCamera();
  }

  if (!sessionId) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
        <div className="text-center text-red-600">
          <p className="text-lg font-bold">Liên kết không hợp lệ</p>
          <p className="text-sm mt-2">Vui lòng quét lại mã QR từ máy tính.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col justify-between relative overflow-hidden">
      {/* Subtle brand color overlay glow */}
      <div className="absolute inset-0 pointer-events-none opacity-20 z-0">
        <div className="absolute -top-[30%] -left-[20%] w-[80%] aspect-square rounded-full bg-primary/20 blur-[100px]" />
      </div>

      <div className="flex-1 flex flex-col z-10">
        {/* Header */}
        <div className="bg-primary text-primary-foreground px-4 py-5 text-center shadow-md relative z-10">
          <div className="flex items-center justify-center gap-2 mb-1">
            <Smartphone className="h-5 w-5 text-primary-foreground/90" />
            <h1 className="text-lg font-bold tracking-wide">Chụp ảnh xác minh</h1>
          </div>
          <p className="text-primary-foreground/80 text-xs">Chụp ảnh selfie để so khớp với CCCD</p>
        </div>

        {/* Camera area */}
        <div className="flex-1 flex flex-col items-center justify-center p-6 gap-6">
          <div className="relative w-full max-w-sm aspect-[3/4] rounded-2xl overflow-hidden bg-gray-950 shadow-xl border border-border">
            <video
              ref={videoRef}
              className={`w-full h-full object-cover ${!cameraActive ? "hidden" : ""}`}
              autoPlay
              muted
              playsInline
            />
            {!cameraActive && (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-white gap-3 bg-gray-900/95">
                {selfieUrl ? (
                  <img src={selfieUrl} alt="Selfie" className="w-full h-full object-cover" />
                ) : (
                  <>
                    <Camera className="h-16 w-16 text-muted-foreground opacity-40 animate-pulse-subtle" />
                    <p className="text-sm text-muted-foreground">Camera chưa được kích hoạt</p>
                  </>
                )}
              </div>
            )}
            {/* Face guide overlay */}
            {cameraActive && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="w-44 h-56 border-2 border-primary rounded-[50%/40%] opacity-70 animate-pulse-subtle" />
              </div>
            )}
          </div>

          {/* Status messages */}
          {status === "uploading" && (
            <div className="flex items-center gap-3 bg-blue-500/10 border border-blue-500/20 rounded-xl px-4 py-3.5 w-full max-w-sm">
              <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />
              <p className="text-sm text-blue-600 dark:text-blue-400 font-medium">Đang gửi ảnh về máy tính...</p>
            </div>
          )}
          {status === "done" && (
            <div className="flex items-center gap-3 bg-primary/10 border border-primary/20 rounded-xl px-4 py-3.5 w-full max-w-sm animate-fade-in">
              <CheckCircle2 className="h-5 w-5 text-primary" />
              <div>
                <p className="text-sm text-primary font-bold">Đã gửi ảnh thành công!</p>
                <p className="text-xs text-primary/80 mt-0.5">Quay lại máy tính để hoàn tất xác minh. Bạn có thể đóng trang này.</p>
              </div>
            </div>
          )}
          {status === "error" && errorMsg && (
            <div className="flex items-center gap-3 bg-destructive/10 border border-destructive/20 rounded-xl px-4 py-3.5 w-full max-w-sm animate-fade-in">
              <p className="text-sm text-destructive font-medium">{errorMsg}</p>
            </div>
          )}

          {/* Action buttons */}
          <div className="w-full max-w-sm space-y-2.5">
            {status === "idle" && (
              <button
                className="w-full py-4 rounded-xl bg-primary text-primary-foreground font-bold text-base flex items-center justify-center gap-2 active:bg-primary/90 transition-all shadow-md cursor-pointer"
                onClick={startCamera}
              >
                <Camera className="h-5 w-5" /> Mở camera & Chụp ảnh
              </button>
            )}
            {status === "camera" && cameraActive && (
              <button
                className="w-full py-4 rounded-xl bg-primary text-primary-foreground font-bold text-base flex items-center justify-center gap-2 active:bg-primary/90 transition-all shadow-md cursor-pointer animate-pulse-subtle"
                onClick={capture}
              >
                <Camera className="h-5 w-5" /> Chụp ảnh ngay
              </button>
            )}
            {(status === "error" || (status === "idle" && selfieUrl)) && (
              <button
                className="w-full py-3.5 rounded-xl border-2 border-primary/20 hover:border-primary/40 text-primary font-bold text-sm flex items-center justify-center gap-2 active:bg-primary/5 transition-all cursor-pointer bg-card"
                onClick={retry}
              >
                <RefreshCw className="h-4 w-4" /> Thử lại
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Tips Footer */}
      <div className="px-4 py-4 bg-muted/40 border-t border-border/60 z-10">
        <p className="text-xs text-muted-foreground text-center font-medium leading-relaxed">
          💡 Hướng dẫn: Giữ khuôn mặt trong vùng khung oval • Đảm bảo đủ ánh sáng • Tháo kính/khẩu trang khi chụp.
        </p>
      </div>
    </div>
  );
}
