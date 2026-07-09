"use client";

import { useEffect, useState } from "react";
import { X, ChevronLeft, ChevronRight } from "lucide-react";
import { getPublicSettings } from "@/services/admin.service";
import { cn } from "@/lib/utils";

interface Banner {
  imageUrl: string;
  linkUrl?: string;
  isActive: boolean;
}

export default function PromoPopupBanner() {
  const [isOpen, setIsOpen] = useState(false);
  const [banners, setBanners] = useState<Banner[]>([]);
  const [activeIdx, setActiveIdx] = useState(0);

  useEffect(() => {
    // Check if shown in this session
    const isShown = sessionStorage.getItem("promo_banner_shown");
    if (isShown === "true") return;

    // Fetch settings
    const fetchSettings = async () => {
      try {
        const res = await getPublicSettings();
        if (res.success && res.data) {
          const loadedBanners = res.data.popupBanners || [];
          const activeBanners = loadedBanners.filter(
            (b: Banner) => b.isActive && b.imageUrl
          );

          if (activeBanners.length > 0) {
            setBanners(activeBanners);
            setIsOpen(true);
            sessionStorage.setItem("promo_banner_shown", "true");
          }
        }
      } catch (err) {
        console.error("Fetch public settings failed:", err);
      }
    };

    fetchSettings();
  }, []);

  // Auto cycle banners
  useEffect(() => {
    if (!isOpen || banners.length <= 1) return;

    const interval = setInterval(() => {
      setActiveIdx((prev) => (prev + 1) % banners.length);
    }, 5000); // 5 seconds interval

    return () => clearInterval(interval);
  }, [isOpen, banners.length]);

  // Close popup
  const handleClose = () => {
    setIsOpen(false);
  };

  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handlePrev = (e: React.MouseEvent) => {
    e.stopPropagation();
    setActiveIdx((prev) => (prev - 1 + banners.length) % banners.length);
  };

  const handleNext = (e: React.MouseEvent) => {
    e.stopPropagation();
    setActiveIdx((prev) => (prev + 1) % banners.length);
  };

  const handleDotClick = (e: React.MouseEvent, idx: number) => {
    e.stopPropagation();
    setActiveIdx(idx);
  };

  if (!isOpen || banners.length === 0) return null;

  const currentBanner = banners[activeIdx];

  return (
    <div
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-[3px] transition-opacity duration-300 animate-in fade-in duration-200"
      onClick={handleClose}
    >
      <div
        className="relative max-w-[95vw] md:max-w-[950px] lg:max-w-[1100px] w-full mx-4 overflow-hidden rounded-none shadow-2xl bg-transparent flex flex-col items-center justify-center"
        onClick={(e) => e.stopPropagation()} // Prevent close on modal body click
      >
        {/* Close Button */}
        <button
          onClick={handleClose}
          className="absolute top-4 right-4 z-[100] p-2 rounded-full bg-black/60 text-white hover:bg-black/85 transition-all duration-200 shadow-md border border-white/10 hover:scale-105"
          aria-label="Đóng quảng cáo"
        >
          <X className="h-4.5 w-4.5" />
        </button>

        {/* Carousel Content Container */}
        <div className="relative w-full overflow-hidden rounded-none flex items-center justify-center bg-slate-950/25">
          {/* Active Banner Display */}
          <div className="w-full h-full flex items-center justify-center transition-all duration-500 ease-in-out">
            {currentBanner.linkUrl ? (
              <a
                href={currentBanner.linkUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="block w-full cursor-pointer group"
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={currentBanner.imageUrl}
                  alt={`Khuyến mãi ${activeIdx + 1}`}
                  className="w-full h-auto object-contain max-h-[82vh] mx-auto rounded-none group-hover:scale-[1.005] transition-transform duration-300 select-none"
                />
              </a>
            ) : (
              <div className="w-full">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={currentBanner.imageUrl}
                  alt={`Khuyến mãi ${activeIdx + 1}`}
                  className="w-full h-auto object-contain max-h-[82vh] mx-auto rounded-none select-none"
                />
              </div>
            )}
          </div>

          {/* Navigation Controls (Only if multiple banners) */}
          {banners.length > 1 && (
            <>
              {/* Left Arrow Button */}
              <button
                onClick={handlePrev}
                className="absolute left-3 top-1/2 -translate-y-1/2 z-50 p-2 rounded-full bg-black/50 text-white hover:bg-black/80 transition-all duration-200 shadow hover:scale-105 border border-white/5"
                aria-label="Banner trước"
              >
                <ChevronLeft className="h-5 w-5" />
              </button>

              {/* Right Arrow Button */}
              <button
                onClick={handleNext}
                className="absolute right-3 top-1/2 -translate-y-1/2 z-50 p-2 rounded-full bg-black/50 text-white hover:bg-black/80 transition-all duration-200 shadow hover:scale-105 border border-white/5"
                aria-label="Banner sau"
              >
                <ChevronRight className="h-5 w-5" />
              </button>

              {/* Dot Indicators */}
              <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-50 flex gap-2">
                {banners.map((_, idx) => (
                  <button
                    key={idx}
                    onClick={(e) => handleDotClick(e, idx)}
                    className={cn(
                      "h-2 w-2 rounded-full transition-all duration-300 shadow",
                      activeIdx === idx
                        ? "bg-white w-4"
                        : "bg-white/40 hover:bg-white/60"
                    )}
                    aria-label={`Chuyển tới slide ${idx + 1}`}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
