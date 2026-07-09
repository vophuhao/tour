'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Ticket, Check, Copy } from 'lucide-react';
import { toast } from 'sonner';

interface PromoCode {
  _id: string;
  code: string;
  description?: string;
  discountType: 'percentage' | 'flat';
  discountValue: number;
  minSubtotal?: number;
  maxDiscountAmount?: number;
  startDate: string;
  endDate: string;
}

interface PropertyPromotionsProps {
  promotions: PromoCode[];
}

export function PropertyPromotions({ promotions }: PropertyPromotionsProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  if (!promotions || promotions.length === 0) return null;

  const handleCopy = async (id: string, code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedId(id);
      toast.success(`Đã sao chép mã: ${code}`);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy code: ', err);
      toast.error('Không thể sao chép mã giảm giá');
    }
  };

  const formatPrice = (price: number) =>
    new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);

  const formatDate = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      const day = String(d.getDate()).padStart(2, '0');
      const month = String(d.getMonth() + 1).padStart(2, '0');
      return `${day}/${month}`;
    } catch (err) {
      return '';
    }
  };

  return (
    <Card className="border border-primary/20 bg-primary/5 dark:border-primary/30 dark:bg-primary/5 overflow-hidden transition-all duration-200 hover:shadow-md">
      <CardHeader className="p-4 pb-2 flex flex-row items-center gap-2 space-y-0">
        <Ticket className="h-5 w-5 text-primary animate-pulse" />
        <CardTitle className="text-sm font-bold text-slate-800 dark:text-slate-200">
          Ưu đãi độc quyền từ Host
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 pt-0 space-y-3">
        <p className="text-xs text-muted-foreground">
          Áp dụng các mã dưới đây tại bước thanh toán để nhận ưu đãi hấp dẫn.
        </p>
        <div className="space-y-3">
          {promotions.map((promo) => {
            const isCopied = copiedId === promo._id;

            // Format large discount representation
            const discountValueFormatted =
              promo.discountType === 'percentage'
                ? `${promo.discountValue}%`
                : promo.discountValue >= 1000
                  ? `${promo.discountValue / 1000}K`
                  : `${promo.discountValue}`;

            return (
              <div
                key={promo._id}
                className="relative flex items-stretch border border-primary/20 rounded-lg bg-white dark:bg-slate-900 shadow-sm hover:shadow-md transition-all duration-200"
              >
                {/* Left Side: Stub */}
                <div className="flex flex-col items-center justify-center bg-gradient-to-br from-primary/95 to-primary text-white p-3 min-w-[75px] text-center rounded-l-md select-none">
                  <span className="text-[17px] font-black tracking-tight leading-none">
                    {discountValueFormatted}
                  </span>
                  <span className="text-[9px] font-bold uppercase tracking-wider opacity-90 mt-1">
                    GIẢM
                  </span>
                </div>

                {/* Dashed Separator */}
                <div className="w-[1px] border-l border-dashed border-primary/30 my-2" />

                {/* Right Side: Details & Action */}
                <div className="flex-1 p-3 flex flex-col justify-between gap-1 bg-gradient-to-r from-primary/[0.01] to-transparent">
                  <div className="flex items-center justify-between gap-2">
                    <div className="space-y-0.5">
                      <div className="font-mono text-xs font-black text-slate-800 dark:text-slate-100 tracking-wider">
                        {promo.code}
                      </div>
                      {promo.description && (
                        <p className="text-[10px] text-slate-500 dark:text-slate-400 line-clamp-2 leading-tight">
                          {promo.description}
                        </p>
                      )}
                    </div>

                    <Button
                      size="sm"
                      variant="outline"
                      className={`h-6 px-2.5 text-[10px] font-bold rounded-full border border-primary/30 text-primary bg-white dark:bg-slate-900 hover:bg-primary hover:text-white transition-all duration-150 shadow-sm shrink-0 gap-1`}
                      onClick={() => handleCopy(promo._id, promo.code)}
                    >
                      {isCopied ? (
                        <>
                          <Check className="h-2.5 w-2.5 text-emerald-500" />
                          Đã lưu
                        </>
                      ) : (
                        <>
                          <Copy className="h-2.5 w-2.5" />
                          Lưu mã
                        </>
                      )}
                    </Button>
                  </div>

                  <div className="text-[11px] font-medium text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-100 dark:border-slate-800/50 flex flex-wrap items-center gap-x-2">
                    {promo.minSubtotal !== undefined && promo.minSubtotal > 0 ? (
                      <span>Áp dụng cho đơn từ {formatPrice(promo.minSubtotal)}</span>
                    ) : (
                      <span></span>
                    )}

                    <span>
                      Áp dụng: {formatDate(promo.startDate)} - {formatDate(promo.endDate)}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
