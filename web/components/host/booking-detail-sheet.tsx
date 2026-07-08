/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import type { Booking } from '@/types/property-site';
import {
  Calendar,
  Car,
  CheckCircle,
  DollarSign,
  Eye,
  Mail,
  MapPin,
  MessageSquare,
  PawPrint,
  Phone,
  Users,
  XCircle,
} from 'lucide-react';
import Image from 'next/image';
import { useRouter } from 'next/navigation';

interface BookingDetailSheetProps {
  booking: Booking | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm?: (booking: Booking) => void;
  onCancel?: (booking: Booking) => void;
  onComplete?: (booking: Booking) => void;
}

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  unpaid: { label: 'Chưa thanh toán', color: 'bg-yellow-100 text-yellow-800' },
  confirmed: { label: 'Đã xác nhận', color: 'bg-green-100 text-green-800' },
  cancelled: { label: 'Đã hủy', color: 'bg-red-100 text-red-800' },
  completed: { label: 'Hoàn thành', color: 'bg-blue-100 text-blue-800' },
  refunded: { label: 'Đã hoàn tiền', color: 'bg-purple-100 text-purple-800' },
};

const PAYMENT_STATUS_LABELS: Record<string, { label: string; color: string }> =
{
  pending: {
    label: 'Chưa thanh toán',
    color: 'bg-yellow-100 text-yellow-800',
  },
  paid: { label: 'Đã thanh toán', color: 'bg-green-100 text-green-800' },
  refunded: { label: 'Đã hoàn tiền', color: 'bg-purple-100 text-purple-800' },
  failed: { label: 'Thất bại', color: 'bg-red-100 text-red-800' },
};

export function BookingDetailSheet({
  booking,
  open,
  onOpenChange,
  onConfirm,
  onCancel,
  onComplete,
}: BookingDetailSheetProps) {
  const router = useRouter();

  if (!booking) return null;

  const site = typeof booking.site === 'object' ? booking.site : null;
  const guest = typeof booking.guest === 'object' ? booking.guest : null;
  const property =
    typeof booking.property === 'object' ? booking.property : null;

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('vi-VN', {
      weekday: 'long',
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
    });
  };

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN').format(price);
  };

  const getCancellationReason = (reason?: string) => {
    if (!reason) return '';
    if (reason === "Auto-cancelled: Payment timeout after 12 hours") {
      return "Tự động hủy: Hết thời gian chờ thanh toán sau 12 giờ";
    }
    if (reason === "Auto-cancelled: Unpaid booking on check-in day") {
      return "Tự động hủy: Đơn đặt chỗ chưa thanh toán vào ngày nhận phòng";
    }
    return reason;
  };

  const canConfirm = booking.status === 'pending';
  const canCancel = booking.status === 'pending';
  const canComplete =
    booking.status === 'confirmed' && new Date(booking.checkOut) < new Date();

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Chi tiết booking</SheetTitle>
          <SheetDescription>
            Mã booking:{' '}
            <span className="font-mono font-medium">{booking.code}</span>
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-6 p-6">
          {/* Site Image */}
          {site && site.photos && site.photos.length > 0 && (
            <div className="relative aspect-video overflow-hidden rounded-lg">
              <Image
                src={site.photos[0].url}
                alt={site.name}
                fill
                className="object-cover"
              />
              <div className="absolute top-3 left-3 flex gap-2">
                <Badge className={STATUS_LABELS[booking.paymentStatus === 'pending' ? 'unpaid' : booking.status]?.color}>
                  {STATUS_LABELS[booking.paymentStatus === 'pending' ? 'unpaid' : booking.status]?.label}
                </Badge>
                {/* {booking.paymentStatus && (
                  <Badge
                    className={
                      PAYMENT_STATUS_LABELS[booking.paymentStatus].color
                    }
                  >
                    {PAYMENT_STATUS_LABELS[booking.paymentStatus].label}
                  </Badge>
                )} */}
              </div>
            </div>
          )}

          {/* Site Info */}
          {site && (
            <div>
              <h3 className="text-lg font-semibold">{site.name}</h3>
              {property && (
                <p className="mt-1 flex items-center gap-1 text-sm text-gray-500">
                  <MapPin className="h-4 w-4" />
                  {property.name}
                </p>
              )}
            </div>
          )}

          <Separator />

          {/* Guest Info */}
          {guest && (
            <div>
              <h4 className="mb-3 flex items-center gap-2 font-semibold">
                <Users className="h-4 w-4" />
                Thông tin khách
              </h4>
              <div className="space-y-2 rounded-lg bg-gray-50 p-4">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Tên:</span>
                  <span className="text-sm">
                    {(guest as any).name || guest.username}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Mail className="h-4 w-4 text-gray-400" />
                  <span className="text-sm">{guest.email}</span>
                </div>
                {(guest as any).phoneNumber && (
                  <div className="flex items-center gap-2">
                    <Phone className="h-4 w-4 text-gray-400" />
                    <span className="text-sm">
                      {(guest as any).phoneNumber}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Booking Details */}
          <div>
            <h4 className="mb-3 flex items-center gap-2 font-semibold">
              <Calendar className="h-4 w-4" />
              Chi tiết đặt chỗ
            </h4>
            <div className="space-y-3 rounded-lg bg-gray-50 p-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs text-gray-500">Check-in</p>
                  <p className="mt-1 text-sm font-medium">
                    {formatDate(booking.checkIn)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-500">Check-out</p>
                  <p className="mt-1 text-sm font-medium">
                    {formatDate(booking.checkOut)}
                  </p>
                </div>
              </div>

              <Separator />

              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-gray-400" />
                  <div>
                    <p className="text-xs text-gray-500">Số đêm</p>
                    <p className="text-sm font-medium">{booking.nights} đêm</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Users className="h-4 w-4 text-gray-400" />
                  <div>
                    <p className="text-xs text-gray-500">Số khách</p>
                    <p className="text-sm font-medium">
                      {booking.numberOfGuests} người
                    </p>
                  </div>
                </div>
              </div>

              {((booking.numberOfPets && booking.numberOfPets > 0) ||
                (booking.numberOfVehicles && booking.numberOfVehicles > 0)) ? (
                <>
                  <Separator />
                  <div className="grid grid-cols-2 gap-3">
                    {booking.numberOfPets && booking.numberOfPets > 0 ? (
                      <div className="flex items-center gap-2">
                        <PawPrint className="h-4 w-4 text-gray-400" />
                        <div>
                          <p className="text-xs text-gray-500">Thú cưng</p>
                          <p className="text-sm font-medium">
                            {booking.numberOfPets}
                          </p>
                        </div>
                      </div>
                    ) : null}
                    {booking.numberOfVehicles && booking.numberOfVehicles > 0 ? (
                      <div className="flex items-center gap-2">
                        <Car className="h-4 w-4 text-gray-400" />
                        <div>
                          <p className="text-xs text-gray-500">Phương tiện</p>
                          <p className="text-sm font-medium">
                            {booking.numberOfVehicles}
                          </p>
                        </div>
                      </div>
                    ) : null}
                  </div>
                </>
              ) : null}
            </div>
          </div>

          {/* Guest Message */}
          {booking.guestMessage && (
            <div>
              <h4 className="mb-3 flex items-center gap-2 font-semibold">
                <MessageSquare className="h-4 w-4" />
                Lời nhắn từ khách
              </h4>
              <div className="rounded-lg bg-blue-50 p-4">
                <p className="text-sm text-gray-700">{booking.guestMessage}</p>
              </div>
            </div>
          )}

          {/* Cancellation Info */}
          {booking.cancellationReason && (
            <div>
              <h4 className="mb-3 flex items-center gap-2 font-semibold text-red-600">
                <XCircle className="h-4 w-4" />
                Lý do hủy
              </h4>
              <div className="rounded-lg bg-red-50 p-4">
                <p className="text-sm text-gray-700">
                  {getCancellationReason(booking.cancellationReason)}
                </p>
                {booking.cancelledAt && (
                  <p className="mt-2 text-xs text-gray-500">
                    Hủy lúc: {formatDate(booking.cancelledAt)}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Pricing Breakdown */}
          <div>
            <h4 className="mb-3 flex items-center gap-2 font-semibold">
              <DollarSign className="h-4 w-4" />
              Chi tiết giá
            </h4>
            <div className="space-y-2 rounded-lg bg-gray-50 p-4">
              <div className="flex justify-between text-sm">
                <span>
                  {formatPrice(booking.pricing.basePrice)} ₫ ×{' '}
                  {booking.pricing.totalNights} đêm
                </span>
                <span className="font-medium">
                  {formatPrice(booking.pricing.subtotal)} ₫
                </span>
              </div>

              {typeof booking.pricing.cleaningFee === 'number' && booking.pricing.cleaningFee > 0 && (
                <div className="flex justify-between text-sm">
                  <span>Phí vệ sinh</span>
                  <span className="font-medium">
                    {formatPrice(booking.pricing.cleaningFee)} ₫
                  </span>
                </div>
              )}

              {typeof booking.pricing.petFee === 'number' && booking.pricing.petFee > 0 && (
                <div className="flex justify-between text-sm">
                  <span>Phí thú cưng</span>
                  <span className="font-medium">
                    {formatPrice(booking.pricing.petFee)} ₫
                  </span>
                </div>
              )}

              {typeof booking.pricing.extraGuestFee === 'number' && booking.pricing.extraGuestFee > 0 && (
                <div className="flex justify-between text-sm">
                  <span>Phí khách thêm</span>
                  <span className="font-medium">
                    {formatPrice(booking.pricing.extraGuestFee)} ₫
                  </span>
                </div>
              )}

              <div className="flex justify-between text-sm">
                <span>Phí dịch vụ</span>
                <span className="font-medium">
                  {formatPrice(booking.pricing.serviceFee)} ₫
                </span>
              </div>

              <div className="flex justify-between text-sm">
                <span>Thuế</span>
                <span className="font-medium">
                  {formatPrice(booking.pricing.tax)} ₫
                </span>
              </div>

              <Separator />

              <div className="flex justify-between text-base font-bold">
                <span>Tổng cộng</span>
                <span className="text-emerald-600">
                  {formatPrice(booking.pricing.total)} ₫
                </span>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="space-y-2 pt-4">
            <Button
              className="w-full"
              variant="outline"
              onClick={() => {
                router.push(`/host/bookings/detail/${booking.code}`);
                onOpenChange(false);
              }}
            >
              <Eye className="mr-2 h-4 w-4" />
              Xem trang chi tiết
            </Button>

            {/* {canConfirm && onConfirm && (
              <Button
                className="w-full bg-emerald-600 hover:bg-emerald-700"
                onClick={() => {
                  onConfirm(booking);
                  onOpenChange(false);
                }}
              >
                <CheckCircle className="mr-2 h-4 w-4" />
                Xác nhận booking
              </Button>
            )}

            {canCancel && onCancel && (
              <Button
                className="w-full"
                variant="outline"
                onClick={() => {
                  onCancel(booking);
                  onOpenChange(false);
                }}
              >
                <XCircle className="mr-2 h-4 w-4" />
                Từ chối booking
              </Button>
            )} */}

            {canComplete && onComplete && (
              <Button
                className="w-full bg-blue-600 hover:bg-blue-700"
                onClick={() => {
                  onComplete(booking);
                  onOpenChange(false);
                }}
              >
                <CheckCircle className="mr-2 h-4 w-4" />
                Đánh dấu hoàn thành
              </Button>
            )}

            <Button
              className="w-full"
              variant="ghost"
              onClick={() => onOpenChange(false)}
            >
              Đóng
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
