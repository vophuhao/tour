/* eslint-disable @typescript-eslint/no-explicit-any */
'use client';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert';
import { cancelBooking, getBookingByCode, refundBooking } from '@/lib/client-actions';
import type { Property, Site } from '@/types/property-site';
import { format, differenceInDays } from 'date-fns';
import { vi } from 'date-fns/locale';
import jsPDF from 'jspdf';
import {
  AlertCircle,
  BanknoteIcon,
  Calendar,
  Car,
  CheckCircle2,
  ChevronLeft,
  CircleDollarSign,
  Clock,
  CreditCard,
  FileText,
  Home,
  Info,
  Loader2,
  MapPin,
  PawPrint,
  RefreshCw,
  Tent,
  Users,
  XCircle,
  Mail,
  Phone,
  Receipt,
  Wallet,
  Building,
  User,
} from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';

// Backend Booking type
interface BookingData {
  id: string;
  code?: string;
  status: 'pending' | 'confirmed' | 'cancelled' | 'completed' | 'refunded';
  checkIn: string;
  checkOut: string;
  numberOfGuests: number;
  numberOfPets?: number;
  numberOfVehicles?: number;
  numberOfUnits?: number;
  nights: number;
  paymentStatus?: 'pending' | 'paid' | 'refunded' | 'failed';
  paymentMethod?: 'deposit' | 'full';
  guestMessage?: string;
  hostMessage?: string;
  cancellInformation?: {
    fullnameGuest?: string;
    bankCode?: string;
    bankType?: string;
  };
  // Property-Site architecture
  property: Partial<Property>;
  site: Partial<Site>;
  unitNumber?: string;

  guest: {
    id: string;
    username: string;
    email: string;
    avatarUrl?: string;
    fullName?: string;
    phone?: string;
  };

  host: {
    id: string;
    username: string;
    email: string;
    avatarUrl?: string;
  };

  pricing: {
    basePrice: number;
    totalNights: number;
    subtotal: number;
    cleaningFee: number;
    petFee: number;
    extraGuestFee: number;
    serviceFee: number;
    tax: number;
    total: number;
    servicesFee?: number;
    promoCode?: string;
    promoDiscount?: number;
  };

  // Guest Info from Booking
  fullnameGuest?: string;
  phone?: string;
  email?: string;

  // Cancellation
  cancelledBy?: string;
  cancelledAt?: string;
  cancellationReason?: string;
  refundAmount?: number;

  // Review
  reviewed: boolean;
  review?: string;

  // Payment
  payOSOrderCode?: number;
  payOSCheckoutUrl?: string;
  transactionId?: string;
  paidAt?: string;

  createdAt: string;
  updatedAt: string;

  services?: Array<{
    name: string;
    price: number;
    unit: string;
    quantity: number;
  }>;
}

const formatServiceUnit = (unit: string) => {
  if (!unit) return 'lượt';
  if (unit.includes('/')) return unit;

  const mapping: Record<string, string> = {
    cai: 'cái',
    chiec: 'chiếc',
    nguoi_lon: 'người lớn',
    tre_em: 'trẻ em',
    khach: 'khách',
    luot: 'lượt',
    gio: 'giờ',
    dem: 'đêm',
    ngay: 'ngày',
  };

  return mapping[unit.toLowerCase()] || unit;
};

export default function BookingDetailPage() {
  const params = useParams();
  const code = params.code as string;

  const [booking, setBooking] = useState<BookingData | null>(null);
  const [loading, setLoading] = useState(true);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [cancelReason, setCancelReason] = useState('');
  const [cancelling, setCancelling] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [timeLeft, setTimeLeft] = useState<number>(0);

  useEffect(() => {
    if (!booking) return;

    const checkTime = () => {
      const createdTime = new Date(booking.createdAt).getTime();
      const thirtyMinsInMs = 30 * 60 * 1000;
      const elapsed = Date.now() - createdTime;
      const remaining = Math.max(0, thirtyMinsInMs - elapsed);
      setTimeLeft(Math.ceil(remaining / 1000));
    };

    checkTime();
    const interval = setInterval(checkTime, 1000);
    return () => clearInterval(interval);
  }, [booking]);

  useEffect(() => {
    fetchBooking();
  }, [code]);

  const fetchBooking = async () => {
    try {
      setLoading(true);
      const res = await getBookingByCode(code);
      setBooking(res.data || [] as any);


    } catch (error) {
      console.error('Error fetching booking:', error);
      toast.error('Không thể tải thông tin booking');
    } finally {
      setLoading(false);
    }
  };

  // Calculate refund amount based on cancellation policy
  const calculateRefundInfo = () => {

    if (!booking || !booking.cancelledAt) {
      return {
        refundPercentage: 0,
        refundAmount: 0,
        daysBeforeCancellation: 0,
        applicableRule: null as any,
      };
    }

    const checkInDate = new Date(booking.checkIn);
    const cancelledDate = new Date(booking.cancelledAt);
    const daysBeforeCancellation = differenceInDays(checkInDate, cancelledDate);

    // Get cancellation policy from property
    const cancellationPolicy = booking.property.cancellationPolicy;

    if (!cancellationPolicy || !cancellationPolicy.refundRules || cancellationPolicy.refundRules.length === 0) {
      return {
        refundPercentage: 100,
        refundAmount: booking.pricing.total,
        daysBeforeCancellation,
        applicableRule: null,
      };
    }

    // Find applicable refund rule
    // Sort rules by daysBeforeCheckIn descending
    const sortedRules = [...cancellationPolicy.refundRules].sort(
      (a, b) => b.daysBeforeCheckIn - a.daysBeforeCheckIn
    );

    let applicableRule = sortedRules.find(
      rule => daysBeforeCancellation >= rule.daysBeforeCheckIn
    );

    // If no rule found, use the strictest one (0 days = no refund)
    if (!applicableRule) {
      applicableRule = sortedRules[sortedRules.length - 1];
    }

    const refundPercentage = applicableRule?.refundPercentage || 0;

    // Calculate refund amount based on what was actually paid
    const paidAmount = getPaidAmount();
    const refundAmount = (paidAmount * refundPercentage) / 100;

    return {
      refundPercentage,
      refundAmount,
      daysBeforeCancellation,
      applicableRule,
    };
  };

  const refundInfo = calculateRefundInfo();

  const handleCancelBooking = async () => {
    if (!cancelReason.trim()) {
      toast.error('Vui lòng nhập lý do hủy');
      return;
    }

    try {
      setCancelling(true);
      const data = {
        cancellationReason: cancelReason.trim(),
      }
      const res = await cancelBooking(booking?.id || '', data);

      if (!res.success) throw new Error('Không thể hủy booking');

      toast.success('Đã hủy booking thành công');
      setCancelDialogOpen(false);
      fetchBooking();
    } catch (error) {
      toast.error('Có lỗi xảy ra khi hủy booking');
    } finally {
      setCancelling(false);
    }
  };

  const handleProcessRefund = async () => {
    if (!booking) return;

    try {
      setProcessing(true);
      const res = await refundBooking(booking.id);
      if (res.success === false) {
        throw new Error(res.message || 'Không thể hoàn tiền');
      }

      toast.success('Đã xử lý hoàn tiền thành công');
      fetchBooking();
    } catch (error) {
      toast.error('Có lỗi xảy ra khi xử lý hoàn tiền');
    } finally {
      setProcessing(false);
    }
  };

  const handleExportPDF = async () => {
    if (!booking) return;

    try {
      setExporting(true);
      const doc = new jsPDF();

      const formatPricePDF = (price: number) => {
        return formatPrice(price).replace(/₫/g, 'đ').replace(/\u20ab/g, 'đ');
      };

      const loadFont = async () => {
        const response = await fetch('/fonts/DejaVuSans.ttf');
        const fontBlob = await response.blob();
        const reader = new FileReader();

        return new Promise((resolve, reject) => {
          reader.onloadend = () => {
            try {
              const base64 = reader.result as string;
              const base64Data = base64.split(',')[1];
              doc.addFileToVFS('DejaVu.ttf', base64Data);
              doc.addFont('DejaVu.ttf', 'DejaVu', 'normal');
              doc.addFont('DejaVu.ttf', 'DejaVu', 'bold');
              doc.setFont('DejaVu', 'normal');
              resolve(true);
            } catch (err) {
              reject(err);
            }
          };
          reader.onerror = reject;
          reader.readAsDataURL(fontBlob);
        });
      };

      await loadFont();

      // Header
      doc.setFontSize(20);
      doc.text('HÓA ĐƠN ĐẶT CHỖ', 105, 20, { align: 'center' });

      doc.setFontSize(10);
      doc.text('TOUR CẮM TRẠI VIỆT NAM', 105, 28, { align: 'center' });
      doc.text(
        'Website: tour-cam-trai.vn | Email: support@tour-cam-trai.vn',
        105,
        34,
        { align: 'center' },
      );

      doc.setLineWidth(0.5);
      doc.line(20, 40, 190, 40);

      let y = 50;
      doc.setFontSize(12);
      doc.text('THÔNG TIN ĐẶT CHỖ', 20, y);

      y += 8;
      doc.setFontSize(10);

      const bookingInfo = [
        `Mã booking: ${booking.code}`,
        `Ngày tạo: ${format(new Date(booking.createdAt), 'dd/MM/yyyy HH:mm', { locale: vi })}`,
        `Trạng thái: ${getStatusLabel(booking.status)}`,
        `Thanh toán: ${getPaymentStatusLabel(booking.paymentStatus)}`,
        `Phương thức: ${getPaymentMethodLabel(booking.paymentMethod)}`,
      ];

      bookingInfo.forEach(info => {
        doc.text(info, 20, y);
        y += 6;
      });

      // Payment amount info
      if (booking.paymentStatus === 'paid' && booking.paymentMethod) {
        y += 2;
        const paidAmount = getPaidAmount();
        const paymentLabel = booking.paymentMethod === 'deposit'
          ? `Số tiền đã cọc (30%): ${formatPricePDF(paidAmount)}`
          : `Số tiền đã thanh toán: ${formatPricePDF(paidAmount)}`;
        doc.text(paymentLabel, 20, y);
        y += 6;

        if (booking.paymentMethod === 'deposit') {
          const remaining = getRemainingAmount();
          doc.text(`Còn lại (70%): ${formatPricePDF(remaining)}`, 20, y);
          y += 6;
        }
      }

      // Refund info if cancelled
      if (booking.status === 'cancelled' && refundInfo.refundAmount > 0) {
        y += 2;
        doc.text(`Số tiền hoàn lại (${refundInfo.refundPercentage}%): ${formatPricePDF(refundInfo.refundAmount)}`, 20, y);
        y += 6;
        doc.text(`Hủy trước check-in: ${refundInfo.daysBeforeCancellation} ngày`, 20, y);
        y += 6;
      }

      // Property & Site
      y += 6;
      doc.text('ĐỊA ĐIỂM', 20, y);
      y += 8;
      doc.text(`Property: ${booking.property.name}`, 20, y);
      y += 6;
      doc.text(`Site: ${booking.site.name}`, 20, y);
      y += 6;

      const address = `Địa chỉ: ${booking.property.location?.address}, ${booking.property.location?.city}, ${booking.property.location?.state}`;
      const splitAddress = doc.splitTextToSize(address, 170);
      doc.text(splitAddress, 20, y);
      y += splitAddress.length * 6;

      // Booking Details
      y += 6;
      doc.text('CHI TIẾT ĐẶT CHỖ', 20, y);
      y += 8;

      const bookingDetails = [
        `Check-in: ${format(new Date(booking.checkIn), 'dd/MM/yyyy HH:mm')}`,
        `Check-out: ${format(new Date(booking.checkOut), 'dd/MM/yyyy HH:mm')}`,
        `Số đêm: ${booking.nights} đêm`,
        `Số khách: ${booking.numberOfGuests} người`,
      ];

      if (booking.numberOfPets && booking.numberOfPets > 0) {
        bookingDetails.push(`Thú cưng: ${booking.numberOfPets} con`);
      }
      if (booking.numberOfVehicles && booking.numberOfVehicles > 0) {
        bookingDetails.push(`Phương tiện: ${booking.numberOfVehicles} xe`);
      }
      if (booking.numberOfUnits && booking.numberOfUnits > 0) {
        bookingDetails.push(`Số lượng vị trí: ${booking.numberOfUnits} vị trí`);
      }

      bookingDetails.forEach(detail => {
        doc.text(detail, 20, y);
        y += 6;
      });

      // Services in PDF
      if (booking.services && booking.services.length > 0) {
        y += 4;
        doc.text('DỊCH VỤ ĐÃ CHỌN:', 20, y);
        y += 6;
        booking.services.forEach(svc => {
          doc.text(`- ${svc.name} (x${svc.quantity} ${formatServiceUnit(svc.unit)}):`, 25, y);
          doc.text(formatPricePDF(svc.price * svc.quantity), 190, y, { align: 'right' });
          y += 6;
        });
      }

      // Pricing
      y += 6;
      doc.text('CHI TIẾT GIÁ', 20, y);
      y += 8;

      const pricing = [
        {
          label: `Giá cơ bản (${formatPricePDF(booking.pricing.basePrice)} x ${booking.pricing.totalNights} đêm)`,
          value: booking.pricing.subtotal,
        },
        { label: 'Phí vệ sinh', value: booking.pricing.cleaningFee },
        { label: 'Phí thú cưng', value: booking.pricing.petFee },
        { label: 'Phí khách thêm', value: booking.pricing.extraGuestFee },
        { label: 'Phí dịch vụ bổ sung', value: booking.pricing.servicesFee || 0 },
        { label: 'Phí dịch vụ', value: booking.pricing.serviceFee },
        { label: 'Thuế', value: booking.pricing.tax },
      ];

      pricing.forEach(item => {
        if (item.value > 0) {
          doc.text(item.label, 20, y);
          doc.text(formatPricePDF(item.value), 190, y, { align: 'right' });
          y += 6;
        }
      });

      if (booking.pricing.promoCode && booking.pricing.promoDiscount && booking.pricing.promoDiscount > 0) {
        doc.text(`Mã giảm giá (${booking.pricing.promoCode}):`, 20, y);
        doc.text(`-${formatPricePDF(booking.pricing.promoDiscount)}`, 190, y, { align: 'right' });
        y += 6;
      }

      y += 4;
      doc.setLineWidth(0.3);
      doc.line(20, y, 190, y);
      y += 8;
      doc.setFontSize(12);
      doc.text('TỔNG CỘNG', 20, y);
      doc.text(formatPricePDF(booking.pricing.total), 190, y, { align: 'right' });

      // Guest Info
      y += 12;
      doc.setFontSize(10);
      doc.text('THÔNG TIN KHÁCH HÀNG', 20, y);
      y += 8;

      const guestInfo = [
        `Tên: ${booking.fullnameGuest || booking.guest.fullName || booking.guest.username}`,
        `Email: ${booking.email || booking.guest.email}`,
      ];

      if (booking.phone || booking.guest.phone) {
        guestInfo.push(`Số điện thoại: ${booking.phone || booking.guest.phone}`);
      }

      guestInfo.forEach(info => {
        doc.text(info, 20, y);
        y += 6;
      });

      y += 10;
      doc.setFontSize(8);
      doc.setTextColor(128, 128, 128);
      doc.text('Cảm ơn bạn đã sử dụng dịch vụ của chúng tôi!', 105, y, {
        align: 'center',
      });

      doc.save(`hoa-don-${booking.code}.pdf`);
      toast.success('Đã xuất hóa đơn PDF thành công');
    } catch (error) {
      console.error('Error exporting PDF:', error);
      toast.error('Không thể xuất hóa đơn');
    } finally {
      setExporting(false);
    }
  };

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);
  };

  const getStatusLabel = (status?: string) => {
    if (booking && booking.paymentStatus === 'pending') {
      return 'Chưa thanh toán';
    }
    const labels: any = {
      pending: 'Chưa thanh toán',
      confirmed: 'Đã xác nhận',
      cancelled: 'Đã hủy',
      completed: 'Hoàn thành',
      refunded: 'Đã hoàn tiền',
    };
    return labels[status || ''] || status;
  };

  const getPaymentStatusLabel = (status?: string) => {
    const labels: any = {
      pending: 'Chưa thanh toán',
      paid: 'Đã thanh toán',
      failed: 'Thanh toán thất bại',
      refunded: 'Đã hoàn tiền',
    };
    return labels[status || ''] || status;
  };

  const getPaymentMethodLabel = (method?: string) => {
    const labels: any = {
      deposit: 'Đặt cọc',
      full: 'Thanh toán đầy đủ',
    };
    return labels[method || ''] || 'Chưa chọn';
  };

  const getCancellationPolicyLabel = (type?: string) => {
    const labels: any = {
      flexible: 'Linh hoạt',
      moderate: 'Trung bình',
      strict: 'Nghiêm ngặt',
    };
    return labels[type || ''] || 'Không rõ';
  };

  // Calculate paid amount based on payment method
  const getPaidAmount = () => {
    if (!booking || booking.paymentStatus !== 'paid') return 0;
    return booking.paymentMethod === 'deposit'
      ? booking.pricing.total * 0.3 // 30% deposit
      : booking.pricing.total;
  };

  const getRemainingAmount = () => {
    if (!booking || booking.paymentMethod !== 'deposit') return 0;
    return booking.pricing.total * 0.7; // 70% remaining
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-600" />
      </div>
    );
  }

  if (!booking) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <XCircle className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-lg font-medium text-gray-900">
            Không tìm thấy booking
          </h3>
          <Button className="mt-4" asChild>
            <Link href="/host/bookings">Quay lại danh sách</Link>
          </Button>
        </div>
      </div>
    );
  }

  const getBookingDisplayStatus = () => {
    if (!booking) return 'confirmed';
    if (booking.paymentStatus === 'pending') {
      return 'unpaid';
    }
    return booking.status;
  };
  const displayStatus = getBookingDisplayStatus();

  const statusConfig: Record<string, { label: string; color: string; icon: any }> = {
    unpaid: {
      label: 'Chưa thanh toán',
      color: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      icon: Clock,
    },
    pending: {
      label: 'Chưa thanh toán',
      color: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      icon: Clock,
    },
    confirmed: {
      label: 'Đã xác nhận',
      color: 'bg-green-100 text-green-800 border-green-200',
      icon: CheckCircle2,
    },
    cancelled: {
      label: 'Đã hủy',
      color: 'bg-red-100 text-red-800 border-red-200',
      icon: XCircle,
    },
    completed: {
      label: 'Hoàn thành',
      color: 'bg-blue-100 text-blue-800 border-blue-200',
      icon: CheckCircle2,
    },
    refunded: {
      label: 'Đã hoàn tiền',
      color: 'bg-purple-100 text-purple-800 border-purple-200',
      icon: AlertCircle,
    },
  };

  const paymentStatusConfig = {
    pending: {
      label: 'Chưa thanh toán',
      color: 'bg-gradient-to-r from-yellow-400 to-orange-400',
      textColor: 'text-white',
      icon: CircleDollarSign,
      glow: 'shadow-lg shadow-yellow-200',
    },
    paid: {
      label: 'Đã thanh toán',
      color: 'bg-gradient-to-r from-emerald-400 to-green-500',
      textColor: 'text-white',
      icon: CheckCircle2,
      glow: 'shadow-lg shadow-emerald-200',
    },
    failed: {
      label: 'Thanh toán thất bại',
      color: 'bg-gradient-to-r from-red-400 to-rose-500',
      textColor: 'text-white',
      icon: XCircle,
      glow: 'shadow-lg shadow-red-200',
    },
    refunded: {
      label: 'Đã hoàn tiền',
      color: 'bg-gradient-to-r from-purple-400 to-pink-500',
      textColor: 'text-white',
      icon: BanknoteIcon,
      glow: 'shadow-lg shadow-purple-200',
    },
  };

  const status = statusConfig[displayStatus];
  const paymentStatus = paymentStatusConfig[booking.paymentStatus || 'pending'];
  const StatusIcon = status.icon;
  const PaymentIcon = paymentStatus.icon;

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-6">
          <Button variant="ghost" size="sm" asChild className="mb-4">
            <Link href="/host/bookings">
              <ChevronLeft className="mr-2 h-4 w-4" />
              Quay lại danh sách booking
            </Link>
          </Button>

          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">
                Chi tiết booking
              </h1>
              <p className="mt-1 text-sm text-gray-500">
                Mã booking: <span className="font-mono font-semibold">{booking.code}</span>
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div
                className={`${status.color} flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-semibold`}
              >
                <StatusIcon className="h-4 w-4" />
                {status.label}
              </div>

              {/* <div
                className={`${paymentStatus.color} ${paymentStatus.textColor} ${paymentStatus.glow} flex items-center gap-2 rounded-full px-4 py-2 text-sm font-semibold`}
              >
                <PaymentIcon className="h-5 w-5" />
                {paymentStatus.label}
              </div> */}

              {/* {booking.paymentMethod && (
                <Badge variant="outline" className="text-sm">
                  {getPaymentMethodLabel(booking.paymentMethod)}
                </Badge>
              )} */}
            </div>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Main Content */}
          <div className="space-y-6 lg:col-span-2">
            {/* Payment Status Alert */}
            {booking.paymentStatus === 'pending' && booking.status !== 'cancelled' && booking.payOSCheckoutUrl && (
              <Card className="border-2 border-yellow-300 bg-gradient-to-r from-yellow-50 to-orange-50">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-4">
                    <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-yellow-500">
                      <CircleDollarSign className="h-6 w-6 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900">
                        Booking chưa thanh toán
                      </h3>
                      <p className="text-sm text-gray-600">
                        Khách hàng cần thanh toán để xác nhận booking
                      </p>
                    </div>
                    <Button
                      size="lg"
                      asChild
                      className="bg-yellow-600 hover:bg-yellow-700"
                    >
                      <a
                        href={booking.payOSCheckoutUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <CreditCard className="mr-2 h-4 w-4" />
                        Link thanh toán
                      </a>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {booking.paymentStatus === 'paid' && (
              <Card className="border-2 border-emerald-300 bg-gradient-to-r from-emerald-50 to-green-50">
                <CardContent className="pt-6">
                  <div className="space-y-4">
                    <div className="flex items-center gap-4">
                      <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-emerald-500">
                        <CheckCircle2 className="h-6 w-6 text-white" />
                      </div>
                      <div className="flex-1">
                        <h3 className="font-semibold text-gray-900">
                          Thanh toán thành công
                        </h3>
                        <div className="mt-1 space-y-1">
                          {booking.paidAt && (
                            <p className="text-sm text-gray-600">
                              🕒 Thanh toán lúc:{' '}
                              {format(new Date(booking.paidAt), 'dd/MM/yyyy HH:mm', {
                                locale: vi,
                              })}
                            </p>
                          )}
                          {booking.payOSOrderCode && (
                            <p className="text-sm text-gray-600">
                              🔢 Mã giao dịch: <span className="font-mono">{booking.payOSOrderCode}</span>
                            </p>
                          )}
                          {booking.transactionId && (
                            <p className="text-sm text-gray-600">
                              💳 Transaction ID: <span className="font-mono text-xs">{booking.transactionId}</span>
                            </p>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Payment Amount Info */}
                    <div className="rounded-lg bg-white/80 p-4">
                      <div className="flex items-center gap-2 mb-3">
                        <Wallet className="h-5 w-5 text-emerald-600" />
                        <h4 className="font-semibold text-emerald-900">Thông tin thanh toán</h4>
                      </div>

                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-700">
                            {booking.paymentMethod === 'deposit' ? 'Số tiền đã cọc (30%):' : 'Số tiền đã thanh toán:'}
                          </span>
                          <span className="font-bold text-emerald-700">
                            {formatPrice(getPaidAmount())}
                          </span>
                        </div>

                        {booking.paymentMethod === 'deposit' && (
                          <>
                            <Separator className="my-2" />
                            <div className="flex justify-between items-center">
                              <span className="text-sm text-gray-700">Còn lại (70%):</span>
                              <span className="font-bold text-orange-600">
                                {formatPrice(getRemainingAmount())}
                              </span>
                            </div>
                            <p className="text-xs text-gray-600 mt-2 italic">
                              * Số tiền còn lại sẽ được thanh toán khi nhận chỗ
                            </p>
                          </>
                        )}

                        <Separator className="my-2" />
                        <div className="flex justify-between items-center pt-2">
                          <span className="text-sm font-semibold text-gray-900">Tổng giá trị booking:</span>
                          <span className="text-lg font-bold text-gray-900">
                            {formatPrice(booking.pricing.total)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Property & Site Info */}
            <Card>
              <CardHeader>
                <CardTitle>Thông tin địa điểm</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Property */}
                <div className="flex gap-4">
                  <div className="relative h-24 w-24 flex-shrink-0 overflow-hidden rounded-lg">
                    <Image
                      src={booking.property.photos?.[0]?.url || '/placeholder.jpg'}
                      alt={booking.property.name || 'Property'}
                      fill
                      className="object-cover"
                    />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Home className="h-4 w-4 text-blue-600" />
                      <span className="text-xs font-medium text-blue-700">
                        PROPERTY
                      </span>
                    </div>
                    <h3 className="mt-1 text-lg font-semibold">
                      {booking.property.name}
                    </h3>
                    <div className="mt-2 flex items-start gap-2 text-sm text-gray-600">
                      <MapPin className="mt-0.5 h-4 w-4 flex-shrink-0" />
                      <span>
                        {booking.property.location?.address},{' '}
                        {booking.property.location?.city},{' '}
                        {booking.property.location?.state}
                      </span>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Site */}
                <div className="flex gap-4">
                  <div className="relative h-24 w-24 flex-shrink-0 overflow-hidden rounded-lg">
                    <Image
                      src={booking.site.photos?.[0]?.url || '/placeholder.jpg'}
                      alt={booking.site.name || 'Site'}
                      fill
                      className="object-cover"
                    />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Tent className="h-4 w-4 text-emerald-600" />
                      <span className="text-xs font-medium text-emerald-700">
                        SITE
                      </span>
                    </div>
                    <h3 className="mt-1 text-lg font-semibold flex items-center gap-2">
                      {booking.site.name}
                      {booking.numberOfUnits !== undefined && booking.numberOfUnits > 0 && (
                        <span className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {booking.numberOfUnits} vị trí
                        </span>
                      )}
                    </h3>
                    <p className="mt-1 text-sm text-gray-600">
                      {booking.site.description}
                    </p>
                  </div>
                </div>

                <Separator />

                <Button variant="outline" size="sm" className="w-full" asChild>
                  <Link href={`/land/${booking.property.slug}`}>
                    Xem chi tiết property
                  </Link>
                </Button>
              </CardContent>
            </Card>

            {/* Booking Details */}
            <Card>
              <CardHeader>
                <CardTitle>Chi tiết đặt chỗ</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="flex items-start gap-3">
                    <Calendar className="mt-0.5 h-5 w-5 text-gray-400" />
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        Nhận chỗ
                      </p>
                      <p className="text-sm text-gray-600">
                        {format(new Date(booking.checkIn), 'dd/MM/yyyy - HH:mm', {
                          locale: vi,
                        })}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <Calendar className="mt-0.5 h-5 w-5 text-gray-400" />
                    <div>
                      <p className="text-sm font-medium text-gray-900">Trả chỗ</p>
                      <p className="text-sm text-gray-600">
                        {format(new Date(booking.checkOut), 'dd/MM/yyyy - HH:mm', {
                          locale: vi,
                        })}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <Users className="mt-0.5 h-5 w-5 text-gray-400" />
                    <div>
                      <p className="text-sm font-medium text-gray-900">Số khách</p>
                      <p className="text-sm text-gray-600">
                        {booking.numberOfGuests} người
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <Clock className="mt-0.5 h-5 w-5 text-gray-400" />
                    <div>
                      <p className="text-sm font-medium text-gray-900">Số đêm</p>
                      <p className="text-sm text-gray-600">{booking.nights} đêm</p>
                    </div>
                  </div>

                  {booking.numberOfUnits !== undefined && booking.numberOfUnits > 0 && (
                    <div className="flex items-start gap-3">
                      <Tent className="mt-0.5 h-5 w-5 text-gray-400" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          Số lượng vị trí (bãi cắm)
                        </p>
                        <p className="text-sm font-semibold text-emerald-700">
                          {booking.numberOfUnits} vị trí
                        </p>
                      </div>
                    </div>
                  )}

                  {booking.numberOfPets !== undefined && booking.numberOfPets > 0 && (
                    <div className="flex items-start gap-3">
                      <PawPrint className="mt-0.5 h-5 w-5 text-gray-400" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          Thú cưng
                        </p>
                        <p className="text-sm text-gray-600">
                          {booking.numberOfPets} con
                        </p>
                      </div>
                    </div>
                  )}

                  {booking.numberOfVehicles !== undefined && booking.numberOfVehicles > 0 && (
                    <div className="flex items-start gap-3">
                      <Car className="mt-0.5 h-5 w-5 text-gray-400" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          Phương tiện
                        </p>
                        <p className="text-sm text-gray-600">
                          {booking.numberOfVehicles} xe
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {booking.guestMessage && (
                  <>
                    <Separator />
                    <div>
                      <p className="mb-2 text-sm font-medium text-gray-900">
                        💬 Lời nhắn từ khách
                      </p>
                      <p className="rounded-lg bg-gray-50 p-3 text-sm text-gray-600">
                        {booking.guestMessage}
                      </p>
                    </div>
                  </>
                )}

                {booking.hostMessage && (
                  <>
                    <Separator />
                    <div>
                      <p className="mb-2 text-sm font-medium text-gray-900">
                        📝 Phản hồi từ chủ nhà
                      </p>
                      <p className="rounded-lg bg-emerald-50 p-3 text-sm text-gray-600">
                        {booking.hostMessage}
                      </p>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {booking.services && booking.services.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Info className="h-5 w-5 text-emerald-600" />
                    Dịch vụ bổ sung đã chọn
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="divide-y divide-gray-100">
                    {booking.services.map((svc, idx) => (
                      <div key={idx} className="flex justify-between py-3 first:pt-0 last:pb-0">
                        <div>
                          <p className="font-medium text-gray-900">{svc.name}</p>
                          <p className="text-xs text-gray-500">
                            Đơn giá: {formatPrice(svc.price)} / {formatServiceUnit(svc.unit)}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="font-semibold text-gray-900">
                            x{svc.quantity}
                          </p>
                          <p className="text-sm font-bold text-emerald-600">
                            {formatPrice(svc.price * svc.quantity)}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                  {booking.pricing.servicesFee !== undefined && booking.pricing.servicesFee > 0 && (
                    <>
                      <Separator />
                      <div className="flex justify-between items-center pt-2">
                        <span className="text-sm font-semibold text-gray-900">Tổng chi phí dịch vụ:</span>
                        <span className="text-base font-bold text-emerald-600">
                          {formatPrice(booking.pricing.servicesFee)}
                        </span>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Guest Info */}
            <Card>
              <CardHeader>
                <CardTitle>Thông tin khách hàng</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="relative h-16 w-16 overflow-hidden rounded-full">
                    {booking.guest.avatarUrl ? (
                      <Image
                        src={booking.guest.avatarUrl}
                        alt={booking.guest.username}
                        fill
                        className="object-cover"
                      />
                    ) : (
                      <div className="flex h-full w-full items-center justify-center bg-gray-200 text-2xl font-semibold text-gray-600">
                        {(booking.fullnameGuest || booking.guest.username).charAt(0).toUpperCase()}
                      </div>
                    )}
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold">
                      {booking.fullnameGuest || booking.guest.fullName || booking.guest.username}
                    </h4>
                    <p className="text-sm text-gray-600">{booking.guest.username}</p>
                  </div>
                </div>

                <Separator />

                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <Mail className="h-4 w-4 text-gray-400" />
                    <div>
                      <p className="text-xs text-gray-500">Email</p>
                      <p className="text-sm font-medium">{booking.email || booking.guest.email}</p>
                    </div>
                  </div>

                  {(booking.phone || booking.guest.phone) && (
                    <div className="flex items-center gap-3">
                      <Phone className="h-4 w-4 text-gray-400" />
                      <div>
                        <p className="text-xs text-gray-500">Số điện thoại</p>
                        <p className="text-sm font-medium">{booking.phone || booking.guest.phone}</p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
            {/* Pricing */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Receipt className="h-5 w-5" />
                  Chi tiết giá
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">
                    {formatPrice(booking.pricing.basePrice)} × {booking.pricing.totalNights} đêm
                  </span>
                  <span className="font-medium">
                    {formatPrice(booking.pricing.subtotal)}
                  </span>
                </div>

                {booking.pricing.cleaningFee > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Phí vệ sinh</span>
                    <span className="font-medium">
                      {formatPrice(booking.pricing.cleaningFee)}
                    </span>
                  </div>
                )}

                {booking.pricing.petFee > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">
                      Phí thú cưng ({booking.numberOfPets} con)
                    </span>
                    <span className="font-medium">
                      {formatPrice(booking.pricing.petFee)}
                    </span>
                  </div>
                )}

                {booking.pricing.extraGuestFee > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Phí khách thêm</span>
                    <span className="font-medium">
                      {formatPrice(booking.pricing.extraGuestFee)}
                    </span>
                  </div>
                )}

                {booking.pricing.servicesFee !== undefined && booking.pricing.servicesFee > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Phí dịch vụ bổ sung</span>
                    <span className="font-medium text-emerald-600">
                      {formatPrice(booking.pricing.servicesFee)}
                    </span>
                  </div>
                )}

                {booking.pricing.serviceFee > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Phí dịch vụ</span>
                    <span className="font-medium">
                      {formatPrice(booking.pricing.serviceFee)}
                    </span>
                  </div>
                )}

                {booking.pricing.tax > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">Thuế VAT</span>
                    <span className="font-medium">
                      {formatPrice(booking.pricing.tax)}
                    </span>
                  </div>
                )}

                {booking.pricing.promoCode && booking.pricing.promoDiscount !== undefined && booking.pricing.promoDiscount > 0 && (
                  <div className="flex justify-between text-sm text-red-600">
                    <span className="flex items-center gap-1.5 font-medium">🏷️ Mã giảm giá ({booking.pricing.promoCode})</span>
                    <span className="font-medium">
                      -{formatPrice(booking.pricing.promoDiscount)}
                    </span>
                  </div>
                )}

                <Separator />

                <div className="flex justify-between text-lg font-bold">
                  <span>Tổng cộng</span>
                  <span className="text-emerald-600">
                    {formatPrice(booking.pricing.total)}
                  </span>
                </div>

                {/* Payment Info in Pricing Card */}
                {booking.paymentStatus === 'paid' && (
                  <>
                    <Separator />
                    <div className="space-y-2 rounded-lg bg-emerald-50 p-3">
                      <div className="flex items-center gap-2">
                        <Wallet className="h-4 w-4 text-emerald-600" />
                        <span className="text-sm font-semibold text-emerald-900">
                          Trạng thái thanh toán
                        </span>
                      </div>

                      <div className="flex justify-between text-sm">
                        <span className="text-emerald-700">
                          {booking.paymentMethod === 'deposit' ? 'Đã cọc:' : 'Đã thanh toán:'}
                        </span>
                        <span className="font-bold text-emerald-900">
                          {formatPrice(getPaidAmount())}
                        </span>
                      </div>

                      {booking.paymentMethod === 'deposit' && (
                        <div className="flex justify-between text-sm">
                          <span className="text-orange-700">Còn lại:</span>
                          <span className="font-bold text-orange-900">
                            {formatPrice(getRemainingAmount())}
                          </span>
                        </div>
                      )}
                    </div>
                  </>
                )}

                {booking.paymentMethod === 'deposit' && booking.paymentStatus !== 'paid' && (
                  <div className="rounded-lg bg-blue-50 p-3 text-sm">
                    <p className="font-medium text-blue-900">
                      💰 Phương thức: Đặt cọc 30%
                    </p>
                    <p className="mt-1 text-xs text-blue-700">
                      Cần thanh toán: {formatPrice(booking.pricing.total * 0.3)}
                    </p>
                    <p className="mt-1 text-xs text-blue-700">
                      Còn lại khi nhận chỗ: {formatPrice(booking.pricing.total * 0.7)}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Timeline */}
            <Card>
              <CardHeader>
                <CardTitle>Lịch sử</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex gap-3">
                    <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-emerald-100">
                      <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                    </div>
                    <div className="flex-1">
                      <p className="text-sm font-medium">Đã tạo booking</p>
                      <p className="text-xs text-gray-500">
                        {format(new Date(booking.createdAt), 'dd/MM/yyyy HH:mm', {
                          locale: vi,
                        })}
                      </p>
                    </div>
                  </div>

                  {booking.paidAt && (
                    <div className="flex gap-3">
                      <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-100">
                        <CreditCard className="h-4 w-4 text-green-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Đã thanh toán</p>
                        <p className="text-xs text-gray-500">
                          {format(new Date(booking.paidAt), 'dd/MM/yyyy HH:mm', {
                            locale: vi,
                          })}
                        </p>
                      </div>
                    </div>
                  )}

                  {booking.cancelledAt && (
                    <div className="flex gap-3">
                      <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-red-100">
                        <XCircle className="h-4 w-4 text-red-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Đã hủy</p>
                        <p className="text-xs text-gray-500">
                          {format(new Date(booking.cancelledAt), 'dd/MM/yyyy HH:mm', {
                            locale: vi,
                          })}
                        </p>
                      </div>
                    </div>
                  )}

                  {booking.paymentStatus === 'refunded' && (
                    <div className="flex gap-3">
                      <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-purple-100">
                        <BanknoteIcon className="h-4 w-4 text-purple-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Đã hoàn tiền</p>
                        <p className="text-xs text-gray-500">
                          {formatPrice(booking.refundAmount || refundInfo.refundAmount)}
                        </p>
                      </div>
                    </div>
                  )}

                  {booking.updatedAt && booking.updatedAt !== booking.createdAt && (
                    <div className="flex gap-3">
                      <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-gray-100">
                        <Clock className="h-4 w-4 text-gray-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Cập nhật gần nhất</p>
                        <p className="text-xs text-gray-500">
                          {format(new Date(booking.updatedAt), 'dd/MM/yyyy HH:mm', {
                            locale: vi,
                          })}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Actions */}
            <Card>
              <CardHeader>
                <CardTitle>Thao tác</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={handleExportPDF}
                  disabled={exporting}
                >
                  {exporting ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <FileText className="mr-2 h-4 w-4" />
                  )}
                  {exporting ? 'Đang xuất...' : 'Xuất hóa đơn PDF'}
                </Button>

                {booking.status !== 'cancelled' &&
                  booking.status !== 'completed' &&
                  booking.status !== 'refunded' && (
                    <div className="space-y-2 pt-2 border-t border-gray-100">
                      {/* Case 1: Booking not paid yet */}
                      {booking.paymentStatus !== 'paid' && (
                        <div className="space-y-2">
                          {timeLeft > 0 && (
                            <div className="text-xs text-amber-700 bg-amber-50 p-3 rounded-lg border border-amber-200 space-y-1">
                              <p className="font-semibold">⚠️ Chờ thanh toán</p>
                              <p>Bạn chỉ có thể hủy booking chưa thanh toán này sau 30 phút kể từ lúc đặt.</p>
                              <p className="font-mono font-semibold">
                                Có thể hủy sau: {Math.floor(timeLeft / 60)} phút {timeLeft % 60} giây
                              </p>
                            </div>
                          )}
                          <Button
                            variant="destructive"
                            className="w-full"
                            onClick={() => {
                              setCancelReason('');
                              setCancelDialogOpen(true);
                            }}
                            disabled={timeLeft > 0}
                          >
                            <XCircle className="mr-2 h-4 w-4" />
                            Hủy booking
                          </Button>
                        </div>
                      )}

                      {/* Case 2: Booking already paid */}
                      {booking.paymentStatus === 'paid' && (
                        <Button
                          variant="destructive"
                          className="w-full bg-red-600 hover:bg-red-700 text-white"
                          onClick={() => {
                            setCancelReason('');
                            setCancelDialogOpen(true);
                          }}
                        >
                          <XCircle className="mr-2 h-4 w-4" />
                          Hủy và hoàn tiền
                        </Button>
                      )}
                    </div>
                  )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Cancel Dialog */}
      <Dialog open={cancelDialogOpen} onOpenChange={setCancelDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {booking?.paymentStatus === 'paid' ? 'Hủy và hoàn tiền' : 'Hủy booking'}
            </DialogTitle>
            <DialogDescription>
              {booking?.paymentStatus === 'paid'
                ? 'Bạn có chắc chắn muốn hủy booking đã thanh toán này? Hệ thống sẽ ghi nhận yêu cầu hoàn tiền 100% cho khách hàng sau khi khách cung cấp thông tin tài khoản ngân hàng.'
                : 'Bạn có chắc chắn muốn hủy booking này? Vui lòng cho biết lý do hủy.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <Textarea
              placeholder="Nhập lý do hủy booking..."
              value={cancelReason}
              onChange={e => setCancelReason(e.target.value)}
              rows={4}
              maxLength={500}
            />
            <p className="text-xs text-gray-500">
              {cancelReason.length}/500 ký tự
            </p>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setCancelDialogOpen(false)}>
              Đóng
            </Button>
            <Button
              variant="destructive"
              onClick={handleCancelBooking}
              disabled={cancelling || !cancelReason.trim()}
            >
              {cancelling ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Đang hủy...
                </>
              ) : (
                'Xác nhận hủy'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}