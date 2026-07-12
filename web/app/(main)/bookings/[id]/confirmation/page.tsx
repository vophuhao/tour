'use client';

import { ReviewDialog } from '@/components/reviews/review-dialog';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Carousel,
  CarouselContent,
  CarouselItem,
  CarouselNext,
  CarouselPrevious,
} from '@/components/ui/carousel';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import {
  cancelBooking,
  completeBooking,
  getBooking,
  requestDissatisfaction,
  submitRefundBankDetails,
} from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import type { Property, Site } from '@/types/property-site';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';
import {
  AlertCircle,
  ArrowLeft,
  Calendar,
  CheckCircle,
  Clock,
  CreditCard,
  Home,
  Loader2,
  MapPin,
  Star,
  Users,
  XCircle,
  Receipt,
  Wallet,
  Info,
  Phone,
  Mail,
  User,
} from 'lucide-react';
import Image from 'next/image';
import { useParams, useRouter } from 'next/navigation';
import { useState } from 'react';
import { toast } from 'sonner';

// Backend Booking type matching the populated response
interface BookingData {
  _id: string;
  id?: string;
  code?: string;
  status: 'pending' | 'confirmed' | 'cancelled' | 'completed' | 'refunded' | 'refund_requested';
  checkIn: string;
  checkOut: string;
  numberOfGuests: number;
  numberOfPets?: number;
  numberOfVehicles?: number;
  numberOfUnits?: number;
  nights: number;
  paymentStatus?: 'pending' | 'paid' | 'refunded' | 'failed';
  paymentMethod?: 'full' | 'deposit';
  guestMessage?: string;
  hostMessage?: string;
  payOSOrderCode?: string;
  payOSCheckoutUrl?: string;
  fullnameGuest?: string;
  phone?: string;
  email?: string;

  // New Property-Site architecture
  property?: Partial<Property>;
  site?: Partial<Site> & {
    property?: Partial<Property> & {
      host?: {
        _id: string;
        fullName: string;
        username: string;
        avatarUrl?: string;
      };
    };
  };

  // Legacy campsite support (for backward compatibility)
  campsite?: {
    _id: string;
    name: string;
    slug?: string;
    images?: string[];
    checkInTime?: string;
    checkOutTime?: string;
    location?: {
      city: string;
      state: string;
      address?: string;
    };
    host?: {
      _id: string;
      name: string;
      avatar?: string;
    };
  };

  guest?: {
    _id: string;
    username: string;
    email: string;
    fullName?: string;
    phone?: string;
    avatarUrl?: string;
  };

  host?: {
    _id: string;
    username: string;
    email: string;
    avatarUrl?: string;
  };

  pricing?: {
    basePrice: number;
    totalNights: number;
    subtotal: number;
    cleaningFee?: number;
    petFee?: number;
    extraGuestFee?: number;
    serviceFee: number;
    tax: number;
    total: number;
    depositAmount?: number;
    depositPercentage?: number;
    servicesFee?: number;
    promoCode?: string;
    promoDiscount?: number;
  };

  services?: Array<{
    name: string;
    price: number;
    unit?: string;
    quantity: number;
  }>;

  reviewed?: boolean;
  review?: string;
  cannotAttendRequest?: {
    requestedAt: string;
    status: 'pending' | 'approved' | 'rejected';
    refundAmount?: number;
    reason?: string;
    bankAccountName?: string;
    bankAccountNumber?: string;
    bankName?: string;
    evidenceImages?: string[];
    adminNote?: string;
    processedAt?: string;
    processedBy?: string;
  };
  dissatisfactionRequest?: {
    requestedAt: string;
    status: 'pending' | 'approved' | 'rejected';
    refundAmount?: number;
  };
  cancellationReason?: string;
  refundAmount?: number;
  hostNetAmount?: number;
  cancellInformation?: {
    fullnameGuest?: string;
    bankCode?: string;
    bankType?: string;
  };
  createdAt: string;
  updatedAt: string;
}

const formatServiceUnit = (unit?: string) => {
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

export default function ConfirmationPage() {
  const router = useRouter();
  const params = useParams();
  const bookingId = params.id as string;
  const { user } = useAuthStore();
  const queryClient = useQueryClient();

  // Cancel dialog state
  const [isCancelDialogOpen, setIsCancelDialogOpen] = useState(false);
  const [cancellationReason, setCancellationReason] = useState('');
  const [cancellInformation, setCancellInformation] = useState({
    fullnameGuest: '',
    bankCode: '',
    bankType: '',
  });
  const [refundBankDetails, setRefundBankDetails] = useState({
    fullnameGuest: '',
    bankCode: '',
    bankType: '',
  });
  const [submittingRefund, setSubmittingRefund] = useState(false);

  // Review dialog state
  const [isReviewDialogOpen, setIsReviewDialogOpen] = useState(false);

  // Dissatisfaction dialog state
  const [isDissatisfactionOpen, setIsDissatisfactionOpen] = useState(false);
  const [dissatisfactionForm, setDissatisfactionForm] = useState({
    reason: '',
    phone: '',
    email: '',
    bankAccountName: '',
    bankAccountNumber: '',
    bankName: '',
  });
  const [dissatisfactionImages, setDissatisfactionImages] = useState<File[]>([]);
  const [uploadingImages, setUploadingImages] = useState(false);
  const [uploadedImageUrls, setUploadedImageUrls] = useState<string[]>([]);

  const { data, isLoading, error } = useQuery({
    queryKey: ['booking', bookingId],
    queryFn: () => getBooking(bookingId),
    enabled: !!bookingId,
  });
  console.log('Booking data:', data);

  // Cancel booking mutation
  const cancelMutation = useMutation({
    mutationFn: (cancellationReason: string) =>
      cancelBooking(bookingId, { cancellationReason, cancellInformation }),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ['booking', bookingId] });
      const previousBooking = queryClient.getQueryData(['booking', bookingId]);
      return { previousBooking };
    },
    onSuccess: () => {
      toast.success('Đã hủy đặt chỗ thành công', {
        description:
          'Chúng tôi sẽ xử lý hoàn tiền trong vòng 5-7 ngày làm việc.',
      });
      queryClient.invalidateQueries({ queryKey: ['booking', bookingId] });
      queryClient.invalidateQueries({ queryKey: ['bookings'] });
      queryClient.invalidateQueries({ queryKey: ['user-bookings'] });
      setIsCancelDialogOpen(false);
      setCancellationReason('');
    },
    onError: (error: Error, _variables, context) => {
      if (context?.previousBooking) {
        queryClient.setQueryData(
          ['booking', bookingId],
          context.previousBooking,
        );
      }
      toast.error('Không thể hủy đặt chỗ', {
        description: error?.message || 'Vui lòng thử lại sau.',
      });
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['booking', bookingId] });
    },
  });

  // Complete booking mutation
  const completeMutation = useMutation({
    mutationFn: () => completeBooking(bookingId),
    onSuccess: () => {
      toast.success('Đã hoàn thành chuyến đi', {
        description: 'Bạn có thể đánh giá trải nghiệm của mình ngay bây giờ.',
      });
      queryClient.invalidateQueries({ queryKey: ['booking', bookingId] });
      queryClient.invalidateQueries({ queryKey: ['bookings'] });
      queryClient.invalidateQueries({ queryKey: ['user-bookings'] });
    },
    onError: (error: Error) => {
      toast.error('Không thể hoàn thành chuyến đi', {
        description: error?.message || 'Vui lòng thử lại sau.',
      });
    },
  });

  // Dissatisfaction mutation
  const dissatisfactionMutation = useMutation({
    mutationFn: (imageUrls: string[]) =>
      requestDissatisfaction(bookingId, {
        ...dissatisfactionForm,
        evidenceImages: imageUrls,
      }),
    onSuccess: () => {
      toast.success('Đã gửi yêu cầu hoàn tiền', {
        description: 'Chúng tôi sẽ xem xét và phản hồi trong vòng 3-5 ngày làm việc.',
      });
      queryClient.invalidateQueries({ queryKey: ['booking', bookingId] });
      setIsDissatisfactionOpen(false);
    },
    onError: (error: Error) => {
      toast.error('Không thể gửi yêu cầu', {
        description: error?.message || 'Vui lòng thử lại sau.',
      });
    },
  });

  const handleSubmitRefundBankDetails = async () => {
    if (!refundBankDetails.fullnameGuest.trim() || !refundBankDetails.bankCode.trim() || !refundBankDetails.bankType.trim()) {
      toast.error('Vui lòng điền đầy đủ thông tin tài khoản ngân hàng');
      return;
    }
    try {
      setSubmittingRefund(true);
      const res = await submitRefundBankDetails(bookingId, refundBankDetails);
      if (res.success) {
        toast.success('Đã gửi thông tin hoàn tiền thành công! Hệ thống đã phê duyệt hoàn tiền 100% cho bạn.');
        queryClient.invalidateQueries({ queryKey: ['booking', bookingId] });
      } else {
        throw new Error(res.message || 'Có lỗi xảy ra');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.message || err.message || 'Lỗi gửi thông tin hoàn tiền');
    } finally {
      setSubmittingRefund(false);
    }
  };

  const handleDissatisfactionSubmit = async () => {
    if (!dissatisfactionForm.reason || dissatisfactionForm.reason.length < 10) {
      toast.error('Lý do phải có ít nhất 10 ký tự');
      return;
    }
    if (!dissatisfactionForm.phone || !dissatisfactionForm.email) {
      toast.error('Vui lòng điền số điện thoại và email');
      return;
    }
    if (!dissatisfactionForm.bankAccountName || !dissatisfactionForm.bankAccountNumber || !dissatisfactionForm.bankName) {
      toast.error('Vui lòng điền đầy đủ thông tin ngân hàng');
      return;
    }
    if (dissatisfactionImages.length < 5) {
      toast.error('Phải cung cấp ít nhất 5 ảnh minh chứng');
      return;
    }

    try {
      setUploadingImages(true);
      toast.info('Đang upload ảnh minh chứng...');
      const { uploadMedia } = await import('@/lib/client-actions');
      const urls: string[] = [];
      for (let i = 0; i < dissatisfactionImages.length; i++) {
        const fd = new FormData();
        fd.append('files', dissatisfactionImages[i]);
        fd.append('folder', 'dissatisfaction');
        const res = await uploadMedia(fd);
        const url = Array.isArray(res?.data) ? res.data[0] : res?.data;
        if (url) urls.push(url as string);
      }
      setUploadedImageUrls(urls);
      if (urls.length < 5) {
        toast.error('Upload ảnh thất bại. Vui lòng thử lại.');
        return;
      }
      await dissatisfactionMutation.mutateAsync(urls);
    } finally {
      setUploadingImages(false);
    }
  };

  const handleCancelBooking = () => {
    if (!cancellationReason.trim()) {
      toast.error('Vui lòng nhập lý do hủy');
      return;
    }

    if (cancellationReason.trim().length < 10) {
      toast.error('Lý do hủy phải có ít nhất 10 ký tự');
      return;
    }

    if (cancellationReason.trim().length > 500) {
      toast.error('Lý do hủy không được vượt quá 500 ký tự');
      return;
    }

    cancelMutation.mutate(cancellationReason);
  };

  const booking = data?.data as BookingData | undefined;

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="text-primary mx-auto h-12 w-12 animate-spin" />
          <p className="text-muted-foreground mt-4">Đang tải thông tin...</p>
        </div>
      </div>
    );
  }

  if (error || !booking) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6">
            <p className="text-center text-red-600">
              Không tìm thấy thông tin đặt chỗ
            </p>
            <Button
              onClick={() => router.push('/')}
              className="mt-4 w-full"
              variant="outline"
            >
              Về trang chủ
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  const getStatusBadge = (status: BookingData['status']) => {
    const styles: Record<BookingData['status'], string> = {
      pending: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      confirmed: 'bg-green-100 text-green-800 border-green-200',
      cancelled: 'bg-red-100 text-red-800 border-red-200',
      completed: 'bg-blue-100 text-blue-800 border-blue-200',
      refunded: 'bg-gray-100 text-gray-800 border-gray-200',
      refund_requested: 'bg-orange-100 text-orange-800 border-orange-200',
    };
    const labels: Record<BookingData['status'], string> = {
      pending: 'Chờ xác nhận',
      confirmed: 'Đã xác nhận',
      cancelled: 'Đã hủy',
      completed: 'Hoàn thành',
      refunded: 'Đã hoàn tiền',
      refund_requested: 'Đang yêu cầu hoàn tiền',
    };
    return (
      <Badge className={`${styles[status]} px-3 py-1`}>{labels[status]}</Badge>
    );
  };

  // Get images: prefer site photos, fallback to property photos, then campsite images
  const siteImages =
    booking.site?.photos?.map(p => p.url) ||
    booking.property?.photos?.map(p => p.url) ||
    booking.campsite?.images ||
    [];
  const images =
    siteImages.length > 0 ? siteImages : ['/placeholder-campsite.jpg'];

  // Get property and site info (support both new and legacy structure)
  const property = booking.site?.property || booking.property;
  const site = booking.site;
  const siteName = site?.name || booking.campsite?.name || 'Site';
  const propertyName = property?.name || booking.campsite?.host?.name || '';
  const location = (property?.location || booking.campsite?.location) as {
    city: string;
    state: string;
    address?: string;
    directions?: string;
    accessInstructions?: string;
    parkingInstructions?: string;
  } | undefined;

  // Google Maps link based on site coordinates or property coordinates
  const coordinates =
    booking.site?.siteLocation?.coordinates?.coordinates ||
    property?.location?.coordinates?.coordinates;

  const googleMapsUrl =
    coordinates && coordinates.length === 2
      ? `https://www.google.com/maps/search/?api=1&query=${coordinates[1]},${coordinates[0]}`
      : null;

  // Booking times - prefer site booking settings, fallback to campsite or defaults
  const checkInTime =
    site?.bookingSettings?.checkInTime ||
    booking.campsite?.checkInTime ||
    '14:00';
  const checkOutTime =
    site?.bookingSettings?.checkOutTime ||
    booking.campsite?.checkOutTime ||
    '12:00';

  // Check if cancellable (only pending/confirmed bookings can be cancelled)
  const isCancellable =
    ['pending', 'confirmed'].includes(booking.status) && new Date(booking.checkIn) > new Date() &&
    booking.paymentStatus !== 'pending';

  // Calculate payment amounts
  const totalAmount = booking.pricing?.total || 0;
  const depositPercentage = booking.paymentMethod === 'deposit' ? 50 : 100;
  const depositAmount = booking.paymentMethod === 'deposit'
    ? Math.round(totalAmount * 0.5)
    : totalAmount;
  const remainingAmount = totalAmount - depositAmount;

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
    }).format(price);
  };

  const getPaidAmount = () => {
    if (booking.paymentStatus !== 'paid') return 0;
    return booking.paymentMethod === 'deposit'
      ? depositAmount
      : totalAmount;
  };

  const getRemainingAmount = () => {
    if (booking.paymentMethod !== 'deposit') return 0;
    return remainingAmount;
  };

  // Determine payment display text
  const getPaymentMethodText = () => {
    if (booking.paymentMethod === 'deposit') {
      return `Đặt cọc ${depositPercentage}%`;
    }
    return 'Thanh toán đầy đủ';
  };

  const getPaymentAmountToPay = () => {
    if (booking.paymentMethod === 'deposit') {
      return depositAmount;
    }
    return totalAmount;
  };

  return (
    <div className="min-h-screen bg-white">
      {/* Back Button */}
      <div className="absolute top-4 left-4 z-10 mt-20 flex gap-2 sm:left-6">
        <Button
          variant="outline"
          size="icon"
          className="h-10 w-10 rounded-full bg-white/90 hover:bg-white"
          onClick={() => router.back()}
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="h-10 w-10 rounded-full bg-white/90 hover:bg-white"
          onClick={() => router.push('/')}
        >
          <Home className="h-5 w-5" />
        </Button>
      </div>

      {/* Image Carousel */}
      <div className="relative h-[300px] w-full md:h-[450px]">
        <Carousel
          opts={{
            loop: true,
          }}
          className="h-full w-full"
        >
          <CarouselContent className="ml-0 h-full">
            {images.map((image, index) => (
              <CarouselItem key={index} className="h-full pl-1 md:basis-1/2">
                <div className="relative h-[300px] w-full md:h-[450px]">
                  <Image
                    src={image}
                    alt={`${siteName} - Ảnh ${index + 1}`}
                    fill
                    sizes="(max-width: 768px) 100vw, 50vw"
                    className="object-cover"
                    priority={index === 0}
                  />
                </div>
              </CarouselItem>
            ))}
          </CarouselContent>
          <CarouselPrevious className="left-4 h-10 w-10 bg-white/90 hover:bg-white" />
          <CarouselNext className="right-4 h-10 w-10 bg-white/90 hover:bg-white" />
        </Carousel>
      </div>

      {/* Main Content */}
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="grid gap-8 lg:grid-cols-3">
          {/* Left Column - Booking Info */}
          <div className="lg:col-span-2">
            {/* Status Badge & Booking ID */}
            <div className="mb-4 flex items-center gap-4">
              {getStatusBadge(booking.status)}
              <span className="text-muted-foreground text-sm">
                Mã xác nhận:{' '}
                {booking.code || `#${(booking.id || booking._id || '').slice(-7).toUpperCase()}`}
              </span>
            </div>

            {/* Payment Status Alert - Pending */}
            {booking.paymentStatus === 'pending' && booking.status !== 'cancelled' && (
              <Card className="mb-6 border-2 border-orange-300 bg-gradient-to-r from-orange-50 to-yellow-50">
                <CardContent className="pt-6">
                  <div className="flex flex-col gap-4 md:flex-row md:items-center">
                    <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-orange-500">
                      <AlertCircle className="h-6 w-6 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900">
                        {booking.paymentMethod === 'deposit'
                          ? `Chưa hoàn tất đặt cọc`
                          : 'Chưa hoàn tất thanh toán '}
                      </h3>
                      <div className="mt-2 flex flex-col gap-1 text-sm">
                        <p className="font-semibold text-gray-900">
                          💳 Cần thanh toán ngay:{' '}
                          <span className="text-lg text-orange-600">
                            {getPaymentAmountToPay().toLocaleString('vi-VN')} ₫
                          </span>
                        </p>
                        {booking.paymentMethod === 'deposit' && (
                          <h4 className="text-xs text-gray-600">
                            📅 Thanh toán khi nhận phòng:{' '}
                            <span className="font-medium">
                              {remainingAmount.toLocaleString('vi-VN')} ₫
                            </span>{' '}
                            ({100 - depositPercentage}%)
                          </h4>
                        )}
                      </div>
                    </div>
                    <Button
                      size="lg"
                      className="bg-orange-600 hover:bg-orange-700"
                      asChild
                    >
                      <a
                        href={booking.payOSCheckoutUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Thanh toán ngay
                      </a>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Payment Status Alert - Paid */}
            {booking.paymentStatus === 'paid' && booking.status !== 'cancelled' && booking.status !== 'refunded' && (
              <Card className="mb-6 border-2 border-green-300 bg-gradient-to-r from-green-50 to-emerald-50">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-4">
                    <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-green-500">
                      <CheckCircle className="h-6 w-6 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900">
                        Thanh toán thành công
                      </h3>
                      <p className="text-sm text-gray-600">
                        {booking.paymentMethod === 'deposit'
                          ? `Đã thanh toán cọc ${depositPercentage}% (${depositAmount.toLocaleString('vi-VN')} ₫)`
                          : `Đã thanh toán đầy đủ ${totalAmount.toLocaleString('vi-VN')} ₫`}
                      </p>
                      {booking.paymentMethod === 'deposit' && (
                        <>
                          <p className="mt-1 text-xs text-gray-600">
                            💰 Còn lại {remainingAmount.toLocaleString('vi-VN')} ₫
                            thanh toán khi nhận phòng
                          </p>
                          {/* <div className="mt-2 space-y-1 text-xs text-emerald-800 bg-emerald-100/50 p-2.5 rounded border border-emerald-200">
                            <p>ℹ️ <strong>Thông tin ví Host:</strong> Hệ thống đã chuyển tiền đặt cọc 50% ({depositAmount.toLocaleString('vi-VN')} ₫) vào ví của chủ nhà.</p>
                            {booking.hostNetAmount !== undefined && booking.hostNetAmount > 0 && (
                              <p>💰 <strong>Số tiền chuyển vào ví Host:</strong> {booking.hostNetAmount.toLocaleString('vi-VN')} ₫ (sau khi trừ phí hệ thống).</p>
                            )}
                          </div> */}
                        </>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Cancelled & Paid: Show Refund details input form */}
            {booking.status === 'cancelled' &&
              booking.paymentStatus === 'paid' &&
              !(booking.cancellInformation?.fullnameGuest && booking.cancellInformation?.bankCode && booking.cancellInformation?.bankType) &&
              !(booking.cannotAttendRequest?.bankAccountName && booking.cannotAttendRequest?.bankName && booking.cannotAttendRequest?.bankAccountNumber) && (
                <Card className="mb-6 border-2 border-red-300 bg-gradient-to-r from-red-50 to-orange-50">
                  <CardContent className="pt-6">
                    <div className="flex flex-col gap-4">
                      <div className="flex items-start gap-4">
                        <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-red-500">
                          <AlertCircle className="h-6 w-6 text-white" />
                        </div>
                        <div className="flex-1">
                          <h3 className="font-semibold text-red-900">
                            Đơn đặt chỗ đã bị hủy bởi Chủ trang trại / Hệ thống
                          </h3>
                          <p className="mt-1 text-sm text-gray-700 font-medium">
                            Lý do hủy: {booking.cancellationReason || "Yêu cầu từ phía chủ nhà hoặc hệ thống"}
                          </p>
                          <p className="mt-2 text-sm text-gray-600">
                            Vì bạn đã thanh toán thành công, vui lòng cung cấp thông tin tài khoản ngân hàng bên dưới để hệ thống thực hiện hoàn tiền 100% tự động cho bạn.
                          </p>
                        </div>
                      </div>

                      <Separator className="bg-red-200" />

                      <div className="space-y-4">
                        <h4 className="text-sm font-semibold text-gray-900">
                          Thông tin tài khoản nhận hoàn tiền (Hoàn 100%: {booking.pricing?.total.toLocaleString('vi-VN')} ₫)
                        </h4>

                        <div className="grid gap-4 sm:grid-cols-3">
                          <div className="space-y-1.5">
                            <label className="text-xs font-medium text-gray-700">Tên chủ tài khoản *</label>
                            <Input
                              placeholder="Nhập tên đầy đủ..."
                              value={refundBankDetails.fullnameGuest}
                              onChange={e => setRefundBankDetails({ ...refundBankDetails, fullnameGuest: e.target.value })}
                              className="h-9 text-xs"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-xs font-medium text-gray-700">Mã ngân hàng *</label>
                            <Input
                              placeholder="VD: Vietcombank, MB, TCB..."
                              value={refundBankDetails.bankCode}
                              onChange={e => setRefundBankDetails({ ...refundBankDetails, bankCode: e.target.value })}
                              className="h-9 text-xs"
                            />
                          </div>
                          <div className="space-y-1.5">
                            <label className="text-xs font-medium text-gray-700">Số tài khoản / Chi nhánh *</label>
                            <Input
                              placeholder="Nhập số tài khoản..."
                              value={refundBankDetails.bankType}
                              onChange={e => setRefundBankDetails({ ...refundBankDetails, bankType: e.target.value })}
                              className="h-9 text-xs"
                            />
                          </div>
                        </div>

                        <div className="flex justify-end pt-2">
                          <Button
                            onClick={handleSubmitRefundBankDetails}
                            disabled={submittingRefund}
                            className="bg-red-600 hover:bg-red-700 text-white"
                          >
                            {submittingRefund ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Đang gửi...
                              </>
                            ) : (
                              'Xác nhận nhận hoàn tiền 100%'
                            )}
                          </Button>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

            {/* Cancelled & Paid but already submitted: Show waiting for refund details */}
            {booking.status === 'cancelled' &&
              booking.paymentStatus === 'paid' &&
              ((booking.cancellInformation?.fullnameGuest && booking.cancellInformation?.bankCode && booking.cancellInformation?.bankType) ||
                (booking.cannotAttendRequest?.bankAccountName && booking.cannotAttendRequest?.bankName && booking.cannotAttendRequest?.bankAccountNumber)) && (
                <Card className="mb-6 border border-gray-200 bg-gray-50">
                  <CardContent className="pt-6">
                    <div className="flex items-center gap-4">
                      <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-gray-400">
                        <Clock className="h-6 w-6 text-white" />
                      </div>
                      <div className="flex-1">
                        <h3 className="font-semibold text-gray-900">
                          Đã ghi nhận thông tin nhận tiền hoàn
                        </h3>
                        <p className="text-sm text-gray-600">
                          Đơn đặt của bạn đã hủy. Chúng tôi đã nhận được thông tin hoàn tiền của bạn và đang tiến hành chuyển trả số tiền trong vòng 5-7 ngày làm việc.
                        </p>
                        <div className="mt-2 text-xs text-gray-500 bg-white p-3 rounded-lg border">
                          <p><strong>Người nhận:</strong> {booking.cancellInformation?.fullnameGuest || booking.cannotAttendRequest?.bankAccountName}</p>
                          <p><strong>Ngân hàng:</strong> {booking.cancellInformation?.bankCode || booking.cannotAttendRequest?.bankName}</p>
                          <p><strong>Số tài khoản:</strong> {booking.cancellInformation?.bankType || booking.cannotAttendRequest?.bankAccountNumber}</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

            {/* Refunded state */}
            {booking.status === 'refunded' && (
              <Card className="mb-6 border-2 border-blue-300 bg-gradient-to-r from-blue-50 to-indigo-50">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-4">
                    <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-blue-500">
                      <CheckCircle className="h-6 w-6 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-blue-900">
                        Đã hoàn tiền thành công
                      </h3>
                      <p className="text-sm text-gray-700">
                        Đơn hàng đã được hoàn trả thành công số tiền cọc/thanh toán: <strong>{(booking.refundAmount || booking.pricing?.total || 0).toLocaleString('vi-VN')} ₫</strong>.
                      </p>
                      {(booking.cancellInformation?.fullnameGuest || booking.cannotAttendRequest?.bankAccountName) && (
                        <div className="mt-2 text-xs text-gray-500 bg-white/70 p-3 rounded-lg border border-blue-100">
                          <p>
                            <strong>Tài khoản nhận:</strong>{' '}
                            {booking.cancellInformation?.fullnameGuest || booking.cannotAttendRequest?.bankAccountName} -{' '}
                            {booking.cancellInformation?.bankCode || booking.cannotAttendRequest?.bankName} ({booking.cancellInformation?.bankType || booking.cannotAttendRequest?.bankAccountNumber})
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Trip Title */}
            <h1 className="mb-6 text-2xl font-bold md:text-3xl">
              Chuyến đi sắp tới của bạn đến {siteName}
              {propertyName && (
                <span className="text-muted-foreground mt-2 block text-lg font-normal">
                  tại {propertyName}
                </span>
              )}
            </h1>

            {/* Action Buttons */}
            <div className="mb-8 flex flex-col gap-3 sm:flex-row">
              {/* View Site / Property Page */}
              <Button
                variant="outline"
                className="flex-1 border-gray-200 hover:bg-gray-50"
                onClick={() => {
                  router.push(`/land/${property?.slug || property?._id}`);
                }}
              >
                <MapPin className="mr-2 h-4 w-4" />
                Xem trang địa điểm
              </Button>

              {/* Nút Không thể đến - luôn hiển thị khi booking confirmed + paid */}
              {booking.status === 'confirmed' &&
                booking.paymentStatus === 'paid' &&
                !booking.cannotAttendRequest &&
                !booking.dissatisfactionRequest?.requestedAt && (
                  <Button
                    variant="outline"
                    className="flex-1 border-orange-300 text-orange-700 hover:bg-orange-50"
                    onClick={() => router.push(`/bookings/${bookingId}/cannot-attend`)}
                  >
                    <AlertCircle className="mr-2 h-4 w-4" />
                    Không thể đến (hoàn 50%)
                  </Button>
                )}

              {/* Nút Không hài lòng - chỉ hiển thị trong 12h sau check-in */}
              {booking.status === 'confirmed' &&
                booking.paymentStatus === 'paid' &&
                !booking.dissatisfactionRequest?.requestedAt &&
                (() => {
                  const now = new Date();
                  const checkIn = new Date(booking.checkIn);
                  const window12h = new Date(checkIn.getTime() + 12 * 60 * 60 * 1000);
                  return now >= checkIn && now <= window12h;
                })() && (
                  <Button
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white"
                    onClick={() => setIsDissatisfactionOpen(true)}
                  >
                    <AlertCircle className="mr-2 h-4 w-4" />
                    Không hài lòng
                  </Button>
                )}


              {/* Trạng thái đang chờ xét duyệt hoàn tiền */}
              {booking.dissatisfactionRequest?.status === 'pending' && (
                <div className="flex-1 rounded-lg border border-orange-200 bg-orange-50 p-3 text-center text-sm text-orange-800">
                  ⏳ Yêu cầu hoàn tiền không hài lòng đang chờ xét duyệt
                </div>
              )}

              {/* Show Complete Trip button for confirmed bookings after checkout */}
              {booking.status === 'confirmed' && booking.paymentStatus === "paid" &&
                (new Date(booking.checkIn) <= new Date() && new Date() <= new Date(new Date(booking.checkOut).getTime() + 3 * 24 * 60 * 60 * 1000)) &&
                (
                  <Button
                    className="flex-1 bg-blue-600 hover:bg-blue-700"
                    onClick={() => completeMutation.mutate()}
                    disabled={completeMutation.isPending}
                  >
                    {completeMutation.isPending ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Đang xử lý...
                      </>
                    ) : (
                      <>
                        <CheckCircle className="mr-2 h-4 w-4" />
                        Hoàn thành chuyến đi
                      </>
                    )}
                  </Button>
                )}
              {/* Show Review button for completed bookings without review */}
              {booking.status === 'completed' && !booking.reviewed && (
                <Button
                  className="flex-1 bg-yellow-600 hover:bg-yellow-700"
                  onClick={() => setIsReviewDialogOpen(true)}
                >
                  <Star className="mr-2 h-4 w-4" />
                  Đánh giá chuyến đi
                </Button>
              )}

              {isCancellable && (
                <Button
                  variant="outline"
                  className="flex-1 border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700"
                  onClick={() => setIsCancelDialogOpen(true)}
                  disabled={cancelMutation.isPending}
                >
                  <XCircle className="mr-2 h-4 w-4" />
                  Hủy đặt chỗ
                </Button>
              )}
            </div>

            {/* Trip Details */}
            <div className="space-y-6">
              <h2 className="text-xl font-semibold">Chi tiết chuyến đi</h2>

              {/* Trip Dates */}
              <div className="flex items-start gap-3">
                <Calendar className="text-muted-foreground mt-1 h-5 w-5" />
                <div>
                  <p className="font-medium">Ngày đi</p>
                  <p className="text-muted-foreground">
                    {format(new Date(booking.checkIn), 'EEEE, dd/MM', {
                      locale: vi,
                    })}{' '}
                    đến{' '}
                    {format(new Date(booking.checkOut), 'EEEE, dd/MM', {
                      locale: vi,
                    })}
                  </p>
                </div>
              </div>

              <Separator />

              {/* Check-in Time */}
              <div className="flex items-start gap-3">
                <Clock className="text-muted-foreground mt-1 h-5 w-5" />
                <div>
                  <p className="font-medium">Check-in</p>
                  <p className="text-muted-foreground">Sau {checkInTime}</p>
                </div>
              </div>

              <Separator />

              {/* Check-out Time */}
              <div className="flex items-start gap-3">
                <Clock className="text-muted-foreground mt-1 h-5 w-5" />
                <div>
                  <p className="font-medium">Check-out</p>
                  <p className="text-muted-foreground">Trước {checkOutTime}</p>
                </div>
              </div>

              <Separator />

              {/* Site/Location */}
              <div className="flex items-start gap-3">
                <MapPin className="text-muted-foreground mt-1 h-5 w-5" />
                <div className="space-y-1.5 flex-1">
                  <p className="font-medium">Địa điểm</p>
                  <p className="text-muted-foreground">
                    {[location?.address, location?.city, location?.state]
                      .filter(Boolean)
                      .join(', ') || 'Chưa cập nhật địa chỉ'}
                  </p>
                  {googleMapsUrl && (
                    <div className="mt-1.5">
                      <a
                        href={googleMapsUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-sm font-semibold text-emerald-600 hover:text-emerald-700 hover:underline cursor-pointer"
                      >
                        <MapPin className="h-3.5 w-3.5" />
                        Mở tọa độ chính xác trên Google Maps
                      </a>
                    </div>
                  )}
                  {location?.directions && (
                    <div className="text-sm bg-gray-50 p-2.5 rounded-lg border border-gray-150 mt-2">
                      <p className="font-semibold text-gray-800 mb-0.5">🚗 Chỉ đường:</p>
                      <p className="text-gray-600">{location.directions}</p>
                    </div>
                  )}
                  {location?.accessInstructions && (
                    <div className="text-sm bg-gray-50 p-2.5 rounded-lg border border-gray-150 mt-2">
                      <p className="font-semibold text-gray-800 mb-0.5">🔑 Hướng dẫn vào cổng:</p>
                      <p className="text-gray-600">{location.accessInstructions}</p>
                    </div>
                  )}
                  {location?.parkingInstructions && (
                    <div className="text-sm bg-gray-50 p-2.5 rounded-lg border border-gray-150 mt-2">
                      <p className="font-semibold text-gray-800 mb-0.5">🅿️ Hướng dẫn đỗ xe:</p>
                      <p className="text-gray-600">{location.parkingInstructions}</p>
                    </div>
                  )}
                </div>
              </div>

              <Separator />

              {/* Guests Info */}
              <div className="flex items-start gap-3">
                <Users className="text-muted-foreground mt-1 h-5 w-5" />
                <div>
                  <p className="font-medium">Khách</p>
                  <p className="text-muted-foreground">
                    {booking.numberOfGuests} người lớn
                    {booking.numberOfPets !== undefined && booking.numberOfPets > 0
                      ? `, ${booking.numberOfPets} thú cưng`
                      : null}
                    {booking.numberOfVehicles !== undefined && booking.numberOfVehicles > 0
                      ? `, ${booking.numberOfVehicles} xe`
                      : null}
                  </p>
                </div>
              </div>

              {booking.numberOfUnits !== undefined && booking.numberOfUnits > 0 && (
                <>
                  <Separator />
                  <div className="flex items-start gap-3">
                    <Home className="text-muted-foreground mt-1 h-5 w-5" />
                    <div>
                      <p className="font-medium">Số vị trí đặt (bãi cắm)</p>
                      <p className="text-muted-foreground">
                        {booking.numberOfUnits} vị trí
                      </p>
                    </div>
                  </div>
                </>
              )}

              {/* Guest Message */}
              {booking.guestMessage && (
                <>
                  <Separator />
                  <div>
                    <p className="mb-1 font-medium">Lời nhắn của bạn</p>
                    <p className="text-muted-foreground">
                      {booking.guestMessage}
                    </p>
                  </div>
                </>
              )}

              {/* Add selected services if any */}
              {booking.services && booking.services.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="mb-3 font-semibold flex items-center gap-2">
                      <Info className="h-4 w-4 text-emerald-600" />
                      Dịch vụ bổ sung đã chọn
                    </p>
                    <Card>
                      <CardContent className="p-4 divide-y divide-gray-100">
                        {booking.services.map((svc, idx) => (
                          <div key={idx} className="flex justify-between py-2.5 first:pt-0 last:pb-0">
                            <div>
                              <p className="font-medium text-sm text-gray-900">{svc.name}</p>
                              <p className="text-xs text-gray-500">
                                Đơn giá: {formatPrice(svc.price)} / {formatServiceUnit(svc.unit)}
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="text-sm font-semibold text-gray-900">
                                x{svc.quantity}
                              </p>
                              <p className="text-sm font-bold text-emerald-600">
                                {formatPrice(svc.price * svc.quantity)}
                              </p>
                            </div>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Right Column - Who's Going & Pricing Details */}
          <div className="lg:col-span-1 lg:sticky lg:top-24 space-y-6">
            <Card>
              <CardContent className="p-6">
                <div className="mb-4 flex items-center justify-between">
                  <h3 className="text-lg font-semibold">Ai sẽ đi</h3>
                  <span className="text-muted-foreground text-sm">
                    {booking.numberOfGuests}/{booking.numberOfGuests}
                  </span>
                </div>

                {/* Guest Avatar */}
                <div className="mb-4 flex items-center gap-3">
                  <Avatar className="h-12 w-12">
                    <AvatarImage
                      src={booking.guest?.avatarUrl || user?.avatarUrl}
                      alt={booking.guest?.username || user?.username || 'Bạn'}
                    />
                    <AvatarFallback>
                      {(booking.guest?.username || user?.username || 'U')
                        .charAt(0)
                        .toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <span className="font-medium">
                    {booking.guest?.username || user?.username || 'Bạn'}
                  </span>
                </div>

                <Button
                  variant="default"
                  className="w-full bg-emerald-500 hover:bg-emerald-600 mb-4"
                  onClick={() => router.push(`/u/${user?.username}`)}
                >
                  Xem hồ sơ
                </Button>

                <Separator className="my-4" />

                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <User className="h-4 w-4 text-gray-400" />
                    <div>
                      <p className="text-xs text-gray-500">Tên khách hàng</p>
                      <p className="text-sm font-medium">
                        {booking.fullnameGuest || booking.guest?.fullName || user?.fullName || booking.guest?.username || user?.username || 'Chưa cung cấp'}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <Mail className="h-4 w-4 text-gray-400" />
                    <div>
                      <p className="text-xs text-gray-500">Email</p>
                      <p className="text-sm font-medium">{booking.email || booking.guest?.email || user?.email}</p>
                    </div>
                  </div>

                  {(booking.phone || booking.guest?.phone || user?.phone) && (
                    <div className="flex items-center gap-3">
                      <Phone className="h-4 w-4 text-gray-400" />
                      <div>
                        <p className="text-xs text-gray-500">Số điện thoại</p>
                        <p className="text-sm font-medium">{booking.phone || booking.guest?.phone || user?.phone}</p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Pricing Details */}
            <Card>
              <CardContent className="p-6 space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Receipt className="h-5 w-5" />
                  Chi tiết thanh toán
                </h3>

                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600">
                      {formatPrice(booking.pricing?.basePrice || 0)} × {booking.pricing?.totalNights || booking.nights} đêm{' '}
                      {booking.site?.pricing?.rateType === 'person'
                        ? `× ${booking.numberOfGuests} khách`
                        : booking.numberOfUnits && booking.numberOfUnits > 1
                          ? `× ${booking.numberOfUnits} vị trí`
                          : ''}
                    </span>
                    <span className="font-medium">
                      {formatPrice(booking.pricing?.subtotal || 0)}
                    </span>
                  </div>

                  {booking.pricing?.cleaningFee !== undefined && booking.pricing.cleaningFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Phí vệ sinh</span>
                      <span className="font-medium">
                        {formatPrice(booking.pricing.cleaningFee)}
                      </span>
                    </div>
                  )}

                  {booking.pricing?.petFee !== undefined && booking.pricing.petFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">
                        Phí thú cưng ({booking.numberOfPets} con)
                      </span>
                      <span className="font-medium">
                        {formatPrice(booking.pricing.petFee)}
                      </span>
                    </div>
                  )}

                  {booking.pricing?.extraGuestFee !== undefined && booking.pricing.extraGuestFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Phí khách thêm</span>
                      <span className="font-medium">
                        {formatPrice(booking.pricing.extraGuestFee)}
                      </span>
                    </div>
                  )}

                  {booking.pricing?.servicesFee !== undefined && booking.pricing.servicesFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Phí dịch vụ bổ sung</span>
                      <span className="font-medium text-emerald-600">
                        {formatPrice(booking.pricing.servicesFee)}
                      </span>
                    </div>
                  )}

                  {booking.pricing?.serviceFee !== undefined && booking.pricing.serviceFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Phí dịch vụ</span>
                      <span className="font-medium">
                        {formatPrice(booking.pricing.serviceFee)}
                      </span>
                    </div>
                  )}

                  {booking.pricing?.tax !== undefined && booking.pricing.tax > 0 && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Thuế VAT</span>
                      <span className="font-medium">
                        {formatPrice(booking.pricing.tax)}
                      </span>
                    </div>
                  )}

                  {booking.pricing?.promoCode && booking.pricing.promoDiscount !== undefined && booking.pricing.promoDiscount > 0 && (
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
                      {formatPrice(booking.pricing?.total || 0)}
                    </span>
                  </div>

                  {/* Payment Details */}
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
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Cancel Booking Dialog */}
      <Dialog open={isCancelDialogOpen} onOpenChange={setIsCancelDialogOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-red-600" />
              Xác nhận hủy đặt chỗ
            </DialogTitle>
            <DialogDescription className="text-left">
              Bạn có chắc chắn muốn hủy đặt chỗ này? Hành động này không thể
              hoàn tác.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Booking Summary */}
            <div className="bg-muted/50 rounded-lg border p-4">
              <div className="mb-2 flex items-center justify-between">
                <span className="font-medium">
                  {siteName}
                  {propertyName && (
                    <span className="text-muted-foreground ml-1 text-sm">
                      - {propertyName}
                    </span>
                  )}
                </span>
              </div>
              <div className="text-muted-foreground text-sm">
                <p>
                  {format(new Date(booking.checkIn), 'dd/MM/yyyy', {
                    locale: vi,
                  })}{' '}
                  -{' '}
                  {format(new Date(booking.checkOut), 'dd/MM/yyyy', {
                    locale: vi,
                  })}
                </p>
                <p className="mt-1">
                  {booking.nights} đêm • {booking.numberOfGuests} khách
                </p>
                <p className="text-foreground mt-2 font-semibold">
                  Tổng: {booking.pricing?.total.toLocaleString('vi-VN')} ₫
                </p>
              </div>
            </div>

            {/* Cancellation Reason */}
            <div className="space-y-2">
              <label
                htmlFor="cancellation-reason"
                className="text-sm font-medium"
              >
                Lý do hủy <span className="text-red-500">*</span>
              </label>
              <Textarea
                id="cancellation-reason"
                placeholder="Vui lòng cho chúng tôi biết lý do bạn muốn hủy đặt chỗ này... (tối thiểu 10 ký tự)"
                value={cancellationReason}
                onChange={e => setCancellationReason(e.target.value)}
                className="min-h-[100px] resize-none"
                disabled={cancelMutation.isPending}
                maxLength={500}
              />
              <div className="flex items-center justify-between">
                <p className="text-muted-foreground text-xs">
                  Thông tin này giúp chúng tôi cải thiện dịch vụ
                </p>
                <p
                  className={`text-xs ${cancellationReason.length < 10
                    ? 'text-red-600'
                    : cancellationReason.length > 450
                      ? 'text-orange-600'
                      : 'text-muted-foreground'
                    }`}
                >
                  {cancellationReason.length}/500
                </p>
              </div>
            </div>



            {/* Refund Input Section */}
            <div className="space-y-3 rounded-lg border border-gray-200 bg-gray-50 p-4">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-900">
                <CreditCard className="h-4 w-4" />
                Thông tin tài khoản nhận hoàn tiền
              </h3>

              {/* Fullname */}
              <div className="space-y-1.5">
                <label
                  htmlFor="refund-fullname"
                  className="text-sm font-medium text-gray-700"
                >
                  Tên chủ tài khoản <span className="text-red-500">*</span>
                </label>
                <Input
                  id="refund-fullname"
                  placeholder="Nhập họ tên đầy đủ chủ tài khoản..."
                  value={cancellInformation.fullnameGuest}
                  onChange={e =>
                    setCancellInformation({
                      ...cancellInformation,
                      fullnameGuest: e.target.value,
                    })
                  }
                  disabled={cancelMutation.isPending}
                  maxLength={200}
                  className="w-full"
                />
              </div>

              {/* Bank Code */}
              <div className="space-y-1.5">
                <label
                  htmlFor="refund-bankcode"
                  className="text-sm font-medium text-gray-700"
                >
                  Mã ngân hàng <span className="text-red-500">*</span>
                </label>
                <Input
                  id="refund-bankcode"
                  placeholder="VD: VCB, ACB, TCB, MB, Vietcombank..."
                  value={cancellInformation.bankCode}
                  onChange={e =>
                    setCancellInformation({
                      ...cancellInformation,
                      bankCode: e.target.value,
                    })
                  }
                  disabled={cancelMutation.isPending}
                  maxLength={20}
                  className="w-full"
                />
                <p className="text-xs text-gray-500">
                  Nhập mã hoặc tên ngân hàng của bạn
                </p>
              </div>

              {/* Bank Type */}
              <div className="space-y-1.5">
                <label
                  htmlFor="refund-banktype"
                  className="text-sm font-medium text-gray-700"
                >
                  Số tài khoản / Phương thức{' '}
                  <span className="text-red-500">*</span>
                </label>
                <Input
                  id="refund-banktype"
                  placeholder="VD: 1234567890, Thẻ ATM, Tài khoản thanh toán..."
                  value={cancellInformation.bankType}
                  onChange={e =>
                    setCancellInformation({
                      ...cancellInformation,
                      bankType: e.target.value,
                    })
                  }
                  disabled={cancelMutation.isPending}
                  maxLength={100}
                  className="w-full"
                />
                <p className="text-xs text-gray-500">
                  Nhập số tài khoản hoặc loại tài khoản
                </p>
              </div>
            </div>

            {/* Refund Info */}
            <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
              <div className="flex items-start gap-2">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-blue-600" />
                <div className="flex-1">
                  <p className="mb-1 text-sm font-medium text-blue-900">
                    Lưu ý về hoàn tiền
                  </p>
                  <p className="text-xs leading-relaxed text-blue-800">
                    • Tiền sẽ được hoàn lại vào tài khoản của bạn trong vòng{' '}
                    <strong>5-7 ngày làm việc</strong>
                    <br />
                    • Vui lòng kiểm tra kỹ thông tin tài khoản trước khi xác
                    nhận
                    <br />• Số tiền hoàn phụ thuộc vào chính sách hủy và thời
                    điểm hủy
                  </p>
                </div>
              </div>
            </div>
          </div>

          <DialogFooter className="bottom-0 gap-2 border-t bg-white pt-4 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setIsCancelDialogOpen(false);
                setCancellationReason('');
                setCancellInformation({
                  fullnameGuest: '',
                  bankCode: '',
                  bankType: '',
                });
              }}
              disabled={cancelMutation.isPending}
            >
              Giữ đặt chỗ
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={handleCancelBooking}
              disabled={
                cancelMutation.isPending ||
                !cancellationReason.trim() ||
                cancellationReason.trim().length < 10 ||
                !cancellInformation.fullnameGuest.trim() ||
                !cancellInformation.bankCode.trim() ||
                !cancellInformation.bankType.trim()
              }
            >
              {cancelMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Đang xử lý...
                </>
              ) : (
                <>
                  <XCircle className="mr-2 h-4 w-4" />
                  Xác nhận hủy
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Review Dialog */}
      {booking.status === 'completed' &&
        !booking.reviewed &&
        (property?._id || property?.id) &&
        (site?._id || site?.id) && (
          <ReviewDialog
            open={isReviewDialogOpen}
            onOpenChange={setIsReviewDialogOpen}
            bookingId={booking.id || booking._id}
            bookingCode={booking.code}
            propertyId={property._id || property.id}
            siteId={site._id || site.id}
            propertyName={propertyName}
            siteName={siteName}
          />
        )}

      {/* Dissatisfaction Dialog */}
      <Dialog open={isDissatisfactionOpen} onOpenChange={setIsDissatisfactionOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-[640px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-700">
              {/* <AlertCircle className="h-5 w-5" /> */}
              Yêu cầu hoàn tiền - Không hài lòng
            </DialogTitle>
            <DialogDescription className="text-left">
              Áp dụng trong vòng 12 tiếng sau check-in. Nếu admin chấp nhận, bạn sẽ được hoàn{' '}
              <strong>100%</strong> số tiền đã thanh toán.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-2">
            {/* Lý do */}
            <div className="space-y-1.5">
              <label className="text-sm font-medium ">
                Lý do không hài lòng <span className="text-red-500">*</span>
              </label>
              <Textarea
                placeholder="Mô tả chi tiết vấn đề: cơ sở vật chất không đúng mô tả, hình ảnh sai thực tế... (tối thiểu 10 ký tự)"
                value={dissatisfactionForm.reason}
                onChange={e => setDissatisfactionForm(f => ({ ...f, reason: e.target.value }))}
                className="mt-3 min-h-[100px] resize-none"
                maxLength={2000}
              />
              <p className="text-xs text-gray-500">{dissatisfactionForm.reason.length}/2000</p>
            </div>

            {/* Thông tin liên hệ */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Số điện thoại <span className="text-red-500">*</span>
                </label>
                <Input
                  placeholder="0909 123 456"
                  value={dissatisfactionForm.phone}
                  onChange={e => setDissatisfactionForm(f => ({ ...f, phone: e.target.value }))}
                  maxLength={20}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Email <span className="text-red-500">*</span>
                </label>
                <Input
                  type="email"
                  placeholder="example@gmail.com"
                  value={dissatisfactionForm.email}
                  onChange={e => setDissatisfactionForm(f => ({ ...f, email: e.target.value }))}
                  maxLength={100}
                />
              </div>
            </div>

            {/* Thông tin ngân hàng */}
            <div className="rounded-lg border border-gray-200 bg-gray-50 p-4 space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <CreditCard className="h-4 w-4" />
                Thông tin tài khoản nhận hoàn tiền
              </h4>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Tên ngân hàng <span className="text-red-500">*</span>
                </label>
                <Input
                  placeholder="VD: Vietcombank, MB Bank, Techcombank..."
                  value={dissatisfactionForm.bankName}
                  onChange={e => setDissatisfactionForm(f => ({ ...f, bankName: e.target.value }))}
                  maxLength={100}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Tên chủ tài khoản <span className="text-red-500">*</span>
                </label>
                <Input
                  placeholder="Nguyễn Văn A (đúng như trên thẻ)"
                  value={dissatisfactionForm.bankAccountName}
                  onChange={e => setDissatisfactionForm(f => ({ ...f, bankAccountName: e.target.value }))}
                  maxLength={200}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">
                  Số tài khoản <span className="text-red-500">*</span>
                </label>
                <Input
                  placeholder="1234567890"
                  value={dissatisfactionForm.bankAccountNumber}
                  onChange={e => setDissatisfactionForm(f => ({ ...f, bankAccountNumber: e.target.value }))}
                  maxLength={50}
                />
              </div>
            </div>

            {/* Upload ảnh minh chứng */}
            <div className="space-y-2">
              <label className="text-sm font-medium">
                Ảnh minh chứng{' '}
                <span className="text-red-500">* (tối thiểu 5 ảnh)</span>
              </label>
              <input
                type="file"
                accept="image/*"
                multiple
                className="block w-full text-sm text-gray-700 file:mr-3 file:rounded-lg file:border-0 file:bg-red-50 file:px-4 file:py-2 file:text-sm file:font-medium file:text-red-700 hover:file:bg-red-100 cursor-pointer"
                onChange={e => {
                  const files = Array.from(e.target.files || []);
                  setDissatisfactionImages(prev => [...prev, ...files].slice(0, 20));
                }}
              />
              <p className={`text-xs ${dissatisfactionImages.length < 5 ? 'text-red-600' : 'text-green-600'
                }`}>
                {dissatisfactionImages.length} ảnh đã chọn{dissatisfactionImages.length < 5 && ` (cần thêm ${5 - dissatisfactionImages.length} ảnh)`}
              </p>
              {dissatisfactionImages.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {dissatisfactionImages.map((file, idx) => (
                    <div key={idx} className="relative group">
                      <img
                        src={URL.createObjectURL(file)}
                        alt={`preview-${idx}`}
                        className="h-16 w-16 rounded-lg object-cover border border-gray-200"
                      />
                      <button
                        onClick={() => setDissatisfactionImages(prev => prev.filter((_, i) => i !== idx))}
                        className="absolute -top-1 -right-1 hidden group-hover:flex h-5 w-5 items-center justify-center rounded-full bg-red-600 text-white text-xs"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800">
              <strong>Lưu ý:</strong> Admin sẽ xem xét yêu cầu và phản hồi qua email trong vòng 3-5 ngày làm việc. Nếu được chấp nhận, bạn sẽ được hoàn 100% số tiền đã thanh toán.
            </div>
          </div>

          <DialogFooter className="gap-2  pt-4">
            <Button
              variant="outline"
              onClick={() => setIsDissatisfactionOpen(false)}
              disabled={dissatisfactionMutation.isPending || uploadingImages}
            >
              Hủy
            </Button>
            <Button
              className="bg-red-600 hover:bg-red-700 text-white"
              onClick={handleDissatisfactionSubmit}
              disabled={
                dissatisfactionMutation.isPending ||
                uploadingImages ||
                dissatisfactionImages.length < 5 ||
                !dissatisfactionForm.reason ||
                !dissatisfactionForm.phone ||
                !dissatisfactionForm.email ||
                !dissatisfactionForm.bankName ||
                !dissatisfactionForm.bankAccountName ||
                !dissatisfactionForm.bankAccountNumber
              }
            >
              {(dissatisfactionMutation.isPending || uploadingImages) ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {uploadingImages ? 'Đang upload ảnh...' : 'Đang gửi...'}
                </>
              ) : (
                'Gửi yêu cầu hoàn tiền'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
