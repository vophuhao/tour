/* eslint-disable react-hooks/set-state-in-effect */
'use client';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';
import { createBooking, getSiteById } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import {
  ArrowLeft,
  Car,
  CreditCard,
  Dog,
  Loader2,
  MapPin,
  Percent,
  Users,
} from 'lucide-react';
import Image from 'next/image';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

interface BookingSummaryData {
  siteId?: string;
  propertyId?: string;
  siteName?: string;
  propertyName?: string;
  campsiteId?: string;
  campsiteName?: string;
  location: string;
  image: string;
  checkIn: string;
  checkOut: string;
  basePrice: number;
  nights: number;
  cleaningFee: number;
  petFee: number;
  vehicleFee: number;
  additionalGuestFee: number;
  total: number;
  currency: string;
  guests: number;
  pets: number;
  vehicles: number;
  depositAmount: number;
}

interface SiteDetails {
  _id: string;
  name: string;
  pricing: {
    basePrice: number;
    cleaningFee?: number;
    petFee?: number;
    vehicleFee?: number;
    additionalGuestFee?: number;
    depositAmount?: number;
    weekendPrice?: number;
    currency: string;
  };
  capacity: {
    maxGuests: number;
    maxPets?: number;
    maxVehicles?: number;
  };
  photos: Array<{
    url: string;
    isCover: boolean;
  }>;
}

export default function PaymentPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user } = useAuthStore();

  // Parse booking data from URL params
  const initialBookingData: BookingSummaryData = {
    siteId: searchParams.get('siteId') || undefined,
    propertyId: searchParams.get('propertyId') || undefined,
    siteName: searchParams.get('name') || undefined,
    campsiteId: searchParams.get('campsiteId') || undefined,
    campsiteName: searchParams.get('name') || undefined,
    location: searchParams.get('location') || '',
    image: searchParams.get('image') || '',
    checkIn: searchParams.get('checkIn') || '',
    checkOut: searchParams.get('checkOut') || '',
    basePrice: Number(searchParams.get('basePrice')) || 0,
    nights: Number(searchParams.get('nights')) || 1,
    cleaningFee: Number(searchParams.get('cleaningFee')) || 0,
    petFee: Number(searchParams.get('petFee')) || 0,
    vehicleFee: Number(searchParams.get('vehicleFee')) || 0,
    additionalGuestFee: Number(searchParams.get('additionalGuestFee')) || 0,
    total: Number(searchParams.get('total')) || 0,
    currency: searchParams.get('currency') || 'VND',
    guests: Number(searchParams.get('guests')) || 1,
    pets: Number(searchParams.get('pets')) || 0,
    vehicles: Number(searchParams.get('vehicles')) || 1,
    depositAmount: Number(searchParams.get('depositAmount')) || 0,
  };

  const [bookingData, setBookingData] = useState(initialBookingData);

  // Sync booking data with URL params when they change (e.g., user clicks back and selects different site)
  useEffect(() => {
    const newBookingData: BookingSummaryData = {
      siteId: searchParams.get('siteId') || undefined,
      propertyId: searchParams.get('propertyId') || undefined,
      siteName: searchParams.get('name') || undefined,
      campsiteId: searchParams.get('campsiteId') || undefined,
      campsiteName: searchParams.get('name') || undefined,
      location: searchParams.get('location') || '',
      image: searchParams.get('image') || '',
      checkIn: searchParams.get('checkIn') || '',
      checkOut: searchParams.get('checkOut') || '',
      basePrice: Number(searchParams.get('basePrice')) || 0,
      nights: Number(searchParams.get('nights')) || 1,
      cleaningFee: Number(searchParams.get('cleaningFee')) || 0,
      petFee: Number(searchParams.get('petFee')) || 0,
      vehicleFee: Number(searchParams.get('vehicleFee')) || 0,
      additionalGuestFee: Number(searchParams.get('additionalGuestFee')) || 0,
      total: Number(searchParams.get('total')) || 0,
      currency: searchParams.get('currency') || 'VND',
      guests: Number(searchParams.get('guests')) || 1,
      pets: Number(searchParams.get('pets')) || 0,
      vehicles: Number(searchParams.get('vehicles')) || 1,
      depositAmount: Number(searchParams.get('depositAmount')) || 0,
    };
    setBookingData(newBookingData);
  }, [searchParams]);

  // Fetch site details if siteId exists
  const { data: siteDetails, isLoading: isSiteLoading } = useQuery({
    queryKey: ['site', bookingData.siteId],
    queryFn: () => getSiteById(bookingData.siteId!),
    enabled: !!bookingData.siteId,
  });

  // Update booking data when site details are loaded
  useEffect(() => {
    if (siteDetails) {
      setBookingData(prev => ({
        ...prev,
        basePrice: siteDetails.data.pricing.basePrice,
        cleaningFee: siteDetails.data.pricing.cleaningFee || 0,
        petFee: siteDetails.data.pricing.petFee || 0,
        vehicleFee: siteDetails.data.pricing.vehicleFee || 0,
        additionalGuestFee: siteDetails.data.pricing.additionalGuestFee || 0,
        depositAmount: siteDetails.data.pricing.depositAmount || 0,
        currency: siteDetails.data.pricing.currency,
      }));
    }
  }, [siteDetails]);

  const isPropertySiteBooking =
    !!bookingData.siteId && !!bookingData.propertyId;
  const displayName = isPropertySiteBooking
    ? bookingData.siteName
    : bookingData.campsiteName || 'Site Name';

  // Form state
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState(user?.email || '');
  const [phone, setPhone] = useState('');
  const [guestMessage, setGuestMessage] = useState('');
  const [paymentMethod, setPaymentMethod] = useState<'deposit' | 'full'>(
    'full',
  );

  // Calculate pricing with proper fees
  const nights = bookingData.nights;

  // Calculate price breakdown day-by-day (seasonal pricing > weekend pricing > base pricing)
  const {
    subtotal,
    weekdayNights,
    weekendNights,
    seasonalNights,
    seasonalDetails,
  } = useMemo(() => {
    const checkIn = bookingData.checkIn;
    const checkOut = bookingData.checkOut;
    const basePrice = bookingData.basePrice;
    const weekendPrice = siteDetails?.data?.pricing?.weekendPrice ?? basePrice;
    const seasonalPricing = siteDetails?.data?.pricing?.seasonalPricing ?? [];

    if (!checkIn || !checkOut) {
      return {
        subtotal: basePrice * nights,
        weekdayNights: nights,
        weekendNights: 0,
        seasonalNights: 0,
        seasonalDetails: [],
      };
    }

    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    let calculatedSubtotal = 0;
    let computedWeekdayNights = 0;
    let computedWeekendNights = 0;
    let computedSeasonalNights = 0;

    // Track seasonal price matches
    const seasonalMatchCounts: Record<string, { name: string; price: number; count: number }> = {};

    const currentDate = new Date(checkInDate);
    while (currentDate < checkOutDate) {
      const dayOfWeek = currentDate.getDay();
      const isWeekend = dayOfWeek === 5 || dayOfWeek === 6; // Friday & Saturday

      let nightPrice = basePrice;
      let isSeasonal = false;
      let matchedSeason: any = null;

      // Seasonal price has highest priority
      if (seasonalPricing && seasonalPricing.length > 0) {
        matchedSeason = seasonalPricing.find((season: any) => {
          const seasonStart = new Date(season.startDate);
          const seasonEnd = new Date(season.endDate);

          // Compare dates without time
          const currentZero = new Date(currentDate);
          currentZero.setHours(0, 0, 0, 0);
          const startZero = new Date(seasonStart);
          startZero.setHours(0, 0, 0, 0);
          const endZero = new Date(seasonEnd);
          endZero.setHours(0, 0, 0, 0);

          return currentZero >= startZero && currentZero <= endZero;
        });

        if (matchedSeason) {
          nightPrice = matchedSeason.price;
          isSeasonal = true;
        }
      }

      if (isSeasonal) {
        computedSeasonalNights++;
        const key = `${matchedSeason.name}_${matchedSeason.price}`;
        if (!seasonalMatchCounts[key]) {
          seasonalMatchCounts[key] = {
            name: matchedSeason.name,
            price: matchedSeason.price,
            count: 0,
          };
        }
        seasonalMatchCounts[key].count++;
      } else if (isWeekend && weekendPrice !== null && weekendPrice > 0 && weekendPrice !== basePrice) {
        nightPrice = weekendPrice;
        computedWeekendNights++;
      } else {
        computedWeekdayNights++;
      }

      calculatedSubtotal += nightPrice;
      currentDate.setDate(currentDate.getDate() + 1);
    }

    return {
      subtotal: calculatedSubtotal,
      weekdayNights: computedWeekdayNights,
      weekendNights: computedWeekendNights,
      seasonalNights: computedSeasonalNights,
      seasonalDetails: Object.values(seasonalMatchCounts),
    };
  }, [bookingData.checkIn, bookingData.checkOut, bookingData.basePrice, siteDetails, nights]);

  const weekendPrice = siteDetails?.data?.pricing?.weekendPrice ?? bookingData.basePrice;
  const hasDetailedPricing = weekendNights > 0 || seasonalNights > 0;

  // Calculate fees based on site pricing
  const totalCleaningFee = bookingData.cleaningFee || 0;
  const totalPetFee = (bookingData.petFee || 0) * bookingData.pets;
  const totalVehicleFee = (bookingData.vehicleFee || 0) * bookingData.vehicles;

  // Calculate additional guest fee (guests over base capacity)
  const baseGuestsIncluded = siteDetails?.data.capacity.maxGuests || 2;
  const additionalGuests = Math.max(0, bookingData.guests - baseGuestsIncluded);
  const totalAdditionalGuestFee =
    (bookingData.additionalGuestFee || 0) * additionalGuests;

  // Calculate total
  const total =
    subtotal +
    totalCleaningFee +
    totalPetFee +
    totalVehicleFee +
    totalAdditionalGuestFee;

  // FIX: Deposit calculation - calculate percentage from total
  const siteDepositAmount = bookingData.depositAmount || 0;

  // If depositAmount > 0, treat it as percentage, else default 30%
  const depositPercentage = siteDepositAmount > 0 ? siteDepositAmount : 30;

  // Calculate actual deposit amount based on total
  const depositAmount = Math.round(total * (depositPercentage / 100));
  const remainingAmount = total - depositAmount;

  // Deposit option is always available
  const hasDepositOption = true;

  const formatPrice = (price: number) =>
    new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: bookingData.currency,
    }).format(price);

  // Form validation
  const isFormValid =
    fullName.trim() &&
    email.trim() &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    phone.trim() &&
    /^[0-9]{10,11}$/.test(phone);

  // Booking mutation
  const bookingMutation = useMutation({
    mutationFn: async () => {
      if (!bookingData.siteId || !bookingData.propertyId) {
        throw new Error('Missing site or property ID');
      }

      return createBooking({
        site: bookingData.siteId,
        property: bookingData.propertyId,
        checkIn: bookingData.checkIn,
        checkOut: bookingData.checkOut,
        numberOfGuests: bookingData.guests,
        numberOfPets: bookingData.pets,
        numberOfVehicles: bookingData.vehicles,
        guestMessage: guestMessage || undefined,
        paymentMethod,
        fullnameGuest: fullName,
        phone,
        email,
      });
    },
    onSuccess: data => {
      const bookingId =
        (data?.data as { _id?: string; id?: string })?._id ||
        (data?.data as { _id?: string; id?: string })?.id;
      console.log('data', data);
      const responseData = data?.data as { payOSCheckoutUrl?: string };
      console.log('responseData', responseData);

      if (responseData?.payOSCheckoutUrl) {
        router.replace(responseData.payOSCheckoutUrl);
      }
    },
  });

  // Helper to extract meaningful error messages (Axios or Error)
  const extractErrorMessage = (err: unknown) => {
    if (!err) return 'Có lỗi xảy ra. Vui lòng thử lại.';
    // Try to safely inspect known shapes
    if (typeof err === 'object' && err !== null) {
      const obj = err as Record<string, unknown>;
      const response = obj['response'] as Record<string, unknown> | undefined;
      if (response && response['data']) {
        const data = response['data'] as Record<string, unknown> | string;
        if (typeof data === 'string') return data;
        if (typeof data === 'object' && data !== null) {
          const d = data as Record<string, unknown>;
          if (typeof d['message'] === 'string') return d['message'] as string;
          const errObj = d['error'] as Record<string, unknown> | undefined;
          if (errObj && typeof errObj['message'] === 'string')
            return errObj['message'] as string;
        }
      }
      if (typeof obj['message'] === 'string') return obj['message'] as string;
    }
    if (typeof err === 'string') return err;
    try {
      return JSON.stringify(err);
    } catch {
      return 'Có lỗi xảy ra. Vui lòng thử lại.';
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isFormValid) return;
    bookingMutation.mutate();
  };

  if (isSiteLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-600" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <Button
          variant="ghost"
          onClick={() => router.back()}
          className="mb-6 gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Quay lại
        </Button>

        <div className="grid gap-8 lg:grid-cols-3">
          {/* Left: Form Section */}
          <form onSubmit={handleSubmit} className="lg:col-span-2">
            <div className="space-y-6">
              {/* Guest Information */}
              <Card>
                <CardHeader>
                  <CardTitle>Thông tin khách hàng</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="fullName">
                      Họ và tên <span className="text-red-500">*</span>
                    </Label>
                    <Input
                      id="fullName"
                      placeholder="Nguyễn Văn A"
                      value={fullName}
                      onChange={e => setFullName(e.target.value)}
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="email">
                      Email <span className="text-red-500">*</span>
                    </Label>
                    <Input
                      id="email"
                      type="email"
                      placeholder="example@email.com"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="phone">
                      Số điện thoại <span className="text-red-500">*</span>
                    </Label>
                    <Input
                      id="phone"
                      type="tel"
                      placeholder="0912345678"
                      value={phone}
                      onChange={e => setPhone(e.target.value)}
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="message">Lời nhắn cho chủ nhà</Label>
                    <Textarea
                      id="message"
                      placeholder="Cho chủ nhà biết thêm về chuyến đi của bạn..."
                      value={guestMessage}
                      onChange={e => setGuestMessage(e.target.value)}
                      rows={4}
                      maxLength={1000}
                    />
                    <p className="text-muted-foreground text-xs">
                      {guestMessage.length}/1000 ký tự
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Payment Method */}
              <Card>
                <CardHeader>
                  <CardTitle>Phương thức thanh toán</CardTitle>
                </CardHeader>
                <CardContent>
                  <RadioGroup
                    value={paymentMethod}
                    onValueChange={(value: string) =>
                      setPaymentMethod(value as 'deposit' | 'full')
                    }
                  >
                    <div className="space-y-3">
                      {/* Full Payment */}
                      <label
                        htmlFor="full"
                        className={`hover:bg-accent flex cursor-pointer items-start space-x-3 rounded-lg border-2 p-4 transition ${paymentMethod === 'full'
                          ? 'border-emerald-600 bg-emerald-50'
                          : 'border-gray-200'
                          }`}
                      >
                        <RadioGroupItem
                          value="full"
                          id="full"
                          className="mt-1"
                        />
                        <div className="flex-1 space-y-1">
                          <div className="flex items-center gap-2">
                            <CreditCard className="h-5 w-5 text-emerald-600" />
                            <p className="font-semibold">Thanh toán đầy đủ</p>
                          </div>
                          <p className="text-muted-foreground text-sm">
                            Thanh toán toàn bộ {formatPrice(total)} ngay bây giờ
                          </p>
                          <div className="mt-2 rounded-md bg-emerald-100 px-3 py-2">
                            <p className="text-sm font-medium text-emerald-800">
                              💳 Số tiền thanh toán: {formatPrice(total)}
                            </p>
                          </div>
                        </div>
                      </label>

                      {/* Deposit Payment */}
                      {/* {hasDepositOption && (
                        <label
                          htmlFor="deposit"
                          className={`hover:bg-accent flex cursor-pointer items-start space-x-3 rounded-lg border-2 p-4 transition ${paymentMethod === 'deposit'
                              ? 'border-blue-600 bg-blue-50'
                              : 'border-gray-200'
                            }`}
                        >
                          <RadioGroupItem
                            value="deposit"
                            id="deposit"
                            className="mt-1"
                          />
                          <div className="flex-1 space-y-1">
                            <div className="flex items-center gap-2">
                              <Percent className="h-5 w-5 text-blue-600" />
                              <p className="font-semibold">
                                Đặt cọc {depositPercentage}%
                              </p>
                              <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700">
                                Phổ biến
                              </span>
                            </div>
                            <p className="text-muted-foreground text-sm">
                              Đặt cọc {depositPercentage}% (
                              {formatPrice(depositAmount)}), trả phần còn lại
                              khi nhận phòng
                            </p>
                            <div className="mt-2 space-y-1 rounded-md bg-blue-100 px-3 py-2">
                              <p className="text-sm font-medium text-blue-800">
                                💰 Đặt cọc ngay ({depositPercentage}%):{' '}
                                {formatPrice(depositAmount)}
                              </p>
                              <p className="text-xs text-blue-700">
                                📅 Trả khi nhận phòng ({100 - depositPercentage}
                                %): {formatPrice(remainingAmount)}
                              </p>
                            </div>
                          </div>
                        </label>
                      )} */}
                    </div>
                  </RadioGroup>

                  {/* Payment Info */}
                  <div className="mt-4 rounded-lg bg-gray-50 p-4">
                    <p className="text-xs text-gray-600">
                      ℹ️ Sau khi xác nhận, bạn sẽ được chuyển đến trang thanh
                      toán an toàn qua PayOS. Hỗ trợ các phương thức: Thẻ ATM,
                      Ví điện tử (MoMo, ZaloPay), QR Code.
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Error Message */}
              {bookingMutation.isError && (
                <Alert variant="destructive">
                  <AlertDescription>
                    {extractErrorMessage(bookingMutation.error)}
                  </AlertDescription>
                </Alert>
              )}

              {/* Submit Button */}
              <Button
                type="submit"
                size="lg"
                className="w-full"
                disabled={!isFormValid || bookingMutation.isPending}
              >
                {bookingMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Đang xử lý...
                  </>
                ) : (
                  `Xác nhận và thanh toán ${formatPrice(paymentMethod === 'deposit' ? depositAmount : total)}`
                )}
              </Button>
            </div>
          </form>

          {/* Right: Booking Summary */}
          <div className="lg:col-span-1">
            <Card className="sticky top-8 border-0">
              <CardHeader>
                <CardTitle>Chi tiết đặt chỗ</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Site Info */}
                <div className="flex gap-4">
                  {bookingData.image && (
                    <Image
                      src={bookingData.image}
                      alt={displayName || 'Site'}
                      width={80}
                      height={80}
                      className="h-20 w-20 rounded-lg object-cover"
                    />
                  )}
                  <div className="flex-1">
                    <h3 className="font-semibold">{displayName}</h3>
                    <p className="text-muted-foreground flex items-center gap-1 text-sm">
                      <MapPin className="h-3 w-3" />
                      {bookingData.location}
                    </p>
                    <p className="text-muted-foreground mt-1 text-xs">
                      {bookingData.nights} đêm • {bookingData.guests} khách
                      {bookingData.pets > 0 &&
                        ` • ${bookingData.pets} thú cưng`}
                      {bookingData.vehicles > 0 &&
                        ` • ${bookingData.vehicles} xe`}
                    </p>
                  </div>
                </div>

                <Separator />

                {/* Guest Details */}
                <div className="space-y-3">
                  <div className="flex items-start gap-3">
                    <Users className="text-muted-foreground mt-0.5 h-5 w-5" />
                    <div className="flex-1">
                      <p className="text-sm font-medium">Khách</p>
                      <p className="text-muted-foreground text-sm">
                        {bookingData.guests} người
                      </p>
                    </div>
                  </div>

                  {bookingData.pets > 0 && (
                    <div className="flex items-start gap-3">
                      <Dog className="text-muted-foreground mt-0.5 h-5 w-5" />
                      <div className="flex-1">
                        <p className="text-sm font-medium">Thú cưng</p>
                        <p className="text-muted-foreground text-sm">
                          {bookingData.pets} con
                        </p>
                      </div>
                    </div>
                  )}

                  {bookingData.vehicles > 0 && (
                    <div className="flex items-start gap-3">
                      <Car className="text-muted-foreground mt-0.5 h-5 w-5" />
                      <div className="flex-1">
                        <p className="text-sm font-medium">Phương tiện</p>
                        <p className="text-muted-foreground text-sm">
                          {bookingData.vehicles} xe
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                <Separator />

                {/* Price Breakdown */}
                <div className="space-y-2">
                  {/* Show pricing breakdown if applicable */}
                  {hasDetailedPricing ? (
                    <>
                      {weekdayNights > 0 && (
                        <div className="flex justify-between text-sm">
                          <span>
                            {formatPrice(bookingData.basePrice)} ×{' '}
                            {weekdayNights} đêm thường
                          </span>
                          <span>
                            {formatPrice(weekdayNights * bookingData.basePrice)}
                          </span>
                        </div>
                      )}
                      {weekendNights > 0 && (
                        <div className="flex justify-between text-sm">
                          <span className="flex items-center gap-1">
                            {formatPrice(weekendPrice)} × {weekendNights} đêm
                            cuối tuần
                            <span className="text-xs text-blue-600">
                              (Thứ 6, 7)
                            </span>
                          </span>
                          <span>
                            {formatPrice(weekendNights * weekendPrice)}
                          </span>
                        </div>
                      )}
                      {seasonalDetails.map((season) => (
                        <div key={season.name} className="flex justify-between text-sm">
                          <span className="flex items-center gap-1">
                            {formatPrice(season.price)} × {season.count} đêm{' '}
                            {season.name}
                            <span className="text-xs text-amber-600 font-medium">
                              (Mùa vụ)
                            </span>
                          </span>
                          <span>
                            {formatPrice(season.count * season.price)}
                          </span>
                        </div>
                      ))}
                      <div className="flex justify-between text-sm font-medium">
                        <span>Tổng tiền phòng</span>
                        <span>{formatPrice(subtotal)}</span>
                      </div>
                      <Separator className="my-1" />
                    </>
                  ) : (
                    <div className="flex justify-between text-sm">
                      <span>
                        {formatPrice(bookingData.basePrice)} × {nights} đêm
                      </span>
                      <span>{formatPrice(subtotal)}</span>
                    </div>
                  )}

                  {totalCleaningFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span>Phí vệ sinh</span>
                      <span>{formatPrice(totalCleaningFee)}</span>
                    </div>
                  )}

                  {totalPetFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span>Phí thú cưng ({bookingData.pets} con)</span>
                      <span>{formatPrice(totalPetFee)}</span>
                    </div>
                  )}

                  {totalVehicleFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span>Phí phương tiện ({bookingData.vehicles} xe)</span>
                      <span>{formatPrice(totalVehicleFee)}</span>
                    </div>
                  )}

                  {totalAdditionalGuestFee > 0 && (
                    <div className="flex justify-between text-sm">
                      <span>Phí khách thêm ({additionalGuests} người)</span>
                      <span>{formatPrice(totalAdditionalGuestFee)}</span>
                    </div>
                  )}

                  <Separator />

                  <div className="flex justify-between font-semibold">
                    <span>Tổng cộng</span>
                    <span>{formatPrice(total)}</span>
                  </div>

                  {/* Payment Summary */}
                  {paymentMethod === 'deposit' && hasDepositOption && (
                    <>
                      <Separator className="my-2" />
                      <div className="space-y-1 rounded-lg bg-blue-50 p-3">
                        <div className="flex justify-between text-sm font-medium text-blue-900">
                          <span>Thanh toán ngay ({depositPercentage}%)</span>
                          <span>{formatPrice(depositAmount)}</span>
                        </div>
                        <div className="flex justify-between text-xs text-blue-700">
                          <span>
                            Thanh toán khi nhận phòng ({100 - depositPercentage}
                            %)
                          </span>
                          <span>{formatPrice(remainingAmount)}</span>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
