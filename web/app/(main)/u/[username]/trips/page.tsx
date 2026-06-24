'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { getUserBookings } from '@/lib/client-actions';
import { useAuthStore } from '@/store/auth.store';
import type { Property, Site } from '@/types/property-site';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';
import { CalendarDays, Loader2, MapPin, Tent } from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';
import { useParams } from 'next/navigation';

// Backend Booking type matching the populated response
interface BookingData {
  _id: string;
  code?: string;
  status: 'pending' | 'confirmed' | 'cancelled' | 'completed' | 'refunded';
  paymentStatus: 'pending' | 'paid' | 'refunded' | 'failed';
  checkIn: string;
  checkOut: string;
  numberOfGuests: number;
  numberOfPets?: number;
  numberOfVehicles?: number;
  extras?: string[];

  // New Property-Site architecture
  site?: Partial<Site> & {
    property?: Partial<Property>;
  };

  // Legacy campsite support (for backward compatibility)
  campsite?: {
    _id: string;
    name: string;
    slug?: string;
    images?: string[];
    location?: {
      city: string;
      state: string;
    };
    host?: {
      name: string;
    };
  };
}

export default function TripsPage() {
  const params = useParams();
  // Decode username to handle special characters and spaces
  const username = decodeURIComponent(params.username as string);
  const { user: currentUser } = useAuthStore();
  const isOwnProfile = currentUser?.username === username;

  const { data, isLoading } = useQuery({
    queryKey: ['user-bookings', username],
    queryFn: () => getUserBookings({ role: 'guest' }),
    enabled: isOwnProfile,
  });

  const bookings = (data?.data || []) as BookingData[];

  // Separate upcoming and past trips
  const now = new Date();
  const upcomingTrips = bookings.filter(
    b =>
      new Date(b.checkOut) >= now &&
      b.status !== 'cancelled' &&
      b.status !== 'completed' &&
      b.status !== 'refunded',
  );
  const pastTrips = bookings.filter(
    b => new Date(b.checkOut) < now || b.status === 'completed',
  );
  const cancelledTrips = bookings.filter(
    b => b.status === 'cancelled' || b.status === 'refunded',
  );

  const getStatusBadge = (status: BookingData['status']) => {
    const styles: Record<BookingData['status'], string> = {
      pending: 'bg-yellow-100 text-yellow-800',
      confirmed: 'bg-primary/10 text-primary',
      cancelled: 'bg-red-100 text-red-800',
      completed: 'bg-blue-100 text-blue-800',
      refunded: 'bg-gray-100 text-gray-800',
    };
    const labels: Record<BookingData['status'], string> = {
      pending: 'Chờ xác nhận',
      confirmed: 'Đã xác nhận',
      cancelled: 'Đã hủy',
      completed: 'Hoàn thành',
      refunded: 'Đã hoàn tiền',
    };
    return <Badge className={`${styles[status]}`}>{labels[status]}</Badge>;
  };

  const getPaymentStatusBadge = (status: BookingData['paymentStatus']) => {
    const styles: Record<BookingData['paymentStatus'], string> = {
      pending: 'bg-yellow-100 text-yellow-800',
      paid: 'bg-primary/10 text-primary',
      refunded: 'bg-gray-100 text-gray-800',
      failed: 'bg-red-100 text-red-800',
    };
    const labels: Record<BookingData['paymentStatus'], string> = {
      pending: 'Chưa thanh toán',
      paid: 'Đã thanh toán',
      refunded: 'Đã hoàn tiền',
      failed: 'Thanh toán thất bại',
    };
    return <Badge className={`${styles[status]}`}>{labels[status]}</Badge>;
  };

  if (!isOwnProfile) {
    return (
      <div className="py-12 text-center">
        <Tent className="text-muted-foreground mx-auto h-12 w-12" />
        <h2 className="mt-4 text-lg font-semibold">Chuyến đi riêng tư</h2>
        <p className="text-muted-foreground mt-2">
          Bạn không thể xem chuyến đi của người dùng khác
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
      </div>
    );
  }

  const TripCard = ({ booking }: { booking: BookingData }) => {
    // Support both new (site/property) and legacy (campsite) structure
    const property = booking.site?.property;

    // Get image: prefer site photos, fallback to campsite images
    const imageUrl =
      booking.site?.photos?.find(p => p.isCover)?.url ||
      booking.site?.photos?.[0]?.url ||
      booking.campsite?.images?.[0] ||
      '/placeholder-campsite.jpg';

    // Get name and location
    const siteName = booking.site?.name || booking.campsite?.name || 'Site';
    const propertyName = property?.name || booking.campsite?.host?.name || '';
    const city =
      property?.location?.city || booking.campsite?.location?.city || '';
    const state =
      property?.location?.state || booking.campsite?.location?.state || '';

    return (
      <Card className="overflow-hidden">
        {/* Trip Image */}
        <div className="relative h-48 w-full">
          <Image
            src={imageUrl}
            alt={siteName}
            fill
            sizes="(max-width: 768px) 100vw, 50vw"
            className="object-cover"
          />
        </div>
        <CardContent className="p-4">
          {/* Status Badge */}
          <div className="flex gap-2">
            <div className="mb-2">{getStatusBadge(booking.status)}</div>
            <div className="mb-2">
              {getPaymentStatusBadge(booking.paymentStatus)}
            </div>
          </div>

          {/* Site Name */}
          <h4 className="text-lg font-semibold line-clamp-2">
            {propertyName && `${propertyName}: `}
            {siteName}
          </h4>

          {/* Location */}
          {(city || state) && (
            <p className="text-muted-foreground mt-1 flex items-center gap-1 text-sm">
              <MapPin className="h-3 w-3" />
              {city}
              {city && state && ', '}
              {state}
            </p>
          )}

          {/* Dates */}
          <div className="text-muted-foreground mt-2 flex items-center gap-1 text-sm">
            <CalendarDays className="h-3 w-3" />
            {format(new Date(booking.checkIn), 'dd/MM', { locale: vi })} -{' '}
            {format(new Date(booking.checkOut), 'dd/MM/yyyy', { locale: vi })}
          </div>

          {/* Guests & Pets */}
          <p className="text-muted-foreground mt-2 text-sm">
            {booking.numberOfGuests} khách
            {booking.numberOfPets &&
              booking.numberOfPets > 0 &&
              ` · ${booking.numberOfPets} thú cưng`}
          </p>

          {/* Extras */}
          {booking.extras && booking.extras.length > 0 && (
            <p className="mt-2 text-sm">
              <span className="font-medium">Dịch vụ thêm:</span>{' '}
              {booking.extras.join(', ')}
            </p>
          )}

          {/* Trip Page Button */}
          <Button asChild variant="outline" className="mt-4 w-full">
            <Link href={`/bookings/${booking.code}/confirmation`}>
              Trang chuyến đi
            </Link>
          </Button>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="space-y-8">
      {/* Upcoming Trips */}
      <section>
        <h2 className="mb-4 text-xl font-semibold">Chuyến đi sắp tới</h2>
        {upcomingTrips.length > 0 ? (
          <div className="grid gap-6 md:grid-cols-3">
            {upcomingTrips.map(booking => (
              <TripCard key={booking._id} booking={booking} />
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="py-12 text-center">
              <Tent className="text-muted-foreground mx-auto h-12 w-12" />
              <h3 className="mt-4 font-semibold">Chưa có chuyến đi nào</h3>
              <p className="text-muted-foreground mt-2 text-sm">
                Khám phá các địa điểm cắm trại tuyệt vời và đặt chỗ ngay!
              </p>
              <Button
                asChild
                className="mt-4 bg-primary hover:bg-primary/90 cursor-pointer"
              >
                <Link href="/search">Khám phá ngay</Link>
              </Button>
            </CardContent>
          </Card>
        )}
      </section>

      {/* Past Trips */}
      {pastTrips.length > 0 && (
        <section>
          <Separator className="mb-6" />
          <h2 className="mb-4 text-xl font-semibold">Chuyến đi đã qua</h2>
          <div className="grid gap-6 md:grid-cols-3">
            {pastTrips.map(booking => (
              <TripCard key={booking._id} booking={booking} />
            ))}
          </div>
        </section>
      )}

      {/* Cancelled Trips */}
      {cancelledTrips.length > 0 && (
        <section>
          <Separator className="mb-6" />
          <h2 className="mb-4 text-xl font-semibold">Chuyến đi đã hủy</h2>
          <div className="grid gap-6 md:grid-cols-3">
            {cancelledTrips.map(booking => (
              <TripCard key={booking._id} booking={booking} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
