/**
 * Booking Service
 * All booking-related API calls
 */
import type { Booking } from '@/types/property-site';
import apiClient from '@/lib/api-client';

export async function createBooking(data: {
  site: string;
  property: string;
  campsite?: string;
  checkIn: string;
  checkOut: string;
  numberOfGuests: number;
  numberOfPets?: number;
  numberOfVehicles?: number;
  guestMessage?: string;
  paymentMethod: 'deposit' | 'full';
  fullnameGuest: string;
  phone?: string;
  email?: string;
  promoCodeId?: string;
  unitNumber?: string;
  numberOfUnits?: number;
  services?: Array<{
    name: string;
    price: number;
    unit: string;
    quantity: number;
  }>;
}): Promise<ApiResponse<Booking>> {
  return apiClient.post('/bookings', data);
}

export async function getBooking(id: string): Promise<ApiResponse<Booking>> {
  return apiClient.get(`/bookings/${id}`);
}

export async function getBookingByCode(code: string): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${code}/code`);
}

export async function getUserBookings(params?: {
  status?: 'pending' | 'confirmed' | 'cancelled' | 'completed' | 'refunded';
  role?: 'guest' | 'host';
  page?: number;
  limit?: number;
}): Promise<ApiResponse<Booking[]>> {
  return apiClient.get('/bookings', { params });
}

export async function getMyBookings(params?: {
  page?: number;
  limit?: number;
}): Promise<ApiResponse<Booking[]>> {
  return apiClient.get('/bookings/my/list', { params });
}

export async function confirmBooking(
  bookingId: string,
  hostMessage?: string,
): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${bookingId}/confirm`, { hostMessage });
}

export async function cancelBooking(
  bookingId: string,
  data: {
    cancellationReason: string;
    cancellInformation?: {
      fullnameGuest: string;
      bankCode: string;
      bankType: string;
    };
  },
): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${bookingId}/cancel`, data);
}

export async function completeBooking(bookingId: string): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${bookingId}/complete`);
}

export async function refundBooking(bookingId: string): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${bookingId}/refund`);
}

export async function requestDissatisfaction(
  bookingId: string,
  data: {
    reason: string;
    phone: string;
    email: string;
    bankAccountName: string;
    bankAccountNumber: string;
    bankName: string;
    evidenceImages: string[];
  },
): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${bookingId}/dissatisfaction`, data);
}

export async function guestConfirmArrival(bookingId: string): Promise<ApiResponse> {
  return apiClient.post(`/bookings/${bookingId}/confirm-arrival`);
}

export async function guestCannotAttend(
  bookingId: string,
  data: {
    reason: string;
    bankAccountName: string;
    bankAccountNumber: string;
    bankName: string;
    evidenceImages?: string[];
  },
): Promise<ApiResponse> {
  return apiClient.post(`/bookings/${bookingId}/cannot-attend`, data);
}

export async function userCancelPayment(bookingId: string): Promise<ApiResponse> {
  return apiClient.post(`/bookings/${bookingId}/cancel-payment`);
}

// ================== AVAILABILITY ==================
export async function getBlockedDates(
  siteId: string,
  startDate: string,
  endDate: string,
): Promise<ApiResponse<{ blockedDates: string[]; totalBlocked: number }>> {
  return apiClient.get(`/sites/${siteId}/blocked-dates`, {
    params: { startDate, endDate },
  });
}

export async function getSiteAvailability(
  siteId: string,
  checkIn?: string,
  checkOut?: string,
): Promise<ApiResponse<{ isAvailable: boolean; reason?: string; blockedDates?: string[] }>> {
  const params = checkIn && checkOut ? { checkIn, checkOut } : {};
  return apiClient.get(`/sites/${siteId}/availability`, { params });
}

// ================== ADMIN BOOKING ==================
export async function getAllBookings(
  page = 1,
  limit = 10,
  search?: string,
): Promise<PaginatedResponse<Booking>> {
  return apiClient.get('/booking', { params: { page, limit, search } });
}

export async function getBookingById(id: string): Promise<ApiResponse> {
  return apiClient.get(`/tour-bookings/${id}`);
}

export async function updateBooking(
  bookingId: string,
  data: any,
): Promise<ApiResponse<Booking>> {
  return apiClient.put(`/bookings/${bookingId}`, data);
}

export async function submitRefundBankDetails(
  bookingId: string,
  cancellInformation: {
    fullnameGuest: string;
    bankCode: string;
    bankType: string;
  },
): Promise<ApiResponse<Booking>> {
  return apiClient.post(`/bookings/${bookingId}/refund-bank-details`, { cancellInformation });
}
