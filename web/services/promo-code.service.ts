import apiClient from '@/lib/api-client';

export async function createPromoCode(data: {
  code: string;
  description?: string;
  discountType: 'percentage' | 'flat';
  discountValue: number;
  maxDiscountAmount?: number;
  minSubtotal?: number;
  applicableProperties?: string[];
  startDate: string | Date;
  endDate: string | Date;
  usageLimit?: number;
  isActive?: boolean;
}): Promise<ApiResponse> {
  return apiClient.post('/host/promotions', data);
}

export async function getMyPromoCodes(): Promise<ApiResponse> {
  return apiClient.get('/host/promotions');
}

export async function updatePromoCode(
  id: string,
  data: {
    description?: string;
    discountType?: 'percentage' | 'flat';
    discountValue?: number;
    maxDiscountAmount?: number;
    minSubtotal?: number;
    applicableProperties?: string[];
    startDate?: string | Date;
    endDate?: string | Date;
    usageLimit?: number;
    isActive?: boolean;
  }
): Promise<ApiResponse> {
  return apiClient.patch(`/host/promotions/${id}`, data);
}

export async function deletePromoCode(id: string): Promise<ApiResponse> {
  return apiClient.delete(`/host/promotions/${id}`);
}

export async function validatePromoCode(data: {
  code: string;
  propertyId: string;
  subtotal: number;
}): Promise<ApiResponse> {
  return apiClient.post('/bookings/validate-promo', data);
}
