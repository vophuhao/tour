import apiClient from '@/lib/api-client';

export async function createCombo(data: {
  name: string;
  description?: string;
  propertyId: string;
  applicableSites?: string[];
  servicesIncluded: Array<{ name: string; quantity: number }>;
  discountType: 'percentage' | 'fixed_price';
  discountValue: number;
  isActive?: boolean;
}): Promise<ApiResponse> {
  return apiClient.post('/host/combos', data);
}

export async function getMyCombos(propertyId?: string): Promise<ApiResponse<any[]>> {
  const url = propertyId ? `/properties/${propertyId}/combos` : '/host/combos';
  return apiClient.get(url);
}

export async function updateCombo(
  id: string,
  data: {
    name?: string;
    description?: string;
    applicableSites?: string[];
    servicesIncluded?: Array<{ name: string; quantity: number }>;
    discountType?: 'percentage' | 'fixed_price';
    discountValue?: number;
    isActive?: boolean;
  }
): Promise<ApiResponse> {
  return apiClient.patch(`/host/combos/${id}`, data);
}

export async function deleteCombo(id: string): Promise<ApiResponse> {
  return apiClient.delete(`/host/combos/${id}`);
}
