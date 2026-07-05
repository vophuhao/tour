/**
 * Service Package Service
 * CRUD API calls for host service packages
 */
import apiClient from '@/lib/api-client';

export async function createServicePackage(data: {
  name: string;
  services: Array<{
    name: string;
    description?: string;
    pricing: Array<{ price: number; unit: string }>;
  }>;
}): Promise<ApiResponse> {
  return apiClient.post('/host/service-packages', data);
}

export async function getMyServicePackages(): Promise<ApiResponse> {
  return apiClient.get('/host/service-packages');
}

export async function updateServicePackage(
  id: string,
  data: {
    name?: string;
    services?: Array<{
      name: string;
      description?: string;
      pricing: Array<{ price: number; unit: string }>;
    }>;
  }
): Promise<ApiResponse> {
  return apiClient.patch(`/host/service-packages/${id}`, data);
}

export async function deleteServicePackage(id: string): Promise<ApiResponse> {
  return apiClient.delete(`/host/service-packages/${id}`);
}
