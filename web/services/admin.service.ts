/**
 * Admin Service
 * Admin-only endpoints: dashboard stats, orders management
 */
import apiClient from '@/lib/api-client';

export const getDashboardStats = async (type: string): Promise<ApiResponse> =>
  apiClient.get(`/dashboard/${type}`);

export const getAllOrders = async (): Promise<ApiResponse> =>
  apiClient.get('/orders');

export const updateOrderStatus = async (
  orderId: string,
  status: string,
): Promise<ApiResponse> =>
  apiClient.post(`/orders/${orderId}/update-status`, { status });

export const approveRefundRequest = async (
  orderId: string,
  note?: string,
): Promise<ApiResponse> =>
  apiClient.post(`/orders/${orderId}/approve-refund`, { note });

export const rejectRefundRequest = async (
  orderId: string,
  note?: string,
): Promise<ApiResponse> =>
  apiClient.post(`/orders/${orderId}/reject-refund`, { note });

export const adminCancelOrder = async (
  orderId: string,
  note?: string,
): Promise<ApiResponse> =>
  apiClient.post(`/orders/${orderId}/admin-cancel`, { note });

// ================== AMENITIES ==================
export async function getAllAmenities(): Promise<ApiResponse<Amenity[]>> {
  return apiClient.get('/amenities');
}

// ================== CATEGORIES ==================
export const getCategories = async (
  page = 1,
  limit = 10,
  search?: string,
): Promise<PaginatedResponse<unknown>> =>
  apiClient.get('/categories', { params: { page, limit, search } });

export const getAllCategories = async (): Promise<ApiResponse> =>
  apiClient.get('/categories/all');

export const getCategoryById = async (id: string): Promise<ApiResponse> =>
  apiClient.get(`/categories/get/${id}`);

export const createCategory = async (data: {
  name: string;
  isActive: boolean;
}): Promise<ApiResponse> => apiClient.post('/categories/create', data);

export const updateCategory = async (
  id: string,
  data: { name: string; isActive: boolean },
): Promise<ApiResponse> => apiClient.post(`/categories/update/${id}`, data);

export const deleteCategory = async (id: string): Promise<ApiResponse> =>
  apiClient.post(`/categories/delete/${id}`);

// ================== LOCATIONS ==================
export const createLocation = async (data: {
  name: string;
  isActive: boolean;
}): Promise<ApiResponse> => apiClient.post('/locations', data);

export const updateLocation = async (
  id: string,
  data: { name: string; isActive: boolean },
): Promise<ApiResponse> => apiClient.post(`/locations/update/${id}`, data);

export const getAllLocations = async (): Promise<ApiResponse> =>
  apiClient.get('/locations/all');

export const deleteLocation = async (id: string): Promise<ApiResponse> =>
  apiClient.post(`/locations/delete/${id}`);

// ================== RATINGS (admin) ==================
export const getAllRatings = async (): Promise<ApiResponse> =>
  apiClient.get('/rating/all');

export const adminReplyToRating = async (
  id: string,
  message: string,
): Promise<ApiResponse> =>
  apiClient.post(`/rating/admin/reply/${id}`, { message });

// ================== ADMIN PROPERTY/SITE MANAGEMENT ==================
/** Lấy danh sách properties + sites của 1 host (admin only) */
export async function getHostPropertiesWithSites(hostId: string): Promise<ApiResponse> {
  return apiClient.get(`/properties/host/${hostId}`);
}

/** Admin khóa property */
export async function adminLockProperty(id: string, reason: string): Promise<ApiResponse> {
  return apiClient.post(`/properties/${id}/admin-lock`, { reason });
}

/** Admin mở khóa property */
export async function adminUnlockProperty(id: string): Promise<ApiResponse> {
  return apiClient.post(`/properties/${id}/admin-unlock`);
}

/** Admin duyệt property đang pending_approval → active */
export async function adminApprovePropertyUpdate(id: string): Promise<ApiResponse> {
  return apiClient.post(`/properties/${id}/admin-approve`);
}

/** Admin khóa site */
export async function adminLockSite(id: string, reason: string, propertyName?: string): Promise<ApiResponse> {
  return apiClient.post(`/sites/${id}/admin-lock`, { reason, propertyName });
}

/** Admin mở khóa site */
export async function adminUnlockSite(id: string, propertyName?: string): Promise<ApiResponse> {
  return apiClient.post(`/sites/${id}/admin-unlock`, { propertyName });
}

// ================== SYSTEM SETTINGS ==================
export async function getSystemSettings(): Promise<ApiResponse<SystemSetting>> {
  return apiClient.get('/admin/settings');
}

export async function updateSystemSettings(data: any): Promise<ApiResponse<SystemSetting>> {
  return apiClient.put('/admin/settings', data);
}

export async function getPublicSettings(): Promise<ApiResponse<SystemSetting>> {
  return apiClient.get('/settings/public');
}

// ================== ADMIN PROMOTIONS ==================
export async function createAdminPromo(data: any): Promise<ApiResponse> {
  return apiClient.post('/admin/promotions', data);
}

export async function getAdminPromos(): Promise<ApiResponse> {
  return apiClient.get('/admin/promotions');
}

export async function updateAdminPromo(id: string, data: any): Promise<ApiResponse> {
  return apiClient.patch(`/admin/promotions/${id}`, data);
}

export async function deleteAdminPromo(id: string): Promise<ApiResponse> {
  return apiClient.delete(`/admin/promotions/${id}`);
}

