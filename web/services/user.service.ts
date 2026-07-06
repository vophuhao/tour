/**
 * User Service
 * All user-related API calls
 */
import apiClient from '@/lib/api-client';

export const getUser = async (): Promise<ApiResponse> =>
  apiClient.get('/users/me');

export const getAllUsers = async (): Promise<ApiResponse> =>
  apiClient.get('/users');

export const updateProfile = async (
  data: Partial<{ username: string; bio: string; avatar: string }>,
): Promise<ApiResponse> => apiClient.patch('/users/me', data);

export const getUserByUsername = async (
  username: string,
): Promise<ApiResponse> => apiClient.get(`/users/${username}`);

export const searchUsers = async (
  query: string,
  page = 1,
  limit = 20,
): Promise<ApiResponse> =>
  apiClient.get(`/users/search?q=${encodeURIComponent(query)}&page=${page}&limit=${limit}`);

export const getUserStats = async (
  username: string,
): Promise<ApiResponse<{ bookings: number; orders: number; reviews: number; saves?: number }>> =>
  apiClient.get(`/users/${username}/stats`);

export const getUserReviews = async (username: string): Promise<ApiResponse> =>
  apiClient.get(`/users/${username}/reviews`);

export const getSessions = async (): Promise<ApiResponse> =>
  apiClient.get('/sessions');

export const deleteSession = async (id: string): Promise<ApiResponse> =>
  apiClient.delete(`/sessions/${id}`);

export const getSuggestedUsers = async (): Promise<ApiResponse> =>
  apiClient.get('/users/suggestions');

export const blockedUser = async (id: string): Promise<ApiResponse> =>
  apiClient.post(`/users/block-user/${id}`);

export const becomeHost = async (data: unknown): Promise<ApiResponse> =>
  apiClient.post('/users/become-host', data);

export const verifyKycAndBecomeHost = async (data: {
  name: string;
  gmail: string;
  phone?: string;
  idNumber: string;
  faceMatchScore: number;
  selfieImage: string;
  idCardImage: string;
}): Promise<ApiResponse> => apiClient.post('/users/kyc-become-host', data);

export const getAllHostRequests = async (): Promise<ApiResponse> =>
  apiClient.get('/users/become-host');

export const updateHostRequestStatus = async (
  id: string,
  status: 'pending' | 'approved' | 'rejected',
): Promise<ApiResponse> =>
  apiClient.post(`/users/update-status-host/${id}`, { status });

export const getAllApprovedHosts = async (): Promise<ApiResponse> =>
  apiClient.get('/users/hosts');

export const getUserPublicStats = async (userId: string): Promise<any> =>
  apiClient.get(`/users/${userId}/public-stats`);

export const getLevelConfigs = async (): Promise<any> =>
  apiClient.get('/users/levels/config');

export const getUserFollowers = async (userId: string): Promise<any> =>
  apiClient.get(`/users/${userId}/followers`);

export const followUser = async (userId: string): Promise<any> =>
  apiClient.post(`/users/${userId}/follow`);

export const unfollowUser = async (userId: string): Promise<any> =>
  apiClient.delete(`/users/${userId}/follow`);
