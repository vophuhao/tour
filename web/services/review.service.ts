/**
 * Review Service
 * Property and site reviews
 */
import apiClient from '@/lib/api-client';

export async function createReview(data: {
  booking: string;
  property: string;
  site: string;
  propertyRatings: {
    location: number;
    communication: number;
    value: number;
  };
  siteRatings: {
    cleanliness: number;
    accuracy: number;
  };
  comment: string;
}): Promise<ApiResponse> {
  return apiClient.post('/reviews', data);
}

export async function getPropertyReviews(
  propertyId: string,
  page = 1,
  limit = 10,
): Promise<PaginatedResponse<unknown>> {
  return apiClient.get(`/properties/${propertyId}/reviews`, {
    params: { page, limit },
  });
}

export async function getSiteReviews(
  siteId: string,
  page = 1,
  limit = 10,
): Promise<PaginatedResponse<unknown>> {
  return apiClient.get(`/sites/${siteId}/reviews`, {
    params: { page, limit },
  });
}

export async function addHostResponse(
  reviewId: string,
  comment: string,
): Promise<ApiResponse> {
  return apiClient.post(`/reviews/${reviewId}/response`, { comment });
}

export async function getMyCampsitesReview(): Promise<ApiResponse<Reviews[]>> {
  return apiClient.get('/reviews/my');
}

export async function updateReview(
  reviewId: string,
  data: {
    propertyRatings?: {
      location?: number;
      communication?: number;
      value?: number;
    };
    siteRatings?: {
      cleanliness?: number;
      accuracy?: number;
      amenities?: number;
    };
    title?: string;
    comment?: string;
    pros?: string[];
    cons?: string[];
    images?: string[];
  },
): Promise<ApiResponse> {
  return apiClient.patch(`/reviews/${reviewId}`, data);
}
