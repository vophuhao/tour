/**
 * Property & Site API Client
 *
 * This module provides API client functions for the new Property-Site architecture.
 *
 * Key Changes from Campsite:
 * - Properties represent land/facilities with shared amenities
 * - Sites represent individual camping spots with specific pricing
 * - Bookings now reference both property and site
 * - Reviews have split ratings (propertyRatings + siteRatings)
 */

import type {
  AvailabilityCheck,
  PricingCalculation,
  Property,
  PropertyListResponse,
  PropertySearchFilters,
  PropertyWithSites,
  Review,
  Site,
  SiteListResponse,
  SiteSearchFilters,
} from '@/types/property-site';
import apiClient from './api-client';

// ==================== PROPERTY ENDPOINTS ====================

/**
 * Search properties with optional filters
 * This is the main search function that accepts all filter parameters
 */
export async function searchProperties(
  filters?: PropertySearchFilters & { page?: number; limit?: number },
): Promise<PropertyListResponse> {
  const params = new URLSearchParams();

  // Location filters
  if (filters?.city) params.append('city', filters.city);
  if (filters?.query) params.append('query', filters.query);

  // Date filters
  if (filters?.checkIn) params.append('checkIn', filters.checkIn);
  if (filters?.checkOut) params.append('checkOut', filters.checkOut);

  // Capacity filters
  if (filters?.guests) params.append('guests', filters.guests.toString());
  if (filters?.pets) params.append('pets', filters.pets.toString());

  // Type filters - Using campingStyle instead of propertyType
  if (filters?.campingStyle) {
    const types = Array.isArray(filters.campingStyle)
      ? filters.campingStyle
      : [filters.campingStyle];
    params.append('campingStyle', types.join(','));
  }
  if (filters?.lodgingType) {
    const types = Array.isArray(filters.lodgingType)
      ? filters.lodgingType
      : [filters.lodgingType];
    params.append('lodgingType', types.join(','));
  }

  // Price filters
  if (filters?.minPrice) params.append('minPrice', filters.minPrice.toString());
  if (filters?.maxPrice) params.append('maxPrice', filters.maxPrice.toString());

  // Amenity filters
  if (filters?.amenities && filters.amenities.length > 0)
    params.append('amenities', filters.amenities.join(','));

  // Geolocation filters
  if (filters?.lat) params.append('lat', filters.lat.toString());
  if (filters?.lng) params.append('lng', filters.lng.toString());
  if (filters?.radius) params.append('radius', filters.radius.toString());

  // Other filters
  if (filters?.instantBook !== undefined)
    params.append('instantBook', filters.instantBook.toString());
  if (filters?.minRating)
    params.append('minRating', filters.minRating.toString());

  // Sorting - backend expects 'sortBy' parameter
  if (filters?.sort) params.append('sortBy', filters.sort);
  if (filters?.sortBy) params.append('sortBy', filters.sortBy);

  // Pagination
  if (filters?.page) params.append('page', filters.page.toString());
  if (filters?.limit) params.append('limit', filters.limit.toString());

  // Backend returns: { success, message, data: Property[], pagination: {...} }
  // We need to transform to: { properties: Property[], pagination: {...} }
  const response = (await apiClient.get(
    `/properties/search?${params.toString()}`,
  )) as any;

  return {
    data: response.data || [],
    properties: response.data || [],
    pagination: response.pagination || {
      page: 1,
      limit: 20,
      total: 0,
      totalPages: 0,
      hasNext: false,
      hasPrev: false,
    },
  };
}

/**
 * Get all properties (alias for searchProperties)
 */
export async function getAllProperties(
  filters?: PropertySearchFilters & { page?: number; limit?: number },
): Promise<PropertyListResponse> {
  return searchProperties(filters);
}

/**
 * Get featured properties
 */
export async function getFeaturedProperties(limit = 10): Promise<Property[]> {
  return apiClient.get(`/properties/featured?limit=${limit}`);
}

/**
 * Get nearby properties using geospatial search
 */
export async function getNearbyProperties(
  lat: number,
  lng: number,
  radius = 50, // miles
  filters?: Omit<PropertySearchFilters, 'location'> & {
    page?: number;
    limit?: number;
  },
): Promise<PropertyListResponse> {
  const params = new URLSearchParams({
    lat: lat.toString(),
    lng: lng.toString(),
    radius: radius.toString(),
  });

  if (filters?.propertyType)
    params.append('propertyType', filters.propertyType.join(','));
  if (filters?.lodgingType)
    params.append('lodgingType', filters.lodgingType.join(','));
  if (filters?.minPrice) params.append('minPrice', filters.minPrice.toString());
  if (filters?.maxPrice) params.append('maxPrice', filters.maxPrice.toString());
  if (filters?.amenities)
    params.append('amenities', filters.amenities.join(','));
  if (filters?.page) params.append('page', filters.page.toString());
  if (filters?.limit) params.append('limit', filters.limit.toString());

  return apiClient.get(`/properties/nearby?${params.toString()}`);
}

/**
 * Get property by ID
 */
export async function getPropertyById(id: string): Promise<Property> {
  return apiClient.get(`/properties/${id}`);
}

/**
 * Get property with all its sites
 */
export async function getPropertyWithSites(
  id: string,
): Promise<PropertyWithSites> {
  return apiClient.get(`/properties/${id}/with-sites`);
}

/**
 * Get property reviews
 */
export async function getPropertyReviews(
  id: string,
  page = 1,
  limit = 10,
): Promise<{
  reviews: Review[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}> {
  return apiClient.get(`/properties/${id}/reviews?page=${page}&limit=${limit}`);
}

/**
 * Get property review statistics
 */
export async function getPropertyReviewStats(id: string): Promise<{
  average: number;
  count: number;
  breakdown: {
    location: number;
    communication: number;
    value: number;
  };
}> {
  return apiClient.get(`/properties/${id}/stats`);
}

/**
 * Create a new property (host only)
 */
export async function createProperty(
  data: Partial<Property>,
): Promise<Property> {
  return apiClient.post('/properties', data);
}

/**
 * Update property (host only)
 */
export async function updateProperty(
  id: string,
  data: Partial<Property>,
): Promise<Property> {
  return apiClient.patch(`/properties/${id}`, data);
}

/**
 * Delete property (host only)
 */
export async function deleteProperty(id: string): Promise<ApiResponse> {
  return apiClient.delete(`/properties/${id}`);
}

/**
 * Activate property (host only)
 */
export async function activateProperty(id: string): Promise<Property> {
  return apiClient.post(`/properties/${id}/activate`);
}

/**
 * Deactivate property (host only)
 */
export async function deactivateProperty(id: string): Promise<Property> {
  return apiClient.post(`/properties/${id}/deactivate`);
}

/**
 * Get current user's properties (host only)
 */
export async function getMyProperties(
  page = 1,
  limit = 10,
): Promise<PropertyListResponse> {
  // return apiClient.get(`/properties/my-properties?page=${page}&limit=${limit}`);
  return apiClient.get(`/properties/my/list`);
}

/**
 * Get all properties for admin (admin only)
 */
export async function getPropertiesForAdmin(
  page = 1,
  limit = 100,
): Promise<ApiResponse<Property[]>> {
  return apiClient.get(`/properties?page=${page}&limit=${limit}`);
}

// ==================== SITE ENDPOINTS ====================

/**
 * Get available units (e.g. Tents 1-10) for a site in a date range
 */
export async function getAvailableUnits(
  siteId: string,
  checkIn: string,
  checkOut: string
): Promise<ApiResponse<{ availableUnits: Array<{ id: string; name: string }>; maxConcurrent: number }>> {
  return apiClient.get(`/sites/${siteId}/available-units?checkIn=${checkIn}&checkOut=${checkOut}`);
}

/**
 * Search sites with optional filters
 * This is the main search function that accepts all filter parameters
 */
export async function searchSites(
  filters?: SiteSearchFilters & { page?: number; limit?: number },
): Promise<SiteListResponse> {
  const params = new URLSearchParams();

  // Location/Property filters
  if (filters?.query) params.append('query', filters.query);
  if (filters?.propertyId) params.append('propertyId', filters.propertyId);
  if (filters?.city) params.append('city', filters.city);

  // Date filters
  if (filters?.checkIn) params.append('checkIn', filters.checkIn);
  if (filters?.checkOut) params.append('checkOut', filters.checkOut);

  // Capacity filters
  if (filters?.guests) params.append('guests', filters.guests.toString());
  if (filters?.pets) params.append('pets', filters.pets.toString());
  if (filters?.vehicles) params.append('vehicles', filters.vehicles.toString());

  // Type filters
  if (filters?.accommodationType) {
    const types = Array.isArray(filters.accommodationType)
      ? filters.accommodationType
      : [filters.accommodationType];
    params.append('accommodationType', types.join(','));
  }

  // Price filters
  if (filters?.minPrice) params.append('minPrice', filters.minPrice.toString());
  if (filters?.maxPrice) params.append('maxPrice', filters.maxPrice.toString());

  // Amenity filters
  if (filters?.amenities && filters.amenities.length > 0)
    params.append('amenities', filters.amenities.join(','));

  // Other filters
  if (filters?.instantBook !== undefined)
    params.append('instantBook', filters.instantBook.toString());
  if (filters?.minRating)
    params.append('minRating', filters.minRating.toString());

  // Sorting
  if (filters?.sortBy) params.append('sortBy', filters.sortBy);

  // Pagination
  if (filters?.page) params.append('page', filters.page.toString());
  if (filters?.limit) params.append('limit', filters.limit.toString());

  // Backend returns: { success, message, data: Site[], pagination: {...} }
  // We need to transform to: { sites: Site[], pagination: {...} }
  const response = (await apiClient.get(`/sites/search?${params.toString()}`)) as any;

  return {
    sites: response.data || [],
    pagination: response.pagination || {
      page: 1,
      limit: 20,
      total: 0,
      totalPages: 0,
      hasNext: false,
      hasPrev: false,
    },
  };
} /**
 * Get all sites (alias for searchSites)
 */
export async function getAllSites(
  filters?: SiteSearchFilters & { page?: number; limit?: number },
): Promise<SiteListResponse> {
  return searchSites(filters);
}

/**
 * Get sites by property ID
 */
export async function getSitesByProperty(
  propertyId: string,
  filters?: { page?: number; limit?: number },
): Promise<SiteListResponse> {
  const params = new URLSearchParams();
  if (filters?.page) params.append('page', filters.page.toString());
  if (filters?.limit) params.append('limit', filters.limit.toString());

  return apiClient.get(`/sites/property/${propertyId}?${params.toString()}`);
}

/**
 * Get site by ID
 */
export async function getSiteById(id: string): Promise<Site> {
  return apiClient.get(`/sites/${id}`);
}

/**
 * Get site reviews
 */
export async function getSiteReviews(
  id: string,
  page = 1,
  limit = 10,
): Promise<{
  reviews: Review[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}> {
  return apiClient.get(`/sites/${id}/reviews?page=${page}&limit=${limit}`);
}

/**
 * Check site availability
 */
export async function checkSiteAvailability(
  id: string,
  checkIn: string,
  checkOut: string,
): Promise<AvailabilityCheck> {
  return apiClient.get(
    `/sites/${id}/availability?checkIn=${checkIn}&checkOut=${checkOut}`,
  );
}

/**
 * Calculate site pricing for specific dates
 */
export async function calculateSitePricing(
  id: string,
  checkIn: string,
  checkOut: string,
  guests: number,
  pets = 0,
  vehicles = 0,
): Promise<PricingCalculation> {
  return apiClient.post(`/sites/${id}/calculate-pricing`, {
    checkIn,
    checkOut,
    guests,
    pets,
    vehicles,
  });
}

/**
 * Create a new site (host only)
 */
export async function createSite(data: Partial<Site>): Promise<Site> {
  return apiClient.post('/sites', data);
}

/**
 * Update site (host only)
 */
export async function updateSite(
  id: string,
  data: Partial<Site>,
): Promise<Site> {
  return apiClient.patch(`/sites/${id}`, data);
}

/**
 * Delete site (host only)
 */
export async function deleteSite(
  id: string,
  siteToDelete?: string,
): Promise<{ message: string }> {
  return apiClient.delete(`/sites/${id}`);
}

/**
 * Activate site (host only)
 */
export async function activateSite(id: string): Promise<Site> {
  return apiClient.post(`/sites/${id}/activate`);
}

/**
 * Deactivate site (host only)
 */
export async function deactivateSite(id: string): Promise<Site> {
  return apiClient.post(`/sites/${id}/deactivate`);
}


/**
 * Update seasonal pricing for a site (host only)
 */
export async function updateSeasonalPricing(
  siteId: string,
  seasonalPricing: Array<{ name: string; startDate: string; endDate: string; price: number }>,
): Promise<any> {
  return apiClient.put(`/sites/${siteId}/seasonal-pricing`, { seasonalPricing });
}

/**
 * Get availability calendar details for a site in a specific month (host only)
 */
export async function getAvailabilityCalendar(
  siteId: string,
  month: string,
): Promise<any> {
  return apiClient.get(`/sites/${siteId}/availability-calendar?month=${month}`);
}

// ==================== HELPER FUNCTIONS ====================

/**
 * Calculate overall rating from split ratings
 */
export function calculateOverallRating(
  propertyRatings: { location: number; communication: number; value: number },
  siteRatings: { cleanliness: number; accuracy: number; amenities: number },
): number {
  const allRatings = [
    propertyRatings.location,
    propertyRatings.communication,
    propertyRatings.value,
    siteRatings.cleanliness,
    siteRatings.accuracy,
    siteRatings.amenities,
  ];

  const average =
    allRatings.reduce((sum, rating) => sum + rating, 0) / allRatings.length;
  return Math.round(average * 10) / 10; // Round to 1 decimal
}

/**
 * Format property type for display
 */
export function formatPropertyType(type: string): string {
  const typeMap: Record<string, string> = {
    private_land: 'Private Land',
    campground: 'Campground',
    ranch: 'Ranch',
    farm: 'Farm',
    retreat_center: 'Retreat Center',
  };
  return typeMap[type] || type;
}

/**
 * Format lodging type for display
 */
export function formatLodgingType(type: string): string {
  const typeMap: Record<string, string> = {
    bring_your_own: 'Bring Your Own (Tent/RV)',
    structure_provided: 'Structure Provided (Cabin/Yurt)',
    vehicle_provided: 'Vehicle Provided (Camper/Van)',
  };
  return typeMap[type] || type;
}

/**
 * Format accommodation type for display
 */
export function formatAccommodationType(type: string): string {
  const typeMap: Record<string, string> = {
    tent: 'Tent Site',
    rv: 'RV Site',
    cabin: 'Cabin',
    yurt: 'Yurt',
    treehouse: 'Treehouse',
    glamping: 'Glamping',
    vehicle: 'Vehicle Camping',
  };
  return typeMap[type] || type;
}

// ==================== PERSONALIZED RECOMMENDATIONS ====================

/**
 * Get personalized property recommendations based on user's booking history
 * Requires authentication
 *
 * @param limit - Number of recommendations to return (default: 8)
 * @returns Array of recommended properties
 */
export async function getPersonalizedRecommendations(
  limit = 8,
): Promise<Property[]> {
  const response = await apiClient.get(
    `/properties/recommendations/list?limit=${limit}`,
  );
  return response.data || [];
}

// ==================== PROPERTY AVAILABILITY BLOCKING ====================

/**
 * Block dates for a property (host only)
 */
export async function blockPropertyDates(
  propertyId: string,
  startDate: string,
  endDate: string,
  reason?: string,
) {
  const response = await apiClient.post(
    `/properties/${propertyId}/block-dates`,
    {
      startDate,
      endDate,
      reason,
    },
  );
  return response.data;
}

/**
 * Unblock dates for a property (host only)
 */
export async function unblockPropertyDates(blockId: string) {
  const response = await apiClient.delete(
    `/properties/blocked-dates/${blockId}`,
  );
  return response.data;
}

/**
 * Get all blocked dates for a property
 */
export async function getPropertyBlockedDates(propertyId: string) {
  const response = await apiClient.get(
    `/properties/${propertyId}/blocked-dates`,
  );
  return response.data || [];
}

/**
 * Block dates for a site (host only)
 */
export async function blockSiteDates(
  siteId: string,
  dates: string[],
  reason?: string,
  slotsToBlock?: number,
) {
  const response = await apiClient.post(`/sites/${siteId}/block-dates`, {
    dates,
    reason,
    slotsToBlock,
  });
  return response.data;
}

/**
 * Unblock dates for a site (host only)
 */
export async function unblockSiteDates(siteId: string, dates: string[]) {
  const response = await apiClient.delete(`/sites/${siteId}/block-dates`, {
    data: { dates },
  });
  return response.data;
}

/**
 * Get properties for comparison
 */
export async function getCompareProperties(ids: string): Promise<any[]> {
  const response = await apiClient.get(`/properties/compare/list?ids=${ids}`) as any;
  return response.data || [];
}
