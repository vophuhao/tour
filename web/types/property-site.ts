/* eslint-disable @typescript-eslint/no-explicit-any */
// ==================== PROPERTY-SITE ARCHITECTURE TYPES ====================

/**
 * Property Types
 * Represents land/facility where camping sites are located
 */

export type PropertyType =
  | 'private_land'
  | 'campground'
  | 'ranch'
  | 'farm'
  | 'retreat_center';

export type LodgingType =
  | 'bring_your_own'
  | 'structure_provided'
  | 'vehicle_provided';

export interface PropertyRule {
  category: 'pets' | 'noise' | 'fire' | 'vehicle' | 'general';
  text: string;
  description: string;
  isRequired: boolean;
  order?: number;
}

export interface ServicePricing {
  price: number;
  unit: string;
}

export interface Service {
  _id?: string;
  name: string;
  description?: string;
  pricing: ServicePricing[];
}

export interface ServicePackage {
  _id: string;
  name: string;
  host: string;
  services: Service[];
  createdAt: string;
  updatedAt: string;
}

export interface PropertyStats {
  totalSites: number;
  activeSites: number;
  totalBookings: number;
  totalReviews: number;
  averageRating: number;
  viewCount: number;
}

export interface PropertyRating {
  average: number;
  count: number;
  breakdown: {
    location: number;
    communication: number;
    value: number;
  };
}

// User type reference
interface User {
  _id: string;
  username: string;
  email: string;
  avatarUrl?: string;
  phoneNumber?: string;
  bio?: string;
}

// Amenity type reference
interface Amenity {
  _id: string;
  name: string;
  description?: string;
  icon?: string;
  category: string;
}

export interface Property {
  [x: string]: any;
  _id: string;
  host: string | User;
  name: string;
  slug: string;
  tagline: string;
  description: string;

  location: {
    address: string;
    city: string;
    state: string;
    country: string;
    zipCode?: string;
    coordinates: {
      type: 'Point';
      coordinates: [number, number]; // [lng, lat]
    };
    accessInstructions?: string;
    directions?: string;
    parkingInstructions?: string;
  };
  cancellationPolicy?: {
    type: 'flexible' | 'moderate' | 'strict';
    description?: string;
    refundRules?: Array<{
      daysBeforeCheckIn: number;
      refundPercentage: number;
    }>;
  };

  propertyType: PropertyType;
  lodgingType: LodgingType;

  landSize?: {
    value: number;
    unit: 'acres' | 'hectares' | 'square_meters';
  };
  minPrice?: number; // Minimum price from sites

  rules: PropertyRule[];

  petPolicy?: {
    allowed: boolean;
    maxPets?: number;
    restrictions?: string;
  };

  childrenPolicy?: {
    allowed: boolean;
    minAge?: number;
  };

  nearbyAttractions?: Array<{
    name: string;
    distance: number; // km
    type: string;
  }>;

  checkInInstructions?: string;
  checkOutInstructions?: string;

  photos: Array<{
    url: string;
    caption?: string;
    isCover: boolean;
    order: number;
    uploadedAt?: string;
  }>;

  stats: PropertyStats;
  rating?: PropertyRating;

  services?: Service[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

/**
 * Site Types
 * Represents individual camping spots within a property
 */

export type AccommodationType =
  | 'tent'
  | 'rv'
  | 'cabin'
  | 'yurt'
  | 'treehouse'
  | 'glamping'
  | 'vehicle';

export interface SiteCapacity {
  maxGuests: number;
  maxAdults?: number;
  maxChildren?: number;
  maxPets?: number;
  maxVehicles?: number;
  maxTents?: number;
  maxRVs?: number;
  rvMaxLength?: number; // feet

  // Concurrent Bookings (Hipcamp-style designated/undesignated)
  // 1 = designated (only 1 booking at a time)
  // 2+ = undesignated (multiple concurrent bookings, "X sites left")
  maxConcurrentBookings: number;
}

export interface SitePricing {
  basePrice: number;
  currency: string;
  weekendPrice?: number;
  weeklyDiscount?: number; // percentage
  monthlyDiscount?: number;
  additionalGuestFee?: number;
  petFee?: number;
  vehicleFee?: number;
  cleaningFee?: number;
  depositAmount?: number;
  seasonalPricing?: Array<{
    name: string;
    startDate: string;
    endDate: string;
    price: number;
  }>;
}

export interface SiteBookingSettings {
  minimumNights: number;
  maximumNights?: number;
  checkInTime: string;
  checkOutTime: string;
  instantBook: boolean;
  advanceNotice: number; // hours
  preparationTime?: number; // days between bookings
  allowSameDayBooking: boolean;
}

export interface SiteRating {
  average: number;
  count: number;
  breakdown: {
    cleanliness: number;
    accuracy: number;
    amenities: number;
  };
}

export interface Site {
  [x: string]: any;
  _id: string;
  property: string | Property;
  name: string;
  slug: string;
  description?: string;
  services?: Service[];

  accommodationType: AccommodationType;
  siteClass?: 'basic' | 'vip';
  lodgingProvided: 'bring_your_own' | 'structure_provided' | 'vehicle_provided';

  // Site-specific Location (matches backend siteLocation field)
  siteLocation?: {
    coordinates?: {
      type: 'Point';
      coordinates: [number, number]; // [lng, lat] - GeoJSON format
    };
    mapPinLabel?: string;
    relativeDescription?: string;
  };

  capacity: SiteCapacity;
  pricing: SitePricing;
  amenities: string[] | Amenity[]; // Array of Amenity IDs or populated Amenity objects
  bookingSettings: SiteBookingSettings;

  photos?: Array<{
    url: string;
    caption?: string;
    isCover: boolean;
    order: number;
    uploadedAt?: string;
  }>;
  included?: string[]; // For glamping: items/amenities included

  images: string[]; // Legacy field

  stats?: {
    totalBookings: number;
    totalReviews: number;
    averageRating: number;
    viewCount: number;
  };
  rating?: SiteRating;

  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

/**
 * Updated Booking Type
 * Now references both Property and Site
 * Matches backend BookingDocument interface
 */

export interface Booking {
  _id: string;
  code?: string; // Booking code (e.g., HDB05122546106)

  // References
  property: string | Property;
  site: string | Site;
  guest: string | User;
  host: string | User;

  // Booking Details
  checkIn: string;
  checkOut: string;
  nights: number;

  // Guest Info
  numberOfGuests: number;
  numberOfPets?: number;
  numberOfVehicles?: number;
  unitNumber?: string;

  // Pricing Breakdown (matches backend exactly)
  pricing: {
    basePrice: number; // Base price per night
    totalNights: number;
    subtotal: number; // basePrice * nights
    cleaningFee?: number;
    petFee?: number;
    extraGuestFee?: number;
    serviceFee: number; // Platform fee
    tax: number;
    total: number; // Final total
  };

  // Status
  status: 'pending' | 'confirmed' | 'cancelled' | 'completed' | 'refunded';

  // Payment
  paymentStatus?: 'pending' | 'paid' | 'refunded' | 'failed';
  paymentMethod?: 'card';
  transactionId?: string;
  paidAt?: string;
  payOSOrderCode?: number;
  payOSCheckoutUrl?: string;

  // Communication
  guestMessage?: string; // Guest's message/request
  hostMessage?: string; // Host's response

  // Cancellation
  cancelledBy?: string | User;
  cancelledAt?: string;
  cancellationReason?: string;
  refundAmount?: number;

  // Review
  reviewed?: boolean;
  review?: string | Review;

  // Timestamps
  createdAt: string;
  updatedAt: string;
}

/**
 * Updated Review Type
 * Now has split ratings for Property and Site
 */

export interface PropertyRatings {
  location: number; // 1-5: How good is the property location
  communication: number; // 1-5: How responsive is the host
  value: number; // 1-5: Is it worth the price
}

export interface SiteRatings {
  cleanliness: number; // 1-5: How clean is the site
  accuracy: number; // 1-5: Does it match the description
}

export interface Review {
  _id: string;
  booking: string | Booking;
  property: string | Property;
  site: string | Site;
  guest?: {
    _id: string;
    fullName: string;
    username?: string;
    email: string;
    avatar?: string;
    avatarUrl?: string;
  };
  user?: {
    _id: string;
    fullName: string;
    username?: string;
    email: string;
    avatar?: string;
    avatarUrl?: string;
  };

  propertyRatings: PropertyRatings;
  siteRatings: SiteRatings;
  ratings: {
    overall: number; // Calculated average of all 5 ratings
  };
  overallRating?: number; // Backend uses this field

  title?: string;
  comment: string;

  images?: string[];

  hostResponse?: {
    text: string;
    createdAt: string;
  };

  isPublished: boolean;

  helpfulCount: number;

  createdAt: string;
  updatedAt: string;
}

/**
 * Search & Filter Types
 */

export interface PropertySearchFilters {
  query?: string;
  propertyType?: PropertyType[];
  lodgingType?: LodgingType[];
  campingStyle?: string[]; // tent, rv, glamping - filters sites
  city?: string;
  checkIn?: string;
  checkOut?: string;
  guests?: number;
  pets?: number;
  minPrice?: number;
  maxPrice?: number;
  lat?: number;
  lng?: number;
  radius?: number; // miles
  amenities?: string[]; // Amenity IDs
  instantBook?: boolean;
  minRating?: number;
  sort?: string; // Frontend URL param - e.g., "minPrice-asc", "minPrice-desc", "rating", "newest"
  sortBy?: string; // Backend API param - maps from 'sort'
}

export interface SiteSearchFilters {
  query?: string;
  city?: string;
  propertyId?: string;
  accommodationType?: AccommodationType[];
  minPrice?: number;
  maxPrice?: number;
  checkIn?: string;
  checkOut?: string;
  guests?: number;
  pets?: number;
  vehicles?: number;
  amenities?: string[];
  instantBook?: boolean;
  minRating?: number;
  sortBy?:
    | 'newest'
    | 'oldest'
    | 'price-low'
    | 'price-high'
    | 'rating'
    | 'name'
    | 'capacity';
}

/**
 * API Response Types
 */

export interface PropertyListResponse {
  data?: any;
  properties: Property[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

export interface SiteListResponse {
  [x: string]: any;
  sites: Site[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

export interface PropertyWithSites extends Property {
  sites: Site[];
}

export interface PricingCalculation {
  basePrice: number;
  nights: number;
  subtotal: number;
  fees: {
    cleaning?: number;
    pet?: number;
    vehicle?: number;
    additionalGuest?: number;
  };
  serviceFee: number;
  tax: number;
  total: number;
  breakdown: Array<{
    date: string;
    price: number;
    isWeekend: boolean;
  }>;
}

export interface AvailabilityCheck {
  available: boolean;
  unavailableDates?: string[];
  spotsLeft?: number; // How many concurrent bookings still available
  reasons?: Array<{
    date: string;
    reason: 'booked' | 'blocked' | 'maintenance';
  }>;
}

export interface PropertyBlockedDates {
  _id: string;
  property: string | { _id: string; name: string };
  startDate: string;
  endDate: string;
  reason?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}
