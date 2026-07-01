export class BookingDTO {
  static toResponse(booking: any) {
    if (!booking) return null;
    return {
      id: booking._id || booking.id,
      code: booking.code,
      checkIn: booking.checkIn,
      checkOut: booking.checkOut,
      nights: booking.nights,
      numberOfGuests: booking.numberOfGuests,
      numberOfPets: booking.numberOfPets,
      numberOfVehicles: booking.numberOfVehicles,
      pricing: booking.pricing ? {
        basePrice: booking.pricing.basePrice,
        weekendPrice: booking.pricing.weekendPrice,
        weekdayNights: booking.pricing.weekdayNights,
        weekendNights: booking.pricing.weekendNights,
        subtotal: booking.pricing.subtotal,
        cleaningFee: booking.pricing.cleaningFee,
        petFee: booking.pricing.petFee,
        extraGuestFee: booking.pricing.extraGuestFee,
        total: booking.pricing.total,
      } : null,
      status: booking.status,
      paymentStatus: booking.paymentStatus,
      fullnameGuest: booking.fullnameGuest,
      phone: booking.phone,
      email: booking.email,
      guestMessage: booking.guestMessage,
      site: booking.site ? (typeof booking.site === 'object' && '_id' in booking.site ? {
        id: booking.site._id,
        name: booking.site.name,
        slug: booking.site.slug,
        photos: booking.site.photos,
        accommodationType: booking.site.accommodationType,
        pricing: booking.site.pricing,
        location: booking.site.location
      } : booking.site) : null,
      property: booking.property ? (typeof booking.property === 'object' && '_id' in booking.property ? {
        id: booking.property._id,
        name: booking.property.name,
        location: booking.property.location,
        photos: booking.property.photos,
        slug: booking.property.slug
      } : booking.property) : null,
      guest: booking.guest ? (typeof booking.guest === 'object' && '_id' in booking.guest ? {
        id: booking.guest._id,
        username: booking.guest.username,
        email: booking.guest.email,
        avatarUrl: booking.guest.avatarUrl
      } : booking.guest) : null,
      host: booking.host ? (typeof booking.host === 'object' && '_id' in booking.host ? {
        id: booking.host._id,
        username: booking.host.username,
        email: booking.host.email,
        avatarUrl: booking.host.avatarUrl
      } : booking.host) : null,
      payOSCheckoutUrl: booking.payOSCheckoutUrl,
      payOSOrderCode: booking.payOSOrderCode,
      paymentMethod: booking.paymentMethod,
      hostMessage: booking.hostMessage,
      cancelledBy: booking.cancelledBy,
      cancelledAt: booking.cancelledAt,
      cancellationReason: booking.cancellationReason,
      cancellInformation: booking.cancellInformation,
      refundAmount: booking.refundAmount,
      reviewed: booking.reviewed,
      review: booking.review,
      transactionId: booking.transactionId,
      paidAt: booking.paidAt,
      updatedAt: booking.updatedAt,
      createdAt: booking.createdAt,
    };
  }

  static toResponseList(bookings: any[]) {
    if (!bookings) return [];
    return bookings.map(b => this.toResponse(b));
  }
}
