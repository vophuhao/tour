import { catchErrors, ErrorFactory } from "@/errors";
import type { PropertyService } from "@/services/property.service";
import { ResponseUtil, appAssert } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  createPropertySchema,
  searchPropertySchema,
  updatePropertySchema,
} from "@/validators/property.validator";
import { routeSearchSchema } from "@/validators/route-search.validator";

export default class PropertyController {
  constructor(private readonly propertyService: PropertyService) { }

  /**
   * Create new property (host/admin only)
   * @route POST /api/properties
   */
  createProperty = catchErrors(async (req, res) => {
    const input = createPropertySchema.parse(req.body);
    const hostId = mongoIdSchema.parse(req.userId);

    const property = await this.propertyService.createProperty(hostId, input);

    return ResponseUtil.created(res, property, "Tạo property thành công");
  });

  /**
   * Search properties with filters
   * @route GET /api/properties
   */
  searchProperties = catchErrors(async (req, res) => {
    const input = searchPropertySchema.parse(req.query);

    const { properties, pagination } = await this.propertyService.searchProperties(input);

    return ResponseUtil.paginated(
      res,
      properties,
      {
        page: pagination.page,
        limit: pagination.limit,
        total: pagination.total,
        totalPages: pagination.pages,
        hasNext: pagination.page < pagination.pages,
        hasPrev: pagination.page > 1,
      },
      "Tìm kiếm property thành công"
    );
  });

  /**
   * Search properties along a route
   * @route POST /api/properties/route-search
   */
  searchPropertiesAlongRoute = catchErrors(async (req, res) => {
    const input = routeSearchSchema.parse(req.body);

    const { properties, pagination } = await this.propertyService.searchPropertiesAlongRoute(input);

    return ResponseUtil.paginated(
      res,
      properties,
      {
        page: pagination.page,
        limit: pagination.limit,
        total: pagination.total,
        totalPages: pagination.pages,
        hasNext: pagination.page < pagination.pages,
        hasPrev: pagination.page > 1,
      },
      "Tìm kiếm địa điểm dọc lộ trình thành công"
    );
  });

  /**
   * Get property by ID or slug
   * @route GET /api/properties/:idOrSlug
   */
  getProperty = catchErrors(async (req, res) => {
    const { idOrSlug } = req.params;

    const property = await this.propertyService.getProperty(idOrSlug || "");

    return ResponseUtil.success(res, property, "Lấy thông tin property thành công");
  });

  /**
   * Get property with all sites
   * @route GET /api/properties/:idOrSlug/with-sites
   */
  getPropertyWithSites = catchErrors(async (req, res) => {
    const { idOrSlug } = req.params;

    const property = await this.propertyService.getPropertyWithSites(idOrSlug || "");

    return ResponseUtil.success(res, property, "Lấy thông tin property và sites thành công");
  });

  /**
   * Update property (host/admin only)
   * @route PATCH /api/properties/:id
   */
  updateProperty = catchErrors(async (req, res) => {
    const { id } = req.params;
    const input = updatePropertySchema.parse(req.body);
    const hostId = mongoIdSchema.parse(req.userId);

    const property = await this.propertyService.updateProperty(id || "", hostId, input);

    return ResponseUtil.success(res, property, "Cập nhật property thành công");
  });

  /**
   * Delete property (host/admin only)
   * @route DELETE /api/properties/:id
   */
  deleteProperty = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    await this.propertyService.deleteProperty(id || "", hostId);

    return ResponseUtil.success(res, null, "Xóa property thành công");
  });

  /**
   * Activate property (host/admin only)
   * Requires at least 1 active site
   * @route POST /api/properties/:id/activate
   */
  activateProperty = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    const property = await this.propertyService.activateProperty(id || "", hostId);

    return ResponseUtil.success(res, property, "Kích hoạt property thành công");
  });

  /**
   * Deactivate property (host/admin only)
   * @route POST /api/properties/:id/deactivate
   */
  deactivateProperty = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    const property = await this.propertyService.updateProperty(id || "", hostId, {
      isActive: false,
    });

    return ResponseUtil.success(res, property, "Vô hiệu hóa property thành công");
  });

  /**
   * Get my properties (host only)
   * @route GET /api/properties/my/list
   */
  getMyProperties = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);

    const properties = await this.propertyService.getPropertiesByHost(hostId);

    return ResponseUtil.success(res, properties, "Lấy danh sách property của bạn thành công");
  });

  /**
   * Get property stats (host/admin only)
   * @route GET /api/properties/:id/stats
   */
  getPropertyStats = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    const stats = await this.propertyService.getPropertyStats(id || "", hostId);

    return ResponseUtil.success(res, stats, "Lấy thống kê property thành công");
  });

  /**
   * Get featured properties
   * @route GET /api/properties/featured/list
   */
  getFeaturedProperties = catchErrors(async (req, res) => {
    const limit = parseInt(req.query.limit as string) || 10;

    const properties = await this.propertyService.getFeaturedProperties(limit);

    return ResponseUtil.success(res, properties, "Lấy danh sách property nổi bật thành công");
  });

  /**
   * Get nearby properties
   * @route GET /api/properties/nearby/:idOrSlug
   */
  getNearbyProperties = catchErrors(async (req, res) => {
    const { idOrSlug } = req.params;
    const maxDistance = parseInt(req.query.maxDistance as string) || 50000; // 50km default
    const limit = parseInt(req.query.limit as string) || 5;

    const properties = await this.propertyService.getNearbyProperties(
      idOrSlug || "",
      maxDistance,
      limit
    );

    return ResponseUtil.success(res, properties, "Lấy danh sách property gần đó thành công");
  });

  /**
   * Get personalized recommendations for logged-in user
   * @route GET /api/properties/recommendations
   */
  getRecommendations = catchErrors(async (req, res) => {
    const userId = mongoIdSchema.parse(req.userId);
    const limit = parseInt(req.query.limit as string) || 8;

    const recommendations = await this.propertyService.getPersonalizedRecommendations(
      userId,
      limit
    );

    return ResponseUtil.success(res, recommendations, "Lấy danh sách property gợi ý thành công");
  });

  /**
   * Block dates for property (host only)
   * @route POST /api/properties/:id/block-dates
   */
  blockPropertyDates = catchErrors(async (req, res) => {
    const id = mongoIdSchema.parse(req.params.id);
    const hostId = mongoIdSchema.parse(req.userId);
    const { startDate, endDate, reason } = req.body;

    const blocked = await this.propertyService.blockPropertyDates(
      id,
      hostId,
      new Date(startDate),
      new Date(endDate),
      reason
    );

    return ResponseUtil.created(res, blocked, "Block dates thành công");
  });

  /**
   * Unblock dates for property (host only)
   * @route DELETE /api/properties/blocked-dates/:blockId
   */
  unblockPropertyDates = catchErrors(async (req, res) => {
    const blockId = mongoIdSchema.parse(req.params.blockId);
    const hostId = mongoIdSchema.parse(req.userId);

    await this.propertyService.unblockPropertyDates(blockId, hostId);

    return ResponseUtil.success(res, null, "Unblock dates thành công");
  });

  /**
   * Get blocked dates for property
   * @route GET /api/properties/:id/blocked-dates
   */
  getPropertyBlockedDates = catchErrors(async (req, res) => {
    const id = mongoIdSchema.parse(req.params.id);

    const blockedDates = await this.propertyService.getPropertyBlockedDates(id);

    return ResponseUtil.success(res, blockedDates, "Lấy danh sách blocked dates thành công");
  });

  /**
   * Admin lock property (set to suspended)
   * @route POST /api/properties/:id/admin-lock
   */
  adminLockProperty = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;

    const property = await this.propertyService.adminLockProperty(id || "", reason || "Vi phạm quy định");

    return ResponseUtil.success(res, property, "Đã khóa property thành công");
  });

  /**
   * Admin unlock property (set to active)
   * @route POST /api/properties/:id/admin-unlock
   */
  adminUnlockProperty = catchErrors(async (req, res) => {
    const { id } = req.params;

    const property = await this.propertyService.adminUnlockProperty(id || "");

    return ResponseUtil.success(res, property, "Đã mở khóa property thành công");
  });

  /**
   * Admin approve property update (pending_approval → active)
   * @route POST /api/properties/:id/admin-approve
   */
  adminApproveProperty = catchErrors(async (req, res) => {
    const { id } = req.params;

    const property = await this.propertyService.adminApproveProperty(id || "");

    return ResponseUtil.success(res, property, "Đã duyệt và mở khóa property thành công");
  });

  /**
   * Get host properties with sites (for admin)
   * @route GET /api/properties/host/:hostId
   */
  getHostPropertiesWithSites = catchErrors(async (req, res) => {
    const { hostId } = req.params;

    const data = await this.propertyService.getHostPropertiesWithSites(hostId || "");

    return ResponseUtil.success(res, data, "Lấy danh sách property của host thành công");
  });

  /**
   * Compare multiple properties
   * @route GET /api/properties/compare/list
   */
  compareProperties = catchErrors(async (req, res) => {
    const idsString = req.query.ids as string | undefined;
    const ids = idsString ? idsString.split(",").map(id => id.trim()).filter(Boolean) : [];

    const data = await this.propertyService.compareProperties(ids);

    return ResponseUtil.success(res, data, "Lấy danh sách so sánh thành công");
  });

  /**
   * Get service availability and maximum remaining inventory for a date range
   * @route GET /api/properties/:id/services/availability
   */
  getPropertyServicesAvailability = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { checkIn, checkOut } = req.query;

    if (!id) {
      return res.status(400).json({ success: false, message: "id là bắt buộc" });
    }

    if (!checkIn || !checkOut) {
      return res.status(400).json({ success: false, message: "checkIn và checkOut là bắt buộc" });
    }

    const mongoose = await import("mongoose");
    const { PropertyModel, BookingModel, ServiceBlockModel } = await import("@/models");
    
    const isValidObjectId = mongoose.Types.ObjectId.isValid(id);
    const property = await PropertyModel.findOne({
      $or: [
        { _id: isValidObjectId ? new mongoose.Types.ObjectId(id) : null },
        { slug: id }
      ]
    });

    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    const checkInDate = new Date(checkIn as string);
    checkInDate.setHours(12, 0, 0, 0);
    const checkOutDate = new Date(checkOut as string);
    checkOutDate.setHours(10, 0, 0, 0);

    const services = property.services || [];
    const results = [];

    // Fetch overlapping bookings
    const overlappingBookings = await BookingModel.find({
      property: property._id,
      status: { $in: ["pending", "confirmed", "completed", "refund_requested"] },
      checkIn: { $lt: checkOutDate },
      checkOut: { $gt: checkInDate }
    }).select("checkIn checkOut services");

    // Fetch overlapping service blocks
    const overlappingBlocks = await ServiceBlockModel.find({
      property: property._id,
      checkIn: { $lt: checkOutDate },
      checkOut: { $gt: checkInDate }
    });

    for (const srv of services) {
      if (!srv.isInventoryTracked) {
        results.push({
          name: srv.name,
          description: srv.description || "",
          pricing: srv.pricing,
          isInventoryTracked: false,
          totalInventory: srv.totalInventory || 0,
          availableCount: 9999 // Unlimited
        });
        continue;
      }

      const totalInventory = srv.totalInventory || 0;
      let minAvailable = totalInventory;

      // Loop through each night in the range
      const startDate = new Date(checkInDate);
      const endDate = new Date(checkOutDate);

      while (startDate < endDate) {
        const nightStart = new Date(startDate);
        nightStart.setHours(12, 0, 0, 0);
        const nightEnd = new Date(startDate);
        nightEnd.setDate(nightEnd.getDate() + 1);
        nightEnd.setHours(10, 0, 0, 0);

        let bookedCountForNight = 0;

        for (const booking of overlappingBookings) {
          const bIn = new Date(booking.checkIn);
          const bOut = new Date(booking.checkOut);

          if (bIn < nightEnd && bOut > nightStart) {
            const bSrv = booking.services?.find(s => s.name === srv.name);
            if (bSrv) {
              bookedCountForNight += (bSrv.quantity || 1);
            }
          }
        }

        for (const block of overlappingBlocks) {
          if (block.serviceName === srv.name) {
            const blockIn = new Date(block.checkIn);
            const blockOut = new Date(block.checkOut);
            if (blockIn < nightEnd && blockOut > nightStart) {
              bookedCountForNight += block.quantity;
            }
          }
        }

        const availableForNight = Math.max(0, totalInventory - bookedCountForNight);
        if (availableForNight < minAvailable) {
          minAvailable = availableForNight;
        }

        startDate.setDate(startDate.getDate() + 1);
      }

      results.push({
        name: srv.name,
        description: srv.description || "",
        pricing: srv.pricing,
        isInventoryTracked: true,
        totalInventory,
        availableCount: minAvailable
      });
    }

    return ResponseUtil.success(res, results, "Lấy thông tin tồn kho dịch vụ thành công");
  });

  /**
   * Create service block
   * @route POST /api/properties/service-blocks
   */
  createServiceBlock = catchErrors(async (req, res) => {
    const { createServiceBlockSchema } = await import("@/validators/service-block.validator");
    const input = createServiceBlockSchema.parse(req.body);
    const hostId = mongoIdSchema.parse(req.userId);

    const { PropertyModel, ServiceBlockModel } = await import("@/models");

    // Verify ownership of the property
    const property = await PropertyModel.findById(input.propertyId);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền quản lý khu đất này")
    );

    // Verify service exists on property
    const serviceExists = property.services?.some(s => s.name === input.serviceName);
    appAssert(serviceExists, ErrorFactory.badRequest(`Dịch vụ "${input.serviceName}" không tồn tại ở khu đất này`));

    // Resolve date range
    const checkInDate = new Date(input.checkIn);
    const checkOutDate = new Date(input.checkOut);
    checkInDate.setHours(12, 0, 0, 0);
    checkOutDate.setHours(10, 0, 0, 0);

    // Save block
    const block = await ServiceBlockModel.create({
      property: input.propertyId,
      serviceName: input.serviceName,
      checkIn: checkInDate,
      checkOut: checkOutDate,
      quantity: input.quantity,
      note: input.note,
    });

    const notifyPropertyChange = (await import("../socket")).notifyPropertyChange;
    notifyPropertyChange(input.propertyId);

    return ResponseUtil.created(res, block, "Khóa tồn kho dịch vụ thành công");
  });

  /**
   * Get my service blocks
   * @route GET /api/properties/service-blocks/my
   */
  getMyServiceBlocks = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const { PropertyModel, ServiceBlockModel } = await import("@/models");

    // Fetch host's property IDs
    const myProperties = await PropertyModel.find({ host: hostId }).select("_id");
    const propIds = myProperties.map(p => p._id);

    // Fetch active blocks for these properties
    const blocks = await ServiceBlockModel.find({ property: { $in: propIds } })
      .populate("property", "name location")
      .sort({ createdAt: -1 });

    return ResponseUtil.success(res, blocks, "Lấy danh sách khóa kho thành công");
  });

  /**
   * Delete service block
   * @route DELETE /api/properties/service-blocks/:blockId
   */
  deleteServiceBlock = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const { blockId } = req.params;
    const { PropertyModel, ServiceBlockModel } = await import("@/models");

    const block = await ServiceBlockModel.findById(blockId);
    appAssert(block, ErrorFactory.resourceNotFound("ServiceBlock"));

    // Verify ownership
    const property = await PropertyModel.findById(block.property);
    appAssert(property, ErrorFactory.resourceNotFound("Property"));
    appAssert(
      property.host.toString() === hostId,
      ErrorFactory.forbidden("Bạn không có quyền quản lý khu đất này")
    );

    await ServiceBlockModel.findByIdAndDelete(blockId);

    const notifyPropertyChange = (await import("../socket")).notifyPropertyChange;
    notifyPropertyChange(block.property.toString());

    return ResponseUtil.success(res, null, "Xóa đợt khóa kho thành công");
  });

  /**
   * Get active promotions for a property (public endpoint)
   * @route GET /api/properties/:idOrSlug/promotions
   */
  getPropertyPromotions = catchErrors(async (req, res) => {
    const { idOrSlug } = req.params;
    const { PromoCodeModel } = await import("@/models");

    // Get property details (handles ID or slug)
    const property = await this.propertyService.getProperty(idOrSlug || "");
    const propertyId = property._id;
    
    // In case property.host is populated or is just an ObjectId
    const hostId = (property.host && typeof property.host === "object" && "_id" in property.host) 
      ? property.host._id 
      : property.host;

    const now = new Date();

    // Query active promotions
    const promotions = await PromoCodeModel.find({
      isActive: true,
      startDate: { $lte: now },
      endDate: { $gte: now },
      $or: [
        { scope: "global" },
        {
          scope: "host",
          $or: [
            { applicableProperties: propertyId },
            {
              $and: [
                {
                  $or: [
                    { applicableProperties: { $exists: false } },
                    { applicableProperties: { $size: 0 } }
                  ]
                },
                { host: hostId }
              ]
            }
          ]
        }
      ]
    }).sort({ createdAt: -1 });

    return ResponseUtil.success(res, promotions, "Lấy danh sách mã giảm giá thành công");
  });
}
