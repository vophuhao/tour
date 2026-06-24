import { catchErrors } from "@/errors";
import type { PropertyService } from "@/services/property.service";
import { ResponseUtil } from "../utils";
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
}
