import { catchErrors } from "@/errors";
import type { SiteService } from "@/services/site.service";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import { createSiteSchema, searchSiteSchema, updateSiteSchema } from "@/validators/site.validator";

export default class SiteController {
  constructor(private readonly siteService: SiteService) { }

  /**
   * Create new site within a property (host/admin only)
   * @route POST /api/sites
   */
  createSite = catchErrors(async (req, res) => {
    const input = createSiteSchema.parse(req.body);
    const hostId = mongoIdSchema.parse(req.userId);

    const site = await this.siteService.createSite(hostId, input);

    return ResponseUtil.created(res, site, "Tạo site thành công");
  });

  /**
   * Search sites with filters
   * @route GET /api/sites
   */
  searchSites = catchErrors(async (req, res) => {
    const input = searchSiteSchema.parse(req.query);

    const { sites, pagination } = await this.siteService.searchSites(input);

    return ResponseUtil.paginated(
      res,
      sites,
      {
        page: pagination.page,
        limit: pagination.limit,
        total: pagination.total,
        totalPages: pagination.pages,
        hasNext: pagination.page < pagination.pages,
        hasPrev: pagination.page > 1,
      },
      "Tìm kiếm site thành công"
    );
  });

  /**
   * Get site by ID or slug
   * @route GET /api/sites/:idOrSlug
   */
  getSite = catchErrors(async (req, res) => {
    const { idOrSlug } = req.params;

    const site = await this.siteService.getSite(idOrSlug || "");

    return ResponseUtil.success(res, site, "Lấy thông tin site thành công");
  });

  /**
   * Get site with availability for date range
   * @route GET /api/sites/:idOrSlug/with-availability
   */
  getSiteWithAvailability = catchErrors(async (req, res) => {
    const { idOrSlug } = req.params;
    const { checkIn, checkOut } = req.query as { checkIn?: string; checkOut?: string };

    const site = await this.siteService.getSiteWithAvailability(idOrSlug || "", checkIn, checkOut);

    return ResponseUtil.success(res, site, "Lấy thông tin site và availability thành công");
  });

  /**
   * Update site (host/admin only)
   * @route PATCH /api/sites/:id
   */
  updateSite = catchErrors(async (req, res) => {
    const { id } = req.params;
    const input = updateSiteSchema.parse(req.body);
    const hostId = mongoIdSchema.parse(req.userId);

    const site = await this.siteService.updateSite(id || "", hostId, input);

    return ResponseUtil.success(res, site, "Cập nhật site thành công");
  });

  /**
   * Delete site (host/admin only)
   * @route DELETE /api/sites/:id
   */
  deleteSite = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    await this.siteService.deleteSite(id || "", hostId);

    return ResponseUtil.success(res, null, "Xóa site thành công");
  });

  /**
   * Activate site (host/admin only)
   * @route POST /api/sites/:id/activate
   */
  activateSite = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    const site = await this.siteService.activateSite(id || "", hostId);

    return ResponseUtil.success(res, site, "Kích hoạt site thành công");
  });

  /**
   * Deactivate site (host/admin only)
   * @route POST /api/sites/:id/deactivate
   */
  deactivateSite = catchErrors(async (req, res) => {
    const { id } = req.params;
    const hostId = mongoIdSchema.parse(req.userId);

    const site = await this.siteService.updateSite(id || "", hostId, {
      isActive: false,
    });

    return ResponseUtil.success(res, site, "Vô hiệu hóa site thành công");
  });

  /**
   * Get all sites for a property
   * @route GET /api/sites/property/:propertyId
   */
  getSitesByProperty = catchErrors(async (req, res) => {
    const { propertyId } = req.params;

    const sites = await this.siteService.getSitesByProperty(propertyId || "");

    return ResponseUtil.success(res, sites, "Lấy danh sách site của property thành công");
  });

  /**
   * Get blocked dates for calendar display
   * @route GET /api/sites/:id/blocked-dates
   */
  getBlockedDates = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { startDate, endDate } = req.query as { startDate: string; endDate: string };

    const result = await this.siteService.getBlockedDates(id || "", startDate, endDate);

    return ResponseUtil.success(res, result, "Lấy danh sách ngày bị block thành công");
  });

  /**
   * Check availability for site in date range
   * @route GET /api/sites/:id/availability
   */
  checkAvailability = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { checkIn, checkOut } = req.query as { checkIn: string; checkOut: string };

    const isAvailable = await this.siteService.checkAvailability(id || "", checkIn, checkOut);

    return ResponseUtil.success(res, { isAvailable }, "Kiểm tra lịch trống thành công");
  });

  getAvailableUnits = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { checkIn, checkOut } = req.query as { checkIn: string; checkOut: string };

    const result = await this.siteService.getAvailableUnits(id || "", checkIn, checkOut);

    return ResponseUtil.success(res, result, "Lấy danh sách lều/vị trí trống thành công");
  });

  /**
   * Calculate pricing for site in date range
   * @route GET /api/sites/:id/calculate-pricing
   */
  calculatePricing = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { checkIn, checkOut, guests } = req.query as {
      checkIn: string;
      checkOut: string;
      guests: string;
    };

    const pricing = await this.siteService.calculatePricing(
      id || "",
      checkIn,
      checkOut,
      parseInt(guests) || 1
    );

    return ResponseUtil.success(res, pricing, "Tính giá thành công");
  });

  /**
   * Block multiple dates for a site
   * @route POST /api/sites/:id/block-dates
   */
  blockSiteDates = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { dates, reason, slotsToBlock } = req.body as {
      dates: string[];
      reason?: string;
      slotsToBlock?: number;
    };
    const hostId = mongoIdSchema.parse(req.userId);

    await this.siteService.blockSiteDates(id || "", hostId, dates, reason, slotsToBlock);

    return ResponseUtil.success(res, null, "Chặn các ngày thành công");
  });

  /**
   * Unblock multiple dates for a site
   * @route DELETE /api/sites/:id/block-dates
   */
  unblockSiteDates = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { dates } = req.body as { dates: string[] };
    const hostId = mongoIdSchema.parse(req.userId);

    await this.siteService.unblockSiteDates(id || "", hostId, dates);

    return ResponseUtil.success(res, null, "Mở chặn các ngày thành công");
  });

  /**
   * Update seasonal pricing for a site
   * @route PUT /api/sites/:id/seasonal-pricing
   */
  updateSeasonalPricing = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { seasonalPricing } = req.body as {
      seasonalPricing: Array<{ name: string; startDate: string; endDate: string; price: number }>;
    };
    const hostId = mongoIdSchema.parse(req.userId);

    const site = await this.siteService.updateSeasonalPricing(id || "", hostId, seasonalPricing);

    return ResponseUtil.success(res, site, "Cập nhật giá mùa vụ thành công");
  });

  /**
   * Get availability calendar for host dashboard
   * @route GET /api/sites/:id/availability-calendar
   */
  getAvailabilityCalendar = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { month } = req.query as { month: string }; // e.g. "2026-06"
    const hostId = mongoIdSchema.parse(req.userId);

    const result = await this.siteService.getAvailabilityCalendar(id || "", hostId, month);

    return ResponseUtil.success(res, result, "Lấy lịch khả dụng thành công");
  });

  /**
   * Admin lock site (set to suspended)
   * @route POST /api/sites/:id/admin-lock
   */
  adminLockSite = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { reason, propertyName } = req.body;

    const site = await this.siteService.adminLockSite(id || "", reason || "Vi phạm quy định", propertyName);

    return ResponseUtil.success(res, site, "Đã khóa site thành công");
  });

  /**
   * Admin unlock site (set to active)
   * @route POST /api/sites/:id/admin-unlock
   */
  adminUnlockSite = catchErrors(async (req, res) => {
    const { id } = req.params;
    const { propertyName } = req.body;

    const site = await this.siteService.adminUnlockSite(id || "", propertyName);

    return ResponseUtil.success(res, site, "Đã mở khóa site thành công");
  });
}
