import { catchErrors, ErrorFactory } from "@/errors";
import { ComboModel, PropertyModel } from "@/models";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  createComboSchema,
  updateComboSchema,
} from "@/validators/combo.validator";
import appAssert from "../utils/app-assert";
import { Types } from "mongoose";

export default class ComboController {
  /**
   * Create a new combo package
   * @route POST /api/host/combos
   */
  createCombo = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const data = createComboSchema.parse(req.body);

    // Verify property ownership
    const property = await PropertyModel.findOne({ _id: data.propertyId, host: hostId });
    appAssert(property, ErrorFactory.resourceNotFound("Khu cắm trại không tồn tại hoặc bạn không có quyền"));

    const combo = await ComboModel.create(data);

    return ResponseUtil.created(res, combo, "Tạo gói combo thành công");
  });

  /**
   * Get all combos of host properties
   * @route GET /api/host/combos
   */
  getMyCombos = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const { propertyId } = req.query;

    let query: any = {};
    if (propertyId) {
      const propId = mongoIdSchema.parse(propertyId);
      const property = await PropertyModel.findOne({ _id: propId, host: hostId });
      appAssert(property, ErrorFactory.resourceNotFound("Khu cắm trại không tồn tại hoặc bạn không có quyền"));
      query.propertyId = propId;
    } else {
      const myProperties = await PropertyModel.find({ host: hostId }, "_id");
      const myPropertyIds = myProperties.map(p => p._id);
      query.propertyId = { $in: myPropertyIds };
    }

    const combos = await ComboModel.find(query)
      .populate("applicableSites", "name siteClass")
      .sort({ createdAt: -1 });

    return ResponseUtil.success(res, combos, "Lấy danh sách gói combo thành công");
  });

  /**
   * Update combo details
   * @route PATCH /api/host/combos/:id
   */
  updateCombo = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const comboId = mongoIdSchema.parse(req.params.id);
    const data = updateComboSchema.parse(req.body);

    const combo = await ComboModel.findById(comboId);
    appAssert(combo, ErrorFactory.resourceNotFound("Gói combo không tồn tại"));

    // Verify property ownership
    const property = await PropertyModel.findOne({ _id: combo.propertyId, host: hostId });
    appAssert(property, ErrorFactory.resourceNotFound("Bạn không có quyền chỉnh sửa gói combo này"));

    if (data.name) combo.name = data.name;
    if (data.description !== undefined) combo.description = data.description;
    if (data.applicableSites) {
      combo.applicableSites = data.applicableSites.map(
        (id) => new Types.ObjectId(mongoIdSchema.parse(id))
      );
    }
    if (data.servicesIncluded) combo.servicesIncluded = data.servicesIncluded;
    if (data.discountType) combo.discountType = data.discountType;
    if (data.discountValue !== undefined) combo.discountValue = data.discountValue;
    if (data.isActive !== undefined) combo.isActive = data.isActive;

    await combo.save();

    return ResponseUtil.success(res, combo, "Cập nhật gói combo thành công");
  });

  /**
   * Delete a combo
   * @route DELETE /api/host/combos/:id
   */
  deleteCombo = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const comboId = mongoIdSchema.parse(req.params.id);

    const combo = await ComboModel.findById(comboId);
    appAssert(combo, ErrorFactory.resourceNotFound("Gói combo không tồn tại"));

    // Verify property ownership
    const property = await PropertyModel.findOne({ _id: combo.propertyId, host: hostId });
    appAssert(property, ErrorFactory.resourceNotFound("Bạn không có quyền xóa gói combo này"));

    await combo.deleteOne();

    return ResponseUtil.success(res, null, "Xóa gói combo thành công");
  });

  /**
   * Get all active combos for a specific property (Public API for guests)
   * @route GET /api/properties/:propertyId/combos
   */
  getPropertyCombos = catchErrors(async (req, res) => {
    const propertyId = mongoIdSchema.parse(req.params.propertyId);

    const combos = await ComboModel.find({
      propertyId,
      isActive: true
    })
      .populate("applicableSites", "name siteClass")
      .sort({ createdAt: -1 });

    return ResponseUtil.success(res, combos, "Lấy danh sách gói combo thành công");
  });
}

