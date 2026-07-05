import { catchErrors, ErrorFactory } from "@/errors";
import { ServicePackageModel } from "@/models";
import { ResponseUtil } from "../utils";
import { mongoIdSchema } from "@/validators";
import {
  createServicePackageSchema,
  updateServicePackageSchema,
} from "@/validators/service-package.validator";
import appAssert from "../utils/app-assert";

export default class ServicePackageController {
  /**
   * Create a new service package
   * @route POST /api/host/service-packages
   */
  createPackage = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const data = createServicePackageSchema.parse(req.body);

    const servicePackage = await ServicePackageModel.create({
      ...data,
      host: hostId,
    });

    return ResponseUtil.created(res, servicePackage, "Tạo gói dịch vụ thành công");
  });

  /**
   * Get all service packages of the current host
   * @route GET /api/host/service-packages
   */
  getMyPackages = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const packages = await ServicePackageModel.find({ host: hostId }).sort({ createdAt: -1 });

    return ResponseUtil.success(res, packages, "Lấy danh sách gói dịch vụ thành công");
  });

  /**
   * Update a specific service package
   * @route PATCH /api/host/service-packages/:id
   */
  updatePackage = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const packageId = mongoIdSchema.parse(req.params.id);
    const data = updateServicePackageSchema.parse(req.body);

    const servicePackage = await ServicePackageModel.findOne({ _id: packageId, host: hostId });
    appAssert(servicePackage, ErrorFactory.resourceNotFound("Gói dịch vụ không tồn tại hoặc bạn không có quyền"));

    if (data.name) servicePackage.name = data.name;
    if (data.services) servicePackage.services = data.services;

    await servicePackage.save();

    return ResponseUtil.success(res, servicePackage, "Cập nhật gói dịch vụ thành công");
  });

  /**
   * Delete a specific service package
   * @route DELETE /api/host/service-packages/:id
   */
  deletePackage = catchErrors(async (req, res) => {
    const hostId = mongoIdSchema.parse(req.userId);
    const packageId = mongoIdSchema.parse(req.params.id);

    const servicePackage = await ServicePackageModel.findOneAndDelete({ _id: packageId, host: hostId });
    appAssert(servicePackage, ErrorFactory.resourceNotFound("Gói dịch vụ không tồn tại hoặc bạn không có quyền"));

    return ResponseUtil.success(res, null, "Xóa gói dịch vụ thành công");
  });
}
