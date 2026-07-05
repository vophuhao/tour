import { Router } from "express";
import ServicePackageController from "@/controllers/service-package.controller";

const servicePackageRoutes = Router();
const controller = new ServicePackageController();

servicePackageRoutes.post("/", controller.createPackage);
servicePackageRoutes.get("/", controller.getMyPackages);
servicePackageRoutes.patch("/:id", controller.updatePackage);
servicePackageRoutes.delete("/:id", controller.deletePackage);

export default servicePackageRoutes;
