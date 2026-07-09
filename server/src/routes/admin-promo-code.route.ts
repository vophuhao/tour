import { Router } from "express";
import PromoCodeController from "@/controllers/promo-code.controller";

const adminPromoCodeRoutes = Router();
const controller = new PromoCodeController();

adminPromoCodeRoutes.post("/", controller.createAdminPromoCode);
adminPromoCodeRoutes.get("/", controller.getAllPromoCodesForAdmin);
adminPromoCodeRoutes.patch("/:id", controller.updateAdminPromoCode);
adminPromoCodeRoutes.delete("/:id", controller.deleteAdminPromoCode);

export default adminPromoCodeRoutes;
