import { Router } from "express";
import PromoCodeController from "@/controllers/promo-code.controller";

const promoCodeRoutes = Router();
const controller = new PromoCodeController();

promoCodeRoutes.post("/", controller.createPromoCode);
promoCodeRoutes.get("/", controller.getMyPromoCodes);
promoCodeRoutes.patch("/:id", controller.updatePromoCode);
promoCodeRoutes.delete("/:id", controller.deletePromoCode);

export default promoCodeRoutes;
