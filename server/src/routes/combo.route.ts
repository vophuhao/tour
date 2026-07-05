import { Router } from "express";
import ComboController from "@/controllers/combo.controller";

const comboRoutes = Router();
const controller = new ComboController();

comboRoutes.post("/", controller.createCombo);
comboRoutes.get("/", controller.getMyCombos);
comboRoutes.patch("/:id", controller.updateCombo);
comboRoutes.delete("/:id", controller.deleteCombo);

export default comboRoutes;
