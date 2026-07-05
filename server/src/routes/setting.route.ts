import { Router } from "express";
import SettingController from "@/controllers/setting.controller";

const settingRoutes = Router();
const settingController = new SettingController();

settingRoutes.get("/", settingController.getSettings);
settingRoutes.put("/", settingController.updateSettings);

export default settingRoutes;
