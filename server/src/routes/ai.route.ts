import { Router } from "express";
import { authenticate } from "@/middleware";
import { aiController } from "@/controllers/ai.controller";

const aiRoutes = Router();

aiRoutes.post("/generate-content", authenticate, aiController.generateContent);
aiRoutes.post("/generate-summary", authenticate, aiController.generateSummary);
aiRoutes.get("/image-suggestions", authenticate, aiController.imageSuggestions);
aiRoutes.get("/search-images", authenticate, aiController.searchImages);
aiRoutes.post("/generate-image-prompt", authenticate, aiController.generateImagePrompt);
aiRoutes.post("/generate-image", authenticate, aiController.generateImage);
aiRoutes.get("/pricing-suggestions", authenticate, aiController.getPricingSuggestions);
aiRoutes.post("/roadtrip-suggestions", aiController.generateRoadtripSuggestions);

export default aiRoutes;
