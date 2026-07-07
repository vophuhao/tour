import { UserController } from "@/controllers";
import { authenticate } from "@/middleware";
import { Router } from "express";

const userRoutes = Router();

const userController = new UserController();

// prefix: /users
userRoutes.get("/become-host", authenticate, userController.getAllBecomeHost);
userRoutes.get("/hosts", authenticate, userController.getAllHost);
userRoutes.get("/search", authenticate, userController.searchUsers);
userRoutes.get("/me", authenticate, userController.getUserHandler);
userRoutes.patch("/me", authenticate, userController.updateProfileHandler);
userRoutes.get("/:username/stats", userController.getUserStats);
userRoutes.get("/:username/reviews", userController.getUserReviews);
userRoutes.get("/:username", userController.getUserByUsernameHandler);
userRoutes.get("/", authenticate, userController.getAllUsers);
userRoutes.post("/become-host", authenticate, userController.becomeHostHandler);
userRoutes.post("/validate-cccd", authenticate, userController.validateCccdHandler);
userRoutes.post("/kyc-become-host", authenticate, userController.kycBecomeHostHandler);
userRoutes.post("/update-status-host/:id", authenticate, userController.updateStatusHostHandler);
userRoutes.post("/block-user/:id", authenticate, userController.blockUser);
export default userRoutes;
