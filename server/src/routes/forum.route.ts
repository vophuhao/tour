import ForumController from "@/controllers/forum.controller";
import { container, TOKENS } from "@/di";
import { authenticate, upload } from "@/middleware";
import type { ForumService } from "@/services/forum.service";
import { Router } from "express";

const forumRoutes = Router();

const forumService = container.resolve<ForumService>(TOKENS.ForumService);
const forumController = new ForumController(forumService);

// Public routes
forumRoutes.get("/", forumController.getPosts);
forumRoutes.get("/trending", forumController.getTrending);
forumRoutes.get("/categories", forumController.getCategories);
forumRoutes.get("/:id", forumController.getPost);
forumRoutes.get("/:userId/posts", forumController.getUserPosts);

// Authenticated routes
forumRoutes.post("/", authenticate, upload.fields([
  { name: 'coverImage', maxCount: 1 },
  { name: 'images', maxCount: 10 }
]), forumController.createPost);
forumRoutes.put("/:id", authenticate, upload.fields([
  { name: 'coverImage', maxCount: 1 },
  { name: 'images', maxCount: 10 }
]), forumController.updatePost);
forumRoutes.delete("/:id", authenticate, forumController.deletePost);
forumRoutes.post("/:id/like", authenticate, forumController.toggleLike);
forumRoutes.post("/:id/save", authenticate, forumController.toggleSave);
forumRoutes.get("/saved", authenticate, forumController.getSavedPosts);
forumRoutes.get("/liked", authenticate, forumController.getLikedPosts);

export default forumRoutes;
