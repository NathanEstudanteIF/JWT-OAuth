import { Router } from "express";
import AuthController from "../controllers/AuthController.js";
import { tokenValidated, isAdmin } from "../middlewares/auth.js";

const router = Router();

router.post("/register", tokenValidated, isAdmin, AuthController.register);
router.post("/login", AuthController.login);
router.get("/github", AuthController.githubLogin);
router.get("/github/callback", AuthController.githubCallback);

export default router;
