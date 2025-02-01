import express from 'express';
import { loginControllers, profileController, registerControllers, setAvatarController } from '../controllers/userController.js';

const router = express.Router();

router.route("/register").post(registerControllers);

router.route("/login").post(loginControllers);

router.route("/setAvatar/:id").post(setAvatarController);

router.route("/profile").get(profileController);

export default router;