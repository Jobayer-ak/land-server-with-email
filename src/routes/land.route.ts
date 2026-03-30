// src/routes/land.route.ts
import { Router } from 'express';
import { LandController } from '../controllers/land.controller';
import { authenticate } from '../middleware/auth.middleware';

const router = Router();

// Protected routes (require authentication)
router.post('/calculate', authenticate, LandController.calculate);
router.post('/convert', authenticate, LandController.convert);

export default router;
