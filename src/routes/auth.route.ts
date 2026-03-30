// src/routes/auth.route.ts
import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { requireAdmin } from '../middleware/role.middleware';

const router = Router();

// ==================== PUBLIC ROUTES ====================

// User registration
router.post('/signup', AuthController.register);

// ==================== LOGIN FLOW (Password + OTP) ====================

// Step 1: Login with email & password → receives OTP
router.post('/login', AuthController.login);

// Step 2: Verify OTP → receives JWT token
router.post('/verify-otp', AuthController.verifyOTP);

// Resend OTP (if needed)
router.post('/resend-otp', AuthController.resendOTP);

// ==================== PROTECTED ROUTES (Authenticated Users) ====================

// User profile
router.get('/profile', authenticate, AuthController.getProfile);

// Token management
router.get('/verify', authenticate, AuthController.verifyToken);
router.post('/refresh', authenticate, AuthController.refreshToken);
router.post('/logout', authenticate, AuthController.logout);

// ==================== ADMIN ONLY ROUTES ====================

// User management (Admin only)
router.get('/users', authenticate, requireAdmin, AuthController.getAllUsers);
router.put(
  '/activate/:userId',
  authenticate,
  requireAdmin,
  AuthController.activateUser,
);
router.put(
  '/update-role/:userId',
  authenticate,
  requireAdmin,
  AuthController.updateUserRole,
);

// Session management (Admin only)
router.put(
  '/reset-session/:userId',
  authenticate,
  requireAdmin,
  AuthController.resetUserSession,
);

// ==================== MODERATOR ROUTES (Example - Optional) ====================
// If you want to give moderators limited access
// router.get('/users', authenticate, requireRole(['admin', 'moderator']), AuthController.getAllUsers);

export default router;
