// src/routes/auth.route.ts
import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { requireAdmin, requireModerator } from '../middleware/role.middleware';

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
router.put('/profile', authenticate, AuthController.updateProfile);

// Token management
router.get('/verify', authenticate, AuthController.verifyToken);
router.post('/refresh', authenticate, AuthController.refreshToken);
router.post('/logout', authenticate, AuthController.logout);

// ==================== MODERATOR ROUTES (Admin & Moderator) ====================
router.get(
  '/users',
  authenticate,
  requireModerator,
  AuthController.getAllUsers,
);
router.get(
  '/users/:userId',
  authenticate,
  requireModerator,
  AuthController.getUserById,
);
router.put(
  '/activate/:userId',
  authenticate,
  requireModerator,
  AuthController.activateUser,
);
router.put(
  '/deactivate/:userId',
  authenticate,
  requireModerator,
  AuthController.deactivateUser,
);
router.put(
  '/reset-session/:userId',
  authenticate,
  requireModerator,
  AuthController.resetUserSession,
);

// ==================== ADMIN ONLY ROUTES ====================
router.put(
  '/toggle-status/:userId',
  authenticate,
  requireAdmin,
  AuthController.toggleUserStatus,
);
router.put(
  '/update-role/:userId',
  authenticate,
  requireAdmin,
  AuthController.updateUserRole,
);
router.delete(
  '/delete/:userId',
  authenticate,
  requireAdmin,
  AuthController.deleteUser,
);

export default router;
