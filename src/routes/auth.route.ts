// src/routes/auth.route.ts
import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';

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

// ==================== ADMIN ROUTES ====================

// User management
router.get('/users', AuthController.getAllUsers);
router.put('/activate/:userId', AuthController.activateUser);

// Session management
router.put('/reset-session/:userId', AuthController.resetUserSession);

// ==================== PROTECTED ROUTES ====================

// User profile
router.get('/profile', authenticate, AuthController.getProfile);

// Token management
router.get('/verify', authenticate, AuthController.verifyToken);
router.post('/refresh', authenticate, AuthController.refreshToken);
router.post('/logout', authenticate, AuthController.logout);

export default router;
