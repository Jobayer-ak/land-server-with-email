// src/controllers/auth.controller.ts
import crypto from 'crypto';
import { Request, Response } from 'express';
import { User } from '../models/user.model';
import { sendOTPEmail } from '../utils/email';
import { generateToken, verifyToken } from '../utils/jwt';

export class AuthController {
  static async register(req: Request, res: Response) {
    try {
      console.log('🔵 Registration started');
      console.log('Request body:', req.body);

      const {
        fullName,
        email,
        password,
        confirmPassword,
        mobileNumber,
        address,
      } = req.body;

      // Validate required fields
      if (
        !fullName ||
        !email ||
        !password ||
        !confirmPassword ||
        !mobileNumber ||
        !address
      ) {
        return res.status(400).json({
          success: false,
          message: 'All fields are required',
        });
      }

      // Check if passwords match
      if (password !== confirmPassword) {
        return res.status(400).json({
          success: false,
          message: 'Passwords do not match',
        });
      }

      // Check if user exists
      const existingUser = await User.findOne({
        $or: [{ email }, { mobileNumber }],
      });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'User with this email or mobile number already exists',
        });
      }

      // Create user with isActive = false (awaiting admin approval)
      const user = new User({
        fullName,
        email,
        password,
        mobileNumber,
        address,
        isActive: false,
        role: 'user',
      });

      await user.save();
      console.log('✅ User saved:', user._id, 'with role:', user.role);

      res.status(201).json({
        success: true,
        message:
          'User registered successfully. Please wait for admin approval.',
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
          role: user.role,
        },
      });
    } catch (error: any) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  // ✅ Step 1: Login with Password - Check if user is active, then send OTP
  static async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email and password are required',
        });
      }

      const user = await User.findOne({ email }).select(
        '+password +lastOtpSentAt',
      );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
        });
      }

      console.log('👤 User found for login:', {
        email: user.email,
        role: user.role,
        isActive: user.isActive,
      });

      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is not activated. Please contact admin.',
        });
      }

      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const minutesLeft = Math.ceil(
          (user.lockedUntil.getTime() - Date.now()) / 60000,
        );
        return res.status(403).json({
          success: false,
          message: `Account is locked. Please try again in ${minutesLeft} minutes.`,
        });
      }

      const isPasswordValid = await user.comparePassword(password);

      if (!isPasswordValid) {
        user.loginAttempts = (user.loginAttempts || 0) + 1;

        if (user.loginAttempts >= 5) {
          user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
          await user.save();
          return res.status(403).json({
            success: false,
            message: 'Too many failed attempts. Account locked for 30 minutes.',
          });
        }

        await user.save();
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
          remainingAttempts: 5 - (user.loginAttempts || 0),
        });
      }

      user.loginAttempts = 0;
      user.lockedUntil = undefined;

      if (user.lastOtpSentAt) {
        const timeSinceLastOtp =
          Date.now() - new Date(user.lastOtpSentAt).getTime();
        if (timeSinceLastOtp < 30000) {
          const remainingSeconds = Math.ceil((30000 - timeSinceLastOtp) / 1000);
          return res.status(429).json({
            success: false,
            message: `Please wait ${remainingSeconds} seconds before requesting another OTP`,
          });
        }
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

      user.otpCode = otp;
      user.otpExpires = otpExpires;
      user.otpVerified = false;
      user.pendingLogin = true;
      user.lastOtpSentAt = new Date();
      await user.save();

      await sendOTPEmail(email, otp);

      console.log(`📧 OTP sent to ${email} for login`);

      res.json({
        success: true,
        message: 'OTP sent to your email. Please verify to complete login.',
        expiresIn: 600,
      });
    } catch (error: any) {
      console.error('❌ Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to process login',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  // ✅ Step 2: Verify OTP and complete login
  static async verifyOTP(req: Request, res: Response) {
    try {
      const { email, otp } = req.body;

      if (!email || !otp) {
        return res.status(400).json({
          success: false,
          message: 'Email and OTP are required',
        });
      }

      const user = await User.findOne({ email }).select(
        '+otpCode +otpExpires +otpVerified +pendingLogin +currentSessionToken',
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      console.log('👤 User found for OTP verification:', {
        id: user._id,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
      });

      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is not activated. Please contact admin.',
        });
      }

      if (!user.pendingLogin) {
        return res.status(400).json({
          success: false,
          message: 'Please login first to request OTP.',
        });
      }

      if (!user.otpCode || user.otpCode !== otp) {
        return res.status(400).json({
          success: false,
          message: 'Invalid OTP',
        });
      }

      if (user.otpExpires && user.otpExpires < new Date()) {
        user.pendingLogin = false;
        await user.save();
        return res.status(400).json({
          success: false,
          message: 'OTP expired. Please login again to request a new OTP.',
        });
      }

      const sessionToken = crypto.randomBytes(32).toString('hex');
      const isNewDevice = !!user.currentSessionToken;

      user.currentSessionToken = sessionToken;
      user.otpCode = undefined;
      user.otpExpires = undefined;
      user.otpVerified = true;
      user.pendingLogin = false;
      await user.save();

      const userRole = user.role || 'user';
      console.log('🎫 Generating token with role:', userRole);

      const token = generateToken({
        userId: user._id.toString(),
        email: user.email,
        sessionToken: sessionToken,
        userRole: userRole,
      });

      console.log(`✅ Login successful for ${email} with role: ${userRole}`);

      res.json({
        success: true,
        message: isNewDevice
          ? 'Login successful. Previous session has been terminated.'
          : 'Login successful',
        token,
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
          role: userRole,
        },
      });
    } catch (error: any) {
      console.error('❌ OTP verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  static async resendOTP(req: Request, res: Response) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message: 'Email is required',
        });
      }

      const user = await User.findOne({ email }).select(
        '+lastOtpSentAt +pendingLogin',
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is not activated.',
        });
      }

      if (!user.pendingLogin) {
        return res.status(400).json({
          success: false,
          message: 'Please login first to request OTP.',
        });
      }

      if (user.lastOtpSentAt) {
        const timeSinceLastOtp =
          Date.now() - new Date(user.lastOtpSentAt).getTime();
        if (timeSinceLastOtp < 30000) {
          const remainingSeconds = Math.ceil((30000 - timeSinceLastOtp) / 1000);
          return res.status(429).json({
            success: false,
            message: `Please wait ${remainingSeconds} seconds before requesting another OTP`,
          });
        }
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

      user.otpCode = otp;
      user.otpExpires = otpExpires;
      user.otpVerified = false;
      user.lastOtpSentAt = new Date();
      await user.save();

      await sendOTPEmail(email, otp);

      res.json({
        success: true,
        message: 'OTP resent to your email',
      });
    } catch (error: any) {
      console.error('❌ Resend OTP error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to resend OTP',
      });
    }
  }

  static async verifyToken(req: Request, res: Response) {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          message: 'No token provided',
        });
      }

      const token = authHeader.split(' ')[1];
      let decoded;

      try {
        decoded = verifyToken(token);
        console.log('🔓 Token verified, userRole:', decoded.userRole);
      } catch (error) {
        return res.status(401).json({
          success: false,
          message: 'Invalid or expired token',
        });
      }

      const user = await User.findById(decoded.userId).select(
        '-password +currentSessionToken',
      );

      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'User not found',
        });
      }

      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: 'Account is not activated',
        });
      }

      if (
        !user.currentSessionToken ||
        user.currentSessionToken !== decoded.sessionToken
      ) {
        return res.status(401).json({
          success: false,
          message:
            'Session expired. You have been logged out from another device.',
          code: 'SESSION_EXPIRED',
        });
      }

      res.json({
        success: true,
        message: 'Token is valid',
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          mobileNumber: user.mobileNumber,
          address: user.address,
          isActive: user.isActive,
          role: user.role || decoded.userRole || 'user',
        },
      });
    } catch (error) {
      console.error('❌ Token verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async logout(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (userId) {
        await User.findByIdAndUpdate(userId, { currentSessionToken: null });
      }
      res.json({ success: true, message: 'Logout successful' });
    } catch (error) {
      console.error('Logout error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async getProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res
          .status(401)
          .json({ success: false, message: 'Unauthorized' });
      }

      const user = await User.findById(userId).select('-password');
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: 'User not found' });
      }

      res.json({ success: true, user });
    } catch (error) {
      console.error('Profile error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async updateProfile(req: Request, res: Response) {
    try {
      const userId = (req as any).user?.userId;
      if (!userId) {
        return res.status(401).json({
          success: false,
          message: 'Unauthorized',
        });
      }

      const { fullName, mobileNumber, address } = req.body;

      if (!fullName || !mobileNumber || !address) {
        return res.status(400).json({
          success: false,
          message: 'Full name, mobile number, and address are required',
        });
      }

      const existingUser = await User.findOne({
        mobileNumber,
        _id: { $ne: userId },
      });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: 'Mobile number is already in use by another account',
        });
      }

      const user = await User.findByIdAndUpdate(
        userId,
        {
          fullName,
          mobileNumber,
          address,
        },
        { new: true, runValidators: true },
      ).select('-password');

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      console.log(`✅ Profile updated for user: ${user.email}`);

      res.json({
        success: true,
        message: 'Profile updated successfully',
        user,
      });
    } catch (error: any) {
      console.error('Profile update error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error:
          process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  static async refreshToken(req: Request, res: Response) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res
          .status(401)
          .json({ success: false, message: 'No token provided' });
      }

      const oldToken = authHeader.split(' ')[1];
      let decoded;

      try {
        decoded = verifyToken(oldToken);
        console.log(
          '🔄 Refreshing token for user:',
          decoded.email,
          'role:',
          decoded.userRole,
        );
      } catch (error) {
        return res
          .status(401)
          .json({ success: false, message: 'Invalid or expired token' });
      }

      const user = await User.findById(decoded.userId).select(
        '+currentSessionToken',
      );
      if (!user) {
        return res
          .status(401)
          .json({ success: false, message: 'User not found' });
      }

      if (!user.isActive) {
        return res
          .status(403)
          .json({ success: false, message: 'Account is not activated' });
      }

      if (
        !user.currentSessionToken ||
        user.currentSessionToken !== decoded.sessionToken
      ) {
        return res.status(401).json({
          success: false,
          message: 'Session expired. Please login again.',
        });
      }

      const userRole = user.role || decoded.userRole || 'user';
      console.log('🔄 Generating new token with role:', userRole);

      const newToken = generateToken({
        userId: user._id.toString(),
        email: user.email,
        userRole: userRole,
        sessionToken: user.currentSessionToken,
      });

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        token: newToken,
      });
    } catch (error) {
      console.error('Token refresh error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  // ==================== MODERATOR & ADMIN ENDPOINTS ====================

  static hasModeratorPermissions(role: string): boolean {
    return role === 'admin' || role === 'moderator';
  }

  static async getAllUsers(req: Request, res: Response) {
    try {
      const users = await User.find().select('-password');
      res.json({ success: true, count: users.length, users });
    } catch (error) {
      console.error('Get all users error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async getUserById(req: Request, res: Response) {
    try {
      const { userId } = req.params;
      const user = await User.findById(userId).select('-password');

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const currentUserRole = (req as any).user?.userRole;
      if (!AuthController.hasModeratorPermissions(currentUserRole)) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to view user details.',
        });
      }

      res.json({
        success: true,
        user,
      });
    } catch (error) {
      console.error('Get user by ID error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async activateUser(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const currentUserRole = (req as any).user?.userRole;
      if (!AuthController.hasModeratorPermissions(currentUserRole)) {
        return res.status(403).json({
          success: false,
          message:
            'Insufficient permissions. Only admins and moderators can activate users.',
        });
      }

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (user.isActive) {
        return res.status(400).json({
          success: false,
          message: 'User is already active',
        });
      }

      user.isActive = true;
      await user.save();

      console.log(`✅ User activated by ${currentUserRole}: ${user.email}`);

      res.json({
        success: true,
        message: `User ${user.fullName} activated successfully.`,
      });
    } catch (error) {
      console.error('Activation error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async deactivateUser(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const currentUserRole = (req as any).user?.userRole;
      if (!AuthController.hasModeratorPermissions(currentUserRole)) {
        return res.status(403).json({
          success: false,
          message:
            'Insufficient permissions. Only admins and moderators can deactivate users.',
        });
      }

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (!user.isActive) {
        return res.status(400).json({
          success: false,
          message: 'User is already deactivated',
        });
      }

      if (currentUserRole === 'moderator' && user.role === 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Moderators cannot deactivate admin accounts.',
        });
      }

      const adminId = (req as any).user?.userId;
      if (userId === adminId) {
        return res.status(400).json({
          success: false,
          message: 'You cannot deactivate your own account',
        });
      }

      user.isActive = false;
      user.currentSessionToken = null;

      await user.save();

      console.log(`⚠️ User deactivated by ${currentUserRole}: ${user.email}`);

      res.json({
        success: true,
        message: `User ${user.fullName} deactivated successfully. They will be logged out immediately.`,
      });
    } catch (error) {
      console.error('Deactivation error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async toggleUserStatus(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const currentUserRole = (req as any).user?.userRole;
      if (currentUserRole !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Only administrators can toggle user status.',
        });
      }

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      const adminId = (req as any).user?.userId;
      if (userId === adminId) {
        return res.status(400).json({
          success: false,
          message: 'You cannot change your own account status',
        });
      }

      user.isActive = !user.isActive;

      if (!user.isActive) {
        user.currentSessionToken = null;
      }

      await user.save();

      const status = user.isActive ? 'activated' : 'deactivated';
      console.log(`✅ User ${status} by admin: ${user.email}`);

      res.json({
        success: true,
        message: `User ${user.fullName} ${status} successfully`,
        isActive: user.isActive,
      });
    } catch (error) {
      console.error('Toggle user status error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async resetUserSession(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const currentUserRole = (req as any).user?.userRole;
      if (!AuthController.hasModeratorPermissions(currentUserRole)) {
        return res.status(403).json({
          success: false,
          message:
            'Insufficient permissions. Only admins and moderators can reset user sessions.',
        });
      }

      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (currentUserRole === 'moderator' && user.role === 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Moderators cannot reset admin sessions.',
        });
      }

      user.currentSessionToken = null;
      user.loginAttempts = 0;
      user.lockedUntil = undefined;
      await user.save();

      console.log(
        `🔄 Session reset by ${currentUserRole} for user: ${user.email}`,
      );

      res.json({
        success: true,
        message: `Session reset successfully for ${user.fullName}`,
      });
    } catch (error) {
      console.error('Reset session error:', error);
      res
        .status(500)
        .json({ success: false, message: 'Internal server error' });
    }
  }

  static async updateUserRole(req: Request, res: Response) {
    try {
      const { userId } = req.params;
      const { role } = req.body;

      if (!role || !['user', 'admin', 'moderator'].includes(role)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid role. Allowed roles: user, admin, moderator',
        });
      }

      const currentUserRole = (req as any).user?.userRole;
      if (currentUserRole !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Only administrators can change user roles.',
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      if (!user.isActive) {
        return res.status(403).json({
          success: false,
          message: `Cannot change role for inactive user "${user.fullName}". Please activate the user first before changing their role.`,
          code: 'USER_INACTIVE',
          userStatus: user.isActive,
        });
      }

      const adminId = (req as any).user?.userId;
      if (userId === adminId && role !== 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount === 1) {
          return res.status(400).json({
            success: false,
            message:
              'Cannot change your own role. You are the only admin in the system.',
            code: 'LAST_ADMIN',
          });
        }
      }

      const oldRole = user.role;
      user.role = role;
      await user.save();

      console.log(
        `🔄 User role updated by admin: ${user.email} from "${oldRole}" to "${role}"`,
      );

      res.json({
        success: true,
        message: `User role updated from "${oldRole}" to "${role}" successfully.`,
        user: {
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          isActive: user.isActive,
        },
      });
    } catch (error) {
      console.error('Update role error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }

  static async deleteUser(req: Request, res: Response) {
    try {
      const { userId } = req.params;

      const currentUserRole = (req as any).user?.userRole;
      if (currentUserRole !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Only administrators can delete users.',
        });
      }

      const adminId = (req as any).user?.userId;
      if (userId === adminId) {
        return res.status(400).json({
          success: false,
          message: 'You cannot delete your own account',
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
        });
      }

      await User.findByIdAndDelete(userId);

      console.log(`🗑️ User deleted by admin: ${user.email}`);

      res.json({
        success: true,
        message: `User ${user.fullName} deleted successfully`,
      });
    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
      });
    }
  }
}
