// src/models/user.model.ts
import bcrypt from 'bcryptjs';
import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  fullName: string;
  email: string;
  mobileNumber: string;
  address: string;
  password: string;
  isActive: boolean;
  userRole: 'user' | 'admin';

  // OTP Fields
  otpCode?: string;
  otpExpires?: Date;
  otpVerified?: boolean;
  pendingLogin?: boolean;
  lastOtpSentAt?: Date;

  // Session Management
  currentSessionToken?: string;

  // Device Fields (optional - can be kept for tracking)
  registeredDeviceId?: string;
  registeredDeviceInfo?: string;
  registeredDeviceFingerprint?: string;
  lastLoginAt?: Date;
  lastLoginDevice?: string;
  lastLoginIP?: string;

  // Security Fields
  loginAttempts?: number;
  lockedUntil?: Date;

  createdAt: Date;
  updatedAt: Date;

  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    // Basic Information
    fullName: {
      type: String,
      required: [true, 'Full name is required'],
      trim: true,
      minlength: [2, 'Full name must be at least 2 characters'],
      maxlength: [100, 'Full name must be less than 100 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email'],
    },
    mobileNumber: {
      type: String,
      required: [true, 'Mobile number is required'],
      unique: true,
      trim: true,
    },
    address: {
      type: String,
      required: [true, 'Address is required'],
      trim: true,
      minlength: [5, 'Address must be at least 5 characters'],
      maxlength: [200, 'Address must be less than 200 characters'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false,
    },
    isActive: {
      type: Boolean,
      default: true, // Changed to true for OTP login flow
      required: true,
    },
    userRole: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    // OTP Fields
    otpCode: {
      type: String,
      select: false,
    },
    otpExpires: {
      type: Date,
      select: false,
    },
    otpVerified: {
      type: Boolean,
      default: false,
    },
    pendingLogin: {
      type: Boolean,
      default: false,
    },
    lastOtpSentAt: {
      type: Date,
    },

    // Session Management
    currentSessionToken: {
      type: String,
      select: false,
    },

    lockedUntil: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

// Hash password before saving
userSchema.pre('save', async function () {
  const user = this;

  if (!user.isModified('password')) {
    return;
  }

  try {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
  } catch (error) {
    throw error;
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (
  candidatePassword: string,
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export const User = mongoose.model<IUser>('User', userSchema);
