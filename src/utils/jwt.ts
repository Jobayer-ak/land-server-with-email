// src/utils/jwt.ts
import jwt, { SignOptions } from 'jsonwebtoken';

interface TokenPayload {
  userId: string;
  email: string;
  userRole: 'user' | 'admin' | 'moderator'; // Added moderator
  sessionToken?: string;
}

export const generateToken = (payload: TokenPayload): string => {
  const secret = process.env.JWT_SECRET as string;
  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  // Debug log
  console.log('🔐 Generating token with payload:', {
    userId: payload.userId,
    email: payload.email,
    userRole: payload.userRole,
    hasSessionToken: !!payload.sessionToken,
  });

  const options: SignOptions = {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
  };

  return jwt.sign(payload, secret, options);
};

export const verifyToken = (token: string): TokenPayload => {
  const secret = process.env.JWT_SECRET as string;
  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  const decoded = jwt.verify(token, secret) as TokenPayload;

  // Debug log
  console.log('🔓 Verified token payload:', {
    userId: decoded.userId,
    email: decoded.email,
    userRole: decoded.userRole,
    hasSessionToken: !!decoded.sessionToken,
  });

  return decoded;
};
