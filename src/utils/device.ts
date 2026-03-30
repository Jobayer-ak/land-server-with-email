// src/utils/device.ts
import crypto from 'crypto';

// Generate a unique device fingerprint
export const generateDeviceFingerprint = (
  userAgent: string,
  ip: string,
  acceptLanguage?: string,
): string => {
  const fingerprintData = `${userAgent}|${ip}|${acceptLanguage || ''}`;
  return crypto.createHash('sha256').update(fingerprintData).digest('hex');
};

// Get detailed device information
export const getDeviceInfo = (userAgent: string): string => {
  const ua = userAgent.toLowerCase();

  if (ua.includes('mobile')) {
    if (ua.includes('iphone')) return 'iPhone';
    if (ua.includes('android')) return 'Android Mobile';
    return 'Mobile Device';
  }

  if (ua.includes('tablet')) {
    if (ua.includes('ipad')) return 'iPad';
    if (ua.includes('android')) return 'Android Tablet';
    return 'Tablet';
  }

  if (ua.includes('windows')) return 'Windows PC';
  if (ua.includes('mac')) return 'Mac';
  if (ua.includes('linux')) return 'Linux';

  return 'Desktop';
};

// Get browser information
export const getBrowserInfo = (userAgent: string): string => {
  const ua = userAgent.toLowerCase();

  if (ua.includes('chrome')) return 'Chrome';
  if (ua.includes('firefox')) return 'Firefox';
  if (ua.includes('safari')) return 'Safari';
  if (ua.includes('edge')) return 'Edge';
  if (ua.includes('opera')) return 'Opera';

  return 'Unknown Browser';
};

// Get OS information
export const getOSInfo = (userAgent: string): string => {
  const ua = userAgent.toLowerCase();

  if (ua.includes('windows')) return 'Windows';
  if (ua.includes('mac')) return 'macOS';
  if (ua.includes('linux')) return 'Linux';
  if (ua.includes('android')) return 'Android';
  if (ua.includes('ios') || ua.includes('iphone')) return 'iOS';

  return 'Unknown OS';
};

// Get complete device details
export const getCompleteDeviceInfo = (userAgent: string) => {
  return {
    deviceType: getDeviceInfo(userAgent),
    browser: getBrowserInfo(userAgent),
    os: getOSInfo(userAgent),
    userAgent: userAgent,
  };
};
