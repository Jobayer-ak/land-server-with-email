// src/utils/email.ts
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';

dotenv.config();

// Gmail Configuration (Works reliably)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your Gmail address
    pass: process.env.EMAIL_PASS, // Your 16-character app password
  },
});

// Verify connection on startup
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email transporter error:', error);
  } else {
    console.log('✅ Email transporter ready for Gmail');
  }
});

export const sendOTPEmail = async (
  email: string,
  otp: string,
): Promise<void> => {
  try {
    console.log(`📧 Attempting to send OTP to ${email}`);

    const info = await transporter.sendMail({
      from: `"Land Calculator" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Login Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
          <h2 style="color: #333;">Land Calculator - Login Verification</h2>
          <p>Your One-Time Password (OTP) is:</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; text-align: center; padding: 20px; background: #f5f5f5; border-radius: 8px; margin: 20px 0;">
            ${otp}
          </div>
          <p>This OTP is valid for <strong>10 minutes</strong>.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <hr style="margin: 20px 0;" />
          <p style="font-size: 12px; color: #777;">Land Calculator - Secure Login System</p>
        </div>
      `,
    });

    console.log(`✅ OTP email sent to ${email}, Message ID: ${info.messageId}`);
  } catch (error) {
    console.error('❌ Email send error:', error);
    throw error;
  }
};
