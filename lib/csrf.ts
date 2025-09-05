/**
 * CSRF (Cross-Site Request Forgery) protection utility
 * Generates and validates CSRF tokens for form submissions
 */

import { cookies } from 'next/headers';
import crypto from 'crypto';

const CSRF_TOKEN_NAME = 'csrf-token';
const CSRF_SECRET_NAME = 'csrf-secret';
const TOKEN_LENGTH = 32;

/**
 * Generate a random token
 */
function generateToken(): string {
  return crypto.randomBytes(TOKEN_LENGTH).toString('hex');
}

/**
 * Generate CSRF token and secret pair
 */
export async function generateCSRFToken(): Promise<string> {
  const cookieStore = await cookies();
  
  // Generate secret if it doesn't exist
  let secret = cookieStore.get(CSRF_SECRET_NAME)?.value;
  if (!secret) {
    secret = generateToken();
    cookieStore.set(CSRF_SECRET_NAME, secret, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24, // 24 hours
    });
  }
  
  // Generate token
  const token = generateToken();
  
  // Create HMAC of token with secret
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(token);
  const signature = hmac.digest('hex');
  
  // Combine token and signature
  const csrfToken = `${token}.${signature}`;
  
  // Store token in cookie
  cookieStore.set(CSRF_TOKEN_NAME, csrfToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60, // 1 hour
  });
  
  return csrfToken;
}

/**
 * Validate CSRF token
 */
export async function validateCSRFToken(token: string): Promise<boolean> {
  try {
    const cookieStore = await cookies();
    
    // Get stored token and secret
    const storedToken = cookieStore.get(CSRF_TOKEN_NAME)?.value;
    const secret = cookieStore.get(CSRF_SECRET_NAME)?.value;
    
    if (!storedToken || !secret || !token) {
      return false;
    }
    
    // Check if tokens match
    if (token !== storedToken) {
      return false;
    }
    
    // Parse token and signature
    const [tokenPart, signature] = token.split('.');
    if (!tokenPart || !signature) {
      return false;
    }
    
    // Verify signature
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(tokenPart);
    const expectedSignature = hmac.digest('hex');
    
    // Use timing-safe comparison
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (error) {
    return false;
  }
}

/**
 * Get CSRF token from cookies (for client-side use)
 */
export async function getCSRFToken(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get(CSRF_TOKEN_NAME)?.value || null;
}

/**
 * Clear CSRF tokens
 */
export async function clearCSRFTokens(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(CSRF_TOKEN_NAME);
  cookieStore.delete(CSRF_SECRET_NAME);
}

/**
 * Middleware function to validate CSRF token from form data
 */
export async function validateCSRFFromFormData(formData: FormData): Promise<boolean> {
  const token = formData.get('csrf-token') as string;
  return await validateCSRFToken(token);
}