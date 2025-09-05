'use server';

import { createClient } from '@/lib/supabase/server';
import { LoginFormData, RegisterFormData } from '../types';
import { authRateLimiter } from '@/lib/rate-limit';
import { headers } from 'next/headers';

/**
 * Get client IP for rate limiting
 */
async function getClientIP(): Promise<string> {
  const headersList = await headers();
  const forwarded = headersList.get('x-forwarded-for');
  const realIP = headersList.get('x-real-ip');
  
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  
  if (realIP) {
    return realIP;
  }
  
  return 'unknown';
}

export async function login(data: LoginFormData) {
  const supabase = await createClient();
  const clientIP = await getClientIP();

  // Check rate limiting
  if (authRateLimiter.isRateLimited(clientIP)) {
    const resetTime = authRateLimiter.getResetTime(clientIP);
    return { 
      error: `Too many login attempts. Please try again in ${Math.ceil(resetTime / 60)} minutes.` 
    };
  }

  // Server-side input validation and sanitization
  const sanitizedEmail = sanitizeInput(data.email.toLowerCase());
  
  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(sanitizedEmail)) {
    return { error: 'Please enter a valid email address' };
  }

  // Validate password is not empty
  if (!data.password || data.password.length === 0) {
    return { error: 'Password is required' };
  }

  try {
    const { error } = await supabase.auth.signInWithPassword({
      email: sanitizedEmail,
      password: data.password,
    });

    if (error) {
      // Record failed attempt for rate limiting
      authRateLimiter.recordFailedAttempt(clientIP);
      // Generic error message to prevent user enumeration
      return { error: 'Invalid email or password' };
    }

    // Record successful attempt (clears rate limit)
    authRateLimiter.recordSuccessfulAttempt(clientIP);
    return { error: null };
  } catch (error) {
    authRateLimiter.recordFailedAttempt(clientIP);
    return { error: 'Login failed. Please try again.' };
  }
}

/**
 * Validates password strength on server-side
 */
function validatePasswordStrength(password: string): string | null {
  if (password.length < 8) {
    return 'Password must be at least 8 characters long';
  }
  if (!/(?=.*[a-z])/.test(password)) {
    return 'Password must contain at least one lowercase letter';
  }
  if (!/(?=.*[A-Z])/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  }
  if (!/(?=.*\d)/.test(password)) {
    return 'Password must contain at least one number';
  }
  if (!/(?=.*[@$!%*?&])/.test(password)) {
    return 'Password must contain at least one special character';
  }
  return null;
}

/**
 * Sanitizes input data to prevent XSS and injection attacks
 */
function sanitizeInput(input: string): string {
  return input.trim().replace(/[<>"'&]/g, (match) => {
    const entities: { [key: string]: string } = {
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '&': '&amp;'
    };
    return entities[match] || match;
  });
}

export async function register(data: RegisterFormData) {
  const supabase = await createClient();
  const clientIP = await getClientIP();

  // Check rate limiting
  if (authRateLimiter.isRateLimited(clientIP)) {
    const resetTime = authRateLimiter.getResetTime(clientIP);
    return { 
      error: `Too many registration attempts. Please try again in ${Math.ceil(resetTime / 60)} minutes.` 
    };
  }

  // Server-side input validation and sanitization
  const sanitizedName = sanitizeInput(data.name);
  const sanitizedEmail = sanitizeInput(data.email.toLowerCase());
  
  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(sanitizedEmail)) {
    return { error: 'Please enter a valid email address' };
  }

  // Validate password strength
  const passwordError = validatePasswordStrength(data.password);
  if (passwordError) {
    return { error: passwordError };
  }

  // Validate name length
  if (sanitizedName.length < 2 || sanitizedName.length > 50) {
    return { error: 'Name must be between 2 and 50 characters' };
  }

  try {
    const { error } = await supabase.auth.signUp({
      email: sanitizedEmail,
      password: data.password,
      options: {
        data: {
          name: sanitizedName,
        },
      },
    });

    if (error) {
      // Record failed attempt for rate limiting
      authRateLimiter.recordFailedAttempt(clientIP);
      // Generic error message to prevent information disclosure
      if (error.message.includes('already registered')) {
        return { error: 'An account with this email already exists' };
      }
      return { error: 'Registration failed. Please try again.' };
    }

    // Record successful attempt (clears rate limit)
    authRateLimiter.recordSuccessfulAttempt(clientIP);
    return { error: null };
  } catch (error) {
    authRateLimiter.recordFailedAttempt(clientIP);
    return { error: 'Registration failed. Please try again.' };
  }
}

export async function logout() {
  const supabase = await createClient();
  const { error } = await supabase.auth.signOut();
  if (error) {
    return { error: error.message };
  }
  return { error: null };
}

export async function getCurrentUser() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

export async function getSession() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}
