'use server';

import { createClient } from '@/lib/supabase/server';
import { LoginFormData, RegisterFormData } from '../types';
import { authRateLimiter } from '@/lib/rate-limit';
import { headers } from 'next/headers';

/**
 * Server-side authentication actions for user login, registration, and session management
 * Implements security measures including rate limiting, input validation, and password strength checks
 */

/**
 * Extracts client IP address from request headers for rate limiting purposes
 * Checks multiple header sources in order of preference for accurate IP detection
 * 
 * @returns Promise<string> - Client IP address or 'unknown' if not determinable
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

/**
 * Authenticates a user with email and password
 * Implements rate limiting, input validation, and secure error handling
 * 
 * @param data - Login form data containing email and password
 * @returns Promise<{error?: string, user?: User}> - Authentication result with user data or error message
 */
export async function login(data: LoginFormData) {
  const supabase = await createClient();
  const clientIP = await getClientIP();

  // Apply rate limiting to prevent brute force attacks
  if (authRateLimiter.isRateLimited(clientIP)) {
    const resetTime = authRateLimiter.getResetTime(clientIP);
    return { 
      error: `Too many login attempts. Please try again in ${Math.ceil(resetTime / 60)} minutes.` 
    };
  }

  // Server-side input validation and sanitization to prevent injection attacks
  const sanitizedEmail = sanitizeInput(data.email.toLowerCase());
  
  // Validate email format using regex pattern
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(sanitizedEmail)) {
    return { error: 'Please enter a valid email address' };
  }

  // Ensure password is provided and not empty
  if (!data.password || data.password.length === 0) {
    return { error: 'Password is required' };
  }

  try {
    // Attempt authentication with Supabase
    const { error } = await supabase.auth.signInWithPassword({
      email: sanitizedEmail,
      password: data.password,
    });

    if (error) {
      // Record failed attempt for rate limiting protection
      authRateLimiter.recordFailedAttempt(clientIP);
      // Return generic error message to prevent user enumeration attacks
      return { error: 'Invalid email or password' };
    }

    // Record successful attempt (clears rate limit counter)
    authRateLimiter.recordSuccessfulAttempt(clientIP);
    return { error: null };
  } catch (error) {
    // Handle unexpected errors and record failed attempt
    authRateLimiter.recordFailedAttempt(clientIP);
    return { error: 'Login failed. Please try again.' };
  }
}

/**
 * Validates password strength against security requirements
 * Enforces minimum length, character diversity, and complexity rules
 * 
 * @param password - The password string to validate
 * @returns string | null - Error message if validation fails, null if password is strong
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
 * Sanitizes user input to prevent XSS and injection attacks
 * Escapes dangerous HTML characters and trims whitespace
 * 
 * @param input - The input string to sanitize
 * @returns string - Sanitized and safe input string
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

/**
 * Handles user registration with comprehensive security measures
 * Implements rate limiting, input validation, password strength checks, and secure user creation
 * 
 * @param data - Registration form data containing name, email, and password
 * @returns Promise<{error: string | null}> - Success/error response object
 */
export async function register(data: RegisterFormData) {
  const supabase = await createClient();
  const clientIP = await getClientIP();

  // Apply rate limiting to prevent spam registrations and brute force attacks
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
    // Create new user account with Supabase Auth
    const { error } = await supabase.auth.signUp({
      email: sanitizedEmail,
      password: data.password,
      options: {
        data: {
          name: sanitizedName, // Store user's name in metadata
        },
      },
    });

    if (error) {
      // Record failed attempt for rate limiting protection
      authRateLimiter.recordFailedAttempt(clientIP);
      // Provide specific error for duplicate email, generic for others
      if (error.message.includes('already registered')) {
        return { error: 'An account with this email already exists' };
      }
      return { error: 'Registration failed. Please try again.' };
    }

    // Record successful attempt (clears rate limit counter)
    authRateLimiter.recordSuccessfulAttempt(clientIP);
    return { error: null };
  } catch (error) {
    // Handle unexpected errors and record failed attempt
    authRateLimiter.recordFailedAttempt(clientIP);
    return { error: 'Registration failed. Please try again.' };
  }
}

/**
 * Handles user logout by terminating the current session
 * Clears authentication state and redirects to login page
 * 
 * @returns Promise<{error: string | null}> - Success/error response object
 */
export async function logout() {
  const supabase = await createClient();
  
  // Sign out user and clear session
  const { error } = await supabase.auth.signOut();
  if (error) {
    return { error: error.message };
  }
  return { error: null };
}

/**
 * Retrieves the currently authenticated user's information
 * Used for server-side user data access and authentication checks
 * 
 * @returns Promise<User | null> - Current user object or null if not authenticated
 */
export async function getCurrentUser() {
  const supabase = await createClient();
  // Retrieve current authenticated user from Supabase session
  const { data } = await supabase.auth.getUser();
  return data.user;
}

/**
 * Retrieves the current authentication session
 * Used for server-side session validation and token access
 * 
 * @returns Promise<Session | null> - Current session object or null if not authenticated
 */
export async function getSession() {
  const supabase = await createClient();
  // Get current session with authentication tokens
  const { data } = await supabase.auth.getSession();
  return data.session;
}
