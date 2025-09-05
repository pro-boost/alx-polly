/**
 * Secure redirect utility to prevent open redirect vulnerabilities
 * Validates redirect URLs to ensure they are safe and internal
 */

import { redirect } from 'next/navigation';

/**
 * List of allowed redirect paths (whitelist approach)
 */
const ALLOWED_REDIRECT_PATHS = [
  '/',
  '/polls',
  '/polls/create',
  '/profile',
  '/settings',
  '/login',
  '/register',
];

/**
 * Check if a URL is safe for redirection
 */
export function isSafeRedirectURL(url: string): boolean {
  try {
    // Handle relative URLs
    if (url.startsWith('/')) {
      // Check against whitelist
      return ALLOWED_REDIRECT_PATHS.some(allowedPath => {
        // Exact match or starts with allowed path followed by /
        return url === allowedPath || url.startsWith(allowedPath + '/');
      });
    }
    
    // Parse absolute URLs
    const parsedURL = new URL(url);
    
    // Only allow same origin
    const currentOrigin = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
    const allowedOrigin = new URL(currentOrigin);
    
    if (parsedURL.origin !== allowedOrigin.origin) {
      return false;
    }
    
    // Check path against whitelist
    return ALLOWED_REDIRECT_PATHS.some(allowedPath => {
      return parsedURL.pathname === allowedPath || parsedURL.pathname.startsWith(allowedPath + '/');
    });
  } catch (error) {
    // Invalid URL
    return false;
  }
}

/**
 * Safely redirect to a URL, with fallback to default
 */
export function safeRedirect(url: string, fallback: string = '/polls'): never {
  const redirectURL = isSafeRedirectURL(url) ? url : fallback;
  redirect(redirectURL);
}

/**
 * Get safe redirect URL from query parameters
 */
export function getSafeRedirectURL(searchParams: URLSearchParams, fallback: string = '/polls'): string {
  const redirectTo = searchParams.get('redirect') || searchParams.get('redirectTo') || searchParams.get('return_to');
  
  if (!redirectTo) {
    return fallback;
  }
  
  return isSafeRedirectURL(redirectTo) ? redirectTo : fallback;
}

/**
 * Validate and sanitize redirect parameter
 */
export function sanitizeRedirectParam(redirectParam: string | null): string {
  if (!redirectParam) {
    return '/polls';
  }
  
  // Decode URL-encoded parameter
  try {
    const decoded = decodeURIComponent(redirectParam);
    return isSafeRedirectURL(decoded) ? decoded : '/polls';
  } catch (error) {
    return '/polls';
  }
}

/**
 * Create a safe login redirect URL with return parameter
 */
export function createLoginRedirectURL(returnTo?: string): string {
  if (!returnTo || !isSafeRedirectURL(returnTo)) {
    return '/login';
  }
  
  const params = new URLSearchParams({ redirect: returnTo });
  return `/login?${params.toString()}`;
}

/**
 * Add a new allowed redirect path (use with caution)
 */
export function addAllowedRedirectPath(path: string): void {
  if (path.startsWith('/') && !ALLOWED_REDIRECT_PATHS.includes(path)) {
    ALLOWED_REDIRECT_PATHS.push(path);
  }
}