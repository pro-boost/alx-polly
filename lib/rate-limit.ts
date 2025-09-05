/**
 * Rate limiting utility to prevent brute force attacks
 * Uses in-memory storage for simplicity - in production, use Redis or database
 */

interface RateLimitEntry {
  count: number;
  resetTime: number;
  blocked: boolean;
}

class RateLimiter {
  private attempts: Map<string, RateLimitEntry> = new Map();
  private readonly maxAttempts: number;
  private readonly windowMs: number;
  private readonly blockDurationMs: number;

  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000, blockDurationMs = 30 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.blockDurationMs = blockDurationMs;
  }

  /**
   * Check if an IP/identifier is rate limited
   */
  isRateLimited(identifier: string): boolean {
    const now = Date.now();
    const entry = this.attempts.get(identifier);

    if (!entry) {
      return false;
    }

    // Check if block period has expired
    if (entry.blocked && now > entry.resetTime) {
      this.attempts.delete(identifier);
      return false;
    }

    // Check if still blocked
    if (entry.blocked) {
      return true;
    }

    // Check if window has expired
    if (now > entry.resetTime) {
      this.attempts.delete(identifier);
      return false;
    }

    return entry.count >= this.maxAttempts;
  }

  /**
   * Record a failed attempt
   */
  recordFailedAttempt(identifier: string): void {
    const now = Date.now();
    const entry = this.attempts.get(identifier);

    if (!entry || now > entry.resetTime) {
      // New window or expired entry
      this.attempts.set(identifier, {
        count: 1,
        resetTime: now + this.windowMs,
        blocked: false
      });
    } else {
      // Increment count
      entry.count++;
      
      // Block if exceeded max attempts
      if (entry.count >= this.maxAttempts) {
        entry.blocked = true;
        entry.resetTime = now + this.blockDurationMs;
      }
    }
  }

  /**
   * Record a successful attempt (clears the record)
   */
  recordSuccessfulAttempt(identifier: string): void {
    this.attempts.delete(identifier);
  }

  /**
   * Get remaining attempts before rate limit
   */
  getRemainingAttempts(identifier: string): number {
    const entry = this.attempts.get(identifier);
    if (!entry || Date.now() > entry.resetTime) {
      return this.maxAttempts;
    }
    return Math.max(0, this.maxAttempts - entry.count);
  }

  /**
   * Get time until rate limit resets (in seconds)
   */
  getResetTime(identifier: string): number {
    const entry = this.attempts.get(identifier);
    if (!entry) {
      return 0;
    }
    return Math.max(0, Math.ceil((entry.resetTime - Date.now()) / 1000));
  }
}

// Global rate limiter instances
export const authRateLimiter = new RateLimiter(5, 15 * 60 * 1000, 30 * 60 * 1000); // 5 attempts per 15 minutes, 30 minute block
export const generalRateLimiter = new RateLimiter(100, 60 * 1000, 5 * 60 * 1000); // 100 requests per minute, 5 minute block

/**
 * Get client IP address from request headers
 */
export function getClientIP(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  const cfConnectingIP = request.headers.get('cf-connecting-ip');
  
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  
  if (realIP) {
    return realIP;
  }
  
  if (cfConnectingIP) {
    return cfConnectingIP;
  }
  
  return 'unknown';
}