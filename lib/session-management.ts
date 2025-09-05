/**
 * Session management utility
 * Handles session timeouts, validation, and security features
 */

import { createClient } from '@/lib/supabase/server';
import { cookies } from 'next/headers';
import { logger } from './logger';

// Session configuration
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const SESSION_WARNING_MS = 5 * 60 * 1000; // 5 minutes before timeout
const MAX_IDLE_TIME_MS = 60 * 60 * 1000; // 1 hour max idle time

interface SessionInfo {
  userId: string;
  sessionId: string;
  lastActivity: number;
  createdAt: number;
  isValid: boolean;
}

/**
 * Get current session information
 */
export async function getCurrentSession(): Promise<SessionInfo | null> {
  try {
    const supabase = await createClient();
    const { data: { session }, error } = await supabase.auth.getSession();
    
    if (error || !session) {
      return null;
    }
    
    const cookieStore = await cookies();
    const lastActivity = parseInt(cookieStore.get('last-activity')?.value || '0');
    const createdAt = parseInt(cookieStore.get('session-created')?.value || Date.now().toString());
    
    return {
      userId: session.user.id,
      sessionId: session.access_token.substring(0, 16), // First 16 chars for logging
      lastActivity,
      createdAt,
      isValid: true
    };
  } catch (error) {
    logger.error('Error getting current session', { error });
    return null;
  }
}

/**
 * Update session activity timestamp
 */
export async function updateSessionActivity(): Promise<void> {
  try {
    const cookieStore = await cookies();
    const now = Date.now();
    
    cookieStore.set('last-activity', now.toString(), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: SESSION_TIMEOUT_MS / 1000,
    });
    
    // Set session created timestamp if it doesn't exist
    if (!cookieStore.get('session-created')?.value) {
      cookieStore.set('session-created', now.toString(), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: MAX_IDLE_TIME_MS / 1000,
      });
    }
  } catch (error) {
    logger.error('Error updating session activity', { error });
  }
}

/**
 * Check if session is expired or should be terminated
 */
export async function validateSession(): Promise<{ isValid: boolean; reason?: string }> {
  const session = await getCurrentSession();
  
  if (!session) {
    return { isValid: false, reason: 'No session found' };
  }
  
  const now = Date.now();
  
  // Check if session has been idle too long
  if (session.lastActivity && (now - session.lastActivity) > MAX_IDLE_TIME_MS) {
    logger.securityEvent('Session expired due to inactivity', {
      userId: session.userId,
      idleTime: now - session.lastActivity
    });
    return { isValid: false, reason: 'Session expired due to inactivity' };
  }
  
  // Check if session is too old (absolute timeout)
  if ((now - session.createdAt) > (24 * 60 * 60 * 1000)) { // 24 hours max
    logger.securityEvent('Session expired due to age', {
      userId: session.userId,
      sessionAge: now - session.createdAt
    });
    return { isValid: false, reason: 'Session expired due to age' };
  }
  
  return { isValid: true };
}

/**
 * Force session termination
 */
export async function terminateSession(reason: string): Promise<void> {
  try {
    const session = await getCurrentSession();
    const supabase = await createClient();
    
    if (session) {
      logger.securityEvent('Session terminated', {
        userId: session.userId,
        reason
      });
    }
    
    // Sign out from Supabase
    await supabase.auth.signOut();
    
    // Clear session cookies
    const cookieStore = await cookies();
    cookieStore.delete('last-activity');
    cookieStore.delete('session-created');
    
  } catch (error) {
    logger.error('Error terminating session', { error, reason });
  }
}

/**
 * Get session timeout warning info
 */
export async function getSessionTimeoutInfo(): Promise<{
  timeUntilWarning: number;
  timeUntilTimeout: number;
  shouldWarn: boolean;
  shouldTimeout: boolean;
} | null> {
  const session = await getCurrentSession();
  
  if (!session || !session.lastActivity) {
    return null;
  }
  
  const now = Date.now();
  const timeSinceActivity = now - session.lastActivity;
  const timeUntilWarning = SESSION_WARNING_MS - timeSinceActivity;
  const timeUntilTimeout = SESSION_TIMEOUT_MS - timeSinceActivity;
  
  return {
    timeUntilWarning,
    timeUntilTimeout,
    shouldWarn: timeUntilWarning <= 0 && timeUntilTimeout > 0,
    shouldTimeout: timeUntilTimeout <= 0
  };
}

/**
 * Extend session (refresh activity)
 */
export async function extendSession(): Promise<boolean> {
  try {
    const validation = await validateSession();
    
    if (!validation.isValid) {
      await terminateSession(validation.reason || 'Invalid session');
      return false;
    }
    
    await updateSessionActivity();
    
    const session = await getCurrentSession();
    if (session) {
      logger.authEvent('Session extended', session.userId);
    }
    
    return true;
  } catch (error) {
    logger.error('Error extending session', { error });
    return false;
  }
}

/**
 * Initialize session tracking for new sessions
 */
export async function initializeSession(): Promise<void> {
  try {
    const session = await getCurrentSession();
    
    if (session) {
      await updateSessionActivity();
      logger.authEvent('Session initialized', session.userId);
    }
  } catch (error) {
    logger.error('Error initializing session', { error });
  }
}