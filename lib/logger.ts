/**
 * Secure logging utility
 * Provides structured logging with different levels and prevents sensitive data exposure
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: Record<string, any>;
  userId?: string;
  sessionId?: string;
}

/**
 * Sensitive data patterns to redact from logs
 */
const SENSITIVE_PATTERNS = [
  /password/i,
  /token/i,
  /secret/i,
  /key/i,
  /auth/i,
  /session/i,
  /cookie/i,
  /csrf/i,
];

/**
 * Redact sensitive information from objects
 */
function redactSensitiveData(obj: any): any {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(redactSensitiveData);
  }

  const redacted: any = {};
  for (const [key, value] of Object.entries(obj)) {
    const isSensitive = SENSITIVE_PATTERNS.some(pattern => pattern.test(key));
    
    if (isSensitive) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      redacted[key] = redactSensitiveData(value);
    } else {
      redacted[key] = value;
    }
  }

  return redacted;
}

/**
 * Format log entry for output
 */
function formatLogEntry(entry: LogEntry): string {
  const { timestamp, level, message, context, userId, sessionId } = entry;
  
  let logString = `[${timestamp}] ${level.toUpperCase()}: ${message}`;
  
  if (userId) {
    logString += ` | User: ${userId}`;
  }
  
  if (sessionId) {
    logString += ` | Session: ${sessionId.substring(0, 8)}...`;
  }
  
  if (context && Object.keys(context).length > 0) {
    const redactedContext = redactSensitiveData(context);
    logString += ` | Context: ${JSON.stringify(redactedContext)}`;
  }
  
  return logString;
}

/**
 * Logger class with different log levels
 */
class Logger {
  private isDevelopment = process.env.NODE_ENV === 'development';
  private logLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || 'info';
  
  private shouldLog(level: LogLevel): boolean {
    const levels: Record<LogLevel, number> = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3,
    };
    
    return levels[level] >= levels[this.logLevel];
  }
  
  private log(level: LogLevel, message: string, context?: Record<string, any>, userId?: string, sessionId?: string): void {
    if (!this.shouldLog(level)) {
      return;
    }
    
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
      userId,
      sessionId,
    };
    
    const formattedLog = formatLogEntry(entry);
    
    // In development, use console methods
    if (this.isDevelopment) {
      switch (level) {
        case 'debug':
          console.debug(formattedLog);
          break;
        case 'info':
          console.info(formattedLog);
          break;
        case 'warn':
          console.warn(formattedLog);
          break;
        case 'error':
          console.error(formattedLog);
          break;
      }
    } else {
      // In production, you might want to send logs to a service
      // For now, we'll use console.log for all levels
      console.log(formattedLog);
    }
  }
  
  debug(message: string, context?: Record<string, any>, userId?: string, sessionId?: string): void {
    this.log('debug', message, context, userId, sessionId);
  }
  
  info(message: string, context?: Record<string, any>, userId?: string, sessionId?: string): void {
    this.log('info', message, context, userId, sessionId);
  }
  
  warn(message: string, context?: Record<string, any>, userId?: string, sessionId?: string): void {
    this.log('warn', message, context, userId, sessionId);
  }
  
  error(message: string, context?: Record<string, any>, userId?: string, sessionId?: string): void {
    this.log('error', message, context, userId, sessionId);
  }
  
  /**
   * Log authentication events
   */
  authEvent(event: string, userId?: string, context?: Record<string, any>): void {
    this.info(`Auth: ${event}`, context, userId);
  }
  
  /**
   * Log security events
   */
  securityEvent(event: string, context?: Record<string, any>, userId?: string): void {
    this.warn(`Security: ${event}`, context, userId);
  }
  
  /**
   * Log rate limiting events
   */
  rateLimitEvent(event: string, identifier: string, context?: Record<string, any>): void {
    this.warn(`RateLimit: ${event}`, { ...context, identifier });
  }
}

// Export singleton logger instance
export const logger = new Logger();

// Export types for external use
export type { LogLevel, LogEntry };