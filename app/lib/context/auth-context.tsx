'use client';

import { createContext, useContext, useEffect, useState, useMemo } from 'react';
import { createClient } from '@/lib/supabase/client';
import type { Session, User } from '@supabase/supabase-js';
import { logger } from '@/lib/logger';

/**
 * Authentication context interface defining the shape of auth state and methods
 * Provides centralized authentication state management across the application
 */

const AuthContext = createContext<{ 
  /** Current Supabase session object containing auth tokens and metadata */
  session: Session | null;
  /** Current authenticated user object from Supabase, null if not authenticated */
  user: User | null;
  /** Function to sign out the current user and clear session */
  signOut: () => void;
  /** Loading state indicator for authentication operations */
  loading: boolean;
}>({ 
  session: null, 
  user: null,
  signOut: () => {},
  loading: true,
});

/**
 * Authentication provider component that wraps the application
 * Manages user authentication state and provides it to child components
 * Handles initial user loading and auth state changes via Supabase listeners
 * 
 * @param children - React components that need access to auth context
 */
export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  // Memoized Supabase client to prevent unnecessary re-instantiation
  const supabase = useMemo(() => createClient(), []);
  
  // Authentication state management
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    
    /**
     * Fetches the current user on component mount
     * Handles initial authentication state setup
     */
    const getUser = async () => {
      const { data, error } = await supabase.auth.getUser();
      
      // Log any errors during user fetching for debugging
      if (error) {
        logger.error('Error fetching user during initialization', { error: error.message });
      }
      
      // Only update state if component is still mounted (prevents memory leaks)
      if (mounted) {
        setUser(data.user ?? null);
        setSession(null); // Session will be set by auth listener
        setLoading(false);
        logger.authEvent('Initial user loaded', data.user?.id);
      }
    };

    getUser();

    /**
     * Set up auth state change listener
     * Responds to login, logout, token refresh, and other auth events
     */
    const { data: authListener } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
      // Note: Do not set loading to false here, only after initial load
      logger.authEvent(`Auth state changed: ${_event}`, session?.user?.id, { event: _event });
    });

    /**
     * Cleanup function to prevent memory leaks
     * Unsubscribes from auth listener and marks component as unmounted
     */
    return () => {
      mounted = false;
      authListener.subscription.unsubscribe();
    };
  }, [supabase]);

  /**
   * Signs out the current user and clears authentication state
   * Triggers auth state change listener which will update context state
   */
  const signOut = async () => {
    await supabase.auth.signOut();
  };

  return (
    <AuthContext.Provider value={{ session, user, signOut, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Custom hook to access authentication context
 * Must be used within an AuthProvider component tree
 * 
 * @returns Authentication context containing user, session, signOut function, and loading state
 * @throws Error if used outside of AuthProvider
 */
export const useAuth = () => useContext(AuthContext);
