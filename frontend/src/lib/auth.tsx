// The signed-in session, shared by every page.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router';

import {
  api,
  ApiError,
  isAbort,
  roleIncludes,
  setCsrfToken,
  setUnauthorizedHandler,
  toApiError,
  type Role,
  type SessionInfo,
} from '../api/client';
import { ErrorState, Loading } from '../components/States';

type AuthState =
  | { status: 'loading' }
  | { status: 'signed-out' }
  | { status: 'error'; error: ApiError }
  | { status: 'signed-in'; session: SessionInfo };

interface AuthContextValue {
  state: AuthState;
  /** Stores a session returned by sign-in or a password change. */
  signedIn: (session: SessionInfo) => void;
  /** Ends the session on the server and forgets it. */
  signOut: () => Promise<void>;
  retry: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    api.session(controller.signal).then(
      (session) => {
        setCsrfToken(session.csrf_token);
        setState({ status: 'signed-in', session });
      },
      (error: unknown) => {
        if (isAbort(error)) return;
        const apiError = toApiError(error);
        setState(apiError.status === 401 ? { status: 'signed-out' } : { status: 'error', error: apiError });
      },
    );
    return () => controller.abort();
  }, [attempt]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken(null);
      setState({ status: 'signed-out' });
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const signedIn = useCallback((session: SessionInfo) => {
    setCsrfToken(session.csrf_token);
    setState({ status: 'signed-in', session });
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setCsrfToken(null);
      setState({ status: 'signed-out' });
    }
  }, []);

  const retry = useCallback(() => {
    setState({ status: 'loading' });
    setAttempt((n) => n + 1);
  }, []);

  const value = useMemo(() => ({ state, signedIn, signOut, retry }), [state, signedIn, signOut, retry]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth needs an AuthProvider');
  return value;
}

/** The signed-in session, or null. */
export function useSession(): SessionInfo | null {
  const { state } = useAuth();
  return state.status === 'signed-in' ? state.session : null;
}

/** Whether the signed-in account's role includes `required`. */
export function useCan(required: Role): boolean {
  return roleIncludes(useSession()?.user.role, required);
}

/** Where to go after signing in: only paths on this site. */
export function safeNext(next: string | null): string {
  return next && next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
}

/** Shows `children` only to a signed-in account; others go to sign-in. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { state, retry } = useAuth();
  const location = useLocation();
  if (state.status === 'loading') return <Loading label="Checking your session…" />;
  if (state.status === 'error') {
    return (
      <main id="main">
        <ErrorState error={state.error} onRetry={retry} title="Could not reach the server" />
      </main>
    );
  }
  if (state.status === 'signed-out') {
    const next = `${location.pathname}${location.search}`;
    return <Navigate to={`/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <>{children}</>;
}
