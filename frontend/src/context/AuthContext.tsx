import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import {
  fetchMeRequest,
  getAccessToken,
  loginRequest,
  logoutRequest,
  refreshSessionRequest,
  registerRequest,
  setAccessToken,
} from '../lib/api';
import type { AuthResponse, AuthUser, JwtMeta } from '../types/auth';

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';

interface AuthContextValue {
  status: AuthStatus;
  user: AuthUser | null;
  jwtMeta: JwtMeta | null;
  login: (payload: { email: string; password: string }) => Promise<void>;
  register: (payload: { name: string; email: string; password: string }) => Promise<void>;
  refreshSession: () => Promise<AuthResponse | null>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [jwtMeta, setJwtMeta] = useState<JwtMeta | null>(null);

  const applySession = useCallback((session: AuthResponse) => {
    setAccessToken(session.accessToken);
    setUser(session.user);
    setJwtMeta(session.jwt);
    setStatus('authenticated');
  }, []);

  const clearSession = useCallback(() => {
    setAccessToken(null);
    setUser(null);
    setJwtMeta(null);
    setStatus('unauthenticated');
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function bootstrapSession() {
      try {
        // Jika access token sudah ada di memori (mis. saat StrictMode remount), cukup verifikasi /api/me
        if (getAccessToken()) {
          const me = await fetchMeRequest();
          if (!cancelled) {
            setUser(me.user);
            setJwtMeta(me.jwt);
            setStatus('authenticated');
          }
          return;
        }

        const refreshed = await refreshSessionRequest();
        if (!cancelled) {
          if (refreshed) {
            applySession(refreshed);
          } else {
            clearSession();
          }
        }
      } catch {
        if (!cancelled) {
          clearSession();
        }
      }
    }

    void bootstrapSession();

    return () => {
      cancelled = true;
    };
  }, [applySession, clearSession]);

  const login = useCallback(
    async (payload: { email: string; password: string }) => {
      const session = await loginRequest(payload);
      applySession(session);
    },
    [applySession],
  );

  const register = useCallback(
    async (payload: { name: string; email: string; password: string }) => {
      const session = await registerRequest(payload);
      applySession(session);
    },
    [applySession],
  );

  const refreshSession = useCallback(async () => {
    const refreshed = await refreshSessionRequest();
    if (refreshed) {
      applySession(refreshed);
      return refreshed;
    }
    clearSession();
    return null;
  }, [applySession, clearSession]);

  const logout = useCallback(async () => {
    await logoutRequest();
    clearSession();
  }, [clearSession]);

  return (
    <AuthContext.Provider
      value={{
        status,
        user,
        jwtMeta,
        login,
        register,
        refreshSession,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth harus digunakan di dalam AuthProvider.');
  }
  return ctx;
}
