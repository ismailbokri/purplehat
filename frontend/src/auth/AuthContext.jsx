import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { apiFetch, clearSession, getStoredUser, getToken, setSession } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(() => getStoredUser());
  const [loading, setLoading] = useState(true);

  // On mount, validate the stored JWT by hitting /auth/me. If invalid → clear.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!getToken()) {
        if (!cancelled) setLoading(false);
        return;
      }
      try {
        const me = await apiFetch('/auth/me');
        if (!cancelled) setUser(me);
      } catch {
        if (!cancelled) setUser(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const login = useCallback(async (email, password) => {
    const data = await apiFetch('/auth/login', {
      method: 'POST',
      body: { email, password },
    });
    setSession({
      token: data.access_token,
      user:  { id: data.user_id, email: data.email, role: data.role },
    });
    setUser({ id: data.user_id, email: data.email, role: data.role });
    return data;
  }, []);

  const register = useCallback(async (email, password, profile = {}) => {
    // `profile` carries optional fields (full_name, phone, location, …).
    // The backend accepts email + password and ignores unknown fields.
    const data = await apiFetch('/auth/register', {
      method: 'POST',
      body: { email, password, ...profile },
    });
    setSession({
      token: data.access_token,
      user:  { id: data.user_id, email: data.email, role: data.role },
    });
    setUser({ id: data.user_id, email: data.email, role: data.role });
    return data;
  }, []);

  const logout = useCallback(() => {
    clearSession();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, register, logout, isAdmin: user?.role === 'admin' }),
    [user, loading, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
