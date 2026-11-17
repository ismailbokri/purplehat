// Minimal fetch wrapper that attaches the JWT from localStorage and handles
// 401 by clearing the token and reloading the SPA so the router falls back
// to /login.

const TOKEN_KEY = 'pentest_jwt';
const USER_KEY  = 'pentest_user';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setSession({ token, user }) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function getStoredUser() {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export async function apiFetch(path, { method = 'GET', body, headers = {} } = {}) {
  const token = getToken();
  const finalHeaders = {
    'Content-Type': 'application/json',
    ...headers,
  };
  if (token) finalHeaders.Authorization = `Bearer ${token}`;

  const res = await fetch(path, {
    method,
    headers: finalHeaders,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  // A 401 on the login/register endpoints means "bad credentials", not an
  // expired session — let it fall through so the real backend message
  // ("Invalid email or password") surfaces inline on the form. Only an
  // authenticated request (one that carried a token) that comes back 401 is
  // a genuinely expired/invalid session worth clearing and redirecting.
  const isAuthAttempt = path.includes('/auth/login') || path.includes('/auth/register');
  if (res.status === 401 && !isAuthAttempt) {
    clearSession();
    // Hard reload so the router redirects to /login.
    if (window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
    throw new Error('Session expired — please log in again');
  }

  let payload = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    payload = await res.json().catch(() => null);
  }

  if (!res.ok) {
    const detail = payload?.detail || `HTTP ${res.status}`;
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
  }

  return payload;
}
