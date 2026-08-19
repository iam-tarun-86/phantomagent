/**
 * Operator authentication.
 *
 * The backend requires a bearer token on every /api route and on the WebSocket.
 * Credentials are exchanged for that token at /api/auth/login; the token lives in
 * sessionStorage so it dies with the tab rather than persisting to disk.
 */

const STORAGE_KEY = 'phantom_token';

// Same-origin by default so the Vite proxy (and any real deployment) works. Override
// with VITE_API_URL when the API lives elsewhere.
export const API_BASE = import.meta.env.VITE_API_URL ?? '/api';

export function getToken() {
    try {
        return sessionStorage.getItem(STORAGE_KEY);
    } catch {
        return null;
    }
}

function setToken(token) {
    try {
        if (token) sessionStorage.setItem(STORAGE_KEY, token);
        else sessionStorage.removeItem(STORAGE_KEY);
    } catch {
        /* private browsing — the in-memory token still works for this session */
    }
}

export function isAuthenticated() {
    return !!getToken();
}

export async function login(username, password) {
    const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
        throw new Error(response.status === 401 ? 'Access denied' : 'Authentication service unavailable');
    }

    const data = await response.json();
    if (!data.token) throw new Error('Malformed authentication response');

    setToken(data.token);
    return data;
}

export function logout() {
    setToken(null);
}

/** fetch() with the bearer token attached. Throws on 401 so callers can force re-login. */
export async function authFetch(path, options = {}) {
    const token = getToken();
    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...options.headers,
        },
    });

    if (response.status === 401) {
        logout();
        throw new Error('Session expired — please log in again');
    }
    return response;
}
