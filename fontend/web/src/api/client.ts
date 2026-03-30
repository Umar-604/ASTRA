// Use same origin (relative) when unset so the app works behind the Go gateway (e.g. :9000 → proxy to :8000).
// Set VITE_API_BASE_URL to the API origin only when the frontend is served from a different host/port.
const BASE_URL =
  (typeof import.meta.env.VITE_API_BASE_URL === 'string' && import.meta.env.VITE_API_BASE_URL.trim() !== '')
    ? import.meta.env.VITE_API_BASE_URL.replace(/\/+$/, '')
    : '';

// In-memory a

// In-memory access token (clears on reload by design)
let ACCESS_TOKEN: string | null = null;

export function setAuthToken(token: string) {
  ACCESS_TOKEN = token || null;
}

export function setAuthToken(token: string) {
  ACCESS_TOKEN = token || null;
}

export function getAuthToken(): string | null {
  return ACCESS_TOKEN;
}

export function clearAuthToken() {
  ACCESS_TOKEN = null;
}

function authHeaders(init?: RequestInit) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string>),
  };
  const token = ACCESS_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: authHeaders(init),
    credentials: 'include', // allow HttpOnly refresh cookie participation
  });
  if (res.status === 401) {
    // Graceful 401 handling: redirect to login
    try {
      clearAuthToken();
    } catch {}
    if (typeof window !== 'undefined') {
      window.location.assign('/login');
    }
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    // Reduce attack surface: do not surface backend error bodies to UI
    const message = res.status === 401 ? 'Unauthorized' : res.status === 403 ? 'Forbidden' : 'Request failed';
    throw new Error(message);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    return (await res.json()) as T;
  }
  // Fallback when server returns empty/no-json body
  return undefined as unknown as T;
}

export const apiClient = {
  BASE_URL,
  get: <T>(path: string) => request<T>(path, { method: 'GET' }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
