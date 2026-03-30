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
