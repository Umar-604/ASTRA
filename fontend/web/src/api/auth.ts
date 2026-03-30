import { apiClient, setAuthToken } from './client';

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export async function login(email: string, password: string) {
  const res = await apiClient.post<TokenPair>('/auth/login', { email, password });
  // Store access in memory; refresh is expected to be set as HttpOnly cookie by server (if supported).
  setAuthToken(res.access_token);
  return res;
}

export async function signup(email: string, password: string, role?: string) {
  const res = await apiClient.post<TokenPair>('/auth/signup', { email, password, role });
  setAuthToken(res.access_token);
  return res;
}