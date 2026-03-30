import { apiClient } from './client';
import type { VerifyResult } from '@app-types/api';

export function verifyIntegrity(eventId: string) {
  return apiClient.get<VerifyResult>(`/audit/verify?event_id=${encodeURIComponent(eventId)}`);
}

export function verifyIntegrityPost(eventId: string) {
  // Preferred business endpoint via POST; backend will not return raw hashes to UI
  return apiClient.post<VerifyResult>('/audit/verify', { event_id: eventId });
}