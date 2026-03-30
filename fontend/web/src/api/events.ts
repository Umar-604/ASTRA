import { apiClient } from './client';
import type { EventSummary } from '@app-types/api';

export function getEvent(eventId: string) {
  return apiClient.get<EventSummary>(`/events/${encodeURIComponent(eventId)}`);
}

