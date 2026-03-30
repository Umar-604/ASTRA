import { apiClient } from './client';
import type { AlertItem } from '@app-types/api';

export interface AlertsQuery {
  severity?: string;
  since?: string;
  until?: string;
  limit?: number;
  summary?: boolean;
}

export async function getAlerts(params?: AlertsQuery) {
  const q = new URLSearchParams();
  if (params?.severity) q.set('severity', params.severity);
  if (params?.since) q.set('since', params.since);
  if (params?.until) q.set('until', params.until);
  if (params?.limit) q.set('limit', String(params.limit));
  if (params?.summary) q.set('summary', 'true');
  const qs = q.toString() ? `?${q.toString()}` : '';
  return apiClient.get<{ items: AlertItem[] }>(`/alerts${qs}`);
}


export type AcknowledgeStatus = 'acknowledged' | 'resolved';

export async function acknowledgeAlert(eventId: string, status: AcknowledgeStatus) {
  return apiClient.patch<{ event_id: string; status: string; acknowledged_by: string }>(
    `/alerts/${encodeURIComponent(eventId)}/acknowledge`,
    { status }
  );
}
