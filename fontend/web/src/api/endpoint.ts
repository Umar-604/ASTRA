import { apiClient } from './client';
import type { AlertItem, EventSummary, VerifyResult } from '@app-types/api';

export const endpoints = {
  getAlerts: (params?: { severity?: string; since?: string; until?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.severity) q.set('severity', params.severity);
    if (params?.since) q.set('since', params.since);
    if (params?.until) q.set('until', params.until);
    if (params?.limit) q.set('limit', String(params.limit));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return apiClient.http<{ items: AlertItem[] }>(`/alerts${qs}`);