import { apiClient } from './client';
import { getAlerts, type AlertsQuery } from './alerts';
import type { HostItem, HostDetail } from '@app-types/api';

export async function getHosts() {
  try {
    return await apiClient.get<{ items: HostItem[] }>('/hosts');
  } catch {