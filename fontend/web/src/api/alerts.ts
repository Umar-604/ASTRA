import { apiClient } from './client';
import type { AlertItem } from '@app-types/api';

export interface AlertsQuery {
  severity?: string;
  since?: string;
  until?: string;
  limit?: number;
  summary?: boolean;
}