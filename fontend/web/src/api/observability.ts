import { apiClient } from './client';

export interface OverviewResponse {
  window?: string;
  app_logs?: {
    total?: number;
    by_level?: Record<string, number>;
  };
  events?: {
    total?: number;
    by_severity?: Record<string, number>;
    by_event_type?: Record<string, number>;
  };
}