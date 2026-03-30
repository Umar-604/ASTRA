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

export interface DashboardMetricsPoint {
  date: string;
  criticalAlerts: number;
  aiDetections: number;
  logsSecured: number;
  totalEvents?: number;
}

export interface DashboardMetricsResponse {
  series: DashboardMetricsPoint[];
  window?: string;
  error?: string;
}

export function getOverview() {
  return apiClient.get<OverviewResponse>('/observability/overview');
}

export type ChartTimeRange = '1h' | '24h' | '7d';

export function getDashboardMetrics(rangeOrDays: ChartTimeRange | number = 7) {
  const param = typeof rangeOrDays === 'string' ? `range=${rangeOrDays}` : `range=7d&days=${rangeOrDays}`;
  return apiClient.get<DashboardMetricsResponse>(`/observability/dashboard-metrics?${param}`);
}

