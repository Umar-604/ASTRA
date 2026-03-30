import { apiClient } from './client';

export interface AdminSettings {
  ai_models: {
    model_name: string;
    task: string;
    model_dir: string;
    decision_threshold: number;
  };
  alert_thresholds: {
    cumulative_risk_threshold: number;
  };
  blockchain: {
    fabric_gateway_url: string;
  };
  ingest: {
    nats_url: string;
    nats_subject: string;
  };
}


export interface AdminSettingsUpdate {
  cumulative_risk_threshold?: number;
  decision_threshold?: number;
  fabric_gateway_url?: string;
  model_name?: string;
  task?: string;
  model_dir?: string;

  export function getAdminSettings(): Promise<AdminSettings> {
  return apiClient.get<AdminSettings>('/admin/settings');
}

export function updateAdminSettings(partial: AdminSettingsUpdate): Promise<AdminSettings> {
  return apiClient.put<AdminSettings>('/admin/settings', partial);
}
  nats_url?: string;
  nats_subject?: string;
}