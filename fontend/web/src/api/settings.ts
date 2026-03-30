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
