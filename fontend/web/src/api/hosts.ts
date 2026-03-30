import { apiClient } from './client';
import { getAlerts, type AlertsQuery } from './alerts';
import type { HostItem, HostDetail } from '@app-types/api';

export async function getHosts() {
  try {
    return await apiClient.get<{ items: HostItem[] }>('/hosts');
  } catch {
     // Fallback: derive list from alerts if /hosts not available
    const alerts = await getAlerts({ limit: 500 });
    const map = new Map<string, HostItem>();
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    (alerts.items || []).forEach((a) => {
      const id = a.host_id || 'unknown';
      const ts = a['@timestamp'];
      const t = new Date(ts).getTime();
      if (!map.has(id)) {
        map.set(id, {
          host_id: id,
          hostname: id,
          os: 'unknown',
          last_seen: ts,
          first_seen: ts,
          events_24h: 0,
          health_status: undefined,
          risk_score: null,
          active_alerts: 0
        });
      }
      const item = map.get(id)!;
      item.active_alerts = (item.active_alerts || 0) + 1;
      if (t > new Date(item.last_seen).getTime()) item.last_seen = ts;
      const first = new Date(item.first_seen!).getTime();
      if (t < first) item.first_seen = ts;
      if (now - t < oneDay) item.events_24h = (item.events_24h ?? 0) + 1;
      const ageMin = (now - new Date(item.last_seen).getTime()) / 60000;
      if (ageMin < 5) item.health_status = 'healthy';
      else if (ageMin < 60) item.health_status = 'warning';
      else item.health_status = 'stale';
    });
    return { items: Array.from(map.values()) };
  }
}