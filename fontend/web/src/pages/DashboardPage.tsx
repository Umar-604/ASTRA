import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getOverview, getDashboardMetrics, type OverviewResponse, type DashboardMetricsPoint, type ChartTimeRange } from '@api/observability';
import { getAlerts } from '@api/alerts';
import { Card } from '@components/ui/Card';
import { useRef } from 'react';
import type { AlertItem } from '@app-types/api';
import { apiClient } from '@api/client';
import { isAiDetection } from '../utils/alertScore';

type SeriesPoint = { t: string; v: number };

function getDefaultSeriesForRange(range: ChartTimeRange): DashboardMetricsPoint[] {
  const out: DashboardMetricsPoint[] = [];
  const now = new Date();
  if (range === '1h') {
    // Last 6 x 10min slots ending at now (align with backend)
    for (let i = 0; i < 6; i++) {
      const d = new Date(now.getTime() - (50 - i * 10) * 60 * 1000);
      d.setMinutes(Math.floor(d.getMinutes() / 10) * 10, 0, 0);
      out.push({ date: `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`, criticalAlerts: 0, aiDetections: 0, logsSecured: 0, totalEvents: 0 });
    }
  } else if (range === '24h') {
    for (let i = 0; i < 24; i++) {
      const d = new Date(now);
      d.setHours(d.getHours() - 23 + i, 0, 0, 0);
      out.push({ date: `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:00`, criticalAlerts: 0, aiDetections: 0, logsSecured: 0, totalEvents: 0 });
    }
  } else {
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      out.push({ date: d.toISOString().slice(0, 10), criticalAlerts: 0, aiDetections: 0, logsSecured: 0, totalEvents: 0 });
    }
  }
  return out;
}

function buildSeriesFromAlerts(items: AlertItem[], range: ChartTimeRange): DashboardMetricsPoint[] {
  const labels = getDefaultSeriesForRange(range).map((p) => p.date);
  const byKey: Record<string, { criticalAlerts: number; aiDetections: number; logsSecured: number; totalEvents: number }> = {};
  labels.forEach((d) => {
    byKey[d] = { criticalAlerts: 0, aiDetections: 0, logsSecured: 0, totalEvents: 0 };
  });
  const nowMs = range === '1h' ? Date.now() : 0;
  const oneHourAgo = range === '1h' ? nowMs - 60 * 60 * 1000 : 0;
  items.forEach((i) => {
    const ts = (i['@timestamp'] || (i as any).timestamp || '').toString();
    if (!ts) return;
    const d = new Date(ts);
    let key: string;
    if (range === '1h') {
      const t = d.getTime();
      if (t < oneHourAgo || t >= nowMs) return;
      const slot = Math.floor(d.getMinutes() / 10) * 10;
      key = `${String(d.getHours()).padStart(2, '0')}:${String(slot).padStart(2, '0')}`;
    } else if (range === '24h') {
      key = `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:00`;
    } else {
      key = ts.slice(0, 10);
    }
    if (!(key in byKey)) return;
    byKey[key].totalEvents += 1;
    const sev = (i.severity || '').toUpperCase();
    if (sev === 'HIGH' || sev === 'CRITICAL') byKey[key].criticalAlerts += 1;
    if (isAiDetection(i)) byKey[key].aiDetections += 1;
    if ((i.integrity_status || '').toString().toUpperCase() === 'VERIFIED') byKey[key].logsSecured += 1;
  });
  return labels.map((date) => ({ date, ...byKey[date] }));
}

export function DashboardPage() {
  const navigate = useNavigate();
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [summary, setSummary] = useState<any>(null);
  const [latest, setLatest] = useState<AlertItem[]>([]);
  const [metrics, setMetrics] = useState<{ critical: number; endpoints: number; ai: number; secured: number }>({
    critical: 0,
    endpoints: 0,
    ai: 0,
    secured: 0
  });
  const [chartTimeRange, setChartTimeRange] = useState<ChartTimeRange>('7d');
  const [dashboardSeries, setDashboardSeries] = useState<DashboardMetricsPoint[]>(() => getDefaultSeriesForRange('7d'));
  const [severityData, setSeverityData] = useState<{ critical: number; high: number; medium: number }>({
    critical: 0,
    high: 0,
    medium: 0
  });
  const lineRef = useRef<HTMLCanvasElement | null>(null);
  const donutRef = useRef<HTMLCanvasElement | null>(null);
  const chartsRef = useRef<{ line?: any; donut?: any }>({});

  const sinceForRange = (range: ChartTimeRange) => {
    const d = new Date();
    if (range === '1h') d.setHours(d.getHours() - 1, 0, 0, 0);
    else if (range === '24h') d.setHours(d.getHours() - 24, 0, 0, 0);
    else { d.setDate(d.getDate() - 6); d.setHours(0, 0, 0, 0); }
    return d.toISOString();
  };

  useEffect(() => {
    let mounted = true;
    const since24h = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    const since7d = sinceForRange('7d');
    Promise.allSettled([
      getOverview(),
      apiClient.get<{ total?: number; by_severity?: Record<string, number>; by_ai_label?: Record<string, number> }>(
        '/ui/threats/summary'
      ),
      getAlerts({ since: since24h, limit: 500 }),
      getAlerts({ severity: 'HIGH', since: since24h, limit: 3 }),
      getDashboardMetrics(chartTimeRange),
      getAlerts({ since: sinceForRange(chartTimeRange), limit: 2000 })
    ]).then((results) => {
      if (!mounted) return;
      const [ov, sev, recent, latestHigh, dashboard, alertsRange] = results;
      const apiBase = apiClient.BASE_URL || '(same origin)';
      const dashboardStatus = dashboard.status === 'fulfilled' ? `OK (${Array.isArray((dashboard as PromiseFulfilledResult<any>).value?.series) ? (dashboard as PromiseFulfilledResult<any>).value.series.length : 0} points)` : `Failed: ${(dashboard as PromiseRejectedResult).reason?.message ?? 'network/error'}`;
      const alertsStatus = alertsRange.status === 'fulfilled' ? `OK (${(alertsRange as PromiseFulfilledResult<any>).value?.items?.length ?? 0} items)` : `Failed: ${(alertsRange as PromiseRejectedResult).reason?.message ?? 'network/error'}`;
      if (typeof window !== 'undefined') {
        console.log('[Dashboard] API base:', apiBase);
        console.log('[Dashboard] Dashboard metrics:', dashboard.status, dashboard.status === 'fulfilled' ? (dashboard as any).value?.series?.length : (dashboard as PromiseRejectedResult).reason);
        console.log('[Dashboard] Alerts:', alertsRange.status, alertsRange.status === 'fulfilled' ? (alertsRange as any).value?.items?.length : (alertsRange as PromiseRejectedResult).reason);
      }
      if (ov.status === 'fulfilled') setOverview(ov.value);

      // Severity for donut: prefer /ui/threats/summary, fallback to alerts we already fetched
      let severitySet = false;
      const sevPayload = sev.status === 'fulfilled' ? (sev.value as { by_severity?: Record<string, number>; error?: string }) : null;
      if (sevPayload && !('error' in sevPayload && sevPayload.error)) {
        const bySev = sevPayload.by_severity || {};
        const total = (bySev['CRITICAL'] || 0) + (bySev['HIGH'] || 0) + (bySev['MEDIUM'] || 0);
        if (total > 0) {
          setSeverityData({
            critical: (bySev['CRITICAL'] || 0) + (bySev['HIGH'] || 0),
            high: bySev['HIGH'] || 0,
            medium: bySev['MEDIUM'] || 0
          });
          severitySet = true;
        }
      }
      if (recent.status === 'fulfilled') {
        const items = recent.value.items || [];
        const uniqueHosts = new Set(items.map((i) => i.host_id).filter(Boolean));
        const aiCount = items.filter(isAiDetection).length;
        const secured = items.filter((i) => (i.integrity_status || '').toUpperCase() === 'VERIFIED').length;
        const bySevRecent: Record<string, number> = {};
        items.forEach((i) => {
          const s = (i.severity || '').toUpperCase();
          bySevRecent[s] = (bySevRecent[s] || 0) + 1;
