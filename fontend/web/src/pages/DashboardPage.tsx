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
        });
        const criticalCount = (bySevRecent['CRITICAL'] || 0) + (bySevRecent['HIGH'] || 0);
        setMetrics({ critical: criticalCount, endpoints: uniqueHosts.size, ai: aiCount, secured });
        // Fallback: if threats/summary didn't provide severity counts, use counts from alerts
        if (!severitySet && items.length > 0) {
          setSeverityData({
            critical: (bySevRecent['CRITICAL'] || 0) + (bySevRecent['HIGH'] || 0),
            high: bySevRecent['HIGH'] || 0,
            medium: bySevRecent['MEDIUM'] || 0
          });
        }
      }
      if (latestHigh.status === 'fulfilled') {
        setLatest(latestHigh.value.items || []);
      }
      const apiSeries = dashboard.status === 'fulfilled' && Array.isArray(dashboard.value?.series) ? dashboard.value.series : null;
      const expectedLen = chartTimeRange === '1h' ? 6 : chartTimeRange === '24h' ? 24 : 7;
      const alertsItems = alertsRange.status === 'fulfilled' ? alertsRange.value?.items ?? [] : [];
      const defaultSeries = getDefaultSeriesForRange(chartTimeRange);

      // Normalize API series: ensure correct length and numeric fields for Chart.js
      const normalize = (arr: DashboardMetricsPoint[]) =>
        arr.map((p) => ({
          date: String(p?.date ?? ''),
          criticalAlerts: Number(p?.criticalAlerts) || 0,
          aiDetections: Number(p?.aiDetections) || 0,
          logsSecured: Number(p?.logsSecured) || 0,
          totalEvents: Number(p?.totalEvents) || 0
        }));
      let nextSeries: DashboardMetricsPoint[];
      if (apiSeries && apiSeries.length >= expectedLen) {
        nextSeries = normalize(apiSeries.slice(-expectedLen));
      } else if (apiSeries && apiSeries.length > 0) {
        const padded = defaultSeries.map((d, i) => (apiSeries[i] ? { ...d, ...normalize([apiSeries[i]])[0] } : d));
        nextSeries = padded;
      } else if (alertsItems.length > 0) {
        nextSeries = buildSeriesFromAlerts(alertsItems, chartTimeRange);
      } else {
        nextSeries = defaultSeries;
      }
      setDashboardSeries(nextSeries);
      if (typeof window !== 'undefined') {
        console.log('[Dashboard] Chart series source:', (apiSeries?.length ?? 0) >= expectedLen ? 'API' : alertsItems.length ? 'alerts' : 'default', '| points:', nextSeries.length);
      }
    });
    return () => { mounted = false; };
  }, [chartTimeRange]);

  // Poll chart data when viewing 24h or 1h for near real-time updates
  useEffect(() => {
    if (chartTimeRange !== '24h' && chartTimeRange !== '1h') return;
    const expectedLen = chartTimeRange === '1h' ? 6 : 24;
    const intervalMs = chartTimeRange === '1h' ? 60_000 : 90_000;
    const t = setInterval(() => {
      getDashboardMetrics(chartTimeRange).then((res) => {
        const raw = res?.series;
        if (Array.isArray(raw) && raw.length >= expectedLen) {
          setDashboardSeries(raw.slice(-expectedLen).map((p) => ({
            date: String(p?.date ?? ''),
            criticalAlerts: Number(p?.criticalAlerts) || 0,
            aiDetections: Number(p?.aiDetections) || 0,
            logsSecured: Number(p?.logsSecured) || 0,
            totalEvents: Number(p?.totalEvents) || 0
          })));
        }
      }).catch(() => {});
    }, intervalMs);
    return () => clearInterval(t);
  }, [chartTimeRange]);

  const totalAlerts24h = overview?.events?.total ?? 0;
  const activeThreats = overview?.events?.by_severity?.HIGH ?? 0;
  // Healthy hosts: derived from summary if available; otherwise N/A
  const healthyHosts = useMemo(() => {
    const hosts = summary?.hosts_total ?? null;
    const unhealthy = summary?.hosts_unhealthy ?? 0;
    return hosts != null ? Math.max(0, hosts - unhealthy) : 'N/A';
  }, [summary]);
  // Integrity summary (verified/pending/tampered) from summary if available
  const integrity = {
    verified: summary?.integrity?.verified ?? 0,
    pending: summary?.integrity?.pending ?? 0,
    tampered: summary?.integrity?.tampered ?? 0
  };

  // Time-series: prefer from summary; else synthesize a flat series
  const series: SeriesPoint[] = (summary?.timeseries as SeriesPoint[]) || [
    { t: 't-4', v: Math.max(0, Math.floor(totalAlerts24h / 5)) },
    { t: 't-3', v: Math.max(0, Math.floor(totalAlerts24h / 5)) },
    { t: 't-2', v: Math.max(0, Math.floor(totalAlerts24h / 5)) },
    { t: 't-1', v: Math.max(0, Math.floor(totalAlerts24h / 5)) },
    { t: 't', v: Math.max(0, totalAlerts24h - Math.floor((totalAlerts24h / 5) * 4)) }
  ];

  // Build charts with Chart.js: multi-line (Critical Alerts, AI Detections, Logs Secured)
  useEffect(() => {
    let mounted = true;
    const styles = getComputedStyle(document.body);
    const textColor = styles.getPropertyValue('--fg').trim() || '#0f172a';
    const gridColor = styles.getPropertyValue('--border-color').trim() || '#e2e8f0';
    const data = dashboardSeries.length ? dashboardSeries : getDefaultSeriesForRange(chartTimeRange);
    const labels = data.map((p) => String(p?.date ?? ''));
    const criticalAlerts = data.map((p) => Number(p?.criticalAlerts) || 0);
    const aiDetections = data.map((p) => Number(p?.aiDetections) || 0);
    const logsSecured = data.map((p) => Number(p?.logsSecured) || 0);
    const totalEvents = data.map((p) => Number(p?.totalEvents) || 0);
    const maxVal = Math.max(0, ...criticalAlerts, ...aiDetections, ...logsSecured, ...totalEvents);

    (async () => {
      const mod = await import('chart.js/auto').catch(() => null as any);
      if (!mounted || !mod) return;
      const Chart: any = (mod as any).default || (mod as any);
      chartsRef.current.line?.destroy();
      chartsRef.current.donut?.destroy();

