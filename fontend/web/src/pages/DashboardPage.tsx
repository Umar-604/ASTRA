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

