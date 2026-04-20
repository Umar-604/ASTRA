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
