import { useEffect, useState, type CSSProperties } from 'react';
import { getAuditLogs, type AuditLogItem } from '@api/audit';
import { Card } from '@components/ui/Card';

const TABLE_GRID_COLS = 'minmax(140px, 1.1fr) minmax(100px, 0.9fr) minmax(100px, 0.85fr) minmax(100px, 0.85fr) 100px minmax(120px, 0.95fr)';

function truncate(v?: string | null, n = 10) {
  if (!v) return '—';
  return v.length > n ? `${v.slice(0, n)}…` : v;
}

function riskBadgeStyle(risk: number | null) {
  if (risk === null) {
    return { label: '—' as const, bg: '#0f172a', fg: '#e5e7eb' };
  }
  if (risk >= 0.7) {
    return { label: `High (${risk.toFixed(2)})` as const, bg: '#b91c1c', fg: '#fee2e2' };
  }
  if (risk >= 0.3) {
    return { label: `Medium (${risk.toFixed(2)})` as const, bg: '#b45309', fg: '#fffbeb' };
  }
  return { label: `Benign (${risk.toFixed(2)})` as const, bg: '#166534', fg: '#dcfce7' };
}

