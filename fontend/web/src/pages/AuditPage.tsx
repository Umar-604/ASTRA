import { useEffect, useState, type CSSProperties } from 'react';
import { getAuditLogs, type AuditLogItem } from '@api/audit';
import { Card } from '@components/ui/Card';

const TABLE_GRID_COLS = 'minmax(140px, 1.1fr) minmax(100px, 0.9fr) minmax(100px, 0.85fr) minmax(100px, 0.85fr) 100px minmax(120px, 0.95fr)';

function truncate(v?: string | null, n = 10) {
  if (!v) return '—';
  return v.length > n ? `${v.slice(0, n)}…` : v;
}

