import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { getAlerts, acknowledgeAlert, type AcknowledgeStatus } from '@api/alerts';
import type { AlertItem, AlertStatus, IntegrityStatus } from '@app-types/api';
import { useNavigate } from 'react-router-dom';
import { Card } from '@components/ui/Card';
import { getAlertScoreDisplay } from '../utils/alertScore';
const sevOptions = ['ANY', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const severityChips: { value: (typeof sevOptions)[number]; label: string }[] = [
{ value: 'ANY', label: 'All' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },];
const alertStatusOptions: { value: 'ANY' | AlertStatus; label: string }[] = [
  { value: 'ANY', label: 'All' },
  ];
const alertStatusOptions: { value: 'ANY' | AlertStatus; label: string }[] = [
  { value: 'ANY', label: 'All' }, { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
{ value: 'resolved', label: 'Resolved' },
];
const integrityOptions: Array<'ANY' | IntegrityStatus> = ['ANY', 'Verified', 'Pending', 'Tampered'];
const integrityOptions: Array<'ANY' | IntegrityStatus> = ['ANY', 'Verified', 'Pending', 'Tampered'];
const IconExport = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
</svg>
);
const ALERTS_GRID_COLS =
'minmax(140px, 1fr) minmax(88px, 1fr) minmax(88px, 1fr) minmax(88px, 1fr) minmax(72px, 100px) minmax(80px, 100px) minmax(76px, 96px) minmax(96px, 120px)';
'minmax(140px, 1fr) minmax(88px, 1fr) minmax(88px, 1fr) minmax(88px, 1fr) minmax(72px, 100px) minmax(80px, 100px) minmax(76px, 96px) minmax(96px, 120px)';
const IconRefresh = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
<polyline points="23 4 23 10 17 10" />
    <polyline points="1 20 1 14 7 14" />
</svg>