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
 <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
  </svg>
);
export function AlertsPage() {
  const [data, setData] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(false);
const [ackLoading, setAckLoading] = useState<string | null>(null);
  const [severity, setSeverity] = useState<(typeof sevOptions)[number]>('ANY');
  const [alertStatusFilter, setAlertStatusFilter] = useState<'ANY' | AlertStatus>('ANY');
  const [integrity, setIntegrity] = useState<(typeof integrityOptions)[number]>('ANY');
  const [hostFilter, setHostFilter] = useState('');
const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [narrow, setNarrow] = useState(false);
  const navigate = useNavigate();
useEffect(() => {
    const mq = window.matchMedia('(max-width: 960px)');
    const apply = () => setNarrow(mq.matches);
apply();
    mq.addEventListener?.('change', apply);
    return () => mq.removeEventListener?.('change', apply);
  }, []);
const fetchAlerts = () => {
    setLoading(true);
    getAlerts({ limit: 200 })
.then((res) => setData(res.items || []))
      .catch(() => setData([]))
      .finally(() => setLoading(false));
  };

.then((res) => setData(res.items || []))
      .catch(() => setData([]))
      .finally(() => setLoading(false));
  };

useEffect(() => {
    let mounted = true;
    setLoading(true);
    getAlerts({ limit: 200 })
.then((res) => {
        if (!mounted) return;
        setData(res.items || []);
      })
.catch(() => {
        if (!mounted) return;
        setData([]);
      })
 .finally(() => {
        if (!mounted) return;
        setLoading(false);
      });
 return () => { mounted = false; };
  }, []);
const filtered = useMemo(() => {
    let items = data;
    if (severity !== 'ANY') {
items = items.filter((a) => (a.severity || '').toUpperCase() === severity);
    }
  if (alertStatusFilter !== 'ANY') {
      items = items.filter((a) => (a.alert_status || 'new') === alertStatusFilter);
    }
 if (integrity !== 'ANY') {
      items = items.filter((a) => (a.integrity_status || 'Pending') === integrity);
    }
if (hostFilter.trim()) {
      const q = hostFilter.trim().toLowerCase();
      items = items.filter((a) => (a.host_id || '').toLowerCase().includes(q));
    }
  return items;
  }, [data, severity, alertStatusFilter, integrity, hostFilter]);const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize);
 useEffect(() => {
    // Reset to page 1 if filters change and current page is out of range
    if (page > totalPages) setPage(1);
  }, [totalPages, page]);
 const handleExport = () => {
    const headers = ['Timestamp', 'Host', 'Event type', 'AI verdict', 'Score', 'Severity', 'Integrity'];
    const rows = filtered.map((a) => {
const score = getAlertScoreDisplay(a, 0);
      return [
        a['@timestamp'] ?? '',
        a.host_id ?? '',
a.event_type ?? '',
        a.ai_label ?? '',
        score.value,
        a.severity ?? '',
a.integrity_status ?? 'Pending',
      ];
    });
const csv = [headers.join(','), ...rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
 link.href = URL.createObjectURL(blob);
    link.download = `alerts-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
 URL.revokeObjectURL(link.href);
  };
 const handleClear = () => {
    setSeverity('ANY');
    setAlertStatusFilter('ANY');
    setIntegrity('ANY');
setHostFilter('');
    setPage(1);
  };
const filterInputStyle: CSSProperties = {
    background: 'var(--panel-bg)',
    color: 'var(--fg)',
</svg>