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

function integrityPill(integrity?: string | null) {
  const status = (integrity || 'Pending').toUpperCase();
  const label =
    status === 'VERIFIED' ? '✅ Verified' : status === 'TAMPERED' ? '❌ Tampered' : 'Pending';
  const bg = status === 'VERIFIED' ? '#14532d' : status === 'TAMPERED' ? '#7f1d1d' : '#334155';
  const fg = status === 'VERIFIED' ? '#dcfce7' : status === 'TAMPERED' ? '#fee2e2' : '#f1f5f9';
  return { label, bg, fg };
}

export function AuditPage() {
  const [items, setItems] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [integrityFilter, setIntegrityFilter] = useState<'ANY' | 'VERIFIED' | 'TAMPERED' | 'PENDING'>('ANY');
  const [hostFilter, setHostFilter] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [narrow, setNarrow] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 960px)');
    const apply = () => setNarrow(mq.matches);
    apply();
    mq.addEventListener?.('change', apply);
    return () => mq.removeEventListener?.('change', apply);
  }, []);

  const fetchAuditLogs = () => {
    setLoading(true);
    getAuditLogs({ limit: 200 })
      .then((res) => setItems(res.items || []))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const filtered = items.filter((it) => {
    const integrity = String(it.integrity || 'Pending').toUpperCase();
    if (integrityFilter !== 'ANY' && integrity !== integrityFilter) return false;
    if (hostFilter.trim()) {
      const q = hostFilter.trim().toLowerCase();
      if (!(it.host || '').toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageItems = filtered.slice((page - 1) * pageSize, page * pageSize);

  const handleExport = () => {
    const headers = ['Timestamp', 'Host', 'Event Type', 'Action', 'Risk Score', 'Integrity'];
    const rows = filtered.map((it) => [
      it.timestamp ?? '',
      it.host ?? '',
      it.event_type ?? '',
      it.action ?? '',
      it.risk_score != null ? String(it.risk_score) : '',
      it.integrity ?? 'Pending',
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `audit-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const handleClear = () => {
    setIntegrityFilter('ANY');
    setHostFilter('');
    setPage(1);
  };

  const filterInputStyle: CSSProperties = {
    background: 'var(--panel-bg)',
    color: 'var(--fg)',
    border: '1px solid var(--panel-border)',
    borderRadius: 6,
    padding: '6px 8px',
    width: narrow ? '100%' : undefined,
    minWidth: narrow ? 0 : 160,
    boxSizing: 'border-box',
  };

  return (
    <div className="audit-page-root" style={{ maxWidth: 'min(1200px, 100%)', margin: '0 auto', padding: '0 12px' }}>
      <h2 style={{ marginTop: 0 }}>Audit</h2>

      {/* Toolbar: Integrity chips, results count, Export / Refresh / Clear */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
          marginBottom: 12,
          padding: '12px 16px',
          background: 'var(--muted)',
          border: '1px solid var(--border-color)',
          borderRadius: 10,
        }}
      >
