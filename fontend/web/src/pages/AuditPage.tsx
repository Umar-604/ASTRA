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

