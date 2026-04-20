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
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', flex: narrow ? '1 1 100%' : undefined }}>
          <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--fg)' }}>Integrity:</span>
          {[
            { value: 'ANY', label: 'All' },
            { value: 'VERIFIED', label: 'Verified' },
            { value: 'TAMPERED', label: 'Tampered' },
            { value: 'PENDING', label: 'Pending' },
          ].map(({ value, label }) => {
            const selected = integrityFilter === value;
            return (
              <button
                key={value}
                type="button"
                onClick={() => {
                  setIntegrityFilter(value as 'ANY' | 'VERIFIED' | 'TAMPERED' | 'PENDING');
                  setPage(1);
                }}
                style={{
                  padding: '8px 14px',
                  borderRadius: 8,
                  border: `1px solid ${selected ? 'var(--accent)' : 'var(--border-color)'}`,
                  background: selected ? 'rgba(var(--accent-rgb), 0.12)' : 'var(--widget-bg)',
                  color: selected ? 'var(--accent)' : 'var(--fg)',
                  fontWeight: selected ? 600 : 500,
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                {label}
              </button>
            );
          })}
        </div>

        <div style={{ fontSize: 14, color: 'var(--fg)', opacity: 0.9, width: narrow ? '100%' : undefined }}>
          {filtered.length} result{filtered.length !== 1 ? 's' : ''}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', width: narrow ? '100%' : undefined, justifyContent: narrow ? 'flex-start' : undefined }}>
          <button
            type="button"
            onClick={handleExport}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '8px 12px',
              borderRadius: 8,
              border: '1px solid var(--border-color)',
              background: 'var(--widget-bg)',
              color: 'var(--fg)',
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            Export
          </button>
          <button
            type="button"
            onClick={fetchAuditLogs}
            disabled={loading}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '8px 12px',
              borderRadius: 8,
              border: '1px solid var(--border-color)',
              background: 'var(--widget-bg)',
              color: 'var(--fg)',
              cursor: loading ? 'wait' : 'pointer',
              fontSize: 13,
              opacity: loading ? 0.7 : 1,
            }}
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={handleClear}
            style={{
              padding: '8px 12px',
              borderRadius: 8,
              border: '1px solid var(--border-color)',
              background: 'var(--widget-bg)',
              color: 'var(--fg)',
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {/* Secondary filters */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: narrow ? '1fr' : 'repeat(auto-fill, minmax(200px, 1fr))',
          gap: 12,
          marginBottom: 12,
          alignItems: 'start',
        }}
      >
        <label style={{ display: 'flex', flexDirection: 'column', fontSize: 12, opacity: 0.8, gap: 4 }}>
          Host filter
          <input
            value={hostFilter}
            onChange={(e) => {
              setHostFilter(e.target.value);
              setPage(1);
            }}
            placeholder="hostname"
            style={filterInputStyle}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', fontSize: 12, opacity: 0.8, gap: 4 }}>
          Page size
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(parseInt(e.target.value, 10));
              setPage(1);
            }}
            style={{ ...filterInputStyle, cursor: 'pointer' }}
          >
            {[10, 20, 50].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
      </div>

      <Card style={{ overflow: 'hidden', padding: 0 }}>
        {loading ? (
          <div style={{ padding: 48, textAlign: 'center', fontSize: 14, color: 'var(--gray-text, #64748b)' }}>Loading…</div>
        ) : pageItems.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center', fontSize: 14, color: 'var(--gray-text, #64748b)' }}>No audit entries</div>
        ) : narrow ? (
          <div className="audit-card-list" style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {pageItems.map((it) => {
              const risk = typeof it.risk_score === 'number' ? it.risk_score : null;
              const rb = riskBadgeStyle(risk);
              const ip = integrityPill(it.integrity);
              return (
                <article
                  key={it.event_id}
                  className="audit-card"
                  style={{
                    padding: '16px',
                    borderBottom: '1px solid var(--border-color)',
                  }}
                >
                  <div style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--gray-text, #64748b)', marginBottom: 10 }}>
                    {it.timestamp ? String(it.timestamp) : '—'}
                  </div>
                  <dl
                    style={{
                      margin: 0,
                      display: 'grid',
                      gridTemplateColumns: 'minmax(100px, 38%) 1fr',
                      gap: '8px 12px',
                      fontSize: 13,
                    }}
                  >
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Host</dt>
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{it.host || '—'}</dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Event type</dt>
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{it.event_type || '—'}</dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Action</dt>
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{it.action || '—'}</dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Risk score</dt>
                    <dd style={{ margin: 0 }}>
                      <span
                        style={{
                          padding: '4px 10px',
                          borderRadius: 999,
                          background: rb.bg,
                          color: rb.fg,
                          fontSize: 12,
                          fontWeight: 600,
                          display: 'inline-block',
                        }}
                      >
                        {rb.label}
                      </span>
                    </dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Integrity</dt>
                    <dd style={{ margin: 0 }}>
                      <span
                        style={{
                          padding: '4px 10px',
                          borderRadius: 999,
                          background: ip.bg,
                          color: ip.fg,
                          fontSize: 12,
                          fontWeight: 600,
                        }}
                      >
                        {ip.label}
                      </span>
                    </dd>
                  </dl>
                </article>
              );
            })}
          </div>
        ) : (
          <div className="audit-table-scroll" style={{ overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
            <div style={{ minWidth: 720 }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: TABLE_GRID_COLS,
                  gap: 16,
                  alignItems: 'center',
                  padding: '14px 20px',
                  background: 'var(--muted-strong, #f1f5f9)',
                  borderBottom: '1px solid var(--border-color)',
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                  color: 'var(--gray-text, #64748b)',
                }}
              >
                <div>Timestamp</div>
                <div>Host</div>
                <div>Event Type</div>
                <div>Action</div>
                <div>Risk Score</div>
                <div>Integrity Status</div>
              </div>
              {pageItems.map((it, idx) => {
                const risk = typeof it.risk_score === 'number' ? it.risk_score : null;
                const rb = riskBadgeStyle(risk);
                const ip = integrityPill(it.integrity);
                return (
                  <div
                    key={it.event_id}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: TABLE_GRID_COLS,
                      gap: 16,
                      alignItems: 'center',
                      padding: '14px 20px',
                      borderBottom: idx < pageItems.length - 1 ? '1px solid var(--border-color)' : 'none',
                    }}
                    className="audit-row"
                  >
                    <div style={{ overflowWrap: 'anywhere', fontSize: 13 }}>{it.timestamp ? String(it.timestamp) : '—'}</div>
                    <div title={it.host || ''} style={{ fontSize: 13 }}>
                      {truncate(it.host || '', 22)}
                    </div>
                    <div title={it.event_type || ''} style={{ fontSize: 13 }}>
                      {truncate(it.event_type || '', 18)}
                    </div>
                    <div title={it.action || ''} style={{ fontSize: 13 }}>
                      {truncate(it.action || '', 18)}
                    </div>
                    <div>
                      <span
                        style={{
                          padding: '2px 8px',
                          borderRadius: 999,
                          background: rb.bg,
                          color: rb.fg,
                          fontSize: 12,
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {rb.label}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <span
                        style={{
                          padding: '2px 8px',
                          borderRadius: 999,
                          background: ip.bg,
                          color: ip.fg,
                          fontSize: 12,
                        }}
                      >
                        {ip.label}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Card>

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: 12,
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ opacity: 0.8, fontSize: 12 }}>
          Page {page} / {totalPages} • {filtered.length} items
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            style={{
              padding: '6px 10px',
              borderRadius: 6,
              border: '1px solid var(--panel-border)',
              background: 'var(--panel-bg)',
              color: 'var(--fg)',
              cursor: page <= 1 ? 'not-allowed' : 'pointer',
              opacity: page <= 1 ? 0.5 : 1,
            }}
          >
            Previous
          </button>
          <button
            type="button"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            style={{
              padding: '6px 10px',
              borderRadius: 6,
              border: '1px solid var(--panel-border)',
              background: 'var(--panel-bg)',
              color: 'var(--fg)',
              cursor: page >= totalPages ? 'not-allowed' : 'pointer',
              opacity: page >= totalPages ? 0.5 : 1,
            }}
          >
            Next
          </button>
        </div>
      </div>

      <style>{`
        .audit-row:hover { background: var(--muted, #f8fafc); }
        body[data-theme="dark"] .audit-row:hover { background: var(--muted); }
        body[data-theme="dark"] .audit-card { background: transparent; }
        @media (max-width: 960px) {
          .audit-card:last-child { border-bottom: none !important; }
        }
      `}</style>
    </div>
  );
}
