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
border: '1px solid var(--panel-border)',
    borderRadius: 6,
    padding: '6px 8px',
    width: narrow ? '100%' : undefined,
    minWidth: narrow ? 0 : 160,
border: '1px solid var(--panel-border)',
    borderRadius: 6,
    padding: '6px 8px',
    width: narrow ? '100%' : undefined,
    minWidth: narrow ? 0 : 160,
 boxSizing: 'border-box',
  };
 const handleAcknowledge = async (e: React.MouseEvent, eventId: string, status: AcknowledgeStatus) => {
    e.stopPropagation();
    setAckLoading(eventId);
    try {
</svg>
 await acknowledgeAlert(eventId, status);
      fetchAlerts();
    } catch {
      // Error already handled by client / redirect
    } finally {
      setAckLoading(null);
    }
  };
return (
    <div className="alerts-page-root" style={{ maxWidth: 'min(1200px, 100%)', margin: '0 auto', padding: '0 12px' }}>
      <h2 style={{ marginTop: 0 }}>Alerts</h2>
{/* Toolbar: Severity chips, results count, Export / Refresh / Clear */}
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
 <div
          style={{
            display: 'flex',
            alignItems: 'center',
   gap: 10,
            flexWrap: 'wrap',
            flex: narrow ? '1 1 100%' : undefined,
          }}
        >
  <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--fg)' }}>Severity:</span>
          {severityChips.map(({ value, label }) => {
            const selected = severity === value;
            return (
              <button  <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--fg)' }}>Severity:</span>
          {severityChips.map(({ value, label }) => {
            const selected = severity === value;
            return (
              <button key={value}
                type="button"
                onClick={() => {
                  setSeverity(value);
                  setPage(1);  }}
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
 <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
  flexWrap: 'wrap',
            width: narrow ? '100%' : undefined,
            justifyContent: narrow ? 'flex-start' : undefined,
          }}
        >
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
  <IconExport />
            Export
          </button>
          <button
            type="button"
 onClick={fetchAlerts}
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
  <IconRefresh />
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

 {/* Secondary filters: Integrity, Host, Page size */}
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
          Status
          <select
            value={alertStatusFilter}
    onChange={(e) => {
              setAlertStatusFilter(e.target.value as 'ANY' | AlertStatus);
              setPage(1);
            }}
            style={{ ...filterInputStyle, cursor: 'pointer' }}
          >
  {alertStatusOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
    </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', fontSize: 12, opacity: 0.8, gap: 4 }}>
          Integrity
          <select
            value={integrity}
  onChange={(e) => {
              setIntegrity(e.target.value as (typeof integrityOptions)[number]);
              setPage(1);
            }}
  onChange={(e) => {
              setIntegrity(e.target.value as (typeof integrityOptions)[number]);
              setPage(1);
            }}
 style={{ ...filterInputStyle, cursor: 'pointer' }}
          >
            {integrityOptions.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
))}
          </select>
        </label>
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
          <div style={{ padding: 48, textAlign: 'center', fontSize: 14, color: 'var(--gray-text, #64748b)' }}>No alerts</div>
        ) : narrow ? (
  <div className="alerts-card-list" style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {pageItems.map((a, index) => {
              const onClick = () =>
  navigate(`/alerts/${encodeURIComponent(a.event_id)}`, { state: { alert: a } });
              const sevColor =
                (a.severity || '').toUpperCase() === 'HIGH'
                  ? '#7f1d1d'
                  : (a.severity || '').toUpperCase() === 'MEDIUM'
                    ? '#92400e'
  : 'var(--accent)';
              const rowKey = a.event_id ? `${a.event_id}-${index}` : `alert-${index}`;
              const score = getAlertScoreDisplay(a, 0);
              const status = a.alert_status || 'new';
  const statusLabel = status === 'new' ? 'New' : status === 'acknowledged' ? 'Acknowledged' : 'Resolved';
              const statusBg = status === 'new' ? '#b91c1c' : status === 'acknowledged' ? '#b45309' : '#15803d';
              const isAckLoading = ackLoading === a.event_id;
              return (
 <article
                  key={rowKey}
                  className="alerts-card"
                  style={{
                    padding: '16px',
                    borderBottom: index < pageItems.length - 1 ? '1px solid var(--border-color)' : 'none',
                    cursor: 'pointer',
                  }}
 onClick={onClick}
                >
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 600,
    textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      color: 'var(--gray-text, #64748b)',
                      marginBottom: 10,
                    }}
                  >
  {a['@timestamp'] || '—'}
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
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{a.host_id || '—'}</dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Event type</dt>
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{a.event_type || '—'}</dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>AI verdict</dt>
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{a.ai_label || '—'}</dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Score</dt>
                    <dd style={{ margin: 0 }} title={score.tooltip ?? undefined}>
                      {score.value}
   {score.isBehavioral && (
                        <span style={{ fontSize: 10, opacity: 0.8, display: 'block' }}>Anomaly</span>
                      )}
                    </dd>
   <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Severity</dt>
                    <dd style={{ margin: 0 }}>
                      <span
                        style={{
                          padding: '4px 10px',
                          borderRadius: 999,
                          background: sevColor,
                          color: '#fff',
                          fontSize: 12,
                          fontWeight: 600,
     display: 'inline-block',
                        }}
                      >
 {a.severity || '—'}
                      </span>
                    </dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Status</dt>
                    <dd style={{ margin: 0 }}>
                      <span
                        style={{
                          padding: '4px 10px',
                          borderRadius: 999,
                          background: statusBg,
                          color: '#fff',
                          fontSize: 12,
                          fontWeight: 600,
                          display: 'inline-block',
                        }}
                      >
    {statusLabel}
                      </span>
                    </dd>
                    <dt style={{ color: 'var(--gray-text, #64748b)', fontWeight: 500 }}>Actions</dt>
                    <dd style={{ margin: 0 }} onClick={(e) => e.stopPropagation()}>
                      {status === 'new' && (
                        <button
                          type="button"
                          disabled={isAckLoading}  onClick={(e) => handleAcknowledge(e, a.event_id, 'acknowledged')}
                          style={{
                            padding: '6px 12px',
                            fontSize: 12,
                            borderRadius: 6,
                            border: 'none',
                            background: 'var(--accent)',
                            color: '#fff',
                            cursor: isAckLoading ? 'wait' : 'pointer',
                          }}
                        >
   {isAckLoading ? '…' : 'Acknowledge'}
                        </button>
                      )}
                      {status === 'acknowledged' && (
                        <button
                          type="button"
                          disabled={isAckLoading}
                          onClick={(e) => handleAcknowledge(e, a.event_id, 'resolved')}
                          style={{
                            padding: '6px 12px',  fontSize: 12,
                            borderRadius: 6,
                            border: 'none',
                            background: '#15803d',
                            color: '#fff',
                            cursor: isAckLoading ? 'wait' : 'pointer',
                          }}
                        >
  {isAckLoading ? '…' : 'Resolve'}
                        </button>
                      )}
                      {status === 'resolved' && <span style={{ opacity: 0.75, fontSize: 13 }}>—</span>}
                    </dd>
                  </dl>
                </article>
              );
            })}
          </div>
        ) : (
<div className="alerts-table-scroll" style={{ overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
            <div style={{ minWidth: 980 }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: ALERTS_GRID_COLS,
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
                <div>Event type</div>
                <div>AI verdict</div>
                <div>Score</div>
                <div>Severity</div>
                <div>Status</div>
                <div>Actions</div>
              </div>
  {pageItems.map((a, index) => {
                const onClick = () =>
                  navigate(`/alerts/${encodeURIComponent(a.event_id)}`, { state: { alert: a } });
                const sevColor =
                  (a.severity || '').toUpperCase() === 'HIGH'
                    ? '#7f1d1d'
                    : (a.severity || '').toUpperCase() === 'MEDIUM'
                      ? '#92400e'
                      : 'var(--accent)';
 const rowKey = a.event_id ? `${a.event_id}-${index}` : `alert-${index}`;
                const score = getAlertScoreDisplay(a, 0);
                const status = a.alert_status || 'new';
                const statusLabel = status === 'new' ? 'New' : status === 'acknowledged' ? 'Acknowledged' : 'Resolved';
                const statusBg = status === 'new' ? '#b91c1c' : status === 'acknowledged' ? '#b45309' : '#15803d';
                const isAckLoading = ackLoading === a.event_id;
                return (
                  <div
 key={rowKey}
                    onClick={onClick}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: ALERTS_GRID_COLS,
                      gap: 16,
                      alignItems: 'center',
                      padding: '14px 20px',
                      borderBottom: index < pageItems.length - 1 ? '1px solid var(--border-color)' : 'none',
                      cursor: 'pointer',
                    }}
  className="alerts-row"
                  >
                    <div style={{ overflowWrap: 'anywhere', fontSize: 13 }} title={a['@timestamp']}>
                      {a['@timestamp']}
                    </div>
                    <div style={{ overflowWrap: 'anywhere', fontSize: 13 }} title={a.host_id}>
                      {a.host_id || ''}
                    </div>
                    <div style={{ overflowWrap: 'anywhere', fontSize: 13 }} title={a.event_type}>
                      {a.event_type}
                    </div>
 <div style={{ overflowWrap: 'anywhere', fontSize: 13 }} title={a.ai_label || ''}>
                      {a.ai_label || ''}
                    </div>
                    <div style={{ fontSize: 13 }} title={score.tooltip ?? undefined}>
                      {score.value}
                      {score.isBehavioral && (
                        <span style={{ fontSize: 10, opacity: 0.8, display: 'block' }}>Anomaly</span>
                      )}
 </div>
                    <div>
                      <span
                        style={{
                          padding: '2px 8px',
                          borderRadius: 999,
                          background: sevColor,
                          color: '#fff',
                          fontSize: 12,
                        }}
                      >
  {a.severity}
                      </span>
                    </div>
                    <div>
                      <span
                        style={{
                          padding: '2px 8px',
                          borderRadius: 999,
                          background: statusBg,
                          color: '#fff',
                          fontSize: 12,
                        }}
                      >
 {statusLabel}
                      </span>
                    </div>
                    <div onClick={(e) => e.stopPropagation()}>
                      {status === 'new' && (
                        <button
                          type="button"
                          disabled={isAckLoading}
                          onClick={(e) => handleAcknowledge(e, a.event_id, 'acknowledged')}
                          style={{
                            padding: '4px 8px',
                            fontSize: 11,
                            borderRadius: 6,
                            border: 'none',
                            background: 'var(--accent)',
                            color: '#fff',
                            cursor: isAckLoading ? 'wait' : 'pointer',
                          }}
                        >
 {isAckLoading ? '…' : 'Acknowledge'}
                        </button>
                      )}
                      {status === 'acknowledged' && (
                        <button
                          type="button"
                          disabled={isAckLoading}
                          onClick={(e) => handleAcknowledge(e, a.event_id, 'resolved')}
                          style={{
                            padding: '4px 8px',
  fontSize: 11,
                            borderRadius: 6,
                            border: 'none',
                            background: '#15803d',
                            color: '#fff',
                            cursor: isAckLoading ? 'wait' : 'pointer',
                          }}
                        >
