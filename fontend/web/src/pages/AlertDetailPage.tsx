import { useEffect, useState } from 'react';
import { useParams, useLocation } from 'react-router-dom';
import { getEvent } from '@api/events';
import { verifyIntegrityPost } from '@api/audit';
import { acknowledgeAlert } from '@api/alerts';
import { getResponseHistory } from '@api/response';
import { BackButton } from '@components/ui/BackButton';
import type { EventSummary, AlertItem, AlertStatus, ResponseHistoryItem } from '@app-types/api';
import { getAlertScoreDisplay } from '../utils/alertScore';
export function AlertDetailPage() {
  const { alertId } = useParams();
  const location = useLocation();
const alertFromList = (location.state as { alert?: AlertItem })?.alert;
  const [event, setEvent] = useState<EventSummary | null>(null);
  const [status, setStatus] = useState<'VERIFIED' | 'PENDING' | 'TAMPERED' | null>(null);
  const [txId, setTxId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
 const [alertStatus, setAlertStatus] = useState<AlertStatus>('new');
  const [ackLoading, setAckLoading] = useState(false);
  const [responseItems, setResponseItems] = useState<ResponseHistoryItem[]>([]);useEffect(() => {
    let mounted = true;
    const id = alertId || '';
    setLoading(true);
Promise.all([
      getEvent(id).catch(() => null),
      verifyIntegrityPost(id).catch(() => null) as Promise<{ status?: string; tx_id?: string } | null>,
      getResponseHistory(id).catch(() => ({ items: [] as ResponseHistoryItem[] }))
])
      .then(([evt, integ, resp]) => {
        if (!mounted) return;
        if (evt) setEvent(evt);
 if (integ && integ.status) setStatus(integ.status as 'VERIFIED' | 'PENDING' | 'TAMPERED');
        if (integ && integ.tx_id) setTxId(integ.tx_id);
        setResponseItems((resp?.items || []).slice().reverse());
 const fromList = (location.state as { alert?: AlertItem })?.alert;
        const s = (evt?.summary as AlertItem)?.alert_status ?? fromList?.alert_status ?? 'new';
        setAlertStatus(s as AlertStatus);
      })
.finally(() => mounted && setLoading(false));
    return () => {
      mounted = false; };
  }, [alertId, location.state]);
 const handleAcknowledge = async (newStatus: 'acknowledged' | 'resolved') => {
    const id = alertId || (summary as AlertItem)?.event_id;
    if (!id) return;
    setAckLoading(true);try {
      await acknowledgeAlert(id, newStatus);
      setAlertStatus(newStatus);
    } finally {
      setAckLoading(false);
    }
  };
// Prefer API event summary/record; fall back to alert row passed from Alerts list
  const summary = event?.summary ?? (alertFromList ? { ...alertFromList, integrity_status: alertFromList.integrity_status } : null);
  const record = event?.record ?? null;
  const aiLabel = summary?.ai_label ?? '';
const score = getAlertScoreDisplay(summary as AlertItem | undefined, 0);
  const severity = summary?.severity ?? '—';
  const integrity = status ?? (summary?.integrity_status ? summary.integrity_status.toUpperCase() : 'PENDING');
  const hasDetails = Boolean(event?.summary || event?.record);

const integBadge = (() => {
    const s = integrity;
    const bg = s === 'VERIFIED' ? '#14532d' : s === 'TAMPERED' ? '#7f1d1d' : '#334155';const fg = s === 'VERIFIED' ? '#dcfce7' : s === 'TAMPERED' ? '#fee2e2' : '#f1f5f9';
    return (
      <span style={{ padding: '2px 8px', borderRadius: 999, background: bg, color: fg, fontSize: 12 }}>
        {s}</span>
    );
  })();
const showContent = summary || alertFromList;
  return (
    <div>
<BackButton fallbackTo="/alerts" />
      <h2 style={{ marginTop: 0 }}>Alert Details</h2>
      {loading ? (
<div style={{ opacity: 0.8 }}>Loading...</div>
      ) : !showContent ? (
        <div style={{ opacity: 0.8 }}>Alert not found</div>
      ) : (
        <>
 {!hasDetails && alertFromList && (
            <div
              style={{
                padding: 12,
                marginBottom: 12,
background: 'var(--muted)',
                border: '1px solid var(--panel-border)',
                borderRadius: 8,
                fontSize: 14,
                opacity: 0.9
}}
            >
Full event details could not be loaded; showing summary from alerts list.
            </div>
)}
          {/* 1) Summary */}
          <section
            style={{
border: '1px solid var(--panel-border)',
              borderRadius: 12,
              padding: 16,
              background: 'var(--panel-bg)',
marginBottom: 12
            }}
          >
 <h3 style={{ marginTop: 0, marginBottom: 8, fontSize: 16 }}>Summary</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', rowGap: 6 }}>
              <div style={{ opacity: 0.7 }}>Event ID</div>
              <div style={{ overflowWrap: 'break-word' }}>{event?.event_id ?? alertId ?? '—'}</div>
              <div style={{ opacity: 0.7 }}>Endpoint</div>
 <div>{(summary as AlertItem)?.host_id ?? '—'}</div>
              <div style={{ opacity: 0.7 }}>AI decision</div>
              <div>{aiLabel || '—'}</div>
              <div style={{ opacity: 0.7 }}>{score.label}</div>
 <div title={score.tooltip ?? undefined}>{score.value}</div>
              <div style={{ opacity: 0.7 }}>Severity</div>
              <div>
                <span
                  style={{  padding: '2px 8px',
                    borderRadius: 999,
                    background:
                      severity.toUpperCase() === 'HIGH'
 ? '#7f1d1d'
                        : severity.toUpperCase() === 'MEDIUM'
                        ? '#92400e'
                        : 'var(--accent)',
                    color: '#fff',
                    fontSize: 12
  }}
                >
                  {severity}
                </span>
              </div>
            </div>
          </section>
  {/* 1b) Alert status & actions */}
          <section
            style={{
              border: '1px solid var(--panel-border)',
              borderRadius: 12,
padding: 16,
              background: 'var(--panel-bg)',
              marginBottom: 12
            }}
          >
 <h3 style={{ marginTop: 0, marginBottom: 8, fontSize: 16 }}>Alert status</h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <span
                style={{
 padding: '6px 12px',
                  borderRadius: 999,
                  background:
                    alertStatus === 'new'
                      ? '#b91c1c'
                      : alertStatus === 'acknowledged'? '#b45309'
                        : '#15803d',
                  color: '#fff',
                  fontSize: 13,
                  fontWeight: 600
                }}
              >
 {alertStatus === 'new' ? 'New' : alertStatus === 'acknowledged' ? 'Acknowledged' : 'Resolved'}
              </span>
              {alertStatus === 'new' && (
                <button
 type="button"
                  disabled={ackLoading}
                  onClick={() => handleAcknowledge('acknowledged')}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 8,
 border: 'none',
                    background: 'var(--accent)',
                    color: '#fff',
                    cursor: ackLoading ? 'wait' : 'pointer',
                    fontWeight: 600
                  }}
                >
 {ackLoading ? '…' : 'Acknowledge'}
                </button>
              )}
              {alertStatus === 'acknowledged' && (
                <button
                  type="button"
                  disabled={ackLoading}
                  onClick={() => handleAcknowledge('resolved')}
 style={{
                    padding: '8px 16px',
                    borderRadius: 8,
                    border: 'none',
                    background: '#15803d',
                    color: '#fff',
 cursor: ackLoading ? 'wait' : 'pointer',
                    fontWeight: 600
                  }}
                >
  {ackLoading ? '…' : 'Resolve'}
                </button>
              )}
            </div>
          </section>
  {/* 2) Integrity panel */}
          <section
            style={{
              border: '1px solid var(--panel-border)',
              borderRadius: 12,
 padding: 16,
              background: 'var(--panel-bg)',
              marginBottom: 12
            }}
          >
<h3 style={{ marginTop: 0, marginBottom: 8, fontSize: 16 }}>Integrity</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', rowGap: 6 }}>
              <div style={{ opacity: 0.7 }}>Status</div>
<div>{integBadge}</div>
              <div style={{ opacity: 0.7 }}>Blockchain Tx</div>
              <div style={{ overflowWrap: 'anywhere' }}>{txId || '—'}</div>
            </div>
          </section>
 {/* 3) Context (record from API or placeholder) */}
          <section
            style={{
              border: '1px solid var(--panel-border)',
              borderRadius: 12,
              padding: 16,
  background: 'var(--panel-bg)',
              marginBottom: 12
            }}
          >
 <h3 style={{ marginTop: 0, marginBottom: 8, fontSize: 16 }}>Context</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', rowGap: 6 }}>
              <div style={{ opacity: 0.7 }}>Agent</div>
              <div>{record?.agent_id ?? (summary as AlertItem)?.agent_id ?? '—'}</div>
              <div style={{ opacity: 0.7 }}>Platform</div>
              <div>{record?.platform ?? '—'}</div>
 <div style={{ opacity: 0.7 }}>Event type</div>
              <div>{record?.event_type ?? (summary as AlertItem)?.event_type ?? '—'}</div>
              <div style={{ opacity: 0.7 }}>Timestamp</div>
              <div>{record?.timestamp ?? (summary as AlertItem)?.['@timestamp'] ?? '—'}</div>
            </div>
          </section>
 {/* 4) Event data (Sysmon / pipeline) – all details captured by the agent */}
          {record?.data && Object.keys(record.data).length > 0 && (
            <section
              style={{ border: '1px solid var(--panel-border)',
                borderRadius: 12,
                padding: 16,
                background: 'var(--panel-bg)',
                marginBottom: 12
}}
            >
              <h3 style={{ marginTop: 0, marginBottom: 8, fontSize: 16 }}>Event data (Sysmon / pipeline)</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', rowGap: 6, fontSize: 14 }}>
                {Object.entries(record.data).map(([k, v]) => (
                  <div key={k} style={{ display: 'contents' }}> <span style={{ opacity: 0.85 }}>{k}</span>
                    <span style={{ overflowWrap: 'break-word', wordBreak: 'break-word' }}>
                      {typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v ?? '—')}
                    </span>
 </div>
                ))}
              </div>
            </section>
          )}

 {/* 4b) Automated response actions against this alert */}
          <section
            style={{
              border: '1px solid var(--panel-border)',
 borderRadius: 12,
              padding: 16,
              background: 'var(--panel-bg)',
              marginBottom: 12
            }}
          >
 <h3 style={{ marginTop: 0, marginBottom: 8, fontSize: 16 }}>Response actions</h3>
            {responseItems.length === 0 ? (
              <div style={{ opacity: 0.75, fontSize: 14 }}>No response actions recorded for this alert yet.</div>
            ) : (
 <div style={{ display: 'grid', gap: 8 }}>
                {responseItems.map((item, idx) => {
                  const status = String(item.status || '').toLowerCase();
                  const bg =
                    status === 'ok'
 ? '#14532d'
                      : status === 'recommended' || status === 'pending_approval'
                        ? '#92400e'
                        : status === 'simulated'
                          ? '#334155'
                          : '#7f1d1d';
 const label = item.action_taken || item.action || 'action';
                  return (
                    <div
                      key={`${item.event_id}-${item.timestamp}-${idx}`}
                      style={{
                        border: '1px solid var(--panel-border)',
                        borderRadius: 8,
                        padding: 10,
                        background: 'var(--widget-bg)'
                      }}
                    >
</div>