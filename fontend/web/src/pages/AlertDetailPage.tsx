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
        {s}