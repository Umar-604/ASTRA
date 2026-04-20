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
