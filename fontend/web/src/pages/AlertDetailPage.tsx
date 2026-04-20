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
