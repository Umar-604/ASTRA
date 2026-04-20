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
