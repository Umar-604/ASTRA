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
  { value: 'MEDIUM', label: 'Medium' },