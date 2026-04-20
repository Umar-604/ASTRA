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
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"></svg>