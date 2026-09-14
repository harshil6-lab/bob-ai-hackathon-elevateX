/**
 * Shared test fixtures. Kept separate from src/mocks/ so that test data and
 * demo-mode data can never be confused for one another.
 */

import type { Alert } from '../types/alert';
import type { Incident } from '../types/incident';
import type { DashboardStats } from '../types/dashboard';

export const alertFixtures: Alert[] = [
  {
    id: 'ALT-1004',
    timestamp: '2026-09-14T10:32:00Z',
    source: 'SIEM',
    event_type: 'Credential Access',
    severity: 'critical',
    source_ip: '10.10.5.17',
    destination_ip: '10.10.5.17',
    host: 'SERVER-17',
    user: 'svc_backup',
    description: 'Handle opened to lsass.exe memory with PROCESS_VM_READ.',
  },
  {
    id: 'ALT-1002',
    timestamp: '2026-09-14T10:14:00Z',
    source: 'SIEM',
    event_type: 'PowerShell',
    severity: 'medium',
    source_ip: '10.10.1.20',
    destination_ip: '10.10.5.17',
    host: 'SERVER-17',
    user: 'svc_backup',
    description: 'Encoded PowerShell command executed with -WindowStyle Hidden.',
  },
  {
    id: 'ALT-2001',
    timestamp: '2026-09-14T09:50:00Z',
    source: 'NETWORK_SENSOR',
    event_type: 'Port Scan',
    severity: 'low',
    source_ip: '10.10.2.14',
    destination_ip: '10.10.2.99',
    host: 'WKS-0142',
    user: 'jdoe',
    description: 'Sequential TCP connection attempts across an internal range.',
  },
];

/** Critical severity, very high confidence. */
export const criticalIncident: Incident = {
  id: 'INC-001',
  severity: 'critical',
  confidence: 94,
  status: 'investigating',
  affected_assets: ['SERVER-17', 'FILE-SRV-31'],
  alert_count: 7,
  sources: ['SIEM', 'NETWORK_SENSOR', 'THREAT_INTEL'],
  bluf: 'A confirmed intrusion is in progress on SERVER-17 and has spread to FILE-SRV-31. Isolate both hosts now.',
  mitre_techniques: [
    { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access' },
    { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
  ],
  evidence: [
    {
      alert_id: 'ALT-1004',
      source: 'SIEM',
      timestamp: '2026-09-14T10:32:00Z',
      host: 'SERVER-17',
      user: 'svc_backup',
      description: 'Handle opened to lsass.exe with PROCESS_VM_READ.',
    },
  ],
  recommended_actions: [
    {
      action: 'Network-isolate SERVER-17 and FILE-SRV-31 immediately',
      priority: 'immediate',
      rationale: 'Lateral movement is active and C2 is live.',
    },
  ],
};

/**
 * LOW severity but VERY HIGH confidence — the case that proves severity and
 * confidence are independent facts and neither masks the other.
 */
export const lowSeverityHighConfidenceIncident: Incident = {
  id: 'INC-007',
  severity: 'low',
  confidence: 96,
  status: 'contained',
  affected_assets: ['WKS-0455'],
  alert_count: 3,
  sources: ['ENDPOINT_EDR'],
  bluf: 'An unapproved removable storage device was attached to WKS-0455 and blocked by policy. Business impact is low.',
  mitre_techniques: ['T1091'],
  evidence: ['ALT-2190 — ENDPOINT_EDR — WKS-0455 — device attached and blocked.'],
  recommended_actions: ['Refer to the acceptable-use process for WKS-0455.'],
};

export const incidentFixtures: Incident[] = [
  lowSeverityHighConfidenceIncident,
  criticalIncident,
];

export const dashboardStatsFixture: DashboardStats = {
  total_alerts: 248,
  total_incidents: 2,
  critical_count: 1,
  high_count: 0,
  severity_distribution: { critical: 1, medium: 1, low: 1 },
  source_distribution: { SIEM: 2, NETWORK_SENSOR: 1 },
  top_incident: criticalIncident,
  recent_incidents: [criticalIncident, lowSeverityHighConfidenceIncident],
  last_analysis_at: '2026-09-14T11:02:00Z',
};
