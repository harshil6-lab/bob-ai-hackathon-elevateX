/**
 * MOCK DATA — for local frontend development only.
 * Not used when VITE_DEMO_MODE is unset.
 *
 * Strictly conforms to the canonical `Alert` type. Fully DETERMINISTIC (a
 * fixed-seed LCG, no Math.random and no Date.now), so the golden demo is
 * byte-for-byte repeatable on every run — as required by the DEMO PRINCIPLE in
 * AGENTS.md.
 *
 * Shape of the dataset: a large volume of multi-source background noise, plus
 * the seven-alert SERVER-17 golden scenario that the correlation engine is
 * meant to lift out of that noise.
 */

import type { Alert, Severity } from '../types/alert';

/* ── Deterministic pseudo-random source ──────────────────────────────────── */

function createRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    // Numerical Recipes LCG — deterministic across every engine.
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function pick<T>(rng: () => number, items: readonly T[]): T {
  return items[Math.floor(rng() * items.length)];
}

/* ── The golden scenario: SERVER-17 ──────────────────────────────────────── */

/**
 * A six-stage intrusion, evidenced by seven alerts across three feeds.
 * external suspicious activity -> PowerShell -> suspicious process ->
 * credential access -> remote connection -> lateral movement
 */
export const GOLDEN_ALERTS: Alert[] = [
  {
    id: 'ALT-1001',
    timestamp: '2026-09-14T09:58:00Z',
    source: 'THREAT_INTEL',
    event_type: 'External Suspicious Activity',
    severity: 'medium',
    source_ip: '203.0.113.47',
    destination_ip: '10.10.5.17',
    host: 'SERVER-17',
    user: '-',
    description:
      'Inbound connection from 203.0.113.47, an address listed on two commercial threat-intelligence feeds as scanning infrastructure. Repeated probing of the public-facing service on SERVER-17.',
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
    description:
      'Encoded PowerShell command executed with -EncodedCommand and -WindowStyle Hidden by service account svc_backup, which has no scripting history in the preceding 90 days.',
  },
  {
    id: 'ALT-1003',
    timestamp: '2026-09-14T10:21:00Z',
    source: 'SIEM',
    event_type: 'Suspicious Process',
    severity: 'high',
    source_ip: '10.10.5.17',
    destination_ip: '10.10.5.17',
    host: 'SERVER-17',
    user: 'svc_backup',
    description:
      'Process rundll32.exe spawned by powershell.exe with no command-line arguments, then allocated executable memory inside lsass.exe. Parent/child relationship is inconsistent with any approved backup job.',
  },
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
    description:
      'Handle opened to lsass.exe memory with PROCESS_VM_READ by a non-security-tooling process. Consistent with credential material being dumped from LSASS.',
  },
  {
    id: 'ALT-1005',
    timestamp: '2026-09-14T10:41:00Z',
    source: 'NETWORK_SENSOR',
    event_type: 'Remote Connection',
    severity: 'high',
    source_ip: '10.10.5.17',
    destination_ip: '198.51.100.23',
    host: 'SERVER-17',
    user: 'svc_backup',
    description:
      'Outbound HTTPS beaconing to 198.51.100.23 at a fixed 60-second interval with low jitter and a consistent 1.4 KB payload. Destination has no business relationship and was first seen 40 minutes ago.',
  },
  {
    id: 'ALT-1006',
    timestamp: '2026-09-14T10:52:00Z',
    source: 'NETWORK_SENSOR',
    event_type: 'Lateral Movement',
    severity: 'critical',
    source_ip: '10.10.5.17',
    destination_ip: '10.10.5.31',
    host: 'SERVER-17',
    user: 'admin',
    description:
      'SMB session established from SERVER-17 to FILE-SRV-31 authenticating as domain account admin, 11 minutes after credential access was detected on SERVER-17. First ever SMB connection between these two hosts.',
  },
  {
    id: 'ALT-1007',
    timestamp: '2026-09-14T10:57:00Z',
    source: 'SIEM',
    event_type: 'Lateral Movement',
    severity: 'high',
    source_ip: '10.10.5.17',
    destination_ip: '10.10.5.31',
    host: 'FILE-SRV-31',
    user: 'admin',
    description:
      'Remote service created on FILE-SRV-31 by account admin originating from SERVER-17. Service binary written to the ADMIN$ share moments before execution.',
  },
];

/* ── Background noise ────────────────────────────────────────────────────── */

const NOISE_SOURCES = ['SIEM', 'NETWORK_SENSOR', 'THREAT_INTEL', 'ENDPOINT_EDR'] as const;

const NOISE_EVENTS = [
  'Failed Login',
  'Port Scan',
  'DNS Query',
  'Policy Violation',
  'Malware Signature',
  'Firewall Deny',
  'Account Lockout',
  'Certificate Warning',
  'USB Device Insert',
  'Privilege Escalation',
  'Config Change',
  'Anomalous Traffic',
] as const;

const NOISE_HOSTS = [
  'WKS-0142', 'WKS-0287', 'WKS-0311', 'WKS-0455', 'WKS-0512',
  'SERVER-03', 'SERVER-09', 'SERVER-22', 'FILE-SRV-31', 'DC-01',
  'MAIL-SRV-02', 'PRINT-SRV-04', 'VPN-GW-01', 'WEB-SRV-11',
] as const;

const NOISE_USERS = [
  'jdoe', 'asmith', 'rpatel', 'mchen', 'kobrien', 'svc_monitor',
  'svc_sql', 'tnguyen', 'lgarcia', 'system', '-',
] as const;

const NOISE_DESCRIPTIONS: Record<string, string> = {
  'Failed Login':
    'Repeated failed authentication attempts against a domain account within a five-minute window.',
  'Port Scan':
    'Sequential TCP connection attempts across a wide port range from a single internal source.',
  'DNS Query':
    'DNS resolution request for a newly registered domain with no prior organisational history.',
  'Policy Violation':
    'Endpoint attempted to reach a category-blocked destination and was denied by policy.',
  'Malware Signature':
    'Signature-based detection triggered on a file in a user download directory; the file was quarantined.',
  'Firewall Deny':
    'Perimeter firewall denied an outbound connection to a destination on the blocklist.',
  'Account Lockout':
    'Account locked after exceeding the configured failed-authentication threshold.',
  'Certificate Warning':
    'TLS certificate presented by an internal service is past its expiry date.',
  'USB Device Insert':
    'Removable storage device attached to a managed endpoint and enumerated.',
  'Privilege Escalation':
    'Local account added to a privileged group outside the scheduled change window.',
  'Config Change':
    'Security-relevant configuration modified on a managed host by an administrative account.',
  'Anomalous Traffic':
    'Egress volume from this host exceeded its 30-day rolling baseline by more than three standard deviations.',
};

/**
 * Severity mix skewed toward the low end, which is the realistic SOC picture
 * and the whole reason prioritisation matters.
 */
const NOISE_SEVERITY_POOL: readonly Severity[] = [
  'low', 'low', 'low', 'low', 'low', 'low', 'low', 'low',
  'medium', 'medium', 'medium', 'medium', 'medium',
  'high', 'high',
  'critical',
];

function octet(rng: () => number): number {
  return 1 + Math.floor(rng() * 253);
}

function buildNoiseAlerts(count: number): Alert[] {
  const rng = createRng(0x5e12b17);
  // Alerts stream backwards from 09:55Z, just before the golden scenario opens.
  const windowEnd = Date.parse('2026-09-14T09:55:00Z');
  const alerts: Alert[] = [];

  for (let i = 0; i < count; i += 1) {
    const event = pick(rng, NOISE_EVENTS);
    const internal = `10.10.${1 + Math.floor(rng() * 6)}.${octet(rng)}`;
    const external = `${pick(rng, ['198.51.100', '203.0.113', '192.0.2'])}.${octet(rng)}`;
    const inbound = rng() > 0.5;
    // ~92 seconds apart, fully deterministic.
    const ts = new Date(windowEnd - i * 92_000).toISOString().replace('.000Z', 'Z');

    alerts.push({
      id: `ALT-${2000 + i}`,
      timestamp: ts,
      source: pick(rng, NOISE_SOURCES),
      event_type: event,
      severity: pick(rng, NOISE_SEVERITY_POOL),
      source_ip: inbound ? external : internal,
      destination_ip: inbound ? internal : external,
      host: pick(rng, NOISE_HOSTS),
      user: pick(rng, NOISE_USERS),
      description:
        NOISE_DESCRIPTIONS[event] ?? 'Security event recorded by the ingest pipeline.',
    });
  }
  return alerts;
}

/** Newest first — the order an analyst expects in a live console. */
export const mockAlerts: Alert[] = [...GOLDEN_ALERTS, ...buildNoiseAlerts(241)].sort(
  (a, b) => b.timestamp.localeCompare(a.timestamp),
);
