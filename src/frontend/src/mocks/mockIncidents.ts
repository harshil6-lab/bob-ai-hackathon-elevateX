/**
 * MOCK DATA — for local frontend development only.
 * Not used when VITE_DEMO_MODE is unset.
 *
 * Strictly conforms to the canonical `Incident` type. Deterministic: this is a
 * static literal, so the golden demo is identical on every run.
 *
 * MITRE NOTE: the technique IDs and names below are genuine MITRE ATT&CK
 * entries, authored here as part of a mock dataset. The frontend itself holds
 * NO ID-to-name lookup table — `MitreChip` renders only the name the data hands
 * it, so against a real backend that supplies IDs alone, no name is displayed
 * and none is invented.
 *
 * SHAPE NOTE: `mitre_techniques`, `evidence` and `recommended_actions` have an
 * unconfirmed element shape (see types/incident.ts). These mocks deliberately
 * exercise BOTH sides of the union — most incidents use the structured object
 * form, INC-009 uses the bare-string form — so the renderers are proven against
 * either backend outcome.
 */

import type { Incident } from '../types/incident';

/** The golden demo incident: the SERVER-17 intrusion, INC-001. */
export const GOLDEN_INCIDENT: Incident = {
  id: 'INC-001',
  severity: 'critical',
  confidence: 94,
  status: 'investigating',
  affected_assets: ['SERVER-17', 'FILE-SRV-31'],
  alert_count: 7,
  sources: ['SIEM', 'NETWORK_SENSOR', 'THREAT_INTEL'],
  bluf:
    'A confirmed hands-on-keyboard intrusion is in progress on SERVER-17 and has already spread to FILE-SRV-31. Between 09:58Z and 10:57Z an external host on two threat-intelligence blocklists probed SERVER-17, after which the dormant service account svc_backup executed encoded PowerShell, injected into lsass.exe, and read credential material from memory. Those credentials were then used to authenticate to FILE-SRV-31 over SMB as the domain account admin and create a remote service — the first SMB session ever recorded between these two hosts. SERVER-17 is simultaneously beaconing to 198.51.100.23 on a fixed 60-second interval, indicating live command-and-control. Seven alerts across three independent feeds corroborate a single attack chain, which is why confidence is 94%. Treat domain account admin as compromised and isolate both hosts now; lateral movement is active and the blast radius is still expanding.',
  mitre_techniques: [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    {
      id: 'T1059.001',
      name: 'Command and Scripting Interpreter: PowerShell',
      tactic: 'Execution',
    },
    { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
    { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access' },
    {
      id: 'T1071.001',
      name: 'Application Layer Protocol: Web Protocols',
      tactic: 'Command and Control',
    },
    {
      id: 'T1021.002',
      name: 'Remote Services: SMB/Windows Admin Shares',
      tactic: 'Lateral Movement',
    },
  ],
  evidence: [
    {
      alert_id: 'ALT-1001',
      source: 'THREAT_INTEL',
      timestamp: '2026-09-14T09:58:00Z',
      host: 'SERVER-17',
      source_ip: '203.0.113.47',
      destination_ip: '10.10.5.17',
      event_type: 'External Suspicious Activity',
      description:
        'Inbound probing from 203.0.113.47, listed on two commercial threat-intelligence feeds as scanning infrastructure.',
    },
    {
      alert_id: 'ALT-1002',
      source: 'SIEM',
      timestamp: '2026-09-14T10:14:00Z',
      host: 'SERVER-17',
      user: 'svc_backup',
      event_type: 'PowerShell',
      description:
        'Encoded PowerShell executed with -EncodedCommand -WindowStyle Hidden by an account with no scripting history in 90 days.',
    },
    {
      alert_id: 'ALT-1003',
      source: 'SIEM',
      timestamp: '2026-09-14T10:21:00Z',
      host: 'SERVER-17',
      user: 'svc_backup',
      event_type: 'Suspicious Process',
      description:
        'rundll32.exe spawned by powershell.exe with no arguments, then allocated executable memory inside lsass.exe.',
    },
    {
      alert_id: 'ALT-1004',
      source: 'SIEM',
      timestamp: '2026-09-14T10:32:00Z',
      host: 'SERVER-17',
      user: 'svc_backup',
      event_type: 'Credential Access',
      description:
        'Handle opened to lsass.exe with PROCESS_VM_READ by a process that is not registered security tooling.',
    },
    {
      alert_id: 'ALT-1005',
      source: 'NETWORK_SENSOR',
      timestamp: '2026-09-14T10:41:00Z',
      host: 'SERVER-17',
      source_ip: '10.10.5.17',
      destination_ip: '198.51.100.23',
      event_type: 'Remote Connection',
      description:
        'Fixed-interval 60s HTTPS beaconing with low jitter and constant 1.4 KB payload to a destination first seen 40 minutes ago.',
    },
    {
      alert_id: 'ALT-1006',
      source: 'NETWORK_SENSOR',
      timestamp: '2026-09-14T10:52:00Z',
      host: 'SERVER-17',
      user: 'admin',
      source_ip: '10.10.5.17',
      destination_ip: '10.10.5.31',
      event_type: 'Lateral Movement',
      description:
        'SMB session to FILE-SRV-31 as domain account admin, 11 minutes after credential access. No prior SMB history between these hosts.',
    },
    {
      alert_id: 'ALT-1007',
      source: 'SIEM',
      timestamp: '2026-09-14T10:57:00Z',
      host: 'FILE-SRV-31',
      user: 'admin',
      event_type: 'Lateral Movement',
      description:
        'Remote service created on FILE-SRV-31 from SERVER-17; service binary staged on the ADMIN$ share immediately beforehand.',
    },
  ],
  recommended_actions: [
    {
      action: 'Network-isolate SERVER-17 and FILE-SRV-31 immediately',
      priority: 'immediate',
      rationale:
        'Lateral movement is active and C2 is live. Isolation halts expansion while preserving volatile memory for forensics.',
    },
    {
      action: 'Force a credential reset for domain account admin and svc_backup',
      priority: 'immediate',
      rationale:
        'LSASS memory was read on SERVER-17 and admin was subsequently used on FILE-SRV-31. Both must be presumed compromised.',
    },
    {
      action: 'Block egress to 198.51.100.23 at the perimeter',
      priority: 'immediate',
      rationale: 'Terminates the command-and-control channel observed beaconing at a fixed 60-second interval.',
    },
    {
      action: 'Capture a memory image of SERVER-17 before any reboot',
      priority: 'high',
      rationale:
        'The injected payload is memory-resident; a reboot destroys the primary evidence of the injection technique.',
    },
    {
      action: 'Hunt for the same SMB pattern across all hosts in 10.10.5.0/24',
      priority: 'high',
      rationale:
        'The admin credential may already have been replayed elsewhere. Scope must be established before containment is declared complete.',
    },
    {
      action: 'Audit svc_backup for interactive-logon rights and scheduled tasks',
      priority: 'medium',
      rationale:
        'A backup service account executing hidden PowerShell indicates a privilege configuration that should not have existed.',
    },
  ],
};

export const mockIncidents: Incident[] = [
  GOLDEN_INCIDENT,
  {
    id: 'INC-002',
    severity: 'high',
    confidence: 41,
    status: 'triage',
    affected_assets: ['WEB-SRV-11'],
    alert_count: 12,
    sources: ['NETWORK_SENSOR', 'SIEM'],
    bluf:
      'WEB-SRV-11 shows a sustained spike in outbound traffic that exceeds its 30-day baseline, alongside repeated authentication failures against the same service account. The pattern is consistent with either data staging or a misconfigured backup job that began after the 12 September change window. Confidence is low at 41% because no execution, injection or credential-access telemetry corroborates a malicious explanation, and the traffic destination is inside an allocated corporate range. Verify the change record before escalating.',
    mitre_techniques: [
      { id: 'T1030', name: 'Data Transfer Size Limits', tactic: 'Exfiltration' },
      { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    ],
    evidence: [
      {
        alert_id: 'ALT-2014',
        source: 'NETWORK_SENSOR',
        timestamp: '2026-09-14T08:12:00Z',
        host: 'WEB-SRV-11',
        description: 'Egress volume exceeded the rolling 30-day baseline by 3.4 standard deviations.',
      },
      {
        alert_id: 'ALT-2031',
        source: 'SIEM',
        timestamp: '2026-09-14T08:44:00Z',
        host: 'WEB-SRV-11',
        user: 'svc_sql',
        description: 'Nine failed authentication attempts for svc_sql within a four-minute window.',
      },
    ],
    recommended_actions: [
      {
        action: 'Correlate the traffic spike against change record CHG-4471',
        priority: 'high',
        rationale: 'A scheduled backup reconfiguration on 12 September is the most likely benign explanation.',
      },
      {
        action: 'Confirm the destination range is corporate-owned',
        priority: 'medium',
        rationale: 'Ownership determines whether this is exfiltration or an internal transfer.',
      },
    ],
  },
  {
    id: 'INC-003',
    severity: 'high',
    confidence: 78,
    status: 'investigating',
    affected_assets: ['DC-01'],
    alert_count: 5,
    sources: ['SIEM', 'ENDPOINT_EDR'],
    bluf:
      'Two local accounts were added to privileged groups on DC-01 outside the approved change window, followed by a security-relevant configuration change from the same session. No corresponding change ticket exists. This is either an undocumented administrative action or the persistence stage of an intrusion. Confidence is 78% that the activity is unauthorised; the originating workstation and the approving manager should be identified before privileges are revoked.',
    mitre_techniques: [
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
    ],
    evidence: [
      {
        alert_id: 'ALT-2077',
        source: 'SIEM',
        timestamp: '2026-09-14T07:31:00Z',
        host: 'DC-01',
        user: 'kobrien',
        description: 'Local account added to Domain Admins outside the scheduled change window.',
      },
      {
        alert_id: 'ALT-2079',
        source: 'ENDPOINT_EDR',
        timestamp: '2026-09-14T07:35:00Z',
        host: 'DC-01',
        user: 'kobrien',
        description: 'Security-relevant Group Policy setting modified from the same logon session.',
      },
    ],
    recommended_actions: [
      {
        action: 'Identify the originating workstation for the kobrien session on DC-01',
        priority: 'high',
        rationale: 'Distinguishes an undocumented admin action from a compromised account.',
      },
      {
        action: 'Require change-ticket evidence before the new group memberships are retained',
        priority: 'high',
        rationale: 'No CHG record currently corresponds to this privilege grant.',
      },
    ],
  },
  {
    id: 'INC-004',
    severity: 'medium',
    confidence: 66,
    status: 'triage',
    affected_assets: ['WKS-0287', 'WKS-0311'],
    alert_count: 9,
    sources: ['ENDPOINT_EDR'],
    bluf:
      'Two workstations triggered signature-based malware detections on files delivered to user download directories within eleven minutes of each other. Both files were quarantined successfully and neither host shows post-execution activity. This most likely represents a single phishing wave that endpoint controls stopped. Confidence is 66%; the shared delivery vector should be confirmed and the mail gateway queried for further recipients.',
    mitre_techniques: [
      { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
    ],
    evidence: [
      {
        alert_id: 'ALT-2102',
        source: 'ENDPOINT_EDR',
        timestamp: '2026-09-14T06:48:00Z',
        host: 'WKS-0287',
        user: 'jdoe',
        description: 'Signature detection on a file in the user download directory; quarantined.',
      },
      {
        alert_id: 'ALT-2108',
        source: 'ENDPOINT_EDR',
        timestamp: '2026-09-14T06:59:00Z',
        host: 'WKS-0311',
        user: 'asmith',
        description: 'Signature detection on a matching file hash; quarantined.',
      },
    ],
    recommended_actions: [
      {
        action: 'Query the mail gateway for other recipients of the matching attachment hash',
        priority: 'high',
        rationale: 'Two hits in eleven minutes suggests a wave rather than an isolated delivery.',
      },
      {
        action: 'Confirm neither host executed the quarantined file',
        priority: 'medium',
        rationale: 'Quarantine success has been reported but post-execution telemetry should be checked directly.',
      },
    ],
  },
  {
    id: 'INC-005',
    severity: 'medium',
    confidence: 52,
    status: 'triage',
    affected_assets: ['VPN-GW-01'],
    alert_count: 18,
    sources: ['NETWORK_SENSOR', 'SIEM'],
    bluf:
      'A high volume of failed VPN authentications originated from a range of residential IP addresses across a two-hour window, with no successful authentication resulting. The distribution across many accounts and the absence of any success is more consistent with opportunistic credential stuffing than with a targeted operation. Confidence is 52%. Existing lockout policy appears to have functioned as designed; monitor for a follow-up attempt using a narrower account set.',
    mitre_techniques: [
      { id: 'T1110.004', name: 'Brute Force: Credential Stuffing', tactic: 'Credential Access' },
    ],
    evidence: [
      {
        alert_id: 'ALT-2140',
        source: 'NETWORK_SENSOR',
        timestamp: '2026-09-14T05:02:00Z',
        host: 'VPN-GW-01',
        description: '218 failed VPN authentication attempts across 47 distinct accounts.',
      },
    ],
    recommended_actions: [
      {
        action: 'Confirm no VPN authentication succeeded from the implicated source ranges',
        priority: 'high',
        rationale: 'A single success would change this from noise to an active intrusion.',
      },
      {
        action: 'Review lockout thresholds against the observed attempt rate',
        priority: 'low',
        rationale: 'Validates that the control is calibrated for this volume.',
      },
    ],
  },
  {
    id: 'INC-006',
    severity: 'medium',
    confidence: 71,
    status: 'investigating',
    affected_assets: ['MAIL-SRV-02'],
    alert_count: 6,
    sources: ['SIEM'],
    bluf:
      'MAIL-SRV-02 resolved several newly registered domains with no prior organisational history, in a pattern consistent with domain-generation algorithm behaviour. No outbound session was successfully established to any resolved address. Confidence is 71% that this reflects an unwanted process on the host rather than legitimate software update behaviour. Identify the resolving process before treating the host as clean.',
    mitre_techniques: [{ id: 'T1568.002', name: 'Dynamic Resolution: Domain Generation Algorithms', tactic: 'Command and Control' }],
    evidence: [
      {
        alert_id: 'ALT-2166',
        source: 'SIEM',
        timestamp: '2026-09-14T04:19:00Z',
        host: 'MAIL-SRV-02',
        description: 'Fourteen DNS queries for newly registered domains within a six-minute window.',
      },
    ],
    recommended_actions: [
      {
        action: 'Identify the process issuing the DNS queries on MAIL-SRV-02',
        priority: 'high',
        rationale: 'Attribution to a process separates DGA malware from an update client with an unusual CDN pattern.',
      },
    ],
  },
  {
    id: 'INC-007',
    severity: 'low',
    confidence: 96,
    status: 'contained',
    affected_assets: ['WKS-0455'],
    alert_count: 3,
    sources: ['ENDPOINT_EDR'],
    bluf:
      'An unapproved removable storage device was attached to WKS-0455 and enumerated by the operating system. No file was read from or written to the device before policy blocked it, and the device was removed nine minutes later. Confidence that this is exactly what occurred is very high at 96% because the endpoint agent captured the complete device lifecycle. Business impact is low; this is a policy matter rather than a security incident, and is recorded for the acceptable-use process.',
    mitre_techniques: [{ id: 'T1091', name: 'Replication Through Removable Media', tactic: 'Lateral Movement' }],
    evidence: [
      {
        alert_id: 'ALT-2190',
        source: 'ENDPOINT_EDR',
        timestamp: '2026-09-14T03:27:00Z',
        host: 'WKS-0455',
        user: 'rpatel',
        description: 'Removable storage device attached and enumerated; policy blocked all file access.',
      },
    ],
    recommended_actions: [
      {
        action: 'Refer to the acceptable-use process for WKS-0455',
        priority: 'low',
        rationale: 'Device control performed correctly; the residual issue is behavioural, not technical.',
      },
    ],
  },
  {
    id: 'INC-008',
    severity: 'low',
    confidence: 88,
    status: 'closed',
    affected_assets: ['PRINT-SRV-04'],
    alert_count: 4,
    sources: ['SIEM'],
    bluf:
      'The TLS certificate presented by the print service on PRINT-SRV-04 expired on 11 September, generating repeated warnings from connecting clients. This is a hygiene defect with no adversary involvement; confidence is 88% based on certificate metadata and the absence of any accompanying anomaly. The practical risk is that analysts learn to dismiss certificate warnings, which erodes a genuine detection signal.',
    mitre_techniques: [],
    evidence: [
      {
        alert_id: 'ALT-2204',
        source: 'SIEM',
        timestamp: '2026-09-14T02:05:00Z',
        host: 'PRINT-SRV-04',
        description: 'TLS certificate past expiry date; clients reporting validation warnings.',
      },
    ],
    recommended_actions: [
      {
        action: 'Renew the PRINT-SRV-04 service certificate and add it to the expiry monitor',
        priority: 'low',
        rationale: 'Removes recurring false-positive noise from the certificate-warning detection.',
      },
    ],
  },
  {
    // Deliberately uses the BARE-STRING element form for mitre_techniques,
    // evidence and recommended_actions, to prove the renderers handle both
    // sides of the compatibility union. See types/incident.ts.
    id: 'INC-009',
    severity: 'low',
    confidence: 34,
    status: 'triage',
    affected_assets: ['WKS-0142'],
    alert_count: 2,
    sources: ['SIEM'],
    bluf:
      'A single host issued a small number of port-scan-like connection attempts across an internal subnet. The volume is far below any threshold that would indicate reconnaissance, and the source is an IT workstation that runs an asset-inventory tool. Confidence is 34% that this is even noteworthy; it is retained only so the pattern can be compared against future activity from the same host.',
    mitre_techniques: ['T1046'],
    evidence: [
      'ALT-2221 — SIEM — WKS-0142 — sequential TCP connection attempts across an internal range.',
      'ALT-2229 — SIEM — WKS-0142 — repeat of the same pattern 40 minutes later.',
    ],
    recommended_actions: [
      'Confirm the asset-inventory tool schedule on WKS-0142 accounts for both time windows.',
    ],
  },
];
