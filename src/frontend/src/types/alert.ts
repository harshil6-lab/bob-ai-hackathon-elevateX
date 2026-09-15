/**
 * CANONICAL ALERT SCHEMA
 *
 * Mirrors the frozen contract in AGENTS.md ("Canonical Alert Schema") exactly.
 * Field names are confirmed against AGENTS.md and the integrated backend.
 *
 * Do not rename, add, or omit fields here without team approval — this type is
 * one half of the frontend/backend contract.
 */

/** Severity ordering used across the UI. Index 0 is the most severe. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

export type Severity = (typeof SEVERITY_ORDER)[number];

export interface Alert {
  id: string;
  /** ISO-8601 UTC timestamp, e.g. "2026-09-14T10:32:00Z". */
  timestamp: string;
  /** Originating feed, e.g. "SIEM", "NETWORK_SENSOR", "THREAT_INTEL". */
  source: string;
  event_type: string;
  severity: Severity;
  source_ip: string;
  destination_ip: string;
  host: string;
  user: string;
  description: string;
}

/**
 * Query parameters for GET /api/alerts.
 *
 * Optional query parameters. The current backend returns the full result set,
 * so the Alert Explorer filters CLIENT-SIDE. These parameters are retained so
 * server-side filtering can be adopted later without changing call sites.
 */
export interface AlertQueryParams {
  severity?: Severity;
  source?: string;
  event_type?: string;
  host?: string;
  limit?: number;
  offset?: number;
}

/** Rank helper: lower number = more severe. Unknown values sort last. */
export function severityRank(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity as Severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

/** Narrowing guard for values arriving from the network. */
export function isSeverity(value: unknown): value is Severity {
  return (
    typeof value === 'string' && SEVERITY_ORDER.includes(value as Severity)
  );
}
