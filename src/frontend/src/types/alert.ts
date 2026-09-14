/**
 * CANONICAL ALERT SCHEMA
 *
 * Mirrors the frozen contract in AGENTS.md ("Canonical Alert Schema") exactly.
 * Field names are CONFIRMED against AGENTS.md, which is the authoritative
 * shared contract for this repository. They are NOT yet confirmed against a
 * running backend, because src/backend/ has not been implemented at the time
 * of writing.
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
 * PROVISIONAL: the backend does not exist yet, so it is unknown which (if any)
 * of these the API supports server-side. The Alert Explorer therefore filters
 * CLIENT-SIDE over the full result set and does not depend on any of these
 * being honoured. They are sent through only so that server-side filtering can
 * be adopted later without changing call sites.
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
