/**
 * DASHBOARD SERVICE — GET /api/dashboard/stats
 *
 * Endpoint path is frozen by AGENTS.md. The RESPONSE SHAPE is provisional —
 * see types/dashboard.ts for the full caveat.
 */

import { apiClient } from './apiClient';
import { isDemoMode, demoDelay } from './demoMode';
import type { Severity } from '../types/alert';
import type { Alert } from '../types/alert';
import type { Incident } from '../types/incident';
import type {
  DashboardStats,
  SeverityDistribution,
  SourceDistribution,
} from '../types/dashboard';
import { byPriority } from './incidentsService';

export async function getDashboardStats(): Promise<DashboardStats> {
  if (isDemoMode()) {
    const { mockDashboardStats } = await import('../mocks/mockDashboardStats');
    await demoDelay();
    return mockDashboardStats;
  }
  return apiClient.get<DashboardStats>('/api/dashboard/stats');
}

/**
 * Computes an equivalent dashboard view from the CONFIRMED /api/alerts and
 * /api/incidents contracts.
 *
 * WHY THIS EXISTS: /api/dashboard/stats has a provisional response shape. If
 * Member 2's implementation names its fields differently, the Dashboard would
 * otherwise render empty sections. This lets the Dashboard fill a gap in a
 * PROVISIONAL field using data it already fetched from a CONFIRMED endpoint.
 *
 * IMPORTANT: this is NOT an error fallback. It is only ever merged into a
 * SUCCESSFUL stats response (see `mergeWithDerived`). If /api/dashboard/stats
 * fails, that failure is surfaced as an ErrorState — never papered over with a
 * derived figure.
 */
export function deriveDashboardStats(
  alerts: Alert[],
  incidents: Incident[],
): Required<Pick<
  DashboardStats,
  | 'total_alerts'
  | 'total_incidents'
  | 'critical_count'
  | 'high_count'
  | 'severity_distribution'
  | 'source_distribution'
  | 'top_incident'
  | 'recent_incidents'
>> {
  const severity_distribution: SeverityDistribution = {};
  const source_distribution: SourceDistribution = {};

  for (const alert of alerts) {
    const key = alert.severity as Severity;
    severity_distribution[key] = (severity_distribution[key] ?? 0) + 1;
    source_distribution[alert.source] = (source_distribution[alert.source] ?? 0) + 1;
  }

  const ranked = [...incidents].sort(byPriority);

  return {
    total_alerts: alerts.length,
    total_incidents: incidents.length,
    critical_count: incidents.filter((i) => i.severity === 'critical').length,
    high_count: incidents.filter((i) => i.severity === 'high').length,
    severity_distribution,
    source_distribution,
    top_incident: ranked[0] ?? null,
    recent_incidents: ranked.slice(0, 5),
  };
}

/**
 * Fills only the PROVISIONAL fields the backend did not return. A field the
 * backend DID return always wins — the frontend never overrides real data.
 */
export function mergeWithDerived(
  stats: DashboardStats,
  alerts: Alert[],
  incidents: Incident[],
): DashboardStats {
  const derived = deriveDashboardStats(alerts, incidents);
  const isMissing = (value: unknown) =>
    value === undefined ||
    value === null ||
    (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) ||
    (Array.isArray(value) && value.length === 0);

  return {
    ...stats,
    total_alerts: stats.total_alerts ?? derived.total_alerts,
    total_incidents: stats.total_incidents ?? derived.total_incidents,
    critical_count: stats.critical_count ?? derived.critical_count,
    high_count: stats.high_count ?? derived.high_count,
    severity_distribution: isMissing(stats.severity_distribution)
      ? derived.severity_distribution
      : stats.severity_distribution,
    source_distribution: isMissing(stats.source_distribution)
      ? derived.source_distribution
      : stats.source_distribution,
    top_incident: stats.top_incident ?? derived.top_incident,
    recent_incidents: isMissing(stats.recent_incidents)
      ? derived.recent_incidents
      : stats.recent_incidents,
  };
}
