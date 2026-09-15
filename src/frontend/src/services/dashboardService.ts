/**
 * DASHBOARD SERVICE — GET /api/dashboard/stats
 *
 * Endpoint path is frozen by AGENTS.md. The backend response is mapped into
 * the frontend dashboard view model below.
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
  const raw = await apiClient.get<{
    total_alerts: number;
    total_incidents: number;
    critical_incidents: number;
    high_incidents: number;
    severity_distribution: SeverityDistribution;
    source_counts: SourceDistribution;
    status_distribution: Record<string, number>;
  }>('/api/dashboard/stats');

  return {
    total_alerts: raw.total_alerts,
    total_incidents: raw.total_incidents,
    critical_count: raw.critical_incidents,
    high_count: raw.high_incidents,
    severity_distribution: raw.severity_distribution,
    source_distribution: raw.source_counts,
  };
}

/**
 * Computes an equivalent dashboard view from the CONFIRMED /api/alerts and
 * /api/incidents contracts.
 *
 * WHY THIS EXISTS: the backend does not currently return `top_incident` or
 * `recent_incidents`. This computes those derived fields from the confirmed
 * `/api/alerts` and `/api/incidents` responses already used by the Dashboard.
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
 * Fills only the derived fields the backend did not return. A field the
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
