/**
 * MOCK DATA — for local frontend development only.
 * Not used when VITE_DEMO_MODE is unset.
 *
 * Conforms to the PROVISIONAL `DashboardStats` type (see types/dashboard.ts).
 * Derived from the mock alerts and incidents rather than hand-written, so the
 * headline numbers on the Dashboard always reconcile exactly with what the
 * Alert Explorer and Incident Explorer actually list. A demo where the summary
 * disagrees with the detail is worse than no summary at all.
 */

import type { DashboardStats, SeverityDistribution, SourceDistribution } from '../types/dashboard';
import type { Severity } from '../types/alert';
import { severityRank } from '../types/alert';
import { confidencePercent } from '../types/incident';
import { mockAlerts } from './mockAlerts';
import { mockIncidents } from './mockIncidents';

function countAlertSeverities(): SeverityDistribution {
  const distribution: SeverityDistribution = {};
  for (const alert of mockAlerts) {
    const key = alert.severity as Severity;
    distribution[key] = (distribution[key] ?? 0) + 1;
  }
  return distribution;
}

function countAlertSources(): SourceDistribution {
  const distribution: SourceDistribution = {};
  for (const alert of mockAlerts) {
    distribution[alert.source] = (distribution[alert.source] ?? 0) + 1;
  }
  return distribution;
}

/** Most severe first; confidence breaks ties. Mirrors the real selection rule. */
const rankedIncidents = [...mockIncidents].sort((a, b) => {
  const bySeverity = severityRank(a.severity) - severityRank(b.severity);
  if (bySeverity !== 0) return bySeverity;
  return confidencePercent(b.confidence) - confidencePercent(a.confidence);
});

export const mockDashboardStats: DashboardStats = {
  total_alerts: mockAlerts.length,
  total_incidents: mockIncidents.length,
  critical_count: mockIncidents.filter((i) => i.severity === 'critical').length,
  high_count: mockIncidents.filter((i) => i.severity === 'high').length,
  severity_distribution: countAlertSeverities(),
  source_distribution: countAlertSources(),
  top_incident: rankedIncidents[0] ?? null,
  recent_incidents: rankedIncidents.slice(0, 5),
  last_analysis_at: '2026-09-14T11:02:00Z',
};
