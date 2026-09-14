/**
 * INCIDENTS SERVICE — GET /api/incidents, GET /api/incidents/{id}
 *
 * Endpoint paths are frozen by AGENTS.md and must not be renamed.
 * All network I/O goes through apiClient. Demo mode is checked BEFORE the
 * request, never as a fallback after one fails.
 */

import { apiClient, ApiError } from './apiClient';
import { isDemoMode, demoDelay } from './demoMode';
import { severityRank } from '../types/alert';
import { confidencePercent } from '../types/incident';
import type { Incident, IncidentQueryParams } from '../types/incident';

/** Response-envelope tolerance only. No Incident field is renamed or invented. */
function unwrapList(payload: unknown): Incident[] {
  if (Array.isArray(payload)) return payload as Incident[];
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>;
    for (const key of ['incidents', 'items', 'results', 'data']) {
      if (Array.isArray(record[key])) return record[key] as Incident[];
    }
  }
  return [];
}

/**
 * The canonical prioritisation rule, used by both the Incident Explorer and the
 * Dashboard's "highest-priority incident" selection so the two can never
 * disagree about which incident matters most.
 *
 * Severity first, then confidence. Severity answers "how bad", confidence
 * answers "how sure" — a critical incident outranks a high-confidence low one.
 */
export function byPriority(a: Incident, b: Incident): number {
  const bySeverity = severityRank(a.severity) - severityRank(b.severity);
  if (bySeverity !== 0) return bySeverity;
  const byConfidence = confidencePercent(b.confidence) - confidencePercent(a.confidence);
  if (byConfidence !== 0) return byConfidence;
  return a.id.localeCompare(b.id);
}

export async function getIncidents(params?: IncidentQueryParams): Promise<Incident[]> {
  if (isDemoMode()) {
    const { mockIncidents } = await import('../mocks/mockIncidents');
    await demoDelay();
    return mockIncidents;
  }
  const payload = await apiClient.get<unknown>('/api/incidents', {
    params: params ? { ...params } : undefined,
  });
  return unwrapList(payload);
}

export async function getIncidentById(id: string): Promise<Incident> {
  if (isDemoMode()) {
    const { mockIncidents } = await import('../mocks/mockIncidents');
    await demoDelay(220);
    const match = mockIncidents.find((incident) => incident.id === id);
    if (!match) {
      throw new ApiError(`Incident ${id} was not found.`, {
        status: 404,
        kind: 'http',
        path: `/api/incidents/${id}`,
      });
    }
    return match;
  }
  return apiClient.get<Incident>(`/api/incidents/${encodeURIComponent(id)}`);
}
