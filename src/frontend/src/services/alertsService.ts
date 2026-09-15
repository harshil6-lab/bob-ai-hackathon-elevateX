/**
 * ALERTS SERVICE — GET /api/alerts, GET /api/alerts/{id}
 *
 * Endpoint paths are frozen by AGENTS.md and must not be renamed.
 * All network I/O goes through apiClient. Demo mode is checked BEFORE the
 * request, never as a fallback after one fails.
 */

import { apiClient, ApiError } from './apiClient';
import { isDemoMode, demoDelay } from './demoMode';
import type { Alert, AlertQueryParams } from '../types/alert';

/**
 * Unwraps the backend's `{ alerts: [...] }` envelope. A bare array is also
 * tolerated for compatibility with alternative API deployments. No field inside
 * an Alert is renamed or invented.
 */
function unwrapList(payload: unknown): Alert[] {
  if (Array.isArray(payload)) return payload as Alert[];
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>;
    for (const key of ['alerts', 'items', 'results', 'data']) {
      if (Array.isArray(record[key])) return record[key] as Alert[];
    }
  }
  return [];
}

export async function getAlerts(params?: AlertQueryParams): Promise<Alert[]> {
  if (isDemoMode()) {
    const { mockAlerts } = await import('../mocks/mockAlerts');
    await demoDelay();
    return mockAlerts;
  }
  const payload = await apiClient.get<unknown>('/api/alerts', {
    params: params ? { ...params } : undefined,
  });
  return unwrapList(payload);
}

export async function getAlertById(id: string): Promise<Alert> {
  if (isDemoMode()) {
    const { mockAlerts } = await import('../mocks/mockAlerts');
    await demoDelay(180);
    const match = mockAlerts.find((alert) => alert.id === id);
    if (!match) {
      throw new ApiError(`Alert ${id} was not found.`, {
        status: 404,
        kind: 'http',
        path: `/api/alerts/${id}`,
      });
    }
    return match;
  }
  return apiClient.get<Alert>(`/api/alerts/${encodeURIComponent(id)}`);
}
