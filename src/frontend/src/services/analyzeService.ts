/**
 * ANALYZE SERVICE — POST /api/analyze
 *
 * Endpoint path is frozen by AGENTS.md. Response shape is PROVISIONAL
 * (see types/dashboard.ts).
 *
 * ---------------------------------------------------------------------------
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE
 * ---------------------------------------------------------------------------
 * A failed analysis is ALWAYS reported as a failure.
 *
 * `triggerAnalysis()` resolves to `{ status: 'success' }` only when the backend
 * actually returned a 2xx. Any non-2xx, timeout or network error resolves to
 * `{ status: 'failure' }` carrying the real ApiError. There is no retry-with-
 * mock-data path, no optimistic success, and no code path in which mock data
 * substitutes for a failed call.
 *
 * In demo mode the request is not attempted at all — the caller is told plainly
 * via `simulated: true`, and DemoModeBanner is on screen throughout, so a judge
 * is never shown a simulated run dressed up as a real one.
 */

import { apiClient, ApiError } from './apiClient';
import { isDemoMode } from './demoMode';
import type { AnalyzeResult } from '../types/dashboard';

export type AnalyzeOutcome =
  | {
      status: 'success';
      result: AnalyzeResult;
      /** True only when demo mode produced this without contacting a backend. */
      simulated: boolean;
    }
  | {
      status: 'failure';
      error: ApiError;
    };

/** Analysis can take a while to correlate a large alert volume. */
const ANALYZE_TIMEOUT_MS = 60_000;

export async function triggerAnalysis(): Promise<AnalyzeOutcome> {
  if (isDemoMode()) {
    const [{ mockAlerts }, { mockIncidents }] = await Promise.all([
      import('../mocks/mockAlerts'),
      import('../mocks/mockIncidents'),
    ]);
    // Long enough for the "analyzing" state to be legible on a projector.
    await new Promise((resolve) => setTimeout(resolve, 1800));
    return {
      status: 'success',
      simulated: true,
      result: {
        alerts_processed: mockAlerts.length,
        incidents_created: mockIncidents.length,
        status: 'completed',
        message: 'Simulated correlation run (demo mode — no backend was contacted).',
      },
    };
  }

  try {
    const result = await apiClient.post<AnalyzeResult>('/api/analyze', undefined, {
      timeoutMs: ANALYZE_TIMEOUT_MS,
    });
    // A 2xx with an unexpected (or empty) body is still a real success.
    return { status: 'success', simulated: false, result: result ?? {} };
  } catch (error) {
    return {
      status: 'failure',
      error:
        error instanceof ApiError
          ? error
          : new ApiError('Analysis request failed.', {
              status: 0,
              kind: 'network',
              path: '/api/analyze',
            }),
    };
  }
}
