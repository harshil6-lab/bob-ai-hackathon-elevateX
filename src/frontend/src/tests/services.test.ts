/**
 * API client and service-layer tests.
 *
 * The critical assertions are the negative ones: a failed request must NEVER
 * resolve as a success, and must NEVER be quietly replaced with mock data.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { apiClient, ApiError, getApiBaseUrl } from '../services/apiClient';
import { getAlerts, getAlertById } from '../services/alertsService';
import { getIncidents, getIncidentById } from '../services/incidentsService';
import { getDashboardStats, deriveDashboardStats, mergeWithDerived } from '../services/dashboardService';
import { triggerAnalysis } from '../services/analyzeService';
import { isDemoMode } from '../services/demoMode';
import type { Alert } from '../types/alert';
import type { Incident } from '../types/incident';

const ALERT: Alert = {
  id: 'ALT-1001',
  timestamp: '2026-09-14T10:32:00Z',
  source: 'SIEM',
  event_type: 'PowerShell',
  severity: 'medium',
  source_ip: '10.10.1.20',
  destination_ip: '10.10.5.17',
  host: 'SERVER-17',
  user: 'admin',
  description: 'Suspicious PowerShell execution',
};

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'OK',
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function errorResponse(status: number, body: unknown = { detail: 'Boom' }): Response {
  return {
    ok: false,
    status,
    statusText: 'Error',
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('apiClient', () => {
  it('reads the base URL from VITE_API_BASE_URL', () => {
    expect(getApiBaseUrl()).toBe('http://localhost:8000');
  });

  it('parses a successful JSON response', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ok: true }));
    await expect(apiClient.get('/api/alerts')).resolves.toEqual({ ok: true });
  });

  it('appends query params and drops empty ones', async () => {
    fetchMock.mockResolvedValue(jsonResponse([]));
    await apiClient.get('/api/alerts', {
      params: { severity: 'critical', host: undefined, source: '' },
    });

    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain('severity=critical');
    expect(url).not.toContain('host=');
    expect(url).not.toContain('source=');
  });

  it('throws a typed ApiError exposing the HTTP status', async () => {
    fetchMock.mockResolvedValue(errorResponse(500, { detail: 'Correlation engine crashed' }));

    await expect(apiClient.get('/api/alerts')).rejects.toMatchObject({
      name: 'ApiError',
      status: 500,
      kind: 'http',
      path: '/api/alerts',
      message: 'Correlation engine crashed',
    });
  });

  it('throws a network ApiError when fetch itself rejects', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));

    const error = await apiClient.get('/api/alerts').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).kind).toBe('network');
    expect((error as ApiError).status).toBe(0);
    expect((error as ApiError).userMessage).toContain('Could not reach the backend');
  });

  it('classifies an aborted request as a timeout', async () => {
    fetchMock.mockImplementation((_url: string, init: RequestInit) => {
      // Simulate the abort signal firing.
      (init.signal as AbortSignal & { onabort?: () => void }) === undefined;
      return Promise.reject(new DOMException('Aborted', 'AbortError'));
    });

    const error = await apiClient.get('/api/alerts').catch((e: unknown) => e);
    expect((error as ApiError).kind).toBe('timeout');
  });

  it('treats an empty 2xx body as a valid success (204 from POST /api/analyze)', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 204,
      statusText: 'No Content',
      text: async () => '',
    } as unknown as Response);

    await expect(apiClient.post('/api/analyze')).resolves.toBeUndefined();
  });

  it('throws a parse error on a malformed body', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () => 'not json {{{',
    } as unknown as Response);

    const error = await apiClient.get('/api/alerts').catch((e: unknown) => e);
    expect((error as ApiError).kind).toBe('parse');
  });
});

describe('alertsService', () => {
  it('calls GET /api/alerts and returns a bare array', async () => {
    fetchMock.mockResolvedValue(jsonResponse([ALERT]));
    const alerts = await getAlerts();

    expect(fetchMock.mock.calls[0][0]).toContain('/api/alerts');
    expect(alerts).toEqual([ALERT]);
  });

  it('unwraps a { alerts: [...] } envelope without renaming any field', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ alerts: [ALERT] }));
    const alerts = await getAlerts();

    expect(alerts).toHaveLength(1);
    // Canonical snake_case field names survive intact.
    expect(alerts[0]).toHaveProperty('event_type', 'PowerShell');
    expect(alerts[0]).toHaveProperty('source_ip', '10.10.1.20');
    expect(alerts[0]).toHaveProperty('destination_ip', '10.10.5.17');
  });

  it('propagates an API error instead of substituting mock data', async () => {
    fetchMock.mockResolvedValue(errorResponse(500));
    await expect(getAlerts()).rejects.toBeInstanceOf(ApiError);
  });

  it('propagates a network failure instead of substituting mock data', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    const result = await getAlerts().then(
      () => 'RESOLVED',
      (e: unknown) => e,
    );
    // Must NOT have resolved with mock alerts.
    expect(result).not.toBe('RESOLVED');
    expect(result).toBeInstanceOf(ApiError);
  });

  it('calls GET /api/alerts/{id}', async () => {
    fetchMock.mockResolvedValue(jsonResponse(ALERT));
    await getAlertById('ALT-1001');
    expect(fetchMock.mock.calls[0][0]).toContain('/api/alerts/ALT-1001');
  });
});

describe('incidentsService', () => {
  it('calls GET /api/incidents and GET /api/incidents/{id}', async () => {
    fetchMock.mockResolvedValue(jsonResponse([]));
    await getIncidents();
    expect(fetchMock.mock.calls[0][0]).toContain('/api/incidents');

    fetchMock.mockResolvedValue(jsonResponse({ id: 'INC-001' }));
    await getIncidentById('INC-001');
    expect(fetchMock.mock.calls[1][0]).toContain('/api/incidents/INC-001');
  });

  it('propagates a 404 with its status intact', async () => {
    fetchMock.mockResolvedValue(errorResponse(404, { detail: 'Not found' }));
    const error = await getIncidentById('INC-999').catch((e: unknown) => e);
    expect((error as ApiError).status).toBe(404);
  });
});

describe('dashboardService', () => {
  it('calls GET /api/dashboard/stats', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ total_alerts: 5 }));
    await getDashboardStats();
    expect(fetchMock.mock.calls[0][0]).toContain('/api/dashboard/stats');
  });

  it('derives distributions and the top incident from confirmed endpoints', () => {
    const incidents = [
      { id: 'INC-002', severity: 'high', confidence: 90 },
      { id: 'INC-001', severity: 'critical', confidence: 50 },
      { id: 'INC-003', severity: 'low', confidence: 99 },
    ] as Incident[];

    const derived = deriveDashboardStats(
      [ALERT, { ...ALERT, id: 'ALT-2', severity: 'critical', source: 'EDR' }],
      incidents,
    );

    expect(derived.total_alerts).toBe(2);
    expect(derived.total_incidents).toBe(3);
    expect(derived.critical_count).toBe(1);
    expect(derived.high_count).toBe(1);
    expect(derived.severity_distribution).toEqual({ medium: 1, critical: 1 });
    expect(derived.source_distribution).toEqual({ SIEM: 1, EDR: 1 });
    // Severity outranks confidence: critical/50 beats low/99.
    expect(derived.top_incident?.id).toBe('INC-001');
  });

  it('never overrides a field the backend actually returned', () => {
    const merged = mergeWithDerived({ total_alerts: 9999 }, [ALERT], []);
    expect(merged.total_alerts).toBe(9999);
    // The omitted field is filled from confirmed data.
    expect(merged.total_incidents).toBe(0);
  });
});

describe('analyzeService — the no-fake-success guarantee', () => {
  it('POSTs to /api/analyze and reports a genuine success', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ incidents_created: 9, alerts_processed: 248 }));

    const outcome = await triggerAnalysis();

    expect(fetchMock.mock.calls[0][0]).toContain('/api/analyze');
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('POST');
    expect(outcome.status).toBe('success');
    if (outcome.status === 'success') {
      expect(outcome.simulated).toBe(false);
      expect(outcome.result.incidents_created).toBe(9);
    }
  });

  it('reports FAILURE on an HTTP error — never a success', async () => {
    fetchMock.mockResolvedValue(errorResponse(500, { detail: 'Pipeline failed' }));

    const outcome = await triggerAnalysis();

    expect(outcome.status).toBe('failure');
    expect(outcome.status).not.toBe('success');
    if (outcome.status === 'failure') {
      expect(outcome.error.status).toBe(500);
      expect(outcome.error.message).toBe('Pipeline failed');
    }
  });

  it('reports FAILURE on a network error — never a success', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));

    const outcome = await triggerAnalysis();

    expect(outcome.status).toBe('failure');
    if (outcome.status === 'failure') {
      expect(outcome.error.kind).toBe('network');
    }
  });

  it('does not fall back to mock data when the real call fails', async () => {
    fetchMock.mockResolvedValue(errorResponse(503));
    const outcome = await triggerAnalysis();

    expect(outcome.status).toBe('failure');
    // No result object of any kind is produced on failure.
    expect(outcome).not.toHaveProperty('result');
  });

  it('accepts a 2xx with an unexpected body shape as a real success', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ something: 'unexpected' }));
    const outcome = await triggerAnalysis();
    expect(outcome.status).toBe('success');
  });
});

describe('demo mode — decided by configuration, never by a failure', () => {
  it('defaults to ON when VITE_DEMO_MODE is unset, so a fresh clone works', async () => {
    // Vite reads .env, never .env.example. A fresh clone has no value at all,
    // and must still render something useful rather than a wall of errors.
    vi.stubEnv('VITE_DEMO_MODE', undefined as unknown as string);
    try {
      expect(isDemoMode()).toBe(true);
      const alerts = await getAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      vi.stubEnv('VITE_DEMO_MODE', 'false');
    }
  });

  it('is OFF when explicitly set to "false"', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'false');
    expect(isDemoMode()).toBe(false);
    fetchMock.mockResolvedValue(jsonResponse([ALERT]));
    await getAlerts();
    expect(fetchMock).toHaveBeenCalled();
  });

  it('treats a blank value as unset, so it stays ON', () => {
    // A blank value is indistinguishable from unset, so it defaults ON.
    vi.stubEnv('VITE_DEMO_MODE', '   ');
    expect(isDemoMode()).toBe(true);
    vi.stubEnv('VITE_DEMO_MODE', 'false');
  });

  it('returns mock data when VITE_DEMO_MODE is explicitly "true"', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true');
    try {
      const alerts = await getAlerts();
      // Mock data was used — and fetch was never called.
      expect(alerts.length).toBeGreaterThan(0);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      vi.stubEnv('VITE_DEMO_MODE', 'false');
    }
  });

  it('with demo mode off, a failed call rejects rather than returning mocks', async () => {
    fetchMock.mockResolvedValue(errorResponse(500));
    await expect(getAlerts()).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalled();
  });
});
