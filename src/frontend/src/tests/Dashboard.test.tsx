/**
 * Dashboard tests — including the full Analyze lifecycle.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { Dashboard } from '../pages/Dashboard';
import { ApiError } from '../services/apiClient';
import { alertFixtures, incidentFixtures, dashboardStatsFixture } from './fixtures';

vi.mock('../services/dashboardService', async () => {
  const actual = await vi.importActual<typeof import('../services/dashboardService')>(
    '../services/dashboardService',
  );
  return { ...actual, getDashboardStats: vi.fn() };
});
vi.mock('../services/alertsService', () => ({ getAlerts: vi.fn(), getAlertById: vi.fn() }));
vi.mock('../services/incidentsService', async () => {
  const actual = await vi.importActual<typeof import('../services/incidentsService')>(
    '../services/incidentsService',
  );
  return { ...actual, getIncidents: vi.fn(), getIncidentById: vi.fn() };
});
vi.mock('../services/analyzeService', () => ({ triggerAnalysis: vi.fn() }));

import { getDashboardStats } from '../services/dashboardService';
import { getAlerts } from '../services/alertsService';
import { getIncidents } from '../services/incidentsService';
import { triggerAnalysis } from '../services/analyzeService';

const mockStats = vi.mocked(getDashboardStats);
const mockAlerts = vi.mocked(getAlerts);
const mockIncidents = vi.mocked(getIncidents);
const mockAnalyze = vi.mocked(triggerAnalysis);

function renderDashboard() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Dashboard />
    </MemoryRouter>,
  );
}

function resolveAll() {
  mockStats.mockResolvedValue(dashboardStatsFixture);
  mockAlerts.mockResolvedValue(alertFixtures);
  mockIncidents.mockResolvedValue(incidentFixtures);
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Dashboard — the four required states', () => {
  it('shows a loading state before data arrives', () => {
    mockStats.mockReturnValue(new Promise(() => {}));
    mockAlerts.mockReturnValue(new Promise(() => {}));
    mockIncidents.mockReturnValue(new Promise(() => {}));

    renderDashboard();

    expect(screen.getByText('Loading command centre statistics…')).toBeInTheDocument();
  });

  it('renders the populated command centre', async () => {
    resolveAll();
    renderDashboard();

    expect(await screen.findByText('248')).toBeInTheDocument(); // alerts ingested
    expect(screen.getByText('Alerts ingested')).toBeInTheDocument();
    expect(screen.getByText('Correlated incidents')).toBeInTheDocument();
    expect(screen.getByText('Critical incidents')).toBeInTheDocument();
    expect(screen.getByText('High incidents')).toBeInTheDocument();

    // Distributions
    expect(screen.getByLabelText('Alert count by severity')).toBeInTheDocument();
    expect(screen.getByLabelText('Alert count by source feed')).toBeInTheDocument();

    // The highest-priority incident is featured and links to its investigation.
    expect(screen.getByRole('heading', { name: 'Highest-priority incident' })).toBeInTheDocument();
    const cta = screen.getByRole('link', { name: /Investigate INC-001/ });
    expect(cta).toHaveAttribute('href', '/incidents/INC-001');
  });

  it('shows a genuine empty state when nothing has been ingested', async () => {
    mockStats.mockResolvedValue({ total_alerts: 0, total_incidents: 0 });
    mockAlerts.mockResolvedValue([]);
    mockIncidents.mockResolvedValue([]);

    renderDashboard();

    expect(await screen.findByText('No alerts have been ingested yet.')).toBeInTheDocument();
  });

  it('shows an error state with a Retry that re-runs the original request', async () => {
    const user = userEvent.setup();
    mockStats.mockRejectedValue(
      new ApiError('Server exploded', { status: 500, kind: 'http', path: '/api/dashboard/stats' }),
    );
    mockAlerts.mockResolvedValue([]);
    mockIncidents.mockResolvedValue([]);

    renderDashboard();

    expect(
      await screen.findByText('Could not load the command centre overview.'),
    ).toBeInTheDocument();
    expect(mockStats).toHaveBeenCalledTimes(1);

    // Retry actually re-issues the request — and succeeds this time.
    mockStats.mockResolvedValue(dashboardStatsFixture);
    mockAlerts.mockResolvedValue(alertFixtures);
    mockIncidents.mockResolvedValue(incidentFixtures);

    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(mockStats).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('248')).toBeInTheDocument();
  });

  it('never renders mock data when the request fails', async () => {
    mockStats.mockRejectedValue(
      new ApiError('down', { status: 0, kind: 'network', path: '/api/dashboard/stats' }),
    );
    mockAlerts.mockRejectedValue(
      new ApiError('down', { status: 0, kind: 'network', path: '/api/alerts' }),
    );
    mockIncidents.mockRejectedValue(
      new ApiError('down', { status: 0, kind: 'network', path: '/api/incidents' }),
    );

    renderDashboard();

    await screen.findByRole('alert');
    // The golden-scenario mock asset must not appear on a failed load.
    expect(screen.queryByText(/SERVER-17/)).toBeNull();
  });
});

describe('Dashboard — Analyze Alerts lifecycle', () => {
  it('starts in the idle state', async () => {
    resolveAll();
    renderDashboard();

    const button = await screen.findByRole('button', { name: 'Analyze Alerts' });
    expect(button).toBeEnabled();
    expect(
      screen.getByText('Correlate ingested alerts into prioritised incidents.'),
    ).toBeInTheDocument();
  });

  it('transitions idle -> analyzing -> success and refreshes dependent views', async () => {
    const user = userEvent.setup();
    resolveAll();

    let settle: (value: { status: 'success'; result: object; simulated: boolean }) => void;
    mockAnalyze.mockReturnValue(
      new Promise((resolve) => {
        settle = resolve as typeof settle;
      }) as ReturnType<typeof triggerAnalysis>,
    );

    renderDashboard();
    const button = await screen.findByRole('button', { name: 'Analyze Alerts' });

    expect(mockStats).toHaveBeenCalledTimes(1);

    // idle -> analyzing
    await user.click(button);
    const analyzingButton = await screen.findByRole('button', { name: /Analyzing alerts/ });
    expect(analyzingButton).toBeDisabled();
    expect(analyzingButton).toHaveAttribute('aria-busy', 'true');
    expect(
      screen.getByText(/Correlating alerts, scoring threats/),
    ).toBeInTheDocument();

    // analyzing -> success
    settle!({
      status: 'success',
      simulated: false,
      result: { alerts_processed: 248, incidents_created: 9 },
    });

    expect(await screen.findByText(/Analysis complete/)).toBeInTheDocument();
    expect(screen.getByText(/248 alerts processed/)).toBeInTheDocument();
    expect(screen.getByText(/9 incidents/)).toBeInTheDocument();

    // Dashboard stats and incidents were refreshed after the success.
    await waitFor(() => expect(mockStats).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(mockIncidents).toHaveBeenCalledTimes(2));
  });

  it('transitions idle -> analyzing -> failure and NEVER shows a fake success', async () => {
    const user = userEvent.setup();
    resolveAll();
    mockAnalyze.mockResolvedValue({
      status: 'failure',
      error: new ApiError('Pipeline failed', {
        status: 500,
        kind: 'http',
        path: '/api/analyze',
      }),
    });

    renderDashboard();
    await user.click(await screen.findByRole('button', { name: 'Analyze Alerts' }));

    expect(await screen.findByText(/Analysis failed/)).toBeInTheDocument();
    expect(
      screen.getByText('The analysis run failed. No incidents were created.'),
    ).toBeInTheDocument();

    // No success language anywhere on the page.
    expect(screen.queryByText(/Analysis complete/)).toBeNull();

    // Dependent views were NOT refreshed, because nothing succeeded.
    expect(mockStats).toHaveBeenCalledTimes(1);
  });

  it('offers a working Retry after a failed analysis', async () => {
    const user = userEvent.setup();
    resolveAll();
    mockAnalyze.mockResolvedValue({
      status: 'failure',
      error: new ApiError('boom', { status: 500, kind: 'http', path: '/api/analyze' }),
    });

    renderDashboard();
    await user.click(await screen.findByRole('button', { name: 'Analyze Alerts' }));
    await screen.findByText(/Analysis failed/);

    mockAnalyze.mockResolvedValue({
      status: 'success',
      simulated: false,
      result: { incidents_created: 9 },
    });

    await user.click(screen.getByRole('button', { name: 'Retry analysis' }));

    expect(await screen.findByText(/Analysis complete/)).toBeInTheDocument();
    expect(mockAnalyze).toHaveBeenCalledTimes(2);
  });

  it('labels a demo-mode run as simulated so it cannot pass for a real one', async () => {
    const user = userEvent.setup();
    resolveAll();
    mockAnalyze.mockResolvedValue({
      status: 'success',
      simulated: true,
      result: { alerts_processed: 248, incidents_created: 9 },
    });

    renderDashboard();
    await user.click(await screen.findByRole('button', { name: 'Analyze Alerts' }));

    expect(
      await screen.findByText(/simulated — demo mode, no backend contacted/),
    ).toBeInTheDocument();
  });
});
