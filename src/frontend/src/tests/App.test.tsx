/**
 * Application shell tests — root render, routing, landmarks and demo mode.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { App } from '../App';
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

function renderApp(route = '/') {
  return render(
    <MemoryRouter
      initialEntries={[route]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <App />
    </MemoryRouter>,
  );
}

/** Waits for the Dashboard's three async resources to settle. */
async function settled() {
  await screen.findByText('Alerts ingested');
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getDashboardStats).mockResolvedValue(dashboardStatsFixture);
  vi.mocked(getAlerts).mockResolvedValue(alertFixtures);
  vi.mocked(getIncidents).mockResolvedValue(incidentFixtures);
});

describe('App — root render', () => {
  it('mounts without crashing and renders the dashboard at /', async () => {
    renderApp();
    expect(
      await screen.findByRole('heading', { name: 'Current threat posture' }),
    ).toBeInTheDocument();
  });

  it('renders the required semantic landmarks', async () => {
    renderApp();
    await settled();
    expect(screen.getByRole('banner')).toBeInTheDocument();          // <header>
    expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
  });

  it('offers a skip link as the first focusable element', async () => {
    const user = userEvent.setup();
    renderApp();
    await settled();

    await user.tab();
    const skip = screen.getByRole('link', { name: 'Skip to main content' });
    expect(skip).toHaveFocus();
    expect(skip).toHaveAttribute('href', '#main-content');
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main-content');
  });

  it('marks the active nav item with aria-current', async () => {
    renderApp('/alerts');
    await screen.findByRole('table');
    const link = screen.getByRole('link', { name: 'Alerts' });
    expect(link).toHaveAttribute('aria-current', 'page');
  });
});

describe('App — routing', () => {
  it('routes to the Alert Explorer', async () => {
    renderApp('/alerts');
    expect(
      await screen.findByRole('heading', { name: 'Raw multi-source alerts' }),
    ).toBeInTheDocument();
  });

  it('routes to the Incident Explorer', async () => {
    renderApp('/incidents');
    expect(
      await screen.findByRole('heading', { name: 'Correlated incidents' }),
    ).toBeInTheDocument();
  });

  it('routes to an investigation page', async () => {
    vi.mocked(
      (await import('../services/incidentsService')).getIncidentById,
    ).mockResolvedValue(incidentFixtures[1]);

    renderApp('/incidents/INC-001');
    expect(await screen.findByRole('heading', { name: 'BLUF' })).toBeInTheDocument();
  });

  it('redirects an unknown route to the dashboard rather than dead-ending', async () => {
    renderApp('/nope/not/a/page');
    expect(
      await screen.findByRole('heading', { name: 'Current threat posture' }),
    ).toBeInTheDocument();
  });

  it('navigates Dashboard -> Alerts by keyboard', async () => {
    const user = userEvent.setup();
    renderApp();
    await screen.findByRole('heading', { name: 'Current threat posture' });

    await user.click(screen.getByRole('link', { name: 'Alerts' }));
    expect(
      await screen.findByRole('heading', { name: 'Raw multi-source alerts' }),
    ).toBeInTheDocument();
  });
});

describe('App — demo mode banner', () => {
  it('is hidden when VITE_DEMO_MODE is not "true"', async () => {
    renderApp();
    await settled();
    expect(screen.queryByText('Demo mode')).toBeNull();
  });

  it('is visible and unmissable when demo mode is on', async () => {
    vi.stubEnv('VITE_DEMO_MODE', 'true');
    try {
      renderApp();
      expect(await screen.findByText('Demo mode')).toBeInTheDocument();
      await settled();
      expect(
        screen.getByText(/No backend\s+is being contacted/),
      ).toBeInTheDocument();
    } finally {
      vi.stubEnv('VITE_DEMO_MODE', 'false');
    }
  });
});
