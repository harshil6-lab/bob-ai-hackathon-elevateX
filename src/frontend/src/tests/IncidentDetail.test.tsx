/**
 * Incident Investigation tests — BLUF, evidence, MITRE, recommended actions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

import { IncidentDetail } from '../pages/IncidentDetail';
import { ApiError } from '../services/apiClient';
import { criticalIncident, lowSeverityHighConfidenceIncident } from './fixtures';

vi.mock('../services/incidentsService', async () => {
  const actual = await vi.importActual<typeof import('../services/incidentsService')>(
    '../services/incidentsService',
  );
  return { ...actual, getIncidents: vi.fn(), getIncidentById: vi.fn() };
});
import { getIncidentById } from '../services/incidentsService';
const mockGetIncident = vi.mocked(getIncidentById);

function renderDetail(id = 'INC-001') {
  return render(
    <MemoryRouter
      initialEntries={[`/incidents/${id}`]}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Routes>
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/incidents" element={<div>Incident list page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('IncidentDetail — states', () => {
  it('shows a loading state', () => {
    mockGetIncident.mockReturnValue(new Promise(() => {}));
    renderDetail();
    expect(screen.getByText('Loading incident…')).toBeInTheDocument();
  });

  it('handles a not-found id distinctly from a general failure', async () => {
    mockGetIncident.mockRejectedValue(
      new ApiError('Not found', { status: 404, kind: 'http', path: '/api/incidents/INC-999' }),
    );
    renderDetail('INC-999');

    expect(await screen.findByText('Incident INC-999 was not found.')).toBeInTheDocument();
    // A 404 is not retryable — retrying the same id cannot help.
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    // But the user is never stranded.
    expect(screen.getByRole('button', { name: /Back to incidents/ })).toBeInTheDocument();
  });

  it('shows an error state with a working Retry for a server failure', async () => {
    const user = userEvent.setup();
    mockGetIncident.mockRejectedValue(
      new ApiError('boom', { status: 500, kind: 'http', path: '/api/incidents/INC-001' }),
    );
    renderDetail();

    expect(await screen.findByText('Could not load this incident.')).toBeInTheDocument();

    mockGetIncident.mockResolvedValue(criticalIncident);
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(mockGetIncident).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('heading', { name: 'BLUF' })).toBeInTheDocument();
  });
});

describe('IncidentDetail — BLUF', () => {
  beforeEach(() => {
    mockGetIncident.mockResolvedValue(criticalIncident);
  });

  it('renders the BLUF prominently, labelled and expanded', async () => {
    renderDetail();
    expect(await screen.findByRole('heading', { name: 'BLUF' })).toBeInTheDocument();
    expect(screen.getByText('Bottom Line Up Front')).toBeInTheDocument();
  });

  it('renders the backend BLUF text verbatim, with no truncation', async () => {
    const { container } = renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const text = container.querySelector('.bluf__text');
    expect(text?.textContent).toBe(criticalIncident.bluf);
  });

  it('places the BLUF before severity, evidence and actions in the document', async () => {
    const { container } = renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const order = Array.from(
      container.querySelectorAll('.bluf, .incident-facts, .detail-grid'),
    ).map((el) => el.className.split(' ')[0]);

    expect(order[0]).toBe('bluf');
  });
});

describe('IncidentDetail — assessment and context', () => {
  beforeEach(() => {
    mockGetIncident.mockResolvedValue(criticalIncident);
  });

  it('shows severity, confidence and status together but distinctly', async () => {
    const { container } = renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const facts = container.querySelector('.incident-facts') as HTMLElement;
    expect(within(facts).getByText('Critical')).toBeInTheDocument();
    expect(within(facts).getByText('94%')).toBeInTheDocument();
    expect(within(facts).getByText('investigating')).toBeInTheDocument();

    // Severity is a badge; confidence is a meter. Different primitives.
    expect(facts.querySelector('.severity-badge')).toBeTruthy();
    expect(within(facts).getByRole('meter')).toBeTruthy();
  });

  it('shows affected assets, alert count and sources', async () => {
    const { container } = renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const facts = container.querySelector('.incident-facts') as HTMLElement;
    expect(within(facts).getByText('SERVER-17, FILE-SRV-31')).toBeInTheDocument();
    expect(within(facts).getByText('7')).toBeInTheDocument();
    expect(within(facts).getByText('SIEM, NETWORK_SENSOR, THREAT_INTEL')).toBeInTheDocument();
  });
});

describe('IncidentDetail — evidence', () => {
  it('renders each evidence record with only the fields the API returned', async () => {
    mockGetIncident.mockResolvedValue(criticalIncident);
    const { container } = renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const panel = screen
      .getByRole('heading', { name: 'Evidence' })
      .closest('section') as HTMLElement;

    expect(within(panel).getByText('ALT-1004')).toBeInTheDocument();
    expect(within(panel).getByText('SIEM')).toBeInTheDocument();
    expect(within(panel).getByText('svc_backup')).toBeInTheDocument();
    expect(within(panel).getByText(/Handle opened to lsass.exe/)).toBeInTheDocument();

    // No fabricated placeholders for absent fields.
    expect(container.textContent).not.toContain('N/A');
  });

  it('shows an EmptyState when evidence is empty', async () => {
    mockGetIncident.mockResolvedValue({ ...criticalIncident, evidence: [] });
    renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    expect(screen.getByText(/No evidence records were returned/)).toBeInTheDocument();
  });
});

describe('IncidentDetail — MITRE ATT&CK', () => {
  it('renders technique IDs with verifiable outbound links', async () => {
    mockGetIncident.mockResolvedValue(criticalIncident);
    renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const link = screen.getByRole('link', { name: /T1003\.001/ });
    expect(link).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1003/001/');
    expect(link).toHaveAttribute('target', '_blank');
  });

  it('shows the ID alone when the API supplied no technique name', async () => {
    mockGetIncident.mockResolvedValue(lowSeverityHighConfidenceIncident);
    const { container } = renderDetail('INC-007');
    await screen.findByRole('heading', { name: 'BLUF' });

    expect(screen.getByText('T1091')).toBeInTheDocument();
    // No name was supplied, so none is rendered — and none is invented.
    expect(container.querySelector('.mitre-chip__name')).toBeNull();
  });

  it('shows an EmptyState when no techniques were mapped', async () => {
    mockGetIncident.mockResolvedValue({ ...criticalIncident, mitre_techniques: [] });
    renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    expect(screen.getByText(/No MITRE ATT&CK techniques were mapped/)).toBeInTheDocument();
  });
});

describe('IncidentDetail — recommended actions', () => {
  it('labels actions as recommended and never as completed', async () => {
    mockGetIncident.mockResolvedValue(criticalIncident);
    renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const panel = screen
      .getByRole('heading', { name: 'Recommended actions' })
      .closest('section') as HTMLElement;

    expect(
      within(panel).getByText('Network-isolate SERVER-17 and FILE-SRV-31 immediately'),
    ).toBeInTheDocument();
    expect(within(panel).getByText(/None of these has been executed/)).toBeInTheDocument();

    const text = panel.textContent ?? '';
    expect(text).not.toMatch(/completed/i);
    expect(text).not.toMatch(/actions taken/i);
    expect(panel.querySelector('input[type="checkbox"]')).toBeNull();
  });
});

describe('IncidentDetail — navigation', () => {
  beforeEach(() => {
    mockGetIncident.mockResolvedValue(criticalIncident);
  });

  it('renders breadcrumbs: Dashboard > Incidents > Incident {id}', async () => {
    renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    const crumbs = screen.getByRole('navigation', { name: 'Breadcrumb' });
    expect(within(crumbs).getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/');
    expect(within(crumbs).getByRole('link', { name: 'Incidents' })).toHaveAttribute(
      'href',
      '/incidents',
    );
    expect(within(crumbs).getByText('Incident INC-001')).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('provides working back navigation to the incident list', async () => {
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole('heading', { name: 'BLUF' });

    await user.click(screen.getByRole('button', { name: /Back to incidents/ }));
    expect(await screen.findByText('Incident list page')).toBeInTheDocument();
  });
});
