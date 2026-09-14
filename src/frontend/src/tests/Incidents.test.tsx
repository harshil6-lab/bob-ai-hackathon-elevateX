/**
 * Incident Explorer tests.
 *
 * The central assertion: severity and confidence are separate, independently
 * readable facts, and Critical/High incidents are emphasised through LAYOUT as
 * well as through their severity indicator.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { Incidents } from '../pages/Incidents';
import { ApiError } from '../services/apiClient';
import { incidentFixtures, criticalIncident, lowSeverityHighConfidenceIncident } from './fixtures';

vi.mock('../services/incidentsService', async () => {
  const actual = await vi.importActual<typeof import('../services/incidentsService')>(
    '../services/incidentsService',
  );
  return { ...actual, getIncidents: vi.fn(), getIncidentById: vi.fn() };
});
import { getIncidents } from '../services/incidentsService';
const mockGetIncidents = vi.mocked(getIncidents);

function renderIncidents() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Incidents />
    </MemoryRouter>,
  );
}

function cardFor(id: string): HTMLElement {
  return screen.getByText(id).closest('.incident-card') as HTMLElement;
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Incidents — states', () => {
  it('shows a loading state', () => {
    mockGetIncidents.mockReturnValue(new Promise(() => {}));
    renderIncidents();
    expect(screen.getByText('Loading the incident list…')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true');
  });

  it('shows an empty state when nothing has been correlated', async () => {
    mockGetIncidents.mockResolvedValue([]);
    renderIncidents();
    expect(
      await screen.findByText('No incidents have been correlated yet.'),
    ).toBeInTheDocument();
  });

  it('shows an error state with a working Retry', async () => {
    const user = userEvent.setup();
    mockGetIncidents.mockRejectedValue(
      new ApiError('down', { status: 0, kind: 'network', path: '/api/incidents' }),
    );
    renderIncidents();

    expect(await screen.findByText('Could not load incidents.')).toBeInTheDocument();

    mockGetIncidents.mockResolvedValue(incidentFixtures);
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(mockGetIncidents).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('INC-001')).toBeInTheDocument();
  });
});

describe('Incidents — contract fields and navigation', () => {
  beforeEach(() => {
    mockGetIncidents.mockResolvedValue(incidentFixtures);
  });

  it('renders every canonical list field for an incident', async () => {
    renderIncidents();
    await screen.findByText('INC-001');

    const card = cardFor('INC-001');
    expect(within(card).getByText('Critical')).toBeInTheDocument();       // severity
    expect(within(card).getByText('94%')).toBeInTheDocument();            // confidence
    expect(within(card).getByText('investigating')).toBeInTheDocument();  // status
    expect(within(card).getByText('SERVER-17, FILE-SRV-31')).toBeInTheDocument(); // assets
    expect(within(card).getByText('7')).toBeInTheDocument();              // alert_count
    expect(
      within(card).getByText('SIEM, NETWORK_SENSOR, THREAT_INTEL'),
    ).toBeInTheDocument();                                                // sources
    expect(within(card).getByText('T1003.001')).toBeInTheDocument();      // mitre
  });

  it('links every incident to its investigation page', async () => {
    renderIncidents();
    await screen.findByText('INC-001');

    expect(
      within(cardFor('INC-001')).getByRole('link', { name: /Investigate/ }),
    ).toHaveAttribute('href', '/incidents/INC-001');
    expect(
      within(cardFor('INC-007')).getByRole('link', { name: /Investigate/ }),
    ).toHaveAttribute('href', '/incidents/INC-007');
  });
});

describe('Incidents — severity and confidence are independent facts', () => {
  beforeEach(() => {
    mockGetIncidents.mockResolvedValue(incidentFixtures);
  });

  it('renders a LOW-severity / HIGH-confidence incident showing both facts clearly', async () => {
    renderIncidents();
    await screen.findByText('INC-007');

    const card = cardFor('INC-007');

    // "Low" severity is stated in words, not implied by colour.
    expect(within(card).getByText('Low')).toBeInTheDocument();
    // 96% confidence is stated independently and is NOT downgraded by the
    // low severity sitting beside it.
    expect(within(card).getByText('96%')).toBeInTheDocument();
    expect(within(card).getByText('Very high')).toBeInTheDocument();
  });

  it('renders severity and confidence as structurally different elements', async () => {
    renderIncidents();
    await screen.findByText('INC-001');

    const card = cardFor('INC-001');

    // Severity: a badge carrying a shape glyph.
    const badge = card.querySelector('.severity-badge');
    expect(badge).toBeTruthy();
    expect(badge?.querySelector('.severity-badge__glyph')?.textContent).toBeTruthy();

    // Confidence: a meter. Different element, different ARIA role.
    const meter = within(card).getByRole('meter');
    expect(meter).toHaveAttribute('aria-valuenow', '94');

    // Neither borrows the other's markup.
    expect(badge?.querySelector('[role="meter"]')).toBeNull();
    expect(meter.closest('.severity-badge')).toBeNull();
  });

  it('does not let a high confidence promote a low-severity incident', async () => {
    renderIncidents();
    await screen.findByText('INC-007');

    // INC-007 has the higher confidence (96 vs 94) but the lower severity,
    // so it belongs under "Monitor", not "Requires action".
    const urgent = screen
      .getByRole('heading', { name: 'Requires action' })
      .closest('section') as HTMLElement;
    const routine = screen
      .getByRole('heading', { name: 'Monitor' })
      .closest('section') as HTMLElement;

    expect(within(urgent).getByText('INC-001')).toBeInTheDocument();
    expect(within(urgent).queryByText('INC-007')).toBeNull();
    expect(within(routine).getByText('INC-007')).toBeInTheDocument();
  });
});

describe('Incidents — Critical/High prominence', () => {
  it('emphasises a critical incident through layout, not only colour', async () => {
    mockGetIncidents.mockResolvedValue(incidentFixtures);
    renderIncidents();
    await screen.findByText('INC-001');

    const critical = cardFor('INC-001');
    const low = cardFor('INC-007');

    // A structural class difference, independent of any colour value.
    expect(critical.className).toContain('incident-card--emphasis');
    expect(low.className).not.toContain('incident-card--emphasis');

    // And they are separated into distinct, labelled sections.
    expect(screen.getByRole('heading', { name: 'Requires action' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Monitor' })).toBeInTheDocument();
  });

  it('orders by severity first, then confidence', async () => {
    mockGetIncidents.mockResolvedValue([
      lowSeverityHighConfidenceIncident,
      { ...criticalIncident, id: 'INC-010', confidence: 20 },
      criticalIncident,
    ]);
    renderIncidents();
    await screen.findByText('INC-001');

    const ids = Array.from(document.querySelectorAll('.incident-card__id')).map(
      (el) => el.textContent,
    );
    // Both criticals lead; between them, the higher confidence wins.
    expect(ids).toEqual(['INC-001', 'INC-010', 'INC-007']);
  });

  it('omits the urgent section entirely when nothing is critical or high', async () => {
    mockGetIncidents.mockResolvedValue([lowSeverityHighConfidenceIncident]);
    renderIncidents();
    await screen.findByText('INC-007');

    expect(screen.queryByRole('heading', { name: 'Requires action' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Monitor' })).toBeInTheDocument();
  });
});
