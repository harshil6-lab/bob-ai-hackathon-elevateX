/**
 * Alert Explorer tests — rendering, filtering, sorting and the four states.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { Alerts } from '../pages/Alerts';
import { ApiError } from '../services/apiClient';
import { alertFixtures } from './fixtures';

vi.mock('../services/alertsService', () => ({ getAlerts: vi.fn(), getAlertById: vi.fn() }));
import { getAlerts } from '../services/alertsService';
const mockGetAlerts = vi.mocked(getAlerts);

function renderAlerts() {
  return render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Alerts />
    </MemoryRouter>,
  );
}

/** Data rows only — excludes the header row. */
function bodyRows(): HTMLElement[] {
  return within(screen.getByRole('table')).getAllByRole('row').slice(1);
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Alerts — states', () => {
  it('shows a loading state', () => {
    mockGetAlerts.mockReturnValue(new Promise(() => {}));
    renderAlerts();
    expect(screen.getByText('Loading alerts…')).toBeInTheDocument();
  });

  it('renders every canonical column', async () => {
    mockGetAlerts.mockResolvedValue(alertFixtures);
    renderAlerts();

    await screen.findByRole('table');
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent);

    for (const expected of [
      'ID',
      'Timestamp',
      'Severity',
      'Source',
      'Event type',
      'Host',
      'User',
      'Source IP',
      'Destination IP',
      'Description',
    ]) {
      expect(headers.some((h) => h?.includes(expected))).toBe(true);
    }
  });

  it('renders alert data with SeverityBadge', async () => {
    mockGetAlerts.mockResolvedValue(alertFixtures);
    renderAlerts();

    expect(await screen.findByText('ALT-1004')).toBeInTheDocument();
    // Two fixtures share this host, so assert on all matches.
    expect(screen.getAllByText('SERVER-17').length).toBeGreaterThan(0);
    expect(bodyRows()).toHaveLength(3);
  });

  it('shows an empty state when the feed is genuinely empty', async () => {
    mockGetAlerts.mockResolvedValue([]);
    renderAlerts();
    expect(await screen.findByText('No alerts have been ingested yet.')).toBeInTheDocument();
  });

  it('shows an error state with a working Retry', async () => {
    const user = userEvent.setup();
    mockGetAlerts.mockRejectedValue(
      new ApiError('down', { status: 0, kind: 'network', path: '/api/alerts' }),
    );
    renderAlerts();

    expect(await screen.findByText('Could not load alerts.')).toBeInTheDocument();

    mockGetAlerts.mockResolvedValue(alertFixtures);
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(mockGetAlerts).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('table')).toBeInTheDocument();
  });
});

describe('Alerts — filtering', () => {
  beforeEach(() => {
    mockGetAlerts.mockResolvedValue(alertFixtures);
  });

  it('filtering by severity narrows the visible rows', async () => {
    const user = userEvent.setup();
    renderAlerts();

    await screen.findByRole('table');
    expect(bodyRows()).toHaveLength(3);

    await user.selectOptions(screen.getByLabelText('Severity'), 'critical');

    const rows = bodyRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText('ALT-1004')).toBeInTheDocument();
    expect(screen.queryByText('ALT-2001')).toBeNull();
  });

  it('filtering by source narrows the visible rows', async () => {
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByRole('table');

    await user.selectOptions(screen.getByLabelText('Source'), 'NETWORK_SENSOR');

    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByText('ALT-2001')).toBeInTheDocument();
  });

  it('filtering by event type narrows the visible rows', async () => {
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByRole('table');

    await user.selectOptions(screen.getByLabelText('Event type'), 'PowerShell');

    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByText('ALT-1002')).toBeInTheDocument();
  });

  it('filtering by host narrows the visible rows', async () => {
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByRole('table');

    await user.selectOptions(screen.getByLabelText('Host'), 'WKS-0142');

    expect(bodyRows()).toHaveLength(1);
  });

  it('searching matches description, host, user and IP', async () => {
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByRole('table');

    await user.type(screen.getByLabelText('Search'), 'lsass');
    expect(bodyRows()).toHaveLength(1);
    expect(screen.getByText('ALT-1004')).toBeInTheDocument();
  });

  it('shows a filtered-empty state distinct from the ingested-nothing state', async () => {
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByRole('table');

    await user.type(screen.getByLabelText('Search'), 'zzzzz-no-match');

    expect(await screen.findByText('No alerts match your filters.')).toBeInTheDocument();
    // NOT the "nothing ingested" message — these are different conditions.
    expect(screen.queryByText('No alerts have been ingested yet.')).toBeNull();
  });

  it('clears filters and restores the full result set', async () => {
    const user = userEvent.setup();
    renderAlerts();
    await screen.findByRole('table');

    await user.selectOptions(screen.getByLabelText('Severity'), 'critical');
    expect(bodyRows()).toHaveLength(1);

    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(bodyRows()).toHaveLength(3);
  });
});

describe('Alerts — sorting', () => {
  it('sorts severity by true rank, not alphabetically', async () => {
    const user = userEvent.setup();
    mockGetAlerts.mockResolvedValue(alertFixtures);
    renderAlerts();
    await screen.findByRole('table');

    // Descending by severity rank puts the LEAST severe first...
    await user.click(screen.getByRole('button', { name: /^Severity/ }));
    // ...so reverse it to lead with critical.
    await user.click(screen.getByRole('button', { name: /^Severity/ }));

    const first = bodyRows()[0];
    expect(within(first).getByText('Critical')).toBeInTheDocument();
    // Alphabetical order would have put "Critical" before "Low" before "Medium";
    // rank order is what we assert here.
    const order = bodyRows().map(
      (r) => within(r).getByText(/Critical|Medium|Low/).textContent,
    );
    expect(order).toEqual(['Critical', 'Medium', 'Low']);
  });

  it('defaults to newest-first by timestamp and reverses on activation', async () => {
    const user = userEvent.setup();
    mockGetAlerts.mockResolvedValue(alertFixtures);
    renderAlerts();
    await screen.findByRole('table');

    const header = screen.getByRole('button', { name: /^Timestamp/ });

    // Default for a SOC console: newest alert first.
    expect(header.closest('th')).toHaveAttribute('aria-sort', 'descending');
    expect(within(bodyRows()[0]).getByText('ALT-1004')).toBeInTheDocument();

    // Activating the active column reverses it.
    await user.click(header);
    expect(header.closest('th')).toHaveAttribute('aria-sort', 'ascending');
    expect(within(bodyRows()[0]).getByText('ALT-2001')).toBeInTheDocument();
  });
});
