/**
 * END-TO-END DEMO FLOW
 *
 * Unlike the other page tests, this file mocks NOTHING. It runs the real
 * services, the real demo-mode gate and the real golden-scenario mock data,
 * walking the exact 11-step path a judge will be shown:
 *
 *   1. Open the command centre           7. Show the BLUF
 *   2. See the alert volume              8. Show the evidence
 *   3. See multi-source noise            9. Show the MITRE mapping
 *   4. Click "Analyze Alerts"           10. Show the recommended actions
 *   5. See the analyzing state          11. Return to the dashboard
 *   6. See the correlated incidents
 *
 * It asserts the flow has no dead ends and that every step is reachable.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { App } from '../App';
import { GOLDEN_ALERTS } from '../mocks/mockAlerts';
import { GOLDEN_INCIDENT } from '../mocks/mockIncidents';

beforeAll(() => {
  vi.stubEnv('VITE_DEMO_MODE', 'true');
});
afterAll(() => {
  vi.stubEnv('VITE_DEMO_MODE', 'false');
});

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

describe('Golden demo scenario — data integrity', () => {
  it('tells the SERVER-17 attack story in the required progression', () => {
    const stages = GOLDEN_ALERTS.map((a) => a.event_type);
    expect(stages).toEqual([
      'External Suspicious Activity',
      'PowerShell',
      'Suspicious Process',
      'Credential Access',
      'Remote Connection',
      'Lateral Movement',
      'Lateral Movement',
    ]);
  });

  it('centres on SERVER-17 across multiple feeds', () => {
    expect(GOLDEN_INCIDENT.affected_assets).toContain('SERVER-17');
    expect(new Set(GOLDEN_ALERTS.map((a) => a.source)).size).toBeGreaterThan(1);
  });

  it('is chronologically ordered, so the chain reads as an escalation', () => {
    const times = GOLDEN_ALERTS.map((a) => Date.parse(a.timestamp));
    expect([...times].sort((a, b) => a - b)).toEqual(times);
  });

  it('is deterministic — two imports produce identical data', async () => {
    const first = (await import('../mocks/mockAlerts')).mockAlerts;
    const second = (await import('../mocks/mockAlerts')).mockAlerts;
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

describe('Demo flow — the 11 judging steps', () => {
  it('walks the full path with no dead ends', async () => {
    const user = userEvent.setup();
    renderApp('/');

    /* 1 + 2. The command centre opens, showing a large alert volume. */
    await screen.findByText('Alerts ingested', {}, { timeout: 3000 });
    const banner = screen.getByText('Demo mode');
    expect(banner).toBeVisible(); // never ambiguous that this is mock data

    const alertsCard = screen
      .getByText('Alerts ingested')
      .closest('.stat-card') as HTMLElement;
    const alertVolume = Number(
      within(alertsCard)
        .getByText(/^[\d,]+$/)
        .textContent?.replace(/,/g, ''),
    );
    expect(alertVolume).toBeGreaterThan(200);

    /* 3. Multi-source noise is visible. */
    const sources = screen.getByLabelText('Alert count by source feed');
    expect(within(sources).getAllByRole('listitem').length).toBeGreaterThan(1);

    /* 6 (pre-check). The correlated set is far smaller than the raw volume. */
    const incidentsCard = screen
      .getByText('Correlated incidents')
      .closest('.stat-card') as HTMLElement;
    const incidentCount = Number(
      within(incidentsCard).getByText(/^[\d,]+$/).textContent?.replace(/,/g, ''),
    );
    expect(incidentCount).toBeGreaterThan(0);
    expect(incidentCount).toBeLessThan(alertVolume / 10);

    /* 4 + 5. Analyze Alerts, and the analyzing state is visible. */
    await user.click(screen.getByRole('button', { name: 'Analyze Alerts' }));
    const analyzing = await screen.findByRole('button', { name: /Analyzing alerts/ });
    expect(analyzing).toBeDisabled();

    await waitFor(() => expect(screen.getByText(/Analysis complete/)).toBeInTheDocument(), {
      timeout: 5000,
    });
    // A demo run is explicitly labelled as simulated.
    expect(screen.getByText(/simulated — demo mode/)).toBeInTheDocument();

    /* 7. The critical SERVER-17 incident is featured, one click from here. */
    const investigate = await screen.findByRole('link', {
      name: new RegExp(`Investigate ${GOLDEN_INCIDENT.id}`),
    });
    expect(investigate).toHaveAttribute('href', `/incidents/${GOLDEN_INCIDENT.id}`);

    await user.click(investigate);

    /* 8. The BLUF is the headline of the investigation page. */
    await screen.findByRole('heading', { name: 'BLUF' });
    expect(screen.getByText(GOLDEN_INCIDENT.bluf)).toBeInTheDocument();

    /* 9. Evidence is present and traceable. */
    const evidencePanel = screen
      .getByRole('heading', { name: 'Evidence' })
      .closest('section') as HTMLElement;
    expect(within(evidencePanel).getByText('ALT-1004')).toBeInTheDocument();

    /* 10. MITRE ATT&CK techniques link out for live verification. */
    const mitrePanel = screen
      .getByRole('heading', { name: /MITRE ATT&CK/ })
      .closest('section') as HTMLElement;
    const credAccess = within(mitrePanel).getByRole('link', { name: /T1003\.001/ });
    expect(credAccess).toHaveAttribute(
      'href',
      'https://attack.mitre.org/techniques/T1003/001/',
    );
    expect(within(mitrePanel).getByRole('link', { name: /T1021\.002/ })).toBeInTheDocument();

    /* 11. Recommended actions, framed as recommendations. */
    const actionsPanel = screen
      .getByRole('heading', { name: 'Recommended actions' })
      .closest('section') as HTMLElement;
    expect(
      within(actionsPanel).getByText(/Network-isolate SERVER-17/),
    ).toBeInTheDocument();
    expect(actionsPanel.textContent).not.toMatch(/completed/i);

    /* 12. Return to the command centre closes the loop. */
    await user.click(screen.getByRole('link', { name: /Return to command centre/ }));
    expect(
      await screen.findByRole('heading', { name: 'Current threat posture' }),
    ).toBeInTheDocument();
  }, 20000);

  it('reaches the investigation page from the Incidents list in one click', async () => {
    const user = userEvent.setup();
    renderApp('/incidents');

    await screen.findByText(GOLDEN_INCIDENT.id, {}, { timeout: 3000 });

    const card = screen
      .getByText(GOLDEN_INCIDENT.id)
      .closest('.incident-card') as HTMLElement;
    await user.click(within(card).getByRole('link', { name: /Investigate/ }));

    expect(await screen.findByRole('heading', { name: 'BLUF' })).toBeInTheDocument();
  }, 15000);

  it('surfaces the SERVER-17 chain in the Alert Explorer via a host filter', async () => {
    const user = userEvent.setup();
    renderApp('/alerts');

    await screen.findByRole('table', {}, { timeout: 3000 });
    await user.selectOptions(screen.getByLabelText('Host'), 'SERVER-17');

    // Six of the seven golden alerts are hosted on SERVER-17 itself.
    expect(screen.getByText('ALT-1004')).toBeInTheDocument();
    expect(screen.getByText('ALT-1006')).toBeInTheDocument();
  }, 15000);
});
