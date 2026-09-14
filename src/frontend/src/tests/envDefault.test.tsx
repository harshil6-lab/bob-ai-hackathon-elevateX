import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';

/**
 * Reproduces the reported bug: a fresh checkout with NO .env file at all.
 * Before the fix this rendered "Could not load incidents." on every page.
 */
beforeEach(() => {
  vi.stubEnv('VITE_DEMO_MODE', undefined as unknown as string);
});

function renderApp(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <App />
    </MemoryRouter>,
  );
}

describe('No .env present (the reported failure)', () => {
  it('Incidents renders real content, not the backend error', async () => {
    renderApp('/incidents');
    expect(await screen.findByText('INC-001', {}, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText('Could not load incidents.')).toBeNull();
    expect(screen.getByText('Demo mode')).toBeVisible();
  }, 15000);

  it('Dashboard renders real content, not the backend error', async () => {
    renderApp('/');
    expect(await screen.findByText('Alerts ingested', {}, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText(/Could not load the command centre/)).toBeNull();
  }, 15000);

  it('Alerts renders real content, not the backend error', async () => {
    renderApp('/alerts');
    expect(await screen.findByRole('table', {}, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText('Could not load alerts.')).toBeNull();
  }, 15000);
});
