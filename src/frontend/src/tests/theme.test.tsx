/**
 * Appearance tests — light/dark switching.
 *
 * The contract being protected:
 *   - the resolved theme is always written to <html data-theme>
 *   - an explicit choice is remembered across sessions
 *   - with no explicit choice, the OS preference decides
 *   - the control names the theme it switches TO, in its accessible name
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ThemeToggle } from '../components/ThemeToggle';
import { Logo } from '../components/Logo';
import { THEME_STORAGE_KEY, resolveTheme, readStoredChoice } from '../services/theme';

const realMatchMedia = window.matchMedia;

/** Makes the OS report a light (or dark) preference for one test. */
function stubOsPreference(light: boolean) {
  window.matchMedia = ((query: string) => ({
    matches: light && query.includes('light'),
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  })) as typeof window.matchMedia;
}

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
});

afterEach(() => {
  window.matchMedia = realMatchMedia;
  vi.restoreAllMocks();
});

describe('Theme switching', () => {
  it('starts on the dark console when the OS states no light preference', () => {
    stubOsPreference(false);
    render(<ThemeToggle />);

    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeInTheDocument();
  });

  it('follows the OS when the analyst has expressed no preference', () => {
    stubOsPreference(true);
    render(<ThemeToggle />);

    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(readStoredChoice()).toBe('system');
  });

  it('switches the document theme and remembers the choice', async () => {
    const user = userEvent.setup();
    stubOsPreference(false);
    render(<ThemeToggle />);

    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }));

    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');

    // ...and back again.
    await user.click(screen.getByRole('button', { name: 'Switch to dark theme' }));

    expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
  });

  it('restores a remembered choice over the OS preference', () => {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'light');
    stubOsPreference(false); // OS says dark; the stored choice must win

    render(<ThemeToggle />);

    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });

  it('falls back to dark when storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('storage blocked');
    });
    stubOsPreference(false);

    expect(readStoredChoice()).toBe('system');
    expect(resolveTheme(readStoredChoice())).toBe('dark');
  });
});

describe('ElevateX logo', () => {
  it('is decorative beside visible text', () => {
    const { container } = render(<Logo />);
    const svg = container.querySelector('svg');

    expect(svg).toHaveAttribute('aria-hidden', 'true');
    expect(svg?.querySelector('title')).toBeNull();
  });

  it('exposes an accessible name when it has to stand in for text', () => {
    render(<Logo title="ElevateX Defence System" />);
    expect(screen.getByRole('img', { name: 'ElevateX Defence System' })).toBeInTheDocument();
  });
});
