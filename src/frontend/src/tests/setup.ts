import '@testing-library/jest-dom/vitest';
import { vi, beforeEach } from 'vitest';

/**
 * Demo mode is OFF for the entire test suite.
 *
 * Tests must exercise the real API paths — success, HTTP error and network
 * failure — rather than the mock-data path. Any test that specifically needs
 * demo mode enables it explicitly with vi.stubEnv.
 */
vi.stubEnv('VITE_DEMO_MODE', 'false');
vi.stubEnv('VITE_API_BASE_URL', 'http://localhost:8000');

beforeEach(() => {
  vi.clearAllMocks();
});

/**
 * jsdom does not implement matchMedia, which the appearance layer probes for
 * the OS light/dark preference. The default stub reports "no preference", so
 * the suite runs on the dark console unless a test overrides it.
 */
if (typeof window !== 'undefined' && !window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  })) as typeof window.matchMedia;
}
