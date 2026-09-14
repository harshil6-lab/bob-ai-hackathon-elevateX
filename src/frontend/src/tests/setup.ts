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
