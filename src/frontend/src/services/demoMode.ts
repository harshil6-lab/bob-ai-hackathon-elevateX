/**
 * DEMO MODE — controlled by the VITE_DEMO_MODE environment variable.
 *
 *   unset / empty  -> ON   (see "Why unset means on" below)
 *   "true"         -> ON
 *   anything else  -> OFF  (so "false" turns it off)
 *
 * WHY UNSET MEANS ON: Vite only reads `.env`, never `.env.example`. A fresh
 * clone therefore has no VITE_DEMO_MODE at all, and defaulting to OFF made the
 * whole app render a wall of "could not reach the backend" errors before
 * src/backend/ exists. Defaulting to ON means the app is useful immediately;
 * `VITE_DEMO_MODE=false` in `.env` turns it off the moment the API is live.
 *
 * THIS IS NOT A SILENT FALLBACK. The distinction that matters:
 *   - Demo mode is decided at STARTUP, from configuration, and is checked
 *     BEFORE any request is attempted.
 *   - It is NEVER decided by a request failing. If demo mode is off and a call
 *     fails, the failure propagates to an ErrorState with a Retry — the UI does
 *     not quietly swap in mock data to hide it.
 *
 * And it is never ambiguous which one you are looking at: whenever demo mode is
 * on, `DemoModeBanner` is pinned above the navigation on every screen and the
 * header's "Data source" reads "demo mode (mock)" instead of the API URL.
 */
export function isDemoMode(): boolean {
  const raw = import.meta.env?.VITE_DEMO_MODE;

  // Unset or blank -> default ON.
  if (raw === undefined || raw === null || String(raw).trim() === '') return true;

  return String(raw).trim().toLowerCase() === 'true';
}

/**
 * Simulated latency for demo-mode reads, so loading skeletons are actually
 * observable during a presentation instead of flashing past.
 */
export function demoDelay(ms = 320): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
