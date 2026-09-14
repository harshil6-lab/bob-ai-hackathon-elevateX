/**
 * DemoModeBanner — renders ONLY when VITE_DEMO_MODE is "true".
 *
 * Its whole purpose is that nobody — least of all a judge — can mistake the
 * local golden-scenario mock data for live backend data. It is pinned above the
 * navigation on every screen and is not dismissible.
 */

import { isDemoMode } from '../services/demoMode';

export function DemoModeBanner() {
  if (!isDemoMode()) return null;

  return (
    <div className="demo-banner" role="status">
      <span className="demo-banner__tag">Demo mode</span>
      <span className="demo-banner__text">
        Showing local mock data from <code className="mono">src/mocks/</code>. No backend
        is being contacted. Set <code className="mono">VITE_DEMO_MODE=false</code> to use
        the live API.
      </span>
    </div>
  );
}
