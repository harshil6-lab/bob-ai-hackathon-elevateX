/**
 * App — routing and the persistent application shell.
 *
 * The shell is: DemoModeBanner (when active) > header/nav > main.
 * `<main id="main-content">` is the target of the skip link, so keyboard users
 * can bypass the navigation on every page.
 */

import { Routes, Route, Navigate } from 'react-router-dom';
import { Nav } from './components/Nav';
import { DemoModeBanner } from './components/DemoModeBanner';
import { Dashboard } from './pages/Dashboard';
import { Alerts } from './pages/Alerts';
import { Incidents } from './pages/Incidents';
import { IncidentDetail } from './pages/IncidentDetail';

export function App() {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <DemoModeBanner />
      <Nav />
      <main id="main-content" tabIndex={-1}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
