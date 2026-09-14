/**
 * Nav — the application header and primary navigation.
 *
 * Semantic <header> + <nav>. NavLink marks the active route with
 * aria-current="page" for assistive technology as well as visually.
 */

import { NavLink } from 'react-router-dom';
import { isDemoMode } from '../services/demoMode';
import { getApiBaseUrl } from '../services/apiClient';

const LINKS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/alerts', label: 'Alerts', end: false },
  { to: '/incidents', label: 'Incidents', end: false },
];

export function Nav() {
  return (
    <header className="app-header">
      <div className="app-header__inner">
        <div className="app-header__brand">
          <span className="app-header__mark" aria-hidden="true">
            ◈
          </span>
          <div className="app-header__titles">
            <span className="app-header__title">Threat Intelligence Command Center</span>
            <span className="app-header__subtitle">
              elevateX · D2 Correlation &amp; Alert Prioritisation
            </span>
          </div>
        </div>

        <nav className="app-nav" aria-label="Primary">
          <ul className="app-nav__list">
            {LINKS.map((link) => (
              <li key={link.to}>
                <NavLink
                  to={link.to}
                  end={link.end}
                  className={({ isActive }) =>
                    `app-nav__link${isActive ? ' app-nav__link--active' : ''}`
                  }
                >
                  {link.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>

        <div className="app-header__meta">
          <span className="app-header__meta-label">Data source</span>
          <span className="app-header__meta-value mono">
            {isDemoMode() ? 'demo mode (mock)' : getApiBaseUrl()}
          </span>
        </div>
      </div>
    </header>
  );
}
