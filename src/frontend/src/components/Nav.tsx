/**
 * Nav — the application header and primary navigation.
 *
 * One low band: the ElevateX Defence System lockup, the routes, the data
 * source this screen is reading from, and the appearance control. Semantic
 * <header> + <nav>. NavLink marks the active route with aria-current="page"
 * for assistive technology as well as visually.
 */

import { NavLink } from 'react-router-dom';
import { Logo } from './Logo';
import { ThemeToggle } from './ThemeToggle';
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
          <Logo size={26} />
          <span className="app-header__titles">
            <span className="app-header__title">
              ElevateX <span className="app-header__title-accent">Defence System</span>
            </span>
            <span className="app-header__subtitle">
              D2 · Threat Intelligence Command Center · Alert Correlation &amp; Prioritisation
            </span>
          </span>
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

        <div className="app-header__controls">
          {/* Demo-mode transparency: what this screen is reading from, always. */}
          <div className="app-header__meta">
            <span className="app-header__meta-label">Data source</span>
            <span className="app-header__meta-value mono">
              {isDemoMode() ? 'demo mode (mock)' : getApiBaseUrl()}
            </span>
          </div>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
