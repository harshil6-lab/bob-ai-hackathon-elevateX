/**
 * ThemeToggle — switches the console between dark and light.
 *
 * One button, because there is only ever one sensible next state. The label
 * names the theme it will switch TO, so the control is unambiguous whether it
 * is read visually or by a screen reader. The icon is a redundant cue, never
 * the only one.
 */

import { useTheme } from '../hooks/useTheme';

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const next = theme === 'dark' ? 'light' : 'dark';

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      data-theme-state={theme}
    >
      <span className="theme-toggle__icon" aria-hidden="true">
        {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
      </span>
      <span className="theme-toggle__label" aria-hidden="true">
        {next === 'light' ? 'Light' : 'Dark'}
      </span>
    </button>
  );
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" focusable="false">
      <circle cx="12" cy="12" r="4.4" stroke="currentColor" strokeWidth="1.8" />
      <path
        d="M12 2.6v2.6M12 18.8v2.6M2.6 12h2.6M18.8 12h2.6M5.3 5.3l1.9 1.9M16.8 16.8l1.9 1.9M18.7 5.3l-1.9 1.9M7.2 16.8l-1.9 1.9"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" focusable="false">
      <path
        d="M20.5 14.2A8.6 8.6 0 0 1 9.8 3.5a8.6 8.6 0 1 0 10.7 10.7Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
    </svg>
  );
}
