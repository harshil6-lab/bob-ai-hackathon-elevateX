/**
 * THEME — light / dark appearance. Presentation only.
 *
 * The resolved theme is written to <html data-theme="light|dark">, which is
 * the single switch every colour token in styles/tokens.css reacts to. No
 * component reads a colour value from here.
 *
 * Three choices are modelled, not two: "system" follows the operating system
 * until the analyst expresses a preference, after which their choice is
 * remembered across sessions. Nothing here touches API data or behaviour.
 */

export type ThemeChoice = 'system' | 'light' | 'dark';
export type ResolvedTheme = 'light' | 'dark';

/** Namespaced so it cannot collide with anything else on the origin. */
export const THEME_STORAGE_KEY = 'd2.theme';

const LIGHT_QUERY = '(prefers-color-scheme: light)';

/** The OS preference, or `false` where the browser cannot report one. */
export function prefersLight(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  try {
    return window.matchMedia(LIGHT_QUERY).matches;
  } catch {
    return false;
  }
}

/** The media query list used to follow the OS while the choice is "system". */
export function lightMediaQuery(): MediaQueryList | null {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return null;
  }
  try {
    return window.matchMedia(LIGHT_QUERY);
  } catch {
    return null;
  }
}

/**
 * The stored choice. Anything unrecognised — including a blocked or empty
 * localStorage — falls back to "system" rather than forcing a theme.
 */
export function readStoredChoice(): ThemeChoice {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
  } catch {
    /* storage unavailable (private mode, blocked cookies) — use the default */
  }
  return 'system';
}

/** Persists an explicit choice; "system" clears the stored preference. */
export function storeChoice(choice: ThemeChoice): void {
  try {
    if (choice === 'system') {
      window.localStorage.removeItem(THEME_STORAGE_KEY);
    } else {
      window.localStorage.setItem(THEME_STORAGE_KEY, choice);
    }
  } catch {
    /* storage unavailable — the choice still applies for this session */
  }
}

/** Turns a choice into the theme actually shown. */
export function resolveTheme(choice: ThemeChoice): ResolvedTheme {
  if (choice === 'light' || choice === 'dark') return choice;
  return prefersLight() ? 'light' : 'dark';
}

/** Writes the theme to the document root. The stylesheet does the rest. */
export function applyTheme(theme: ResolvedTheme): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', theme);
}
