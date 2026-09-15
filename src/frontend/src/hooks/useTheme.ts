/**
 * useTheme — reads, applies and remembers the light/dark choice.
 *
 * While the choice is "system" the hook keeps following the OS, so a laptop
 * switching to night mode mid-shift switches the console with it. Once the
 * analyst picks a theme, that choice wins and is remembered.
 */

import { useCallback, useEffect, useState } from 'react';

import {
  applyTheme,
  lightMediaQuery,
  readStoredChoice,
  resolveTheme,
  storeChoice,
  type ResolvedTheme,
  type ThemeChoice,
} from '../services/theme';

export interface UseThemeResult {
  /** What the analyst asked for: "system" until they choose. */
  choice: ThemeChoice;
  /** What is actually on screen right now. */
  theme: ResolvedTheme;
  setTheme: (choice: ThemeChoice) => void;
  /** Flips to the opposite of what is currently displayed. */
  toggle: () => void;
}

export function useTheme(): UseThemeResult {
  const [choice, setChoice] = useState<ThemeChoice>(() => readStoredChoice());
  const [theme, setResolved] = useState<ResolvedTheme>(() =>
    resolveTheme(readStoredChoice()),
  );

  // Apply on mount and whenever the choice changes. The inline script in
  // index.html has already applied the same value before first paint; this
  // keeps the document in step with React from here on.
  useEffect(() => {
    const resolved = resolveTheme(choice);
    setResolved(resolved);
    applyTheme(resolved);
  }, [choice]);

  // Follow the OS only while no explicit choice has been made.
  useEffect(() => {
    if (choice !== 'system') return;
    const query = lightMediaQuery();
    if (!query?.addEventListener) return;

    const onChange = () => {
      const resolved = resolveTheme('system');
      setResolved(resolved);
      applyTheme(resolved);
    };
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, [choice]);

  const setTheme = useCallback((next: ThemeChoice) => {
    storeChoice(next);
    setChoice(next);
  }, []);

  const toggle = useCallback(() => {
    setTheme(resolveTheme(readStoredChoice()) === 'dark' ? 'light' : 'dark');
  }, [setTheme]);

  return { choice, theme, setTheme, toggle };
}
