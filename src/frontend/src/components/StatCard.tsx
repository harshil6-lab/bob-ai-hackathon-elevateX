/**
 * StatCard — a single headline figure with its label and optional context.
 * No API calls, no business logic. Presentational only.
 */

import type { ReactNode } from 'react';

export interface StatCardProps {
  label: string;
  /** Rendered as-is. `0` renders as "0"; null/undefined renders as an em dash. */
  value: ReactNode;
  /** Short qualifier under the value, e.g. "across 4 feeds". */
  context?: ReactNode;
  /** Optional leading glyph, e.g. a SeverityBadge glyph. Decorative. */
  accent?: 'critical' | 'high' | 'medium' | 'low' | 'accent' | 'confidence' | 'neutral';
  /** Optional emphasis for the single most important figure on a screen. */
  emphasis?: boolean;
  children?: ReactNode;
}

export function StatCard({
  label,
  value,
  context,
  accent = 'neutral',
  emphasis = false,
  children,
}: StatCardProps) {
  const displayValue =
    value === null || value === undefined || value === '' ? '—' : value;

  return (
    <div
      className={`stat-card stat-card--${accent}${emphasis ? ' stat-card--emphasis' : ''}`}
    >
      <div className="stat-card__label">{label}</div>
      <div className="stat-card__value">{displayValue}</div>
      {context ? <div className="stat-card__context">{context}</div> : null}
      {children}
    </div>
  );
}
