/**
 * SeverityBadge — "how bad is this?"
 *
 * ACCESSIBILITY CONTRACT: severity is NEVER communicated by colour alone.
 * Every badge renders three redundant encodings:
 *   1. colour   — the severity hue from tokens.css
 *   2. shape    — a distinct geometric glyph (◆ ▲ ■ ●), legible in greyscale
 *                 and to colourblind users
 *   3. text     — the severity word itself
 *
 * Deliberately distinct in form from ConfidenceIndicator, which is a meter.
 * A badge and a meter can never be mistaken for one another at a glance.
 */

import type { Severity } from '../types/alert';
import { isSeverity } from '../types/alert';

/** Non-colour cue. Shapes, not colours, carry the meaning in greyscale. */
const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: '◆', // ◆ diamond
  high: '▲', // ▲ triangle
  medium: '■', // ■ square
  low: '●', // ● circle
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export interface SeverityBadgeProps {
  /** Tolerates unknown strings from the network rather than crashing. */
  severity: Severity | string | null | undefined;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function SeverityBadge({ severity, size = 'md', className }: SeverityBadgeProps) {
  if (!isSeverity(severity)) {
    // Honest fallback: the backend sent something we do not recognise. Show
    // that plainly rather than silently defaulting to a severity we invented.
    return (
      <span
        className={`severity-badge severity-badge--unknown severity-badge--${size}${
          className ? ` ${className}` : ''
        }`}
      >
        <span className="severity-badge__glyph" aria-hidden="true">
          {'○'}
        </span>
        <span className="severity-badge__label">
          {typeof severity === 'string' && severity ? severity : 'Unknown'}
        </span>
      </span>
    );
  }

  return (
    <span
      className={`severity-badge severity-badge--${severity} severity-badge--${size}${
        className ? ` ${className}` : ''
      }`}
      data-severity={severity}
    >
      <span className="severity-badge__glyph" aria-hidden="true">
        {SEVERITY_GLYPH[severity]}
      </span>
      <span className="severity-badge__label">{SEVERITY_LABEL[severity]}</span>
      <span className="sr-only">severity</span>
    </span>
  );
}

export { SEVERITY_GLYPH, SEVERITY_LABEL };
