/**
 * ConfidenceIndicator — "how sure are we?"
 *
 * DELIBERATELY UNLIKE SeverityBadge in every visual dimension:
 *   - form:   a horizontal METER with a filled track, not a pill badge
 *   - colour: a single cool teal, entirely outside the warm severity ramp
 *   - text:   a percentage plus an explicit "confidence" label
 *
 * Confidence intensity is expressed by BAR LENGTH, not by hue — so a
 * low-confidence value never borrows the visual language of "low severity".
 * The two facts are independent and must always be independently readable:
 * a low-severity / 96%-confidence incident reads exactly as that.
 */

import { confidencePercent } from '../types/incident';

export interface ConfidenceIndicatorProps {
  /** 0-100 integer (per AGENTS.md) — a 0-1 float is also tolerated. */
  confidence: number | null | undefined;
  /** `bar` for cards and detail panels, `compact` for dense table cells. */
  variant?: 'bar' | 'compact';
  className?: string;
}

/** Qualitative band, shown as words so the meaning is never colour-dependent. */
function confidenceBand(percent: number): string {
  if (percent >= 85) return 'Very high';
  if (percent >= 70) return 'High';
  if (percent >= 50) return 'Moderate';
  if (percent >= 30) return 'Low';
  return 'Very low';
}

export function ConfidenceIndicator({
  confidence,
  variant = 'bar',
  className,
}: ConfidenceIndicatorProps) {
  if (confidence === null || confidence === undefined || !Number.isFinite(confidence)) {
    return (
      <span className={`confidence confidence--unknown${className ? ` ${className}` : ''}`}>
        <span className="confidence__label">Confidence</span>
        <span className="confidence__value text-muted">Not reported</span>
      </span>
    );
  }

  const percent = confidencePercent(confidence);
  const band = confidenceBand(percent);

  if (variant === 'compact') {
    return (
      <span
        className={`confidence confidence--compact${className ? ` ${className}` : ''}`}
        title={`Confidence: ${percent}% (${band})`}
      >
        <span className="confidence__track confidence__track--compact" aria-hidden="true">
          <span className="confidence__fill" style={{ width: `${percent}%` }} />
        </span>
        <span className="confidence__value mono">{percent}%</span>
        <span className="sr-only">confidence, {band}</span>
      </span>
    );
  }

  return (
    <div className={`confidence${className ? ` ${className}` : ''}`}>
      <div className="confidence__header">
        <span className="confidence__label">Confidence</span>
        <span className="confidence__value mono">{percent}%</span>
      </div>
      <div
        className="confidence__track"
        role="meter"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Correlation confidence: ${percent} percent, ${band}`}
      >
        <span className="confidence__fill" style={{ width: `${percent}%` }} />
      </div>
      <div className="confidence__band">{band}</div>
    </div>
  );
}
