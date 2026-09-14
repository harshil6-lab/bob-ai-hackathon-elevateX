/**
 * DistributionBars — a lightweight CSS bar chart for a name -> count map.
 *
 * Intentionally NOT a charting library. Two distributions matter on this
 * dashboard (alert severity, alert source) and both are one-dimensional
 * categorical counts, which a labelled bar communicates better — and far more
 * legibly on a projector — than a pie or donut would. Every bar carries its own
 * numeric label, so the chart is readable without colour and without hover.
 */

export interface DistributionDatum {
  key: string;
  label: string;
  value: number;
  /** CSS custom-property colour, e.g. "var(--color-critical)". */
  color?: string;
  /** Non-colour cue rendered before the label, e.g. a severity glyph. */
  glyph?: string;
}

export interface DistributionBarsProps {
  data: DistributionDatum[];
  /** Accessible description of what the bars represent. */
  ariaLabel: string;
  /** Appended after the count, e.g. "alerts". */
  unit?: string;
}

export function DistributionBars({ data, ariaLabel, unit }: DistributionBarsProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const max = data.reduce((m, d) => Math.max(m, d.value), 0);

  if (total === 0) {
    return <p className="text-muted">No distribution data was returned.</p>;
  }

  return (
    <ul className="dist" aria-label={ariaLabel}>
      {data.map((datum) => {
        const share = total > 0 ? Math.round((datum.value / total) * 100) : 0;
        const width = max > 0 ? (datum.value / max) * 100 : 0;

        return (
          <li className="dist__row" key={datum.key}>
            <span className="dist__label">
              {datum.glyph ? (
                <span className="dist__glyph" aria-hidden="true" style={{ color: datum.color }}>
                  {datum.glyph}
                </span>
              ) : null}
              <span className="dist__name">{datum.label}</span>
            </span>
            <span className="dist__track">
              <span
                className="dist__fill"
                style={{
                  width: `${width}%`,
                  background: datum.color ?? 'var(--color-accent)',
                }}
              />
            </span>
            <span className="dist__value mono">
              {datum.value.toLocaleString()}
              <span className="dist__share"> · {share}%</span>
              {unit ? <span className="sr-only"> {unit}</span> : null}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
