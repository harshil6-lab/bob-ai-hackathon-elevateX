/**
 * LoadingSkeleton — the single loading primitive for the whole app.
 * Pages must not define their own; use `variant` instead.
 */

export interface LoadingSkeletonProps {
  variant?: 'card' | 'row' | 'text' | 'stat' | 'panel';
  /** How many skeleton units to render. */
  count?: number;
  /** Accessible status text announced while content loads. */
  label?: string;
  className?: string;
}

export function LoadingSkeleton({
  variant = 'text',
  count = 1,
  label = 'Loading…',
  className,
}: LoadingSkeletonProps) {
  const units = Array.from({ length: Math.max(1, count) });

  return (
    <div
      className={`skeleton-group skeleton-group--${variant}${className ? ` ${className}` : ''}`}
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <span className="sr-only">{label}</span>
      {units.map((_, index) => (
        <div
          key={index}
          className={`skeleton skeleton--${variant}`}
          aria-hidden="true"
        />
      ))}
    </div>
  );
}
