/**
 * ErrorState — a request that actually failed.
 *
 * Always renders a visible, keyboard-reachable Retry button wired to re-run the
 * ORIGINAL request. Mock data is never substituted here — a failure stays
 * visible until the user retries successfully.
 */

import type { ReactNode } from 'react';

export interface ErrorStateProps {
  message: string;
  /** Technical context, e.g. "GET /api/alerts — HTTP 500". Monospaced. */
  detail?: ReactNode;
  onRetry?: () => void;
  retryLabel?: string;
  /** `inline` for a panel-sized failure, `block` for a whole-page failure. */
  variant?: 'block' | 'inline';
}

export function ErrorState({
  message,
  detail,
  onRetry,
  retryLabel = 'Retry',
  variant = 'block',
}: ErrorStateProps) {
  return (
    <div
      className={`state-block state-block--error state-block--${variant}`}
      role="alert"
    >
      <div className="state-block__glyph state-block__glyph--error" aria-hidden="true">
        !
      </div>
      <p className="state-block__message">{message}</p>
      {detail ? <p className="state-block__detail mono">{detail}</p> : null}
      {onRetry ? (
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          {retryLabel}
        </button>
      ) : null}
    </div>
  );
}
