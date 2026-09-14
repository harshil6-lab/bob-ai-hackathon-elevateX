/**
 * EmptyState — a genuinely empty successful result.
 *
 * Used ONLY when a request succeeded and returned nothing. Never used to
 * disguise an error: a failed request renders ErrorState instead.
 */

import type { ReactNode } from 'react';

export interface EmptyStateProps {
  message: string;
  /** Optional supporting sentence explaining what would populate this view. */
  hint?: ReactNode;
  action?: {
    label: string;
    onClick: () => void;
  };
  /** Decorative glyph. Hidden from assistive technology. */
  glyph?: string;
}

export function EmptyState({ message, hint, action, glyph = '◇' }: EmptyStateProps) {
  return (
    <div className="state-block state-block--empty">
      <div className="state-block__glyph" aria-hidden="true">
        {glyph}
      </div>
      <p className="state-block__message">{message}</p>
      {hint ? <p className="state-block__hint">{hint}</p> : null}
      {action ? (
        <button type="button" className="btn" onClick={action.onClick}>
          {action.label}
        </button>
      ) : null}
    </div>
  );
}
