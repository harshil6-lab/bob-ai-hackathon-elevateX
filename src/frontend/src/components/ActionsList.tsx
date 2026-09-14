/**
 * ActionsList — recommended actions.
 *
 * ---------------------------------------------------------------------------
 * "RECOMMENDED", NEVER "COMPLETED".
 * ---------------------------------------------------------------------------
 * The API contract carries no execution-status field, so nothing here may imply
 * an action has been carried out. No checkmarks, no checkboxes, no "done"
 * styling, no past-tense labelling. These are proposals for an analyst to act
 * on, and the wording says so explicitly.
 *
 * Handles both sides of the provisional element union (bare string / object).
 */

import { EmptyState } from './EmptyState';
import type { RecommendedAction } from '../types/incident';
import { recommendedActionText, recommendedActionDetail } from '../types/incident';

function priorityOf(action: RecommendedAction): string | null {
  if (typeof action === 'string') return null;
  return typeof action.priority === 'string' && action.priority.trim()
    ? action.priority
    : null;
}

export interface ActionsListProps {
  actions: RecommendedAction[] | null | undefined;
}

export function ActionsList({ actions }: ActionsListProps) {
  const items = Array.isArray(actions) ? actions : [];

  if (items.length === 0) {
    return <EmptyState message="No recommended actions were returned for this incident." />;
  }

  return (
    <>
      <p className="actions-list__preamble">
        Proposed by the intelligence layer for analyst review. None of these has been
        executed — the API reports no execution status.
      </p>
      <ol className="actions-list">
        {items.map((action, index) => {
          const text = recommendedActionText(action);
          if (!text) return null;
          const detail = recommendedActionDetail(action);
          const priority = priorityOf(action);

          return (
            <li className="action-item" key={`action-${index}`}>
              <span className="action-item__index" aria-hidden="true">
                {index + 1}
              </span>
              <div className="action-item__body">
                <div className="action-item__head">
                  <span className="action-item__text">{text}</span>
                  {priority ? (
                    <span
                      className={`action-item__priority action-item__priority--${priority.toLowerCase()}`}
                    >
                      {priority}
                      <span className="sr-only"> priority</span>
                    </span>
                  ) : null}
                </div>
                {detail ? <p className="action-item__detail">{detail}</p> : null}
              </div>
            </li>
          );
        })}
      </ol>
    </>
  );
}
