/**
 * EvidencePanel — the audit trail behind the BLUF.
 *
 * ---------------------------------------------------------------------------
 * ONLY FIELDS ACTUALLY PRESENT IN THE RESPONSE ARE RENDERED.
 * ---------------------------------------------------------------------------
 * Each evidence item becomes a compact, traceable record — a labelled field
 * grid, not a prose blob — so an analyst can follow a claim back to the alert
 * that supports it. A field the API did not return is simply absent; no
 * placeholder, no "N/A", nothing invented to fill the gap.
 *
 * Handles both sides of the provisional element union (bare string / object).
 */

import { EmptyState } from './EmptyState';
import type { EvidenceItem, EvidenceObject } from '../types/incident';

/** Ordered so the most identifying fields lead. Label -> object key. */
const FIELD_ORDER: Array<{ key: keyof EvidenceObject; label: string; mono?: boolean }> = [
  { key: 'alert_id', label: 'Alert', mono: true },
  { key: 'related_alert', label: 'Related alert', mono: true },
  { key: 'source', label: 'Source' },
  { key: 'timestamp', label: 'Timestamp', mono: true },
  { key: 'event_type', label: 'Event type' },
  { key: 'host', label: 'Host', mono: true },
  { key: 'source_ip', label: 'Source IP', mono: true },
  { key: 'destination_ip', label: 'Destination IP', mono: true },
  { key: 'ip', label: 'IP', mono: true },
  { key: 'user', label: 'User', mono: true },
];

function hasValue(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== '';
}

export interface EvidencePanelProps {
  evidence: EvidenceItem[] | null | undefined;
}

export function EvidencePanel({ evidence }: EvidencePanelProps) {
  const items = Array.isArray(evidence) ? evidence : [];

  if (items.length === 0) {
    return (
      <EmptyState
        message="No evidence records were returned for this incident."
        hint="Evidence is extracted by the intelligence layer during correlation."
      />
    );
  }

  return (
    <ol className="evidence-list">
      {items.map((item, index) => {
        // Bare-string form: render the string exactly as supplied.
        if (typeof item === 'string') {
          return (
            <li className="evidence-item" key={`evidence-${index}`}>
              <span className="evidence-item__index" aria-hidden="true">
                {index + 1}
              </span>
              <div className="evidence-item__body">
                <p className="evidence-item__description">{item}</p>
              </div>
            </li>
          );
        }

        const present = FIELD_ORDER.filter(({ key }) => hasValue(item[key]));
        const description = hasValue(item.description) ? item.description : null;

        return (
          <li className="evidence-item" key={`evidence-${index}`}>
            <span className="evidence-item__index" aria-hidden="true">
              {index + 1}
            </span>
            <div className="evidence-item__body">
              {present.length > 0 ? (
                <dl className="evidence-item__fields">
                  {present.map(({ key, label, mono }) => (
                    <div className="evidence-item__field" key={String(key)}>
                      <dt className="evidence-item__field-label">{label}</dt>
                      <dd className={`evidence-item__field-value${mono ? ' mono' : ''}`}>
                        {item[key]}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : null}
              {description ? (
                <p className="evidence-item__description">{description}</p>
              ) : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
