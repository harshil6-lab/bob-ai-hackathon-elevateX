/**
 * MitreChip — one MITRE ATT&CK technique.
 *
 * ---------------------------------------------------------------------------
 * NO LOCAL LOOKUP TABLE. EVER.
 * ---------------------------------------------------------------------------
 * The technique ID is always shown. The technique NAME and TACTIC are shown
 * ONLY when the API supplied them. This component holds no ID-to-name mapping
 * and will never manufacture one — if the backend returns bare IDs, bare IDs
 * are what a judge sees.
 *
 * Each chip links out to the public MITRE ATT&CK page for its ID so the mapping
 * can be verified live during a demo.
 */

import type { MitreTechnique } from '../types/incident';
import { mitreTechniqueId, mitreTechniqueName, mitreTechniqueTactic } from '../types/incident';

/**
 * Builds the canonical ATT&CK URL.
 * Sub-techniques are path-segmented, not dotted:
 *   T1059     -> /techniques/T1059/
 *   T1059.001 -> /techniques/T1059/001/
 */
export function mitreUrl(id: string): string {
  const normalised = id.trim().toUpperCase();
  return `https://attack.mitre.org/techniques/${normalised.replace('.', '/')}/`;
}

/** Only well-formed technique IDs get an outbound link. */
export function isValidTechniqueId(id: string): boolean {
  return /^T\d{4}(\.\d{3})?$/i.test(id.trim());
}

export interface MitreChipProps {
  technique: MitreTechnique;
}

export function MitreChip({ technique }: MitreChipProps) {
  const id = mitreTechniqueId(technique);
  if (!id) return null;

  const name = mitreTechniqueName(technique);
  const tactic = mitreTechniqueTactic(technique);
  const linkable = isValidTechniqueId(id);

  const body = (
    <>
      <span className="mitre-chip__id mono">{id}</span>
      {/* Rendered only when the API supplied it. Never looked up locally. */}
      {name ? <span className="mitre-chip__name">{name}</span> : null}
      {tactic ? <span className="mitre-chip__tactic">{tactic}</span> : null}
    </>
  );

  if (!linkable) {
    return <span className="mitre-chip">{body}</span>;
  }

  return (
    <a
      className="mitre-chip mitre-chip--link"
      href={mitreUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      aria-label={`${id}${name ? `: ${name}` : ''} — open on attack.mitre.org in a new tab`}
    >
      {body}
      <span className="mitre-chip__external" aria-hidden="true">
        ↗
      </span>
    </a>
  );
}
