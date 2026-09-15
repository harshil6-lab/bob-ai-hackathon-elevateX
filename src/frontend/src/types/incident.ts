/**
 * CANONICAL INCIDENT SCHEMA
 *
 * Mirrors the frozen contract in AGENTS.md ("Canonical Incident Schema")
 * exactly. The eleven top-level field names are CONFIRMED against AGENTS.md.
 *
 * ---------------------------------------------------------------------------
 * CONFIRMED ELEMENT SHAPES
 * ---------------------------------------------------------------------------
 * The integrated backend returns `mitre_techniques`, `evidence`, and
 * `recommended_actions` as lists of strings.
 *
 * The object variants below remain as a compatibility shim for demo fixtures
 * and future contract extensions. The UI renders only fields actually present
 * and never fabricates a value to fill a gap.
 *
 * Accessor helpers at the bottom of this file absorb any future element-shape
 * differences without spreading contract handling across components.
 */

import type { Severity } from './alert';

/* ── MITRE ATT&CK ────────────────────────────────────────────────────────── */

/** Compatibility object form. Only `id` is treated as guaranteed. */
export interface MitreTechniqueObject {
  id?: string;
  technique_id?: string;
  /** Rendered only when the API supplies it. Never looked up locally. */
  name?: string;
  tactic?: string;
}

export type MitreTechnique = string | MitreTechniqueObject;

/* ── Evidence ────────────────────────────────────────────────────────────── */

/**
 * Compatibility object form. Every field is optional and rendered only when
 * present, per the "never fabricate evidence" rule.
 */
export interface EvidenceObject {
  source?: string;
  timestamp?: string;
  alert_id?: string;
  related_alert?: string;
  host?: string;
  ip?: string;
  source_ip?: string;
  destination_ip?: string;
  user?: string;
  event_type?: string;
  description?: string;
}

export type EvidenceItem = string | EvidenceObject;

/* ── Recommended actions ─────────────────────────────────────────────────── */

/**
 * Compatibility object form.
 *
 * NOTE: there is deliberately no `completed` / `executed` field here. The UI
 * labels these strictly as "Recommended actions" and must never imply an
 * action has been performed unless the backend adds an explicit execution
 * status field to the contract.
 */
export interface RecommendedActionObject {
  action?: string;
  description?: string;
  priority?: string;
  rationale?: string;
}

export type RecommendedAction = string | RecommendedActionObject;

/* ── Incident ────────────────────────────────────────────────────────────── */

export interface Incident {
  id: string;
  severity: Severity;
  /**
   * CONFIRMED-BY-EXAMPLE: AGENTS.md shows `"confidence": 94`, i.e. an integer
   * percentage on a 0-100 scale. `formatConfidence()` below tolerates a 0-1
   * float as well, so a backend that returns 0.94 will not render as "1%".
   */
  confidence: number;
  status: string;
  affected_assets: string[];
  alert_count: number;
  sources: string[];
  mitre_techniques: MitreTechnique[];
  evidence: EvidenceItem[];
  bluf: string;
  recommended_actions: RecommendedAction[];
}

/**
 * Query parameters for GET /api/incidents.
 * Optional query parameters; filtering is currently client-side.
 */
export interface IncidentQueryParams {
  severity?: Severity;
  status?: string;
  limit?: number;
  offset?: number;
}

/* ── Accessors — the single place that absorbs the provisional shapes ────── */

/** Extracts a MITRE technique ID. Returns null rather than inventing one. */
export function mitreTechniqueId(technique: MitreTechnique): string | null {
  if (typeof technique === 'string') return technique.trim() || null;
  return technique.id ?? technique.technique_id ?? null;
}

/** Returns the technique name ONLY if the API supplied it. Never looked up. */
export function mitreTechniqueName(technique: MitreTechnique): string | null {
  if (typeof technique === 'string') return null;
  return technique.name ?? null;
}

/** Returns the tactic ONLY if the API supplied it. */
export function mitreTechniqueTactic(technique: MitreTechnique): string | null {
  if (typeof technique === 'string') return null;
  return technique.tactic ?? null;
}

/** Normalises confidence to a 0-100 percentage. Tolerates a 0-1 float. */
export function confidencePercent(confidence: number): number {
  if (!Number.isFinite(confidence)) return 0;
  const scaled = confidence > 0 && confidence <= 1 ? confidence * 100 : confidence;
  return Math.max(0, Math.min(100, Math.round(scaled)));
}

/** Extracts the primary text of a recommended action. */
export function recommendedActionText(action: RecommendedAction): string {
  if (typeof action === 'string') return action;
  return action.action ?? action.description ?? '';
}

/** Extracts the supporting detail of an action, if distinct from its text. */
export function recommendedActionDetail(
  action: RecommendedAction,
): string | null {
  if (typeof action === 'string') return null;
  if (action.action && action.description) return action.description;
  return action.rationale ?? null;
}
