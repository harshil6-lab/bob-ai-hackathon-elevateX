/**
 * DASHBOARD STATS — ⚠️ PROVISIONAL SCHEMA ⚠️
 *
 * ---------------------------------------------------------------------------
 * THIS TYPE IS NOT CONFIRMED AGAINST ANY BACKEND.
 * ---------------------------------------------------------------------------
 * AGENTS.md freezes the ENDPOINT (`GET /api/dashboard/stats`) but does not
 * specify its response body, and `src/backend/` did not exist when this was
 * written. There was therefore no implementation and no OpenAPI document to
 * read the real shape from.
 *
 * Per MEMBER3_EXECUTION_GUIDE Step 5.2, the fields below are derived from the
 * Dashboard REQUIREMENTS (total alerts, total incidents, critical/high counts,
 * severity distribution, source distribution, most important incident) and are
 * explicitly marked provisional pending confirmation from Member 2.
 *
 * ACTION REQUIRED (Member 2): confirm or correct these field names before the
 * demo. Every field below is OPTIONAL and the Dashboard degrades gracefully
 * when one is absent, so a partial match will not crash the UI — but an
 * unconfirmed name will silently render as an empty section.
 *
 * DERIVATION FALLBACK: `deriveDashboardStats()` in services/dashboardService.ts
 * can compute an equivalent view from the CONFIRMED /api/alerts and
 * /api/incidents contracts if this endpoint's shape turns out to differ. That
 * derivation is only used when explicitly requested — never as a silent
 * substitute for a failed request.
 */

import type { Severity } from './alert';
import type { Incident } from './incident';

/** PROVISIONAL — a severity -> count map, e.g. { critical: 3, high: 8, ... }. */
export type SeverityDistribution = Partial<Record<Severity, number>>;

/** PROVISIONAL — a source-name -> count map, e.g. { SIEM: 412, ... }. */
export type SourceDistribution = Record<string, number>;

export interface DashboardStats {
  /** PROVISIONAL */ total_alerts?: number;
  /** PROVISIONAL */ total_incidents?: number;
  /** PROVISIONAL */ critical_count?: number;
  /** PROVISIONAL */ high_count?: number;
  /** PROVISIONAL */ severity_distribution?: SeverityDistribution;
  /** PROVISIONAL */ source_distribution?: SourceDistribution;
  /**
   * PROVISIONAL — the single highest-priority open incident.
   * If the backend omits this, the Dashboard falls back to selecting it from
   * the CONFIRMED /api/incidents response instead.
   */
  top_incident?: Incident | null;
  /** PROVISIONAL — most recently correlated incidents, newest first. */
  recent_incidents?: Incident[];
  /** PROVISIONAL — ISO-8601 timestamp of the last completed analysis run. */
  last_analysis_at?: string | null;
}

/**
 * POST /api/analyze response — ⚠️ PROVISIONAL ⚠️
 *
 * The endpoint is frozen by AGENTS.md; its response body is not specified and
 * no backend exists to read it from. Every field is optional, and the UI
 * treats a 2xx response as success REGARDLESS of body shape, so an unexpected
 * body cannot cause a false failure. Correspondingly, a non-2xx response or a
 * network error is ALWAYS surfaced as a failure — never masked as success.
 */
export interface AnalyzeResult {
  /** PROVISIONAL */ incidents_created?: number;
  /** PROVISIONAL */ alerts_processed?: number;
  /** PROVISIONAL */ status?: string;
  /** PROVISIONAL */ message?: string;
  /** PROVISIONAL */ duration_ms?: number;
}

/** Explicit lifecycle of the Analyze workflow. No state is ever skipped. */
export type AnalyzeStatus = 'idle' | 'analyzing' | 'success' | 'failure';
