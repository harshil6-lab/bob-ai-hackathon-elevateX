/**
 * DASHBOARD STATS — frontend view model
 *
 * The backend response is confirmed and mapped in
 * services/dashboardService.ts. Fields remain optional because demo mode and
 * partially-loaded states may not provide every derived value.
 */

import type { Severity } from './alert';
import type { Incident } from './incident';

/** A severity -> count map, e.g. { critical: 3, high: 8, ... }. */
export type SeverityDistribution = Partial<Record<Severity, number>>;

/** A source-name -> count map, e.g. { SIEM: 412, ... }. */
export type SourceDistribution = Record<string, number>;

export interface DashboardStats {
  total_alerts?: number;
  total_incidents?: number;
  critical_count?: number;
  high_count?: number;
  severity_distribution?: SeverityDistribution;
  source_distribution?: SourceDistribution;
  /**
   * The single highest-priority open incident, derived from `/api/incidents`.
   */
  top_incident?: Incident | null;
  /** Most recently correlated incidents, newest first. */
  recent_incidents?: Incident[];
  /** ISO-8601 timestamp of the last completed analysis run, when available. */
  last_analysis_at?: string | null;
}

/**
 * POST /api/analyze — frontend view model
 *
 * The backend returns `{ incidents, count }`; the service layer maps `count`
 * to `incidents_created`. A non-2xx response or network error is always
 * surfaced as a failure.
 */
export interface AnalyzeResult {
  incidents_created?: number;
  alerts_processed?: number;
  status?: string;
  message?: string;
  duration_ms?: number;
}

/** Explicit lifecycle of the Analyze workflow. No state is ever skipped. */
export type AnalyzeStatus = 'idle' | 'analyzing' | 'success' | 'failure';
