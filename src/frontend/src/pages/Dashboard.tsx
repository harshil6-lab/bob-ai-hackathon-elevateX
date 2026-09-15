/**
 * Dashboard — "Are we under threat, how bad is it, and what do I do next?"
 *
 * INFORMATION PRIORITY (top to bottom, strongest to quietest):
 *   1. Threat posture      — one verdict line + the 248 -> 9 -> 1 reduction
 *   2. Priority threat     — the single incident that needs attention now
 *   3. Incident queue      — everything else, scannable in one pass
 *   4. Alert analytics     — supporting distributions, deliberately quiet
 *
 * Four states are handled explicitly: loading, populated, genuinely empty, and
 * failed-with-retry. A backend failure is always visible; it is never hidden
 * behind mock data or a fabricated success.
 */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import { StatCard } from '../components/StatCard';
import { SeverityBadge, SEVERITY_GLYPH } from '../components/SeverityBadge';
import { ConfidenceIndicator } from '../components/ConfidenceIndicator';
import { DistributionBars } from '../components/DistributionBars';
import { MitreChip } from '../components/MitreChip';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

import { useDashboardStats } from '../hooks/useDashboardStats';
import { useAlerts } from '../hooks/useAlerts';
import { useIncidents } from '../hooks/useIncidents';
import { useAnalyze } from '../hooks/useAnalyze';

import { mergeWithDerived } from '../services/dashboardService';
import { SEVERITY_ORDER } from '../types/alert';
import type { Severity } from '../types/alert';
import { mitreTechniqueId } from '../types/incident';
import type { Incident } from '../types/incident';

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
};

export function Dashboard() {
  const statsResource = useDashboardStats();
  const alertsResource = useAlerts();
  const incidentsResource = useIncidents();

  /** Refresh every dependent view — only ever called after a real success. */
  const refreshAll = () => {
    statsResource.reload();
    alertsResource.reload();
    incidentsResource.reload();
  };

  const analyze = useAnalyze(refreshAll);

  const alerts = alertsResource.data ?? [];
  const incidents = incidentsResource.data ?? [];

  /**
   * Fill only the derived stats fields the backend omitted, using the
   * CONFIRMED /api/alerts and /api/incidents data already on screen. Applied
   * to a SUCCESSFUL stats response only — never as an error fallback.
   */
  const stats = useMemo(() => {
    if (!statsResource.data) return null;
    return mergeWithDerived(statsResource.data, alerts, incidents);
  }, [statsResource.data, alerts, incidents]);

  const severityData = useMemo(() => {
    const distribution = stats?.severity_distribution ?? {};
    return SEVERITY_ORDER.map((severity) => ({
      key: severity,
      label: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: distribution[severity] ?? 0,
      color: SEVERITY_COLOR[severity],
      glyph: SEVERITY_GLYPH[severity],
    })).filter((d) => d.value > 0);
  }, [stats]);

  const sourceData = useMemo(() => {
    const distribution = stats?.source_distribution ?? {};
    return Object.entries(distribution)
      .sort((a, b) => b[1] - a[1])
      .map(([source, count]) => ({
        key: source,
        label: source,
        value: count,
        color: 'var(--color-source-bar)',
      }));
  }, [stats]);

  const topIncident = stats?.top_incident ?? null;
  const recentIncidents = stats?.recent_incidents ?? [];

  /* ── Whole-page states ────────────────────────────────────────────────── */

  if (statsResource.status === 'loading') {
    return (
      <div className="page">
        {/*
          The page-header wrapper is identical in all three branches so the
          heading DOM node is reused across state transitions instead of being
          remounted — no flicker when stats arrive.
        */}
        <div className="page-header">
          <PageHeading />
        </div>
        <LoadingSkeleton variant="stat" count={4} label="Loading command centre statistics…" />
        <div className="support-grid" style={{ marginTop: 'var(--space-6)' }}>
          <LoadingSkeleton variant="panel" count={1} />
          <LoadingSkeleton variant="panel" count={1} />
        </div>
      </div>
    );
  }

  if (statsResource.status === 'error') {
    return (
      <div className="page">
        <div className="page-header">
          <PageHeading />
        </div>
        <ErrorState
          message="Could not load the command centre overview."
          detail={statsResource.error?.userMessage}
          onRetry={refreshAll}
        />
      </div>
    );
  }

  const hasNothingYet =
    (stats?.total_alerts ?? 0) === 0 && (stats?.total_incidents ?? 0) === 0;

  const criticalCount = stats?.critical_count ?? 0;
  const highCount = stats?.high_count ?? 0;

  /* ── Populated ────────────────────────────────────────────────────────── */

  return (
    <div className="page">
      <div className="page-header">
        <PageHeading />
        <AnalyzeControl analyze={analyze} />
      </div>

      {analyze.status === 'failure' ? (
        <div className="dash-analyze-error">
          <ErrorState
            variant="inline"
            message="The analysis run failed. No incidents were created."
            detail={analyze.error?.userMessage}
            onRetry={analyze.run}
            retryLabel="Retry analysis"
          />
        </div>
      ) : null}

      {hasNothingYet ? (
        <EmptyState
          message="No alerts have been ingested yet."
          hint="Once the ingestion pipeline has run, alert volume and correlated incidents will appear here."
          action={{ label: 'Refresh', onClick: refreshAll }}
        />
      ) : (
        <>
          {/* ── LEVEL 1/2: posture verdict + the reduction that produced it ── */}
          <PostureBand
            critical={criticalCount}
            high={highCount}
            totalAlerts={stats?.total_alerts ?? 0}
            totalIncidents={stats?.total_incidents ?? 0}
            feedCount={sourceData.length}
            lastAnalysisAt={stats?.last_analysis_at ?? null}
          />

          {/* ── LEVEL 1: the one incident that matters most right now ────── */}
          <section className="priority-section" aria-labelledby="priority-heading">
            <div className="section-heading section-heading--urgent">
              <h2 id="priority-heading">Priority threat</h2>
              <p className="section-heading__note">
                Highest severity, then highest correlation confidence
              </p>
            </div>

            {incidentsResource.status === 'loading' ? (
              <LoadingSkeleton variant="card" count={1} label="Loading priority incident…" />
            ) : incidentsResource.status === 'error' ? (
              <ErrorState
                variant="inline"
                message="Could not load incidents."
                detail={incidentsResource.error?.userMessage}
                onRetry={incidentsResource.reload}
              />
            ) : topIncident ? (
              <PriorityThreat incident={topIncident} />
            ) : (
              <EmptyState
                message="No incidents have been correlated yet."
                hint="Run an analysis to correlate the ingested alerts into incidents."
              />
            )}
          </section>

          {/* ── LEVEL 3: everything else, in one scannable pass ──────────── */}
          <section className="queue-section" aria-labelledby="queue-heading">
            <div className="section-heading">
              <h2 id="queue-heading">Incident queue</h2>
              <p className="section-heading__note">Ordered by priority</p>
              <Link className="section-heading__link" to="/incidents">
                All incidents →
              </Link>
            </div>

            {incidentsResource.status === 'loading' ? (
              <LoadingSkeleton variant="row" count={4} />
            ) : recentIncidents.length > 0 ? (
              <IncidentQueue incidents={recentIncidents} />
            ) : (
              <EmptyState message="No incidents to queue yet." />
            )}
          </section>

          {/* ── LEVEL 4: supporting analytics, deliberately quiet ────────── */}
          <section className="analytics-section" aria-labelledby="analytics-heading">
            <div className="section-heading">
              <h2 id="analytics-heading">Alert analytics</h2>
              <p className="section-heading__note">
                Supporting context across all ingested alerts
              </p>
            </div>

            <div className="support-grid">
              <div className="support-block">
                <h3 className="support-block__title">By severity</h3>
                {alertsResource.status === 'loading' ? (
                  <LoadingSkeleton variant="row" count={4} />
                ) : severityData.length > 0 ? (
                  <DistributionBars
                    data={severityData}
                    ariaLabel="Alert count by severity"
                    unit="alerts"
                  />
                ) : (
                  <p className="text-muted">No severity distribution was returned.</p>
                )}
              </div>

              <div className="support-block">
                <h3 className="support-block__title">By source feed</h3>
                {alertsResource.status === 'loading' ? (
                  <LoadingSkeleton variant="row" count={4} />
                ) : sourceData.length > 0 ? (
                  <DistributionBars
                    data={sourceData}
                    ariaLabel="Alert count by source feed"
                    unit="alerts"
                  />
                ) : (
                  <p className="text-muted">No source distribution was returned.</p>
                )}
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

/* ── Sub-components local to this page ──────────────────────────────────── */

function PageHeading() {
  return (
    <div className="page-title-group">
      <div className="page-eyebrow">Threat intelligence command center</div>
      <h1>Current threat posture</h1>
    </div>
  );
}

/**
 * The single visual anchor of the page: a plain-language verdict on the left,
 * the alert -> incident reduction that produced it on the right.
 *
 * Every figure comes from the stats response. The verdict wording is derived
 * only from the critical/high counts already on screen — nothing is invented.
 */
function PostureBand({
  critical,
  high,
  totalAlerts,
  totalIncidents,
  feedCount,
  lastAnalysisAt,
}: {
  critical: number;
  high: number;
  totalAlerts: number;
  totalIncidents: number;
  feedCount: number;
  lastAnalysisAt: string | null;
}) {
  const level: Severity | 'clear' =
    critical > 0 ? 'critical' : high > 0 ? 'high' : 'clear';

  const verdict =
    level === 'critical'
      ? 'Critical threat detected'
      : level === 'high'
        ? 'High-severity activity'
        : totalIncidents > 0
          ? 'No critical or high threats'
          : 'No correlated threats';

  const note =
    critical > 0 || high > 0
      ? `${countPhrase(critical, 'critical incident')}${
          critical > 0 && high > 0 ? ' and ' : ''
        }${high > 0 ? countPhrase(high, 'high incident') : ''} require action`
      : `${totalIncidents.toLocaleString()} correlated incident${
          totalIncidents === 1 ? '' : 's'
        } under review`;

  const reduction =
    totalAlerts > 0 && totalIncidents > 0
      ? Math.round(totalAlerts / totalIncidents)
      : 0;

  return (
    <section className={`posture posture--${level}`} aria-label="Current threat posture">
      <div className="posture__verdict">
        <span className="posture__state">
          {level !== 'clear' ? (
            <span className="posture__glyph" aria-hidden="true">
              {SEVERITY_GLYPH[level]}
            </span>
          ) : null}
          {verdict}
        </span>
        <span className="posture__note">{note}</span>
        {lastAnalysisAt ? (
          <span className="posture__meta mono">
            Last analysis {formatTimestamp(lastAnalysisAt)}
          </span>
        ) : null}
      </div>

      {/*
        The correlation story, read left to right: raw volume in, prioritised
        incidents out, and how many of those demand action.
      */}
      <div className="posture__chain">
        <StatCard
          label="Alerts ingested"
          value={totalAlerts.toLocaleString()}
          context={
            feedCount > 0
              ? `across ${feedCount} feed${feedCount === 1 ? '' : 's'}`
              : 'raw, uncorrelated'
          }
        />
        <span className="posture__arrow" aria-hidden="true">
          →
        </span>
        <StatCard
          label="Correlated incidents"
          value={totalIncidents.toLocaleString()}
          context={reduction >= 2 ? `${reduction}× fewer to triage` : 'from correlated alerts'}
        />
        <span className="posture__arrow" aria-hidden="true">
          →
        </span>
        {/* Coloured only when the count is non-zero — a red "0" is a lie. */}
        <StatCard
          label="Critical incidents"
          value={critical.toLocaleString()}
          accent={critical > 0 ? 'critical' : 'neutral'}
          context="immediate action"
        />
        <StatCard
          label="High incidents"
          value={high.toLocaleString()}
          accent={high > 0 ? 'high' : 'neutral'}
          context="action this shift"
        />
      </div>
    </section>
  );
}

/**
 * Presentation only: drops the seconds and the "T" from an ISO-8601 stamp.
 * If the value is not in that shape it is shown exactly as the API sent it.
 */
function formatTimestamp(iso: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(iso);
  return match ? `${match[1]} ${match[2]}Z` : iso;
}

function countPhrase(count: number, noun: string): string {
  if (count === 0) return '';
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

/**
 * The highest-priority incident, composed so an analyst can answer
 * "what, where, how sure, what next" without reading a sentence.
 */
function PriorityThreat({ incident }: { incident: Incident }) {
  const assets = incident.affected_assets?.length
    ? incident.affected_assets.join(', ')
    : '—';
  const [lead, rest] = splitLead(incident.bluf);

  return (
    <article className={`threat threat--${incident.severity}`}>
      {/* Identity line: severity, id, asset, confidence — all at a glance. */}
      <div className="threat__identity">
        <div className="threat__flags">
          <SeverityBadge severity={incident.severity} size="lg" />
          <span className="status-pill">{incident.status}</span>
        </div>

        <div className="threat__id-block">
          <span className="metric-label">Incident</span>
          <span className="threat__id mono">{incident.id}</span>
        </div>

        <div className="threat__asset-block">
          <span className="metric-label">
            Affected asset{(incident.affected_assets?.length ?? 0) === 1 ? '' : 's'}
          </span>
          <span className="threat__asset mono" title={assets}>
            {assets}
          </span>
        </div>

        <ConfidenceIndicator
          confidence={incident.confidence}
          variant="inline"
          className="threat__confidence"
        />
      </div>

      <div className="threat__body">
        {/*
          Threat assessment: the backend BLUF, verbatim. The opening sentence
          is set larger as the lead and the remainder follows as body copy — a
          typographic split only. No word is dropped, reworded or summarised.
        */}
        <div className="threat__assessment">
          <span className="metric-label">Threat assessment</span>
          <p className="threat__bluf">{lead}</p>
          {rest ? <p className="threat__bluf-rest">{rest}</p> : null}
        </div>

        {/* What corroborates it — beside the narrative, not below it. */}
        <aside className="threat__aside">
          <dl className="threat__facts">
            <div>
              <dt>Correlated alerts</dt>
              <dd className="mono">{incident.alert_count}</dd>
            </div>
            <div>
              <dt>Sources</dt>
              <dd className="mono">
                {incident.sources?.length ? incident.sources.join(' · ') : '—'}
              </dd>
            </div>
          </dl>

          {incident.mitre_techniques?.length ? (
            <div className="threat__mitre">
              <span className="metric-label">MITRE ATT&amp;CK</span>
              <div className="chip-row chip-row--stack">
                {incident.mitre_techniques.map((technique, i) => (
                  <MitreChip key={mitreTechniqueId(technique) ?? i} technique={technique} />
                ))}
              </div>
            </div>
          ) : null}
        </aside>
      </div>

      <div className="threat__action">
        <Link className="btn btn-primary btn-lg" to={`/incidents/${incident.id}`}>
          Investigate {incident.id} →
        </Link>
      </div>
    </article>
  );
}

/**
 * Splits a BLUF into its opening sentence and the remainder, for typographic
 * emphasis only. Nothing is removed: `lead + ' ' + rest` is always the
 * original string. A BLUF with no sentence break is returned whole as `lead`.
 */
function splitLead(bluf: string | null | undefined): [string, string | null] {
  const text = typeof bluf === 'string' ? bluf.trim() : '';
  if (!text) return ['', null];

  const break_ = /(?<=[.!?])\s+(?=[A-Z0-9"'(])/g;
  let match: RegExpExecArray | null;
  while ((match = break_.exec(text)) !== null) {
    // Ignore a break that lands too early to be a real opening sentence
    // (abbreviations such as "e.g." or a bare identifier).
    if (match.index >= 40) {
      return [text.slice(0, match.index), text.slice(break_.lastIndex)];
    }
  }
  return [text, null];
}

/**
 * The prioritised queue as a compact operational list: one row per incident,
 * fixed columns, no wrapping. Each row remains a single link to its
 * investigation page — exactly as before.
 */
function IncidentQueue({ incidents }: { incidents: Incident[] }) {
  return (
    <div className="queue">
      <div className="queue__head">
        <span>Severity</span>
        <span>Incident</span>
        <span>Asset</span>
        <span>Confidence</span>
        <span>Alerts</span>
        <span>Status</span>
        <span className="sr-only">Action</span>
      </div>

      <ul className="queue__list">
        {incidents.map((incident) => {
          const assets = incident.affected_assets?.length
            ? incident.affected_assets.join(', ')
            : '—';
          return (
            <li key={incident.id} className={`queue__row queue__row--${incident.severity}`}>
              <Link className="queue__link" to={`/incidents/${incident.id}`}>
                <SeverityBadge severity={incident.severity} size="sm" />
                {/* Long IDs truncate visually; the full value stays in the title. */}
                <span className="queue__id mono truncate" title={incident.id}>
                  {incident.id}
                </span>
                <span className="queue__asset mono truncate" title={assets}>
                  {assets}
                </span>
                <ConfidenceIndicator confidence={incident.confidence} variant="compact" />
                <span className="queue__alerts mono">{incident.alert_count}</span>
                <span className="status-pill status-pill--sm">{incident.status}</span>
                <span className="queue__open" aria-hidden="true">
                  Open →
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * The Analyze control. Renders one visibly distinct treatment per lifecycle
 * state: idle, analyzing, success, failure. Success is only ever shown when
 * the service reported a genuine success.
 */
function AnalyzeControl({ analyze }: { analyze: ReturnType<typeof useAnalyze> }) {
  const { status, result, simulated, run } = analyze;

  return (
    <div className="analyze-control">
      <button
        type="button"
        className="btn"
        onClick={run}
        disabled={status === 'analyzing'}
        aria-busy={status === 'analyzing'}
      >
        {status === 'analyzing' ? (
          <>
            <span className="spinner" aria-hidden="true" />
            Analyzing alerts…
          </>
        ) : (
          'Analyze Alerts'
        )}
      </button>

      <div className="analyze-control__status" role="status" aria-live="polite">
        {status === 'idle' ? (
          <span className="text-muted">
            Correlate ingested alerts into prioritised incidents.
          </span>
        ) : null}

        {status === 'analyzing' ? (
          <span className="text-secondary">
            Correlating alerts, scoring threats and generating BLUF summaries…
          </span>
        ) : null}

        {status === 'success' ? (
          <span className="analyze-control__success">
            <span aria-hidden="true">✓</span> Analysis complete
            {typeof result?.alerts_processed === 'number'
              ? ` — ${result.alerts_processed.toLocaleString()} alerts processed`
              : ''}
            {typeof result?.incidents_created === 'number'
              ? `, ${result.incidents_created} incidents`
              : ''}
            {simulated ? ' (simulated — demo mode, no backend contacted)' : ''}
          </span>
        ) : null}

        {status === 'failure' ? (
          <span className="analyze-control__failure">
            <span aria-hidden="true">✕</span> Analysis failed — see the error below.
          </span>
        ) : null}
      </div>
    </div>
  );
}
