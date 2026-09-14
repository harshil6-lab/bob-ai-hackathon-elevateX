/**
 * Dashboard — "What is happening right now?"
 *
 * Tells the core story of the product in one screen:
 *   many noisy multi-source alerts  ->  a handful of prioritised incidents
 *                                   ->  one incident that needs attention now
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
   * Fill only the PROVISIONAL stats fields the backend omitted, using the
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
        color: 'var(--color-accent)',
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
        <div className="dash-grid" style={{ marginTop: 'var(--space-6)' }}>
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
          {/* ── Headline figures: the noise-to-signal reduction ─────────── */}
          <section aria-label="Current posture" className="stat-grid">
            <StatCard
              label="Alerts ingested"
              value={(stats?.total_alerts ?? 0).toLocaleString()}
              context={
                sourceData.length > 0
                  ? `across ${sourceData.length} feed${sourceData.length === 1 ? '' : 's'}`
                  : 'raw, uncorrelated'
              }
            />
            <StatCard
              label="Correlated incidents"
              value={(stats?.total_incidents ?? 0).toLocaleString()}
              accent="accent"
              context={<ReductionNote alerts={stats?.total_alerts} incidents={stats?.total_incidents} />}
            />
            <StatCard
              label="Critical incidents"
              value={(stats?.critical_count ?? 0).toLocaleString()}
              accent="critical"
              context="require immediate action"
            />
            <StatCard
              label="High incidents"
              value={(stats?.high_count ?? 0).toLocaleString()}
              accent="high"
              context="require action this shift"
            />
          </section>

          {/* ── The one incident that matters most right now ────────────── */}
          <section className="priority-section" aria-labelledby="priority-heading">
            <div className="section-heading">
              <h2 id="priority-heading">Highest-priority incident</h2>
              <p className="section-heading__note">
                Ranked by severity, then correlation confidence.
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
              <article className={`priority-card priority-card--${topIncident.severity}`}>
                <div className="priority-card__top">
                  <div className="priority-card__identity">
                    <span className="priority-card__id mono">{topIncident.id}</span>
                    <SeverityBadge severity={topIncident.severity} size="lg" />
                    <span className="status-pill">{topIncident.status}</span>
                  </div>
                  <ConfidenceIndicator confidence={topIncident.confidence} />
                </div>

                <p className="priority-card__bluf">{topIncident.bluf}</p>

                <dl className="priority-card__facts">
                  <div>
                    <dt>Affected assets</dt>
                    <dd className="mono">
                      {topIncident.affected_assets?.length
                        ? topIncident.affected_assets.join(', ')
                        : '—'}
                    </dd>
                  </div>
                  <div>
                    <dt>Correlated alerts</dt>
                    <dd className="mono">{topIncident.alert_count}</dd>
                  </div>
                  <div>
                    <dt>Sources</dt>
                    <dd className="mono">
                      {topIncident.sources?.length ? topIncident.sources.join(', ') : '—'}
                    </dd>
                  </div>
                </dl>

                {topIncident.mitre_techniques?.length ? (
                  <div className="priority-card__mitre">
                    <span className="metric-label">MITRE ATT&amp;CK</span>
                    <div className="chip-row">
                      {topIncident.mitre_techniques.map((technique, i) => (
                        <MitreChip key={mitreTechniqueId(technique) ?? i} technique={technique} />
                      ))}
                    </div>
                  </div>
                ) : null}

                <Link className="btn btn-primary btn-lg" to={`/incidents/${topIncident.id}`}>
                  Investigate {topIncident.id} →
                </Link>
              </article>
            ) : (
              <EmptyState
                message="No incidents have been correlated yet."
                hint="Run an analysis to correlate the ingested alerts into incidents."
              />
            )}
          </section>

          {/* ── Distributions + recent activity ─────────────────────────── */}
          <div className="dash-grid">
            <section className="panel" aria-labelledby="sev-dist-heading">
              <div className="panel-header">
                <h2 id="sev-dist-heading" className="panel-title">
                  Alert severity distribution
                </h2>
              </div>
              <div className="panel-body">
                {alertsResource.status === 'loading' ? (
                  <LoadingSkeleton variant="row" count={4} />
                ) : severityData.length > 0 ? (
                  <DistributionBars
                    data={severityData}
                    ariaLabel="Alert count by severity"
                    unit="alerts"
                  />
                ) : (
                  <EmptyState message="No severity distribution was returned." />
                )}
              </div>
            </section>

            <section className="panel" aria-labelledby="src-dist-heading">
              <div className="panel-header">
                <h2 id="src-dist-heading" className="panel-title">
                  Alert source distribution
                </h2>
              </div>
              <div className="panel-body">
                {alertsResource.status === 'loading' ? (
                  <LoadingSkeleton variant="row" count={4} />
                ) : sourceData.length > 0 ? (
                  <DistributionBars
                    data={sourceData}
                    ariaLabel="Alert count by source feed"
                    unit="alerts"
                  />
                ) : (
                  <EmptyState message="No source distribution was returned." />
                )}
              </div>
            </section>
          </div>

          <section className="panel" aria-labelledby="recent-heading">
            <div className="panel-header">
              <h2 id="recent-heading" className="panel-title">
                Prioritised incident queue
              </h2>
              <Link className="panel-link" to="/incidents">
                View all incidents →
              </Link>
            </div>
            <div className="panel-body panel-body--flush">
              {incidentsResource.status === 'loading' ? (
                <div style={{ padding: 'var(--space-5)' }}>
                  <LoadingSkeleton variant="row" count={4} />
                </div>
              ) : recentIncidents.length > 0 ? (
                <ul className="recent-list">
                  {recentIncidents.map((incident) => (
                    <li key={incident.id} className="recent-item">
                      <Link className="recent-item__link" to={`/incidents/${incident.id}`}>
                        <span className="recent-item__id mono">{incident.id}</span>
                        <SeverityBadge severity={incident.severity} size="sm" />
                        <ConfidenceIndicator confidence={incident.confidence} variant="compact" />
                        <span className="recent-item__assets mono truncate">
                          {incident.affected_assets?.join(', ') || '—'}
                        </span>
                        <span className="recent-item__count text-muted">
                          {incident.alert_count} alerts
                        </span>
                        <span className="status-pill status-pill--sm">{incident.status}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <div style={{ padding: 'var(--space-5)' }}>
                  <EmptyState message="No incidents to queue yet." />
                </div>
              )}
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
      <div className="page-eyebrow">Command centre</div>
      <h1>Current threat posture</h1>
      <p className="page-subtitle">
        Multi-source alert volume, correlated into prioritised incidents.
      </p>
    </div>
  );
}

function ReductionNote({
  alerts,
  incidents,
}: {
  alerts?: number;
  incidents?: number;
}) {
  if (!alerts || !incidents || incidents === 0) return <>from correlated alerts</>;
  const factor = Math.round(alerts / incidents);
  if (factor < 2) return <>from correlated alerts</>;
  return <>{factor}× fewer items to triage</>;
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
        className="btn btn-primary btn-lg"
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
