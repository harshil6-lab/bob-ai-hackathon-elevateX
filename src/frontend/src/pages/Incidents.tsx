/**
 * Incidents — the Incident Explorer.
 *
 * The "signal" half of the story. Ordered by severity, then confidence, and
 * split into two visually distinct groups so Critical/High incidents are
 * prominent through LAYOUT as well as through their severity indicator —
 * emphasis never rests on colour alone.
 *
 * Severity and confidence are rendered as separate, non-interchangeable
 * elements: a badge with a shape glyph vs. a teal meter. A low-severity /
 * high-confidence incident therefore reads as exactly that, with neither fact
 * masking the other.
 */

import { useMemo } from 'react';
import { Link } from 'react-router-dom';

import { SeverityBadge } from '../components/SeverityBadge';
import { ConfidenceIndicator } from '../components/ConfidenceIndicator';
import { MitreChip } from '../components/MitreChip';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

import { useIncidents } from '../hooks/useIncidents';
import { byPriority } from '../services/incidentsService';
import { mitreTechniqueId } from '../types/incident';
import type { Incident } from '../types/incident';

export function Incidents() {
  const { data, status, error, reload } = useIncidents();

  const incidents = useMemo(() => [...(data ?? [])].sort(byPriority), [data]);

  const urgent = incidents.filter(
    (i) => i.severity === 'critical' || i.severity === 'high',
  );
  const routine = incidents.filter(
    (i) => i.severity !== 'critical' && i.severity !== 'high',
  );

  if (status === 'loading') {
    return (
      <div className="page">
        <Heading total={null} />
        <LoadingSkeleton variant="card" count={3} label="Loading the incident list…" />
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="page">
        <Heading total={null} />
        <ErrorState
          message="Could not load incidents."
          detail={error?.userMessage}
          onRetry={reload}
        />
      </div>
    );
  }

  if (incidents.length === 0) {
    return (
      <div className="page">
        <Heading total={0} />
        <EmptyState
          message="No incidents have been correlated yet."
          hint="Run an analysis from the command centre to correlate ingested alerts into incidents."
          action={{ label: 'Refresh', onClick: reload }}
        />
      </div>
    );
  }

  return (
    <div className="page">
      <Heading total={incidents.length} />

      {urgent.length > 0 ? (
        <section className="incident-group" aria-labelledby="urgent-heading">
          <div className="section-heading section-heading--urgent">
            <h2 id="urgent-heading">Requires action</h2>
            <p className="section-heading__note">
              {urgent.length} critical or high-severity incident
              {urgent.length === 1 ? '' : 's'}
            </p>
          </div>
          <div className="incident-grid">
            {urgent.map((incident) => (
              <IncidentCard key={incident.id} incident={incident} emphasis />
            ))}
          </div>
        </section>
      ) : null}

      {routine.length > 0 ? (
        <section className="incident-group" aria-labelledby="routine-heading">
          <div className="section-heading">
            <h2 id="routine-heading">Monitor</h2>
            <p className="section-heading__note">
              {routine.length} medium or low-severity incident
              {routine.length === 1 ? '' : 's'}
            </p>
          </div>
          <div className="incident-grid incident-grid--routine">
            {routine.map((incident) => (
              <IncidentCard key={incident.id} incident={incident} />
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

function Heading({ total }: { total: number | null }) {
  return (
    <div className="page-header">
      <div className="page-title-group">
        <div className="page-eyebrow">Incident explorer</div>
        <h1>Correlated incidents</h1>
        <p className="page-subtitle">
          {total === null
            ? 'Loading correlated incidents…'
            : `${total} prioritised incident${total === 1 ? '' : 's'}, ordered by severity then correlation confidence.`}
        </p>
      </div>
    </div>
  );
}

function IncidentCard({
  incident,
  emphasis = false,
}: {
  incident: Incident;
  emphasis?: boolean;
}) {
  return (
    <article
      className={`incident-card incident-card--${incident.severity}${
        emphasis ? ' incident-card--emphasis' : ''
      }`}
    >
      <div className="incident-card__head">
        <span className="incident-card__id mono">{incident.id}</span>
        <span className="status-pill status-pill--sm">{incident.status}</span>
      </div>

      {/*
        Severity and confidence side by side but formally distinct: a shaped
        badge answering "how bad", a teal meter answering "how sure".
      */}
      <div className="incident-card__signals">
        <div className="incident-card__signal">
          <span className="metric-label">Severity</span>
          <SeverityBadge severity={incident.severity} />
        </div>
        <div className="incident-card__signal incident-card__signal--confidence">
          <ConfidenceIndicator confidence={incident.confidence} />
        </div>
      </div>

      <p className="incident-card__bluf">{incident.bluf}</p>

      <dl className="incident-card__facts">
        <div>
          <dt>Assets</dt>
          <dd className="mono">
            {incident.affected_assets?.length ? incident.affected_assets.join(', ') : '—'}
          </dd>
        </div>
        <div>
          <dt>Alerts</dt>
          <dd className="mono">{incident.alert_count}</dd>
        </div>
        <div>
          <dt>Sources</dt>
          <dd className="mono">
            {incident.sources?.length ? incident.sources.join(', ') : '—'}
          </dd>
        </div>
      </dl>

      {incident.mitre_techniques?.length ? (
        <div className="chip-row chip-row--tight">
          {incident.mitre_techniques.map((technique, i) => (
            <MitreChip key={mitreTechniqueId(technique) ?? i} technique={technique} />
          ))}
        </div>
      ) : null}

      {/*
        A list of equals: every card gets the same quiet control. The solid
        primary treatment is reserved for the single next step on a screen,
        which on this page is whichever incident the analyst chooses.
      */}
      <Link className="btn incident-card__cta" to={`/incidents/${incident.id}`}>
        Investigate <span className="sr-only">incident {incident.id}</span> →
      </Link>
    </article>
  );
}
