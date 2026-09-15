/**
 * IncidentDetail — the investigation view. Route: /incidents/:id
 *
 * Answers the five investigation questions in descending visual priority:
 *   1. What happened and why does it matter?  -> BLUF (most prominent)
 *   2. How bad / how sure / what is affected? -> one facts strip, read in a
 *                                                single pass
 *   3. How did it unfold?                     -> attack chain, only where the
 *                                                MITRE data supports it
 *   4. What proves it?                        -> evidence
 *   5. What technique, and what do I do?      -> MITRE, recommended actions
 */

import { Link, useParams, useNavigate } from 'react-router-dom';

import { BlufPanel } from '../components/BlufPanel';
import { EvidencePanel } from '../components/EvidencePanel';
import { ActionsList } from '../components/ActionsList';
import { MitreChip } from '../components/MitreChip';
import { SeverityBadge } from '../components/SeverityBadge';
import { ConfidenceIndicator } from '../components/ConfidenceIndicator';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

import { useIncident } from '../hooks/useIncident';
import { mitreTechniqueId } from '../types/incident';

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: incident, status, error, reload } = useIncident(id);

  /* ── States ───────────────────────────────────────────────────────────── */

  if (status === 'loading') {
    return (
      <div className="page">
        <Breadcrumbs id={id} />
        <LoadingSkeleton variant="panel" count={1} label="Loading incident…" />
        <div style={{ marginTop: 'var(--space-5)' }}>
          <LoadingSkeleton variant="card" count={2} />
        </div>
      </div>
    );
  }

  if (status === 'error') {
    const notFound = error?.status === 404;
    return (
      <div className="page">
        <Breadcrumbs id={id} />
        <ErrorState
          message={
            notFound
              ? `Incident ${id} was not found.`
              : 'Could not load this incident.'
          }
          detail={notFound ? `GET /api/incidents/${id} — HTTP 404` : error?.userMessage}
          onRetry={notFound ? undefined : reload}
        />
        <div className="detail-back">
          <button type="button" className="btn" onClick={() => navigate('/incidents')}>
            ← Back to incidents
          </button>
        </div>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="page">
        <Breadcrumbs id={id} />
        <EmptyState
          message="No incident data was returned."
          action={{ label: 'Back to incidents', onClick: () => navigate('/incidents') }}
        />
      </div>
    );
  }

  /* ── Populated ────────────────────────────────────────────────────────── */

  // Ordered unique tactics for the attack chain, derived from the MITRE
  // techniques the API actually returned. Stages are never invented: an
  // incident whose techniques carry no tactic renders no chain at all.
  const tacticOrder = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
    'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact',
  ];
  const presentTactics = (() => {
    if (!incident.mitre_techniques?.length) return [];
    const seen = new Set<string>();
    const result: string[] = [];
    for (const order of tacticOrder) {
      if (incident.mitre_techniques.some((t) => {
        const tactic = typeof t === 'string' ? null : (t as { tactic?: string }).tactic;
        return tactic === order;
      })) {
        if (!seen.has(order)) { seen.add(order); result.push(order); }
      }
    }
    return result;
  })();

  return (
    <div className="page">
      <Breadcrumbs id={incident.id} />

      <div className="page-header detail-header">
        <div className="page-title-group">
          <div className="page-eyebrow">Incident investigation</div>
          <div className="detail-identity">
            <h1 className="detail-title">{incident.id}</h1>
            <SeverityBadge severity={incident.severity} size="lg" />
          </div>
        </div>
        <button type="button" className="btn" onClick={() => navigate('/incidents')}>
          ← Back to incidents
        </button>
      </div>

      {/* 1. BLUF — the single most prominent element on the page. */}
      <BlufPanel bluf={incident.bluf} />

      {/*
        2. Assessment and context in ONE strip. Severity and confidence stay
        formally distinct — a shaped badge answering "how bad", a teal meter
        answering "how sure" — but they are read in a single pass alongside
        what is affected, rather than spread across three separate blocks.
      */}
      <section className="incident-facts" aria-label="Threat assessment and context">
        <div className="incident-facts__cell">
          <span className="metric-label">Severity</span>
          <SeverityBadge severity={incident.severity} />
          <p className="incident-facts__note">How damaging this is if genuine.</p>
        </div>
        <div className="incident-facts__cell incident-facts__cell--confidence">
          <ConfidenceIndicator confidence={incident.confidence} />
          <p className="incident-facts__note">
            How certain the correlation is. Independent of severity.
          </p>
        </div>
        <div className="incident-facts__cell">
          <span className="metric-label">Status</span>
          <span className="status-pill">{incident.status}</span>
          <p className="incident-facts__note">Position in the response workflow.</p>
        </div>
        <div className="incident-facts__cell incident-facts__cell--wide">
          <span className="metric-label">Affected assets</span>
          <span className="incident-facts__value mono">
            {incident.affected_assets?.length
              ? incident.affected_assets.join(', ')
              : 'None reported'}
          </span>
        </div>
        <div className="incident-facts__cell">
          <span className="metric-label">Correlated alerts</span>
          <span className="incident-facts__value mono">{incident.alert_count}</span>
        </div>
        <div className="incident-facts__cell incident-facts__cell--wide">
          <span className="metric-label">Contributing sources</span>
          <span className="incident-facts__value mono">
            {incident.sources?.length ? incident.sources.join(', ') : 'None reported'}
          </span>
        </div>
      </section>

      {/* 3. Attack chain — purely the tactics present in the returned data. */}
      {presentTactics.length > 0 ? (
        <div className="attack-chain" aria-label="Attack chain stages">
          <span className="attack-chain__label">
            Attack chain <span className="attack-chain__source">from mapped ATT&amp;CK tactics</span>
          </span>
          <div className="attack-chain__stages">
            {presentTactics.map((tactic, i) => (
              <span key={tactic} style={{ display: 'contents' }}>
                {i > 0 ? (
                  <span className="attack-chain__arrow" aria-hidden="true">→</span>
                ) : null}
                <span className="attack-chain__stage">{tactic}</span>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <div className="detail-grid">
        {/* 4. Evidence. */}
        <section className="panel" aria-labelledby="evidence-heading">
          <div className="panel-header">
            <h2 id="evidence-heading" className="panel-title">
              Evidence
            </h2>
            <span className="panel-note text-muted">
              {incident.evidence?.length ?? 0} record
              {(incident.evidence?.length ?? 0) === 1 ? '' : 's'}
            </span>
          </div>
          <div className="panel-body">
            <EvidencePanel evidence={incident.evidence} />
          </div>
        </section>

        <div className="detail-column">
          {/* 5a. MITRE ATT&CK. */}
          <section className="panel" aria-labelledby="mitre-heading">
            <div className="panel-header">
              <h2 id="mitre-heading" className="panel-title">
                MITRE ATT&amp;CK
              </h2>
              <span className="panel-note text-muted">verify on attack.mitre.org</span>
            </div>
            <div className="panel-body">
              {incident.mitre_techniques?.length ? (
                <div className="chip-row chip-row--stack">
                  {incident.mitre_techniques.map((technique, i) => (
                    <MitreChip
                      key={mitreTechniqueId(technique) ?? i}
                      technique={technique}
                    />
                  ))}
                </div>
              ) : (
                <EmptyState message="No MITRE ATT&CK techniques were mapped to this incident." />
              )}
            </div>
          </section>

          {/* 5b. Recommended actions. */}
          <section className="panel" aria-labelledby="actions-heading">
            <div className="panel-header">
              <h2 id="actions-heading" className="panel-title">
                Recommended actions
              </h2>
            </div>
            <div className="panel-body">
              <ActionsList actions={incident.recommended_actions} />
            </div>
          </section>
        </div>
      </div>

      <div className="detail-back">
        <Link className="btn" to="/incidents">
          ← Back to incidents
        </Link>
        <Link className="btn btn-ghost" to="/">
          Return to command centre
        </Link>
      </div>
    </div>
  );
}

function Breadcrumbs({ id }: { id: string | undefined }) {
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <ol className="breadcrumbs__list">
        <li>
          <Link to="/">Dashboard</Link>
        </li>
        <li aria-hidden="true" className="breadcrumbs__sep">
          ›
        </li>
        <li>
          <Link to="/incidents">Incidents</Link>
        </li>
        <li aria-hidden="true" className="breadcrumbs__sep">
          ›
        </li>
        <li>
          <span aria-current="page" className="mono">
            {id ? `Incident ${id}` : 'Incident'}
          </span>
        </li>
      </ol>
    </nav>
  );
}
