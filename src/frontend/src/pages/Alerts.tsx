/**
 * Alerts — the Alert Explorer.
 *
 * This is the "noise" half of the story: the raw, multi-source, largely
 * un-actionable feed that correlation exists to reduce.
 *
 * Filtering is CLIENT-SIDE. The backend's query-parameter support is unknown
 * (see AlertQueryParams), so the page fetches once and filters locally rather
 * than depending on parameters that may be ignored. Pagination keeps the DOM
 * bounded regardless of how many alerts come back.
 */

import { useMemo, useState } from 'react';

import { DataTable } from '../components/DataTable';
import type { Column } from '../components/DataTable';
import { SeverityBadge } from '../components/SeverityBadge';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { EmptyState } from '../components/EmptyState';
import { ErrorState } from '../components/ErrorState';

import { useAlerts } from '../hooks/useAlerts';
import { severityRank, SEVERITY_ORDER } from '../types/alert';
import type { Alert } from '../types/alert';

const PAGE_SIZE = 25;
const ALL = '__all__';

/** Compact, sortable UTC rendering. Keeps the column narrow on a projector. */
function formatTimestamp(iso: string): string {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return iso;
  return new Date(parsed).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
}

export function Alerts() {
  const { data, status, error, reload } = useAlerts();

  const [search, setSearch] = useState('');
  const [source, setSource] = useState(ALL);
  const [severity, setSeverity] = useState(ALL);
  const [eventType, setEventType] = useState(ALL);
  const [host, setHost] = useState(ALL);
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const alerts = useMemo(() => data ?? [], [data]);

  /** Filter options are derived from the data itself, never hard-coded. */
  const options = useMemo(() => {
    const unique = (values: string[]) => Array.from(new Set(values)).sort();
    return {
      sources: unique(alerts.map((a) => a.source).filter(Boolean)),
      eventTypes: unique(alerts.map((a) => a.event_type).filter(Boolean)),
      hosts: unique(alerts.map((a) => a.host).filter(Boolean)),
      severities: SEVERITY_ORDER.filter((s) => alerts.some((a) => a.severity === s)),
    };
  }, [alerts]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return alerts.filter((alert) => {
      if (source !== ALL && alert.source !== source) return false;
      if (severity !== ALL && alert.severity !== severity) return false;
      if (eventType !== ALL && alert.event_type !== eventType) return false;
      if (host !== ALL && alert.host !== host) return false;
      if (!needle) return true;
      return (
        alert.id.toLowerCase().includes(needle) ||
        alert.description.toLowerCase().includes(needle) ||
        alert.host.toLowerCase().includes(needle) ||
        alert.user.toLowerCase().includes(needle) ||
        alert.source_ip.toLowerCase().includes(needle) ||
        alert.destination_ip.toLowerCase().includes(needle) ||
        alert.event_type.toLowerCase().includes(needle)
      );
    });
  }, [alerts, search, source, severity, eventType, host]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visible = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  const resetFilters = () => {
    setSearch('');
    setSource(ALL);
    setSeverity(ALL);
    setEventType(ALL);
    setHost(ALL);
    setPage(0);
  };

  const hasActiveFilters =
    search.trim() !== '' ||
    source !== ALL ||
    severity !== ALL ||
    eventType !== ALL ||
    host !== ALL;

  const columns: Column<Alert>[] = useMemo(
    () => [
      {
        key: 'id',
        header: 'ID',
        width: '104px',
        cellClassName: 'mono',
        render: (a) => a.id,
        sortValue: (a) => a.id,
      },
      {
        key: 'timestamp',
        header: 'Timestamp (UTC)',
        width: '178px',
        cellClassName: 'mono',
        render: (a) => formatTimestamp(a.timestamp),
        sortValue: (a) => a.timestamp,
      },
      {
        key: 'severity',
        header: 'Severity',
        width: '124px',
        render: (a) => <SeverityBadge severity={a.severity} size="sm" />,
        // Sorts by true severity order, not alphabetically.
        sortValue: (a) => severityRank(a.severity),
      },
      {
        key: 'source',
        header: 'Source',
        width: '140px',
        render: (a) => a.source,
        sortValue: (a) => a.source,
      },
      {
        key: 'event_type',
        header: 'Event type',
        width: '160px',
        render: (a) => a.event_type,
        sortValue: (a) => a.event_type,
      },
      {
        key: 'host',
        header: 'Host',
        width: '124px',
        cellClassName: 'mono',
        render: (a) => a.host,
        sortValue: (a) => a.host,
      },
      {
        key: 'user',
        header: 'User',
        width: '110px',
        cellClassName: 'mono',
        secondary: true,
        render: (a) => a.user,
        sortValue: (a) => a.user,
      },
      {
        key: 'source_ip',
        header: 'Source IP',
        width: '124px',
        cellClassName: 'mono',
        secondary: true,
        render: (a) => a.source_ip,
        sortValue: (a) => a.source_ip,
      },
      {
        key: 'destination_ip',
        header: 'Destination IP',
        width: '124px',
        cellClassName: 'mono',
        secondary: true,
        render: (a) => a.destination_ip,
        sortValue: (a) => a.destination_ip,
      },
      {
        key: 'description',
        header: 'Description',
        // Long text is clamped to one line and expands on click, so a verbose
        // description can never blow out the row height or the table width.
        render: (a) => (
          <button
            type="button"
            className={`desc-toggle${expanded === a.id ? ' desc-toggle--open' : ''}`}
            onClick={() => setExpanded((cur) => (cur === a.id ? null : a.id))}
            aria-expanded={expanded === a.id}
            title={a.description}
          >
            {a.description}
          </button>
        ),
      },
    ],
    [expanded],
  );

  /* ── States ───────────────────────────────────────────────────────────── */

  if (status === 'loading') {
    return (
      <div className="page">
        <Heading total={null} />
        <LoadingSkeleton variant="row" count={10} label="Loading alerts…" />
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="page">
        <Heading total={null} />
        <ErrorState
          message="Could not load alerts."
          detail={error?.userMessage}
          onRetry={reload}
        />
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="page">
        <Heading total={0} />
        <EmptyState
          message="No alerts have been ingested yet."
          hint="Alerts appear here as soon as the ingestion pipeline has processed a feed."
          action={{ label: 'Refresh', onClick: reload }}
        />
      </div>
    );
  }

  return (
    <div className="page">
      <Heading total={alerts.length} />

      <section className="filter-bar" aria-label="Alert filters">
        <div className="field field--grow">
          <label className="field-label" htmlFor="alert-search">
            Search
          </label>
          <input
            id="alert-search"
            className="input"
            type="search"
            placeholder="ID, description, host, user or IP…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
        </div>

        <FilterSelect
          id="alert-severity"
          label="Severity"
          value={severity}
          onChange={(v) => {
            setSeverity(v);
            setPage(0);
          }}
          options={options.severities.map((s) => ({
            value: s,
            label: s.charAt(0).toUpperCase() + s.slice(1),
          }))}
          allLabel="All severities"
        />

        <FilterSelect
          id="alert-source"
          label="Source"
          value={source}
          onChange={(v) => {
            setSource(v);
            setPage(0);
          }}
          options={options.sources.map((s) => ({ value: s, label: s }))}
          allLabel="All sources"
        />

        <FilterSelect
          id="alert-event-type"
          label="Event type"
          value={eventType}
          onChange={(v) => {
            setEventType(v);
            setPage(0);
          }}
          options={options.eventTypes.map((s) => ({ value: s, label: s }))}
          allLabel="All event types"
        />

        <FilterSelect
          id="alert-host"
          label="Host"
          value={host}
          onChange={(v) => {
            setHost(v);
            setPage(0);
          }}
          options={options.hosts.map((s) => ({ value: s, label: s }))}
          allLabel="All hosts"
        />

        <button
          type="button"
          className="btn btn-ghost"
          onClick={resetFilters}
          disabled={!hasActiveFilters}
        >
          Clear filters
        </button>
      </section>

      <div className="result-summary" role="status" aria-live="polite">
        Showing <strong>{visible.length.toLocaleString()}</strong> of{' '}
        <strong>{filtered.length.toLocaleString()}</strong> matching alerts
        {filtered.length !== alerts.length ? (
          <> (filtered from {alerts.length.toLocaleString()})</>
        ) : null}
        .
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          message="No alerts match your filters."
          hint="Try widening the severity, source or event-type filter."
          action={{ label: 'Clear filters', onClick: resetFilters }}
        />
      ) : (
        <>
          <DataTable
            caption="Ingested alerts, filterable and sortable"
            columns={columns}
            rows={visible}
            rowKey={(a) => a.id}
            defaultSortKey="timestamp"
            defaultSortDirection="desc"
            rowClassName={(a) =>
              a.severity === 'critical' ? 'data-table__row--critical' : undefined
            }
          />

          {pageCount > 1 ? (
            <nav className="pager" aria-label="Alert pagination">
              <button
                type="button"
                className="btn"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={safePage === 0}
              >
                ← Previous
              </button>
              <span className="pager__status">
                Page <strong>{safePage + 1}</strong> of <strong>{pageCount}</strong>
              </span>
              <button
                type="button"
                className="btn"
                onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                disabled={safePage >= pageCount - 1}
              >
                Next →
              </button>
            </nav>
          ) : null}
        </>
      )}
    </div>
  );
}

function Heading({ total }: { total: number | null }) {
  return (
    <div className="page-header">
      <div className="page-title-group">
        <div className="page-eyebrow">Alert explorer</div>
        <h1>Raw multi-source alerts</h1>
        <p className="page-subtitle">
          {total === null
            ? 'Loading the ingested alert feed…'
            : `${total.toLocaleString()} normalised alerts across every connected feed — the noise correlation reduces.`}
        </p>
      </div>
    </div>
  );
}

function FilterSelect({
  id,
  label,
  value,
  onChange,
  options,
  allLabel,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  allLabel: string;
}) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className="select"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value={ALL}>{allLabel}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}
