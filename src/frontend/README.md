# Frontend — Threat Intelligence Command Center

**Owner:** Member 3 (Jenil Viradia) · **Branch:** `member3/frontend-ui` · **Scope:** `src/frontend/` only

React + Vite + TypeScript UI for D2 — Threat Intelligence Correlation & Alert
Prioritisation Assistant.

The whole interface exists to tell one story:

> Noisy multi-source alerts → correlated, prioritised incidents → investigation
> with BLUF, evidence, MITRE ATT&CK mapping and recommended actions.

---

## Running it locally

```bash
cd src/frontend
npm install
cp .env.example .env     # then edit if the backend is not on :8000
npm run dev              # http://localhost:5173
```

| Script | What it does |
| --- | --- |
| `npm run dev` | Dev server on port 5173 |
| `npm run build` | Type-check (`tsc -b`) + production build to `dist/` |
| `npm run preview` | Serve the production build locally |
| `npm test` | Run the full test suite once |
| `npm run test:watch` | Watch mode |

### Environment variables

Defined in `.env.example`. `.env` is already ignored by the repository-root
`.gitignore`; no frontend-level `.gitignore` was added.

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend base URL. Port 8000 matches `APP_PORT` in the repo's `src/.env.example`. |
| `VITE_DEMO_MODE` | unset → **ON** | `true` / unset renders the local golden-scenario mock data; `false` talks only to the real API. |

> **Vite reads `.env`, never `.env.example`.** Because a fresh clone has no
> `.env` at all, `VITE_DEMO_MODE` defaults to **ON when unset** — otherwise every
> page would render "could not reach the backend" before `src/backend/` exists.
> See `src/services/demoMode.ts`. `src/tests/envDefault.test.tsx` pins this.

No backend URL is hard-coded anywhere outside `apiClient.ts`. No secrets are
read, stored, or logged by the frontend.

---

## Demo mode — read this before demoing

Demo mode is **opt-in and loud**. It is controlled solely by `VITE_DEMO_MODE`,
checked *before* any request is attempted.

- When it is on, a **`DemoModeBanner`** is pinned above the navigation on every
  screen, and the header's "Data source" reads `demo mode (mock)`. A judge can
  never mistake mock data for live backend data.
- Mock data is **never** a fallback. If demo mode is off and an API call fails,
  the page renders an `ErrorState` with a working Retry — it does not quietly
  swap in mock data to hide the failure.
- A demo-mode analysis run is explicitly labelled *"simulated — demo mode, no
  backend contacted"* in the UI.

**It defaults to ON when `VITE_DEMO_MODE` is unset**, because Vite does not read
`.env.example`. Copy the example file and set `VITE_DEMO_MODE=false` to use the
integrated backend.

Note the distinction that keeps this honest: demo mode is decided at **startup,
from configuration**. It is never decided by a request failing.

### Golden scenario

`src/mocks/` holds a deterministic 248-alert dataset (fixed-seed PRNG, no
`Math.random`, no `Date.now`) containing the seven-alert **SERVER-17** chain:

```
external suspicious activity → PowerShell → suspicious process
→ credential access → remote connection → lateral movement
```

correlated into **INC-001** (critical, 94% confidence, 2 affected assets,
3 contributing feeds).

---

## What was built

### Pages

| Page | Route | Purpose |
| --- | --- | --- |
| Dashboard | `/` | "What is happening right now?" — volume, distributions, the single highest-priority incident, and the Analyze Alerts control. |
| Alert Explorer | `/alerts` | The raw noise. All ten canonical alert fields, five filters, sorting, pagination. |
| Incident Explorer | `/incidents` | The signal. Severity-then-confidence ordering, split into "Requires action" and "Monitor". |
| Investigation | `/incidents/:id` | BLUF, severity/confidence/status, context, evidence, MITRE, recommended actions. |

### Components

`Nav` · `SeverityBadge` · `ConfidenceIndicator` · `StatCard` · `DataTable` ·
`MitreChip` · `BlufPanel` · `EvidencePanel` · `ActionsList` ·
`LoadingSkeleton` · `EmptyState` · `ErrorState` · `DemoModeBanner` ·
`DistributionBars`

None contain API calls or business logic.

### Services and hooks

`apiClient` (the only place that calls `fetch`) plus `alertsService`,
`incidentsService`, `dashboardService`, `analyzeService`, `demoMode`.
Hooks: `useAlerts`, `useIncidents`, `useIncident`, `useDashboardStats`,
`useAnalyze`, and the shared `useAsyncResource` primitive that gives every page
its four states.

---

## Design decisions worth knowing

**Severity is never communicated by colour alone.** Every `SeverityBadge`
carries three redundant encodings: colour, a distinct geometric glyph
(◆ critical, ▲ high, ■ medium, ● low), and the severity word. It stays readable
in greyscale and on a bad projector.

**Severity and confidence use different visual idioms and can never be
confused.** Severity is a shaped badge on a warm hue ramp ("how bad"); confidence
is a teal meter whose *length* carries the value ("how sure"). A low-severity /
96%-confidence incident displays both facts independently — there is a test for
exactly this.

**No charting library.** Two distributions matter and both are one-dimensional
categorical counts, which a labelled CSS bar communicates more legibly than a
pie would. Every bar carries its own numeric label, so it reads without colour
and without hover.

**No UI component library.** Everything is built on ~40 CSS custom properties in
`styles/tokens.css`.

---

## Testing

```bash
npm test
```

**Status as of this writing: 136 tests across 9 files, all passing.
`npm run build` completes with no TypeScript errors.**

| File | Covers |
| --- | --- |
| `components.test.tsx` | All reusable components; the severity-colour-alone and severity-vs-confidence invariants. |
| `services.test.ts` | apiClient success / HTTP error / network failure / timeout / parse error; every service; the no-fake-success guarantee. |
| `App.test.tsx` | Root render, routing, semantic landmarks, skip link, demo banner. |
| `Dashboard.test.tsx` | Four states, retry, and the full Analyze lifecycle (idle → analyzing → success / failure). |
| `Alerts.test.tsx` | Columns, all five filters, severity-rank sorting, four states. |
| `Incidents.test.tsx` | Canonical fields, severity/confidence independence, Critical/High layout emphasis, ordering. |
| `IncidentDetail.test.tsx` | BLUF verbatim + prominence, evidence, MITRE links, recommended-action framing, breadcrumbs, 404 vs error. |
| `demoFlow.test.tsx` | The full 11-step judging flow end to end against the **real** services (mocks nothing). |
| `envDefault.test.tsx` | Regression: with **no `.env` at all**, every page renders real content rather than a backend error. |

The suite produces no console warnings.

---

## Confirmed API integration

The backend is now integrated and verified against the frontend services.

### `GET /api/dashboard/stats`

The backend returns:

```json
{
  "total_alerts": 27,
  "total_incidents": 17,
  "critical_incidents": 1,
  "high_incidents": 1,
  "severity_distribution": {
    "informational": 7,
    "low": 10,
    "medium": 1,
    "high": 7,
    "critical": 2
  },
  "source_counts": {
    "ENDPOINT_SENSOR": 8,
    "INTEL_REPORT": 3,
    "NETWORK_SENSOR": 7,
    "SIEM": 5,
    "THREAT_INTEL": 4
  },
  "status_distribution": {
    "investigating": 17
  }
}
```

`dashboardService.getDashboardStats()` maps `critical_incidents`, `high_incidents`, and `source_counts` into the existing dashboard view fields.

### `POST /api/analyze`

The backend returns:

```json
{
  "incidents": [],
  "count": 17
}
```

`analyzeService.triggerAnalysis()` maps `count` into `incidents_created` for the existing UI status message.

### Incident fields

The frozen public Incident schema is confirmed:

- `id`
- `severity`
- `confidence` — integer from 0 to 100
- `status`
- `affected_assets` — list of strings
- `alert_count`
- `sources` — list of strings
- `mitre_techniques` — list of technique ID strings
- `evidence` — list of evidence ID strings
- `bluf`
- `recommended_actions` — list of strings

### Filtering

`GET /api/alerts` and `GET /api/incidents` currently return the full result set. The Alert Explorer filters client-side for the demo dataset.

---

## Known limitations

- **Real-backend integration is complete**, but the UI still supports a clearly-labelled demo mode for offline presentations.
- **Dashboard and analyze response shapes are confirmed** and mapped in the service layer.
- **Alert filtering and pagination are client-side.** Fine for the demo's
  ~250 alerts; a production volume would need server-side paging.
- **Not visually regression-tested.** Responsive behaviour was built to the
  target widths (1920 / 1440 / 1280 priority, degrading at 1024 / 768) but has
  not been verified on the actual demo laptop or projector. Do that before the
  presentation.
- **Accessibility was built in, not audited by tooling.** Semantic landmarks,
  keyboard-operable sort headers, a skip link, visible focus rings, `aria-sort`,
  `aria-current`, `role="meter"` and non-colour severity cues are all present and
  covered by tests. No automated axe/Lighthouse run has been performed.
- `getAlertById` (`GET /api/alerts/{id}`) is implemented in the service layer but
  no page currently calls it — alert detail is shown inline in the table instead.

---

## Ownership

Everything in this feature lives under `src/frontend/`. No file in
`src/backend/`, `src/data/`, `src/intelligence/`, `docs/`, or
`.github/workflows/validate.yml` was created or modified.
