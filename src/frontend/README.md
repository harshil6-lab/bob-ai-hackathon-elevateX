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

**It defaults to ON when `VITE_DEMO_MODE` is unset**, because `src/backend/`
does not exist yet and Vite does not read `.env.example`. Set
`VITE_DEMO_MODE=false` in `.env` as soon as the backend is running.

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

## ⚠️ API contract issues for Member 1 / Member 2

`src/backend/` did not exist when this frontend was written, so **nothing below
has been verified against a running API.** The canonical `Alert` and `Incident`
field names come from `AGENTS.md`, which is authoritative; these five items are
the gaps `AGENTS.md` does not settle.

### 1. `GET /api/dashboard/stats` — response shape is PROVISIONAL
`AGENTS.md` freezes the endpoint but not its body. Every field in
`types/dashboard.ts` is marked `PROVISIONAL` and optional, derived from the
dashboard requirements:

```
total_alerts, total_incidents, critical_count, high_count,
severity_distribution, source_distribution, top_incident,
recent_incidents, last_analysis_at
```

**Mitigation already in place:** `mergeWithDerived()` computes any field the
backend omits from the *confirmed* `/api/alerts` and `/api/incidents` responses,
so a partial match degrades gracefully instead of rendering blank panels. A
field the backend *does* return always wins. This runs only on a **successful**
stats response — never as an error fallback.

**Needed from Member 2:** confirm or correct these names.

### 2. `POST /api/analyze` — response shape is PROVISIONAL
`AnalyzeResult` fields (`incidents_created`, `alerts_processed`, `status`,
`message`, `duration_ms`) are all optional. Any **2xx is treated as success
regardless of body shape**, so an unexpected body cannot cause a false failure.
Conversely any non-2xx, timeout or network error is *always* surfaced as a
failure. Also unconfirmed: whether the endpoint is synchronous or returns a job
handle to poll.

### 3. `incident.evidence[]` — element shape unconfirmed
`AGENTS.md` shows `[]`. The renderer handles **both** a bare string and an
object with optional `source`, `timestamp`, `alert_id` / `related_alert`,
`host`, `ip` / `source_ip` / `destination_ip`, `user`, `event_type`,
`description`. Only fields actually present are rendered — absent fields are
omitted entirely, never filled with a placeholder.

### 4. `incident.mitre_techniques[]` — element shape unconfirmed
Handles both a bare ID string and `{ id | technique_id, name?, tactic? }`.
**The frontend holds no ID-to-name lookup table and will never invent one.** If
the backend returns bare IDs, bare IDs are what is displayed. If technique names
are wanted in the UI, the backend must supply them — flagging this as a
coordination item rather than hard-coding a mapping.

### 5. `incident.confidence` — scale confirmed only by example
`AGENTS.md` shows `"confidence": 94`, read as an integer 0–100.
`confidencePercent()` also tolerates a 0–1 float, so `0.94` renders as 94%
rather than 1%. Worth an explicit confirmation.

**Also unconfirmed:** whether `GET /api/alerts` and `GET /api/incidents` support
query-parameter filtering. The Alert Explorer therefore **filters client-side**
over the full result set and does not depend on any parameter being honoured.
`AlertQueryParams` / `IncidentQueryParams` are still sent so server-side
filtering can be adopted later without touching call sites.

> If any of the above turns out to differ, the fix is localised: the element
> unions and accessor helpers at the bottom of `types/incident.ts` are the only
> place that needs to change.

---

## Known limitations

- **Not yet integrated with a real backend.** Every claim above about the API is
  a claim about the frontend's *handling* of it, verified against mocked and
  fixture data only. Phase 13 of the execution guide (real-backend verification)
  cannot be completed until `src/backend/` exists.
- **`DashboardStats` and `AnalyzeResult` are provisional** — see above.
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
