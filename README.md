# D2 Threat Intelligence Command Center

## Team

- **Team:** elevateX
- **Track:** AI
- **Lead:** Harshil Kalsariya
- **Members:** Pranav Dabhi, Jenil Viradia, Shivam Prajapati

## Problem

Defence and security analysts receive thousands of alerts every day from SIEM systems, network sensors, endpoint agents, and intelligence reports in different formats. Manually correlating those alerts makes it difficult to separate genuine threats from noise, while commanders need concise, prioritised, and evidence-grounded assessments.

## Solution

The D2 Threat Intelligence Command Center ingests multi-source threat data, normalises it into a canonical Alert schema, correlates related events into incidents, scores and prioritises them, maps attacker behaviour to MITRE ATT&CK, and produces evidence-grounded BLUF summaries with recommended actions. The current prototype keeps a deterministic intelligence engine as the authoritative layer and exposes a bounded optional AI-provider interface for future model-assisted explanation work. This is a focused demo prototype, not a production deployment with live external runtime integration. A React dashboard presents the alerts, incidents, evidence, MITRE mappings, and recommended actions.

## Key Features

- Multi-source threat alert ingestion and normalisation
- Deterministic correlation of related alerts into incidents
- Threat prioritisation with severity and confidence scoring
- MITRE ATT&CK technique mapping with evidence references
- Evidence-grounded BLUF summaries and recommended actions

## Tech Stack

| Category | Technologies |
|---|---|
| Languages | Python, TypeScript |
| Backend | FastAPI, SQLAlchemy, SQLite |
| Intelligence | Deterministic Python correlation, scoring, MITRE mapping, and BLUF pipeline with an optional bounded AI provider interface |
| Frontend | React, Vite, TypeScript |
| Tooling | Docker, Docker Compose, GitHub Actions |

## Repository Structure

```text
src/
  backend/       FastAPI backend, SQLite storage, repositories, API routes
  intelligence/  Deterministic correlation, scoring, evidence, MITRE, BLUF
  frontend/      React dashboard and investigation UI
  data/          Synthetic multi-source threat feeds
docs/            Architecture, setup, and solution documentation
demo/            Demo artifacts
presentation/    Slide deck
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker Desktop (optional, for containerised execution)

### Local Development

```bash
# Backend
cd src/backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m app.db.seed --reset
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (separate terminal)
cd src/frontend
npm install
npm run dev
```

The frontend runs at `http://localhost:5173`; the backend API runs at `http://localhost:8000`.

### Docker

```bash
docker compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`

The backend uses SQLite at `/app/data/elevatex.db` inside the container and mounts the repository’s `./data` directory for persistence.

## Tests

```bash
# Intelligence (264 tests) — run from workspace root
python -m pytest src/intelligence/tests/ -q

# Backend (50 tests)
cd src/backend
.venv\Scripts\python.exe -m pytest

# Frontend (136 tests)
cd src/frontend
npx vitest run
```

Total: **450 tests, 0 failures** expected.

See [`docs/end-to-end-operations-guide.md`](docs/end-to-end-operations-guide.md) for the complete operations reference.

## API

The frozen API surface is:

- `GET /api/alerts`
- `GET /api/alerts/{id}`
- `GET /api/incidents`
- `GET /api/incidents/{id}`
- `GET /api/dashboard/stats`
- `POST /api/analyze`

Example request and response payloads are documented in [`src/backend/docs/example_payloads.md`](src/backend/docs/example_payloads.md).

## IBM Technologies

- **IBM Bob**: Used as an engineering partner during architecture design, review, prompt engineering, validation, and documentation. Its contribution is within the development lifecycle and is documented in [`docs/ibm-bob-contribution.md`](docs/ibm-bob-contribution.md).
- **Optional AI model experiments**: The codebase includes bounded adapter patterns for Groq and IBM Granite/Ollama evaluation. These are not required for the default demo path and are not presented as a live IBM runtime deployment in this prototype.
- **Deterministic-first execution**: The shipped solution remains grounded in the deterministic intelligence engine. The AI layer is optional and secondary, and it does not replace the core threat-correlation logic.

## AI Providers

- **Deterministic** (default and recommended for the demo): No external AI call; uses the deterministic BLUF from the intelligence engine.
- **Groq** (`AI_PROVIDER=groq`): Optional cloud-inference path for experimentation and future explanation augmentation. Requires `GROQ_API_KEY`.
- **IBM Granite via Ollama** (`AI_PROVIDER=granite`): Optional local provider path for experimentation. Requires `GRANITE_ENABLED=true` and a local Ollama instance with a Granite model pulled.

All provider paths are subject to the same grounding validator — none can invent security facts. The prototype does not depend on any live IBM runtime to function, and the deterministic pipeline remains the default, production-safe path.

## Known Limitations

- The demo uses synthetic threat data.
- MITRE ATT&CK coverage is focused on the demonstrated attack chain rather than the full framework.
- The demo remains deterministic-first; optional AI provider adapters are not required for the core workflow.
- No live IBM runtime integration is implemented in the current prototype; the AI layer is bounded and future-facing.
- The Groq AI provider requires a `GROQ_API_KEY`; IBM Granite requires Ollama running locally. The deterministic BLUF is always the fallback.
- Operational security controls are simplified for the hackathon environment.
