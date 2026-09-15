# D2 Threat Intelligence Command Center

## Team

- **Team:** elevateX
- **Track:** AI
- **Lead:** Harshil Kalsariya
- **Members:** Pranav Dabhi, Jenil Viradia, Shivam Prajapati

## Problem

Defence and security analysts receive thousands of alerts every day from SIEM systems, network sensors, endpoint agents, and intelligence reports in different formats. Manually correlating those alerts makes it difficult to separate genuine threats from noise, while commanders need concise, prioritised, and evidence-grounded assessments.

## Solution

The D2 Threat Intelligence Command Center ingests multi-source threat data, normalises it into a canonical Alert schema, correlates related events into Incidents, scores and prioritises them, maps attacker behaviour to MITRE ATT&CK, and produces evidence-grounded BLUF summaries with recommended actions. A React dashboard presents the alerts, incidents, evidence, MITRE mappings, and recommended actions.

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
| Intelligence | Deterministic Python pipeline with Groq (cloud) and IBM Granite (local Ollama) AI providers |
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

- **IBM Granite**: IBM's open-source foundation model, available as an optional local AI provider via Ollama (`AI_PROVIDER=granite`). No IBM cloud credentials required. IBM Granite models run on the operator's own hardware through Ollama's OpenAI-compatible API.
- **IBM Bob**: Used throughout the development lifecycle — architecture design, intelligence engine review, AI provider implementation (Groq + IBM Granite), grounded prompt engineering, test suite authorship, documentation, and security review. See [`docs/ibm-bob-contribution.md`](docs/ibm-bob-contribution.md).

## AI Providers

- **Groq** (`AI_PROVIDER=groq`): Cloud inference via Groq API. Requires `GROQ_API_KEY`. Default model: `llama-3.1-8b-instant`.
- **IBM Granite via Ollama** (`AI_PROVIDER=granite`): Local inference using IBM open-source Granite models through Ollama. Requires `GRANITE_ENABLED=true` and Ollama running locally with a Granite model pulled.
- **Deterministic** (default): No external AI call; uses the deterministic BLUF from the intelligence engine.

All providers are subject to the same grounding validator — neither can invent security facts.

## Known Limitations

- The demo uses synthetic threat data.
- MITRE ATT&CK coverage is focused on the demonstrated attack chain rather than the full framework.
- The Groq AI provider requires a `GROQ_API_KEY`; IBM Granite requires Ollama running locally. The deterministic BLUF is always the fallback.
- Operational security controls are simplified for the hackathon environment.
