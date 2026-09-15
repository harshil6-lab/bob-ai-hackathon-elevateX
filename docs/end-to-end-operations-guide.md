# End-to-End Operations Guide

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**
Team elevateX · IBM Bobathon 2026

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Prerequisites](#2-prerequisites)
3. [Environment Configuration](#3-environment-configuration)
4. [Local Development Setup](#4-local-development-setup)
5. [Running the Full Stack](#5-running-the-full-stack)
6. [Docker Deployment](#6-docker-deployment)
7. [AI Provider Configuration](#7-ai-provider-configuration)
8. [The Golden Demo Scenario](#8-the-golden-demo-scenario)
9. [API Reference](#9-api-reference)
10. [Intelligence Pipeline Internals](#10-intelligence-pipeline-internals)
11. [Running the Test Suites](#11-running-the-test-suites)
12. [Troubleshooting](#12-troubleshooting)
13. [Security Checklist](#13-security-checklist)
14. [Architecture Quick Reference](#14-architecture-quick-reference)

---

## 1. System Overview

The D2 Threat Intelligence Copilot ingests multi-source security feeds, correlates
related alerts into incidents, and delivers prioritised, evidence-grounded assessments
to analysts and commanders.

**Core capabilities:**

| Capability | Where it lives |
|---|---|
| Multi-source alert ingestion | `src/backend` + `src/data/raw/` |
| Alert normalization | `src/backend/app/services/data_ingestion.py` |
| Correlation and incident grouping | `src/intelligence/correlation.py` |
| Threat scoring and risk calculation | `src/intelligence/scoring.py` |
| Evidence extraction | `src/intelligence/evidence.py` |
| MITRE ATT&CK mapping | `src/intelligence/mitre.py` |
| BLUF generation (deterministic) | `src/intelligence/bluf.py` |
| BLUF explanation (optional AI) | `src/intelligence/ai/` |
| REST API | `src/backend/app/api/` |
| React dashboard | `src/frontend/` |

**Design principle:** The deterministic intelligence engine is always authoritative.
External AI providers (Groq, IBM Granite) contribute only the optional analyst-facing
BLUF natural-language explanation. Every AI output is grounding-validated before use.
If a provider is unavailable or its output fails validation, the system falls back to
the deterministic BLUF. The application never crashes due to an AI provider issue.

---

## 2. Prerequisites

| Tool | Version | Required for |
|---|---|---|
| Python | 3.11 or newer | Backend + Intelligence |
| Node.js | 20 or newer | Frontend |
| npm | 9 or newer | Frontend |
| Docker Desktop | any recent | Docker deployment (optional) |
| Ollama | any recent | IBM Granite local inference (optional) |

Verify your environment:

```bash
python --version          # Python 3.11.x
node --version            # v20.x.x
npm --version             # 9.x.x or higher
docker --version          # Docker version 2x.x (optional)
ollama --version          # ollama version 0.x.x (optional)
```

---

## 3. Environment Configuration

Three `.env` files control the application.

### 3.1 Create the env files

```bash
# From the workspace root
cp src/.env.example        src/.env
cp src/backend/.env.example  src/backend/.env
cp src/frontend/.env.example src/frontend/.env
```

### 3.2 Variable reference

#### `src/.env` — shared / top-level

| Variable | Default | Description |
|---|---|---|
| `AI_PROVIDER` | `deterministic` | Active AI provider: `groq`, `granite`, or `deterministic` |
| `GROQ_API_KEY` | _(unset)_ | Required when `AI_PROVIDER=groq`. Never commit this value. |
| `GROQ_MODEL_ID` | `llama-3.1-8b-instant` | Groq model. Change to any Groq-hosted LLM. |
| `GRANITE_ENABLED` | `false` | Set `true` to enable IBM Granite via Ollama. |
| `GRANITE_BASE_URL` | `http://localhost:11434/v1` | Ollama API endpoint. |
| `GRANITE_MODEL_ID` | `granite3-moe:3b` | Ollama model name. Must match a pulled model. |

#### `src/backend/.env`

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./data/elevatex.db` | SQLite connection string. |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins. |
| `INTELLIGENCE_MODE` | `real` | `real` = live intelligence engine; `mock` = labelled mock. |

#### `src/frontend/.env`

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend API base URL. |
| `VITE_DEMO_MODE` | `false` | `true` = serve mock data without contacting the backend. |

> **Security note:** `.env` files are listed in `.gitignore` and must never be committed.
> The `GROQ_API_KEY` must never appear in logs, API responses, frontend code, or documentation.

---

## 4. Local Development Setup

### 4.1 Backend

```bash
cd src/backend

# Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 4.2 Intelligence (no separate install needed)

The intelligence layer is pure Python (stdlib only for production code) and is
imported directly by the backend. No separate install is required.

### 4.3 Frontend

```bash
cd src/frontend
npm install
```

---

## 5. Running the Full Stack

### Step 1 — Seed the database

```bash
cd src/backend

# Windows
.venv\Scripts\python.exe -m app.db.seed --reset

# macOS / Linux
python -m app.db.seed --reset
```

This creates `src/backend/data/elevatex.db` and loads the synthetic demo dataset
from `src/data/`. The `--reset` flag drops and recreates all tables first, giving
a clean deterministic state for every demo run.

### Step 2 — Start the backend

```bash
cd src/backend

# Windows
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# macOS / Linux
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The API is available at `http://localhost:8000`.
Interactive API docs are at `http://localhost:8000/docs`.

### Step 3 — Start the frontend

```bash
cd src/frontend
npm run dev
```

The dashboard is available at `http://localhost:5173`.

### Step 4 — Verify the stack

Open `http://localhost:5173`. You should see:

- A command centre header with threat statistics.
- Alert count, correlated incident count, and critical incident count populated.
- The incidents table showing at least one `critical` incident.

---

## 6. Docker Deployment

Docker builds both services from the workspace root using the top-level
`docker-compose.yml`.

```bash
# Build and start both containers
docker compose up --build

# Stop
docker compose down
```

| Service | URL |
|---|---|
| Frontend (Nginx) | `http://localhost:80` |
| Backend (FastAPI) | `http://localhost:8000` |

### AI provider in Docker

AI provider credentials are passed as environment variables at runtime, never
baked into the image.

```bash
# Groq (Linux / macOS)
AI_PROVIDER=groq GROQ_API_KEY=gsk_... docker compose up --build

# Windows PowerShell
$env:AI_PROVIDER = "groq"
$env:GROQ_API_KEY = "gsk_..."
docker compose up --build
```

For IBM Granite with Ollama running on the host:

```bash
# docker-compose.yml override
GRANITE_BASE_URL: http://host.docker.internal:11434/v1   # Docker Desktop
# or
GRANITE_BASE_URL: http://<host-machine-ip>:11434/v1       # Linux without Desktop
```

### Database persistence

The backend container writes to `/app/data/elevatex.db`. Mount a host volume
to persist the database across container restarts:

```yaml
# docker-compose.yml (already configured)
volumes:
  - ./data:/app/data
```

---

## 7. AI Provider Configuration

The AI provider controls only the optional natural-language BLUF explanation.
All intelligence results (correlation, scoring, MITRE, evidence, actions) are
identical regardless of which provider is active.

### 7.1 Deterministic mode (default)

No configuration required. Leave `AI_PROVIDER` unset or set it to `deterministic`.

```bash
AI_PROVIDER=deterministic   # or just don't set it
```

The backend uses the template-based deterministic BLUF generator in
`src/intelligence/bluf.py`. All 450 tests pass in this mode.

### 7.2 Groq cloud inference

1. Obtain a free API key at [https://console.groq.com](https://console.groq.com).
2. Set the environment variables **before** starting the backend:

```bash
# Linux / macOS
export AI_PROVIDER=groq
export GROQ_API_KEY=gsk_...
export GROQ_MODEL_ID=llama-3.1-8b-instant   # optional; this is the default

# Windows PowerShell
$env:AI_PROVIDER    = "groq"
$env:GROQ_API_KEY   = "gsk_..."
$env:GROQ_MODEL_ID  = "llama-3.1-8b-instant"
```

When a `POST /api/analyze` request is processed, the `GroqProvider` sends a
bounded, grounding-safe prompt to `https://api.groq.com/openai/v1/chat/completions`
and receives a JSON BLUF explanation. The `validate_ai_output()` grounding validator
then checks every reference in the AI output against the deterministic facts before
the BLUF is included in the response.

If grounding fails (e.g. the model hallucinated an alert ID), the deterministic
fallback is used silently. No error is surfaced to the user.

### 7.3 IBM Granite via Ollama (local inference)

IBM Granite is IBM's open-source foundation model family. This provider runs
entirely locally — no IBM cloud credentials are needed.

1. Install Ollama: [https://ollama.com](https://ollama.com)

2. Pull a Granite model:

```bash
ollama pull granite3-moe:3b     # compact and fast (recommended for demo)
ollama pull granite3.3:8b       # full instruct model (better quality)
```

3. Verify Ollama is running:

```bash
ollama serve          # starts the Ollama daemon if not already running
curl http://localhost:11434/api/tags   # lists available models
```

4. Set environment variables:

```bash
AI_PROVIDER=granite
GRANITE_ENABLED=true
GRANITE_MODEL_ID=granite3-moe:3b    # must match the pulled model name
```

5. Start the backend normally (Step 2 above).

### 7.4 Provider selection logic

```
AI_PROVIDER env var
        │
        ├─ "groq"        → GROQ_API_KEY set?    → GroqProvider
        │                   else                 → None (deterministic fallback)
        │
        ├─ "granite"     → GRANITE_ENABLED=true? → GraniteProvider
        │                   else                 → None (deterministic fallback)
        │
        └─ any other     → None (deterministic BLUF)
```

The factory (`src/intelligence/ai/factory.py`) logs a warning and returns `None`
on any misconfiguration. The application always produces a valid response.

---

## 8. The Golden Demo Scenario

The golden demo runs the full pipeline against a carefully constructed
multi-source dataset that demonstrates every D2 challenge requirement.

### 8.1 What the dataset contains

The synthetic dataset in `src/data/` includes:

- **SIEM alerts** — PowerShell execution, lateral movement, credential access
- **Network sensor alerts** — port scans, C2 beaconing, data exfiltration
- **Threat intelligence feed entries** — known-bad IP matches, TTPs

### 8.2 Running the golden demo

```bash
# 1. Seed (always reset for determinism)
cd src/backend
python -m app.db.seed --reset

# 2. Start backend
uvicorn app.main:app --host 127.0.0.1 --port 8000

# 3. Start frontend (separate terminal)
cd src/frontend
npm run dev

# 4. Open dashboard
#    http://localhost:5173
```

### 8.3 The demo narrative (11 judging steps)

| Step | What to show | Where in the UI |
|---|---|---|
| 1 | Raw alert volume | Dashboard — "Total alerts" metric |
| 2 | Multi-source ingestion | Dashboard — sources: SIEM, NETWORK_SENSOR, THREAT_INTEL |
| 3 | Noisy raw alerts | Alert Explorer — full unfiltered list |
| 4 | Click "Analyze Alerts" | Dashboard — command-centre button |
| 5 | Pipeline runs | Dashboard — loading state |
| 6 | Correlated incidents (far fewer) | Dashboard — "Correlated incidents" metric |
| 7 | Prioritised critical incident | Incidents page — first row is `critical` |
| 8 | Evidence panel | Incident detail — Evidence tab |
| 9 | MITRE ATT&CK mapping | Incident detail — MITRE chips (T1003, T1021, T1059.001) |
| 10 | BLUF summary | Incident detail — BLUF panel at top |
| 11 | Recommended actions | Incident detail — Actions panel |

### 8.4 Deterministic golden facts (SERVER-17 attack chain)

These values are hardcoded expectations and must never change:

| Field | Expected value |
|---|---|
| Incident severity | `critical` |
| Risk score | 91 |
| Confidence | 100 % |
| Alert count | 6 |
| Source count | 3 (SIEM, NETWORK_SENSOR, THREAT_INTEL) |
| MITRE techniques | T1003, T1021, T1059.001 |

The test `test_every_golden_scenario_passes` in `src/intelligence/tests/test_evaluation.py`
validates these facts on every CI run.

---

## 9. API Reference

Base URL: `http://localhost:8000`

Interactive docs: `http://localhost:8000/docs`

### GET /api/alerts

Returns all normalised alerts.

```bash
curl http://localhost:8000/api/alerts
```

**Response (array of Alert):**
```json
[
  {
    "id": "ALT-1001",
    "timestamp": "2026-09-14T10:32:00Z",
    "source": "SIEM",
    "event_type": "PowerShell",
    "severity": "medium",
    "source_ip": "10.10.1.20",
    "destination_ip": "10.10.5.17",
    "host": "SERVER-17",
    "user": "admin",
    "description": "Suspicious PowerShell execution"
  }
]
```

### GET /api/alerts/{id}

Returns a single alert by ID.

```bash
curl http://localhost:8000/api/alerts/ALT-1001
```

### GET /api/incidents

Returns all correlated and scored incidents.

```bash
curl http://localhost:8000/api/incidents
```

**Response (array of Incident):**
```json
[
  {
    "id": "INC-001",
    "severity": "critical",
    "confidence": 94,
    "status": "investigating",
    "affected_assets": ["SERVER-17"],
    "alert_count": 7,
    "sources": ["SIEM", "NETWORK_SENSOR", "THREAT_INTEL"],
    "mitre_techniques": [{"id": "T1059.001", "name": "PowerShell"}],
    "evidence": [{"id": "EV-001", "type": "log", "description": "..."}],
    "bluf": "CRITICAL: ...",
    "recommended_actions": ["Isolate SERVER-17", "..."]
  }
]
```

### GET /api/incidents/{id}

Returns a single incident by ID.

```bash
curl http://localhost:8000/api/incidents/INC-001
```

### GET /api/dashboard/stats

Returns aggregate statistics for the command-centre header.

```bash
curl http://localhost:8000/api/dashboard/stats
```

**Response:**
```json
{
  "total_alerts": 42,
  "critical_incidents": 1,
  "active_incidents": 3,
  "recent_incidents": [...],
  "sources": ["SIEM", "NETWORK_SENSOR", "THREAT_INTEL"]
}
```

### POST /api/analyze

Loads all persisted alerts, runs the full intelligence pipeline, persists the
resulting incidents, and returns them.

```bash
curl -X POST http://localhost:8000/api/analyze
```

**Response:** same schema as `GET /api/incidents`.

> This endpoint loads alerts from the database. Seed the database before calling it.

---

## 10. Intelligence Pipeline Internals

The pipeline in `src/intelligence/pipeline.py` runs in the following order:

```
1. normalize_alerts(raw)          → canonical Alert list
2. correlate(alerts)              → correlated groups
3. score_incident(group)          → risk score, severity, confidence
4. extract_evidence(group)        → Evidence list
5. map_mitre(group)               → MITRE ATT&CK Technique list
6. build_ai_context(...)          → bounded AIContext (deterministic facts only)
7. provider.generate(context)     → AIReasoningOutput  ← optional
8. validate_ai_output(output)     → grounding check     ← optional
9. generate_bluf(...)             → BLUF string
10. build_recommended_actions()   → action list
11. IntelligenceAnalysis          → to_public_incidents() → public dicts
```

Steps 1–6 and 9–11 are always deterministic. Steps 7–8 are skipped when
`AI_PROVIDER=deterministic` (the default).

### Grounding boundary

`validate_ai_output()` in `src/intelligence/ai/grounding.py` enforces:

- Alert IDs referenced in AI output must exist in the correlated group.
- Evidence IDs must exist in the extracted evidence.
- MITRE technique IDs must exist in the controlled mapping.
- Hosts, users, source IPs, destination IPs must appear in the actual alerts.
- Numeric claims (risk score, alert count, confidence) must exactly match deterministic values.

Violation of any rule → silent fallback to deterministic BLUF.

---

## 11. Running the Test Suites

All three test suites must pass before any submission.

### Intelligence — 264 tests

```bash
# From workspace root
python -m pytest src/intelligence/tests/ -v
```

Key test files:

| File | Coverage |
|---|---|
| `test_pipeline.py` | Full pipeline end-to-end |
| `test_evaluation.py` | Golden scenario determinism (11 tests) |
| `test_ai_boundary.py` | Grounding validation |
| `test_groq_granite_providers.py` | Groq + Granite + factory (43 tests, fully mocked) |
| `test_bluf.py` | BLUF generation + fallback |
| `test_correlation.py` | Correlation logic |
| `test_mitre.py` | MITRE mapping |
| `test_scoring.py` | Risk scoring |

### Backend — 50 tests

```bash
cd src/backend
python -m pytest tests/ -v
```

Key test files:

| File | Coverage |
|---|---|
| `test_api.py` | All 6 frozen API endpoints |
| `test_intelligence_adapter.py` | Provider loading + `provider=None` path |
| `test_data_ingestion.py` | Normalization |
| `test_models.py` | Schema validation |

### Frontend — 136 tests

```bash
cd src/frontend
npx vitest run
```

Key test files:

| File | Coverage |
|---|---|
| `demoFlow.test.tsx` | Full 11-step judge walkthrough |
| `Dashboard.test.tsx` | Command-centre lifecycle |
| `Alerts.test.tsx` | Alert Explorer filtering + sorting |
| `IncidentDetail.test.tsx` | MITRE, evidence, BLUF, actions display |
| `Incidents.test.tsx` | Incident list |
| `envDefault.test.tsx` | No-backend graceful degradation |
| `services.test.ts` | API service layer |

### Run all three in sequence

```bash
# From workspace root
python -m pytest src/intelligence/tests/ -q
cd src/backend && python -m pytest tests/ -q && cd ../..
cd src/frontend && npx vitest run --reporter=verbose && cd ../..
```

Expected total: **450 tests, 0 failures**.

---

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: app` | Running backend commands from wrong directory | `cd src/backend` first |
| `ModuleNotFoundError: src` | Running intelligence tests from wrong directory | Run `python -m pytest src/intelligence/tests/` from workspace root |
| Dashboard shows no data | Backend not running or seeding skipped | Start backend, run `python -m app.db.seed --reset` |
| `POST /api/analyze` returns empty incidents | Database is empty | Run seed, then analyze |
| Frontend cannot reach backend | `VITE_API_BASE_URL` misconfigured | Set to `http://localhost:8000` in `src/frontend/.env` |
| Groq returns 401 | Invalid API key | Check key at [console.groq.com](https://console.groq.com) |
| Groq returns 429 | Rate limit | Wait 1 minute or upgrade to paid tier |
| BLUF is deterministic despite `AI_PROVIDER=groq` | Grounding validation rejected AI output | This is correct fallback behaviour; check backend logs |
| Ollama connection refused | Ollama daemon not running | Run `ollama serve` |
| Granite model not found | Model not pulled | Run `ollama pull granite3-moe:3b` |
| Docker: Granite unreachable | Ollama on host not reachable from container | Set `GRANITE_BASE_URL=http://host.docker.internal:11434/v1` |
| `CORS` errors in browser | Frontend origin not in allowed list | Add `http://localhost:5173` to `CORS_ORIGINS` in backend `.env` |
| Tests fail with `No module named 'src'` | pytest run from wrong directory | Run from workspace root: `python -m pytest src/intelligence/tests/` |

---

## 13. Security Checklist

Before demo or deployment, verify:

- [ ] `src/.env`, `src/backend/.env`, `src/frontend/.env` are **not** tracked by git (`git status` shows no `.env` files).
- [ ] `GROQ_API_KEY` is **not** present in any committed file.
- [ ] `GROQ_API_KEY` is **not** visible in browser network tab (the frontend never receives it).
- [ ] `GROQ_API_KEY` is **not** in Docker image layers (`docker history <image>`).
- [ ] `AI_PROVIDER=deterministic` for the public demo if no API key is available.
- [ ] Backend CORS is restricted to the actual frontend origin.
- [ ] `python -m pytest src/intelligence/tests/ -q` passes (no hallucination regression).

---

## 14. Architecture Quick Reference

```
src/data/raw/           ← synthetic multi-source feeds (JSON, log, CSV)
        │
src/backend/            ← FastAPI, SQLAlchemy, ingestion, seed
        │
        ├── GET /api/alerts
        ├── GET /api/incidents
        ├── GET /api/dashboard/stats
        └── POST /api/analyze
                │
                ▼
src/intelligence/       ← deterministic engine (Member 1)
        │
        ├── correlation.py       alert grouping
        ├── scoring.py           risk / severity / confidence
        ├── evidence.py          evidence extraction
        ├── mitre.py             MITRE ATT&CK mapping
        ├── bluf.py              BLUF generation + fallback
        ├── pipeline.py          orchestration entry point
        └── ai/
                ├── factory.py          provider selection
                ├── context.py          bounded AIContext builder
                ├── grounding.py        validate_ai_output()
                ├── groq_provider.py    Groq cloud provider
                └── granite_provider.py IBM Granite / Ollama provider
        │
src/frontend/           ← React + Vite + TypeScript (Member 3)
        │
        └── Dashboard → Incidents → Incident detail
                           (BLUF, MITRE, Evidence, Actions)
```

**Test counts:** 264 intelligence · 50 backend · 136 frontend = **450 total**

**Golden scenario:** SERVER-17 attack chain → severity=critical, risk_score=91,
confidence=100, alert_count=6, sources=3, MITRE={T1003, T1021, T1059.001}

---

*Made with IBM Bob · Team elevateX · IBM Bobathon 2026*
