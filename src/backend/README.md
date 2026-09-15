# D2 Threat Copilot Backend

FastAPI backend for alert ingestion, normalized SQLite storage, the frozen D2 API contract, and integration with Member 1’s deterministic intelligence engine.

## Setup

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run

```bash
.venv\Scripts\python.exe -m app.db.seed --reset
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The API is available at `http://127.0.0.1:8000`.

## Reset and Seed

```bash
.venv\Scripts\python.exe -m app.db.seed --reset
```

This clears Alerts and Incidents, then reloads the deterministic synthetic dataset.

## Intelligence Integration

`POST /api/analyze`:

1. Loads persisted canonical Alerts.
2. Calls `intelligence.pipeline.analyze(alerts, provider=None)`.
3. Converts `IntelligenceAnalysis.to_public_incidents()` to the frozen public Incident schema.
4. Persists and returns the resulting Incidents.

Set `INTELLIGENCE_MODE=mock` to use the clearly-labelled fallback adapter.

## Docker

Build from the repository root:

```bash
docker compose up --build
```

The backend image includes:

- `src/backend/app`
- `src/intelligence`
- `src/data`

SQLite persistence uses `/app/data/elevatex.db`, which is bind-mounted to the repository’s `./data` directory.

## Tests

```bash
.venv\Scripts\python.exe -m pytest
```
