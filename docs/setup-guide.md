# Setup Guide

## Prerequisites

- Python 3.11 or newer
- Node.js 20 or newer
- Docker Desktop (optional, for the containerised demo)

## Environment Variables

Copy the example files and adjust them for your environment:

```bash
cp src/.env.example src/.env
cp src/backend/.env.example src/backend/.env
cp src/frontend/.env.example src/frontend/.env
```

| Variable | Used by | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Backend | `sqlite:///./data/elevatex.db` | SQLite connection string. |
| `CORS_ORIGINS` | Backend | `http://localhost:5173` | Comma-separated allowed frontend origins. |
| `INTELLIGENCE_MODE` | Backend | `real` | `real` uses Member 1's engine; `mock` uses the labelled fallback. |
| `VITE_API_BASE_URL` | Frontend | `http://localhost:8000` | Backend API base URL. |
| `VITE_DEMO_MODE` | Frontend | `false` | `true` renders mock data without contacting the backend. |
| `AI_PROVIDER` | Backend | `deterministic` | AI provider: `groq`, `granite`, or `deterministic`. |
| `GROQ_API_KEY` | Backend | _(unset)_ | Groq API key. Required when `AI_PROVIDER=groq`. |
| `GROQ_MODEL_ID` | Backend | `llama-3.1-8b-instant` | Groq model ID. |
| `GRANITE_ENABLED` | Backend | `false` | Set to `true` to enable the IBM Granite/Ollama provider. |
| `GRANITE_BASE_URL` | Backend | `http://localhost:11434/v1` | Ollama API base URL. |
| `GRANITE_MODEL_ID` | Backend | `granite3-moe:3b` | Ollama model name for Granite. |

## Local Installation

### Backend

```bash
cd src/backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Frontend

```bash
cd src/frontend
npm install
```

## Running the Application

### Backend

```bash
cd src/backend
.venv\Scripts\python.exe -m app.db.seed --reset
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The API is available at `http://localhost:8000`.

### Frontend

```bash
cd src/frontend
npm run dev
```

The dashboard is available at `http://localhost:5173`.

## Docker

```bash
docker compose up --build
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`

The backend container seeds the SQLite database on startup and persists it in the mounted `./data` directory at `/app/data/elevatex.db`.

## Tests

```bash
# Backend
cd src/backend
.venv\Scripts\python.exe -m pytest

# Intelligence
python -m unittest discover -s src/intelligence -p test_*.py -v

# Frontend
cd src/frontend
npm test
npm run build
```

## Running with Groq (cloud AI inference)

Set the following before starting the backend:

```bash
# Linux / macOS
export AI_PROVIDER=groq
export GROQ_API_KEY=your-groq-api-key
export GROQ_MODEL_ID=llama-3.1-8b-instant  # optional; this is the default

# Windows PowerShell
$env:AI_PROVIDER = "groq"
$env:GROQ_API_KEY = "your-groq-api-key"
$env:GROQ_MODEL_ID = "llama-3.1-8b-instant"
```

When `AI_PROVIDER=groq` and a valid `GROQ_API_KEY` is set, `POST /api/analyze` will use the Groq API to generate the analyst-facing BLUF explanation. All deterministic intelligence results (correlation, scoring, MITRE, evidence, actions) remain unchanged.

Get a free Groq API key at [https://console.groq.com](https://console.groq.com).

## Running with IBM Granite via Ollama (local AI inference)

IBM Granite is IBM's open-source foundation model family. This provider runs Granite locally through Ollama — no IBM cloud credentials are required.

1. Install Ollama: [https://ollama.com](https://ollama.com)
2. Pull a Granite model:

```bash
ollama pull granite3-moe:3b      # compact, fast
# or
ollama pull granite3.3:8b        # full instruct model
```

3. Set environment variables:

```bash
AI_PROVIDER=granite
GRANITE_ENABLED=true
GRANITE_MODEL_ID=granite3-moe:3b   # match the pulled model name
```

**Docker note:** Ollama running on the host is NOT accessible at `localhost` from inside the Docker container. Use:

```yaml
# docker-compose.yml
GRANITE_BASE_URL: http://host.docker.internal:11434/v1  # Docker Desktop
# or use the host machine's actual IP address
```

## Running without any AI provider (deterministic mode)

Leave `AI_PROVIDER` unset or set it to `deterministic`. The backend uses the deterministic BLUF generator. The application is fully functional.

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError: app` | Run backend commands from `src/backend`. |
| Frontend cannot reach the backend | Confirm the backend is running and `VITE_API_BASE_URL` is correct. |
| Database is empty | Run `python -m app.db.seed --reset`. |
| Docker is unavailable | Install Docker Desktop or use the local development commands above. |
| Groq returns 401 | Check that `GROQ_API_KEY` is a valid key from console.groq.com. |
| Groq returns 429 | Rate limit hit; wait or use a paid tier key. |
| BLUF is deterministic despite AI_PROVIDER=groq | Check logs for grounding validation failures; the fallback is working correctly. |
| Ollama connection refused | Confirm Ollama is running: `ollama serve`. Check `GRANITE_BASE_URL`. |
| Granite model not found | Run `ollama pull granite3-moe:3b` (or whichever model is in `GRANITE_MODEL_ID`). |
