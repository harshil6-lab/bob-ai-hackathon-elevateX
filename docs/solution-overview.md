# Solution Overview

## What We Built

We built a working threat intelligence command center that turns noisy, multi-source alerts into prioritised, evidence-grounded incidents. The system normalises SIEM, network, endpoint, threat-intelligence, and report data; correlates related activity; scores and prioritises threats; maps behaviour to MITRE ATT&CK; and produces BLUF summaries with recommended actions.

## How It Works

1. Raw threat feeds are ingested from `src/data/raw/`.
2. The backend normalises them into the canonical Alert schema.
3. Alerts are stored in SQLite.
4. `POST /api/analyze` sends persisted Alerts to the deterministic intelligence engine.
5. The engine correlates alerts, scores threats, extracts evidence, maps MITRE techniques, and generates BLUF and recommended actions.
6. Optionally, an AI provider (Groq or IBM Granite via Ollama) generates an analyst-oriented BLUF explanation grounded in the deterministic results.
7. The backend persists the resulting Incidents and exposes them through the frozen API.
8. The React dashboard presents alerts, incidents, evidence, MITRE mappings, BLUF, and actions.

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Deterministic intelligence pipeline | Makes the demo repeatable and auditable. |
| Canonical Alert and Incident schemas | Keeps the backend, intelligence, and frontend contracts stable. |
| SQLite | Simple, reliable persistence for the hackathon prototype. |
| React dashboard | Gives analysts and commanders a clear operational view. |
| AI-provider boundary with grounding | Allows analyst-facing explanation without fabricating evidence. |
| Provider factory (`AI_PROVIDER`) | Explicit, single provider per analysis; no silent multi-provider calls. |

## IBM Technologies

### IBM Granite

IBM Granite is IBM's open-source foundation model family. The `GraniteProvider` (`src/intelligence/ai/granite_provider.py`) runs a Granite model locally through Ollama using its OpenAI-compatible API. This does NOT require watsonx.ai or any IBM cloud credentials. The model weight and inference remain fully under the operator's control.

**How it works:** When `AI_PROVIDER=granite` and `GRANITE_ENABLED=true`, the backend sends the bounded deterministic `AIContext` to a local Ollama instance, parses the response into `AIReasoningOutput`, and validates every reference and numeric claim against the established intelligence before accepting the output.

**Supported models (local Ollama):**
- `granite3-moe:3b` — IBM Granite 3 MoE 3B (compact, fast)
- `granite3.3:8b` — IBM Granite 3.3 8B Instruct (full capability)

### IBM Bob

IBM Bob was used throughout the development lifecycle of this project. See [`docs/ibm-bob-contribution.md`](ibm-bob-contribution.md) for details.

## Groq Runtime Inference

The `GroqProvider` (`src/intelligence/ai/groq_provider.py`) calls the Groq cloud API for fast LLM inference. Groq is used as the practical cloud runtime; IBM Granite is the IBM model technology available through the optional local provider.

**Default model:** `llama-3.1-8b-instant` (fast, JSON-capable, free tier available)

**Grounding:** The same `validate_ai_output()` grounding validator applies to both Groq and Granite outputs. Neither provider can invent security facts.

## Deterministic Safety Net

The application always works without any AI provider. When `AI_PROVIDER` is unset or `deterministic`, or when any provider fails, the deterministic BLUF is used. All structured security facts (severity, risk score, confidence, MITRE techniques, evidence, recommended actions) are always produced by the deterministic engine regardless of AI provider status.
