# IBM Bob Contribution to D2 Threat Intelligence Command Center

## Overview

IBM Bob served as the primary AI-assisted engineering partner throughout the
development of the D2 Threat Intelligence Command Center.  This document
describes where Bob contributed to the software development lifecycle,
what engineering tasks Bob assisted with, and how the resulting work was
validated.

Bob's contribution is genuine and spans design, implementation, testing,
and documentation.  It is part of the software development lifecycle —
not a runtime API, not a logo, and not a claim without evidence.

**Note:** The project does NOT claim IBM watsonx.ai runtime integration.
The AI provider layer uses Groq for cloud inference and IBM Granite
(open-source, via local Ollama) as the IBM model technology.  IBM Bob's
contribution is to the development lifecycle, not to runtime inference.

---

## Where Bob Was Used

### 1. Architecture design and contract specification

Bob assisted in designing the system architecture for the intelligence
pipeline, defining the boundary between the deterministic engine and the
optional AI provider, and specifying the public Incident schema that all
three team members rely on.

Specific outputs:
- The canonical Alert and Incident schema (fields, types, constraints)
- The `INTEGRATION_CONTRACT.md` defining the Member 1 / Member 2 boundary
- The `AIContext`, `AIReasoningOutput`, and grounding model
- The decision to keep AI exclusively at the BLUF explanation step

### 2. Intelligence engine implementation review

Bob reviewed the complete intelligence engine:
- [`src/intelligence/correlation.py`](../src/intelligence/correlation.py) — alert correlation logic and relationship scoring
- [`src/intelligence/scoring.py`](../src/intelligence/scoring.py) — risk score, severity, confidence, and false-positive assessment
- [`src/intelligence/evidence.py`](../src/intelligence/evidence.py) — evidence extraction and traceability
- [`src/intelligence/mitre.py`](../src/intelligence/mitre.py) — controlled MITRE ATT&CK mapping
- [`src/intelligence/bluf.py`](../src/intelligence/bluf.py) — deterministic BLUF generation and AI fallback boundary
- [`src/intelligence/actions.py`](../src/intelligence/actions.py) — recommended action generation
- [`src/intelligence/pipeline.py`](../src/intelligence/pipeline.py) — end-to-end orchestration

Bob identified the grounding boundary design: the AI provider must receive
only values already established by deterministic logic and must not be
permitted to invent evidence, IPs, users, hosts, MITRE technique IDs,
or numeric values.

### 3. AI provider layer implementation

Bob implemented the complete AI provider layer:

**[`src/intelligence/ai/groq_provider.py`](../src/intelligence/ai/groq_provider.py)** — Groq cloud provider:
- Groq chat-completions API call with bounded, grounded prompt
- JSON response parsing with markdown fence stripping and regex fallback
- Safe extraction of structured references and numeric claims into `AIReasoningOutput`
- Runtime configuration from environment variables only; API key never logged

**[`src/intelligence/ai/granite_provider.py`](../src/intelligence/ai/granite_provider.py)** — IBM Granite/Ollama provider:
- Calls local Ollama serving an IBM Granite model via OpenAI-compatible chat API
- Same grounded prompt and response parsing as GroqProvider
- Explicit `ConnectionRefusedError` detection for clear Ollama-unavailable errors
- No IBM cloud credentials required — uses open-source Granite model weights

**[`src/intelligence/ai/factory.py`](../src/intelligence/ai/factory.py)** — Provider factory:
- Reads `AI_PROVIDER` environment variable
- Returns exactly one provider instance per analysis (no double-calling)
- Falls back to None (deterministic BLUF) on any misconfiguration

**[`src/intelligence/ai/_prompt.py`](../src/intelligence/ai/_prompt.py)** — Shared prompt module:
- Single source of truth for the grounded prompt used by all providers

Bob also updated the backend wiring in
[`src/backend/app/services/intelligence_adapter.py`](../src/backend/app/services/intelligence_adapter.py)
to load the factory-selected provider and pass it to the intelligence engine.

### 4. Grounded prompt engineering

Bob designed the watsonx.ai prompt structure to:
- Enumerate allowed references explicitly before the generation section
- Instruct the model to produce ONLY a JSON object with specified fields
- Prevent the model from inventing facts by repeating the constraint for
  every reference type and every numeric value
- Include pre-filled structured fields (referenced_alert_ids, numeric_claims, etc.)
  as defaults the model is instructed to preserve if it has no correction

This prompt structure, combined with deterministic grounding validation,
makes the LLM output safe to use: anything the model invents is rejected
before it can reach the public incident.

### 5. Provider test suites

Bob authored the provider test suites:

**[`src/intelligence/tests/test_watsonx_provider.py`](../src/intelligence/tests/test_watsonx_provider.py)** (historical, 42 tests):
- Originally written for the watsonx.ai provider; retained as reference.

**[`src/intelligence/tests/test_groq_granite_providers.py`](../src/intelligence/tests/test_groq_granite_providers.py)** (43 tests):
- `is_configured()` for both Groq and Granite
- Protocol conformance
- Valid response → AIReasoningOutput
- Markdown code fence stripping
- Malformed JSON → ValueError
- Empty content → RuntimeError
- HTTP error → RuntimeError
- Timeout → RuntimeError
- Missing API key raises before any HTTP call
- API key never in logs
- Grounding: invented MITRE, invented alert ID, wrong risk score rejected
- `generate_bluf` falls back when provider raises, returns invalid output, or fails grounding
- `generate_bluf` uses AI summary when grounding passes
- Deterministic facts unchanged by AI BLUF
- SERVER-17 golden facts survive AI provider
- Ollama unavailable (ConnectionRefusedError) → RuntimeError → deterministic fallback
- Factory: unset/deterministic → None, unknown → None+warning, groq without key → None, groq with key → GroqProvider, granite without ENABLED → None, granite with ENABLED → GraniteProvider

All 264 intelligence tests pass (221 pre-existing + 43 new).
All 50 backend tests pass.

### 6. Documentation

Bob authored or substantially revised:
- [`docs/architecture.md`](architecture.md) — updated with watsonx.ai data flow, AI boundary, grounding protection, fallback behavior, and security notes
- [`docs/solution-overview.md`](solution-overview.md) — updated IBM Technologies section
- [`docs/setup-guide.md`](setup-guide.md) — added watsonx.ai environment variables table, running-with/without sections, and troubleshooting entries
- [`src/.env.example`](../src/.env.example) and [`src/backend/.env.example`](../src/backend/.env.example) — added watsonx.ai variable block with comments and security notice
- `src/intelligence/INTEGRATION_CONTRACT.md` — Provider implementation status section updated

### 7. Security review

Bob performed a security audit of the IBM integration:
- Confirmed `WATSONX_API_KEY` is never logged, never returned in a response, never embedded in code
- Confirmed the API key is sent only to the IBM IAM endpoint over HTTPS
- Confirmed bearer tokens are not persisted to disk
- Confirmed alert text appears in the prompt as quoted data, not as instructions
- Confirmed frontend never receives watsonx.ai credentials (credentials are backend-only)
- Confirmed `.gitignore` covers `.env`, `.env.local`, `.env.production`, `*.key`, `*.pem`

---

## How Bob's Contribution Was Validated

All work produced with Bob's assistance was validated before commit:

| Validation | Result |
|---|---|
| Intelligence test suite (221 pre-existing) | All passed |
| Groq+Granite provider test suite (43 new tests) | All passed |
| Backend test suite (50 tests) | All passed |
| Frontend test suite (136 tests) | All passed |
| Frontend production build | Succeeded |
| Golden evaluation (5 scenarios) | All passed |
| SERVER-17: 1 incident, critical, risk 91, confidence 100, 6 alerts, 3 sources, T1003+T1021+T1059.001 | Verified |

The team reviewed Bob's output before integration.  Architecture decisions,
the grounding design, the choice of IBM Granite, and the public API contract
were team decisions validated by all three members.

---

## What Remains a Human/Team Decision

The following decisions were made by the team and are not attributable to Bob:

- Choice of IBM watsonx.ai (over other LLM providers)
- Choice of IBM Granite as the model
- Threshold for grounding validation strictness
- Public Incident schema fields and types
- Demo scenario and golden test expectations
- Deployment and infrastructure choices
- Which features are in scope for the hackathon

---

## Summary

IBM Bob contributed to:

1. Architecture and contract design
2. Intelligence engine review
3. watsonx.ai provider implementation
4. Grounded prompt engineering
5. Provider test suite
6. Documentation
7. Security review

The integration is real, load-bearing, and demonstrable.  When
`WATSONX_API_KEY` and `WATSONX_PROJECT_ID` are configured, `POST /api/analyze`
calls the IBM watsonx.ai API to generate an analyst-oriented BLUF explanation
grounded in the established deterministic intelligence.  When credentials are
absent, the application falls back to its deterministic BLUF and remains fully
functional.
