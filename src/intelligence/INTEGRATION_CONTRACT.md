# Intelligence Engine Integration Contract

This document defines the integration boundary between Member 1's intelligence
engine and Member 2's backend/data layer. It is an audit of the completed
implementation; it does not change any runtime behavior or public schema.

## 1. Ownership and scope

The intelligence engine is owned by Member 1 and lives under
`src/intelligence/`. It owns canonical alert validation, deterministic
correlation and incident grouping, threat scoring, confidence, false-positive
assessment, evidence extraction, controlled MITRE ATT&CK mapping, the AI
grounding boundary, BLUF generation, recommended actions, end-to-end
orchestration, and deterministic golden-scenario evaluation.

The backend must not duplicate these responsibilities. Its role is to validate
the external request, convert request data to canonical alert mappings, invoke
the intelligence engine, and expose the resulting public incident contract.

## 2. Single entry point

The backend-facing entry point is:

```python
analyze(alerts, provider=None)
```

It is defined in `src/intelligence/pipeline.py`.

### Input

`alerts` is an `Iterable[Mapping[str, Any]]`. The backend should pass decoded
JSON objects or equivalent mappings, not JSON strings. Every mapping must use
the canonical alert field names:

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `id` | Yes | non-empty string | Must be unique within the request. |
| `timestamp` | Yes | string | Parseable ISO-8601 timestamp; a trailing `Z` is supported. |
| `source` | Yes | non-empty string | Alert producer, such as `SIEM`. |
| `event_type` | Yes | non-empty string | Unknown values are safe downstream. |
| `severity` | Yes | string | Exactly `low`, `medium`, `high`, or `critical`; `info` is rejected. |
| `source_ip` | Key required | string | Empty string means unavailable; non-empty values must be valid IPs. |
| `destination_ip` | Key required | string | Empty string means unavailable; non-empty values must be valid IPs. |
| `host` | Key required | string | Empty string means unavailable. |
| `user` | Key required | string | Empty string means unavailable. |
| `description` | Yes | non-empty string | Treated as untrusted data, never as code or instructions. |

`provider` is optional and must implement `AIReasoningProvider` when supplied.
The normal backend integration should omit it and use the deterministic BLUF.

### Validation behavior

`analyze` validates the complete batch before correlation. It rejects missing
canonical fields, non-string values, empty required text fields, unsupported
severity values, unparseable timestamps, invalid non-empty IP addresses,
control characters in text fields, and duplicate alert IDs.

Validation failures raise `AlertValidationError`, a subclass of `ValueError`.
The exception exposes a tuple of caller-safe messages through `errors`. The
pipeline does not catch or hide validation failures.

The input mappings are not mutated. Alert descriptions and other text are used
as data only.

### Output

`analyze` returns an immutable `IntelligenceAnalysis`:

```python
IntelligenceAnalysis(incidents: tuple[IntelligenceIncident, ...])
```

Each `IntelligenceIncident` contains internal artifacts:

- `record`: the internal `IncidentRecord`,
- `assessment`: the deterministic `ThreatAssessment`,
- `evidence`: the `EvidenceCollection`,
- `mitre`: the controlled `MitreMappingResult`,
- `bluf`: the structured internal `Bluf`,
- `actions`: the `RecommendedActionCollection`.

Backend/API serialization must use:

```python
analysis.to_public_incidents()
```

This returns a tuple of dictionaries containing only the frozen public
incident fields. A JSON response should normally convert that tuple to a list.

### Empty and invalid input

- `analyze([])` returns `IntelligenceAnalysis(incidents=())`. No incident or
  identifier is invented.
- Invalid input raises `AlertValidationError` before analysis begins.
- Other unexpected implementation exceptions are not swallowed.

### Multiple incidents

Correlation can produce zero, one, or many groups. Each group becomes one
`IntelligenceIncident`. Groups are processed independently so evidence, MITRE
mappings, BLUF findings, and actions cannot leak between incidents.

Incidents are deterministically ordered by `(started_at, first alert ID,
group ID)`.

### Determinism

With the same alert set and the same optional deterministic provider,
`analyze` produces the same incident IDs and ordering, correlated alert IDs,
risk score, severity, confidence, false-positive assessment, evidence, MITRE
mappings, BLUF, recommendations, and public incident dictionaries.

Alert input order does not change the assessment. Group IDs are derived from
the sorted alert membership. The implementation uses no randomness, current
time, network calls, database state, subprocess execution, or LLM calls.

With no provider, the complete result is deterministic. If an external provider
is eventually supplied, provider availability and response quality are outside
the deterministic engine; the grounding and fallback rules below still apply.

### Optional AI provider and fallback

`provider` is passed only to the existing BLUF boundary. If it is `None`, the
deterministic BLUF is used.

If a supplied provider raises an exception, returns a non-conforming structure,
or returns output that fails grounding validation, `generate_bluf` falls back
to the deterministic BLUF. AI failure does not change correlation, scoring,
evidence, MITRE mappings, confidence, or recommended actions.

## 3. Public Incident contract

`IntelligenceAnalysis.to_public_incidents()` emits one dictionary per incident.
The frozen fields and types are:

| Public field | Internal source | Type | Meaning | Deterministic | API safe |
| --- | --- | --- | --- | --- | --- |
| `id` | `CorrelatedAlertGroup.group_id` copied to `IncidentRecord.id` | string | Stable incident identifier derived from correlated alert membership. | Yes | Yes |
| `severity` | `ThreatAssessment.severity` | `low`, `medium`, `high`, or `critical` | Observed activity priority derived from the risk score. | Yes | Yes |
| `confidence` | `ThreatAssessment.confidence` | integer `0`-`100` | Confidence in the assessment and its corroboration; not the risk score. | Yes | Yes |
| `status` | Set by the pipeline | `investigating` | Initial intelligence lifecycle state. Backend workflow may manage later transitions. | Yes | Yes |
| `affected_assets` | `ThreatAssessment.affected_assets` | list of strings | Non-empty hosts observed in the group's actual alerts. | Yes | Yes |
| `alert_count` | `ThreatAssessment.alert_count` | integer | Number of alerts in the correlated group. | Yes | Yes |
| `sources` | `ThreatAssessment.sources` | sorted list of strings | Distinct alert sources in the group. | Yes | Yes |
| `mitre_techniques` | `MitreMappingResult.technique_ids` | sorted list of strings | Controlled ATT&CK technique IDs supported by supplied evidence. | Yes | Yes |
| `evidence` | `EvidenceCollection.evidence_ids` | list of strings | Stable evidence IDs only; nested evidence records remain internal. | Yes | Yes |
| `bluf` | `Bluf.summary` | string | Concise analyst-facing bottom-line assessment. | Deterministic without provider; validated AI may replace only grounded explanation | Yes |
| `recommended_actions` | `RecommendedActionCollection.to_public_recommended_actions()` | list of strings | Analyst recommendations; never claims an action has already been performed. | Yes | Yes |

The following established values are internal and are **not** public fields:

- risk score,
- false-positive assessment and reasons,
- correlated alert IDs,
- scoring factors and reasons,
- rich evidence records,
- MITRE names, tactics, and mapping confidence,
- structured BLUF findings and reasoning,
- action IDs, priorities, categories, and rationales.

These internal artifacts exist on `IntelligenceIncident` for in-process
traceability and future approved extensions. They must not be added to the
public contract without shared-contract approval.

## 4. Traceability model

The complete internal trace chain is:

```text
IntelligenceIncident
    -> IncidentRecord.correlated_alert_ids
        -> original input alert IDs
    -> EvidenceCollection.evidence_ids
        -> Evidence records
            -> Evidence.alert_id
                -> original input alert
    -> MitreMappingResult.mappings
        -> MitreMapping.technique_id
        -> MitreMapping.evidence_ids
            -> evidence records and original alerts
    -> RecommendedActionCollection.actions
        -> RecommendedAction.alert_ids
        -> RecommendedAction.evidence_ids
        -> optional RecommendedAction.mitre_technique_ids
```

### Public references

The public incident directly exposes:

- incident `id`,
- `evidence` evidence IDs,
- `mitre_techniques` technique IDs,
- `recommended_actions` recommendation strings.

### Internal-only references

The public incident does not directly expose:

- correlated alert IDs,
- evidence records, alert IDs, descriptions, or rationale,
- MITRE names, tactics, mapping confidence, or evidence links,
- action IDs, priorities, categories, rationales, or evidence links.

The backend can retain the `IntelligenceAnalysis` in the same request scope if
it needs to perform approved internal traceability. It must not expose these
internal structures through the frozen `/api/incidents` response without an
explicit shared-contract change.

## 5. AI boundary

### Where AI enters

AI is used only at the optional BLUF explanation step:

```text
deterministic intelligence
    -> AIContext
    -> optional AIReasoningProvider.generate_reasoning(context)
    -> grounding validation
    -> BLUF
```

Correlation, scoring, confidence, false-positive assessment, evidence, MITRE
mapping, and recommended actions are generated deterministically before any
provider is called.

### What AI receives

The provider receives a bounded, deterministic `AIContext` containing only
values already established by the intelligence engine, including:

- incident ID,
- alert IDs and canonical alert fields,
- correlation relationships and reasons,
- scoring factors, risk, severity, confidence, and false-positive assessment,
- evidence IDs, descriptions, and rationale,
- MITRE technique IDs, names, tactics, and mapping confidence,
- affected assets, source count, and alert count.

### What AI cannot do

AI cannot:

- change correlation or incident grouping,
- recalculate risk, severity, or confidence,
- create evidence,
- create alert IDs, hosts, users, or IP addresses,
- add MITRE technique IDs,
- alter deterministic recommended actions,
- claim that an action has already been performed,
- bypass grounding validation.

Grounding validation checks structured references against the supplied context
and validates supported numeric claims. It does not attempt to prove arbitrary
natural language using another model.

### Provider implementation status

There is **no actual watsonx.ai network provider in this codebase yet**. The
current code provides only the replaceable `AIReasoningProvider` protocol.
There are no credentials, API keys, `.env` files, external HTTP calls, or fake
provider responses.

No IBM Bob runtime integration is implemented or claimed by this intelligence
layer.

## 6. SERVER-17 verified golden result

The independently declared golden evaluation scenario and the full pipeline
test suite verify the SERVER-17-style multi-source attack chain:

- incidents: `1`
- severity: `critical`
- risk score: `91`
- confidence: `100`
- alert count: `6`
- source count: `3`
- MITRE techniques:
  - `T1003` - OS Credential Dumping,
  - `T1021` - Remote Services,
  - `T1059.001` - PowerShell.
- evidence: non-empty and traceable to the six actual alerts,
- BLUF: generated,
- recommended actions: generated, including threat investigation, credential
  access, remote services, PowerShell execution, and source-corroboration
  actions.

Scoring runs before MITRE mapping, so adding the controlled technique mappings
does not change the established SERVER-17 risk score of `91`.

## 7. Backend integration guidance

The minimal backend flow for `POST /api/analyze` is:

```text
POST /api/analyze
    -> validate the backend request envelope
    -> convert request alerts to canonical alert mappings
    -> intelligence.analyze(alerts)
    -> analysis.to_public_incidents()
    -> serialize the public incident dictionaries as JSON
```

Member 2 should:

1. Keep request-envelope validation in the backend.
2. Use the exact canonical alert field names.
3. Map invalid request data to the backend's existing error response behavior;
   do not silently repair malformed intelligence input.
4. Pass `provider=None` unless a real, approved provider adapter is implemented.
5. Use `to_public_incidents()` rather than manually assembling incidents.
6. Preserve the frozen public field names and types.
7. Avoid re-implementing correlation, scoring, evidence, MITRE, grounding,
   BLUF, or action logic.

## 8. Frontend integration guidance

Member 3 can safely consume the frozen public fields:

- `id`,
- `severity`,
- `confidence`,
- `status`,
- `affected_assets`,
- `alert_count`,
- `sources`,
- `mitre_techniques`,
- `evidence`,
- `bluf`,
- `recommended_actions`.

The frontend should treat `evidence` as a list of IDs and `bluf` as the primary
human-readable assessment. It must not depend on internal evidence, MITRE, or
action structures. Any richer investigator view requires an explicit approved
shared-contract extension.

## 9. Verification

The integration audit does not change executable code. The full intelligence
suite is the regression gate:

```powershell
python -m unittest discover -s src/intelligence -p test_*.py -v
```

Current verified result: **179 tests passed, 0 failed**.
