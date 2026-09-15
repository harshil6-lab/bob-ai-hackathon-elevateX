# Intelligence Integration Contract

This document describes the backend boundary to Member 1's intelligence engine.
It is backend-specific and does not modify or override any shared top-level documentation.

## Function Signature

The backend calls exactly one function:

```python
def analyze_alerts(alerts: list[dict]) -> list[dict]
```

- `alerts` is a list of canonical `Alert` dictionaries.
- The return value is a list of canonical `Incident` dictionaries.
- Member 1 owns all correlation, scoring, evidence extraction, and MITRE ATT&CK mapping logic inside `src/intelligence/`.
- Member 2 owns only this adapter boundary in `src/backend/app/services/intelligence_adapter.py`.

## Input Example

```json
[
  {
    "id": "ALT-1001",
    "timestamp": "2026-09-14T10:32:00Z",
    "source": "SIEM",
    "event_type": "PowerShell",
    "severity": "high",
    "source_ip": "10.10.1.20",
    "destination_ip": "10.10.5.17",
    "host": "SERVER-17",
    "user": "admin",
    "description": "Suspicious PowerShell execution"
  }
]
```

## Output Example

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
    "mitre_techniques": ["T1059.001"],
    "evidence": [
      {
        "alert_id": "ALT-1001",
        "host": "SERVER-17",
        "description": "Suspicious PowerShell execution"
      }
    ],
    "bluf": "Critical multi-stage activity affected SERVER-17.",
    "recommended_actions": [
      "Isolate SERVER-17",
      "Review lateral movement to SERVER-12"
    ]
  }
]
```

## Mode Switching

The backend supports two modes:

### Real Mode

By default, the adapter attempts to import Member 1's engine from:

- `src.intelligence.engine`
- `intelligence.engine`

If Member 1 uses a different module path, set:

```text
INTELLIGENCE_ENGINE_MODULE=<actual_module_path>
```

The engine must expose:

```python
analyze_alerts(alerts: list[dict]) -> list[dict]
```

### Mock Mode

Set:

```text
INTELLIGENCE_MODE=mock
```

This forces the adapter to use a deterministic, clearly-labeled mock that groups alerts by host.
The mock never pretends to be the real intelligence engine.

## Failure Handling

Member 1's module should raise clear exceptions on failure rather than returning malformed data.
The backend catches exceptions at this boundary and returns HTTP `503` to the API caller.
This keeps the API contract predictable and prevents invalid incident data from reaching the frontend.
