"""THE MEMBER 1 INTEGRATION CONTRACT.

Input:
    list[dict] — canonical Alert objects.

Output:
    list[dict] — canonical Incident objects.

Member 2 owns this adapter/boundary.
Member 1 owns everything inside src/intelligence/.
This file must be updated only to match Member 1's actual function
signature — never to reimplement their logic here.

AI provider integration
-----------------------
The adapter calls the provider factory (intelligence.ai.factory.get_provider)
to obtain the configured AI reasoning provider, then passes it to the
intelligence engine's analyze() call.

Provider selection is controlled by AI_PROVIDER (environment variable):
  groq          → GroqProvider (requires GROQ_API_KEY)
  granite       → GraniteProvider via Ollama (requires GRANITE_ENABLED=true)
  deterministic → no external AI call (uses deterministic BLUF)
  (unset)       → same as "deterministic"

The AI provider is used ONLY for the optional BLUF explanation step.
All deterministic intelligence facts are authoritative and unchanged.

The application always works without any AI provider configured.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable


logger = logging.getLogger(__name__)

_REAL_ENGINE_MODULE = "intelligence.pipeline"
_REAL_ENGINE_FUNCTION_NAME = "analyze"
_SOURCE_ROOT = Path(__file__).resolve().parents[3]


def analyze_alerts(alerts: list[dict]) -> list[dict]:
    """Analyze canonical Alerts and return canonical Incidents.

    Tries the real Member 1 intelligence engine, optionally with an AI
    reasoning provider selected by AI_PROVIDER.  Falls back to a
    clearly-labelled deterministic mock when the engine is unavailable
    or INTELLIGENCE_MODE=mock is set.
    """

    if os.getenv("INTELLIGENCE_MODE", "").strip().lower() == "mock":
        logger.warning("Using MOCK intelligence adapter — real engine not available")
        return _mock_analyze_alerts(alerts)

    real_engine = _load_real_engine()
    if real_engine is None:
        logger.warning("Using MOCK intelligence adapter — real engine not available")
        return _mock_analyze_alerts(alerts)

    provider = _load_ai_provider()
    if provider is not None:
        ai_name = type(provider).__name__
        logger.info("AI provider active: %s — AI-augmented BLUF enabled", ai_name)
    else:
        logger.debug("No AI provider configured — deterministic BLUF will be used")

    prepared_alerts = [_prepare_alert_for_engine(alert) for alert in alerts]
    analysis = real_engine(prepared_alerts, provider=provider)
    return list(analysis.to_public_incidents())


def _load_real_engine() -> Callable[[list[dict]], list[dict]] | None:
    """Load Member 1's real intelligence engine if it is importable."""

    configured_module = os.getenv("INTELLIGENCE_ENGINE_MODULE", _REAL_ENGINE_MODULE)
    if str(_SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(_SOURCE_ROOT))

    try:
        module = importlib.import_module(configured_module)
    except ImportError:
        return None

    engine_function = getattr(module, _REAL_ENGINE_FUNCTION_NAME, None)
    if callable(engine_function):
        return engine_function

    return None


def _load_ai_provider() -> Any | None:
    """Return the configured AI provider from the factory, or None.

    Imports the factory module lazily so that missing intelligence modules
    or import errors never prevent the application from starting.

    Security: no credentials are logged.
    """
    if str(_SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(_SOURCE_ROOT))

    try:
        from intelligence.ai.factory import get_provider
    except ImportError:
        logger.debug("AI factory not importable — using deterministic BLUF")
        return None

    try:
        return get_provider()
    except Exception as exc:
        logger.warning(
            "AI provider factory failed: %s — using deterministic BLUF",
            type(exc).__name__,
        )
        return None


def _prepare_alert_for_engine(alert: dict[str, Any]) -> dict[str, Any]:
    """Adapt one stored Alert to Member 1's engine input contract."""

    prepared = dict(alert)
    prepared["timestamp"] = _iso_timestamp(prepared["timestamp"])

    for field in ("source_ip", "destination_ip", "host", "user"):
        if prepared.get(field) is None:
            prepared[field] = ""

    if prepared.get("severity") == "informational":
        prepared["severity"] = "low"

    return prepared


def _iso_timestamp(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _mock_analyze_alerts(alerts: list[dict]) -> list[dict]:
    """Deterministically group Alerts by host as a clearly-labeled mock."""

    grouped_alerts: dict[str, list[dict[str, Any]]] = {}
    for alert in alerts:
        host = alert.get("host") or "UNKNOWN"
        grouped_alerts.setdefault(host, []).append(alert)

    incidents: list[dict[str, Any]] = []
    for index, (host, host_alerts) in enumerate(sorted(grouped_alerts.items()), start=1):
        sources: list[str] = []
        for alert in host_alerts:
            source = alert.get("source")
            if source and source not in sources:
                sources.append(source)

        incidents.append(
            {
                "id": f"INC-MOCK-{index:03d}",
                "severity": "high",
                "confidence": 50,
                "status": "investigating",
                "affected_assets": [host],
                "alert_count": len(host_alerts),
                "sources": sources,
                "mitre_techniques": [],
                "evidence": [alert.get("id", "") for alert in host_alerts],
                "bluf": f"[MOCK] Multiple alerts correlated on {host}.",
                "recommended_actions": [
                    f"[MOCK] Review correlated alerts on {host}."
                ],
            }
        )

    return incidents
