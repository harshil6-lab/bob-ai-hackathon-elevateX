"""Unit tests for GroqProvider, GraniteProvider, and the provider factory.

All network calls are mocked.  No real Groq API key or Ollama instance is
required.  Tests verify every failure path documented in the task spec.

Coverage:
  GroqProvider:
    - valid response → AIReasoningOutput
    - valid response passes grounding validation
    - malformed JSON response → ValueError
    - empty content → RuntimeError
    - HTTP error → RuntimeError
    - timeout/network failure → RuntimeError
    - missing API key → RuntimeError before any HTTP call
    - API key not logged
    - markdown code fence stripping
    - invalid AIReasoningOutput (bad reference) → grounding rejects it
    - generate_bluf falls back on raise
    - generate_bluf falls back on grounding failure
    - generate_bluf uses AI summary when grounding passes
    - deterministic facts unchanged by AI BLUF
    - SERVER-17 golden facts survive AI provider

  GraniteProvider:
    - valid response → AIReasoningOutput
    - Ollama unavailable (ConnectionRefusedError) → RuntimeError
    - malformed response → ValueError
    - grounding failure → deterministic fallback via generate_bluf
    - generate_bluf fallback on any raise

  Factory (get_provider):
    - AI_PROVIDER unset → None
    - AI_PROVIDER=deterministic → None
    - AI_PROVIDER=groq without GROQ_API_KEY → None (warning)
    - AI_PROVIDER=groq with GROQ_API_KEY → GroqProvider instance
    - AI_PROVIDER=granite without GRANITE_ENABLED → None (warning)
    - AI_PROVIDER=granite with GRANITE_ENABLED=true → GraniteProvider
    - AI_PROVIDER=unknown → None (warning)
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

_SOURCE_ROOT = Path(__file__).resolve().parents[4]
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from src.intelligence.ai.context import build_ai_context
from src.intelligence.ai.grounding import (
    AINumericClaim,
    AIReasoningOutput,
    validate_ai_output,
)
from src.intelligence.ai.groq_provider import GroqProvider, is_configured as groq_is_configured
from src.intelligence.ai.granite_provider import GraniteProvider, is_configured as granite_is_configured
from src.intelligence.ai.factory import get_provider
from src.intelligence.ai.provider import AIReasoningProvider
from src.intelligence.bluf import generate_bluf
from src.intelligence.correlation import correlate_alerts
from src.intelligence.evidence import extract_evidence
from src.intelligence.mitre import map_mitre_behaviors
from src.intelligence.scoring import assess_threat


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _ts(minutes: int = 0) -> str:
    base = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)
    return (base + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def _golden_alerts() -> list[dict]:
    return [
        {"id": "ALT-1001", "timestamp": _ts(0), "source": "SIEM",
         "event_type": "ExternalActivity", "severity": "medium",
         "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
         "host": "SERVER-17", "user": "admin",
         "description": "Suspicious external activity detected"},
        {"id": "ALT-1002", "timestamp": _ts(5), "source": "NETWORK_SENSOR",
         "event_type": "PowerShell", "severity": "high",
         "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
         "host": "SERVER-17", "user": "admin",
         "description": "Suspicious PowerShell execution"},
        {"id": "ALT-1003", "timestamp": _ts(10), "source": "SIEM",
         "event_type": "SuspiciousProcess", "severity": "high",
         "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
         "host": "SERVER-17", "user": "admin",
         "description": "Suspicious process launched from PowerShell"},
        {"id": "ALT-1004", "timestamp": _ts(15), "source": "THREAT_INTEL",
         "event_type": "CredentialAccess", "severity": "critical",
         "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
         "host": "SERVER-17", "user": "admin",
         "description": "Credential dumping detected"},
        {"id": "ALT-1005", "timestamp": _ts(20), "source": "NETWORK_SENSOR",
         "event_type": "RemoteConnection", "severity": "high",
         "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
         "host": "SERVER-17", "user": "admin",
         "description": "Remote desktop connection established"},
        {"id": "ALT-1006", "timestamp": _ts(25), "source": "SIEM",
         "event_type": "LateralMovement", "severity": "critical",
         "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
         "host": "SERVER-17", "user": "admin",
         "description": "Lateral movement observed"},
    ]


def _build_context():
    alerts = _golden_alerts()
    groups = correlate_alerts(alerts)
    group = groups[0]
    evidence = extract_evidence(group)
    mitre = map_mitre_behaviors(group.alerts, evidence)
    assessment = assess_threat(group, mitre_mappings=mitre.mappings)
    return build_ai_context(group, assessment, evidence, mitre)


def _valid_response_data(context) -> dict:
    """Build a valid AI response dict for the given context."""
    return {
        "incident_id": context.incident_id,
        "summary": "Critical threat confirmed on SERVER-17 with credential dumping and lateral movement.",
        "reasoning": "Six correlated alerts from three independent sources confirm a multi-stage attack.",
        "referenced_alert_ids": list(context.alert_ids),
        "referenced_evidence_ids": list(context.evidence_ids),
        "referenced_mitre_technique_ids": list(context.mitre_technique_ids),
        "referenced_hosts": sorted({a.host for a in context.alerts if a.host}),
        "referenced_users": sorted({a.user for a in context.alerts if a.user}),
        "referenced_source_ips": sorted({a.source_ip for a in context.alerts if a.source_ip}),
        "referenced_destination_ips": sorted({a.destination_ip for a in context.alerts if a.destination_ip}),
        "referenced_assets": list(context.scoring.affected_assets),
        "numeric_claims": [
            {"name": "alert_count", "value": context.scoring.alert_count},
            {"name": "source_count", "value": context.scoring.source_count},
            {"name": "risk_score", "value": context.scoring.risk_score},
            {"name": "confidence", "value": context.scoring.confidence},
            {"name": "evidence_count", "value": len(context.evidence_ids)},
            {"name": "mitre_technique_count", "value": len(context.mitre_technique_ids)},
        ],
    }


class _FakeHTTPResponse:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _chat_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def _mock_urlopen(response_data: dict):
    raw = _FakeHTTPResponse(json.dumps(response_data).encode())

    def fake(req, timeout=None):
        return raw

    return patch("urllib.request.urlopen", side_effect=fake)


# ---------------------------------------------------------------------------
# GroqProvider tests
# ---------------------------------------------------------------------------


class GroqIsConfiguredTests(unittest.TestCase):
    def test_false_when_key_absent(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GROQ_API_KEY", None)
            self.assertFalse(groq_is_configured())

    def test_false_when_key_whitespace(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "  "}, clear=False):
            self.assertFalse(groq_is_configured())

    def test_true_when_key_set(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}, clear=False):
            self.assertTrue(groq_is_configured())


class GroqProviderProtocolTests(unittest.TestCase):
    def test_satisfies_aireasoning_provider_protocol(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "k"}, clear=False):
            provider = GroqProvider()
        self.assertIsInstance(provider, AIReasoningProvider)


class GroqProviderNetworkTests(unittest.TestCase):
    def _provider(self) -> GroqProvider:
        with patch.dict(os.environ,
                        {"GROQ_API_KEY": "gsk_test", "GROQ_MODEL_ID": "llama-3.1-8b-instant"},
                        clear=False):
            return GroqProvider()

    def test_valid_response_returns_aireasoning_output(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        with _mock_urlopen(_chat_response(json.dumps(data))):
            output = provider.generate_reasoning(ctx)
        self.assertIsInstance(output, AIReasoningOutput)
        self.assertEqual(output.incident_id, ctx.incident_id)
        self.assertGreater(len(output.summary), 0)

    def test_valid_response_passes_grounding(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        with _mock_urlopen(_chat_response(json.dumps(data))):
            output = provider.generate_reasoning(ctx)
        result = validate_ai_output(ctx, output)
        self.assertTrue(result.is_valid, f"Grounding issues: {result.issues}")

    def test_markdown_code_fence_stripped(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        fenced = f"```json\n{json.dumps(data)}\n```"
        with _mock_urlopen(_chat_response(fenced)):
            output = provider.generate_reasoning(ctx)
        self.assertEqual(output.incident_id, ctx.incident_id)

    def test_malformed_json_raises_value_error(self):
        ctx = _build_context()
        provider = self._provider()
        with _mock_urlopen(_chat_response("this is not json")):
            with self.assertRaises(ValueError):
                provider.generate_reasoning(ctx)

    def test_empty_content_raises_runtime_error(self):
        ctx = _build_context()
        provider = self._provider()
        with _mock_urlopen({"choices": [{"message": {"content": ""}}]}):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_no_choices_raises_runtime_error(self):
        ctx = _build_context()
        provider = self._provider()
        with _mock_urlopen({"choices": []}):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_http_error_raises_runtime_error(self):
        import urllib.error
        ctx = _build_context()
        provider = self._provider()
        http_err = urllib.error.HTTPError(url=None, code=429, msg="Rate limit", hdrs=None, fp=None)
        with patch("urllib.request.urlopen", side_effect=http_err):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_timeout_raises_runtime_error(self):
        ctx = _build_context()
        provider = self._provider()
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timeout")):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_missing_api_key_raises_before_http_call(self):
        ctx = _build_context()
        with patch.dict(os.environ, {"GROQ_API_KEY": ""}, clear=False):
            provider = GroqProvider()
        with patch("urllib.request.urlopen") as mock_url:
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)
            mock_url.assert_not_called()

    def test_api_key_not_in_logs(self):
        import logging
        ctx = _build_context()
        with patch.dict(os.environ, {"GROQ_API_KEY": "super-secret-groq-key"}, clear=False):
            provider = GroqProvider()
        log_records = []

        class Cap(logging.Handler):
            def emit(self, record):
                log_records.append(self.format(record))

        h = Cap()
        logging.getLogger().addHandler(h)
        try:
            import urllib.error
            with patch("urllib.request.urlopen",
                       side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", None, None)):
                try:
                    provider.generate_reasoning(ctx)
                except RuntimeError:
                    pass
        finally:
            logging.getLogger().removeHandler(h)

        for record in log_records:
            self.assertNotIn("super-secret-groq-key", record)


class GroqGroundingFallbackTests(unittest.TestCase):
    def _provider(self) -> GroqProvider:
        with patch.dict(os.environ, {"GROQ_API_KEY": "k"}, clear=False):
            return GroqProvider()

    def test_invented_mitre_id_rejected(self):
        from src.intelligence.ai.groq_provider import _parse_response
        ctx = _build_context()
        data = _valid_response_data(ctx)
        data["referenced_mitre_technique_ids"] = ["T9999"]
        output = _parse_response(ctx, json.dumps(data))
        self.assertFalse(validate_ai_output(ctx, output).is_valid)

    def test_invented_alert_id_rejected(self):
        from src.intelligence.ai.groq_provider import _parse_response
        ctx = _build_context()
        data = _valid_response_data(ctx)
        data["referenced_alert_ids"] = ["ALT-INVENTED"]
        output = _parse_response(ctx, json.dumps(data))
        self.assertFalse(validate_ai_output(ctx, output).is_valid)

    def test_wrong_risk_score_rejected(self):
        from src.intelligence.ai.groq_provider import _parse_response
        ctx = _build_context()
        data = _valid_response_data(ctx)
        data["numeric_claims"] = [{"name": "risk_score", "value": 0}]
        output = _parse_response(ctx, json.dumps(data))
        self.assertFalse(validate_ai_output(ctx, output).is_valid)

    def test_generate_bluf_falls_back_when_provider_raises(self):
        ctx = _build_context()
        provider = self._provider()
        with patch("urllib.request.urlopen", side_effect=RuntimeError("network down")):
            bluf = generate_bluf(ctx, provider=provider)
        self.assertEqual(bluf.generated_by, "deterministic")

    def test_generate_bluf_falls_back_when_grounding_fails(self):
        ctx = _build_context()

        class BadProvider:
            def generate_reasoning(self, context):
                return AIReasoningOutput(
                    incident_id=context.incident_id,
                    summary="Summary.",
                    reasoning="Reasoning.",
                    referenced_mitre_technique_ids=("T9999",),
                )

        bluf = generate_bluf(ctx, provider=BadProvider())
        self.assertEqual(bluf.generated_by, "deterministic")

    def test_generate_bluf_uses_ai_when_grounding_passes(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        with _mock_urlopen(_chat_response(json.dumps(data))):
            bluf = generate_bluf(ctx, provider=provider)
        self.assertEqual(bluf.generated_by, "ai")
        self.assertIn("credential", bluf.summary.lower())

    def test_deterministic_facts_unchanged_by_ai_bluf(self):
        from src.intelligence.pipeline import analyze
        alerts = _golden_alerts()
        det = analyze(alerts)
        ctx = _build_context()
        data = _valid_response_data(ctx)
        provider = self._provider()
        with _mock_urlopen(_chat_response(json.dumps(data))):
            ai_result = analyze(alerts, provider=provider)
        det_rec = det.incidents[0].record
        ai_rec = ai_result.incidents[0].record
        self.assertEqual(det_rec.risk_score, ai_rec.risk_score)
        self.assertEqual(det_rec.confidence, ai_rec.confidence)
        self.assertEqual(det_rec.severity, ai_rec.severity)
        self.assertEqual(det_rec.alert_count, ai_rec.alert_count)
        self.assertEqual(sorted(det_rec.sources), sorted(ai_rec.sources))
        self.assertEqual(sorted(det_rec.mitre_techniques), sorted(ai_rec.mitre_techniques))

    def test_server17_golden_facts_survive_groq_provider(self):
        from src.intelligence.pipeline import analyze
        alerts = _golden_alerts()
        ctx = _build_context()
        data = _valid_response_data(ctx)
        provider = self._provider()
        with _mock_urlopen(_chat_response(json.dumps(data))):
            result = analyze(alerts, provider=provider)
        self.assertEqual(len(result.incidents), 1)
        inc = result.incidents[0].record
        self.assertEqual(inc.severity, "critical")
        self.assertEqual(inc.risk_score, 91)
        self.assertEqual(inc.confidence, 100)
        self.assertEqual(inc.alert_count, 6)
        self.assertEqual(len(inc.sources), 3)
        self.assertIn("T1003", inc.mitre_techniques)
        self.assertIn("T1021", inc.mitre_techniques)
        self.assertIn("T1059.001", inc.mitre_techniques)


# ---------------------------------------------------------------------------
# GraniteProvider tests
# ---------------------------------------------------------------------------


class GraniteIsConfiguredTests(unittest.TestCase):
    def test_false_when_enabled_absent(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GRANITE_ENABLED", None)
            self.assertFalse(granite_is_configured())

    def test_false_when_enabled_false(self):
        with patch.dict(os.environ, {"GRANITE_ENABLED": "false"}, clear=False):
            self.assertFalse(granite_is_configured())

    def test_true_when_enabled_true(self):
        with patch.dict(os.environ, {"GRANITE_ENABLED": "true"}, clear=False):
            self.assertTrue(granite_is_configured())

    def test_case_insensitive(self):
        with patch.dict(os.environ, {"GRANITE_ENABLED": "TRUE"}, clear=False):
            self.assertTrue(granite_is_configured())


class GraniteProviderTests(unittest.TestCase):
    def _provider(self) -> GraniteProvider:
        with patch.dict(os.environ,
                        {"GRANITE_ENABLED": "true",
                         "GRANITE_BASE_URL": "http://localhost:11434/v1",
                         "GRANITE_MODEL_ID": "granite3-moe:3b"},
                        clear=False):
            return GraniteProvider()

    def test_valid_response_returns_aireasoning_output(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        with _mock_urlopen(_chat_response(json.dumps(data))):
            output = provider.generate_reasoning(ctx)
        self.assertIsInstance(output, AIReasoningOutput)
        self.assertEqual(output.incident_id, ctx.incident_id)

    def test_valid_response_passes_grounding(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        with _mock_urlopen(_chat_response(json.dumps(data))):
            output = provider.generate_reasoning(ctx)
        result = validate_ai_output(ctx, output)
        self.assertTrue(result.is_valid)

    def test_ollama_unavailable_raises_runtime_error(self):
        ctx = _build_context()
        provider = self._provider()
        with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError()):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_malformed_response_raises_value_error(self):
        ctx = _build_context()
        provider = self._provider()
        with _mock_urlopen(_chat_response("not json at all")):
            with self.assertRaises(ValueError):
                provider.generate_reasoning(ctx)

    def test_http_error_raises_runtime_error(self):
        import urllib.error
        ctx = _build_context()
        provider = self._provider()
        err = urllib.error.HTTPError(None, 404, "Not Found", None, None)
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_generate_bluf_falls_back_on_ollama_unavailable(self):
        ctx = _build_context()
        provider = self._provider()
        with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError()):
            bluf = generate_bluf(ctx, provider=provider)
        self.assertEqual(bluf.generated_by, "deterministic")

    def test_generate_bluf_falls_back_on_grounding_failure(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_response_data(ctx)
        data["referenced_mitre_technique_ids"] = ["T9999"]
        with _mock_urlopen(_chat_response(json.dumps(data))):
            bluf = generate_bluf(ctx, provider=provider)
        self.assertEqual(bluf.generated_by, "deterministic")

    def test_satisfies_aireasoning_provider_protocol(self):
        provider = self._provider()
        self.assertIsInstance(provider, AIReasoningProvider)


# ---------------------------------------------------------------------------
# Provider factory tests
# ---------------------------------------------------------------------------


class FactoryTests(unittest.TestCase):
    def _clean_env(self) -> dict:
        """Return a clean env dict without any provider keys."""
        keys_to_remove = {
            "AI_PROVIDER", "GROQ_API_KEY", "GROQ_MODEL_ID",
            "GRANITE_ENABLED", "GRANITE_BASE_URL", "GRANITE_MODEL_ID",
        }
        return {k: v for k, v in os.environ.items() if k not in keys_to_remove}

    def test_unset_returns_none(self):
        with patch.dict(os.environ, self._clean_env(), clear=True):
            self.assertIsNone(get_provider())

    def test_deterministic_returns_none(self):
        with patch.dict(os.environ, {"AI_PROVIDER": "deterministic"}, clear=False):
            self.assertIsNone(get_provider())

    def test_empty_string_returns_none(self):
        with patch.dict(os.environ, {"AI_PROVIDER": ""}, clear=False):
            self.assertIsNone(get_provider())

    def test_unknown_provider_returns_none_with_warning(self):
        with patch.dict(os.environ, {"AI_PROVIDER": "openai"}, clear=False):
            result = get_provider()
        self.assertIsNone(result)

    def test_groq_without_key_returns_none(self):
        env = self._clean_env()
        env["AI_PROVIDER"] = "groq"
        with patch.dict(os.environ, env, clear=True):
            result = get_provider()
        self.assertIsNone(result)

    def test_groq_with_key_returns_groq_provider(self):
        env = self._clean_env()
        env["AI_PROVIDER"] = "groq"
        env["GROQ_API_KEY"] = "gsk_test_key"
        with patch.dict(os.environ, env, clear=True):
            result = get_provider()
        self.assertIsInstance(result, GroqProvider)

    def test_granite_without_enabled_returns_none(self):
        env = self._clean_env()
        env["AI_PROVIDER"] = "granite"
        with patch.dict(os.environ, env, clear=True):
            result = get_provider()
        self.assertIsNone(result)

    def test_granite_with_enabled_returns_granite_provider(self):
        env = self._clean_env()
        env["AI_PROVIDER"] = "granite"
        env["GRANITE_ENABLED"] = "true"
        with patch.dict(os.environ, env, clear=True):
            result = get_provider()
        self.assertIsInstance(result, GraniteProvider)

    def test_factory_is_deterministic_across_calls(self):
        env = self._clean_env()
        env["AI_PROVIDER"] = "groq"
        env["GROQ_API_KEY"] = "k"
        with patch.dict(os.environ, env, clear=True):
            r1 = get_provider()
            r2 = get_provider()
        self.assertIsInstance(r1, GroqProvider)
        self.assertIsInstance(r2, GroqProvider)


if __name__ == "__main__":
    unittest.main()
