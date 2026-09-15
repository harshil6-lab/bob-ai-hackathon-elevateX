"""Unit tests for the IBM watsonx.ai provider.

All tests mock the HTTP/network boundary.  No real IBM credentials or network
calls are made.  Tests verify:

  1. Valid watsonx.ai response → AIReasoningOutput with correct fields
  2. Malformed / non-JSON response → ValueError raised
  3. Timeout / network failure → RuntimeError raised
  4. Authentication (IAM) failure → RuntimeError raised
  5. Empty generated_text → RuntimeError raised
  6. Unsupported AI claim (bad reference) → grounding rejects it
  7. Grounding validation failure → bluf falls back to deterministic
  8. Deterministic fallback when no credentials configured
  9. is_configured() behavior
 10. Prompt construction contains required context elements
 11. _parse_response handles <output> wrapper stripping
 12. _parse_response handles regex fallback extraction
 13. WatsonxProvider satisfies AIReasoningProvider protocol
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure src/ is on sys.path for absolute imports.
_SOURCE_ROOT = Path(__file__).resolve().parents[4]
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from src.intelligence.ai.context import build_ai_context
from src.intelligence.ai.grounding import (
    AINumericClaim,
    AIReasoningOutput,
    validate_ai_output,
)
from src.intelligence.ai.provider import AIReasoningProvider
from src.intelligence.ai.watsonx_provider import (
    WatsonxProvider,
    _build_prompt,
    _parse_response,
    is_configured,
)
from src.intelligence.bluf import generate_bluf
from src.intelligence.correlation import correlate_alerts
from src.intelligence.evidence import extract_evidence
from src.intelligence.mitre import map_mitre_behaviors
from src.intelligence.scoring import assess_threat


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(minutes: int = 0) -> str:
    base = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)
    from datetime import timedelta
    return (base + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def _golden_alerts() -> list[dict]:
    return [
        {
            "id": "ALT-1001", "timestamp": _ts(0), "source": "SIEM",
            "event_type": "ExternalActivity", "severity": "medium",
            "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
            "host": "SERVER-17", "user": "admin",
            "description": "Suspicious external activity detected",
        },
        {
            "id": "ALT-1002", "timestamp": _ts(5), "source": "NETWORK_SENSOR",
            "event_type": "PowerShell", "severity": "high",
            "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
            "host": "SERVER-17", "user": "admin",
            "description": "Suspicious PowerShell execution",
        },
        {
            "id": "ALT-1003", "timestamp": _ts(10), "source": "SIEM",
            "event_type": "SuspiciousProcess", "severity": "high",
            "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
            "host": "SERVER-17", "user": "admin",
            "description": "Suspicious process launched from PowerShell",
        },
        {
            "id": "ALT-1004", "timestamp": _ts(15), "source": "THREAT_INTEL",
            "event_type": "CredentialAccess", "severity": "critical",
            "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
            "host": "SERVER-17", "user": "admin",
            "description": "Credential dumping detected",
        },
        {
            "id": "ALT-1005", "timestamp": _ts(20), "source": "NETWORK_SENSOR",
            "event_type": "RemoteConnection", "severity": "high",
            "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
            "host": "SERVER-17", "user": "admin",
            "description": "Remote desktop connection established",
        },
        {
            "id": "ALT-1006", "timestamp": _ts(25), "source": "SIEM",
            "event_type": "LateralMovement", "severity": "critical",
            "source_ip": "10.10.1.20", "destination_ip": "10.10.5.17",
            "host": "SERVER-17", "user": "admin",
            "description": "Lateral movement observed",
        },
    ]


def _build_context():
    alerts = _golden_alerts()
    groups = correlate_alerts(alerts)
    group = groups[0]
    evidence = extract_evidence(group)
    mitre = map_mitre_behaviors(group.alerts, evidence)
    assessment = assess_threat(group, mitre_mappings=mitre.mappings)
    return build_ai_context(group, assessment, evidence, mitre)


def _valid_output(context) -> dict:
    """Build a valid watsonx-style JSON response dict for the given context."""
    hosts = sorted({a.host for a in context.alerts if a.host})
    users = sorted({a.user for a in context.alerts if a.user})
    src_ips = sorted({a.source_ip for a in context.alerts if a.source_ip})
    dst_ips = sorted({a.destination_ip for a in context.alerts if a.destination_ip})
    return {
        "incident_id": context.incident_id,
        "summary": "Critical threat on SERVER-17 with credential dumping and lateral movement.",
        "reasoning": "Six correlated alerts from three sources confirm an attack chain.",
        "referenced_alert_ids": list(context.alert_ids),
        "referenced_evidence_ids": list(context.evidence_ids),
        "referenced_mitre_technique_ids": list(context.mitre_technique_ids),
        "referenced_hosts": hosts,
        "referenced_users": users,
        "referenced_source_ips": src_ips,
        "referenced_destination_ips": dst_ips,
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


def _mock_iam_response(token: str = "test-token") -> dict:
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


def _mock_generation_response(text: str) -> dict:
    return {"results": [{"generated_text": text}]}


class _FakeHTTPResponse:
    """Minimal urllib response mock."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# is_configured() tests
# ---------------------------------------------------------------------------


class IsConfiguredTests(unittest.TestCase):
    def test_returns_false_when_both_vars_absent(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("WATSONX_API_KEY", "WATSONX_PROJECT_ID")}
        with patch.dict(os.environ, env, clear=True):
            self.assertFalse(is_configured())

    def test_returns_false_when_only_api_key_set(self):
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "key", "WATSONX_PROJECT_ID": ""},
                        clear=False):
            os.environ.pop("WATSONX_PROJECT_ID", None)
            self.assertFalse(is_configured())

    def test_returns_false_when_only_project_id_set(self):
        with patch.dict(os.environ,
                        {"WATSONX_PROJECT_ID": "proj"},
                        clear=False):
            os.environ.pop("WATSONX_API_KEY", None)
            self.assertFalse(is_configured())

    def test_returns_true_when_both_vars_set(self):
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "key", "WATSONX_PROJECT_ID": "proj"},
                        clear=False):
            self.assertTrue(is_configured())

    def test_whitespace_only_values_are_treated_as_absent(self):
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "  ", "WATSONX_PROJECT_ID": "  "},
                        clear=False):
            self.assertFalse(is_configured())


# ---------------------------------------------------------------------------
# WatsonxProvider protocol conformance
# ---------------------------------------------------------------------------


class ProviderProtocolTests(unittest.TestCase):
    def test_watsonx_provider_satisfies_aireasoning_provider_protocol(self):
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "k", "WATSONX_PROJECT_ID": "p"},
                        clear=False):
            provider = WatsonxProvider()
        self.assertIsInstance(provider, AIReasoningProvider)

    def test_generate_reasoning_method_exists(self):
        self.assertTrue(hasattr(WatsonxProvider, "generate_reasoning"))
        self.assertTrue(callable(WatsonxProvider.generate_reasoning))


# ---------------------------------------------------------------------------
# Prompt construction tests
# ---------------------------------------------------------------------------


class PromptConstructionTests(unittest.TestCase):
    def test_prompt_contains_incident_id(self):
        ctx = _build_context()
        prompt = _build_prompt(ctx)
        self.assertIn(ctx.incident_id, prompt)

    def test_prompt_contains_all_alert_ids(self):
        ctx = _build_context()
        prompt = _build_prompt(ctx)
        for alert_id in ctx.alert_ids:
            self.assertIn(alert_id, prompt)

    def test_prompt_contains_mitre_technique_ids(self):
        ctx = _build_context()
        prompt = _build_prompt(ctx)
        for technique_id in ctx.mitre_technique_ids:
            self.assertIn(technique_id, prompt)

    def test_prompt_contains_numeric_constraints(self):
        ctx = _build_context()
        prompt = _build_prompt(ctx)
        self.assertIn(str(ctx.scoring.alert_count), prompt)
        self.assertIn(str(ctx.scoring.risk_score), prompt)
        self.assertIn(str(ctx.scoring.confidence), prompt)

    def test_prompt_does_not_contain_api_key_placeholder(self):
        ctx = _build_context()
        prompt = _build_prompt(ctx)
        self.assertNotIn("WATSONX_API_KEY", prompt)
        self.assertNotIn("Bearer", prompt)


# ---------------------------------------------------------------------------
# _parse_response tests
# ---------------------------------------------------------------------------


class ParseResponseTests(unittest.TestCase):
    def setUp(self):
        self.ctx = _build_context()

    def test_valid_json_response_is_parsed(self):
        data = _valid_output(self.ctx)
        raw = json.dumps(data)
        output = _parse_response(self.ctx, raw)
        self.assertIsInstance(output, AIReasoningOutput)
        self.assertEqual(output.incident_id, self.ctx.incident_id)
        self.assertIn("credential", output.summary.lower())

    def test_output_wrapper_tags_are_stripped(self):
        data = _valid_output(self.ctx)
        raw = f"<output>\n{json.dumps(data)}\n</output>"
        output = _parse_response(self.ctx, raw)
        self.assertEqual(output.incident_id, self.ctx.incident_id)

    def test_json_embedded_in_text_is_extracted(self):
        data = _valid_output(self.ctx)
        raw = f"Sure! Here is my analysis:\n{json.dumps(data)}\nDone."
        output = _parse_response(self.ctx, raw)
        self.assertEqual(output.incident_id, self.ctx.incident_id)

    def test_non_json_response_raises_value_error(self):
        with self.assertRaises(ValueError):
            _parse_response(self.ctx, "I cannot help with that request.")

    def test_empty_string_raises_value_error(self):
        with self.assertRaises(ValueError):
            _parse_response(self.ctx, "")

    def test_non_object_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            _parse_response(self.ctx, '["array", "not", "object"]')

    def test_missing_summary_uses_empty_string(self):
        data = _valid_output(self.ctx)
        del data["summary"]
        output = _parse_response(self.ctx, json.dumps(data))
        self.assertEqual(output.summary, "")

    def test_non_string_list_references_are_filtered(self):
        data = _valid_output(self.ctx)
        data["referenced_alert_ids"] = [123, None, "ALT-1001"]
        output = _parse_response(self.ctx, json.dumps(data))
        self.assertEqual(output.referenced_alert_ids, ("ALT-1001",))

    def test_non_int_numeric_claims_are_dropped(self):
        data = _valid_output(self.ctx)
        data["numeric_claims"] = [
            {"name": "alert_count", "value": "six"},
            {"name": "risk_score", "value": self.ctx.scoring.risk_score},
        ]
        output = _parse_response(self.ctx, json.dumps(data))
        # Only the int claim survives
        self.assertEqual(len(output.numeric_claims), 1)
        self.assertEqual(output.numeric_claims[0].name, "risk_score")


# ---------------------------------------------------------------------------
# WatsonxProvider.generate_reasoning — mocked network tests
# ---------------------------------------------------------------------------


class WatsonxProviderNetworkTests(unittest.TestCase):
    """All network calls are mocked.  No real IBM credentials are required."""

    def _provider(self) -> WatsonxProvider:
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "test-key",
                         "WATSONX_PROJECT_ID": "test-project",
                         "WATSONX_URL": "https://test.example.com"},
                        clear=False):
            return WatsonxProvider()

    def _mock_urlopen(self, responses: list[dict]):
        """Return a context-manager mock that yields sequential responses."""
        call_count = [0]
        raw_responses = [
            _FakeHTTPResponse(json.dumps(r).encode()) for r in responses
        ]

        def fake_urlopen(req, timeout=None):
            idx = call_count[0]
            call_count[0] += 1
            return raw_responses[idx]

        return patch("urllib.request.urlopen", side_effect=fake_urlopen)

    def test_valid_response_returns_aireasoning_output(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_output(ctx)
        iam = _mock_iam_response()
        gen = _mock_generation_response(json.dumps(data))

        with self._mock_urlopen([iam, gen]):
            output = provider.generate_reasoning(ctx)

        self.assertIsInstance(output, AIReasoningOutput)
        self.assertEqual(output.incident_id, ctx.incident_id)
        self.assertGreater(len(output.summary), 0)

    def test_valid_response_passes_grounding_validation(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_output(ctx)
        iam = _mock_iam_response()
        gen = _mock_generation_response(json.dumps(data))

        with self._mock_urlopen([iam, gen]):
            output = provider.generate_reasoning(ctx)

        result = validate_ai_output(ctx, output)
        self.assertTrue(result.is_valid, f"Grounding issues: {result.issues}")

    def test_iam_token_is_cached_across_calls(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_output(ctx)
        # First call: IAM + generation; second call: generation only (token cached)
        iam = _mock_iam_response()
        gen1 = _mock_generation_response(json.dumps(data))
        gen2 = _mock_generation_response(json.dumps(data))

        call_count = [0]
        responses = [
            _FakeHTTPResponse(json.dumps(iam).encode()),
            _FakeHTTPResponse(json.dumps(gen1).encode()),
            _FakeHTTPResponse(json.dumps(gen2).encode()),
        ]

        def fake_urlopen(req, timeout=None):
            idx = call_count[0]
            call_count[0] += 1
            return responses[idx]

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            provider.generate_reasoning(ctx)
            provider.generate_reasoning(ctx)

        # Three total HTTP calls: 1 IAM + 2 generation
        self.assertEqual(call_count[0], 3)

    def test_network_timeout_raises_runtime_error(self):
        import urllib.error
        ctx = _build_context()
        provider = self._provider()

        with patch("urllib.request.urlopen",
                   side_effect=TimeoutError("connection timed out")):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_iam_http_error_raises_runtime_error(self):
        import urllib.error
        ctx = _build_context()
        provider = self._provider()

        http_error = urllib.error.HTTPError(
            url=None, code=401, msg="Unauthorized", hdrs=None, fp=None
        )
        with patch("urllib.request.urlopen", side_effect=http_error):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_generation_http_error_raises_runtime_error(self):
        import urllib.error
        ctx = _build_context()
        provider = self._provider()

        iam = _mock_iam_response()
        http_error = urllib.error.HTTPError(
            url=None, code=500, msg="Internal Server Error", hdrs=None, fp=None
        )
        responses = [_FakeHTTPResponse(json.dumps(iam).encode())]
        call_count = [0]

        def fake_urlopen(req, timeout=None):
            idx = call_count[0]
            call_count[0] += 1
            if idx == 0:
                return responses[0]
            raise http_error

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_empty_generated_text_raises_runtime_error(self):
        ctx = _build_context()
        provider = self._provider()
        iam = _mock_iam_response()
        gen = _mock_generation_response("")

        with self._mock_urlopen([iam, gen]):
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)

    def test_malformed_json_response_raises_value_error(self):
        ctx = _build_context()
        provider = self._provider()
        iam = _mock_iam_response()
        gen = _mock_generation_response("This is not JSON at all.")

        with self._mock_urlopen([iam, gen]):
            with self.assertRaises(ValueError):
                provider.generate_reasoning(ctx)

    def test_missing_credentials_raises_runtime_error(self):
        """Provider with blank credentials raises before any HTTP call."""
        ctx = _build_context()
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "", "WATSONX_PROJECT_ID": ""},
                        clear=False):
            provider = WatsonxProvider()

        with patch("urllib.request.urlopen") as mock_url:
            with self.assertRaises(RuntimeError):
                provider.generate_reasoning(ctx)
            mock_url.assert_not_called()

    def test_ai_api_key_is_not_logged(self):
        """Ensure the API key never appears in log output."""
        import logging

        ctx = _build_context()
        provider = self._provider()
        provider._api_key = "super-secret-key-12345"

        log_records: list[str] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record):
                log_records.append(self.format(record))

        handler = CapturingHandler()
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)

        import urllib.error
        try:
            with patch("urllib.request.urlopen",
                       side_effect=urllib.error.HTTPError(
                           url=None, code=401, msg="Unauthorized",
                           hdrs=None, fp=None
                       )):
                try:
                    provider.generate_reasoning(ctx)
                except RuntimeError:
                    pass
        finally:
            root_logger.removeHandler(handler)

        for record in log_records:
            self.assertNotIn("super-secret-key-12345", record,
                             "API key must never appear in log output")


# ---------------------------------------------------------------------------
# Grounding integration: unsupported AI claim triggers fallback
# ---------------------------------------------------------------------------


class GroundingFallbackTests(unittest.TestCase):
    def test_unsupported_mitre_technique_rejected_by_grounding(self):
        ctx = _build_context()
        data = _valid_output(ctx)
        data["referenced_mitre_technique_ids"] = ["T9999"]
        output = _parse_response(ctx, json.dumps(data))

        result = validate_ai_output(ctx, output)
        self.assertFalse(result.is_valid)

    def test_invented_alert_id_rejected_by_grounding(self):
        ctx = _build_context()
        data = _valid_output(ctx)
        data["referenced_alert_ids"] = ["ALT-INVENTED-9999"]
        output = _parse_response(ctx, json.dumps(data))

        result = validate_ai_output(ctx, output)
        self.assertFalse(result.is_valid)

    def test_wrong_risk_score_rejected_by_grounding(self):
        ctx = _build_context()
        data = _valid_output(ctx)
        data["numeric_claims"] = [{"name": "risk_score", "value": 0}]
        output = _parse_response(ctx, json.dumps(data))

        result = validate_ai_output(ctx, output)
        self.assertFalse(result.is_valid)

    def test_generate_bluf_falls_back_when_provider_raises(self):
        ctx = _build_context()

        class RaisingProvider:
            def generate_reasoning(self, context):
                raise RuntimeError("Simulated network error")

        bluf = generate_bluf(ctx, provider=RaisingProvider())
        # Must return deterministic BLUF, not raise
        self.assertEqual(bluf.generated_by, "deterministic")
        self.assertGreater(len(bluf.summary), 0)

    def test_generate_bluf_falls_back_when_provider_returns_invalid_output(self):
        ctx = _build_context()

        class BadOutputProvider:
            def generate_reasoning(self, context):
                return "not an AIReasoningOutput"

        bluf = generate_bluf(ctx, provider=BadOutputProvider())
        self.assertEqual(bluf.generated_by, "deterministic")

    def test_generate_bluf_falls_back_when_grounding_fails(self):
        ctx = _build_context()

        class GroundingFailProvider:
            def generate_reasoning(self, context):
                return AIReasoningOutput(
                    incident_id=context.incident_id,
                    summary="Summary with invented technique T9999.",
                    reasoning="References T9999.",
                    referenced_mitre_technique_ids=("T9999",),
                )

        bluf = generate_bluf(ctx, provider=GroundingFailProvider())
        self.assertEqual(bluf.generated_by, "deterministic")

    def test_generate_bluf_uses_ai_summary_when_grounding_passes(self):
        ctx = _build_context()

        class ValidProvider:
            def generate_reasoning(self, context):
                return AIReasoningOutput(
                    incident_id=context.incident_id,
                    summary="AI-generated valid summary.",
                    reasoning="AI reasoning grounded in context.",
                )

        bluf = generate_bluf(ctx, provider=ValidProvider())
        self.assertEqual(bluf.generated_by, "ai")
        self.assertEqual(bluf.summary, "AI-generated valid summary.")


# ---------------------------------------------------------------------------
# WatsonxProvider + full BLUF pipeline integration (mocked network)
# ---------------------------------------------------------------------------


class WatsonxBLUFIntegrationTests(unittest.TestCase):
    def _provider(self) -> WatsonxProvider:
        with patch.dict(os.environ,
                        {"WATSONX_API_KEY": "test-key",
                         "WATSONX_PROJECT_ID": "test-project",
                         "WATSONX_URL": "https://test.example.com"},
                        clear=False):
            return WatsonxProvider()

    def _mock_urlopen_responses(self, responses: list[dict]):
        call_count = [0]
        raw = [_FakeHTTPResponse(json.dumps(r).encode()) for r in responses]

        def fake(req, timeout=None):
            idx = call_count[0]
            call_count[0] += 1
            return raw[idx]

        return patch("urllib.request.urlopen", side_effect=fake)

    def test_valid_watsonx_response_produces_ai_bluf(self):
        ctx = _build_context()
        provider = self._provider()
        data = _valid_output(ctx)
        iam = _mock_iam_response()
        gen = _mock_generation_response(json.dumps(data))

        with self._mock_urlopen_responses([iam, gen]):
            bluf = generate_bluf(ctx, provider=provider)

        self.assertEqual(bluf.generated_by, "ai")
        self.assertIn("credential", bluf.summary.lower())

    def test_network_failure_produces_deterministic_bluf(self):
        ctx = _build_context()
        provider = self._provider()

        with patch("urllib.request.urlopen",
                   side_effect=TimeoutError("no route to host")):
            bluf = generate_bluf(ctx, provider=provider)

        self.assertEqual(bluf.generated_by, "deterministic")
        self.assertGreater(len(bluf.summary), 0)

    def test_deterministic_facts_unchanged_by_ai_bluf(self):
        """AI BLUF must not change scoring, MITRE, evidence, or actions."""
        from src.intelligence.pipeline import analyze

        alerts = _golden_alerts()

        # Deterministic run (no provider)
        det = analyze(alerts)
        det_incident = det.incidents[0]

        # AI-augmented run (mocked good response)
        ctx = _build_context()
        data = _valid_output(ctx)
        iam = _mock_iam_response()
        gen = _mock_generation_response(json.dumps(data))

        provider = self._provider()
        call_count = [0]
        raw = [
            _FakeHTTPResponse(json.dumps(iam).encode()),
            _FakeHTTPResponse(json.dumps(gen).encode()),
        ]

        def fake(req, timeout=None):
            idx = call_count[0]
            call_count[0] += 1
            return raw[idx]

        with patch("urllib.request.urlopen", side_effect=fake):
            ai_result = analyze(alerts, provider=provider)

        ai_incident = ai_result.incidents[0]
        rec_det = det_incident.record
        rec_ai = ai_incident.record

        # All deterministic facts must be identical.
        self.assertEqual(rec_det.risk_score, rec_ai.risk_score)
        self.assertEqual(rec_det.confidence, rec_ai.confidence)
        self.assertEqual(rec_det.severity, rec_ai.severity)
        self.assertEqual(rec_det.alert_count, rec_ai.alert_count)
        self.assertEqual(sorted(rec_det.sources), sorted(rec_ai.sources))
        self.assertEqual(
            sorted(rec_det.mitre_techniques), sorted(rec_ai.mitre_techniques)
        )
        self.assertEqual(
            sorted(rec_det.recommended_actions),
            sorted(rec_ai.recommended_actions),
        )
        # Only the BLUF summary may differ (AI vs deterministic)
        self.assertNotEqual(rec_det.bluf, "")
        self.assertNotEqual(rec_ai.bluf, "")

    def test_server_17_deterministic_facts_survive_ai_provider(self):
        """SERVER-17 golden facts must be unchanged regardless of AI BLUF."""
        from src.intelligence.pipeline import analyze

        alerts = _golden_alerts()
        provider = self._provider()
        ctx = _build_context()
        data = _valid_output(ctx)
        iam = _mock_iam_response()
        gen = _mock_generation_response(json.dumps(data))

        call_count = [0]
        raw = [
            _FakeHTTPResponse(json.dumps(iam).encode()),
            _FakeHTTPResponse(json.dumps(gen).encode()),
        ]

        def fake(req, timeout=None):
            idx = call_count[0]
            call_count[0] += 1
            return raw[idx]

        with patch("urllib.request.urlopen", side_effect=fake):
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


if __name__ == "__main__":
    unittest.main()
