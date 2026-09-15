"""IBM watsonx.ai provider for the AI reasoning boundary.

This module implements the AIReasoningProvider protocol using the IBM
watsonx.ai Inference API.  It is the ONLY place in the codebase that makes
HTTP calls to IBM.

Architecture invariant
----------------------
The deterministic intelligence engine is authoritative for:
  - alert normalization, correlation, scoring, evidence extraction,
    MITRE mapping, and recommended actions.

This provider is responsible ONLY for:
  - constructing a grounded, bounded prompt from the supplied AIContext,
  - calling the watsonx.ai text-generation API,
  - parsing the JSON response into AIReasoningOutput,
  - returning structured output that the BLUF validator can accept.

If credentials are absent, the network is unavailable, the API returns an
error, or the response fails grounding validation, the caller (bluf.py)
falls back deterministically.  This provider never crashes the application.

Environment variables
---------------------
WATSONX_API_KEY     IBM Cloud IAM API key (required for live calls)
WATSONX_PROJECT_ID  watsonx.ai project identifier (required for live calls)
WATSONX_URL         watsonx.ai endpoint URL
                    (default: https://us-south.ml.cloud.ibm.com)
WATSONX_MODEL_ID    Model to use
                    (default: ibm/granite-13b-instruct-v2)

Security
--------
- Credentials are read from environment variables only.
- The API key is sent in the Authorization header over HTTPS.
- The API key is NEVER logged, returned in a response, or embedded in code.
- Alert text is quoted in the prompt as data, never executed.
- The response is parsed as JSON; no eval() or exec() is used.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .context import AIContext
from .grounding import AINumericClaim, AIReasoningOutput

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_URL = "https://us-south.ml.cloud.ibm.com"
_DEFAULT_MODEL = "ibm/granite-13b-instruct-v2"
_IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
_GENERATION_PATH = "/ml/v1/text/generation?version=2023-05-29"

# Generation parameters — conservative settings to stay on-topic.
_MAX_NEW_TOKENS = 512
_TEMPERATURE = 0.2          # Low temperature: focused, repeatable output.
_REQUEST_TIMEOUT_SECONDS = 20


# ---------------------------------------------------------------------------
# Public provider class
# ---------------------------------------------------------------------------


class WatsonxProvider:
    """AIReasoningProvider that calls the IBM watsonx.ai Inference API.

    Construct with no arguments; credentials are read from the environment.
    The constructor does NOT make network calls.  All network I/O is deferred
    to generate_reasoning(), which handles every failure gracefully.

    Usage
    -----
    from src.intelligence.ai.watsonx_provider import WatsonxProvider, is_configured

    if is_configured():
        provider = WatsonxProvider()
    else:
        provider = None  # deterministic BLUF is used

    analysis = analyze(alerts, provider=provider)
    """

    def __init__(self) -> None:
        self._api_key: str = os.environ.get("WATSONX_API_KEY", "").strip()
        self._project_id: str = os.environ.get("WATSONX_PROJECT_ID", "").strip()
        self._base_url: str = (
            os.environ.get("WATSONX_URL", _DEFAULT_URL).rstrip("/")
        )
        self._model_id: str = (
            os.environ.get("WATSONX_MODEL_ID", _DEFAULT_MODEL).strip()
            or _DEFAULT_MODEL
        )
        # Cached IAM token (not persisted across instances)
        self._iam_token: str | None = None

    # ------------------------------------------------------------------
    # AIReasoningProvider protocol
    # ------------------------------------------------------------------

    def generate_reasoning(self, context: AIContext) -> AIReasoningOutput:
        """Call watsonx.ai and return structured, grounded reasoning output.

        Any exception raised here is caught by bluf.generate_bluf() which
        falls back to the deterministic BLUF.  This method may raise on
        misconfiguration or network failure; it does not swallow exceptions
        itself — the boundary in bluf.py is responsible for fallback.
        """
        if not self._api_key or not self._project_id:
            raise RuntimeError(
                "WATSONX_API_KEY and WATSONX_PROJECT_ID must both be set."
            )

        token = self._get_iam_token()
        prompt = _build_prompt(context)
        raw_text = self._call_generation_api(token, prompt)
        output = _parse_response(context, raw_text)
        return output

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_iam_token(self) -> str:
        """Exchange the IBM Cloud API key for a short-lived IAM bearer token.

        The token is cached for the lifetime of this provider instance.
        A fresh token is fetched only once per instance to minimize network
        round-trips in the common path.

        Security: the API key is sent only to the IBM IAM endpoint over HTTPS.
        It is never logged.
        """
        if self._iam_token:
            return self._iam_token

        data = urllib.parse.urlencode(
            {
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": self._api_key,
            }
        ).encode()
        req = urllib.request.Request(
            _IAM_TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            # Do NOT include response body in the log; it might contain token data.
            raise RuntimeError(
                f"IAM token exchange failed with HTTP {exc.code}."
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"IAM token exchange failed: {type(exc).__name__}"
            ) from exc

        token = body.get("access_token", "")
        if not token:
            raise RuntimeError("IAM response did not contain an access_token.")
        self._iam_token = token
        return token

    def _call_generation_api(self, token: str, prompt: str) -> str:
        """POST to the watsonx.ai text-generation endpoint.

        Security: the bearer token is sent in the Authorization header over
        HTTPS only.  Alert text appears in the prompt as quoted data.
        """
        url = self._base_url + _GENERATION_PATH
        payload = json.dumps(
            {
                "model_id": self._model_id,
                "input": prompt,
                "parameters": {
                    "max_new_tokens": _MAX_NEW_TOKENS,
                    "temperature": _TEMPERATURE,
                    "stop_sequences": ["</output>"],
                },
                "project_id": self._project_id,
            }
        ).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"watsonx.ai generation API failed with HTTP {exc.code}."
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"watsonx.ai generation API failed: {type(exc).__name__}"
            ) from exc

        results = body.get("results", [])
        if not results:
            raise RuntimeError("watsonx.ai response contained no results.")
        generated_text = results[0].get("generated_text", "")
        if not generated_text:
            raise RuntimeError("watsonx.ai result contained no generated_text.")
        return generated_text


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def _build_prompt(context: AIContext) -> str:
    """Build a grounded, bounded prompt from deterministic intelligence context.

    The prompt instructs the model to:
      - produce ONLY a JSON object with the exact fields specified,
      - use ONLY IDs, hosts, users, and IPs that appear in the context,
      - NOT invent facts, scores, counts, or technique IDs,
      - produce analyst-facing natural language for summary and reasoning.

    The structured context section is rendered deterministically so that
    tests can inspect the prompt shape without calling the real API.
    """

    # Build compact context representations to stay within token limits.
    alert_lines = "\n".join(
        f"  - {a.alert_id} | {a.timestamp} | {a.source} | {a.event_type} "
        f"| {a.severity} | host={a.host or 'N/A'} user={a.user or 'N/A'}"
        for a in context.alerts
    )

    technique_lines = (
        "\n".join(
            f"  - {m.technique_id} ({m.technique_name}, {m.tactic})"
            for m in context.mitre_mappings
        )
        or "  (none)"
    )

    evidence_lines = (
        "\n".join(
            f"  - {e.evidence_id}: {e.evidence_type} — {e.description}"
            for e in context.evidence_records
        )
        or "  (none)"
    )

    # Comma-joined lists for the grounding instruction block.
    alert_ids_csv = ", ".join(context.alert_ids)
    evidence_ids_csv = (
        ", ".join(context.evidence_ids) if context.evidence_ids else "(none)"
    )
    mitre_ids_csv = (
        ", ".join(context.mitre_technique_ids) if context.mitre_technique_ids else "(none)"
    )
    hosts_csv = (
        ", ".join(
            sorted({a.host for a in context.alerts if a.host})
        ) or "(none)"
    )
    users_csv = (
        ", ".join(
            sorted({a.user for a in context.alerts if a.user})
        ) or "(none)"
    )
    source_ips_csv = (
        ", ".join(
            sorted({a.source_ip for a in context.alerts if a.source_ip})
        ) or "(none)"
    )
    destination_ips_csv = (
        ", ".join(
            sorted({a.destination_ip for a in context.alerts if a.destination_ip})
        ) or "(none)"
    )
    assets_csv = (
        ", ".join(context.scoring.affected_assets) if context.scoring.affected_assets else "(none)"
    )

    prompt = f"""You are a cybersecurity analyst AI assistant. You will be given structured intelligence
results from a deterministic threat intelligence engine. Your job is to write a concise,
analyst-oriented explanation (summary and reasoning) of what the intelligence means.

CRITICAL RULES:
1. You MUST output ONLY a JSON object. No other text before or after it.
2. Your summary and reasoning MUST be grounded in the context below.
3. You MUST NOT invent alert IDs, evidence IDs, MITRE techniques, hosts, users, IP addresses,
   risk scores, confidence values, or alert counts.
4. You MUST reference only values that appear in the ALLOWED REFERENCES section.
5. The summary should be 1-3 sentences suitable for a commander's BLUF.
6. The reasoning should be 2-5 sentences explaining the key technical findings.

ALLOWED REFERENCES (use ONLY these values in referenced_* fields):
  incident_id: {context.incident_id}
  alert_ids: {alert_ids_csv}
  evidence_ids: {evidence_ids_csv}
  mitre_technique_ids: {mitre_ids_csv}
  hosts: {hosts_csv}
  users: {users_csv}
  source_ips: {source_ips_csv}
  destination_ips: {destination_ips_csv}
  assets: {assets_csv}
  alert_count (exact): {context.scoring.alert_count}
  source_count (exact): {context.scoring.source_count}
  risk_score (exact): {context.scoring.risk_score}
  confidence (exact): {context.scoring.confidence}
  evidence_count (exact): {len(context.evidence_ids)}
  mitre_technique_count (exact): {len(context.mitre_technique_ids)}

INTELLIGENCE CONTEXT:
Incident: {context.incident_id}
Assessment: {context.scoring.severity} severity, risk {context.scoring.risk_score}/100,
  confidence {context.scoring.confidence}/100, {context.scoring.false_positive_assessment}

Correlated alerts ({context.scoring.alert_count} total, {context.scoring.source_count} sources):
{alert_lines}

MITRE ATT&CK mappings:
{technique_lines}

Evidence:
{evidence_lines}

Now write the analyst BLUF explanation. Output ONLY this JSON object:
<output>
{{
  "incident_id": "{context.incident_id}",
  "summary": "<1-3 sentence commander BLUF>",
  "reasoning": "<2-5 sentence technical explanation>",
  "referenced_alert_ids": [{_json_str_list(context.alert_ids)}],
  "referenced_evidence_ids": [{_json_str_list(context.evidence_ids)}],
  "referenced_mitre_technique_ids": [{_json_str_list(context.mitre_technique_ids)}],
  "referenced_hosts": [{_json_str_list(sorted({a.host for a in context.alerts if a.host}))}],
  "referenced_users": [{_json_str_list(sorted({a.user for a in context.alerts if a.user}))}],
  "referenced_source_ips": [{_json_str_list(sorted({a.source_ip for a in context.alerts if a.source_ip}))}],
  "referenced_destination_ips": [{_json_str_list(sorted({a.destination_ip for a in context.alerts if a.destination_ip}))}],
  "referenced_assets": [{_json_str_list(context.scoring.affected_assets)}],
  "numeric_claims": [
    {{"name": "alert_count", "value": {context.scoring.alert_count}}},
    {{"name": "source_count", "value": {context.scoring.source_count}}},
    {{"name": "risk_score", "value": {context.scoring.risk_score}}},
    {{"name": "confidence", "value": {context.scoring.confidence}}},
    {{"name": "evidence_count", "value": {len(context.evidence_ids)}}},
    {{"name": "mitre_technique_count", "value": {len(context.mitre_technique_ids)}}}
  ]
}}
</output>"""

    return prompt


def _json_str_list(values: Any) -> str:
    """Render an iterable of strings as a comma-separated JSON string list."""
    items = list(values)
    return ", ".join(json.dumps(v) for v in items)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def _parse_response(context: AIContext, raw_text: str) -> AIReasoningOutput:
    """Extract and validate the JSON block from the generated text.

    The model is instructed to produce ONLY the JSON object.  We attempt to
    parse it directly; if that fails we try to extract a JSON object with a
    regex fallback.  The result is validated by the caller via grounding.
    """
    text = raw_text.strip()

    # Remove the <output> wrapper if the model echoed it.
    text = re.sub(r"^<output>\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*</output>$", "", text, flags=re.IGNORECASE)
    text = text.strip()

    # Attempt direct JSON parse.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Regex fallback: extract first {...} block.
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ValueError(
                "watsonx.ai response did not contain a parseable JSON object."
            )
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"watsonx.ai JSON extraction failed: {exc}"
            ) from exc

    if not isinstance(data, dict):
        raise ValueError("watsonx.ai response JSON is not an object.")

    # Build AIReasoningOutput — only safe, typed fields are used.
    return AIReasoningOutput(
        incident_id=_safe_str(data.get("incident_id"), context.incident_id),
        summary=_safe_str(data.get("summary"), ""),
        reasoning=_safe_str(data.get("reasoning"), ""),
        referenced_alert_ids=_safe_str_tuple(data.get("referenced_alert_ids")),
        referenced_evidence_ids=_safe_str_tuple(data.get("referenced_evidence_ids")),
        referenced_mitre_technique_ids=_safe_str_tuple(
            data.get("referenced_mitre_technique_ids")
        ),
        referenced_hosts=_safe_str_tuple(data.get("referenced_hosts")),
        referenced_users=_safe_str_tuple(data.get("referenced_users")),
        referenced_source_ips=_safe_str_tuple(data.get("referenced_source_ips")),
        referenced_destination_ips=_safe_str_tuple(data.get("referenced_destination_ips")),
        referenced_assets=_safe_str_tuple(data.get("referenced_assets")),
        numeric_claims=_safe_numeric_claims(data.get("numeric_claims")),
    )


def _safe_str(value: Any, default: str) -> str:
    """Return value as a string if it is a non-empty string, else default."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _safe_str_tuple(value: Any) -> tuple[str, ...]:
    """Return a tuple of non-empty strings from a list, ignoring non-strings."""
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _safe_numeric_claims(value: Any) -> tuple[AINumericClaim, ...]:
    """Parse numeric_claims list into AINumericClaim instances safely."""
    if not isinstance(value, list):
        return ()
    claims: list[AINumericClaim] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        val = item.get("value")
        if isinstance(name, str) and name and isinstance(val, int) and not isinstance(val, bool):
            claims.append(AINumericClaim(name=name, value=val))
    return tuple(claims)


# ---------------------------------------------------------------------------
# Configuration helper
# ---------------------------------------------------------------------------


def is_configured() -> bool:
    """Return True if the required watsonx.ai environment variables are set.

    Use this before constructing a WatsonxProvider to decide whether to pass
    a real provider or None (deterministic fallback) to analyze().

    Security: never logs or returns credential values.
    """
    return bool(
        os.environ.get("WATSONX_API_KEY", "").strip()
        and os.environ.get("WATSONX_PROJECT_ID", "").strip()
    )
