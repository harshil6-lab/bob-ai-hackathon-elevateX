"""Groq cloud inference provider for the AI reasoning boundary.

This module implements the AIReasoningProvider protocol using the Groq API,
which exposes an OpenAI-compatible endpoint for text/chat generation.

Architecture invariant
----------------------
The deterministic intelligence engine is authoritative for ALL structured
security facts: correlation, scoring, evidence, MITRE mapping, confidence,
risk score, and recommended actions.

This provider is responsible ONLY for:
  - constructing a grounded, bounded prompt from the supplied AIContext,
  - calling the Groq chat-completion API,
  - parsing the JSON response into AIReasoningOutput,
  - returning structured output that the grounding validator can accept.

If credentials are absent, the network is unavailable, the API returns an
error, the response cannot be parsed, or grounding validation fails, the
caller (bluf.py) falls back to the deterministic BLUF automatically.
This provider never crashes the application.

Environment variables
---------------------
GROQ_API_KEY      Groq cloud API key (required for live calls)
GROQ_MODEL_ID     Groq model to use
                  (default: llama-3.1-8b-instant — fast, JSON-capable,
                   verified available on the free tier)

Security
--------
- Credentials are read from environment variables only.
- GROQ_API_KEY is sent in the Authorization header over HTTPS only.
- GROQ_API_KEY is NEVER logged, returned in a response, or embedded in code.
- Alert text is embedded in the prompt as quoted data, not as instructions.
- Responses are parsed as JSON; no eval() or exec() is used.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .context import AIContext
from .grounding import AINumericClaim, AIReasoningOutput
from ._prompt import build_grounded_prompt, json_str_list

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GROQ_API_BASE = "https://api.groq.com/openai/v1"
_CHAT_COMPLETIONS_PATH = "/chat/completions"
_DEFAULT_MODEL = "llama-3.1-8b-instant"

_MAX_TOKENS = 1024
_TEMPERATURE = 0.2
_REQUEST_TIMEOUT_SECONDS = 30


# ---------------------------------------------------------------------------
# Public provider class
# ---------------------------------------------------------------------------


class GroqProvider:
    """AIReasoningProvider that calls the Groq chat-completion API.

    Construct with no arguments; credentials are read from the environment.
    The constructor does NOT make network calls.  All network I/O is deferred
    to generate_reasoning(), which raises on any failure so the grounding/
    fallback layer in bluf.py can handle it cleanly.

    Usage
    -----
    from src.intelligence.ai.groq_provider import GroqProvider, is_configured

    if is_configured():
        provider = GroqProvider()
    else:
        provider = None  # deterministic BLUF is used
    """

    def __init__(self) -> None:
        self._api_key: str = os.environ.get("GROQ_API_KEY", "").strip()
        self._model_id: str = (
            os.environ.get("GROQ_MODEL_ID", _DEFAULT_MODEL).strip()
            or _DEFAULT_MODEL
        )

    # ------------------------------------------------------------------
    # AIReasoningProvider protocol
    # ------------------------------------------------------------------

    def generate_reasoning(self, context: AIContext) -> AIReasoningOutput:
        """Call Groq and return structured, grounded reasoning output.

        Raises RuntimeError or ValueError on any failure so that
        bluf.generate_bluf() catches it and uses the deterministic BLUF.
        Never returns silently invalid output — all errors propagate.
        """
        if not self._api_key:
            raise RuntimeError("GROQ_API_KEY must be set.")

        prompt = build_grounded_prompt(context)
        raw_text = self._call_chat_completions(prompt)
        output = _parse_response(context, raw_text)
        return output

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_chat_completions(self, prompt: str) -> str:
        """POST to the Groq chat-completions endpoint.

        Security: the API key is sent in the Authorization header over
        HTTPS only.  Alert text appears in the prompt as quoted data.
        """
        url = _GROQ_API_BASE + _CHAT_COMPLETIONS_PATH
        payload = json.dumps(
            {
                "model": self._model_id,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity analyst AI assistant. "
                            "You output ONLY valid JSON. "
                            "You NEVER invent facts not present in the user message."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": _MAX_TOKENS,
                "temperature": _TEMPERATURE,
                "response_format": {"type": "json_object"},
            }
        ).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"Groq API failed with HTTP {exc.code}."
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Groq API failed: {type(exc).__name__}"
            ) from exc

        choices = body.get("choices", [])
        if not choices:
            raise RuntimeError("Groq response contained no choices.")
        content = choices[0].get("message", {}).get("content", "")
        if not content:
            raise RuntimeError("Groq response message contained no content.")
        return content


# ---------------------------------------------------------------------------
# Response parsing (shared with GraniteProvider via same format)
# ---------------------------------------------------------------------------


def _parse_response(context: AIContext, raw_text: str) -> AIReasoningOutput:
    """Extract and validate the JSON block from generated text.

    Attempts direct JSON parse; falls back to regex extraction.
    """
    text = raw_text.strip()

    # Strip markdown code fences if the model added them.
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
    text = text.strip()

    # Remove <output> wrapper if echoed.
    text = re.sub(r"^<output>\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*</output>$", "", text, flags=re.IGNORECASE)
    text = text.strip()

    # Attempt direct JSON parse.
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ValueError(
                "AI response did not contain a parseable JSON object."
            )
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise ValueError(f"AI JSON extraction failed: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("AI response JSON is not an object.")

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
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _safe_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _safe_numeric_claims(value: Any) -> tuple[AINumericClaim, ...]:
    if not isinstance(value, list):
        return ()
    claims: list[AINumericClaim] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        val = item.get("value")
        if (
            isinstance(name, str) and name
            and isinstance(val, int) and not isinstance(val, bool)
        ):
            claims.append(AINumericClaim(name=name, value=val))
    return tuple(claims)


# ---------------------------------------------------------------------------
# Configuration helper
# ---------------------------------------------------------------------------


def is_configured() -> bool:
    """Return True when GROQ_API_KEY is set.

    Security: never logs or returns the key value.
    """
    return bool(os.environ.get("GROQ_API_KEY", "").strip())
