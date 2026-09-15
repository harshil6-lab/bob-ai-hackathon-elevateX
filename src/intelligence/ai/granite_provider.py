"""IBM Granite provider via local Ollama for the AI reasoning boundary.

This module implements the AIReasoningProvider protocol using a locally-running
Ollama instance serving an IBM Granite model.

IBM Granite is an IBM foundation model technology.  This provider accesses it
through Ollama's OpenAI-compatible local API — NOT through IBM watsonx.ai.
IBM does not host or operate the local Ollama inference.

Architecture invariant
----------------------
All deterministic intelligence facts (correlation, scoring, evidence, MITRE
mapping, recommended actions) are authoritative and unchanged.  This provider
is responsible ONLY for producing an analyst-oriented BLUF explanation.

Availability
------------
This provider is designed for LOCAL DEVELOPMENT ONLY.  It requires:
  - Ollama installed and running (https://ollama.com)
  - An IBM Granite model pulled locally, e.g.:
      ollama pull granite3-moe:3b   (IBM Granite 3 MoE 3B — compact)
      ollama pull granite3.3:8b     (IBM Granite 3.3 8B — full instruct)

In Docker, Ollama is NOT accessible at localhost from inside the container.
See docs/setup-guide.md for Docker configuration guidance.

Environment variables
---------------------
GRANITE_ENABLED      Set to "true" to activate this provider (default: false)
GRANITE_BASE_URL     Ollama API base URL (default: http://localhost:11434/v1)
GRANITE_MODEL_ID     Ollama model name (default: granite3-moe:3b)

Security
--------
- No API keys are required for local Ollama.
- Alert text is embedded in the prompt as quoted data, not as instructions.
- The provider raises on any error; the grounding fallback in bluf.py handles it.
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
from ._prompt import build_grounded_prompt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = "http://localhost:11434/v1"
_CHAT_PATH = "/chat/completions"
_DEFAULT_MODEL = "granite3-moe:3b"

_MAX_TOKENS = 1024
_TEMPERATURE = 0.2
_REQUEST_TIMEOUT_SECONDS = 60  # Longer — local inference can be slow.


# ---------------------------------------------------------------------------
# Public provider class
# ---------------------------------------------------------------------------


class GraniteProvider:
    """AIReasoningProvider that calls Ollama serving an IBM Granite model.

    Requires Ollama to be running locally with a Granite model pulled.
    The provider raises on any failure so bluf.generate_bluf() can fall
    back to the deterministic BLUF.

    This provider does NOT require watsonx.ai or any IBM cloud credentials.
    It uses IBM's open-source Granite model weights running locally.
    """

    def __init__(self) -> None:
        self._base_url: str = (
            os.environ.get("GRANITE_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")
        )
        self._model_id: str = (
            os.environ.get("GRANITE_MODEL_ID", _DEFAULT_MODEL).strip()
            or _DEFAULT_MODEL
        )

    # ------------------------------------------------------------------
    # AIReasoningProvider protocol
    # ------------------------------------------------------------------

    def generate_reasoning(self, context: AIContext) -> AIReasoningOutput:
        """Call local Ollama/Granite and return structured reasoning output.

        Raises RuntimeError or ValueError on failure; never crashes the app.
        """
        prompt = build_grounded_prompt(context)
        raw_text = self._call_ollama(prompt)
        return _parse_response(context, raw_text)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_ollama(self, prompt: str) -> str:
        """POST to the Ollama OpenAI-compatible chat endpoint."""
        url = self._base_url + _CHAT_PATH
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
                "stream": False,
            }
        ).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_SECONDS) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"Ollama API failed with HTTP {exc.code}."
            ) from exc
        except ConnectionRefusedError as exc:
            raise RuntimeError(
                "Ollama is not running or not reachable at "
                f"{self._base_url}."
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Ollama API failed: {type(exc).__name__}"
            ) from exc

        choices = body.get("choices", [])
        if not choices:
            raise RuntimeError("Ollama response contained no choices.")
        content = choices[0].get("message", {}).get("content", "")
        if not content:
            raise RuntimeError("Ollama response message contained no content.")
        return content


# ---------------------------------------------------------------------------
# Response parsing (same logic as GroqProvider)
# ---------------------------------------------------------------------------


def _parse_response(context: AIContext, raw_text: str) -> AIReasoningOutput:
    text = raw_text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^<output>\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*</output>$", "", text, flags=re.IGNORECASE)
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ValueError(
                "Granite/Ollama response did not contain a parseable JSON object."
            )
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Granite/Ollama JSON extraction failed: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Granite/Ollama response JSON is not an object.")

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
    """Return True when GRANITE_ENABLED=true is set in the environment."""
    return (
        os.environ.get("GRANITE_ENABLED", "").strip().lower() == "true"
    )
