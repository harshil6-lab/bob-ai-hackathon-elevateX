"""Provider factory for the AI reasoning boundary.

Reads AI_PROVIDER from the environment and returns the appropriate
AIReasoningProvider instance, or None for deterministic-only mode.

Provider selection
------------------
AI_PROVIDER=groq        → GroqProvider (requires GROQ_API_KEY)
AI_PROVIDER=granite     → GraniteProvider (requires GRANITE_ENABLED=true)
AI_PROVIDER=deterministic → None (no external AI call; deterministic BLUF)
(unset)                 → same as "deterministic"

Priority fallback:
If the selected provider cannot be instantiated (missing credentials, import
error, etc.), a warning is logged and None is returned — the deterministic
BLUF remains the result.  No secondary provider is tried automatically.

Security
--------
- No credentials are logged.
- Provider selection is entirely backend-side.
- The frontend never receives or chooses providers.
- Only one provider is called per analysis (no double-calling).
"""

from __future__ import annotations

import logging
import os

from .provider import AIReasoningProvider

logger = logging.getLogger(__name__)

# Supported provider names.
_GROQ = "groq"
_GRANITE = "granite"
_DETERMINISTIC = "deterministic"

_SUPPORTED = {_GROQ, _GRANITE, _DETERMINISTIC}


def get_provider() -> AIReasoningProvider | None:
    """Return the configured AI reasoning provider, or None.

    None means the caller (bluf.generate_bluf) uses the deterministic BLUF.
    Never raises; all errors are logged and None is returned.
    """
    selection = os.environ.get("AI_PROVIDER", "").strip().lower()

    if not selection or selection == _DETERMINISTIC:
        logger.debug("AI_PROVIDER=deterministic — using deterministic BLUF only")
        return None

    if selection not in _SUPPORTED:
        logger.warning(
            "AI_PROVIDER=%r is not a recognised provider; "
            "supported values: %s. Falling back to deterministic BLUF.",
            selection,
            ", ".join(sorted(_SUPPORTED)),
        )
        return None

    if selection == _GROQ:
        return _load_groq()

    if selection == _GRANITE:
        return _load_granite()

    return None  # unreachable but satisfies the type checker


def _load_groq() -> AIReasoningProvider | None:
    """Import and instantiate GroqProvider; return None on any failure."""
    try:
        from .groq_provider import GroqProvider, is_configured
    except ImportError:
        logger.warning("groq_provider module not importable — falling back to deterministic BLUF")
        return None

    if not is_configured():
        logger.warning(
            "AI_PROVIDER=groq but GROQ_API_KEY is not set — "
            "falling back to deterministic BLUF"
        )
        return None

    try:
        return GroqProvider()
    except Exception as exc:
        logger.warning(
            "GroqProvider construction failed: %s — "
            "falling back to deterministic BLUF",
            type(exc).__name__,
        )
        return None


def _load_granite() -> AIReasoningProvider | None:
    """Import and instantiate GraniteProvider; return None on any failure."""
    try:
        from .granite_provider import GraniteProvider, is_configured
    except ImportError:
        logger.warning(
            "granite_provider module not importable — falling back to deterministic BLUF"
        )
        return None

    if not is_configured():
        logger.warning(
            "AI_PROVIDER=granite but GRANITE_ENABLED is not 'true' — "
            "falling back to deterministic BLUF"
        )
        return None

    try:
        return GraniteProvider()
    except Exception as exc:
        logger.warning(
            "GraniteProvider construction failed: %s — "
            "falling back to deterministic BLUF",
            type(exc).__name__,
        )
        return None
