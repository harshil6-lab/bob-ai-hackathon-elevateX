"""Safe AI reasoning boundary for the intelligence engine.

Exports are loaded lazily so ``unittest discover`` can safely traverse this
package from the intelligence directory without treating it as a top-level
package that imports its parent.
"""

from collections.abc import Callable
from typing import Any


def __getattr__(name: str) -> Any:
    """Load a boundary API lazily while preserving the package interface."""

    factory: Callable[[], Any] | None = None
    if name in {"AIContext", "build_ai_context"}:
        from .context import AIContext, build_ai_context

        factory = {
            "AIContext": lambda: AIContext,
            "build_ai_context": lambda: build_ai_context,
        }[name]
    elif name in {
        "AINumericClaim",
        "AIReasoningOutput",
        "GroundingIssue",
        "GroundingResult",
        "validate_ai_output",
    }:
        from .grounding import (
            AINumericClaim,
            AIReasoningOutput,
            GroundingIssue,
            GroundingResult,
            validate_ai_output,
        )

        factory = {
            "AINumericClaim": lambda: AINumericClaim,
            "AIReasoningOutput": lambda: AIReasoningOutput,
            "GroundingIssue": lambda: GroundingIssue,
            "GroundingResult": lambda: GroundingResult,
            "validate_ai_output": lambda: validate_ai_output,
        }[name]
    elif name == "AIReasoningProvider":
        from .provider import AIReasoningProvider

        factory = lambda: AIReasoningProvider

    if factory is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    value = factory()
    globals()[name] = value
    return value
