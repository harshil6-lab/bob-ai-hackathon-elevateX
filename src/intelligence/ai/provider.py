"""Provider abstraction for future AI reasoning services."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .context import AIContext
from .grounding import AIReasoningOutput


@runtime_checkable
class AIReasoningProvider(Protocol):
    """Boundary that a future IBM watsonx.ai adapter can implement.

    Implementations must accept deterministic structured context and return
    structured reasoning output. They must not mutate the context or become an
    authority over correlation, scoring, evidence, or MITRE mapping.
    """

    def generate_reasoning(self, context: AIContext) -> AIReasoningOutput:
        """Return structured reasoning for the supplied context."""
        ...
