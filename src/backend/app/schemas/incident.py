from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["informational", "low", "medium", "high", "critical"]


class Incident(BaseModel):
    """Frozen shared Incident contract.

    Field names are part of the cross-team API contract and must not be
    renamed or removed without explicit approval from all team members.
    """

    id: str
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    status: str
    affected_assets: list[str]
    alert_count: int = Field(ge=0)
    sources: list[str]
    mitre_techniques: list[str]
    evidence: list[str]
    bluf: str
    recommended_actions: list[str]

    model_config = {"extra": "forbid"}
