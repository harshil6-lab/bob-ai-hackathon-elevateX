from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["informational", "low", "medium", "high", "critical"]


class Alert(BaseModel):
    """Frozen shared Alert contract.

    Field names are part of the cross-team API contract and must not be
    renamed or removed without explicit approval from all team members.
    """

    id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: Severity
    source_ip: str | None
    destination_ip: str | None
    host: str | None
    user: str | None
    description: str | None

    model_config = {"extra": "forbid"}
