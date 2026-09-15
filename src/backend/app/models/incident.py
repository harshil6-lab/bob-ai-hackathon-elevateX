from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Incident(Base):
    """Persistent representation of the canonical Incident contract."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    severity: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(64))
    affected_assets: Mapped[list[str]] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    bluf: Mapped[str] = mapped_column(Text, default="")
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
