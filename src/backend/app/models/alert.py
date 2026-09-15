from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class Alert(Base):
    """Persistent representation of the canonical Alert contract."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(32), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column("user", String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
