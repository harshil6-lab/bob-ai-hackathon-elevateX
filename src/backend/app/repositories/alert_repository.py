from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models import Alert as AlertModel


def create_alerts(alerts: list[Any]) -> None:
    """Bulk insert alerts and replace existing rows with the same id.

    Duplicate handling is deterministic: the latest supplied alert for a given
    id replaces the previously stored alert.
    """

    with SessionLocal() as session:
        for alert in alerts:
            session.merge(AlertModel(**_as_dict(alert)))
        session.commit()


def get_all_alerts() -> list[dict[str, Any]]:
    """Return all alerts as plain dictionaries, ordered by timestamp."""

    with SessionLocal() as session:
        alerts = session.scalars(select(AlertModel).order_by(AlertModel.timestamp)).all()
        return [_alert_to_dict(alert) for alert in alerts]


def get_alert_by_id(alert_id: str) -> dict[str, Any] | None:
    """Return one alert as a plain dictionary, or None if it does not exist."""

    with SessionLocal() as session:
        alert = session.get(AlertModel, alert_id)
        return _alert_to_dict(alert) if alert is not None else None


def _as_dict(item: Any) -> dict[str, Any]:
    if hasattr(item, "model_dump"):
        return item.model_dump()
    if hasattr(item, "dict"):
        return item.dict()
    return dict(item)


def _alert_to_dict(alert: AlertModel) -> dict[str, Any]:
    return {
        "id": alert.id,
        "timestamp": alert.timestamp,
        "source": alert.source,
        "event_type": alert.event_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "host": alert.host,
        "user": alert.user,
        "description": alert.description,
    }
