from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select

from app.db.database import SessionLocal
from app.models import Alert as AlertModel
from app.models import Incident as IncidentModel


_JSON_FIELDS = (
    "affected_assets",
    "sources",
    "mitre_techniques",
    "evidence",
    "recommended_actions",
)


def create_incidents(incidents: list[Any]) -> None:
    """Bulk insert incidents and replace existing rows with the same id.

    Duplicate handling is deterministic: the latest supplied incident for a
    given id replaces the previously stored incident.
    """

    with SessionLocal() as session:
        for incident in incidents:
            session.merge(IncidentModel(**_encode_incident(_as_dict(incident))))
        session.commit()


def get_all_incidents() -> list[dict[str, Any]]:
    """Return all incidents as plain dictionaries, ordered by id."""

    with SessionLocal() as session:
        incidents = session.scalars(select(IncidentModel).order_by(IncidentModel.id)).all()
        return [_decode_incident(incident) for incident in incidents]


def get_incident_by_id(incident_id: str) -> dict[str, Any] | None:
    """Return one incident as a plain dictionary, or None if it does not exist."""

    with SessionLocal() as session:
        incident = session.get(IncidentModel, incident_id)
        return _decode_incident(incident) if incident is not None else None


def get_stats() -> dict[str, Any]:
    """Return dashboard counts for alerts and incidents."""

    with SessionLocal() as session:
        total_alerts = session.scalar(select(func.count()).select_from(AlertModel)) or 0
        total_incidents = session.scalar(select(func.count()).select_from(IncidentModel)) or 0

        alerts_by_severity = {
            severity: count
            for severity, count in session.execute(
                select(AlertModel.severity, func.count())
                .group_by(AlertModel.severity)
                .order_by(AlertModel.severity)
            ).all()
        }
        incidents_by_severity = {
            severity: count
            for severity, count in session.execute(
                select(IncidentModel.severity, func.count())
                .group_by(IncidentModel.severity)
                .order_by(IncidentModel.severity)
            ).all()
        }
        incidents_by_status = {
            status: count
            for status, count in session.execute(
                select(IncidentModel.status, func.count())
                .group_by(IncidentModel.status)
                .order_by(IncidentModel.status)
            ).all()
        }
        source_counts = {
            source: count
            for source, count in session.execute(
                select(AlertModel.source, func.count())
                .group_by(AlertModel.source)
                .order_by(AlertModel.source)
            ).all()
        }

    return {
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "alerts_by_severity": alerts_by_severity,
        "incidents_by_severity": incidents_by_severity,
        "incidents_by_status": incidents_by_status,
        "source_counts": source_counts,
    }


def _as_dict(item: Any) -> dict[str, Any]:
    if hasattr(item, "model_dump"):
        return item.model_dump()
    if hasattr(item, "dict"):
        return item.dict()
    return dict(item)


def _encode_incident(incident: dict[str, Any]) -> dict[str, Any]:
    encoded = dict(incident)
    for field in _JSON_FIELDS:
        value = encoded.get(field, [])
        encoded[field] = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    return encoded


def _decode_incident(incident: IncidentModel) -> dict[str, Any]:
    decoded = {
        "id": incident.id,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "status": incident.status,
        "affected_assets": incident.affected_assets,
        "alert_count": incident.alert_count,
        "sources": incident.sources,
        "mitre_techniques": incident.mitre_techniques,
        "evidence": incident.evidence,
        "bluf": incident.bluf,
        "recommended_actions": incident.recommended_actions,
    }

    for field in _JSON_FIELDS:
        value = decoded[field]
        decoded[field] = json.loads(value) if isinstance(value, str) else (value or [])

    return decoded
