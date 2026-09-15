from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.db.database import Base
from app.repositories import alert_repository, incident_repository


def _configure_database(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    test_session = sessionmaker(bind=engine)
    monkeypatch.setattr(alert_repository, "SessionLocal", test_session)
    monkeypatch.setattr(incident_repository, "SessionLocal", test_session)


def _alert(alert_id: str, severity: str = "high") -> dict:
    return {
        "id": alert_id,
        "timestamp": datetime(2026, 9, 14, 10, 20, tzinfo=timezone.utc),
        "source": "SIEM",
        "event_type": "network_connection",
        "severity": severity,
        "source_ip": "203.0.113.55",
        "destination_ip": "10.10.5.17",
        "host": "SERVER-17",
        "user": "admin",
        "description": "Unusual inbound connection",
    }


def _incident(incident_id: str, severity: str = "critical", status: str = "investigating") -> dict:
    return {
        "id": incident_id,
        "severity": severity,
        "confidence": 94,
        "status": status,
        "affected_assets": ["SERVER-17"],
        "alert_count": 7,
        "sources": ["SIEM", "NETWORK_SENSOR", "THREAT_INTEL"],
        "mitre_techniques": ["T1059.001"],
        "evidence": ["EV-ALT-1001"],
        "bluf": "Critical multi-stage activity on SERVER-17.",
        "recommended_actions": ["Isolate SERVER-17"],
    }


def test_alert_repository_crud_and_duplicate_replacement(monkeypatch):
    _configure_database(monkeypatch)

    alert_repository.create_alerts([_alert("ALT-1001")])
    replaced_alert = _alert("ALT-1001", severity="critical")
    alert_repository.create_alerts([replaced_alert])

    alerts = alert_repository.get_all_alerts()
    stored_alert = alert_repository.get_alert_by_id("ALT-1001")

    assert len(alerts) == 1
    assert stored_alert is not None
    assert stored_alert["severity"] == "critical"
    assert alert_repository.get_alert_by_id("ALT-404") is None


def test_incident_repository_crud_and_json_round_trip(monkeypatch):
    _configure_database(monkeypatch)

    incident_repository.create_incidents([_incident("INC-001")])
    stored_incident = incident_repository.get_incident_by_id("INC-001")

    assert stored_incident is not None
    assert stored_incident["affected_assets"] == ["SERVER-17"]
    assert stored_incident["sources"] == ["SIEM", "NETWORK_SENSOR", "THREAT_INTEL"]
    assert stored_incident["mitre_techniques"] == ["T1059.001"]
    assert stored_incident["evidence"] == ["EV-ALT-1001"]
    assert stored_incident["recommended_actions"] == ["Isolate SERVER-17"]
    assert incident_repository.get_incident_by_id("INC-404") is None


def test_get_stats_counts_alerts_and_incidents(monkeypatch):
    _configure_database(monkeypatch)

    alert_repository.create_alerts(
        [
            _alert("ALT-1001", severity="high"),
            _alert("ALT-1002", severity="critical"),
        ]
    )
    incident_repository.create_incidents(
        [
            _incident("INC-001", severity="critical", status="investigating"),
            _incident("INC-002", severity="high", status="contained"),
        ]
    )

    stats = incident_repository.get_stats()

    assert stats["total_alerts"] == 2
    assert stats["total_incidents"] == 2
    assert stats["alerts_by_severity"] == {"critical": 1, "high": 1}
    assert stats["incidents_by_severity"] == {"critical": 1, "high": 1}
    assert stats["incidents_by_status"] == {"contained": 1, "investigating": 1}
    assert stats["source_counts"] == {"SIEM": 2}
