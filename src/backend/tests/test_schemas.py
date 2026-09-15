from app.schemas.alert import Alert
from app.schemas.incident import Incident


def test_alert_schema_fields_and_types():
    alert = Alert(
        id="ALT-1001",
        timestamp="2026-09-14T10:32:00Z",
        source="SIEM",
        event_type="PowerShell",
        severity="medium",
        source_ip="10.10.1.20",
        destination_ip="10.10.5.17",
        host="SERVER-17",
        user="admin",
        description="Suspicious PowerShell execution",
    )

    assert set(Alert.model_fields) == {
        "id",
        "timestamp",
        "source",
        "event_type",
        "severity",
        "source_ip",
        "destination_ip",
        "host",
        "user",
        "description",
    }
    assert alert.severity == "medium"


def test_incident_schema_fields_and_types():
    incident = Incident(
        id="INC-001",
        severity="critical",
        confidence=94,
        status="investigating",
        affected_assets=["SERVER-17"],
        alert_count=7,
        sources=["SIEM", "NETWORK_SENSOR", "THREAT_INTEL"],
        mitre_techniques=["T1059.001"],
        evidence=["EV-ALT-1001"],
        bluf="Critical multi-stage activity on SERVER-17.",
        recommended_actions=["Isolate SERVER-17"],
    )

    assert set(Incident.model_fields) == {
        "id",
        "severity",
        "confidence",
        "status",
        "affected_assets",
        "alert_count",
        "sources",
        "mitre_techniques",
        "evidence",
        "bluf",
        "recommended_actions",
    }
    assert incident.mitre_techniques == ["T1059.001"]
