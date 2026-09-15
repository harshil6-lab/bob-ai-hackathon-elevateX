from app.schemas.incident import Incident
from app.services import intelligence_adapter


def _alert(alert_id: str, host: str, source: str = "SIEM") -> dict:
    return {
        "id": alert_id,
        "timestamp": "2026-09-14T10:20:00Z",
        "source": source,
        "event_type": "network_connection",
        "severity": "high",
        "source_ip": "203.0.113.55",
        "destination_ip": "10.10.5.17",
        "host": host,
        "user": "admin",
        "description": "Unusual inbound connection",
    }


def test_mock_groups_alerts_by_host(monkeypatch, caplog):
    monkeypatch.setenv("INTELLIGENCE_MODE", "mock")

    alerts = [
        _alert("ALT-1", "SERVER-17", "SIEM"),
        _alert("ALT-2", "SERVER-17", "ENDPOINT_SENSOR"),
        _alert("ALT-3", "SERVER-12", "NETWORK_SENSOR"),
    ]

    with caplog.at_level("WARNING"):
        incidents = intelligence_adapter.analyze_alerts(alerts)

    assert len(incidents) == 2
    assert incidents[0]["affected_assets"] == ["SERVER-12"]
    assert incidents[1]["affected_assets"] == ["SERVER-17"]
    assert incidents[1]["alert_count"] == 2
    assert incidents[1]["sources"] == ["SIEM", "ENDPOINT_SENSOR"]
    assert incidents[1]["bluf"] == "[MOCK] Multiple alerts correlated on SERVER-17."
    assert "Using MOCK intelligence adapter — real engine not available" in caplog.text


def test_mock_output_matches_incident_schema(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_MODE", "mock")

    incidents = intelligence_adapter.analyze_alerts([_alert("ALT-1", "SERVER-17")])

    assert len(incidents) == 1
    validated = Incident(**incidents[0])
    assert validated.id == "INC-MOCK-001"
    assert validated.severity == "high"
    assert validated.confidence == 50
    assert validated.status == "investigating"


def test_real_engine_is_used_when_available(monkeypatch):
    input_alerts = [_alert("ALT-1", "SERVER-17")]

    class FakeAnalysis:
        def to_public_incidents(self):
            return (
            {
                "id": "INC-REAL-001",
                "severity": "critical",
                "confidence": 99,
                "status": "investigating",
                "affected_assets": ["SERVER-17"],
                    "alert_count": len(input_alerts),
                "sources": ["SIEM"],
                "mitre_techniques": ["T1059.001"],
                    "evidence": [f"EV-{input_alerts[0]['id']}"],
                "bluf": "Real engine output.",
                "recommended_actions": ["Investigate SERVER-17"],
            },
            )

    def fake_engine(alerts: list[dict], provider=None):
        return FakeAnalysis()

    monkeypatch.delenv("INTELLIGENCE_MODE", raising=False)
    monkeypatch.setattr(intelligence_adapter, "_load_real_engine", lambda: fake_engine)

    incidents = intelligence_adapter.analyze_alerts(input_alerts)

    assert incidents[0]["id"] == "INC-REAL-001"
    assert incidents[0]["bluf"] == "Real engine output."


def test_empty_alerts_return_empty_incidents(monkeypatch):
    monkeypatch.setenv("INTELLIGENCE_MODE", "mock")

    assert intelligence_adapter.analyze_alerts([]) == []
