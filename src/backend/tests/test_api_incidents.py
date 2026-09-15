from fastapi.testclient import TestClient

from app.main import app
from app.repositories import incident_repository


client = TestClient(app)


def _sample_incident(incident_id: str = "INC-001") -> dict:
    return {
        "id": incident_id,
        "severity": "critical",
        "confidence": 94,
        "status": "investigating",
        "affected_assets": ["SERVER-17"],
        "alert_count": 7,
        "sources": ["SIEM", "NETWORK_SENSOR", "THREAT_INTEL", "ENDPOINT_SENSOR"],
        "mitre_techniques": ["T1059.001", "T1003.001", "T1021.001"],
        "evidence": ["EV-ALT-1001"],
        "bluf": "Critical multi-stage activity affected SERVER-17 and moved laterally toward SERVER-12.",
        "recommended_actions": [
            "Isolate SERVER-17",
            "Review lateral movement to SERVER-12",
            "Reset potentially exposed credentials",
        ],
    }


def test_list_incidents_returns_repository_incidents(monkeypatch):
    monkeypatch.setattr(incident_repository, "get_all_incidents", lambda: [_sample_incident()])

    response = client.get("/api/incidents")

    assert response.status_code == 200
    assert response.json() == {"incidents": [_sample_incident()], "count": 1}


def test_list_incidents_returns_empty_list(monkeypatch):
    monkeypatch.setattr(incident_repository, "get_all_incidents", lambda: [])

    response = client.get("/api/incidents")

    assert response.status_code == 200
    assert response.json() == {"incidents": [], "count": 0}


def test_get_incident_returns_incident_by_id(monkeypatch):
    monkeypatch.setattr(
        incident_repository,
        "get_incident_by_id",
        lambda incident_id: _sample_incident(incident_id),
    )

    response = client.get("/api/incidents/INC-001")

    assert response.status_code == 200
    assert response.json()["id"] == "INC-001"


def test_get_incident_returns_404_when_missing(monkeypatch):
    monkeypatch.setattr(incident_repository, "get_incident_by_id", lambda incident_id: None)

    response = client.get("/api/incidents/INC-404")

    assert response.status_code == 404
    assert response.json() == {"error": "incident not found", "id": "INC-404"}
