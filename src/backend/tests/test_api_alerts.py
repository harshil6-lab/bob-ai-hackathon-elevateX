from fastapi.testclient import TestClient

from app.main import app
from app.repositories import alert_repository


client = TestClient(app)


def _sample_alert(alert_id: str = "ALT-1001") -> dict:
    return {
        "id": alert_id,
        "timestamp": "2026-09-14T10:20:00Z",
        "source": "SIEM",
        "event_type": "network_connection",
        "severity": "high",
        "source_ip": "203.0.113.55",
        "destination_ip": "10.10.5.17",
        "host": "SERVER-17",
        "user": "admin",
        "description": "Unusual inbound connection",
    }


def test_list_alerts_returns_repository_alerts(monkeypatch):
    monkeypatch.setattr(alert_repository, "get_all_alerts", lambda: [_sample_alert()])

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert response.json() == {"alerts": [_sample_alert()], "count": 1}


def test_list_alerts_returns_empty_list(monkeypatch):
    monkeypatch.setattr(alert_repository, "get_all_alerts", lambda: [])

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert response.json() == {"alerts": [], "count": 0}


def test_get_alert_returns_alert_by_id(monkeypatch):
    monkeypatch.setattr(alert_repository, "get_alert_by_id", lambda alert_id: _sample_alert(alert_id))

    response = client.get("/api/alerts/ALT-1001")

    assert response.status_code == 200
    assert response.json()["id"] == "ALT-1001"


def test_get_alert_returns_404_when_missing(monkeypatch):
    monkeypatch.setattr(alert_repository, "get_alert_by_id", lambda alert_id: None)

    response = client.get("/api/alerts/ALT-404")

    assert response.status_code == 404
    assert response.json() == {"error": "alert not found", "id": "ALT-404"}
