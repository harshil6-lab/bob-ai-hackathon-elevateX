from fastapi.testclient import TestClient

from app.main import app
from app.services import stats_service


client = TestClient(app)


def test_dashboard_stats_returns_service_shape(monkeypatch):
    sample_stats = {
        "total_alerts": 36,
        "total_incidents": 1,
        "critical_incidents": 1,
        "high_incidents": 0,
        "severity_distribution": {
            "informational": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 1,
        },
        "source_counts": {"SIEM": 8},
        "status_distribution": {"investigating": 1},
    }
    monkeypatch.setattr(stats_service, "get_stats", lambda: sample_stats)

    response = client.get("/api/dashboard/stats")

    assert response.status_code == 200
    assert response.json() == sample_stats
