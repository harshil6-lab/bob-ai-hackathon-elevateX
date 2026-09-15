from app.repositories import incident_repository
from app.services import stats_service


def test_get_stats_returns_zeroed_dashboard_shape(monkeypatch):
    monkeypatch.setattr(
        incident_repository,
        "get_stats",
        lambda: {
            "total_alerts": 0,
            "total_incidents": 0,
            "alerts_by_severity": {},
            "incidents_by_severity": {},
            "incidents_by_status": {},
            "source_counts": {},
        },
    )

    stats = stats_service.get_stats()

    assert stats == {
        "total_alerts": 0,
        "total_incidents": 0,
        "critical_incidents": 0,
        "high_incidents": 0,
        "severity_distribution": {
            "informational": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        },
        "source_counts": {},
        "status_distribution": {},
    }


def test_get_stats_maps_repository_counts(monkeypatch):
    monkeypatch.setattr(
        incident_repository,
        "get_stats",
        lambda: {
            "total_alerts": 36,
            "total_incidents": 2,
            "alerts_by_severity": {"critical": 5, "high": 10},
            "incidents_by_severity": {"critical": 1, "high": 1},
            "incidents_by_status": {"investigating": 1, "contained": 1},
            "source_counts": {"SIEM": 8, "ENDPOINT_SENSOR": 6},
        },
    )

    stats = stats_service.get_stats()

    assert stats["total_alerts"] == 36
    assert stats["total_incidents"] == 2
    assert stats["critical_incidents"] == 1
    assert stats["high_incidents"] == 1
    assert stats["severity_distribution"] == {
        "informational": 0,
        "low": 0,
        "medium": 0,
        "high": 10,
        "critical": 5,
    }
    assert stats["source_counts"] == {"SIEM": 8, "ENDPOINT_SENSOR": 6}
    assert stats["status_distribution"] == {"investigating": 1, "contained": 1}
