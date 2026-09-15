from typing import Any

from app.repositories import incident_repository


_SEVERITIES = ("informational", "low", "medium", "high", "critical")


def get_stats() -> dict[str, Any]:
    """Build dashboard statistics from persisted data."""

    raw_stats = incident_repository.get_stats()
    alerts_by_severity = raw_stats.get("alerts_by_severity", {})
    incidents_by_severity = raw_stats.get("incidents_by_severity", {})

    return {
        "total_alerts": raw_stats.get("total_alerts", 0),
        "total_incidents": raw_stats.get("total_incidents", 0),
        "critical_incidents": incidents_by_severity.get("critical", 0),
        "high_incidents": incidents_by_severity.get("high", 0),
        "severity_distribution": {
            severity: alerts_by_severity.get(severity, 0)
            for severity in _SEVERITIES
        },
        "source_counts": raw_stats.get("source_counts", {}),
        "status_distribution": raw_stats.get("incidents_by_status", {}),
    }
