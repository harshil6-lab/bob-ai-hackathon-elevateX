from datetime import datetime, timezone

from app.services.normalization_service import normalize_alert, normalize_alerts


def test_normalizes_siem_record():
    raw = {
        "detected_at": "2026-09-14T10:20:00Z",
        "category": "network_connection",
        "priority": "high",
        "src_ip": "203.0.113.55",
        "dst_ip": "10.10.5.17",
        "endpoint": "SERVER-17",
        "account": "admin",
        "summary": "Unusual inbound connection",
    }

    alert = normalize_alert({"source": "SIEM_EXPORT", "raw": raw})

    assert alert is not None
    assert alert.source == "SIEM"
    assert alert.event_type == "network_connection"
    assert alert.severity == "high"
    assert alert.source_ip == "203.0.113.55"
    assert alert.destination_ip == "10.10.5.17"
    assert alert.host == "SERVER-17"
    assert alert.user == "admin"
    assert alert.description == "Unusual inbound connection"


def test_normalizes_threat_intel_indicator():
    raw = {
        "type": "ipv4",
        "value": "203.0.113.55",
        "severity": "high",
        "tags": ["initial-access"],
        "first_seen": "2026-09-12T14:00:00Z",
        "last_seen": "2026-09-14T09:45:00Z",
    }

    alert = normalize_alert({"source": "THREAT_INTEL_FEED", "raw": raw})

    assert alert is not None
    assert alert.source == "THREAT_INTEL"
    assert alert.event_type == "indicator"
    assert alert.source_ip == "203.0.113.55"
    assert alert.destination_ip is None
    assert alert.host is None
    assert alert.user is None
    assert "203.0.113.55" in alert.description


def test_normalizes_endpoint_record():
    raw = {
        "observed_at": "2026-09-14T10:32:00Z",
        "host": "SERVER-17",
        "user": "admin",
        "category": "process_execution",
        "severity": "high",
        "description": "PowerShell launched with encoded command",
    }

    alert = normalize_alert({"source": "ENDPOINT_SENSOR", "raw": raw})

    assert alert is not None
    assert alert.source == "ENDPOINT_SENSOR"
    assert alert.event_type == "process_execution"
    assert alert.host == "SERVER-17"
    assert alert.user == "admin"
    assert alert.source_ip is None
    assert alert.destination_ip is None


def test_normalizes_network_log_record():
    raw = (
        "2026-09-14T10:47:00Z | remote_connection | high | "
        "src=10.10.5.17 | dst=10.10.5.12 | host=SERVER-17 | "
        "user=admin | desc=Outbound RDP session"
    )

    alert = normalize_alert({"source": "NETWORK_SENSOR", "raw": raw})

    assert alert is not None
    assert alert.source == "NETWORK_SENSOR"
    assert alert.event_type == "remote_connection"
    assert alert.severity == "high"
    assert alert.source_ip == "10.10.5.17"
    assert alert.destination_ip == "10.10.5.12"
    assert alert.host == "SERVER-17"
    assert alert.user == "admin"
    assert alert.description == "Outbound RDP session"


def test_normalizes_intel_report_line_with_report_date():
    records = [
        {"source": "INTEL_REPORT", "raw": "REPORT DATE: 2026-09-14"},
        {"source": "INTEL_REPORT", "raw": "- IPv4: 203.0.113.55"},
    ]

    alerts = normalize_alerts(records)

    assert len(alerts) == 2
    report_alert = alerts[1]
    assert report_alert.timestamp == datetime(2026, 9, 14, tzinfo=timezone.utc)
    assert report_alert.event_type == "intel_report"
    assert report_alert.severity == "informational"
    assert report_alert.source_ip == "203.0.113.55"


def test_ids_are_deterministic_and_distinct_by_source():
    raw = {
        "detected_at": "2026-09-14T10:20:00Z",
        "category": "network_connection",
        "priority": "high",
        "src_ip": "203.0.113.55",
        "dst_ip": "10.10.5.17",
        "endpoint": "SERVER-17",
        "account": "admin",
        "summary": "Unusual inbound connection",
    }
    first = normalize_alert({"source": "SIEM_EXPORT", "raw": raw})
    second = normalize_alert({"source": "SIEM_EXPORT", "raw": raw})
    endpoint_raw = {
        "observed_at": "2026-09-14T10:32:00Z",
        "host": "SERVER-17",
        "user": "admin",
        "category": "process_execution",
        "severity": "high",
        "description": "PowerShell launched with encoded command",
    }
    different_source = normalize_alert({"source": "ENDPOINT_SENSOR", "raw": endpoint_raw})

    assert first is not None and second is not None and different_source is not None
    assert first.id == second.id
    assert first.id != different_source.id


def test_normalizes_info_alias_and_unknown_severity():
    raw = {
        "detected_at": "2026-09-14T10:20:00Z",
        "category": "software_update",
        "priority": "info",
    }
    alert = normalize_alert({"source": "SIEM_EXPORT", "raw": raw})
    assert alert is not None
    assert alert.severity == "informational"

    raw["priority"] = "unknown"
    alert = normalize_alert({"source": "SIEM_EXPORT", "raw": raw})
    assert alert is not None
    assert alert.severity == "informational"
