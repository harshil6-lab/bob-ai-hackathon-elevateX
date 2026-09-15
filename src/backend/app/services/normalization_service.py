from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.schemas.alert import Alert


logger = logging.getLogger(__name__)

_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_SOURCE_NAMES = {
    "SIEM_EXPORT": "SIEM",
    "NETWORK_SENSOR": "NETWORK_SENSOR",
    "THREAT_INTEL_FEED": "THREAT_INTEL",
    "ENDPOINT_SENSOR": "ENDPOINT_SENSOR",
    "INTEL_REPORT": "INTEL_REPORT",
}
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def normalize_alerts(raw_records: list[dict[str, Any]]) -> list[Alert]:
    """Convert ingested raw records into canonical Alert objects."""

    report_date = _extract_report_date(raw_records)
    alerts: list[Alert] = []

    for raw_record in raw_records:
        alert = _normalize_record(raw_record, report_date)
        if alert is not None:
            alerts.append(alert)

    return alerts


def normalize_alert(raw_record: dict[str, Any], report_date: datetime | None = None) -> Alert | None:
    """Convert one ingested raw record into a canonical Alert object."""

    return _normalize_record(raw_record, report_date)


def _normalize_record(raw_record: dict[str, Any], report_date: datetime | None) -> Alert | None:
    source_name = _source_name(raw_record.get("source"))
    raw_payload = raw_record.get("raw")

    if source_name == "SIEM":
        normalized = _normalize_siem_record(raw_payload)
    elif source_name == "NETWORK_SENSOR":
        normalized = _normalize_network_record(raw_payload)
    elif source_name == "THREAT_INTEL":
        normalized = _normalize_threat_intel_record(raw_payload)
    elif source_name == "ENDPOINT_SENSOR":
        normalized = _normalize_endpoint_record(raw_payload)
    elif source_name == "INTEL_REPORT":
        normalized = _normalize_intel_report_record(raw_payload, report_date)
    else:
        logger.warning("Skipping raw record from unknown source: %s", source_name)
        return None

    if normalized is None:
        return None

    if normalized.get("timestamp") is None or normalized.get("event_type") is None:
        logger.warning("Skipping raw record with missing timestamp or event_type: %s", raw_payload)
        return None

    normalized["id"] = _stable_id(source_name, raw_payload)
    normalized["source"] = source_name
    normalized["severity"] = _normalize_severity(normalized.get("severity"))
    return Alert(**normalized)


def _normalize_siem_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    return {
        "timestamp": _parse_timestamp(raw.get("detected_at")),
        "event_type": raw.get("category"),
        "severity": raw.get("priority"),
        "source_ip": raw.get("src_ip"),
        "destination_ip": raw.get("dst_ip"),
        "host": raw.get("endpoint"),
        "user": raw.get("account"),
        "description": raw.get("summary"),
    }


def _normalize_network_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, str):
        return None

    parts = [part.strip() for part in raw.split("|")]
    if len(parts) < 4:
        return None

    fields: dict[str, str] = {}
    for part in parts[3:]:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key.strip()] = value.strip()

    return {
        "timestamp": _parse_timestamp(parts[0]),
        "event_type": parts[1],
        "severity": parts[2],
        "source_ip": fields.get("src"),
        "destination_ip": fields.get("dst"),
        "host": fields.get("host"),
        "user": fields.get("user"),
        "description": fields.get("desc"),
    }


def _normalize_threat_intel_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    indicator_type = raw.get("type")
    indicator_value = raw.get("value")
    tags = raw.get("tags", [])
    description = f"Threat intelligence indicator: {indicator_value}"
    if tags:
        description += f"; tags: {', '.join(tags)}"

    timestamp = raw.get("last_seen") or raw.get("first_seen")

    return {
        "timestamp": _parse_timestamp(timestamp),
        "event_type": "indicator",
        "severity": raw.get("severity"),
        "source_ip": indicator_value if indicator_type == "ipv4" else None,
        "destination_ip": None,
        "host": None,
        "user": None,
        "description": description,
    }


def _normalize_endpoint_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    return {
        "timestamp": _parse_timestamp(raw.get("observed_at")),
        "event_type": raw.get("category"),
        "severity": raw.get("severity"),
        "source_ip": None,
        "destination_ip": None,
        "host": raw.get("host"),
        "user": raw.get("user"),
        "description": raw.get("description"),
    }


def _normalize_intel_report_record(raw: Any, report_date: datetime | None) -> dict[str, Any] | None:
    if not isinstance(raw, str):
        return None

    ipv4_match = _IPV4_PATTERN.search(raw)

    return {
        "timestamp": report_date,
        "event_type": "intel_report",
        "severity": "informational",
        "source_ip": ipv4_match.group(0) if ipv4_match else None,
        "destination_ip": None,
        "host": None,
        "user": None,
        "description": raw,
    }


def _source_name(source: Any) -> str:
    if not isinstance(source, str):
        return ""
    return _SOURCE_NAMES.get(source.upper(), source.upper())


def _normalize_severity(severity: Any) -> str:
    if not isinstance(severity, str):
        return "informational"

    normalized = severity.strip().lower()
    if normalized == "info":
        normalized = "informational"

    return normalized if normalized in _SEVERITIES else "informational"


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_report_date(raw_records: list[dict[str, Any]]) -> datetime | None:
    for raw_record in raw_records:
        if _source_name(raw_record.get("source")) != "INTEL_REPORT":
            continue
        raw = raw_record.get("raw")
        if not isinstance(raw, str) or not raw.startswith("REPORT DATE:"):
            continue
        date_value = raw.split(":", 1)[1].strip()
        try:
            return datetime.fromisoformat(date_value).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _stable_id(source_name: str, raw_payload: Any) -> str:
    serialized = json.dumps(
        {"source": source_name, "raw": raw_payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return f"ALT-{digest[:12].upper()}"
