"""Canonical field and value contracts for the intelligence layer."""

from typing import Final, Literal


CANONICAL_ALERT_FIELDS: Final[tuple[str, ...]] = (
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
)

CANONICAL_INCIDENT_FIELDS: Final[tuple[str, ...]] = (
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
)

Severity = Literal["low", "medium", "high", "critical"]
IncidentLifecycleStatus = Literal[
    "investigating", "contained", "resolved", "false_positive"
]

ALLOWED_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"low", "medium", "high", "critical"}
)

ALLOWED_INCIDENT_STATUSES: Final[frozenset[str]] = frozenset(
    {"investigating", "contained", "resolved", "false_positive"}
)
