"""Deterministic alert correlation for the D2 intelligence engine.

This module answers one question only: which alerts appear to belong to the
same underlying activity? It does not calculate incident severity, incident
confidence, or false-positive classification. Those decisions belong to later
intelligence stages.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Any, Final, cast

from .contracts import Severity
from .models import Alert
from .validation import validate_alerts


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    """Centralized prototype heuristics for deterministic correlation.

    The weights and threshold are intentionally separate from threat scoring.
    They describe relationship strength only, not incident severity or
    analyst confidence.
    """

    time_window: timedelta = timedelta(minutes=45)
    relationship_threshold: int = 3
    time_window_weight: int = 1
    same_host_weight: int = 2
    same_source_ip_weight: int = 2
    same_user_weight: int = 2
    same_network_pair_weight: int = 3
    attack_progression_weight: int = 3
    progression_stage_gap: int = 1


DEFAULT_CORRELATION_CONFIG: Final[CorrelationConfig] = CorrelationConfig()


@dataclass(frozen=True, slots=True)
class AlertRelationship:
    """A deterministic relationship between two correlated alerts."""

    left_alert_id: str
    right_alert_id: str
    reasons: tuple[str, ...]
    relationship_score: int


@dataclass(frozen=True, slots=True)
class CorrelatedAlertGroup:
    """An internal correlated group suitable for later scoring stages."""

    group_id: str
    alert_ids: tuple[str, ...]
    alerts: tuple[Alert, ...]
    relationships: tuple[AlertRelationship, ...]
    correlation_reasons: tuple[str, ...]
    started_at: datetime
    ended_at: datetime


_PROGRESSION_STAGES: Final[tuple[tuple[str, tuple[re.Pattern[str], ...]], ...]] = (
    (
        "external_suspicious_activity",
        (
            re.compile(r"external\s+suspicious\s+activity", re.IGNORECASE),
            re.compile(r"suspicious\s+external\s+activity", re.IGNORECASE),
            re.compile(r"external\s+reconnaissance", re.IGNORECASE),
        ),
    ),
    (
        "powershell_execution",
        (re.compile(r"powershell", re.IGNORECASE),),
    ),
    (
        "suspicious_process",
        (
            re.compile(r"suspicious\s+process", re.IGNORECASE),
            re.compile(r"malicious\s+process", re.IGNORECASE),
            re.compile(r"process\s+injection", re.IGNORECASE),
        ),
    ),
    (
        "credential_access",
        (
            re.compile(r"credential\s+access", re.IGNORECASE),
            re.compile(r"credential\s+dumping", re.IGNORECASE),
            re.compile(r"lsass", re.IGNORECASE),
            re.compile(r"kerberoasting", re.IGNORECASE),
        ),
    ),
    (
        "remote_connection",
        (
            re.compile(r"remote\s+connection", re.IGNORECASE),
            re.compile(r"remote\s+desktop", re.IGNORECASE),
            re.compile(r"\brdp\b", re.IGNORECASE),
            re.compile(r"\bssh\b", re.IGNORECASE),
        ),
    ),
    (
        "lateral_movement",
        (
            re.compile(r"lateral\s+movement", re.IGNORECASE),
            re.compile(r"\bpsexec\b", re.IGNORECASE),
            re.compile(r"\bsmb\b", re.IGNORECASE),
        ),
    ),
)


def correlate_alerts(
    alerts: Iterable[Mapping[str, Any]],
    config: CorrelationConfig = DEFAULT_CORRELATION_CONFIG,
) -> tuple[CorrelatedAlertGroup, ...]:
    """Correlate validated canonical alerts into deterministic groups.

    Input order does not affect logical grouping. Alerts are canonicalized by
    timestamp and ID before relationships are evaluated. The caller's input is
    never mutated.
    """

    alert_mappings = list(alerts)
    validate_alerts(alert_mappings)

    parsed_alerts = tuple(_parse_alert(alert) for alert in alert_mappings)
    sorted_alerts = tuple(
        sorted(parsed_alerts, key=lambda alert: (alert.timestamp, alert.id))
    )

    if not sorted_alerts:
        return ()

    parent = list(range(len(sorted_alerts)))
    relationships: list[AlertRelationship] = []

    for left_index, left_alert in enumerate(sorted_alerts):
        for right_index in range(left_index + 1, len(sorted_alerts)):
            right_alert = sorted_alerts[right_index]
            time_difference = right_alert.timestamp - left_alert.timestamp
            if time_difference > config.time_window:
                break

            reasons, score = _evaluate_relationship(left_alert, right_alert, config)
            if score < config.relationship_threshold:
                continue

            relationship = AlertRelationship(
                left_alert_id=left_alert.id,
                right_alert_id=right_alert.id,
                reasons=reasons,
                relationship_score=score,
            )
            relationships.append(relationship)
            _union(parent, left_index, right_index)

    grouped_indices: dict[int, list[int]] = {}
    for index in range(len(sorted_alerts)):
        root = _find(parent, index)
        grouped_indices.setdefault(root, []).append(index)

    groups: list[CorrelatedAlertGroup] = []
    for indices in grouped_indices.values():
        group_alerts = tuple(sorted_alerts[index] for index in indices)
        group_relationships = tuple(
            relationship
            for relationship in relationships
            if relationship.left_alert_id in {alert.id for alert in group_alerts}
            and relationship.right_alert_id in {alert.id for alert in group_alerts}
        )
        sorted_relationships = tuple(
            sorted(
                group_relationships,
                key=lambda relationship: (
                    relationship.left_alert_id,
                    relationship.right_alert_id,
                ),
            )
        )
        alert_ids = tuple(alert.id for alert in group_alerts)
        correlation_reasons = tuple(
            sorted(
                {
                    reason
                    for relationship in sorted_relationships
                    for reason in relationship.reasons
                }
            )
        )
        groups.append(
            CorrelatedAlertGroup(
                group_id=_group_id(alert_ids),
                alert_ids=alert_ids,
                alerts=group_alerts,
                relationships=sorted_relationships,
                correlation_reasons=correlation_reasons,
                started_at=group_alerts[0].timestamp,
                ended_at=group_alerts[-1].timestamp,
            )
        )

    return tuple(
        sorted(
            groups,
            key=lambda group: (group.started_at, group.alert_ids[0], group.group_id),
        )
    )


def _parse_alert(alert: Mapping[str, Any]) -> Alert:
    return Alert(
        id=str(alert["id"]),
        timestamp=_parse_timestamp(str(alert["timestamp"])),
        source=str(alert["source"]),
        event_type=str(alert["event_type"]),
        severity=cast(Severity, str(alert["severity"])),
        source_ip=str(alert["source_ip"]),
        destination_ip=str(alert["destination_ip"]),
        host=str(alert["host"]),
        user=str(alert["user"]),
        description=str(alert["description"]),
    )


def _parse_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _evaluate_relationship(
    left_alert: Alert, right_alert: Alert, config: CorrelationConfig
) -> tuple[tuple[str, ...], int]:
    reasons: list[str] = []
    score = 0

    reasons.append("within_time_window")
    score += config.time_window_weight

    if left_alert.host and left_alert.host == right_alert.host:
        reasons.append("same_host")
        score += config.same_host_weight

    if left_alert.source_ip and left_alert.source_ip == right_alert.source_ip:
        reasons.append("same_source_ip")
        score += config.same_source_ip_weight

    if left_alert.user and left_alert.user == right_alert.user:
        reasons.append("same_user")
        score += config.same_user_weight

    if (
        left_alert.source_ip
        and left_alert.destination_ip
        and left_alert.source_ip == right_alert.source_ip
        and left_alert.destination_ip == right_alert.destination_ip
    ):
        reasons.append("same_network_pair")
        score += config.same_network_pair_weight

    left_stage = _progression_stage(left_alert)
    right_stage = _progression_stage(right_alert)
    if (
        left_stage is not None
        and right_stage is not None
        and abs(left_stage - right_stage) == config.progression_stage_gap
    ):
        reasons.append("attack_progression")
        score += config.attack_progression_weight

    return tuple(reasons), score


def _progression_stage(alert: Alert) -> int | None:
    searchable_text = f"{alert.event_type} {alert.description}"
    for stage_index, (_, patterns) in enumerate(_PROGRESSION_STAGES):
        if any(pattern.search(searchable_text) for pattern in patterns):
            return stage_index
    return None


def _group_id(alert_ids: tuple[str, ...]) -> str:
    canonical_membership = "\n".join(sorted(alert_ids))
    digest = hashlib.sha256(canonical_membership.encode("utf-8")).hexdigest()
    return f"GRP-{digest[:16].upper()}"


def _find(parent: list[int], index: int) -> int:
    if parent[index] != index:
        parent[index] = _find(parent, parent[index])
    return parent[index]


def _union(parent: list[int], left_index: int, right_index: int) -> None:
    left_root = _find(parent, left_index)
    right_root = _find(parent, right_index)
    if left_root != right_root:
        parent[right_root] = left_root
