"""Deterministic evidence extraction for correlated alert groups.

Evidence is not inference. This module structures facts that already exist in
validated alerts and correlation results. It never invents hosts, users, IPs,
event types, MITRE techniques, or conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import re
from typing import Final

from .correlation import AlertRelationship, CorrelatedAlertGroup
from .models import Alert, Evidence


class EvidenceType(str, Enum):
    """Controlled internal evidence taxonomy."""

    ALERT_OBSERVATION = "alert_observation"
    SUSPICIOUS_INDICATOR = "suspicious_indicator"
    CORRELATION_OBSERVATION = "correlation_observation"
    ATTACK_PROGRESSION_OBSERVATION = "attack_progression_observation"


@dataclass(frozen=True, slots=True)
class EvidenceCollection:
    """Internal deterministic evidence result for one correlated group."""

    group_id: str
    records: tuple[Evidence, ...]
    evidence_ids: tuple[str, ...]
    alert_ids: tuple[str, ...]
    alert_evidence_ids: tuple[tuple[str, tuple[str, ...]], ...]


_SUSPICIOUS_INDICATORS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "PowerShell execution",
        re.compile(r"powershell", re.IGNORECASE),
    ),
    (
        "credential access",
        re.compile(r"credential\s+access|credential\s+dumping|lsass|kerberoasting", re.IGNORECASE),
    ),
    (
        "suspicious process",
        re.compile(r"suspicious\s+process|malicious\s+process|process\s+injection", re.IGNORECASE),
    ),
    (
        "remote connection",
        re.compile(r"remote\s+connection|remote\s+desktop|\brdp\b|\bssh\b", re.IGNORECASE),
    ),
    (
        "lateral movement",
        re.compile(r"lateral\s+movement|\bpsexec\b|\bsmb\b", re.IGNORECASE),
    ),
    (
        "suspicious IP indicator",
        re.compile(r"suspicious\s+ip|malicious\s+ip", re.IGNORECASE),
    ),
    (
        "threat-intelligence indicator",
        re.compile(r"threat\s+intel|indicator\s+of\s+compromise|\bioc\b", re.IGNORECASE),
    ),
)


def extract_evidence(group: CorrelatedAlertGroup) -> EvidenceCollection:
    """Extract deterministic, traceable evidence from a correlated group."""

    alert_by_id = {alert.id: alert for alert in group.alerts}
    records_by_id: dict[str, Evidence] = {}

    for alert in group.alerts:
        observation = _alert_observation(alert)
        records_by_id[observation.evidence_id] = observation

        for indicator_name, pattern in _SUSPICIOUS_INDICATORS:
            if not pattern.search(f"{alert.event_type} {alert.description}"):
                continue
            indicator = _suspicious_indicator_evidence(alert, indicator_name)
            records_by_id[indicator.evidence_id] = indicator

    for relationship in group.relationships:
        for alert_id in (relationship.left_alert_id, relationship.right_alert_id):
            alert = alert_by_id[alert_id]
            counterpart_id = (
                relationship.right_alert_id
                if alert_id == relationship.left_alert_id
                else relationship.left_alert_id
            )
            counterpart = alert_by_id[counterpart_id]

            non_progression_reasons = tuple(
                reason
                for reason in relationship.reasons
                if reason != "attack_progression"
            )
            if non_progression_reasons:
                correlation = _correlation_evidence(
                    alert,
                    counterpart,
                    non_progression_reasons,
                )
                records_by_id[correlation.evidence_id] = correlation

            if "attack_progression" in relationship.reasons:
                progression = _attack_progression_evidence(alert, counterpart)
                records_by_id[progression.evidence_id] = progression

    records = tuple(
        sorted(records_by_id.values(), key=lambda evidence: evidence.evidence_id)
    )
    evidence_ids = tuple(evidence.evidence_id for evidence in records)
    alert_ids = tuple(sorted(alert_by_id))
    alert_evidence_ids = tuple(
        (
            alert_id,
            tuple(
                evidence.evidence_id
                for evidence in records
                if evidence.alert_id == alert_id
            ),
        )
        for alert_id in alert_ids
    )

    return EvidenceCollection(
        group_id=group.group_id,
        records=records,
        evidence_ids=evidence_ids,
        alert_ids=alert_ids,
        alert_evidence_ids=alert_evidence_ids,
    )


def _alert_observation(alert: Alert) -> Evidence:
    return Evidence(
        evidence_id=_evidence_id(EvidenceType.ALERT_OBSERVATION, alert.id),
        alert_id=alert.id,
        timestamp=alert.timestamp,
        source=alert.source,
        event_type=alert.event_type,
        host=alert.host,
        user=alert.user,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        description=alert.description,
        rationale=f"{alert.event_type} was observed in {alert.id}.",
        evidence_type=EvidenceType.ALERT_OBSERVATION.value,
    )


def _suspicious_indicator_evidence(
    alert: Alert, indicator_name: str
) -> Evidence:
    return Evidence(
        evidence_id=_evidence_id(
            EvidenceType.SUSPICIOUS_INDICATOR,
            alert.id,
            context=indicator_name,
        ),
        alert_id=alert.id,
        timestamp=alert.timestamp,
        source=alert.source,
        event_type=alert.event_type,
        host=alert.host,
        user=alert.user,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        description=alert.description,
        rationale=f"{alert.id} contains a recognized {indicator_name} indicator.",
        evidence_type=EvidenceType.SUSPICIOUS_INDICATOR.value,
    )


def _correlation_evidence(
    alert: Alert, counterpart: Alert, reasons: tuple[str, ...]
) -> Evidence:
    rationale_parts: list[str] = []
    if "same_host" in reasons and alert.host:
        rationale_parts.append(f"share host {alert.host}")
    if "same_source_ip" in reasons and alert.source_ip:
        rationale_parts.append(f"share source IP {alert.source_ip}")
    if "same_user" in reasons and alert.user:
        rationale_parts.append(f"share user {alert.user}")
    if (
        "same_network_pair" in reasons
        and alert.source_ip
        and alert.destination_ip
    ):
        rationale_parts.append(
            f"share network pair {alert.source_ip} to {alert.destination_ip}"
        )
    if "within_time_window" in reasons:
        rationale_parts.append("occur within the correlation time window")

    if not rationale_parts:
        rationale_parts.append("are correlated")

    rationale = (
        f"{alert.id} and {counterpart.id} "
        + ", ".join(rationale_parts[:-1])
        + (", and " if len(rationale_parts) > 1 else "")
        + rationale_parts[-1]
        + "."
    )
    context = f"{counterpart.id}|{'|'.join(sorted(reasons))}"

    return Evidence(
        evidence_id=_evidence_id(
            EvidenceType.CORRELATION_OBSERVATION,
            alert.id,
            context=context,
        ),
        alert_id=alert.id,
        timestamp=alert.timestamp,
        source=alert.source,
        event_type=alert.event_type,
        host=alert.host,
        user=alert.user,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        description=alert.description,
        rationale=rationale,
        evidence_type=EvidenceType.CORRELATION_OBSERVATION.value,
    )


def _attack_progression_evidence(
    alert: Alert, counterpart: Alert
) -> Evidence:
    context = f"{counterpart.id}|attack_progression"
    if alert.timestamp <= counterpart.timestamp:
        earlier_event = alert.event_type
        later_event = counterpart.event_type
    else:
        earlier_event = counterpart.event_type
        later_event = alert.event_type
    return Evidence(
        evidence_id=_evidence_id(
            EvidenceType.ATTACK_PROGRESSION_OBSERVATION,
            alert.id,
            context=context,
        ),
        alert_id=alert.id,
        timestamp=alert.timestamp,
        source=alert.source,
        event_type=alert.event_type,
        host=alert.host,
        user=alert.user,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        description=alert.description,
        rationale=(
            f"{alert.id} and {counterpart.id} show attack progression "
            f"from {earlier_event} to {later_event}."
        ),
        evidence_type=EvidenceType.ATTACK_PROGRESSION_OBSERVATION.value,
    )


def _evidence_id(
    evidence_type: EvidenceType,
    alert_id: str,
    context: str = "",
) -> str:
    canonical = f"{evidence_type.value}|{alert_id}|{context}"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"EV-{digest[:16].upper()}"
