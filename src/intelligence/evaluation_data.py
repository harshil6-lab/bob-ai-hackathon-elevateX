"""Deterministic golden scenarios for intelligence-engine evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Any


@dataclass(frozen=True, slots=True)
class ScenarioExpectations:
    """Independently declared expected behavior for one golden scenario."""

    incident_count: int
    expected_risk_score: int | None = None
    min_risk_score: int | None = None
    max_risk_score: int | None = None
    expected_confidence: int | None = None
    expected_severity: str | None = None
    expected_false_positive_assessment: str | None = None
    expected_mitre_technique_ids: frozenset[str] = frozenset()
    min_alert_count: int | None = None
    min_source_count: int | None = None
    required_evidence_types: frozenset[str] = frozenset()
    required_action_categories: frozenset[str] = frozenset()
    forbidden_action_categories: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class GoldenScenario:
    """One fixed alert batch plus its independently declared expectations."""

    name: str
    description: str
    alerts: tuple[Mapping[str, Any], ...]
    expectations: ScenarioExpectations


def _timestamp(minutes: int) -> str:
    value = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)
    value += timedelta(minutes=minutes)
    return value.isoformat().replace("+00:00", "Z")


def _alert(
    alert_id: str,
    *,
    timestamp: str,
    source: str,
    event_type: str,
    severity: str,
    source_ip: str,
    destination_ip: str,
    host: str,
    user: str,
    description: str,
) -> dict[str, str]:
    return {
        "id": alert_id,
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "host": host,
        "user": user,
        "description": description,
    }


def _multi_source_attack_chain_alerts() -> tuple[dict[str, str], ...]:
    return (
        _alert(
            "ALT-1001",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="ExternalActivity",
            severity="medium",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Suspicious external activity detected",
        ),
        _alert(
            "ALT-1002",
            timestamp=_timestamp(5),
            source="NETWORK_SENSOR",
            event_type="PowerShell",
            severity="high",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Suspicious PowerShell execution",
        ),
        _alert(
            "ALT-1003",
            timestamp=_timestamp(10),
            source="SIEM",
            event_type="SuspiciousProcess",
            severity="high",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Suspicious process launched from PowerShell",
        ),
        _alert(
            "ALT-1004",
            timestamp=_timestamp(15),
            source="THREAT_INTEL",
            event_type="CredentialAccess",
            severity="critical",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Credential dumping detected",
        ),
        _alert(
            "ALT-1005",
            timestamp=_timestamp(20),
            source="NETWORK_SENSOR",
            event_type="RemoteConnection",
            severity="high",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Remote desktop connection established",
        ),
        _alert(
            "ALT-1006",
            timestamp=_timestamp(25),
            source="SIEM",
            event_type="LateralMovement",
            severity="critical",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Lateral movement observed",
        ),
    )


def _likely_false_positive_alerts() -> tuple[dict[str, str], ...]:
    return (
        _alert(
            "ALT-2001",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="AdministrativeTask",
            severity="low",
            source_ip="10.10.2.30",
            destination_ip="10.10.5.18",
            host="WORKSTATION-42",
            user="analyst",
            description="Suspicious scheduled administrative activity",
        ),
        _alert(
            "ALT-2002",
            timestamp=_timestamp(5),
            source="SIEM",
            event_type="AdministrativeTask",
            severity="low",
            source_ip="10.10.2.30",
            destination_ip="10.10.5.18",
            host="WORKSTATION-42",
            user="analyst",
            description="Suspicious scheduled administrative activity",
        ),
    )


def _single_suspicious_alert() -> tuple[dict[str, str], ...]:
    return (
        _alert(
            "ALT-3001",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="PowerShell",
            severity="medium",
            source_ip="10.10.3.40",
            destination_ip="10.10.5.19",
            host="WORKSTATION-43",
            user="service_account",
            description="Suspicious PowerShell execution",
        ),
    )


def _multi_source_corroboration_alerts() -> tuple[dict[str, str], ...]:
    return (
        _alert(
            "ALT-4001",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="PowerShell",
            severity="medium",
            source_ip="10.10.4.50",
            destination_ip="10.10.5.20",
            host="SERVER-18",
            user="admin",
            description="Suspicious PowerShell execution observed independently",
        ),
        _alert(
            "ALT-4002",
            timestamp=_timestamp(3),
            source="NETWORK_SENSOR",
            event_type="PowerShell",
            severity="medium",
            source_ip="10.10.4.50",
            destination_ip="10.10.5.20",
            host="SERVER-18",
            user="admin",
            description="Suspicious PowerShell execution observed independently",
        ),
        _alert(
            "ALT-4003",
            timestamp=_timestamp(6),
            source="THREAT_INTEL",
            event_type="PowerShell",
            severity="medium",
            source_ip="10.10.4.50",
            destination_ip="10.10.5.20",
            host="SERVER-18",
            user="admin",
            description="Suspicious PowerShell execution observed independently",
        ),
    )


def _multiple_independent_incidents_alerts() -> tuple[dict[str, str], ...]:
    attack_chain = _multi_source_attack_chain_alerts()
    single_alert = _single_suspicious_alert()
    shifted_single_alert = {
        **single_alert[0],
        "timestamp": _timestamp(90),
        "host": "WORKSTATION-99",
        "user": "remote_admin",
        "source_ip": "10.10.9.90",
        "destination_ip": "10.10.9.91",
    }
    return attack_chain + (shifted_single_alert,)


GOLDEN_SCENARIOS: tuple[GoldenScenario, ...] = (
    GoldenScenario(
        name="multi_source_attack_chain",
        description=(
            "A correlated multi-source attack chain with PowerShell, "
            "credential access, and remote-service behavior."
        ),
        alerts=_multi_source_attack_chain_alerts(),
        expectations=ScenarioExpectations(
            incident_count=1,
            expected_risk_score=91,
            expected_confidence=100,
            expected_severity="critical",
            expected_false_positive_assessment="likely_genuine",
            expected_mitre_technique_ids=frozenset(
                {"T1003", "T1021", "T1059.001"}
            ),
            min_alert_count=6,
            min_source_count=3,
            required_evidence_types=frozenset(
                {
                    "alert_observation",
                    "suspicious_indicator",
                    "correlation_observation",
                    "attack_progression_observation",
                }
            ),
            required_action_categories=frozenset(
                {
                    "threat_investigation",
                    "credential_access",
                    "remote_services",
                    "powershell_execution",
                    "source_corroboration",
                }
            ),
        ),
    ),
    GoldenScenario(
        name="likely_false_positive",
        description=(
            "A single-source scheduled administrative activity that initially "
            "looks suspicious but is explicitly benign."
        ),
        alerts=_likely_false_positive_alerts(),
        expectations=ScenarioExpectations(
            incident_count=1,
            expected_risk_score=1,
            expected_confidence=15,
            expected_severity="low",
            expected_false_positive_assessment="likely_false_positive",
            expected_mitre_technique_ids=frozenset(),
            min_alert_count=2,
            min_source_count=1,
            required_evidence_types=frozenset(
                {"alert_observation", "correlation_observation"}
            ),
            required_action_categories=frozenset(
                {"activity_review", "false_positive_validation"}
            ),
            forbidden_action_categories=frozenset({"containment_consideration"}),
        ),
    ),
    GoldenScenario(
        name="single_suspicious_alert",
        description=(
            "A single suspicious PowerShell alert that must still produce a "
            "complete incident without requiring correlation."
        ),
        alerts=_single_suspicious_alert(),
        expectations=ScenarioExpectations(
            incident_count=1,
            expected_risk_score=28,
            expected_confidence=25,
            expected_severity="medium",
            expected_false_positive_assessment="likely_genuine",
            expected_mitre_technique_ids=frozenset({"T1059.001"}),
            min_alert_count=1,
            min_source_count=1,
            required_evidence_types=frozenset(
                {"alert_observation", "suspicious_indicator"}
            ),
            required_action_categories=frozenset(
                {"activity_review", "powershell_execution"}
            ),
            forbidden_action_categories=frozenset({"containment_consideration"}),
        ),
    ),
    GoldenScenario(
        name="multi_source_corroboration",
        description=(
            "The same suspicious PowerShell activity observed independently by "
            "three sources."
        ),
        alerts=_multi_source_corroboration_alerts(),
        expectations=ScenarioExpectations(
            incident_count=1,
            expected_risk_score=47,
            expected_confidence=90,
            expected_severity="medium",
            expected_false_positive_assessment="likely_genuine",
            expected_mitre_technique_ids=frozenset({"T1059.001"}),
            min_alert_count=3,
            min_source_count=3,
            required_evidence_types=frozenset(
                {
                    "alert_observation",
                    "suspicious_indicator",
                    "correlation_observation",
                }
            ),
            required_action_categories=frozenset(
                {
                    "activity_review",
                    "powershell_execution",
                    "source_corroboration",
                }
            ),
            forbidden_action_categories=frozenset({"containment_consideration"}),
        ),
    ),
    GoldenScenario(
        name="multiple_independent_incidents",
        description=(
            "A multi-source attack chain and a later single suspicious alert "
            "that must remain separate incidents."
        ),
        alerts=_multiple_independent_incidents_alerts(),
        expectations=ScenarioExpectations(
            incident_count=2,
            expected_mitre_technique_ids=frozenset(
                {"T1003", "T1021", "T1059.001"}
            ),
            min_alert_count=1,
            min_source_count=1,
            required_evidence_types=frozenset(
                {
                    "alert_observation",
                    "suspicious_indicator",
                    "correlation_observation",
                    "attack_progression_observation",
                }
            ),
            required_action_categories=frozenset(
                {"threat_investigation", "powershell_execution"}
            ),
        ),
    ),
)
