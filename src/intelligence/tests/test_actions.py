from copy import deepcopy
from datetime import datetime, timedelta, timezone
import re
import unittest

from src.intelligence.actions import generate_recommended_actions
from src.intelligence.ai.context import build_ai_context
from src.intelligence.contracts import CANONICAL_INCIDENT_FIELDS
from src.intelligence.correlation import correlate_alerts
from src.intelligence.evidence import EvidenceCollection, extract_evidence
from src.intelligence.mitre import map_mitre_behaviors
from src.intelligence.models import IncidentRecord
from src.intelligence.scoring import assess_threat


def _timestamp(minutes: int = 0) -> str:
    value = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)
    value += timedelta(minutes=minutes)
    return value.isoformat().replace("+00:00", "Z")


def _alert(
    alert_id: str,
    *,
    timestamp: str | None = None,
    source: str = "SIEM",
    event_type: str = "PowerShell",
    severity: str = "medium",
    source_ip: str = "10.10.1.20",
    destination_ip: str = "10.10.5.17",
    host: str = "SERVER-17",
    user: str = "admin",
    description: str = "Suspicious PowerShell execution",
) -> dict[str, str]:
    return {
        "id": alert_id,
        "timestamp": timestamp or _timestamp(),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "host": host,
        "user": user,
        "description": description,
    }


def _golden_scenario() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-1001",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="ExternalActivity",
            severity="medium",
            description="Suspicious external activity detected",
        ),
        _alert(
            "ALT-1002",
            timestamp=_timestamp(5),
            source="NETWORK_SENSOR",
            event_type="PowerShell",
            severity="high",
            description="Suspicious PowerShell execution",
        ),
        _alert(
            "ALT-1003",
            timestamp=_timestamp(10),
            source="SIEM",
            event_type="SuspiciousProcess",
            severity="high",
            description="Suspicious process launched from PowerShell",
        ),
        _alert(
            "ALT-1004",
            timestamp=_timestamp(15),
            source="THREAT_INTEL",
            event_type="CredentialAccess",
            severity="critical",
            description="Credential dumping detected",
        ),
        _alert(
            "ALT-1005",
            timestamp=_timestamp(20),
            source="NETWORK_SENSOR",
            event_type="RemoteConnection",
            severity="high",
            description="Remote desktop connection established",
        ),
        _alert(
            "ALT-1006",
            timestamp=_timestamp(25),
            source="SIEM",
            event_type="LateralMovement",
            severity="critical",
            description="Lateral movement observed",
        ),
    ]


def _high_scenario() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-2001",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="PowerShell",
            severity="high",
            description="Suspicious PowerShell execution",
        ),
        _alert(
            "ALT-2002",
            timestamp=_timestamp(5),
            source="NETWORK_SENSOR",
            event_type="SuspiciousProcess",
            severity="high",
            description="Suspicious process launched from PowerShell",
        ),
        _alert(
            "ALT-2003",
            timestamp=_timestamp(10),
            source="THREAT_INTEL",
            event_type="CredentialAccess",
            severity="high",
            description="Credential access detected",
        ),
    ]


def _first_group(alerts: list[dict[str, str]]):
    groups = correlate_alerts(alerts)
    if not groups:
        raise AssertionError("Expected at least one correlated group")
    return groups[0]


def _empty_evidence(group) -> EvidenceCollection:
    return EvidenceCollection(
        group_id=group.group_id,
        records=(),
        evidence_ids=(),
        alert_ids=tuple(alert.id for alert in group.alerts),
        alert_evidence_ids=tuple((alert.id, ()) for alert in group.alerts),
    )


def _context(
    alerts: list[dict[str, str]],
    *,
    empty_evidence: bool = False,
):
    group = _first_group(alerts)
    evidence = _empty_evidence(group) if empty_evidence else extract_evidence(group)
    mitre = map_mitre_behaviors(group.alerts, evidence)
    assessment = assess_threat(group)
    return build_ai_context(group, assessment, evidence, mitre)


class RecommendedActionsTests(unittest.TestCase):
    def test_critical_threat_generates_highest_priority_actions(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        self.assertEqual(actions[0].priority, "critical")
        self.assertTrue(
            any(action.category == "containment_consideration" for action in actions)
        )

    def test_high_threat_generates_high_priority_investigation(self) -> None:
        context = _context(_high_scenario())

        actions = generate_recommended_actions(context).actions

        self.assertEqual(context.scoring.severity, "high")
        self.assertTrue(
            any(
                action.category == "threat_investigation"
                and action.priority == "high"
                for action in actions
            )
        )

    def test_medium_or_low_threat_avoids_aggressive_containment(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-MEDIUM-1",
                    event_type="UnknownActivity",
                    severity="medium",
                    description="Unrecognized activity",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertIn(context.scoring.severity, {"medium", "low"})
        self.assertFalse(
            any(action.category == "containment_consideration" for action in actions)
        )

    def test_likely_false_positive_prioritizes_validation_not_containment(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-BENIGN-1",
                    event_type="HealthCheck",
                    severity="low",
                    description="Routine monitoring health check",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertEqual(
            context.scoring.false_positive_assessment,
            "likely_false_positive",
        )
        self.assertTrue(
            any(action.category == "false_positive_validation" for action in actions)
        )
        self.assertFalse(
            any(action.category == "containment_consideration" for action in actions)
        )

    def test_t1003_generates_credential_access_action(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-CRED-1",
                    event_type="CredentialAccess",
                    severity="critical",
                    description="Credential dumping detected",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertTrue(
            any(
                action.category == "credential_access"
                and action.mitre_technique_ids == ("T1003",)
                for action in actions
            )
        )

    def test_t1021_generates_remote_services_action(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-REMOTE-1",
                    event_type="RemoteConnection",
                    severity="high",
                    description="Remote desktop connection established",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertTrue(
            any(
                action.category == "remote_services"
                and action.mitre_technique_ids == ("T1021",)
                for action in actions
            )
        )

    def test_t1059_001_generates_powershell_action(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-PS-1",
                    event_type="PowerShell",
                    severity="medium",
                    description="Suspicious PowerShell execution",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertTrue(
            any(
                action.category == "powershell_execution"
                and action.mitre_technique_ids == ("T1059.001",)
                for action in actions
            )
        )

    def test_multiple_techniques_generate_multiple_actions(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        technique_actions = [
            action for action in actions if action.mitre_technique_ids
        ]
        self.assertEqual(len(technique_actions), 3)

    def test_actions_reference_only_supplied_evidence(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        for action in actions:
            self.assertTrue(set(action.evidence_ids).issubset(context.evidence_ids))
        self.assertTrue(
            any(action.evidence_ids for action in actions if action.mitre_technique_ids)
        )

    def test_actions_reference_only_supplied_alerts(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        for action in actions:
            self.assertTrue(set(action.alert_ids).issubset(context.alert_ids))
        self.assertTrue(all(action.alert_ids for action in actions))

    def test_actions_are_deterministically_ordered(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        self.assertEqual(
            actions,
            tuple(
                sorted(
                    actions,
                    key=lambda action: (
                        {"critical": 0, "high": 1, "medium": 2, "low": 3}[
                            action.priority
                        ],
                        action.action_id,
                    ),
                )
            ),
        )

    def test_no_fabricated_identifiers_are_generated(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        for action in actions:
            self.assertNotIn("ALT-UNKNOWN", action.alert_ids)
            self.assertNotIn("EV-UNKNOWN", action.evidence_ids)
            self.assertNotIn("T9999", action.mitre_technique_ids)

    def test_missing_optional_fields_produce_generic_actions(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-OPTIONAL-1",
                    event_type="UnknownActivity",
                    severity="medium",
                    description="Unrecognized activity",
                    source_ip="",
                    destination_ip="",
                    host="",
                    user="",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertTrue(actions)
        for action in actions:
            self.assertNotIn("SERVER-", action.recommendation)
            self.assertNotIn("10.10.", action.recommendation)
            self.assertNotIn("admin", action.recommendation)

    def test_empty_evidence_does_not_invent_evidence(self) -> None:
        context = _context(_high_scenario(), empty_evidence=True)

        actions = generate_recommended_actions(context).actions

        self.assertFalse(any(action.evidence_ids for action in actions))
        self.assertFalse(any(action.mitre_technique_ids for action in actions))

    def test_empty_mitre_mappings_do_not_generate_technique_actions(self) -> None:
        context = _context(
            [
                _alert(
                    "ALT-UNKNOWN-1",
                    event_type="UnknownActivity",
                    severity="medium",
                    description="Some unusual thing happened",
                )
            ]
        )

        actions = generate_recommended_actions(context).actions

        self.assertFalse(any(action.mitre_technique_ids for action in actions))

    def test_repeated_input_produces_identical_actions(self) -> None:
        alerts = _golden_scenario()

        first = generate_recommended_actions(_context(alerts))
        second = generate_recommended_actions(_context(deepcopy(alerts)))

        self.assertEqual(first, second)

    def test_actions_do_not_claim_actions_were_already_performed(self) -> None:
        context = _context(_golden_scenario())

        actions = generate_recommended_actions(context).actions

        completed_action_pattern = re.compile(
            r"\b(?:was|were|has been|had been)\s+"
            r"(?:blocked|isolated|disabled|contained|removed)\b",
            re.IGNORECASE,
        )
        for action in actions:
            self.assertIsNone(completed_action_pattern.search(action.recommendation))

    def test_public_incident_contract_remains_unchanged(self) -> None:
        context = _context(_golden_scenario())
        actions = generate_recommended_actions(context)
        incident = IncidentRecord(
            id=context.incident_id,
            severity=context.scoring.severity,
            confidence=context.scoring.confidence,
            status="investigating",
            affected_assets=context.scoring.affected_assets,
            alert_count=context.scoring.alert_count,
            sources=context.scoring.sources,
            mitre_techniques=context.mitre_technique_ids,
            evidence=context.evidence_ids,
            bluf="",
            recommended_actions=actions.to_public_recommended_actions(),
        )

        public = incident.to_public_incident()

        self.assertEqual(tuple(public), CANONICAL_INCIDENT_FIELDS)
        self.assertEqual(
            public["recommended_actions"],
            list(actions.to_public_recommended_actions()),
        )


if __name__ == "__main__":
    unittest.main()
