from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from src.intelligence.ai.grounding import AIReasoningOutput
from src.intelligence.contracts import CANONICAL_INCIDENT_FIELDS
from src.intelligence.pipeline import IntelligenceAnalysis, analyze
from src.intelligence.validation import AlertValidationError


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


def _independent_scenario() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-3001",
            timestamp=_timestamp(120),
            source="SIEM",
            event_type="UnknownActivity",
            severity="low",
            source_ip="198.51.100.10",
            destination_ip="198.51.100.20",
            host="WORKSTATION-42",
            user="analyst",
            description="Some unusual thing happened",
        ),
        _alert(
            "ALT-3002",
            timestamp=_timestamp(125),
            source="NETWORK_SENSOR",
            event_type="HealthCheck",
            severity="low",
            source_ip="198.51.100.10",
            destination_ip="198.51.100.20",
            host="WORKSTATION-42",
            user="analyst",
            description="Routine monitoring health check",
        ),
    ]


class _InvalidProvider:
    def generate_reasoning(self, context):
        return AIReasoningOutput(
            incident_id=context.incident_id,
            summary="Unsupported summary",
            reasoning="Unsupported reasoning",
            referenced_alert_ids=("ALT-UNKNOWN",),
        )


class PipelineTests(unittest.TestCase):
    def test_empty_input_returns_empty_analysis(self) -> None:
        analysis = analyze([])

        self.assertIsInstance(analysis, IntelligenceAnalysis)
        self.assertEqual(analysis.incidents, ())
        self.assertEqual(analysis.to_public_incidents(), ())

    def test_single_alert_produces_one_incident(self) -> None:
        analysis = analyze([_alert("ALT-1001")])

        self.assertEqual(len(analysis.incidents), 1)
        self.assertEqual(analysis.incidents[0].record.alert_count, 1)
        self.assertTrue(analysis.incidents[0].record.bluf)
        self.assertTrue(analysis.incidents[0].record.recommended_actions)

    def test_server_17_golden_case(self) -> None:
        analysis = analyze(_golden_scenario())

        self.assertEqual(len(analysis.incidents), 1)
        incident = analysis.incidents[0]
        record = incident.record

        self.assertEqual(record.severity, "critical")
        self.assertEqual(record.risk_score, 91)
        self.assertEqual(record.confidence, 100)
        self.assertEqual(record.alert_count, 6)
        self.assertEqual(record.sources, ("NETWORK_SENSOR", "SIEM", "THREAT_INTEL"))
        self.assertEqual(record.affected_assets, ("SERVER-17",))
        self.assertEqual(record.mitre_techniques, ("T1003", "T1021", "T1059.001"))
        self.assertTrue(record.evidence)
        self.assertTrue(record.bluf)
        self.assertTrue(record.recommended_actions)

        public = record.to_public_incident()
        self.assertEqual(tuple(public), CANONICAL_INCIDENT_FIELDS)
        self.assertEqual(public["severity"], "critical")
        self.assertEqual(public["confidence"], 100)
        self.assertEqual(public["alert_count"], 6)
        self.assertEqual(public["mitre_techniques"], ["T1003", "T1021", "T1059.001"])

    def test_multiple_independent_groups_produce_separate_incidents(self) -> None:
        alerts = _golden_scenario() + _independent_scenario()

        analysis = analyze(alerts)

        self.assertEqual(len(analysis.incidents), 2)
        first, second = analysis.incidents

        self.assertEqual(
            first.record.correlated_alert_ids,
            ("ALT-1001", "ALT-1002", "ALT-1003", "ALT-1004", "ALT-1005", "ALT-1006"),
        )
        self.assertEqual(
            second.record.correlated_alert_ids,
            ("ALT-3001", "ALT-3002"),
        )
        self.assertFalse(set(first.record.evidence) & set(second.record.evidence))
        self.assertFalse(set(first.record.mitre_techniques) & set(second.record.mitre_techniques))
        first_action_evidence = {
            evidence_id
            for action in first.actions.actions
            for evidence_id in action.evidence_ids
        }
        second_action_evidence = {
            evidence_id
            for action in second.actions.actions
            for evidence_id in action.evidence_ids
        }
        self.assertFalse(first_action_evidence & second_action_evidence)
        self.assertFalse(
            set(first.record.correlated_alert_ids)
            & set(second.record.correlated_alert_ids)
        )

    def test_reordered_input_produces_equivalent_analysis(self) -> None:
        alerts = _golden_scenario() + _independent_scenario()

        first = analyze(alerts)
        second = analyze(list(reversed(alerts)))

        self.assertEqual(first, second)
        self.assertEqual(first.to_public_incidents(), second.to_public_incidents())

    def test_repeated_input_produces_identical_analysis(self) -> None:
        alerts = _golden_scenario()

        first = analyze(alerts)
        second = analyze(deepcopy(alerts))

        self.assertEqual(first, second)

    def test_invalid_alerts_are_rejected(self) -> None:
        invalid_alert = _alert("ALT-1001")
        invalid_alert["severity"] = "info"

        with self.assertRaises(AlertValidationError):
            analyze([invalid_alert])

    def test_deterministic_bluf_is_used_without_provider(self) -> None:
        analysis = analyze(_golden_scenario())

        self.assertEqual(analysis.incidents[0].bluf.generated_by, "deterministic")

    def test_invalid_ai_output_falls_back_to_deterministic_bluf(self) -> None:
        analysis = analyze(_golden_scenario(), _InvalidProvider())

        self.assertEqual(analysis.incidents[0].bluf.generated_by, "deterministic")

    def test_mitre_does_not_change_risk_score(self) -> None:
        analysis = analyze(_golden_scenario())

        self.assertEqual(analysis.incidents[0].record.risk_score, 91)
        self.assertEqual(analysis.incidents[0].assessment.risk_score, 91)

    def test_incident_ids_and_order_are_deterministic(self) -> None:
        alerts = _golden_scenario() + _independent_scenario()

        first = analyze(alerts)
        second = analyze(list(reversed(alerts)))

        self.assertEqual(
            [incident.record.id for incident in first.incidents],
            [incident.record.id for incident in second.incidents],
        )
        self.assertEqual(
            [incident.record.correlated_alert_ids[0] for incident in first.incidents],
            ["ALT-1001", "ALT-3001"],
        )

    def test_internal_artifacts_remain_traceable_to_their_group(self) -> None:
        alerts = _golden_scenario() + _independent_scenario()

        analysis = analyze(alerts)

        for incident in analysis.incidents:
            alert_ids = set(incident.record.correlated_alert_ids)
            self.assertTrue(alert_ids)
            self.assertTrue(set(incident.evidence.alert_ids).issubset(alert_ids))
            for evidence_record in incident.evidence.records:
                self.assertIn(evidence_record.alert_id, alert_ids)
            for mapping in incident.mitre.mappings:
                self.assertTrue(set(mapping.evidence_ids).issubset(incident.evidence.evidence_ids))
            for action in incident.actions.actions:
                self.assertTrue(set(action.alert_ids).issubset(alert_ids))

    def test_no_fabricated_identifiers_are_generated(self) -> None:
        analysis = analyze(_golden_scenario() + _independent_scenario())

        all_alert_ids = {
            alert_id
            for incident in analysis.incidents
            for alert_id in incident.record.correlated_alert_ids
        }
        all_evidence_ids = {
            evidence_id
            for incident in analysis.incidents
            for evidence_id in incident.record.evidence
        }

        self.assertNotIn("ALT-UNKNOWN", all_alert_ids)
        self.assertNotIn("EV-UNKNOWN", all_evidence_ids)
        for incident in analysis.incidents:
            self.assertNotIn("T9999", incident.record.mitre_techniques)

    def test_public_incident_contract_remains_unchanged(self) -> None:
        analysis = analyze(_golden_scenario())

        public_incidents = analysis.to_public_incidents()

        self.assertEqual(len(public_incidents), 1)
        self.assertEqual(tuple(public_incidents[0]), CANONICAL_INCIDENT_FIELDS)


if __name__ == "__main__":
    unittest.main()
