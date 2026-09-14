from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from src.intelligence.contracts import CANONICAL_INCIDENT_FIELDS
from src.intelligence.correlation import correlate_alerts
from src.intelligence.evidence import EvidenceCollection, extract_evidence
from src.intelligence.models import IncidentRecord
from src.intelligence.mitre import (
    MITRE_CATALOG_VERSION,
    map_mitre_behaviors,
)
from src.intelligence.validation import validate_alerts


def _timestamp(minutes: int = 0) -> str:
    value = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)
    value += timedelta(minutes=minutes)
    return value.isoformat().replace("+00:00", "Z")


def _alert(
    alert_id: str,
    *,
    timestamp: str | None = None,
    source: str = "SIEM",
    event_type: str = "UnknownEvent",
    severity: str = "low",
    source_ip: str = "10.10.1.20",
    destination_ip: str = "10.10.5.17",
    host: str = "SERVER-17",
    user: str = "admin",
    description: str = "Some unusual thing happened",
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


def _first_group(alerts: list[dict[str, str]]):
    validate_alerts(alerts)
    groups = correlate_alerts(alerts)
    if not groups:
        raise AssertionError("Expected at least one correlated group")
    return groups[0]


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


class MitreMappingTests(unittest.TestCase):
    def test_catalog_version_is_explicit(self) -> None:
        self.assertEqual(MITRE_CATALOG_VERSION, "prototype-1")

    def test_powershell_maps_to_t1059_001(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="PowerShell",
                description="Suspicious PowerShell execution",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertIn("T1059.001", result.technique_ids)
        mapping = next(m for m in result.mappings if m.technique_id == "T1059.001")
        self.assertEqual(mapping.technique_name, "PowerShell")
        self.assertEqual(mapping.tactic, "Execution")
        self.assertTrue(mapping.evidence_ids)

    def test_credential_access_maps_to_t1003(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="CredentialAccess",
                description="Credential dumping detected",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertIn("T1003", result.technique_ids)
        mapping = next(m for m in result.mappings if m.technique_id == "T1003")
        self.assertEqual(mapping.technique_name, "OS Credential Dumping")
        self.assertEqual(mapping.tactic, "Credential Access")

    def test_remote_services_maps_to_t1021(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="RemoteConnection",
                description="Remote desktop connection established",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertIn("T1021", result.technique_ids)
        mapping = next(m for m in result.mappings if m.technique_id == "T1021")
        self.assertEqual(mapping.technique_name, "Remote Services")
        self.assertEqual(mapping.tactic, "Lateral Movement")

    def test_unknown_behavior_produces_no_mapping(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="UnknownEvent",
                description="Some unusual thing happened",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertEqual(result.mappings, ())
        self.assertEqual(result.technique_ids, ())
        self.assertEqual(result.evidence_ids, ())

    def test_broad_remote_text_does_not_map_to_t1021(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="RemoteWork",
                description="Remote worker logged in",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertNotIn("T1021", result.technique_ids)

    def test_case_insensitive_patterns_behave_consistently(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="powershell",
                description="powershell execution detected",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertIn("T1059.001", result.technique_ids)

    def test_mapping_is_deterministic(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        first = map_mitre_behaviors(group.alerts, evidence)
        second = map_mitre_behaviors(group.alerts, evidence)

        self.assertEqual(first, second)

    def test_repeated_mapping_produces_identical_results(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        first = map_mitre_behaviors(group.alerts, evidence)
        second = map_mitre_behaviors(group.alerts, deepcopy(evidence))

        self.assertEqual(first, second)

    def test_reordered_input_produces_deterministic_results(self) -> None:
        alerts = _golden_scenario()

        first_group = _first_group(alerts)
        first_evidence = extract_evidence(first_group)
        first_result = map_mitre_behaviors(first_group.alerts, first_evidence)

        second_group = _first_group(list(reversed(alerts)))
        second_evidence = extract_evidence(second_group)
        second_result = map_mitre_behaviors(second_group.alerts, second_evidence)

        self.assertEqual(first_result, second_result)

    def test_evidence_ids_come_only_from_supplied_evidence(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertTrue(set(result.evidence_ids).issubset(set(evidence.evidence_ids)))

    def test_mapping_without_supporting_evidence_does_not_invent_evidence(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="PowerShell",
                description="Suspicious PowerShell execution",
            )
        ]
        group = _first_group(alerts)
        empty_evidence = EvidenceCollection(
            group_id=group.group_id,
            records=(),
            evidence_ids=(),
            alert_ids=tuple(alert.id for alert in group.alerts),
            alert_evidence_ids=((alert.id, ()) for alert in group.alerts),
        )

        result = map_mitre_behaviors(group.alerts, empty_evidence)

        self.assertEqual(result.mappings, ())
        self.assertEqual(result.evidence_ids, ())

    def test_evidence_linked_mapping_preserves_traceability(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        for mapping in result.mappings:
            self.assertTrue(mapping.evidence_ids)
            for evidence_id in mapping.evidence_ids:
                self.assertIn(evidence_id, evidence.evidence_ids)

    def test_multiple_alerts_supporting_one_technique_are_grouped(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                timestamp=_timestamp(0),
                event_type="PowerShell",
                description="Suspicious PowerShell execution",
            ),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(5),
                event_type="PowerShell",
                description="Another PowerShell execution",
            ),
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        mappings = [m for m in result.mappings if m.technique_id == "T1059.001"]
        self.assertEqual(len(mappings), 1)
        self.assertGreaterEqual(len(mappings[0].evidence_ids), 2)

    def test_duplicate_mappings_are_eliminated(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="PowerShell",
                description="Suspicious PowerShell execution",
            )
        ]
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        technique_ids = [mapping.technique_id for mapping in result.mappings]
        self.assertEqual(len(technique_ids), len(set(technique_ids)))

    def test_public_technique_ids_are_deduplicated_and_sorted(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        result = map_mitre_behaviors(group.alerts, evidence)

        self.assertEqual(result.technique_ids, tuple(sorted(set(result.technique_ids))))

    def test_internal_mitre_details_do_not_leak_into_public_incident(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)
        result = map_mitre_behaviors(group.alerts, evidence)

        incident = IncidentRecord(
            id="INC-001",
            severity="critical",
            confidence=94,
            status="investigating",
            affected_assets=("SERVER-17",),
            alert_count=len(alerts),
            sources=("SIEM", "NETWORK_SENSOR", "THREAT_INTEL"),
            mitre_techniques=result.technique_ids,
            evidence=evidence.evidence_ids,
            bluf="",
            recommended_actions=(),
            mitre_mappings=result.mappings,
        )

        public = incident.to_public_incident()

        self.assertEqual(tuple(public), CANONICAL_INCIDENT_FIELDS)
        self.assertEqual(public["mitre_techniques"], list(result.technique_ids))
        self.assertNotIn("mitre_mappings", public)
        self.assertNotIn("technique_name", public)
        self.assertNotIn("tactic", public)
        self.assertNotIn("mapping_confidence", public)

    def test_no_random_or_external_behavior_is_used(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)
        evidence = extract_evidence(group)

        first = map_mitre_behaviors(group.alerts, evidence)
        second = map_mitre_behaviors(group.alerts, evidence)

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
