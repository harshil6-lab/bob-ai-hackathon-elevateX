from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from src.intelligence.contracts import CANONICAL_INCIDENT_FIELDS
from src.intelligence.correlation import correlate_alerts
from src.intelligence.evidence import EvidenceType, extract_evidence
from src.intelligence.models import IncidentRecord
from src.intelligence.validation import AlertValidationError, validate_alerts


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
    source_ip: str = "",
    destination_ip: str = "",
    host: str = "",
    user: str = "",
    description: str = "Unrecognized activity",
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
            source_ip="203.0.113.10",
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
            source_ip="203.0.113.10",
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
            source_ip="203.0.113.10",
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
            source_ip="203.0.113.10",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Credential access activity detected",
        ),
        _alert(
            "ALT-1005",
            timestamp=_timestamp(20),
            source="NETWORK_SENSOR",
            event_type="RemoteConnection",
            severity="high",
            source_ip="203.0.113.10",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Suspicious remote connection established",
        ),
        _alert(
            "ALT-1006",
            timestamp=_timestamp(25),
            source="SIEM",
            event_type="LateralMovement",
            severity="critical",
            source_ip="203.0.113.10",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Lateral movement observed",
        ),
    ]


class EvidenceTests(unittest.TestCase):
    def test_valid_alert_produces_traceable_evidence(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="PowerShell",
                source_ip="10.10.1.20",
                destination_ip="10.10.5.17",
                host="SERVER-17",
                user="admin",
                description="Suspicious PowerShell execution",
            )
        ]

        evidence = extract_evidence(_first_group(alerts))

        self.assertTrue(evidence.records)
        self.assertTrue(all(record.alert_id == "ALT-1001" for record in evidence.records))

    def test_evidence_references_real_alert_ids(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)

        evidence = extract_evidence(group)

        self.assertEqual(evidence.alert_ids, tuple(sorted(alert["id"] for alert in alerts)))
        self.assertTrue(set(evidence.alert_ids).issubset({alert["id"] for alert in alerts}))

    def test_evidence_ids_are_deterministic(self) -> None:
        alerts = _golden_scenario()

        first = extract_evidence(_first_group(alerts))
        second = extract_evidence(_first_group(alerts))

        self.assertEqual(first.evidence_ids, second.evidence_ids)

    def test_repeated_extraction_produces_identical_results(self) -> None:
        alerts = _golden_scenario()
        group = _first_group(alerts)

        first = extract_evidence(group)
        second = extract_evidence(group)

        self.assertEqual(first, second)

    def test_reordered_input_produces_deterministic_results(self) -> None:
        alerts = _golden_scenario()

        first = extract_evidence(_first_group(alerts))
        second = extract_evidence(_first_group(list(reversed(alerts))))

        self.assertEqual(first, second)

    def test_missing_optional_values_do_not_crash(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="UnknownEvent",
                source_ip="",
                destination_ip="",
                host="",
                user="",
                description="Unrecognized activity",
            )
        ]

        evidence = extract_evidence(_first_group(alerts))

        self.assertTrue(evidence.records)
        self.assertEqual(evidence.records[0].host, "")
        self.assertEqual(evidence.records[0].user, "")
        self.assertEqual(evidence.records[0].source_ip, "")
        self.assertEqual(evidence.records[0].destination_ip, "")

    def test_powershell_evidence_requires_actual_support(self) -> None:
        supported = extract_evidence(
            _first_group(
                [
                    _alert(
                        "ALT-1001",
                        event_type="PowerShell",
                        description="Suspicious PowerShell execution",
                    )
                ]
            )
        )
        unsupported = extract_evidence(
            _first_group(
                [
                    _alert(
                        "ALT-1002",
                        event_type="UnknownEvent",
                        description="Unrecognized activity",
                    )
                ]
            )
        )

        self.assertTrue(
            any(
                record.evidence_type == EvidenceType.SUSPICIOUS_INDICATOR.value
                and "PowerShell" in record.rationale
                for record in supported.records
            )
        )
        self.assertFalse(
            any(
                record.evidence_type == EvidenceType.SUSPICIOUS_INDICATOR.value
                and "PowerShell" in record.rationale
                for record in unsupported.records
            )
        )

    def test_credential_access_evidence_requires_actual_support(self) -> None:
        supported = extract_evidence(
            _first_group(
                [
                    _alert(
                        "ALT-1001",
                        event_type="CredentialAccess",
                        description="Credential access activity detected",
                    )
                ]
            )
        )
        unsupported = extract_evidence(
            _first_group(
                [
                    _alert(
                        "ALT-1002",
                        event_type="UnknownEvent",
                        description="Unrecognized activity",
                    )
                ]
            )
        )

        self.assertTrue(
            any("credential access" in record.rationale.lower() for record in supported.records)
        )
        self.assertFalse(
            any("credential access" in record.rationale.lower() for record in unsupported.records)
        )

    def test_remote_connection_evidence_requires_actual_support(self) -> None:
        supported = extract_evidence(
            _first_group(
                [
                    _alert(
                        "ALT-1001",
                        event_type="RemoteConnection",
                        description="Suspicious remote connection established",
                    )
                ]
            )
        )
        unsupported = extract_evidence(
            _first_group(
                [
                    _alert(
                        "ALT-1002",
                        event_type="UnknownEvent",
                        description="Unrecognized activity",
                    )
                ]
            )
        )

        self.assertTrue(
            any("remote connection" in record.rationale.lower() for record in supported.records)
        )
        self.assertFalse(
            any("remote connection" in record.rationale.lower() for record in unsupported.records)
        )

    def test_unknown_event_types_remain_safe(self) -> None:
        alerts = [
            _alert("ALT-1001", event_type="UnknownEvent", description="Unrecognized activity"),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(5),
                event_type="AnotherUnknownEvent",
                description="Another unrecognized activity",
            ),
        ]

        evidence = extract_evidence(_first_group(alerts))

        self.assertTrue(evidence.records)
        self.assertTrue(
            all(record.evidence_type != EvidenceType.SUSPICIOUS_INDICATOR.value for record in evidence.records)
        )

    def test_no_fabricated_optional_values_appear(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="UnknownEvent",
                source_ip="",
                destination_ip="",
                host="",
                user="",
                description="Unrecognized activity",
            )
        ]

        evidence = extract_evidence(_first_group(alerts))

        for record in evidence.records:
            self.assertEqual(record.host, "")
            self.assertEqual(record.user, "")
            self.assertEqual(record.source_ip, "")
            self.assertEqual(record.destination_ip, "")

    def test_rationale_is_grounded_in_source_fields(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="PowerShell",
                host="SERVER-17",
                user="admin",
                source_ip="10.10.1.20",
                destination_ip="10.10.5.17",
                description="Suspicious PowerShell execution",
            )
        ]

        evidence = extract_evidence(_first_group(alerts))

        self.assertTrue(any("ALT-1001" in record.rationale for record in evidence.records))
        self.assertTrue(any("PowerShell" in record.rationale for record in evidence.records))

    def test_correlation_evidence_references_actual_relationships(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                timestamp=_timestamp(0),
                host="SERVER-17",
                user="admin",
                source_ip="10.10.1.20",
                destination_ip="10.10.5.17",
            ),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(5),
                host="SERVER-17",
                user="admin",
                source_ip="10.10.1.20",
                destination_ip="10.10.5.17",
            ),
        ]

        group = _first_group(alerts)
        evidence = extract_evidence(group)

        correlation_records = [
            record
            for record in evidence.records
            if record.evidence_type == EvidenceType.CORRELATION_OBSERVATION.value
        ]
        self.assertTrue(correlation_records)
        self.assertTrue(
            any("ALT-1001 and ALT-1002" in record.rationale for record in correlation_records)
        )

    def test_duplicate_evidence_is_deduplicated(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                event_type="PowerShell",
                description="Suspicious PowerShell execution and PowerShell script block",
            )
        ]

        evidence = extract_evidence(_first_group(alerts))
        indicator_records = [
            record
            for record in evidence.records
            if record.evidence_type == EvidenceType.SUSPICIOUS_INDICATOR.value
            and "PowerShell" in record.rationale
        ]

        self.assertEqual(len(indicator_records), 1)

    def test_input_alerts_are_not_mutated(self) -> None:
        alerts = _golden_scenario()
        original = deepcopy(alerts)

        extract_evidence(_first_group(alerts))

        self.assertEqual(alerts, original)

    def test_public_incident_exposes_only_evidence_ids(self) -> None:
        alerts = _golden_scenario()
        evidence = extract_evidence(_first_group(alerts))
        incident = IncidentRecord(
            id="INC-001",
            severity="critical",
            confidence=94,
            status="investigating",
            affected_assets=("SERVER-17",),
            alert_count=len(alerts),
            sources=("SIEM", "NETWORK_SENSOR", "THREAT_INTEL"),
            mitre_techniques=(),
            evidence=evidence.evidence_ids,
            bluf="",
            recommended_actions=(),
            evidence_records=evidence.records,
        )

        public = incident.to_public_incident()

        self.assertEqual(tuple(public), CANONICAL_INCIDENT_FIELDS)
        self.assertEqual(public["evidence"], list(evidence.evidence_ids))
        self.assertNotIn("evidence_records", public)
        self.assertNotIn("evidence_type", public)
        self.assertNotIn("rationale", public)

    def test_rich_internal_evidence_does_not_leak(self) -> None:
        alerts = _golden_scenario()
        evidence = extract_evidence(_first_group(alerts))
        incident = IncidentRecord(
            id="INC-001",
            severity="critical",
            confidence=94,
            status="investigating",
            affected_assets=("SERVER-17",),
            alert_count=len(alerts),
            sources=("SIEM", "NETWORK_SENSOR", "THREAT_INTEL"),
            mitre_techniques=(),
            evidence=evidence.evidence_ids,
            bluf="",
            recommended_actions=(),
            evidence_records=evidence.records,
        )

        public = incident.to_public_incident()

        self.assertEqual(tuple(public), CANONICAL_INCIDENT_FIELDS)
        for field in (
            "evidence_id",
            "alert_id",
            "timestamp",
            "source",
            "event_type",
            "host",
            "user",
            "source_ip",
            "destination_ip",
            "description",
            "rationale",
            "evidence_type",
        ):
            self.assertNotIn(field, public)

    def test_golden_scenario_produces_all_evidence_types(self) -> None:
        evidence = extract_evidence(_first_group(_golden_scenario()))
        evidence_types = {record.evidence_type for record in evidence.records}

        self.assertIn(EvidenceType.ALERT_OBSERVATION.value, evidence_types)
        self.assertIn(EvidenceType.SUSPICIOUS_INDICATOR.value, evidence_types)
        self.assertIn(EvidenceType.CORRELATION_OBSERVATION.value, evidence_types)
        self.assertIn(EvidenceType.ATTACK_PROGRESSION_OBSERVATION.value, evidence_types)

    def test_malformed_input_is_rejected_by_existing_validation(self) -> None:
        alert = _alert("ALT-1001")
        del alert["severity"]

        with self.assertRaises(AlertValidationError):
            validate_alerts([alert])


if __name__ == "__main__":
    unittest.main()
