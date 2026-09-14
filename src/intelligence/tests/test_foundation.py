from dataclasses import fields
from datetime import datetime, timezone
import unittest

from src.intelligence.contracts import (
    ALLOWED_SEVERITIES,
    CANONICAL_ALERT_FIELDS,
    CANONICAL_INCIDENT_FIELDS,
)
from src.intelligence.models import Alert, Evidence, IncidentRecord, MitreMapping
from src.intelligence.validation import (
    AlertValidationError,
    validate_alert,
    validate_alerts,
)


def canonical_alert() -> dict[str, str]:
    return {
        "id": "ALT-1001",
        "timestamp": "2026-09-14T10:32:00Z",
        "source": "SIEM",
        "event_type": "PowerShell",
        "severity": "medium",
        "source_ip": "10.10.1.20",
        "destination_ip": "10.10.5.17",
        "host": "SERVER-17",
        "user": "admin",
        "description": "Suspicious PowerShell execution",
    }


class ValidationTests(unittest.TestCase):
    def test_valid_alert_is_accepted(self) -> None:
        validate_alert(canonical_alert())

    def test_missing_required_field_is_rejected(self) -> None:
        alert = canonical_alert()
        del alert["timestamp"]

        with self.assertRaises(AlertValidationError) as context:
            validate_alert(alert)

        self.assertIn("missing required field 'timestamp'", str(context.exception))

    def test_invalid_severity_is_rejected(self) -> None:
        alert = canonical_alert()
        alert["severity"] = "urgent"

        with self.assertRaises(AlertValidationError) as context:
            validate_alert(alert)

        self.assertIn("invalid severity 'urgent'", str(context.exception))

    def test_application_severity_vocabulary(self) -> None:
        for severity in ("low", "medium", "high", "critical"):
            with self.subTest(severity=severity):
                alert = canonical_alert()
                alert["severity"] = severity
                validate_alert(alert)

        self.assertEqual(
            ALLOWED_SEVERITIES,
            frozenset({"low", "medium", "high", "critical"}),
        )

    def test_info_severity_is_rejected(self) -> None:
        alert = canonical_alert()
        alert["severity"] = "info"

        with self.assertRaises(AlertValidationError) as context:
            validate_alert(alert)

        self.assertIn("invalid severity 'info'", str(context.exception))

    def test_invalid_timestamp_is_rejected(self) -> None:
        alert = canonical_alert()
        alert["timestamp"] = "not-a-timestamp"

        with self.assertRaises(AlertValidationError) as context:
            validate_alert(alert)

        self.assertIn("invalid timestamp 'not-a-timestamp'", str(context.exception))

    def test_invalid_ip_is_rejected_when_supplied(self) -> None:
        alert = canonical_alert()
        alert["destination_ip"] = "999.999.999.999"

        with self.assertRaises(AlertValidationError) as context:
            validate_alert(alert)

        self.assertIn("invalid destination_ip '999.999.999.999'", str(context.exception))

    def test_duplicate_alert_ids_are_detected(self) -> None:
        alerts = [canonical_alert(), canonical_alert()]

        with self.assertRaises(AlertValidationError) as context:
            validate_alerts(alerts)

        self.assertIn("duplicate alert ID 'ALT-1001'", str(context.exception))

    def test_validation_does_not_mutate_input(self) -> None:
        alert = canonical_alert()
        original = dict(alert)

        try:
            validate_alerts([alert])
        except AlertValidationError:
            pass

        self.assertEqual(alert, original)


class ModelTests(unittest.TestCase):
    def test_alert_model_exposes_canonical_fields(self) -> None:
        self.assertEqual(
            [field.name for field in fields(Alert)],
            list(CANONICAL_ALERT_FIELDS),
        )

    def test_alert_model_can_be_created(self) -> None:
        alert = Alert(
            id="ALT-1001",
            timestamp=datetime(2026, 9, 14, 10, 32, tzinfo=timezone.utc),
            source="SIEM",
            event_type="PowerShell",
            severity="medium",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            host="SERVER-17",
            user="admin",
            description="Suspicious PowerShell execution",
        )

        self.assertEqual(alert.id, "ALT-1001")
        self.assertEqual(alert.severity, "medium")

    def test_incident_serializes_only_public_fields(self) -> None:
        evidence = Evidence(
            evidence_id="EV-001",
            alert_id="ALT-1001",
            timestamp=datetime(2026, 9, 14, 10, 32, tzinfo=timezone.utc),
            source="SIEM",
            event_type="PowerShell",
            host="SERVER-17",
            user="admin",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            description="Suspicious PowerShell execution",
            rationale="Alert-derived execution evidence",
        )
        mapping = MitreMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            confidence=90,
            evidence_ids=("EV-001",),
        )
        incident = IncidentRecord(
            id="INC-001",
            severity="critical",
            confidence=94,
            status="investigating",
            affected_assets=("SERVER-17",),
            alert_count=7,
            sources=("SIEM", "NETWORK_SENSOR"),
            mitre_techniques=("T1059.001",),
            evidence=("EV-001",),
            bluf="Critical multi-source activity affected SERVER-17.",
            recommended_actions=("Isolate SERVER-17",),
            correlated_alert_ids=("ALT-1001", "ALT-1002"),
            risk_score=91.5,
            false_positive_reasons=("Benign administrative pattern",),
            evidence_records=(evidence,),
            mitre_mappings=(mapping,),
        )

        public = incident.to_public_incident()

        self.assertEqual(tuple(public), CANONICAL_INCIDENT_FIELDS)
        self.assertEqual(public["evidence"], ["EV-001"])
        self.assertEqual(public["recommended_actions"], ["Isolate SERVER-17"])
        self.assertNotIn("correlated_alert_ids", public)
        self.assertNotIn("risk_score", public)
        self.assertNotIn("false_positive_reasons", public)
        self.assertNotIn("evidence_records", public)
        self.assertNotIn("mitre_mappings", public)

    def test_internal_evidence_preserves_traceability(self) -> None:
        evidence = Evidence(
            evidence_id="EV-001",
            alert_id="ALT-1001",
            timestamp=datetime(2026, 9, 14, 10, 32, tzinfo=timezone.utc),
            source="SIEM",
            event_type="PowerShell",
            host="SERVER-17",
            user="admin",
            source_ip="10.10.1.20",
            destination_ip="10.10.5.17",
            description="Suspicious PowerShell execution",
            rationale="Alert-derived execution evidence",
        )

        self.assertEqual(evidence.evidence_id, "EV-001")
        self.assertEqual(evidence.alert_id, "ALT-1001")
        self.assertEqual(evidence.event_type, "PowerShell")
        self.assertEqual(evidence.host, "SERVER-17")
        self.assertEqual(evidence.user, "admin")

    def test_internal_mitre_mapping_preserves_traceability(self) -> None:
        mapping = MitreMapping(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            confidence=90,
            evidence_ids=("EV-001",),
        )

        self.assertEqual(mapping.technique_id, "T1059.001")
        self.assertEqual(mapping.technique_name, "PowerShell")
        self.assertEqual(mapping.tactic, "Execution")
        self.assertEqual(mapping.evidence_ids, ("EV-001",))


if __name__ == "__main__":
    unittest.main()
