from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from src.intelligence.contracts import ALLOWED_SEVERITIES
from src.intelligence.correlation import correlate_alerts
from src.intelligence.scoring import (
    DEFAULT_SCORING_CONFIG,
    ThreatAssessmentResult,
    assess_threat,
)


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
    groups = correlate_alerts(alerts)
    if not groups:
        raise AssertionError("Expected at least one correlated group")
    return groups[0]


def _low_activity() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-LOW-1",
            event_type="UnknownEvent",
            severity="low",
            description="Unrecognized low-level activity",
        )
    ]


def _medium_activity() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-MED-1",
            event_type="UnknownEvent",
            severity="medium",
            description="Unrecognized medium-level activity",
        )
    ]


def _high_activity() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-HIGH-1",
            event_type="UnknownEvent",
            severity="high",
            description="Unrecognized high-level activity",
        )
    ]


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
            description="Credential access activity detected",
        ),
        _alert(
            "ALT-1005",
            timestamp=_timestamp(20),
            source="NETWORK_SENSOR",
            event_type="RemoteConnection",
            severity="high",
            description="Suspicious remote connection established",
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


def _noisy_activity() -> list[dict[str, str]]:
    return [
        _alert(
            "ALT-NOISE-1",
            timestamp=_timestamp(0),
            source="SIEM",
            event_type="Monitoring",
            severity="low",
            description="Routine monitoring health check",
            host="WORKSTATION-42",
            user="monitoring_service",
            source_ip="192.0.2.10",
            destination_ip="192.0.2.20",
        ),
        _alert(
            "ALT-NOISE-2",
            timestamp=_timestamp(5),
            source="SIEM",
            event_type="AdministrativeTask",
            severity="low",
            description="Scheduled administrative activity",
            host="WORKSTATION-42",
            user="monitoring_service",
            source_ip="192.0.2.10",
            destination_ip="192.0.2.20",
        ),
        _alert(
            "ALT-NOISE-3",
            timestamp=_timestamp(10),
            source="SIEM",
            event_type="Scan",
            severity="low",
            description="Known benign scan",
            host="WORKSTATION-42",
            user="monitoring_service",
            source_ip="192.0.2.10",
            destination_ip="192.0.2.20",
        ),
    ]


class ScoringTests(unittest.TestCase):
    def test_low_activity_produces_low_score(self) -> None:
        assessment = assess_threat(_first_group(_low_activity()))

        self.assertEqual(assessment.severity, "low")
        self.assertLessEqual(assessment.risk_score, 24)

    def test_medium_activity_scores_higher_than_low(self) -> None:
        low = assess_threat(_first_group(_low_activity()))
        medium = assess_threat(_first_group(_medium_activity()))

        self.assertGreater(medium.risk_score, low.risk_score)

    def test_high_severity_increases_score(self) -> None:
        medium = assess_threat(_first_group(_medium_activity()))
        high = assess_threat(_first_group(_high_activity()))

        self.assertGreater(high.risk_score, medium.risk_score)

    def test_critical_corroborated_activity_can_reach_critical(self) -> None:
        assessment = assess_threat(_first_group(_golden_scenario()))

        self.assertEqual(assessment.severity, "critical")
        self.assertGreaterEqual(assessment.risk_score, 75)

    def test_multiple_sources_increase_confidence(self) -> None:
        single_source_alerts = [
            _alert("ALT-A1", timestamp=_timestamp(0), source="SIEM"),
            _alert("ALT-A2", timestamp=_timestamp(5), source="SIEM"),
        ]
        multi_source_alerts = [
            _alert("ALT-B1", timestamp=_timestamp(0), source="SIEM"),
            _alert("ALT-B2", timestamp=_timestamp(5), source="NETWORK_SENSOR"),
        ]

        single = assess_threat(_first_group(single_source_alerts))
        multi = assess_threat(_first_group(multi_source_alerts))

        self.assertGreater(multi.confidence, single.confidence)

    def test_multiple_alerts_increase_confidence(self) -> None:
        one_alert = [_alert("ALT-A1", timestamp=_timestamp(0))]
        three_alerts = [
            _alert("ALT-B1", timestamp=_timestamp(0)),
            _alert("ALT-B2", timestamp=_timestamp(5)),
            _alert("ALT-B3", timestamp=_timestamp(10)),
        ]

        single = assess_threat(_first_group(one_alert))
        multiple = assess_threat(_first_group(three_alerts))

        self.assertGreater(multiple.confidence, single.confidence)

    def test_attack_progression_increases_score(self) -> None:
        progression_alerts = [
            _alert(
                "ALT-P1",
                timestamp=_timestamp(0),
                event_type="ExternalActivity",
                description="Suspicious external activity detected",
            ),
            _alert(
                "ALT-P2",
                timestamp=_timestamp(5),
                event_type="PowerShell",
                description="Suspicious PowerShell execution",
            ),
        ]
        non_progression_alerts = [
            _alert("ALT-N1", timestamp=_timestamp(0), description="Unrecognized activity"),
            _alert("ALT-N2", timestamp=_timestamp(5), description="Another unrecognized activity"),
        ]

        progression = assess_threat(_first_group(progression_alerts))
        non_progression = assess_threat(_first_group(non_progression_alerts))

        self.assertGreater(progression.risk_score, non_progression.risk_score)

    def test_weak_noisy_activity_remains_low_priority(self) -> None:
        assessment = assess_threat(_first_group(_noisy_activity()))

        self.assertEqual(assessment.severity, "low")
        self.assertEqual(
            assessment.false_positive_assessment,
            ThreatAssessmentResult.LIKELY_FALSE_POSITIVE,
        )

    def test_confidence_is_not_equal_to_risk_score(self) -> None:
        assessment = assess_threat(_first_group(_golden_scenario()))

        self.assertNotEqual(assessment.confidence, assessment.risk_score)

    def test_false_positive_pattern_reduces_priority(self) -> None:
        benign = assess_threat(_first_group(_noisy_activity()))
        comparable = assess_threat(
            _first_group(
                [
                    _alert(
                        "ALT-COMP-1",
                        timestamp=_timestamp(0),
                        event_type="UnknownEvent",
                        severity="low",
                        description="Unrecognized activity",
                        host="WORKSTATION-42",
                        user="monitoring_service",
                        source_ip="192.0.2.10",
                        destination_ip="192.0.2.20",
                    )
                ]
            )
        )

        self.assertLess(benign.risk_score, comparable.risk_score)

    def test_benign_keyword_cannot_dismiss_strong_chain(self) -> None:
        alerts = _golden_scenario()
        alerts.append(
            _alert(
                "ALT-BENIGN-1",
                timestamp=_timestamp(30),
                source="SIEM",
                event_type="AdministrativeTask",
                severity="low",
                description="Scheduled administrative activity",
            )
        )

        assessment = assess_threat(_first_group(alerts))

        self.assertEqual(assessment.severity, "critical")
        self.assertEqual(
            assessment.false_positive_assessment,
            ThreatAssessmentResult.LIKELY_THREAT,
        )

    def test_single_source_has_lower_corroboration(self) -> None:
        single = assess_threat(_first_group(_low_activity()))
        multi = assess_threat(_first_group(_golden_scenario()))

        self.assertLess(single.confidence, multi.confidence)

    def test_affected_assets_are_derived_only_from_alerts(self) -> None:
        alerts = [
            _alert("ALT-A1", timestamp=_timestamp(0), host="SERVER-17"),
            _alert("ALT-A2", timestamp=_timestamp(5), host="WORKSTATION-42"),
            _alert("ALT-A3", timestamp=_timestamp(10), host="SERVER-17"),
        ]

        assessment = assess_threat(_first_group(alerts))

        self.assertEqual(assessment.affected_assets, ("SERVER-17", "WORKSTATION-42"))

    def test_source_diversity_is_deterministic(self) -> None:
        alerts = [
            _alert("ALT-A1", timestamp=_timestamp(0), source="NETWORK_SENSOR"),
            _alert("ALT-A2", timestamp=_timestamp(5), source="SIEM"),
            _alert("ALT-A3", timestamp=_timestamp(10), source="THREAT_INTEL"),
        ]

        first = assess_threat(_first_group(alerts))
        second = assess_threat(_first_group(list(reversed(alerts))))

        self.assertEqual(first.sources, second.sources)
        self.assertEqual(first.source_count, 3)

    def test_scoring_factors_sum_to_risk_score_before_clamping(self) -> None:
        assessment = assess_threat(_first_group(_golden_scenario()))
        factor_sum = sum(factor.value for factor in assessment.scoring_factors)

        self.assertEqual(assessment.risk_score, max(0, min(100, factor_sum)))
        self.assertLessEqual(factor_sum, 100)

    def test_risk_score_stays_within_bounds(self) -> None:
        for alerts in (_low_activity(), _medium_activity(), _golden_scenario(), _noisy_activity()):
            assessment = assess_threat(_first_group(alerts))
            self.assertGreaterEqual(assessment.risk_score, 0)
            self.assertLessEqual(assessment.risk_score, 100)

    def test_confidence_stays_within_bounds(self) -> None:
        for alerts in (_low_activity(), _medium_activity(), _golden_scenario(), _noisy_activity()):
            assessment = assess_threat(_first_group(alerts))
            self.assertGreaterEqual(assessment.confidence, 0)
            self.assertLessEqual(assessment.confidence, 100)

    def test_severity_uses_exact_vocabulary(self) -> None:
        assessment = assess_threat(_first_group(_golden_scenario()))

        self.assertIn(assessment.severity, ALLOWED_SEVERITIES)
        self.assertNotEqual(assessment.severity, "info")

    def test_info_is_not_produced(self) -> None:
        assessment = assess_threat(_first_group(_low_activity()))

        self.assertNotEqual(assessment.severity, "info")

    def test_reordering_alerts_does_not_change_assessment(self) -> None:
        alerts = _golden_scenario()

        first = assess_threat(_first_group(alerts))
        second = assess_threat(_first_group(list(reversed(alerts))))

        self.assertEqual(first, second)

    def test_same_input_produces_identical_output(self) -> None:
        alerts = _golden_scenario()

        first = assess_threat(_first_group(alerts))
        second = assess_threat(_first_group(deepcopy(alerts)))

        self.assertEqual(first, second)

    def test_no_mitre_data_is_neutral(self) -> None:
        assessment = assess_threat(_first_group(_golden_scenario()))
        mitre_factor = next(
            factor for factor in assessment.scoring_factors if factor.name == "mitre_factor"
        )

        self.assertEqual(mitre_factor.value, 0)
        self.assertEqual(mitre_factor.maximum, DEFAULT_SCORING_CONFIG.mitre_points_per_technique * DEFAULT_SCORING_CONFIG.mitre_technique_cap)


if __name__ == "__main__":
    unittest.main()
