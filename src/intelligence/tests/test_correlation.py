from copy import deepcopy
from datetime import datetime, timedelta, timezone
import unittest

from src.intelligence.correlation import (
    CorrelationConfig,
    correlate_alerts,
)
from src.intelligence.validation import AlertValidationError


def _timestamp(minutes: int = 0, seconds: int = 0) -> str:
    value = datetime(2026, 9, 14, 10, 0, tzinfo=timezone.utc)
    value += timedelta(minutes=minutes, seconds=seconds)
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


class CorrelationTests(unittest.TestCase):
    def test_empty_alert_list_returns_no_groups(self) -> None:
        self.assertEqual(correlate_alerts([]), ())

    def test_single_alert_creates_one_group(self) -> None:
        groups = correlate_alerts([_alert("ALT-1001")])

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].alert_ids, ("ALT-1001",))
        self.assertEqual(groups[0].relationships, ())
        self.assertEqual(groups[0].correlation_reasons, ())
        self.assertEqual(groups[0].started_at, groups[0].ended_at)

    def test_same_host_within_time_window_correlates(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0)),
            _alert("ALT-1002", timestamp=_timestamp(10), source_ip="192.0.2.10"),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].alert_ids, ("ALT-1001", "ALT-1002"))
        self.assertIn("same_host", groups[0].correlation_reasons)
        self.assertIn("within_time_window", groups[0].correlation_reasons)

    def test_same_source_ip_within_time_window_correlates(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0), host="SERVER-17"),
            _alert("ALT-1002", timestamp=_timestamp(10), host="WORKSTATION-42"),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertIn("same_source_ip", groups[0].correlation_reasons)

    def test_same_user_within_time_window_correlates(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0), host="SERVER-17"),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(10),
                host="WORKSTATION-42",
                source_ip="192.0.2.10",
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertIn("same_user", groups[0].correlation_reasons)

    def test_same_network_pair_within_time_window_correlates(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0), host="SERVER-17"),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(10),
                host="WORKSTATION-42",
                user="service_account",
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertIn("same_network_pair", groups[0].correlation_reasons)

    def test_alerts_outside_time_window_do_not_correlate_by_shared_host(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0)),
            _alert("ALT-1002", timestamp=_timestamp(60)),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].alert_ids, ("ALT-1001",))
        self.assertEqual(groups[1].alert_ids, ("ALT-1002",))

    def test_multiple_independent_groups_remain_separate(self) -> None:
        alerts = [
            _alert("ALT-1001", host="SERVER-17", user="admin"),
            _alert("ALT-1002", host="SERVER-17", user="admin"),
            _alert(
                "ALT-2001",
                host="WORKSTATION-42",
                user="analyst",
                source_ip="198.51.100.20",
                destination_ip="198.51.100.30",
                timestamp=_timestamp(5),
            ),
            _alert(
                "ALT-2002",
                host="WORKSTATION-42",
                user="analyst",
                source_ip="198.51.100.20",
                destination_ip="198.51.100.30",
                timestamp=_timestamp(15),
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0].alert_ids, ("ALT-1001", "ALT-1002"))
        self.assertEqual(groups[1].alert_ids, ("ALT-2001", "ALT-2002"))

    def test_transitive_correlation_groups_connected_alerts(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0), host="SERVER-17"),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(10),
                host="SERVER-17",
                source_ip="192.0.2.10",
            ),
            _alert(
                "ALT-1003",
                timestamp=_timestamp(20),
                host="WORKSTATION-42",
                source_ip="192.0.2.10",
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].alert_ids, ("ALT-1001", "ALT-1002", "ALT-1003"))
        self.assertGreaterEqual(len(groups[0].relationships), 2)

    def test_unrelated_alerts_are_not_grouped(self) -> None:
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
                "ALT-2001",
                timestamp=_timestamp(10),
                host="WORKSTATION-42",
                user="service_account",
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 2)

    def test_attack_progression_can_connect_related_events(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                timestamp=_timestamp(0),
                event_type="ExternalActivity",
                description="Suspicious external activity detected",
            ),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(10),
                event_type="PowerShell",
                description="Suspicious PowerShell execution",
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertIn("attack_progression", groups[0].correlation_reasons)

    def test_unknown_event_types_are_handled_safely(self) -> None:
        alerts = [
            _alert(
                "ALT-1001",
                timestamp=_timestamp(0),
                event_type="UnknownEvent",
                description="Unrecognized activity",
            ),
            _alert(
                "ALT-1002",
                timestamp=_timestamp(10),
                event_type="AnotherUnknownEvent",
                description="Another unrecognized activity",
            ),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertIn("same_host", groups[0].correlation_reasons)

    def test_group_ids_are_deterministic(self) -> None:
        alerts = [_alert("ALT-1001"), _alert("ALT-1002", timestamp=_timestamp(10))]

        first_groups = correlate_alerts(alerts)
        second_groups = correlate_alerts(alerts)

        self.assertEqual(first_groups[0].group_id, second_groups[0].group_id)

    def test_reordering_input_produces_same_logical_groups(self) -> None:
        alerts = [
            _alert("ALT-1002", timestamp=_timestamp(10)),
            _alert("ALT-1001", timestamp=_timestamp(0)),
            _alert(
                "ALT-2002",
                timestamp=_timestamp(15),
                host="WORKSTATION-42",
                user="analyst",
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
            ),
            _alert(
                "ALT-2001",
                timestamp=_timestamp(5),
                host="WORKSTATION-42",
                user="analyst",
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
            ),
        ]

        groups = correlate_alerts(alerts)
        reordered_groups = correlate_alerts(list(reversed(alerts)))

        self.assertEqual(
            [group.alert_ids for group in groups],
            [group.alert_ids for group in reordered_groups],
        )
        self.assertEqual(
            [group.group_id for group in groups],
            [group.group_id for group in reordered_groups],
        )

    def test_input_alerts_are_not_mutated(self) -> None:
        alerts = [_alert("ALT-1001"), _alert("ALT-1002", timestamp=_timestamp(10))]
        original = deepcopy(alerts)

        correlate_alerts(alerts)

        self.assertEqual(alerts, original)

    def test_correlation_reasons_are_deterministic(self) -> None:
        alerts = [_alert("ALT-1001"), _alert("ALT-1002", timestamp=_timestamp(10))]

        first_groups = correlate_alerts(alerts)
        second_groups = correlate_alerts(alerts)

        self.assertEqual(
            first_groups[0].correlation_reasons,
            second_groups[0].correlation_reasons,
        )

    def test_duplicate_alert_ids_are_rejected(self) -> None:
        alerts = [_alert("ALT-1001"), _alert("ALT-1001", timestamp=_timestamp(10))]

        with self.assertRaises(AlertValidationError):
            correlate_alerts(alerts)

    def test_malformed_alert_is_rejected(self) -> None:
        alert = _alert("ALT-1001")
        del alert["severity"]

        with self.assertRaises(AlertValidationError):
            correlate_alerts([alert])

    def test_identical_timestamps_are_supported(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0)),
            _alert("ALT-1002", timestamp=_timestamp(0)),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].started_at, groups[0].ended_at)

    def test_same_host_but_distant_timestamps_stay_separate(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0)),
            _alert("ALT-1002", timestamp=_timestamp(90)),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 2)

    def test_same_source_ip_but_distant_timestamps_stay_separate(self) -> None:
        alerts = [
            _alert("ALT-1001", timestamp=_timestamp(0), host="SERVER-17"),
            _alert("ALT-1002", timestamp=_timestamp(120), host="WORKSTATION-42"),
        ]

        groups = correlate_alerts(alerts)

        self.assertEqual(len(groups), 2)

    def test_relationship_score_is_not_incident_severity_or_confidence(self) -> None:
        groups = correlate_alerts([_alert("ALT-1001")])

        self.assertFalse(hasattr(groups[0], "severity"))
        self.assertFalse(hasattr(groups[0], "confidence"))


if __name__ == "__main__":
    unittest.main()
