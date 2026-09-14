"""Validation for canonical alerts entering the intelligence boundary."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
import ipaddress
import re
from typing import Any

from .contracts import ALLOWED_SEVERITIES, CANONICAL_ALERT_FIELDS


_REQUIRED_TEXT_FIELDS = frozenset(
    {"id", "timestamp", "source", "event_type", "severity", "description"}
)
_IP_FIELDS = frozenset({"source_ip", "destination_ip"})
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


class AlertValidationError(ValueError):
    """Clear, caller-safe validation failure for one or more alerts."""

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors))


def validate_alert(alert: Mapping[str, Any]) -> None:
    """Validate one canonical alert without mutating it."""

    errors = _collect_alert_errors(alert)
    if errors:
        raise AlertValidationError(errors)


def validate_alerts(alerts: Iterable[Mapping[str, Any]]) -> None:
    """Validate a collection of canonical alerts and detect duplicate IDs."""

    alert_list = list(alerts)
    errors: list[str] = []
    seen_ids: dict[str, int] = {}

    for index, alert in enumerate(alert_list):
        label = f"alert[{index}]"
        for error in _collect_alert_errors(alert):
            errors.append(f"{label}: {error}")

        alert_id = _valid_id(alert)
        if alert_id is None:
            continue
        if alert_id in seen_ids:
            errors.append(
                f"{label}: duplicate alert ID '{alert_id}' "
                f"(first seen at alert[{seen_ids[alert_id]}])"
            )
        else:
            seen_ids[alert_id] = index

    if errors:
        raise AlertValidationError(errors)


def _collect_alert_errors(alert: object) -> tuple[str, ...]:
    if not isinstance(alert, Mapping):
        return ("alert must be a mapping",)

    errors: list[str] = []
    for field in CANONICAL_ALERT_FIELDS:
        if field not in alert:
            errors.append(f"missing required field '{field}'")

    for field in CANONICAL_ALERT_FIELDS:
        if field not in alert:
            continue
        value = alert[field]
        text_error = _validate_text(field, value, required=field in _REQUIRED_TEXT_FIELDS)
        if text_error is not None:
            errors.append(text_error)

    if isinstance(alert.get("severity"), str) and alert["severity"] not in ALLOWED_SEVERITIES:
        errors.append(
            "invalid severity "
            f"'{alert['severity']}'; expected one of {sorted(ALLOWED_SEVERITIES)}"
        )

    if isinstance(alert.get("timestamp"), str) and not _is_parseable_timestamp(alert["timestamp"]):
        errors.append(f"invalid timestamp '{alert['timestamp']}'")

    for field in _IP_FIELDS:
        value = alert.get(field)
        if isinstance(value, str) and value and not _is_valid_ip(value):
            errors.append(f"invalid {field} '{value}'")

    return tuple(errors)


def _validate_text(field: str, value: object, *, required: bool) -> str | None:
    if not isinstance(value, str):
        return f"field '{field}' must be a string"
    if required and not value.strip():
        return f"field '{field}' must not be empty"
    if _CONTROL_CHARACTERS.search(value):
        return f"field '{field}' contains control characters"
    return None


def _is_parseable_timestamp(value: str) -> bool:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return True


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _valid_id(alert: object) -> str | None:
    if not isinstance(alert, Mapping):
        return None
    value = alert.get("id")
    if isinstance(value, str) and value.strip():
        return value
    return None
