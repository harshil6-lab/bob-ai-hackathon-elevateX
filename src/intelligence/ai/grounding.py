"""Deterministic grounding validation for structured AI reasoning output."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .context import AIContext


class GroundingIssueType(str, Enum):
    """Stable categories for grounding-validation failures."""

    INVALID_INCIDENT_ID = "invalid_incident_id"
    INVALID_ALERT_ID = "invalid_alert_id"
    INVALID_EVIDENCE_ID = "invalid_evidence_id"
    INVALID_MITRE_TECHNIQUE_ID = "invalid_mitre_technique_id"
    INVALID_HOST = "invalid_host"
    INVALID_USER = "invalid_user"
    INVALID_SOURCE_IP = "invalid_source_ip"
    INVALID_DESTINATION_IP = "invalid_destination_ip"
    INVALID_ASSET = "invalid_asset"
    UNKNOWN_NUMERIC_FIELD = "unknown_numeric_field"
    INVALID_NUMERIC_VALUE = "invalid_numeric_value"
    INVALID_NUMERIC_CLAIM = "invalid_numeric_claim"


@dataclass(frozen=True, slots=True)
class AINumericClaim:
    """A structured numeric claim that can be checked against AI context."""

    name: str
    value: int


@dataclass(frozen=True, slots=True)
class AIReasoningOutput:
    """Internal machine-validatable output from a future AI provider.

    ``summary`` and ``reasoning`` are natural-language fields. They are not
    parsed or evaluated by the grounding validator. Only structured references
    and numeric claims are validated.
    """

    incident_id: str
    summary: str
    reasoning: str
    referenced_alert_ids: tuple[str, ...] = ()
    referenced_evidence_ids: tuple[str, ...] = ()
    referenced_mitre_technique_ids: tuple[str, ...] = ()
    referenced_hosts: tuple[str, ...] = ()
    referenced_users: tuple[str, ...] = ()
    referenced_source_ips: tuple[str, ...] = ()
    referenced_destination_ips: tuple[str, ...] = ()
    referenced_assets: tuple[str, ...] = ()
    numeric_claims: tuple[AINumericClaim, ...] = ()


@dataclass(frozen=True, slots=True)
class GroundingIssue:
    """One deterministic grounding failure."""

    issue_type: GroundingIssueType
    value: str
    message: str


@dataclass(frozen=True, slots=True)
class GroundingResult:
    """Result of validating structured AI output against established context."""

    issues: tuple[GroundingIssue, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.issues


def validate_ai_output(context: AIContext, output: AIReasoningOutput) -> GroundingResult:
    """Validate structured references and numeric claims deterministically.

    This function does not prove the truth of arbitrary natural-language text.
    It checks that machine-readable references used by the AI output exist in
    the supplied deterministic context.
    """

    expected_hosts = {
        alert.host for alert in context.alerts if alert.host is not None
    }
    expected_users = {
        alert.user for alert in context.alerts if alert.user is not None
    }
    expected_source_ips = {
        alert.source_ip for alert in context.alerts if alert.source_ip is not None
    }
    expected_destination_ips = {
        alert.destination_ip
        for alert in context.alerts
        if alert.destination_ip is not None
    }

    issues: list[GroundingIssue] = []
    issues.extend(
        _validate_references(
            (output.incident_id,),
            {context.incident_id},
            GroundingIssueType.INVALID_INCIDENT_ID,
            "incident ID",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_alert_ids,
            set(context.alert_ids),
            GroundingIssueType.INVALID_ALERT_ID,
            "alert ID",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_evidence_ids,
            set(context.evidence_ids),
            GroundingIssueType.INVALID_EVIDENCE_ID,
            "evidence ID",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_mitre_technique_ids,
            set(context.mitre_technique_ids),
            GroundingIssueType.INVALID_MITRE_TECHNIQUE_ID,
            "MITRE technique ID",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_hosts,
            expected_hosts,
            GroundingIssueType.INVALID_HOST,
            "host",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_users,
            expected_users,
            GroundingIssueType.INVALID_USER,
            "user",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_source_ips,
            expected_source_ips,
            GroundingIssueType.INVALID_SOURCE_IP,
            "source IP",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_destination_ips,
            expected_destination_ips,
            GroundingIssueType.INVALID_DESTINATION_IP,
            "destination IP",
        )
    )
    issues.extend(
        _validate_references(
            output.referenced_assets,
            set(context.scoring.affected_assets),
            GroundingIssueType.INVALID_ASSET,
            "asset",
        )
    )
    issues.extend(_validate_numeric_claims(context, output.numeric_claims))

    return GroundingResult(issues=tuple(issues))


def _validate_references(
    values: object,
    expected: set[str],
    issue_type: GroundingIssueType,
    label: str,
) -> list[GroundingIssue]:
    """Validate references without evaluating their content."""

    issues: list[GroundingIssue] = []
    if not isinstance(values, (list, tuple)):
        issues.append(
            GroundingIssue(
                issue_type=issue_type,
                value=_display_value(values),
                message=f"Referenced {label} values must be a list or tuple.",
            )
        )
        return issues

    seen: set[str] = set()

    for value in values:
        if not isinstance(value, str) or not value:
            issues.append(
                GroundingIssue(
                    issue_type=issue_type,
                    value=_display_value(value),
                    message=f"Referenced {label} must be a non-empty string.",
                )
            )
            continue
        if value in seen:
            continue
        seen.add(value)
        if value not in expected:
            issues.append(
                GroundingIssue(
                    issue_type=issue_type,
                    value=value,
                    message=f"Referenced {label} is not present in the structured context.",
                )
            )

    return issues


def _validate_numeric_claims(
    context: AIContext,
    claims: object,
) -> list[GroundingIssue]:
    """Validate numeric claims against values already established upstream."""

    expected_values = {
        "alert_count": context.scoring.alert_count,
        "source_count": context.scoring.source_count,
        "evidence_count": len(context.evidence_ids),
        "mitre_technique_count": len(context.mitre_technique_ids),
        "risk_score": context.scoring.risk_score,
        "confidence": context.scoring.confidence,
    }
    issues: list[GroundingIssue] = []
    if not isinstance(claims, (list, tuple)):
        issues.append(
            GroundingIssue(
                issue_type=GroundingIssueType.INVALID_NUMERIC_CLAIM,
                value=_display_value(claims),
                message="Numeric claims must be a list or tuple.",
            )
        )
        return issues

    seen: set[tuple[object, object]] = set()

    for claim in claims:
        if not isinstance(claim, AINumericClaim):
            issues.append(
                GroundingIssue(
                    issue_type=GroundingIssueType.INVALID_NUMERIC_CLAIM,
                    value=_display_value(claim),
                    message="Numeric claim must use the AINumericClaim structure.",
                )
            )
            continue

        identity = (claim.name, claim.value)
        if identity in seen:
            continue
        seen.add(identity)

        if claim.name not in expected_values:
            issues.append(
                GroundingIssue(
                    issue_type=GroundingIssueType.UNKNOWN_NUMERIC_FIELD,
                    value=claim.name,
                    message="Numeric claim field is not present in the structured context.",
                )
            )
            continue
        if not isinstance(claim.value, int) or isinstance(claim.value, bool):
            issues.append(
                GroundingIssue(
                    issue_type=GroundingIssueType.INVALID_NUMERIC_VALUE,
                    value=_display_value(claim.value),
                    message=f"Numeric claim for {claim.name} must be an integer.",
                )
            )
            continue
        if claim.value != expected_values[claim.name]:
            issues.append(
                GroundingIssue(
                    issue_type=GroundingIssueType.INVALID_NUMERIC_CLAIM,
                    value=_display_value(claim.value),
                    message=f"Numeric claim for {claim.name} does not match the structured context.",
                )
            )

    return issues


def _display_value(value: object) -> str:
    """Return a bounded display value without evaluating untrusted content."""

    if value is None:
        return "null"
    if isinstance(value, str):
        return value
    return type(value).__name__
