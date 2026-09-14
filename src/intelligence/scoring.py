"""Deterministic threat scoring and false-positive assessment.

This module deliberately separates three questions:

* Severity: how serious does the observed activity appear?
* Confidence: how well is the assessment corroborated?
* False-positive assessment: does the activity match explicit benign patterns?

The values below are transparent hackathon prototype heuristics. They are not
official defence-scoring standards and are not externally validated.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
import re
from typing import Final

from .contracts import Severity
from .correlation import CorrelatedAlertGroup
from .models import Alert, MitreMapping


class ThreatAssessmentResult(str, Enum):
    """Deterministic false-positive assessment result."""

    LIKELY_THREAT = "likely_threat"
    SUSPICIOUS = "suspicious"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


@dataclass(frozen=True, slots=True)
class ConfidenceConfig:
    """Centralized prototype weights for assessment confidence."""

    source_points: tuple[int, ...] = (15, 30, 40)
    alert_points: tuple[int, ...] = (10, 20, 30)
    relationship_points: tuple[int, ...] = (0, 10, 20)
    progression_points: int = 10
    suspicious_points: tuple[int, ...] = (0, 3, 6, 10)
    false_positive_penalty_divisor: int = 4


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    """Centralized prototype heuristics for deterministic threat scoring.

    The six base factors sum to 100 points. MITRE coverage is a separate,
    capped modifier that is neutral until mappings are supplied by a later
    intelligence stage. False-positive adjustment is a negative modifier.
    Final risk is always clamped to the 0-100 range.
    """

    low_severity_points: int = 8
    medium_severity_points: int = 16
    high_severity_points: int = 24
    critical_severity_points: int = 30

    correlation_points_per_alert: int = 2
    correlation_points_per_relationship: int = 2
    correlation_alert_cap: int = 5
    correlation_relationship_cap: int = 5

    source_diversity_points: tuple[int, ...] = (3, 8, 12, 15)

    suspicious_indicator_points: int = 3
    suspicious_indicator_cap: int = 5

    asset_impact_points: tuple[int, ...] = (4, 7, 10)

    attack_progression_points: int = 10

    mitre_points_per_technique: int = 2
    mitre_technique_cap: int = 5

    false_positive_adjustment: int = -20
    partial_false_positive_adjustment: int = -5
    strong_chain_false_positive_adjustment: int = -5

    severity_thresholds: tuple[int, int, int] = (25, 50, 75)

    confidence: ConfidenceConfig = ConfidenceConfig()


DEFAULT_SCORING_CONFIG: Final[ScoringConfig] = ScoringConfig()


@dataclass(frozen=True, slots=True)
class ScoringFactor:
    """One explainable scoring contribution or adjustment."""

    name: str
    value: int
    maximum: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    """Internal deterministic assessment for a correlated alert group."""

    risk_score: int
    severity: Severity
    confidence: int
    false_positive_assessment: ThreatAssessmentResult
    false_positive_reasons: tuple[str, ...]
    false_positive_confidence: int
    false_positive_adjustment: int
    affected_assets: tuple[str, ...]
    sources: tuple[str, ...]
    source_count: int
    alert_count: int
    scoring_factors: tuple[ScoringFactor, ...]
    reasons: tuple[str, ...]


_SUSPICIOUS_INDICATORS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "external suspicious activity",
        re.compile(r"external\s+suspicious\s+activity", re.IGNORECASE),
    ),
    (
        "PowerShell execution",
        re.compile(r"powershell", re.IGNORECASE),
    ),
    (
        "suspicious process",
        re.compile(r"suspicious\s+process|malicious\s+process|process\s+injection", re.IGNORECASE),
    ),
    (
        "credential access",
        re.compile(r"credential\s+access|credential\s+dumping|lsass|kerberoasting", re.IGNORECASE),
    ),
    (
        "remote connection",
        re.compile(r"remote\s+connection|remote\s+desktop|\brdp\b|\bssh\b", re.IGNORECASE),
    ),
    (
        "lateral movement",
        re.compile(r"lateral\s+movement|\bpsexec\b|\bsmb\b", re.IGNORECASE),
    ),
    (
        "data exfiltration",
        re.compile(r"data\s+exfiltration|exfiltration", re.IGNORECASE),
    ),
    (
        "privilege escalation",
        re.compile(r"privilege\s+escalation", re.IGNORECASE),
    ),
)

_BENIGN_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "documented health check",
        re.compile(r"health\s*check", re.IGNORECASE),
    ),
    (
        "routine monitoring",
        re.compile(r"routine\s+monitoring", re.IGNORECASE),
    ),
    (
        "scheduled administrative activity",
        re.compile(r"scheduled\s+administrative\s+activity", re.IGNORECASE),
    ),
    (
        "known benign scan",
        re.compile(r"benign\s+scan|known\s+benign", re.IGNORECASE),
    ),
)


def assess_threat(
    group: CorrelatedAlertGroup,
    config: ScoringConfig = DEFAULT_SCORING_CONFIG,
    mitre_mappings: Sequence[MitreMapping] = (),
) -> ThreatAssessment:
    """Produce a deterministic internal threat assessment for one group."""

    alerts = group.alerts
    sources = tuple(sorted({alert.source for alert in alerts if alert.source}))
    affected_assets = tuple(sorted({alert.host for alert in alerts if alert.host}))
    source_count = len(sources)
    alert_count = len(alerts)
    relationship_count = len(group.relationships)
    progression_present = "attack_progression" in group.correlation_reasons

    severity = _highest_severity(alerts)
    severity_points = _severity_points(severity, config)
    correlation_points = _correlation_points(alert_count, relationship_count, config)
    source_points = _points_from_tier(source_count, config.source_diversity_points)
    suspicious_indicators = _matched_indicators(alerts, _SUSPICIOUS_INDICATORS)
    suspicious_points = min(
        len(suspicious_indicators) * config.suspicious_indicator_points,
        config.suspicious_indicator_points * config.suspicious_indicator_cap,
    )
    asset_points = _points_from_tier(len(affected_assets), config.asset_impact_points)
    progression_points = config.attack_progression_points if progression_present else 0
    mitre_points = _mitre_points(mitre_mappings, config)

    false_positive = _false_positive_assessment(
        alerts,
        source_count,
        alert_count,
        progression_present,
        config,
    )

    scoring_factors = (
        ScoringFactor(
            name="severity_factor",
            value=severity_points,
            maximum=config.critical_severity_points,
            reasons=(f"Highest alert severity is {severity}.",),
        ),
        ScoringFactor(
            name="correlation_factor",
            value=correlation_points,
            maximum=(
                config.correlation_points_per_alert * config.correlation_alert_cap
                + config.correlation_points_per_relationship
                * config.correlation_relationship_cap
            ),
            reasons=(
                f"Correlated activity contains {alert_count} alerts "
                f"and {relationship_count} relationships.",
            ),
        ),
        ScoringFactor(
            name="source_diversity_factor",
            value=source_points,
            maximum=config.source_diversity_points[-1],
            reasons=(f"Activity is corroborated by {source_count} distinct sources.",),
        ),
        ScoringFactor(
            name="suspicious_indicator_factor",
            value=suspicious_points,
            maximum=config.suspicious_indicator_points * config.suspicious_indicator_cap,
            reasons=(
                f"Activity contains {len(suspicious_indicators)} distinct suspicious indicators.",
            ),
        ),
        ScoringFactor(
            name="asset_factor",
            value=asset_points,
            maximum=config.asset_impact_points[-1],
            reasons=(f"Activity affects {len(affected_assets)} distinct assets.",),
        ),
        ScoringFactor(
            name="progression_factor",
            value=progression_points,
            maximum=config.attack_progression_points,
            reasons=(
                "Observed events show attack progression."
                if progression_present
                else "No attack progression was detected."
            ),
        ),
        ScoringFactor(
            name="mitre_factor",
            value=mitre_points,
            maximum=config.mitre_points_per_technique * config.mitre_technique_cap,
            reasons=(
                "MITRE technique mappings were supplied."
                if mitre_mappings
                else "No MITRE technique mappings were supplied."
            ),
        ),
        ScoringFactor(
            name="false_positive_adjustment",
            value=false_positive.adjustment,
            maximum=abs(config.false_positive_adjustment),
            reasons=false_positive.reasons,
        ),
    )

    raw_score = sum(factor.value for factor in scoring_factors)
    risk_score = max(0, min(100, raw_score))
    public_severity = _severity_for_score(risk_score, config)
    confidence = _confidence(
        source_count,
        alert_count,
        relationship_count,
        progression_present,
        len(suspicious_indicators),
        false_positive.confidence,
        config.confidence,
    )
    reasons = tuple(
        reason for factor in scoring_factors for reason in factor.reasons
    )

    return ThreatAssessment(
        risk_score=risk_score,
        severity=public_severity,
        confidence=confidence,
        false_positive_assessment=false_positive.assessment,
        false_positive_reasons=false_positive.reasons,
        false_positive_confidence=false_positive.confidence,
        false_positive_adjustment=false_positive.adjustment,
        affected_assets=affected_assets,
        sources=sources,
        source_count=source_count,
        alert_count=alert_count,
        scoring_factors=scoring_factors,
        reasons=reasons,
    )


@dataclass(frozen=True, slots=True)
class _FalsePositiveResult:
    assessment: ThreatAssessmentResult
    reasons: tuple[str, ...]
    confidence: int
    adjustment: int


def _highest_severity(alerts: Sequence[Alert]) -> Severity:
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return max(
        (alert.severity for alert in alerts),
        key=lambda severity: severity_order[severity],
    )


def _severity_points(severity: Severity, config: ScoringConfig) -> int:
    if severity == "low":
        return config.low_severity_points
    if severity == "medium":
        return config.medium_severity_points
    if severity == "high":
        return config.high_severity_points
    return config.critical_severity_points


def _correlation_points(
    alert_count: int, relationship_count: int, config: ScoringConfig
) -> int:
    alert_points = min(alert_count, config.correlation_alert_cap) * config.correlation_points_per_alert
    relationship_points = (
        min(relationship_count, config.correlation_relationship_cap)
        * config.correlation_points_per_relationship
    )
    return alert_points + relationship_points


def _points_from_tier(count: int, tiers: tuple[int, ...]) -> int:
    if count <= 0:
        return 0
    return tiers[min(count, len(tiers)) - 1]


def _matched_indicators(
    alerts: Sequence[Alert],
    patterns: tuple[tuple[str, re.Pattern[str]], ...],
) -> tuple[str, ...]:
    matched = {
        label
        for alert in alerts
        for label, pattern in patterns
        if pattern.search(f"{alert.event_type} {alert.description}")
    }
    return tuple(sorted(matched))


def _mitre_points(
    mappings: Sequence[MitreMapping], config: ScoringConfig
) -> int:
    distinct_techniques = {mapping.technique_id for mapping in mappings}
    return min(
        len(distinct_techniques) * config.mitre_points_per_technique,
        config.mitre_points_per_technique * config.mitre_technique_cap,
    )


def _false_positive_assessment(
    alerts: Sequence[Alert],
    source_count: int,
    alert_count: int,
    progression_present: bool,
    config: ScoringConfig,
) -> _FalsePositiveResult:
    benign_alert_ids = {
        alert.id
        for alert in alerts
        if any(
            pattern.search(f"{alert.event_type} {alert.description}")
            for _, pattern in _BENIGN_PATTERNS
        )
    }

    if not benign_alert_ids:
        return _FalsePositiveResult(
            assessment=ThreatAssessmentResult.LIKELY_THREAT,
            reasons=("No explicit benign pattern was detected.",),
            confidence=0,
            adjustment=0,
        )

    all_alerts_benign = len(benign_alert_ids) == alert_count
    strong_chain = progression_present and source_count >= 2 and alert_count >= 3

    if all_alerts_benign and source_count <= 1 and not progression_present:
        return _FalsePositiveResult(
            assessment=ThreatAssessmentResult.LIKELY_FALSE_POSITIVE,
            reasons=(
                "All correlated alerts match explicit benign patterns.",
                "Activity is limited to a single source with no attack progression.",
            ),
            confidence=80,
            adjustment=config.false_positive_adjustment,
        )

    if strong_chain:
        return _FalsePositiveResult(
            assessment=ThreatAssessmentResult.LIKELY_THREAT,
            reasons=(
                "Some alerts match explicit benign patterns.",
                "Benign indicators are outweighed by corroborated attack progression.",
            ),
            confidence=20,
            adjustment=config.strong_chain_false_positive_adjustment,
        )

    return _FalsePositiveResult(
        assessment=ThreatAssessmentResult.SUSPICIOUS,
        reasons=("Some alerts match explicit benign patterns.",),
        confidence=50,
        adjustment=config.partial_false_positive_adjustment,
    )


def _severity_for_score(score: int, config: ScoringConfig) -> Severity:
    medium, high, critical = config.severity_thresholds
    if score < medium:
        return "low"
    if score < high:
        return "medium"
    if score < critical:
        return "high"
    return "critical"


def _confidence(
    source_count: int,
    alert_count: int,
    relationship_count: int,
    progression_present: bool,
    suspicious_indicator_count: int,
    false_positive_confidence: int,
    config: ConfidenceConfig,
) -> int:
    source_points = _points_from_tier(source_count, config.source_points)
    alert_points = _points_from_tier(alert_count, config.alert_points)
    relationship_points = _points_from_tier(
        relationship_count, config.relationship_points
    )
    progression_points = config.progression_points if progression_present else 0
    suspicious_points = _points_from_tier(
        suspicious_indicator_count, config.suspicious_points
    )
    false_positive_penalty = false_positive_confidence // config.false_positive_penalty_divisor

    confidence = (
        source_points
        + alert_points
        + relationship_points
        + progression_points
        + suspicious_points
        - false_positive_penalty
    )
    return max(0, min(100, confidence))
