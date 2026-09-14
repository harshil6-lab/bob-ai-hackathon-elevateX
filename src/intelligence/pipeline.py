"""End-to-end orchestration for the deterministic intelligence engine."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .actions import RecommendedActionCollection, generate_recommended_actions
from .ai.context import build_ai_context
from .ai.provider import AIReasoningProvider
from .bluf import Bluf, generate_bluf
from .correlation import CorrelatedAlertGroup, correlate_alerts
from .evidence import EvidenceCollection, extract_evidence
from .mitre import MitreMappingResult, map_mitre_behaviors
from .models import Action, FalsePositiveAssessment, IncidentRecord
from .scoring import ThreatAssessment, ThreatAssessmentResult, assess_threat
from .validation import validate_alerts


@dataclass(frozen=True, slots=True)
class IntelligenceIncident:
    """One correlated group with all deterministic intelligence artifacts."""

    record: IncidentRecord
    assessment: ThreatAssessment
    evidence: EvidenceCollection
    mitre: MitreMappingResult
    bluf: Bluf
    actions: RecommendedActionCollection


@dataclass(frozen=True, slots=True)
class IntelligenceAnalysis:
    """Internal analysis result for one complete alert batch."""

    incidents: tuple[IntelligenceIncident, ...]

    def to_public_incidents(self) -> tuple[dict[str, object], ...]:
        """Return the frozen public representation for every incident."""

        return tuple(
            incident.record.to_public_incident()
            for incident in self.incidents
        )


def analyze(
    alerts: Iterable[Mapping[str, Any]],
    provider: AIReasoningProvider | None = None,
) -> IntelligenceAnalysis:
    """Run the complete deterministic intelligence pipeline.

    Validation failures propagate to the caller. Optional AI-provider failures
    are handled by the existing BLUF fallback and never replace deterministic
    intelligence.
    """

    alert_list = list(alerts)
    validate_alerts(alert_list)
    groups = correlate_alerts(alert_list)

    incidents = tuple(
        _analyze_group(group, provider)
        for group in groups
    )
    return IntelligenceAnalysis(incidents=incidents)


def _analyze_group(
    group: CorrelatedAlertGroup,
    provider: AIReasoningProvider | None,
) -> IntelligenceIncident:
    assessment = assess_threat(group)
    evidence = extract_evidence(group)
    mitre = map_mitre_behaviors(group.alerts, evidence)
    context = build_ai_context(group, assessment, evidence, mitre)
    bluf = generate_bluf(context, provider)
    actions = generate_recommended_actions(context)

    record = IncidentRecord(
        id=group.group_id,
        severity=assessment.severity,
        confidence=assessment.confidence,
        status="investigating",
        affected_assets=assessment.affected_assets,
        alert_count=assessment.alert_count,
        sources=assessment.sources,
        mitre_techniques=mitre.technique_ids,
        evidence=evidence.evidence_ids,
        bluf=bluf.summary,
        recommended_actions=actions.to_public_recommended_actions(),
        correlated_alert_ids=group.alert_ids,
        risk_score=assessment.risk_score,
        false_positive_assessment=_false_positive_assessment(assessment),
        false_positive_reasons=assessment.false_positive_reasons,
        mitre_mappings=mitre.mappings,
        evidence_records=evidence.records,
        actions=tuple(
            Action(
                action=action.recommendation,
                rationale=action.rationale,
                evidence_ids=action.evidence_ids,
            )
            for action in actions.actions
        ),
    )

    return IntelligenceIncident(
        record=record,
        assessment=assessment,
        evidence=evidence,
        mitre=mitre,
        bluf=bluf,
        actions=actions,
    )


def _false_positive_assessment(
    assessment: ThreatAssessment,
) -> FalsePositiveAssessment:
    if assessment.false_positive_assessment is ThreatAssessmentResult.LIKELY_FALSE_POSITIVE:
        return FalsePositiveAssessment.LIKELY_FALSE_POSITIVE
    if assessment.false_positive_assessment is ThreatAssessmentResult.SUSPICIOUS:
        return FalsePositiveAssessment.POSSIBLE_FALSE_POSITIVE
    return FalsePositiveAssessment.LIKELY_GENUINE
