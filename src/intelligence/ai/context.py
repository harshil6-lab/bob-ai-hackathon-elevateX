"""Deterministic structured context for future AI reasoning providers."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ..correlation import CorrelatedAlertGroup
from ..evidence import EvidenceCollection
from ..mitre import MitreMappingResult
from ..scoring import ThreatAssessment


@dataclass(frozen=True, slots=True)
class AIAlertContext:
    alert_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str
    host: str | None
    user: str | None
    source_ip: str | None
    destination_ip: str | None
    description: str


@dataclass(frozen=True, slots=True)
class AICorrelationRelationshipContext:
    left_alert_id: str
    right_alert_id: str
    reasons: tuple[str, ...]
    relationship_score: int


@dataclass(frozen=True, slots=True)
class AIScoringFactorContext:
    name: str
    value: int
    maximum: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AIScoringContext:
    risk_score: int
    severity: str
    confidence: int
    false_positive_assessment: str
    false_positive_reasons: tuple[str, ...]
    false_positive_confidence: int
    false_positive_adjustment: int
    affected_assets: tuple[str, ...]
    sources: tuple[str, ...]
    source_count: int
    alert_count: int
    scoring_factors: tuple[AIScoringFactorContext, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AIEvidenceContext:
    evidence_id: str
    alert_id: str
    evidence_type: str
    description: str
    rationale: str


@dataclass(frozen=True, slots=True)
class AIMitreMappingContext:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: int
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AIContext:
    incident_id: str
    alert_ids: tuple[str, ...]
    alerts: tuple[AIAlertContext, ...]
    correlation_reasons: tuple[str, ...]
    correlation_relationships: tuple[AICorrelationRelationshipContext, ...]
    scoring: AIScoringContext
    evidence_ids: tuple[str, ...]
    evidence_records: tuple[AIEvidenceContext, ...]
    mitre_catalog_version: str
    mitre_technique_ids: tuple[str, ...]
    mitre_mappings: tuple[AIMitreMappingContext, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_ai_context(
    group: CorrelatedAlertGroup,
    assessment: ThreatAssessment,
    evidence: EvidenceCollection,
    mitre: MitreMappingResult,
) -> AIContext:
    alerts = tuple(sorted(group.alerts, key=lambda alert: (alert.timestamp, alert.id)))
    alert_contexts = tuple(_alert_context(alert) for alert in alerts)
    relationships = tuple(
        sorted(
            group.relationships,
            key=lambda relationship: (
                relationship.left_alert_id,
                relationship.right_alert_id,
            ),
        )
    )
    relationship_contexts = tuple(
        AICorrelationRelationshipContext(
            left_alert_id=relationship.left_alert_id,
            right_alert_id=relationship.right_alert_id,
            reasons=tuple(sorted(relationship.reasons)),
            relationship_score=relationship.relationship_score,
        )
        for relationship in relationships
    )
    scoring_factors = tuple(
        sorted(
            (
                AIScoringFactorContext(
                    name=factor.name,
                    value=factor.value,
                    maximum=factor.maximum,
                    reasons=tuple(sorted(factor.reasons)),
                )
                for factor in assessment.scoring_factors
            ),
            key=lambda factor: factor.name,
        )
    )
    scoring_context = AIScoringContext(
        risk_score=assessment.risk_score,
        severity=assessment.severity,
        confidence=assessment.confidence,
        false_positive_assessment=assessment.false_positive_assessment.value,
        false_positive_reasons=tuple(sorted(assessment.false_positive_reasons)),
        false_positive_confidence=assessment.false_positive_confidence,
        false_positive_adjustment=assessment.false_positive_adjustment,
        affected_assets=tuple(sorted(assessment.affected_assets)),
        sources=tuple(sorted(assessment.sources)),
        source_count=assessment.source_count,
        alert_count=assessment.alert_count,
        scoring_factors=scoring_factors,
        reasons=tuple(sorted(assessment.reasons)),
    )
    evidence_records = tuple(
        sorted(evidence.records, key=lambda record: record.evidence_id)
    )
    evidence_contexts = tuple(
        AIEvidenceContext(
            evidence_id=record.evidence_id,
            alert_id=record.alert_id,
            evidence_type=record.evidence_type,
            description=record.description,
            rationale=record.rationale,
        )
        for record in evidence_records
    )
    mitre_mappings = tuple(
        sorted(mitre.mappings, key=lambda mapping: mapping.technique_id)
    )
    mitre_contexts = tuple(
        AIMitreMappingContext(
            technique_id=mapping.technique_id,
            technique_name=mapping.technique_name,
            tactic=mapping.tactic,
            confidence=mapping.confidence,
            evidence_ids=tuple(sorted(mapping.evidence_ids)),
        )
        for mapping in mitre_mappings
    )

    return AIContext(
        incident_id=group.group_id,
        alert_ids=tuple(alert.alert_id for alert in alert_contexts),
        alerts=alert_contexts,
        correlation_reasons=tuple(sorted(group.correlation_reasons)),
        correlation_relationships=relationship_contexts,
        scoring=scoring_context,
        evidence_ids=tuple(record.evidence_id for record in evidence_contexts),
        evidence_records=evidence_contexts,
        mitre_catalog_version=mitre.catalog_version,
        mitre_technique_ids=tuple(mapping.technique_id for mapping in mitre_contexts),
        mitre_mappings=mitre_contexts,
    )


def _alert_context(alert: object) -> AIAlertContext:
    timestamp = getattr(alert, "timestamp", "")
    return AIAlertContext(
        alert_id=getattr(alert, "id", ""),
        timestamp=timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
        source=getattr(alert, "source", ""),
        event_type=getattr(alert, "event_type", ""),
        severity=getattr(alert, "severity", ""),
        host=_optional(getattr(alert, "host", "")),
        user=_optional(getattr(alert, "user", "")),
        source_ip=_optional(getattr(alert, "source_ip", "")),
        destination_ip=_optional(getattr(alert, "destination_ip", "")),
        description=getattr(alert, "description", ""),
    )


def _optional(value: str) -> str | None:
    return value if value else None
