"""Typed internal models for deterministic intelligence processing."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from .contracts import IncidentLifecycleStatus, Severity


class FalsePositiveAssessment(str, Enum):
    """Deterministic assessment labels used internally by later stages."""

    LIKELY_GENUINE = "likely_genuine"
    POSSIBLE_FALSE_POSITIVE = "possible_false_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


@dataclass(frozen=True, slots=True)
class Alert:
    """Validated internal representation of a canonical alert."""

    id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: Severity
    source_ip: str
    destination_ip: str
    host: str
    user: str
    description: str


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single grounded evidence record derived from an alert."""

    evidence_id: str
    alert_id: str
    timestamp: datetime
    source: str
    event_type: str
    host: str
    user: str
    source_ip: str
    destination_ip: str
    description: str
    rationale: str
    evidence_type: str = "alert_observation"


@dataclass(frozen=True, slots=True)
class MitreMapping:
    """A controlled MITRE ATT&CK mapping with evidence references."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: int
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Action:
    """A recommended action with deterministic rationale and evidence links."""

    action: str
    rationale: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    """Internal incident representation plus processing metadata."""

    id: str
    severity: Severity
    confidence: int
    status: IncidentLifecycleStatus
    affected_assets: tuple[str, ...]
    alert_count: int
    sources: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    evidence: tuple[str, ...]
    bluf: str
    recommended_actions: tuple[str, ...]
    correlated_alert_ids: tuple[str, ...] = ()
    risk_score: float = 0.0
    false_positive_assessment: FalsePositiveAssessment = (
        FalsePositiveAssessment.POSSIBLE_FALSE_POSITIVE
    )
    false_positive_reasons: tuple[str, ...] = ()
    mitre_mappings: tuple[MitreMapping, ...] = ()
    evidence_records: tuple[Evidence, ...] = ()
    actions: tuple[Action, ...] = ()

    def to_public_incident(self) -> dict[str, object]:
        """Return only the frozen canonical public incident fields."""

        return {
            "id": self.id,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "affected_assets": list(self.affected_assets),
            "alert_count": self.alert_count,
            "sources": list(self.sources),
            "mitre_techniques": list(self.mitre_techniques),
            "evidence": list(self.evidence),
            "bluf": self.bluf,
            "recommended_actions": list(self.recommended_actions),
        }
