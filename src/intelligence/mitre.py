"""Controlled MITRE ATT&CK behavior mapping.

This module maps observed alert behavior to a small, versioned, explicit
prototype catalog. It does not attempt to reproduce the full MITRE ATT&CK
knowledge base and never invents technique IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, Sequence

from .evidence import EvidenceCollection
from .models import Alert, MitreMapping


MITRE_CATALOG_VERSION: Final[str] = "prototype-1"


@dataclass(frozen=True, slots=True)
class MitreTechniqueRule:
    """One controlled technique rule in the prototype catalog."""

    technique_id: str
    technique_name: str
    tactic: str
    event_type_patterns: tuple[re.Pattern[str], ...]
    description_patterns: tuple[re.Pattern[str], ...]
    event_type_confidence: int
    description_confidence: int


MITRE_TECHNIQUE_CATALOG: Final[tuple[MitreTechniqueRule, ...]] = (
    MitreTechniqueRule(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        event_type_patterns=(
            re.compile(r"^powershell$", re.IGNORECASE),
            re.compile(r"^powershell\s+execution$", re.IGNORECASE),
            re.compile(r"^windows\s+powershell$", re.IGNORECASE),
        ),
        description_patterns=(
            re.compile(r"\bpowershell\b", re.IGNORECASE),
            re.compile(r"\bpowershell\s+(?:execution|script|command)s?\b", re.IGNORECASE),
        ),
        event_type_confidence=95,
        description_confidence=85,
    ),
    MitreTechniqueRule(
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        tactic="Credential Access",
        event_type_patterns=(
            re.compile(r"^credentialaccess$", re.IGNORECASE),
            re.compile(r"^credential\s+access$", re.IGNORECASE),
            re.compile(r"^credential\s+dumping$", re.IGNORECASE),
            re.compile(r"^os\s+credential\s+dumping$", re.IGNORECASE),
            re.compile(r"^lsass\s+access$", re.IGNORECASE),
            re.compile(r"^kerberoasting$", re.IGNORECASE),
        ),
        description_patterns=(
            re.compile(r"\bcredential\s+dumping\b", re.IGNORECASE),
            re.compile(r"\bcredential\s+access\b", re.IGNORECASE),
            re.compile(r"\blsass\b", re.IGNORECASE),
            re.compile(r"\bkerberoasting\b", re.IGNORECASE),
        ),
        event_type_confidence=95,
        description_confidence=85,
    ),
    MitreTechniqueRule(
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="Lateral Movement",
        event_type_patterns=(
            re.compile(r"^remoteconnection$", re.IGNORECASE),
            re.compile(r"^remote\s+services$", re.IGNORECASE),
            re.compile(r"^remote\s+connection$", re.IGNORECASE),
            re.compile(r"^remote\s+desktop$", re.IGNORECASE),
            re.compile(r"^rdp$", re.IGNORECASE),
            re.compile(r"^ssh$", re.IGNORECASE),
        ),
        description_patterns=(
            re.compile(r"\bremote\s+services\b", re.IGNORECASE),
            re.compile(r"\bremote\s+desktop\b", re.IGNORECASE),
            re.compile(r"\bremote\s+connection\b", re.IGNORECASE),
            re.compile(r"\brdp\b", re.IGNORECASE),
            re.compile(r"\bssh\b", re.IGNORECASE),
        ),
        event_type_confidence=95,
        description_confidence=85,
    ),
)


@dataclass(frozen=True, slots=True)
class MitreMappingResult:
    """Internal deterministic result for controlled MITRE mappings."""

    mappings: tuple[MitreMapping, ...]
    technique_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    catalog_version: str


def map_mitre_behaviors(
    alerts: Sequence[Alert],
    evidence: EvidenceCollection,
) -> MitreMappingResult:
    """Map supported alert behavior to controlled MITRE techniques.

    A technique is emitted only when at least one supplied evidence record is
    traceable to one of the supplied alerts and matches the technique rule.
    No evidence IDs are invented.
    """

    alert_by_id = {alert.id: alert for alert in alerts}
    mappings: list[MitreMapping] = []
    all_evidence_ids: set[str] = set()
    direct_evidence_types = {"alert_observation", "suspicious_indicator"}

    for rule in MITRE_TECHNIQUE_CATALOG:
        supporting_evidence_ids: set[str] = set()
        mapping_confidence = 0

        for evidence_record in evidence.records:
            if evidence_record.evidence_type not in direct_evidence_types:
                continue
            alert = alert_by_id.get(evidence_record.alert_id)
            if alert is None:
                continue
            if evidence_record.event_type != alert.event_type:
                continue
            if evidence_record.description != alert.description:
                continue

            confidence = _rule_confidence(rule, evidence_record)
            if confidence is None:
                continue

            supporting_evidence_ids.add(evidence_record.evidence_id)
            mapping_confidence = max(mapping_confidence, confidence)

        if not supporting_evidence_ids:
            continue

        mappings.append(
            MitreMapping(
                technique_id=rule.technique_id,
                technique_name=rule.technique_name,
                tactic=rule.tactic,
                confidence=mapping_confidence,
                evidence_ids=tuple(sorted(supporting_evidence_ids)),
            )
        )
        all_evidence_ids.update(supporting_evidence_ids)

    mappings.sort(key=lambda mapping: mapping.technique_id)
    technique_ids = tuple(sorted({mapping.technique_id for mapping in mappings}))
    evidence_ids = tuple(sorted(all_evidence_ids))

    return MitreMappingResult(
        mappings=tuple(mappings),
        technique_ids=technique_ids,
        evidence_ids=evidence_ids,
        catalog_version=MITRE_CATALOG_VERSION,
    )


def _rule_confidence(
    rule: MitreTechniqueRule,
    evidence_record: object,
) -> int | None:
    event_type = getattr(evidence_record, "event_type", "")
    description = getattr(evidence_record, "description", "")

    if any(pattern.search(event_type) for pattern in rule.event_type_patterns):
        return rule.event_type_confidence
    if any(pattern.search(description) for pattern in rule.description_patterns):
        return rule.description_confidence
    return None
