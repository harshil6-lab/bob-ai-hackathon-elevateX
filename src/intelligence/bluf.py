"""Evidence-grounded BLUF generation for correlated intelligence.

The deterministic generator is authoritative. A future AI provider may explain
the same established intelligence, but invalid provider output never replaces
the deterministic result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Literal

from .ai.context import AIContext
from .ai.grounding import AIReasoningOutput, validate_ai_output
from .ai.provider import AIReasoningProvider


BlufSource = Literal["deterministic", "ai"]


@dataclass(frozen=True, slots=True)
class BlufFinding:
    """One deterministic finding with its supporting intelligence references."""

    statement: str
    alert_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    mitre_technique_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Bluf:
    """Internal structured BLUF result.

    Public incident serialization remains unchanged. This representation gives
    later pipeline stages structured, traceable fields plus explanation text.
    """

    incident_id: str
    summary: str
    reasoning: str
    severity: str
    risk_score: int
    confidence: int
    false_positive_assessment: str
    alert_count: int
    source_count: int
    sources: tuple[str, ...]
    affected_assets: tuple[str, ...]
    alert_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    mitre_technique_ids: tuple[str, ...]
    hosts: tuple[str, ...]
    users: tuple[str, ...]
    source_ips: tuple[str, ...]
    destination_ips: tuple[str, ...]
    key_findings: tuple[BlufFinding, ...]
    generated_by: BlufSource

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def generate_deterministic_bluf(context: AIContext) -> Bluf:
    """Generate the authoritative BLUF without an AI provider."""

    return Bluf(
        incident_id=context.incident_id,
        summary=_summary(context),
        reasoning=_reasoning(context),
        severity=context.scoring.severity,
        risk_score=context.scoring.risk_score,
        confidence=context.scoring.confidence,
        false_positive_assessment=context.scoring.false_positive_assessment,
        alert_count=context.scoring.alert_count,
        source_count=context.scoring.source_count,
        sources=context.scoring.sources,
        affected_assets=context.scoring.affected_assets,
        alert_ids=context.alert_ids,
        evidence_ids=context.evidence_ids,
        mitre_technique_ids=context.mitre_technique_ids,
        hosts=_values(alert.host for alert in context.alerts),
        users=_values(alert.user for alert in context.alerts),
        source_ips=_values(alert.source_ip for alert in context.alerts),
        destination_ips=_values(alert.destination_ip for alert in context.alerts),
        key_findings=_key_findings(context),
        generated_by="deterministic",
    )


def generate_bluf(
    context: AIContext,
    provider: AIReasoningProvider | None = None,
) -> Bluf:
    """Generate a BLUF, falling back deterministically on any AI failure.

    Provider output is used only when it is an ``AIReasoningOutput`` and passes
    the existing grounding validator. Deterministic scoring, correlation,
    evidence, and MITRE results always remain authoritative.
    """

    deterministic = generate_deterministic_bluf(context)
    if provider is None:
        return deterministic

    try:
        output = provider.generate_reasoning(context)
    except Exception:
        return deterministic

    if not isinstance(output, AIReasoningOutput):
        return deterministic
    if not isinstance(output.summary, str) or not isinstance(output.reasoning, str):
        return deterministic
    if not validate_ai_output(context, output).is_valid:
        return deterministic

    return replace(
        deterministic,
        summary=output.summary.strip() or deterministic.summary,
        reasoning=output.reasoning.strip() or deterministic.reasoning,
        alert_ids=_unique(output.referenced_alert_ids),
        evidence_ids=_unique(output.referenced_evidence_ids),
        mitre_technique_ids=_unique(output.referenced_mitre_technique_ids),
        hosts=_unique(output.referenced_hosts),
        users=_unique(output.referenced_users),
        source_ips=_unique(output.referenced_source_ips),
        destination_ips=_unique(output.referenced_destination_ips),
        affected_assets=_unique(output.referenced_assets),
        generated_by="ai",
    )


def _summary(context: AIContext) -> str:
    assessment = _assessment_label(context)
    asset_phrase = (
        f"affects {len(context.scoring.affected_assets)} "
        f"{_plural('asset', len(context.scoring.affected_assets))}"
        if context.scoring.affected_assets
        else "has no established affected assets"
    )

    return (
        f"Bottom line: {assessment}. Risk score "
        f"{context.scoring.risk_score}/100; confidence "
        f"{context.scoring.confidence}/100. "
        f"{context.scoring.alert_count} correlated "
        f"{_plural('alert', context.scoring.alert_count)} from "
        f"{context.scoring.source_count} "
        f"{_plural('source', context.scoring.source_count)} {asset_phrase}."
    )


def _reasoning(context: AIContext) -> str:
    parts = [
        f"Deterministic scoring assessed the activity as "
        f"{_assessment_label(context)}.",
        f"The group contains {context.scoring.alert_count} alerts from "
        f"{context.scoring.source_count} distinct sources.",
    ]
    if context.scoring.affected_assets:
        parts.append(
            "Affected assets: " + ", ".join(context.scoring.affected_assets) + "."
        )
    else:
        parts.append("No affected assets were established.")

    if context.mitre_technique_ids:
        parts.append(
            "Controlled MITRE mappings: "
            + ", ".join(context.mitre_technique_ids)
            + "."
        )
    else:
        parts.append("No controlled MITRE mappings were established.")

    return " ".join(parts)


def _key_findings(context: AIContext) -> tuple[BlufFinding, ...]:
    findings: list[BlufFinding] = []
    progression_records = tuple(
        record
        for record in context.evidence_records
        if record.evidence_type == "attack_progression_observation"
    )
    if progression_records:
        findings.append(
            BlufFinding(
                statement="Correlated alerts show attack progression.",
                alert_ids=_unique(record.alert_id for record in progression_records),
                evidence_ids=_unique(
                    record.evidence_id for record in progression_records
                ),
            )
        )

    for mapping in context.mitre_mappings:
        findings.append(
            BlufFinding(
                statement=(
                    f"Observed behavior maps to {mapping.technique_id} "
                    f"({mapping.technique_name}, {mapping.tactic})."
                ),
                alert_ids=_alert_ids_for_evidence(context, mapping.evidence_ids),
                evidence_ids=_unique(mapping.evidence_ids),
                mitre_technique_ids=(mapping.technique_id,),
            )
        )

    if context.scoring.source_count > 1:
        alert_observations = tuple(
            record
            for record in context.evidence_records
            if record.evidence_type == "alert_observation"
        )
        if alert_observations:
            findings.append(
                BlufFinding(
                    statement=(
                        f"Activity is corroborated by "
                        f"{context.scoring.source_count} distinct sources."
                    ),
                    alert_ids=context.alert_ids,
                    evidence_ids=_unique(
                        record.evidence_id for record in alert_observations
                    ),
                )
            )

    return tuple(findings)


def _alert_ids_for_evidence(
    context: AIContext,
    evidence_ids: tuple[str, ...],
) -> tuple[str, ...]:
    evidence_by_id = {
        record.evidence_id: record.alert_id
        for record in context.evidence_records
    }
    return _unique(
        evidence_by_id[evidence_id]
        for evidence_id in evidence_ids
        if evidence_id in evidence_by_id
    )


def _assessment_label(context: AIContext) -> str:
    if context.scoring.false_positive_assessment == "likely_false_positive":
        return "likely false-positive activity"
    if context.scoring.false_positive_assessment == "likely_threat":
        return f"{context.scoring.severity} threat activity"
    return f"{context.scoring.severity} suspicious activity"


def _values(values: object) -> tuple[str, ...]:
    return _unique(
        value for value in values if isinstance(value, str) and value
    )


def _unique(values: object) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for value in values
                if isinstance(value, str) and value
            }
        )
    )


def _plural(word: str, count: int) -> str:
    return word if count == 1 else f"{word}s"
