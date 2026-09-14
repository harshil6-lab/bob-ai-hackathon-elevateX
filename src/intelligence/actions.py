"""Deterministic recommended actions for established intelligence.

Actions are analyst-facing recommendations only. They never claim that an
action has already been performed and never invent supporting identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .ai.context import AIContext


ActionPriority = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class RecommendedAction:
    """One deterministic, evidence-linked analyst recommendation."""

    action_id: str
    priority: ActionPriority
    category: str
    recommendation: str
    rationale: str
    evidence_ids: tuple[str, ...]
    alert_ids: tuple[str, ...]
    mitre_technique_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecommendedActionCollection:
    """Internal action collection with a public-contract-compatible view."""

    actions: tuple[RecommendedAction, ...]

    def to_public_recommended_actions(self) -> tuple[str, ...]:
        """Return recommendation strings for Incident.recommended_actions."""

        return tuple(action.recommendation for action in self.actions)


def generate_recommended_actions(context: AIContext) -> RecommendedActionCollection:
    """Generate deterministic actions from already-established intelligence."""

    actions: list[RecommendedAction] = []
    actions.extend(_threat_actions(context))
    actions.extend(_technique_actions(context))
    actions.extend(_corroboration_actions(context))
    actions.extend(_false_positive_actions(context))

    ordered = tuple(
        sorted(
            actions,
            key=lambda action: (_priority_rank(action.priority), action.action_id),
        )
    )
    return RecommendedActionCollection(actions=ordered)


def _threat_actions(context: AIContext) -> list[RecommendedAction]:
    actions: list[RecommendedAction] = []
    severity = context.scoring.severity
    assessment = context.scoring.false_positive_assessment

    if severity in {"critical", "high"}:
        actions.append(
            RecommendedAction(
                action_id="ACTION-THREAT-INVESTIGATION",
                priority="critical" if severity == "critical" else "high",
                category="threat_investigation",
                recommendation=(
                    "Prioritize analyst investigation of the correlated alerts "
                    "and supporting evidence."
                ),
                rationale=(
                    f"Deterministic scoring assessed this activity as {severity} "
                    f"with risk {context.scoring.risk_score}/100 and confidence "
                    f"{context.scoring.confidence}/100."
                ),
                evidence_ids=context.evidence_ids,
                alert_ids=context.alert_ids,
            )
        )

    if (
        severity == "critical"
        and assessment == "likely_threat"
        and context.scoring.affected_assets
    ):
        actions.append(
            RecommendedAction(
                action_id="ACTION-CONTAINMENT-CONSIDERATION",
                priority="critical",
                category="containment_consideration",
                recommendation=(
                    "Consider isolating the affected host after analyst validation."
                ),
                rationale=(
                    "Critical likely-threat activity and established affected "
                    "assets justify considering containment after validation."
                ),
                evidence_ids=context.evidence_ids,
                alert_ids=context.alert_ids,
            )
        )

    if severity in {"medium", "low"}:
        actions.append(
            RecommendedAction(
                action_id="ACTION-ACTIVITY-REVIEW",
                priority="medium" if severity == "medium" else "low",
                category="activity_review",
                recommendation=(
                    "Review the correlated alerts and supporting evidence."
                ),
                rationale=(
                    f"Deterministic scoring assessed this activity as {severity} "
                    f"with risk {context.scoring.risk_score}/100."
                ),
                evidence_ids=context.evidence_ids,
                alert_ids=context.alert_ids,
            )
        )

    return actions


def _technique_actions(context: AIContext) -> list[RecommendedAction]:
    actions: list[RecommendedAction] = []
    evidence_alert_ids = _evidence_alert_ids(context)

    for mapping in context.mitre_mappings:
        if mapping.technique_id == "T1003":
            actions.append(
                RecommendedAction(
                    action_id="ACTION-CREDENTIAL-ACCESS-T1003",
                    priority="high",
                    category="credential_access",
                    recommendation=(
                        "Investigate possible credential exposure and review "
                        "authentication activity linked to the supporting alerts."
                    ),
                    rationale=(
                        "Controlled MITRE mapping T1003 is supported by supplied "
                        "evidence."
                    ),
                    evidence_ids=_unique(mapping.evidence_ids),
                    alert_ids=_unique(
                        evidence_alert_ids[evidence_id]
                        for evidence_id in mapping.evidence_ids
                        if evidence_id in evidence_alert_ids
                    ),
                    mitre_technique_ids=("T1003",),
                )
            )
        elif mapping.technique_id == "T1021":
            actions.append(
                RecommendedAction(
                    action_id="ACTION-REMOTE-SERVICES-T1021",
                    priority="high",
                    category="remote_services",
                    recommendation=(
                        "Investigate remote-service activity and review the source "
                        "and destination systems linked to the supporting alerts."
                    ),
                    rationale=(
                        "Controlled MITRE mapping T1021 is supported by supplied "
                        "evidence."
                    ),
                    evidence_ids=_unique(mapping.evidence_ids),
                    alert_ids=_unique(
                        evidence_alert_ids[evidence_id]
                        for evidence_id in mapping.evidence_ids
                        if evidence_id in evidence_alert_ids
                    ),
                    mitre_technique_ids=("T1021",),
                )
            )
        elif mapping.technique_id == "T1059.001":
            actions.append(
                RecommendedAction(
                    action_id="ACTION-POWERSHELL-T1059.001",
                    priority="medium",
                    category="powershell_execution",
                    recommendation=(
                        "Review PowerShell command and script execution details, "
                        "including the initiating process, user, and host where "
                        "available."
                    ),
                    rationale=(
                        "Controlled MITRE mapping T1059.001 is supported by "
                        "supplied evidence."
                    ),
                    evidence_ids=_unique(mapping.evidence_ids),
                    alert_ids=_unique(
                        evidence_alert_ids[evidence_id]
                        for evidence_id in mapping.evidence_ids
                        if evidence_id in evidence_alert_ids
                    ),
                    mitre_technique_ids=("T1059.001",),
                )
            )

    return actions


def _corroboration_actions(context: AIContext) -> list[RecommendedAction]:
    if context.scoring.source_count < 2:
        return []

    alert_observation_ids = tuple(
        record.evidence_id
        for record in context.evidence_records
        if record.evidence_type == "alert_observation"
    )
    return [
        RecommendedAction(
            action_id="ACTION-SOURCE-CORROBORATION",
            priority="medium",
            category="source_corroboration",
            recommendation=(
                "Cross-check the independent source observations for the "
                "correlated alerts."
            ),
            rationale=(
                f"The activity is corroborated by "
                f"{context.scoring.source_count} distinct sources."
            ),
            evidence_ids=_unique(alert_observation_ids),
            alert_ids=context.alert_ids,
        )
    ]


def _false_positive_actions(context: AIContext) -> list[RecommendedAction]:
    if context.scoring.false_positive_assessment != "likely_false_positive":
        return []

    return [
        RecommendedAction(
            action_id="ACTION-FALSE-POSITIVE-VALIDATION",
            priority="low",
            category="false_positive_validation",
            recommendation=(
                "Validate whether this activity is expected and compare it with "
                "known administrative or scheduled activity."
            ),
            rationale=(
                "Deterministic scoring assessed this activity as a likely "
                "false positive."
            ),
            evidence_ids=context.evidence_ids,
            alert_ids=context.alert_ids,
        )
    ]


def _evidence_alert_ids(context: AIContext) -> dict[str, str]:
    return {
        record.evidence_id: record.alert_id
        for record in context.evidence_records
    }


def _priority_rank(priority: ActionPriority) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}[priority]


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
