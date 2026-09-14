"""Deterministic evaluation harness for golden intelligence scenarios."""

from __future__ import annotations

from dataclasses import dataclass

from .evaluation_data import GOLDEN_SCENARIOS, GoldenScenario
from .pipeline import IntelligenceAnalysis, IntelligenceIncident, analyze


@dataclass(frozen=True, slots=True)
class EvaluationCheck:
    """One structured evaluation result."""

    name: str
    passed: bool
    message: str


@dataclass(frozen=True, slots=True)
class ScenarioEvaluationResult:
    """Evaluation result for one golden scenario."""

    scenario_name: str
    checks: tuple[EvaluationCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)


@dataclass(frozen=True, slots=True)
class GoldenEvaluationResult:
    """Aggregate evaluation result for every golden scenario."""

    results: tuple[ScenarioEvaluationResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)


def evaluate_scenario(scenario: GoldenScenario) -> ScenarioEvaluationResult:
    """Evaluate one golden scenario against fixed expectations."""

    analysis = analyze(scenario.alerts)
    checks = (
        _check_incident_count(scenario, analysis),
        _check_risk_score(scenario, analysis),
        _check_confidence(scenario, analysis),
        _check_severity(scenario, analysis),
        _check_false_positive_assessment(scenario, analysis),
        _check_mitre_techniques(scenario, analysis),
        _check_alert_count(scenario, analysis),
        _check_source_count(scenario, analysis),
        _check_evidence_types(scenario, analysis),
        _check_action_categories(scenario, analysis),
        _check_forbidden_action_categories(scenario, analysis),
        _check_cross_group_isolation(scenario, analysis),
        _check_evidence_traceability(scenario, analysis),
        _check_bluf_and_actions_generated(scenario, analysis),
    )

    return ScenarioEvaluationResult(
        scenario_name=scenario.name,
        checks=tuple(check for check in checks if check is not None),
    )


def evaluate_golden_scenarios() -> GoldenEvaluationResult:
    """Evaluate every fixed golden scenario."""

    return GoldenEvaluationResult(
        results=tuple(evaluate_scenario(scenario) for scenario in GOLDEN_SCENARIOS)
    )


def _check_incident_count(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    expected = scenario.expectations.incident_count
    actual = len(analysis.incidents)
    return EvaluationCheck(
        name="incident_count",
        passed=actual == expected,
        message=f"expected {expected}, got {actual}",
    )


def _check_risk_score(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    expectations = scenario.expectations
    if expectations.expected_risk_score is None:
        return _skipped_check("risk_score")

    expected = expectations.expected_risk_score
    passed = all(
        incident.record.risk_score == expected
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="risk_score",
        passed=passed,
        message=f"expected {expected} for every incident",
    )


def _check_confidence(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    expectations = scenario.expectations
    if expectations.expected_confidence is None:
        return _skipped_check("confidence")

    expected = expectations.expected_confidence
    passed = all(
        incident.record.confidence == expected
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="confidence",
        passed=passed,
        message=f"expected {expected} for every incident",
    )


def _check_severity(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    expected = scenario.expectations.expected_severity
    if expected is None:
        return _skipped_check("severity")

    passed = all(
        incident.record.severity == expected
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="severity",
        passed=passed,
        message=f"expected {expected} for every incident",
    )


def _check_false_positive_assessment(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    expected = scenario.expectations.expected_false_positive_assessment
    if expected is None:
        return _skipped_check("false_positive_assessment")

    passed = all(
        incident.record.false_positive_assessment.value == expected
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="false_positive_assessment",
        passed=passed,
        message=f"expected {expected} for every incident",
    )


def _check_mitre_techniques(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    expected = set(scenario.expectations.expected_mitre_technique_ids)
    actual = {
        technique_id
        for incident in analysis.incidents
        for technique_id in incident.record.mitre_techniques
    }
    return EvaluationCheck(
        name="mitre_techniques",
        passed=actual == expected,
        message=f"expected {sorted(expected)}, got {sorted(actual)}",
    )


def _check_alert_count(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    minimum = scenario.expectations.min_alert_count
    if minimum is None:
        return _skipped_check("alert_count")

    passed = all(
        incident.record.alert_count >= minimum
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="alert_count",
        passed=passed,
        message=f"expected at least {minimum} alerts per incident",
    )


def _check_source_count(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    minimum = scenario.expectations.min_source_count
    if minimum is None:
        return _skipped_check("source_count")

    passed = all(
        len(incident.record.sources) >= minimum
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="source_count",
        passed=passed,
        message=f"expected at least {minimum} sources per incident",
    )


def _check_evidence_types(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    required = set(scenario.expectations.required_evidence_types)
    actual = {
        evidence_record.evidence_type
        for incident in analysis.incidents
        for evidence_record in incident.evidence.records
    }
    passed = required.issubset(actual)
    return EvaluationCheck(
        name="evidence_types",
        passed=passed,
        message=f"required {sorted(required)}, got {sorted(actual)}",
    )


def _check_action_categories(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    required = set(scenario.expectations.required_action_categories)
    actual = {
        action.category
        for incident in analysis.incidents
        for action in incident.actions.actions
    }
    passed = required.issubset(actual)
    return EvaluationCheck(
        name="action_categories",
        passed=passed,
        message=f"required {sorted(required)}, got {sorted(actual)}",
    )


def _check_forbidden_action_categories(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    forbidden = set(scenario.expectations.forbidden_action_categories)
    actual = {
        action.category
        for incident in analysis.incidents
        for action in incident.actions.actions
    }
    passed = not (forbidden & actual)
    return EvaluationCheck(
        name="forbidden_action_categories",
        passed=passed,
        message=f"forbidden {sorted(forbidden)}, got {sorted(actual)}",
    )


def _check_cross_group_isolation(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    if len(analysis.incidents) < 2:
        return _skipped_check("cross_group_isolation")

    alert_ids = [
        set(incident.record.correlated_alert_ids)
        for incident in analysis.incidents
    ]
    evidence_ids = [
        set(incident.record.evidence)
        for incident in analysis.incidents
    ]
    mitre_evidence_ids = [
        {
            evidence_id
            for mapping in incident.mitre.mappings
            for evidence_id in mapping.evidence_ids
        }
        for incident in analysis.incidents
    ]
    action_evidence_ids = [
        {
            evidence_id
            for action in incident.actions.actions
            for evidence_id in action.evidence_ids
        }
        for incident in analysis.incidents
    ]

    passed = True
    for index in range(len(analysis.incidents)):
        for other_index in range(index + 1, len(analysis.incidents)):
            passed = passed and not (
                alert_ids[index] & alert_ids[other_index]
                or evidence_ids[index] & evidence_ids[other_index]
                or mitre_evidence_ids[index] & mitre_evidence_ids[other_index]
                or action_evidence_ids[index] & action_evidence_ids[other_index]
            )

    return EvaluationCheck(
        name="cross_group_isolation",
        passed=passed,
        message="incidents must not share alert, evidence, MITRE, or action references",
    )


def _check_evidence_traceability(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    passed = True
    for incident in analysis.incidents:
        alert_ids = set(incident.record.correlated_alert_ids)
        evidence_ids = set(incident.record.evidence)
        passed = passed and all(
            evidence_record.alert_id in alert_ids
            for evidence_record in incident.evidence.records
        )
        passed = passed and all(
            set(mapping.evidence_ids).issubset(evidence_ids)
            for mapping in incident.mitre.mappings
        )
        passed = passed and all(
            set(action.evidence_ids).issubset(evidence_ids)
            and set(action.alert_ids).issubset(alert_ids)
            for action in incident.actions.actions
        )

    return EvaluationCheck(
        name="evidence_traceability",
        passed=passed,
        message="every evidence, MITRE, and action reference must stay traceable",
    )


def _check_bluf_and_actions_generated(
    scenario: GoldenScenario,
    analysis: IntelligenceAnalysis,
) -> EvaluationCheck:
    passed = all(
        incident.record.bluf and incident.record.recommended_actions
        for incident in analysis.incidents
    )
    return EvaluationCheck(
        name="bluf_and_actions_generated",
        passed=passed,
        message="every incident must produce BLUF and recommended actions",
    )


def _skipped_check(name: str) -> EvaluationCheck:
    return EvaluationCheck(
        name=name,
        passed=True,
        message="not asserted for this scenario",
    )
