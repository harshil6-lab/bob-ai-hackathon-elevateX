from dataclasses import replace
import unittest

from src.intelligence.evaluation import (
    evaluate_golden_scenarios,
    evaluate_scenario,
)
from src.intelligence.evaluation_data import GOLDEN_SCENARIOS


class GoldenEvaluationTests(unittest.TestCase):
    def test_every_golden_scenario_passes(self) -> None:
        result = evaluate_golden_scenarios()

        self.assertTrue(result.passed)
        self.assertEqual(len(result.results), len(GOLDEN_SCENARIOS))

    def test_multi_source_attack_chain_expectations(self) -> None:
        scenario = self._scenario("multi_source_attack_chain")
        result = evaluate_scenario(scenario)

        self.assertTrue(result.passed)
        self.assertTrue(self._check(result, "mitre_techniques").passed)
        self.assertTrue(self._check(result, "evidence_types").passed)
        self.assertTrue(self._check(result, "action_categories").passed)

    def test_likely_false_positive_expectations(self) -> None:
        scenario = self._scenario("likely_false_positive")
        result = evaluate_scenario(scenario)

        self.assertTrue(result.passed)
        self.assertTrue(
            self._check(result, "false_positive_assessment").passed
        )
        self.assertTrue(
            self._check(result, "forbidden_action_categories").passed
        )

    def test_single_suspicious_alert_expectations(self) -> None:
        scenario = self._scenario("single_suspicious_alert")
        result = evaluate_scenario(scenario)

        self.assertTrue(result.passed)
        self.assertTrue(self._check(result, "mitre_techniques").passed)
        self.assertTrue(self._check(result, "evidence_types").passed)

    def test_multi_source_corroboration_expectations(self) -> None:
        scenario = self._scenario("multi_source_corroboration")
        result = evaluate_scenario(scenario)

        self.assertTrue(result.passed)
        self.assertTrue(self._check(result, "source_count").passed)
        self.assertTrue(self._check(result, "action_categories").passed)

    def test_multiple_independent_incidents_expectations(self) -> None:
        scenario = self._scenario("multiple_independent_incidents")
        result = evaluate_scenario(scenario)

        self.assertTrue(result.passed)
        self.assertTrue(self._check(result, "incident_count").passed)
        self.assertTrue(self._check(result, "cross_group_isolation").passed)

    def test_evaluation_detects_wrong_mitre_expectation(self) -> None:
        scenario = self._scenario("multi_source_attack_chain")
        broken_scenario = replace(
            scenario,
            expectations=replace(
                scenario.expectations,
                expected_mitre_technique_ids=frozenset({"T9999"}),
            ),
        )

        result = evaluate_scenario(broken_scenario)

        self.assertFalse(result.passed)
        self.assertFalse(self._check(result, "mitre_techniques").passed)

    def test_evaluation_detects_wrong_incident_count(self) -> None:
        scenario = self._scenario("multiple_independent_incidents")
        broken_scenario = replace(
            scenario,
            expectations=replace(
                scenario.expectations,
                incident_count=3,
            ),
        )

        result = evaluate_scenario(broken_scenario)

        self.assertFalse(result.passed)
        self.assertFalse(self._check(result, "incident_count").passed)

    def test_repeated_evaluation_is_deterministic(self) -> None:
        scenario = self._scenario("multi_source_attack_chain")

        first = evaluate_scenario(scenario)
        second = evaluate_scenario(scenario)

        self.assertEqual(first, second)

    def test_golden_evaluation_is_deterministic(self) -> None:
        first = evaluate_golden_scenarios()
        second = evaluate_golden_scenarios()

        self.assertEqual(first, second)

    def test_expectations_are_independently_declared(self) -> None:
        scenario = self._scenario("multi_source_attack_chain")
        broken_scenario = replace(
            scenario,
            expectations=replace(
                scenario.expectations,
                expected_risk_score=999,
            ),
        )

        result = evaluate_scenario(broken_scenario)

        self.assertFalse(result.passed)
        self.assertFalse(self._check(result, "risk_score").passed)

    def _scenario(self, name: str):
        return next(
            scenario
            for scenario in GOLDEN_SCENARIOS
            if scenario.name == name
        )

    def _check(self, result, name):
        return next(
            check
            for check in result.checks
            if check.name == name
        )


if __name__ == "__main__":
    unittest.main()
