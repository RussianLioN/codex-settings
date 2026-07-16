from __future__ import annotations

import itertools
import sys
import unittest
from pathlib import Path


PLUGIN_SRC = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "codex-smart-subagents"
    / "src"
)
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.routing import (  # noqa: E402
    ALLOWED_INTERVALS,
    ComplexityFactors,
    DelegationAssessment,
    Disposition,
    Interval,
    ModelUnavailable,
    ReasoningFactors,
    classify_delegation,
    normalize_model_effort,
    resolve_boundary,
    select_model,
    select_reasoning_effort,
)


class DelegationRoutingTests(unittest.TestCase):
    def test_all_interval_combinations_follow_the_formal_rule(self) -> None:
        for q, p, v, o in itertools.product(ALLOWED_INTERVALS, repeat=4):
            assessment = DelegationAssessment(q=q, p=p, v=v, o=o)
            decision = classify_delegation(assessment)
            score_min = q.minimum + p.minimum + v.minimum - o.maximum
            score_max = q.maximum + p.maximum + v.maximum - o.minimum

            if v.maximum == 0 or score_max < 2:
                expected = Disposition.DIRECT
            elif v.minimum >= 1 and score_min >= 2:
                expected = Disposition.DELEGATE
            else:
                expected = Disposition.BOUNDARY

            self.assertEqual(expected, decision.disposition, assessment)
            self.assertEqual(score_min, decision.score_min)
            self.assertEqual(score_max, decision.score_max)

    def test_hard_ban_precedes_scores(self) -> None:
        high_value = DelegationAssessment(
            q=Interval(2, 2),
            p=Interval(2, 2),
            v=Interval(2, 2),
            o=Interval(0, 0),
            hard_ban=Disposition.DIRECT,
        )
        self.assertEqual(Disposition.DIRECT, classify_delegation(high_value).disposition)

        high_value = DelegationAssessment(
            q=Interval(2, 2),
            p=Interval(2, 2),
            v=Interval(2, 2),
            o=Interval(0, 0),
            hard_ban=Disposition.CLARIFY,
        )
        self.assertEqual(Disposition.CLARIFY, classify_delegation(high_value).disposition)

    def test_writer_requires_certain_verifiability(self) -> None:
        assessment = DelegationAssessment(
            q=Interval(2, 2),
            p=Interval(2, 2),
            v=Interval(1, 2),
            o=Interval(0, 0),
            writer=True,
        )
        self.assertEqual(Disposition.BOUNDARY, classify_delegation(assessment).disposition)

    def test_boundary_allows_exactly_one_independent_reclassification(self) -> None:
        primary = DelegationAssessment(
            q=Interval(0, 2),
            p=Interval(0, 0),
            v=Interval(1, 2),
            o=Interval(0, 2),
        )
        secondary = DelegationAssessment(
            q=Interval(2, 2),
            p=Interval(1, 1),
            v=Interval(2, 2),
            o=Interval(0, 0),
        )
        resolved = resolve_boundary(primary, secondary)
        self.assertEqual(Disposition.DELEGATE, resolved.disposition)
        self.assertTrue(resolved.reclassified)

    def test_unresolved_or_failed_reclassification_is_direct(self) -> None:
        primary = DelegationAssessment(
            q=Interval(0, 2),
            p=Interval(0, 0),
            v=Interval(1, 2),
            o=Interval(0, 2),
        )
        self.assertEqual(Disposition.DIRECT, resolve_boundary(primary, None).disposition)
        self.assertEqual(
            Disposition.DIRECT,
            resolve_boundary(primary, primary).disposition,
        )


class ModelRoutingTests(unittest.TestCase):
    def test_all_complexity_combinations_follow_thresholds(self) -> None:
        for values in itertools.product(range(3), repeat=6):
            factors = ComplexityFactors(*values)
            score = sum(values)
            expected = (
                "gpt-5.6-luna"
                if score <= 3
                else "gpt-5.6-terra"
                if score <= 7
                else "gpt-5.6-sol"
            )
            self.assertEqual(expected, select_model(factors), factors)

    def test_risk_floors_never_downgrade(self) -> None:
        simple = ComplexityFactors(0, 0, 0, 0, 0, 0)
        self.assertEqual(
            "gpt-5.6-terra",
            select_model(simple, risk_flags={"security"}),
        )
        self.assertEqual(
            "gpt-5.6-sol",
            select_model(simple, risk_flags={"irreversible"}),
        )

    def test_unavailable_models_promote_only_upward(self) -> None:
        simple = ComplexityFactors(0, 0, 0, 0, 0, 0)
        medium = ComplexityFactors(1, 1, 1, 1, 0, 0)
        self.assertEqual(
            "gpt-5.6-terra",
            select_model(simple, available={"gpt-5.6-terra", "gpt-5.6-sol"}),
        )
        self.assertEqual(
            "gpt-5.6-sol",
            select_model(medium, available={"gpt-5.6-sol"}),
        )
        with self.assertRaises(ModelUnavailable):
            select_model(simple, available=set())


class ReasoningRoutingTests(unittest.TestCase):
    def test_all_reasoning_combinations_follow_thresholds(self) -> None:
        expected_by_score = {
            0: "low",
            1: "low",
            2: "medium",
            3: "medium",
            4: "high",
            5: "xhigh",
            6: "max",
        }
        for values in itertools.product(range(3), repeat=3):
            factors = ReasoningFactors(*values)
            self.assertEqual(
                expected_by_score[sum(values)],
                select_reasoning_effort(factors),
                factors,
            )

    def test_model_effort_normalization_uses_exact_promotion_table(self) -> None:
        cases = {
            ("gpt-5.6-luna", "low"): ("gpt-5.6-luna", "low"),
            ("gpt-5.6-luna", "medium"): ("gpt-5.6-luna", "medium"),
            ("gpt-5.6-luna", "high"): ("gpt-5.6-terra", "high"),
            ("gpt-5.6-luna", "xhigh"): ("gpt-5.6-terra", "xhigh"),
            ("gpt-5.6-luna", "max"): ("gpt-5.6-sol", "max"),
            ("gpt-5.6-terra", "low"): ("gpt-5.6-terra", "medium"),
            ("gpt-5.6-terra", "medium"): ("gpt-5.6-terra", "medium"),
            ("gpt-5.6-terra", "high"): ("gpt-5.6-terra", "high"),
            ("gpt-5.6-terra", "xhigh"): ("gpt-5.6-terra", "xhigh"),
            ("gpt-5.6-terra", "max"): ("gpt-5.6-sol", "max"),
            ("gpt-5.6-sol", "low"): ("gpt-5.6-sol", "high"),
            ("gpt-5.6-sol", "medium"): ("gpt-5.6-sol", "high"),
            ("gpt-5.6-sol", "high"): ("gpt-5.6-sol", "high"),
            ("gpt-5.6-sol", "xhigh"): ("gpt-5.6-sol", "xhigh"),
            ("gpt-5.6-sol", "max"): ("gpt-5.6-sol", "max"),
        }
        for requested, expected in cases.items():
            self.assertEqual(expected, normalize_model_effort(*requested), requested)


if __name__ == "__main__":
    unittest.main()

