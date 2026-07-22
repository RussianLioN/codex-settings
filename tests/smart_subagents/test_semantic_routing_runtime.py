from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.semantic_routing_v2 import (  # noqa: E402
    ContractError,
    SemanticRouterV2,
    derive_p_criterion_states,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_v1,
    domain_fingerprint,
)


def load_json(relative_path: str) -> Any:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def deep_merge(base: Any, patch: Any) -> Any:
    if type(base) is dict and type(patch) is dict:
        result = copy.deepcopy(base)
        for key, value in patch.items():
            result[key] = deep_merge(result[key], value) if key in result else copy.deepcopy(value)
        return result
    return copy.deepcopy(patch)


def resolve_copy(value: Any, vectors: dict[str, Any]) -> Any:
    if type(value) is str and value.startswith("$copy:"):
        current: Any = vectors
        for token in value.removeprefix("$copy:").split("/"):
            current = current[token]
        return copy.deepcopy(current)
    if type(value) is list:
        return [resolve_copy(item, vectors) for item in value]
    if type(value) is dict:
        return {key: resolve_copy(item, vectors) for key, item in value.items()}
    return copy.deepcopy(value)


def materialize(case: dict[str, Any], vectors: dict[str, Any]) -> dict[str, Any]:
    return deep_merge(vectors["baseInput"], resolve_copy(case["patch"], vectors))


def policy_snapshot(vector: dict[str, Any]) -> dict[str, Any]:
    return {
        "domain": vector["domain"],
        "policy": copy.deepcopy(vector["policy"]),
        "canonicalUtf8": vector["canonicalUtf8"],
        "fingerprint": vector["fingerprint"],
    }


def fingerprint_snapshot(snapshot: dict[str, Any]) -> None:
    canonical = canonical_json_v1(snapshot["policy"])
    snapshot["canonicalUtf8"] = canonical
    snapshot["fingerprint"] = domain_fingerprint(
        snapshot["domain"], snapshot["policy"]
    )


class SemanticRoutingRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.routing_vectors = load_json("docs/contracts/vectors/routing-input-v2.json")
        self.policy_vector = load_json("docs/contracts/vectors/routing-policy-v2.json")
        self.delegation_policy = load_json(
            "docs/contracts/vectors/delegation-policy-v2.json"
        )["policy"]
        self.role_templates = load_json(
            "docs/contracts/vectors/role-template-v1.json"
        )["templates"]

    def router(self, snapshot: dict[str, Any] | None = None) -> SemanticRouterV2:
        return SemanticRouterV2(
            policy_snapshot=policy_snapshot(self.policy_vector)
            if snapshot is None
            else snapshot,
            delegation_policy=self.delegation_policy,
            role_templates=self.role_templates,
        )

    def test_p2_scope_threshold_is_symmetric_for_unknown_counts(self) -> None:
        for scope_units, work_units, expected in (
            (1, None, "unknown"),
            (None, 1, "unknown"),
            (6, None, "true"),
            (None, 6, "true"),
            (1, 5, "false"),
            (5, 1, "false"),
        ):
            with self.subTest(scope_units=scope_units, work_units=work_units):
                work_shape = {
                    "scopeUnits": {"value": scope_units, "evidenceRefIds": []},
                    "workUnits": {"value": work_units, "evidenceRefIds": []},
                    "boundaries": {"value": 1, "evidenceRefIds": []},
                    "workstreams": {"value": 1, "evidenceRefIds": []},
                }
                self.assertEqual(
                    expected,
                    derive_p_criterion_states(work_shape)["p2-scope-6-plus"],
                )

    def test_unknown_scope_count_does_not_silently_lower_the_model(self) -> None:
        cases = {case["name"]: case for case in self.routing_vectors["cases"]}
        for name in (
            "known-scope-unknown-work-keeps-conservative-model",
            "unknown-scope-known-work-keeps-conservative-model",
        ):
            with self.subTest(case=name):
                result = self.router().evaluate(
                    materialize(cases[name], self.routing_vectors)
                )
                self.assertEqual(
                    {"model": "gpt-5.6-terra", "reasoningEffort": "medium"},
                    result["pair"],
                )
                self.assertEqual(
                    {"q": 1, "p": 2, "v": 0, "o": 0}, result["factors"]
                )

    def test_production_router_executes_every_routing_vector(self) -> None:
        router = self.router()
        for case in self.routing_vectors["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    case["expected"],
                    router.evaluate(materialize(case, self.routing_vectors)),
                )

    def test_router_rejects_a_tampered_policy_snapshot(self) -> None:
        snapshot = policy_snapshot(self.policy_vector)
        snapshot["policy"]["tiers"][0]["scoreMax"] = 1
        with self.assertRaisesRegex(ContractError, "ROUTING_POLICY_CANONICAL_MISMATCH"):
            self.router(snapshot)

    def test_model_names_are_read_from_the_passed_policy(self) -> None:
        snapshot = policy_snapshot(self.policy_vector)
        old_model = snapshot["policy"]["tiers"][0]["model"]
        new_model = "test-policy-small-model"
        snapshot["policy"]["tiers"][0]["model"] = new_model
        for pair in snapshot["policy"]["allowedPairs"]:
            if pair["model"] == old_model:
                pair["model"] = new_model
        fingerprint_snapshot(snapshot)

        value = copy.deepcopy(self.routing_vectors["baseInput"])
        for source in ("policyPairs", "bundledSnapshotPairs"):
            for pair in value["catalogs"][source]:
                if pair["model"] == old_model:
                    pair["model"] = new_model

        self.assertEqual(
            {"model": new_model, "reasoningEffort": "low"},
            self.router(snapshot).evaluate(value)["pair"],
        )

    def test_all_policy_scores_and_hard_floors_use_the_production_selector(self) -> None:
        router = self.router()
        for case in self.policy_vector["scoreCases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    {
                        "model": case["expected"]["model"],
                        "reasoningEffort": case["expected"]["reasoningEffort"],
                    },
                    router.select_pair(
                        case["factors"], hard_floor_reasons=()
                    ),
                )
        for case in self.policy_vector["hardFloorCases"]:
            if case["expected"] == "schema-invalid":
                continue
            with self.subTest(case=case["name"]):
                factors = {"q": case["score"], "p": 0, "v": 0, "o": 0}
                if case["score"] > 2:
                    factors = next(
                        score_case["factors"]
                        for score_case in self.policy_vector["scoreCases"]
                        if score_case["score"] == case["score"]
                    )
                self.assertEqual(
                    {
                        "model": case["expected"]["model"],
                        "reasoningEffort": case["expected"]["reasoningEffort"],
                    },
                    router.select_pair(
                        factors, hard_floor_reasons=case["reasons"]
                    ),
                )

    def test_smart_plan_never_consumes_account_evidence(self) -> None:
        value = copy.deepcopy(self.routing_vectors["baseInput"])
        value["catalogs"]["accountPairs"] = copy.deepcopy(
            value["catalogs"]["policyPairs"]
        )
        value["accountEvidenceJobs"] = [
            {
                "jobId": "unexpected",
                "attemptId": "unexpected",
                "fullCollection": True,
                "processCount": 5,
                "cacheHit": False,
                "hiddenRetry": False,
            }
        ]
        result = self.router().evaluate(value)
        self.assertEqual(
            "ACCOUNT_EVIDENCE_FORBIDDEN_DURING_SMART_PLAN", result["errorCode"]
        )
        self.assertEqual(0, result["accountEvidenceJobsConsumed"])

    def test_node_attempt_requires_exactly_one_fresh_full_five_process_job(self) -> None:
        cases = {case["name"]: case for case in self.routing_vectors["cases"]}
        valid = materialize(
            cases["node-attempt-one-full-account-evidence-job"],
            self.routing_vectors,
        )
        self.assertEqual(1, self.router().evaluate(valid)["accountEvidenceJobsConsumed"])

        invalid = copy.deepcopy(valid)
        invalid["accountEvidenceJobs"].append(copy.deepcopy(invalid["accountEvidenceJobs"][0]))
        result = self.router().evaluate(invalid)
        self.assertEqual("ACCOUNT_EVIDENCE_JOB_COUNT_INVALID", result["errorCode"])
        self.assertEqual(0, result["accountEvidenceJobsConsumed"])

    def test_direct_and_clarify_never_require_account_evidence(self) -> None:
        cases = {case["name"]: case for case in self.routing_vectors["cases"]}
        for name, decision in (
            ("direct-without-account-evidence", "direct"),
            ("clarify-without-account-evidence", "clarify"),
        ):
            with self.subTest(case=name):
                value = materialize(cases[name], self.routing_vectors)
                value["phase"] = "node-attempt"
                result = self.router().evaluate(value)
                self.assertEqual(decision, result["decision"])
                self.assertNotIn("errorCode", result)
                self.assertEqual(0, result["accountEvidenceJobsConsumed"])

        forbidden = materialize(
            cases["node-attempt-one-full-account-evidence-job"],
            self.routing_vectors,
        )
        forbidden["taskFacts"] = materialize(
            cases["direct-without-account-evidence"], self.routing_vectors
        )["taskFacts"]
        result = self.router().evaluate(forbidden)
        self.assertEqual("direct", result["decision"])
        self.assertEqual(
            "ACCOUNT_EVIDENCE_FORBIDDEN_FOR_NON_DELEGATE", result["errorCode"]
        )
        self.assertEqual(0, result["accountEvidenceJobsConsumed"])

    def test_malformed_catalogs_raise_a_contract_error(self) -> None:
        for mutate in (
            lambda value: value.update(catalogs=None),
            lambda value: value["catalogs"].pop("policyPairs"),
            lambda value: value["catalogs"]["policyPairs"][0].pop(
                "reasoningEffort"
            ),
        ):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.routing_vectors["baseInput"])
                mutate(value)
                with self.assertRaisesRegex(
                    ContractError, "ROUTING_CATALOGS_MALFORMED"
                ):
                    self.router().evaluate(value)

    def test_unavailable_exact_pair_is_rejected_without_substitution(self) -> None:
        case = next(
            case
            for case in self.routing_vectors["cases"]
            if case["name"] == "exact-pair-unavailable-no-fallback"
        )
        result = self.router().evaluate(materialize(case, self.routing_vectors))
        self.assertEqual("ROUTING_PAIR_UNAVAILABLE", result["errorCode"])
        self.assertIsNone(result["pair"])


if __name__ == "__main__":
    unittest.main()
