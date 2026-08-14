from __future__ import annotations

import importlib.util
import copy
import json
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_semantic_routing_vectors.py"


def load_json(relative_path: str) -> object:
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


class SemanticRoutingContractTests(unittest.TestCase):
    def load_contract(self) -> ModuleType:
        self.assertTrue(
            VALIDATOR_PATH.is_file(),
            "нет отдельного эталонного исполнителя смысловой маршрутизации",
        )
        spec = importlib.util.spec_from_file_location(
            "validate_semantic_routing_vectors", VALIDATOR_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_all_five_new_schemas_are_closed(self) -> None:
        expected = {
            "task-facts-v1": (1, "codex-task-facts-v1"),
            "routing-input-v2": (2, "codex-routing-input-v2"),
            "delegation-policy-v2": (2, "codex-delegation-policy-v2"),
            "role-template-v1": (1, "codex-role-template-v1"),
            "context-bundle-v1": (1, "codex-context-bundle-v1"),
        }
        for name, (schema_version, contract_version) in expected.items():
            with self.subTest(name=name):
                path = ROOT / f"docs/contracts/schemas/{name}.schema.json"
                self.assertTrue(path.is_file(), f"нет схемы {name}")
                schema = load_json(f"docs/contracts/schemas/{name}.schema.json")
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(
                    schema_version,
                    schema["properties"]["schemaVersion"]["const"],
                )
                self.assertEqual(
                    contract_version,
                    schema["properties"]["contractVersion"]["const"],
                )

    def test_legacy_and_v2_formulae_are_not_interchangeable(self) -> None:
        contract = self.load_contract()
        legacy = {
            "ambiguity": 1,
            "dependencyDepth": 1,
            "breadth": 1,
            "novelty": 1,
            "harm": 1,
            "crossDomain": 1,
        }
        semantic = {"q": 1, "p": 1, "v": 1, "o": 1}
        self.assertEqual(6, contract.legacy_v1_score(legacy))
        self.assertEqual(4, contract.semantic_v2_score(semantic))
        with self.assertRaisesRegex(contract.ContractError, "SEMANTIC_VERSION_MISMATCH"):
            contract.semantic_v2_score({**semantic, "semanticVersion": "legacy-v1"})
        with self.assertRaisesRegex(contract.ContractError, "LEGACY_VERSION_MISMATCH"):
            contract.legacy_v1_score(semantic)

    def test_unproved_false_becomes_unknown_and_p_is_computed(self) -> None:
        contract = self.load_contract()
        vectors = load_json("docs/contracts/vectors/task-facts-v1.json")
        false_case = next(
            case for case in vectors["normalizationCases"]
            if case["name"] == "unproved-false-becomes-unknown"
        )
        normalized = contract.normalize_task_facts(false_case["value"])
        self.assertEqual(
            "unknown",
            normalized["factorClaims"]["q"]["q1-dependent-chain"]["state"],
        )
        self.assertEqual(false_case["expected"], normalized)

        p2_case = next(
            case for case in vectors["normalizationCases"]
            if case["name"] == "counts-compute-p2"
        )
        normalized = contract.normalize_task_facts(p2_case["value"])
        self.assertEqual(
            p2_case["expectedPStates"],
            contract.derive_p_criterion_states(normalized["workShape"]),
        )

    def test_decision_is_made_before_pair_selection(self) -> None:
        contract = self.load_contract()
        vectors = load_json("docs/contracts/vectors/routing-input-v2.json")
        cases = {case["name"]: case for case in vectors["cases"]}

        direct = contract.evaluate_routing_input(
            contract.materialize_routing_case(
                cases["direct-without-account-evidence"], vectors
            ),
            root=ROOT,
        )
        clarify = contract.evaluate_routing_input(
            contract.materialize_routing_case(
                cases["clarify-without-account-evidence"], vectors
            ),
            root=ROOT,
        )
        plan = contract.evaluate_routing_input(
            contract.materialize_routing_case(
                cases["delegate-smart-plan-without-account-evidence"], vectors
            ),
            root=ROOT,
        )
        attempt_without_account = contract.evaluate_routing_input(
            contract.materialize_routing_case(
                cases["node-attempt-requires-account-evidence"], vectors
            ),
            root=ROOT,
        )

        self.assertEqual(cases["direct-without-account-evidence"]["expected"], direct)
        self.assertEqual(
            cases["clarify-without-account-evidence"]["expected"], clarify
        )
        self.assertIsNone(direct["pair"])
        self.assertIsNone(clarify["pair"])
        self.assertEqual("delegate", plan["decision"])
        self.assertEqual(0, plan["accountEvidenceJobsConsumed"])
        self.assertEqual(
            "ACCOUNT_EVIDENCE_REQUIRED", attempt_without_account["errorCode"]
        )

    def test_one_fresh_account_evidence_job_per_actual_node_attempt(self) -> None:
        contract = self.load_contract()
        vectors = load_json("docs/contracts/vectors/routing-input-v2.json")
        cases = {case["name"]: case for case in vectors["cases"]}
        value = contract.materialize_routing_case(
            cases["node-attempt-one-full-account-evidence-job"], vectors
        )
        result = contract.evaluate_routing_input(value, root=ROOT)
        self.assertEqual(1, result["accountEvidenceJobsConsumed"])
        self.assertEqual(5, value["accountEvidenceJobs"][0]["processCount"])
        self.assertFalse(value["accountEvidenceJobs"][0]["cacheHit"])
        self.assertFalse(value["accountEvidenceJobs"][0]["hiddenRetry"])

        cached = copy.deepcopy(value)
        cached["accountEvidenceJobs"][0]["cacheHit"] = True
        self.assertEqual(
            "ACCOUNT_EVIDENCE_REUSE_FORBIDDEN",
            contract.evaluate_routing_input(cached, root=ROOT)["errorCode"],
        )

    def test_unavailable_pair_and_unapproved_reassessment_are_rejected(self) -> None:
        contract = self.load_contract()
        vectors = load_json("docs/contracts/vectors/routing-input-v2.json")
        cases = {case["name"]: case for case in vectors["cases"]}
        for name, error_code in (
            ("exact-pair-unavailable-no-fallback", "ROUTING_PAIR_UNAVAILABLE"),
            ("promote-only-without-explicit-policy", "REASSESSMENT_POLICY_REQUIRED"),
        ):
            with self.subTest(name=name):
                actual = contract.evaluate_routing_input(
                    contract.materialize_routing_case(cases[name], vectors), root=ROOT
                )
                self.assertEqual(error_code, actual["errorCode"])
                self.assertIsNone(actual["pair"])

    def test_context_budget_and_semantic_role_mapping_are_enforced(self) -> None:
        contract = self.load_contract()
        context_vectors = load_json("docs/contracts/vectors/context-bundle-v1.json")
        for case in context_vectors["positiveCases"]:
            contract.validate_context_bundle(
                case["value"], context_vectors["evidenceSnapshots"][case["name"]]
            )
        role_vectors = load_json("docs/contracts/vectors/role-template-v1.json")
        for template in role_vectors["templates"]:
            contract.validate_role_template(template)
        self.assertEqual(
            {
                "researcher": "reader",
                "diagnostician": "reader",
                "validator": "reader",
                "risk_auditor": "reader",
                "implementer": "writer",
            },
            {
                template["semanticRole"]: template["executionProfile"]
                for template in role_vectors["templates"]
            },
        )

    def test_context_source_reference_cannot_be_stale(self) -> None:
        contract = self.load_contract()
        vectors = load_json("docs/contracts/vectors/context-bundle-v1.json")
        case = next(
            item
            for item in vectors["positiveCases"]
            if item["name"] == "two-materialized-contexts-within-budget"
        )
        stale = copy.deepcopy(case["value"])
        stale["entries"][0]["sourceEvidenceRefs"][0]["evidenceSha256"] = "f" * 64
        with self.assertRaisesRegex(contract.ContractError, "CONTEXT_SOURCE_STALE"):
            contract.validate_context_bundle(
                stale, vectors["evidenceSnapshots"][case["name"]]
            )

    def test_text_to_facts_to_features_to_decision_to_pair_corpus_is_green(
        self,
    ) -> None:
        contract = self.load_contract()
        summary = contract.validate_repository(ROOT)
        self.assertEqual(0, summary["failed"])
        self.assertGreaterEqual(summary["routingCases"], 7)
        self.assertGreaterEqual(summary["mutations"], 12)
        self.assertEqual(summary["passed"], summary["total"])


if __name__ == "__main__":
    unittest.main()
