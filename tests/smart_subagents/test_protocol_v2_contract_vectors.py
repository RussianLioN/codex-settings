from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_protocol_v2_contract_vectors.py"
SCHEMA_ROOT = ROOT / "docs/contracts/schemas"
VECTOR_ROOT = ROOT / "docs/contracts/vectors"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class ProtocolV2ContractTests(unittest.TestCase):
    def test_all_protocol_artifacts_exist(self) -> None:
        expected = (
            SCHEMA_ROOT / "controller-protocol-v2.schema.json",
            SCHEMA_ROOT / "smart-turn-protocol-v2.schema.json",
            SCHEMA_ROOT / "child-attestation-v2.schema.json",
            SCHEMA_ROOT / "protocol-vector-suite-v2.schema.json",
            VECTOR_ROOT / "controller-protocol-v2.json",
            VECTOR_ROOT / "smart-turn-protocol-v2.json",
            VALIDATOR_PATH,
        )
        self.assertEqual([], [str(path) for path in expected if not path.is_file()])

    def test_public_and_internal_method_sets_are_disjoint_and_closed(self) -> None:
        controller = load_json(SCHEMA_ROOT / "controller-protocol-v2.schema.json")
        smart_turn = load_json(SCHEMA_ROOT / "smart-turn-protocol-v2.schema.json")

        controller_methods = set(controller["$defs"]["method"]["enum"])
        public_methods = set(smart_turn["$defs"]["method"]["enum"])
        self.assertEqual(
            {
                "issue_turn_binding",
                "smart_plan",
                "route_start",
                "smart_wait",
                "smart_cancel",
            },
            public_methods,
        )
        self.assertIn("admit_node", controller_methods)
        self.assertNotIn("smart_start", controller_methods)
        self.assertTrue(public_methods.isdisjoint(controller_methods))

    def test_start_request_precedes_admission_and_evidence_counts_are_exact(
        self,
    ) -> None:
        controller = load_json(SCHEMA_ROOT / "controller-protocol-v2.schema.json")
        smart_turn = load_json(SCHEMA_ROOT / "smart-turn-protocol-v2.schema.json")

        counts = controller["$defs"]["workCounts"]
        self.assertEqual(
            {
                "nonterminalRoutes",
                "nonterminalNodes",
                "activeAttempts",
                "activeLeases",
                "openIntents",
                "inflightLaunchPermits",
                "activeRuntimeArtifacts",
                "pendingCandidatePublications",
                "activeEvidenceJobs",
                "queuedEvidenceJobs",
            },
            set(counts["required"]),
        )
        self.assertEqual(
            {"startRequestId", "routeId", "nodeId", "evidenceJobId", "activationGate"},
            set(controller["$defs"]["admitNodeParams"]["required"]),
        )
        route_started = smart_turn["$defs"]["routeStartPayload"]
        self.assertIn("startRequestId", route_started["required"])
        self.assertIn("evidenceJob", route_started["required"])
        self.assertEqual({"type": "null"}, route_started["properties"]["admissionId"])

    def test_coordinator_generator_owns_health_selection_schema_and_vector(
        self,
    ) -> None:
        generator_path = ROOT / "scripts" / "update_coordinator_contract_cascade.py"
        spec = importlib.util.spec_from_file_location(
            "coordinator_contract_generator",
            generator_path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        generated = module.generate()
        schema_path = Path("docs/contracts/schemas/controller-protocol-v2.schema.json")
        vector_path = Path("docs/contracts/vectors/controller-protocol-v2.json")
        lifecycle_path = Path("docs/contracts/vectors/lifecycle-v2.json")
        self.assertIn(schema_path, generated)
        self.assertIn(vector_path, generated)
        self.assertIn(lifecycle_path, generated)
        schema = json.loads(generated[schema_path])
        vectors = json.loads(generated[vector_path])
        lifecycle = json.loads(generated[lifecycle_path])
        health = schema["$defs"]["healthPayload"]
        self.assertIn("coordinatorSelection", health["required"])
        self.assertEqual(
            "first-verified-available",
            schema["$defs"]["coordinatorSelection"]["properties"][
                "selection"
            ]["const"],
        )
        health_response = next(
            case["message"]
            for case in vectors["positiveCases"]
            if case["name"] == "health-response"
        )
        self.assertEqual(
            "SELECTED",
            health_response["payload"]["coordinatorSelection"]["status"],
        )
        self.assertEqual(
            "SELECTED",
            lifecycle["fixtures"]["healthResponse"]["payload"][
                "coordinatorSelection"
            ]["status"],
        )

    def test_coordinator_generator_rejects_semantic_schema_drift(self) -> None:
        generator_path = ROOT / "scripts" / "update_coordinator_contract_cascade.py"
        spec = importlib.util.spec_from_file_location(
            "coordinator_contract_drift_generator",
            generator_path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as raw_root:
            temporary_root = Path(raw_root)
            schema_path = temporary_root / module.CONTROLLER_SCHEMA
            vector_path = temporary_root / module.CONTROLLER_VECTOR
            schema_path.parent.mkdir(parents=True)
            vector_path.parent.mkdir(parents=True)
            schema = load_json(ROOT / module.CONTROLLER_SCHEMA)
            schema["$defs"]["coordinatorSelection"]["properties"][
                "selection"
            ]["const"] = "last-candidate"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            vector_path.write_bytes((ROOT / module.CONTROLLER_VECTOR).read_bytes())
            module.ROOT = temporary_root

            with self.assertRaisesRegex(RuntimeError, "семантика"):
                module._update_controller_protocol()

    def test_wait_cancel_and_attestation_are_closed(self) -> None:
        smart_turn = load_json(SCHEMA_ROOT / "smart-turn-protocol-v2.schema.json")
        attestation = load_json(SCHEMA_ROOT / "child-attestation-v2.schema.json")

        wait_params = smart_turn["$defs"]["smartWaitParams"]
        self.assertEqual(
            {"startRequestId", "cursor", "pageSize", "waitDeadlineAt"},
            set(wait_params["required"]),
        )
        cancel_params = smart_turn["$defs"]["smartCancelParams"]
        self.assertIn("startRequestId", cancel_params["required"])
        self.assertIn("reasonCode", cancel_params["required"])
        self.assertEqual(
            {"requested", "observed"},
            {
                name
                for name in ("requested", "observed")
                if name in attestation["required"]
            },
        )
        self.assertFalse(attestation["additionalProperties"])
        self.assertEqual(7, len(attestation["$defs"]["modelPair"]["oneOf"]))
        self.assertIn(
            "CHILD_FAILED_BEFORE_START",
            smart_turn["$defs"]["waitEvent"]["properties"]["kind"]["enum"],
        )
        route_completed = smart_turn["$defs"]["waitEvent"]["allOf"][-1]
        self.assertIn(
            "STALE",
            route_completed["then"]["properties"]["startState"]["enum"],
        )
        vectors = load_json(VECTOR_ROOT / "smart-turn-protocol-v2.json")
        self.assertIn(
            "smart-wait-child-failed-before-start-response",
            {case["name"] for case in vectors["positiveCases"]},
        )

    def test_tracked_validator_accepts_positives_rejects_negatives_and_covers_methods(
        self,
    ) -> None:
        if importlib.util.find_spec("jsonschema") is None:
            self.skipTest("нужна закреплённая среда проверки JSON Schema")
        spec = importlib.util.spec_from_file_location(
            "protocol_v2_validator", VALIDATOR_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        summary = module.validate_all(ROOT)
        self.assertEqual(summary.total, summary.passed)
        self.assertGreaterEqual(summary.positive_cases, 34)
        self.assertGreaterEqual(summary.negative_cases, 17)


if __name__ == "__main__":
    unittest.main()
