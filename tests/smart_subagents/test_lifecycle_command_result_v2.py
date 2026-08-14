from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs/contracts/schemas/lifecycle-command-result-v2.schema.json"
VECTOR_PATH = ROOT / "docs/contracts/vectors/lifecycle-command-result-v2.json"
VALIDATOR_PATH = ROOT / "scripts/validate_lifecycle_command_result_vectors.py"
COMBINED_VALIDATOR = ROOT / "scripts/validate_contracts.py"


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class LifecycleCommandResultV2Tests(unittest.TestCase):
    def test_tracked_contract_artifacts_exist(self) -> None:
        expected = (SCHEMA_PATH, VECTOR_PATH, VALIDATOR_PATH)
        self.assertEqual([], [str(path) for path in expected if not path.is_file()])

    def test_schema_is_strict_and_declares_every_public_status(self) -> None:
        schema = load_json(SCHEMA_PATH)
        Draft202012Validator.check_schema(schema)
        self.assertFalse(schema["$defs"]["base"]["additionalProperties"])
        branches = schema["oneOf"]
        command_statuses = {
            branch["properties"]["command"]["const"]: set(
                branch["properties"]["status"]["enum"]
            )
            for branch in branches
        }
        self.assertEqual(
            {
                "apply": {
                    "planned",
                    "installed",
                    "upgraded",
                    "reconciled",
                    "repaired",
                    "unchanged",
                    "failed",
                },
                "doctor": {
                    "READY",
                    "AWAITING_HOOK_TRUST",
                    "DEGRADED",
                    "BROKEN",
                },
                "smoke": {"READY", "NOT_READY", "failed"},
                "inspect": {"inspected", "failed"},
                "rollback": {"planned", "rolled_back", "unchanged", "failed"},
                "cleanup": {"planned", "cleaned", "unchanged", "failed"},
                "uninstall": {"planned", "uninstalled", "unchanged", "failed"},
                "recover": {"planned", "recovered", "unchanged", "failed"},
            },
            command_statuses,
        )

    def test_fingerprint_registry_has_nonrecursive_command_result_domain(self) -> None:
        registry = load_json(
            ROOT / "docs/contracts/schemas/lifecycle-fingerprint-registry-v2.schema.json"
        )
        specification = registry["properties"]["lifecycleCommandResult"][
            "properties"
        ]
        self.assertEqual(
            "codex-smart/command-result/v2",
            specification["domain"]["const"],
        )
        self.assertEqual(
            [
                "schemaVersion",
                "command",
                "status",
                "readiness",
                "smokeInvocationId",
                "changes",
                "problems",
            ],
            specification["projectionFields"]["const"],
        )
        self.assertEqual(
            [
                "operationId",
                "attemptId",
                "resultFingerprint",
                "problems.message",
                "problems.remediation",
                "extensions",
            ],
            specification["excludedFields"]["const"],
        )

    def test_vectors_prove_schema_semantics_order_and_fingerprint(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "lifecycle_command_result_validator",
            VALIDATOR_PATH,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        summary = module.validate_all(ROOT)
        self.assertEqual(summary.total, summary.passed)
        self.assertGreaterEqual(summary.positive_cases, 8)
        self.assertGreaterEqual(summary.negative_cases, 18)

    def test_combined_contract_entrypoint_runs_command_result_validator(self) -> None:
        source = COMBINED_VALIDATOR.read_text(encoding="utf-8")
        self.assertIn("validate_lifecycle_command_result_vectors.py", source)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("LIFECYCLE_COMMAND_RESULTS_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
