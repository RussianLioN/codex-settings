from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_VALIDATOR = ROOT / "scripts/validate_lifecycle_contract_vectors.py"
PREPARATION_VALIDATOR = (
    ROOT / "scripts/validate_activation_preparation_vectors.py"
)
COMBINED_VALIDATOR = ROOT / "scripts/validate_contracts.py"


class LifecycleContractVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.combined_result = subprocess.run(
            [sys.executable, str(COMBINED_VALIDATOR)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_lifecycle_validator_is_tracked_and_self_contained(self) -> None:
        self.assertTrue(
            LIFECYCLE_VALIDATOR.is_file(),
            "нет отслеживаемого исполнителя договора жизненного цикла",
        )
        source = LIFECYCLE_VALIDATOR.read_text(encoding="utf-8")
        self.assertNotIn(".superpowers", source)
        self.assertNotIn("task-2-report.md", source)

    def test_dynamic_effect_vectors_separate_constraints_from_observations(self) -> None:
        projection_schema = json.loads(
            (
                ROOT
                / "docs/contracts/schemas/lifecycle-projection-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        operation_schema = json.loads(
            (
                ROOT / "docs/contracts/schemas/operation-step-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        vectors = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )

        controller = projection_schema["$defs"]["controllerState"]
        self.assertTrue(
            {"EXPECTED_MAINTENANCE", "EXPECTED_ACCEPTING"}
            <= set(controller["properties"]["state"]["enum"])
        )
        shutdown = projection_schema["$defs"]["shutdownIntent"]
        self.assertIn(
            "EXPECTED_SHUTDOWN_PROOF",
            shutdown["properties"]["status"]["enum"],
        )
        self.assertIn(
            "SHUTDOWN_COMMITTED",
            shutdown["properties"]["status"]["enum"],
        )
        registry = projection_schema["$defs"]["registryState"]
        self.assertIn("status", registry["required"])
        self.assertTrue(
            {
                "EXPECTED_MARKETPLACE_REGISTERED",
                "MARKETPLACE_REGISTERED",
                "EXPECTED_PLUGIN_ENABLED",
                "PLUGIN_ENABLED",
            }
            <= set(registry["properties"]["status"]["enum"])
        )

        socket_cleanup = operation_schema["$defs"]["actionSocketCleanup"]
        result_fields = {
            "proofSourceFingerprint",
            "processExitProofFingerprint",
            "exclusiveLockProofFingerprint",
        }
        self.assertTrue(result_fields.isdisjoint(socket_cleanup["required"]))
        self.assertTrue(
            result_fields.isdisjoint(socket_cleanup["properties"])
        )
        candidate_spawn = operation_schema["$defs"]["actionControllerSpawn"]
        self.assertIn("argv", candidate_spawn["required"])

        fixtures = vectors["fixtures"]
        self.assertEqual(
            fixtures["controllerShutdownStep"]["expectedAfter"],
            fixtures["shutdownSocketCleanupStep"]["before"],
        )
        self.assertEqual(
            fixtures["controllerCandidateSpawnStep"]["expectedAfter"],
            fixtures["controllerAcceptStep"]["before"],
        )

        expected_actual_states = {
            "controllerShutdownStep": (
                "EXPECTED_SHUTDOWN_PROOF",
                "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
            ),
            "controllerAcceptStep": (
                "EXPECTED_MAINTENANCE",
                "MAINTENANCE",
            ),
            "maintenanceResumeStep": (
                "EXPECTED_ACCEPTING",
                "ACCEPTING",
            ),
            "controllerCandidateSpawnStep": (
                "EXPECTED_REGISTRATION",
                "REGISTERED_READY",
            ),
        }
        for fixture_name, (expected_state, actual_state) in (
            expected_actual_states.items()
        ):
            with self.subTest(fixture=fixture_name):
                if fixture_name == "maintenanceResumeStep":
                    step = next(
                        item
                        for item in fixtures["abortTerminalJournal"]["steps"]
                        if item["kind"] == "maintenance_resume"
                    )
                else:
                    step = fixtures[fixture_name]
                discriminator = (
                    "status"
                    if step["expectedAfter"]["schemaId"]
                    in {"shutdown-intent-v2", "controller-candidate-v2"}
                    else "state"
                )
                self.assertEqual(
                    expected_state,
                    step["expectedAfter"]["value"][discriminator],
                )
                self.assertEqual(
                    actual_state,
                    step["observedAfter"]["value"][discriminator],
                )
                self.assertNotEqual(
                    step["expectedAfter"], step["observedAfter"]
                )

    def test_lifecycle_validator_proves_full_contract(self) -> None:
        result = self.combined_result
        self.assertEqual(0, result.returncode, result.stdout)
        expected_metrics = {
            "METASCHEMA_FAILURES": 0,
            "SUITE_ERRORS": 0,
            "POSITIVE_FAILURES": 0,
            "NEGATIVE_FAILURES": 0,
            "SEMANTIC_SCHEMA_FAILURES": 0,
            "SEMANTIC_BASELINE_ERRORS": 0,
            "DECLARED_STEP_OCCURRENCES": 215,
            "MUTABLE_STEP_OCCURRENCES": 167,
            "SELF_HOSTING_STEP_OCCURRENCES": 48,
            "ENUMERATED_CRASH_WINDOWS": 334,
            "TERMINAL_PRESENCE_PAIRS": 4,
            "SEMANTIC_MUTANT_FAILURES": 0,
        }
        actual_metrics: dict[str, int] = {}
        for line in result.stdout.splitlines():
            name, separator, value = line.partition(" ")
            if separator and name in expected_metrics:
                actual_metrics[name] = int(value)
        self.assertEqual(expected_metrics, actual_metrics, result.stdout)

    def test_combined_validator_runs_every_contract_layer(self) -> None:
        self.assertTrue(
            COMBINED_VALIDATOR.is_file(), "нет единой команды проверки договоров"
        )
        result = self.combined_result
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("TASK1_CONTRACTS_OK", result.stdout)
        self.assertIn("SEMANTIC_ROUTING_CONTRACTS_OK", result.stdout)
        self.assertIn("PROTOCOL_V2_CONTRACTS_OK", result.stdout)
        self.assertIn("STATE_SCHEMA_ARTIFACTS_OK", result.stdout)
        self.assertIn("LIFECYCLE_CONTRACTS_OK", result.stdout)
        self.assertIn("LIFECYCLE_COMMAND_RESULT_CONTRACTS_OK", result.stdout)
        self.assertIn("ACTIVATION_PREPARATION_CONTRACTS_OK", result.stdout)

    def test_activation_preparation_contract_is_machine_checked(self) -> None:
        expected_artifacts = (
            PREPARATION_VALIDATOR,
            ROOT
            / "docs/contracts/schemas/activation-preparation-journal-v2.schema.json",
            ROOT
            / "docs/contracts/schemas/activation-preparation-receipt-v2.schema.json",
            ROOT / "docs/contracts/vectors/activation-preparation-v2.json",
        )
        for artifact in expected_artifacts:
            with self.subTest(artifact=artifact.name):
                self.assertTrue(artifact.is_file(), f"нет артефакта {artifact}")

        lifecycle_contract = (
            ROOT / "docs/contracts/adaptive-subagents-lifecycle-v2.md"
        ).read_text(encoding="utf-8")
        for invariant in (
            "activation-preparation-journal-v2",
            "activation-preparation-receipt-v2",
            "preparation_intent",
            "activation_tree_prepare",
            "database_inode_prepare",
            "preparation_freeze",
            "preparation_receipt_publish",
            "preparation_journal_close",
        ):
            with self.subTest(invariant=invariant):
                self.assertIn(invariant, lifecycle_contract)

    def test_reproducible_environment_pins_validator_dependencies(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('jsonschema[format]==4.25.1', pyproject)
        self.assertIn('referencing==0.36.2', pyproject)
        self.assertTrue((ROOT / "uv.lock").is_file(), "нет файла блокировки uv")


class QualityGateEntrypointTests(unittest.TestCase):
    def test_local_and_ci_entrypoints_use_complete_locked_quality_gate(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/contracts.yml").read_text(
            encoding="utf-8"
        )
        makefile_commands = (
            "uv run --locked python scripts/validate_contracts.py",
            (
                "uv run --locked python -m unittest discover "
                "-s tests/smart_subagents -p 'test_*.py'"
            ),
            "uv run --locked python scripts/validate_docs_navigation.py",
            (
                "uv run --locked python -m compileall -q scripts "
                "plugins/codex-smart-subagents/src tests/smart_subagents"
            ),
        )
        for command in makefile_commands:
            with self.subTest(command=command):
                self.assertIn(command, makefile)
        self.assertIn("quality: contracts docs tests compile", makefile)
        self.assertIn("run: make quality", workflow)
        self.assertNotIn(
            "run: uv run --locked python scripts/validate_contracts.py",
            workflow,
        )


class LifecycleConstraintSchemaShapeTests(unittest.TestCase):
    def test_manifest_commit_preserves_prepared_source_binding(self) -> None:
        operation_schema = json.loads(
            (
                ROOT / "docs/contracts/schemas/operation-step-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        prepared_action = operation_schema["$defs"]["actionPreparedManifest"]
        self.assertEqual(
            {
                "actionKind",
                "method",
                "sourcePath",
                "targetPath",
                "durability",
            },
            set(prepared_action["required"]),
        )
        manifest_commit = operation_schema["$defs"]["manifestCommit"]
        self.assertEqual(
            "#/$defs/actionPreparedManifest",
            manifest_commit["properties"]["action"]["$ref"],
        )

    def test_database_prepare_promotes_target_to_live_binding(self) -> None:
        operation_schema = json.loads(
            (
                ROOT / "docs/contracts/schemas/operation-step-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        database_prepare = operation_schema["$defs"]["databasePrepare"]
        self.assertEqual(
            "#/$defs/file",
            database_prepare["properties"]["before"]["$ref"],
        )
        self.assertEqual(
            "#/$defs/databaseBinding",
            database_prepare["properties"]["expectedAfter"]["$ref"],
        )


if __name__ == "__main__":
    unittest.main()
