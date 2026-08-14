from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.lifecycle_constraint_matcher_v2 import (  # noqa: E402
    matches_controller_candidate_registration_v2,
    matches_controller_runtime_constraint_v2,
    matches_registry_constraint_v2,
    matches_shutdown_constraint_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import ProjectionV2  # noqa: E402


VECTOR_PATH = ROOT / "docs" / "contracts" / "vectors" / "lifecycle-v2.json"


class LifecycleConstraintMatcherV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))["fixtures"]

    def test_candidate_expected_registration_accepts_only_bound_ready_fact(
        self,
    ) -> None:
        spawn = self.fixtures["controllerCandidateSpawnStep"]
        constraint = ProjectionV2.from_document(spawn["expectedAfter"])
        actual = ProjectionV2.from_document(spawn["observedAfter"])

        self.assertTrue(
            matches_controller_candidate_registration_v2(actual, constraint)
        )
        changed = copy.deepcopy(spawn["observedAfter"])
        changed["value"]["readinessTokenHash"] = "0" * 64
        self.assertFalse(
            matches_controller_candidate_registration_v2(
                ProjectionV2.from_document(changed),
                constraint,
            )
        )
        changed_window = copy.deepcopy(spawn["observedAfter"])
        changed_window["value"]["readinessWindowMs"] -= 1
        self.assertFalse(
            matches_controller_candidate_registration_v2(
                ProjectionV2.from_document(changed_window),
                constraint,
            )
        )

    def test_spawn_contract_uses_window_and_previous_accept_uses_constraint(
        self,
    ) -> None:
        operation_schema = json.loads(
            (
                ROOT
                / "docs"
                / "contracts"
                / "schemas"
                / "operation-step-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        projection_schema = json.loads(
            (
                ROOT
                / "docs"
                / "contracts"
                / "schemas"
                / "lifecycle-projection-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        spawn_action = operation_schema["$defs"]["actionControllerSpawn"]
        candidate_projection = projection_schema["$defs"]["controllerCandidate"]

        self.assertIn("readinessWindowMs", spawn_action["required"])
        self.assertNotIn("absoluteDeadlineMonotonicMs", spawn_action["properties"])
        self.assertIn("readinessWindowMs", candidate_projection["required"])
        self.assertNotIn(
            "absoluteDeadlineMonotonicMs",
            candidate_projection["properties"],
        )
        self.assertEqual(
            {"$ref": "#/$defs/controllerCandidateExpected"},
            operation_schema["$defs"]["controllerPreviousAccept"]["properties"][
                "before"
            ],
        )
        self.assertNotIn(
            '"absoluteDeadlineMonotonicMs"',
            VECTOR_PATH.read_text(encoding="utf-8"),
        )

    def test_shutdown_constraint_distinguishes_commit_and_orphan_proof(self) -> None:
        step = self.fixtures["controllerShutdownStep"]
        constraint = ProjectionV2.from_document(step["expectedAfter"])
        proven = ProjectionV2.from_document(step["observedAfter"])
        committed_document = copy.deepcopy(step["observedAfter"])
        committed_document["value"].update(
            {
                "status": "SHUTDOWN_COMMITTED",
                "processExitProofFingerprint": None,
                "exclusiveLockProofFingerprint": None,
            }
        )
        committed = ProjectionV2.from_document(committed_document)

        self.assertTrue(matches_shutdown_constraint_v2(committed, constraint))
        self.assertFalse(
            matches_shutdown_constraint_v2(
                committed,
                constraint,
                require_orphan_proof=True,
            )
        )
        self.assertTrue(
            matches_shutdown_constraint_v2(
                proven,
                constraint,
                require_orphan_proof=True,
            )
        )

    def test_controller_runtime_constraint_accepts_bound_runtime_identity(self) -> None:
        accept = self.fixtures["controllerAcceptStep"]
        expected = ProjectionV2.from_document(accept["expectedAfter"])
        actual = ProjectionV2.from_document(accept["observedAfter"])

        self.assertTrue(matches_controller_runtime_constraint_v2(actual, expected))
        changed = copy.deepcopy(accept["observedAfter"])
        changed["value"]["databaseId"] = "db2_" + "0" * 32
        self.assertFalse(
            matches_controller_runtime_constraint_v2(
                ProjectionV2.from_document(changed),
                expected,
            )
        )

    def test_maintenance_begin_constraint_accepts_only_two_bound_race_results(
        self,
    ) -> None:
        accept = self.fixtures["controllerAcceptStep"]["observedAfter"]
        base = copy.deepcopy(accept)
        base["value"].update(
            {
                "controlEpoch": 8,
                "maintenanceMode": "drain",
                "operationId": "op2_" + "1" * 32,
                "acceptingNewRoutes": False,
            }
        )
        constraint_document = copy.deepcopy(base)
        constraint_document["value"].update(
            {
                "state": "EXPECTED_DRAIN_OR_MAINTENANCE",
                "quiescent": False,
            }
        )
        constraint = ProjectionV2.from_document(constraint_document)

        for state, quiescent in (("DRAINING", False), ("MAINTENANCE", True)):
            with self.subTest(state=state):
                actual_document = copy.deepcopy(base)
                actual_document["value"].update(
                    {"state": state, "quiescent": quiescent}
                )
                self.assertTrue(
                    matches_controller_runtime_constraint_v2(
                        ProjectionV2.from_document(actual_document),
                        constraint,
                    )
                )

        changed = copy.deepcopy(base)
        changed["value"].update({"state": "MAINTENANCE", "quiescent": False})
        self.assertFalse(
            matches_controller_runtime_constraint_v2(
                ProjectionV2.from_document(changed),
                constraint,
            )
        )

    def test_registry_constraint_never_requires_a_fictional_file_inode(self) -> None:
        common = {
            "marketplaceName": "codex-settings-adaptive",
            "marketplacePath": "/private/marketplace",
            "marketplaceFingerprint": "1" * 64,
            "pluginId": "codex-smart-subagents@codex-settings-adaptive",
            "pluginEnabled": True,
            "pluginFingerprint": "2" * 64,
            "configSemanticFingerprint": "3" * 64,
        }
        constraint = ProjectionV2(
            schema_id="registry-state-v2",
            schema_sha256="4" * 64,
            value={
                **common,
                "status": "EXPECTED_PLUGIN_ENABLED",
                "configFile": None,
                "marketplaceListFingerprint": None,
                "pluginListFingerprint": None,
            },
            value_fingerprint="5" * 64,
        )
        actual = ProjectionV2(
            schema_id="registry-state-v2",
            schema_sha256="4" * 64,
            value={
                **common,
                "status": "PLUGIN_ENABLED",
                "configFile": {
                    "path": "/private/config.toml",
                    "device": 1,
                    "inode": 99,
                    "ownerUid": 501,
                    "ownerGid": 20,
                    "mode": "0600",
                    "linkCount": 1,
                    "size": 100,
                    "sha256": "6" * 64,
                },
                "marketplaceListFingerprint": "7" * 64,
                "pluginListFingerprint": "8" * 64,
            },
            value_fingerprint="9" * 64,
        )

        self.assertTrue(matches_registry_constraint_v2(actual, constraint))
        changed = ProjectionV2(
            schema_id=actual.schema_id,
            schema_sha256=actual.schema_sha256,
            value={**actual.value, "marketplacePath": "/private/other"},
            value_fingerprint=actual.value_fingerprint,
        )
        self.assertFalse(matches_registry_constraint_v2(changed, constraint))


if __name__ == "__main__":
    unittest.main()
