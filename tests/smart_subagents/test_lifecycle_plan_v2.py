from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ExecutionPlanV2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanBlockedV2,
    LifecyclePlanContractErrorV2,
    LifecyclePlanRegistryV2,
)


VECTOR_PATH = ROOT / "docs" / "contracts" / "vectors" / "lifecycle-v2.json"
PLAN_ID = "pl2_1234567890abcdef1234567890abcdef"


class LifecyclePlanV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.automaton = vectors["fixtures"]["automaton"]

    def setUp(self) -> None:
        self.registry = LifecyclePlanRegistryV2.from_document(self.automaton)

    def test_update_plan_is_exact_conditional_prefix_then_common_machine(self) -> None:
        selected = self.registry.select(
            machine_id="apply",
            branch_id="update-matched-active",
            plan_id=PLAN_ID,
        )

        self.assertIsInstance(selected, ExecutionPlanV2)
        self.assertEqual(selected.machine_id, "apply")
        self.assertEqual(selected.selected_branch_id, "update-matched-active")
        self.assertEqual(
            selected.composed_step_kinds,
            (
                "gate_close",
                "maintenance_begin",
                "wait_runtime_quiescent",
                "maintenance_strengthen",
                "controller_shutdown",
                "shutdown_socket_cleanup",
                "database_prepare",
                "activation_link",
                "recovery_forward_only",
                "marketplace_registry",
                "plugin_registry",
                "launchers",
                "controller_candidate_spawn",
                "controller_accept",
                "verify_candidate",
                "manifest_commit",
                "maintenance_resume",
                "terminal_journal_freeze",
                "commit_receipt_publish",
                "gate_open",
            ),
        )
        self.assertEqual(20, len(selected.composed_step_kinds))

    def test_first_install_rollback_and_both_uninstall_paths_are_exact(self) -> None:
        cases = {
            ("apply", "fresh-proven-absent"): (
                "gate_close",
                "stage",
                "verify_staged",
                "database_prepare",
                "activation_link",
                "recovery_forward_only",
                "marketplace_registry",
                "plugin_registry",
                "launchers",
                "controller_candidate_spawn",
                "controller_accept",
                "verify_candidate",
                "manifest_commit",
                "maintenance_resume",
                "terminal_journal_freeze",
                "commit_receipt_publish",
                "gate_open",
            ),
            ("rollback", "rollback-matched-active"): (
                "gate_close",
                "maintenance_begin",
                "wait_runtime_quiescent",
                "maintenance_strengthen",
                "controller_shutdown",
                "shutdown_socket_cleanup",
                "activation_link_restore",
                "recovery_forward_only",
                "registry_restore",
                "launchers_restore",
                "controller_candidate_spawn",
                "controller_previous_accept",
                "verify_candidate",
                "manifest_restore",
                "maintenance_resume",
                "terminal_journal_freeze",
                "commit_receipt_publish",
                "gate_open",
            ),
            ("uninstall", "active-matched-controller"): (
                "gate_close",
                "maintenance_begin",
                "wait_runtime_quiescent",
                "maintenance_strengthen",
                "controller_shutdown",
                "shutdown_socket_cleanup",
                "recovery_forward_only",
                "uninstall_plugin_remove",
                "uninstall_marketplace_remove",
                "uninstall_launchers_restore",
                "uninstall_activation_link_remove",
                "uninstall_activation_remove",
                "uninstall_manifest_remove",
                "terminal_journal_freeze",
                "uninstall_receipt_publish",
                "uninstall_tombstone_publish",
                "uninstall_journal_close",
            ),
            ("uninstall", "disabled-or-missing-proven"): (
                "gate_close",
                "recovery_forward_only",
                "uninstall_plugin_remove",
                "uninstall_marketplace_remove",
                "uninstall_launchers_restore",
                "uninstall_activation_link_remove",
                "uninstall_activation_remove",
                "uninstall_manifest_remove",
                "terminal_journal_freeze",
                "uninstall_receipt_publish",
                "uninstall_tombstone_publish",
                "uninstall_journal_close",
            ),
        }

        for (machine_id, branch_id), expected in cases.items():
            with self.subTest(machine=machine_id, branch=branch_id):
                selected = self.registry.select(
                    machine_id=machine_id,
                    branch_id=branch_id,
                    plan_id=PLAN_ID,
                )
                self.assertEqual(selected.composed_step_kinds, expected)

    def test_ambiguous_unknown_and_non_public_machine_selection_fail_closed(self) -> None:
        with self.assertRaises(LifecyclePlanBlockedV2):
            self.registry.select(
                machine_id="apply",
                branch_id="mismatched-live-or-socket",
                plan_id=PLAN_ID,
            )
        with self.assertRaises(LifecyclePlanContractErrorV2):
            self.registry.select(
                machine_id="apply",
                branch_id="missing",
                plan_id=PLAN_ID,
            )
        with self.assertRaises(LifecyclePlanContractErrorV2):
            self.registry.select(
                machine_id="cleanup",
                branch_id=None,
                plan_id=PLAN_ID,
            )

    def test_contract_rejects_wrong_composition_rule_and_forward_pivot(self) -> None:
        wrong_rule = json.loads(json.dumps(self.automaton))
        wrong_rule["planSelectionRule"]["compositionOrder"] = "COMMON_THEN_PREFIX"
        with self.assertRaises(LifecyclePlanContractErrorV2):
            LifecyclePlanRegistryV2.from_document(wrong_rule)

        missing_pivot = json.loads(json.dumps(self.automaton))
        missing_pivot["machines"]["rollback"]["orderedSteps"].remove(
            "recovery_forward_only"
        )
        with self.assertRaises(LifecyclePlanContractErrorV2):
            LifecyclePlanRegistryV2.from_document(missing_pivot)

        duplicate_pivot = json.loads(json.dumps(self.automaton))
        duplicate_pivot["machines"]["apply"]["orderedSteps"].append(
            "recovery_forward_only"
        )
        with self.assertRaises(LifecyclePlanContractErrorV2):
            LifecyclePlanRegistryV2.from_document(duplicate_pivot)

    def test_document_is_deep_copied_and_selection_is_deterministic(self) -> None:
        document = json.loads(json.dumps(self.automaton))
        registry = LifecyclePlanRegistryV2.from_document(document)
        first = registry.select(
            machine_id="apply",
            branch_id="fresh-proven-absent",
            plan_id=PLAN_ID,
        )
        document["machines"]["apply"]["orderedSteps"].clear()
        second = registry.select(
            machine_id="apply",
            branch_id="fresh-proven-absent",
            plan_id=PLAN_ID,
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
