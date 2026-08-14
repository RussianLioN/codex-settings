from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    domain_fingerprint,
)
from codex_smart_subagents.installer_maintenance_v2 import (  # noqa: E402
    InstallerMaintenanceLayoutV2,
    RegistrationCallbacksV2,
    RegistrationObservationV2,
    _verify_completed_uninstall,
    inspect_maintenance_inventory_v2,
)
from codex_smart_subagents.installer_uninstall_composition_v2 import (  # noqa: E402
    UNINSTALL_ACTIVE_STEPS_V2,
    build_active_uninstall_composition_v2,
    recover_active_uninstall_composition_v2,
)
from codex_smart_subagents.installer_update_operation_v2 import (  # noqa: E402
    UpdateStepPortV2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    FailurePointV2,
    OperationJournalStoreV2,
    RecoveryStateAmbiguousV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)
from codex_smart_subagents.operation_definition_rehydration_v2 import (  # noqa: E402
    operation_definition_from_journal_v2,
)
from codex_smart_subagents.shutdown_socket_cleanup_v2 import (  # noqa: E402
    ShutdownSocketOrphanProofV2,
)


class _InjectedUninstallCrash(RuntimeError):
    pass


class InstallerUninstallCompositionV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from tests.smart_subagents.test_activation_transition_v2 import (
            ActivationTransitionV2Tests,
        )

        cls.fixture_class = ActivationTransitionV2Tests
        cls.fixture_class.setUpClass()
        automaton = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )["fixtures"]["automaton"]
        cls.registry = LifecyclePlanRegistryV2.from_document(automaton)

    def setUp(self) -> None:
        self.fixture = self.fixture_class(methodName="runTest")
        self.fixture.setUp()
        self.proof = self.fixture.capture()
        config_path = self.fixture.codex_home / "config.toml"
        config_path.write_text("[test]\nenabled=true\n", encoding="utf-8")
        config_path.chmod(0o600)

        self.protocol = LifecycleControllerProtocolV2(
            database_path=self.proof.database_path,
            codex_home=self.fixture.codex_home,
            controller_lock_path=self.proof.state_home / "controller.lock",
        )
        self.fixture.runtime.bind_lifecycle_handler(self.protocol.handle)

        marketplace = self.proof.activation_dir / "marketplace"
        plugin = marketplace / "plugins" / "codex-smart-subagents"
        self.registration_state = {
            "plugin": RegistrationObservationV2(
                kind="plugin",
                name=(
                    "codex-smart-subagents@codex-settings-adaptive"
                ),
                target=plugin,
            ),
            "marketplace": RegistrationObservationV2(
                kind="marketplace",
                name="codex-settings-adaptive",
                target=marketplace,
            ),
        }

        def observe(
            kind: str,
            name: str,
        ) -> RegistrationObservationV2 | None:
            value = self.registration_state.get(kind)
            return value if value is not None and value.name == name else None

        def remove(expected: RegistrationObservationV2) -> None:
            if self.registration_state.get(expected.kind) != expected:
                raise AssertionError("registration changed before removal")
            del self.registration_state[expected.kind]

        self.registrations = RegistrationCallbacksV2(
            observe=observe,
            remove=remove,
        )
        manifest_root = self.proof.layout.manifest_root
        self.maintenance = InstallerMaintenanceLayoutV2(
            codex_home=self.fixture.codex_home,
            managed_root=self.proof.layout.managed_root,
            activations_root=self.proof.layout.managed_root / "activations",
            manifest_path=self.proof.layout.manifest_path,
            installer_receipt_path=self.fixture.installer_receipt_path,
            marketplace_link=self.proof.layout.marketplace_link,
            receipts_root=self.proof.layout.receipts_root,
            cleanup_journal_path=(
                manifest_root
                / "codex-smart-subagents-v2.cleanup.transaction.json"
            ),
            uninstall_journal_path=(
                manifest_root
                / "codex-smart-subagents-v2.uninstall.transaction.json"
            ),
            tombstone_path=(
                manifest_root / "codex-smart-subagents-v2.tombstone.json"
            ),
            lock_path=(
                manifest_root / "codex-smart-subagents-v2.installer.lock"
            ),
            state_home=self.proof.state_home,
            databases_root=self.proof.state_home / "databases",
            backups_root=self.proof.state_home / "backups",
            quarantine_root=self.proof.state_home / "quarantine",
            recovery_entrypoint=ROOT / "scripts/install_adaptive_subagents.py",
        )
        self.inventory = inspect_maintenance_inventory_v2(
            self.maintenance,
            registrations=self.registrations,
        )
        self.assertEqual((), self.inventory.issues)
        self.store = OperationJournalStoreV2(
            journal_path=self.proof.layout.journal_path,
            lock_path=self.maintenance.lock_path,
            validate_document=build_operation_journal_validator_v2(
                ROOT / "docs/contracts/schemas"
            ),
        )
        self.cleanup_done = False
        self.plan_fingerprint: str | None = None

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _orphan_proof(self, shutdown) -> ShutdownSocketOrphanProofV2:
        if self.plan_fingerprint is None:
            raise AssertionError("shutdown cleanup plan is not bound")
        draft = ShutdownSocketOrphanProofV2(
            plan_fingerprint=self.plan_fingerprint,
            shutdown_proof_fingerprint=shutdown.proof_fingerprint,
            process_exit_proof_fingerprint="d" * 64,
            exclusive_lock_proof_fingerprint="e" * 64,
            proof_fingerprint="0" * 64,
        )
        fingerprint = domain_fingerprint(
            "codex-smart/shutdown-socket-orphan-proof/v2",
            {
                "planFingerprint": draft.plan_fingerprint,
                "shutdownProofFingerprint": (
                    draft.shutdown_proof_fingerprint
                ),
                "processExitProofFingerprint": (
                    draft.process_exit_proof_fingerprint
                ),
                "exclusiveLockProofFingerprint": (
                    draft.exclusive_lock_proof_fingerprint
                ),
            },
        )
        return ShutdownSocketOrphanProofV2(
            plan_fingerprint=draft.plan_fingerprint,
            shutdown_proof_fingerprint=draft.shutdown_proof_fingerprint,
            process_exit_proof_fingerprint=(
                draft.process_exit_proof_fingerprint
            ),
            exclusive_lock_proof_fingerprint=(
                draft.exclusive_lock_proof_fingerprint
            ),
            proof_fingerprint=fingerprint,
        )

    def _cleanup_port(self) -> UpdateStepPortV2:
        def observe(step):
            if self.cleanup_done or not os.path.lexists(
                Path(str(step.action["socketPath"]))
            ):
                return step.expected_after
            return step.before

        def apply(step) -> None:
            self.fixture.runtime.close()
            if os.path.lexists(Path(str(step.action["socketPath"]))):
                raise AssertionError("test controller socket survived close")
            self.cleanup_done = True

        return UpdateStepPortV2(
            observe=observe,
            apply=apply,
            matches_before=lambda observed, step: observed == step.before,
            matches_after=lambda observed, step: observed == step.expected_after,
            completed_current_matches=lambda persisted, current, step: (
                persisted == current == step.expected_after
            ),
        )

    def _bind_plan_fingerprint(self, composition) -> None:
        steps = {
            step.kind: step for step in composition.definition.mutable_steps
        }
        cleanup = steps["shutdown_socket_cleanup"]
        self.plan_fingerprint = domain_fingerprint(
            "codex-smart/shutdown-socket-cleanup-plan/v2",
            {
                "installationId": self.proof.installation_id,
                "activationProofFingerprint": self.proof.proof_fingerprint,
                "operationId": composition.definition.operation_id,
                "shutdownCommandId": cleanup.action["proofSourceId"],
                "action": dict(cleanup.action),
            },
        )

    def _build(self, *, port_overrides=None):
        overrides = {
            "shutdown_socket_cleanup": self._cleanup_port(),
            **({} if port_overrides is None else dict(port_overrides)),
        }
        composition = build_active_uninstall_composition_v2(
            registry=self.registry,
            proof=self.proof,
            maintenance_layout=self.maintenance,
            inventory=self.inventory,
            registrations=self.registrations,
            store=self.store,
            controller_port_options={
                "shutdown_orphan_prover": self._orphan_proof,
            },
            port_overrides=overrides,
        )
        self._bind_plan_fingerprint(composition)
        return composition

    def _recover(self):
        definition = operation_definition_from_journal_v2(self.store.read())
        composition = recover_active_uninstall_composition_v2(
            registry=self.registry,
            definition=definition,
            maintenance_layout=self.maintenance,
            registrations=self.registrations,
            store=self.store,
            controller_port_options={
                "shutdown_orphan_prover": self._orphan_proof,
            },
            port_overrides={
                "shutdown_socket_cleanup": self._cleanup_port(),
            },
        )
        self._bind_plan_fingerprint(composition)
        return composition

    def test_live_controller_executes_exact_active_uninstall_plan(self) -> None:
        composition = self._build()
        database_path = self.proof.database_path
        recovery_bytes = self.maintenance.recovery_entrypoint.read_bytes()

        run, result = composition.execute()

        self.assertEqual("COMPLETED", run.status)
        self.assertEqual("uninstalled", result.status)
        self.assertEqual(
            UNINSTALL_ACTIVE_STEPS_V2,
            composition.definition.execution_plan.composed_step_kinds,
        )
        self.assertFalse(self.store.journal_path.exists())
        self.assertTrue(self.maintenance.lock_path.is_file())
        self.assertEqual(0o600, self.maintenance.lock_path.stat().st_mode & 0o777)
        self.assertTrue(result.receipt_path.is_file())
        self.assertTrue(self.maintenance.tombstone_path.is_file())
        self.assertFalse(self.maintenance.manifest_path.exists())
        self.assertFalse(self.maintenance.installer_receipt_path.exists())
        self.assertFalse(self.maintenance.marketplace_link.exists())
        self.assertEqual({}, self.registration_state)
        self.assertTrue(database_path.is_file())
        self.assertEqual(
            recovery_bytes,
            self.maintenance.recovery_entrypoint.read_bytes(),
        )
        verified = _verify_completed_uninstall(
            self.maintenance,
            registrations=self.registrations,
        )
        self.assertEqual("unchanged", verified.status)
        self.assertEqual(result.operation_id, verified.operation_id)

    def test_preview_and_apply_build_the_identical_durable_definition(self) -> None:
        preview = self._build()
        apply = self._build()

        self.assertEqual(preview.definition, apply.definition)
        self.assertEqual(
            UNINSTALL_ACTIVE_STEPS_V2,
            preview.definition.execution_plan.composed_step_kinds,
        )
        self.assertFalse(self.store.journal_path.exists())
        self.assertEqual({"plugin", "marketplace"}, set(self.registration_state))
        self.assertTrue(self.maintenance.manifest_path.is_file())

    def test_crash_before_first_controller_action_runs_no_later_effect(self) -> None:
        composition = self._build()
        link_target = os.readlink(self.maintenance.marketplace_link)

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "maintenance_begin"
            ):
                raise _InjectedUninstallCrash(kind)

        with self.assertRaises(_InjectedUninstallCrash):
            composition.execute(failure_injector=crash)

        journal = self.store.read()
        states = {step["kind"]: step["state"] for step in journal["steps"]}
        self.assertEqual("COMPLETED", states["gate_close"])
        self.assertEqual("INTENT_DURABLE", states["maintenance_begin"])
        self.assertTrue(
            all(
                states[kind] == "PLANNED"
                for kind in UNINSTALL_ACTIVE_STEPS_V2[2:13]
            )
        )
        self.assertEqual({"plugin", "marketplace"}, set(self.registration_state))
        self.assertEqual(link_target, os.readlink(self.maintenance.marketplace_link))
        self.assertTrue(self.maintenance.activations_root.is_dir())
        self.assertTrue(self.maintenance.manifest_path.is_file())
        self.assertFalse(self.maintenance.tombstone_path.exists())

    def test_recovery_continues_after_destructive_plugin_effect(self) -> None:
        composition = self._build()

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "uninstall_plugin_remove"
            ):
                raise _InjectedUninstallCrash(kind)

        with self.assertRaises(_InjectedUninstallCrash):
            composition.execute(failure_injector=crash)

        journal = self.store.read()
        states = {step["kind"]: step["state"] for step in journal["steps"]}
        self.assertEqual("FORWARD_ONLY", journal["recoveryPolicy"])
        self.assertEqual("COMPLETED", states["recovery_forward_only"])
        self.assertEqual("INTENT_DURABLE", states["uninstall_plugin_remove"])
        self.assertNotIn("plugin", self.registration_state)
        self.assertIn("marketplace", self.registration_state)

        run, result = self._recover().execute()

        self.assertEqual("COMPLETED", run.status)
        self.assertEqual("uninstalled", result.status)
        self.assertFalse(self.store.journal_path.exists())
        self.assertEqual({}, self.registration_state)
        self.assertTrue(result.receipt_path.is_file())
        self.assertTrue(self.maintenance.tombstone_path.is_file())

    def test_manifest_removal_resumes_from_partially_deleted_owned_pair(self) -> None:
        baseline = self._build()
        step = next(
            item
            for item in baseline.definition.mutable_steps
            if item.kind == "uninstall_manifest_remove"
        )
        production_port = baseline.ports[step.kind]

        self.assertEqual(
            str(self.maintenance.installer_receipt_path),
            step.action["installerReceiptPath"],
        )
        both_present = production_port.observe(step)
        self.assertTrue(production_port.matches_before(both_present, step))
        self.assertFalse(
            production_port.matches_intent_resume(both_present, step)
        )
        crashed = False

        def unlink_first_then_crash(received) -> None:
            nonlocal crashed
            if crashed:
                production_port.apply(received)
                return
            crashed = True
            path = Path(str(received.action["path"]))
            path.unlink()
            descriptor = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise _InjectedUninstallCrash("between manifest pair unlinks")

        crashing_port = UpdateStepPortV2(
            observe=production_port.observe,
            apply=unlink_first_then_crash,
            matches_before=production_port.matches_before,
            matches_after=production_port.matches_after,
            matches_intent_resume=production_port.matches_intent_resume,
            replay_safe_when_indistinguishable=(
                production_port.replay_safe_when_indistinguishable
            ),
            completed_current_matches=production_port.completed_current_matches,
        )
        composition = self._build(
            port_overrides={"uninstall_manifest_remove": crashing_port}
        )
        operation_id = composition.definition.operation_id

        with self.assertRaisesRegex(
            _InjectedUninstallCrash, "between manifest pair unlinks"
        ):
            composition.execute()

        journal = self.store.read()
        persisted = [
            item
            for item in journal["steps"]
            if item["kind"] == "uninstall_manifest_remove"
        ]
        self.assertEqual(1, len(persisted))
        self.assertEqual("INTENT_DURABLE", persisted[0]["state"])
        self.assertEqual(operation_id, journal["operationId"])
        self.assertFalse(self.maintenance.manifest_path.exists())
        self.assertTrue(self.maintenance.installer_receipt_path.exists())
        partial = production_port.observe(step)
        self.assertFalse(production_port.matches_before(partial, step))
        self.assertFalse(production_port.matches_after(partial, step))
        self.assertTrue(production_port.matches_intent_resume(partial, step))

        run, result = self._recover().execute()

        self.assertEqual("COMPLETED", run.status)
        self.assertEqual(operation_id, result.operation_id)
        self.assertFalse(self.store.journal_path.exists())
        self.assertFalse(self.maintenance.installer_receipt_path.exists())
        both_absent = production_port.observe(step)
        self.assertTrue(production_port.matches_after(both_absent, step))
        self.assertFalse(
            production_port.matches_intent_resume(both_absent, step)
        )

    def test_manifest_pair_observer_distinguishes_other_partial_state(self) -> None:
        composition = self._build()
        step = next(
            item
            for item in composition.definition.mutable_steps
            if item.kind == "uninstall_manifest_remove"
        )
        port = composition.ports[step.kind]
        self.maintenance.installer_receipt_path.unlink()

        partial = port.observe(step)

        self.assertEqual("absence-observation-v2", partial.schema_id)
        self.assertEqual(
            [str(self.maintenance.installer_receipt_path)],
            [entry["path"] for entry in partial.value["entries"]],
        )
        self.assertFalse(port.matches_before(partial, step))
        self.assertFalse(port.matches_after(partial, step))
        self.assertTrue(port.matches_intent_resume(partial, step))

    def test_planned_manifest_pair_rejects_partial_state_without_unlinking_survivor(
        self,
    ) -> None:
        composition = self._build()
        self.maintenance.manifest_path.unlink()
        descriptor = os.open(
            self.maintenance.manifest_path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        with self.assertRaises(RecoveryStateAmbiguousV2):
            composition.execute()

        journal = self.store.read()
        manifest_steps = [
            item
            for item in journal["steps"]
            if item["kind"] == "uninstall_manifest_remove"
        ]
        self.assertEqual(1, len(manifest_steps))
        self.assertEqual("PLANNED", manifest_steps[0]["state"])
        self.assertTrue(self.maintenance.installer_receipt_path.exists())
        self.assertEqual("FAILED", journal["attempts"][-1]["outcome"])

    def test_recovery_publishes_terminal_artifacts_after_frozen_crash(self) -> None:
        composition = self._build()

        def crash(point: FailurePointV2, _kind: str) -> None:
            if point is FailurePointV2.AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT:
                raise _InjectedUninstallCrash("terminal_journal_freeze")

        with self.assertRaises(_InjectedUninstallCrash):
            composition.execute(failure_injector=crash)

        frozen = self.store.read()
        self.assertEqual("TERMINAL_FROZEN", frozen["phase"])
        self.assertEqual("FORWARD_ONLY", frozen["recoveryPolicy"])
        terminal = composition.definition.terminal
        assert terminal is not None
        self.assertFalse(terminal.receipt_path.exists())
        self.assertFalse(self.maintenance.tombstone_path.exists())
        self.assertFalse(self.maintenance.manifest_path.exists())

        run, result = self._recover().execute()

        self.assertEqual("COMPLETED", run.status)
        self.assertFalse(self.store.journal_path.exists())
        self.assertTrue(result.receipt_path.is_file())
        self.assertTrue(self.maintenance.tombstone_path.is_file())


if __name__ == "__main__":
    unittest.main()
