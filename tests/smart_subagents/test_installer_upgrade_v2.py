from __future__ import annotations

import copy
import os
import shutil
import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    ActivationPreparationExecutorV2,
    ActivationPreparationFailurePointV2,
    ActivationPreparationIntegrityErrorV2,
    prepared_receipt_to_staged_activation_v2,
)
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.installer_upgrade_v2 import (  # noqa: E402
    _installer_source_digest_from_activation_v2,
    build_persisted_upgrade_preparation_recovery_v2,
    build_upgrade_preparation_v2,
    execute_and_verify_upgrade_preparation_v2,
    installer_source_digest_from_materialized_activation_v2,
    observe_upgrade_database_v2,
    prepared_manifest_from_upgrade_receipt_v2,
    prepare_upgrade_database_v2,
)
from codex_smart_subagents.activation_transition_rehydration_v2 import (  # noqa: E402
    ActivationTransitionProofSnapshotV2,
    ActivationTransitionRehydrationV2Error,
    rehydrate_activation_transition_proof_v2,
)
from codex_smart_subagents import activation_transition_v2  # noqa: E402
from codex_smart_subagents import activation_transition_rehydration_v2  # noqa: E402
from codex_smart_subagents import activation_preparation_v2  # noqa: E402
from codex_smart_subagents import installer_upgrade_v2  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)
from tests.smart_subagents.test_activation_transition_v2 import (  # noqa: E402
    ActivationTransitionV2Tests,
)
from tests.smart_subagents.test_activation_preparation_contract_runtime import (  # noqa: E402
    _validators,
)
from tests.smart_subagents.test_installer_entrypoint_v2 import (  # noqa: E402
    _filesystem_snapshot,
    _load_installer,
)


class InstallerUpgradePreparationV2Tests(unittest.TestCase):
    def test_rehydration_preserves_the_exact_operation_deadline(self) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="rollback",
            phase="rehydration",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )
        with mock.patch.object(
            activation_transition_rehydration_v2,
            "_rehydrate_activation_transition_proof_v2",
            side_effect=original,
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                rehydrate_activation_transition_proof_v2({})

        self.assertIs(original, caught.exception)

    def _source_digest(self, source_root: Path = ROOT) -> str:
        installer = _load_installer()
        return installer._source_digest(
            installer.InstallLayout(
                source_root=source_root,
                codex_home=self.fixture.codex_home,
                bin_dir=self.fixture.operator_bin,
                codex_binary=self.fixture.codex_binary,
                state_home=self.fixture.binding.state_home,
            )
        )

    def test_persisted_recovery_aborts_before_the_first_effect_without_source(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "6" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )

        def crash(point, _step_kind) -> None:
            if point is ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT:
                raise RuntimeError("simulated crash before first effect")

        with self.assertRaisesRegex(RuntimeError, "before first effect"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
                failure_injector=crash,
            ).execute()

        recovery = build_persisted_upgrade_preparation_recovery_v2(
            journal_path=preparation.definition.journal_path,
        )
        aborted = recovery.recover()

        self.assertEqual("ABORTED_BEFORE_FIRST_EFFECT", aborted.status)
        self.assertFalse(preparation.definition.journal_path.exists())
        self.assertFalse(preparation.definition.receipt_path.exists())
        self.assertFalse(
            preparation.definition.activation_intent.activation_dir.exists()
        )

    def test_persisted_recovery_finishes_from_candidate_and_codex_snapshots(
        self,
    ) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "7" * 32
        source_root = self.fixture.root / "ephemeral-source"
        for relative in (
            Path(".agents"),
            Path(".claude-plugin"),
            Path(".codex"),
            Path("docs/contracts"),
            Path("plugins/codex-smart-subagents"),
        ):
            shutil.copytree(ROOT / relative, source_root / relative)
        installer_path = source_root / "scripts" / "install_adaptive_subagents.py"
        installer_path.parent.mkdir(mode=0o700)
        shutil.copy2(ROOT / "scripts" / "install_adaptive_subagents.py", installer_path)
        installer = _load_installer()
        source_digest = installer._source_digest(
            installer.InstallLayout(
                source_root=source_root,
                codex_home=self.fixture.codex_home,
                bin_dir=self.fixture.operator_bin,
                codex_binary=self.fixture.codex_binary,
                state_home=self.fixture.binding.state_home,
            )
        )
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=source_root,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )

        def crash(point, step_kind) -> None:
            if (
                point
                is ActivationPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE
                and step_kind == "activation_tree"
            ):
                raise RuntimeError("simulated crash after candidate effect")

        with self.assertRaisesRegex(RuntimeError, "after candidate effect"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
                failure_injector=crash,
            ).execute()
        shutil.rmtree(source_root)
        self.fixture.codex_binary.unlink()

        with (
            mock.patch(
                "codex_smart_subagents.installer_upgrade_v2._materialize_marketplace",
                side_effect=AssertionError("persisted recovery read source_root"),
            ),
            mock.patch(
                "codex_smart_subagents.installer_upgrade_v2.probe_codex_interface_v1",
                side_effect=AssertionError("persisted recovery probed Codex"),
            ),
        ):
            recovery = build_persisted_upgrade_preparation_recovery_v2(
                journal_path=preparation.definition.journal_path,
            )
            receipt = recovery.recover()

        self.assertEqual(operation_id, receipt.operation_id)
        self.assertFalse(preparation.definition.journal_path.exists())
        self.assertTrue(preparation.definition.receipt_path.exists())
        self.assertEqual(
            source_digest,
            recovery.prepared_manifest_plan.manifest_document["extensions"][
                "installerSourceDigest"
            ],
        )

    def test_persisted_recovery_preserves_a_manifest_without_source_digest(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "8" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )

        def crash(point, step_kind) -> None:
            if (
                point
                is ActivationPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE
                and step_kind == "activation_tree"
            ):
                raise RuntimeError("simulated source-digest-free crash")

        with self.assertRaisesRegex(RuntimeError, "source-digest-free"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
                failure_injector=crash,
            ).execute()

        with mock.patch(
            "codex_smart_subagents.installer_upgrade_v2."
            "_installer_source_digest_from_activation_v2",
            side_effect=AssertionError("digest-free recovery reconstructed source"),
        ):
            recovery = build_persisted_upgrade_preparation_recovery_v2(
                journal_path=preparation.definition.journal_path,
            )
            receipt = recovery.recover()

        self.assertEqual(
            preparation.definition.activation_intent.operation_id, receipt.operation_id
        )
        self.assertNotIn(
            "installerSourceDigest",
            recovery.prepared_manifest_plan.manifest_document["extensions"],
        )

    def test_recovery_rejects_entrypoints_bound_to_different_python_files(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "d" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        plugin_root = (
            preparation.definition.activation_intent.activation_dir
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
        )
        entrypoint = sorted(
            (plugin_root / "bin").iterdir(),
            key=lambda path: path.name.encode("utf-8"),
        )[0]
        other_python = (self.fixture.root / "other-python").resolve()
        other_python.write_bytes(b"different-python-runtime")
        other_python.chmod(0o500)
        payload = entrypoint.read_bytes()
        line_end = payload.find(b"\n")
        entrypoint.chmod(0o700)
        entrypoint.write_bytes(
            f"#!{other_python} -B\n".encode("utf-8") + payload[line_end + 1 :]
        )
        entrypoint.chmod(0o500)

        with self.assertRaisesRegex(ValueError, "bind different runtimes"):
            _installer_source_digest_from_activation_v2(preparation.definition)

    def test_recovery_digest_accepts_isolated_python_entrypoint_runtime(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "e" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        plugin_root = (
            preparation.definition.activation_intent.activation_dir
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
        )
        entrypoint = sorted(
            (plugin_root / "bin").iterdir(),
            key=lambda path: path.name.encode("utf-8"),
        )[0]
        payload = entrypoint.read_bytes()
        line_end = payload.find(b"\n")
        runtime = Path(sys.executable).resolve(strict=True)
        entrypoint.chmod(0o700)
        entrypoint.write_bytes(
            f"#!{runtime} -S -B\n".encode("utf-8") + payload[line_end + 1 :]
        )
        entrypoint.chmod(0o500)

        digest = _installer_source_digest_from_activation_v2(preparation.definition)

        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_bound_python_runtime_rejects_carriage_return_in_path(
        self,
    ) -> None:
        entrypoint = self.fixture.root / "entrypoint"
        payload = b"#!/tmp/py\rbin -S -B\nprint('no')\n"

        with self.assertRaisesRegex(ValueError, "invalid runtime path"):
            installer_upgrade_v2._bound_python_runtime_from_shebang_v2(
                entrypoint,
                payload,
            )

    def setUp(self) -> None:
        self.fixture = ActivationTransitionV2Tests(methodName="runTest")
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def test_builder_prepares_inactive_candidate_without_changing_publication(
        self,
    ) -> None:
        proof = self.fixture.capture()
        before_manifest = proof.layout.manifest_path.read_bytes()
        before_link = os.readlink(proof.layout.marketplace_link)
        operation_id = "op2_" + "9" * 32

        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        self.assertFalse(preparation.prepared_manifest_plan.prepared_path.exists())
        self.assertFalse(
            preparation.prepared_manifest_plan.prepared_path.parent.exists()
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        staged = prepared_receipt_to_staged_activation_v2(receipt)

        self.assertEqual(before_manifest, proof.layout.manifest_path.read_bytes())
        self.assertEqual(before_link, os.readlink(proof.layout.marketplace_link))
        self.assertNotEqual(proof.activation_id, staged.activation_id)
        self.assertEqual(operation_id, staged.operation_id)
        self.assertTrue(staged.activation_dir.is_dir())
        self.assertTrue(staged.database_path.is_file())
        self.assertEqual(0, staged.database_path.stat().st_size)
        self.assertFalse(preparation.definition.journal_path.exists())
        self.assertTrue(preparation.definition.receipt_path.exists())

    def test_preparation_definition_and_receipt_freeze_transition_proof(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "1" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )

        snapshot = preparation.definition.transition_proof_snapshot
        self.assertIsInstance(snapshot, ActivationTransitionProofSnapshotV2)
        self.assertTrue(snapshot.complete)
        self.assertEqual(operation_id, snapshot.operation_id)
        self.assertEqual(
            snapshot,
            ActivationTransitionProofSnapshotV2.from_document(snapshot.to_document()),
        )

        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()

        self.assertEqual(snapshot, receipt.transition_proof_snapshot)
        self.assertEqual(
            snapshot.to_document(),
            receipt.to_document()["transitionProofSnapshot"],
        )

        foreign_document = snapshot.to_document()
        foreign_document["stateHome"] = str(snapshot.state_home.parent / "foreign")
        foreign_document["snapshotFingerprint"] = domain_fingerprint(
            "codex-smart/activation-transition-proof-snapshot/v2",
            {
                key: value
                for key, value in foreign_document.items()
                if key != "snapshotFingerprint"
            },
        )
        foreign_snapshot = ActivationTransitionProofSnapshotV2.from_document(
            foreign_document
        )
        with self.assertRaises(ActivationPreparationIntegrityErrorV2):
            replace(
                preparation.definition,
                transition_proof_snapshot=foreign_snapshot,
            )
        with self.assertRaises(ActivationPreparationIntegrityErrorV2):
            replace(receipt, transition_proof_snapshot=foreign_snapshot)

    def test_transition_proof_rehydrates_after_durable_device_drift(
        self,
    ) -> None:
        self.fixture.shift_commit_receipt_devices(1)
        proof = self.fixture.capture()
        operation_id = "op2_" + "2" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        staged = prepared_receipt_to_staged_activation_v2(receipt)
        prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=receipt,
        )
        link_plan = activation_transition_v2.build_activation_link_plan_v2(
            proof=proof,
            staged=staged,
        )
        manifest_plan = activation_transition_v2.build_manifest_commit_plan_v2(
            proof=proof,
            staged=staged,
            prepared=prepared,
        )
        journal = {
            "installationId": proof.installation_id,
            "operationId": operation_id,
            "executionPlan": {
                "planId": "pl2_" + "2" * 32,
                "firstIncompleteOrdinal": 1,
            },
            "steps": [
                {
                    "kind": "gate_close",
                    "state": "COMPLETED",
                    "planOrdinal": 0,
                    "planId": "pl2_" + "2" * 32,
                    "recordCarrier": "JOURNAL_ATOMIC_BOUNDARY",
                },
                {
                    "kind": "activation_link",
                    "state": "PLANNED",
                    "planOrdinal": 1,
                    "planId": "pl2_" + "2" * 32,
                    "recordCarrier": "JOURNAL_MUTABLE",
                    "action": dict(link_plan.action),
                    "before": link_plan.before.to_document(),
                    "expectedAfter": link_plan.expected_after.to_document(),
                    "observedAfter": None,
                },
                {
                    "kind": "manifest_commit",
                    "state": "PLANNED",
                    "planOrdinal": 2,
                    "planId": "pl2_" + "2" * 32,
                    "recordCarrier": "JOURNAL_MUTABLE",
                    "action": dict(manifest_plan.action),
                    "before": manifest_plan.before.to_document(),
                    "expectedAfter": manifest_plan.expected_after.to_document(),
                    "observedAfter": None,
                },
            ],
        }
        snapshot = receipt.transition_proof_snapshot

        before = rehydrate_activation_transition_proof_v2(
            snapshot,
            journal=journal,
        )
        self.assertEqual(proof.proof_fingerprint, before.proof_fingerprint)
        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            rehydrate_activation_transition_proof_v2(
                snapshot,
                journal={**journal, "operationId": "op2_" + "f" * 32},
            )
        reordered = {**journal, "steps": list(reversed(journal["steps"]))}
        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            rehydrate_activation_transition_proof_v2(
                snapshot,
                journal=reordered,
            )
        foreign_plan = copy.deepcopy(journal)
        foreign_plan["steps"][1]["planId"] = "pl2_" + "f" * 32
        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            rehydrate_activation_transition_proof_v2(
                snapshot,
                journal=foreign_plan,
            )

        temporary_link = proof.layout.marketplace_link.parent / "candidate-link"
        os.symlink(str(link_plan.action["target"]), temporary_link)
        os.replace(temporary_link, proof.layout.marketplace_link)
        journal["steps"][0].update(
            state="COMPLETED",
        )
        journal["steps"][1].update(
            state="COMPLETED",
            observedAfter=link_plan.expected_after.to_document(),
        )
        journal["executionPlan"]["firstIncompleteOrdinal"] = 2
        after_link = rehydrate_activation_transition_proof_v2(
            snapshot,
            journal=journal,
        )
        self.assertEqual(proof.proof_fingerprint, after_link.proof_fingerprint)

        os.replace(prepared.prepared_path, proof.layout.manifest_path)
        journal["steps"][2].update(
            state="COMPLETED",
            observedAfter=manifest_plan.expected_after.to_document(),
        )
        journal["executionPlan"]["firstIncompleteOrdinal"] = 3
        after_manifest = rehydrate_activation_transition_proof_v2(
            snapshot,
            journal=journal,
        )
        self.assertEqual(proof.proof_fingerprint, after_manifest.proof_fingerprint)

        rogue_link = proof.layout.marketplace_link.parent / "rogue-link"
        os.symlink("activations/rogue/marketplace", rogue_link)
        os.replace(rogue_link, proof.layout.marketplace_link)
        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            rehydrate_activation_transition_proof_v2(
                snapshot,
                journal=journal,
            )

    def test_main_recovery_reuses_receipt_after_activation_link_completed(
        self,
    ) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "b" * 32
        source_digest = self._source_digest()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )
        receipt = execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )
        staged = prepared_receipt_to_staged_activation_v2(receipt)
        prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=receipt,
        )
        link_plan = activation_transition_v2.build_activation_link_plan_v2(
            proof=proof,
            staged=staged,
        )
        manifest_plan = activation_transition_v2.build_manifest_commit_plan_v2(
            proof=proof,
            staged=staged,
            prepared=prepared,
        )
        plan_id = "pl2_" + "b" * 32
        journal = {
            "kind": "activation",
            "operation": "apply",
            "installationId": proof.installation_id,
            "operationId": operation_id,
            "executionPlan": {
                "planId": plan_id,
                "firstIncompleteOrdinal": 2,
            },
            "steps": [
                {
                    "kind": "gate_close",
                    "state": "COMPLETED",
                    "planOrdinal": 0,
                    "planId": plan_id,
                    "recordCarrier": "JOURNAL_ATOMIC_BOUNDARY",
                },
                {
                    "kind": "activation_link",
                    "state": "COMPLETED",
                    "planOrdinal": 1,
                    "planId": plan_id,
                    "recordCarrier": "JOURNAL_MUTABLE",
                    "action": dict(link_plan.action),
                    "before": link_plan.before.to_document(),
                    "expectedAfter": link_plan.expected_after.to_document(),
                    "observedAfter": link_plan.expected_after.to_document(),
                },
                {
                    "kind": "manifest_commit",
                    "state": "PLANNED",
                    "planOrdinal": 2,
                    "planId": plan_id,
                    "recordCarrier": "JOURNAL_MUTABLE",
                    "action": dict(manifest_plan.action),
                    "before": manifest_plan.before.to_document(),
                    "expectedAfter": manifest_plan.expected_after.to_document(),
                    "observedAfter": None,
                },
            ],
        }
        temporary_link = proof.layout.marketplace_link.parent / "recovery-link"
        os.symlink(str(link_plan.action["target"]), temporary_link)
        os.replace(temporary_link, proof.layout.marketplace_link)
        with self.assertRaises(
            activation_transition_v2.ActivationTransitionV2Error
        ) as strict_builder:
            build_upgrade_preparation_v2(
                proof=proof,
                operation_id=operation_id,
                source_root=ROOT,
                codex_binary=self.fixture.codex_binary,
                policy_bundle=self.fixture.policy,
                source_digest=source_digest,
            )
        self.assertEqual("ACTIVE_LINK_CHANGED", strict_builder.exception.code)
        filesystem_before = _filesystem_snapshot(self.fixture.root)

        installer = _load_installer()
        layout = installer.InstallLayout(
            source_root=ROOT,
            codex_home=self.fixture.codex_home,
            bin_dir=self.fixture.operator_bin,
            codex_binary=self.fixture.codex_binary,
            state_home=self.fixture.binding.state_home,
        )
        recovered_composition = object()
        store = SimpleNamespace(read=lambda: journal)
        contract = SimpleNamespace(
            plugin_source_path="plugins/codex-smart-subagents",
            plugin_version="0.2.0",
            install_policy="AVAILABLE",
            auth_policy="ON_INSTALL",
        )
        read_private_json = installer._read_private_json

        def read_recovery_json(path, *, code):
            if path == proof.layout.journal_path:
                return copy.deepcopy(journal)
            return read_private_json(path, code=code)

        with (
            mock.patch.object(
                installer,
                "_read_private_json",
                side_effect=read_recovery_json,
            ),
            mock.patch.object(
                installer,
                "OperationJournalStoreV2",
                return_value=store,
            ),
            mock.patch.object(
                installer,
                "_load_installer_receipt",
                return_value=proof.installer_receipt_document,
            ),
            mock.patch.object(
                installer,
                "_build_update_launcher_plan_v2",
                return_value=SimpleNamespace(bindings=()),
            ),
            mock.patch.object(
                installer,
                "_load_activation_marketplace_contract_v2",
                return_value=contract,
            ),
            mock.patch.object(
                installer,
                "_lifecycle_plan_registry_v2",
                return_value=object(),
            ),
            mock.patch.object(
                installer,
                "_registry_command_runner_v2",
                return_value=lambda *args, **kwargs: None,
            ),
            mock.patch.object(
                installer_upgrade_v2,
                "_materialize_marketplace",
                side_effect=AssertionError("recovery read working source"),
            ),
            mock.patch.object(
                installer_upgrade_v2,
                "probe_codex_interface_v1",
                side_effect=AssertionError("recovery probed working Codex"),
            ),
            mock.patch(
                "codex_smart_subagents.installer_update_composition_v2."
                "recover_update_matched_active_composition_v2",
                return_value=recovered_composition,
            ) as recover_composition,
        ):
            try:
                result = installer._build_update_main_recovery_composition_v2(
                    layout,
                    extra_environment=None,
                )
            except activation_transition_v2.ActivationTransitionV2Error as error:
                self.fail(
                    "main recovery повторно потребовал ссылку before: "
                    f"{error.code}"
                )

        self.assertIs(recovered_composition, result)
        recovered_preparation = recover_composition.call_args.kwargs["preparation"]
        self.assertEqual(preparation.definition, recovered_preparation.definition)
        self.assertEqual(
            preparation.prepared_manifest_plan,
            recovered_preparation.prepared_manifest_plan,
        )
        self.assertEqual(filesystem_before, _filesystem_snapshot(self.fixture.root))

        rogue_link = proof.layout.marketplace_link.parent / "rogue-recovery-link"
        os.symlink("activations/rogue/marketplace", rogue_link)
        os.replace(rogue_link, proof.layout.marketplace_link)
        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            installer_upgrade_v2._recover_upgrade_preparation_from_main_journal_v2(
                preparation_receipt_path=preparation.definition.receipt_path,
                journal=journal,
            )

        restored_link = proof.layout.marketplace_link.parent / "restored-link"
        os.symlink(str(link_plan.action["target"]), restored_link)
        os.replace(restored_link, proof.layout.marketplace_link)
        tampered_after = copy.deepcopy(journal)
        tampered_after["steps"][1]["expectedAfter"] = (
            link_plan.before.to_document()
        )
        tampered_after["steps"][1]["observedAfter"] = (
            link_plan.before.to_document()
        )
        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            installer_upgrade_v2._recover_upgrade_preparation_from_main_journal_v2(
                preparation_receipt_path=preparation.definition.receipt_path,
                journal=tampered_after,
            )

        os.replace(prepared.prepared_path, proof.layout.manifest_path)
        journal["steps"][2].update(
            state="COMPLETED",
            observedAfter=manifest_plan.expected_after.to_document(),
        )
        journal["executionPlan"]["firstIncompleteOrdinal"] = 3
        committed_filesystem = _filesystem_snapshot(self.fixture.root)
        committed = (
            installer_upgrade_v2._recover_upgrade_preparation_from_main_journal_v2(
                preparation_receipt_path=preparation.definition.receipt_path,
                journal=journal,
            )
        )
        self.assertEqual(preparation.definition, committed.definition)
        self.assertEqual(
            preparation.prepared_manifest_plan,
            committed.prepared_manifest_plan,
        )
        self.assertEqual(
            committed_filesystem,
            _filesystem_snapshot(self.fixture.root),
        )

    def test_transition_proof_rehydration_rejects_stable_tree_tamper(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "3" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        activation_file = proof.activation_dir / "activation.json"
        activation_file.chmod(0o600)
        activation_file.write_bytes(activation_file.read_bytes() + b"\n")

        with self.assertRaises(ActivationTransitionRehydrationV2Error):
            rehydrate_activation_transition_proof_v2(
                receipt.transition_proof_snapshot,
            )

    def test_repeat_reuses_exact_receipt_and_does_not_allocate_new_ids(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "a" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        executor = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        )
        first = executor.execute()

        rebuilt = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        second = ActivationPreparationExecutorV2(
            definition=rebuilt.definition,
            callbacks=rebuilt.callbacks,
        ).execute()

        self.assertEqual(first.to_document(), second.to_document())
        first_prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=first,
        )
        second_prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=rebuilt,
            receipt=second,
        )
        self.assertEqual(
            first_prepared.prepared_file_projection,
            second_prepared.prepared_file_projection,
        )
        self.assertEqual(first_prepared.prepared_path, second_prepared.prepared_path)

    def test_repeat_reuses_exact_receipt_after_main_journal_is_created(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "4" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        first = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        self.fixture.create_gate_journal(operation_id)

        rebuilt = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        second = ActivationPreparationExecutorV2(
            definition=rebuilt.definition,
            callbacks=rebuilt.callbacks,
        ).execute()

        self.assertEqual(first.to_document(), second.to_document())
        self.assertEqual(preparation.definition, rebuilt.definition)
        self.assertEqual(
            preparation.prepared_manifest_plan,
            rebuilt.prepared_manifest_plan,
        )

    def test_repeat_rejects_a_main_journal_for_another_operation(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "5" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        self.fixture.create_gate_journal("op2_" + "6" * 32)

        with self.assertRaises(
            activation_transition_v2.ActivationTransitionV2Error
        ) as captured:
            build_upgrade_preparation_v2(
                proof=proof,
                operation_id=operation_id,
                source_root=ROOT,
                codex_binary=self.fixture.codex_binary,
                policy_bundle=self.fixture.policy,
                snapshotter=self.fixture.snapshotter,
                interface_executor=self.fixture.interface_executor,
            )
        self.assertEqual("OPERATION_JOURNAL_INVALID", captured.exception.code)

    def test_prepared_manifest_is_bound_into_preparation_receipt(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "e" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )

        receipt = execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )

        prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=receipt,
        )
        self.assertEqual(
            proof.layout.manifest_root / "prepared-manifests",
            prepared.prepared_path.parent,
        )
        self.assertTrue(prepared.prepared_path.is_file())
        self.assertIn(prepared.prepared_file, receipt.desired.file_objects)
        self.assertEqual(
            prepared.prepared_file.value["inode"],
            prepared.prepared_path.stat().st_ino,
        )
        self.assertEqual(
            prepared.expected_after.value["file"]["inode"],
            prepared.prepared_path.stat().st_ino,
        )
        self.assertEqual(
            str(proof.layout.manifest_path),
            prepared.expected_after.value["file"]["path"],
        )
        errors = list(_validators()["receipt"].iter_errors(receipt.to_document()))
        self.assertEqual([], errors, errors[0].message if errors else "")

        incomplete_receipt = receipt.to_document()
        incomplete_receipt.pop("transitionProofSnapshot")
        self.assertTrue(list(_validators()["receipt"].iter_errors(incomplete_receipt)))

    def test_prepared_manifest_persists_installer_source_digest_for_reconciliation(
        self,
    ) -> None:
        proof = self.fixture.capture()
        source_digest = self._source_digest()

        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "d" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )

        self.assertEqual(
            source_digest,
            preparation.prepared_manifest_plan.manifest_document["extensions"][
                "installerSourceDigest"
            ],
        )
        receipt = execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )
        prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=receipt,
        )
        self.assertEqual(
            source_digest,
            prepared.manifest_document["extensions"]["installerSourceDigest"],
        )

    def test_capsule_reconstructs_exact_installer_source_digest(self) -> None:
        proof = self.fixture.capture()
        source_digest = self._source_digest()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "6" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )
        execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )
        intent = preparation.definition.activation_intent

        self.assertEqual(
            source_digest,
            installer_source_digest_from_materialized_activation_v2(
                activation_dir=intent.activation_dir,
                codex_binary=intent.codex_binary,
                source_locator=intent.source_locator,
                snapshot_locator=intent.snapshot_locator,
                snapshot_path=intent.snapshot_path,
            ),
        )

    def test_capsule_installer_mutation_breaks_source_digest(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "7" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        original_materialize = installer_upgrade_v2._materialize_marketplace

        def materialize_then_mutate_installer(**arguments) -> None:
            original_materialize(**arguments)
            installer = (
                arguments["marketplace"]
                / "scripts"
                / "install_adaptive_subagents.py"
            )
            installer.chmod(0o700)
            installer.write_bytes(installer.read_bytes() + b"\n")
            installer.chmod(0o500)

        with (
            mock.patch.object(
                installer_upgrade_v2,
                "_materialize_marketplace",
                side_effect=materialize_then_mutate_installer,
            ),
            self.assertRaisesRegex(
                ValueError,
                "sourceDigest differs from immutable candidate",
            ),
        ):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )

    def test_capsule_root_catalog_mutation_breaks_source_digest(self) -> None:
        proof = self.fixture.capture()
        source_digest = self._source_digest()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "8" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )
        execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )
        intent = preparation.definition.activation_intent
        catalog = (
            intent.activation_dir
            / "marketplace"
            / ".codex"
            / "adaptive-subagents.toml"
        )
        catalog.chmod(0o600)
        catalog.write_bytes(catalog.read_bytes() + b"\n# changed\n")

        reconstructed = installer_source_digest_from_materialized_activation_v2(
            activation_dir=intent.activation_dir,
            codex_binary=intent.codex_binary,
            source_locator=intent.source_locator,
            snapshot_locator=intent.snapshot_locator,
            snapshot_path=intent.snapshot_path,
        )

        self.assertNotEqual(source_digest, reconstructed)

    def test_preparation_rejects_source_digest_not_reproducible_from_candidate(
        self,
    ) -> None:
        proof = self.fixture.capture()
        with self.assertRaisesRegex(
            ValueError,
            "sourceDigest differs from immutable candidate",
        ):
            build_upgrade_preparation_v2(
                proof=proof,
                operation_id="op2_" + "e" * 32,
                source_root=ROOT,
                codex_binary=self.fixture.codex_binary,
                policy_bundle=self.fixture.policy,
                snapshotter=self.fixture.snapshotter,
                interface_executor=self.fixture.interface_executor,
                source_digest="0" * 64,
            )

        self.assertFalse(proof.layout.journal_path.exists())
        self.assertFalse(
            (
                proof.layout.manifest_root
                / "codex-smart-subagents-v2.activation-preparation.transaction.json"
            ).exists()
        )
        self.assertEqual(
            [],
            list(proof.layout.receipts_root.rglob("*.preparation.json")),
        )

    def test_source_change_after_build_aborts_candidate_and_next_attempt_succeeds(
        self,
    ) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "f" * 32
        source_root = self.fixture.root / "mutable-source"
        for relative in (
            Path(".agents"),
            Path(".claude-plugin"),
            Path(".codex"),
            Path("docs/contracts"),
            Path("plugins/codex-smart-subagents"),
        ):
            shutil.copytree(ROOT / relative, source_root / relative)
        installer_path = source_root / "scripts" / "install_adaptive_subagents.py"
        installer_path.parent.mkdir(mode=0o700)
        shutil.copy2(ROOT / "scripts" / "install_adaptive_subagents.py", installer_path)
        source_digest = self._source_digest(source_root)
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=source_root,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )
        changed = source_root / "plugins" / "codex-smart-subagents" / "README.md"
        original = changed.read_bytes()
        changed.write_bytes(original + b"\nchanged after build\n")

        with self.assertRaisesRegex(
            ValueError,
            "sourceDigest differs from immutable candidate",
        ):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )

        self.assertFalse(preparation.definition.activation_intent.activation_dir.exists())
        self.assertFalse(preparation.definition.receipt_path.exists())
        self.assertTrue(preparation.definition.journal_path.exists())
        aborted = build_persisted_upgrade_preparation_recovery_v2(
            journal_path=preparation.definition.journal_path,
        ).recover()
        self.assertEqual("ABORTED_BEFORE_FIRST_EFFECT", aborted.status)
        self.assertFalse(preparation.definition.journal_path.exists())

        changed.write_bytes(original)
        repeated = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=source_root,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=source_digest,
        )
        receipt = execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=repeated,
        )
        self.assertEqual(operation_id, receipt.operation_id)

    def test_activation_tree_is_built_in_a_sibling_stage_before_publication(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "1" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        activation_dir = preparation.definition.activation_intent.activation_dir
        observed_roots: list[Path] = []
        original = installer_upgrade_v2._materialize_marketplace

        def observe(**arguments):
            stage = arguments["marketplace"].parent
            observed_roots.append(stage)
            self.assertNotEqual(activation_dir, stage)
            self.assertEqual(activation_dir.parent, stage.parent)
            self.assertTrue(stage.name.startswith("." + activation_dir.name + "."))
            return original(**arguments)

        with mock.patch.object(
            installer_upgrade_v2,
            "_materialize_marketplace",
            side_effect=observe,
        ):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )

        self.assertEqual(1, len(observed_roots))
        self.assertTrue(activation_dir.is_dir())
        self.assertFalse(observed_roots[0].exists())

    def test_persisted_recovery_removes_an_incomplete_owned_stage_and_aborts(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "2" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )

        def stop_after_intent(point, _step_kind) -> None:
            if point is ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT:
                raise RuntimeError("simulated crash before tree publication")

        with self.assertRaisesRegex(RuntimeError, "before tree publication"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
                failure_injector=stop_after_intent,
            ).execute()
        intent = preparation.definition.activation_intent
        stage = (
            intent.activation_dir.parent
            / f".{intent.activation_id}.{intent.operation_id}.preparing"
        )
        installer_upgrade_v2._create_activation_stage_owner_v2(intent)
        stage.mkdir(mode=0o700)
        (stage / "partial").write_bytes(b"partial candidate\n")
        (stage / "partial").chmod(0o666)

        aborted = build_persisted_upgrade_preparation_recovery_v2(
            journal_path=preparation.definition.journal_path,
        ).recover()

        self.assertEqual("ABORTED_BEFORE_FIRST_EFFECT", aborted.status)
        self.assertFalse(stage.exists())
        self.assertFalse(preparation.definition.journal_path.exists())
        self.assertFalse(intent.activation_dir.exists())

    def test_persisted_recovery_normalizes_an_owned_stage_left_without_mode(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "8" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )

        def stop_after_intent(point, _step_kind) -> None:
            if point is ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT:
                raise RuntimeError("simulated crash before stage mode publication")

        with self.assertRaisesRegex(RuntimeError, "before stage mode publication"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
                failure_injector=stop_after_intent,
            ).execute()
        intent = preparation.definition.activation_intent
        stage = installer_upgrade_v2._activation_tree_stage_path_v2(intent)
        installer_upgrade_v2._create_activation_stage_owner_v2(intent)
        previous_umask = os.umask(0o777)
        try:
            stage.mkdir(mode=0o700)
        finally:
            os.umask(previous_umask)
        self.assertEqual(0o000, stage.stat().st_mode & 0o777)

        aborted = build_persisted_upgrade_preparation_recovery_v2(
            journal_path=preparation.definition.journal_path,
        ).recover()

        self.assertEqual("ABORTED_BEFORE_FIRST_EFFECT", aborted.status)
        self.assertFalse(stage.exists())
        self.assertFalse(
            installer_upgrade_v2._activation_tree_stage_owner_path_v2(
                intent
            ).exists()
        )
        self.assertFalse(preparation.definition.journal_path.exists())

    def test_recovery_never_removes_an_unproven_foreign_stage(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "5" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )

        def stop_after_intent(point, _step_kind) -> None:
            if point is ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT:
                raise RuntimeError("simulated crash before foreign stage")

        with self.assertRaisesRegex(RuntimeError, "before foreign stage"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
                failure_injector=stop_after_intent,
            ).execute()
        intent = preparation.definition.activation_intent
        stage = (
            intent.activation_dir.parent
            / f".{intent.activation_id}.{intent.operation_id}.preparing"
        )
        stage.mkdir(mode=0o700)
        foreign = stage / "foreign"
        foreign.write_bytes(b"foreign\n")
        foreign.chmod(0o600)

        with self.assertRaisesRegex(ValueError, "no ownership marker"):
            build_persisted_upgrade_preparation_recovery_v2(
                journal_path=preparation.definition.journal_path,
            ).recover()

        self.assertEqual(b"foreign\n", foreign.read_bytes())
        self.assertTrue(preparation.definition.journal_path.exists())

    def test_stage_owner_publication_never_exposes_a_partial_marker(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "6" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        intent = preparation.definition.activation_intent
        marker = installer_upgrade_v2._activation_tree_stage_owner_path_v2(intent)
        original_write = installer_upgrade_v2.os.write
        attempted = False

        def interrupt_write(descriptor, payload):
            nonlocal attempted
            if not attempted:
                attempted = True
                original_write(descriptor, payload[: max(1, len(payload) // 2)])
                raise OSError("simulated interrupted marker write")
            return original_write(descriptor, payload)

        with (
            mock.patch.object(
                installer_upgrade_v2.os,
                "write",
                side_effect=interrupt_write,
            ),
            self.assertRaisesRegex(OSError, "interrupted marker write"),
        ):
            installer_upgrade_v2._create_activation_stage_owner_v2(intent)

        self.assertFalse(marker.exists())
        self.assertEqual(
            [],
            list(marker.parent.glob(f".{marker.name}.publish-*")),
        )

    def test_stage_owner_mode_does_not_depend_on_inherited_umask(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "9" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        intent = preparation.definition.activation_intent
        marker = installer_upgrade_v2._activation_tree_stage_owner_path_v2(intent)

        previous_umask = os.umask(0o777)
        try:
            installer_upgrade_v2._create_activation_stage_owner_v2(intent)
        finally:
            os.umask(previous_umask)

        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        installer_upgrade_v2._unlink_activation_stage_owner_v2(intent)

    def test_stage_owner_validation_finishes_publication_after_link(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "a" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        intent = preparation.definition.activation_intent
        marker = installer_upgrade_v2._activation_tree_stage_owner_path_v2(intent)
        temporary = marker.with_name(f".{marker.name}.publish-{'b' * 32}")
        temporary.write_bytes(installer_upgrade_v2._stage_owner_raw_v2(intent))
        temporary.chmod(0o600)
        os.link(temporary, marker, follow_symlinks=False)

        observed = installer_upgrade_v2._validate_activation_stage_owner_v2(intent)

        self.assertEqual(1, observed.st_nlink)
        self.assertFalse(temporary.exists())
        installer_upgrade_v2._unlink_activation_stage_owner_v2(intent)

    def test_stage_directory_mode_is_private_at_creation_time(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "0" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        intent = preparation.definition.activation_intent
        stage = installer_upgrade_v2._activation_tree_stage_path_v2(intent)
        observed_modes: list[int] = []
        original_mkdir = Path.mkdir

        def observe_mkdir(path: Path, *args, **kwargs):
            result = original_mkdir(path, *args, **kwargs)
            if path == stage:
                observed_modes.append(path.stat().st_mode & 0o777)
            return result

        previous_umask = os.umask(0o777)
        try:
            with mock.patch.object(Path, "mkdir", new=observe_mkdir):
                execute_and_verify_upgrade_preparation_v2(
                    proof=proof,
                    preparation=preparation,
                )
        finally:
            os.umask(previous_umask)

        self.assertEqual([0o700], observed_modes)

    def test_partial_stage_failure_is_removed_and_recovery_can_abort(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "3" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        intent = preparation.definition.activation_intent
        stage = (
            intent.activation_dir.parent
            / f".{intent.activation_id}.{intent.operation_id}.preparing"
        )

        def fail_partway(**arguments):
            marketplace = arguments["marketplace"]
            marketplace.mkdir(parents=True, mode=0o700)
            partial = marketplace / "partial"
            partial.write_bytes(b"partial candidate\n")
            partial.chmod(0o600)
            raise OSError("simulated partial copy failure")

        with (
            mock.patch.object(
                installer_upgrade_v2,
                "_materialize_marketplace",
                side_effect=fail_partway,
            ),
            self.assertRaisesRegex(OSError, "partial copy failure"),
        ):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )

        self.assertFalse(stage.exists())
        self.assertFalse(intent.activation_dir.exists())
        self.assertFalse(preparation.definition.receipt_path.exists())
        aborted = build_persisted_upgrade_preparation_recovery_v2(
            journal_path=preparation.definition.journal_path,
        ).recover()
        self.assertEqual("ABORTED_BEFORE_FIRST_EFFECT", aborted.status)
        self.assertFalse(preparation.definition.journal_path.exists())

    def test_existing_final_activation_is_never_removed_by_staging_failure(
        self,
    ) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "4" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
            source_digest=self._source_digest(),
        )
        activation_dir = preparation.definition.activation_intent.activation_dir
        activation_dir.mkdir(mode=0o700)
        sentinel = activation_dir / "foreign"
        sentinel.write_bytes(b"foreign\n")
        sentinel.chmod(0o600)

        with self.assertRaisesRegex(Exception, "target exists"):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )

        self.assertEqual(b"foreign\n", sentinel.read_bytes())

    def test_orphan_prepared_manifest_without_journal_is_rejected(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "2" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        plan = preparation.prepared_manifest_plan
        plan.prepared_path.parent.mkdir(mode=0o700)
        plan.prepared_path.write_bytes(plan.prepared_raw)
        plan.prepared_path.chmod(0o600)

        with self.assertRaisesRegex(Exception, "without preparation journal"):
            ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
            ).execute()

        self.assertFalse(preparation.definition.journal_path.exists())
        self.assertFalse(preparation.definition.receipt_path.exists())

    def test_repeat_fsyncs_existing_prepared_manifest_parent(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "1" * 32
        first = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )

        def crash_after_manifest_intent(_point, step_kind) -> None:
            if step_kind == "prepared_manifest_file":
                raise RuntimeError("simulated crash after manifest intent")

        with self.assertRaisesRegex(RuntimeError, "simulated crash"):
            ActivationPreparationExecutorV2(
                definition=first.definition,
                callbacks=first.callbacks,
                failure_injector=crash_after_manifest_intent,
            ).execute()

        plan = first.prepared_manifest_plan
        plan.prepared_path.parent.mkdir(mode=0o700)
        plan.prepared_path.write_bytes(plan.prepared_raw)
        plan.prepared_path.chmod(0o600)
        synced: list[Path] = []
        original_sync = activation_preparation_v2._fsync_directory
        with mock.patch.object(
            activation_preparation_v2,
            "_fsync_directory",
            side_effect=lambda path: (synced.append(path), original_sync(path))[-1],
        ):
            repeated_receipt = ActivationPreparationExecutorV2(
                definition=first.definition,
                callbacks=first.callbacks,
            ).execute()
        repeated_prepared = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=first,
            receipt=repeated_receipt,
        )
        self.assertEqual(
            plan.prepared_path,
            repeated_prepared.prepared_path,
        )
        self.assertIn(repeated_prepared.prepared_path.parent, synced)

    def test_handoff_rejects_prepared_manifest_changed_after_receipt(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "f" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        preparation.prepared_manifest_plan.prepared_path.write_bytes(b"{}")

        with self.assertRaisesRegex(Exception, "physical identity changed"):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )
        self.assertFalse(proof.layout.journal_path.exists())

    def test_database_adapter_populates_pinned_file_and_repeats_safely(self) -> None:
        proof = self.fixture.capture()
        operation_id = "op2_" + "b" * 32
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        before = receipt.activation_intent.database_path.stat()

        empty_state, empty_projection = observe_upgrade_database_v2(receipt)

        first = prepare_upgrade_database_v2(receipt)
        after_first = receipt.activation_intent.database_path.stat()
        second = prepare_upgrade_database_v2(receipt)
        after_second = receipt.activation_intent.database_path.stat()
        prepared_state, prepared_projection = observe_upgrade_database_v2(receipt)

        self.assertEqual("EMPTY", empty_state.value)
        self.assertEqual(receipt.database_empty_file, empty_projection)
        self.assertEqual("PREPARED", prepared_state.value)
        self.assertEqual(first, prepared_projection)
        self.assertEqual("database-binding-v2", first.schema_id)
        self.assertEqual(first.to_document(), second.to_document())
        self.assertEqual(
            (before.st_dev, before.st_ino),
            (after_first.st_dev, after_first.st_ino),
        )
        self.assertEqual(
            (after_first.st_dev, after_first.st_ino),
            (after_second.st_dev, after_second.st_ino),
        )
        with closing(
            sqlite3.connect(receipt.activation_intent.database_path)
        ) as connection:
            journal_mode = connection.execute("pragma journal_mode").fetchone()[0]
            identity = connection.execute(
                "select database_id,created_operation_id,source_shape "
                "from database_identity"
            ).fetchone()
            controller = connection.execute(
                "select control_epoch,state,maintenance_mode,reason_code,operation_id "
                "from controller_state"
            ).fetchone()
        self.assertEqual(
            (receipt.activation_intent.database_id, operation_id, "fresh-v2"),
            identity,
        )
        self.assertEqual(
            (1, "MAINTENANCE", "FREEZE", "AWAITING_CONTROLLER_ACCEPT", operation_id),
            controller,
        )
        self.assertEqual("wal", str(journal_mode).lower())

    def test_database_adapter_recovers_real_process_death_inside_wal(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "d" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        database_path = receipt.activation_intent.database_path
        before = database_path.stat()
        interrupted = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import os,sqlite3,sys;"
                    "connection=sqlite3.connect(sys.argv[1],isolation_level=None);"
                    "connection.execute('pragma journal_mode=WAL');"
                    "connection.execute('BEGIN IMMEDIATE');"
                    "connection.execute('create table interrupted(value text)');"
                    "os._exit(93)"
                ),
                str(database_path),
            ],
            check=False,
        )

        self.assertEqual(93, interrupted.returncode)
        interrupted_state, interrupted_projection = observe_upgrade_database_v2(
            receipt
        )
        self.assertEqual("RECOVERABLE", interrupted_state.value)
        self.assertEqual("file-object-v2", interrupted_projection.schema_id)

        recovered = prepare_upgrade_database_v2(receipt)
        state, observed = observe_upgrade_database_v2(receipt)

        after = database_path.stat()
        self.assertEqual("PREPARED", state.value)
        self.assertEqual(recovered, observed)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertFalse(Path(f"{database_path}-wal").exists())
        self.assertFalse(Path(f"{database_path}-shm").exists())

    def test_handoff_reloads_live_receipt_before_main_journal_exists(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "c" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )

        receipt = execute_and_verify_upgrade_preparation_v2(
            proof=proof,
            preparation=preparation,
        )

        self.assertFalse(proof.layout.journal_path.exists())
        self.assertFalse(preparation.definition.journal_path.exists())
        self.assertEqual(
            receipt.to_document(),
            type(receipt).from_path(preparation.definition.receipt_path).to_document(),
        )
        self.assertEqual(0, receipt.activation_intent.database_path.stat().st_size)

    def test_handoff_rejects_database_changed_after_receipt(self) -> None:
        proof = self.fixture.capture()
        preparation = build_upgrade_preparation_v2(
            proof=proof,
            operation_id="op2_" + "d" * 32,
            source_root=ROOT,
            codex_binary=self.fixture.codex_binary,
            policy_bundle=self.fixture.policy,
            snapshotter=self.fixture.snapshotter,
            interface_executor=self.fixture.interface_executor,
        )
        receipt = ActivationPreparationExecutorV2(
            definition=preparation.definition,
            callbacks=preparation.callbacks,
        ).execute()
        receipt.activation_intent.database_path.write_bytes(b"changed")

        with self.assertRaisesRegex(Exception, "physical identity changed"):
            execute_and_verify_upgrade_preparation_v2(
                proof=proof,
                preparation=preparation,
            )
        self.assertFalse(proof.layout.journal_path.exists())


if __name__ == "__main__":
    unittest.main()
