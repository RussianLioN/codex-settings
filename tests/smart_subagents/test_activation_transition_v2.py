from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayLayout,
    _tree_sha256,
)
from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.activation_transition_v2 import (  # noqa: E402
    ActivationTransitionV2Error,
    accept_upgrade_candidate_v2,
    apply_activation_link_primitive_v2,
    apply_manifest_commit_primitive_v2,
    authorize_activation_link_plan_v2,
    authorize_manifest_commit_plan_v2,
    build_activation_link_plan_v2,
    build_activation_link_primitive_v2,
    build_manifest_commit_plan_v2,
    capture_activation_transition_proof_v2,
    observe_prepared_manifest_transition_v2,
    prepare_manifest_file_v2,
    prepare_manifest_commit_primitive_v2,
    reverify_activation_transition_proof_v2,
    shutdown_current_activation_v2,
    stage_upgrade_activation_v2,
)
import codex_smart_subagents.activation_transition_v2 as transition_v2  # noqa: E402
from codex_smart_subagents.health_bootstrap_v2 import (  # noqa: E402
    bootstrap_health_activation_v2,
)
from codex_smart_subagents.policy_bundle_v2 import (  # noqa: E402
    load_policy_bundle_v2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerCommandProofV2,
    LifecycleControllerQuiescenceV2,
)
from tests.smart_subagents.test_health_bootstrap_v2 import (  # noqa: E402
    _InterfaceExecutor,
    _Snapshotter,
)


NOW = datetime(2026, 7, 19, 16, 0, 0, tzinfo=timezone.utc)


def _operation_step_validator() -> Draft202012Validator:
    schema_dir = ROOT / "docs" / "contracts" / "schemas"
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in schema_dir.glob("*.json")
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values()
    )
    return Draft202012Validator(
        schemas["operation-step-v2.schema.json"], registry=registry
    )


class _ControllerPort:
    def __init__(self, *, control_epoch: int, quiescent: bool = True) -> None:
        self.control_epoch = control_epoch
        self.candidate_control_epoch = 1
        self.quiescent = quiescent
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.forge_next_epoch = False

    def _command(
        self,
        method: str,
        status: str,
        arguments: dict[str, object],
    ) -> LifecycleControllerCommandProofV2:
        self.calls.append((method, dict(arguments)))
        previous = self.control_epoch
        self.control_epoch += 2 if self.forge_next_epoch else 1
        self.forge_next_epoch = False
        command_id = "cc2_" + f"{len(self.calls):032x}"
        request_fingerprint = f"{len(self.calls):064x}"
        response_fingerprint = f"{len(self.calls) + 100:064x}"
        payload = {
            "status": status,
            "previousControlEpoch": previous,
            "newControlEpoch": self.control_epoch,
            "commandReceipt": {
                "commandId": command_id,
                "requestFingerprint": request_fingerprint,
                "resultFingerprint": f"{len(self.calls) + 200:064x}",
                "controlEpoch": self.control_epoch,
            },
        }
        return LifecycleControllerCommandProofV2(
            method=method,
            status=status,
            command_id=command_id,
            request_fingerprint=request_fingerprint,
            response_fingerprint=response_fingerprint,
            previous_control_epoch=previous,
            new_control_epoch=self.control_epoch,
            payload=payload,
        )

    def maintenance_begin(self, *, operation_id: str, reason_code: str):
        return self._command(
            "maintenance_begin",
            "MAINTENANCE_BEGUN",
            {"operation_id": operation_id, "reason_code": reason_code},
        )

    def wait_quiescent(self, *, operation_id: str, timeout_seconds: float):
        self.calls.append(
            (
                "wait_quiescent",
                {
                    "operation_id": operation_id,
                    "timeout_seconds": timeout_seconds,
                },
            )
        )
        return LifecycleControllerQuiescenceV2(
            operation_id=operation_id,
            state="MAINTENANCE" if self.quiescent else "DRAINING",
            maintenance_mode="DRAIN",
            control_epoch=self.control_epoch,
            quiescent=self.quiescent,
        )

    def maintenance_strengthen(self, *, operation_id: str):
        return self._command(
            "maintenance_strengthen",
            "MAINTENANCE_STRENGTHENED",
            {"operation_id": operation_id},
        )

    def shutdown(self, *, operation_id: str):
        return self._command(
            "shutdown", "SHUTDOWN_COMMITTED", {"operation_id": operation_id}
        )

    def candidate_accept(
        self,
        *,
        operation_id: str,
        activation_id: str,
        database_id: str,
        pid: int,
        process_start_marker: str,
        process_group_id: int,
    ):
        # The candidate owns a newly prepared database.  Its controller epoch
        # therefore starts independently from the epoch of the old database.
        self.control_epoch = self.candidate_control_epoch
        return self._command(
            "controller_accept",
            "CONTROLLER_ACCEPTED",
            {
                "operation_id": operation_id,
                "activation_id": activation_id,
                "database_id": database_id,
                "pid": pid,
                "process_start_marker": process_start_marker,
                "process_group_id": process_group_id,
            },
        )

    def candidate_recover(
        self,
        *,
        operation_id: str,
        activation_id: str,
        database_id: str,
        pid: int,
        process_start_marker: str,
        process_group_id: int,
    ):
        return self._command(
            "controller_recover",
            "CONTROLLER_RECOVERED",
            {
                "operation_id": operation_id,
                "activation_id": activation_id,
                "database_id": database_id,
                "pid": pid,
                "process_start_marker": process_start_marker,
                "process_group_id": process_group_id,
            },
        )

    def maintenance_resume(self, *, operation_id: str):
        return self._command(
            "maintenance_resume",
            "MAINTENANCE_RESUMED",
            {"operation_id": operation_id},
        )


class ActivationTransitionV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.step_validator = _operation_step_validator()
        cls.lifecycle_vectors = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="csat2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.codex_binary = self.root / "codex-source"
        self.codex_binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.codex_binary.chmod(0o500)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_bytes(b"#!/bin/sh\n")
        self.wrapper.chmod(0o500)
        self.layout = GatewayLayout.for_codex_home(self.codex_home)
        vectors = ROOT / "docs" / "contracts" / "vectors"
        self.policy = load_policy_bundle_v2(
            catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
            routing_vector_path=vectors / "routing-policy-v2.json",
            delegation_vector_path=vectors / "delegation-policy-v2.json",
            role_vector_path=vectors / "role-template-v1.json",
            child_profile_vector_path=vectors / "child-profile-v1.json",
        )
        self.snapshotter = _Snapshotter(self.layout.managed_root / "codex-snapshots")
        self.interface_executor = _InterfaceExecutor()
        self.runtime = bootstrap_health_activation_v2(
            source_root=ROOT,
            codex_home=self.codex_home,
            state_home=self.codex_home / "state" / "codex-smart-subagents-v2",
            codex_binary=self.codex_binary,
            wrapper=self.wrapper,
            policy_bundle=self.policy,
            snapshotter=self.snapshotter,
            interface_executor=self.interface_executor,
            snapshot_verifier=lambda _subject: None,
            completed_at=NOW,
        )
        self.binding = self.runtime.gateway_decision.runtime_binding
        assert self.binding is not None
        self.installer_receipt_path = (
            self.layout.manifest_root / "codex-smart-subagents-v2.installer.json"
        )
        self.operator_bin = self.root / "bin"
        self.operator_bin.mkdir(mode=0o700)
        links = []
        installed_bin = (
            self.layout.marketplace_link / "plugins" / "codex-smart-subagents" / "bin"
        )
        for name in ("codex-smart", "codex-smart-subagents-admin"):
            link = self.operator_bin / name
            target = installed_bin / name
            link.symlink_to(target)
            links.append({"path": str(link), "target": str(target)})
        installer_receipt = {
            "schemaVersion": 2,
            "kind": "codex-smart-installer-receipt/v2",
            "sourceDigest": "a" * 64,
            "installationId": self.runtime.materialization.installation_id,
            "activationId": self.runtime.materialization.activation_id,
            "codexHome": str(self.codex_home),
            "codexBinary": str(self.codex_binary),
            "stateHome": str(self.binding.state_home),
            "marketplacePath": str(self.layout.marketplace_link),
            "registeredMarketplacePath": str(self.binding.marketplace_path),
            "links": links,
            "marketplaceName": "codex-settings-adaptive",
            "pluginId": "codex-smart-subagents@codex-settings-adaptive",
            "extensions": {},
        }
        self.installer_receipt_path.write_text(
            json.dumps(installer_receipt, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        self.installer_receipt_path.chmod(0o600)

    def tearDown(self) -> None:
        self.runtime.close()
        self.temporary.cleanup()

    def capture(self):
        return capture_activation_transition_proof_v2(
            codex_home=self.codex_home,
            wrapper=self.wrapper,
            installer_receipt_path=self.installer_receipt_path,
            snapshot_verifier=lambda _subject: None,
        )

    def create_gate_journal(self, operation_id: str) -> None:
        document = {
            "schemaVersion": 2,
            "kind": "activation",
            "installationId": self.runtime.materialization.installation_id,
            "operationId": operation_id,
            "operation": "apply",
            "phase": "DISCOVERED",
            "steps": [{"kind": "gate_close", "state": "COMPLETED"}],
        }
        document["journalFingerprint"] = domain_fingerprint(
            "codex-smart/operation-journal/v2", document
        )
        self.layout.journal_path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        self.layout.journal_path.chmod(0o600)

    def shift_commit_receipt_devices(self, delta: int) -> None:
        receipt_path = self.runtime.materialization.receipt_path
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for name, domain in (
            ("manifest", "codex-smart/journal-state/v2"),
            ("activation", "codex-smart/journal-state/v2"),
            ("databaseBinding", "codex-smart/database-binding/v2"),
        ):
            projection = receipt[name]
            if name == "manifest":
                projection["value"]["file"]["device"] += delta
            elif name == "activation":
                projection["value"]["directory"]["device"] += delta
                projection["value"]["activationFile"]["device"] += delta
            else:
                projection["value"]["device"] += delta
            projection["valueFingerprint"] = domain_fingerprint(
                domain,
                {
                    key: value
                    for key, value in projection.items()
                    if key != "valueFingerprint"
                },
            )
        absence = receipt["journalAbsenceTarget"]
        absence_value = absence["value"]
        for entry in absence_value["entries"]:
            entry["parentDevice"] += delta
        absence_value["proofFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof/v2",
            {
                key: value
                for key, value in absence_value.items()
                if key != "proofFingerprint"
            },
        )
        absence["valueFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof-projection/v2",
            {
                key: value
                for key, value in absence.items()
                if key != "valueFingerprint"
            },
        )
        receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2",
            {
                key: value
                for key, value in receipt.items()
                if key != "receiptFingerprint"
            },
        )
        receipt_path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def stage(self, proof, operation_id: str):
        return stage_upgrade_activation_v2(
            proof=proof,
            operation_id=operation_id,
            source_root=ROOT,
            codex_binary=self.codex_binary,
            policy_bundle=self.policy,
            snapshotter=self.snapshotter,
            interface_executor=self.interface_executor,
            completed_at=NOW,
        )

    def test_capture_binds_every_owned_current_activation_artifact(self) -> None:
        proof = self.capture()

        active = proof.manifest_document["activeActivation"]
        link_info = self.layout.marketplace_link.lstat()
        self.assertEqual(self.layout.manifest_path.read_bytes(), proof.manifest_raw)
        self.assertEqual(active, proof.active_pointer)
        self.assertEqual(active["symlinkTarget"], proof.link_target)
        self.assertEqual(link_info.st_ino, proof.link_inode)
        self.assertEqual(link_info.st_dev, proof.link_device)
        self.assertEqual(
            self.runtime.materialization.activation_id,
            proof.activation_document["activationId"],
        )
        self.assertEqual(
            proof.commit_receipt_document["activation"]["value"]["directory"][
                "treeSha256"
            ],
            proof.activation_tree_projection.value["treeSha256"],
        )
        self.assertEqual(
            self.runtime.materialization.receipt_path.read_bytes(),
            proof.commit_receipt_raw,
        )
        self.assertEqual(
            dict(self.binding.database_identity_row), proof.database_identity_row
        )
        self.assertEqual(dict(self.binding.controller_row), proof.controller_row)
        self.assertEqual(
            self.binding.controller_row["controller_identity"],
            proof.controller_identity,
        )
        self.assertEqual(
            self.installer_receipt_path.read_bytes(), proof.installer_receipt_raw
        )
        self.assertTrue(proof.complete)
        self.assertFalse(self.layout.journal_path.exists())

    def test_capture_and_reverify_accept_device_drift_after_reboot(self) -> None:
        self.shift_commit_receipt_devices(1)

        proof = self.capture()
        operation_id = "op2_" + "f" * 32
        self.create_gate_journal(operation_id)
        reverified = reverify_activation_transition_proof_v2(
            proof,
            operation_id=operation_id,
            require_journal=True,
        )

        self.assertEqual(proof.proof_fingerprint, reverified.proof_fingerprint)

    def test_reverify_keeps_same_operation_device_check_strict(self) -> None:
        proof = self.capture()
        operation_id = "op2_" + "e" * 32
        self.create_gate_journal(operation_id)
        original_file_projection = transition_v2._file_projection

        def changed_file_projection(path: Path):
            projection = original_file_projection(path)
            if path == self.layout.manifest_path:
                projection = dict(projection)
                projection["device"] += 1
            return projection

        with (
            mock.patch.object(
                transition_v2,
                "_file_projection",
                side_effect=changed_file_projection,
            ),
            self.assertRaises(ActivationTransitionV2Error) as captured,
        ):
            reverify_activation_transition_proof_v2(
                proof,
                operation_id=operation_id,
                require_journal=True,
            )

        self.assertEqual("MANIFEST_CHANGED", captured.exception.code)

    def test_capture_refuses_missing_or_foreign_installer_ownership_receipt(
        self,
    ) -> None:
        self.installer_receipt_path.unlink()
        with self.assertRaises(ActivationTransitionV2Error) as missing:
            self.capture()
        self.assertEqual("INSTALLER_RECEIPT_MISSING", missing.exception.code)

        self.installer_receipt_path.write_text("{}", encoding="utf-8")
        self.installer_receipt_path.chmod(0o600)
        with self.assertRaises(ActivationTransitionV2Error) as malformed:
            self.capture()
        self.assertEqual("INSTALLER_RECEIPT_INVALID", malformed.exception.code)

    def test_reverify_after_journal_detects_foreign_link_inode(self) -> None:
        proof = self.capture()
        operation_id = "op2_" + "1" * 32
        self.create_gate_journal(operation_id)
        target = os.readlink(self.layout.marketplace_link)
        self.layout.marketplace_link.unlink()
        self.layout.marketplace_link.symlink_to(target)

        with self.assertRaises(ActivationTransitionV2Error) as captured:
            reverify_activation_transition_proof_v2(
                proof,
                operation_id=operation_id,
                require_journal=True,
            )

        self.assertEqual("ACTIVE_LINK_CHANGED", captured.exception.code)

    def test_reverify_after_journal_detects_tree_or_receipt_changes(self) -> None:
        proof = self.capture()
        operation_id = "op2_" + "2" * 32
        self.create_gate_journal(operation_id)
        active_file = (
            proof.activation_dir
            / "marketplace"
            / "plugins"
            / "codex-smart-subagents"
            / "README.md"
        )
        active_file.write_bytes(active_file.read_bytes() + b"\nforeign\n")
        active_file.chmod(0o600)

        with self.assertRaises(ActivationTransitionV2Error) as tree:
            reverify_activation_transition_proof_v2(
                proof,
                operation_id=operation_id,
                require_journal=True,
            )
        self.assertEqual("ACTIVE_TREE_CHANGED", tree.exception.code)

    def test_stage_upgrade_preserves_current_publication_and_stages_new_identity(
        self,
    ) -> None:
        proof = self.capture()
        operation_id = "op2_" + "3" * 32
        self.create_gate_journal(operation_id)
        before = {
            "manifest": self.layout.manifest_path.read_bytes(),
            "linkTarget": os.readlink(self.layout.marketplace_link),
            "linkInode": self.layout.marketplace_link.lstat().st_ino,
            "commitReceipt": proof.commit_receipt_path.read_bytes(),
            "installerReceipt": self.installer_receipt_path.read_bytes(),
            "operatorLinks": tuple(
                os.readlink(Path(item["path"]))
                for item in proof.installer_receipt_document["links"]
            ),
            "activeTree": proof.activation_tree_projection,
        }

        staged = self.stage(proof, operation_id)
        self.assertEqual(proof.installation_id, staged.installation_id)
        self.assertEqual(operation_id, staged.operation_id)
        self.assertNotEqual(proof.activation_id, staged.activation_id)
        self.assertEqual("IDENTITY_STAGED", staged.status)
        self.assertTrue(staged.activation_dir.is_dir())
        self.assertFalse(staged.database_path.exists())
        self.assertEqual(before["manifest"], self.layout.manifest_path.read_bytes())
        self.assertEqual(
            before["linkTarget"], os.readlink(self.layout.marketplace_link)
        )
        self.assertEqual(
            before["linkInode"], self.layout.marketplace_link.lstat().st_ino
        )
        self.assertEqual(
            before["commitReceipt"], proof.commit_receipt_path.read_bytes()
        )
        self.assertEqual(
            before["installerReceipt"], self.installer_receipt_path.read_bytes()
        )
        self.assertEqual(
            before["operatorLinks"],
            tuple(
                os.readlink(Path(item["path"]))
                for item in proof.installer_receipt_document["links"]
            ),
        )
        reverified = reverify_activation_transition_proof_v2(
            proof,
            operation_id=operation_id,
            require_journal=True,
        )
        self.assertEqual(proof.proof_fingerprint, reverified.proof_fingerprint)
        self.assertEqual(before["activeTree"], reverified.activation_tree_projection)

    def test_stage_refuses_incomplete_proof_or_missing_gate_journal(self) -> None:
        proof = self.capture()
        operation_id = "op2_" + "4" * 32

        with self.assertRaises(ActivationTransitionV2Error) as captured:
            stage_upgrade_activation_v2(
                proof=proof,
                operation_id=operation_id,
                source_root=ROOT,
                codex_binary=self.codex_binary,
                policy_bundle=self.policy,
                snapshotter=self.snapshotter,
                interface_executor=self.interface_executor,
                completed_at=NOW,
            )

        self.assertEqual("OPERATION_JOURNAL_MISSING", captured.exception.code)

    def test_controller_port_proves_shutdown_then_exact_candidate_acceptance(
        self,
    ) -> None:
        proof = self.capture()
        operation_id = "op2_" + "5" * 32
        self.create_gate_journal(operation_id)
        staged = self.stage(proof, operation_id)
        port = _ControllerPort(control_epoch=int(proof.controller_row["control_epoch"]))

        shutdown = shutdown_current_activation_v2(
            proof=proof,
            operation_id=operation_id,
            controller_port=port,
            timeout_seconds=60.0,
        )
        link = build_activation_link_primitive_v2(
            proof=proof,
            staged=staged,
            shutdown=shutdown,
        )
        apply_activation_link_primitive_v2(link, shutdown=shutdown)
        accepted = accept_upgrade_candidate_v2(
            proof=proof,
            staged=staged,
            shutdown=shutdown,
            controller_port=port,
            pid=os.getpid(),
            process_start_marker="test-process-start",
            process_group_id=os.getpgrp(),
        )

        self.assertTrue(shutdown.complete)
        self.assertTrue(accepted.complete)
        self.assertEqual(
            [
                "maintenance_begin",
                "wait_quiescent",
                "maintenance_strengthen",
                "shutdown",
                "controller_accept",
            ],
            [name for name, _arguments in port.calls],
        )
        self.assertEqual(operation_id, accepted.operation_id)
        self.assertEqual(staged.activation_id, accepted.activation_id)
        self.assertEqual(staged.database_id, accepted.database_id)
        self.assertGreater(shutdown.shutdown.new_control_epoch, 1)
        self.assertEqual(1, accepted.candidate_accept.previous_control_epoch)
        self.assertEqual(2, accepted.candidate_accept.new_control_epoch)

    def test_active_work_is_resumed_and_never_reported_as_shutdown(self) -> None:
        proof = self.capture()
        operation_id = "op2_" + "6" * 32
        self.create_gate_journal(operation_id)
        port = _ControllerPort(
            control_epoch=int(proof.controller_row["control_epoch"]),
            quiescent=False,
        )

        with self.assertRaises(ActivationTransitionV2Error) as captured:
            shutdown_current_activation_v2(
                proof=proof,
                operation_id=operation_id,
                controller_port=port,
                timeout_seconds=1.0,
            )

        self.assertEqual("ACTIVE_WORK", captured.exception.code)
        self.assertEqual(
            ["maintenance_begin", "wait_quiescent", "maintenance_resume"],
            [name for name, _arguments in port.calls],
        )

    def test_forged_controller_epoch_stops_the_chain(self) -> None:
        proof = self.capture()
        operation_id = "op2_" + "7" * 32
        self.create_gate_journal(operation_id)
        port = _ControllerPort(control_epoch=int(proof.controller_row["control_epoch"]))
        port.forge_next_epoch = True

        with self.assertRaises(ActivationTransitionV2Error) as captured:
            shutdown_current_activation_v2(
                proof=proof,
                operation_id=operation_id,
                controller_port=port,
            )

        self.assertEqual("CONTROLLER_PROOF_INVALID", captured.exception.code)
        self.assertEqual(["maintenance_begin"], [name for name, _ in port.calls])

    def test_link_and_manifest_handlers_survive_durable_device_drift(
        self,
    ) -> None:
        self.shift_commit_receipt_devices(1)
        proof = self.capture()
        operation_id = "op2_" + "8" * 32
        self.create_gate_journal(operation_id)
        staged = self.stage(proof, operation_id)
        prepared_manifest = prepare_manifest_file_v2(
            proof=proof,
            staged=staged,
            activation_tree_sha256=_tree_sha256(staged.activation_dir),
        )
        link_plan = build_activation_link_plan_v2(proof=proof, staged=staged)
        manifest_plan = build_manifest_commit_plan_v2(
            proof=proof,
            staged=staged,
            prepared=prepared_manifest,
        )
        self.assertTrue(link_plan.complete)
        self.assertTrue(manifest_plan.complete)
        self.assertEqual(proof.link_projection, link_plan.before)
        self.assertEqual(proof.manifest_projection, manifest_plan.before)
        for fixture_name, plan in (
            ("activationLinkStep", link_plan),
            ("manifestCommitStep", manifest_plan),
        ):
            step = copy.deepcopy(self.lifecycle_vectors["fixtures"][fixture_name])
            step["action"] = copy.deepcopy(dict(plan.action))
            step["before"] = plan.before.to_document()
            step["expectedAfter"] = plan.expected_after.to_document()
            step["observedAfter"] = plan.expected_after.to_document()
            errors = list(self.step_validator.iter_errors(step))
            self.assertEqual([], errors, errors[0].message if errors else "")
        self.assertEqual(
            "BEFORE",
            observe_prepared_manifest_transition_v2(
                proof=proof,
                staged=staged,
                prepared=prepared_manifest,
            ).value,
        )
        port = _ControllerPort(control_epoch=int(proof.controller_row["control_epoch"]))
        shutdown = shutdown_current_activation_v2(
            proof=proof,
            operation_id=operation_id,
            controller_port=port,
        )
        link = authorize_activation_link_plan_v2(
            plan=link_plan,
            proof=proof,
            staged=staged,
            shutdown=shutdown,
        )

        link_result = apply_activation_link_primitive_v2(
            link,
            shutdown=shutdown,
        )

        self.assertEqual(link.before, link_result.before)
        self.assertEqual(link.expected_after, link_result.expected_after)
        self.assertEqual(link.expected_after, link_result.observed_after)
        self.assertEqual(
            f"activations/{staged.activation_id}/marketplace",
            os.readlink(self.layout.marketplace_link),
        )
        recovered_link = authorize_activation_link_plan_v2(
            plan=link_plan,
            proof=proof,
            staged=staged,
            shutdown=shutdown,
        )
        self.assertEqual(link.primitive_fingerprint, recovered_link.primitive_fingerprint)
        accepted = accept_upgrade_candidate_v2(
            proof=proof,
            staged=staged,
            shutdown=shutdown,
            controller_port=port,
            pid=os.getpid(),
            process_start_marker="test-process-start",
            process_group_id=os.getpgrp(),
        )
        manifest = authorize_manifest_commit_plan_v2(
            plan=manifest_plan,
            proof=proof,
            staged=staged,
            acceptance=accepted,
        )

        manifest_result = apply_manifest_commit_primitive_v2(
            manifest,
            acceptance=accepted,
        )
        self.assertEqual(
            "AFTER",
            observe_prepared_manifest_transition_v2(
                proof=proof,
                staged=staged,
                prepared=prepared_manifest,
            ).value,
        )
        recovered_manifest = authorize_manifest_commit_plan_v2(
            plan=manifest_plan,
            proof=proof,
            staged=staged,
            acceptance=accepted,
        )
        self.assertEqual(
            manifest.primitive_fingerprint,
            recovered_manifest.primitive_fingerprint,
        )

        committed = json.loads(self.layout.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest.before, manifest_result.before)
        self.assertEqual(manifest.expected_after, manifest_result.expected_after)
        self.assertEqual(manifest.expected_after, manifest_result.observed_after)
        self.assertEqual(
            staged.activation_id, committed["activeActivation"]["activationId"]
        )
        self.assertEqual(proof.active_pointer, committed["previousActivation"])
        self.assertEqual(proof.installation_id, committed["installationId"])
        self.assertEqual(operation_id, committed["lastCommittedOperation"])

    def test_manifest_commit_rejects_device_normalized_bad_value_fingerprint(
        self,
    ) -> None:
        proof = self.capture()
        operation_id = "op2_" + "7" * 32
        self.create_gate_journal(operation_id)
        staged = self.stage(proof, operation_id)
        prepared_manifest = prepare_manifest_file_v2(
            proof=proof,
            staged=staged,
            activation_tree_sha256=_tree_sha256(staged.activation_dir),
        )
        link_plan = build_activation_link_plan_v2(proof=proof, staged=staged)
        manifest_plan = build_manifest_commit_plan_v2(
            proof=proof,
            staged=staged,
            prepared=prepared_manifest,
        )
        port = _ControllerPort(control_epoch=int(proof.controller_row["control_epoch"]))
        shutdown = shutdown_current_activation_v2(
            proof=proof,
            operation_id=operation_id,
            controller_port=port,
        )
        link = authorize_activation_link_plan_v2(
            plan=link_plan,
            proof=proof,
            staged=staged,
            shutdown=shutdown,
        )
        apply_activation_link_primitive_v2(link, shutdown=shutdown)
        accepted = accept_upgrade_candidate_v2(
            proof=proof,
            staged=staged,
            shutdown=shutdown,
            controller_port=port,
            pid=os.getpid(),
            process_start_marker="test-process-start",
            process_group_id=os.getpgrp(),
        )
        manifest = authorize_manifest_commit_plan_v2(
            plan=manifest_plan,
            proof=proof,
            staged=staged,
            acceptance=accepted,
        )
        apply_manifest_commit_primitive_v2(manifest, acceptance=accepted)
        recovered_manifest = authorize_manifest_commit_plan_v2(
            plan=manifest_plan,
            proof=proof,
            staged=staged,
            acceptance=accepted,
        )
        bad_expected_after = replace(
            recovered_manifest.expected_after,
            value_fingerprint="1" * 64,
        )
        self.assertEqual(
            recovered_manifest.expected_after.value,
            bad_expected_after.value,
        )
        self.assertNotEqual(
            recovered_manifest.expected_after.value_fingerprint,
            bad_expected_after.value_fingerprint,
        )
        corrupted = replace(
            recovered_manifest,
            expected_after=bad_expected_after,
            primitive_fingerprint="0" * 64,
        )
        corrupted = transition_v2._replace_primitive_fingerprint(
            corrupted,
            transition_v2._primitive_fingerprint(corrupted),
        )

        with self.assertRaises(ActivationTransitionV2Error) as captured:
            apply_manifest_commit_primitive_v2(corrupted, acceptance=accepted)

        self.assertEqual("MANIFEST_CHANGED", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
