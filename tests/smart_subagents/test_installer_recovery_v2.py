from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_preparation_v2 import (  # noqa: E402
    capture_file_projection_v2,
    capture_tree_projection_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.installer_recovery_v2 import (  # noqa: E402
    apply_activation_bytecode_repair_v2,
    ControllerRecoveryIntentV2,
    InstallerRecoveryV2Error,
    MainJournalRecoveryV2,
    PreparationJournalRecoveryV2,
    execute_recovery_v2,
    execute_rollback_v2,
    inspect_recovery_v2,
    inspect_activation_bytecode_repair_v2,
    plan_recovery_v2,
    plan_rollback_v2,
    read_rollback_v2,
    read_rollback_from_transition_v2,
)
from codex_smart_subagents.activation_gateway_v2 import _tree_sha256  # noqa: E402
from codex_smart_subagents.activation_transition_v2 import (  # noqa: E402
    ActivationTransitionProofV2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerCommandProofV2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    FailurePointV2,
    InjectedCrashV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    StoppedControllerLineageV2,
    TerminalCallbacksV2,
    TerminalDefinitionV2,
    TransitionSourceReceiptV2,
)
from codex_smart_subagents.lifecycle_plan_v2 import (  # noqa: E402
    LifecyclePlanRegistryV2,
)


SCHEMA_SHA256 = "a" * 64
INSTALLATION_ID = "ins2_" + "1" * 32
CURRENT_OPERATION_ID = "op2_" + "2" * 32
PREVIOUS_OPERATION_ID = "op2_" + "3" * 32
ROLLBACK_OPERATION_ID = "op2_" + "4" * 32
PLAN_ID = "pl2_" + "5" * 32
CURRENT_ACTIVATION_ID = "act2_" + "6" * 64
PREVIOUS_ACTIVATION_ID = "act2_" + "7" * 64
CURRENT_DATABASE_ID = "db2_" + "8" * 32
PREVIOUS_DATABASE_ID = "db2_" + "9" * 32


def _projection(
    schema_id: str,
    value: dict[str, object],
    domain: str,
) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": SCHEMA_SHA256,
        "value": copy.deepcopy(value),
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=SCHEMA_SHA256,
        value=value,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _bundle(*, activation: ProjectionV2 | None) -> StateBundleV2:
    return StateBundleV2(
        file_objects=(),
        tree_objects=(),
        symlinks=(),
        manifest=None,
        activation=activation,
        database=None,
        controller=None,
        controller_candidates=(),
        watchdogs=(),
        registry=None,
        launchers=None,
        legacy_processes=None,
        quiescence=None,
        external_commands=(),
        receipts=(),
        absence_proofs=(),
    )


def _write_private_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(canonical_json_bytes(document))
    path.chmod(0o600)


def _filesystem_snapshot(root: Path) -> tuple[tuple[str, str, object], ...]:
    values: list[tuple[str, str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            values.append((relative, "symlink", os.readlink(path)))
        elif path.is_dir():
            values.append((relative, "directory", None))
        elif path.is_file():
            values.append((relative, "file", path.read_bytes()))
        else:
            values.append((relative, "other", None))
    return tuple(values)


def _symlink_projection(path: Path) -> ProjectionV2:
    info = path.lstat()
    parent = path.parent.lstat()
    target = os.readlink(path)
    return _projection(
        "symlink-object-v2",
        {
            "path": str(path),
            "parentDevice": parent.st_dev,
            "parentInode": parent.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": f"0{info.st_mode & 0o777:03o}",
            "target": target,
            "targetFingerprint": hashlib.sha256(target.encode()).hexdigest(),
        },
        "codex-smart/symlink-object/v2",
    )


def _expected_symlink_projection(path: Path, target: str) -> ProjectionV2:
    value = dict(_symlink_projection(path).value)
    value["target"] = target
    value["targetFingerprint"] = hashlib.sha256(target.encode()).hexdigest()
    return _projection("symlink-object-v2", value, "codex-smart/symlink-object/v2")


def _marker_projection(path: Path, state: dict[str, bool]) -> ProjectionV2:
    return _projection(
        "file-object-v2",
        {"path": str(path), "state": copy.deepcopy(state)},
        "codex-smart/file-object/v2",
    )


def _absence(path: Path) -> ProjectionV2:
    parent = path.parent.stat()
    unsigned = {
        "proofId": "ap2_" + "a" * 32,
        "installationId": INSTALLATION_ID,
        "operationId": ROLLBACK_OPERATION_ID,
        "entries": [
            {
                "path": str(path),
                "basename": path.name,
                "parentDevice": parent.st_dev,
                "parentInode": parent.st_ino,
                "absent": True,
            }
        ],
        "directorySyncCompleted": True,
    }
    value = {
        **unsigned,
        "proofFingerprint": domain_fingerprint(
            "codex-smart/absence-proof/v2", unsigned
        ),
    }
    return _projection(
        "absence-proof-v2",
        value,
        "codex-smart/absence-proof-projection/v2",
    )


def _journal_document(domain: str, projection: dict[str, object]) -> dict[str, object]:
    return {
        **copy.deepcopy(projection),
        "journalFingerprint": domain_fingerprint(domain, projection),
    }


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 19, 13, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


class _Ids:
    def __init__(self) -> None:
        self.value = 1

    def __call__(self, prefix: str) -> str:
        result = f"{prefix}_{self.value:032x}"
        self.value += 1
        return result


class _FileEffects:
    def __init__(self, marker_path: Path, link_path: Path) -> None:
        self.marker_path = marker_path
        self.link_path = link_path
        self.calls: list[str] = []

    def callbacks(self) -> StepCallbacksV2:
        return StepCallbacksV2(
            observe=self.observe,
            apply=self.apply,
            completed_current_matches=self.completed_current_matches,
        )

    @staticmethod
    def completed_current_matches(
        persisted_after: ProjectionV2,
        current_observed: ProjectionV2,
        _definition: StepDefinitionV2,
    ) -> bool:
        if persisted_after.schema_id != "file-object-v2":
            return persisted_after == current_observed
        if current_observed.schema_id != persisted_after.schema_id:
            return False
        persisted_value = dict(persisted_after.value)
        current_value = dict(current_observed.value)
        if persisted_value.get("path") != current_value.get("path"):
            return False
        persisted_state = persisted_value.get("state")
        current_state = current_value.get("state")
        return (
            type(persisted_state) is dict
            and type(current_state) is dict
            and all(
                current_state.get(kind) is value
                for kind, value in persisted_state.items()
            )
        )

    def observe(self, step: StepDefinitionV2) -> ProjectionV2:
        if step.kind == "activation_link_restore":
            return _symlink_projection(self.link_path)
        state = json.loads(self.marker_path.read_text(encoding="utf-8"))
        return _marker_projection(self.marker_path, state)

    def apply(self, step: StepDefinitionV2) -> None:
        self.calls.append(step.kind)
        if step.kind == "activation_link_restore":
            target = str(step.expected_after.value["target"])
            temporary = self.link_path.with_name(".rollback-link")
            temporary.unlink(missing_ok=True)
            os.symlink(target, temporary)
            os.replace(temporary, self.link_path)
            return
        state = json.loads(self.marker_path.read_text(encoding="utf-8"))
        state[step.kind] = True
        _write_private_json(self.marker_path, state)


class _TerminalFiles:
    def __init__(self, receipt_path: Path) -> None:
        self.receipt_path = receipt_path
        self.publish_count = 0

    def callbacks(self) -> TerminalCallbacksV2:
        return TerminalCallbacksV2(
            receipt_matches=self.matches,
            publish_receipt=self.publish,
        )

    def matches(self, journal: dict[str, object]) -> bool:
        if not self.receipt_path.exists():
            return False
        document = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        return document == {
            "frozenJournalFingerprint": journal["journalFingerprint"],
            "operationId": journal["operationId"],
        }

    def publish(self, journal: dict[str, object]) -> None:
        self.publish_count += 1
        _write_private_json(
            self.receipt_path,
            {
                "frozenJournalFingerprint": journal["journalFingerprint"],
                "operationId": journal["operationId"],
            },
        )


@dataclass
class _PreparedReceipt:
    installation_id: str
    operation_id: str


class _PreparationExecutor:
    def __init__(
        self,
        journal_path: Path,
        *,
        installation_id: str = INSTALLATION_ID,
        operation_id: str = CURRENT_OPERATION_ID,
    ) -> None:
        self.definition = type(
            "Definition",
            (),
            {
                "journal_path": journal_path,
                "activation_intent": type(
                    "Intent",
                    (),
                    {
                        "installation_id": installation_id,
                        "operation_id": operation_id,
                    },
                )(),
            },
        )()
        self.installation_id = installation_id
        self.operation_id = operation_id
        self.calls = 0
        self.read_calls = 0

    def _read_journal(self) -> dict[str, object]:
        self.read_calls += 1
        return json.loads(self.definition.journal_path.read_text(encoding="utf-8"))

    def recover(self) -> _PreparedReceipt:
        self.calls += 1
        self.definition.journal_path.unlink()
        return _PreparedReceipt(self.installation_id, self.operation_id)


class _ControllerPort:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def command_id_for(self, operation_id: str, method: str) -> str | None:
        if operation_id == CURRENT_OPERATION_ID and method == "controller_recover":
            return "cc2_" + "b" * 32
        return None

    def candidate_recover(self, **arguments):
        self.calls.append(dict(arguments))
        return LifecycleControllerCommandProofV2(
            method="controller_recover",
            status="CONTROLLER_RECOVERED",
            command_id="cc2_" + "b" * 32,
            request_fingerprint="c" * 64,
            response_fingerprint="d" * 64,
            previous_control_epoch=7,
            new_control_epoch=8,
            payload={
                "status": "CONTROLLER_RECOVERED",
                "previousControlEpoch": 7,
                "newControlEpoch": 8,
                "commandReceipt": {
                    "commandId": "cc2_" + "b" * 32,
                    "requestFingerprint": "c" * 64,
                    "resultFingerprint": "e" * 64,
                    "controlEpoch": 8,
                },
            },
        )


class InstallerRecoveryV2Tests(unittest.TestCase):
    def test_exact_bytecode_drift_is_repaired_idempotently(self) -> None:
        activation = self.root / "bytecode-activation"
        package = activation / "marketplace" / "package"
        package.mkdir(parents=True, mode=0o700)
        activation.chmod(0o700)
        (activation / "marketplace").chmod(0o700)
        package.chmod(0o700)
        source = package / "module.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        source.chmod(0o600)
        expected = _tree_sha256(activation)
        cache = package / "__pycache__"
        cache.mkdir(mode=0o755)
        bytecode = cache / "module.cpython-313.pyc"
        bytecode.write_bytes(b"bytecode")
        bytecode.chmod(0o644)

        plan = inspect_activation_bytecode_repair_v2(
            activation_dir=activation,
            expected_tree_sha256=expected,
        )

        self.assertEqual("ACTIVATION_BYTECODE_REPAIR_REQUIRED", plan.reason_code)
        self.assertEqual((bytecode,), plan.bytecode_files)
        applied = apply_activation_bytecode_repair_v2(plan)
        self.assertEqual("recovered", applied.status)
        self.assertEqual(expected, _tree_sha256(activation))
        repeated = inspect_activation_bytecode_repair_v2(
            activation_dir=activation,
            expected_tree_sha256=expected,
        )
        self.assertEqual("unchanged", repeated.status)

    def test_bytecode_repair_rejects_any_foreign_drift(self) -> None:
        activation = self.root / "unsafe-bytecode-activation"
        package = activation / "marketplace" / "package"
        package.mkdir(parents=True, mode=0o700)
        activation.chmod(0o700)
        (activation / "marketplace").chmod(0o700)
        package.chmod(0o700)
        source = package / "module.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        source.chmod(0o600)
        expected = _tree_sha256(activation)
        cache = package / "__pycache__"
        cache.mkdir(mode=0o755)
        (cache / "foreign.txt").write_text("not bytecode", encoding="utf-8")

        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            inspect_activation_bytecode_repair_v2(
                activation_dir=activation,
                expected_tree_sha256=expected,
            )

        self.assertEqual(
            "ACTIVATION_BYTECODE_REPAIR_UNSAFE",
            captured.exception.code,
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="installer-recovery-v2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.receipts = self.root / "receipts" / INSTALLATION_ID
        self.receipts.mkdir(parents=True, mode=0o700)
        self.managed = self.root / "managed"
        self.activations = self.managed / "activations"
        self.activations.mkdir(parents=True, mode=0o700)
        self.marketplace_link = self.managed / "marketplace-current"
        self.current_activation = self._make_activation(
            CURRENT_ACTIVATION_ID,
            CURRENT_DATABASE_ID,
            "6" * 64,
            "b" * 64,
        )
        self.previous_activation = self._make_activation(
            PREVIOUS_ACTIVATION_ID,
            PREVIOUS_DATABASE_ID,
            "7" * 64,
            "d" * 64,
        )
        os.symlink(
            f"activations/{CURRENT_ACTIVATION_ID}/marketplace",
            self.marketplace_link,
        )
        self.manifest_path = self.root / "manifest.json"
        self.manifest = self._manifest_document(
            active=self.current_activation,
            previous=self.previous_activation,
            operation_id=CURRENT_OPERATION_ID,
        )
        _write_private_json(self.manifest_path, self.manifest)
        manifest_file = capture_file_projection_v2(
            self.manifest_path, schema_sha256=SCHEMA_SHA256
        ).value
        source_path = self.receipts / f"{CURRENT_OPERATION_ID}.preparation.json"
        source_receipt = {
            "schemaVersion": 2,
            "receiptKind": "activation-preparation",
            "installationId": INSTALLATION_ID,
            "operationId": CURRENT_OPERATION_ID,
            "transitionProofSnapshot": {
                "installationId": INSTALLATION_ID,
                "operationId": CURRENT_OPERATION_ID,
                "currentOperationId": PREVIOUS_OPERATION_ID,
                "activationId": PREVIOUS_ACTIVATION_ID,
            },
            "receiptFingerprint": "d" * 64,
        }
        _write_private_json(source_path, source_receipt)
        current_lineage = ActivationTransitionLineageV2(
            transition_kind="update",
            source_receipt=TransitionSourceReceiptV2(
                receipt_kind="activation-preparation",
                path=source_path,
                raw_sha256=hashlib.sha256(
                    canonical_json_bytes(source_receipt)
                ).hexdigest(),
                receipt_fingerprint="d" * 64,
            ),
            activation_proof_fingerprint="e" * 64,
            shutdown_command_ids=ControllerShutdownLineageV2(
                maintenance_begin="cc2_" + "1" * 32,
                maintenance_strengthen="cc2_" + "2" * 32,
                shutdown="cc2_" + "3" * 32,
            ),
            stopped_controller=StoppedControllerLineageV2(
                operation_id=CURRENT_OPERATION_ID,
                activation_id=PREVIOUS_ACTIVATION_ID,
                database_id=PREVIOUS_DATABASE_ID,
                controller_identity="8" * 64,
                control_epoch=4,
            ),
        )
        self.current_receipt = self._make_commit_receipt(
            CURRENT_OPERATION_ID,
            self.current_activation,
            manifest_file=manifest_file,
            manifest_document=self.manifest,
            transition_lineage=current_lineage,
        )
        previous_manifest = self._manifest_document(
            active=self.previous_activation,
            previous=None,
            operation_id=PREVIOUS_OPERATION_ID,
        )
        previous_raw = canonical_json_bytes(previous_manifest)
        self.previous_receipt = self._make_commit_receipt(
            PREVIOUS_OPERATION_ID,
            self.previous_activation,
            manifest_file={
                **manifest_file,
                "size": len(previous_raw),
                "sha256": hashlib.sha256(previous_raw).hexdigest(),
            },
            manifest_document=previous_manifest,
            transition_lineage=ActivationTransitionLineageV2(
                transition_kind="initial",
                source_receipt=None,
                activation_proof_fingerprint=None,
                shutdown_command_ids=None,
                stopped_controller=None,
            ),
        )
        _write_private_json(
            self.receipts / f"{CURRENT_OPERATION_ID}.commit.json",
            self.current_receipt,
        )
        _write_private_json(
            self.receipts / f"{PREVIOUS_OPERATION_ID}.commit.json",
            self.previous_receipt,
        )
        automaton = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )["fixtures"]["automaton"]
        self.registry = LifecyclePlanRegistryV2.from_document(automaton)
        _write_private_json(self.root / "effects.json", {})

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _publish_mutated_current_receipt(
        self,
        receipt: dict[str, object],
    ) -> None:
        unsigned = {
            key: copy.deepcopy(value)
            for key, value in receipt.items()
            if key != "receiptFingerprint"
        }
        receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2",
            unsigned,
        )
        _write_private_json(
            self.receipts / f"{CURRENT_OPERATION_ID}.commit.json",
            receipt,
        )

    @staticmethod
    def _refresh_lineage_fingerprint(lineage: dict[str, object]) -> None:
        projection = {
            key: copy.deepcopy(value)
            for key, value in lineage.items()
            if key != "lineageFingerprint"
        }
        lineage["lineageFingerprint"] = domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            projection,
        )

    def test_rollback_rejects_substituted_transition_source_path(self) -> None:
        receipt = copy.deepcopy(self.current_receipt)
        lineage = receipt["transitionLineage"]
        assert isinstance(lineage, dict)
        source = lineage["sourceReceipt"]
        assert isinstance(source, dict)
        source["path"] = str(self.receipts / "foreign.preparation.json")
        self._refresh_lineage_fingerprint(lineage)
        self._publish_mutated_current_receipt(receipt)

        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )

        self.assertEqual(
            "ROLLBACK_TRANSITION_LINEAGE_INVALID",
            captured.exception.code,
        )

    def test_rollback_rejects_substituted_transition_source_operation(self) -> None:
        source_path = self.receipts / f"{CURRENT_OPERATION_ID}.preparation.json"
        source = json.loads(source_path.read_text(encoding="utf-8"))
        source["operationId"] = "op2_" + "f" * 32
        _write_private_json(source_path, source)
        receipt = copy.deepcopy(self.current_receipt)
        lineage = receipt["transitionLineage"]
        assert isinstance(lineage, dict)
        source_binding = lineage["sourceReceipt"]
        assert isinstance(source_binding, dict)
        source_binding["rawSha256"] = hashlib.sha256(
            canonical_json_bytes(source)
        ).hexdigest()
        self._refresh_lineage_fingerprint(lineage)
        self._publish_mutated_current_receipt(receipt)

        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )

        self.assertEqual(
            "ROLLBACK_TRANSITION_SOURCE_INVALID",
            captured.exception.code,
        )

    def test_rollback_requires_both_exact_operation_receipts(self) -> None:
        for path, expected_code in (
            (
                self.receipts / f"{CURRENT_OPERATION_ID}.commit.json",
                "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
            ),
            (
                self.receipts / f"{PREVIOUS_OPERATION_ID}.commit.json",
                "ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
            ),
        ):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises(InstallerRecoveryV2Error) as captured:
                        read_rollback_v2(
                            manifest_path=self.manifest_path,
                            receipts_root=self.receipts,
                            activations_root=self.activations,
                            marketplace_link=self.marketplace_link,
                        )
                    self.assertEqual(expected_code, captured.exception.code)
                finally:
                    path.write_bytes(original)
                    path.chmod(0o600)

    def test_rollback_rejects_duplicate_receipt_for_exact_operation(self) -> None:
        duplicate = self.receipts / "duplicate.commit.json"
        _write_private_json(duplicate, copy.deepcopy(self.current_receipt))

        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )

        self.assertEqual(
            "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
            captured.exception.code,
        )

    def _make_activation(
        self,
        activation_id: str,
        database_id: str,
        activation_fingerprint: str,
        generation_fingerprint: str,
    ) -> dict[str, object]:
        directory = self.activations / activation_id
        marketplace = directory / "marketplace"
        marketplace.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
        marketplace.chmod(0o700)
        payload = {
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "identity": {
                "generationId": "gen2_" + generation_fingerprint,
                "database": {"databaseId": database_id},
            },
        }
        _write_private_json(directory / "activation.json", payload)
        plugin = marketplace / "plugin.txt"
        plugin.write_bytes(activation_id.encode())
        plugin.chmod(0o600)
        tree = capture_tree_projection_v2(directory, schema_sha256=SCHEMA_SHA256)
        activation_file = capture_file_projection_v2(
            directory / "activation.json", schema_sha256=SCHEMA_SHA256
        )
        value = {
            "directory": dict(tree.value),
            "activationFile": dict(activation_file.value),
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
            "generationId": payload["identity"]["generationId"],
            "release": "0.2.0",
            "databaseId": database_id,
            "databaseIdentityFingerprint": "1" * 64,
            "marketplaceTreeSha256": "2" * 64,
            "generationTreeSha256": "3" * 64,
        }
        return {
            "directory": directory,
            "document": payload,
            "projection": _projection(
                "activation-v2", value, "codex-smart/activation/v2"
            ),
        }

    def _pointer(self, activation: dict[str, object]) -> dict[str, object]:
        value = activation["projection"].value
        return {
            "activationId": value["activationId"],
            "activationFingerprint": value["activationFingerprint"],
            "symlinkTarget": (f"activations/{value['activationId']}/marketplace"),
            "generationId": value["generationId"],
            "databaseId": value["databaseId"],
        }

    def _manifest_document(
        self,
        *,
        active: dict[str, object],
        previous: dict[str, object] | None,
        operation_id: str,
    ) -> dict[str, object]:
        return {
            "schemaVersion": 2,
            "installationId": INSTALLATION_ID,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "marketplaceName": "codex-settings-adaptive",
            "stateHome": str(self.root / "state"),
            "sourceLocator": {"kind": "test"},
            "codexSnapshot": {"kind": "test"},
            "activeActivation": self._pointer(active),
            "previousActivation": (
                None if previous is None else self._pointer(previous)
            ),
            "interfaceEvidence": {},
            "routingPolicyFingerprint": "4" * 64,
            "bundledCatalogFingerprint": "5" * 64,
            "artifacts": [],
            "originalBackup": None,
            "lastCommittedOperation": operation_id,
            "databaseSchemaVersion": 2,
            "extensions": {},
        }

    def _make_commit_receipt(
        self,
        operation_id: str,
        activation: dict[str, object],
        *,
        manifest_file: dict[str, object],
        manifest_document: dict[str, object],
        transition_lineage: ActivationTransitionLineageV2,
    ) -> dict[str, object]:
        activation_projection = activation["projection"]
        activation_id = str(activation_projection.value["activationId"])
        database_id = str(activation_projection.value["databaseId"])
        manifest_projection = _projection(
            "manifest-v2",
            {
                "file": copy.deepcopy(manifest_file),
                "schemaVersion": 2,
                "installationId": INSTALLATION_ID,
                "release": "0.2.0",
                "pluginId": "codex-smart-subagents",
                "stateHome": str(self.root / "state"),
                "activeActivationId": activation_id,
                "previousActivationId": (
                    None
                    if manifest_document["previousActivation"] is None
                    else manifest_document["previousActivation"]["activationId"]
                ),
                "lastCommittedOperation": operation_id,
                "sourceLocatorFingerprint": hashlib.sha256(
                    canonical_json_bytes(manifest_document["sourceLocator"])
                ).hexdigest(),
                "artifactsFingerprint": hashlib.sha256(
                    canonical_json_bytes(manifest_document["artifacts"])
                ).hexdigest(),
                "semanticFingerprint": domain_fingerprint(
                    "codex-smart/manifest-semantic/v2",
                    {
                        key: copy.deepcopy(value)
                        for key, value in manifest_document.items()
                        if key != "extensions"
                    },
                ),
            },
            "codex-smart/journal-state/v2",
        )
        database = _projection(
            "database-binding-v2",
            {
                **self._database_file_binding(database_id),
                "databaseId": database_id,
                "activationIdentity": {
                    "activationId": activation_id,
                    "activationFingerprint": activation_projection.value[
                        "activationFingerprint"
                    ],
                },
            },
            "codex-smart/database-binding/v2",
        )
        absence = _projection(
            "absence-proof-v2",
            {"operationId": operation_id},
            "codex-smart/absence-proof-projection/v2",
        )
        activation_envelope = {
            "schemaId": activation_projection.schema_id,
            "schemaSha256": activation_projection.schema_sha256,
            "value": copy.deepcopy(dict(activation_projection.value)),
        }
        commit_activation = ProjectionV2(
            schema_id=activation_projection.schema_id,
            schema_sha256=activation_projection.schema_sha256,
            value=activation_envelope["value"],
            value_fingerprint=domain_fingerprint(
                "codex-smart/journal-state/v2",
                activation_envelope,
            ),
        )
        unsigned = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": INSTALLATION_ID,
            "operationId": operation_id,
            "frozenJournalFingerprint": "7" * 64,
            "manifest": manifest_projection.to_document(),
            "manifestDocument": copy.deepcopy(manifest_document),
            "transitionLineage": transition_lineage.to_document(),
            "activation": commit_activation.to_document(),
            "databaseBinding": database.to_document(),
            "journalAbsenceTarget": absence.to_document(),
            "controllerIdentity": "8" * 64,
            "completedStepIds": ["st2_" + "9" * 32],
            "completedAt": "2026-07-19T10:00:00Z",
        }
        return {
            **unsigned,
            "receiptFingerprint": domain_fingerprint(
                "codex-smart/activation-commit-receipt/v2", unsigned
            ),
        }

    def _database_file_binding(self, database_id: str) -> dict[str, object]:
        path = self.root / "state" / f"{database_id}.sqlite3"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.parent.chmod(0o700)
            path.write_bytes(database_id.encode())
            path.chmod(0o600)
        info = path.lstat()
        return {
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": "0600",
            "linkCount": info.st_nlink,
            "schemaVersion": 2,
            "userVersion": 2,
        }

    def _rollback_definition(self, evidence, execution_plan):
        journal_path = self.control / "operation.transaction.json"
        marker_path = self.root / "effects.json"
        state: dict[str, bool] = {}
        steps: list[StepDefinitionV2] = []
        for kind in execution_plan.composed_step_kinds[1:]:
            if kind in {
                "terminal_journal_freeze",
                "commit_receipt_publish",
                "gate_open",
            }:
                continue
            if kind == "activation_link_restore":
                before = _symlink_projection(self.marketplace_link)
                expected = _expected_symlink_projection(
                    self.marketplace_link,
                    f"activations/{PREVIOUS_ACTIVATION_ID}/marketplace",
                )
            else:
                before = _marker_projection(marker_path, state)
                after = dict(state)
                after[kind] = True
                expected = _marker_projection(marker_path, after)
                if kind != "recovery_forward_only":
                    state = after
            steps.append(
                StepDefinitionV2(
                    kind=kind,
                    command_id=None,
                    action={"actionKind": "test-file-transition", "kind": kind},
                    before=before,
                    expected_after=expected,
                )
            )
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action={"actionKind": "journal-transition", "kind": "gate_close"},
            before=_absence(journal_path),
            expected_after=_projection(
                "journal-state-v2",
                {"path": str(journal_path), "state": "DISCOVERED"},
                "codex-smart/journal-state/v2",
            ),
        )
        freeze = StepDefinitionV2(
            kind="terminal_journal_freeze",
            command_id=None,
            action={"actionKind": "journal-transition", "kind": "freeze"},
            before=_projection(
                "journal-state-v2",
                {"path": str(journal_path), "state": "COMMITTING"},
                "codex-smart/journal-state/v2",
            ),
            expected_after=_projection(
                "journal-state-v2",
                {"path": str(journal_path), "state": "TERMINAL_FROZEN"},
                "codex-smart/journal-state/v2",
            ),
        )
        absence = _absence(journal_path)
        manifest_document = copy.deepcopy(
            dict(evidence.previous_receipt["manifestDocument"])
        )
        manifest_document["activeActivation"] = copy.deepcopy(
            dict(evidence.previous_pointer)
        )
        manifest_document["previousActivation"] = copy.deepcopy(
            dict(evidence.current_pointer)
        )
        manifest_document["lastCommittedOperation"] = ROLLBACK_OPERATION_ID
        manifest_raw = canonical_json_bytes(manifest_document)
        manifest_file = copy.deepcopy(
            dict(evidence.current_manifest_projection.value["file"])
        )
        manifest_file["size"] = len(manifest_raw)
        manifest_file["sha256"] = hashlib.sha256(manifest_raw).hexdigest()
        active_pointer = manifest_document["activeActivation"]
        previous_pointer = manifest_document["previousActivation"]
        manifest_projection = _projection(
            "manifest-v2",
            {
                "file": manifest_file,
                "schemaVersion": 2,
                "installationId": INSTALLATION_ID,
                "release": manifest_document["release"],
                "pluginId": manifest_document["pluginId"],
                "stateHome": manifest_document["stateHome"],
                "activeActivationId": active_pointer["activationId"],
                "previousActivationId": previous_pointer["activationId"],
                "lastCommittedOperation": ROLLBACK_OPERATION_ID,
                "sourceLocatorFingerprint": hashlib.sha256(
                    canonical_json_bytes(manifest_document["sourceLocator"])
                ).hexdigest(),
                "artifactsFingerprint": hashlib.sha256(
                    canonical_json_bytes(manifest_document["artifacts"])
                ).hexdigest(),
                "semanticFingerprint": domain_fingerprint(
                    "codex-smart/manifest-semantic/v2",
                    {
                        key: copy.deepcopy(value)
                        for key, value in manifest_document.items()
                        if key != "extensions"
                    },
                ),
            },
            "codex-smart/journal-state/v2",
        )
        current_database = ProjectionV2.from_document(
            evidence.current_receipt["databaseBinding"]
        )
        source_path = (
            self.receipts / f"{ROLLBACK_OPERATION_ID}.rollback-preparation.json"
        )
        terminal = TerminalDefinitionV2(
            terminal_kind="COMMIT",
            receipt_kind="activation-commit",
            receipt_path=self.receipts / f"{ROLLBACK_OPERATION_ID}.commit.json",
            freeze=freeze,
            journal_absence_target=absence,
            receipt_payload=ActivationCommitPayloadIntentV2(
                manifest=manifest_projection,
                manifest_document=manifest_document,
                transition_lineage=ActivationTransitionLineageV2(
                    transition_kind="rollback",
                    source_receipt=TransitionSourceReceiptV2(
                        receipt_kind="rollback-manifest-preparation",
                        path=source_path,
                        raw_sha256="a" * 64,
                        receipt_fingerprint="b" * 64,
                    ),
                    activation_proof_fingerprint=evidence.evidence_fingerprint,
                    shutdown_command_ids=ControllerShutdownLineageV2(
                        maintenance_begin="cc2_" + "4" * 32,
                        maintenance_strengthen="cc2_" + "5" * 32,
                        shutdown="cc2_" + "6" * 32,
                    ),
                    stopped_controller=StoppedControllerLineageV2(
                        operation_id=ROLLBACK_OPERATION_ID,
                        activation_id=evidence.current_activation_id,
                        database_id=str(current_database.value["databaseId"]),
                        controller_identity=str(
                            evidence.current_receipt["controllerIdentity"]
                        ),
                        control_epoch=7,
                    ),
                ),
                activation=evidence.previous_activation_projection,
                database_binding=evidence.previous_database_binding,
                journal_absence_target=absence,
                controller_identity="f" * 64,
            ),
        )
        definition = OperationDefinitionV2(
            kind="rollback",
            installation_id=INSTALLATION_ID,
            operation_id=ROLLBACK_OPERATION_ID,
            operation="rollback",
            execution_plan=execution_plan,
            discovery_before=_bundle(activation=evidence.current_activation_projection),
            fenced_before=_bundle(activation=evidence.current_activation_projection),
            desired=_bundle(activation=evidence.previous_activation_projection),
            gate_close=gate,
            mutable_steps=tuple(steps),
            terminal=terminal,
        )
        return definition

    def test_rollback_preview_requires_exact_previous_receipt_and_has_no_effect(
        self,
    ) -> None:
        evidence = read_rollback_v2(
            manifest_path=self.manifest_path,
            receipts_root=self.receipts,
            activations_root=self.activations,
            marketplace_link=self.marketplace_link,
        )
        before = os.readlink(self.marketplace_link)

        plan = plan_rollback_v2(
            evidence=evidence,
            registry=self.registry,
            plan_id=PLAN_ID,
            build_definition=self._rollback_definition,
        )
        result = execute_rollback_v2(plan=plan, preview=True)

        self.assertEqual("planned", result.status)
        self.assertEqual(ROLLBACK_OPERATION_ID, result.operation_id)
        self.assertEqual(before, os.readlink(self.marketplace_link))

        self.assertFalse((self.control / "operation.transaction.json").exists())
        self.assertEqual({}, json.loads((self.root / "effects.json").read_text()))

        forged = copy.deepcopy(self.previous_receipt)
        forged["activation"]["value"]["databaseId"] = CURRENT_DATABASE_ID
        _write_private_json(
            self.receipts / f"{PREVIOUS_OPERATION_ID}.commit.json",
            forged,
        )
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )
        self.assertEqual("ROLLBACK_RECEIPT_INVALID", captured.exception.code)
        self.assertEqual(before, os.readlink(self.marketplace_link))

        semantically_forged = copy.deepcopy(self.previous_receipt)
        manifest_projection = semantically_forged["manifest"]
        manifest_projection["value"]["activeActivationId"] = CURRENT_ACTIVATION_ID
        manifest_projection["valueFingerprint"] = domain_fingerprint(
            "codex-smart/journal-state/v2",
            {
                "schemaId": manifest_projection["schemaId"],
                "schemaSha256": manifest_projection["schemaSha256"],
                "value": manifest_projection["value"],
            },
        )
        unsigned = {
            name: copy.deepcopy(value)
            for name, value in semantically_forged.items()
            if name != "receiptFingerprint"
        }
        semantically_forged["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", unsigned
        )
        _write_private_json(
            self.receipts / f"{PREVIOUS_OPERATION_ID}.commit.json",
            semantically_forged,
        )
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )
        self.assertEqual("ROLLBACK_RECEIPT_INVALID", captured.exception.code)
        self.assertEqual(before, os.readlink(self.marketplace_link))

    def test_commit_receipt_requires_journal_state_activation_projection(
        self,
    ) -> None:
        def rewrite_activation_domain(
            receipt: dict[str, object],
            domain: str,
        ) -> dict[str, object]:
            rewritten = copy.deepcopy(receipt)
            activation = rewritten["activation"]
            assert isinstance(activation, dict)
            activation["valueFingerprint"] = domain_fingerprint(
                domain,
                {
                    "schemaId": activation["schemaId"],
                    "schemaSha256": activation["schemaSha256"],
                    "value": activation["value"],
                },
            )
            unsigned = {
                name: copy.deepcopy(value)
                for name, value in rewritten.items()
                if name != "receiptFingerprint"
            }
            rewritten["receiptFingerprint"] = domain_fingerprint(
                "codex-smart/activation-commit-receipt/v2",
                unsigned,
            )
            return rewritten

        current = rewrite_activation_domain(
            self.current_receipt,
            "codex-smart/journal-state/v2",
        )
        previous = rewrite_activation_domain(
            self.previous_receipt,
            "codex-smart/journal-state/v2",
        )
        _write_private_json(
            self.receipts / f"{CURRENT_OPERATION_ID}.commit.json",
            current,
        )
        _write_private_json(
            self.receipts / f"{PREVIOUS_OPERATION_ID}.commit.json",
            previous,
        )

        try:
            evidence = read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )
        except InstallerRecoveryV2Error as error:
            self.fail(
                "activation-commit отклонил нормативный journal-state домен: "
                f"{error}"
            )

        self.assertEqual(CURRENT_ACTIVATION_ID, evidence.current_activation_id)
        self.assertEqual(PREVIOUS_ACTIVATION_ID, evidence.previous_activation_id)

        legacy_current = rewrite_activation_domain(
            current,
            "codex-smart/activation/v2",
        )
        _write_private_json(
            self.receipts / f"{CURRENT_OPERATION_ID}.commit.json",
            legacy_current,
        )
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            read_rollback_v2(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts,
                activations_root=self.activations,
                marketplace_link=self.marketplace_link,
            )
        self.assertEqual("ROLLBACK_RECEIPT_INVALID", captured.exception.code)

    def test_rollback_preview_can_select_steps_without_preparing_definition(
        self,
    ) -> None:
        evidence = read_rollback_v2(
            manifest_path=self.manifest_path,
            receipts_root=self.receipts,
            activations_root=self.activations,
            marketplace_link=self.marketplace_link,
        )
        before = _filesystem_snapshot(self.root)

        plan = plan_rollback_v2(
            evidence=evidence,
            registry=self.registry,
            plan_id=PLAN_ID,
            build_definition=None,
        )
        result = execute_rollback_v2(plan=plan, preview=True)

        self.assertIsNone(plan.definition)
        self.assertEqual(
            self.registry.select(
                machine_id="rollback",
                branch_id="rollback-matched-active",
                plan_id=PLAN_ID,
            ).composed_step_kinds,
            plan.step_kinds,
        )
        self.assertEqual("planned", result.status)
        self.assertIsNone(result.operation_id)
        self.assertEqual(before, _filesystem_snapshot(self.root))

    def test_transition_proof_entrypoint_binds_the_current_activation(self) -> None:
        proof = object.__new__(ActivationTransitionProofV2)
        object.__setattr__(
            proof,
            "layout",
            SimpleNamespace(
                manifest_path=self.manifest_path,
                receipts_root=self.receipts.parent,
                managed_root=self.managed,
                marketplace_link=self.marketplace_link,
            ),
        )
        object.__setattr__(proof, "installation_id", INSTALLATION_ID)
        object.__setattr__(proof, "current_operation_id", CURRENT_OPERATION_ID)
        object.__setattr__(proof, "activation_id", CURRENT_ACTIVATION_ID)
        object.__setattr__(
            proof,
            "commit_receipt_path",
            self.receipts / f"{CURRENT_OPERATION_ID}.commit.json",
        )
        object.__setattr__(proof, "commit_receipt_document", self.current_receipt)
        object.__setattr__(
            proof,
            "activation_projection",
            ProjectionV2.from_document(self.current_receipt["activation"]),
        )
        object.__setattr__(
            proof,
            "manifest_projection",
            ProjectionV2.from_document(self.current_receipt["manifest"]),
        )
        object.__setattr__(proof, "proof_fingerprint", "e" * 64)

        with mock.patch(
            "codex_smart_subagents.installer_recovery_v2."
            "reverify_activation_transition_proof_v2",
            return_value=proof,
        ) as reverify:
            evidence = read_rollback_from_transition_v2(proof=proof)
            plan_rollback_v2(
                evidence=evidence,
                registry=self.registry,
                plan_id=PLAN_ID,
                build_definition=self._rollback_definition,
            )

        self.assertEqual([mock.call(proof), mock.call(proof)], reverify.call_args_list)
        self.assertEqual("e" * 64, evidence.transition_proof_fingerprint)
        self.assertEqual(CURRENT_ACTIVATION_ID, evidence.current_activation_id)

    def test_rollback_plan_rejects_replaced_previous_database_inode(self) -> None:
        evidence = read_rollback_v2(
            manifest_path=self.manifest_path,
            receipts_root=self.receipts,
            activations_root=self.activations,
            marketplace_link=self.marketplace_link,
        )
        database_path = Path(str(evidence.previous_database_binding.value["path"]))
        database_path.unlink()
        database_path.write_bytes(b"replacement")
        database_path.chmod(0o600)

        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            plan_rollback_v2(
                evidence=evidence,
                registry=self.registry,
                plan_id=PLAN_ID,
                build_definition=self._rollback_definition,
            )

        self.assertEqual("ROLLBACK_DATABASE_CHANGED", captured.exception.code)

    def test_recover_continues_same_main_journal_after_real_link_crash(self) -> None:
        evidence = read_rollback_v2(
            manifest_path=self.manifest_path,
            receipts_root=self.receipts,
            activations_root=self.activations,
            marketplace_link=self.marketplace_link,
        )
        plan = plan_rollback_v2(
            evidence=evidence,
            registry=self.registry,
            plan_id=PLAN_ID,
            build_definition=self._rollback_definition,
        )
        journal_path = self.control / "operation.transaction.json"
        store = OperationJournalStoreV2(
            journal_path=journal_path,
            lock_path=self.control / "operation.lock",
            validate_document=lambda _document: None,
        )
        executor = OperationExecutorV2(
            store=store,
            now=_Clock(),
            id_factory=_Ids(),
        )
        effects = _FileEffects(self.root / "effects.json", self.marketplace_link)
        terminal = _TerminalFiles(self.root / "rollback-terminal-receipt.json")

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED
                and kind == "activation_link_restore"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            execute_rollback_v2(
                plan=plan,
                preview=False,
                executor=executor,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                installation_lock=None,
            )
        self.assertEqual("INSTALLATION_LOCK_REQUIRED", captured.exception.code)
        self.assertFalse(journal_path.exists())

        with self.assertRaises(InjectedCrashV2):
            execute_rollback_v2(
                plan=plan,
                preview=False,
                executor=executor,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                installation_lock=lambda: nullcontext(),
                failure_injector=crash,
            )
        self.assertEqual(
            f"activations/{PREVIOUS_ACTIVATION_ID}/marketplace",
            os.readlink(self.marketplace_link),
        )
        persisted = journal_path.read_bytes()

        controller_document = json.loads(persisted)
        recovery_plan_id = "pl2_" + "d" * 32
        controller_document["recoveryPlans"] = [
            {
                "planId": recovery_plan_id,
                "selectedRecoveryBranchId": "controller-missing-proven",
                "status": "ACTIVE",
                "candidateId": "cand2_" + "e" * 32,
                "overlayStepKinds": [
                    "controller_candidate_spawn",
                    "controller_recover",
                    "recovery_resume_operation",
                ],
            }
        ]
        candidate_action = {
            "operationId": ROLLBACK_OPERATION_ID,
            "activationId": PREVIOUS_ACTIVATION_ID,
            "databaseId": PREVIOUS_DATABASE_ID,
            "candidateId": "cand2_" + "e" * 32,
        }
        candidate_observed = {
            "value": {
                **candidate_action,
                "pid": os.getpid(),
                "processStartMarker": "test-start-marker",
                "processGroupId": os.getpgrp(),
            }
        }
        controller_action = {
            "method": "controller_recover",
            "operationId": ROLLBACK_OPERATION_ID,
            "activationId": PREVIOUS_ACTIVATION_ID,
            "databaseId": PREVIOUS_DATABASE_ID,
        }
        controller_document["steps"].extend(
            [
                {
                    "stepId": "st2_" + "d" * 32,
                    "ordinal": len(controller_document["steps"]),
                    "planId": recovery_plan_id,
                    "planOrdinal": 0,
                    "recordCarrier": "JOURNAL_MUTABLE",
                    "kind": "controller_candidate_spawn",
                    "state": "COMPLETED",
                    "commandId": None,
                    "action": candidate_action,
                    "actionFingerprint": domain_fingerprint(
                        "codex-smart/step-action/v2", {"action": candidate_action}
                    ),
                    "before": plan.definition.mutable_steps[0].before.to_document(),
                    "expectedAfter": plan.definition.mutable_steps[
                        0
                    ].expected_after.to_document(),
                    "observedAfter": candidate_observed,
                    "intentAt": "2026-07-19T13:00:00Z",
                    "completedAt": "2026-07-19T13:00:01Z",
                },
                {
                    "stepId": "st2_" + "e" * 32,
                    "ordinal": len(controller_document["steps"]) + 1,
                    "planId": recovery_plan_id,
                    "planOrdinal": 1,
                    "recordCarrier": "JOURNAL_MUTABLE",
                    "kind": "controller_recover",
                    "state": "PLANNED",
                    "commandId": "cc2_" + "b" * 32,
                    "action": controller_action,
                    "actionFingerprint": domain_fingerprint(
                        "codex-smart/step-action/v2", {"action": controller_action}
                    ),
                    "before": plan.definition.mutable_steps[0].before.to_document(),
                    "expectedAfter": plan.definition.mutable_steps[
                        0
                    ].expected_after.to_document(),
                    "observedAfter": None,
                    "intentAt": None,
                    "completedAt": None,
                },
            ]
        )
        controller_document.pop("journalFingerprint")
        controller_document = _journal_document(
            "codex-smart/operation-journal/v2", controller_document
        )
        _write_private_json(journal_path, controller_document)
        controller_inspection = inspect_recovery_v2(
            journal_root=self.control,
            preparation_journal_path=self.control
            / "activation-preparation.transaction.json",
            operation_journal_path=journal_path,
        )
        controller_intent = ControllerRecoveryIntentV2(
            operation_id=ROLLBACK_OPERATION_ID,
            activation_id=PREVIOUS_ACTIVATION_ID,
            database_id=PREVIOUS_DATABASE_ID,
            expected_command_id="cc2_" + "b" * 32,
            pid=os.getpid(),
            process_start_marker="test-start-marker",
            process_group_id=os.getpgrp(),
        )
        planned_controller = plan_recovery_v2(
            inspection=controller_inspection,
            main=MainJournalRecoveryV2(
                executor=executor,
                definition=plan.definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                controller_recovery=controller_intent,
                controller_port=_ControllerPort(),
                installation_lock=lambda: nullcontext(),
            ),
        )
        self.assertEqual(controller_intent, planned_controller.main.controller_recovery)
        journal_path.write_bytes(persisted)

        inspection = inspect_recovery_v2(
            journal_root=self.control,
            preparation_journal_path=self.control
            / "activation-preparation.transaction.json",
            operation_journal_path=journal_path,
        )
        recovery = plan_recovery_v2(
            inspection=inspection,
            main=MainJournalRecoveryV2(
                executor=executor,
                definition=plan.definition,
                callbacks=effects.callbacks(),
                terminal_callbacks=terminal.callbacks(),
                installation_lock=lambda: nullcontext(),
            ),
        )
        preview = execute_recovery_v2(plan=recovery, preview=True)
        self.assertEqual("planned", preview.status)
        self.assertEqual(persisted, journal_path.read_bytes())

        applied = execute_recovery_v2(plan=recovery, preview=False)
        self.assertEqual("recovered", applied.status)
        self.assertEqual(ROLLBACK_OPERATION_ID, applied.operation_id)
        self.assertFalse(journal_path.exists())
        self.assertEqual(1, terminal.publish_count)

        empty = plan_recovery_v2(
            inspection=inspect_recovery_v2(
                journal_root=self.control,
                preparation_journal_path=self.control
                / "activation-preparation.transaction.json",
                operation_journal_path=journal_path,
            )
        )
        repeated = execute_recovery_v2(plan=empty, preview=False)
        self.assertEqual("unchanged", repeated.status)
        self.assertEqual(1, terminal.publish_count)

    def test_recovery_fails_closed_for_unknown_or_two_journals(self) -> None:
        preparation = self.control / "activation-preparation.transaction.json"
        operation = self.control / "operation.transaction.json"
        _write_private_json(
            preparation,
            {
                "journalKind": "activation-preparation",
                "installationId": INSTALLATION_ID,
                "operationId": CURRENT_OPERATION_ID,
            },
        )
        _write_private_json(
            operation,
            {
                "kind": "rollback",
                "installationId": INSTALLATION_ID,
                "operationId": ROLLBACK_OPERATION_ID,
            },
        )
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            inspect_recovery_v2(
                journal_root=self.control,
                preparation_journal_path=preparation,
                operation_journal_path=operation,
            )
        self.assertEqual("MULTIPLE_LIFECYCLE_JOURNALS", captured.exception.code)

        operation.unlink()
        preparation.unlink()
        _write_private_json(self.control / "alien.transaction.json", {"kind": "x"})
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            inspect_recovery_v2(
                journal_root=self.control,
                preparation_journal_path=preparation,
                operation_journal_path=operation,
            )
        self.assertEqual("UNKNOWN_LIFECYCLE_JOURNAL", captured.exception.code)

        (self.control / "alien.transaction.json").unlink()
        _write_private_json(
            preparation,
            {
                "journalKind": "activation-preparation",
                "installationId": INSTALLATION_ID,
                "operationId": CURRENT_OPERATION_ID,
            },
        )
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            inspect_recovery_v2(
                journal_root=self.control,
                preparation_journal_path=preparation,
                operation_journal_path=operation,
            )
        self.assertEqual("RECOVERY_JOURNAL_INVALID", captured.exception.code)

    def test_preparation_recovery_uses_persisted_ids_and_controller_recover_is_distinct(
        self,
    ) -> None:
        preparation_path = self.control / "activation-preparation.transaction.json"
        _write_private_json(
            preparation_path,
            _journal_document(
                "codex-smart/activation-preparation-journal/v2",
                {
                    "journalKind": "activation-preparation",
                    "installationId": INSTALLATION_ID,
                    "operationId": CURRENT_OPERATION_ID,
                },
            ),
        )
        executor = _PreparationExecutor(preparation_path)
        inspection = inspect_recovery_v2(
            journal_root=self.control,
            preparation_journal_path=preparation_path,
            operation_journal_path=self.control / "operation.transaction.json",
        )
        plan = plan_recovery_v2(
            inspection=inspection,
            preparation=PreparationJournalRecoveryV2(executor=executor),
        )
        self.assertEqual(1, executor.read_calls)
        preview = execute_recovery_v2(plan=plan, preview=True)
        self.assertEqual("planned", preview.status)
        self.assertEqual(0, executor.calls)
        applied = execute_recovery_v2(plan=plan, preview=False)
        self.assertEqual("recovered", applied.status)
        self.assertEqual(CURRENT_OPERATION_ID, applied.operation_id)
        self.assertEqual(1, executor.calls)

        port = _ControllerPort()
        intent = ControllerRecoveryIntentV2(
            operation_id=CURRENT_OPERATION_ID,
            activation_id=CURRENT_ACTIVATION_ID,
            database_id=CURRENT_DATABASE_ID,
            expected_command_id="cc2_" + "b" * 32,
            pid=os.getpid(),
            process_start_marker="test-start-marker",
            process_group_id=os.getpgrp(),
        )
        proof = intent.execute(port)
        self.assertEqual("controller_recover", proof.method)
        self.assertEqual("CONTROLLER_RECOVERED", proof.status)
        self.assertEqual(CURRENT_OPERATION_ID, port.calls[0]["operation_id"])

        class _UnrestoredPort(_ControllerPort):
            command_id_for = None

        unrestored = _UnrestoredPort()
        with self.assertRaises(InstallerRecoveryV2Error) as captured:
            intent.execute(unrestored)
        self.assertEqual("CONTROLLER_COMMAND_ID_NOT_RESTORED", captured.exception.code)
        self.assertEqual([], unrestored.calls)

    def test_rollback_manifest_preparation_is_a_distinct_recoverable_journal(
        self,
    ) -> None:
        activation_path = self.control / "activation-preparation.transaction.json"
        rollback_path = (
            self.control
            / "codex-smart-subagents-v2.rollback-manifest-preparation.transaction.json"
        )
        operation_path = self.control / "operation.transaction.json"
        _write_private_json(
            rollback_path,
            _journal_document(
                "codex-smart/rollback-manifest-preparation-journal/v2",
                {
                    "journalKind": "rollback-manifest-preparation",
                    "installationId": INSTALLATION_ID,
                    "operationId": ROLLBACK_OPERATION_ID,
                },
            ),
        )
        executor = _PreparationExecutor(
            rollback_path,
            operation_id=ROLLBACK_OPERATION_ID,
        )

        inspection = inspect_recovery_v2(
            journal_root=self.control,
            preparation_journal_path=activation_path,
            rollback_preparation_journal_path=rollback_path,
            operation_journal_path=operation_path,
        )
        self.assertEqual("rollback_preparation", inspection.journal_kind)
        plan = plan_recovery_v2(
            inspection=inspection,
            preparation=PreparationJournalRecoveryV2(executor=executor),
        )
        preview = execute_recovery_v2(plan=plan, preview=True)
        self.assertEqual("planned", preview.status)
        self.assertEqual("rollback_preparation", preview.journal_kind)
        self.assertEqual(0, executor.calls)

        applied = execute_recovery_v2(plan=plan, preview=False)
        self.assertEqual("recovered", applied.status)
        self.assertEqual(ROLLBACK_OPERATION_ID, applied.operation_id)
        self.assertEqual("rollback_preparation", applied.journal_kind)
        self.assertEqual(1, executor.calls)


if __name__ == "__main__":
    unittest.main()
