from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.closed_json_schema_v2 import (  # noqa: E402
    build_closed_json_schema_validator_v2,
)
from codex_smart_subagents.installer_maintenance_v2 import (  # noqa: E402
    InstallerMaintenanceLayoutV2,
    InstallerMaintenanceV2Error,
    RegistrationCallbacksV2,
    RegistrationObservationV2,
    cleanup_inactive_activations_v2,
    inspect_maintenance_inventory_v2,
    uninstall_retain_data_v2,
)
from codex_smart_subagents import installer_maintenance_v2  # noqa: E402
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ActivationTransitionLineageV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)


INSTALLATION_ID = "ins2_" + "1" * 32
ACTIVE_ID = "act2_" + "a" * 64
PREVIOUS_ID = "act2_" + "b" * 64
STALE_ID = "act2_" + "c" * 64
SECOND_STALE_ID = "act2_" + "d" * 64
DATABASE_ID = "db2_" + "2" * 32
NOW = "2026-07-19T12:00:00Z"
SCHEMA_DIR = ROOT / "docs" / "contracts" / "schemas"


class _MonotonicNanoseconds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file_projection(path: Path) -> dict[str, object]:
    info = path.lstat()
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _sha256_file(path),
    }


def _tree_sha256(root: Path) -> str:
    entries: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            info = child.lstat()
            relative = child.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "mode": stat.S_IMODE(info.st_mode),
                        "target": os.readlink(child),
                    }
                )
            elif stat.S_ISDIR(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "directory",
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                pending.append(child)
            else:
                entries.append(
                    {
                        "path": relative,
                        "type": "regular",
                        "mode": stat.S_IMODE(info.st_mode),
                        "size": info.st_size,
                        "sha256": _sha256_file(child),
                    }
                )
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def _tree_projection(path: Path) -> dict[str, object]:
    info = path.lstat()
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "entryCount": sum(1 for item in path.rglob("*") if not item.is_symlink()),
        "treeSha256": _tree_sha256(path),
    }


def _projection(schema_id: str, value: dict[str, object]) -> dict[str, object]:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": "e" * 64,
        "value": value,
    }
    envelope["valueFingerprint"] = domain_fingerprint(
        "codex-smart/test-projection/v2", envelope
    )
    return envelope


def _snapshot(root: Path) -> tuple[tuple[str, str, bytes | str], ...]:
    values: list[tuple[str, str, bytes | str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item)):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            values.append((relative, "link", os.readlink(path)))
        elif stat.S_ISDIR(info.st_mode):
            values.append((relative, "directory", b""))
        elif stat.S_ISREG(info.st_mode):
            values.append((relative, "file", path.read_bytes()))
        else:
            values.append((relative, "other", b""))
    return tuple(values)


class _Registrations:
    def __init__(self, marketplace: Path) -> None:
        self.values = {
            ("marketplace", "codex-settings-adaptive"): marketplace,
            (
                "plugin",
                "codex-smart-subagents@codex-settings-adaptive",
            ): marketplace / "plugins" / "codex-smart-subagents",
        }
        self.removed: list[tuple[str, str, Path]] = []

    def observe(
        self, kind: str, name: str
    ) -> RegistrationObservationV2 | None:
        target = self.values.get((kind, name))
        if target is None:
            return None
        return RegistrationObservationV2(kind=kind, name=name, target=target)

    def remove(self, expected: RegistrationObservationV2) -> None:
        key = (expected.kind, expected.name)
        if self.values.get(key) != expected.target:
            raise AssertionError("удаление вызвано без точного наблюдения")
        self.removed.append((expected.kind, expected.name, expected.target))
        del self.values[key]

    @property
    def callbacks(self) -> RegistrationCallbacksV2:
        return RegistrationCallbacksV2(observe=self.observe, remove=self.remove)


class _CrashOnce:
    def __init__(self, point: str) -> None:
        self.point = point
        self.triggered = False

    def __call__(self, point: str) -> None:
        if point == self.point and not self.triggered:
            self.triggered = True
            raise RuntimeError(f"сбой: {point}")


class _InstallationFixture:
    def __init__(self, root: Path, *, stale_ids: tuple[str, ...] = (STALE_ID,)) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.codex_home = root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.managed_root = self.codex_home / "codex-smart-subagents-v2"
        self.activations_root = self.managed_root / "activations"
        self.activations_root.mkdir(parents=True, mode=0o700)
        self.manifest_root = self.codex_home / "install-manifests"
        self.manifest_root.mkdir(mode=0o700)
        self.receipts_root = self.manifest_root / "codex-smart-subagents-v2.receipts"
        self.receipts_root.mkdir(mode=0o700)
        self.state_home = root / "state"
        self.databases_root = self.state_home / "databases"
        database_parent = self.databases_root / DATABASE_ID
        database_parent.mkdir(parents=True, mode=0o700)
        self.database_path = database_parent / "smart-subagents.sqlite3"
        self.database_path.write_bytes(b"sqlite-state")
        self.database_path.chmod(0o600)
        self.backups_root = self.state_home / "backups"
        self.backups_root.mkdir(mode=0o700)
        (self.backups_root / "keep").write_text("backup", encoding="utf-8")
        self.quarantine_root = self.state_home / "quarantine"
        self.quarantine_root.mkdir(mode=0o700)
        (self.quarantine_root / "keep").write_text("quarantine", encoding="utf-8")
        self.recovery_entrypoint = self.state_home / "recover"
        self.recovery_entrypoint.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.recovery_entrypoint.chmod(0o500)
        self.bin_dir = root / "bin"
        self.bin_dir.mkdir(mode=0o700)
        self.activation_ids = (ACTIVE_ID, PREVIOUS_ID, *stale_ids)
        self.operation_ids: dict[str, str] = {}
        for ordinal, activation_id in enumerate(self.activation_ids, start=1):
            self._create_activation(activation_id, ordinal)
        self.marketplace = self.activations_root / ACTIVE_ID / "marketplace"
        self.marketplace_link = self.managed_root / "marketplace-current"
        self.marketplace_link.symlink_to(f"activations/{ACTIVE_ID}/marketplace")
        self.manifest_path = self.manifest_root / "codex-smart-subagents-v2.json"
        self.installer_receipt_path = (
            self.manifest_root / "codex-smart-subagents-v2.installer.json"
        )
        self._write_manifest()
        self._write_installer_receipt()
        self.lock_path = self.manifest_root / "codex-smart-subagents-v2.installer.lock"
        self.lock_path.write_bytes(b"")
        self.lock_path.chmod(0o600)
        self.cleanup_journal_path = (
            self.manifest_root / "codex-smart-subagents-v2.cleanup.transaction.json"
        )
        self.uninstall_journal_path = (
            self.manifest_root / "codex-smart-subagents-v2.uninstall.transaction.json"
        )
        self.tombstone_path = (
            self.manifest_root / "codex-smart-subagents-v2.tombstone.json"
        )
        self.layout = InstallerMaintenanceLayoutV2(
            codex_home=self.codex_home,
            managed_root=self.managed_root,
            activations_root=self.activations_root,
            manifest_path=self.manifest_path,
            installer_receipt_path=self.installer_receipt_path,
            marketplace_link=self.marketplace_link,
            receipts_root=self.receipts_root,
            cleanup_journal_path=self.cleanup_journal_path,
            uninstall_journal_path=self.uninstall_journal_path,
            tombstone_path=self.tombstone_path,
            lock_path=self.lock_path,
            state_home=self.state_home,
            databases_root=self.databases_root,
            backups_root=self.backups_root,
            quarantine_root=self.quarantine_root,
            recovery_entrypoint=self.recovery_entrypoint,
        )
        self.registrations = _Registrations(self.marketplace)

    def _create_activation(self, activation_id: str, ordinal: int) -> None:
        activation = self.activations_root / activation_id
        binary_root = activation / "marketplace" / "plugins" / "codex-smart-subagents" / "bin"
        binary_root.mkdir(parents=True, mode=0o700)
        for parent in (
            activation,
            activation / "marketplace",
            activation / "marketplace" / "plugins",
            activation / "marketplace" / "plugins" / "codex-smart-subagents",
        ):
            parent.chmod(0o700)
        for name in ("codex-smart", "codex-smart-subagents-admin"):
            binary = binary_root / name
            binary.write_bytes(f"#!/bin/sh\n# {activation_id}\n".encode())
            binary.chmod(0o500)
        activation_document = {
            "schemaVersion": 2,
            "installationId": INSTALLATION_ID,
            "activationId": activation_id,
        }
        activation_file = activation / "activation.json"
        activation_file.write_bytes(canonical_json_bytes(activation_document))
        activation_file.chmod(0o600)
        operation_id = "op2_" + f"{ordinal:032x}"
        self.operation_ids[activation_id] = operation_id
        database_value = {
            **_file_projection(self.database_path),
            "databaseId": DATABASE_ID,
            "databaseIdentity": {
                "databaseId": DATABASE_ID,
                "activationBindingNonce": "3" * 64,
                "activationId": ACTIVE_ID,
                "activationFingerprint": "a" * 64,
            },
            "databaseIdentityFingerprint": "4" * 64,
            "activationIdentity": {
                "activationId": ACTIVE_ID,
                "activationFingerprint": "a" * 64,
            },
            "databaseVersion": "0.2.0",
            "schemaVersion": 2,
            "userVersion": 2,
            "schemaFingerprint": "5" * 64,
            "schemaArtifactSha256": "6" * 64,
        }
        database_value.pop("size")
        database_value.pop("sha256")
        activation_value = {
            "directory": _tree_projection(activation),
            "activationFile": _file_projection(activation_file),
            "activationId": activation_id,
            "activationFingerprint": activation_id.removeprefix("act2_"),
        }
        receipt = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": INSTALLATION_ID,
            "operationId": operation_id,
            "frozenJournalFingerprint": "7" * 64,
            "manifest": _projection(
                "manifest-v2", {"installationId": INSTALLATION_ID}
            ),
            "manifestDocument": {
                "installationId": INSTALLATION_ID,
                "activeActivation": {"activationId": activation_id},
                "lastCommittedOperation": operation_id,
            },
            "transitionLineage": ActivationTransitionLineageV2(
                transition_kind="initial",
                source_receipt=None,
                activation_proof_fingerprint=None,
                shutdown_command_ids=None,
                stopped_controller=None,
            ).to_document(),
            "activation": _projection("activation-v2", activation_value),
            "databaseBinding": _projection("database-binding-v2", database_value),
            "journalAbsenceTarget": _projection(
                "absence-proof-v2", {"installationId": INSTALLATION_ID}
            ),
            "controllerIdentity": "8" * 64,
            "completedStepIds": ["st2_" + "9" * 32],
            "completedAt": NOW,
        }
        receipt["receiptFingerprint"] = domain_fingerprint(
            "codex-smart/activation-commit-receipt/v2", receipt
        )
        receipt_dir = self.receipts_root / INSTALLATION_ID
        receipt_dir.mkdir(exist_ok=True, mode=0o700)
        receipt_path = receipt_dir / f"{operation_id}.commit.json"
        receipt_path.write_bytes(canonical_json_bytes(receipt))
        receipt_path.chmod(0o600)

    def shift_persisted_devices(self, delta: int) -> None:
        receipt_dir = self.receipts_root / INSTALLATION_ID
        for receipt_path in receipt_dir.glob("*.commit.json"):
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            activation_projection = receipt["activation"]
            activation_value = activation_projection["value"]
            activation_value["directory"]["device"] += delta
            activation_value["activationFile"]["device"] += delta
            activation_projection["valueFingerprint"] = domain_fingerprint(
                "codex-smart/test-projection/v2",
                {
                    key: value
                    for key, value in activation_projection.items()
                    if key != "valueFingerprint"
                },
            )
            database_projection = receipt["databaseBinding"]
            database_projection["value"]["device"] += delta
            database_projection["valueFingerprint"] = domain_fingerprint(
                "codex-smart/test-projection/v2",
                {
                    key: value
                    for key, value in database_projection.items()
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
            receipt_path.write_bytes(canonical_json_bytes(receipt))

    def shift_persisted_directory_inode(
        self,
        activation_id: str,
        delta: int,
    ) -> None:
        operation_id = self.operation_ids[activation_id]
        receipt_path = (
            self.receipts_root
            / INSTALLATION_ID
            / f"{operation_id}.commit.json"
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        activation_projection = receipt["activation"]
        activation_projection["value"]["directory"]["inode"] += delta
        activation_projection["valueFingerprint"] = domain_fingerprint(
            "codex-smart/test-projection/v2",
            {
                key: value
                for key, value in activation_projection.items()
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
        receipt_path.write_bytes(canonical_json_bytes(receipt))

    def _write_manifest(self) -> None:
        manifest = {
            "schemaVersion": 2,
            "installationId": INSTALLATION_ID,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "marketplaceName": "codex-settings-adaptive",
            "stateHome": str(self.state_home),
            "activeActivation": {
                "activationId": ACTIVE_ID,
                "activationFingerprint": "a" * 64,
                "symlinkTarget": f"activations/{ACTIVE_ID}/marketplace",
                "generationId": "gen2_" + "a" * 64,
                "databaseId": DATABASE_ID,
            },
            "previousActivation": {
                "activationId": PREVIOUS_ID,
                "activationFingerprint": "b" * 64,
            },
            "lastCommittedOperation": self.operation_ids[ACTIVE_ID],
            "originalBackup": {
                "type": "absent",
                "path": str(self.codex_home / "original-codex-backup"),
            },
            "extensions": {},
        }
        self.manifest_path.write_bytes(canonical_json_bytes(manifest))
        self.manifest_path.chmod(0o600)

    def _write_installer_receipt(self) -> None:
        links = []
        installed_bin = (
            self.marketplace_link / "plugins" / "codex-smart-subagents" / "bin"
        )
        for name in ("codex-smart", "codex-smart-subagents-admin"):
            link = self.bin_dir / name
            target = installed_bin / name
            link.symlink_to(target)
            links.append({"path": str(link), "target": str(target)})
        receipt = {
            "schemaVersion": 2,
            "kind": "codex-smart-installer-receipt/v2",
            "sourceDigest": "f" * 64,
            "installationId": INSTALLATION_ID,
            "activationId": ACTIVE_ID,
            "codexHome": str(self.codex_home),
            "codexBinary": str(self.root / "codex"),
            "stateHome": str(self.state_home),
            "marketplacePath": str(self.marketplace_link),
            "registeredMarketplacePath": str(self.marketplace),
            "links": links,
            "marketplaceName": "codex-settings-adaptive",
            "pluginId": "codex-smart-subagents@codex-settings-adaptive",
            "extensions": {
                "sourceLineage": {
                    "schemaVersion": 1,
                    "generation": 2,
                    "implementationDigest": "e" * 64,
                }
            },
        }
        self.installer_receipt_path.write_bytes(canonical_json_bytes(receipt))
        self.installer_receipt_path.chmod(0o600)


class InstallerMaintenanceV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = _InstallationFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_hash_and_bounded_read_check_shared_deadline_between_blocks(self) -> None:
        path = self.root / "large-document"
        path.write_bytes(b"x" * (2 * 1024 * 1024 + 17))
        descriptor = os.open(path, os.O_RDONLY)
        try:
            with mock.patch.object(
                installer_maintenance_v2,
                "_checkpoint_operation_deadline_if_scoped_v2",
            ) as checkpoint:
                digest = installer_maintenance_v2._sha256_file(path)
                payload = installer_maintenance_v2._read_bounded(
                    descriptor,
                    path.stat().st_size,
                )
        finally:
            os.close(descriptor)

        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(path.read_bytes(), payload)
        self.assertGreaterEqual(checkpoint.call_count, 6)

    def test_cleanup_runs_lineage_guard_before_first_mutation(self) -> None:
        before = _snapshot(self.root)

        with self.assertRaisesRegex(RuntimeError, "stale source"):
            cleanup_inactive_activations_v2(
                self.fixture.layout,
                execute=True,
                now=lambda: NOW,
                pre_mutation_check=lambda: (_ for _ in ()).throw(
                    RuntimeError("stale source")
                ),
            )

        self.assertEqual(before, _snapshot(self.root))

    def test_uninstall_runs_lineage_guard_before_first_mutation(self) -> None:
        before = _snapshot(self.root)

        with self.assertRaisesRegex(RuntimeError, "stale source"):
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
                pre_mutation_check=lambda: (_ for _ in ()).throw(
                    RuntimeError("stale source")
                ),
            )

        self.assertEqual(before, _snapshot(self.root))

    def test_inventory_is_read_only_and_separates_protected_and_cleanup_trees(self) -> None:
        before = _snapshot(self.root)

        inventory = inspect_maintenance_inventory_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
        )

        self.assertEqual(before, _snapshot(self.root))
        self.assertEqual(INSTALLATION_ID, inventory.installation_id)
        self.assertEqual((ACTIVE_ID, PREVIOUS_ID), inventory.protected_activation_ids)
        self.assertEqual((STALE_ID,), inventory.cleanup_candidate_ids)
        self.assertEqual((), inventory.issues)
        self.assertIn(self.fixture.database_path, inventory.retained_paths)
        self.assertIn(self.fixture.backups_root, inventory.retained_paths)
        self.assertIn(self.fixture.quarantine_root, inventory.retained_paths)

    def test_inventory_accepts_persisted_device_drift_after_reboot(self) -> None:
        self.fixture.shift_persisted_devices(1)

        inventory = inspect_maintenance_inventory_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
        )

        self.assertEqual((), inventory.issues)
        self.assertEqual((STALE_ID,), inventory.cleanup_candidate_ids)

    def test_cleanup_accepts_persisted_device_drift_after_reboot(self) -> None:
        self.fixture.shift_persisted_devices(1)

        result = cleanup_inactive_activations_v2(
            self.fixture.layout,
            execute=True,
            now=lambda: NOW,
            id_factory=lambda _prefix: "cl2_" + "a" * 32,
        )

        self.assertEqual("cleaned", result.status)
        self.assertFalse((self.fixture.activations_root / STALE_ID).exists())

    def test_inventory_still_rejects_persisted_inode_drift(self) -> None:
        self.fixture.shift_persisted_directory_inode(STALE_ID, 1)

        inventory = inspect_maintenance_inventory_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
        )

        self.assertIn(
            "ACTIVATION_PROJECTION_CHANGED",
            {issue.code for issue in inventory.issues},
        )

    def test_cleanup_preview_has_no_effect(self) -> None:
        before = _snapshot(self.root)

        result = cleanup_inactive_activations_v2(
            self.fixture.layout,
            execute=False,
            now=lambda: NOW,
            id_factory=lambda _prefix: "cl2_" + "a" * 32,
        )

        self.assertEqual("planned", result.status)
        self.assertEqual((STALE_ID,), result.activation_ids)
        self.assertEqual(before, _snapshot(self.root))

    def test_cleanup_removes_only_owned_inactive_tree_and_repeats_unchanged(self) -> None:
        result = cleanup_inactive_activations_v2(
            self.fixture.layout,
            execute=True,
            now=lambda: NOW,
            id_factory=lambda _prefix: "cl2_" + "a" * 32,
        )

        self.assertEqual("cleaned", result.status)
        self.assertFalse((self.fixture.activations_root / STALE_ID).exists())
        self.assertTrue((self.fixture.activations_root / ACTIVE_ID).is_dir())
        self.assertTrue((self.fixture.activations_root / PREVIOUS_ID).is_dir())
        self.assertIsNotNone(result.receipt_path)
        assert result.receipt_path is not None
        receipt_bytes = result.receipt_path.read_bytes()
        self.assertFalse(self.fixture.cleanup_journal_path.exists())

        repeated = cleanup_inactive_activations_v2(
            self.fixture.layout,
            execute=True,
            now=lambda: "2026-07-19T12:01:00Z",
            id_factory=lambda _prefix: "cl2_" + "b" * 32,
        )

        self.assertEqual("unchanged", repeated.status)
        self.assertEqual(receipt_bytes, result.receipt_path.read_bytes())

    def test_cleanup_refuses_foreign_entry_before_deleting_owned_candidate(self) -> None:
        foreign = self.fixture.activations_root / ("act2_" + "f" * 64)
        foreign.symlink_to(self.fixture.state_home)
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            cleanup_inactive_activations_v2(
                self.fixture.layout,
                execute=True,
                now=lambda: NOW,
            )

        self.assertEqual("ACTIVATION_OWNERSHIP_AMBIGUOUS", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))

    def test_cleanup_refuses_tree_changed_after_commit_receipt(self) -> None:
        changed = self.fixture.activations_root / STALE_ID / "changed"
        changed.write_text("foreign", encoding="utf-8")
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            cleanup_inactive_activations_v2(
                self.fixture.layout,
                execute=True,
                now=lambda: NOW,
            )

        self.assertEqual("ACTIVATION_PROJECTION_CHANGED", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))

    def test_cleanup_resumes_after_delete_before_journal_completion(self) -> None:
        self.fixture = _InstallationFixture(
            self.root / "second", stale_ids=(STALE_ID, SECOND_STALE_ID)
        )
        crash = _CrashOnce("cleanup_after_delete")

        with self.assertRaisesRegex(RuntimeError, "cleanup_after_delete"):
            cleanup_inactive_activations_v2(
                self.fixture.layout,
                execute=True,
                now=lambda: NOW,
                id_factory=lambda _prefix: "cl2_" + "a" * 32,
                failure_injector=crash,
            )

        self.assertTrue(self.fixture.cleanup_journal_path.is_file())
        result = cleanup_inactive_activations_v2(
            self.fixture.layout,
            execute=True,
            now=lambda: NOW,
            id_factory=lambda _prefix: "cl2_" + "b" * 32,
        )
        self.assertEqual("cleaned", result.status)
        self.assertFalse((self.fixture.activations_root / STALE_ID).exists())
        self.assertFalse((self.fixture.activations_root / SECOND_STALE_ID).exists())
        self.assertFalse(self.fixture.cleanup_journal_path.exists())

    def test_cleanup_deadline_after_delete_preserves_journal_for_recovery(
        self,
    ) -> None:
        monotonic = _MonotonicNanoseconds()
        deadline = OperationDeadlineV2.start(
            operation="cleanup",
            timeout_seconds=1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=monotonic,
        )

        def expire_after_delete(point: str) -> None:
            if point == "cleanup_after_delete":
                monotonic.value = 1_000_000_000

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2):
                cleanup_inactive_activations_v2(
                    self.fixture.layout,
                    execute=True,
                    now=lambda: NOW,
                    id_factory=lambda _prefix: "cl2_" + "a" * 32,
                    failure_injector=expire_after_delete,
                )

        journal = json.loads(
            self.fixture.cleanup_journal_path.read_text(encoding="utf-8")
        )
        self.assertEqual("MUTATING", journal["phase"])
        self.assertEqual([], journal["completedActivationIds"])
        self.assertFalse((self.fixture.activations_root / STALE_ID).exists())

    def test_cleanup_recovers_after_receipt_without_rewriting_it(self) -> None:
        crash = _CrashOnce("cleanup_after_receipt")
        with self.assertRaisesRegex(RuntimeError, "cleanup_after_receipt"):
            cleanup_inactive_activations_v2(
                self.fixture.layout,
                execute=True,
                now=lambda: NOW,
                id_factory=lambda _prefix: "cl2_" + "a" * 32,
                failure_injector=crash,
            )

        journal = json.loads(
            self.fixture.cleanup_journal_path.read_text(encoding="utf-8")
        )
        receipt_path = Path(journal["receiptPath"])
        receipt_bytes = receipt_path.read_bytes()

        result = cleanup_inactive_activations_v2(
            self.fixture.layout,
            execute=True,
            now=lambda: "2026-07-19T12:05:00Z",
        )

        self.assertEqual("cleaned", result.status)
        self.assertEqual(receipt_bytes, receipt_path.read_bytes())
        self.assertFalse(self.fixture.cleanup_journal_path.exists())

    def test_uninstall_requires_retain_data_before_any_effect(self) -> None:
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=False,
                now=lambda: NOW,
            )

        self.assertEqual("RETAIN_DATA_REQUIRED", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))
        self.assertEqual([], self.fixture.registrations.removed)

    def test_uninstall_preview_is_read_only(self) -> None:
        before = _snapshot(self.root)

        result = uninstall_retain_data_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
            execute=False,
            retain_data=True,
            now=lambda: NOW,
        )

        self.assertEqual("planned", result.status)
        self.assertIsNone(result.operation_id)
        self.assertEqual(self.fixture.activation_ids, result.activation_ids)
        self.assertIn(self.fixture.database_path, result.retained_paths)
        self.assertIn(self.fixture.recovery_entrypoint, result.retained_paths)
        self.assertEqual(before, _snapshot(self.root))
        self.assertEqual([], self.fixture.registrations.removed)

    def test_uninstall_apply_retains_data_and_repeats_unchanged(self) -> None:
        retained_before = {
            path: _snapshot(path)
            for path in (
                self.fixture.databases_root,
                self.fixture.backups_root,
                self.fixture.quarantine_root,
            )
        }
        recovery_before = self.fixture.recovery_entrypoint.read_bytes()

        result = uninstall_retain_data_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
            execute=True,
            retain_data=True,
            now=lambda: NOW,
            id_factory=lambda _prefix: "op2_" + "a" * 32,
        )

        self.assertEqual("uninstalled", result.status)
        self.assertEqual("op2_" + "a" * 32, result.operation_id)
        self.assertEqual(
            len(result.retained_paths), len(set(result.retained_paths))
        )
        self.assertEqual({}, self.fixture.registrations.values)
        self.assertEqual(2, len(self.fixture.registrations.removed))
        for activation_id in self.fixture.activation_ids:
            self.assertFalse(
                (self.fixture.activations_root / activation_id).exists()
            )
        for path in (
            self.fixture.marketplace_link,
            self.fixture.manifest_path,
            self.fixture.installer_receipt_path,
            self.fixture.bin_dir / "codex-smart",
            self.fixture.bin_dir / "codex-smart-subagents-admin",
        ):
            self.assertFalse(os.path.lexists(path), path)
        for path, expected in retained_before.items():
            self.assertEqual(expected, _snapshot(path))
        self.assertEqual(
            recovery_before, self.fixture.recovery_entrypoint.read_bytes()
        )
        self.assertIsNotNone(result.receipt_path)
        assert result.receipt_path is not None
        receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
        build_closed_json_schema_validator_v2(
            SCHEMA_DIR,
            "installation-uninstall-receipt-v2.schema.json",
        )(receipt)
        absence_paths = {
            item["path"] for item in receipt["absenceProof"]["value"]["entries"]
        }
        self.assertTrue(
            {
                str(self.fixture.bin_dir / "codex-smart"),
                str(self.fixture.bin_dir / "codex-smart-subagents-admin"),
            }.issubset(absence_paths)
        )
        self.assertEqual(
            [str(self.fixture.marketplace_link)],
            [
                item["value"]["path"]
                for item in receipt["removedState"]["symlinks"]
            ],
        )
        self.assertFalse(
            Path(
                receipt["removedState"]["symlinks"][0]["value"]["target"]
            ).is_absolute()
        )
        build_closed_json_schema_validator_v2(
            SCHEMA_DIR,
            "installation-tombstone-v2.schema.json",
        )(
            json.loads(
                self.fixture.tombstone_path.read_text(encoding="utf-8")
            )
        )
        receipt_bytes = result.receipt_path.read_bytes()
        tombstone_bytes = self.fixture.tombstone_path.read_bytes()
        self.assertFalse(self.fixture.uninstall_journal_path.exists())
        self.assertTrue(self.fixture.tombstone_path.is_file())

        repeated = uninstall_retain_data_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
            execute=True,
            retain_data=True,
            now=lambda: "2026-07-19T12:05:00Z",
            id_factory=lambda _prefix: "op2_" + "b" * 32,
        )

        self.assertEqual("unchanged", repeated.status)
        self.assertEqual(result.operation_id, repeated.operation_id)
        self.assertEqual(receipt_bytes, result.receipt_path.read_bytes())
        self.assertEqual(tombstone_bytes, self.fixture.tombstone_path.read_bytes())

    def test_uninstall_resumes_after_first_registration_effect(self) -> None:
        crash = _CrashOnce("uninstall_after_registration_remove")
        with self.assertRaisesRegex(
            RuntimeError, "uninstall_after_registration_remove"
        ):
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
                id_factory=lambda _prefix: "op2_" + "a" * 32,
                failure_injector=crash,
            )

        self.assertTrue(self.fixture.uninstall_journal_path.is_file())
        self.assertEqual(1, len(self.fixture.registrations.removed))
        result = uninstall_retain_data_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
            execute=True,
            retain_data=True,
            now=lambda: "2026-07-19T12:01:00Z",
        )

        self.assertEqual("uninstalled", result.status)
        self.assertEqual("op2_" + "a" * 32, result.operation_id)
        self.assertFalse(self.fixture.uninstall_journal_path.exists())
        self.assertTrue(self.fixture.database_path.is_file())
        self.assertTrue(self.fixture.recovery_entrypoint.is_file())

    def test_uninstall_recovers_terminal_publications_without_rewriting(self) -> None:
        crash = _CrashOnce("uninstall_after_receipt")
        with self.assertRaisesRegex(RuntimeError, "uninstall_after_receipt"):
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
                id_factory=lambda _prefix: "op2_" + "a" * 32,
                failure_injector=crash,
            )

        journal = json.loads(
            self.fixture.uninstall_journal_path.read_text(encoding="utf-8")
        )
        receipt_path = Path(journal["receiptPath"])
        receipt_bytes = receipt_path.read_bytes()
        self.assertFalse(self.fixture.tombstone_path.exists())

        crash = _CrashOnce("uninstall_after_tombstone")
        with self.assertRaisesRegex(RuntimeError, "uninstall_after_tombstone"):
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: "2026-07-19T12:01:00Z",
                failure_injector=crash,
            )

        tombstone_bytes = self.fixture.tombstone_path.read_bytes()
        self.assertEqual(receipt_bytes, receipt_path.read_bytes())
        result = uninstall_retain_data_v2(
            self.fixture.layout,
            registrations=self.fixture.registrations.callbacks,
            execute=True,
            retain_data=True,
            now=lambda: "2026-07-19T12:02:00Z",
        )

        self.assertEqual("uninstalled", result.status)
        self.assertEqual(receipt_bytes, receipt_path.read_bytes())
        self.assertEqual(tombstone_bytes, self.fixture.tombstone_path.read_bytes())
        self.assertFalse(self.fixture.uninstall_journal_path.exists())

    def test_uninstall_refuses_foreign_registration_before_first_effect(self) -> None:
        self.fixture.registrations.values[
            ("marketplace", "codex-settings-adaptive")
        ] = self.fixture.root / "foreign-marketplace"
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
            )

        self.assertEqual("REGISTRATION_OWNERSHIP_AMBIGUOUS", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))
        self.assertEqual([], self.fixture.registrations.removed)

    def test_uninstall_refuses_a_competing_lifecycle_journal_before_effect(self) -> None:
        competing = self.fixture.manifest_root / "main.transaction.json"
        competing.write_bytes(canonical_json_bytes({"kind": "other"}))
        competing.chmod(0o600)
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
            )

        self.assertEqual("OPERATION_IN_PROGRESS", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))
        self.assertEqual([], self.fixture.registrations.removed)

    def test_uninstall_refuses_replaced_launcher_before_first_effect(self) -> None:
        launcher = self.fixture.bin_dir / "codex-smart"
        launcher.unlink()
        launcher.symlink_to(self.fixture.recovery_entrypoint)
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
            )

        self.assertEqual("LAUNCHER_OWNERSHIP_AMBIGUOUS", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))
        self.assertEqual([], self.fixture.registrations.removed)

    def test_existing_foreign_tombstone_blocks_before_effect(self) -> None:
        self.fixture.tombstone_path.write_text("{}", encoding="utf-8")
        self.fixture.tombstone_path.chmod(0o600)
        before = _snapshot(self.root)

        with self.assertRaises(InstallerMaintenanceV2Error) as caught:
            uninstall_retain_data_v2(
                self.fixture.layout,
                registrations=self.fixture.registrations.callbacks,
                execute=True,
                retain_data=True,
                now=lambda: NOW,
            )

        self.assertEqual("TOMBSTONE_CONFLICT", caught.exception.code)
        self.assertEqual(before, _snapshot(self.root))

    def test_layout_rejects_retained_data_inside_activation_root(self) -> None:
        with self.assertRaises(ValueError):
            replace(
                self.fixture.layout,
                state_home=self.fixture.activations_root / ACTIVE_ID / "state",
            )


if __name__ == "__main__":
    unittest.main()
