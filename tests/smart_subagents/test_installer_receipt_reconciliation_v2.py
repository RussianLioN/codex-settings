from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.installer_receipt_reconciliation_v2 import (  # noqa: E402
    InstallerReceiptReconciliationV2Error,
    reconcile_installer_receipt_v2,
)


class InstallerReceiptReconciliationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="cs-installer-receipt-v2-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.installation_id = "ins2_" + "1" * 32
        self.operation_id = "op2_" + "2" * 32
        self.previous_operation_id = "op2_" + "7" * 32
        self.old_activation_id = "act2_" + "3" * 64
        self.new_activation_id = "act2_" + "4" * 64
        self.old_digest = "5" * 64
        self.new_digest = "6" * 64
        self.manifest_path = self.root / "manifest.json"
        self.receipt_path = self.root / "installer.json"
        self.commit_path = self.root / "commit.json"
        self.journal_path = self.root / "operation.json"
        self.manifest = {
            "schemaVersion": 2,
            "installationId": self.installation_id,
            "activeActivation": {"activationId": self.new_activation_id},
            "previousActivation": {"activationId": self.old_activation_id},
            "lastCommittedOperation": self.operation_id,
            "sourceLocator": {
                "lexicalPath": str(self.root / "new-codex"),
            },
            "extensions": {"installerSourceDigest": self.new_digest},
        }
        self._write(self.manifest_path, self.manifest)
        self.old_receipt = self._installer_receipt(
            activation_id=self.old_activation_id,
            source_digest=self.old_digest,
            registered_marketplace=self.root / "old-marketplace",
            codex_binary=self.root / "old-codex",
        )
        self.expected_receipt = self._installer_receipt(
            activation_id=self.new_activation_id,
            source_digest=self.new_digest,
            registered_marketplace=self.root / "new-marketplace",
            codex_binary=self.root / "new-codex",
        )
        self._write(self.receipt_path, self.old_receipt)
        self.commit_receipt = self._commit_receipt()
        self._write(self.commit_path, self.commit_receipt)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_reconciles_only_old_receipt_bound_to_previous_activation(self) -> None:
        external_checks: list[str] = []

        result = reconcile_installer_receipt_v2(
            receipt_path=self.receipt_path,
            manifest_path=self.manifest_path,
            commit_receipt_path=self.commit_path,
            operation_journal_path=self.journal_path,
            expected_receipt=self.expected_receipt,
            verify_external_state=lambda: external_checks.append("verified"),
        )

        self.assertEqual("RECONCILED", result.status)
        self.assertEqual(["verified"], external_checks)
        self.assertEqual(self.expected_receipt, self._read(self.receipt_path))
        self.assertEqual(0o600, stat.S_IMODE(self.receipt_path.stat().st_mode))

    def test_repeat_after_replace_is_unchanged_and_resynchronizes_parent(self) -> None:
        self._write(self.receipt_path, self.expected_receipt)
        with mock.patch(
            "codex_smart_subagents.installer_receipt_reconciliation_v2._fsync_directory"
        ) as sync:
            result = reconcile_installer_receipt_v2(
                receipt_path=self.receipt_path,
                manifest_path=self.manifest_path,
                commit_receipt_path=self.commit_path,
                operation_journal_path=self.journal_path,
                expected_receipt=self.expected_receipt,
                verify_external_state=lambda: None,
            )

        self.assertEqual("ALREADY_RECONCILED", result.status)
        self.assertEqual([mock.call(self.root), mock.call(self.root)], sync.call_args_list)

    def test_retry_completes_after_replace_succeeded_but_parent_sync_failed(self) -> None:
        def fail_after_replace(_path: Path) -> None:
            raise OSError("simulated parent sync failure")

        with mock.patch(
            "codex_smart_subagents.installer_receipt_reconciliation_v2._fsync_directory_fd",
            side_effect=fail_after_replace,
        ):
            with self.assertRaises(OSError):
                reconcile_installer_receipt_v2(
                    receipt_path=self.receipt_path,
                    manifest_path=self.manifest_path,
                    commit_receipt_path=self.commit_path,
                    operation_journal_path=self.journal_path,
                    expected_receipt=self.expected_receipt,
                    verify_external_state=lambda: None,
                )

        self.assertEqual(self.expected_receipt, self._read(self.receipt_path))
        result = reconcile_installer_receipt_v2(
            receipt_path=self.receipt_path,
            manifest_path=self.manifest_path,
            commit_receipt_path=self.commit_path,
            operation_journal_path=self.journal_path,
            expected_receipt=self.expected_receipt,
            verify_external_state=lambda: None,
        )
        self.assertEqual("ALREADY_RECONCILED", result.status)

    def test_rejects_unrelated_current_receipt_without_replacing_it(self) -> None:
        unrelated = dict(self.old_receipt)
        unrelated["activationId"] = "act2_" + "7" * 64
        self._write(self.receipt_path, unrelated)
        before = self.receipt_path.read_bytes()

        with self.assertRaises(InstallerReceiptReconciliationV2Error) as caught:
            reconcile_installer_receipt_v2(
                receipt_path=self.receipt_path,
                manifest_path=self.manifest_path,
                commit_receipt_path=self.commit_path,
                operation_journal_path=self.journal_path,
                expected_receipt=self.expected_receipt,
                verify_external_state=lambda: None,
            )

        self.assertEqual("INSTALLER_RECEIPT_CURRENT_MISMATCH", caught.exception.code)
        self.assertEqual(before, self.receipt_path.read_bytes())

    def test_rejects_expected_codex_path_not_bound_to_committed_manifest(self) -> None:
        unrelated = dict(self.expected_receipt)
        unrelated["codexBinary"] = str(self.root / "unrelated-codex")
        before = self.receipt_path.read_bytes()

        with self.assertRaises(InstallerReceiptReconciliationV2Error) as caught:
            reconcile_installer_receipt_v2(
                receipt_path=self.receipt_path,
                manifest_path=self.manifest_path,
                commit_receipt_path=self.commit_path,
                operation_journal_path=self.journal_path,
                expected_receipt=unrelated,
                verify_external_state=lambda: None,
            )

        self.assertEqual("COMMITTED_MANIFEST_INVALID", caught.exception.code)
        self.assertEqual(before, self.receipt_path.read_bytes())

    def test_rejects_present_operation_journal_and_invalid_commit_receipt(self) -> None:
        self._write(self.journal_path, {"unfinished": True})
        with self.assertRaises(InstallerReceiptReconciliationV2Error) as caught:
            reconcile_installer_receipt_v2(
                receipt_path=self.receipt_path,
                manifest_path=self.manifest_path,
                commit_receipt_path=self.commit_path,
                operation_journal_path=self.journal_path,
                expected_receipt=self.expected_receipt,
                verify_external_state=lambda: None,
            )
        self.assertEqual("OPERATION_NOT_COMMITTED", caught.exception.code)

        self.journal_path.unlink()
        damaged = dict(self.commit_receipt)
        damaged["receiptFingerprint"] = "0" * 64
        self._write(self.commit_path, damaged)
        with self.assertRaises(InstallerReceiptReconciliationV2Error) as caught:
            reconcile_installer_receipt_v2(
                receipt_path=self.receipt_path,
                manifest_path=self.manifest_path,
                commit_receipt_path=self.commit_path,
                operation_journal_path=self.journal_path,
                expected_receipt=self.expected_receipt,
                verify_external_state=lambda: None,
            )
        self.assertEqual("COMMIT_RECEIPT_INVALID", caught.exception.code)

    def test_external_state_failure_leaves_old_receipt_unchanged(self) -> None:
        before = self.receipt_path.read_bytes()

        with self.assertRaisesRegex(RuntimeError, "registration changed"):
            reconcile_installer_receipt_v2(
                receipt_path=self.receipt_path,
                manifest_path=self.manifest_path,
                commit_receipt_path=self.commit_path,
                operation_journal_path=self.journal_path,
                expected_receipt=self.expected_receipt,
                verify_external_state=lambda: (_ for _ in ()).throw(
                    RuntimeError("registration changed")
                ),
            )

        self.assertEqual(before, self.receipt_path.read_bytes())

    def _installer_receipt(
        self,
        *,
        activation_id: str,
        source_digest: str,
        registered_marketplace: Path,
        codex_binary: Path,
    ) -> dict[str, object]:
        return {
            "schemaVersion": 2,
            "kind": "codex-smart-installer-receipt/v2",
            "sourceDigest": source_digest,
            "installationId": self.installation_id,
            "activationId": activation_id,
            "codexHome": str(self.root / "codex-home"),
            "codexBinary": str(codex_binary),
            "stateHome": str(self.root / "state"),
            "marketplacePath": str(self.root / "marketplace-current"),
            "registeredMarketplacePath": str(registered_marketplace),
            "links": [
                {
                    "path": str(self.root / "bin" / "codex-smart"),
                    "target": str(
                        self.root
                        / "marketplace-current"
                        / "plugins"
                        / "codex-smart-subagents"
                        / "bin"
                        / "codex-smart"
                    ),
                },
                {
                    "path": str(
                        self.root / "bin" / "codex-smart-subagents-admin"
                    ),
                    "target": str(
                        self.root
                        / "marketplace-current"
                        / "plugins"
                        / "codex-smart-subagents"
                        / "bin"
                        / "codex-smart-subagents-admin"
                    ),
                },
            ],
            "marketplaceName": "codex-settings-adaptive",
            "pluginId": (
                "codex-smart-subagents@codex-settings-adaptive"
            ),
            "extensions": {},
        }

    def _commit_receipt(self) -> dict[str, object]:
        info = self.manifest_path.stat()
        manifest_value = {
            "file": {
                "path": str(self.manifest_path),
                "device": info.st_dev,
                "inode": info.st_ino,
                "ownerUid": info.st_uid,
                "ownerGid": info.st_gid,
                "mode": "0600",
                "linkCount": info.st_nlink,
                "size": info.st_size,
                "sha256": hashlib.sha256(
                    self.manifest_path.read_bytes()
                ).hexdigest(),
            },
            "schemaVersion": 2,
            "installationId": self.installation_id,
            "release": "0.2.0",
            "pluginId": "codex-smart-subagents",
            "stateHome": str(self.root / "state"),
            "activeActivationId": self.new_activation_id,
            "previousActivationId": self.old_activation_id,
            "lastCommittedOperation": self.operation_id,
            "sourceLocatorFingerprint": "8" * 64,
            "artifactsFingerprint": "9" * 64,
            "semanticFingerprint": "a" * 64,
        }
        projection = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "frozenJournalFingerprint": "b" * 64,
            "manifest": {
                "schemaId": "manifest-v2",
                "schemaSha256": "c" * 64,
                "value": manifest_value,
                "valueFingerprint": "d" * 64,
            },
            "manifestDocument": self.manifest,
            "transitionLineage": {
                "transitionKind": "update",
                "sourceReceipt": {
                    "receiptKind": "activation-preparation",
                    "path": str(self.root / "activation-preparation.json"),
                    "rawSha256": "6" * 64,
                    "receiptFingerprint": "7" * 64,
                },
                "activationProofFingerprint": "8" * 64,
                "shutdownCommandIds": {
                    "maintenanceBegin": "cc2_" + "8" * 32,
                    "maintenanceStrengthen": "cc2_" + "9" * 32,
                    "shutdown": "cc2_" + "a" * 32,
                },
                "stoppedController": {
                    "operationId": self.previous_operation_id,
                    "activationId": self.old_activation_id,
                    "databaseId": "db2_" + "e" * 32,
                    "controllerIdentity": "f" * 64,
                    "controlEpoch": 4,
                },
            },
            "activation": {
                "schemaId": "activation-v2",
                "schemaSha256": "c" * 64,
                "value": {
                    "activationId": self.new_activation_id,
                },
                "valueFingerprint": "e" * 64,
            },
            "databaseBinding": {
                "schemaId": "database-binding-v2",
                "schemaSha256": "c" * 64,
                "value": {"databaseId": "db2_" + "f" * 32},
                "valueFingerprint": "f" * 64,
            },
            "journalAbsenceTarget": {
                "schemaId": "absence-proof-v2",
                "schemaSha256": "c" * 64,
                "value": {
                    "proofId": "ap2_" + "1" * 32,
                    "installationId": self.installation_id,
                    "operationId": self.operation_id,
                    "entries": [
                        {
                            "path": str(self.journal_path),
                            "basename": self.journal_path.name,
                            "parentDevice": self.root.stat().st_dev,
                            "parentInode": self.root.stat().st_ino,
                            "absent": True,
                        }
                    ],
                    "directorySyncCompleted": True,
                    "proofFingerprint": "2" * 64,
                },
                "valueFingerprint": "3" * 64,
            },
            "controllerIdentity": "4" * 64,
            "completedStepIds": ["st2_" + "5" * 32],
            "completedAt": "2026-07-19T00:00:00Z",
        }
        projection["transitionLineage"]["lineageFingerprint"] = domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            projection["transitionLineage"],
        )
        return {
            **projection,
            "receiptFingerprint": domain_fingerprint(
                "codex-smart/activation-commit-receipt/v2", projection
            ),
        }

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(0o600)

    @staticmethod
    def _read(path: Path) -> object:
        return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
