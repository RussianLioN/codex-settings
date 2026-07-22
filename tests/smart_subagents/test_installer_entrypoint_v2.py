from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.installer_maintenance_v2 import (  # noqa: E402
    InstallerMaintenanceLayoutV2,
    MaintenanceInventoryV2,
    MaintenanceResultV2,
    RegistrationCallbacksV2,
)
from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipStoreV2,
)
from codex_smart_subagents.installer_recovery_v2 import (  # noqa: E402
    InstallerLifecycleAdapterResultV2,
    MainJournalRecoveryV2,
    RecoveryPlanV2,
    execute_recovery_v2 as execute_recovery_adapter_v2,
    inspect_recovery_v2 as inspect_recovery_adapter_v2,
    plan_recovery_v2 as plan_recovery_adapter_v2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    StepCallbacksV2,
    TerminalCallbacksV2,
)
from codex_smart_subagents.operation_process_group_supervisor_v2 import (  # noqa: E402
    TransientProcessLeaseV2,
)


INSTALLER_PATH = ROOT / "scripts" / "install_adaptive_subagents.py"
INSTALLATION_ID = "ins2_" + "1" * 32
ACTIVE_ID = "act2_" + "2" * 64
PREVIOUS_ID = "act2_" + "3" * 64
STALE_ID = "act2_" + "4" * 64
OPERATION_ID = "op2_" + "5" * 32


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


def _load_installer():
    name = "install_adaptive_subagents_entrypoint_v2_under_test"
    spec = importlib.util.spec_from_file_location(name, INSTALLER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("installer module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class InstallerEntrypointV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = _load_installer()

    def _run_main(self, argv: list[str]) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = self.installer.main(argv)
        return code, json.loads(output.getvalue())

    def _layout(self, root: Path):
        return self.installer.InstallLayout(
            source_root=ROOT,
            codex_home=(root / "codex-home").resolve(),
            bin_dir=(root / "bin").resolve(),
            codex_binary=(root / "codex").resolve(),
            state_home=(root / "state").resolve(),
        )

    def _ready_diagnosis(self) -> dict[str, object]:
        return {
            "ok": True,
            "status": "FULL_READY",
            "readiness": "FULL_READY",
            "gatewayReason": "READY",
            "problems": [],
            "sourceDigest": "a" * 64,
            "activationId": ACTIVE_ID,
        }

    def test_preview_runs_with_isolated_python_without_site_packages(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="csi-v2-") as raw:
            root = Path(raw).resolve()
            codex_home = root / "c"
            bin_dir = root / "b"
            state_home = root / "s"
            for directory in (codex_home, bin_dir):
                directory.mkdir(mode=0o700)
            codex_binary = root / "codex"
            codex_binary.write_text(
                (
                    "#!/bin/sh\n"
                    "if [ \"$1\" = \"--version\" ]; then\n"
                    "  printf 'codex-cli 0.144.6\\n'\n"
                    "  exit 0\n"
                    "fi\n"
                    "exit 1\n"
                ),
                encoding="utf-8",
            )
            codex_binary.chmod(0o700)

            completed = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(INSTALLER_PATH),
                    "--source-root",
                    str(ROOT),
                    "--codex-home",
                    str(codex_home),
                    "--bin-dir",
                    str(bin_dir),
                    "--state-home",
                    str(state_home),
                    "--codex-binary",
                    str(codex_binary),
                    "--preview",
                    "--json",
                ),
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(2, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("apply", result["command"])
        self.assertEqual("planned", result["status"])
        self.assertNotIn("ModuleNotFoundError", completed.stderr)

    def _inventory(
        self,
        layout,
        *,
        unsupported_launcher_projection: bool = False,
    ) -> MaintenanceInventoryV2:
        original_backup = layout.codex_home / "original-codex-backup"
        installer_receipt = None
        manifest = None
        if unsupported_launcher_projection:
            manifest = {
                "originalBackup": {
                    "type": "absent",
                    "path": str(original_backup),
                }
            }
            installer_receipt = {
                "links": [
                    {
                        "path": str(layout.launcher_path),
                        "target": str(layout.launcher_target),
                    }
                ]
            }
        return MaintenanceInventoryV2(
            installation_id=INSTALLATION_ID,
            active_activation_id=ACTIVE_ID,
            previous_activation_id=PREVIOUS_ID,
            protected_activation_ids=(ACTIVE_ID, PREVIOUS_ID),
            cleanup_candidate_ids=(STALE_ID,),
            owned_activations=(),
            retained_paths=(
                layout.state_home,
                layout.state_home / "databases",
                layout.state_home / "backups",
                layout.state_home / "quarantine",
            ),
            manifest=manifest,
            installer_receipt=installer_receipt,
            registrations=(),
            issues=(),
        )

    def test_invalid_invocation_returns_64_and_strict_json(self) -> None:
        code, result = self._run_main(["--rollback"])

        self.assertEqual(64, code)
        self.assertEqual(2, result["schemaVersion"])
        self.assertEqual("INVALID_INVOCATION", result["code"])
        self.assertEqual("failed", result["status"])

    def test_doctor_is_projected_to_the_strict_public_result(self) -> None:
        layout = object()
        diagnosis = {
            "ok": True,
            "status": "FULL_READY",
            "readiness": "FULL_READY",
            "gatewayReason": "READY",
            "problems": [],
            "sourceDigest": "a" * 64,
            "activationId": "act2_" + "b" * 64,
        }
        with (
            mock.patch.object(self.installer, "default_layout", return_value=layout),
            mock.patch.object(self.installer, "doctor", return_value=diagnosis),
        ):
            code, result = self._run_main(["--doctor", "--json"])

        self.assertEqual(0, code)
        self.assertEqual("doctor", result["command"])
        self.assertEqual("READY", result["status"])
        self.assertEqual("READY", result["readiness"])
        self.assertEqual([], result["changes"])
        self.assertEqual([], result["problems"])
        self.assertRegex(result["resultFingerprint"], r"^[0-9a-f]{64}$")

    def test_changed_source_digest_dispatches_a_real_upgrade_adapter(self) -> None:
        layout = SimpleNamespace(
            installer_receipt_path=Path("/tmp/receipt"),
            gateway_layout=SimpleNamespace(journal_path=Path("/tmp/main-journal")),
        )
        receipt = {"sourceDigest": "a" * 64}
        upgraded = {
            "status": "upgraded",
            "readiness": "FULL_READY",
            "sourceDigest": "b" * 64,
            "codexVersion": "0.144.6",
            "installationId": "ins2_" + "1" * 32,
            "activationId": "act2_" + "2" * 64,
            "operationId": "op2_" + "3" * 32,
            "attemptId": "opa2_" + "4" * 32,
        }
        with (
            mock.patch.object(
                self.installer, "_load_installer_receipt", return_value=receipt
            ),
            mock.patch.object(
                self.installer, "_upgrade_install", return_value=upgraded
            ) as upgrade,
            mock.patch.object(
                self.installer,
                "_try_reconcile_pending_committed_upgrade_v2",
                return_value=None,
            ),
            mock.patch.object(
                self.installer,
                "_inspect_installation_recovery_v2",
                return_value=SimpleNamespace(journal_kind="none"),
            ),
        ):
            result = self.installer._repeat_install(
                layout,
                source_digest="b" * 64,
                codex_version="0.144.6",
                extra_environment=None,
            )

        self.assertEqual(upgraded, result)
        upgrade.assert_called_once_with(
            layout,
            previous_receipt=receipt,
            source_digest="b" * 64,
            codex_version="0.144.6",
            extra_environment=None,
        )

    def test_lifecycle_identity_accepts_a_distinct_previous_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            layout.gateway_layout.manifest_root.mkdir(parents=True, mode=0o700)
            document = {
                "schemaVersion": 2,
                "installationId": INSTALLATION_ID,
                "activeActivation": {
                    "activationId": ACTIVE_ID,
                    "symlinkTarget": f"activations/{ACTIVE_ID}/marketplace",
                },
                "previousActivation": {
                    "activationId": PREVIOUS_ID,
                    "symlinkTarget": f"activations/{PREVIOUS_ID}/marketplace",
                },
                "lastCommittedOperation": OPERATION_ID,
                "stateHome": str(layout.state_home),
            }
            layout.gateway_layout.manifest_path.write_text(
                json.dumps(document, separators=(",", ":")),
                encoding="utf-8",
            )
            layout.gateway_layout.manifest_path.chmod(0o600)

            identity = self.installer._load_lifecycle_identity(layout)

            self.assertEqual(ACTIVE_ID, identity["activationId"])
            self.assertEqual(PREVIOUS_ID, identity["previousActivationId"])
            with self.assertRaises(self.installer.InstallError) as caught:
                self.installer._load_lifecycle_identity(
                    layout,
                    require_first_activation=True,
                )
            self.assertEqual("LIFECYCLE_MANIFEST_INVALID", caught.exception.code)

    def test_committed_upgrade_reconciles_installer_receipt_without_second_update(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            old_receipt = {"sourceDigest": "a" * 64}
            expected_receipt = {"sourceDigest": "b" * 64}
            manifest = {
                "schemaVersion": 2,
                "installationId": INSTALLATION_ID,
                "activeActivation": {"activationId": ACTIVE_ID},
                "previousActivation": {"activationId": PREVIOUS_ID},
                "lastCommittedOperation": OPERATION_ID,
                "extensions": {"installerSourceDigest": "b" * 64},
            }

            def reconcile(**arguments):
                self.assertIs(True, arguments["verify_external_state"]())
                return SimpleNamespace(
                    source_digest="b" * 64,
                    installation_id=INSTALLATION_ID,
                    activation_id=ACTIVE_ID,
                    operation_id=OPERATION_ID,
                )

            with (
                mock.patch.object(
                    self.installer,
                    "_read_private_json",
                    return_value=manifest,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=old_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_archive_previous_installer_receipt_v2",
                    return_value=Path("/tmp/previous.installer.json"),
                ) as archive_receipt,
                mock.patch.object(
                    self.installer,
                    "_build_installer_receipt",
                    return_value=expected_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_installation_problems",
                    return_value=[],
                ) as problems,
                mock.patch.object(
                    self.installer,
                    "_supervise_existing",
                    return_value=SimpleNamespace(
                        state=self.installer.GatewayState.READY,
                        reason_code="READY",
                    ),
                ) as supervise,
                mock.patch.object(
                    self.installer,
                    "reconcile_installer_receipt_v2",
                    side_effect=reconcile,
                ) as reconcile_receipt,
            ):
                result = self.installer._try_reconcile_committed_upgrade_v2(
                    layout,
                    previous_receipt=old_receipt,
                    source_digest="b" * 64,
                    codex_version="0.144.6",
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual("reconciled", result["status"])
            self.assertEqual(ACTIVE_ID, result["activationId"])
            self.assertEqual(PREVIOUS_ID, result["previousActivationId"])
            self.assertEqual(OPERATION_ID, result["operationId"])
            self.assertEqual(2, problems.call_count)
            supervise.assert_called_once()
            reconcile_receipt.assert_called_once()
            archive_receipt.assert_called_once_with(
                layout,
                receipt=old_receipt,
                activation_id=PREVIOUS_ID,
            )

    def test_committed_upgrade_retry_accepts_the_already_replaced_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            old_receipt = {"sourceDigest": "a" * 64}
            expected_receipt = {"sourceDigest": "b" * 64}
            manifest = {
                "schemaVersion": 2,
                "installationId": INSTALLATION_ID,
                "activeActivation": {"activationId": ACTIVE_ID},
                "previousActivation": {"activationId": PREVIOUS_ID},
                "lastCommittedOperation": OPERATION_ID,
                "extensions": {"installerSourceDigest": "b" * 64},
            }
            low_level = SimpleNamespace(
                source_digest="b" * 64,
                installation_id=INSTALLATION_ID,
                activation_id=ACTIVE_ID,
                operation_id=OPERATION_ID,
            )

            with (
                mock.patch.object(
                    self.installer,
                    "_read_private_json",
                    return_value=manifest,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=expected_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_archive_previous_installer_receipt_v2",
                    return_value=Path("/tmp/previous.installer.json"),
                ) as archive_receipt,
                mock.patch.object(
                    self.installer,
                    "_build_installer_receipt",
                    return_value=expected_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_installation_problems",
                    return_value=[],
                ),
                mock.patch.object(
                    self.installer,
                    "_supervise_existing",
                    return_value=SimpleNamespace(
                        state=self.installer.GatewayState.READY,
                        reason_code="READY",
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "reconcile_installer_receipt_v2",
                    return_value=low_level,
                ) as reconcile_receipt,
            ):
                result = self.installer._try_reconcile_committed_upgrade_v2(
                    layout,
                    previous_receipt=old_receipt,
                    source_digest="b" * 64,
                    codex_version="0.144.6",
                    extra_environment=None,
                )

            self.assertEqual("reconciled", result["status"])
            archive_receipt.assert_called_once_with(
                layout,
                receipt=old_receipt,
                activation_id=PREVIOUS_ID,
            )
            reconcile_receipt.assert_called_once()

    def test_previous_installer_receipt_archive_is_immutable_and_idempotent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            receipt = {
                "schemaVersion": 2,
                "kind": "codex-smart-installer-receipt/v2",
                "sourceDigest": "a" * 64,
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "codexHome": str(layout.codex_home),
                "codexBinary": str(layout.codex_binary),
                "stateHome": str(layout.state_home),
                "marketplacePath": str(layout.gateway_layout.marketplace_link),
                "registeredMarketplacePath": str(
                    layout.gateway_layout.managed_root
                    / "activations"
                    / PREVIOUS_ID
                    / "marketplace"
                ),
                "links": [
                    {
                        "path": str(layout.launcher_path),
                        "target": str(layout.launcher_target),
                    },
                    {
                        "path": str(layout.admin_path),
                        "target": str(layout.admin_target),
                    },
                ],
                "marketplaceName": "codex-settings-adaptive",
                "pluginId": ("codex-smart-subagents@codex-settings-adaptive"),
                "extensions": {},
            }

            first = self.installer._archive_previous_installer_receipt_v2(
                layout,
                receipt=receipt,
                activation_id=PREVIOUS_ID,
            )
            repeated = self.installer._archive_previous_installer_receipt_v2(
                layout,
                receipt=receipt,
                activation_id=PREVIOUS_ID,
            )

            self.assertEqual(first, repeated)
            self.assertEqual(0o600, first.stat().st_mode & 0o777)
            self.assertEqual(
                receipt,
                self.installer._load_installer_receipt(first),
            )
            changed = {**receipt, "sourceDigest": "b" * 64}
            with self.assertRaises(self.installer.InstallError) as caught:
                self.installer._archive_previous_installer_receipt_v2(
                    layout,
                    receipt=changed,
                    activation_id=PREVIOUS_ID,
                )
            self.assertEqual(
                "INSTALLER_RECEIPT_ARCHIVE_CONFLICT",
                caught.exception.code,
            )

            first.unlink()
            with mock.patch.object(
                self.installer,
                "_fsync_directory",
                side_effect=OSError("simulated archive directory sync failure"),
            ):
                with self.assertRaises(OSError):
                    self.installer._archive_previous_installer_receipt_v2(
                        layout,
                        receipt=receipt,
                        activation_id=PREVIOUS_ID,
                    )
            self.assertTrue(first.exists())
            with mock.patch.object(self.installer, "_fsync_directory") as sync:
                retried = self.installer._archive_previous_installer_receipt_v2(
                    layout,
                    receipt=receipt,
                    activation_id=PREVIOUS_ID,
                )
            self.assertEqual(first, retried)
            sync.assert_called_once_with(first.parent)

    def test_repeat_install_reconciles_hidden_d1_before_returning_to_d0(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            d0 = "0" * 64
            d1 = "1" * 64
            d0_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": d0,
            }
            d1_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": ACTIVE_ID,
                "sourceDigest": d1,
            }
            final = {
                "status": "upgraded",
                "sourceDigest": d0,
                "operationId": "op2_" + "6" * 32,
            }
            with (
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    side_effect=[d0_receipt, d1_receipt],
                ),
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_pending_committed_upgrade_v2",
                    return_value={
                        "status": "reconciled",
                        "sourceDigest": d1,
                        "operationId": OPERATION_ID,
                    },
                ) as reconcile_pending,
                mock.patch.object(
                    self.installer,
                    "_upgrade_install",
                    return_value=final,
                ) as upgrade,
                mock.patch.object(
                    self.installer,
                    "_load_lifecycle_identity",
                    side_effect=AssertionError(
                        "нельзя проверять unchanged до согласования D1"
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "_inspect_installation_recovery_v2",
                    return_value=SimpleNamespace(journal_kind="none"),
                ),
            ):
                result = self.installer._repeat_install(
                    layout,
                    source_digest=d0,
                    codex_version="0.144.6",
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(final, result)
            reconcile_pending.assert_called_once()
            upgrade.assert_called_once_with(
                layout,
                previous_receipt=d1_receipt,
                source_digest=d0,
                codex_version="0.144.6",
                extra_environment={"TEST_BOUNDARY": "closed"},
            )

    def test_repeat_install_recovers_main_journal_before_digest_comparison(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "0" * 64,
            }
            inspection = SimpleNamespace(journal_kind="main")
            with (
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_inspect_installation_recovery_v2",
                    side_effect=[
                        inspection,
                        SimpleNamespace(journal_kind="none"),
                    ],
                ),
                mock.patch.object(
                    self.installer,
                    "_recover_pending_install_journal_v2",
                    return_value=InstallerLifecycleAdapterResultV2(
                        command="recover",
                        status="recovered",
                        operation_id=OPERATION_ID,
                        journal_kind="main",
                    ),
                ) as recover,
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_pending_committed_upgrade_v2",
                    return_value=None,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_lifecycle_identity",
                    return_value={
                        "installationId": INSTALLATION_ID,
                        "activationId": PREVIOUS_ID,
                    },
                ),
                mock.patch.object(
                    self.installer,
                    "_build_installer_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_installation_problems",
                    return_value=[],
                ),
                mock.patch.object(
                    self.installer,
                    "_supervise_existing",
                    return_value=SimpleNamespace(
                        state=self.installer.GatewayState.READY,
                        reason_code="READY",
                    ),
                ),
            ):
                result = self.installer._repeat_install(
                    layout,
                    source_digest="0" * 64,
                    codex_version="0.144.6",
                    extra_environment=None,
                )

            self.assertEqual("unchanged", result["status"])
            recover.assert_called_once_with(
                layout,
                inspection=inspection,
                extra_environment=None,
            )

    def test_uncommitted_source_digest_does_not_enter_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            with (
                mock.patch.object(
                    self.installer,
                    "_read_private_json",
                    return_value={
                        "schemaVersion": 2,
                        "extensions": {"installerSourceDigest": "a" * 64},
                    },
                ),
                mock.patch.object(
                    self.installer,
                    "reconcile_installer_receipt_v2",
                ) as reconcile_receipt,
            ):
                result = self.installer._try_reconcile_committed_upgrade_v2(
                    layout,
                    previous_receipt={"sourceDigest": "a" * 64},
                    source_digest="b" * 64,
                    codex_version="0.144.6",
                    extra_environment=None,
                )

            self.assertIsNone(result)
            reconcile_receipt.assert_not_called()

    def test_completed_d1_is_reconciled_before_a_new_d2_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            d0 = "0" * 64
            d1 = "1" * 64
            d2 = "2" * 64
            d1_codex = (root / "persisted-d1-codex").resolve()
            previous_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": d0,
            }
            d1_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": ACTIVE_ID,
                "sourceDigest": d1,
            }
            manifest = {
                "schemaVersion": 2,
                "installationId": INSTALLATION_ID,
                "activeActivation": {"activationId": ACTIVE_ID},
                "previousActivation": {"activationId": PREVIOUS_ID},
                "lastCommittedOperation": OPERATION_ID,
                "sourceLocator": {"lexicalPath": str(d1_codex)},
                "extensions": {"installerSourceDigest": d1},
            }
            d1_result = {
                "status": "reconciled",
                "sourceDigest": d1,
                "operationId": OPERATION_ID,
            }
            d2_result = {
                "status": "reconciled",
                "sourceDigest": d2,
                "operationId": "op2_" + "6" * 32,
            }
            proof = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                current_operation_id=OPERATION_ID,
                activation_id=ACTIVE_ID,
            )
            preparation_receipt = SimpleNamespace(operation_id="op2_" + "6" * 32)
            preparation = SimpleNamespace(
                definition=object(),
                callbacks=object(),
            )
            reconciliation_order: list[tuple[str, Path]] = []

            def reconcile(reconcile_layout, **arguments):
                digest = arguments["source_digest"]
                reconciliation_order.append((digest, reconcile_layout.codex_binary))
                return d1_result if digest == d1 else d2_result

            with (
                mock.patch.object(
                    self.installer,
                    "_read_private_json",
                    return_value=manifest,
                ),
                mock.patch.object(
                    self.installer,
                    "_registration_runtime_layout_v2",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_probe_version",
                    return_value="0.144.4",
                ),
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_committed_upgrade_v2",
                    side_effect=reconcile,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=d1_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "capture_activation_transition_proof_v2",
                    return_value=proof,
                ),
                mock.patch.object(
                    self.installer,
                    "_update_operation_id_v2",
                    return_value=preparation_receipt.operation_id,
                ),
                mock.patch.object(
                    self.installer,
                    "build_upgrade_preparation_v2",
                    return_value=preparation,
                ),
                mock.patch.object(
                    self.installer,
                    "execute_and_verify_upgrade_preparation_v2",
                    return_value=preparation_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_execute_fresh_update_composition_v2",
                    return_value=SimpleNamespace(attempt_id="opa2_" + "7" * 32),
                ) as execute_d2,
                mock.patch.object(
                    self.installer,
                    "file_digest",
                    return_value="8" * 64,
                ),
            ):
                result = self.installer._upgrade_install(
                    layout,
                    previous_receipt=previous_receipt,
                    source_digest=d2,
                    codex_version="0.145.0",
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(
                [(d1, d1_codex), (d2, layout.codex_binary)],
                reconciliation_order,
            )
            self.assertEqual("upgraded", result["status"])
            self.assertEqual(d2, result["sourceDigest"])
            execute_d2.assert_called_once()

    def test_recovered_d1_is_reconciled_before_dispatching_d2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            d1 = "1" * 64
            d2 = "2" * 64
            previous_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "0" * 64,
            }
            d1_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": ACTIVE_ID,
                "sourceDigest": d1,
            }
            recovered = {
                "status": "reconciled",
                "sourceDigest": d1,
                "operationId": OPERATION_ID,
            }
            final = {
                "status": "upgraded",
                "sourceDigest": d2,
                "operationId": "op2_" + "6" * 32,
            }
            events: list[str] = []
            composition = SimpleNamespace(
                operation=SimpleNamespace(
                    execute=lambda: (
                        events.append("execute-d1")
                        or SimpleNamespace(attempt_id="opa2_" + "7" * 32)
                    )
                )
            )

            def reconcile(_layout, **arguments):
                events.append(f"reconcile-{arguments['source_digest']}")
                return recovered if arguments["source_digest"] == d1 else None

            def start_d2(*args, **kwargs):
                events.append("start-d2")
                self.assertEqual(d1_receipt, kwargs["previous_receipt"])
                self.assertEqual(d2, kwargs["source_digest"])
                return final

            with (
                mock.patch.object(
                    self.installer,
                    "_build_update_main_recovery_composition_v2",
                    return_value=composition,
                ),
                mock.patch.object(
                    self.installer,
                    "_read_private_json",
                    return_value={
                        "schemaVersion": 2,
                        "installationId": INSTALLATION_ID,
                        "activeActivation": {"activationId": ACTIVE_ID},
                        "previousActivation": {"activationId": PREVIOUS_ID},
                        "lastCommittedOperation": OPERATION_ID,
                        "sourceLocator": {
                            "lexicalPath": str(
                                (Path(directory) / "persisted-d1-codex").resolve()
                            )
                        },
                        "extensions": {"installerSourceDigest": d1},
                    },
                ),
                mock.patch.object(
                    self.installer,
                    "_registration_runtime_layout_v2",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_probe_version",
                    return_value="0.144.4",
                ),
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_committed_upgrade_v2",
                    side_effect=reconcile,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=d1_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_upgrade_install",
                    side_effect=start_d2,
                ) as upgrade,
            ):
                result = self.installer._recover_update_install_v2(
                    layout,
                    previous_receipt=previous_receipt,
                    source_digest=d2,
                    codex_version="0.145.0",
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(final, result)
            self.assertEqual(
                ["execute-d1", f"reconcile-{d1}", "start-d2"],
                events,
            )
            upgrade.assert_called_once()

    def test_existing_main_journal_is_recovered_before_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            layout.gateway_layout.manifest_root.mkdir(parents=True, mode=0o700)
            layout.gateway_layout.journal_path.write_text("{}", encoding="utf-8")
            recovered = {
                "status": "upgraded",
                "sourceDigest": "2" * 64,
                "operationId": "op2_" + "6" * 32,
            }
            with (
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_pending_committed_upgrade_v2",
                    side_effect=AssertionError(
                        "существующий журнал сначала должен быть восстановлен"
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "_recover_update_install_v2",
                    return_value=recovered,
                ) as recover,
            ):
                result = self.installer._upgrade_install(
                    layout,
                    previous_receipt={"sourceDigest": "0" * 64},
                    source_digest="2" * 64,
                    codex_version="0.145.0",
                    extra_environment=None,
                )

            self.assertEqual(recovered, result)
            recover.assert_called_once()

    def test_preparation_recovery_uses_only_the_persisted_executor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            executor = object()
            journal_path = (
                layout.gateway_layout.manifest_root
                / "codex-smart-subagents-v2.activation-preparation.transaction.json"
            )
            inspection = SimpleNamespace(
                journal_kind="preparation",
                operation_id=OPERATION_ID,
                journal_path=journal_path,
            )
            with mock.patch.object(
                self.installer,
                "build_persisted_upgrade_preparation_recovery_v2",
                return_value=executor,
            ) as build:
                preparation_context, main_context = self.installer._recovery_context_v2(
                    layout, inspection
                )

            self.assertIsNone(main_context)
            self.assertIs(executor, preparation_context.executor)
            build.assert_called_once_with(journal_path=journal_path)

    def test_rollback_preparation_recovery_rehydrates_persisted_definition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            journal_path = (
                layout.gateway_layout.manifest_root
                / "codex-smart-subagents-v2.rollback-manifest-preparation.transaction.json"
            )
            definition_document = {"persisted": "definition"}
            definition = SimpleNamespace(
                journal_path=journal_path,
                activation_intent=SimpleNamespace(operation_id=OPERATION_ID),
            )
            executor = object()
            inspection = SimpleNamespace(
                journal_kind="rollback_preparation",
                operation_id=OPERATION_ID,
                journal_path=journal_path,
                document={"definition": definition_document},
            )
            with (
                mock.patch(
                    "codex_smart_subagents.rollback_manifest_preparation_v2."
                    "RollbackManifestPreparationDefinitionV2.from_document",
                    return_value=definition,
                ) as rehydrate,
                mock.patch(
                    "codex_smart_subagents.rollback_manifest_preparation_v2."
                    "RollbackManifestPreparationExecutorV2",
                    return_value=executor,
                ) as executor_type,
            ):
                preparation_context, main_context = self.installer._recovery_context_v2(
                    layout, inspection
                )

            self.assertIsNone(main_context)
            self.assertIs(executor, preparation_context.executor)
            rehydrate.assert_called_once_with(definition_document)
            executor_type.assert_called_once_with(definition=definition)

    def test_main_update_recovery_uses_persisted_production_composition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            main_context = object()
            composition = mock.Mock()
            composition.as_main_journal_recovery_v2.return_value = main_context
            inspection = SimpleNamespace(
                journal_kind="main",
                document={"kind": "activation", "operation": "apply"},
            )
            extra_environment = {"FAKE_CODEX_STATE": "ready"}

            with mock.patch.object(
                self.installer,
                "_build_update_main_recovery_composition_v2",
                return_value=composition,
            ) as build:
                preparation_context, observed_main = (
                    self.installer._recovery_context_v2(
                        layout,
                        inspection,
                        extra_environment=extra_environment,
                    )
                )

            self.assertIsNone(preparation_context)
            self.assertIs(main_context, observed_main)
            build.assert_called_once_with(
                layout,
                extra_environment=extra_environment,
            )
            installation_lock_factory = (
                composition.as_main_journal_recovery_v2.call_args.kwargs[
                    "installation_lock"
                ]
            )
            self.assertTrue(callable(installation_lock_factory))

    def test_main_rollback_recovery_uses_frozen_evidence_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            document = {"kind": "rollback", "operation": "rollback"}
            inspection = SimpleNamespace(
                journal_kind="main",
                document=document,
            )
            definition = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                operation_id=OPERATION_ID,
            )
            evidence = object()
            external_artifacts = object()
            external_bindings = object()
            executor = object()
            callbacks = StepCallbacksV2(
                observe=lambda _definition: None,
                apply=lambda _definition: None,
            )
            terminal_callbacks = TerminalCallbacksV2(
                receipt_matches=lambda _document: True,
                publish_receipt=lambda _document: None,
            )
            composition = SimpleNamespace(
                callbacks=callbacks,
                terminal_callbacks=terminal_callbacks,
            )
            preparation_receipt_path = (
                layout.gateway_layout.receipts_root
                / INSTALLATION_ID
                / f"{OPERATION_ID}.rollback-preparation.json"
            )
            extra_environment = {"FAKE_CODEX_STATE": "ready"}

            with (
                mock.patch(
                    "codex_smart_subagents.operation_definition_rehydration_v2."
                    "operation_definition_from_journal_v2",
                    return_value=definition,
                ) as rehydrate_definition,
                mock.patch(
                    "codex_smart_subagents.rollback_runtime_bindings_v2."
                    "rehydrate_rollback_evidence_v2",
                    return_value=evidence,
                ) as rehydrate_evidence,
                mock.patch(
                    "codex_smart_subagents.installer_rollback_composition_v2."
                    "read_rollback_external_artifacts_v2",
                    return_value=external_artifacts,
                ) as read_artifacts,
                mock.patch(
                    "codex_smart_subagents.rollback_runtime_bindings_v2."
                    "recover_rollback_runtime_external_bindings_v2",
                    return_value=external_bindings,
                ) as recover_bindings,
                mock.patch(
                    "codex_smart_subagents.installer_rollback_composition_v2."
                    "build_rollback_recovery_composition_from_receipt_v2",
                    return_value=composition,
                ) as build_composition,
                mock.patch.object(
                    self.installer,
                    "_rollback_operation_executor_v2",
                    return_value=executor,
                ),
            ):
                preparation_context, main_context = self.installer._recovery_context_v2(
                    layout,
                    inspection,
                    extra_environment=extra_environment,
                )

            self.assertIsNone(preparation_context)
            self.assertIs(executor, main_context.executor)
            self.assertIs(definition, main_context.definition)
            self.assertIs(callbacks, main_context.callbacks)
            self.assertIs(terminal_callbacks, main_context.terminal_callbacks)
            rehydrate_definition.assert_called_once_with(document)
            rehydrate_evidence.assert_called_once_with(
                definition=definition,
                journal=document,
                preparation_receipt_path=preparation_receipt_path,
            )
            read_artifacts.assert_called_once_with(
                evidence=evidence,
                installer_receipt_path=layout.installer_receipt_path,
            )
            self.assertIsNone(recover_bindings.call_args.kwargs["readiness_token"])
            self.assertIs(
                external_bindings,
                build_composition.call_args.kwargs["external_bindings"],
            )
            self.assertEqual(
                preparation_receipt_path,
                build_composition.call_args.kwargs["preparation_receipt"],
            )

    def test_lifecycle_registry_can_be_loaded_from_immutable_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self.installer.InstallLayout(
                source_root=root / "missing-source",
                codex_home=root / "codex-home",
                bin_dir=root / "bin",
                codex_binary=root / "codex",
                state_home=root / "state",
            )
            activation_dir = root / "candidate"
            vector = (
                activation_dir
                / "marketplace"
                / "docs"
                / "contracts"
                / "vectors"
                / "lifecycle-v2.json"
            )
            vector.parent.mkdir(parents=True, mode=0o700)
            vector.write_bytes(
                (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_bytes()
            )
            vector.chmod(0o600)

            registry = self.installer._lifecycle_plan_registry_v2(
                layout,
                activation_dir=activation_dir,
            )

            selected = registry.select(
                machine_id="apply",
                branch_id="update-matched-active",
                plan_id="pl2_" + "9" * 32,
            )
            self.assertEqual("update-matched-active", selected.selected_branch_id)

    def test_update_operation_id_converges_across_preparation_handoff_retry(
        self,
    ) -> None:
        arguments = {
            "installation_id": INSTALLATION_ID,
            "current_operation_id": OPERATION_ID,
            "current_activation_id": ACTIVE_ID,
            "source_digest": "e" * 64,
            "codex_binary_path": Path("/opt/homebrew/bin/codex"),
            "codex_binary_sha256": "7" * 64,
        }

        first = self.installer._update_operation_id_v2(**arguments)
        repeated = self.installer._update_operation_id_v2(**arguments)
        another_source = self.installer._update_operation_id_v2(
            **{**arguments, "source_digest": "f" * 64}
        )
        after_another_commit = self.installer._update_operation_id_v2(
            **{
                **arguments,
                "current_operation_id": "op2_" + "9" * 32,
            }
        )
        another_codex_binary = self.installer._update_operation_id_v2(
            **{
                **arguments,
                "codex_binary_sha256": "8" * 64,
            }
        )
        another_codex_path = self.installer._update_operation_id_v2(
            **{
                **arguments,
                "codex_binary_path": Path("/usr/local/bin/codex"),
            }
        )

        self.assertRegex(first, r"^op2_[0-9a-f]{32}$")
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, another_source)
        self.assertNotEqual(first, after_another_commit)
        self.assertNotEqual(first, another_codex_binary)
        self.assertNotEqual(first, another_codex_path)

    def test_rollback_plan_id_is_deterministic_for_evidence(self) -> None:
        evidence = SimpleNamespace(
            installation_id=INSTALLATION_ID,
            current_operation_id=OPERATION_ID,
            evidence_fingerprint="e" * 64,
        )

        first = self.installer._rollback_plan_id_v2(evidence)
        repeated = self.installer._rollback_plan_id_v2(evidence)
        changed = self.installer._rollback_plan_id_v2(
            SimpleNamespace(
                installation_id=INSTALLATION_ID,
                current_operation_id=OPERATION_ID,
                evidence_fingerprint="f" * 64,
            )
        )

        self.assertRegex(first, r"^pl2_[0-9a-f]{32}$")
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, changed)

    def test_maintenance_layout_and_callbacks_are_derived_from_install_layout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            gateway = layout.gateway_layout

            maintenance = self.installer._maintenance_layout_v2(layout)

            self.assertIsInstance(maintenance, InstallerMaintenanceLayoutV2)
            self.assertEqual(layout.codex_home, maintenance.codex_home)
            self.assertEqual(gateway.managed_root, maintenance.managed_root)
            self.assertEqual(
                gateway.managed_root / "activations",
                maintenance.activations_root,
            )
            self.assertEqual(gateway.manifest_path, maintenance.manifest_path)
            self.assertEqual(gateway.receipts_root, maintenance.receipts_root)
            self.assertEqual(
                gateway.manifest_root
                / "codex-smart-subagents-v2.cleanup.transaction.json",
                maintenance.cleanup_journal_path,
            )
            self.assertEqual(
                gateway.manifest_root
                / "codex-smart-subagents-v2.uninstall.transaction.json",
                maintenance.uninstall_journal_path,
            )
            self.assertEqual(layout.state_home, maintenance.state_home)
            self.assertEqual(
                layout.state_home / "databases",
                maintenance.databases_root,
            )
            self.assertEqual(
                layout.state_home / "backups",
                maintenance.backups_root,
            )
            self.assertEqual(
                layout.state_home / "quarantine",
                maintenance.quarantine_root,
            )

            environment = {"TEST_BOUNDARY": "closed"}
            marketplace_target = root / "accepted" / "marketplace"
            plugin_target = marketplace_target / "plugins" / "codex-smart-subagents"
            marketplace_entry = {"root": str(marketplace_target)}
            plugin_entry = {"source": {"path": str(plugin_target)}}
            with (
                mock.patch.object(
                    self.installer,
                    "_target_marketplaces",
                    return_value=[marketplace_entry],
                ) as marketplaces,
                mock.patch.object(
                    self.installer,
                    "_target_plugins",
                    return_value=[plugin_entry],
                ) as plugins,
                mock.patch.object(
                    self.installer,
                    "_marketplace_entry_matches",
                    return_value=True,
                ),
                mock.patch.object(
                    self.installer,
                    "_plugin_entry_matches",
                    return_value=True,
                ),
            ):
                callbacks = self.installer._registration_callbacks_v2(
                    layout, environment
                )
                marketplace = callbacks.observe(
                    "marketplace", self.installer.MARKETPLACE_NAME
                )
                plugin = callbacks.observe("plugin", self.installer.PLUGIN_ID)

            self.assertIsInstance(callbacks, RegistrationCallbacksV2)
            self.assertIsNotNone(marketplace)
            self.assertIsNotNone(plugin)
            assert marketplace is not None
            assert plugin is not None
            self.assertEqual(marketplace_target, marketplace.target)
            self.assertEqual(plugin_target, plugin.target)
            marketplaces.assert_called_once_with(layout, environment)
            plugins.assert_called_once_with(layout, environment)

    def test_inspect_uses_real_maintenance_inventory_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            layout.codex_home.mkdir(mode=0o700)
            lease = TransientProcessLeaseV2(
                lease_id="transient-" + "6" * 32,
                label="candidate-controller",
                pid=9106,
                process_group_id=9106,
                session_id=9106,
                process_start_marker="inspect-safe-projection-marker",
                process=object(),
            )
            DurableProcessOwnershipStoreV2(layout.codex_home).publish(
                lease,
                {
                    "schemaVersion": 2,
                    "contextKind": "candidate-dispatch-v2",
                    "operationId": "op2_" + "1" * 32,
                    "candidateId": "cand2_" + "2" * 32,
                    "controllerStartId": "cs2_" + "3" * 32,
                    "actionFingerprint": "4" * 64,
                    "dispatchReceiptFingerprint": "5" * 64,
                },
            )
            inventory = self._inventory(layout)
            before = _filesystem_snapshot(root)
            with (
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
                mock.patch.object(
                    self.installer,
                    "inspect_maintenance_inventory_v2",
                    return_value=inventory,
                ) as inspect_inventory,
            ):
                result = self.installer.inspect_installation_v2(
                    layout,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(before, _filesystem_snapshot(root))

            maintenance = inspect_inventory.call_args.args[0]
            registrations = inspect_inventory.call_args.kwargs["registrations"]
            self.assertIsInstance(maintenance, InstallerMaintenanceLayoutV2)
            self.assertEqual(layout.codex_home, maintenance.codex_home)
            self.assertIsInstance(registrations, RegistrationCallbacksV2)
            self.assertEqual(2, result["schemaVersion"])
            self.assertEqual("inspect", result["command"])
            self.assertEqual("inspected", result["status"])
            self.assertEqual("READY", result["readiness"])
            self.assertEqual(
                INSTALLATION_ID,
                result["extensions"]["maintenanceInventory"]["installationId"],
            )
            self.assertEqual(
                [
                    {
                        "leaseId": lease.lease_id,
                        "state": "OWNED",
                        "contextKind": "candidate-dispatch-v2",
                    }
                ],
                result["extensions"]["durableProcessOwnership"],
            )
            self.assertRegex(result["resultFingerprint"], r"^[0-9a-f]{64}$")

    def test_registration_observer_distinguishes_absence_from_foreign_owner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            callbacks = self.installer._registration_callbacks_v2(layout, None)

            with mock.patch.object(
                self.installer,
                "_target_marketplaces",
                return_value=[],
            ):
                self.assertIsNone(
                    callbacks.observe(
                        "marketplace",
                        self.installer.MARKETPLACE_NAME,
                    )
                )

            with (
                mock.patch.object(
                    self.installer,
                    "_target_plugins",
                    return_value=[
                        {"source": {"path": "/tmp/foreign-plugin"}}
                    ],
                ),
                mock.patch.object(
                    self.installer,
                    "_plugin_entry_matches",
                    return_value=False,
                ),
            ):
                with self.assertRaises(self.installer.InstallError) as caught:
                    callbacks.observe("plugin", self.installer.PLUGIN_ID)

            self.assertEqual(
                "REGISTRATION_OWNERSHIP_AMBIGUOUS",
                caught.exception.code,
            )

    def test_cleanup_preview_is_read_only_and_execute_reaches_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            planned = MaintenanceResultV2(
                command="cleanup",
                status="planned",
                installation_id=INSTALLATION_ID,
                operation_id=None,
                activation_ids=(STALE_ID,),
                removed_paths=(),
                retained_paths=(layout.state_home,),
            )
            before = _filesystem_snapshot(root)
            with (
                mock.patch.object(
                    self.installer,
                    "cleanup_inactive_activations_v2",
                    return_value=planned,
                ) as cleanup,
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                preview = self.installer.cleanup_installation_v2(
                    layout,
                    execute=False,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(before, _filesystem_snapshot(root))
            self.assertIsInstance(
                cleanup.call_args.args[0], InstallerMaintenanceLayoutV2
            )
            self.assertIs(False, cleanup.call_args.kwargs["execute"])
            self.assertIs(
                self.installer._maintenance_now_v2,
                cleanup.call_args.kwargs["now"],
            )
            self.assertEqual("planned", preview["status"])
            self.assertEqual("READY", preview["readiness"])
            self.assertIsNone(preview["operationId"])
            self.assertIsNone(preview["attemptId"])
            self.assertEqual([], preview["changes"])

            cleaned = MaintenanceResultV2(
                command="cleanup",
                status="cleaned",
                installation_id=INSTALLATION_ID,
                operation_id="cl2_" + "6" * 32,
                activation_ids=(STALE_ID,),
                removed_paths=(
                    layout.gateway_layout.managed_root / "activations" / STALE_ID,
                ),
                retained_paths=(layout.state_home,),
            )
            with (
                mock.patch.object(
                    self.installer,
                    "cleanup_inactive_activations_v2",
                    return_value=cleaned,
                ) as cleanup,
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                applied = self.installer.cleanup_installation_v2(
                    layout,
                    execute=True,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertIs(True, cleanup.call_args.kwargs["execute"])
            self.assertEqual("cleaned", applied["status"])
            self.assertRegex(applied["operationId"], r"^op2_[0-9a-f]{32}$")
            self.assertRegex(applied["attemptId"], r"^opa2_[0-9a-f]{32}$")
            self.assertEqual("retired_generation", applied["changes"][0]["kind"])

    def test_uninstall_public_entrypoint_supports_preview_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            maintenance = self.installer._maintenance_layout_v2(layout)
            expected_keys = {
                "schemaVersion",
                "command",
                "status",
                "readiness",
                "operationId",
                "attemptId",
                "smokeInvocationId",
                "resultFingerprint",
                "changes",
                "problems",
                "extensions",
            }
            for execute, modifier in ((False, "--preview"), (True, "--apply")):
                with self.subTest(execute=execute):
                    before = _filesystem_snapshot(root)
                    internal = MaintenanceResultV2(
                        command="uninstall",
                        status="uninstalled" if execute else "planned",
                        installation_id=INSTALLATION_ID,
                        operation_id=OPERATION_ID if execute else None,
                        activation_ids=(ACTIVE_ID,),
                        removed_paths=(),
                        retained_paths=(layout.state_home,),
                        receipt_path=(
                            maintenance.receipts_root
                            / INSTALLATION_ID
                            / f"{OPERATION_ID}.uninstall.json"
                        ),
                        tombstone_path=maintenance.tombstone_path,
                    )
                    with (
                        mock.patch.object(
                            self.installer,
                            "uninstall_retain_data_v2",
                            return_value=internal,
                        ) as uninstall,
                        mock.patch.object(
                            self.installer,
                            "_execute_fresh_uninstall_composition_v2",
                            return_value=internal,
                        ) as execute_main,
                        mock.patch.object(
                            self.installer,
                            "_plan_fresh_uninstall_composition_v2",
                            return_value=internal,
                        ) as plan_main,
                        mock.patch.object(
                            self.installer,
                            "default_layout",
                            return_value=layout,
                        ),
                        mock.patch.object(
                            self.installer,
                            "doctor",
                            return_value=self._ready_diagnosis(),
                        ),
                    ):
                        code, result = self._run_main(
                            [
                                "--uninstall",
                                modifier,
                                "--retain-data",
                                "--json",
                            ]
                        )

                    self.assertEqual(before, _filesystem_snapshot(root))
                    self.assertEqual(0, code)
                    self.assertEqual(expected_keys, set(result))
                    self.assertEqual("uninstall", result["command"])
                    self.assertEqual(
                        "uninstalled" if execute else "planned",
                        result["status"],
                    )
                    self.assertEqual("DISABLED" if execute else "READY", result["readiness"])
                    self.assertEqual([], result["problems"])
                    self.assertRegex(result["resultFingerprint"], r"^[0-9a-f]{64}$")
                    if execute:
                        execute_main.assert_called_once_with(
                            layout,
                            extra_environment=None,
                        )
                        plan_main.assert_not_called()
                        uninstall.assert_not_called()
                    else:
                        execute_main.assert_not_called()
                        plan_main.assert_called_once_with(
                            layout,
                            extra_environment=None,
                        )
                        uninstall.assert_not_called()

    def test_fresh_active_uninstall_uses_the_main_operation_composition(self) -> None:
        """Новый uninstall не должен создавать прежний пакетный журнал."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            internal = MaintenanceResultV2(
                command="uninstall",
                status="uninstalled",
                installation_id=INSTALLATION_ID,
                operation_id=OPERATION_ID,
                activation_ids=(ACTIVE_ID,),
                removed_paths=(),
                retained_paths=(layout.state_home,),
            )
            with (
                mock.patch.object(
                    self.installer,
                    "_execute_fresh_uninstall_composition_v2",
                    create=True,
                    return_value=internal,
                ) as execute_main,
                mock.patch.object(
                    self.installer,
                    "uninstall_retain_data_v2",
                    return_value=internal,
                ) as execute_legacy,
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                result = self.installer.uninstall_installation_v2(
                    layout,
                    execute=True,
                    retain_data=True,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual("uninstalled", result["status"])
            execute_main.assert_called_once_with(
                layout,
                extra_environment={"TEST_BOUNDARY": "closed"},
            )
            execute_legacy.assert_not_called()

    def test_fresh_uninstall_holds_one_lock_across_snapshot_and_execute(self) -> None:
        """Конкурирующий установщик не входит между снимком и journal intent."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            layout.gateway_layout.manifest_root.mkdir(parents=True, mode=0o700)
            layout.lock_path.write_bytes(b"")
            layout.lock_path.chmod(0o600)
            acquired = threading.Event()
            competitor_started = threading.Event()
            competitor: threading.Thread | None = None
            internal = MaintenanceResultV2(
                command="uninstall",
                status="uninstalled",
                installation_id=INSTALLATION_ID,
                operation_id=OPERATION_ID,
                activation_ids=(ACTIVE_ID,),
                removed_paths=(),
                retained_paths=(layout.state_home,),
            )

            def compete() -> None:
                competitor_started.set()
                with self.installer.installation_lock(layout.lock_path):
                    acquired.set()

            def execute():
                nonlocal competitor
                competitor = threading.Thread(target=compete, daemon=True)
                competitor.start()
                self.assertTrue(competitor_started.wait(1.0))
                self.assertFalse(acquired.wait(0.1))
                return SimpleNamespace(status="COMPLETED"), internal

            composition = SimpleNamespace(execute=execute)
            with mock.patch.object(
                self.installer,
                "_build_fresh_uninstall_composition_v2",
                return_value=composition,
            ) as build:
                result = self.installer._execute_fresh_uninstall_composition_v2(
                    layout,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(internal, result)
            self.assertIsNotNone(competitor)
            assert competitor is not None
            competitor.join(timeout=2.0)
            self.assertFalse(competitor.is_alive())
            self.assertTrue(acquired.is_set())
            self.assertTrue(layout.lock_path.is_file())
            passed_store = build.call_args.kwargs["store"]
            self.assertIsInstance(
                passed_store,
                self.installer._AlreadyHeldOperationJournalStoreV2,
            )

    def test_fresh_uninstall_preview_holds_lock_across_the_exact_snapshot(self) -> None:
        """Preview не допускает mutator между inventory, proof и definition."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            layout.gateway_layout.manifest_root.mkdir(parents=True, mode=0o700)
            layout.lock_path.write_bytes(b"")
            layout.lock_path.chmod(0o600)
            acquired = threading.Event()
            competitor_started = threading.Event()
            competitor: threading.Thread | None = None
            internal = MaintenanceResultV2(
                command="uninstall",
                status="planned",
                installation_id=INSTALLATION_ID,
                operation_id=OPERATION_ID,
                activation_ids=(ACTIVE_ID,),
                removed_paths=(),
                retained_paths=(layout.state_home,),
            )
            composition = SimpleNamespace(
                definition=object(),
                maintenance_layout=object(),
            )

            def compete() -> None:
                competitor_started.set()
                with self.installer.installation_lock(layout.lock_path):
                    acquired.set()

            def build(*_args, **_arguments):
                nonlocal competitor
                competitor = threading.Thread(target=compete, daemon=True)
                competitor.start()
                self.assertTrue(competitor_started.wait(1.0))
                self.assertFalse(acquired.wait(0.1))
                return composition

            def project(*_arguments, **_keywords):
                self.assertFalse(acquired.is_set())
                return internal

            with (
                mock.patch.object(
                    self.installer,
                    "_build_fresh_uninstall_composition_v2",
                    side_effect=build,
                ) as build_exact,
                mock.patch.object(
                    self.installer,
                    "uninstall_maintenance_result_v2",
                    side_effect=project,
                ) as project_exact,
            ):
                result = self.installer._plan_fresh_uninstall_composition_v2(
                    layout,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(internal, result)
            self.assertIsNotNone(competitor)
            assert competitor is not None
            competitor.join(timeout=2.0)
            self.assertFalse(competitor.is_alive())
            self.assertTrue(acquired.is_set())
            self.assertTrue(layout.lock_path.is_file())
            self.assertFalse(layout.gateway_layout.journal_path.exists())
            passed_store = build_exact.call_args.kwargs["store"]
            self.assertIsInstance(
                passed_store,
                self.installer._AlreadyHeldOperationJournalStoreV2,
            )
            project_exact.assert_called_once_with(
                composition.definition,
                composition.maintenance_layout,
                status="planned",
            )

    def test_repeated_uninstall_apply_resumes_the_same_durable_journal(self) -> None:
        from tests.smart_subagents.test_installer_maintenance_v2 import (
            NOW as MAINTENANCE_NOW,
            _CrashOnce,
            _InstallationFixture,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = _InstallationFixture(root / "installation")
            operation_id = "op2_" + "a" * 32
            with self.assertRaisesRegex(
                RuntimeError, "uninstall_after_registration_remove"
            ):
                self.installer.uninstall_retain_data_v2(
                    fixture.layout,
                    registrations=fixture.registrations.callbacks,
                    execute=True,
                    retain_data=True,
                    now=lambda: MAINTENANCE_NOW,
                    id_factory=lambda _prefix: operation_id,
                    failure_injector=_CrashOnce(
                        "uninstall_after_registration_remove"
                    ),
                )
            self.assertTrue(fixture.uninstall_journal_path.is_file())
            database_before = fixture.database_path.read_bytes()
            recovery_before = fixture.recovery_entrypoint.read_bytes()
            layout = self._layout(root / "entrypoint")

            actual_uninstall = self.installer.uninstall_retain_data_v2
            with (
                mock.patch.object(
                    self.installer,
                    "default_layout",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_maintenance_layout_v2",
                    return_value=fixture.layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_registration_callbacks_v2",
                    return_value=fixture.registrations.callbacks,
                ),
                mock.patch.object(
                    self.installer,
                    "uninstall_retain_data_v2",
                    wraps=actual_uninstall,
                ) as uninstall,
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                first_code, first = self._run_main(
                    ["--uninstall", "--retain-data", "--apply", "--json"]
                )
                repeated_code, repeated = self._run_main(
                    ["--uninstall", "--retain-data", "--apply", "--json"]
                )

            self.assertEqual(0, first_code)
            self.assertEqual("uninstalled", first["status"])
            self.assertEqual(operation_id, first["operationId"])
            self.assertEqual(0, repeated_code)
            self.assertEqual("unchanged", repeated["status"])
            self.assertIsNone(repeated["operationId"])
            self.assertEqual(1, uninstall.call_count)
            for call in uninstall.call_args_list:
                self.assertIs(True, call.kwargs["execute"])
                self.assertIs(True, call.kwargs["retain_data"])
            self.assertFalse(fixture.uninstall_journal_path.exists())
            self.assertTrue(fixture.tombstone_path.is_file())
            self.assertEqual(database_before, fixture.database_path.read_bytes())
            self.assertEqual(
                recovery_before, fixture.recovery_entrypoint.read_bytes()
            )

    def test_recover_without_journal_uses_real_adapter_chain_and_is_read_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            manifest_root = layout.gateway_layout.manifest_root
            manifest_root.mkdir(parents=True, mode=0o700)
            layout.codex_home.chmod(0o700)
            manifest_root.chmod(0o700)
            before = _filesystem_snapshot(root)
            for execute in (False, True):
                with self.subTest(execute=execute):
                    with (
                        mock.patch.object(
                            self.installer,
                            "inspect_recovery_v2",
                            wraps=inspect_recovery_adapter_v2,
                        ) as inspect_recovery,
                        mock.patch.object(
                            self.installer,
                            "plan_recovery_v2",
                            wraps=plan_recovery_adapter_v2,
                        ) as plan_recovery,
                        mock.patch.object(
                            self.installer,
                            "execute_recovery_v2",
                            wraps=execute_recovery_adapter_v2,
                        ) as execute_recovery,
                        mock.patch.object(
                            self.installer,
                            "doctor",
                            return_value=self._ready_diagnosis(),
                        ),
                    ):
                        result = self.installer.recover_installation_v2(
                            layout,
                            execute=execute,
                            extra_environment={"TEST_BOUNDARY": "closed"},
                        )

                    expected_preparation = manifest_root / (
                        "codex-smart-subagents-v2."
                        "activation-preparation.transaction.json"
                    )
                    expected_rollback_preparation = manifest_root / (
                        "codex-smart-subagents-v2."
                        "rollback-manifest-preparation.transaction.json"
                    )
                    self.assertEqual(
                        {
                            "journal_root": manifest_root,
                            "preparation_journal_path": expected_preparation,
                            "rollback_preparation_journal_path": (
                                expected_rollback_preparation
                            ),
                            "operation_journal_path": (
                                layout.gateway_layout.journal_path
                            ),
                        },
                        inspect_recovery.call_args.kwargs,
                    )
                    inspection = plan_recovery.call_args.kwargs["inspection"]
                    self.assertEqual("none", inspection.journal_kind)
                    self.assertIs(
                        not execute,
                        execute_recovery.call_args.kwargs["preview"],
                    )
                    self.assertEqual("recover", result["command"])
                    self.assertEqual("unchanged", result["status"])
                    self.assertEqual("READY", result["readiness"])
                    self.assertIsNone(result["operationId"])
                    self.assertIsNone(result["attemptId"])

            self.assertEqual(before, _filesystem_snapshot(root))

    def test_recover_routes_an_unfinished_uninstall_through_its_bound_adapter(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            layout.codex_home.mkdir(mode=0o700)
            lease = TransientProcessLeaseV2(
                lease_id="transient-" + "7" * 32,
                label="candidate-controller",
                pid=9107,
                process_group_id=9107,
                session_id=9107,
                process_start_marker="recover-preview-safe-projection-marker",
                process=object(),
            )
            DurableProcessOwnershipStoreV2(layout.codex_home).publish(
                lease,
                {
                    "schemaVersion": 2,
                    "contextKind": "candidate-dispatch-v2",
                    "operationId": "op2_" + "1" * 32,
                    "candidateId": "cand2_" + "2" * 32,
                    "controllerStartId": "cs2_" + "3" * 32,
                    "actionFingerprint": "4" * 64,
                    "dispatchReceiptFingerprint": "5" * 64,
                },
            )
            maintenance = self.installer._maintenance_layout_v2(layout)
            maintenance.uninstall_journal_path.parent.mkdir(
                parents=True, mode=0o700, exist_ok=True
            )
            maintenance.uninstall_journal_path.write_text("{}", encoding="utf-8")
            maintenance.uninstall_journal_path.chmod(0o600)

            for execute, status in ((False, "planned"), (True, "uninstalled")):
                with self.subTest(execute=execute):
                    internal = MaintenanceResultV2(
                        command="uninstall",
                        status=status,
                        installation_id=INSTALLATION_ID,
                        operation_id=OPERATION_ID,
                        activation_ids=(ACTIVE_ID,),
                        removed_paths=(),
                        retained_paths=(layout.state_home,),
                        receipt_path=(
                            maintenance.receipts_root
                            / INSTALLATION_ID
                            / f"{OPERATION_ID}.uninstall.json"
                        ),
                        tombstone_path=maintenance.tombstone_path,
                    )
                    with (
                        mock.patch.object(
                            self.installer,
                            "uninstall_retain_data_v2",
                            return_value=internal,
                        ) as uninstall,
                        mock.patch.object(
                            self.installer,
                            "inspect_recovery_v2",
                        ) as generic_inspect,
                        mock.patch.object(
                            self.installer,
                            "doctor",
                            return_value=self._ready_diagnosis(),
                        ),
                    ):
                        result = self.installer.recover_installation_v2(
                            layout,
                            execute=execute,
                            extra_environment={"TEST_BOUNDARY": "closed"},
                        )

                    generic_inspect.assert_not_called()
                    self.assertEqual("recover", result["command"])
                    self.assertEqual(
                        "recovered" if execute else "planned", result["status"]
                    )
                    self.assertEqual(
                        "uninstall",
                        result["extensions"]["lifecycleAdapter"]["journalKind"],
                    )
                    self.assertEqual(
                        [
                            {
                                "leaseId": lease.lease_id,
                                "state": "OWNED",
                                "contextKind": "candidate-dispatch-v2",
                            }
                        ],
                        result["extensions"]["durableProcessOwnership"],
                    )
                    self.assertIs(
                        execute, uninstall.call_args.kwargs["execute"]
                    )
                    self.assertIs(True, uninstall.call_args.kwargs["retain_data"])
                    self.assertIsInstance(
                        uninstall.call_args.kwargs["registrations"],
                        RegistrationCallbacksV2,
                    )

    def test_main_uninstall_recovery_rehydrates_the_new_composition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            definition = object()
            callbacks = StepCallbacksV2(
                observe=lambda _step: None,
                apply=lambda _step: None,
            )
            terminal_callbacks = TerminalCallbacksV2(
                receipt_matches=lambda _journal: True,
                publish_receipt=lambda _journal: None,
                tombstone_matches=lambda _journal: True,
                publish_tombstone=lambda _journal: None,
            )
            executor = object()
            composition = SimpleNamespace(
                executor=executor,
                callbacks=callbacks,
                terminal_callbacks=terminal_callbacks,
            )
            inspection = SimpleNamespace(
                journal_kind="main",
                document={"kind": "uninstall", "operation": "uninstall"},
            )
            rehydration_module = importlib.import_module(
                "codex_smart_subagents.operation_definition_rehydration_v2"
            )

            with (
                mock.patch.object(
                    rehydration_module,
                    "operation_definition_from_journal_v2",
                    return_value=definition,
                ) as rehydrate,
                mock.patch.object(
                    self.installer,
                    "recover_active_uninstall_composition_v2",
                    return_value=composition,
                ) as recover_composition,
                mock.patch.object(
                    self.installer,
                    "_lifecycle_plan_registry_v2",
                    return_value=object(),
                ),
                mock.patch.object(
                    self.installer,
                    "_maintenance_layout_v2",
                    return_value=object(),
                ),
                mock.patch.object(
                    self.installer,
                    "_registration_callbacks_v2",
                    return_value=object(),
                ),
            ):
                preparation, main = self.installer._recovery_context_v2(
                    layout,
                    inspection,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertIsNone(preparation)
            self.assertIsNotNone(main)
            assert main is not None
            self.assertIs(executor, main.executor)
            self.assertIs(definition, main.definition)
            self.assertIs(callbacks, main.callbacks)
            self.assertIs(terminal_callbacks, main.terminal_callbacks)
            rehydrate.assert_called_once_with(inspection.document)
            passed_store = recover_composition.call_args.kwargs["store"]
            self.assertIsInstance(
                passed_store,
                self.installer._AlreadyHeldOperationJournalStoreV2,
            )

    def test_recover_without_journal_reconciles_a_committed_transition_under_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            manifest_root = layout.gateway_layout.manifest_root
            manifest_root.mkdir(parents=True, mode=0o700)
            layout.installer_receipt_path.write_text("{}", encoding="utf-8")
            old_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "0" * 64,
            }
            held = False

            @contextmanager
            def lock(_path):
                nonlocal held
                self.assertFalse(held)
                held = True
                try:
                    yield
                finally:
                    held = False

            def reconcile(_layout, **arguments):
                self.assertTrue(held)
                self.assertEqual(old_receipt, arguments["previous_receipt"])
                return {
                    "status": "reconciled",
                    "sourceDigest": "1" * 64,
                    "operationId": OPERATION_ID,
                }

            with (
                mock.patch.object(
                    self.installer, "installation_lock", side_effect=lock
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=old_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_pending_committed_upgrade_v2",
                    side_effect=reconcile,
                ) as reconcile_pending,
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                result = self.installer.recover_installation_v2(
                    layout,
                    execute=True,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertFalse(held)
            reconcile_pending.assert_called_once()
            self.assertEqual("recovered", result["status"])
            self.assertEqual(OPERATION_ID, result["operationId"])

    def test_preparation_recovery_is_serialized_by_the_installer_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            inspection = SimpleNamespace(
                journal_kind="preparation",
                operation_id=OPERATION_ID,
                document={"journalKind": "activation-preparation"},
            )
            adapter_result = InstallerLifecycleAdapterResultV2(
                command="recover",
                status="recovered",
                operation_id=OPERATION_ID,
                journal_kind="preparation",
            )
            held = False

            @contextmanager
            def lock(_path):
                nonlocal held
                held = True
                try:
                    yield
                finally:
                    held = False

            def execute_recovery(**_arguments):
                self.assertTrue(held)
                return adapter_result

            with (
                mock.patch.object(
                    self.installer,
                    "inspect_recovery_v2",
                    return_value=inspection,
                ),
                mock.patch.object(
                    self.installer,
                    "_recovery_context_v2",
                    return_value=(object(), None),
                ),
                mock.patch.object(
                    self.installer,
                    "plan_recovery_v2",
                    return_value=SimpleNamespace(main=None),
                ),
                mock.patch.object(
                    self.installer,
                    "execute_recovery_v2",
                    side_effect=execute_recovery,
                ),
                mock.patch.object(
                    self.installer, "installation_lock", side_effect=lock
                ),
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                result = self.installer.recover_installation_v2(
                    layout,
                    execute=True,
                    extra_environment=None,
                )

            self.assertFalse(held)
            self.assertEqual("recovered", result["status"])

    def test_main_recovery_preview_does_not_build_effectful_runtime_ports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            inspection = SimpleNamespace(
                journal_kind="main",
                operation_id=OPERATION_ID,
                document={"kind": "rollback", "operation": "rollback"},
            )
            before = _filesystem_snapshot(Path(directory).resolve())
            with (
                mock.patch.object(
                    self.installer,
                    "_inspect_installation_recovery_v2",
                    return_value=inspection,
                ),
                mock.patch.object(
                    self.installer,
                    "_recovery_context_v2",
                    side_effect=AssertionError(
                        "preview не должен собирать runtime-порты восстановления"
                    ),
                ) as recovery_context,
                mock.patch.object(
                    self.installer,
                    "execute_recovery_v2",
                    return_value=InstallerLifecycleAdapterResultV2(
                        command="recover",
                        status="planned",
                        operation_id=OPERATION_ID,
                        journal_kind="main",
                    ),
                ) as execute_recovery,
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                result = self.installer.recover_installation_v2(
                    layout,
                    execute=False,
                    extra_environment=None,
                )

            recovery_context.assert_not_called()
            self.assertTrue(execute_recovery.call_args.kwargs["preview"])
            self.assertEqual("planned", result["status"])
            self.assertIsNone(result["operationId"])
            self.assertEqual(before, _filesystem_snapshot(Path(directory).resolve()))

    def test_recovery_preview_reports_a_pending_committed_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            layout.installer_receipt_path.parent.mkdir(parents=True, mode=0o700)
            layout.installer_receipt_path.write_text("{}", encoding="utf-8")
            layout.installer_receipt_path.chmod(0o600)
            inspection = SimpleNamespace(journal_kind="none")
            receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "a" * 64,
            }
            pending = {
                "operationId": OPERATION_ID,
                "activeActivationId": ACTIVE_ID,
            }
            with (
                mock.patch.object(
                    self.installer,
                    "_inspect_installation_recovery_v2",
                    return_value=inspection,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_inspect_pending_committed_upgrade_v2",
                    return_value=pending,
                ) as inspect_pending,
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_pending_committed_upgrade_v2",
                    side_effect=AssertionError(
                        "preview не должен согласовывать квитанцию"
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                result = self.installer.recover_installation_v2(
                    layout,
                    execute=False,
                    extra_environment=None,
                )

            inspect_pending.assert_called_once_with(
                layout,
                previous_receipt=receipt,
            )
            self.assertEqual("planned", result["status"])
            self.assertIsNone(result["operationId"])
            self.assertIsNone(result["attemptId"])
            self.assertEqual(
                OPERATION_ID,
                result["extensions"]["lifecycleAdapter"]["internalOperationId"],
            )

    def test_main_recovery_preview_rejects_an_unsupported_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            inspection = SimpleNamespace(
                journal_kind="main",
                operation_id=OPERATION_ID,
                document={"kind": "rollback", "operation": "apply"},
            )
            with (
                mock.patch.object(
                    self.installer,
                    "_inspect_installation_recovery_v2",
                    return_value=inspection,
                ),
                mock.patch.object(
                    self.installer,
                    "_recovery_context_v2",
                    side_effect=AssertionError(
                        "preview не должен собирать runtime-порты восстановления"
                    ),
                ) as recovery_context,
                mock.patch.object(
                    self.installer,
                    "execute_recovery_v2",
                ) as execute_recovery,
            ):
                with self.assertRaises(self.installer.InstallError) as caught:
                    self.installer.recover_installation_v2(
                        layout,
                        execute=False,
                        extra_environment=None,
                    )

            recovery_context.assert_not_called()
            execute_recovery.assert_not_called()
            self.assertEqual(
                "RECOVERY_OPERATION_UNSUPPORTED",
                caught.exception.code,
            )

    def test_main_apply_recovery_reconciles_d1_before_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            d0_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "0" * 64,
            }
            d1 = "1" * 64
            inspection = SimpleNamespace(
                journal_kind="main",
                operation_id=OPERATION_ID,
                document={"kind": "activation", "operation": "apply"},
            )
            adapter_result = InstallerLifecycleAdapterResultV2(
                command="recover",
                status="recovered",
                operation_id=OPERATION_ID,
                journal_kind="main",
            )
            public_result = {"command": "recover", "status": "recovered"}
            events: list[str] = []
            held = False

            @contextmanager
            def lock(_path):
                nonlocal held
                events.append("lock-enter")
                held = True
                try:
                    yield
                finally:
                    held = False
                    events.append("lock-exit")

            def execute_recovery(**_arguments):
                self.assertTrue(held)
                events.append("execute-d1")
                return adapter_result

            def reconcile(_layout, **arguments):
                self.assertTrue(held)
                events.append(f"reconcile-{arguments['source_digest']}")
                self.assertEqual(d0_receipt, arguments["previous_receipt"])
                return {
                    "status": "reconciled",
                    "sourceDigest": d1,
                    "operationId": OPERATION_ID,
                }

            def project(*_args, **_kwargs):
                events.append("doctor")
                return public_result

            with (
                mock.patch.object(
                    self.installer,
                    "inspect_recovery_v2",
                    return_value=inspection,
                ),
                mock.patch.object(
                    self.installer,
                    "_recovery_context_v2",
                    return_value=(
                        None,
                        MainJournalRecoveryV2(
                            executor=object(),
                            definition=object(),
                            callbacks=object(),
                            installation_lock=lambda: lock(layout.lock_path),
                        ),
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "plan_recovery_v2",
                    side_effect=lambda **arguments: RecoveryPlanV2(
                        inspection=arguments["inspection"],
                        main=arguments["main"],
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "execute_recovery_v2",
                    side_effect=execute_recovery,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=d0_receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_read_private_json",
                    return_value={
                        "schemaVersion": 2,
                        "installationId": INSTALLATION_ID,
                        "activeActivation": {"activationId": ACTIVE_ID},
                        "previousActivation": {"activationId": PREVIOUS_ID},
                        "lastCommittedOperation": OPERATION_ID,
                        "sourceLocator": {
                            "lexicalPath": str(
                                (Path(directory) / "persisted-d1-codex").resolve()
                            )
                        },
                        "extensions": {"installerSourceDigest": d1},
                    },
                ),
                mock.patch.object(
                    self.installer,
                    "_registration_runtime_layout_v2",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_probe_version",
                    return_value="0.144.4",
                ),
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_committed_upgrade_v2",
                    side_effect=reconcile,
                ),
                mock.patch.object(
                    self.installer,
                    "_lifecycle_adapter_public_result_v2",
                    side_effect=project,
                ),
                mock.patch.object(
                    self.installer, "installation_lock", side_effect=lock
                ),
            ):
                result = self.installer.recover_installation_v2(
                    layout,
                    execute=True,
                    extra_environment={"TEST_BOUNDARY": "closed"},
                )

            self.assertEqual(public_result, result)
            self.assertEqual(
                [
                    "lock-enter",
                    "execute-d1",
                    f"reconcile-{d1}",
                    "lock-exit",
                    "doctor",
                ],
                events,
            )

    def test_rollback_passes_preview_and_real_execution_context_to_adapters(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            layout = self._layout(root)
            evidence = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                current_operation_id=OPERATION_ID,
                current_activation_id=ACTIVE_ID,
                previous_activation_id=PREVIOUS_ID,
                activations_root=(layout.gateway_layout.managed_root / "activations"),
                evidence_fingerprint="e" * 64,
            )
            plan = object()
            registry = object()
            execution_plan = object()
            current_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": ACTIVE_ID,
                "sourceDigest": "a" * 64,
            }
            composition = SimpleNamespace(
                definition=object(),
                callbacks=StepCallbacksV2(
                    observe=lambda _definition: None,
                    apply=lambda _definition: None,
                ),
                terminal_callbacks=TerminalCallbacksV2(
                    receipt_matches=lambda _document: True,
                    publish_receipt=lambda _document: None,
                ),
            )
            executor = object()
            before = _filesystem_snapshot(root)
            for execute in (False, True):
                with self.subTest(execute=execute):
                    adapter_result = InstallerLifecycleAdapterResultV2(
                        command="rollback",
                        status="rolled_back" if execute else "planned",
                        operation_id=OPERATION_ID,
                        journal_kind="main" if execute else None,
                    )

                    def build_plan(**arguments):
                        builder = arguments["build_definition"]
                        if execute:
                            self.assertTrue(callable(builder))
                            self.assertIs(
                                composition.definition,
                                builder(evidence, execution_plan),
                            )
                        else:
                            self.assertIsNone(builder)
                        return plan

                    @contextmanager
                    def lock(_path):
                        yield

                    with (
                        mock.patch.object(
                            self.installer,
                            "_load_lifecycle_identity",
                            return_value={"installationId": INSTALLATION_ID},
                        ),
                        mock.patch.object(
                            self.installer,
                            "read_rollback_v2",
                            return_value=evidence,
                        ) as read_rollback,
                        mock.patch.object(
                            self.installer,
                            "plan_rollback_v2",
                            side_effect=build_plan,
                        ) as plan_rollback,
                        mock.patch.object(
                            self.installer,
                            "_lifecycle_plan_registry_v2",
                            return_value=registry,
                        ),
                        mock.patch.object(
                            self.installer,
                            "execute_rollback_v2",
                            return_value=adapter_result,
                        ) as execute_rollback,
                        mock.patch.object(
                            self.installer,
                            "installation_lock",
                            side_effect=lock,
                        ),
                        mock.patch.object(
                            self.installer,
                            "inspect_recovery_v2",
                            return_value=SimpleNamespace(journal_kind="none"),
                        ),
                        mock.patch.object(
                            self.installer,
                            "_load_installer_receipt",
                            return_value=current_receipt,
                        ),
                        mock.patch.object(
                            self.installer,
                            "_try_reconcile_pending_committed_upgrade_v2",
                            side_effect=(
                                [
                                    None,
                                    {
                                        "sourceDigest": "b" * 64,
                                        "operationId": OPERATION_ID,
                                    },
                                ]
                                if execute
                                else AssertionError(
                                    "preview не должен согласовывать квитанцию"
                                )
                            ),
                        ) as reconcile_pending,
                        mock.patch.object(
                            self.installer,
                            "_build_fresh_rollback_composition_v2",
                            return_value=composition,
                        ) as build_composition,
                        mock.patch.object(
                            self.installer,
                            "_rollback_operation_executor_v2",
                            return_value=executor,
                        ),
                        mock.patch.object(
                            self.installer,
                            "doctor",
                            return_value=self._ready_diagnosis(),
                        ),
                    ):
                        result = self.installer.rollback_installation_v2(
                            layout,
                            execute=execute,
                            extra_environment={"TEST_BOUNDARY": "closed"},
                        )

                    gateway = layout.gateway_layout
                    self.assertEqual(
                        {
                            "manifest_path": gateway.manifest_path,
                            "receipts_root": (gateway.receipts_root / INSTALLATION_ID),
                            "activations_root": gateway.managed_root / "activations",
                            "marketplace_link": gateway.marketplace_link,
                        },
                        read_rollback.call_args.kwargs,
                    )
                    plan_arguments = plan_rollback.call_args.kwargs
                    self.assertIs(evidence, plan_arguments["evidence"])
                    self.assertIs(registry, plan_arguments["registry"])
                    self.assertRegex(plan_arguments["plan_id"], r"^pl2_[0-9a-f]{32}$")
                    execution_arguments = execute_rollback.call_args.kwargs
                    self.assertIs(plan, execution_arguments["plan"])
                    self.assertIs(not execute, execution_arguments["preview"])
                    if execute:
                        self.assertIs(executor, execution_arguments["executor"])
                        self.assertIs(
                            composition.callbacks,
                            execution_arguments["callbacks"],
                        )
                        self.assertIs(
                            composition.terminal_callbacks,
                            execution_arguments["terminal_callbacks"],
                        )
                        self.assertIs(
                            self.installer._already_held_installation_lock_v2,
                            execution_arguments["installation_lock"],
                        )
                        build_composition.assert_called_once()
                        self.assertEqual(2, reconcile_pending.call_count)
                    else:
                        build_composition.assert_not_called()
                        reconcile_pending.assert_not_called()
                    self.assertEqual("rollback", result["command"])
                    self.assertEqual(adapter_result.status, result["status"])
                    self.assertEqual("READY", result["readiness"])
                    if execute:
                        self.assertEqual(OPERATION_ID, result["operationId"])
                        self.assertRegex(result["attemptId"], r"^opa2_[0-9a-f]{32}$")
                    else:
                        self.assertIsNone(result["operationId"])
                        self.assertIsNone(result["attemptId"])

            self.assertEqual(before, _filesystem_snapshot(root))

    def test_completed_rollback_is_unchanged_without_a_second_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            evidence = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                current_operation_id=OPERATION_ID,
                current_activation_id=PREVIOUS_ID,
                previous_activation_id=ACTIVE_ID,
            )
            receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "a" * 64,
            }

            @contextmanager
            def lock(_path):
                yield

            for execute in (False, True, True):
                with self.subTest(execute=execute):
                    with (
                        mock.patch.object(
                            self.installer,
                            "installation_lock",
                            side_effect=lock,
                        ),
                        mock.patch.object(
                            self.installer,
                            "inspect_recovery_v2",
                            return_value=SimpleNamespace(journal_kind="none"),
                        ),
                        mock.patch.object(
                            self.installer,
                            "_try_reconcile_pending_committed_upgrade_v2",
                            return_value=None,
                        ),
                        mock.patch.object(
                            self.installer,
                            "_load_installer_receipt",
                            return_value=receipt,
                        ),
                        mock.patch.object(
                            self.installer,
                            "_load_lifecycle_identity",
                            return_value={"installationId": INSTALLATION_ID},
                        ),
                        mock.patch.object(
                            self.installer,
                            "read_rollback_v2",
                            return_value=evidence,
                        ),
                        mock.patch.object(
                            self.installer,
                            "_completed_rollback_operation_v2",
                            return_value=OPERATION_ID,
                        ) as completed,
                        mock.patch.object(
                            self.installer,
                            "plan_rollback_v2",
                            side_effect=AssertionError(
                                "повторный rollback не должен строить новую операцию"
                            ),
                        ),
                        mock.patch.object(
                            self.installer,
                            "_build_fresh_rollback_composition_v2",
                            side_effect=AssertionError(
                                "повторный rollback не должен запускать кандидата"
                            ),
                        ),
                        mock.patch.object(
                            self.installer,
                            "execute_rollback_v2",
                            side_effect=AssertionError(
                                "повторный rollback не должен менять активацию"
                            ),
                        ),
                        mock.patch.object(
                            self.installer,
                            "doctor",
                            return_value=self._ready_diagnosis(),
                        ),
                    ):
                        result = self.installer.rollback_installation_v2(
                            layout,
                            execute=execute,
                            extra_environment=None,
                        )

                    completed.assert_called_once_with(
                        layout,
                        evidence=evidence,
                        current_installer_receipt=receipt,
                    )
                    self.assertEqual("unchanged", result["status"])
                    self.assertIsNone(result["operationId"])
                    self.assertIsNone(result["attemptId"])

    def test_rollback_reconciliation_reports_the_completed_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            evidence = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                current_operation_id=OPERATION_ID,
                current_activation_id=PREVIOUS_ID,
                previous_activation_id=ACTIVE_ID,
            )
            receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "a" * 64,
            }

            @contextmanager
            def lock(_path):
                yield

            with (
                mock.patch.object(
                    self.installer,
                    "installation_lock",
                    side_effect=lock,
                ),
                mock.patch.object(
                    self.installer,
                    "inspect_recovery_v2",
                    return_value=SimpleNamespace(journal_kind="none"),
                ),
                mock.patch.object(
                    self.installer,
                    "_try_reconcile_pending_committed_upgrade_v2",
                    return_value={"operationId": OPERATION_ID},
                ),
                mock.patch.object(
                    self.installer,
                    "_load_installer_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    self.installer,
                    "_load_lifecycle_identity",
                    return_value={"installationId": INSTALLATION_ID},
                ),
                mock.patch.object(
                    self.installer,
                    "read_rollback_v2",
                    return_value=evidence,
                ),
                mock.patch.object(
                    self.installer,
                    "_completed_rollback_operation_v2",
                    return_value=OPERATION_ID,
                ),
                mock.patch.object(
                    self.installer,
                    "plan_rollback_v2",
                    side_effect=AssertionError(
                        "согласованный rollback не должен строиться повторно"
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "execute_rollback_v2",
                    side_effect=AssertionError(
                        "согласованный rollback не должен исполняться повторно"
                    ),
                ),
                mock.patch.object(
                    self.installer,
                    "doctor",
                    return_value=self._ready_diagnosis(),
                ),
            ):
                result = self.installer.rollback_installation_v2(
                    layout,
                    execute=True,
                    extra_environment=None,
                )

            self.assertEqual("rolled_back", result["status"])
            self.assertEqual(OPERATION_ID, result["operationId"])
            self.assertRegex(result["attemptId"], r"^opa2_[0-9a-f]{32}$")

    def test_rollback_preview_requires_recovery_for_an_existing_journal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            with (
                mock.patch.object(
                    self.installer,
                    "_inspect_installation_recovery_v2",
                    return_value=SimpleNamespace(journal_kind="main"),
                ),
                mock.patch.object(
                    self.installer,
                    "plan_rollback_v2",
                    side_effect=AssertionError(
                        "при существующем журнале новый rollback недопустим"
                    ),
                ),
            ):
                with self.assertRaises(self.installer.InstallError) as caught:
                    self.installer.rollback_installation_v2(
                        layout,
                        execute=False,
                        extra_environment=None,
                    )

            self.assertEqual("ROLLBACK_RECOVERY_REQUIRED", caught.exception.code)

    def test_completed_rollback_requires_the_exact_durable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            layout = self._layout(Path(directory).resolve())
            receipts = layout.gateway_layout.receipts_root / INSTALLATION_ID
            receipts.mkdir(parents=True, mode=0o700)
            receipt_path = receipts / f"{OPERATION_ID}.rollback-preparation.json"
            receipt_path.write_text("{}", encoding="utf-8")
            receipt_path.chmod(0o600)
            manifest = {
                "lastCommittedOperation": OPERATION_ID,
                "extensions": {"installerSourceDigest": "a" * 64},
            }
            projection = object()
            previous_operation_id = "op2_" + "6" * 32
            evidence = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                current_operation_id=OPERATION_ID,
                previous_operation_id=previous_operation_id,
                current_activation_id=PREVIOUS_ID,
                previous_activation_id=ACTIVE_ID,
                manifest_document=manifest,
                current_manifest_projection=projection,
            )
            installer_receipt = {
                "installationId": INSTALLATION_ID,
                "activationId": PREVIOUS_ID,
                "sourceDigest": "a" * 64,
            }
            receipt = SimpleNamespace(
                installation_id=INSTALLATION_ID,
                operation_id=OPERATION_ID,
                current_operation_id=previous_operation_id,
                current_activation_id=ACTIVE_ID,
                previous_activation_id=PREVIOUS_ID,
                target_path=layout.gateway_layout.manifest_path,
                manifest_document=manifest,
                expected_after=projection,
            )
            target = (
                "codex_smart_subagents.rollback_manifest_preparation_v2."
                "RollbackManifestPreparationReceiptV2.from_path"
            )
            with (
                mock.patch(target, return_value=receipt) as load_receipt,
                mock.patch.object(
                    self.installer,
                    "_committed_installer_layout_v2",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_build_installer_receipt",
                    return_value=installer_receipt,
                ) as build_installer_receipt,
            ):
                observed = self.installer._completed_rollback_operation_v2(
                    layout,
                    evidence=evidence,
                    current_installer_receipt=installer_receipt,
                )

            self.assertEqual(OPERATION_ID, observed)
            load_receipt.assert_called_once_with(receipt_path)
            build_installer_receipt.assert_called_once_with(
                layout,
                source_digest="a" * 64,
                identity={
                    "installationId": INSTALLATION_ID,
                    "activationId": PREVIOUS_ID,
                },
            )

            with (
                mock.patch(target, return_value=receipt),
                mock.patch.object(
                    self.installer,
                    "_committed_installer_layout_v2",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_build_installer_receipt",
                    return_value=installer_receipt,
                ),
            ):
                with self.assertRaises(self.installer.InstallError) as caught:
                    self.installer._completed_rollback_operation_v2(
                        layout,
                        evidence=evidence,
                        current_installer_receipt={
                            **installer_receipt,
                            "sourceDigest": "f" * 64,
                        },
                    )
            self.assertEqual(
                "ROLLBACK_COMPLETION_RECEIPT_INVALID",
                caught.exception.code,
            )

            receipt.previous_activation_id = ACTIVE_ID
            with (
                mock.patch(target, return_value=receipt),
                mock.patch.object(
                    self.installer,
                    "_committed_installer_layout_v2",
                    return_value=layout,
                ),
                mock.patch.object(
                    self.installer,
                    "_build_installer_receipt",
                    return_value=installer_receipt,
                ),
            ):
                with self.assertRaises(self.installer.InstallError) as caught:
                    self.installer._completed_rollback_operation_v2(
                        layout,
                        evidence=evidence,
                        current_installer_receipt=installer_receipt,
                    )
            self.assertEqual(
                "ROLLBACK_COMPLETION_RECEIPT_INVALID",
                caught.exception.code,
            )


if __name__ == "__main__":
    unittest.main()
