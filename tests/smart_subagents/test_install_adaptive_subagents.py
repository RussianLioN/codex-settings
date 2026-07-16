from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
INSTALLER_PATH = SCRIPTS / "install_adaptive_subagents.py"
ROLLBACK_PATH = SCRIPTS / "rollback_adaptive_subagents.py"
LEGACY_HIGHFD = (
    REPO
    / "tests"
    / "smart_subagents"
    / "fixtures"
    / "codex-highfd-legacy"
)


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class MarketplaceContractTests(unittest.TestCase):
    def test_repo_marketplace_exposes_the_bundled_plugin(self) -> None:
        path = REPO / ".agents" / "plugins" / "marketplace.json"
        document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual("codex-settings-adaptive", document["name"])
        self.assertEqual(
            {"displayName": "Адаптивные субагенты Codex"},
            document["interface"],
        )
        self.assertEqual(1, len(document["plugins"]))
        plugin = document["plugins"][0]
        self.assertEqual("codex-smart-subagents", plugin["name"])
        self.assertEqual(
            {
                "source": "local",
                "path": "./plugins/codex-smart-subagents",
            },
            plugin["source"],
        )
        self.assertEqual(
            {
                "installation": "AVAILABLE",
                "authentication": "ON_INSTALL",
            },
            plugin["policy"],
        )

    def test_operator_documents_keep_installation_disabled_by_default(self) -> None:
        documents = {
            "plugin": (
                REPO / "plugins" / "codex-smart-subagents" / "README.md"
            ),
            "runbook": (
                REPO
                / "docs"
                / "runbooks"
                / "adaptive-subagents-v2-operations.md"
            ),
            "migration": (
                REPO
                / "docs"
                / "migrations"
                / "adaptive-subagents-v2.md"
            ),
        }
        for path in documents.values():
            self.assertTrue(path.is_file(), path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("CODEX_SMART_ENABLED=1", text)
            self.assertIn(
                "codex-smart-subagents-admin rollback --dry-run",
                text,
            )
            self.assertIn(
                "codex-smart-subagents-admin rollback --apply",
                text,
            )
            self.assertIn("rollback_adaptive_subagents.py", text)
        runbook = documents["runbook"].read_text(encoding="utf-8")
        self.assertIn("по умолчанию выключен", runbook)
        self.assertIn("--doctor", runbook)
        self.assertIn("--smoke", runbook)
        self.assertIn("Codex 0.144.4", runbook)
        self.assertIn("AWAITING_HOOK_TRUST", runbook)
        self.assertIn("CODEX_SQLITE_HOME", runbook)
        self.assertIn("models_cache.json", runbook)
        self.assertIn("/hooks", runbook)
        for command in (
            "explain ROUTE_ID",
            "report ROUTE_ID",
            "metrics",
            "recover --dry-run",
            "recover --apply",
        ):
            self.assertIn(command, runbook)
        for path in documents.values():
            self.assertNotIn(
                "--dangerously-bypass-hook-trust",
                path.read_text(encoding="utf-8"),
            )


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_script(
            "install_adaptive_subagents_under_test",
            INSTALLER_PATH,
        )
        sys.modules["install_adaptive_subagents"] = cls.installer
        cls.rollback = load_script(
            "rollback_adaptive_subagents_under_test",
            ROLLBACK_PATH,
        )

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(mode=0o700)
        self.fake_codex = self.root / "codex"
        self.fake_codex.write_text(
            (REPO / "tests" / "smart_subagents" / "test_install_fake_codex.py")
            .read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.fake_codex.chmod(0o700)
        self.layout = self.installer.InstallLayout(
            source_root=REPO.resolve(),
            codex_home=self.codex_home.resolve(),
            bin_dir=self.bin_dir.resolve(),
            codex_binary=self.fake_codex.resolve(),
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write_hook_configuration(self, document: object) -> Path:
        path = self.codex_home / "fake-hook-state.json"
        path.write_text(
            json.dumps(document, separators=(",", ":")),
            encoding="utf-8",
        )
        return path

    def test_dry_run_does_not_create_installation_artifacts(self) -> None:
        result = self.installer.install(self.layout, apply=False)

        self.assertEqual("planned", result["status"])
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())
        self.assertFalse(self.layout.launcher_path.exists())

    def test_apply_installs_owned_files_and_manifest_atomically(self) -> None:
        original = "[projects.\"/tmp/example\"]\ntrust_level = \"trusted\"\n"
        self.layout.config_path.write_text(original, encoding="utf-8")

        result = self.installer.install(self.layout, apply=True)

        self.assertEqual("installed", result["status"])
        manifest = json.loads(
            self.layout.manifest_path.read_text(encoding="utf-8")
        )
        self.assertEqual(1, manifest["schemaVersion"])
        self.assertEqual(
            "codex-smart-subagents@codex-settings-adaptive",
            manifest["pluginId"],
        )
        self.assertTrue(Path(manifest["backup"]["directory"]).is_dir())
        self.assertEqual(
            original,
            Path(manifest["backup"]["config"]).read_text(encoding="utf-8"),
        )
        self.assertEqual(
            0o600,
            stat.S_IMODE(self.layout.manifest_path.stat().st_mode),
        )
        self.assertTrue(self.layout.launcher_path.is_symlink())
        self.assertTrue(self.layout.launcher_path.resolve().is_file())
        self.assertTrue(self.layout.admin_path.is_symlink())
        self.assertEqual(
            self.layout.admin_target,
            self.layout.admin_path.resolve(),
        )
        self.assertEqual(
            self.layout.highfd_source.read_bytes(),
            self.layout.highfd_path.read_bytes(),
        )
        self.assertEqual(
            0o755,
            stat.S_IMODE(self.layout.highfd_path.stat().st_mode),
        )
        self.assertEqual(
            self.layout.catalog_source.read_bytes(),
            self.layout.catalog_path.read_bytes(),
        )
        self.assertEqual(
            self.layout.marketplace_source.read_bytes(),
            self.layout.marketplace_path.read_bytes(),
        )
        self.assertEqual(
            Path(".agents/plugins/marketplace.json"),
            self.layout.marketplace_path.relative_to(
                self.layout.marketplace_root
            ),
        )
        self.assertNotEqual(
            original,
            self.layout.config_path.read_text(encoding="utf-8"),
        )

        diagnosis = self.installer.doctor(self.layout)
        self.assertTrue(diagnosis["ok"])
        self.assertEqual([], diagnosis["problems"])

    def test_repeated_apply_is_idempotent(self) -> None:
        first = self.installer.install(self.layout, apply=True)
        first_manifest = self.layout.manifest_path.read_bytes()
        first_backups = sorted(self.layout.backups_root.iterdir())

        second = self.installer.install(self.layout, apply=True)

        self.assertEqual("installed", first["status"])
        self.assertEqual("unchanged", second["status"])
        self.assertEqual(
            first_manifest,
            self.layout.manifest_path.read_bytes(),
        )
        self.assertEqual(first_backups, sorted(self.layout.backups_root.iterdir()))

    def test_symlinked_codex_binary_is_canonical_in_manifest_and_rollback(
        self,
    ) -> None:
        link = self.root / "codex-link"
        link.symlink_to(self.fake_codex)
        layout = self.installer.InstallLayout(
            source_root=self.layout.source_root,
            codex_home=self.layout.codex_home,
            bin_dir=self.layout.bin_dir,
            codex_binary=link,
        )

        self.installer.install(layout, apply=True)
        manifest = json.loads(
            layout.manifest_path.read_text(encoding="utf-8")
        )

        self.assertEqual(
            str(self.fake_codex.resolve()),
            manifest["codexBinary"],
        )
        context = self.rollback.RollbackContext.from_installation(
            codex_home=layout.codex_home,
            codex_binary=link,
            state_home=(self.root / "state-home").resolve(),
        )
        preflight = self.rollback.probe_rollback_preflight(context)
        result = self.rollback.apply_rollback(
            context,
            preflight=preflight,
        )
        self.assertEqual("rolled_back", result["status"])

    def test_unknown_launcher_is_never_overwritten(self) -> None:
        self.layout.launcher_path.write_text("foreign\n", encoding="utf-8")

        with self.assertRaisesRegex(
            self.installer.InstallError,
            "TARGET_OWNERSHIP_CONFLICT",
        ):
            self.installer.install(self.layout, apply=True)

        self.assertEqual(
            "foreign\n",
            self.layout.launcher_path.read_text(encoding="utf-8"),
        )
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())

    def test_unknown_admin_command_is_never_overwritten(self) -> None:
        self.layout.admin_path.write_text("foreign\n", encoding="utf-8")

        with self.assertRaisesRegex(
            self.installer.InstallError,
            "TARGET_OWNERSHIP_CONFLICT",
        ):
            self.installer.install(self.layout, apply=True)

        self.assertEqual(
            "foreign\n",
            self.layout.admin_path.read_text(encoding="utf-8"),
        )
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())

    def test_installation_lock_never_follows_a_symbolic_link(self) -> None:
        foreign = self.root / "foreign-lock-target"
        foreign.write_text("keep\n", encoding="utf-8")
        self.layout.manifest_root.mkdir(mode=0o700)
        self.layout.lock_path.symlink_to(foreign)

        with self.assertRaisesRegex(
            self.installer.InstallError,
            "UNSAFE_INSTALL_LOCK",
        ):
            self.installer.install(self.layout, apply=True)

        self.assertEqual("keep\n", foreign.read_text(encoding="utf-8"))
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())

    def test_failed_install_never_deletes_a_racing_foreign_link(self) -> None:
        foreign_target = self.root / "foreign-launcher-target"
        foreign_target.write_text("keep\n", encoding="utf-8")

        def race(_layout: object) -> None:
            self.layout.launcher_path.symlink_to(foreign_target)
            raise self.installer.InstallError(
                "TARGET_OWNERSHIP_CONFLICT",
                "synthetic launcher race",
            )

        with mock.patch.object(
            self.installer,
            "_install_launcher",
            side_effect=race,
        ):
            with self.assertRaisesRegex(
                self.installer.InstallError,
                "TARGET_OWNERSHIP_CONFLICT",
            ):
                self.installer.install(self.layout, apply=True)

        self.assertTrue(self.layout.launcher_path.is_symlink())
        self.assertEqual(
            foreign_target.resolve(),
            self.layout.launcher_path.resolve(),
        )
        self.assertEqual(
            "keep\n",
            foreign_target.read_text(encoding="utf-8"),
        )
        self.assertFalse(self.layout.owned_root.exists())
        self.assertFalse(self.layout.manifest_path.exists())

    def test_failed_install_preserves_concurrent_config_changes(self) -> None:
        original = "[features]\nplugins = true\n"
        concurrent = "\n[projects.\"/tmp/new\"]\ntrust_level = \"trusted\"\n"
        self.layout.config_path.write_text(original, encoding="utf-8")

        def race(_layout: object) -> None:
            with self.layout.config_path.open("a", encoding="utf-8") as stream:
                stream.write(concurrent)
            raise self.installer.InstallError(
                "TARGET_OWNERSHIP_CONFLICT",
                "synthetic config race",
            )

        with mock.patch.object(
            self.installer,
            "_install_launcher",
            side_effect=race,
        ):
            with self.assertRaisesRegex(
                self.installer.InstallError,
                "CONFIG_CHANGED_DURING_CLEANUP",
            ):
                self.installer.install(self.layout, apply=True)

        current = self.layout.config_path.read_text(encoding="utf-8")
        self.assertEqual(original + concurrent, current)
        self.assertFalse(self.layout.owned_root.exists())
        self.assertFalse(self.layout.manifest_path.exists())

    def test_failed_cli_operation_restores_original_config_and_owned_paths(self) -> None:
        original = "[features]\nplugins = true\n"
        self.layout.config_path.write_text(original, encoding="utf-8")
        environment = {"FAKE_CODEX_FAIL_PLUGIN_ADD": "1"}

        with self.assertRaisesRegex(
            self.installer.InstallError,
            "CODEX_PLUGIN_ADD_FAILED",
        ):
            self.installer.install(
                self.layout,
                apply=True,
                extra_environment=environment,
            )

        self.assertEqual(
            original,
            self.layout.config_path.read_text(encoding="utf-8"),
        )
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())
        self.assertFalse(self.layout.launcher_path.exists())

    def test_doctor_detects_tampering_without_repairing_it(self) -> None:
        self.installer.install(self.layout, apply=True)
        self.layout.catalog_path.chmod(0o600)
        self.layout.catalog_path.write_text("tampered\n", encoding="utf-8")

        diagnosis = self.installer.doctor(self.layout)

        self.assertFalse(diagnosis["ok"])
        self.assertTrue(
            any(
                problem["code"] == "ARTIFACT_FINGERPRINT_MISMATCH"
                for problem in diagnosis["problems"]
            )
        )
        self.assertEqual(
            "tampered\n",
            self.layout.catalog_path.read_text(encoding="utf-8"),
        )

    def test_doctor_rejects_an_unsafe_install_manifest(self) -> None:
        self.installer.install(self.layout, apply=True)
        self.layout.manifest_path.chmod(0o644)

        diagnosis = self.installer.doctor(self.layout)

        self.assertFalse(diagnosis["ok"])
        self.assertEqual("BROKEN", diagnosis["status"])
        self.assertEqual(
            "INSTALL_MANIFEST_UNSAFE",
            diagnosis["problems"][0]["code"],
        )

    def test_smoke_checks_launcher_and_four_mcp_tools(self) -> None:
        self.installer.install(self.layout, apply=True)

        result = self.installer.smoke(self.layout)

        self.assertTrue(result["ok"])
        self.assertEqual("READY", result["status"])
        self.assertEqual(
            [
                "smart_plan",
                "smart_start",
                "smart_wait",
                "smart_cancel",
            ],
            result["tools"],
        )
        self.assertEqual("codex-cli 0.144.4", result["launcherVersion"])
        self.assertEqual(
            "codex-cli 0.144.4",
            result["highfdLauncherVersion"],
        )
        self.assertTrue(self.installer.doctor(self.layout)["ok"])

    def test_doctor_waits_for_both_hook_trust_decisions_without_mutation(
        self,
    ) -> None:
        hook_state = {
            "trustStatuses": {
                "userPromptSubmit": "untrusted",
                "stop": "modified",
            }
        }
        path = self.write_hook_configuration(hook_state)
        before = path.read_bytes()

        installed = self.installer.install(self.layout, apply=True)
        diagnosis = self.installer.doctor(self.layout)

        self.assertEqual("installed", installed["status"])
        self.assertEqual("AWAITING_HOOK_TRUST", installed["readiness"])
        self.assertFalse(diagnosis["ok"])
        self.assertEqual("AWAITING_HOOK_TRUST", diagnosis["status"])
        self.assertEqual(
            {
                "userPromptSubmit": "untrusted",
                "stop": "modified",
            },
            {
                hook["eventName"]: hook["trustStatus"]
                for hook in diagnosis["hookTrust"]
            },
        )
        self.assertTrue(
            all(not hook["ready"] for hook in diagnosis["hookTrust"])
        )
        self.assertEqual(before, path.read_bytes())

    def test_doctor_keeps_codex_state_database_outside_codex_home(
        self,
    ) -> None:
        self.installer.install(self.layout, apply=True)
        database = self.layout.codex_home / "state_5.sqlite"
        database.write_bytes(b"existing-state")
        database.chmod(0o600)

        diagnosis = self.installer.doctor(self.layout)

        self.assertTrue(diagnosis["ok"])
        self.assertEqual(b"existing-state", database.read_bytes())
        self.assertFalse(
            (self.layout.codex_home / "state_5.sqlite-shm").exists()
        )
        self.assertFalse(
            (self.layout.codex_home / "state_5.sqlite-wal").exists()
        )

    def test_doctor_requires_an_exact_complete_plugin_hook_list(self) -> None:
        self.installer.install(self.layout, apply=True)
        self.write_hook_configuration({"events": ["userPromptSubmit"]})

        diagnosis = self.installer.doctor(self.layout)

        self.assertFalse(diagnosis["ok"])
        self.assertEqual("HOOK_DISCOVERY_INCOMPLETE", diagnosis["status"])
        self.assertTrue(
            any(
                problem["code"] == "HOOK_LIST_INCOMPLETE"
                for problem in diagnosis["problems"]
            )
        )

    def test_doctor_rejects_malformed_hook_discovery_as_broken(self) -> None:
        self.installer.install(self.layout, apply=True)
        self.write_hook_configuration({"responseMode": "malformed"})

        diagnosis = self.installer.doctor(self.layout)

        self.assertFalse(diagnosis["ok"])
        self.assertEqual("BROKEN", diagnosis["status"])
        self.assertTrue(
            any(
                problem["code"] == "HOOK_DISCOVERY_INVALID"
                for problem in diagnosis["problems"]
            )
        )

    def test_smoke_stops_before_runtime_when_hook_trust_is_pending(self) -> None:
        self.installer.install(self.layout, apply=True)
        self.write_hook_configuration(
            {
                "trustStatuses": {
                    "userPromptSubmit": "untrusted",
                    "stop": "managed",
                }
            }
        )
        smoke_state = self.codex_home / "adaptive-subagents-smoke-state"

        result = self.installer.smoke(self.layout)

        self.assertFalse(result["ok"])
        self.assertEqual("AWAITING_HOOK_TRUST", result["status"])
        self.assertFalse(smoke_state.exists())
        self.assertEqual([], result["tools"])

    def test_trusted_and_managed_hooks_are_ready(self) -> None:
        self.write_hook_configuration(
            {
                "trustStatuses": {
                    "userPromptSubmit": "trusted",
                    "stop": "managed",
                }
            }
        )

        self.installer.install(self.layout, apply=True)
        diagnosis = self.installer.doctor(self.layout)

        self.assertTrue(diagnosis["ok"])
        self.assertEqual("READY", diagnosis["status"])
        self.assertTrue(
            all(hook["ready"] for hook in diagnosis["hookTrust"])
        )

    def test_highfd_keeps_smart_mode_disabled_until_explicit_rollout(self) -> None:
        self.installer.install(self.layout, apply=True)
        probe = self.root / "smart-probe"
        probe.write_text(
            "#!/bin/sh\nprintf 'smart-enabled\\n'\n",
            encoding="utf-8",
        )
        probe.chmod(0o700)
        environment = {
            **os.environ,
            "CODEX_HOME": str(self.codex_home),
            "CODEX_REAL_BIN": str(self.fake_codex),
            "CODEX_SMART_LAUNCHER": str(probe),
            "CODEX_NOFILE_LIMIT": "64",
        }

        disabled = subprocess.run(
            [str(self.layout.highfd_path), "--version"],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        enabled = subprocess.run(
            [str(self.layout.highfd_path), "--version"],
            env={**environment, "CODEX_SMART_ENABLED": "1"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

        self.assertEqual("codex-cli 0.144.4", disabled.stdout.strip())
        self.assertEqual("smart-enabled", enabled.stdout.strip())

    def test_known_legacy_highfd_is_backed_up_replaced_and_restored(self) -> None:
        legacy = LEGACY_HIGHFD.read_bytes()
        self.layout.highfd_path.write_bytes(legacy)
        self.layout.highfd_path.chmod(0o755)

        self.installer.install(self.layout, apply=True)

        manifest = json.loads(
            self.layout.manifest_path.read_text(encoding="utf-8")
        )
        prior = manifest["backup"]["highfd"]
        self.assertTrue(prior["existed"])
        self.assertEqual(
            legacy,
            Path(prior["path"]).read_bytes(),
        )
        self.assertEqual(
            self.layout.highfd_source.read_bytes(),
            self.layout.highfd_path.read_bytes(),
        )

        self.rollback.rollback(self.layout, apply=True)

        self.assertEqual(legacy, self.layout.highfd_path.read_bytes())
        self.assertEqual(
            0o755,
            stat.S_IMODE(self.layout.highfd_path.stat().st_mode),
        )

    def test_unknown_highfd_is_never_overwritten(self) -> None:
        self.layout.highfd_path.write_text("foreign\n", encoding="utf-8")
        self.layout.highfd_path.chmod(0o755)

        with self.assertRaisesRegex(
            self.installer.InstallError,
            "TARGET_OWNERSHIP_CONFLICT",
        ):
            self.installer.install(self.layout, apply=True)

        self.assertEqual(
            "foreign\n",
            self.layout.highfd_path.read_text(encoding="utf-8"),
        )
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())

    def test_rollback_removes_only_verified_owned_artifacts(self) -> None:
        self.installer.install(self.layout, apply=True)
        foreign = self.codex_home / "foreign.txt"
        foreign.write_text("keep\n", encoding="utf-8")

        result = self.rollback.rollback(self.layout, apply=True)

        self.assertEqual("rolled_back", result["status"])
        self.assertEqual("keep\n", foreign.read_text(encoding="utf-8"))
        self.assertFalse(self.layout.manifest_path.exists())
        self.assertFalse(self.layout.owned_root.exists())
        self.assertFalse(self.layout.launcher_path.exists())
        self.assertFalse(self.layout.admin_path.exists())
        self.assertFalse(self.layout.highfd_path.exists())
        self.assertFalse(self.layout.config_path.exists())
        listed = subprocess.run(
            [str(self.fake_codex), "plugin", "list", "--json"],
            env={
                **os.environ,
                "CODEX_HOME": str(self.codex_home),
            },
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual([], json.loads(listed.stdout)["installed"])

    def test_rollback_refuses_to_delete_modified_owned_artifact(self) -> None:
        self.installer.install(self.layout, apply=True)
        self.layout.catalog_path.chmod(0o600)
        self.layout.catalog_path.write_text("foreign change\n", encoding="utf-8")

        with self.assertRaisesRegex(
            self.rollback.RollbackError,
            "ROLLBACK_OWNERSHIP_CONFLICT",
        ):
            self.rollback.rollback(self.layout, apply=True)

        self.assertTrue(self.layout.manifest_path.exists())
        self.assertTrue(self.layout.owned_root.exists())
        self.assertTrue(self.layout.launcher_path.exists())
        self.assertTrue(self.layout.highfd_path.exists())

    def test_rollback_refuses_before_removal_when_backup_is_damaged(
        self,
    ) -> None:
        self.installer.install(self.layout, apply=True)
        manifest = json.loads(
            self.layout.manifest_path.read_text(encoding="utf-8")
        )
        marker = Path(manifest["backup"]["directory"]) / "config.absent"
        marker.unlink()

        with self.assertRaisesRegex(
            self.rollback.RollbackError,
            "ROLLBACK_BACKUP_CONFLICT",
        ):
            self.rollback.rollback(self.layout, apply=True)

        self.assertTrue(self.layout.manifest_path.exists())
        self.assertTrue(self.layout.owned_root.exists())
        self.assertTrue(self.layout.launcher_path.exists())
        listed = subprocess.run(
            [str(self.fake_codex), "plugin", "list", "--json"],
            env={**os.environ, "CODEX_HOME": str(self.codex_home)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(
            1,
            len(json.loads(listed.stdout)["installed"]),
        )

    def test_failed_rollback_repairs_plugin_state_without_config_loss(
        self,
    ) -> None:
        original = "[features]\nplugins = true\n"
        self.layout.config_path.write_text(original, encoding="utf-8")
        self.installer.install(self.layout, apply=True)
        configured = self.layout.config_path.read_bytes()

        with self.assertRaisesRegex(
            self.rollback.RollbackError,
            "CODEX_MARKETPLACE_REMOVE_FAILED",
        ):
            self.rollback.rollback(
                self.layout,
                apply=True,
                extra_environment={
                    "FAKE_CODEX_FAIL_MARKETPLACE_REMOVE": "1",
                },
            )

        self.assertEqual(configured, self.layout.config_path.read_bytes())
        self.assertTrue(self.layout.manifest_path.exists())
        self.assertTrue(self.layout.owned_root.exists())
        plugin_list = subprocess.run(
            [str(self.fake_codex), "plugin", "list", "--json"],
            env={**os.environ, "CODEX_HOME": str(self.codex_home)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        market_list = subprocess.run(
            [
                str(self.fake_codex),
                "plugin",
                "marketplace",
                "list",
                "--json",
            ],
            env={**os.environ, "CODEX_HOME": str(self.codex_home)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual(
            1,
            len(json.loads(plugin_list.stdout)["installed"]),
        )
        self.assertEqual(
            1,
            len(json.loads(market_list.stdout)["marketplaces"]),
        )

    def test_common_rollback_module_preserves_runtime_state_and_backups(
        self,
    ) -> None:
        self.installer.install(self.layout, apply=True)
        state_home = self.root / "state-home"
        context = self.rollback.RollbackContext.from_installation(
            codex_home=self.codex_home.resolve(),
            codex_binary=self.fake_codex.resolve(),
            state_home=state_home.resolve(),
        )
        context.database_path.parent.mkdir(parents=True, mode=0o700)
        connection = sqlite3.connect(context.database_path)
        try:
            connection.execute("create table routes(state text not null)")
            connection.execute("create table attempts(state text not null)")
            connection.commit()
        finally:
            connection.close()
        context.database_path.chmod(0o600)
        database_before = context.database_path.read_bytes()
        context.quarantine_path.mkdir(parents=True, mode=0o700)
        quarantine_marker = context.quarantine_path / "preserve"
        quarantine_marker.write_text("keep\n", encoding="utf-8")
        backup_markers = sorted(context.backups_path.rglob("*"))
        preflight = self.rollback.RollbackPreflight(
            smart_mode_disabled=True,
            controller_stopped=True,
            active_routes=0,
            active_attempts=0,
        )

        plan = self.rollback.plan_rollback(
            context,
            preflight=preflight,
        )
        result = self.rollback.apply_rollback(
            context,
            preflight=preflight,
        )

        self.assertTrue(plan["ready"])
        self.assertEqual("rolled_back", result["status"])
        self.assertEqual(
            database_before,
            context.database_path.read_bytes(),
        )
        self.assertEqual(
            "keep\n",
            quarantine_marker.read_text(encoding="utf-8"),
        )
        self.assertEqual(backup_markers, sorted(context.backups_path.rglob("*")))
        self.assertFalse(context.manifest_path.exists())
        self.assertFalse(context.owned_root.exists())
        self.assertFalse(context.launcher_path.exists())

    def test_common_rollback_module_requires_external_preflight(self) -> None:
        self.installer.install(self.layout, apply=True)
        context = self.rollback.RollbackContext.from_installation(
            codex_home=self.codex_home.resolve(),
            codex_binary=self.fake_codex.resolve(),
            state_home=(self.root / "state-home").resolve(),
        )
        blocked = self.rollback.RollbackPreflight(
            smart_mode_disabled=True,
            controller_stopped=False,
            active_routes=0,
            active_attempts=0,
            blockers=("CONTROLLER_ACTIVE",),
        )

        with self.assertRaisesRegex(
            self.rollback.RollbackError,
            "ROLLBACK_PREFLIGHT_REQUIRED",
        ):
            self.rollback.apply_rollback(
                context,
                preflight=blocked,
            )

        self.assertTrue(context.manifest_path.exists())
        self.assertTrue(context.owned_root.exists())
        self.assertTrue(context.launcher_path.exists())

    def test_common_rollback_never_follows_install_lock_symlink(self) -> None:
        self.installer.install(self.layout, apply=True)
        context = self.rollback.RollbackContext.from_installation(
            codex_home=self.codex_home.resolve(),
            codex_binary=self.fake_codex.resolve(),
            state_home=(self.root / "state-home").resolve(),
        )
        context.lock_path.unlink()
        foreign = self.root / "foreign-rollback-lock"
        foreign.write_text("keep\n", encoding="utf-8")
        context.lock_path.symlink_to(foreign)
        preflight = self.rollback.RollbackPreflight(
            smart_mode_disabled=True,
            controller_stopped=True,
            active_routes=0,
            active_attempts=0,
        )

        with self.assertRaisesRegex(
            self.rollback.RollbackError,
            "ROLLBACK_UNSAFE_INSTALL_LOCK",
        ):
            self.rollback.apply_rollback(
                context,
                preflight=preflight,
            )

        self.assertEqual("keep\n", foreign.read_text(encoding="utf-8"))
        self.assertTrue(context.manifest_path.exists())
        self.assertTrue(context.owned_root.exists())

    def test_common_rollback_apply_closes_controller_start_race(self) -> None:
        self.installer.install(self.layout, apply=True)
        context = self.rollback.RollbackContext.from_installation(
            codex_home=self.codex_home.resolve(),
            codex_binary=self.fake_codex.resolve(),
            state_home=(self.root / "state-home").resolve(),
        )
        preflight = self.rollback.probe_rollback_preflight(
            context,
            environment={"CODEX_SMART_ENABLED": "0"},
        )
        self.assertTrue(preflight.ready)
        context.runtime_paths.run_dir.mkdir(parents=True, mode=0o700)
        descriptor = os.open(
            context.runtime_paths.lock_path,
            os.O_RDWR | os.O_CREAT,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaisesRegex(
                self.rollback.RollbackError,
                "ROLLBACK_CONTROLLER_ACTIVE",
            ):
                self.rollback.apply_rollback(
                    context,
                    preflight=preflight,
                    extra_environment={"CODEX_SMART_ENABLED": "0"},
                )
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertTrue(context.manifest_path.exists())
        self.assertTrue(context.owned_root.exists())
        self.assertTrue(context.launcher_path.exists())
        self.assertTrue(context.admin_path.exists())

    def test_common_rollback_rechecks_routes_attempts_and_smart_flag(
        self,
    ) -> None:
        for scenario in ("active-state", "smart-enabled"):
            with self.subTest(scenario=scenario):
                self.installer.install(self.layout, apply=True)
                state_home = self.root / f"state-{scenario}"
                context = self.rollback.RollbackContext.from_installation(
                    codex_home=self.codex_home.resolve(),
                    codex_binary=self.fake_codex.resolve(),
                    state_home=state_home.resolve(),
                )
                preflight = self.rollback.probe_rollback_preflight(
                    context,
                    environment={"CODEX_SMART_ENABLED": "0"},
                )
                self.assertTrue(preflight.ready)
                environment = {"CODEX_SMART_ENABLED": "0"}
                expected = "ACTIVE_ROUTES"
                if scenario == "active-state":
                    context.database_path.parent.mkdir(
                        parents=True,
                        mode=0o700,
                    )
                    connection = sqlite3.connect(context.database_path)
                    try:
                        connection.execute(
                            "create table routes(state text not null)"
                        )
                        connection.execute(
                            "create table attempts(state text not null)"
                        )
                        connection.execute(
                            "insert into routes(state) values ('RUNNING')"
                        )
                        connection.execute(
                            "insert into attempts(state) values ('RUNNING')"
                        )
                        connection.commit()
                    finally:
                        connection.close()
                    context.database_path.chmod(0o600)
                else:
                    environment["CODEX_SMART_ENABLED"] = "1"
                    expected = "SMART_MODE_ENABLED"

                with self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    f"ROLLBACK_PREFLIGHT_STALE.*{expected}",
                ):
                    self.rollback.apply_rollback(
                        context,
                        preflight=preflight,
                        extra_environment=environment,
                    )

                self.assertTrue(context.manifest_path.exists())
                self.assertTrue(context.owned_root.exists())
                if scenario == "active-state":
                    connection = sqlite3.connect(context.database_path)
                    try:
                        connection.execute(
                            "update routes set state = 'CANCELLED'"
                        )
                        connection.execute(
                            "update attempts set state = 'SUCCEEDED'"
                        )
                        connection.commit()
                    finally:
                        connection.close()
                self.rollback.rollback(
                    self.layout,
                    apply=True,
                    extra_environment={
                        "CODEX_SMART_ENABLED": "0",
                        "XDG_STATE_HOME": str(state_home),
                    },
                )

    def test_common_preflight_detects_enabled_mode_without_creating_state(
        self,
    ) -> None:
        self.installer.install(self.layout, apply=True)
        state_home = self.root / "state-home"
        context = self.rollback.RollbackContext.from_installation(
            codex_home=self.codex_home.resolve(),
            codex_binary=self.fake_codex.resolve(),
            state_home=state_home.resolve(),
        )

        preflight = self.rollback.probe_rollback_preflight(
            context,
            environment={"CODEX_SMART_ENABLED": "1"},
        )

        self.assertFalse(preflight.ready)
        self.assertFalse(preflight.smart_mode_disabled)
        self.assertIn("SMART_MODE_ENABLED", preflight.blockers)
        self.assertFalse(state_home.exists())


if __name__ == "__main__":
    unittest.main()
