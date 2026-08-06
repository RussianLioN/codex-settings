from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "apply_runtime_fd_guardrails.py"
SOURCE_DOCTOR = ROOT / "scripts" / "codex_fd_doctor.sh"
SOURCE_INVENTORY = ROOT / "scripts" / "codex_process_inventory.py"
SOURCE_POLICY = ROOT / "scripts" / "autonomous_policy.py"
SOURCE_CAPACITY = ROOT / "scripts" / "codex_capacity.py"
SOURCE_OBSERVER = ROOT / "scripts" / "codex_capacity_observer.py"
SOURCE_MANIFEST_VALIDATOR = ROOT / "scripts" / "validate_wide_wave_manifest.py"
SOURCE_TRUSTED_REGISTRY = ROOT / "config" / "trusted-wide-wave-skills.json"
ROLLBACK = ROOT / "scripts" / "codex_autonomous_rollback.py"
PROFILE_VALUES = {
    "batch-workers": 1,
    "deep-review": 4,
    "full-access": 4,
    "safe-readonly": 2,
    "small": 2,
    "standard": 4,
    "wide-readers-16": 16,
    "wide-readers": 8,
}


class RuntimeFdGuardrailInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir=ROOT,
            prefix=".runtime-fd-guardrails-",
        )
        self.root = Path(self.temporary.name)
        self.codex_home = self.root / ".codex"
        self.codex_home.mkdir()
        self.config = self.codex_home / "config.toml"
        self.agents = self.codex_home / "AGENTS.md"
        self.installed_doctor = self.root / "libexec" / "codex_fd_doctor.sh"
        self.installed_inventory = self.root / "libexec" / "codex_process_inventory.py"
        self.hooks_json = self.codex_home / "hooks.json"
        self.installed_policy = self.codex_home / "hooks" / "autonomous_policy.py"
        self.installed_capacity = self.codex_home / "hooks" / "codex_capacity.py"
        self.installed_observer = self.codex_home / "hooks" / "codex_capacity_observer.py"
        self.installed_doctor.parent.mkdir()
        self.installed_policy.parent.mkdir()
        self.config.write_text(
            """approval_policy = "on-request"

[agents]
max_threads = 1000
max_depth = 1
job_max_runtime_seconds = 1800

[features.multi_agent_v2]
enabled = true
max_concurrent_threads_per_session = 1000
""",
            encoding="utf-8",
        )
        self.agents.write_text(
            "# AGENTS.md\n\n## Ожидание субагентов\n\n- Существующее правило.\n",
            encoding="utf-8",
        )
        self.installed_doctor.write_text("old doctor\n", encoding="utf-8")
        self.hooks_json.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {"hooks": [{"type": "command", "command": "echo unrelated", "timeout": 9}]},
                            {"hooks": [{"type": "command", "command": f"python {self.installed_policy.parent / 'old' / 'autonomous_policy.py'} PreToolUse", "timeout": 10}]},
                            {
                                "matcher": "mixed",
                                "hooks": [
                                    {"type": "command", "command": "echo keep-me", "timeout": 4},
                                    {"type": "command", "command": f"python {self.installed_policy.parent / 'old' / 'autonomous_policy.py'} PreToolUse", "timeout": 10},
                                    {"type": "command", "command": "echo keep-two", "timeout": 5},
                                ],
                            },
                        ],
                        "Stop": [
                            {"hooks": [{"type": "command", "command": "echo stop", "timeout": 2}]}
                        ],
                    }
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.installed_policy.write_text("old policy\n", encoding="utf-8")
        self.write_valid_profiles()
        self.create_source_repo()

    def write_valid_profiles(self) -> None:
        for profile_name, value in PROFILE_VALUES.items():
            (self.codex_home / f"{profile_name}.config.toml").write_text(
                f"""model = "gpt-5"

[agents]
max_threads = {value}
max_depth = 1
""",
                encoding="utf-8",
            )

    def create_source_repo(self) -> None:
        self.source_repo = self.root / "source-repo"
        self.source_repo.mkdir()
        source_files = {
            "scripts/codex_fd_doctor.sh": SOURCE_DOCTOR,
            "scripts/codex_process_inventory.py": SOURCE_INVENTORY,
            "scripts/autonomous_policy.py": SOURCE_POLICY,
            "scripts/codex_capacity.py": SOURCE_CAPACITY,
            "scripts/codex_capacity_observer.py": SOURCE_OBSERVER,
            "scripts/validate_wide_wave_manifest.py": SOURCE_MANIFEST_VALIDATOR,
            "config/trusted-wide-wave-skills.json": SOURCE_TRUSTED_REGISTRY,
        }
        for relative, source in source_files.items():
            destination = self.source_repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        self.git_source("init")
        self.git_source("config", "user.email", "codex-tests@example.invalid")
        self.git_source("config", "user.name", "Codex Tests")
        self.git_source("add", ".")
        self.git_source("commit", "-m", "source fixture")
        self.source_commit = self.git_source("rev-parse", "HEAD").stdout.strip()
        self.source_doctor = self.source_repo / "scripts" / "codex_fd_doctor.sh"
        self.source_inventory = self.source_repo / "scripts" / "codex_process_inventory.py"
        self.source_policy = self.source_repo / "scripts" / "autonomous_policy.py"
        self.source_capacity = self.source_repo / "scripts" / "codex_capacity.py"
        self.source_observer = self.source_repo / "scripts" / "codex_capacity_observer.py"
        self.source_manifest_validator = self.source_repo / "scripts" / "validate_wide_wave_manifest.py"
        self.source_trusted_registry = self.source_repo / "config" / "trusted-wide-wave-skills.json"

    def git_source(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.source_repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def expected_paths(self) -> dict[str, Path]:
        return {
            "config.toml": self.config,
            "AGENTS.md": self.agents,
            "codex_fd_doctor.sh": self.installed_doctor,
            "codex_process_inventory.py": self.installed_inventory,
            "validate_wide_wave_manifest.py": self.installed_doctor.parent / "validate_wide_wave_manifest.py",
            "trusted-wide-wave-skills.json": self.codex_home / "config" / "trusted-wide-wave-skills.json",
            "hooks.json": self.hooks_json,
            "autonomous_policy.py": self.installed_policy,
            "codex_capacity.py": self.installed_capacity,
            "codex_capacity_observer.py": self.installed_observer,
            **{
                f"{name}.config.toml": self.codex_home / f"{name}.config.toml"
                for name in PROFILE_VALUES
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_installer(
        self,
        *extra: str,
        codex_home: Path | str | None = None,
        installed_doctor: Path | str | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--codex-home",
                str(codex_home or self.codex_home),
                "--installed-doctor",
                str(installed_doctor or self.installed_doctor),
                "--source-doctor",
                str(self.source_doctor),
                "--installed-process-inventory",
                str(self.installed_inventory),
                "--source-process-inventory",
                str(self.source_inventory),
                "--source-autonomous-policy",
                str(self.source_policy),
                "--source-capacity",
                str(self.source_capacity),
                "--source-capacity-observer",
                str(self.source_observer),
                "--source-manifest-validator",
                str(self.source_manifest_validator),
                "--source-trusted-registry",
                str(self.source_trusted_registry),
                "--source-commit",
                self.source_commit,
                "--timestamp",
                "20260804-212800",
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )

    def test_check_reports_unsafe_state_without_writing(self) -> None:
        config_before = self.config.read_bytes()
        agents_before = self.agents.read_bytes()
        doctor_before = self.installed_doctor.read_bytes()

        completed = self.run_installer()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=BLOCK", completed.stdout)
        self.assertIn("agents_max_concurrent_threads_not_20", completed.stdout)
        self.assertIn("agents_max_threads_legacy_present", completed.stdout)
        self.assertIn("native_session_thread_cap_legacy_present", completed.stdout)
        self.assertIn("installation_receipt_v2_missing", completed.stdout)
        self.assertEqual(config_before, self.config.read_bytes())
        self.assertEqual(agents_before, self.agents.read_bytes())
        self.assertEqual(doctor_before, self.installed_doctor.read_bytes())

    def test_check_reports_dirty_tracked_managed_source_without_writing(self) -> None:
        config_before = self.config.read_bytes()
        capacity_before = self.source_capacity.read_bytes()
        self.source_capacity.write_bytes(capacity_before + b"\n# dirty source\n")

        completed = self.run_installer()

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=BLOCK", completed.stdout)
        self.assertIn("managed_source_status_dirty:codex_capacity.py", completed.stdout)
        self.assertIn("managed_source_drifted:codex_capacity.py", completed.stdout)
        self.assertEqual(config_before, self.config.read_bytes())

    def test_apply_rejects_dirty_tracked_managed_source_before_backup(self) -> None:
        capacity_before = self.source_capacity.read_bytes()
        self.source_capacity.write_bytes(capacity_before + b"\n# dirty source\n")

        completed = self.run_installer("--apply")

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("managed_source_drifted:codex_capacity.py", completed.stdout)
        self.assertFalse((self.codex_home / "backups" / "fd-guardrails-20260804-212800").exists())
        config = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(1000, config["agents"]["max_threads"])

    def test_dirty_managed_source_blocks_legacy_backup_migration_before_move(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        legacy = self.codex_home / "backups" / "runtime-fd-20260804-2128"
        legacy.mkdir()
        (legacy / "config.toml").write_text("sensitive\n", encoding="utf-8")
        (legacy / "AGENTS.md").write_text("policy\n", encoding="utf-8")
        self.source_capacity.write_bytes(self.source_capacity.read_bytes() + b"\n# dirty source\n")

        completed = self.run_installer(
            "--apply",
            "--migrate-legacy-backup",
            "20260804-2128",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("managed_source_drifted:codex_capacity.py", completed.stdout)
        self.assertTrue(legacy.is_dir())
        self.assertFalse((self.codex_home / "backups" / "fd-guardrails-20260804-2128").exists())

    def test_apply_allows_unrelated_dirty_source_repo_file(self) -> None:
        unrelated = self.source_repo / "unrelated.txt"
        unrelated.write_text("tracked\n", encoding="utf-8")
        self.git_source("add", "unrelated.txt")
        self.git_source("commit", "-m", "add unrelated")
        unrelated.write_text("tracked\ndirty\n", encoding="utf-8")

        completed = self.run_installer("--apply")

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=APPLIED", completed.stdout)

    def test_rejects_untracked_managed_source(self) -> None:
        untracked_capacity = self.source_repo / "scripts" / "untracked_capacity.py"
        untracked_capacity.write_text("print('untracked')\n", encoding="utf-8")

        completed = self.run_installer(
            "--apply",
            "--source-capacity",
            str(untracked_capacity),
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("managed_source_untracked:codex_capacity.py", completed.stdout)
        self.assertFalse((self.codex_home / "backups" / "fd-guardrails-20260804-212800").exists())

    def test_apply_preserves_commented_table_headers(self) -> None:
        self.config.write_text(
            """approval_policy = "on-request"

[agents] # общие пределы
max_threads = 1000
max_depth = 1

[features.multi_agent_v2] # нативное дерево
enabled = true
max_concurrent_threads_per_session = 1000
""",
            encoding="utf-8",
        )

        completed = self.run_installer("--apply")

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        repaired_text = self.config.read_text(encoding="utf-8")
        repaired = tomllib.loads(repaired_text)
        self.assertEqual(20, repaired["agents"]["max_concurrent_threads_per_session"])
        self.assertNotIn("max_threads", repaired["agents"])
        self.assertTrue(repaired["features"]["multi_agent_v2"]["enabled"])
        self.assertNotIn(
            "max_concurrent_threads_per_session",
            repaired["features"]["multi_agent_v2"],
        )
        self.assertEqual(1, repaired_text.count("[agents]"))
        self.assertEqual(1, repaired_text.count("[features.multi_agent_v2]"))

    def test_apply_backs_up_repairs_and_rechecks_all_owned_files(self) -> None:
        completed = self.run_installer("--apply")

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=APPLIED", completed.stdout)
        self.assertIn("next_action=Откройте /hooks и подтвердите изменённые hooks", completed.stdout)
        config = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(20, config["agents"]["max_concurrent_threads_per_session"])
        self.assertNotIn("max_threads", config["agents"])
        self.assertTrue(config["features"]["multi_agent_v2"]["enabled"])
        self.assertNotIn(
            "max_concurrent_threads_per_session",
            config["features"]["multi_agent_v2"],
        )
        agents = self.agents.read_text(encoding="utf-8")
        self.assertIn("не более 6 живых субагентов", agents)
        self.assertIn("`BLOCK` запрещает новые запуски", agents)
        self.assertIn("доверенной широкой волны 7-20", agents)
        self.assertIn("--skill-id ID --skill-file PATH --manifest PATH", agents)
        self.assertIn("роли широкой волны не запускают вложенное делегирование", agents)
        self.assertIn("20 узлов умного графа маршрутизатора", agents)
        self.assertIn("один интегратор для общих или генерируемых файлов", agents)
        self.assertEqual(self.source_doctor.read_bytes(), self.installed_doctor.read_bytes())
        self.assertEqual(self.source_inventory.read_bytes(), self.installed_inventory.read_bytes())
        self.assertEqual(self.source_policy.read_bytes(), self.installed_policy.read_bytes())
        self.assertEqual(self.source_capacity.read_bytes(), self.installed_capacity.read_bytes())
        self.assertEqual(self.source_observer.read_bytes(), self.installed_observer.read_bytes())
        for profile_name, value in PROFILE_VALUES.items():
            profile_text = (self.codex_home / f"{profile_name}.config.toml").read_text(encoding="utf-8")
            profile = tomllib.loads(profile_text)
            self.assertEqual(value, profile["agents"]["max_concurrent_threads_per_session"])
            self.assertNotIn("max_threads", profile["agents"])
            self.assertEqual(1, profile["agents"]["max_depth"])
        self.assertTrue((self.installed_doctor.parent / "validate_wide_wave_manifest.py").is_file())
        self.assertTrue((self.codex_home / "config" / "trusted-wide-wave-skills.json").is_file())
        hooks = json.loads(self.hooks_json.read_text(encoding="utf-8"))["hooks"]
        self.assertIn("SessionEnd", hooks)
        self.assertEqual("echo unrelated", hooks["PreToolUse"][0]["hooks"][0]["command"])
        self.assertEqual("echo stop", hooks["Stop"][0]["hooks"][0]["command"])
        self.assertEqual(3, len(hooks["PreToolUse"]))
        self.assertEqual(2, len(hooks["Stop"]))
        self.assertEqual(
            ["echo keep-me", "echo keep-two"],
            [hook["command"] for hook in hooks["PreToolUse"][2]["hooks"]],
        )
        for event in ("PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop", "Stop", "SessionEnd"):
            managed = [entry for entry in hooks[event] if "autonomous_policy.py" in entry["hooks"][0]["command"]]
            self.assertEqual(1, len(managed), event)
            self.assertIn(str(self.installed_policy), managed[0]["hooks"][0]["command"])
        self.assertEqual(1, hooks["PreToolUse"][1]["hooks"][0]["timeout"])
        self.assertEqual(3, hooks["SessionEnd"][-1]["hooks"][0]["timeout"])

        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        self.assertFalse(list((self.codex_home / "backups").glob("runtime-fd-*")))
        self.assertEqual(0o700, stat.S_IMODE(backup.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((backup / "config.toml").stat().st_mode))
        backup_config = tomllib.loads((backup / "config.toml").read_text())
        self.assertEqual(1000, backup_config["agents"]["max_threads"])
        self.assertEqual(1000, backup_config["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"])
        self.assertEqual("old doctor\n", (backup / "codex_fd_doctor.sh").read_text())
        receipt = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(2, receipt["version"])
        self.assertEqual(self.source_commit, receipt["source_commit"])
        self.assertRegex(receipt["created_at"], r"^20[0-9]{2}-")
        self.assertEqual(
            {
                "config.toml",
                "AGENTS.md",
                "codex_fd_doctor.sh",
                "codex_process_inventory.py",
                "validate_wide_wave_manifest.py",
                "trusted-wide-wave-skills.json",
                "hooks.json",
                "autonomous_policy.py",
                "codex_capacity.py",
                "codex_capacity_observer.py",
                *(f"{name}.config.toml" for name in PROFILE_VALUES),
            },
            {target["id"] for target in receipt["targets"]},
        )
        installed_entry = next(
            target
            for target in receipt["targets"]
            if target["id"] == "codex_process_inventory.py"
        )
        self.assertFalse(installed_entry["existed"])
        self.assertEqual(0o755, int(installed_entry["installed_mode"], 8))
        self.assertEqual(
            hashlib.sha256(self.source_inventory.read_bytes()).hexdigest(),
            installed_entry["installed_sha256"],
        )
        expected_paths = self.expected_paths()
        for target in receipt["targets"]:
            installed_path = expected_paths[target["id"]]
            self.assertEqual(str(installed_path.resolve(strict=False)), target["target_path"])
            self.assertEqual(
                hashlib.sha256(installed_path.read_bytes()).hexdigest(),
                target["installed_sha256"],
            )
            self.assertEqual(
                stat.S_IMODE(installed_path.stat().st_mode),
                int(target["installed_mode"], 8),
            )

        checked = self.run_installer()
        self.assertEqual(0, checked.returncode, checked.stdout + checked.stderr)
        self.assertIn("status=OK", checked.stdout)

    def test_repeat_apply_without_drift_does_not_create_new_backup(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)

        repeated = self.run_installer("--apply", "--timestamp", "20260804-212801")

        self.assertEqual(0, repeated.returncode, repeated.stdout + repeated.stderr)
        self.assertIn("status=OK", repeated.stdout)
        self.assertFalse((self.codex_home / "backups" / "fd-guardrails-20260804-212801").exists())

    def test_full_version_two_rollback_restores_hooks_and_removes_new_targets(self) -> None:
        original_hooks = self.hooks_json.read_bytes()
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        for path in self.expected_paths().values():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("mutated\n", encoding="utf-8")

        rollback = subprocess.run(
            [
                sys.executable,
                str(ROLLBACK),
                "--backup",
                str(backup),
                "--apply",
                "--codex-home",
                str(self.codex_home),
                "--installed-doctor",
                str(self.installed_doctor),
                "--installed-process-inventory",
                str(self.installed_inventory),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(0, rollback.returncode, rollback.stdout + rollback.stderr)
        self.assertEqual(original_hooks, self.hooks_json.read_bytes())
        self.assertEqual("old policy\n", self.installed_policy.read_text(encoding="utf-8"))
        self.assertFalse(self.installed_inventory.exists())
        self.assertFalse(self.installed_capacity.exists())
        self.assertFalse(self.installed_observer.exists())

    def test_legacy_runtime_cache_rollback_requires_explicit_confirmation(self) -> None:
        backup = self.root / "legacy-runtime-backup"
        backup.mkdir()

        rollback = subprocess.run(
            [sys.executable, str(ROLLBACK), "--backup", str(backup)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertNotEqual(0, rollback.returncode)
        self.assertIn("--legacy-runtime-cache-rollback", rollback.stderr)

    def test_apply_compensates_failures_on_new_runtime_targets(self) -> None:
        originals = {
            self.config: self.config.read_bytes(),
            self.agents: self.agents.read_bytes(),
            self.installed_doctor: self.installed_doctor.read_bytes(),
            self.hooks_json: self.hooks_json.read_bytes(),
            self.installed_policy: self.installed_policy.read_bytes(),
            **{
                self.codex_home / f"{name}.config.toml": (self.codex_home / f"{name}.config.toml").read_bytes()
                for name in PROFILE_VALUES
            },
        }
        absent = [
            self.installed_inventory,
            self.installed_doctor.parent / "validate_wide_wave_manifest.py",
            self.codex_home / "config" / "trusted-wide-wave-skills.json",
            self.installed_capacity,
            self.installed_observer,
        ]

        for index in range(1, len(self.expected_paths()) + 1):
            with self.subTest(index=index):
                completed = self.run_installer(
                    "--apply",
                    "--timestamp",
                    f"20260804-2128{index:02d}",
                    "--fail-after-atomic-write",
                    str(index),
                )
                self.assertNotEqual(0, completed.returncode)
                self.assertIn("automatic rollback applied", completed.stderr)
                for path, data in originals.items():
                    self.assertEqual(data, path.read_bytes(), path)
                for path in absent:
                    self.assertFalse(path.exists(), path)

    def test_rejects_symlink_and_hardlink_managed_targets(self) -> None:
        self.hooks_json.unlink()
        outside = self.root / "outside-hooks.json"
        outside.write_text("{}\n", encoding="utf-8")
        self.hooks_json.symlink_to(outside)

        symlink_result = self.run_installer("--apply")

        self.assertNotEqual(0, symlink_result.returncode)
        self.assertIn("managed target is a symlink", symlink_result.stderr)
        self.hooks_json.unlink()
        self.hooks_json.write_text("{}\n", encoding="utf-8")
        linked = self.root / "policy-hardlink.py"
        os.link(self.installed_policy, linked)

        hardlink_result = self.run_installer("--apply", "--timestamp", "20260804-212801")

        self.assertNotEqual(0, hardlink_result.returncode)
        self.assertIn("managed target hardlink count is unsafe", hardlink_result.stderr)

    def test_rejects_non_finite_hooks_json_before_writing(self) -> None:
        self.hooks_json.write_text('{"hooks":{"Stop":[]},"bad":NaN}\n', encoding="utf-8")
        before = self.hooks_json.read_bytes()

        completed = self.run_installer("--apply")

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("non-finite JSON value is unsupported: NaN", completed.stderr)
        self.assertEqual(before, self.hooks_json.read_bytes())

    def test_relative_codex_home_is_normalized_in_receipt_and_hook_command(self) -> None:
        completed = self.run_installer("--apply", codex_home=".codex", cwd=self.root)

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        receipt = json.loads(
            (self.codex_home / "backups" / "fd-guardrails-20260804-212800" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        target_paths = self.expected_paths()
        for target in receipt["targets"]:
            self.assertEqual(str(target_paths[target["id"]].resolve(strict=False)), target["target_path"])
            self.assertTrue(Path(target["target_path"]).is_absolute())
        hooks = json.loads(self.hooks_json.read_text(encoding="utf-8"))["hooks"]
        managed = [entry for entry in hooks["Stop"] if "autonomous_policy.py" in entry["hooks"][0]["command"]]
        self.assertEqual(1, len(managed))
        command = managed[0]["hooks"][0]["command"]
        self.assertIn(str(self.installed_policy.resolve(strict=False)), command)
        self.assertNotIn(" .codex/", command)

    def test_rejects_symlink_parent_inside_managed_tree(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        link_parent = self.root / "link-parent"
        link_parent.symlink_to(outside)

        completed = self.run_installer(
            "--apply",
            installed_doctor=link_parent / "codex_fd_doctor.sh",
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("managed target parent is a symlink", completed.stderr)
        self.assertFalse((outside / "codex_fd_doctor.sh").exists())

    def test_rejects_world_writable_parent_inside_managed_tree(self) -> None:
        bad_parent = self.root / "bad-parent"
        bad_parent.mkdir()
        bad_parent.chmod(0o777)
        try:
            completed = self.run_installer(
                "--apply",
                installed_doctor=bad_parent / "codex_fd_doctor.sh",
            )
        finally:
            bad_parent.chmod(0o700)

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("managed target parent permissions are unsafe", completed.stderr)
        self.assertFalse((bad_parent / "codex_fd_doctor.sh").exists())

    def test_rejects_symlink_backup_parent_before_creating_external_backup(self) -> None:
        outside = self.root / "outside-backups"
        outside.mkdir()
        backups = self.codex_home / "backups"
        backups.symlink_to(outside)

        completed = self.run_installer("--apply")

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("managed target parent is a symlink", completed.stderr)
        self.assertFalse(list(outside.glob("fd-guardrails-*")))

    def test_rejects_legacy_backup_migration_through_symlink_backup_root(self) -> None:
        outside = self.root / "outside-legacy-backups"
        outside.mkdir()
        legacy = outside / "runtime-fd-20260804-2128"
        legacy.mkdir()
        (legacy / "config.toml").write_text("sensitive\n", encoding="utf-8")
        (legacy / "AGENTS.md").write_text("policy\n", encoding="utf-8")
        (legacy / "codex_fd_doctor.sh").write_text("doctor\n", encoding="utf-8")
        backups = self.codex_home / "backups"
        backups.symlink_to(outside)

        completed = self.run_installer(
            "--apply",
            "--migrate-legacy-backup",
            "20260804-2128",
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("managed target parent is a symlink", completed.stderr)
        self.assertTrue(legacy.is_dir())
        self.assertEqual("sensitive\n", (legacy / "config.toml").read_text(encoding="utf-8"))
        self.assertFalse((outside / "fd-guardrails-20260804-2128").exists())

    def test_rejects_world_writable_backup_parent_before_creating_backup(self) -> None:
        backups = self.codex_home / "backups"
        backups.mkdir()
        backups.chmod(0o777)
        try:
            completed = self.run_installer("--apply")
        finally:
            backups.chmod(0o700)

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("managed target parent permissions are unsafe", completed.stderr)
        self.assertFalse(list(backups.glob("fd-guardrails-*")))

    def test_replaces_managed_hook_in_mixed_entry_without_reordering_handlers(self) -> None:
        self.hooks_json.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "mixed",
                                "hooks": [
                                    {"type": "command", "command": "echo keep-before", "timeout": 4},
                                    {"type": "command", "command": f"python {self.installed_policy.parent / 'old' / 'autonomous_policy.py'} PreToolUse", "timeout": 10},
                                    {"type": "command", "command": "echo keep-after", "timeout": 5},
                                ],
                            }
                        ]
                    }
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        completed = self.run_installer("--apply")

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        hooks = json.loads(self.hooks_json.read_text(encoding="utf-8"))["hooks"]
        mixed_hooks = hooks["PreToolUse"][0]["hooks"]
        self.assertEqual("echo keep-before", mixed_hooks[0]["command"])
        self.assertIn(str(self.installed_policy), mixed_hooks[1]["command"])
        self.assertEqual("echo keep-after", mixed_hooks[2]["command"])

    def test_does_not_treat_foreign_autonomous_policy_path_as_managed_hook(self) -> None:
        self.hooks_json.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": "/usr/bin/python3 /tmp/autonomous_policy.py PreToolUse",
                                        "timeout": 4,
                                    }
                                ]
                            }
                        ]
                    }
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        completed = self.run_installer("--apply")

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        hooks = json.loads(self.hooks_json.read_text(encoding="utf-8"))["hooks"]
        self.assertEqual(
            "/usr/bin/python3 /tmp/autonomous_policy.py PreToolUse",
            hooks["PreToolUse"][0]["hooks"][0]["command"],
        )
        managed = [
            hook
            for entry in hooks["PreToolUse"]
            for hook in entry["hooks"]
            if str(self.installed_policy) in hook.get("command", "")
        ]
        self.assertEqual(1, len(managed))

    def test_rejects_invalid_profile_caps_before_writing(self) -> None:
        scenarios = [
            (
                "small",
                """model = "gpt-5"

[agents]
max_concurrent_threads_per_session = 3
max_depth = 1
""",
                "small: agent thread cap must be 2",
            ),
            (
                "wide-readers",
                """model = "gpt-5"

[agents]
max_concurrent_threads_per_session = 20
max_depth = 1
""",
                "wide-readers: agent thread cap must be 8",
            ),
            ("standard", None, "required file is missing"),
            (
                "safe-readonly",
                """model = "gpt-5"

[agents]
max_threads = 2
max_concurrent_threads_per_session = 2
max_depth = 1
""",
                "safe-readonly: duplicate agent thread cap keys",
            ),
            (
                "batch-workers",
                """model = "gpt-5"

[agents]
max_concurrent_threads_per_session = "1"
max_depth = 1
""",
                "batch-workers: agent thread cap must be an integer",
            ),
            (
                "batch-workers",
                """model = "gpt-5"

[agents]
max_concurrent_threads_per_session = 0
max_depth = 1
""",
                "batch-workers: agent thread cap must be in 1..20",
            ),
        ]
        for index, (profile_name, profile_text, expected_error) in enumerate(scenarios, start=1):
            with self.subTest(profile_name=profile_name, expected_error=expected_error):
                self.write_valid_profiles()
                profile_path = self.codex_home / f"{profile_name}.config.toml"
                if profile_text is None:
                    profile_path.unlink()
                else:
                    profile_path.write_text(profile_text, encoding="utf-8")
                originals = {
                    self.config: self.config.read_bytes(),
                    self.agents: self.agents.read_bytes(),
                    self.installed_doctor: self.installed_doctor.read_bytes(),
                    self.hooks_json: self.hooks_json.read_bytes(),
                    self.installed_policy: self.installed_policy.read_bytes(),
                }

                completed = self.run_installer(
                    "--apply",
                    "--timestamp",
                    f"20260804-2129{index:02d}",
                )

                self.assertNotEqual(0, completed.returncode)
                self.assertIn(expected_error, completed.stdout + completed.stderr)
                self.assertFalse((self.codex_home / "backups" / f"fd-guardrails-20260804-2129{index:02d}").exists())
                for path, data in originals.items():
                    self.assertEqual(data, path.read_bytes(), path)

    def test_install_and_rollback_never_signal_codex_or_chatgpt(self) -> None:
        combined = SCRIPT.read_text(encoding="utf-8") + ROLLBACK.read_text(encoding="utf-8")

        for forbidden in ("os.kill", "pkill", "killall", "SIGTERM", "SIGKILL"):
            self.assertNotIn(forbidden, combined)

    def test_check_blocks_when_version_two_receipt_does_not_match_installed_bytes(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        manifest = self.codex_home / "backups" / "fd-guardrails-20260804-212800" / "manifest.json"
        receipt = json.loads(manifest.read_text(encoding="utf-8"))
        config_entry = next(target for target in receipt["targets"] if target["id"] == "config.toml")
        config_entry["installed_sha256"] = "0" * 64
        manifest.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        checked = self.run_installer()

        self.assertEqual(2, checked.returncode, checked.stdout + checked.stderr)
        self.assertIn("installation_receipt_target_hash_drifted:config.toml", checked.stdout)

    def test_check_blocks_old_version_two_receipt_with_six_targets(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        manifest = backup / "manifest.json"
        receipt = json.loads(manifest.read_text(encoding="utf-8"))
        keep_ids = {
            "config.toml",
            "AGENTS.md",
            "codex_fd_doctor.sh",
            "codex_process_inventory.py",
            "validate_wide_wave_manifest.py",
            "trusted-wide-wave-skills.json",
        }
        receipt["targets"] = [target for target in receipt["targets"] if target["id"] in keep_ids]
        for backup_file in backup.iterdir():
            if backup_file.name == "manifest.json" or backup_file.name in {
                target["backup"] for target in receipt["targets"] if target["existed"]
            }:
                continue
            backup_file.unlink()
        manifest.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        checked = self.run_installer()

        self.assertEqual(2, checked.returncode, checked.stdout + checked.stderr)
        self.assertIn("installation_receipt_target_set_drifted", checked.stdout)

    def test_rollback_rejects_receipt_with_public_permissions(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        (backup / "manifest.json").chmod(0o644)

        rollback = subprocess.run(
            [
                sys.executable,
                str(ROLLBACK),
                "--backup",
                str(backup),
                "--installed-doctor",
                str(self.installed_doctor),
                "--installed-process-inventory",
                str(self.installed_inventory),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertNotEqual(0, rollback.returncode)
        self.assertIn("manifest permissions are unsafe", rollback.stderr)

    def test_rejects_duplicate_keys_before_writing(self) -> None:
        self.config.write_text(
            """[agents]
max_concurrent_threads_per_session = 20
max_concurrent_threads_per_session = 21

[features.multi_agent_v2]
enabled = true
""",
            encoding="utf-8",
        )
        before = self.config.read_bytes()

        completed = self.run_installer("--apply")

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("Cannot overwrite a value", completed.stderr)
        self.assertEqual(before, self.config.read_bytes())

    def test_apply_compensates_after_first_atomic_write_failure(self) -> None:
        originals = {
            self.config: self.config.read_bytes(),
            self.agents: self.agents.read_bytes(),
            self.installed_doctor: self.installed_doctor.read_bytes(),
        }
        modes = {path: stat.S_IMODE(path.stat().st_mode) for path in originals}

        completed = self.run_installer(
            "--apply",
            "--fail-after-atomic-write",
            "1",
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("automatic rollback applied", completed.stderr)
        for path, data in originals.items():
            self.assertEqual(data, path.read_bytes(), path)
            self.assertEqual(modes[path], stat.S_IMODE(path.stat().st_mode), path)

    def test_rejects_unsafe_timestamp_before_creating_backup(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--codex-home",
                str(self.codex_home),
                "--installed-doctor",
                str(self.installed_doctor),
                "--source-doctor",
                str(SOURCE_DOCTOR),
                "--timestamp",
                "../../outside",
                "--apply",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("invalid timestamp", completed.stderr)
        self.assertFalse((self.root / "outside").exists())

    def test_migrates_legacy_partial_backup_out_of_rollback_namespace(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        legacy = self.codex_home / "backups" / "runtime-fd-20260804-2128"
        legacy.mkdir()
        (legacy / "config.toml").write_text("sensitive\n", encoding="utf-8")
        (legacy / "AGENTS.md").write_text("policy\n", encoding="utf-8")
        (legacy / "codex_fd_doctor.sh").write_text("doctor\n", encoding="utf-8")

        completed = self.run_installer(
            "--apply",
            "--migrate-legacy-backup",
            "20260804-2128",
        )

        migrated = self.codex_home / "backups" / "fd-guardrails-20260804-2128"
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn(f"migrated_backup={migrated}", completed.stdout)
        self.assertFalse(legacy.exists())
        self.assertTrue(migrated.is_dir())
        self.assertEqual(0o700, stat.S_IMODE(migrated.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((migrated / "config.toml").stat().st_mode))
        legacy_config = self.codex_home / "backups" / "config.toml.20260804.bak"
        legacy_config.write_text("legacy config\n", encoding="utf-8")
        rollback_env = os.environ.copy()
        rollback_env["HOME"] = str(self.root)
        rollback = subprocess.run(
            [
                sys.executable,
                str(ROLLBACK),
                "--installed-doctor",
                str(self.installed_doctor),
                "--installed-process-inventory",
                str(self.installed_inventory),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=rollback_env,
        )
        self.assertEqual(0, rollback.returncode, rollback.stdout + rollback.stderr)
        self.assertIn("restore config.toml", rollback.stdout)
        self.assertNotIn(str(migrated), rollback.stdout)
        self.assertNotIn(str(legacy_config), rollback.stdout)

    def test_rollback_accepts_version_one_receipt_without_removing_inventory(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        receipt = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
        legacy_targets = []
        for target in receipt["targets"]:
            if target["id"] not in {
                "config.toml",
                "AGENTS.md",
                "codex_fd_doctor.sh",
                "validate_wide_wave_manifest.py",
                "trusted-wide-wave-skills.json",
            }:
                continue
            legacy_targets.append(
                {
                    key: target[key]
                    for key in ("id", "backup", "existed", "mode", "sha256")
                }
            )
        (backup / "manifest.json").write_text(
            json.dumps(
                {
                    "kind": receipt["kind"],
                    "version": 1,
                    "targets": legacy_targets,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        for backup_file in (
            backup / "codex_process_inventory.py",
            backup / "hooks.json",
            backup / "autonomous_policy.py",
            backup / "codex_capacity.py",
            backup / "codex_capacity_observer.py",
            *(backup / f"{name}.config.toml" for name in PROFILE_VALUES),
        ):
            if backup_file.exists():
                backup_file.unlink()

        rollback = subprocess.run(
            [
                sys.executable,
                str(ROLLBACK),
                "--backup",
                str(backup),
                "--apply",
                "--codex-home",
                str(self.codex_home),
                "--installed-doctor",
                str(self.installed_doctor),
                "--installed-process-inventory",
                str(self.installed_inventory),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(0, rollback.returncode, rollback.stdout + rollback.stderr)
        restored = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(1000, restored["agents"]["max_threads"])
        self.assertTrue(self.installed_inventory.is_file())

    def test_rollback_accepts_old_version_two_receipt_with_six_targets(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        receipt = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
        receipt["targets"] = [
            target
            for target in receipt["targets"]
            if target["id"] in {
                "config.toml",
                "AGENTS.md",
                "codex_fd_doctor.sh",
                "codex_process_inventory.py",
                "validate_wide_wave_manifest.py",
                "trusted-wide-wave-skills.json",
            }
        ]
        for backup_file in (
            backup / "hooks.json",
            backup / "autonomous_policy.py",
            backup / "codex_capacity.py",
            backup / "codex_capacity_observer.py",
            *(backup / f"{name}.config.toml" for name in PROFILE_VALUES),
        ):
            if backup_file.exists():
                backup_file.unlink()
        (backup / "manifest.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.installed_capacity.write_text("keep capacity\n", encoding="utf-8")

        rollback = subprocess.run(
            [
                sys.executable,
                str(ROLLBACK),
                "--backup",
                str(backup),
                "--apply",
                "--codex-home",
                str(self.codex_home),
                "--installed-doctor",
                str(self.installed_doctor),
                "--installed-process-inventory",
                str(self.installed_inventory),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(0, rollback.returncode, rollback.stdout + rollback.stderr)
        restored = tomllib.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(1000, restored["agents"]["max_threads"])
        self.assertEqual("keep capacity\n", self.installed_capacity.read_text(encoding="utf-8"))

    def test_migrates_legacy_partial_backup_without_doctor_copy(self) -> None:
        applied = self.run_installer("--apply")
        self.assertEqual(0, applied.returncode, applied.stdout + applied.stderr)
        legacy = self.codex_home / "backups" / "runtime-fd-20260804-2129"
        legacy.mkdir()
        (legacy / "config.toml").write_text("sensitive\n", encoding="utf-8")
        (legacy / "AGENTS.md").write_text("policy\n", encoding="utf-8")

        completed = self.run_installer(
            "--apply",
            "--migrate-legacy-backup",
            "20260804-2129",
        )

        migrated = self.codex_home / "backups" / "fd-guardrails-20260804-2129"
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertFalse(legacy.exists())
        self.assertTrue(migrated.is_dir())


if __name__ == "__main__":
    unittest.main()
