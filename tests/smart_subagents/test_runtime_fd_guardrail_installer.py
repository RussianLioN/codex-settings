from __future__ import annotations

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
ROLLBACK = ROOT / "scripts" / "codex_autonomous_rollback.py"


class RuntimeFdGuardrailInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="runtime-fd-guardrails-",
        )
        self.root = Path(self.temporary.name)
        self.codex_home = self.root / ".codex"
        self.codex_home.mkdir()
        self.config = self.codex_home / "config.toml"
        self.agents = self.codex_home / "AGENTS.md"
        self.installed_doctor = self.root / "libexec" / "codex_fd_doctor.sh"
        self.installed_doctor.parent.mkdir()
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

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_installer(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
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
                "20260804-212800",
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
        self.assertEqual(config_before, self.config.read_bytes())
        self.assertEqual(agents_before, self.agents.read_bytes())
        self.assertEqual(doctor_before, self.installed_doctor.read_bytes())

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
        self.assertEqual(SOURCE_DOCTOR.read_bytes(), self.installed_doctor.read_bytes())
        self.assertTrue((self.installed_doctor.parent / "validate_wide_wave_manifest.py").is_file())
        self.assertTrue((self.codex_home / "config" / "trusted-wide-wave-skills.json").is_file())

        backup = self.codex_home / "backups" / "fd-guardrails-20260804-212800"
        self.assertFalse(list((self.codex_home / "backups").glob("runtime-fd-*")))
        self.assertEqual(0o700, stat.S_IMODE(backup.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE((backup / "config.toml").stat().st_mode))
        backup_config = tomllib.loads((backup / "config.toml").read_text())
        self.assertEqual(1000, backup_config["agents"]["max_threads"])
        self.assertEqual(1000, backup_config["features"]["multi_agent_v2"]["max_concurrent_threads_per_session"])
        self.assertEqual("old doctor\n", (backup / "codex_fd_doctor.sh").read_text())

        checked = self.run_installer()
        self.assertEqual(0, checked.returncode, checked.stdout + checked.stderr)
        self.assertIn("status=OK", checked.stdout)

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
            [sys.executable, str(ROLLBACK)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=rollback_env,
        )
        self.assertEqual(0, rollback.returncode, rollback.stdout + rollback.stderr)
        self.assertIn(str(legacy_config), rollback.stdout)

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
