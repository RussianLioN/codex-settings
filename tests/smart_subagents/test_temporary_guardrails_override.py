from __future__ import annotations

import json
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OVERRIDE = ROOT / "scripts" / "temporary_guardrails_override.py"
FD_DOCTOR = ROOT / "scripts" / "codex_fd_doctor.sh"
POLICY_START = "<!-- codex-runtime-fd-guardrails:start -->"
POLICY_END = "<!-- codex-runtime-fd-guardrails:end -->"


class TemporaryGuardrailsOverrideTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="temporary-guardrails-")
        self.root = Path(self.temporary.name)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.config = self.codex_home / "config.toml"
        self.hooks = self.codex_home / "hooks.json"
        self.agents = self.codex_home / "AGENTS.md"
        self.config.write_text("[features]\nhooks = true\n", encoding="utf-8")
        self.hooks.write_text('{"hooks":{"Stop":[{"command":"blocked"}]}}\n', encoding="utf-8")
        self.agents.write_text(
            "До блока.\n"
            f"{POLICY_START}\n"
            "Ограничение.\n"
            f"{POLICY_END}\n"
            "После блока.\n",
            encoding="utf-8",
        )
        self.original = {path: path.read_bytes() for path in (self.config, self.hooks, self.agents)}
        for path in self.original:
            path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_override(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(OVERRIDE),
                *arguments,
                "--codex-home",
                str(self.codex_home),
                "--timestamp",
                "20260818-120000",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_enable_disables_all_local_hooks_and_restore_returns_exact_snapshot(self) -> None:
        enabled = self.run_override("enable", "--confirm", "disable-all-local-guardrails")

        self.assertEqual(0, enabled.returncode, enabled.stdout + enabled.stderr)
        self.assertIn("status=ENABLED", enabled.stdout)
        self.assertFalse("hooks = true" in self.config.read_text(encoding="utf-8"))
        self.assertIn("hooks = false", self.config.read_text(encoding="utf-8"))
        self.assertEqual(b'{"hooks":{}}\n', self.hooks.read_bytes())
        self.assertNotIn(POLICY_START, self.agents.read_text(encoding="utf-8"))
        self.assertNotIn(POLICY_END, self.agents.read_text(encoding="utf-8"))
        for path in self.original:
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

        state = self.codex_home / "state" / "temporary-guardrails-override.json"
        self.assertEqual(0o600, stat.S_IMODE(state.stat().st_mode))
        payload = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual("enabled", payload["status"])
        self.assertEqual(3, len(payload["targets"]))

        restored = self.run_override("restore", "--confirm", "restore-local-guardrails")

        self.assertEqual(0, restored.returncode, restored.stdout + restored.stderr)
        self.assertIn("status=RESTORED", restored.stdout)
        self.assertFalse(state.exists())
        for path, expected in self.original.items():
            self.assertEqual(expected, path.read_bytes(), path)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))

    def test_restore_refuses_to_overwrite_changed_disabled_target(self) -> None:
        self.assertEqual(
            0,
            self.run_override("enable", "--confirm", "disable-all-local-guardrails").returncode,
        )
        self.hooks.write_text('{"hooks":{"Stop":[]}}\n', encoding="utf-8")

        restored = self.run_override("restore", "--confirm", "restore-local-guardrails")

        self.assertEqual(2, restored.returncode, restored.stdout + restored.stderr)
        self.assertIn("disabled_target_drifted:hooks.json", restored.stderr)
        self.assertTrue((self.codex_home / "state" / "temporary-guardrails-override.json").exists())

    def test_restore_compensates_partial_write_failure(self) -> None:
        self.assertEqual(
            0,
            self.run_override("enable", "--confirm", "disable-all-local-guardrails").returncode,
        )
        disabled = {path: path.read_bytes() for path in self.original}
        spec = importlib.util.spec_from_file_location("temporary_guardrails_override_under_test", OVERRIDE)
        assert spec is not None and spec.loader is not None
        override = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(override)
        original_atomic_write = override.atomic_write

        def fail_second_restore(path: Path, data: bytes, mode: int) -> None:
            if path.name == "hooks.json" and data == self.original[self.hooks]:
                raise OSError("injected write failure")
            original_atomic_write(path, data, mode)

        override.atomic_write = fail_second_restore
        with self.assertRaises(OSError):
            override.restore(self.codex_home)

        for path, expected in disabled.items():
            self.assertEqual(expected, path.read_bytes(), path)
        self.assertTrue((self.codex_home / "state" / "temporary-guardrails-override.json").exists())

    def test_enabled_override_makes_doctor_report_explicit_bypass(self) -> None:
        self.assertEqual(
            0,
            self.run_override("enable", "--confirm", "disable-all-local-guardrails").returncode,
        )
        environment = os.environ.copy()
        environment.update({"CODEX_HOME": str(self.codex_home)})

        doctor = subprocess.run(
            [str(FD_DOCTOR), "--wave-size", "20"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

        self.assertEqual(0, doctor.returncode, doctor.stdout + doctor.stderr)
        self.assertIn("status=OK", doctor.stdout)
        self.assertIn("allowed_wave_size=20", doctor.stdout)
        self.assertIn("temporary_guardrails_override=enabled", doctor.stdout)
        self.assertIn("reasons=temporary_guardrails_override_enabled", doctor.stdout)

    def test_enable_requires_explicit_confirmation_and_does_not_modify_targets(self) -> None:
        rejected = self.run_override("enable")

        self.assertEqual(2, rejected.returncode)
        self.assertIn("confirmation_required", rejected.stderr)
        for path, expected in self.original.items():
            self.assertEqual(expected, path.read_bytes(), path)


if __name__ == "__main__":
    unittest.main()
