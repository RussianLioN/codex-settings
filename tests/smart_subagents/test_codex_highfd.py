from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "codex-highfd"


class CodexHighFdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="codex-highfd-test-",
        )
        self.root = Path(self.temporary_directory.name)
        self.real_codex = self.write_launcher("real-codex", "real")
        self.smart_launcher = self.write_launcher("codex-smart", "smart")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_launcher(self, name: str, label: str) -> Path:
        path = self.root / name
        path.write_text(
            "#!/bin/zsh\n"
            f"print -r -- 'launcher={label}'\n"
            "print -r -- \"args=$*\"\n"
            "print -r -- \"real_bin=${CODEX_REAL_BIN-unset}\"\n"
            "print -r -- \"smart_enabled=${CODEX_SMART_ENABLED-unset}\"\n"
            "print -r -- \"smart_required=${CODEX_SMART_REQUIRED-unset}\"\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def run_wrapper(self, *arguments: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CODEX_NOFILE_LIMIT": "256",
                "CODEX_REAL_BIN": str(self.real_codex),
                "CODEX_SMART_LAUNCHER": str(self.smart_launcher),
            }
        )
        environment.update(overrides)
        return subprocess.run(
            [str(WRAPPER), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def test_smart_mode_dispatches_to_smart_launcher_with_contract(self) -> None:
        completed = self.run_wrapper(
            "--model",
            "test-model",
            CODEX_SMART_ENABLED="1",
            CODEX_SMART_REQUIRED="1",
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("launcher=smart", completed.stdout)
        self.assertIn("args=--model test-model", completed.stdout)
        self.assertIn(f"real_bin={self.real_codex}", completed.stdout)
        self.assertIn("smart_enabled=1", completed.stdout)
        self.assertIn("smart_required=1", completed.stdout)

    def test_direct_mode_dispatches_to_real_codex_without_smart_flags(self) -> None:
        completed = self.run_wrapper("resume", CODEX_SMART_ENABLED="0")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("launcher=real", completed.stdout)
        self.assertIn("args=resume", completed.stdout)
        self.assertIn("smart_enabled=unset", completed.stdout)
        self.assertIn("smart_required=unset", completed.stdout)

    def test_rejects_invalid_smart_mode_value(self) -> None:
        completed = self.run_wrapper(CODEX_SMART_ENABLED="sometimes")

        self.assertEqual(2, completed.returncode)
        self.assertIn("CODEX_SMART_ENABLED must be 0 or 1", completed.stderr)

    def test_required_smart_mode_cannot_be_disabled(self) -> None:
        completed = self.run_wrapper(
            CODEX_SMART_ENABLED="0",
            CODEX_SMART_REQUIRED="1",
        )

        self.assertEqual(2, completed.returncode)
        self.assertIn("CODEX_SMART_REQUIRED=1 requires CODEX_SMART_ENABLED=1", completed.stderr)


if __name__ == "__main__":
    unittest.main()
