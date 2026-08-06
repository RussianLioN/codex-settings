from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate_autonomous_workflow.py"


def load_validator() -> ModuleType:
    name = "autonomous_workflow_resource_contract_under_test"
    spec = importlib.util.spec_from_file_location(name, VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load validator: {VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AutonomousWorkflowResourceLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_base_config_rejects_missing_public_thread_cap_and_legacy_limits(
        self,
    ) -> None:
        config = {
            "agents": {**self.validator.EXPECTED_BASE_AGENT_LIMITS, "max_threads": 20},
            "features": {
                "multi_agent_v2": {
                    "enabled": True,
                    "max_concurrent_threads_per_session": 1_000,
                }
            },
        }

        failures = self.validator.base_agent_limit_failures(config)

        for marker in (
            "agents.max_concurrent_threads_per_session",
            "agents.max_threads",
            "features.multi_agent_v2.max_concurrent_threads_per_session",
        ):
            self.assertTrue(
                any(marker in failure for failure in failures),
                failures,
            )

    def run_fd_doctor(
        self,
        wave_size: int,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CODEX_FD_DOCTOR_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_HARD_LIMIT": "unlimited",
                "CODEX_FD_DOCTOR_LAUNCHD_FD_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_CODEX_FD_COUNT": "32",
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "2",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "2",
                "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT": "0",
                "CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT": "0",
                "CODEX_FD_DOCTOR_MCP_COMMAND": "/bin/sh",
                "CODEX_FD_DOCTOR_AGENT_THREAD_CAP": "20",
                "CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT": "2666",
                "CODEX_FD_DOCTOR_USER_PROCESS_COUNT": "100",
            }
        )
        environment.update(overrides)
        return subprocess.run(
            [str(self.validator.FD_DOCTOR), "--wave-size", str(wave_size)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def test_fd_doctor_blocks_unsafe_public_agent_thread_cap(self) -> None:
        completed = self.run_fd_doctor(
            6,
            CODEX_FD_DOCTOR_AGENT_THREAD_CAP="1000",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("agents_max_concurrent_threads_not_20", completed.stdout)

    def test_fd_doctor_accepts_sufficient_fd_and_process_headroom(self) -> None:
        completed = self.run_fd_doctor(6)

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=OK", completed.stdout)
        self.assertIn("launchd_fd_soft_limit=4096", completed.stdout)
        self.assertIn("user_process_soft_limit=2666", completed.stdout)
        self.assertIn("user_process_count=100", completed.stdout)
        self.assertIn("process_headroom=2566", completed.stdout)
        self.assertIn("required_process_headroom=64", completed.stdout)

    def test_fd_doctor_blocks_when_process_headroom_is_too_low(self) -> None:
        completed = self.run_fd_doctor(
            8,
            CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT="120",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="120",
            CODEX_FD_DOCTOR_USER_PROCESS_COUNT="70",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_headroom_below_64", completed.stdout)

    def test_fd_doctor_blocks_wide_wave_when_process_limit_is_unknown(self) -> None:
        completed = self.run_fd_doctor(
            8,
            CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT="unknown",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="unknown",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_limit_unknown_for_wide_wave", completed.stdout)

    def test_fd_doctor_warns_default_wave_when_process_limit_is_unknown(self) -> None:
        completed = self.run_fd_doctor(
            6,
            CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT="unknown",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="unknown",
        )

        self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_limit_unknown", completed.stdout)

    def test_fd_doctor_distinguishes_maxfiles_from_maxproc(self) -> None:
        completed = self.run_fd_doctor(
            6,
            CODEX_FD_DOCTOR_SOFT_LIMIT="256",
            CODEX_FD_DOCTOR_LAUNCHD_FD_SOFT_LIMIT="256",
            CODEX_FD_DOCTOR_LAUNCHD_SOFT_LIMIT="256",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="2666",
        )

        self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("soft_limit_below_1024", completed.stdout)
        self.assertIn("launchd_fd_soft_limit=256", completed.stdout)
        self.assertIn("user_process_soft_limit=2666", completed.stdout)
        self.assertNotIn("process_headroom_below", completed.stdout)

    def test_fd_doctor_accepts_safe_public_cap_with_toml_comment(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-config-") as root:
            codex_home = Path(root) / ".codex"
            codex_home.mkdir()
            (codex_home / "config.toml").write_text(
                """[agents] # публичные пределы
max_concurrent_threads_per_session = 20 # безопасный потолок

[features.multi_agent_v2] # настройки дерева
enabled = true
""",
                encoding="utf-8",
            )
            completed = self.run_fd_doctor(
                6,
                CODEX_HOME=str(codex_home),
            )

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=OK", completed.stdout)
        self.assertIn("agent_thread_cap=20", completed.stdout)


if __name__ == "__main__":
    unittest.main()
