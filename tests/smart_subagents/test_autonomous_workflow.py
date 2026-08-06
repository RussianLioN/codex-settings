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

    def test_base_config_rejects_unsafe_native_session_thread_cap(self) -> None:
        config = {
            "agents": dict(self.validator.EXPECTED_BASE_AGENT_LIMITS),
            "features": {
                "multi_agent_v2": {
                    "enabled": True,
                    "max_concurrent_threads_per_session": 1000,
                }
            },
        }

        failures = self.validator.base_agent_limit_failures(config)

        self.assertTrue(
            any("max_concurrent_threads_per_session" in failure for failure in failures),
            failures,
        )

    def doctor_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CODEX_FD_DOCTOR_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_HARD_LIMIT": "unlimited",
                "CODEX_FD_DOCTOR_LAUNCHD_SOFT_LIMIT": "256",
                "CODEX_FD_DOCTOR_CODEX_FD_COUNT": "32",
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "2",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "2",
                "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT": "0",
                "CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT": "0",
                "CODEX_FD_DOCTOR_MCP_COMMAND": "/bin/sh",
            }
        )
        return environment

    def test_fd_doctor_blocks_unsafe_native_session_thread_cap(self) -> None:
        environment = self.doctor_environment()
        environment["CODEX_FD_DOCTOR_NATIVE_SESSION_THREAD_CAP"] = "1000"

        completed = subprocess.run(
            [str(self.validator.FD_DOCTOR), "--wave-size", "6"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("native_session_thread_cap_not_20", completed.stdout)

    def test_fd_doctor_accepts_safe_native_cap_with_toml_comment(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-config-") as root:
            codex_home = Path(root) / ".codex"
            codex_home.mkdir()
            (codex_home / "config.toml").write_text(
                """[features.multi_agent_v2] # настройки дерева
max_concurrent_threads_per_session = 20 # безопасный потолок
""",
                encoding="utf-8",
            )
            environment = self.doctor_environment()
            environment["CODEX_HOME"] = str(codex_home)

            completed = subprocess.run(
                [str(self.validator.FD_DOCTOR), "--wave-size", "6"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=OK", completed.stdout)
        self.assertIn("native_session_thread_cap=20", completed.stdout)


if __name__ == "__main__":
    unittest.main()
