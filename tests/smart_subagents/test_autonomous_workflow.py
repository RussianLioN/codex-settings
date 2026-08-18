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
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-isolated-home-") as root:
            environment = os.environ.copy()
            environment.update(
                {
                    "CODEX_HOME": str(Path(root) / ".codex"),
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
                    "CODEX_FD_DOCTOR_TEST_MODE": "1",
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

    def test_fd_doctor_leaves_profile_thread_cap_to_config_validator(self) -> None:
        completed = self.run_fd_doctor(
            6,
            CODEX_FD_DOCTOR_AGENT_THREAD_CAP="1000",
        )

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("agent_thread_cap=1000", completed.stdout)
        self.assertNotIn("agents_max_concurrent_threads_not_20", completed.stdout)

    def test_fd_doctor_accepts_sufficient_fd_and_process_headroom(self) -> None:
        completed = self.run_fd_doctor(6)

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=OK", completed.stdout)
        self.assertIn("launchd_fd_soft_limit=4096", completed.stdout)
        self.assertIn("user_process_soft_limit=2666", completed.stdout)
        self.assertIn("user_process_count=100", completed.stdout)
        self.assertIn("process_headroom=2566", completed.stdout)
        self.assertIn("required_process_headroom=248", completed.stdout)

    def test_fd_doctor_blocks_when_process_headroom_is_too_low(self) -> None:
        completed = self.run_fd_doctor(
            8,
            CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT="120",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="120",
            CODEX_FD_DOCTOR_USER_PROCESS_COUNT="70",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_headroom_below_288", completed.stdout)

    def test_fd_doctor_blocks_wide_wave_when_process_budget_is_unknown(self) -> None:
        completed = self.run_fd_doctor(
            8,
            CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT="unknown",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="unknown",
            CODEX_FD_DOCTOR_KERN_MAXPROCPERUID="unknown",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_budget_unavailable", completed.stdout)

    def test_fd_doctor_blocks_default_wave_when_process_budget_is_unknown(self) -> None:
        completed = self.run_fd_doctor(
            6,
            CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT="unknown",
            CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT="unknown",
            CODEX_FD_DOCTOR_KERN_MAXPROCPERUID="unknown",
        )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_budget_unavailable", completed.stdout)

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

    def test_profile_validator_requires_public_caps_and_expected_values(self) -> None:
        valid_small = {
            "model": "gpt-5.4-mini",
            "model_reasoning_effort": "medium",
            "sandbox_mode": "workspace-write",
            "approval_policy": "on-request",
            "agents": {
                "max_concurrent_threads_per_session": 2,
                "max_depth": 1,
            },
        }

        self.assertEqual([], self.validator.profile_config_failures("small", valid_small))

        legacy = {**valid_small, "agents": {"max_threads": 2, "max_depth": 1}}
        both = {
            **valid_small,
            "agents": {
                "max_threads": 2,
                "max_concurrent_threads_per_session": 2,
                "max_depth": 1,
            },
        }
        wrong_small = {
            **valid_small,
            "agents": {
                "max_concurrent_threads_per_session": 3,
                "max_depth": 1,
            },
        }
        non_int = {
            **valid_small,
            "agents": {
                "max_concurrent_threads_per_session": "2",
                "max_depth": 1,
            },
        }

        for config, marker in (
            (legacy, "agents.max_threads is legacy"),
            (both, "agents.max_threads is legacy"),
            (wrong_small, "agents.max_concurrent_threads_per_session must be 2"),
            (non_int, "got '2'"),
        ):
            failures = self.validator.profile_config_failures("small", config)
            self.assertTrue(any(marker in failure for failure in failures), failures)

    def test_hook_validator_requires_session_end_managed_policy_contract(self) -> None:
        policy_path = Path("/tmp/autonomous_policy.py")
        document = {
            "hooks": {
                event: [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"/usr/bin/python3 {policy_path} {event}",
                                "timeout": 3 if event == "SessionEnd" else 1,
                            }
                        ]
                    }
                ]
                for event in self.validator.HOOK_EVENTS
            }
        }

        self.assertEqual([], self.validator.managed_hook_contract_failures(document, policy_path))

        missing_session_end = {"hooks": dict(document["hooks"])}
        missing_session_end["hooks"].pop("SessionEnd")
        failures = self.validator.managed_hook_contract_failures(missing_session_end, policy_path)
        self.assertTrue(any("SessionEnd must contain a list" in failure for failure in failures), failures)

        wrong_timeout = {"hooks": dict(document["hooks"])}
        wrong_timeout["hooks"]["SessionEnd"] = [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": f"/usr/bin/python3 {policy_path} SessionEnd",
                        "timeout": 1,
                    }
                ]
            }
        ]
        failures = self.validator.managed_hook_contract_failures(wrong_timeout, policy_path)
        self.assertTrue(any("SessionEnd managed hook timeout must be 3" in failure for failure in failures), failures)


if __name__ == "__main__":
    unittest.main()
