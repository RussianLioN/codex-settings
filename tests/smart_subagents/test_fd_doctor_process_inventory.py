from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FD_DOCTOR = ROOT / "scripts" / "codex_fd_doctor.sh"
NODE_REPL = "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl"


class FdDoctorProcessInventoryTests(unittest.TestCase):
    def base_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CODEX_FD_DOCTOR_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_HARD_LIMIT": "unlimited",
                "CODEX_FD_DOCTOR_LAUNCHD_FD_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_CODEX_FD_COUNT": "32",
                "CODEX_FD_DOCTOR_MCP_COMMAND": "/bin/sh",
                "CODEX_FD_DOCTOR_AGENT_THREAD_CAP": "20",
                "CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT": "4096",
                "CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT": "2666",
                "CODEX_FD_DOCTOR_KERN_MAXPROCPERUID": "3000",
                "CODEX_FD_DOCTOR_USER_PROCESS_COUNT": "100",
                "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT": "0",
                "CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT": "0",
            }
        )
        return environment

    def run_doctor(
        self,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(FD_DOCTOR), "--wave-size", "6"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def test_legacy_count_overrides_do_not_derive_a_node_repl_ceiling(self) -> None:
        for codex_count, node_count in ((1, 21), (4, 81), (5, 81)):
            with self.subTest(codex_count=codex_count, node_count=node_count):
                environment = self.base_environment()
                environment.update(
                    {
                        "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": str(codex_count),
                        "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": str(node_count),
                    }
                )

                completed = self.run_doctor(environment)

                self.assertEqual(
                    0,
                    completed.returncode,
                    completed.stdout + completed.stderr,
                )
                self.assertIn(
                    "max_expected_node_repl_processes=unknown",
                    completed.stdout,
                )
                self.assertNotIn(
                    "node_repl_processes_exceed_thread_capacity",
                    completed.stdout,
                )

    def test_single_snapshot_classifies_twenty_one_attached_helpers(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="codex-inventory-") as root:
            snapshot = Path(root) / "snapshot.json"
            processes = [
                {
                    "pid": 100,
                    "ppid": 1,
                    "uid": os.getuid(),
                    "user": "operator",
                    "started_epoch": 900.0,
                    "executable": "/opt/homebrew/bin/codex",
                    "command": "/opt/homebrew/bin/codex",
                },
                {
                    "pid": 101,
                    "ppid": 100,
                    "uid": os.getuid(),
                    "user": "operator",
                    "started_epoch": 901.0,
                    "executable": "/bin/zsh",
                    "command": "/bin/zsh doctor",
                },
            ]
            for index in range(21):
                processes.append(
                    {
                        "pid": 200 + index,
                        "ppid": 101,
                        "uid": os.getuid(),
                        "user": "operator",
                        "started_epoch": 902.0,
                        "executable": NODE_REPL,
                        "command": f"{NODE_REPL} {index}",
                    }
                )
            snapshot.write_text(
                json.dumps({"processes": processes}),
                encoding="utf-8",
            )
            environment = self.base_environment()
            for key in (
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT",
                "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT",
                "CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT",
                "CODEX_FD_DOCTOR_USER_PROCESS_COUNT",
            ):
                environment.pop(key, None)
            environment.update(
                {
                    "CODEX_FD_DOCTOR_PROCESS_SNAPSHOT": str(snapshot),
                    "CODEX_FD_DOCTOR_CALLER_PID": "101",
                    "CODEX_FD_DOCTOR_NOW_EPOCH": "1000",
                }
            )

            completed = self.run_doctor(environment)

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("node_repl_processes=21", completed.stdout)
        self.assertIn("node_repl_attached_processes=21", completed.stdout)
        self.assertIn("max_expected_node_repl_processes=unknown", completed.stdout)

    def test_unavailable_inventory_blocks_new_work(self) -> None:
        environment = self.base_environment()
        for key in (
            "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT",
            "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT",
            "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT",
            "CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT",
            "CODEX_FD_DOCTOR_USER_PROCESS_COUNT",
        ):
            environment.pop(key, None)
        environment["CODEX_FD_DOCTOR_PROCESS_INVENTORY"] = "/missing/inventory.py"

        completed = self.run_doctor(environment)

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_inventory_unavailable", completed.stdout)

    def test_proven_fd_and_process_exhaustion_still_block(self) -> None:
        fd_environment = self.base_environment()
        fd_environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_CODEX_FD_COUNT": "4080",
            }
        )
        process_environment = self.base_environment()
        process_environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_USER_PROCESS_SOFT_LIMIT": "300",
                "CODEX_FD_DOCTOR_LAUNCHD_MAXPROC_SOFT_LIMIT": "300",
                "CODEX_FD_DOCTOR_KERN_MAXPROCPERUID": "300",
                "CODEX_FD_DOCTOR_USER_PROCESS_COUNT": "100",
            }
        )

        fd_result = self.run_doctor(fd_environment)
        process_result = self.run_doctor(process_environment)

        self.assertEqual(2, fd_result.returncode, fd_result.stdout + fd_result.stderr)
        self.assertIn("fd_headroom_below_64", fd_result.stdout)
        self.assertEqual(
            2,
            process_result.returncode,
            process_result.stdout + process_result.stderr,
        )
        self.assertIn("process_headroom_below_248", process_result.stdout)


if __name__ == "__main__":
    unittest.main()
