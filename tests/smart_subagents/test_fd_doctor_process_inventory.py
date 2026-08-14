from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FD_DOCTOR = ROOT / "scripts" / "codex_fd_doctor.sh"
CAPACITY = ROOT / "scripts" / "codex_capacity.py"
NODE_REPL = "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl"


class FdDoctorProcessInventoryTests(unittest.TestCase):
    def base_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        environment.pop("CODEX_HOME", None)
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
                "CODEX_FD_DOCTOR_TEST_MODE": "1",
            }
        )
        return environment

    def run_doctor(
        self,
        environment: dict[str, str],
        *args: str,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-codex-home-") as temporary:
            isolated_environment = dict(environment)
            isolated_environment.setdefault("CODEX_HOME", temporary)
            return subprocess.run(
                [str(FD_DOCTOR), "--wave-size", "6", *args],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=isolated_environment,
            )

    def write_trusted_wide_wave_inputs(self, root: Path, *, wave_size: int = 19) -> tuple[Path, Path, Path]:
        skill = root / "consilium-skill.md"
        skill.write_text("---\nname: consilium\n---\n", encoding="utf-8")
        registry = root / "consilium-registry.json"
        registry.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "trusted_skills": [
                        {
                            "skill_id": "consilium",
                            "sha256": hashlib.sha256(skill.read_bytes()).hexdigest(),
                            "max_live_wave": 19,
                            "execution_kind": "flat-trusted-wide-wave",
                            "fallback": "6+6+6+1",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        repository = root / "repo"
        repository.mkdir()
        manifest = root / "consilium-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "skill_id": "consilium",
                    "wave_size": wave_size,
                    "repository_root": str(repository),
                    "base_commit": "1318542fb00df4eaef4fc4e8abfa8cd99e656bb3",
                    "participants": [
                        {"id": f"reader-{index}", "access": "read-only", "owned_write_scope": []}
                        for index in range(wave_size)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return skill, registry, manifest

    def write_observer_snapshot(self, root: Path, *, cpu_idle_percent: float = 55.0) -> Path:
        snapshot = root / "observer-snapshot.json"
        snapshot.write_text(
            json.dumps(
                {
                    "total_ram_bytes": 32 * 1024 * 1024 * 1024,
                    "available_memory_bytes": 16 * 1024 * 1024 * 1024,
                    "memory_pressure": "normal",
                    "swapouts_total_bytes": 0,
                    "cpu_idle_percent": cpu_idle_percent,
                    "user_process_limit": 4096,
                    "user_process_count": 300,
                    "root_fd_soft_limit": 8192,
                    "root_fd_used": 900,
                    "system_fd_max": 65536,
                    "system_fd_used": 6000,
                    "disk_free_bytes": 250 * 1024 * 1024 * 1024,
                    "disk_total_bytes": 1000 * 1024 * 1024 * 1024,
                    "heavy_lanes_in_use": 0,
                    "active_slots": 0,
                    "codex_root_count": 0,
                }
            ),
            encoding="utf-8",
        )
        return snapshot

    def write_dynamic_green_observer_state(self, root: Path, *, effective_capacity: int) -> Path:
        observer_state_dir = root / "dynamic-observer"
        observer_state_dir.mkdir()
        sample = {"memory_bytes": 1, "processes": 1, "root_fds": 1, "system_fds": 1, "heavy_lanes": 0}
        sample_count = 30 if effective_capacity == 6 else 70
        samples = [dict(sample) for _ in range(sample_count)]
        (observer_state_dir / "observer_state.json").write_text(
            json.dumps(
                {
                    "protocol_version": 1,
                    "last_observed_at": 100.0,
                    "last_status": "GREEN",
                    "last_snapshot": None,
                    "recovery": {"from_status": None, "started_at": None, "normal_count": 0, "last_normal_at": None},
                    "observations": [],
                    "successful_observations": sample_count,
                    "clean_cycles": 0,
                    "effective_capacity": effective_capacity,
                    "proven_capacity": effective_capacity,
                    "cost_samples": {"normal": samples},
                    "cost_estimates": {},
                    "cost_updated_at": {},
                }
            ),
            encoding="utf-8",
        )
        (observer_state_dir / "calibration_state.json").write_text(
            json.dumps(
                {
                    "protocol_version": 1,
                    "active": None,
                    "classes": {"normal": {"samples": samples, "accepted_count": sample_count, "rejected_count": 0, "last_rejection_code": None, "saturated_clean_cycles": 0, "effective_capacity": effective_capacity, "proven_capacity": effective_capacity, "cost_estimate": dict(sample), "cost_updated_at": 1000.0}},
                }
            ),
            encoding="utf-8",
        )
        return observer_state_dir

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

    def test_process_count_overrides_are_ignored_outside_test_mode(self) -> None:
        environment = self.base_environment()
        environment.pop("CODEX_FD_DOCTOR_TEST_MODE")
        environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_PROCESS_INVENTORY": "/missing/inventory.py",
            }
        )

        completed = self.run_doctor(environment)

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("process_inventory_unavailable", completed.stdout)
        self.assertNotIn("process_inventory_status=overridden", completed.stdout)

    def test_profile_thread_cap_is_reported_but_not_enforced(self) -> None:
        environment = self.base_environment()
        environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_AGENT_THREAD_CAP": "6",
            }
        )

        completed = self.run_doctor(environment)

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("agent_thread_cap=6", completed.stdout)
        self.assertNotIn("agents_max_concurrent_threads_not_20", completed.stdout)

    def test_unconfigured_profile_thread_cap_is_reported_explicitly(self) -> None:
        environment = self.base_environment()
        environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
            }
        )
        environment.pop("CODEX_FD_DOCTOR_AGENT_THREAD_CAP")

        completed = self.run_doctor(environment)

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("agent_thread_cap=not_configured", completed.stdout)

    def test_trusted_wide_wave_preserves_partial_capacity_as_warn(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-wide-") as temporary:
            root = Path(temporary)
            skill, registry, manifest = self.write_trusted_wide_wave_inputs(root)
            snapshot = self.write_observer_snapshot(root)
            observer_state_dir = self.write_dynamic_green_observer_state(root, effective_capacity=6)
            environment = self.base_environment()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_TRUSTED_REGISTRY": str(registry),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_SNAPSHOT": str(snapshot),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_STATE_DIR": str(observer_state_dir),
                }
            )

            completed = self.run_doctor(
                environment,
                "--wave-size",
                "19",
                "--skill-id",
                "consilium",
                "--skill-file",
                str(skill),
                "--manifest",
                str(manifest),
            )

        self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=WARN", completed.stdout)
        self.assertIn("wave_size=19", completed.stdout)
        self.assertIn("allowed_wave_size=6", completed.stdout)
        self.assertIn("capacity_decision=WARN", completed.stdout)

    def test_trusted_wide_wave_allows_nineteen_only_at_full_capacity(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-wide-") as temporary:
            root = Path(temporary)
            skill, registry, manifest = self.write_trusted_wide_wave_inputs(root)
            snapshot = self.write_observer_snapshot(root)
            observer_state_dir = self.write_dynamic_green_observer_state(root, effective_capacity=20)
            environment = self.base_environment()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_TRUSTED_REGISTRY": str(registry),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_SNAPSHOT": str(snapshot),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_STATE_DIR": str(observer_state_dir),
                }
            )

            completed = self.run_doctor(
                environment,
                "--wave-size",
                "19",
                "--skill-id",
                "consilium",
                "--skill-file",
                str(skill),
                "--manifest",
                str(manifest),
            )

        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=OK", completed.stdout)
        self.assertIn("allowed_wave_size=19", completed.stdout)
        self.assertIn("capacity_decision=ALLOW", completed.stdout)

    def test_trusted_wide_wave_warning_clamps_admission_to_fallback_size(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-wide-") as temporary:
            root = Path(temporary)
            skill, registry, manifest = self.write_trusted_wide_wave_inputs(root)
            snapshot = self.write_observer_snapshot(root)
            observer_state_dir = self.write_dynamic_green_observer_state(root, effective_capacity=20)
            environment = self.base_environment()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT": "1",
                    "CODEX_FD_DOCTOR_TRUSTED_REGISTRY": str(registry),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_SNAPSHOT": str(snapshot),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_STATE_DIR": str(observer_state_dir),
                }
            )

            completed = self.run_doctor(
                environment,
                "--wave-size",
                "19",
                "--skill-id",
                "consilium",
                "--skill-file",
                str(skill),
                "--manifest",
                str(manifest),
            )

        self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=WARN", completed.stdout)
        self.assertIn("allowed_wave_size=6", completed.stdout)
        self.assertIn("capacity_decision=WARN", completed.stdout)
        self.assertIn("orphan_candidate_node_repl_processes", completed.stdout)

    def test_non_test_capacity_script_override_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-capacity-override-") as temporary:
            root = Path(temporary)
            skill, registry, manifest = self.write_trusted_wide_wave_inputs(root)
            codex_home = root / "codex-home"
            registry_path = codex_home / "config" / "trusted-wide-wave-skills.json"
            registry_path.parent.mkdir(parents=True)
            registry_path.write_bytes(registry.read_bytes())
            fake_capacity = root / "fake_capacity.py"
            fake_capacity.write_text(
                "import json\n"
                "print(json.dumps({'allowed_wave_size': 19, 'capacity_decision': 'ALLOW', "
                "'observer_reasons': ['fake_capacity_script_used']}))\n",
                encoding="utf-8",
            )
            environment = self.base_environment()
            environment.pop("CODEX_FD_DOCTOR_TEST_MODE")
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_HOME": str(codex_home),
                    "CODEX_FD_DOCTOR_CAPACITY_SCRIPT": str(fake_capacity),
                }
            )

            completed = subprocess.run(
                [
                    str(FD_DOCTOR),
                    "--wave-size",
                    "19",
                    "--skill-id",
                    "consilium",
                    "--skill-file",
                    str(skill),
                    "--manifest",
                    str(manifest),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )

        self.assertNotIn("fake_capacity_script_used", completed.stdout + completed.stderr)

    def test_untrusted_wide_wave_blocks_with_zero_allowed_capacity(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-wide-") as temporary:
            root = Path(temporary)
            skill, registry, manifest = self.write_trusted_wide_wave_inputs(root)
            snapshot = self.write_observer_snapshot(root)
            environment = self.base_environment()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_TRUSTED_REGISTRY": str(registry),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_SNAPSHOT": str(snapshot),
                }
            )
            skill.write_text("tampered", encoding="utf-8")

            completed = self.run_doctor(
                environment,
                "--wave-size",
                "19",
                "--skill-id",
                "consilium",
                "--skill-file",
                str(skill),
                "--manifest",
                str(manifest),
            )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=BLOCK", completed.stdout)
        self.assertIn("allowed_wave_size=0", completed.stdout)
        self.assertIn("capacity_decision=BLOCK", completed.stdout)

    def test_observer_refusal_blocks_wide_wave_with_zero_allowed_capacity(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="fd-doctor-wide-") as temporary:
            root = Path(temporary)
            skill, registry, manifest = self.write_trusted_wide_wave_inputs(root)
            snapshot = self.write_observer_snapshot(root)
            snapshot_payload = json.loads(snapshot.read_text(encoding="utf-8"))
            snapshot_payload["memory_pressure"] = "critical"
            snapshot.write_text(json.dumps(snapshot_payload), encoding="utf-8")
            environment = self.base_environment()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                    "CODEX_FD_DOCTOR_TRUSTED_REGISTRY": str(registry),
                    "CODEX_FD_DOCTOR_CAPACITY_OBSERVER_SNAPSHOT": str(snapshot),
                }
            )

            completed = self.run_doctor(
                environment,
                "--wave-size",
                "19",
                "--skill-id",
                "consilium",
                "--skill-file",
                str(skill),
                "--manifest",
                str(manifest),
            )

        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("status=BLOCK", completed.stdout)
        self.assertIn("allowed_wave_size=0", completed.stdout)
        self.assertIn("capacity_decision=BLOCK", completed.stdout)

    def test_orphan_candidate_warns_but_confirmed_orphan_blocks(self) -> None:
        candidate_environment = self.base_environment()
        candidate_environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT": "1",
            }
        )
        confirmed_environment = self.base_environment()
        confirmed_environment.update(
            {
                "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "1",
                "CODEX_FD_DOCTOR_CONFIRMED_ORPHAN_NODE_REPL_COUNT": "1",
            }
        )

        candidate = self.run_doctor(candidate_environment)
        confirmed = self.run_doctor(confirmed_environment)

        self.assertEqual(1, candidate.returncode, candidate.stdout + candidate.stderr)
        self.assertIn("orphan_candidate_node_repl_processes", candidate.stdout)
        self.assertEqual(2, confirmed.returncode, confirmed.stdout + confirmed.stderr)
        self.assertIn("confirmed_orphan_node_repl_processes", confirmed.stdout)

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
