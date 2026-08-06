from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "scripts" / "autonomous_policy.py"
CAPACITY = ROOT / "scripts" / "codex_capacity.py"
PYTHON_39 = "/usr/bin/python3"


class AutonomousCapacityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="codex-policy-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.codex_home = self.root / "codex-home"
        self.home.mkdir()
        self.codex_home.mkdir()
        self.observer_snapshot_path = self.write_observer_snapshot()
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "CODEX_HOME": str(self.codex_home),
                "PYTHONPATH": str(ROOT / "scripts"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "CODEX_CAPACITY_OBSERVER_SNAPSHOT": str(self.observer_snapshot_path),
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_policy(
        self,
        event: str,
        payload: dict[str, object],
        *,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(POLICY), event],
            input=json.dumps(payload),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env=env or self.env,
        )


    def run_policy_with_python(
        self,
        executable: str,
        event: str,
        payload: dict[str, object],
        *,
        env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], float]:
        started = time.perf_counter()
        completed = subprocess.run(
            [executable, str(POLICY), event],
            input=json.dumps(payload),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env=env or self.env,
        )
        return completed, (time.perf_counter() - started) * 1000

    def capacity_cli(self, *args: str) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(CAPACITY), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            env=self.env,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        return json.loads(completed.stdout)

    def spawn_payload(self, task_name: str = "task-a", *, tool_name: str = "spawn_agent") -> dict[str, object]:
        return {
            "session_id": "session-1",
            "turn_id": "turn-1",
            "tool_name": tool_name,
            "tool_input": {"task_name": task_name, "agent_type": "worker"},
        }

    def audit_text(self) -> str:
        path = self.codex_home / "audit" / "hooks.jsonl"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def database_text(self) -> str:
        state = self.home / ".local" / "state" / "codex-capacity-v1"
        combined = ""
        for path in (state / "capacity.sqlite3", state / "events.jsonl"):
            if path.exists():
                combined += path.read_text(encoding="utf-8", errors="ignore")
        return combined

    def write_observer_snapshot(self, **overrides: object) -> Path:
        snapshot = {
            "total_ram_bytes": 32 * 1024 * 1024 * 1024,
            "available_memory_bytes": 16 * 1024 * 1024 * 1024,
            "memory_pressure": "normal",
            "swapouts_total_bytes": 0,
            "cpu_idle_percent": 55.0,
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
        snapshot.update(overrides)
        path = getattr(self, "observer_snapshot_path", self.root / "observer-snapshot.json")
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        return path

    def test_spawn_pretool_leases_and_aliases_are_recognized(self) -> None:
        first = self.run_policy("PreToolUse", self.spawn_payload("first", tool_name="spawn_agent"))
        second = self.run_policy("PreToolUse", self.spawn_payload("second", tool_name="Agent"))
        third = self.run_policy("PreToolUse", self.spawn_payload("third", tool_name="collaboration.spawn_agent"))

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(0, third.returncode, third.stderr)
        snapshot = self.capacity_cli("snapshot")
        self.assertEqual(3, snapshot["active_count"])

    def test_capacity_queue_blocks_with_retry_json(self) -> None:
        for index in range(6):
            completed = self.run_policy("PreToolUse", self.spawn_payload(f"fill-{index}"))
            self.assertEqual(0, completed.returncode, completed.stderr)

        queued = self.run_policy("PreToolUse", self.spawn_payload("queued"))

        self.assertEqual(2, queued.returncode)
        denial = json.loads(queued.stderr)
        self.assertEqual("CAPACITY_QUEUED", denial["code"])
        self.assertGreaterEqual(denial["retry_delay_ms"], 1)
        self.assertIn("wait", denial["wait_command"])

    def test_observer_red_blocks_new_spawn_before_lease(self) -> None:
        snapshot = self.write_observer_snapshot(memory_pressure="critical")
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        blocked = self.run_policy("PreToolUse", self.spawn_payload("red"), env=env)

        self.assertEqual(2, blocked.returncode)
        denial = json.loads(blocked.stderr)
        self.assertEqual("CAPACITY_OBSERVER_RED", denial["code"])
        self.assertEqual("RED", denial["status"])
        self.assertEqual(0, self.capacity_cli("snapshot")["active_count"])
        audit = [json.loads(line) for line in self.audit_text().splitlines()]
        self.assertEqual("RED", audit[-1]["details"]["capacity_observer"]["status"])

    def test_external_codex_roots_input_reduces_managed_capacity(self) -> None:
        snapshot = self.write_observer_snapshot(codex_root_count=6, external_codex_roots=6)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        blocked = self.run_policy("PreToolUse", self.spawn_payload("external-roots"), env=env)

        self.assertEqual(2, blocked.returncode)
        self.assertIn("CAPACITY_QUEUED", blocked.stderr)
        self.assertEqual(0, self.capacity_cli("snapshot")["active_count"])

    def test_codex_root_count_without_external_roots_does_not_reduce_capacity(self) -> None:
        snapshot = self.write_observer_snapshot(codex_root_count=6)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        allowed = self.run_policy("PreToolUse", self.spawn_payload("managed-root-count"), env=env)

        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual(1, self.capacity_cli("snapshot")["active_count"])

    def test_yellow_limits_new_wave_to_two_slots(self) -> None:
        snapshot = self.write_observer_snapshot(cpu_idle_percent=10.0)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        first = self.run_policy("PreToolUse", self.spawn_payload("yellow-1"), env=env)
        second = self.run_policy("PreToolUse", self.spawn_payload("yellow-2"), env=env)
        third = self.run_policy("PreToolUse", self.spawn_payload("yellow-3"), env=env)

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(2, third.returncode)
        self.assertEqual("CAPACITY_QUEUED", json.loads(third.stderr)["code"])
        self.assertEqual(2, self.capacity_cli("snapshot")["active_count"])

    def test_reserved_slots_are_passed_to_observer(self) -> None:
        first = self.run_policy("PreToolUse", self.spawn_payload("reserved-1"))
        second = self.run_policy("PreToolUse", self.spawn_payload("reserved-2"))

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        audit = [json.loads(line) for line in self.audit_text().splitlines()]
        observed_slots = [
            record["details"]["capacity_observer"]["measurements"]["active_slots"]
            for record in audit
            if record["event"] == "PreToolUse" and record["details"].get("request_id")
        ]
        self.assertEqual([0.0, 1.0], observed_slots)

    def test_failed_spawn_releases_provisional_but_success_does_not(self) -> None:
        payload = self.spawn_payload("will-fail")
        leased = self.run_policy("PreToolUse", payload)
        self.assertEqual(0, leased.returncode, leased.stderr)
        failed_payload = dict(payload)
        failed_payload["tool_response"] = {"ok": False}

        failed = self.run_policy("PostToolUse", failed_payload)

        self.assertEqual(0, failed.returncode, failed.stderr)
        self.assertEqual(0, self.capacity_cli("snapshot")["active_count"])

        success_payload = self.spawn_payload("will-succeed")
        self.assertEqual(0, self.run_policy("PreToolUse", success_payload).returncode)
        success_payload["tool_response"] = {"ok": True}
        self.assertEqual(0, self.run_policy("PostToolUse", success_payload).returncode)
        self.assertEqual(1, self.capacity_cli("snapshot")["active_count"])

    def test_lifecycle_events_activate_release_cancel_and_reconcile(self) -> None:
        self.assertEqual(0, self.run_policy("PreToolUse", self.spawn_payload("life")).returncode)

        started = self.run_policy(
            "SubagentStart",
            {"session_id": "session-1", "turn_id": "turn-1", "agent_id": "agent-1", "agent_type": "worker"},
        )
        self.assertEqual(0, started.returncode, started.stderr)
        self.assertEqual("ACTIVE", self.capacity_cli("snapshot")["leases"][0]["state"])

        stopped = self.run_policy("SubagentStop", {"session_id": "session-1", "agent_id": "agent-1"})
        self.assertEqual(0, stopped.returncode, stopped.stderr)
        self.assertEqual(0, self.capacity_cli("snapshot")["active_count"])

        queued = self.spawn_payload("queued", tool_name="spawn_agent")
        self.assertEqual(0, self.run_policy("PreToolUse", queued).returncode)
        self.run_policy("Stop", {"session_id": "session-1", "turn_id": "turn-1"})
        ended = self.run_policy("SessionEnd", {"session_id": "session-1", "reason": "shutdown"})
        self.assertEqual(0, ended.returncode, ended.stderr)

    def test_enforcement_can_be_disabled(self) -> None:
        env = dict(self.env, CODEX_CAPACITY_ENFORCEMENT="0")
        for index in range(8):
            completed = self.run_policy("PreToolUse", self.spawn_payload(f"bypass-{index}"), env=env)
            self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(0, self.capacity_cli("snapshot")["active_count"])

    def test_sensitive_task_text_is_not_audited_or_stored(self) -> None:
        secret = "secret task phrase for capacity policy"
        completed = self.run_policy("PreToolUse", self.spawn_payload(secret))

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertNotIn(secret, completed.stdout + completed.stderr)
        self.assertNotIn(secret, self.audit_text())
        self.assertNotIn(secret, self.database_text())
        self.assertNotIn("tool_input", self.audit_text())
        self.assertNotIn("message", self.audit_text())

    def test_lifecycle_identity_fail_open_but_pretool_fails_closed(self) -> None:
        self.assertEqual(0, self.run_policy("SubagentStart", {"session_id": "s"}).returncode)
        self.assertEqual(0, self.run_policy("SubagentStop", {"session_id": "s"}).returncode)
        self.assertEqual(0, self.run_policy("SessionEnd", {}).returncode)

        missing = self.run_policy("PreToolUse", {"tool_name": "spawn_agent", "tool_input": {"task_name": "x"}})
        self.assertEqual(2, missing.returncode)
        self.assertIn("session_id", missing.stderr)

    def test_usr_bin_python_black_box_hook_latency_uses_internal_hook_metric(self) -> None:
        env = dict(
            self.env,
            CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(self.write_observer_snapshot()),
        )
        warmup_payload = self.spawn_payload("warmup")
        warmup_payload["session_id"] = "latency-warmup"
        warmup, _ = self.run_policy_with_python(PYTHON_39, "PreToolUse", warmup_payload, env=env)
        self.assertEqual(0, warmup.returncode, warmup.stderr)

        def run_one(index: int) -> float:
            payload = self.spawn_payload(f"latency-{index}")
            payload["session_id"] = f"latency-{index}"
            payload["turn_id"] = f"turn-{index}"
            completed, elapsed_ms = self.run_policy_with_python(PYTHON_39, "PreToolUse", payload, env=env)
            self.assertIn(completed.returncode, (0, 2), completed.stderr)
            if completed.returncode == 2:
                self.assertEqual("CAPACITY_QUEUED", json.loads(completed.stderr)["code"])
            return elapsed_ms

        wall_latencies = [run_one(index) for index in range(32)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            wall_latencies.extend(pool.map(run_one, range(32, 64)))

        records = [json.loads(line) for line in self.audit_text().splitlines()]
        hook_latencies = sorted(
            record["details"]["hook_elapsed_ms"]
            for record in records
            if record["event"] == "PreToolUse"
            and record["details"].get("session_id", "").startswith("latency")
        )
        self.assertEqual(65, len(hook_latencies))
        hook_latencies = hook_latencies[1:]
        p95 = hook_latencies[int(len(hook_latencies) * 0.95) - 1]
        p99 = hook_latencies[int(len(hook_latencies) * 0.99) - 1]
        self.assertLess(p95, 250, hook_latencies)
        self.assertLess(p99, 500, hook_latencies)


if __name__ == "__main__":
    unittest.main()
