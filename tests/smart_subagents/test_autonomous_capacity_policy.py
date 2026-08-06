from __future__ import annotations

import concurrent.futures
import importlib.util
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


def load_policy_module():
    name = "autonomous_policy_under_test"
    spec = importlib.util.spec_from_file_location(name, POLICY)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load policy module: {POLICY}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


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
                "CODEX_CAPACITY_OBSERVER_TEST_MODE": "1",
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

    def test_observer_snapshot_env_is_ignored_without_test_mode(self) -> None:
        invalid_snapshot = self.root / "invalid-observer-snapshot.json"
        invalid_snapshot.write_text("not json", encoding="utf-8")
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(invalid_snapshot))
        env.pop("CODEX_CAPACITY_OBSERVER_TEST_MODE", None)

        completed = self.run_policy("PreToolUse", self.spawn_payload("ignored-snapshot"), env=env)

        self.assertIn(completed.returncode, (0, 2), completed.stderr)
        self.assertNotIn("Expecting value", completed.stderr)
        self.assertNotIn("capacity observer snapshot must", completed.stderr)
        audit = [json.loads(line) for line in self.audit_text().splitlines()]
        self.assertEqual("ignored_without_test_mode", audit[-1]["details"]["capacity_observer_snapshot_env"])

    def test_policy_subtracts_external_roots_from_observer_admission_once(self) -> None:
        snapshot = self.write_observer_snapshot(codex_root_count=2, external_codex_roots=2)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        allowed = self.run_policy("PreToolUse", self.spawn_payload("external-roots"), env=env)

        self.assertEqual(0, allowed.returncode, allowed.stderr)
        audit = [json.loads(line) for line in self.audit_text().splitlines()]
        details = audit[-1]["details"]
        admission = details["capacity_observer"]["admission_capacity"]
        self.assertEqual(2, details["capacity_external_codex_roots"])
        self.assertEqual(admission - 2, details["capacity_limit"])

    def test_observer_admission_capacity_is_not_reduced_twice_by_external_roots(self) -> None:
        snapshot = self.write_observer_snapshot(codex_root_count=2, external_codex_roots=2)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        first = self.run_policy("PreToolUse", self.spawn_payload("external-admission-0"), env=env)
        self.assertEqual(0, first.returncode, first.stderr)
        audit = [json.loads(line) for line in self.audit_text().splitlines()]
        admission = int(audit[-1]["details"]["capacity_observer"]["admission_capacity"])
        capacity_limit = admission - int(audit[-1]["details"]["capacity_external_codex_roots"])

        for index in range(1, capacity_limit):
            allowed = self.run_policy("PreToolUse", self.spawn_payload(f"external-admission-{index}"), env=env)
            self.assertEqual(0, allowed.returncode, allowed.stderr)

        queued = self.run_policy("PreToolUse", self.spawn_payload("external-admission-queued"), env=env)

        self.assertEqual(2, queued.returncode)
        self.assertEqual("CAPACITY_QUEUED", json.loads(queued.stderr)["code"])
        self.assertEqual(capacity_limit, self.capacity_cli("snapshot")["active_count"])

    def test_codex_root_count_without_external_roots_does_not_reduce_capacity(self) -> None:
        snapshot = self.write_observer_snapshot(codex_root_count=6)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        allowed = self.run_policy("PreToolUse", self.spawn_payload("managed-root-count"), env=env)

        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual(1, self.capacity_cli("snapshot")["active_count"])

    def test_pretool_registers_current_root_identity_without_auditing_it(self) -> None:
        snapshot = self.write_observer_snapshot(
            codex_root_count=1,
            external_codex_roots=0,
            current_codex_root_pid=700,
            current_codex_root_start_marker="root-start-marker",
        )
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        allowed = self.run_policy("PreToolUse", self.spawn_payload("managed-root"), env=env)

        self.assertEqual(0, allowed.returncode, allowed.stderr)
        capacity = self.capacity_cli("snapshot")
        self.assertEqual(1, capacity["managed_root_count"])
        self.assertEqual(1, capacity["managed_root_session_count"])
        audit = self.audit_text()
        self.assertNotIn("700", audit)
        self.assertNotIn("root-start-marker", audit)

    def test_test_snapshot_does_not_reconcile_live_root_registry(self) -> None:
        registered = self.spawn_payload("registered-root")
        snapshot = self.write_observer_snapshot(
            codex_root_count=1,
            external_codex_roots=0,
            current_codex_root_pid=700,
            current_codex_root_start_marker="root-secret",
        )
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))
        allowed = self.run_policy("PreToolUse", registered, env=env)
        self.assertEqual(0, allowed.returncode, allowed.stderr)

        missing_snapshot = self.write_observer_snapshot(codex_root_count=0, external_codex_roots=0)
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(missing_snapshot))
        second = self.spawn_payload("after-test-snapshot")
        second["turn_id"] = "turn-2"
        completed = self.run_policy("PreToolUse", second, env=env)

        self.assertEqual(0, completed.returncode, completed.stderr)
        states = {lease["session_id"]: lease["state"] for lease in self.capacity_cli("snapshot")["leases"]}
        self.assertEqual("PROVISIONAL", states["session-1"])
        audit = self.audit_text()
        self.assertNotIn("root-secret", audit)

    def test_red_observer_keeps_existing_lease_reserved_and_blocks_new_spawn(self) -> None:
        first = self.run_policy("PreToolUse", self.spawn_payload("before-red"))
        self.assertEqual(0, first.returncode, first.stderr)
        snapshot = self.write_observer_snapshot(memory_pressure="critical")
        env = dict(self.env, CODEX_CAPACITY_OBSERVER_SNAPSHOT=str(snapshot))

        blocked = self.run_policy("PreToolUse", self.spawn_payload("during-red"), env=env)

        self.assertEqual(2, blocked.returncode)
        self.assertEqual("CAPACITY_OBSERVER_RED", json.loads(blocked.stderr)["code"])
        self.assertEqual(1, self.capacity_cli("snapshot")["active_count"])

    def test_live_observer_without_current_root_identity_fails_closed(self) -> None:
        policy = load_policy_module()

        class FakeStore:
            state_dir = self.root / "state"

            def snapshot(self):
                return {"state": "OK", "active_count": 0, "reserved_count": 0}

            def managed_root_identities(self):
                return []

            def reconcile_managed_roots(self, **kwargs):
                raise AssertionError("reconcile must not run without current root")

        snapshot = self.write_observer_snapshot(codex_root_count=0, external_codex_roots=0)
        payload = json.loads(snapshot.read_text(encoding="utf-8"))
        payload["codex_process_snapshot_started_at"] = 1000.0
        original_collect = policy.capacity_observer.collect_snapshot
        try:
            policy.capacity_observer.collect_snapshot = lambda **kwargs: payload
            _limit, _wave, reason, root_identity = policy.observed_capacity_limit(FakeStore(), {}, deadline=time.perf_counter() + 1.0)
        finally:
            policy.capacity_observer.collect_snapshot = original_collect

        self.assertIsNone(root_identity)
        denial = json.loads(reason)
        self.assertEqual("CAPACITY_OBSERVER_RED", denial["code"])
        self.assertIn("current_codex_root_identity_missing", denial["reasons"])

    def test_managed_root_recovery_error_blocks_pretool_admission(self) -> None:
        policy = load_policy_module()

        class FakeStore:
            state_dir = self.root / "state"

            def snapshot(self):
                return {"state": "OK", "active_count": 1, "reserved_count": 1}

            def managed_root_identities(self):
                return [(700, "old-root")]

            def reconcile_managed_roots(self, **kwargs):
                return {"state": "ERROR", "reason": "proof_failed"}

        snapshot = self.write_observer_snapshot(codex_root_count=1, external_codex_roots=0)
        payload = json.loads(snapshot.read_text(encoding="utf-8"))
        payload["current_codex_root_identity"] = (800, "current-root")
        payload["managed_codex_root_identities"] = []
        payload["codex_process_snapshot_started_at"] = 1000.0
        original_collect = policy.capacity_observer.collect_snapshot
        try:
            policy.capacity_observer.collect_snapshot = lambda **kwargs: payload
            _limit, _wave, reason, root_identity = policy.observed_capacity_limit(FakeStore(), {}, deadline=time.perf_counter() + 1.0)
        finally:
            policy.capacity_observer.collect_snapshot = original_collect

        self.assertEqual((800, "current-root"), root_identity)
        self.assertEqual("capacity error: proof_failed", reason)

    def test_two_codex_homes_share_one_global_capacity_database(self) -> None:
        codex_home_a = self.root / "codex-home-a"
        codex_home_b = self.root / "codex-home-b"
        codex_home_a.mkdir()
        codex_home_b.mkdir()
        env_a = dict(self.env, CODEX_HOME=str(codex_home_a))
        env_b = dict(self.env, CODEX_HOME=str(codex_home_b))

        leased_payloads: list[tuple[dict[str, object], dict[str, str]]] = []
        for index in range(6):
            payload = self.spawn_payload(f"shared-{index}")
            payload["session_id"] = f"shared-session-{index}"
            payload["turn_id"] = f"shared-turn-{index}"
            env = env_a if index % 2 == 0 else env_b
            completed = self.run_policy("PreToolUse", payload, env=env)
            self.assertEqual(0, completed.returncode, completed.stderr)
            leased_payloads.append((payload, env))

        queued_payload = self.spawn_payload("shared-queued")
        queued_payload["session_id"] = "shared-session-queued"
        queued_payload["turn_id"] = "shared-turn-queued"
        queued = self.run_policy("PreToolUse", queued_payload, env=env_b)
        self.assertEqual(2, queued.returncode)
        self.assertEqual("CAPACITY_QUEUED", json.loads(queued.stderr)["code"])
        self.assertEqual(6, self.capacity_cli("snapshot")["active_count"])

        release_payload, release_env = leased_payloads[0]
        failed_payload = dict(release_payload)
        failed_payload["tool_response"] = {"ok": False}
        released = self.run_policy("PostToolUse", failed_payload, env=release_env)
        self.assertEqual(0, released.returncode, released.stderr)

        retried = self.run_policy("PreToolUse", queued_payload, env=env_b)
        self.assertEqual(0, retried.returncode, retried.stderr)
        self.assertEqual(6, self.capacity_cli("snapshot")["active_count"])

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

    def test_pretool_capacity_path_fails_closed_when_absolute_deadline_is_exhausted(self) -> None:
        env = dict(self.env, CODEX_CAPACITY_HOOK_DEADLINE_MS="1")

        completed = self.run_policy("PreToolUse", self.spawn_payload("deadline"), env=env)

        self.assertEqual(2, completed.returncode)
        denial = json.loads(completed.stderr)
        self.assertEqual("CAPACITY_DEADLINE_EXHAUSTED", denial["code"])
        audit = [json.loads(line) for line in self.audit_text().splitlines()]
        self.assertLess(audit[-1]["details"]["hook_elapsed_ms"], 1000)

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
