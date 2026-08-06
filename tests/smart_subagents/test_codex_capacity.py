from __future__ import annotations

import importlib.util
import hashlib
import json
import math
import multiprocessing
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
CAPACITY = ROOT / "scripts" / "codex_capacity.py"


def load_capacity() -> ModuleType:
    name = "codex_capacity_under_test"
    spec = importlib.util.spec_from_file_location(name, CAPACITY)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load capacity module: {CAPACITY}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def process_acquire_worker(home: str, index: int, start_event, queue) -> None:
    capacity = load_capacity()
    store = capacity.CapacityStore(home=Path(home), capacity=20)
    start_event.wait(10)
    started = time.monotonic()
    result = store.acquire_or_queue(session_id=f"proc-{index}", turn_id="t1", task_name=f"task-{index}")
    elapsed = time.monotonic() - started
    reason = str(result.get("reason", ""))
    queue.put(
        {
            "elapsed": elapsed,
            "state": result.get("state"),
            "reason": reason,
            "locked_or_busy": "locked" in reason.lower() or "busy" in reason.lower(),
        }
    )


class CodexCapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="codex-capacity-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = os.environ.copy()
        self.env.update({"HOME": str(self.home)})
        self.capacity = load_capacity()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def state_dir(self) -> Path:
        return self.home / ".local" / "state" / "codex-capacity-v1"

    @property
    def db_path(self) -> Path:
        return self.state_dir / "capacity.sqlite3"

    def manager(self, *, limit: int = 6) -> object:
        return self.capacity.CapacityStore(home=self.home, capacity=limit)

    def lease_states_by_session(self, store: object) -> dict[str, str]:
        return {str(lease["session_id"]): str(lease["state"]) for lease in store.snapshot()["leases"]}

    def cli(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CAPACITY), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env or self.env,
        )

    def read_cli_json(self, *args: str, env: dict[str, str] | None = None) -> dict[str, object]:
        completed = self.cli(*args, env=env)
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertIsInstance(payload, dict)
        return payload

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
        path = self.root / "observer-snapshot.json"
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        return path

    def write_trusted_wide_wave_inputs(self, *, wave_size: int = 8) -> tuple[Path, Path, Path]:
        skill = self.root / "trusted-wide-skill.md"
        skill.write_text("---\nname: trusted-wide\n---\n", encoding="utf-8")
        registry = self.root / "trusted-wide-registry.json"
        registry.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "trusted_skills": [
                        {
                            "skill_id": "trusted-wide",
                            "sha256": hashlib.sha256(skill.read_bytes()).hexdigest(),
                            "max_live_wave": 20,
                            "execution_kind": "wide-wave",
                            "fallback": "block",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        repo = self.root / "repo"
        repo.mkdir(exist_ok=True)
        manifest = self.root / "trusted-wide-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "skill_id": "trusted-wide",
                    "wave_size": wave_size,
                    "repository_root": str(repo),
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

    def write_dynamic_green_observer_state(self, state_dir: Path, *, effective_capacity: int = 20) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        sample = {"memory_bytes": 1, "processes": 1, "root_fds": 1, "system_fds": 1, "heavy_lanes": 0}
        samples = [
            dict(sample)
            for _ in range(30)
        ]
        (state_dir / "observer_state.json").write_text(
            json.dumps(
                {
                    "protocol_version": 1,
                    "last_observed_at": 100.0,
                    "last_status": "GREEN",
                    "last_snapshot": None,
                    "recovery": {"from_status": None, "started_at": None, "normal_count": 0, "last_normal_at": None},
                    "observations": [],
                    "successful_observations": 30,
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
        accepted_count = 30 + 10 * [8, 12, 16, 20].index(effective_capacity) + 10 if effective_capacity > 6 else 30
        (state_dir / "calibration_state.json").write_text(
            json.dumps(
                {
                    "protocol_version": 1,
                    "active": None,
                    "classes": {
                        "normal": {
                            "samples": [dict(sample) for _ in range(accepted_count)],
                            "accepted_count": accepted_count,
                            "rejected_count": 0,
                            "last_rejection_code": None,
                            "saturated_clean_cycles": 0,
                            "effective_capacity": effective_capacity,
                            "proven_capacity": effective_capacity,
                            "cost_estimate": dict(sample),
                            "cost_updated_at": 1000.0,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
    def request(self, index: int, *, session: str = "s1", turn: str = "t1") -> dict[str, str]:
        return {"session_id": session, "turn_id": turn, "task_name": f"task-{index}"}

    def test_two_codex_home_values_share_one_user_database(self) -> None:
        env_one = dict(self.env, CODEX_HOME=str(self.root / "codex-one"))
        env_two = dict(self.env, CODEX_HOME=str(self.root / "codex-two"))

        first = self.read_cli_json(
            "acquire-or-queue",
            "--session-id",
            "s1",
            "--turn-id",
            "t1",
            "--task-name",
            "alpha",
            "--capacity",
            "1",
            env=env_one,
        )
        second = self.read_cli_json(
            "acquire-or-queue",
            "--session-id",
            "s2",
            "--turn-id",
            "t1",
            "--task-name",
            "beta",
            "--capacity",
            "1",
            env=env_two,
        )

        self.assertEqual("LEASED", first["state"])
        self.assertEqual("PENDING", second["ticket_state"])
        self.assertEqual("CAPACITY_QUEUED", second["state"])
        self.assertEqual(1, second["ticket_position"])
        self.assertGreaterEqual(second["retry_delay_ms"], 1)
        self.assertIn(" wait ", second["wait_command"])
        self.assertIn(str(second["ticket_id"]), second["wait_command"])
        self.assertTrue(self.db_path.exists())

    def test_acquire_is_idempotent_and_does_not_store_task_text(self) -> None:
        store = self.manager()
        first = store.acquire_or_queue(**self.request(1, session="s1"))
        second = store.acquire_or_queue(**self.request(1, session="s1"))

        self.assertEqual(first["request_id"], second["request_id"])
        self.assertEqual(first["lease_id"], second["lease_id"])
        self.assertEqual(1, store.snapshot()["active_count"])
        self.assertNotIn("task-1", self.db_path.read_text(encoding="utf-8", errors="ignore"))

    def test_managed_root_registry_deduplicates_sessions_and_requires_start_marker(self) -> None:
        store = self.manager()

        first = store.acquire_or_queue(
            **self.request(1, session="tab-a"),
            root_pid=700,
            root_start_marker="start-a",
        )
        second = store.acquire_or_queue(
            **self.request(1, session="tab-b"),
            root_pid=700,
            root_start_marker="start-a",
        )

        self.assertEqual("LEASED", first["state"])
        self.assertEqual("LEASED", second["state"])
        self.assertEqual(
            [(700, "start-a")],
            store.managed_root_identities(),
        )
        self.assertTrue(store.is_managed_root(root_pid=700, root_start_marker="start-a"))
        self.assertFalse(store.is_managed_root(root_pid=700, root_start_marker="start-b"))
        self.assertEqual(2, store.snapshot()["managed_root_session_count"])
        self.assertEqual(1, store.snapshot()["managed_root_count"])

    def test_session_end_removes_only_that_session_root_registration(self) -> None:
        store = self.manager()
        store.acquire_or_queue(
            **self.request(1, session="tab-a"),
            root_pid=700,
            root_start_marker="start-a",
        )
        store.acquire_or_queue(
            **self.request(1, session="tab-b"),
            root_pid=800,
            root_start_marker="start-b",
        )

        store.cancel_session(session_id="tab-a")

        self.assertFalse(store.is_managed_root(root_pid=700, root_start_marker="start-a"))
        self.assertTrue(store.is_managed_root(root_pid=800, root_start_marker="start-b"))
        self.assertEqual([(800, "start-b")], store.managed_root_identities())

    def test_missing_managed_root_recovery_advances_one_stage_per_proof(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            lease = store.acquire_or_queue(
                **self.request(1, session="dead-tab", turn="t1"),
                root_pid=700,
                root_start_marker="root-old",
            )
            store.activate_next(session_id="dead-tab", turn_id="t1", agent_id="agent-a")
            queued = store.acquire_or_queue(**self.request(2, session="next-tab", turn="t1"))

            clock["now"] = 100.0
            first = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=99.0)
            self.assertEqual(1, first["suspect_leases"])
            self.assertEqual("SUSPECT", self.lease_states_by_session(store)["dead-tab"])
            self.assertEqual("PENDING", store.wait(str(queued["ticket_id"]))["ticket_state"])

            clock["now"] = 105.0
            early = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=104.0)
            self.assertEqual(0, early["recovering_leases"])
            self.assertEqual("SUSPECT", self.lease_states_by_session(store)["dead-tab"])

            clock["now"] = 111.0
            second = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=110.0)
            self.assertEqual(1, second["recovering_leases"])
            self.assertEqual("RECOVERING", self.lease_states_by_session(store)["dead-tab"])

            clock["now"] = 130.0
            final = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=129.0)
            self.assertEqual(1, final["released_leases"])
            self.assertEqual("RELEASED", self.lease_states_by_session(store)["dead-tab"])
            self.assertEqual("READY", store.wait(str(queued["ticket_id"]))["ticket_state"])
            self.assertEqual(0, store.snapshot()["managed_root_count"])
            repeated_release = store.release(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
            self.assertEqual("LEASED", repeated_release["state"])
            self.assertEqual("RELEASED", repeated_release["lease_state"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_recovery_never_advances_more_than_one_stage_per_call(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 100.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            store.acquire_or_queue(
                **self.request(1, session="tab-a", turn="t1"),
                root_pid=700,
                root_start_marker="root-a",
            )
            store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")

            result = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=999.0, stage_seconds=0)

            self.assertEqual(1, result["suspect_leases"])
            self.assertEqual(0, result["recovering_leases"])
            self.assertEqual(0, result["released_leases"])
            self.assertEqual("SUSPECT", self.lease_states_by_session(store)["tab-a"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_present_managed_root_restores_suspect_and_recovering_to_active(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=2, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            store.acquire_or_queue(
                **self.request(1, session="tab-a", turn="t1"),
                root_pid=700,
                root_start_marker="root-a",
            )
            store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")
            clock["now"] = 1.0
            store.reconcile_managed_roots(live_root_identities=[], proof_started_at=0.5)
            self.assertEqual("SUSPECT", self.lease_states_by_session(store)["tab-a"])

            clock["now"] = 2.0
            restored = store.reconcile_managed_roots(live_root_identities=[(700, "root-a")], proof_started_at=1.5)
            self.assertEqual(1, restored["restored_leases"])
            self.assertEqual("ACTIVE", self.lease_states_by_session(store)["tab-a"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_reused_pid_with_different_start_marker_is_treated_as_missing_owner(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=2, provisional_ttl_seconds=999)
        store.acquire_or_queue(
            **self.request(1, session="tab-a", turn="t1"),
            root_pid=700,
            root_start_marker="root-old",
        )
        store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")

        result = store.reconcile_managed_roots(live_root_identities=[(700, "root-new")], proof_started_at=time.time() + 1)

        self.assertEqual(1, result["suspect_leases"])
        self.assertEqual("SUSPECT", self.lease_states_by_session(store)["tab-a"])

    def test_invalid_or_incomplete_root_proof_does_not_release_capacity(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        store.acquire_or_queue(
            **self.request(1, session="tab-a", turn="t1"),
            root_pid=700,
            root_start_marker="root-a",
        )
        store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")

        invalid_identity = store.reconcile_managed_roots(live_root_identities=[(700, "")], proof_started_at=time.time() + 1)
        invalid_time = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=float("nan"))

        self.assertEqual("ERROR", invalid_identity["state"])
        self.assertEqual("ERROR", invalid_time["state"])
        self.assertEqual("ACTIVE", self.lease_states_by_session(store)["tab-a"])
        self.assertEqual(1, store.snapshot()["active_count"])

    def test_recovery_skips_leases_updated_after_proof_started(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        store.acquire_or_queue(
            **self.request(1, session="tab-a", turn="t1"),
            root_pid=700,
            root_start_marker="root-a",
        )
        store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("update leases set updated_at = 200 where session_id = 'tab-a'")
            conn.commit()
        finally:
            conn.close()

        result = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=100.0)

        self.assertEqual(0, result["suspect_leases"])
        self.assertEqual("ACTIVE", self.lease_states_by_session(store)["tab-a"])

    def test_late_activate_does_not_revive_root_recovery_states(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=2, provisional_ttl_seconds=999)
        for index, recovery_state in enumerate(("SUSPECT", "RECOVERING"), start=1):
            with self.subTest(recovery_state=recovery_state):
                lease = store.acquire_or_queue(
                    **self.request(index, session=f"tab-{index}", turn="t1"),
                    root_pid=700 + index,
                    root_start_marker=f"root-{index}",
                )
                store.activate_next(session_id=f"tab-{index}", turn_id="t1", agent_id=f"agent-{index}")
                conn = sqlite3.connect(self.db_path)
                try:
                    conn.execute(
                        "update leases set state = ?, cleanup_after = 1 where lease_id = ?",
                        (recovery_state, lease["lease_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()

                result = store.activate(
                    lease_id=str(lease["lease_id"]),
                    fencing_epoch=int(lease["fencing_epoch"]),
                    agent_id=f"late-agent-{index}",
                )

                self.assertEqual("STALE", result["state"])
                self.assertEqual("managed_root_recovery_required", result["reason"])
                self.assertEqual(recovery_state, self.lease_states_by_session(store)[f"tab-{index}"])

    def test_live_session_cannot_replace_managed_root_generation(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=2, provisional_ttl_seconds=999)
        lease = store.acquire_or_queue(
            **self.request(1, session="tab-a", turn="t1"),
            root_pid=700,
            root_start_marker="root-old",
        )

        conflict = store.acquire_or_queue(
            **self.request(2, session="tab-a", turn="t2"),
            root_pid=701,
            root_start_marker="root-new",
        )

        self.assertEqual("ERROR", conflict["state"])
        self.assertEqual("managed_root_generation_conflict", conflict["reason"])
        self.assertEqual([(700, "root-old")], store.managed_root_identities())

        store.release(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
        replacement = store.acquire_or_queue(
            **self.request(3, session="tab-a", turn="t3"),
            root_pid=701,
            root_start_marker="root-new",
        )
        self.assertEqual("LEASED", replacement["state"])
        self.assertEqual([(701, "root-new")], store.managed_root_identities())

    def test_final_recovery_does_not_cancel_tickets_updated_after_proof_started(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            store.acquire_or_queue(
                **self.request(1, session="tab-a", turn="t1"),
                root_pid=700,
                root_start_marker="root-a",
            )
            store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")
            old_ticket = store.acquire_or_queue(**self.request(2, session="tab-a", turn="t1"))
            new_ticket = store.acquire_or_queue(**self.request(3, session="tab-a", turn="t1"))
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("update leases set state = 'RECOVERING', cleanup_after = 1, updated_at = 1 where session_id = 'tab-a'")
                conn.execute("update tickets set updated_at = 1 where ticket_id = ?", (old_ticket["ticket_id"],))
                conn.execute("update tickets set updated_at = 200 where ticket_id = ?", (new_ticket["ticket_id"],))
                conn.commit()
            finally:
                conn.close()

            clock["now"] = 20.0
            result = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=100.0)

            self.assertEqual(1, result["released_leases"])
            self.assertEqual("CANCELED", store.wait(str(old_ticket["ticket_id"]))["ticket_state"])
            self.assertEqual("READY", store.wait(str(new_ticket["ticket_id"]))["ticket_state"])
            self.assertEqual(1, store.snapshot()["managed_root_count"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_missing_root_with_only_old_tickets_is_canceled_and_unregistered_after_proof(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            lease = store.acquire_or_queue(
                **self.request(1, session="dead-tab", turn="t1"),
                root_pid=700,
                root_start_marker="root-old",
            )
            store.activate_next(session_id="dead-tab", turn_id="t1", agent_id="agent-a")
            ready = store.acquire_or_queue(**self.request(2, session="dead-tab", turn="t1"))
            next_ticket = store.acquire_or_queue(**self.request(1, session="next-tab", turn="t1"))
            self.assertEqual("PENDING", next_ticket["ticket_state"])
            store.release(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
            self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("update tickets set updated_at = 1 where ticket_id = ?", (ready["ticket_id"],))
                conn.commit()
            finally:
                conn.close()

            clock["now"] = 100.0
            first = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=99.0)
            self.assertEqual(1, first["suspect_roots"])
            self.assertEqual(0, first["canceled_tickets"])
            self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])

            clock["now"] = 111.0
            second = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=110.0)
            self.assertEqual(1, second["recovering_roots"])
            self.assertEqual(0, second["canceled_tickets"])
            self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])

            clock["now"] = 130.0
            result = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=129.0)

            self.assertEqual(0, result["released_leases"])
            self.assertEqual(1, result["canceled_tickets"])
            self.assertEqual("CANCELED", store.wait(str(ready["ticket_id"]))["ticket_state"])
            self.assertEqual("READY", store.wait(str(next_ticket["ticket_id"]))["ticket_state"])
            self.assertEqual(0, store.snapshot()["managed_root_count"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_missing_root_does_not_cancel_new_or_live_session_tickets(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=2, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            dead_lease = store.acquire_or_queue(
                **self.request(1, session="dead-tab", turn="t1"),
                root_pid=700,
                root_start_marker="root-old",
            )
            live_lease = store.acquire_or_queue(
                **self.request(1, session="live-tab", turn="t1"),
                root_pid=800,
                root_start_marker="root-live",
            )
            store.activate_next(session_id="dead-tab", turn_id="t1", agent_id="agent-a")
            store.activate_next(session_id="live-tab", turn_id="t1", agent_id="agent-b")
            old_ticket = store.acquire_or_queue(**self.request(2, session="dead-tab", turn="t1"))
            new_ticket = store.acquire_or_queue(**self.request(3, session="dead-tab", turn="t1"))
            live_ticket = store.acquire_or_queue(**self.request(2, session="live-tab", turn="t1"))
            store.release(lease_id=str(dead_lease["lease_id"]), fencing_epoch=int(dead_lease["fencing_epoch"]))
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "update managed_roots set root_state = 'RECOVERING', cleanup_after = 1, updated_at = 1 where session_id = 'dead-tab'"
                )
                conn.execute("update tickets set updated_at = 1 where ticket_id = ?", (old_ticket["ticket_id"],))
                conn.execute("update tickets set updated_at = 200 where ticket_id = ?", (new_ticket["ticket_id"],))
                conn.execute("update tickets set updated_at = 1 where ticket_id = ?", (live_ticket["ticket_id"],))
                conn.commit()
            finally:
                conn.close()

            clock["now"] = 20.0
            result = store.reconcile_managed_roots(live_root_identities=[(800, "root-live")], proof_started_at=100.0)

            self.assertEqual(1, result["canceled_tickets"])
            self.assertEqual("CANCELED", store.wait(str(old_ticket["ticket_id"]))["ticket_state"])
            self.assertIn(store.wait(str(new_ticket["ticket_id"]))["ticket_state"], {"PENDING", "READY"})
            self.assertIn(store.wait(str(live_ticket["ticket_id"]))["ticket_state"], {"PENDING", "READY"})
            self.assertEqual("ACTIVE", self.lease_states_by_session(store)["live-tab"])
            self.assertEqual("LEASED", store.release(lease_id=str(live_lease["lease_id"]), fencing_epoch=int(live_lease["fencing_epoch"]))["state"])
            self.assertEqual(2, store.snapshot()["managed_root_session_count"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_present_root_between_ticket_recovery_stages_keeps_tickets_and_root_registration(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            lease = store.acquire_or_queue(
                **self.request(1, session="tab-a", turn="t1"),
                root_pid=700,
                root_start_marker="root-a",
            )
            store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")
            ready = store.acquire_or_queue(**self.request(2, session="tab-a", turn="t1"))
            store.release(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
            self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])

            clock["now"] = 100.0
            first = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=99.0)
            self.assertEqual(1, first["suspect_roots"])

            clock["now"] = 105.0
            restored = store.reconcile_managed_roots(live_root_identities=[(700, "root-a")], proof_started_at=104.0)

            self.assertEqual(1, restored["restored_roots"])
            self.assertEqual(0, restored["canceled_tickets"])
            self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])
            self.assertEqual(1, store.snapshot()["managed_root_count"])

            clock["now"] = 130.0
            later_missing = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=129.0)
            self.assertEqual(1, later_missing["suspect_roots"])
            self.assertEqual(0, later_missing["canceled_tickets"])
            self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_recovery_returns_exact_counts_after_release_cancel_and_promote(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            store.acquire_or_queue(
                **self.request(1, session="tab-a", turn="t1"),
                root_pid=700,
                root_start_marker="root-a",
            )
            store.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")
            same_session_ticket = store.acquire_or_queue(**self.request(2, session="tab-a", turn="t1"))
            other_session_ticket = store.acquire_or_queue(**self.request(1, session="tab-b", turn="t1"))
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("update leases set state = 'RECOVERING', cleanup_after = 1, updated_at = 1 where session_id = 'tab-a'")
                conn.execute(
                    "update tickets set state = 'READY', ready_at = 1, updated_at = 1 where ticket_id = ?",
                    (same_session_ticket["ticket_id"],),
                )
                conn.execute("update tickets set updated_at = 1 where ticket_id = ?", (other_session_ticket["ticket_id"],))
                conn.commit()
            finally:
                conn.close()

            clock["now"] = 20.0
            result = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=100.0)

            self.assertEqual(1, result["released_leases"])
            self.assertEqual(1, result["canceled_tickets"])
            self.assertEqual(0, result["active_count"])
            self.assertEqual(1, result["reserved_count"])
            self.assertEqual("CANCELED", store.wait(str(same_session_ticket["ticket_id"]))["ticket_state"])
            self.assertEqual("READY", store.wait(str(other_session_ticket["ticket_id"]))["ticket_state"])
            snapshot = store.snapshot()
            self.assertEqual(result["active_count"], snapshot["active_count"])
            self.assertEqual(result["reserved_count"], snapshot["reserved_count"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_recovery_promotes_for_released_lease_and_canceled_ready_ticket_without_overfill(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=2, provisional_ttl_seconds=999)
        original_time = self.capacity.current_time
        clock = {"now": 0.0}
        self.capacity.current_time = lambda: clock["now"]  # type: ignore[assignment]
        try:
            store.acquire_or_queue(
                **self.request(1, session="dead-tab", turn="t1"),
                root_pid=700,
                root_start_marker="root-old",
            )
            holder = store.acquire_or_queue(**self.request(1, session="holder-tab", turn="t1"))
            store.activate_next(session_id="dead-tab", turn_id="t1", agent_id="agent-a")
            store.activate_next(session_id="holder-tab", turn_id="t1", agent_id="agent-b")
            ready_same_session = store.acquire_or_queue(**self.request(2, session="dead-tab", turn="t1"))
            store.release(lease_id=str(holder["lease_id"]), fencing_epoch=int(holder["fencing_epoch"]))
            self.assertEqual("READY", store.wait(str(ready_same_session["ticket_id"]))["ticket_state"])
            first_pending = store.acquire_or_queue(**self.request(1, session="next-a", turn="t1"))
            second_pending = store.acquire_or_queue(**self.request(1, session="next-b", turn="t1"))
            third_pending = store.acquire_or_queue(**self.request(1, session="next-c", turn="t1"))
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("update leases set state = 'RECOVERING', cleanup_after = 1, updated_at = 1 where session_id = 'dead-tab'")
                conn.execute(
                    "update tickets set state = 'READY', ready_at = 1, updated_at = 1 where ticket_id = ?",
                    (ready_same_session["ticket_id"],),
                )
                conn.execute("update tickets set updated_at = 1 where ticket_id in (?, ?, ?)", (
                    first_pending["ticket_id"],
                    second_pending["ticket_id"],
                    third_pending["ticket_id"],
                ))
                conn.commit()
            finally:
                conn.close()

            clock["now"] = 20.0
            result = store.reconcile_managed_roots(live_root_identities=[], proof_started_at=100.0)

            self.assertEqual(1, result["released_leases"])
            self.assertEqual(1, result["canceled_tickets"])
            self.assertEqual("CANCELED", store.wait(str(ready_same_session["ticket_id"]))["ticket_state"])
            self.assertEqual("READY", store.wait(str(first_pending["ticket_id"]))["ticket_state"])
            self.assertEqual("READY", store.wait(str(second_pending["ticket_id"]))["ticket_state"])
            self.assertEqual("PENDING", store.wait(str(third_pending["ticket_id"]))["ticket_state"])
            self.assertEqual(2, result["reserved_count"])
        finally:
            self.capacity.current_time = original_time  # type: ignore[assignment]

    def test_recovery_uses_shared_database_across_tabs_and_does_not_log_identity(self) -> None:
        first = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        second = self.capacity.CapacityStore(home=self.home, capacity=1, provisional_ttl_seconds=999)
        first.acquire_or_queue(
            **self.request(1, session="tab-a", turn="t1"),
            root_pid=700,
            root_start_marker="root-secret",
        )
        first.activate_next(session_id="tab-a", turn_id="t1", agent_id="agent-a")

        result = second.reconcile_managed_roots(live_root_identities=[], proof_started_at=time.time() + 1)

        self.assertEqual(1, result["suspect_leases"])
        self.assertEqual("SUSPECT", self.lease_states_by_session(first)["tab-a"])
        event_log = (self.state_dir / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn('"root_pid":700', event_log)
        self.assertNotIn("root-secret", event_log)

    def test_schema_v1_database_migrates_managed_root_registry_without_losing_leases(self) -> None:
        self.state_dir.mkdir(parents=True, mode=0o700)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(
                """
                create table meta (key text primary key, value text not null);
                insert into meta (key, value) values ('next_epoch', '2'), ('fair_cursor', '');
                create table requests (
                  request_id text primary key,
                  session_id text not null,
                  turn_id text not null,
                  ticket_id text,
                  lease_id text,
                  created_at real not null,
                  updated_at real not null
                );
                create table tickets (
                  ticket_id text primary key,
                  request_id text not null unique references requests(request_id),
                  session_id text not null,
                  turn_id text not null,
                  state text not null check (state in ('PENDING', 'READY', 'CANCELED')),
                  created_at real not null,
                  ready_at real,
                  consumed_at real,
                  updated_at real not null
                );
                create table leases (
                  lease_id text primary key,
                  request_id text not null references requests(request_id),
                  ticket_id text references tickets(ticket_id),
                  session_id text not null,
                  turn_id text not null,
                  state text not null check (
                    state in ('PROVISIONAL', 'ACTIVE', 'SUSPECT', 'RECOVERING', 'CLEANUP_REQUIRED', 'RELEASED')
                  ),
                  fencing_epoch integer not null,
                  agent_id text,
                  created_at real not null,
                  updated_at real not null,
                  cleanup_after real,
                  released_at real
                );
                create unique index leases_active_request
                  on leases(request_id)
                  where state != 'RELEASED';
                create table events (
                  id integer primary key autoincrement,
                  created_at real not null,
                  event text not null,
                  payload_json text not null
                );
                insert into requests (request_id, session_id, turn_id, lease_id, created_at, updated_at)
                values ('request-a', 'session-a', 'turn-a', 'lease-a', 1.0, 1.0);
                insert into leases (lease_id, request_id, session_id, turn_id, state, fencing_epoch, created_at, updated_at)
                values ('lease-a', 'request-a', 'session-a', 'turn-a', 'ACTIVE', 1, 1.0, 1.0);
                pragma user_version = 1;
                """
            )
        finally:
            conn.close()

        snapshot = self.manager().snapshot()

        self.assertEqual("OK", snapshot["state"])
        self.assertEqual(1, snapshot["active_count"])
        self.assertEqual(0, snapshot["managed_root_count"])
        conn = sqlite3.connect(self.db_path)
        try:
            self.assertEqual(3, conn.execute("pragma user_version").fetchone()[0])
            self.assertIsNotNone(
                conn.execute("select name from sqlite_master where type = 'table' and name = 'managed_roots'").fetchone()
            )
        finally:
            conn.close()

    def test_failed_initial_schema_creation_rolls_back_without_partial_tables_or_version(self) -> None:
        store = self.manager()
        store._prepare_state_dir()
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        original_ensure_column = store._ensure_column

        def fail_after_base_schema(*args: object, **kwargs: object) -> None:
            raise RuntimeError("injected migration failure")

        store._ensure_column = fail_after_base_schema  # type: ignore[method-assign]
        try:
            with self.assertRaises(RuntimeError):
                store._run_initialization_transaction(conn, time.monotonic() + 1.0)
        finally:
            store._ensure_column = original_ensure_column  # type: ignore[method-assign]
            conn.close()

        verify = sqlite3.connect(self.db_path)
        try:
            tables = {
                row[0]
                for row in verify.execute(
                    "select name from sqlite_master where type = 'table' and name not like 'sqlite_%'"
                )
            }
            self.assertEqual(set(), tables)
            self.assertEqual(0, verify.execute("pragma user_version").fetchone()[0])
        finally:
            verify.close()

    def test_ready_tickets_do_not_hold_capacity_and_cancellation_covers_ready(self) -> None:
        store = self.manager(limit=1)
        lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        ready = store.acquire_or_queue(**self.request(2, session="s1", turn="t1"))

        store.release(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
        snapshot = store.snapshot()
        self.assertEqual("READY", store.wait(str(ready["ticket_id"]))["ticket_state"])
        self.assertEqual(0, snapshot["active_count"])
        self.assertEqual(1, snapshot["reserved_count"])

        canceled = store.cancel_turn(session_id="s1", turn_id="t1")
        self.assertEqual(1, canceled["canceled"])
        self.assertEqual("CANCELED", store.wait(str(ready["ticket_id"]))["ticket_state"])

    def test_cancel_session_cancels_ready_and_pending_tickets(self) -> None:
        store = self.manager(limit=1)
        lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        ready = store.acquire_or_queue(**self.request(2, session="s1", turn="t1"))
        pending = store.acquire_or_queue(**self.request(3, session="s1", turn="t2"))

        store.release(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
        canceled = store.cancel_session(session_id="s1")

        self.assertEqual(2, canceled["canceled_tickets"])
        self.assertEqual("CANCELED", store.wait(str(ready["ticket_id"]))["ticket_state"])
        self.assertEqual("CANCELED", store.wait(str(pending["ticket_id"]))["ticket_state"])

    def test_cancel_turn_promotes_one_next_pending_for_canceled_ready_reserve(self) -> None:
        store = self.manager(limit=1)
        active = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        ready = store.acquire_or_queue(**self.request(1, session="s2", turn="t1"))
        next_ticket = store.acquire_or_queue(**self.request(1, session="s3", turn="t1"))

        store.release(lease_id=str(active["lease_id"]), fencing_epoch=int(active["fencing_epoch"]))
        canceled = store.cancel_turn(session_id="s2", turn_id="t1")
        newcomer = store.acquire_or_queue(**self.request(1, session="s4", turn="t1"))
        repeated = store.cancel_turn(session_id="s2", turn_id="t1")

        self.assertEqual(1, canceled["canceled"])
        self.assertEqual(1, canceled["ready_canceled"])
        self.assertEqual("CANCELED", store.wait(str(ready["ticket_id"]))["ticket_state"])
        self.assertEqual("READY", store.wait(str(next_ticket["ticket_id"]))["ticket_state"])
        self.assertEqual("CAPACITY_QUEUED", newcomer["state"])
        self.assertEqual("PENDING", store.wait(str(newcomer["ticket_id"]))["ticket_state"])
        self.assertEqual(0, repeated["canceled"])
        self.assertEqual(0, repeated["ready_canceled"])

    def test_cancel_session_promotes_one_next_pending_for_canceled_ready_reserve(self) -> None:
        store = self.manager(limit=1)
        active = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        ready = store.acquire_or_queue(**self.request(1, session="s2", turn="t1"))
        next_ticket = store.acquire_or_queue(**self.request(1, session="s3", turn="t1"))

        store.release(lease_id=str(active["lease_id"]), fencing_epoch=int(active["fencing_epoch"]))
        canceled = store.cancel_session(session_id="s2")
        newcomer = store.acquire_or_queue(**self.request(1, session="s4", turn="t1"))
        repeated = store.cancel_session(session_id="s2")

        self.assertEqual(1, canceled["canceled_tickets"])
        self.assertEqual(1, canceled["ready_canceled"])
        self.assertEqual("CANCELED", store.wait(str(ready["ticket_id"]))["ticket_state"])
        self.assertEqual("READY", store.wait(str(next_ticket["ticket_id"]))["ticket_state"])
        self.assertEqual("CAPACITY_QUEUED", newcomer["state"])
        self.assertEqual("PENDING", store.wait(str(newcomer["ticket_id"]))["ticket_state"])
        self.assertEqual(0, repeated["canceled_tickets"])
        self.assertEqual(0, repeated["ready_canceled"])

    def test_cancel_pending_only_does_not_promote_beyond_capacity(self) -> None:
        store = self.manager(limit=1)
        active = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        canceled_pending = store.acquire_or_queue(**self.request(1, session="s2", turn="t1"))
        surviving_pending = store.acquire_or_queue(**self.request(1, session="s3", turn="t1"))

        canceled = store.cancel_turn(session_id="s2", turn_id="t1")

        self.assertEqual(1, canceled["canceled"])
        self.assertEqual(0, canceled["ready_canceled"])
        self.assertEqual("CANCELED", store.wait(str(canceled_pending["ticket_id"]))["ticket_state"])
        self.assertEqual("PENDING", store.wait(str(surviving_pending["ticket_id"]))["ticket_state"])
        self.assertEqual(1, store.snapshot()["active_count"])
        store.release(lease_id=str(active["lease_id"]), fencing_epoch=int(active["fencing_epoch"]))
        self.assertEqual("READY", store.wait(str(surviving_pending["ticket_id"]))["ticket_state"])

    def test_fair_ready_order_cycles_sessions_one_ticket_per_session(self) -> None:
        store = self.manager(limit=2)
        lease_a = store.acquire_or_queue(**self.request(1, session="a"))
        lease_b = store.acquire_or_queue(**self.request(1, session="b"))
        queued = [
            store.acquire_or_queue(**self.request(2, session="a")),
            store.acquire_or_queue(**self.request(2, session="b")),
            store.acquire_or_queue(**self.request(3, session="a")),
            store.acquire_or_queue(**self.request(3, session="b")),
        ]

        store.release(
            lease_id=str(lease_a["lease_id"]),
            fencing_epoch=int(lease_a["fencing_epoch"]),
        )
        store.release(
            lease_id=str(lease_b["lease_id"]),
            fencing_epoch=int(lease_b["fencing_epoch"]),
        )

        refreshed = [store.wait(str(item["ticket_id"])) for item in queued]
        self.assertEqual(["READY", "READY", "PENDING", "PENDING"], [item["ticket_state"] for item in refreshed])
        self.assertEqual(
            ["a", "b"],
            [item["session_id"] for item in store.snapshot()["tickets"] if item["state"] == "READY"],
        )

    def test_queue_overflow_is_enforced_per_session_and_user(self) -> None:
        store = self.manager(limit=0)
        for index in range(20):
            result = store.acquire_or_queue(**self.request(index, session="full"))
            self.assertEqual("PENDING", result["ticket_state"])

        overflow = store.acquire_or_queue(**self.request(21, session="full"))
        self.assertEqual("ERROR", overflow["state"])
        self.assertEqual("session_queue_full", overflow["reason"])

        user_home = self.root / "user-home"
        user_home.mkdir()
        user_store = self.capacity.CapacityStore(home=user_home, capacity=0)
        for index in range(512):
            session = f"s{index}"
            result = user_store.acquire_or_queue(**self.request(index, session=session))
            self.assertEqual("PENDING", result["ticket_state"])
        overflow_user = user_store.acquire_or_queue(**self.request(999, session="extra"))
        self.assertEqual("ERROR", overflow_user["state"])
        self.assertEqual("user_queue_full", overflow_user["reason"])

    def test_late_release_with_old_epoch_does_not_release_new_lease(self) -> None:
        store = self.manager(limit=1)
        old = store.acquire_or_queue(**self.request(1, session="s1"))
        queued = store.acquire_or_queue(**self.request(2, session="s1"))

        store.release(lease_id=str(old["lease_id"]), fencing_epoch=int(old["fencing_epoch"]))
        ready = store.acquire_or_queue(**self.request(2, session="s1"))
        stale = store.release(lease_id=str(ready["lease_id"]), fencing_epoch=int(old["fencing_epoch"]))

        self.assertEqual("READY", store.wait(str(queued["ticket_id"]))["ticket_state"])
        self.assertEqual("LEASED", ready["state"])
        self.assertEqual("STALE", stale["state"])
        self.assertEqual(1, store.snapshot()["active_count"])

    def test_ready_ticket_blocks_new_direct_acquire_until_ready_retries(self) -> None:
        store = self.manager(limit=1)
        first = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        retry = store.acquire_or_queue(**self.request(2, session="s1", turn="t1"))
        store.release(lease_id=str(first["lease_id"]), fencing_epoch=int(first["fencing_epoch"]))
        self.assertEqual("READY", store.wait(str(retry["ticket_id"]))["ticket_state"])

        other = store.acquire_or_queue(**self.request(3, session="other", turn="t1"))
        retried = store.acquire_or_queue(**self.request(2, session="s1", turn="t1"))

        self.assertEqual("CAPACITY_QUEUED", other["state"])
        self.assertEqual("LEASED", retried["state"])
        self.assertEqual(1, store.snapshot()["active_count"])

    def test_ready_fairness_prevents_starvation_by_new_requests(self) -> None:
        store = self.manager(limit=1)
        active = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        second = store.acquire_or_queue(**self.request(1, session="s2", turn="t1"))
        third = store.acquire_or_queue(**self.request(1, session="s3", turn="t1"))

        store.release(lease_id=str(active["lease_id"]), fencing_epoch=int(active["fencing_epoch"]))
        newcomer = store.acquire_or_queue(**self.request(1, session="new", turn="t1"))
        leased_second = store.acquire_or_queue(**self.request(1, session="s2", turn="t1"))
        store.release(lease_id=str(leased_second["lease_id"]), fencing_epoch=int(leased_second["fencing_epoch"]))

        self.assertEqual("READY", store.wait(str(second["ticket_id"]))["ticket_state"])
        self.assertEqual("CAPACITY_QUEUED", newcomer["state"])
        self.assertEqual("READY", store.wait(str(third["ticket_id"]))["ticket_state"])
        self.assertEqual("PENDING", store.wait(str(newcomer["ticket_id"]))["ticket_state"])

    def test_request_hash_uses_canonical_boundaries(self) -> None:
        joined_one = self.capacity.request_hash("ab", "c", "d")
        joined_two = self.capacity.request_hash("a", "bc", "d")

        self.assertNotEqual(joined_one, joined_two)
        self.assertEqual(joined_one, self.capacity.request_hash("ab", "c", "d"))

    def test_machine_capacity_defaults_to_six_and_rejects_above_twenty(self) -> None:
        store = self.manager()
        for index in range(6):
            self.assertEqual("LEASED", store.acquire_or_queue(**self.request(index))["state"])
        queued = store.acquire_or_queue(**self.request(7))
        self.assertEqual("CAPACITY_QUEUED", queued["state"])

        completed = self.cli("snapshot", "--capacity", "21")
        self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("invalid_capacity", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)

    def test_cleanup_required_releases_only_by_recover_or_ttl_reconcile(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, cleanup_ttl_seconds=60)
        lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        queued = store.acquire_or_queue(**self.request(2, session="s2", turn="t1"))

        ended = store.cancel_session(session_id="s1")
        self.assertEqual(1, ended["leases_marked"])
        self.assertEqual("CLEANUP_REQUIRED", store.snapshot()["leases"][0]["state"])
        self.assertEqual("PENDING", store.wait(str(queued["ticket_id"]))["ticket_state"])

        recovered = store.recover(lease_id=str(lease["lease_id"]), fencing_epoch=int(lease["fencing_epoch"]))
        self.assertEqual("RELEASED", recovered["lease_state"])
        self.assertEqual("READY", store.wait(str(queued["ticket_id"]))["ticket_state"])

        ttl_home = self.root / "ttl-home"
        ttl_home.mkdir()
        ttl_store = self.capacity.CapacityStore(home=ttl_home, capacity=1, cleanup_ttl_seconds=0)
        ttl_lease = ttl_store.acquire_or_queue(**self.request(1, session="ttl", turn="t1"))
        ttl_store.acquire_or_queue(**self.request(2, session="next", turn="t1"))
        ttl_store.cancel_session(session_id="ttl")
        expired = ttl_store.reconcile()
        self.assertEqual(1, expired["ttl_released"])
        self.assertEqual("RELEASED", ttl_store.snapshot()["leases"][0]["state"])
        self.assertEqual("STALE", ttl_store.recover(
            lease_id=str(ttl_lease["lease_id"]),
            fencing_epoch=int(ttl_lease["fencing_epoch"]),
        )["state"])

    def test_late_activate_does_not_revive_cleanup_required_lease(self) -> None:
        store = self.manager(limit=1)
        lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))

        store.cancel_session(session_id="s1")
        activated = store.activate(
            lease_id=str(lease["lease_id"]),
            fencing_epoch=int(lease["fencing_epoch"]),
            agent_id="late-agent",
        )

        self.assertEqual("STALE", activated["state"])
        self.assertEqual("CLEANUP_REQUIRED", store.snapshot()["leases"][0]["state"])

    def test_activate_next_and_release_agent_are_idempotent_and_reorder_safe(self) -> None:
        store = self.manager(limit=1)
        lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))

        early_stop = store.release_agent(session_id="s1", agent_id="agent-a")
        activated = store.activate_next(session_id="s1", turn_id="t1", agent_id="agent-a")
        repeated_activate = store.activate_next(session_id="s1", turn_id="t1", agent_id="agent-a")
        stopped = store.release_agent(session_id="s1", agent_id="agent-a")
        repeated_stop = store.release_agent(session_id="s1", agent_id="agent-a")

        self.assertEqual("NOOP", early_stop["state"])
        self.assertEqual(str(lease["lease_id"]), activated["lease_id"])
        self.assertEqual("ACTIVE", activated["lease_state"])
        self.assertEqual(activated["lease_id"], repeated_activate["lease_id"])
        self.assertEqual("RELEASED", stopped["lease_state"])
        self.assertEqual("RELEASED", repeated_stop["lease_state"])

    def test_activate_next_does_not_rebind_same_agent_after_released_lease(self) -> None:
        store = self.manager(limit=2)
        first = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        activated = store.activate_next(session_id="s1", turn_id="t1", agent_id="agent-a")
        stopped = store.release_agent(session_id="s1", agent_id="agent-a")
        second = store.acquire_or_queue(**self.request(2, session="s1", turn="t1"))

        rebound = store.activate_next(session_id="s1", turn_id="t1", agent_id="agent-a")

        self.assertEqual(str(first["lease_id"]), activated["lease_id"])
        self.assertEqual("RELEASED", stopped["lease_state"])
        self.assertEqual("LEASED", second["state"])
        self.assertEqual(stopped["lease_id"], rebound["lease_id"])
        self.assertEqual("RELEASED", rebound["lease_state"])
        leases = store.snapshot()["leases"]
        self.assertEqual("PROVISIONAL", [lease for lease in leases if lease["lease_id"] == second["lease_id"]][0]["state"])

    def test_reordered_and_repeated_events_are_idempotent(self) -> None:
        store = self.manager(limit=2)
        lease = store.acquire_or_queue(**self.request(1))

        activated = store.activate(
            lease_id=str(lease["lease_id"]),
            fencing_epoch=int(lease["fencing_epoch"]),
            agent_id="agent-a",
        )
        repeated_activate = store.activate(
            lease_id=str(lease["lease_id"]),
            fencing_epoch=int(lease["fencing_epoch"]),
            agent_id="agent-a",
        )
        released = store.release(
            lease_id=str(lease["lease_id"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )
        repeated_release = store.release(
            lease_id=str(lease["lease_id"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )

        self.assertEqual("ACTIVE", activated["lease_state"])
        self.assertEqual("ACTIVE", repeated_activate["lease_state"])
        self.assertEqual("RELEASED", released["lease_state"])
        self.assertEqual("RELEASED", repeated_release["lease_state"])
        self.assertEqual(0, store.snapshot()["active_count"])

    def test_held_sqlite_write_lock_returns_quick_machine_error_without_mutation(self) -> None:
        store = self.manager(limit=1)
        store.snapshot()
        blocker = sqlite3.connect(self.db_path, isolation_level=None)
        blocker.execute("begin immediate")
        started = time.monotonic()
        try:
            result = store.acquire_or_queue(session_id="s1", turn_id="t1", task_name="blocked")
        finally:
            elapsed = time.monotonic() - started
            blocker.rollback()
            blocker.close()

        self.assertEqual("ERROR", result["state"])
        self.assertIn("database_error", result["reason"])
        self.assertLess(elapsed, 0.5)
        self.assertEqual(0, store.snapshot()["active_count"])

    def test_expired_cleanup_is_released_by_acquire_without_reconcile(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, capacity=1, cleanup_ttl_seconds=0)
        lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        queued = store.acquire_or_queue(**self.request(2, session="s2", turn="t1"))
        store.cancel_session(session_id="s1")

        result = store.acquire_or_queue(**self.request(3, session="s3", turn="t1"))

        self.assertEqual("RELEASED", store.snapshot()["leases"][0]["state"])
        self.assertEqual("READY", store.wait(str(queued["ticket_id"]))["ticket_state"])
        self.assertEqual("CAPACITY_QUEUED", result["state"])
        self.assertEqual(0, store.snapshot()["active_count"])
        self.assertEqual("STALE", store.recover(
            lease_id=str(lease["lease_id"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )["state"])

    def test_64_parallel_clients_create_state_once_without_locked_errors(self) -> None:
        store = self.manager(limit=20)

        def call(index: int) -> tuple[float, dict[str, object]]:
            local = self.capacity.CapacityStore(home=self.home, capacity=20)
            started = time.monotonic()
            result = local.acquire_or_queue(session_id=f"s{index}", turn_id="t1", task_name=f"task-{index}")
            return time.monotonic() - started, result

        with ThreadPoolExecutor(max_workers=64) as pool:
            results = list(pool.map(call, range(64)))

        durations = sorted(duration for duration, _ in results)
        reasons = [result.get("reason", "") for _, result in results]
        self.assertFalse(any("database is locked" in str(reason) for reason in reasons), reasons)
        self.assertTrue(all(result["state"] in {"LEASED", "CAPACITY_QUEUED"} for _, result in results))
        self.assertLessEqual(durations[-1], 0.5)
        self.assertLessEqual(store.snapshot()["active_count"], 20)

    def test_process_clients_share_start_and_report_lock_busy_and_p99(self) -> None:
        client_count = 64
        context = multiprocessing.get_context("spawn")
        start_event = context.Event()
        queue = context.Queue()
        processes = [
            context.Process(target=process_acquire_worker, args=(str(self.home), index, start_event, queue))
            for index in range(client_count)
        ]
        for process in processes:
            process.start()
        start_event.set()
        records = [queue.get(timeout=20) for _ in range(client_count)]
        for process in processes:
            process.join(timeout=10)
            self.assertEqual(0, process.exitcode)

        durations = sorted(float(record["elapsed"]) for record in records)
        p99 = durations[min(len(durations) - 1, math.ceil(len(durations) * 0.99) - 1)]
        locked_busy = sum(1 for record in records if record["locked_or_busy"])

        self.assertEqual(0, locked_busy, records)
        self.assertTrue(all(record["state"] in {"LEASED", "CAPACITY_QUEUED"} for record in records), records)
        self.assertLess(p99, 0.250, records)
        self.assertLessEqual(locked_busy / client_count, 0.001, records)
        self.assertLessEqual(self.manager(limit=20).snapshot()["active_count"], 20)

    def test_recreated_database_same_path_is_migrated_again(self) -> None:
        store = self.manager(limit=1)
        first = store.acquire_or_queue(**self.request(1))
        self.assertEqual("LEASED", first["state"])
        for path in (
            self.db_path,
            self.state_dir / "capacity.sqlite3-wal",
            self.state_dir / "capacity.sqlite3-shm",
        ):
            if path.exists():
                path.unlink()
        self.db_path.write_text("", encoding="utf-8")

        second = store.acquire_or_queue(**self.request(2))

        self.assertEqual("LEASED", second["state"])
        self.assertEqual(1, store.snapshot()["active_count"])

    def test_global_and_local_capacity_arguments_are_predictable(self) -> None:
        global_capacity = self.read_cli_json("--capacity", "0", "snapshot")
        local_capacity = self.read_cli_json("snapshot", "--capacity", "0")
        local_wins = self.read_cli_json("--capacity", "1", "snapshot", "--capacity", "0")

        self.assertEqual(0, global_capacity["capacity"])
        self.assertEqual(0, local_capacity["capacity"])
        self.assertEqual(0, local_wins["capacity"])

        global_acquire = self.read_cli_json(
            "--capacity",
            "0",
            "acquire-or-queue",
            "--session-id",
            "global",
            "--turn-id",
            "t1",
            "--task-name",
            "task",
        )
        local_acquire = self.read_cli_json(
            "acquire-or-queue",
            "--session-id",
            "local",
            "--turn-id",
            "t1",
            "--task-name",
            "task",
            "--capacity",
            "0",
        )
        self.assertEqual("CAPACITY_QUEUED", global_acquire["state"])
        self.assertEqual("CAPACITY_QUEUED", local_acquire["state"])

    def test_prepare_wave_clamps_yellow_status_to_two_slots(self) -> None:
        snapshot = self.write_observer_snapshot(cpu_idle_percent=10.0)

        result = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
        )

        self.assertEqual("YELLOW", result["observer_status"])
        self.assertEqual(2, result["allowed_wave_size"])
        self.assertEqual("DEGRADED", result["decision"])

    def test_prepare_wave_without_trust_never_allows_more_than_six(self) -> None:
        snapshot = self.write_observer_snapshot()

        result = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
        )

        self.assertEqual("GREEN", result["observer_status"])
        self.assertEqual(6, result["allowed_wave_size"])
        self.assertEqual("DEGRADED", result["decision"])
        self.assertEqual(False, result["wide_wave_trusted"])

    def test_prepare_wave_subtracts_external_roots_exactly_once(self) -> None:
        snapshot = self.write_observer_snapshot(external_codex_roots=2)

        result = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "6",
            "--observer-snapshot-json",
            str(snapshot),
        )

        self.assertEqual("GREEN", result["observer_status"])
        self.assertEqual(6, result["admission_capacity"])
        self.assertEqual(2, result["external_codex_roots"])
        self.assertEqual(4, result["allowed_wave_size"])

    def test_prepare_wave_above_six_requires_complete_trust_contract(self) -> None:
        snapshot = self.write_observer_snapshot()
        observer_state_dir = self.root / "dynamic-observer"
        self.write_dynamic_green_observer_state(observer_state_dir)
        skill, registry, manifest = self.write_trusted_wide_wave_inputs(wave_size=8)
        test_env = dict(self.env, CODEX_CAPACITY_TEST_MODE="1")

        missing = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
            "--observer-state-dir",
            str(observer_state_dir),
            "--wide-wave-skill-id",
            "trusted-wide",
            "--wide-wave-skill-file",
            str(skill),
            "--wide-wave-trusted-registry",
            str(registry),
            env=test_env,
        )
        trusted = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
            "--observer-state-dir",
            str(observer_state_dir),
            "--wide-wave-skill-id",
            "trusted-wide",
            "--wide-wave-skill-file",
            str(skill),
            "--wide-wave-manifest",
            str(manifest),
            "--wide-wave-trusted-registry",
            str(registry),
            env=test_env,
        )

        self.assertEqual("BLOCK", missing["decision"])
        self.assertEqual(0, missing["allowed_wave_size"])
        self.assertEqual("wide_wave_requires_trust_manifest", missing["wide_wave_trust_reason"])
        self.assertEqual("ALLOW", trusted["decision"], trusted)
        self.assertEqual(8, trusted["allowed_wave_size"])
        self.assertEqual(True, trusted["wide_wave_trusted"])

    def test_prepare_wave_validator_uses_exact_requested_wave_size(self) -> None:
        snapshot = self.write_observer_snapshot()
        observer_state_dir = self.root / "dynamic-observer"
        self.write_dynamic_green_observer_state(observer_state_dir)
        skill, registry, manifest = self.write_trusted_wide_wave_inputs(wave_size=7)
        test_env = dict(self.env, CODEX_CAPACITY_TEST_MODE="1")

        result = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
            "--observer-state-dir",
            str(observer_state_dir),
            "--wide-wave-skill-id",
            "trusted-wide",
            "--wide-wave-skill-file",
            str(skill),
            "--wide-wave-manifest",
            str(manifest),
            "--wide-wave-trusted-registry",
            str(registry),
            env=test_env,
        )

        self.assertEqual("BLOCK", result["decision"])
        self.assertEqual(0, result["allowed_wave_size"])
        self.assertEqual("wide_wave_manifest_untrusted", result["wide_wave_trust_reason"])
        self.assertIn("expected_wave_size_mismatch", result["wide_wave_validator_reasons"])

    def test_prepare_wave_blocks_trust_registry_and_validator_overrides_outside_capacity_test_mode(self) -> None:
        snapshot = self.write_observer_snapshot()
        observer_state_dir = self.root / "dynamic-observer"
        self.write_dynamic_green_observer_state(observer_state_dir)
        skill, registry, manifest = self.write_trusted_wide_wave_inputs(wave_size=8)
        env = dict(self.env, TEST_MODE="1")

        result = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
            "--observer-state-dir",
            str(observer_state_dir),
            "--wide-wave-skill-id",
            "trusted-wide",
            "--wide-wave-skill-file",
            str(skill),
            "--wide-wave-manifest",
            str(manifest),
            "--wide-wave-trusted-registry",
            str(registry),
            "--wide-wave-manifest-validator",
            str(self.root / "fake-validator.py"),
            env=env,
        )

        self.assertEqual("BLOCK", result["decision"])
        self.assertEqual(0, result["allowed_wave_size"])
        self.assertEqual("wide_wave_trust_override_forbidden", result["wide_wave_trust_reason"])

    def test_prepare_wave_ignores_trusted_registry_environment_override_outside_test_mode(self) -> None:
        snapshot = self.write_observer_snapshot()
        observer_state_dir = self.root / "dynamic-observer"
        self.write_dynamic_green_observer_state(observer_state_dir)
        skill, registry, manifest = self.write_trusted_wide_wave_inputs(wave_size=8)
        env = dict(self.env, CODEX_FD_DOCTOR_TRUSTED_REGISTRY=str(registry))

        result = self.read_cli_json(
            "prepare-wave",
            "--wave-size",
            "8",
            "--observer-snapshot-json",
            str(snapshot),
            "--observer-state-dir",
            str(observer_state_dir),
            "--wide-wave-skill-id",
            "trusted-wide",
            "--wide-wave-skill-file",
            str(skill),
            "--wide-wave-manifest",
            str(manifest),
            env=env,
        )

        self.assertEqual("BLOCK", result["decision"])
        self.assertEqual(0, result["allowed_wave_size"])
        self.assertEqual("wide_wave_manifest_untrusted", result["wide_wave_trust_reason"])
        self.assertIn("unknown_skill", result["wide_wave_validator_reasons"])

    def test_cli_and_store_accept_absolute_operation_budget(self) -> None:
        store = self.capacity.CapacityStore(home=self.home, max_operation_seconds=0)

        result = store.snapshot()
        cli_result = self.cli("--max-operation-seconds", "0", "snapshot")

        self.assertEqual("ERROR", result["state"])
        self.assertEqual("operation_timeout", result["reason"])
        self.assertNotEqual(0, cli_result.returncode)
        self.assertIn("operation_timeout", cli_result.stdout)

    def test_policy_can_limit_operation_budget_through_environment(self) -> None:
        env = dict(self.env, CODEX_CAPACITY_MAX_OPERATION_SECONDS="0")

        completed = self.cli("snapshot", env=env)

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("operation_timeout", completed.stdout)

    def test_operation_budget_rejects_nan_and_infinity(self) -> None:
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                env = dict(self.env, CODEX_CAPACITY_MAX_OPERATION_SECONDS=value)

                completed = self.cli("snapshot", env=env)

                self.assertNotEqual(0, completed.returncode)
                self.assertIn("invalid_operation_budget", completed.stdout)

    def test_old_active_lease_without_owner_missing_proof_is_not_released_by_age(self) -> None:
        store = self.capacity.CapacityStore(
            home=self.home,
            capacity=1,
            cleanup_ttl_seconds=5,
        )
        real_current_time = self.capacity.current_time
        clock = {"now": 100.0}
        self.capacity.current_time = lambda: clock["now"]
        try:
            lease = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
            store.activate(
                lease_id=str(lease["lease_id"]),
                fencing_epoch=int(lease["fencing_epoch"]),
                agent_id="agent-a",
            )
            queued = store.acquire_or_queue(**self.request(2, session="s2", turn="t1"))

            clock["now"] = 100_000.0
            first = store.reconcile()
        finally:
            self.capacity.current_time = real_current_time

        self.assertEqual(0, first["ttl_released"])
        self.assertEqual(
            ["ACTIVE"],
            [lease["state"] for lease in store.snapshot()["leases"] if lease["agent_id"] == "agent-a"],
        )
        self.assertEqual("PENDING", store.wait(str(queued["ticket_id"]))["ticket_state"])

    def test_cancel_turn_session_reconcile_and_wait_exit_codes(self) -> None:
        store = self.manager(limit=0)
        one = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        two = store.acquire_or_queue(**self.request(2, session="s1", turn="t2"))
        three = store.acquire_or_queue(**self.request(1, session="s2", turn="t1"))

        canceled_turn = store.cancel_turn(session_id="s1", turn_id="t1")
        self.assertEqual(1, canceled_turn["canceled"])
        pending_wait = self.cli("wait", "--ticket-id", str(two["ticket_id"]))
        canceled_wait = self.cli("wait", "--ticket-id", str(one["ticket_id"]))
        canceled_session = store.cancel_session(session_id="s1")
        reconciled = store.reconcile(session_id="s2")

        self.assertEqual(75, pending_wait.returncode, pending_wait.stdout + pending_wait.stderr)
        self.assertEqual(1, canceled_wait.returncode, canceled_wait.stdout + canceled_wait.stderr)
        self.assertEqual(1, canceled_session["canceled_tickets"])
        self.assertEqual(1, reconciled["tickets_canceled"])
        self.assertEqual("CANCELED", store.wait(str(three["ticket_id"]))["ticket_state"])

    def test_corrupt_database_returns_machine_error_without_traceback(self) -> None:
        self.state_dir.mkdir(parents=True)
        self.db_path.write_text("not sqlite", encoding="utf-8")

        completed = self.cli("snapshot")

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("database_error", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)

    def test_state_directory_and_files_have_private_permissions(self) -> None:
        store = self.manager()
        store.acquire_or_queue(**self.request(1))

        directory_mode = stat.S_IMODE(self.state_dir.stat().st_mode)
        db_mode = stat.S_IMODE(self.db_path.stat().st_mode)
        lock_mode = stat.S_IMODE((self.state_dir / "capacity.lock").stat().st_mode)
        log_mode = stat.S_IMODE((self.state_dir / "events.jsonl").stat().st_mode)

        self.assertEqual(0o700, directory_mode)
        self.assertEqual(0o600, db_mode)
        self.assertEqual(0o600, lock_mode)
        self.assertEqual(0o600, log_mode)

    def test_hot_path_skips_chmod_when_private_modes_are_already_exact(self) -> None:
        store = self.manager()
        store.acquire_or_queue(**self.request(1))
        real_chmod = self.capacity.os.chmod
        chmod_calls: list[tuple[Path, int]] = []

        def record_chmod(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], mode: int) -> None:
            chmod_calls.append((Path(path), mode))
            real_chmod(path, mode)

        self.capacity.os.chmod = record_chmod
        try:
            result = store.acquire_or_queue(**self.request(2))
        finally:
            self.capacity.os.chmod = real_chmod

        self.assertEqual("LEASED", result["state"])
        self.assertEqual([], chmod_calls)

    def test_state_paths_reject_symlinks_unexpected_types_and_wrong_owner(self) -> None:
        symlink_home = self.root / "symlink-home"
        symlink_home.mkdir()
        symlink_state = symlink_home / ".local" / "state" / "codex-capacity-v1"
        symlink_state.parent.mkdir(parents=True)
        os.symlink(self.root, symlink_state)
        symlink_store = self.capacity.CapacityStore(home=symlink_home)
        self.assertEqual("ERROR", symlink_store.snapshot()["state"])
        self.assertIn("unsafe_state_dir_symlink", symlink_store.snapshot()["reason"])

        type_home = self.root / "type-home"
        type_home.mkdir()
        type_store = self.capacity.CapacityStore(home=type_home)
        type_store.state_dir.mkdir(parents=True)
        (type_store.state_dir / "capacity.sqlite3").mkdir()
        result = type_store.snapshot()
        self.assertEqual("ERROR", result["state"])
        self.assertIn("unsafe_state_file_type", result["reason"])

        owner_home = self.root / "owner-home"
        owner_home.mkdir()
        owner_store = self.capacity.CapacityStore(home=owner_home)
        owner_store.state_dir.mkdir(parents=True)
        owner_store.db_path.write_text("", encoding="utf-8")
        real_stat = os.stat

        def fake_stat(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], *args: object, **kwargs: object) -> os.stat_result:
            row = real_stat(path, *args, **kwargs)
            if Path(path) == owner_store.db_path:
                values = list(row)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return row

        self.capacity.os.stat = fake_stat
        try:
            owner_result = owner_store.snapshot()
        finally:
            self.capacity.os.stat = real_stat
        self.assertEqual("ERROR", owner_result["state"])
        self.assertIn("unsafe_state_file_owner", owner_result["reason"])

    def test_state_paths_reject_parent_symlink_and_hardlinked_managed_file(self) -> None:
        parent_home = self.root / "parent-symlink-home"
        parent_home.mkdir()
        real_local = self.root / "real-local"
        real_local.mkdir()
        os.symlink(real_local, parent_home / ".local")
        parent_store = self.capacity.CapacityStore(home=parent_home)

        parent_result = parent_store.snapshot()
        self.assertEqual("ERROR", parent_result["state"])
        self.assertIn("unsafe_state_parent_symlink", parent_result["reason"])

        hardlink_home = self.root / "hardlink-home"
        hardlink_home.mkdir()
        hardlink_store = self.capacity.CapacityStore(home=hardlink_home)
        hardlink_store.state_dir.mkdir(parents=True)
        hardlink_store.db_path.write_text("", encoding="utf-8")
        os.link(hardlink_store.db_path, self.root / "capacity-hardlink")

        hardlink_result = hardlink_store.snapshot()
        self.assertEqual("ERROR", hardlink_result["state"])
        self.assertIn("unsafe_state_file_nlink", hardlink_result["reason"])

    def test_task_name_never_appears_in_database_or_log(self) -> None:
        phrase = "secret task phrase must not be stored"
        store = self.manager(limit=0)

        store.acquire_or_queue(session_id="s1", turn_id="t1", task_name=phrase)
        combined = self.db_path.read_text(encoding="utf-8", errors="ignore")
        combined += (self.state_dir / "events.jsonl").read_text(encoding="utf-8", errors="ignore")

        self.assertNotIn(phrase, combined)

    def test_release_request_only_releases_unbound_provisional_and_promotes_one(self) -> None:
        store = self.manager(limit=1)
        first = store.acquire_or_queue(**self.request(1, session="s1", turn="t1"))
        second = store.acquire_or_queue(**self.request(2, session="s2", turn="t1"))
        third = store.acquire_or_queue(**self.request(3, session="s3", turn="t1"))

        stale = store.release_request(str(first["request_id"]), expected_state="ACTIVE")
        released = store.release_request(str(first["request_id"]))
        repeated = store.release_request(str(first["request_id"]))

        self.assertEqual("STALE", stale["state"])
        self.assertEqual("RELEASED", released["lease_state"])
        self.assertEqual("RELEASED", repeated["lease_state"])
        self.assertEqual("READY", store.wait(str(second["ticket_id"]))["ticket_state"])
        self.assertEqual("PENDING", store.wait(str(third["ticket_id"]))["ticket_state"])

    def test_release_request_rejects_bound_or_unknown_request_without_task_text(self) -> None:
        phrase = "release request secret text"
        store = self.manager(limit=1)
        lease = store.acquire_or_queue(session_id="s1", turn_id="t1", task_name=phrase)
        store.activate_next(session_id="s1", turn_id="t1", agent_id="agent-a")

        bound = store.release_request(str(lease["request_id"]))
        missing = store.release_request("missing")

        self.assertEqual("STALE", bound["state"])
        self.assertEqual("NOOP", missing["state"])
        self.assertNotIn(phrase, json.dumps(bound, sort_keys=True))
        combined = self.db_path.read_text(encoding="utf-8", errors="ignore")
        combined += (self.state_dir / "events.jsonl").read_text(encoding="utf-8", errors="ignore")
        self.assertNotIn(phrase, combined)

    def test_unbound_provisional_lease_expires_before_next_acquire(self) -> None:
        store = self.capacity.CapacityStore(
            home=self.home,
            capacity=1,
            provisional_ttl_seconds=0.01,
        )
        first = store.acquire_or_queue(**self.request(1))
        self.assertEqual("LEASED", first["state"])
        time.sleep(0.02)

        second = store.acquire_or_queue(**self.request(2))

        self.assertEqual("LEASED", second["state"])
        snapshot = store.snapshot()
        self.assertEqual(1, snapshot["active_count"])
        self.assertEqual("RELEASED", snapshot["leases"][0]["state"])
        self.assertEqual("PROVISIONAL", snapshot["leases"][1]["state"])

    def test_same_request_reacquires_after_unbound_provisional_ttl(self) -> None:
        store = self.capacity.CapacityStore(
            home=self.home,
            capacity=1,
            provisional_ttl_seconds=0.01,
        )
        first = store.acquire_or_queue(**self.request(1))
        time.sleep(0.02)

        repeated = store.acquire_or_queue(**self.request(1))

        self.assertEqual("LEASED", repeated["state"])
        self.assertEqual(first["request_id"], repeated["request_id"])
        self.assertNotEqual(first["lease_id"], repeated["lease_id"])
        self.assertGreater(int(repeated["fencing_epoch"]), int(first["fencing_epoch"]))
        snapshot = store.snapshot()
        self.assertEqual(1, snapshot["active_count"])
        self.assertEqual(["RELEASED", "PROVISIONAL"], [lease["state"] for lease in snapshot["leases"]])


if __name__ == "__main__":
    unittest.main()
