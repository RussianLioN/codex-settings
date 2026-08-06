from __future__ import annotations

import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
