from __future__ import annotations

import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path


PLUGIN_SRC = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "codex-smart-subagents"
    / "src"
)
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.identity import RequestContext  # noqa: E402
from codex_smart_subagents.state import (  # noqa: E402
    RouteState,
    StateTransitionError,
    assert_transition,
)
from codex_smart_subagents.store import (  # noqa: E402
    RouteForbidden,
    SmartStore,
    TurnBindingError,
)


def context(session_id: str = "session-1") -> RequestContext:
    return RequestContext(
        shell_session_id="shell-1",
        session_id=session_id,
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root="/repo",
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
    )


class StateMachineTests(unittest.TestCase):
    def test_main_route_path_is_allowed(self) -> None:
        path = [
            RouteState.PLANNED,
            RouteState.QUEUED,
            RouteState.LEASED,
            RouteState.PREPARING,
            RouteState.RUNNING,
            RouteState.COLLECTING,
            RouteState.ATTESTING,
            RouteState.VALIDATING,
            RouteState.SUCCEEDED,
        ]
        for before, after in zip(path, path[1:]):
            assert_transition(before, after)

    def test_invalid_transition_is_rejected(self) -> None:
        with self.assertRaises(StateTransitionError):
            assert_transition(RouteState.PLANNED, RouteState.RUNNING)
        with self.assertRaises(StateTransitionError):
            assert_transition(RouteState.SUCCEEDED, RouteState.QUEUED)


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.directory.name) / "state"
        self.store = SmartStore(self.state_dir)

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def test_sqlite_security_and_durability_pragmas(self) -> None:
        db_path = self.state_dir / "smart-subagents.sqlite3"
        self.assertTrue(stat.S_ISREG(db_path.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(db_path.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(self.state_dir.stat().st_mode))
        self.assertEqual(os.getuid(), db_path.stat().st_uid)

        with closing(sqlite3.connect(db_path)) as connection:
            self.assertEqual("wal", connection.execute("pragma journal_mode").fetchone()[0])
            self.assertEqual(2, connection.execute("pragma synchronous").fetchone()[0])
            self.assertEqual(1, connection.execute("pragma user_version").fetchone()[0])
            self.assertNotEqual(0, connection.execute("pragma application_id").fetchone()[0])
            self.assertEqual("ok", connection.execute("pragma integrity_check").fetchone()[0])

    def test_turn_binding_is_context_bound_and_single_use(self) -> None:
        binding = self.store.issue_turn_binding(context(), ttl_seconds=120)
        self.assertRegex(binding, r"^tb1_[A-Za-z0-9_-]{43}$")

        with self.assertRaises(TurnBindingError):
            self.store.consume_turn_binding(binding, context("other-session"))

        self.store.consume_turn_binding(binding, context())
        with self.assertRaises(TurnBindingError):
            self.store.consume_turn_binding(binding, context())

    def test_turn_binding_allows_only_the_exact_recorded_request_pair(
        self,
    ) -> None:
        binding = self.store.issue_turn_binding(context(), ttl_seconds=120)
        pair = {
            "request_key": "request-0001",
            "request_hash": "c" * 64,
        }

        self.store.consume_turn_binding(binding, context(), **pair)
        self.store.consume_turn_binding(binding, context(), **pair)
        for changed in (
            {**pair, "request_key": "request-0002"},
            {**pair, "request_hash": "d" * 64},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(TurnBindingError) as caught:
                    self.store.consume_turn_binding(
                        binding,
                        context(),
                        **changed,
                    )
                self.assertEqual(
                    "TURN_BINDING_USED",
                    caught.exception.code,
                )

    def test_version_one_database_adds_turn_binding_request_columns(
        self,
    ) -> None:
        self.store.close()
        database = self.state_dir / "smart-subagents.sqlite3"
        for suffix in ("-wal", "-shm"):
            Path(f"{database}{suffix}").unlink(missing_ok=True)
        database.unlink()
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(
                """
                create table turn_bindings (
                  token_hash text primary key,
                  context_hash text not null,
                  context_json text not null,
                  created_at text not null,
                  expires_at text not null,
                  consumed_at text
                );
                pragma user_version=1;
                """
            )
        database.chmod(0o600)

        self.store = SmartStore(self.state_dir)

        with closing(sqlite3.connect(database)) as connection:
            columns = {
                row[1]: row[2].upper()
                for row in connection.execute(
                    "pragma table_info(turn_bindings)"
                )
            }
            self.assertEqual("TEXT", columns["request_key"])
            self.assertEqual("TEXT", columns["request_hash"])
            self.assertEqual(
                1,
                connection.execute("pragma user_version").fetchone()[0],
            )

    def test_route_access_is_bound_to_original_context(self) -> None:
        route_id = self.store.create_route(
            request_context=context(),
            request_key="request-0001",
            request_hash="c" * 64,
            catalog_generation="cg1_" + "d" * 16,
            algorithm_version="route-v1",
            disposition="delegate",
            startable=True,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            plan_output={"routeId": "placeholder"},
            nodes=[],
        )
        self.store.get_route(route_id, context())
        with self.assertRaises(RouteForbidden):
            self.store.get_route(route_id, context("other-session"))

    def test_state_transition_and_event_are_atomic(self) -> None:
        route_id = self._route()
        self.store.transition_route(
            route_id,
            context(),
            RouteState.QUEUED,
            event="route_queued",
            code="QUEUED",
            message="",
        )
        route = self.store.get_route(route_id, context())
        self.assertEqual(RouteState.QUEUED, route.state)
        events = self.store.events_after(route_id, context(), 0)
        self.assertEqual("route_queued", events[-1]["event"])
        self.assertEqual("QUEUED", events[-1]["code"])

        with self.assertRaises(StateTransitionError):
            self.store.transition_route(
                route_id,
                context(),
                RouteState.RUNNING,
                event="invalid",
                code="INVALID",
                message="",
            )
        self.assertEqual(RouteState.QUEUED, self.store.get_route(route_id, context()).state)

    def test_stale_lease_recovery_marks_route_recovering(self) -> None:
        route_id = self._route()
        self.store.transition_route(
            route_id,
            context(),
            RouteState.QUEUED,
            event="route_queued",
            code="QUEUED",
            message="",
        )
        self.store.transition_route(
            route_id,
            context(),
            RouteState.LEASED,
            event="route_leased",
            code="LEASED",
            message="",
        )
        self.store.record_lease(
            route_id=route_id,
            node_id="node-1",
            owner_id="controller-1",
            token="lease-token",
            pid=123,
            start_marker="start-1",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        recovered = self.store.recover_stale_leases(
            now=datetime.now(timezone.utc),
        )
        self.assertEqual([route_id], recovered)
        self.assertEqual(
            RouteState.RECOVERING,
            self.store.get_route(route_id, context()).state,
        )

    def _route(self) -> str:
        return self.store.create_route(
            request_context=context(),
            request_key="request-0001",
            request_hash="c" * 64,
            catalog_generation="cg1_" + "d" * 16,
            algorithm_version="route-v1",
            disposition="delegate",
            startable=True,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            plan_output={"routeId": "placeholder"},
            nodes=[],
        )


if __name__ == "__main__":
    unittest.main()
