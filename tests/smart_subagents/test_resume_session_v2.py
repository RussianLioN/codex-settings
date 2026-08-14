from __future__ import annotations

import os
import json
import fcntl
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents import (  # noqa: E402
    finite_file_lock_v2,
    operation_deadline_v2,
    sqlite_deadline_v2,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    ProjectIdentityV2,
    ResumeCandidateV2,
    ResumeClaimV2,
    ResumeSessionV2Error,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    discover_resume_candidate_v2,
    route_is_terminal_v2,
)


class RootSessionLeaseStoreV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state_home = Path(self.temporary.name)
        self.observed: dict[int, str | None] = {}
        self.store = RootSessionLeaseStoreV2(
            self.state_home,
            process_marker_reader=lambda pid: self.observed.get(pid),
        )
        self.project = ProjectIdentityV2(
            repo_root="/work/project",
            base_sha="a" * 40,
            worktree_fingerprint="b" * 64,
            compatibility_fingerprint="c" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _root(self, pid: int, marker: str) -> RootIdentityV2:
        self.observed[pid] = marker
        return RootIdentityV2(pid=pid, process_start_marker=marker)

    def _candidate(self, route_id: str = "route2_" + "1" * 32) -> ResumeCandidateV2:
        return ResumeCandidateV2(
            route_id=route_id,
            original_shell_session_id="cas2_original",
            original_session_id="codex-session",
            original_turn_id="turn-old",
            route_state="RUNNING",
            start_request_id="sr2_" + "2" * 32,
            node_id="node2_" + "3" * 32,
            terminal_result_unacknowledged=False,
        )

    def _write_v2_lease(
        self,
        *,
        root: RootIdentityV2,
        project: ProjectIdentityV2,
        attachment: dict[str, object] | None,
    ) -> None:
        projection = {
            "schemaVersion": 2,
            "sessionId": "codex-session",
            "shellSessionId": "cas2_original",
            "generation": 1,
            "root": root.value(),
            "project": project.value(),
            "attachment": attachment,
            "active": True,
        }
        value = {
            **projection,
            "leaseFingerprint": domain_fingerprint(
                "codex-smart/root-session-lease/v2", projection
            ),
        }
        self.store._prepare_directory()
        path = self.store._path("codex-session")
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(0o600)

    def test_lease_lock_wait_is_finite_and_reports_busy_state(self) -> None:
        timeout = finite_file_lock_v2.FileLockTimeoutV2(
            "RESUME_LEASE_LOCK_TIMEOUT",
            0.25,
        )

        with (
            mock.patch.object(
                finite_file_lock_v2,
                "acquire_flock_v2",
                side_effect=timeout,
            ) as acquire,
            self.assertRaises(ResumeSessionV2Error) as captured,
        ):
            self.store.load("codex-session")

        self.assertEqual("RESUME_LEASE_BUSY", captured.exception.code)
        acquire.assert_called_once_with(
            mock.ANY,
            exclusive=True,
            timeout_seconds=0.25,
            timeout_code="RESUME_LEASE_LOCK_TIMEOUT",
        )

    def test_load_honors_shared_deadline_while_lease_lock_is_busy(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        descriptor = os.open(self.store._lock_path("codex-session"), os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            started = time.monotonic()
            with self.assertRaises(ResumeSessionV2Error) as captured:
                self.store.load("codex-session", deadline=started + 0.05)
            elapsed = time.monotonic() - started
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertEqual("RESUME_LEASE_BUSY", captured.exception.code)
        self.assertLess(elapsed, 0.20)
        self.assertEqual(original, self.store.load("codex-session").root)

    def test_defer_deadline_does_not_apply_partial_resume_transition(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        candidate = self._candidate()
        self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=candidate,
        )
        bound = self.store.bind_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
        )
        descriptor = os.open(self.store._lock_path("codex-session"), os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            with self.assertRaises(ResumeSessionV2Error):
                self.store.defer_resume_to_next_turn(
                    session_id="codex-session",
                    shell_session_id="cas2_resumed",
                    turn_id="turn-new",
                    root=resumed,
                    project=self.project,
                    route_id=candidate.route_id,
                    deadline=time.monotonic() + 0.05,
                )
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertEqual(bound, self.store.load("codex-session"))
        pending = self.store.defer_resume_to_next_turn(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
            route_id=candidate.route_id,
            deadline=time.monotonic() + 1.0,
        )
        self.assertEqual("PENDING_NEXT_TURN", pending.attachment.state)

    def test_route_terminal_lookup_honors_expired_deadline(self) -> None:
        database_path = self.state_home / "routes.sqlite3"
        connection = sqlite3.connect(database_path)
        try:
            connection.execute("create table routes(route_id text primary key,state text)")
            connection.execute(
                "insert into routes(route_id,state) values(?,?)",
                ("route2_" + "4" * 32, "SUCCEEDED"),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(ResumeSessionV2Error) as captured:
            route_is_terminal_v2(
                database_path,
                "route2_" + "4" * 32,
                deadline=time.monotonic() - 0.01,
            )

        self.assertEqual("RESUME_DEADLINE_EXCEEDED", captured.exception.code)

    def test_route_terminal_lookup_honors_deadline_while_database_is_locked(
        self,
    ) -> None:
        database_path = self.state_home / "routes.sqlite3"
        route_id = "route2_" + "4" * 32
        connection = sqlite3.connect(database_path)
        try:
            connection.execute("create table routes(route_id text primary key,state text)")
            connection.execute(
                "insert into routes(route_id,state) values(?,?)",
                (route_id, "SUCCEEDED"),
            )
            connection.commit()
        finally:
            connection.close()
        observed_deadlines = []
        real_connect = sqlite_deadline_v2.connect_sqlite_with_deadline_v2

        def observing_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            observed_deadlines.append(
                operation_deadline_v2.current_operation_deadline_v2()
            )
            return real_connect(*args, **kwargs)

        locking_connection = sqlite3.connect(database_path)
        try:
            locking_connection.execute("begin exclusive")
            started = time.monotonic()
            with mock.patch(
                "codex_smart_subagents.sqlite_deadline_v2."
                "connect_sqlite_with_deadline_v2",
                side_effect=observing_connect,
            ):
                with self.assertRaises(ResumeSessionV2Error) as captured:
                    route_is_terminal_v2(
                        database_path,
                        route_id,
                        deadline=started + 0.05,
                    )
            elapsed = time.monotonic() - started
        finally:
            locking_connection.rollback()
            locking_connection.close()

        self.assertIn(
            captured.exception.code,
            {"RESUME_DEADLINE_EXCEEDED", "RESUME_ROUTE_READ_FAILED"},
        )
        self.assertTrue(observed_deadlines)
        self.assertTrue(all(deadline is not None for deadline in observed_deadlines))
        self.assertLess(elapsed, 0.20)

    def test_authorize_route_does_not_hide_expired_deadline(self) -> None:
        with self.assertRaises(ResumeSessionV2Error) as captured:
            self.store.authorize_route(
                route_id=self._candidate().route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=self._root(202, "start-resumed"),
                project=self.project,
                deadline=time.monotonic() - 0.01,
            )

        self.assertEqual("RESUME_DEADLINE_EXCEEDED", captured.exception.code)

    def test_live_original_root_blocks_resume_without_replacing_owner(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        resumed = self._root(202, "start-resumed")

        result = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=self._candidate(),
        )

        self.assertEqual("RESUME_OWNER_ACTIVE", result.status)
        lease = self.store.load("codex-session")
        self.assertEqual(101, lease.root.pid)
        self.assertIsNone(lease.attachment)

    def test_pid_reuse_does_not_count_as_live_original_owner(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = "start-reused"
        resumed = self._root(202, "start-resumed")

        result = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=self._candidate(),
        )

        self.assertEqual("RESUME_PREPARED", result.status)
        self.assertEqual(2, result.lease_generation)
        self.assertEqual(self._candidate().route_id, result.route_id)

    def test_context_mismatch_starts_new_smart_turn_without_attachment(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        other_project = ProjectIdentityV2(
            repo_root="/work/other",
            base_sha="d" * 40,
            worktree_fingerprint="e" * 64,
            compatibility_fingerprint="c" * 64,
        )

        result = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=self._root(202, "start-resumed"),
            project=other_project,
            candidate=self._candidate(),
        )

        self.assertEqual("RESUME_CONTEXT_MISMATCH", result.status)
        detached = self.store.load("codex-session").attachment
        self.assertEqual("DETACHED", detached.state)
        self.assertEqual(self._candidate().route_id, detached.candidate.route_id)

    def test_compatibility_mismatch_is_detached_from_old_route(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        incompatible = ProjectIdentityV2(
            repo_root=self.project.repo_root,
            base_sha=self.project.base_sha,
            worktree_fingerprint=self.project.worktree_fingerprint,
            compatibility_fingerprint="f" * 64,
        )
        candidate = self._candidate()

        result = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=self._root(202, "start-resumed"),
            project=incompatible,
            candidate=candidate,
        )

        self.assertEqual("RESUME_COMPATIBILITY_MISMATCH", result.status)
        self.assertEqual("DETACHED", self.store.load("codex-session").attachment.state)
        self.assertFalse(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=self._root(202, "start-resumed"),
                project=incompatible,
            )
        )

    def test_bind_authorize_acknowledge_and_release_are_idempotent(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        candidate = self._candidate()
        self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=candidate,
        )

        first = self.store.bind_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
        )
        second = self.store.bind_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
        )

        self.assertEqual(first, second)
        self.assertEqual("BOUND", first.attachment.state)
        self.assertTrue(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=resumed,
                project=self.project,
            )
        )
        self.assertFalse(
            self.store.authorize_route(
                route_id="route2_" + "9" * 32,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=resumed,
                project=self.project,
            )
        )
        acknowledged = self.store.acknowledge_result(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            route_id=candidate.route_id,
        )
        self.assertEqual("ACKNOWLEDGED", acknowledged.attachment.state)
        self.assertEqual(
            acknowledged,
            self.store.acknowledge_result(
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=resumed,
                route_id=candidate.route_id,
            ),
        )
        self.assertTrue(
            self.store.release(
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                root=resumed,
            )
        )
        released = self.store.load("codex-session")
        self.assertIsNotNone(released)
        self.assertFalse(released.active)

        repeated = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_next",
            root=self._root(303, "start-next-resume"),
            project=self.project,
            candidate=candidate,
        )
        self.assertEqual("RESUME_NO_ROUTE", repeated.status)
        self.assertIsNone(self.store.load("codex-session").attachment)

    def test_bounded_route_can_handoff_binding_to_next_turn_once_pending(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        candidate = self._candidate()
        self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=candidate,
        )
        self.store.bind_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
        )

        rebound = self.store.bind_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-next",
            root=resumed,
            project=self.project,
        )

        self.assertEqual("BOUND", rebound.attachment.state)
        self.assertEqual("turn-next", rebound.attachment.bound_turn_id)
        self.assertFalse(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=resumed,
                project=self.project,
            )
        )
        self.assertTrue(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-next",
                root=resumed,
                project=self.project,
            )
        )
        self.assertEqual(
            rebound,
            self.store.bind_resume(
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-next",
                root=resumed,
                project=self.project,
            ),
        )

    def test_handoff_pending_rejects_different_bound_turn_or_route(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        candidate = self._candidate()
        self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=candidate,
        )
        self.store.bind_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
        )

        with self.assertRaises(ResumeSessionV2Error) as wrong_turn:
            self.store.defer_resume_to_next_turn(
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-other",
                root=resumed,
                project=self.project,
                route_id=candidate.route_id,
            )
        with self.assertRaises(ResumeSessionV2Error) as wrong_route:
            self.store.defer_resume_to_next_turn(
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=resumed,
                project=self.project,
                route_id="route2_" + "9" * 32,
            )

        self.assertEqual("RESUME_ATTACHMENT_CHANGED", wrong_turn.exception.code)
        self.assertEqual("RESUME_ATTACHMENT_CHANGED", wrong_route.exception.code)
        lease = self.store.load("codex-session")
        self.assertEqual("BOUND", lease.attachment.state)
        self.assertEqual("turn-new", lease.attachment.bound_turn_id)

    def test_symlinked_lease_directory_is_rejected(self) -> None:
        outside = self.state_home / "outside"
        outside.mkdir()
        os.symlink(outside, self.state_home / "root-session-leases")

        with self.assertRaisesRegex(Exception, "каталог аренды"):
            self.store.register_startup(
                session_id="codex-session",
                shell_session_id="cas2_original",
                root=self._root(101, "start-original"),
                project=self.project,
            )

    def test_candidate_discovery_selects_newest_route_for_same_codex_session(self) -> None:
        database = self.state_home / "routes.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                "create table routes (route_id text, shell_session_id text, "
                "session_id text, turn_id text, state text, disposition text, "
                "terminal_result_json text, created_at text);"
                "create table nodes (route_id text, node_id text, ordinal integer);"
                "create table start_requests (start_request_id text, route_id text, "
                "evidence_job_id text, created_at text);"
                "create table account_evidence_jobs (evidence_job_id text, boundary_id text);"
            )
            for suffix, created in (("1", "2026-08-05T10:00:00Z"), ("2", "2026-08-05T11:00:00Z")):
                route_id = "route2_" + suffix * 32
                connection.execute(
                    "insert into routes values (?,?,?,?,?,'DELEGATE',null,?)",
                    (
                        route_id,
                        "cas2_original",
                        "codex-session",
                        "turn-" + suffix,
                        "RUNNING",
                        created,
                    ),
                )
                connection.execute(
                    "insert into nodes values (?,?,0)",
                    (route_id, "node2_" + suffix * 32),
                )
            connection.commit()
        finally:
            connection.close()

        candidate = discover_resume_candidate_v2(
            database,
            session_id="codex-session",
        )

        self.assertIsNotNone(candidate)
        self.assertEqual("route2_" + "2" * 32, candidate.route_id)
        self.assertEqual("node2_" + "2" * 32, candidate.node_id)

    def test_candidate_discovery_honors_deadline_while_database_is_locked(
        self,
    ) -> None:
        database = self.state_home / "routes.sqlite3"
        route_id = "route2_" + "1" * 32
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                "create table routes (route_id text, shell_session_id text, "
                "session_id text, turn_id text, state text, disposition text, "
                "terminal_result_json text, created_at text);"
                "create table nodes (route_id text, node_id text, ordinal integer);"
                "create table start_requests (start_request_id text, route_id text, "
                "evidence_job_id text, created_at text);"
                "create table account_evidence_jobs (evidence_job_id text, boundary_id text);"
            )
            connection.execute(
                "insert into routes values (?,?,?,?,?,'DELEGATE',null,?)",
                (
                    route_id,
                    "cas2_original",
                    "codex-session",
                    "turn-1",
                    "RUNNING",
                    "2026-08-05T10:00:00Z",
                ),
            )
            connection.execute(
                "insert into nodes values (?,?,0)",
                (route_id, "node2_" + "1" * 32),
            )
            connection.commit()
        finally:
            connection.close()
        observed_deadlines = []
        real_connect = sqlite_deadline_v2.connect_sqlite_with_deadline_v2

        def observing_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            observed_deadlines.append(
                operation_deadline_v2.current_operation_deadline_v2()
            )
            return real_connect(*args, **kwargs)

        locking_connection = sqlite3.connect(database)
        try:
            locking_connection.execute("begin exclusive")
            started = time.monotonic()
            with mock.patch(
                "codex_smart_subagents.sqlite_deadline_v2."
                "connect_sqlite_with_deadline_v2",
                side_effect=observing_connect,
            ):
                with self.assertRaises(ResumeSessionV2Error) as captured:
                    discover_resume_candidate_v2(
                        database,
                        session_id="codex-session",
                        deadline=started + 0.05,
                    )
            elapsed = time.monotonic() - started
        finally:
            locking_connection.rollback()
            locking_connection.close()

        self.assertIn(
            captured.exception.code,
            {"RESUME_DEADLINE_EXCEEDED", "RESUME_ROUTE_READ_FAILED"},
        )
        self.assertTrue(observed_deadlines)
        self.assertTrue(all(deadline is not None for deadline in observed_deadlines))
        self.assertLess(elapsed, 0.20)

    def test_v3_separates_stable_identity_from_mutable_snapshot(self) -> None:
        root = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=root,
            project=self.project,
        )

        lease_path = self.store._path("codex-session")
        value = json.loads(lease_path.read_text(encoding="utf-8"))

        self.assertEqual(3, value["schemaVersion"])
        self.assertEqual(
            {
                "repoRoot": self.project.repo_root,
                "compatibilityFingerprint": self.project.compatibility_fingerprint,
            },
            value["stableProjectIdentity"],
        )
        self.assertEqual(
            {
                "baseSha": self.project.base_sha,
                "worktreeFingerprint": self.project.worktree_fingerprint,
            },
            value["turnSnapshot"],
        )
        self.assertNotIn("project", value)

    def test_snapshot_change_detaches_without_losing_route_evidence(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        candidate = self._candidate()
        changed = ProjectIdentityV2(
            repo_root=self.project.repo_root,
            base_sha="d" * 40,
            worktree_fingerprint="e" * 64,
            compatibility_fingerprint=self.project.compatibility_fingerprint,
        )

        result = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=changed,
            candidate=candidate,
        )

        self.assertEqual("RESUME_SNAPSHOT_MISMATCH", result.status)
        lease = self.store.load("codex-session")
        self.assertEqual("DETACHED", lease.attachment.state)
        self.assertEqual(candidate.route_id, lease.attachment.candidate.route_id)
        self.assertFalse(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-new",
                root=resumed,
                project=changed,
            )
        )

    def test_claim_is_two_phase_and_rebinds_bound_route_without_stop(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        candidate = self._candidate()
        self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=candidate,
        )

        first = self.store.begin_resume_claim(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-one",
            root=resumed,
            project=self.project,
        )
        self.assertIsInstance(first, ResumeClaimV2)
        self.assertEqual("CLAIMING", first.status)
        self.assertRegex(first.claim_nonce or "", r"^claim3_[0-9a-f]{32}$")
        self.assertEqual("CLAIMING", self.store.load("codex-session").attachment.state)
        self.assertFalse(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-one",
                root=resumed,
                project=self.project,
            )
        )

        bound = self.store.finalize_resume_claim(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-one",
            root=resumed,
            project=self.project,
            claim_nonce=first.claim_nonce,
            context_claim_nonce=first.claim_nonce,
        )
        self.assertEqual("BOUND", bound.attachment.state)
        self.assertTrue(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-one",
                root=resumed,
                project=self.project,
            )
        )

        second = self.store.begin_resume_claim(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-two",
            root=resumed,
            project=self.project,
        )
        self.assertEqual("CLAIMING", second.status)
        self.assertNotEqual(first.claim_nonce, second.claim_nonce)
        self.assertFalse(
            self.store.authorize_route(
                route_id=candidate.route_id,
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-one",
                root=resumed,
                project=self.project,
            )
        )

    def test_incomplete_claim_is_idempotent_for_same_turn_and_detached_for_next(self) -> None:
        original = self._root(101, "start-original")
        self.store.register_startup(
            session_id="codex-session",
            shell_session_id="cas2_original",
            root=original,
            project=self.project,
        )
        self.observed[101] = None
        resumed = self._root(202, "start-resumed")
        self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=resumed,
            project=self.project,
            candidate=self._candidate(),
        )
        first = self.store.begin_resume_claim(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-one",
            root=resumed,
            project=self.project,
        )
        retry = self.store.begin_resume_claim(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-one",
            root=resumed,
            project=self.project,
        )
        self.assertEqual(first, retry)

        next_turn = self.store.begin_resume_claim(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-two",
            root=resumed,
            project=self.project,
        )
        self.assertEqual("DETACHED", next_turn.status)
        self.assertEqual("DETACHED", self.store.load("codex-session").attachment.state)

    def test_exact_v2_lease_migrates_lazily_to_v3(self) -> None:
        original = self._root(101, "start-original")
        candidate = self._candidate()
        self._write_v2_lease(
            root=original,
            project=self.project,
            attachment={
                "routeId": candidate.route_id,
                "originalShellSessionId": candidate.original_shell_session_id,
                "originalSessionId": candidate.original_session_id,
                "originalTurnId": candidate.original_turn_id,
                "routeState": candidate.route_state,
                "startRequestId": candidate.start_request_id,
                "nodeId": candidate.node_id,
                "terminalResultUnacknowledged": False,
                "state": "PREPARED",
                "boundTurnId": None,
            },
        )
        self.observed[101] = None

        prepared = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=self._root(202, "start-resumed"),
            project=self.project,
            candidate=candidate,
        )

        self.assertEqual("RESUME_PREPARED", prepared.status)
        value = json.loads(
            self.store._path("codex-session").read_text(encoding="utf-8")
        )
        self.assertEqual(3, value["schemaVersion"])

    def test_mismatched_or_corrupt_v2_becomes_safe_detached_v3(self) -> None:
        original = self._root(101, "start-original")
        candidate = self._candidate()
        self._write_v2_lease(root=original, project=self.project, attachment=None)
        self.observed[101] = None
        changed = ProjectIdentityV2(
            repo_root=self.project.repo_root,
            base_sha="d" * 40,
            worktree_fingerprint="e" * 64,
            compatibility_fingerprint=self.project.compatibility_fingerprint,
        )
        mismatch = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            root=self._root(202, "start-resumed"),
            project=changed,
            candidate=candidate,
        )
        self.assertEqual("RESUME_SNAPSHOT_MISMATCH", mismatch.status)
        self.assertEqual("DETACHED", self.store.load("codex-session").attachment.state)

        path = self.store._path("codex-session")
        path.write_text('{"schemaVersion":2,"leaseFingerprint":"damaged"}', encoding="utf-8")
        path.chmod(0o600)
        corrupt = self.store.prepare_resume(
            session_id="codex-session",
            shell_session_id="cas2_next",
            root=self._root(303, "start-next"),
            project=changed,
            candidate=candidate,
        )
        self.assertEqual("RESUME_LEASE_INVALID", corrupt.status)
        safe = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(3, safe["schemaVersion"])
        self.assertEqual("DETACHED", safe["attachment"]["state"])


if __name__ == "__main__":
    unittest.main()
