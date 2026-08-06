from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents import finite_file_lock_v2  # noqa: E402
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    ProjectIdentityV2,
    ResumeCandidateV2,
    ResumeSessionV2Error,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    discover_resume_candidate_v2,
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
        self.assertIsNone(self.store.load("codex-session").attachment)

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

        with self.assertRaises(ResumeSessionV2Error) as still_bound:
            self.store.bind_resume(
                session_id="codex-session",
                shell_session_id="cas2_resumed",
                turn_id="turn-next",
                root=resumed,
                project=self.project,
            )

        self.assertEqual("RESUME_ATTACHMENT_CHANGED", still_bound.exception.code)
        pending = self.store.defer_resume_to_next_turn(
            session_id="codex-session",
            shell_session_id="cas2_resumed",
            turn_id="turn-new",
            root=resumed,
            project=self.project,
            route_id=candidate.route_id,
        )
        self.assertEqual("PENDING_NEXT_TURN", pending.attachment.state)
        self.assertIsNone(pending.attachment.bound_turn_id)

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
        with sqlite3.connect(database) as connection:
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

        candidate = discover_resume_candidate_v2(
            database,
            session_id="codex-session",
        )

        self.assertIsNotNone(candidate)
        self.assertEqual("route2_" + "2" * 32, candidate.route_id)
        self.assertEqual("node2_" + "2" * 32, candidate.node_id)


if __name__ == "__main__":
    unittest.main()
