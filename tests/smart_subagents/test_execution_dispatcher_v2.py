from __future__ import annotations

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.execution_dispatcher_v2 import (  # noqa: E402
    ExecutionDispatcherV2,
    ExecutionDispatcherV2Error,
)
from codex_smart_subagents import production_runtime_v2  # noqa: E402
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    QueuedStartDispatchV2,
    RequestContextV2,
    StartRequestV2,
)


def _context() -> RequestContextV2:
    return RequestContextV2(
        shell_session_id="shell",
        session_id="session",
        turn_id="turn",
        codex_home="/private/codex-home",
        repo_root="/private/repo",
        base_sha="1" * 64,
        worktree_fingerprint="2" * 64,
        activation_fingerprint="3" * 64,
        compatibility_fingerprint="4" * 64,
        issued_control_epoch=1,
    )


def _start(
    identifier: str,
    *,
    state: str = "ATTESTING",
    deadline_at: datetime | None = None,
) -> StartRequestV2:
    suffix = identifier.removeprefix("sr2_")
    return StartRequestV2(
        start_request_id=identifier,
        evidence_job_id="aej2_" + suffix,
        attempt_id="att2_" + suffix,
        route_id="route2_" + suffix,
        node_id="node2_" + suffix,
        queue_position=1,
        deadline_at=(
            deadline_at
            if deadline_at is not None
            else datetime.now(timezone.utc) + timedelta(seconds=60)
        ),
        state=state,
    )


class _Store:
    def __init__(
        self,
        *,
        terminal: bool = False,
        deadline_at: datetime | None = None,
    ) -> None:
        self.reads: list[tuple[str, RequestContextV2]] = []
        self.terminal = terminal
        self.deadline_at = deadline_at
        self.terminal_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.terminal_mutations = 0
        self._lock = threading.Lock()

    def read_start_request(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
    ) -> StartRequestV2:
        with self._lock:
            self.reads.append((start_request_id, request_context))
            return _start(
                start_request_id,
                state="FAILED" if self.terminal else "ATTESTING",
                deadline_at=self.deadline_at,
            )

    def record_account_evidence_terminal(
        self, *args: object, **kwargs: object
    ) -> object:
        with self._lock:
            self.terminal_calls.append((args, kwargs))
            replayed = self.terminal
            if not replayed:
                self.terminal = True
                self.terminal_mutations += 1
        return SimpleNamespace(state="FAILED", terminal=True, replayed=replayed)


class _QueuedStore(_Store):
    def __init__(self, identifier: str, context: RequestContextV2) -> None:
        super().__init__()
        self.identifier = identifier
        self.context = context

    def queued_start_dispatches(self):
        return (
            QueuedStartDispatchV2(
                start_request_id=self.identifier,
                evidence_job_id="aej2_" + "1" * 32,
                deadline_at=datetime.now(timezone.utc) + timedelta(seconds=60),
                request_context=self.context,
            ),
        )

    def record_account_evidence_terminal(self, *args: object, **kwargs: object) -> None:
        raise AssertionError((args, kwargs))


class _BlockingExecution:
    def __init__(self) -> None:
        self.release = threading.Event()
        self.two_started = threading.Event()
        self._lock = threading.Lock()
        self.active = 0
        self.maximum_active = 0
        self.calls: list[str] = []

    def run(
        self,
        start_request: StartRequestV2,
        request_context: RequestContextV2,
    ) -> object:
        del request_context
        with self._lock:
            self.calls.append(start_request.start_request_id)
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            if self.active == 2:
                self.two_started.set()
        try:
            if not self.release.wait(2):
                raise TimeoutError("test release was not signalled")
            return SimpleNamespace(state="SUCCEEDED")
        finally:
            with self._lock:
                self.active -= 1


class _FailingExecution:
    def run(self, start_request: StartRequestV2, request_context: RequestContextV2):
        del start_request, request_context
        raise RuntimeError("worker failed")


class _CountingExecution:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def run(
        self,
        start_request: StartRequestV2,
        request_context: RequestContextV2,
    ) -> object:
        del request_context
        self.calls.append(start_request.start_request_id)
        return SimpleNamespace(state="SUCCEEDED")


class ExecutionDispatcherV2Tests(unittest.TestCase):
    def test_timezone_without_offset_is_rejected_as_invalid_clock(self) -> None:
        class MissingOffset(tzinfo):
            def utcoffset(self, _value: datetime | None) -> None:
                return None

        dispatcher = object.__new__(ExecutionDispatcherV2)
        dispatcher._clock = lambda: datetime(
            2026,
            7,
            20,
            12,
            0,
            tzinfo=MissingOffset(),
        )

        with self.assertRaisesRegex(ExecutionDispatcherV2Error, "CLOCK_INVALID"):
            dispatcher._now()

    def test_clock_exception_is_terminalized_before_future_is_removed(self) -> None:
        store = _Store(
            deadline_at=datetime(2026, 7, 20, 12, 1, tzinfo=timezone.utc)
        )
        execution = _CountingExecution()
        errors: list[BaseException] = []

        def failed_clock() -> datetime:
            raise RuntimeError("clock callback failed")

        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=1,
            clock=failed_clock,
            error_sink=lambda _identifier, error: errors.append(error),
        )
        identifier = "sr2_" + "d" * 32
        try:
            self.assertTrue(dispatcher.submit(identifier, _context()))
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            dispatcher.close()

        self.assertEqual([], execution.calls)
        self.assertEqual(1, store.terminal_mutations)
        self.assertEqual(1, len(errors))
        self.assertEqual("CLOCK_INVALID", getattr(errors[0], "code", None))
        _, options = store.terminal_calls[0]
        self.assertEqual("CLOCK_INVALID", options["failure_code"])
        self.assertEqual("INTERNAL", options["problem"]["category"])
        self.assertEqual("INTERNAL_ERROR", options["problem"]["code"])

    def test_expired_attesting_request_is_terminalized_before_execution(
        self,
    ) -> None:
        now = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        store = _Store(deadline_at=now - timedelta(microseconds=1))
        execution = _CountingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=1,
            clock=lambda: now,
        )
        identifier = "sr2_" + "a" * 32
        try:
            self.assertTrue(dispatcher.submit(identifier, _context()))
            self.assertTrue(dispatcher.wait_idle(2))
            self.assertTrue(dispatcher.submit(identifier, _context()))
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            dispatcher.close()

        self.assertEqual([], execution.calls)
        self.assertEqual(1, store.terminal_mutations)
        self.assertEqual(1, len(store.terminal_calls))
        arguments, options = store.terminal_calls[0]
        self.assertEqual(("aej2_" + "a" * 32, _context()), arguments)
        self.assertEqual("FAILED", options["state"])
        self.assertEqual(
            "REQUEST_DEADLINE_EXCEEDED",
            options["failure_code"],
        )

    def test_expired_request_remains_owned_until_terminal_record_commits(
        self,
    ) -> None:
        now = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)

        class BlockingTerminalStore(_Store):
            def __init__(self) -> None:
                super().__init__(deadline_at=now - timedelta(seconds=1))
                self.terminalization_started = threading.Event()
                self.terminalization_release = threading.Event()

            def record_account_evidence_terminal(
                self, *args: object, **kwargs: object
            ) -> object:
                self.terminalization_started.set()
                if not self.terminalization_release.wait(2):
                    raise TimeoutError("испытание не разрешило терминализацию")
                return super().record_account_evidence_terminal(*args, **kwargs)

        store = BlockingTerminalStore()
        execution = _CountingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=1,
            clock=lambda: now,
        )
        identifier = "sr2_" + "b" * 32
        try:
            self.assertTrue(dispatcher.submit(identifier, _context()))
            self.assertTrue(store.terminalization_started.wait(1))
            self.assertFalse(dispatcher.submit(identifier, _context()))
            self.assertFalse(dispatcher.wait_idle(0.01))
            store.terminalization_release.set()
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            store.terminalization_release.set()
            dispatcher.close()

        self.assertEqual([], execution.calls)
        self.assertEqual(1, store.terminal_mutations)

    def test_parallel_submissions_mutate_expired_terminal_once(self) -> None:
        now = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        store = _Store(deadline_at=now - timedelta(seconds=1))
        execution = _CountingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=2,
            clock=lambda: now,
        )
        identifier = "sr2_" + "c" * 32
        try:
            with ThreadPoolExecutor(max_workers=8) as callers:
                submitted = tuple(
                    callers.map(
                        lambda _index: dispatcher.submit(identifier, _context()),
                        range(16),
                    )
                )
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            dispatcher.close()

        self.assertTrue(any(submitted))
        self.assertEqual([], execution.calls)
        self.assertEqual(1, store.terminal_mutations)

    def test_runs_at_most_two_jobs_and_reads_the_durable_request(self) -> None:
        store = _Store()
        execution = _BlockingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=2,
        )
        context = _context()
        identifiers = ["sr2_" + str(index) * 32 for index in (1, 2, 3)]
        try:
            for identifier in identifiers:
                self.assertTrue(dispatcher.submit(identifier, context))
            self.assertTrue(execution.two_started.wait(1))
            self.assertEqual(2, execution.maximum_active)
            self.assertEqual(2, len(execution.calls))
            execution.release.set()
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            execution.release.set()
            dispatcher.close()

        self.assertEqual(set(identifiers), set(execution.calls))
        self.assertEqual(
            set(identifiers),
            {start_request_id for start_request_id, _ in store.reads},
        )
        self.assertTrue(all(observed == context for _, observed in store.reads))

    def test_duplicate_inflight_submission_is_idempotent(self) -> None:
        execution = _BlockingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=_Store(),
            execution=execution,
            max_workers=1,
        )
        identifier = "sr2_" + "1" * 32
        try:
            self.assertTrue(dispatcher.submit(identifier, _context()))
            self.assertFalse(dispatcher.submit(identifier, _context()))
            execution.release.set()
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            execution.release.set()
            dispatcher.close()
        self.assertEqual([identifier], execution.calls)

    def test_bootstrap_and_route_replay_do_not_execute_the_same_start_twice(
        self,
    ) -> None:
        identifier = "sr2_" + "1" * 32
        context = _context()
        store = _QueuedStore(identifier, context)
        execution = _BlockingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=1,
        )
        try:
            restored = production_runtime_v2.restore_queued_start_requests_v2(
                store=store,
                dispatcher=dispatcher,
                now=datetime.now(timezone.utc),
            )
            self.assertEqual(1, restored)
            self.assertFalse(dispatcher.submit(identifier, context))
            execution.release.set()
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            execution.release.set()
            dispatcher.close()

        self.assertEqual([identifier], execution.calls)

    def test_terminal_request_is_not_executed_again(self) -> None:
        store = _Store(terminal=True)
        execution = _BlockingExecution()
        dispatcher = ExecutionDispatcherV2(store=store, execution=execution)
        try:
            self.assertTrue(dispatcher.submit("sr2_" + "1" * 32, _context()))
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            dispatcher.close()
        self.assertEqual([], execution.calls)

    def test_worker_error_is_reported_and_does_not_poison_the_queue(self) -> None:
        errors: list[tuple[str, BaseException]] = []
        dispatcher = ExecutionDispatcherV2(
            store=_Store(),
            execution=_FailingExecution(),
            max_workers=1,
            error_sink=lambda identifier, error: errors.append((identifier, error)),
        )
        first = "sr2_" + "1" * 32
        second = "sr2_" + "2" * 32
        try:
            self.assertTrue(dispatcher.submit(first, _context()))
            self.assertTrue(dispatcher.wait_idle(2))
            self.assertTrue(dispatcher.submit(second, _context()))
            self.assertTrue(dispatcher.wait_idle(2))
        finally:
            dispatcher.close()
        self.assertEqual([first, second], [identifier for identifier, _ in errors])
        self.assertTrue(all(str(error) == "worker failed" for _, error in errors))

    def test_capacity_and_closed_state_are_explicit(self) -> None:
        execution = _BlockingExecution()
        dispatcher = ExecutionDispatcherV2(
            store=_Store(),
            execution=execution,
            max_workers=1,
            max_pending=2,
        )
        try:
            self.assertTrue(dispatcher.submit("sr2_" + "1" * 32, _context()))
            self.assertTrue(dispatcher.submit("sr2_" + "2" * 32, _context()))
            with self.assertRaisesRegex(ExecutionDispatcherV2Error, "QUEUE_FULL"):
                dispatcher.submit("sr2_" + "3" * 32, _context())
        finally:
            execution.release.set()
            dispatcher.close()
        with self.assertRaisesRegex(ExecutionDispatcherV2Error, "CLOSED"):
            dispatcher.submit("sr2_" + "4" * 32, _context())


if __name__ == "__main__":
    unittest.main()
