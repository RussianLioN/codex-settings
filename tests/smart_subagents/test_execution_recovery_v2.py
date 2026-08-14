from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from codex_smart_subagents.execution_recovery_v2 import (  # noqa: E402
    ExecutionRecoveryV2,
    ExecutionRecoveryV2Error,
    LaunchPermitRecoveryV2,
    terminate_process_identity_v2,
)
from codex_smart_subagents.child_guard_v2 import ChildGuardV2Error  # noqa: E402


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


class _Store:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records
        self.begun: list[tuple[str, int, str]] = []
        self.completed: list[tuple[str, int, str]] = []

    def stranded_attempts(self) -> list[dict[str, object]]:
        return [dict(item) for item in self.records]

    def begin_stranded_attempt_recovery(
        self,
        attempt_id: str,
        *,
        pid: int,
        process_start_marker: str,
        now: datetime,
    ) -> dict[str, object]:
        self.assert_aware(now)
        self.begun.append((attempt_id, pid, process_start_marker))
        return {"state": "PENDING"}

    def complete_stranded_attempt_recovery(
        self,
        attempt_id: str,
        *,
        pid: int,
        process_start_marker: str,
        now: datetime,
    ) -> dict[str, object]:
        self.assert_aware(now)
        self.completed.append((attempt_id, pid, process_start_marker))
        return {"state": "FAILED", "errorCode": "CONTROLLER_RESTARTED"}

    @staticmethod
    def assert_aware(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise AssertionError("recovery time must be timezone-aware")


class _PermitStore:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records
        self.begun: list[str] = []
        self.completed: list[str] = []

    def stranded_launch_permits(self) -> list[dict[str, object]]:
        return [dict(item) for item in self.records]

    def begin_stranded_permit_recovery(
        self,
        permit_id: str,
        *,
        guard_pid: int | None,
        guard_start_marker: str | None,
        now: datetime,
    ) -> dict[str, object]:
        _Store.assert_aware(now)
        del guard_pid, guard_start_marker
        self.begun.append(permit_id)
        return {"state": "PENDING"}

    def complete_stranded_permit_recovery(
        self,
        permit_id: str,
        *,
        guard_pid: int | None,
        guard_start_marker: str | None,
        now: datetime,
    ) -> dict[str, object]:
        _Store.assert_aware(now)
        del guard_pid, guard_start_marker
        self.completed.append(permit_id)
        return {"state": "FAILED_BEFORE_START", "errorCode": "CONTROLLER_RESTARTED"}


def _record(*, attempt_id: str = "att2_" + "a" * 32) -> dict[str, object]:
    return {
        "attemptId": attempt_id,
        "routeId": "route2_" + "b" * 32,
        "nodeId": "node2_" + "c" * 32,
        "state": "RUNNING",
        "pid": 741,
        "processStartMarker": "darwin:10:20",
    }


class ExecutionRecoveryV2Tests(unittest.TestCase):
    def test_dry_run_reports_exact_live_process_without_changes(self) -> None:
        store = _Store([_record()])
        terminated: list[tuple[int, str]] = []
        recovery = ExecutionRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: "EXACT",
            process_terminator=lambda pid, marker: terminated.append((pid, marker)),
            clock=lambda: NOW,
        )

        report = recovery.run(apply=False)

        self.assertTrue(report.ok)
        self.assertFalse(report.applied)
        self.assertEqual("TERMINATE_AND_FAIL", report.actions[0].kind)
        self.assertEqual([], store.begun)
        self.assertEqual([], store.completed)
        self.assertEqual([], terminated)

    def test_apply_persists_intent_before_terminating_and_terminalizes(self) -> None:
        order: list[str] = []
        store = _Store([_record()])
        original_begin = store.begin_stranded_attempt_recovery
        original_complete = store.complete_stranded_attempt_recovery

        def begin(*args, **kwargs):
            order.append("begin")
            return original_begin(*args, **kwargs)

        def terminate(pid: int, marker: str) -> None:
            del pid, marker
            order.append("terminate")

        def complete(*args, **kwargs):
            order.append("complete")
            return original_complete(*args, **kwargs)

        store.begin_stranded_attempt_recovery = begin  # type: ignore[method-assign]
        store.complete_stranded_attempt_recovery = complete  # type: ignore[method-assign]
        observations = iter(("EXACT", "EXACT", "EXACT", "ABSENT"))
        recovery = ExecutionRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: next(observations),
            process_terminator=terminate,
            clock=lambda: NOW,
        )

        report = recovery.run(apply=True)

        self.assertTrue(report.ok)
        self.assertTrue(report.applied)
        self.assertEqual(["begin", "terminate", "complete"], order)

    def test_absent_or_reused_process_is_never_signalled(self) -> None:
        for observation in ("ABSENT", "REUSED"):
            with self.subTest(observation=observation):
                store = _Store([_record()])
                recovery = ExecutionRecoveryV2(
                    store=store,
                    process_observer=lambda pid, marker, value=observation: value,
                    process_terminator=lambda pid, marker: self.fail(
                        "process must not be signalled"
                    ),
                    clock=lambda: NOW,
                )

                report = recovery.run(apply=True)

                self.assertTrue(report.ok)
                self.assertEqual("FAIL_ABSENT", report.actions[0].kind)
                self.assertEqual(1, len(store.completed))

    def test_unverifiable_process_blocks_all_changes(self) -> None:
        store = _Store([_record()])
        recovery = ExecutionRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: "UNVERIFIABLE",
            clock=lambda: NOW,
        )

        report = recovery.run(apply=True)

        self.assertFalse(report.ok)
        self.assertFalse(report.applied)
        self.assertEqual(("PROCESS_IDENTITY_UNVERIFIABLE",), report.blockers)
        self.assertEqual([], store.begun)

    def test_plan_change_before_apply_is_rejected(self) -> None:
        first = _record()
        second = _record(attempt_id="att2_" + "d" * 32)
        calls = iter(([first], [second]))
        store = _Store([])
        store.stranded_attempts = lambda: [dict(item) for item in next(calls)]  # type: ignore[method-assign]
        recovery = ExecutionRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: "ABSENT",
            clock=lambda: NOW,
        )

        report = recovery.run(apply=True)

        self.assertFalse(report.ok)
        self.assertIn("EXECUTION_RECOVERY_PLAN_CHANGED", report.blockers)
        self.assertEqual([], store.begun)

    def test_invalid_store_record_is_a_blocker(self) -> None:
        record = _record()
        record["pid"] = True
        recovery = ExecutionRecoveryV2(
            store=_Store([record]),
            process_observer=lambda pid, marker: "ABSENT",
            clock=lambda: NOW,
        )

        report = recovery.run(apply=False)

        self.assertFalse(report.ok)
        self.assertEqual(("STRANDED_ATTEMPT_RECORD_INVALID",), report.blockers)

    def test_invalid_observer_result_raises_closed_error(self) -> None:
        recovery = ExecutionRecoveryV2(
            store=_Store([_record()]),
            process_observer=lambda pid, marker: "MAYBE",
            clock=lambda: NOW,
        )

        with self.assertRaises(ExecutionRecoveryV2Error) as caught:
            recovery.run(apply=False)
        self.assertEqual("PROCESS_OBSERVATION_INVALID", caught.exception.code)

    def test_process_disappearing_before_group_lookup_is_already_terminated(self) -> None:
        with (
            patch(
                "codex_smart_subagents.execution_recovery_v2.observe_process_identity_v2",
                side_effect=("EXACT", "ABSENT"),
            ),
            patch(
                "codex_smart_subagents.execution_recovery_v2.os.getpgid",
                side_effect=ProcessLookupError(),
            ),
        ):
            terminate_process_identity_v2(741, "darwin:10:20")

    def test_nonrunning_process_marker_is_absent_even_while_pid_is_reapable(self) -> None:
        with (
            patch(
                "codex_smart_subagents.execution_recovery_v2.system_process_start_marker_v2",
                side_effect=ChildGuardV2Error(
                    "PROCESS_NOT_RUNNING",
                    "process is absent or awaiting collection",
                ),
            ),
            patch(
                "codex_smart_subagents.execution_recovery_v2.os.kill",
                side_effect=AssertionError("kill(0) must not reinterpret a zombie"),
            ),
        ):
            from codex_smart_subagents.execution_recovery_v2 import (
                observe_process_identity_v2,
            )

            self.assertEqual(
                "ABSENT",
                observe_process_identity_v2(741, "darwin:10:20"),
            )

    def test_reserved_permit_is_aborted_without_process_signal(self) -> None:
        store = _PermitStore(
            [
                {
                    "permitId": "lp2_" + "1" * 32,
                    "routeId": "route2_" + "2" * 32,
                    "nodeId": "node2_" + "3" * 32,
                    "state": "RESERVED",
                    "guardPid": None,
                    "guardStartMarker": None,
                }
            ]
        )
        recovery = LaunchPermitRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: self.fail("no process expected"),
            process_terminator=lambda pid, marker: self.fail("no signal expected"),
            clock=lambda: NOW,
        )

        report = recovery.run(apply=True)

        self.assertTrue(report.ok)
        self.assertTrue(report.applied)
        self.assertEqual("ABORT_RESERVED", report.actions[0].kind)
        self.assertEqual(["lp2_" + "1" * 32], store.completed)

    def test_guarded_permit_records_intent_then_terminates_exact_guard(self) -> None:
        store = _PermitStore(
            [
                {
                    "permitId": "lp2_" + "1" * 32,
                    "routeId": "route2_" + "2" * 32,
                    "nodeId": "node2_" + "3" * 32,
                    "state": "GUARDED",
                    "guardPid": 951,
                    "guardStartMarker": "darwin:30:40",
                }
            ]
        )
        order: list[str] = []
        original_begin = store.begin_stranded_permit_recovery
        original_complete = store.complete_stranded_permit_recovery

        def begin(*args, **kwargs):
            order.append("begin")
            return original_begin(*args, **kwargs)

        def complete(*args, **kwargs):
            order.append("complete")
            return original_complete(*args, **kwargs)

        store.begin_stranded_permit_recovery = begin  # type: ignore[method-assign]
        store.complete_stranded_permit_recovery = complete  # type: ignore[method-assign]
        observations = iter(("EXACT", "EXACT", "EXACT", "ABSENT"))
        recovery = LaunchPermitRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: next(observations),
            process_terminator=lambda pid, marker: order.append("terminate"),
            clock=lambda: NOW,
        )

        report = recovery.run(apply=True)

        self.assertTrue(report.ok)
        self.assertEqual(["begin", "terminate", "complete"], order)

    def test_guarded_permit_with_unverifiable_process_blocks_all(self) -> None:
        store = _PermitStore(
            [
                {
                    "permitId": "lp2_" + "1" * 32,
                    "routeId": "route2_" + "2" * 32,
                    "nodeId": "node2_" + "3" * 32,
                    "state": "GUARDED",
                    "guardPid": 951,
                    "guardStartMarker": "darwin:30:40",
                }
            ]
        )
        recovery = LaunchPermitRecoveryV2(
            store=store,
            process_observer=lambda pid, marker: "UNVERIFIABLE",
            clock=lambda: NOW,
        )

        report = recovery.run(apply=True)

        self.assertFalse(report.ok)
        self.assertEqual(("PROCESS_IDENTITY_UNVERIFIABLE",), report.blockers)
        self.assertEqual([], store.begun)


if __name__ == "__main__":
    unittest.main()
