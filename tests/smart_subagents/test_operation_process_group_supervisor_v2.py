from __future__ import annotations

import errno
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))
MODULE_PATH = (
    PLUGIN_SRC
    / "codex_smart_subagents"
    / "operation_process_group_supervisor_v2.py"
)

from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineV2,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)


def _load_module() -> ModuleType:
    if not MODULE_PATH.is_file():
        raise AssertionError(f"missing module: {MODULE_PATH}")
    name = (
        "codex_smart_subagents."
        "operation_process_group_supervisor_v2_test_subject"
    )
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _Clock:
    def __init__(self, value: int = 1_000_000_000) -> None:
        self.value = value
        self.sleeps: list[float] = []

    def __call__(self) -> int:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += int(seconds * 1_000_000_000)


class _FakeProcess:
    def __init__(self, pid: int = 43210) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self.poll_calls = 0

    def poll(self) -> int | None:
        self.poll_calls += 1
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -signal.SIGTERM


class _TrackedStream:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _matching_identity_reader(
    module: ModuleType, *, marker: str = "fake-system-start-marker"
) -> Any:
    return lambda pid: module.ProcessIdentityV2(
        pid=pid,
        process_group_id=pid,
        session_id=pid,
        start_marker=marker,
    )


class OperationProcessGroupSupervisorV2Tests(unittest.TestCase):
    def test_durable_callbacks_cover_publish_accept_and_cleanup_required(
        self,
    ) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        events: list[tuple[Any, ...]] = []
        supervisor: Any

        def publish(lease: Any, context: Any) -> None:
            self.assertIn(lease.lease_id, supervisor.owned_lease_ids())
            events.append(("publish", lease.lease_id, dict(context)))

        def transition(
            lease: Any,
            context: Any,
            outcome: str,
            obligation: Any,
        ) -> None:
            events.append(
                (
                    "transition",
                    lease.lease_id,
                    dict(context),
                    outcome,
                    None if obligation is None else dict(obligation),
                )
            )

        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: None,
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
            ownership_publisher=publish,
            ownership_transition=transition,
        )
        accepted = supervisor.spawn_transient(
            label="candidate",
            argv=("/usr/bin/true",),
            ownership_context={"kind": "candidate", "operationId": "op2_test"},
        )
        supervisor.release_after_acceptance(accepted)

        stubborn = supervisor.spawn_transient(
            label="probe",
            argv=("/usr/bin/false",),
            ownership_context={"kind": "short-command"},
        )
        result = supervisor.terminate_transient(
            stubborn,
            deadline=OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="ROOT_EXPIRED",
                monotonic_ns=clock,
            ),
            max_wait_seconds=0.001,
            reason_code="PROBE_FAILED",
        )

        self.assertEqual("cleanup-required", result.state)
        self.assertEqual("publish", events[0][0])
        self.assertEqual("accepted", events[1][3])
        self.assertEqual("publish", events[2][0])
        self.assertEqual("cleanup-required", events[3][3])
        self.assertEqual(result.cleanup_obligation, events[3][4])

    def test_spawn_forces_new_session_and_registers_before_any_poll(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

        def popen(argv: tuple[str, ...], **kwargs: Any) -> _FakeProcess:
            calls.append((argv, kwargs))
            return process

        holder: dict[str, Any] = {}

        def identity_reader(pid: int) -> Any:
            self.assertEqual(
                1, len(holder["supervisor"].owned_lease_ids())
            )
            return module.ProcessIdentityV2(
                pid=pid,
                process_group_id=pid,
                session_id=pid,
                start_marker="captured-after-registration",
            )

        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=popen,
            killpg=lambda _pgid, _signal: None,
            group_exists=lambda _pgid: True,
            identity_reader=identity_reader,
        )
        holder["supervisor"] = supervisor
        lease = supervisor.spawn_transient(
            label="probe",
            argv=("/usr/bin/true",),
        )

        self.assertEqual(0, process.poll_calls)
        self.assertEqual((lease.lease_id,), supervisor.owned_lease_ids())
        self.assertEqual(process.pid, lease.pid)
        self.assertEqual(process.pid, lease.process_group_id)
        self.assertEqual(process.pid, lease.session_id)
        self.assertEqual(
            "captured-after-registration", lease.process_start_marker
        )
        self.assertIs(process, lease.process)
        self.assertEqual(("/usr/bin/true",), calls[0][0])
        self.assertIs(False, calls[0][1]["shell"])
        self.assertIs(True, calls[0][1]["start_new_session"])
        self.assertIs(True, calls[0][1]["close_fds"])

    def test_terminate_signals_entire_group_in_term_then_cont_order(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        signal_calls: list[tuple[int, int]] = []
        observations = iter((True, False))
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda pgid, signum: signal_calls.append((pgid, signum)),
            group_exists=lambda _pgid: next(observations),
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/true",)
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
            monotonic_ns=clock,
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=deadline,
            max_wait_seconds=0.01,
            reason_code="PROBE_FINISHED",
        )

        self.assertEqual(
            [
                (lease.process_group_id, signal.SIGCONT),
                (lease.process_group_id, signal.SIGTERM),
                (lease.process_group_id, signal.SIGCONT),
            ],
            signal_calls,
        )
        self.assertEqual("terminated", result.state)
        self.assertTrue(result.continuation_allowed)
        self.assertIsNone(result.cleanup_obligation)
        self.assertEqual((), supervisor.owned_lease_ids())

    def test_leader_exit_after_term_never_leaves_preexisting_stopped_children(
        self,
    ) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        signal_calls: list[int] = []
        exact = module.ProcessIdentityV2(
            pid=process.pid,
            process_group_id=process.pid,
            session_id=process.pid,
            start_marker="fake-system-start-marker",
        )
        identities = iter((exact, exact, exact, None))
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, signum: signal_calls.append(signum),
            group_exists=lambda _pgid: True,
            identity_reader=lambda _pid: next(identities),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="stopped-child", argv=("/usr/bin/false",)
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="ROOT_EXPIRED",
                monotonic_ns=clock,
            ),
            max_wait_seconds=0.001,
            reason_code="PROBE_FAILED",
        )

        self.assertEqual([signal.SIGCONT, signal.SIGTERM], signal_calls)
        self.assertEqual("cleanup-required", result.state)
        self.assertTrue(result.cont_sent)
        self.assertEqual(
            "PROCESS_IDENTITY_UNAVAILABLE_AFTER_TERM",
            result.identity_failure_code,
        )

    def test_stubborn_group_returns_closed_durable_obligation_and_blocks(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        signal_calls: list[int] = []
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, signum: signal_calls.append(signum),
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="stubborn", argv=("/usr/bin/false",)
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
            monotonic_ns=clock,
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=deadline,
            max_wait_seconds=0.003,
            reason_code="PROBE_FAILED",
        )

        self.assertEqual("cleanup-required", result.state)
        self.assertFalse(result.continuation_allowed)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            signal_calls,
        )
        obligation = result.cleanup_obligation
        self.assertIsNotNone(obligation)
        assert obligation is not None
        self.assertEqual(
            {
                "schemaVersion",
                "obligationType",
                "obligationId",
                "status",
                "operation",
                "phase",
                "processLabel",
                "pid",
                "processGroupId",
                "reasonCode",
                "attempt",
                "termSent",
                "contSent",
                "preContSent",
                "postContSent",
                "termErrorErrno",
                "contErrorErrno",
                "preContErrorErrno",
                "postContErrorErrno",
                "observedAlive",
                "nextAction",
                "automaticSignalAuthorized",
                "continuationAllowed",
                "expectedProcessIdentity",
                "observedProcessIdentity",
                "identityFailureCode",
                "deadlineProof",
            },
            set(obligation),
        )
        self.assertEqual(
            "transient-process-group-cleanup-v2",
            obligation["obligationType"],
        )
        self.assertEqual("pending", obligation["status"])
        self.assertEqual("reconcile-identity-and-retry-term-cont", obligation["nextAction"])
        self.assertIs(False, obligation["automaticSignalAuthorized"])
        self.assertIs(False, obligation["continuationAllowed"])
        self.assertEqual(
            obligation, module.validate_cleanup_obligation_v2(obligation)
        )
        json.dumps(obligation, allow_nan=False, sort_keys=True)
        self.assertNotIn("argv", json.dumps(obligation).lower())
        self.assertEqual(
            (obligation,), supervisor.outstanding_cleanup_obligations()
        )
        with self.assertRaises(
            module.OutstandingProcessCleanupObligationV2
        ):
            supervisor.assert_continuation_allowed()

    def test_common_deadline_has_priority_over_local_cleanup_wait(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: None,
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.000000001,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.000000002,
            timeout_code="COMMON_DEADLINE",
            monotonic_ns=clock,
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=deadline,
            max_wait_seconds=10,
            reason_code="PROBE_FAILED",
        )

        assert result.cleanup_obligation is not None
        proof = result.cleanup_obligation["deadlineProof"]
        self.assertEqual("COMMON_DEADLINE", proof["timeoutCode"])
        self.assertEqual("operation", proof["deadlineKind"])
        self.assertEqual([0.000000001, 0.000000001], clock.sleeps)

    def test_signal_failures_are_preserved_in_obligation_without_escape(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()

        def denied(_pgid: int, signum: int) -> None:
            if signum == signal.SIGTERM:
                raise PermissionError(errno.EPERM, "denied")

        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=denied,
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=deadline,
            max_wait_seconds=0.001,
            reason_code="PROBE_FAILED",
        )

        assert result.cleanup_obligation is not None
        self.assertFalse(result.term_sent)
        self.assertTrue(result.cont_sent)
        self.assertEqual(errno.EPERM, result.cleanup_obligation["termErrorErrno"])
        self.assertIsNone(result.cleanup_obligation["contErrorErrno"])

    def test_cleanup_obligation_validator_rejects_open_and_malformed_data(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: None,
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )
        result = supervisor.terminate_transient(
            lease,
            deadline=OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="ROOT_EXPIRED",
                monotonic_ns=clock,
            ),
            max_wait_seconds=0.001,
            reason_code="PROBE_FAILED",
        )
        assert result.cleanup_obligation is not None
        valid = dict(result.cleanup_obligation)
        malformed = [
            {**valid, "unexpected": True},
            {key: value for key, value in valid.items() if key != "pid"},
            {**valid, "pid": True},
            {**valid, "pid": int(valid["pid"]) + 1},
            {**valid, "continuationAllowed": True},
            {**valid, "automaticSignalAuthorized": True},
            {
                **valid,
                "expectedProcessIdentity": {
                    **valid["expectedProcessIdentity"],
                    "sessionId": int(valid["pid"]) + 1,
                },
            },
            {**valid, "termSent": True, "termErrorErrno": errno.EPERM},
            {**valid, "termSent": False, "contSent": True},
            {**valid, "preContSent": False},
            {**valid, "preContErrorErrno": errno.EPERM},
            {**valid, "postContErrorErrno": errno.EPERM},
            {
                **valid,
                "deadlineProof": {
                    **valid["deadlineProof"],
                    "operation": "different-operation",
                },
            },
            {
                **valid,
                "observedProcessIdentity": {
                    **valid["expectedProcessIdentity"],
                    "startMarker": "different-marker",
                },
            },
            {
                **valid,
                "observedProcessIdentity": valid["expectedProcessIdentity"],
                "identityFailureCode": "PROCESS_IDENTITY_MISMATCH",
                "deadlineProof": None,
            },
            {**valid, "deadlineProof": {"schemaVersion": 2}},
        ]

        for document in malformed:
            with self.subTest(document=document):
                with self.assertRaises(
                    module.CleanupObligationValidationErrorV2
                ):
                    module.validate_cleanup_obligation_v2(document)

    def test_cleanup_validator_accepts_only_exact_sent_sequence_checkpoint(
        self,
    ) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: None,
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )
        result = supervisor.terminate_transient(
            lease,
            deadline=OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="ROOT_EXPIRED",
                monotonic_ns=clock,
            ),
            max_wait_seconds=0.001,
            reason_code="PROBE_FAILED",
        )
        assert result.cleanup_obligation is not None
        expected_identity = result.cleanup_obligation[
            "expectedProcessIdentity"
        ]
        checkpoint = {
            **result.cleanup_obligation,
            "operation": "recover",
            "phase": "durable-process-ownership",
            "reasonCode": "DURABLE_PROCESS_OWNERSHIP_SIGNAL_SEQUENCE_SENT",
            "attempt": 1,
            "termSent": True,
            "contSent": True,
            "preContSent": True,
            "postContSent": True,
            "termErrorErrno": None,
            "contErrorErrno": None,
            "preContErrorErrno": None,
            "postContErrorErrno": None,
            "observedAlive": True,
            "nextAction": "reconcile-identity-without-repeat-signals",
            "observedProcessIdentity": expected_identity,
            "identityFailureCode": None,
            "deadlineProof": None,
        }

        self.assertEqual(
            checkpoint,
            module.validate_cleanup_obligation_v2(checkpoint),
        )

        invalid_checkpoints = (
            {
                **checkpoint,
                "reasonCode": "UNRELATED_REASON",
            },
            {
                **checkpoint,
                "nextAction": "reconcile-identity-and-retry-term-cont",
            },
            {
                **checkpoint,
                "postContSent": False,
            },
            {
                **checkpoint,
                "observedProcessIdentity": None,
            },
            {
                **checkpoint,
                "observedAlive": False,
            },
            {
                **checkpoint,
                "operation": "apply",
            },
        )
        for document in invalid_checkpoints:
            with self.subTest(document=document):
                with self.assertRaises(
                    module.CleanupObligationValidationErrorV2
                ):
                    module.validate_cleanup_obligation_v2(document)

    def test_retry_can_close_obligation_and_reopen_continuation(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        alive = True
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: None,
            group_exists=lambda _pgid: alive,
            identity_reader=_matching_identity_reader(module),
            sleep=clock.sleep,
            poll_interval_seconds=0.001,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )
        first_deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        first = supervisor.terminate_transient(
            lease,
            deadline=first_deadline,
            max_wait_seconds=0.001,
            reason_code="PROBE_FAILED",
        )
        self.assertFalse(first.continuation_allowed)

        alive = False
        retry_deadline = OperationDeadlineV2.start(
            operation="recovery",
            timeout_seconds=1,
            timeout_code="RECOVERY_EXPIRED",
            monotonic_ns=clock,
        )
        second = supervisor.terminate_transient(
            lease,
            deadline=retry_deadline,
            max_wait_seconds=0.001,
            reason_code="RECOVERY_RETRY",
        )

        self.assertEqual("terminated", second.state)
        supervisor.assert_continuation_allowed()
        self.assertEqual((), supervisor.outstanding_cleanup_obligations())

    def test_identity_mismatch_before_term_sends_no_signal_and_blocks(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        marker = "original-start-marker"
        signal_calls: list[int] = []

        def identity_reader(pid: int) -> Any:
            return module.ProcessIdentityV2(
                pid=pid,
                process_group_id=pid,
                session_id=pid,
                start_marker=marker,
            )

        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, signum: signal_calls.append(signum),
            group_exists=lambda _pgid: True,
            identity_reader=identity_reader,
            sleep=clock.sleep,
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )
        marker = "reused-pid-start-marker"

        result = supervisor.terminate_transient(
            lease,
            deadline=OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="ROOT_EXPIRED",
                monotonic_ns=clock,
            ),
            max_wait_seconds=0.1,
            reason_code="PROBE_FAILED",
        )

        self.assertEqual([], signal_calls)
        self.assertEqual("cleanup-required", result.state)
        self.assertEqual(
            "PROCESS_IDENTITY_MISMATCH", result.identity_failure_code
        )
        assert result.cleanup_obligation is not None
        self.assertIsNone(result.cleanup_obligation["deadlineProof"])
        self.assertEqual(
            "PROCESS_IDENTITY_MISMATCH",
            result.cleanup_obligation["identityFailureCode"],
        )
        self.assertEqual(
            "original-start-marker",
            result.cleanup_obligation["expectedProcessIdentity"][
                "startMarker"
            ],
        )
        self.assertEqual(
            "reused-pid-start-marker",
            result.cleanup_obligation["observedProcessIdentity"][
                "startMarker"
            ],
        )
        with self.assertRaises(
            module.OutstandingProcessCleanupObligationV2
        ):
            supervisor.assert_continuation_allowed()

    def test_identity_is_rechecked_between_term_and_cont(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        clock = _Clock()
        markers = iter(("original", "original", "original", "replacement"))
        signal_calls: list[int] = []

        def identity_reader(pid: int) -> Any:
            return module.ProcessIdentityV2(
                pid=pid,
                process_group_id=pid,
                session_id=pid,
                start_marker=next(markers),
            )

        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, signum: signal_calls.append(signum),
            group_exists=lambda _pgid: True,
            identity_reader=identity_reader,
            sleep=clock.sleep,
        )
        lease = supervisor.spawn_transient(
            label="stopped", argv=("/usr/bin/false",)
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=OperationDeadlineV2.start(
                operation="recovery",
                timeout_seconds=1,
                timeout_code="RECOVERY_EXPIRED",
                monotonic_ns=clock,
            ),
            max_wait_seconds=0.1,
            reason_code="STOPPED_PROCESS_REJECTED",
        )

        self.assertEqual([signal.SIGCONT, signal.SIGTERM], signal_calls)
        self.assertTrue(result.cont_sent)
        self.assertEqual(
            "PROCESS_IDENTITY_CHANGED_AFTER_TERM",
            result.identity_failure_code,
        )
        self.assertFalse(result.continuation_allowed)

    def test_unavailable_identity_before_term_sends_no_signal_and_blocks(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        identities = iter(
            (
                module.ProcessIdentityV2(
                    pid=process.pid,
                    process_group_id=process.pid,
                    session_id=process.pid,
                    start_marker="original",
                ),
                None,
            )
        )
        signal_calls: list[int] = []
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, signum: signal_calls.append(signum),
            group_exists=lambda _pgid: False,
            identity_reader=lambda _pid: next(identities),
        )
        lease = supervisor.spawn_transient(
            label="probe", argv=("/usr/bin/false",)
        )

        result = supervisor.terminate_transient(
            lease,
            deadline=OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=1,
                timeout_code="ROOT_EXPIRED",
            ),
            max_wait_seconds=0.1,
            reason_code="PROBE_FAILED",
        )

        self.assertEqual([], signal_calls)
        self.assertEqual(
            "PROCESS_IDENTITY_UNAVAILABLE", result.identity_failure_code
        )
        self.assertFalse(result.observed_group_alive)
        self.assertFalse(result.continuation_allowed)

    def test_invalid_popen_pid_is_softly_terminated_and_not_left_unmanaged(self) -> None:
        module = _load_module()
        process = _FakeProcess(pid=0)
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: self.fail(
                "invalid pid must never reach group signaling"
            ),
            identity_reader=lambda _pid: self.fail(
                "invalid pid must not reach identity lookup"
            ),
        )

        with self.assertRaises(module.TransientProcessIdentityErrorV2):
            supervisor.spawn_transient(
                label="invalid", argv=("/usr/bin/false",)
            )

        self.assertEqual(-signal.SIGTERM, process.returncode)
        self.assertEqual((), supervisor.owned_lease_ids())
        self.assertEqual((), supervisor.unverified_launch_ids())
        supervisor.assert_continuation_allowed()

    def test_finished_unverified_process_closes_all_owned_streams(self) -> None:
        module = _load_module()
        process = _FakeProcess(pid=0)
        process.stdin = _TrackedStream()
        process.stdout = _TrackedStream()
        process.stderr = _TrackedStream()
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: self.fail(
                "invalid pid must never reach group signaling"
            ),
            identity_reader=lambda _pid: self.fail(
                "invalid pid must not reach identity lookup"
            ),
        )

        with self.assertRaises(module.TransientProcessIdentityErrorV2):
            supervisor.spawn_transient(
                label="invalid-with-pipes",
                argv=("/usr/bin/false",),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_unverified_live_invalid_popen_pid_is_registered_and_blocks(self) -> None:
        module = _load_module()

        class StubbornInvalidProcess(_FakeProcess):
            def terminate(self) -> None:
                pass

        process = StubbornInvalidProcess(pid=0)
        process.stdin = _TrackedStream()
        process.stdout = _TrackedStream()
        process.stderr = _TrackedStream()
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: self.fail(
                "invalid pid must never reach group signaling"
            ),
            identity_reader=lambda _pid: self.fail(
                "invalid pid must not reach identity lookup"
            ),
        )

        with self.assertRaises(module.TransientProcessIdentityErrorV2):
            supervisor.spawn_transient(
                label="invalid", argv=("/usr/bin/false",)
            )

        self.assertEqual(1, len(supervisor.unverified_launch_ids()))
        self.assertFalse(process.stdin.closed)
        self.assertFalse(process.stdout.closed)
        self.assertFalse(process.stderr.closed)
        with self.assertRaises(
            module.OutstandingProcessCleanupObligationV2
        ):
            supervisor.assert_continuation_allowed()

        process.returncode = 0
        removed = supervisor.reconcile_unverified_launches()
        self.assertEqual(1, len(removed))
        self.assertEqual((), supervisor.unverified_launch_ids())
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        supervisor.assert_continuation_allowed()

    def test_unverified_valid_pid_keeps_gate_closed_until_group_disappears(
        self,
    ) -> None:
        module = _load_module()
        process = _FakeProcess()
        group_alive = True
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: self.fail(
                "an unverified group must never receive a group signal"
            ),
            group_exists=lambda _pgid: group_alive,
            identity_reader=lambda _pid: None,
        )

        with self.assertRaises(module.TransientProcessIdentityErrorV2):
            supervisor.spawn_transient(
                label="identity-race", argv=("/usr/bin/false",)
            )

        self.assertEqual(-signal.SIGTERM, process.returncode)
        self.assertEqual(1, len(supervisor.unverified_launch_ids()))
        self.assertEqual((), supervisor.reconcile_unverified_launches())
        with self.assertRaises(
            module.OutstandingProcessCleanupObligationV2
        ):
            supervisor.assert_continuation_allowed()

        group_alive = False
        self.assertEqual(1, len(supervisor.reconcile_unverified_launches()))
        supervisor.assert_continuation_allowed()

    def test_accepted_process_is_no_longer_owned_or_signalable(self) -> None:
        module = _load_module()
        process = _FakeProcess()
        signal_calls: list[int] = []
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, signum: signal_calls.append(signum),
            group_exists=lambda _pgid: True,
            identity_reader=_matching_identity_reader(module),
        )
        lease = supervisor.spawn_transient(
            label="candidate", argv=("/usr/bin/true",)
        )

        accepted = supervisor.release_after_acceptance(lease)

        self.assertIs(process, accepted)
        self.assertEqual((), supervisor.owned_lease_ids())
        with self.assertRaises(module.TransientProcessOwnershipErrorV2):
            supervisor.terminate_transient(
                lease,
                deadline=OperationDeadlineV2.start(
                    operation="apply",
                    timeout_seconds=1,
                    timeout_code="ROOT_EXPIRED",
                ),
                max_wait_seconds=0.01,
                reason_code="SHOULD_NOT_SIGNAL",
            )
        self.assertEqual([], signal_calls)

    def test_completed_process_with_live_group_stays_owned_until_reconciled(
        self,
    ) -> None:
        module = _load_module()
        process = _FakeProcess()
        process.returncode = 0
        process.stdin = _TrackedStream()
        process.stdout = _TrackedStream()
        process.stderr = _TrackedStream()
        group_alive = True
        supervisor = module.OperationProcessGroupSupervisorV2(
            popen_factory=lambda _argv, **_kwargs: process,
            killpg=lambda _pgid, _signum: self.fail(
                "a completed leader must not authorize a new signal"
            ),
            group_exists=lambda _pgid: group_alive,
            identity_reader=_matching_identity_reader(module),
        )
        lease = supervisor.spawn_transient(
            label="completed-with-descendant", argv=("/usr/bin/true",)
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
        )

        result = supervisor.release_after_verified_exit(
            lease,
            deadline=deadline,
            reason_code="GROUP_REMAINS_AFTER_EXIT",
        )

        self.assertIsInstance(result, module.ProcessGroupTerminationResultV2)
        self.assertFalse(result.continuation_allowed)
        assert result.cleanup_obligation is not None
        self.assertEqual(
            "PROCESS_IDENTITY_PRESENT_AFTER_EXIT",
            result.cleanup_obligation["identityFailureCode"],
        )
        self.assertEqual(
            result.cleanup_obligation,
            module.validate_cleanup_obligation_v2(
                result.cleanup_obligation
            ),
        )
        with self.assertRaises(
            module.OutstandingProcessCleanupObligationV2
        ):
            supervisor.assert_continuation_allowed()
        self.assertFalse(process.stdin.closed)
        self.assertFalse(process.stdout.closed)
        self.assertFalse(process.stderr.closed)

        group_alive = False
        self.assertEqual(
            (lease.lease_id,), supervisor.reconcile_completed_transients()
        )
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        supervisor.assert_continuation_allowed()

    def test_scoped_supervisor_reuses_identity_and_restores_outer_state(
        self,
    ) -> None:
        module = _load_module()
        first = module.OperationProcessGroupSupervisorV2()
        second = module.OperationProcessGroupSupervisorV2()

        self.assertIsNone(module.current_process_group_supervisor_v2())
        with module.scoped_current_process_group_supervisor_v2(first):
            self.assertIs(first, module.current_process_group_supervisor_v2())
            with module.scoped_current_process_group_supervisor_v2(first):
                self.assertIs(
                    first, module.current_process_group_supervisor_v2()
                )
            with self.assertRaises(
                module.CurrentProcessGroupSupervisorConflictV2
            ):
                with module.scoped_current_process_group_supervisor_v2(
                    second
                ):
                    self.fail("a different nested supervisor must be rejected")
        self.assertIsNone(module.current_process_group_supervisor_v2())

    def test_production_module_contains_no_sigkill_escalation(self) -> None:
        _load_module()
        self.assertNotIn("SIGKILL", MODULE_PATH.read_text(encoding="utf-8"))

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "killpg"),
        "requires POSIX process groups",
    )
    def test_real_group_termination_leaves_no_live_descendant(self) -> None:
        module = _load_module()
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="process-group-v2-"
        ) as raw:
            marker = Path(raw) / "child.pid"
            script = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import time; time.sleep(30)']);"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
                "time.sleep(30)"
            )
            supervisor = module.OperationProcessGroupSupervisorV2(
                poll_interval_seconds=0.01
            )
            lease = supervisor.spawn_transient(
                label="real-tree",
                argv=(sys.executable, "-c", script, str(marker)),
            )
            try:
                _wait_for_file(marker, timeout_seconds=2)
                child_pid = int(marker.read_text(encoding="utf-8"))
                self.assertEqual(lease.pid, os.getpgid(lease.pid))
                self.assertEqual(lease.pid, os.getsid(lease.pid))
                self.assertEqual(
                    system_process_start_marker_v2(lease.pid),
                    lease.process_start_marker,
                )
                self.assertEqual(lease.process_group_id, os.getpgid(child_pid))
                deadline = OperationDeadlineV2.start(
                    operation="apply",
                    timeout_seconds=3,
                    timeout_code="ROOT_EXPIRED",
                )

                result = supervisor.terminate_transient(
                    lease,
                    deadline=deadline,
                    max_wait_seconds=1,
                    reason_code="REAL_TEST_FINISHED",
                )

                self.assertEqual("terminated", result.state)
                self.assertTrue(
                    _wait_until_not_live(child_pid, timeout_seconds=2)
                )
                self.assertFalse(_group_exists(lease.process_group_id))
            finally:
                _force_test_cleanup(lease.process_group_id, lease.process)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "killpg"),
        "requires POSIX process groups",
    )
    def test_real_stopped_group_is_resumed_after_term_and_disappears(self) -> None:
        module = _load_module()
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="stopped-group-v2-"
        ) as raw:
            ready = Path(raw) / "ready"
            script = (
                "import pathlib,signal,sys,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "pathlib.Path(sys.argv[1]).write_text('ready');"
                "time.sleep(0.3)"
            )
            supervisor = module.OperationProcessGroupSupervisorV2(
                poll_interval_seconds=0.01
            )
            lease = supervisor.spawn_transient(
                label="stopped",
                argv=(sys.executable, "-c", script, str(ready)),
            )
            try:
                _wait_for_file(ready, timeout_seconds=2)
                os.killpg(lease.process_group_id, signal.SIGSTOP)
                self.assertTrue(
                    _wait_for_process_state(
                        lease.pid, prefix="T", timeout_seconds=2
                    )
                )
                deadline = OperationDeadlineV2.start(
                    operation="recovery",
                    timeout_seconds=3,
                    timeout_code="RECOVERY_EXPIRED",
                )

                result = supervisor.terminate_transient(
                    lease,
                    deadline=deadline,
                    max_wait_seconds=1,
                    reason_code="STOPPED_TEST_FINISHED",
                )

                self.assertTrue(result.term_sent)
                self.assertTrue(result.cont_sent)
                self.assertEqual("terminated", result.state)
                self.assertFalse(_group_exists(lease.process_group_id))
            finally:
                _force_test_cleanup(lease.process_group_id, lease.process)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "killpg"),
        "requires POSIX process groups",
    )
    def test_real_temporarily_stubborn_group_creates_obligation_then_cleans(self) -> None:
        module = _load_module()
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="stubborn-group-v2-"
        ) as raw:
            ready = Path(raw) / "ready"
            child_ready = Path(raw) / "child-ready"
            child_code = (
                "import pathlib,signal,sys,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "pathlib.Path(sys.argv[1]).write_text('ready');"
                "time.sleep(0.25);"
                "signal.signal(signal.SIGTERM,signal.SIG_DFL);"
                "time.sleep(2)"
            )
            parent_code = (
                "import pathlib,signal,subprocess,sys,time;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "child=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[3]]);"
                "limit=time.monotonic()+2;"
                "child_ready=pathlib.Path(sys.argv[3]);"
                "\nwhile not child_ready.exists() and time.monotonic()<limit: time.sleep(0.005);"
                "\npathlib.Path(sys.argv[2]).write_text(str(child.pid));"
                "\ntime.sleep(0.25);"
                "\nsignal.signal(signal.SIGTERM,signal.SIG_DFL);"
                "\ntime.sleep(2)"
            )
            supervisor = module.OperationProcessGroupSupervisorV2(
                poll_interval_seconds=0.005
            )
            lease = supervisor.spawn_transient(
                label="temporarily-stubborn",
                argv=(
                    sys.executable,
                    "-c",
                    parent_code,
                    child_code,
                    str(ready),
                    str(child_ready),
                ),
            )
            try:
                _wait_for_file(ready, timeout_seconds=2)
                child_pid = int(ready.read_text(encoding="utf-8"))
                first = supervisor.terminate_transient(
                    lease,
                    deadline=OperationDeadlineV2.start(
                        operation="apply",
                        timeout_seconds=1,
                        timeout_code="ROOT_EXPIRED",
                    ),
                    max_wait_seconds=0.02,
                    reason_code="TEMPORARY_PROCESS_REJECTED",
                )

                self.assertEqual("cleanup-required", first.state)
                self.assertFalse(first.continuation_allowed)
                with self.assertRaises(
                    module.OutstandingProcessCleanupObligationV2
                ):
                    supervisor.assert_continuation_allowed()

                time.sleep(0.35)
                second = supervisor.terminate_transient(
                    lease,
                    deadline=OperationDeadlineV2.start(
                        operation="recovery",
                        timeout_seconds=2,
                        timeout_code="RECOVERY_EXPIRED",
                    ),
                    max_wait_seconds=1,
                    reason_code="CLEANUP_RETRY",
                )

                self.assertEqual("terminated", second.state)
                self.assertTrue(second.continuation_allowed)
                self.assertTrue(
                    _wait_until_not_live(child_pid, timeout_seconds=2)
                )
                self.assertFalse(_group_exists(lease.process_group_id))
            finally:
                _force_test_cleanup(lease.process_group_id, lease.process)


def _group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_file(path: Path, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {path}")
        time.sleep(0.01)


def _wait_until_not_live(pid: int, *, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = subprocess.run(
            ("/bin/ps", "-o", "stat=", "-p", str(pid)),
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
        state = completed.stdout.strip()
        if not state or state.startswith("Z"):
            return True
        time.sleep(0.01)
    return False


def _wait_for_process_state(
    pid: int, *, prefix: str, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = subprocess.run(
            ("/bin/ps", "-o", "stat=", "-p", str(pid)),
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
        if completed.stdout.strip().startswith(prefix):
            return True
        time.sleep(0.01)
    return False


def _force_test_cleanup(process_group_id: int, process: object) -> None:
    if _group_exists(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGTERM)
            os.killpg(process_group_id, signal.SIGCONT)
        except (ProcessLookupError, PermissionError):
            pass
    poll = getattr(process, "poll", None)
    wait = getattr(process, "wait", None)
    if callable(poll) and poll() is None and callable(wait):
        try:
            wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


if __name__ == "__main__":
    unittest.main()
