from __future__ import annotations

import copy
import errno
import os
import signal
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipStoreV2,
    DurableProcessOwnershipV2Error,
    OutstandingDurableProcessOwnershipV2,
    ownership_directory_path_v2,
)
from codex_smart_subagents.operation_process_group_supervisor_v2 import (  # noqa: E402
    ProcessIdentityV2,
    TransientProcessLeaseV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)


OPERATION_ID = "op2_" + "1" * 32
CANDIDATE_ID = "cand2_" + "2" * 32
CONTROLLER_START_ID = "cs2_" + "3" * 32
ACTION_FINGERPRINT = "4" * 64
DISPATCH_FINGERPRINT = "5" * 64
INVOCATION_ID = "inv2_" + "6" * 32


class _Process:
    pass


class _Clock:
    def __init__(self) -> None:
        self.value = 10.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds

    def monotonic_ns(self) -> int:
        return int(self.value * 1_000_000_000)


def _lease(*, marker: str = "boot:123") -> TransientProcessLeaseV2:
    return TransientProcessLeaseV2(
        lease_id="transient-" + "a" * 32,
        label="candidate-controller",
        pid=7311,
        process_group_id=7311,
        session_id=7311,
        process_start_marker=marker,
        process=_Process(),
    )


def _candidate_context() -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "contextKind": "candidate-dispatch-v2",
        "operationId": OPERATION_ID,
        "candidateId": CANDIDATE_ID,
        "controllerStartId": CONTROLLER_START_ID,
        "actionFingerprint": ACTION_FINGERPRINT,
        "dispatchReceiptFingerprint": DISPATCH_FINGERPRINT,
    }


def _cleanup_obligation(lease: TransientProcessLeaseV2) -> dict[str, object]:
    identity = {
        "pid": lease.pid,
        "processGroupId": lease.process_group_id,
        "sessionId": lease.session_id,
        "startMarker": lease.process_start_marker,
    }
    return {
        "schemaVersion": 2,
        "obligationType": "transient-process-group-cleanup-v2",
        "obligationId": lease.lease_id,
        "status": "pending",
        "operation": "update",
        "phase": "candidate-ready",
        "processLabel": lease.label,
        "pid": lease.pid,
        "processGroupId": lease.process_group_id,
        "reasonCode": "CANDIDATE_READY_TIMEOUT",
        "attempt": 1,
        "termSent": False,
        "contSent": False,
        "preContSent": False,
        "postContSent": False,
        "termErrorErrno": None,
        "contErrorErrno": None,
        "preContErrorErrno": None,
        "postContErrorErrno": None,
        "observedAlive": True,
        "nextAction": "reconcile-identity-and-retry-term-cont",
        "automaticSignalAuthorized": False,
        "continuationAllowed": False,
        "expectedProcessIdentity": identity,
        "observedProcessIdentity": None,
        "identityFailureCode": "PROCESS_IDENTITY_UNAVAILABLE",
        "deadlineProof": None,
    }


class DurableProcessOwnershipStoreV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="durable-ownership-v2-"
        )
        self.codex_home = Path(self.temporary.name).resolve() / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.manifests = self.codex_home / "install-manifests"
        self.manifests.mkdir(mode=0o700)
        self.store = DurableProcessOwnershipStoreV2(
            self.codex_home,
            operation="update",
            phase="installer-invocation",
            invocation_id=INVOCATION_ID,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_candidate_publication_is_canonical_private_and_idempotent(self) -> None:
        lease = _lease()

        first = self.store.publish(lease, _candidate_context())
        second = self.store.publish(lease, _candidate_context())

        self.assertEqual(first, second)
        self.assertEqual("OWNED", first.state)
        self.assertIsNone(first.cleanup_obligation)
        self.assertEqual(_candidate_context(), first.context)
        self.assertEqual((first,), self.store.load_all())
        path = ownership_directory_path_v2(self.codex_home) / (
            lease.lease_id + ".json"
        )
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
        raw = path.read_bytes()
        self.assertFalse(raw.endswith(b"\n"))
        self.assertIn(b'"recordFingerprint"', raw)

    def test_concurrent_recovery_waiter_reloads_without_repeating_signals(
        self,
    ) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        second_store = DurableProcessOwnershipStoreV2(
            self.codex_home,
            operation="update",
            phase="installer-invocation",
            invocation_id=INVOCATION_ID,
        )
        identity = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        first_inside = threading.Event()
        second_inside = threading.Event()
        release_first = threading.Event()
        proof_calls = 0
        proof_lock = threading.Lock()
        signal_calls: list[int] = []
        signal_lock = threading.Lock()
        results: list[object] = []
        errors: list[BaseException] = []

        def accepted_candidate_proof(_record) -> bool:
            nonlocal proof_calls
            with proof_lock:
                proof_calls += 1
                call = proof_calls
            if call == 1:
                first_inside.set()
                self.assertTrue(release_first.wait(timeout=2))
            else:
                second_inside.set()
            return False

        def killpg(_process_group_id: int, signum: int) -> None:
            with signal_lock:
                signal_calls.append(signum)

        def recover(store: DurableProcessOwnershipStoreV2) -> None:
            try:
                results.append(
                    store.recover(
                        accepted_candidate_proof=accepted_candidate_proof,
                        candidate_termination_authorized=lambda _record: True,
                        identity_reader=lambda _pid: identity,
                        group_exists=lambda _process_group_id: True,
                        killpg=killpg,
                        max_wait_seconds=0.01,
                        poll_interval_seconds=0.005,
                    )
                )
            except BaseException as error:
                errors.append(error)

        first = threading.Thread(target=recover, args=(self.store,))
        second = threading.Thread(target=recover, args=(second_store,))
        first.start()
        self.assertTrue(first_inside.wait(timeout=2))
        second.start()
        second_inside.wait(timeout=0.2)
        release_first.set()
        first.join(timeout=3)
        second.join(timeout=3)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(1, proof_calls)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            signal_calls,
        )
        self.assertEqual((lease.lease_id,), results[1].remaining_lease_ids)

    def test_recovery_thread_lock_timeout_preserves_root_deadline_error(
        self,
    ) -> None:
        from codex_smart_subagents import durable_process_ownership_v2 as module

        thread_lock = module._recovery_thread_lock_v2(self.codex_home)
        self.assertTrue(thread_lock.acquire(blocking=False))
        deadline = OperationDeadlineV2.start(
            operation="recover",
            timeout_seconds=0.01,
            timeout_code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
        )
        try:
            with (
                scoped_current_deadline_v2(deadline),
                self.assertRaises(OperationDeadlineExceededV2) as caught,
            ):
                self.store.recover(
                    accepted_candidate_proof=lambda _record: False,
                )
        finally:
            thread_lock.release()

        self.assertEqual(
            "RECOVERY_OPERATION_DEADLINE_TIMEOUT",
            caught.exception.code,
        )

    def test_recovery_validates_arguments_before_waiting_for_contended_lock(
        self,
    ) -> None:
        from codex_smart_subagents import durable_process_ownership_v2 as module

        thread_lock = module._recovery_thread_lock_v2(self.codex_home)
        self.assertTrue(thread_lock.acquire(blocking=False))
        deadline = OperationDeadlineV2.start(
            operation="recover",
            timeout_seconds=0.01,
            timeout_code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
        )
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaisesRegex(
                    TypeError,
                    "accepted_candidate_proof must be callable",
                ):
                    self.store.recover(accepted_candidate_proof=None)  # type: ignore[arg-type]
                with self.assertRaisesRegex(
                    ValueError,
                    "context_kinds must be null or a supported frozenset",
                ):
                    self.store.recover(
                        accepted_candidate_proof=lambda _record: False,
                        context_kinds=frozenset({"unknown"}),
                    )
        finally:
            thread_lock.release()

    def test_existing_invalid_recovery_lock_is_rejected_without_mutation(
        self,
    ) -> None:
        lock_path = (
            self.codex_home
            / ".durable-process-ownership-recovery-v2.lock"
        )
        witness_path = self.codex_home / "recovery-lock-witness"
        lock_path.write_bytes(b"do-not-change")
        lock_path.chmod(0o640)
        os.link(lock_path, witness_path)
        before = lock_path.stat()

        with self.assertRaises(DurableProcessOwnershipV2Error) as caught:
            self.store.recover(
                accepted_candidate_proof=lambda _record: False,
            )

        after = lock_path.stat()
        self.assertEqual(
            "DURABLE_OWNERSHIP_RECOVERY_LOCK_INVALID",
            caught.exception.code,
        )
        self.assertEqual(b"do-not-change", lock_path.read_bytes())
        self.assertEqual(b"do-not-change", witness_path.read_bytes())
        self.assertEqual(before.st_mode, after.st_mode)
        self.assertEqual(before.st_nlink, after.st_nlink)
        self.assertEqual(before.st_ino, after.st_ino)

    def test_recovery_lock_release_failure_does_not_mask_primary_error(
        self,
    ) -> None:
        from codex_smart_subagents import durable_process_ownership_v2 as module

        self.store.publish(_lease(), _candidate_context())
        real_flock = module.fcntl.flock
        recovery_descriptor: list[int] = []

        def fail_recovery_unlock(descriptor: int, operation: int) -> None:
            if (
                not recovery_descriptor
                and operation == module.fcntl.LOCK_EX | module.fcntl.LOCK_NB
            ):
                recovery_descriptor.append(descriptor)
            if (
                recovery_descriptor
                and descriptor == recovery_descriptor[0]
                and operation == module.fcntl.LOCK_UN
            ):
                raise OSError(errno.EIO, "forced recovery unlock failure")
            real_flock(descriptor, operation)

        def fail_primary(_record) -> bool:
            raise RuntimeError("primary acceptance proof failure")

        with (
            mock.patch.object(
                module.fcntl,
                "flock",
                side_effect=fail_recovery_unlock,
            ),
            self.assertRaises(DurableProcessOwnershipV2Error) as caught,
        ):
            self.store.recover(
                accepted_candidate_proof=fail_primary,
            )

        self.assertEqual(
            "DURABLE_OWNERSHIP_ACCEPTANCE_PROOF_FAILED",
            caught.exception.code,
        )
        self.assertTrue(
            any(
                "recovery lock release also failed" in note
                for note in getattr(caught.exception, "__notes__", ())
            )
        )

    def test_generic_context_is_completed_by_invocation_binding(self) -> None:
        lease = _lease()
        context = {
            "schemaVersion": 2,
            "contextKind": "installer-transient-v2",
            "processLabel": lease.label,
        }

        record = self.store.publish(lease, context)

        self.assertEqual(
            {
                **context,
                "operation": "update",
                "phase": "installer-invocation",
                "invocationId": INVOCATION_ID,
            },
            record.context,
        )

    def test_conflicting_republication_is_rejected_without_overwrite(self) -> None:
        lease = _lease()
        original = self.store.publish(lease, _candidate_context())
        changed = _candidate_context()
        changed["candidateId"] = "cand2_" + "9" * 32

        with self.assertRaises(DurableProcessOwnershipV2Error) as raised:
            self.store.publish(lease, changed)

        self.assertEqual("DURABLE_OWNERSHIP_CONFLICT", raised.exception.code)
        self.assertEqual((original,), self.store.load_all())

    def test_cleanup_transition_persists_and_success_removes_last_directory(self) -> None:
        lease = _lease()
        context = _candidate_context()
        self.store.publish(lease, context)

        pending = self.store.transition(
            lease,
            context,
            "cleanup-required",
            _cleanup_obligation(lease),
        )

        self.assertIsNotNone(pending)
        assert pending is not None
        self.assertEqual("CLEANUP_REQUIRED", pending.state)
        self.assertEqual(_cleanup_obligation(lease), pending.cleanup_obligation)
        removed = self.store.transition(
            lease,
            context,
            "soft-terminated",
            None,
        )
        self.assertIsNone(removed)
        self.assertEqual((), self.store.load_all())
        self.assertFalse(ownership_directory_path_v2(self.codex_home).exists())

    def test_transition_requires_exact_lease_and_context(self) -> None:
        lease = _lease()
        context = _candidate_context()
        original = self.store.publish(lease, context)
        changed = copy.deepcopy(context)
        changed["dispatchReceiptFingerprint"] = "f" * 64

        with self.assertRaises(DurableProcessOwnershipV2Error) as raised:
            self.store.transition(lease, changed, "accepted", None)

        self.assertEqual("DURABLE_OWNERSHIP_BINDING_MISMATCH", raised.exception.code)
        self.assertEqual((original,), self.store.load_all())

    def test_invalid_context_and_invalid_transition_leave_no_artifact(self) -> None:
        lease = _lease()
        invalid = _candidate_context()
        invalid["extra"] = "forbidden"

        with self.assertRaises(DurableProcessOwnershipV2Error) as raised:
            self.store.publish(lease, invalid)

        self.assertEqual("DURABLE_OWNERSHIP_CONTEXT_INVALID", raised.exception.code)
        self.assertFalse(ownership_directory_path_v2(self.codex_home).exists())
        self.store.publish(lease, _candidate_context())
        with self.assertRaises(DurableProcessOwnershipV2Error) as outcome_error:
            self.store.transition(
                lease,
                _candidate_context(),
                "accepted",
                _cleanup_obligation(lease),
            )
        self.assertEqual(
            "DURABLE_OWNERSHIP_TRANSITION_INVALID", outcome_error.exception.code
        )

    def test_non_private_or_noncanonical_record_is_rejected(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        path = ownership_directory_path_v2(self.codex_home) / (
            lease.lease_id + ".json"
        )
        path.chmod(0o644)

        with self.assertRaises(DurableProcessOwnershipV2Error) as raised:
            self.store.load_all()

        self.assertEqual("DURABLE_OWNERSHIP_FILE_UNSAFE", raised.exception.code)

    def test_empty_store_does_not_create_new_paths(self) -> None:
        empty_home = Path(self.temporary.name).resolve() / "empty-home"
        empty_home.mkdir(mode=0o700)
        store = DurableProcessOwnershipStoreV2(
            empty_home,
            operation="status",
            phase="preflight",
            invocation_id="inv2_" + "7" * 32,
        )

        self.assertEqual((), store.load_all())
        self.assertEqual(["empty-home"], sorted(path.name for path in empty_home.parent.iterdir() if path == empty_home))
        self.assertEqual([], list(empty_home.iterdir()))

    def test_recover_proven_accepted_candidate_clears_without_signal(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        signals: list[tuple[int, int]] = []

        result = self.store.recover(
            accepted_candidate_proof=lambda record: (
                record.context["candidateId"] == CANDIDATE_ID
            ),
            identity_reader=lambda _pid: self.fail(
                "accepted proof must precede process inspection"
            ),
            group_exists=lambda _pgid: self.fail(
                "accepted proof must precede process inspection"
            ),
            killpg=lambda pgid, signum: signals.append((pgid, signum)),
        )

        self.assertEqual((lease.lease_id,), result.resolved_lease_ids)
        self.assertEqual((), result.remaining_lease_ids)
        self.assertEqual([], signals)
        self.assertFalse(ownership_directory_path_v2(self.codex_home).exists())

    def test_acceptance_proof_preserves_exact_root_deadline_error(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        deadline_error = OperationDeadlineExceededV2(
            code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
            operation="recover",
            phase="candidate-acceptance-proof",
            deadline_kind="operation",
            configured_timeout_nanoseconds=120_000_000_000,
            elapsed_monotonic_nanoseconds=120_000_000_000,
        )

        def expired_proof(_record: object) -> bool:
            raise deadline_error

        with self.assertRaises(OperationDeadlineExceededV2) as raised:
            self.store.recover(
                accepted_candidate_proof=expired_proof,
            )

        self.assertIs(deadline_error, raised.exception)
        self.assertEqual((lease.lease_id,), tuple(
            record.lease_id for record in self.store.load_all()
        ))

    def test_recover_exact_identity_uses_only_soft_group_signals(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        signals: list[tuple[int, int]] = []
        alive = iter((True, True, True, True, False))
        identities = iter((expected, expected, expected, expected, None))

        result = self.store.recover(
            accepted_candidate_proof=lambda _record: False,
            candidate_termination_authorized=lambda _record: True,
            identity_reader=lambda _pid: next(identities),
            group_exists=lambda _pgid: next(alive),
            killpg=lambda pgid, signum: signals.append((pgid, signum)),
            max_wait_seconds=0.05,
            poll_interval_seconds=0.01,
        )

        self.assertEqual((lease.lease_id,), result.resolved_lease_ids)
        self.assertEqual((), result.remaining_lease_ids)
        self.assertEqual(
            [
                (lease.process_group_id, signal.SIGCONT),
                (lease.process_group_id, signal.SIGTERM),
                (lease.process_group_id, signal.SIGCONT),
            ],
            signals,
        )
        self.assertNotIn(signal.SIGKILL, [item[1] for item in signals])

    def test_recover_rejects_nan_monotonic_before_any_signal(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        signals: list[tuple[int, int]] = []

        with self.assertRaisesRegex(
            ValueError,
            "monotonic must return a finite non-negative number",
        ):
            self.store.recover(
                accepted_candidate_proof=lambda _record: False,
                candidate_termination_authorized=lambda _record: True,
                identity_reader=lambda _pid: expected,
                group_exists=lambda _pgid: True,
                killpg=lambda pgid, signum: signals.append((pgid, signum)),
                monotonic=lambda: float("nan"),
            )

        self.assertEqual([], signals)
        self.assertEqual("OWNED", self.store.load_all()[0].state)

    def test_recover_persists_sent_signals_before_sleep_failure(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        signals: list[tuple[int, int]] = []
        clock = _Clock()
        primary_error = RuntimeError("forced recovery sleep failure")

        with self.assertRaises(RuntimeError) as raised:
            self.store.recover(
                accepted_candidate_proof=lambda _record: False,
                candidate_termination_authorized=lambda _record: True,
                identity_reader=lambda _pid: expected,
                group_exists=lambda _pgid: True,
                killpg=lambda pgid, signum: signals.append((pgid, signum)),
                monotonic=clock,
                sleep=lambda _seconds: (_ for _ in ()).throw(primary_error),
            )

        self.assertIs(primary_error, raised.exception)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            [signum for _pgid, signum in signals],
        )
        self._assert_all_soft_signals_persisted(lease)

    def test_recover_persists_sent_signals_before_late_clock_failure(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        readings = 0
        signals: list[tuple[int, int]] = []
        primary_error = RuntimeError("forced late recovery clock failure")

        def monotonic() -> float:
            nonlocal readings
            readings += 1
            if readings == 2:
                raise primary_error
            return 10.0

        with self.assertRaises(RuntimeError) as raised:
            self.store.recover(
                accepted_candidate_proof=lambda _record: False,
                candidate_termination_authorized=lambda _record: True,
                identity_reader=lambda _pid: expected,
                group_exists=lambda _pgid: True,
                killpg=lambda pgid, signum: signals.append((pgid, signum)),
                monotonic=monotonic,
            )

        self.assertIs(primary_error, raised.exception)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            [signum for _pgid, signum in signals],
        )
        self._assert_all_soft_signals_persisted(lease)

    def test_recover_persists_sent_signals_before_identity_failure(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        observations = 0
        signals: list[tuple[int, int]] = []
        primary_error = RuntimeError("forced recovery identity failure")

        def identity_reader(_pid: int) -> ProcessIdentityV2:
            nonlocal observations
            observations += 1
            if observations == 5:
                raise primary_error
            return expected

        with self.assertRaises(RuntimeError) as raised:
            self.store.recover(
                accepted_candidate_proof=lambda _record: False,
                candidate_termination_authorized=lambda _record: True,
                identity_reader=identity_reader,
                group_exists=lambda _pgid: True,
                killpg=lambda pgid, signum: signals.append((pgid, signum)),
            )

        self.assertIs(primary_error, raised.exception)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            [signum for _pgid, signum in signals],
        )
        self._assert_all_soft_signals_persisted(lease)

    def test_recover_persists_sent_signals_before_group_failure(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        observations = 0
        signals: list[tuple[int, int]] = []
        primary_error = RuntimeError("forced recovery group failure")

        def group_exists(_process_group_id: int) -> bool:
            nonlocal observations
            observations += 1
            if observations == 5:
                raise primary_error
            return True

        with self.assertRaises(RuntimeError) as raised:
            self.store.recover(
                accepted_candidate_proof=lambda _record: False,
                candidate_termination_authorized=lambda _record: True,
                identity_reader=lambda _pid: expected,
                group_exists=group_exists,
                killpg=lambda pgid, signum: signals.append((pgid, signum)),
            )

        self.assertIs(primary_error, raised.exception)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            [signum for _pgid, signum in signals],
        )
        self._assert_all_soft_signals_persisted(lease)

    def _assert_all_soft_signals_persisted(
        self,
        lease: TransientProcessLeaseV2,
    ) -> None:
        remaining = self.store.load_all()[0]
        self.assertEqual("CLEANUP_REQUIRED", remaining.state)
        obligation = remaining.cleanup_obligation
        assert obligation is not None
        self.assertEqual(lease.lease_id, obligation["obligationId"])
        self.assertEqual(1, obligation["attempt"])
        self.assertTrue(obligation["preContSent"])
        self.assertTrue(obligation["termSent"])
        self.assertTrue(obligation["postContSent"])
        self.assertTrue(obligation["contSent"])
        self.assertIsNone(obligation["preContErrorErrno"])
        self.assertIsNone(obligation["termErrorErrno"])
        self.assertIsNone(obligation["postContErrorErrno"])
        self.assertIsNone(obligation["contErrorErrno"])
        self.assertEqual(
            "DURABLE_PROCESS_OWNERSHIP_SIGNAL_SEQUENCE_SENT",
            obligation["reasonCode"],
        )
        self.assertEqual(
            "reconcile-identity-without-repeat-signals",
            obligation["nextAction"],
        )
        self.assertFalse(obligation["automaticSignalAuthorized"])
        self.assertFalse(obligation["continuationAllowed"])

    def test_recover_identity_mismatch_never_signals_and_blocks_continuation(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        mismatched = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker="other-start-marker",
        )
        signals: list[tuple[int, int]] = []

        result = self.store.recover(
            accepted_candidate_proof=lambda _record: False,
            candidate_termination_authorized=lambda _record: True,
            identity_reader=lambda _pid: mismatched,
            group_exists=lambda _pgid: True,
            killpg=lambda pgid, signum: signals.append((pgid, signum)),
        )

        self.assertEqual((), result.resolved_lease_ids)
        self.assertEqual((lease.lease_id,), result.remaining_lease_ids)
        self.assertEqual([], signals)
        remaining = self.store.load_all()[0]
        self.assertEqual("CLEANUP_REQUIRED", remaining.state)
        assert remaining.cleanup_obligation is not None
        self.assertEqual(
            "PROCESS_IDENTITY_MISMATCH",
            remaining.cleanup_obligation["identityFailureCode"],
        )
        with self.assertRaises(OutstandingDurableProcessOwnershipV2) as raised:
            self.store.assert_continuation_allowed()
        self.assertEqual((lease.lease_id,), raised.exception.lease_ids)

    def test_recover_rechecks_identity_before_every_signal(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        changed = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker="reused-after-first-check",
        )
        identities = iter((expected, expected, changed))
        signals: list[tuple[int, int]] = []

        result = self.store.recover(
            accepted_candidate_proof=lambda _record: False,
            candidate_termination_authorized=lambda _record: True,
            identity_reader=lambda _pid: next(identities),
            group_exists=lambda _pgid: True,
            killpg=lambda pgid, signum: signals.append((pgid, signum)),
        )

        self.assertEqual((lease.lease_id,), result.remaining_lease_ids)
        self.assertEqual([(lease.process_group_id, signal.SIGCONT)], signals)

    def test_recover_stubborn_group_keeps_deadline_obligation(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        clock = _Clock()
        signals: list[tuple[int, int]] = []

        result = self.store.recover(
            accepted_candidate_proof=lambda _record: False,
            candidate_termination_authorized=lambda _record: True,
            identity_reader=lambda _pid: expected,
            group_exists=lambda _pgid: True,
            killpg=lambda pgid, signum: signals.append((pgid, signum)),
            monotonic=clock,
            sleep=clock.sleep,
            max_wait_seconds=0.02,
            poll_interval_seconds=0.01,
        )

        self.assertEqual((lease.lease_id,), result.remaining_lease_ids)
        remaining = self.store.load_all()[0]
        assert remaining.cleanup_obligation is not None
        proof = remaining.cleanup_obligation["deadlineProof"]
        self.assertIsInstance(proof, dict)
        self.assertEqual("DURABLE_OWNERSHIP_RECOVERY_TIMEOUT", proof["timeoutCode"])
        self.assertNotIn(signal.SIGKILL, [item[1] for item in signals])

    def test_repeated_recover_reconciles_without_resending_soft_signals(
        self,
    ) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        clock = _Clock()
        signals: list[tuple[int, int]] = []
        arguments = {
            "accepted_candidate_proof": lambda _record: False,
            "candidate_termination_authorized": lambda _record: True,
            "identity_reader": lambda _pid: expected,
            "group_exists": lambda _pgid: True,
            "killpg": lambda pgid, signum: signals.append((pgid, signum)),
            "monotonic": clock,
            "sleep": clock.sleep,
            "max_wait_seconds": 0.02,
            "poll_interval_seconds": 0.01,
        }

        first = self.store.recover(**arguments)
        first_fingerprint = self.store.load_all()[0].record_fingerprint
        second = self.store.recover(**arguments)
        remaining = self.store.load_all()[0]

        self.assertEqual((lease.lease_id,), first.remaining_lease_ids)
        self.assertEqual((lease.lease_id,), second.remaining_lease_ids)
        assert remaining.cleanup_obligation is not None
        self.assertEqual(2, remaining.cleanup_obligation["attempt"])
        self.assertNotEqual(first_fingerprint, remaining.record_fingerprint)
        self.assertEqual(
            [signal.SIGCONT, signal.SIGTERM, signal.SIGCONT],
            [item[1] for item in signals],
        )
        self.assertNotIn(signal.SIGKILL, [item[1] for item in signals])

    def test_recover_proven_absence_clears_without_signal(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        signals: list[tuple[int, int]] = []

        result = self.store.recover(
            accepted_candidate_proof=lambda _record: False,
            candidate_termination_authorized=lambda _record: True,
            identity_reader=lambda _pid: None,
            group_exists=lambda _pgid: False,
            killpg=lambda pgid, signum: signals.append((pgid, signum)),
        )

        self.assertEqual((lease.lease_id,), result.resolved_lease_ids)
        self.assertEqual([], signals)

    def test_unknown_candidate_acceptance_resolves_only_exact_absence_without_signal(
        self,
    ) -> None:
        lease = _lease()

        for authorization in (None, lambda _record: False):
            with self.subTest(authorization_present=authorization is not None):
                self.store.publish(lease, _candidate_context())
                observations: list[tuple[str, int]] = []
                arguments = (
                    {}
                    if authorization is None
                    else {"candidate_termination_authorized": authorization}
                )

                result = self.store.recover(
                    accepted_candidate_proof=lambda _record: False,
                    identity_reader=lambda pid: observations.append(
                        ("identity", pid)
                    ),
                    group_exists=lambda pgid: (
                        observations.append(("group", pgid)) or False
                    ),
                    killpg=lambda _pgid, _signum: self.fail(
                        "exact absence must never authorize a signal"
                    ),
                    **arguments,
                )

                self.assertEqual((lease.lease_id,), result.resolved_lease_ids)
                self.assertEqual((), result.remaining_lease_ids)
                self.assertEqual(
                    [("identity", lease.pid), ("group", lease.process_group_id)],
                    observations,
                )
                self.assertEqual((), self.store.load_all())

    def test_unknown_candidate_acceptance_preserves_non_absence_without_signal(
        self,
    ) -> None:
        lease = _lease()
        exact = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        mismatch = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker="reused-candidate-marker",
        )

        for label, identity, group_alive in (
            ("alive", exact, True),
            ("mismatch", mismatch, True),
            ("unknown", None, True),
        ):
            for authorization in (None, lambda _record: False):
                with self.subTest(
                    observation=label,
                    authorization_present=authorization is not None,
                ):
                    original = self.store.publish(lease, _candidate_context())
                    observations: list[tuple[str, int]] = []
                    arguments = (
                        {}
                        if authorization is None
                        else {"candidate_termination_authorized": authorization}
                    )

                    result = self.store.recover(
                        accepted_candidate_proof=lambda _record: False,
                        identity_reader=lambda pid: (
                            observations.append(("identity", pid)) or identity
                        ),
                        group_exists=lambda pgid: (
                            observations.append(("group", pgid)) or group_alive
                        ),
                        killpg=lambda _pgid, _signum: self.fail(
                            "negative authorization must never send a signal"
                        ),
                        **arguments,
                    )

                    self.assertEqual((), result.resolved_lease_ids)
                    self.assertEqual((lease.lease_id,), result.remaining_lease_ids)
                    self.assertEqual(
                        [
                            ("identity", lease.pid),
                            ("group", lease.process_group_id),
                        ],
                        observations,
                    )
                    self.assertEqual((original,), self.store.load_all())
                    self.store.transition(
                        lease,
                        _candidate_context(),
                        "verified-exit",
                        None,
                    )

    def test_recovery_wait_cannot_outlive_earlier_root_deadline(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())
        expected = ProcessIdentityV2(
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            session_id=lease.session_id,
            start_marker=lease.process_start_marker,
        )
        clock = _Clock()
        deadline = OperationDeadlineV2.start(
            operation="recover",
            timeout_seconds=0.015,
            timeout_code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=clock.monotonic_ns,
        )

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2) as raised:
                self.store.recover(
                    accepted_candidate_proof=lambda _record: False,
                    candidate_termination_authorized=lambda _record: True,
                    identity_reader=lambda _pid: expected,
                    group_exists=lambda _pgid: True,
                    killpg=lambda _pgid, _signum: None,
                    monotonic=clock,
                    sleep=clock.sleep,
                    max_wait_seconds=0.5,
                    poll_interval_seconds=0.01,
                )

        self.assertEqual(
            "RECOVERY_OPERATION_DEADLINE_TIMEOUT", raised.exception.code
        )
        self.assertLessEqual(clock.value, 10.015)
        self.assertEqual((lease.lease_id,), tuple(
            record.lease_id for record in self.store.load_all()
        ))

    def test_busy_home_lock_stops_at_exact_root_deadline(self) -> None:
        clock = _Clock()
        deadline = OperationDeadlineV2.start(
            operation="recover",
            timeout_seconds=0.02,
            timeout_code="RECOVERY_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=clock.monotonic_ns,
        )

        def busy(_descriptor: int, _operation: int) -> None:
            raise BlockingIOError(errno.EWOULDBLOCK, "busy")

        from codex_smart_subagents import finite_file_lock_v2

        original_acquire = finite_file_lock_v2.acquire_flock_v2

        def acquire_with_busy_lock(descriptor: int, **arguments: object) -> None:
            original_acquire(
                descriptor,
                exclusive=bool(arguments["exclusive"]),
                timeout_seconds=float(arguments["timeout_seconds"]),
                timeout_code=str(arguments["timeout_code"]),
                poll_interval_seconds=0.01,
                monotonic=clock,
                sleep=clock.sleep,
                flock=busy,
            )

        with (
            scoped_current_deadline_v2(deadline),
            mock.patch.object(
                finite_file_lock_v2,
                "acquire_flock_v2",
                side_effect=acquire_with_busy_lock,
            ),
            self.assertRaises(OperationDeadlineExceededV2) as raised,
        ):
            self.store.load_all()

        self.assertEqual(
            "RECOVERY_OPERATION_DEADLINE_TIMEOUT", raised.exception.code
        )

    def test_release_accepted_candidate_requires_exact_durable_identity(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())

        released = self.store.release_accepted_candidate_identity(
            operation_id=OPERATION_ID,
            candidate_id=CANDIDATE_ID,
            controller_start_id=CONTROLLER_START_ID,
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            process_start_marker=lease.process_start_marker,
        )

        self.assertTrue(released)
        self.assertEqual((), self.store.load_all())

    def test_release_accepted_candidate_preserves_identity_mismatch(self) -> None:
        lease = _lease()
        self.store.publish(lease, _candidate_context())

        with self.assertRaises(DurableProcessOwnershipV2Error) as raised:
            self.store.release_accepted_candidate_identity(
                operation_id=OPERATION_ID,
                candidate_id=CANDIDATE_ID,
                controller_start_id=CONTROLLER_START_ID,
                pid=lease.pid,
                process_group_id=lease.process_group_id,
                process_start_marker="different-marker",
            )

        self.assertEqual("DURABLE_OWNERSHIP_BINDING_MISMATCH", raised.exception.code)
        self.assertEqual((lease.lease_id,), tuple(r.lease_id for r in self.store.load_all()))


if __name__ == "__main__":
    unittest.main()
