from __future__ import annotations

import errno
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents import finite_file_lock_v2  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    current_operation_deadline_v2,
    scoped_current_deadline_v2,
)
from codex_smart_subagents.operation_process_group_supervisor_v2 import (  # noqa: E402
    TransientProcessLeaseV2,
    current_process_group_supervisor_v2,
)
from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipStoreV2,
    DurableProcessOwnershipV2Error,
    OutstandingDurableProcessOwnershipV2,
    ownership_directory_path_v2,
)
from codex_smart_subagents.installer_command_v2 import (  # noqa: E402
    InstallerInvocationV2,
)


INSTALLER_PATH = ROOT / "scripts" / "install_adaptive_subagents.py"


def _load_installer():
    name = "install_adaptive_subagents_deadline_integration_under_test"
    spec = importlib.util.spec_from_file_location(name, INSTALLER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("installer module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _invocation(command: str, *, execute: bool) -> SimpleNamespace:
    return SimpleNamespace(command=command, execute=execute, json=True)


def _cleanup_obligation(
    obligation_id: str = "transient-" + "a" * 32,
) -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "obligationType": "transient-process-group-cleanup-v2",
        "obligationId": obligation_id,
        "status": "pending",
        "operation": "apply",
        "phase": "operation",
        "processLabel": "test-command",
        "pid": 8111,
        "processGroupId": 8111,
        "reasonCode": "TEST_CLEANUP_REQUIRED",
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
        "expectedProcessIdentity": {
            "pid": 8111,
            "processGroupId": 8111,
            "sessionId": 8111,
            "startMarker": "test-start-marker",
        },
        "observedProcessIdentity": None,
        "identityFailureCode": "PROCESS_IDENTITY_UNAVAILABLE",
        "deadlineProof": None,
    }


class _NanosecondClock:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class OperationDeadlineInstallerIntegrationV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = _load_installer()

    def test_executed_mutation_scopes_one_600_second_deadline_before_work(self) -> None:
        observed: list[object] = []
        real_start = OperationDeadlineV2.start

        def start(**kwargs):
            observed.append(dict(kwargs))
            return real_start(**kwargs)

        def execute_without_budget(invocation, **_kwargs):
            observed.append(current_operation_deadline_v2())
            return {"status": "ok", "command": invocation.command}

        with (
            mock.patch.object(
                self.installer.operation_deadline_v2.OperationDeadlineV2,
                "start",
                side_effect=start,
            ),
            mock.patch.object(
                self.installer,
                "_execute_installer_invocation_without_lock_budget_v2",
                side_effect=execute_without_budget,
            ),
        ):
            result = self.installer._execute_installer_invocation_with_lock_budget_v2(
                _invocation("apply", execute=True)
            )

        self.assertEqual({"status": "ok", "command": "apply"}, result)
        self.assertEqual(2, len(observed))
        self.assertEqual(
            {
                "operation": "apply",
                "timeout_seconds": 600.0,
                "timeout_code": "MUTATING_OPERATION_DEADLINE_TIMEOUT",
            },
            observed[0],
        )
        self.assertIsInstance(observed[1], OperationDeadlineV2)
        self.assertIsNone(current_operation_deadline_v2())

    def test_recover_uses_120_seconds_and_preview_creates_no_deadline(self) -> None:
        starts: list[dict[str, object]] = []
        real_start = OperationDeadlineV2.start

        def start(**kwargs):
            starts.append(dict(kwargs))
            return real_start(**kwargs)

        with (
            mock.patch.object(
                self.installer.operation_deadline_v2.OperationDeadlineV2,
                "start",
                side_effect=start,
            ),
            mock.patch.object(
                self.installer,
                "_execute_installer_invocation_without_lock_budget_v2",
                return_value={"status": "ok"},
            ),
        ):
            self.installer._execute_installer_invocation_with_lock_budget_v2(
                _invocation("recover", execute=True)
            )
            self.installer._execute_installer_invocation_with_lock_budget_v2(
                _invocation("cleanup", execute=False)
            )

        self.assertEqual(
            [
                {
                    "operation": "recover",
                    "timeout_seconds": 120.0,
                    "timeout_code": "RECOVERY_OPERATION_DEADLINE_TIMEOUT",
                }
            ],
            starts,
        )

    def test_nested_public_execution_reuses_current_deadline_without_extension(self) -> None:
        clock = _NanosecondClock()
        outer = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="OUTER_TIMEOUT",
            monotonic_ns=clock,
        )
        observed: list[OperationDeadlineV2 | None] = []

        def execute_without_budget(_invocation, **_kwargs):
            observed.append(current_operation_deadline_v2())
            return {"status": "ok"}

        with (
            scoped_current_deadline_v2(outer),
            mock.patch.object(
                self.installer.operation_deadline_v2.OperationDeadlineV2,
                "start",
            ) as start,
            mock.patch.object(
                self.installer,
                "_execute_installer_invocation_without_lock_budget_v2",
                side_effect=execute_without_budget,
            ),
        ):
            self.installer._execute_installer_invocation_with_lock_budget_v2(
                _invocation("apply", execute=True)
            )

        start.assert_not_called()
        self.assertEqual([outer], observed)

    def test_executed_operation_scopes_one_process_supervisor(self) -> None:
        observed: list[object] = []

        def execute_without_budget(_invocation, **_kwargs):
            observed.append(current_process_group_supervisor_v2())
            return {"status": "ok"}

        with mock.patch.object(
            self.installer,
            "_execute_installer_invocation_without_lock_budget_v2",
            side_effect=execute_without_budget,
        ):
            self.installer._execute_installer_invocation_with_lock_budget_v2(
                _invocation("apply", execute=True)
            )

        self.assertEqual(1, len(observed))
        self.assertIsInstance(
            observed[0],
            self.installer.operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2,
        )
        self.assertIsNone(current_process_group_supervisor_v2())

    def test_cli_deadline_failure_returns_70_with_closed_deadline_proof(self) -> None:
        error = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="operation",
            deadline_kind="operation",
            configured_timeout_nanoseconds=600_000_000_000,
            elapsed_monotonic_nanoseconds=600_000_000_001,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                self.installer,
                "execute_installer_invocation_v2",
                side_effect=error,
            ),
            redirect_stdout(output),
        ):
            code = self.installer.main(["--apply", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(70, code)
        self.assertEqual(
            {
                "schemaVersion",
                "proofType",
                "operation",
                "phase",
                "timeoutCode",
                "deadlineKind",
                "configuredTimeoutNanoseconds",
                "elapsedMonotonicNanoseconds",
                "deadlineExceeded",
            },
            set(result["extensions"]["deadlineProof"]),
        )
        self.assertEqual(
            "MUTATING_OPERATION_DEADLINE_TIMEOUT",
            result["extensions"]["deadlineProof"]["timeoutCode"],
        )
        self.assertNotIn("busyProof", result["extensions"])

    def test_public_outstanding_cleanup_error_has_stable_code_and_closed_extension(
        self,
    ) -> None:
        error = (
            self.installer.operation_process_group_supervisor_v2.
            OutstandingProcessCleanupObligationV2(
                (
                    "transient-" + "b" * 32,
                    "transient-" + "a" * 32,
                    "transient-" + "b" * 32,
                )
            )
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                self.installer,
                "execute_installer_invocation_v2",
                side_effect=error,
            ),
            redirect_stdout(output),
        ):
            exit_code = self.installer.main(["--apply", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(2, exit_code)
        self.assertEqual(
            "OUTSTANDING_PROCESS_CLEANUP_OBLIGATION",
            result["problems"][0]["code"],
        )
        self.assertEqual(
            "OUTSTANDING_PROCESS_CLEANUP_OBLIGATION",
            result["extensions"]["error"]["code"],
        )
        cleanup_required = result["extensions"]["cleanupRequired"]
        self.assertEqual(
            {"obligationIds", "cleanupObligation"},
            set(cleanup_required),
        )
        self.assertEqual(
            [
                "transient-" + "a" * 32,
                "transient-" + "b" * 32,
            ],
            cleanup_required["obligationIds"],
        )
        self.assertIsNone(cleanup_required["cleanupObligation"])

    def test_public_durable_outstanding_error_has_closed_cleanup_extension(
        self,
    ) -> None:
        error = OutstandingDurableProcessOwnershipV2(
            (
                "transient-" + "b" * 32,
                "transient-" + "a" * 32,
                "transient-" + "b" * 32,
            )
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                self.installer,
                "execute_installer_invocation_v2",
                side_effect=error,
            ),
            redirect_stdout(output),
        ):
            exit_code = self.installer.main(["--apply", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(2, exit_code)
        self.assertEqual(
            "DURABLE_PROCESS_OWNERSHIP_OUTSTANDING",
            result["problems"][0]["code"],
        )
        self.assertEqual(
            "DURABLE_PROCESS_OWNERSHIP_OUTSTANDING",
            result["extensions"]["error"]["code"],
        )
        cleanup_required = result["extensions"]["cleanupRequired"]
        self.assertEqual(
            {"obligationIds", "cleanupObligation"},
            set(cleanup_required),
        )
        self.assertEqual(
            [
                "transient-" + "a" * 32,
                "transient-" + "b" * 32,
            ],
            cleanup_required["obligationIds"],
        )
        self.assertIsNone(cleanup_required["cleanupObligation"])

    def test_public_durable_callback_error_exposes_validated_cleanup_obligation(
        self,
    ) -> None:
        lease_id = "transient-" + "c" * 32
        obligation = _cleanup_obligation("transient-" + "e" * 32)
        error = (
            self.installer.operation_process_group_supervisor_v2.
            DurableProcessOwnershipCallbackErrorV2(
                lease_id=lease_id,
                outcome="cleanup-required",
                cleanup_obligation=obligation,
            )
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                self.installer,
                "execute_installer_invocation_v2",
                side_effect=error,
            ),
            redirect_stdout(output),
        ):
            exit_code = self.installer.main(["--apply", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(2, exit_code)
        self.assertEqual(
            "DURABLE_PROCESS_OWNERSHIP_CALLBACK_FAILED",
            result["problems"][0]["code"],
        )
        self.assertEqual(
            "DURABLE_PROCESS_OWNERSHIP_CALLBACK_FAILED",
            result["extensions"]["error"]["code"],
        )
        cleanup_required = result["extensions"]["cleanupRequired"]
        self.assertEqual(
            {"obligationIds", "cleanupObligation"},
            set(cleanup_required),
        )
        self.assertEqual(
            [lease_id, obligation["obligationId"]],
            cleanup_required["obligationIds"],
        )
        self.assertEqual(
            obligation,
            cleanup_required["cleanupObligation"],
        )

    def test_public_supervised_cleanup_error_derives_id_from_validated_obligation(
        self,
    ) -> None:
        obligation = _cleanup_obligation("transient-" + "d" * 32)
        supervisor = (
            self.installer.operation_process_group_supervisor_v2.
            OperationProcessGroupSupervisorV2()
        )
        error = self.installer.supervised_subprocess_v2.SupervisedCommandCleanupRequiredV2(
            cleanup_obligation=obligation,
            supervisor=supervisor,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                self.installer,
                "execute_installer_invocation_v2",
                side_effect=error,
            ),
            redirect_stdout(output),
        ):
            exit_code = self.installer.main(["--apply", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(2, exit_code)
        self.assertEqual(
            "SUPERVISED_COMMAND_CLEANUP_REQUIRED",
            result["problems"][0]["code"],
        )
        self.assertEqual(
            "SUPERVISED_COMMAND_CLEANUP_REQUIRED",
            result["extensions"]["error"]["code"],
        )
        cleanup_required = result["extensions"]["cleanupRequired"]
        self.assertEqual(
            {"obligationIds", "cleanupObligation"},
            set(cleanup_required),
        )
        self.assertEqual(
            [obligation["obligationId"]],
            cleanup_required["obligationIds"],
        )
        self.assertEqual(
            obligation,
            cleanup_required["cleanupObligation"],
        )

    def test_explicitly_wrapped_deadline_is_recovered_at_public_boundary(
        self,
    ) -> None:
        deadline_error = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="operation",
            deadline_kind="operation",
            configured_timeout_nanoseconds=600_000_000_000,
            elapsed_monotonic_nanoseconds=600_000_000_001,
        )

        def wrapped_failure(*_args, **_kwargs):
            try:
                raise deadline_error
            except OperationDeadlineExceededV2 as cause:
                raise RuntimeError("обёртка отката") from cause

        with mock.patch.object(
            self.installer,
            "_execute_installer_invocation_with_lock_budget_v2",
            side_effect=wrapped_failure,
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as captured:
                self.installer.execute_installer_invocation_v2(
                    _invocation("apply", execute=True)
                )

        self.assertIs(deadline_error, captured.exception)

    def test_outstanding_cleanup_has_priority_over_nested_deadline(self) -> None:
        deadline_error = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="operation",
            deadline_kind="operation",
            configured_timeout_nanoseconds=600_000_000_000,
            elapsed_monotonic_nanoseconds=600_000_000_001,
        )
        outstanding = OutstandingDurableProcessOwnershipV2(
            ("transient-" + "a" * 32,)
        )

        def cleanup_failure(*_args, **_kwargs):
            try:
                raise deadline_error
            except OperationDeadlineExceededV2 as cause:
                raise outstanding from cause

        with mock.patch.object(
            self.installer,
            "_execute_installer_invocation_with_lock_budget_v2",
            side_effect=cleanup_failure,
        ):
            with self.assertRaises(
                OutstandingDurableProcessOwnershipV2
            ) as captured:
                self.installer.execute_installer_invocation_v2(
                    _invocation("apply", execute=True)
                )

        self.assertIs(outstanding, captured.exception)

    def test_real_public_mutation_configures_callbacks_without_success_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="installer-durable-callbacks-v2-"
        ) as temporary:
            root = Path(temporary).resolve()
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            invocation = InstallerInvocationV2(
                command="apply",
                execute=True,
                json=True,
                source_root=str(ROOT),
                codex_home=str(codex_home),
                bin_dir=str(root / "bin"),
                state_home=str(root / "state"),
                codex_binary=sys.executable,
                retain_data=False,
            )
            observed: list[object] = []

            def execute_without_budget(_invocation, **_kwargs):
                observed.append(current_process_group_supervisor_v2())
                return {"status": "ok"}

            with mock.patch.object(
                self.installer,
                "_execute_installer_invocation_without_lock_budget_v2",
                side_effect=execute_without_budget,
            ):
                result = (
                    self.installer.
                    execute_installer_invocation_v2(invocation)
                )

            self.assertEqual({"status": "ok"}, result)
            self.assertEqual(1, len(observed))
            supervisor = observed[0]
            self.assertTrue(callable(supervisor._ownership_publisher))
            self.assertTrue(callable(supervisor._ownership_transition))
            self.assertFalse(ownership_directory_path_v2(codex_home).exists())

    def test_ordinary_mutation_is_blocked_before_work_by_durable_record(self) -> None:
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="installer-durable-preflight-v2-"
        ) as temporary:
            root = Path(temporary).resolve()
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            store = DurableProcessOwnershipStoreV2(codex_home)
            lease = TransientProcessLeaseV2(
                lease_id="transient-" + "b" * 32,
                label="candidate-controller",
                pid=8111,
                process_group_id=8111,
                session_id=8111,
                process_start_marker="preflight-marker",
                process=object(),
            )
            store.publish(
                lease,
                {
                    "schemaVersion": 2,
                    "contextKind": "candidate-dispatch-v2",
                    "operationId": "op2_" + "1" * 32,
                    "candidateId": "cand2_" + "2" * 32,
                    "controllerStartId": "cs2_" + "3" * 32,
                    "actionFingerprint": "4" * 64,
                    "dispatchReceiptFingerprint": "5" * 64,
                },
            )
            invocation = InstallerInvocationV2(
                command="apply",
                execute=True,
                json=True,
                source_root=str(ROOT),
                codex_home=str(codex_home),
                bin_dir=str(root / "bin"),
                state_home=str(root / "state"),
                codex_binary=sys.executable,
                retain_data=False,
            )

            with (
                mock.patch.object(
                    self.installer,
                    "_execute_installer_invocation_without_lock_budget_v2",
                ) as execute,
                self.assertRaises(OutstandingDurableProcessOwnershipV2),
            ):
                self.installer._execute_installer_invocation_with_lock_budget_v2(
                    invocation
                )

            execute.assert_not_called()

    def test_recover_apply_resolves_proven_absent_candidate_without_signal(
        self,
    ) -> None:
        """Исчезнувшая точная группа не требует сигнала."""

        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="installer-durable-unknown-accept-v2-"
        ) as temporary:
            root = Path(temporary).resolve()
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            store = DurableProcessOwnershipStoreV2(codex_home)
            lease = TransientProcessLeaseV2(
                lease_id="transient-" + "c" * 32,
                label="candidate-controller",
                pid=8222,
                process_group_id=8222,
                session_id=8222,
                process_start_marker="accepted-before-release-marker",
                process=object(),
            )
            store.publish(
                lease,
                {
                    "schemaVersion": 2,
                    "contextKind": "candidate-dispatch-v2",
                    "operationId": "op2_" + "1" * 32,
                    "candidateId": "cand2_" + "2" * 32,
                    "controllerStartId": "cs2_" + "3" * 32,
                    "actionFingerprint": "4" * 64,
                    "dispatchReceiptFingerprint": "5" * 64,
                },
            )
            public_result = self.installer.build_lifecycle_command_result_v2(
                command="recover",
                status="recovered",
                readiness="READY",
                operation_id="op2_" + "6" * 32,
                attempt_id="opa2_" + "7" * 32,
            )
            output = io.StringIO()

            with (
                mock.patch.object(
                    self.installer,
                    "_execute_installer_invocation_without_lock_budget_v2",
                    return_value=public_result,
                ),
                mock.patch(
                    "codex_smart_subagents.durable_process_ownership_v2."
                    "_default_identity_reader",
                    return_value=None,
                ) as identity_reader,
                mock.patch(
                    "codex_smart_subagents.durable_process_ownership_v2."
                    "_default_group_exists",
                    return_value=False,
                ) as group_exists,
                mock.patch("os.killpg") as killpg,
                redirect_stdout(output),
            ):
                code = self.installer.main(
                    [
                        "--recover",
                        "--apply",
                        "--json",
                        "--source-root",
                        str(ROOT),
                        "--codex-home",
                        str(codex_home),
                        "--bin-dir",
                        str(root / "bin"),
                        "--state-home",
                        str(root / "state"),
                        "--codex-binary",
                        sys.executable,
                    ]
                )

            self.assertEqual(0, code)
            self.assertEqual(public_result, json.loads(output.getvalue()))
            identity_reader.assert_called_once_with(lease.pid)
            group_exists.assert_called_once_with(lease.process_group_id)
            killpg.assert_not_called()
            self.assertEqual((), store.load_all())

    def test_publication_failure_proves_spawned_group_exit_before_scope_loss(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="installer-publish-failure-v2-"
        ) as temporary:
            root = Path(temporary).resolve()
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            invocation = InstallerInvocationV2(
                command="apply",
                execute=True,
                json=True,
                source_root=str(ROOT),
                codex_home=str(codex_home),
                bin_dir=str(root / "bin"),
                state_home=str(root / "state"),
                codex_binary=sys.executable,
                retain_data=False,
            )
            spawned_pid: list[int] = []

            def publish_failure(lease, _context):
                spawned_pid.append(lease.pid)
                raise DurableProcessOwnershipV2Error(
                    "DURABLE_OWNERSHIP_IO_FAILED",
                    "искусственный отказ публикации",
                )

            def execute_without_budget(_invocation, **_kwargs):
                supervisor = current_process_group_supervisor_v2()
                assert supervisor is not None
                supervisor.spawn_transient(
                    label="publisher-failure-probe",
                    argv=(
                        sys.executable,
                        "-c",
                        "import time; time.sleep(60)",
                    ),
                )
                self.fail("spawn must raise when durable publication fails")

            with (
                mock.patch.object(
                    self.installer.DurableProcessOwnershipStoreV2,
                    "publish",
                    side_effect=publish_failure,
                ),
                mock.patch.object(
                    self.installer,
                    "_execute_installer_invocation_without_lock_budget_v2",
                    side_effect=execute_without_budget,
                ),
                self.assertRaises(
                    self.installer.operation_process_group_supervisor_v2.
                    DurableProcessOwnershipCallbackErrorV2
                ),
            ):
                self.installer._execute_installer_invocation_with_lock_budget_v2(
                    invocation
                )

            self.assertGreaterEqual(len(spawned_pid), 1)
            pid = spawned_pid[0]
            with self.assertRaises(ProcessLookupError):
                os.getpgid(pid)
            self.assertFalse(ownership_directory_path_v2(codex_home).exists())


class OperationDeadlineFileLockIntegrationV2Tests(unittest.TestCase):
    def test_earlier_operation_deadline_wins_as_software_timeout(self) -> None:
        operation_clock = _NanosecondClock()
        lock_time = [0.0]
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.1,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=operation_clock,
        )

        def busy(_descriptor: int, _operation: int) -> None:
            raise OSError(errno.EWOULDBLOCK, "busy")

        def sleep(seconds: float) -> None:
            lock_time[0] += seconds
            operation_clock.value += int(seconds * 1_000_000_000)

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(OperationDeadlineExceededV2) as captured:
                finite_file_lock_v2.acquire_flock_v2(
                    1,
                    exclusive=True,
                    timeout_seconds=30.0,
                    timeout_code="INSTALLATION_LOCK_TIMEOUT",
                    poll_interval_seconds=0.05,
                    monotonic=lambda: lock_time[0],
                    sleep=sleep,
                    flock=busy,
                )

        self.assertEqual(
            "MUTATING_OPERATION_DEADLINE_TIMEOUT", captured.exception.code
        )

    def test_earlier_local_lock_timeout_remains_proven_busy(self) -> None:
        operation_clock = _NanosecondClock()
        lock_time = [0.0]
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=operation_clock,
        )

        def busy(_descriptor: int, _operation: int) -> None:
            raise OSError(errno.EWOULDBLOCK, "busy")

        def sleep(seconds: float) -> None:
            lock_time[0] += seconds
            operation_clock.value += int(seconds * 1_000_000_000)

        with scoped_current_deadline_v2(deadline):
            with self.assertRaises(
                finite_file_lock_v2.FileLockTimeoutV2
            ) as captured:
                finite_file_lock_v2.acquire_flock_v2(
                    1,
                    exclusive=True,
                    timeout_seconds=0.1,
                    timeout_code="INSTALLATION_LOCK_TIMEOUT",
                    poll_interval_seconds=0.05,
                    monotonic=lambda: lock_time[0],
                    sleep=sleep,
                    flock=busy,
                )

        self.assertEqual("INSTALLATION_LOCK_TIMEOUT", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
