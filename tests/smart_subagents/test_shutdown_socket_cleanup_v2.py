from __future__ import annotations

import copy
import fcntl
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.controller_transition_rehydration_v2 import (  # noqa: E402
    ControllerShutdownCommandIdsV2,
    rehydrate_controller_shutdown_proof_v2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
    build_lifecycle_controller_request_v2,
)
from codex_smart_subagents.shutdown_socket_cleanup_v2 import (  # noqa: E402
    ShutdownSocketCleanupV2Error,
    apply_shutdown_socket_cleanup_v2,
    build_shutdown_socket_cleanup_plan_v2,
    observe_shutdown_socket_cleanup_v2,
    prove_shutdown_socket_orphan_v2,
    wait_for_shutdown_socket_orphan_v2,
)
from codex_smart_subagents.state_store_v2 import SmartStoreV2  # noqa: E402
from tests.smart_subagents.test_state_store_v2 import (  # noqa: E402
    controller,
    database_identity,
)
from tests.smart_subagents.test_activation_transition_v2 import (  # noqa: E402
    _operation_step_validator,
)


NOW = datetime(2026, 7, 19, 18, 0, 0, tzinfo=timezone.utc)
INSTALLATION_ID = "ins2_" + "1" * 32
OPERATION_ID = "op2_" + "2" * 32
ACTIVATION_PROOF_FINGERPRINT = "a" * 64


class ShutdownSocketCleanupV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.step_validator = _operation_step_validator()
        cls.lifecycle_vectors = json.loads(
            (ROOT / "docs/contracts/vectors/lifecycle-v2.json").read_text(
                encoding="utf-8"
            )
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cssc2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.database_path = self.state_home / "controller.sqlite3"
        self.lock_path = self.state_home / "controller.lock"
        self.lock_path.write_bytes(b"")
        self.lock_path.chmod(0o600)
        self.socket_path = self.state_home / "controller.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        marker = system_process_start_marker_v2(self.process.pid)
        identity = replace(
            database_identity(),
            activation_id="act2_" + database_identity().activation_fingerprint,
        )
        socket_info = self.socket_path.lstat()
        self.initial_controller = replace(
            controller(),
            controller_pid=self.process.pid,
            controller_process_start_marker=marker,
            controller_process_group_id=os.getpgid(self.process.pid),
            socket_path=str(self.socket_path),
            socket_device=socket_info.st_dev,
            socket_inode=socket_info.st_ino,
            socket_owner_uid=socket_info.st_uid,
            socket_owner_gid=socket_info.st_gid,
            activation_id=identity.activation_id,
            updated_at=NOW,
        )
        store = SmartStoreV2(
            self.database_path,
            database_identity=identity,
            controller=self.initial_controller,
        )
        store.close()
        self.protocol = LifecycleControllerProtocolV2(
            database_path=self.database_path,
            codex_home=self.codex_home,
            controller_lock_path=self.lock_path,
            clock=lambda: NOW,
        )
        self.command_ids = ControllerShutdownCommandIdsV2(
            maintenance_begin="cc2_" + "3" * 32,
            maintenance_strengthen="cc2_" + "4" * 32,
            shutdown="cc2_" + "5" * 32,
        )
        self.plan = build_shutdown_socket_cleanup_plan_v2(
            installation_id=INSTALLATION_ID,
            activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
            operation_id=OPERATION_ID,
            shutdown_command_id=self.command_ids.shutdown,
            state_home=self.state_home,
            controller_state=asdict(self.initial_controller),
        )
        self.shutdown = self._shutdown()

    def tearDown(self) -> None:
        self.listener.close()
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.temporary.cleanup()

    def _request(
        self,
        method: str,
        *,
        epoch: int,
        command_id: str,
        params: dict[str, object],
    ) -> dict[str, object]:
        return build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method=method,
            controller_identity=self.initial_controller.controller_identity,
            instance_id=self.initial_controller.instance_id,
            controller_start_id=self.initial_controller.controller_start_id,
            command_id=command_id,
            expected_control_epoch=epoch,
            operation_id=OPERATION_ID,
            params=params,
        )

    def _shutdown(self):
        begun = self.protocol.handle(
            self._request(
                "maintenance_begin",
                epoch=self.initial_controller.control_epoch,
                command_id=self.command_ids.maintenance_begin,
                params={"reasonCode": "UPGRADE"},
            )
        )
        strengthened = self.protocol.handle(
            self._request(
                "maintenance_strengthen",
                epoch=int(begun["controlEpoch"]),
                command_id=self.command_ids.maintenance_strengthen,
                params={"mode": "freeze"},
            )
        )
        self.protocol.handle(
            self._request(
                "shutdown",
                epoch=int(strengthened["controlEpoch"]),
                command_id=self.command_ids.shutdown,
                params={},
            )
        )
        return rehydrate_controller_shutdown_proof_v2(
            database_path=self.database_path,
            activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
            operation_id=OPERATION_ID,
            command_ids=self.command_ids,
        )

    def _stop_process(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.listener.close()

    def test_plan_contains_only_preknown_inputs_and_parent_binding(self) -> None:
        self.assertTrue(self.plan.complete)
        self.assertEqual(self.command_ids.shutdown, self.plan.action["proofSourceId"])
        self.assertIn("socketParentDevice", self.plan.action)
        self.assertIn("socketParentInode", self.plan.action)
        self.assertNotIn("processExitProofFingerprint", self.plan.action)
        self.assertNotIn("exclusiveLockProofFingerprint", self.plan.action)
        step = copy.deepcopy(
            self.lifecycle_vectors["fixtures"]["shutdownSocketCleanupStep"]
        )
        step["action"] = copy.deepcopy(dict(self.plan.action))
        errors = list(self.step_validator.iter_errors(step))
        self.assertEqual([], errors, errors[0].message if errors else "")

    def test_active_original_process_blocks_orphan_proof(self) -> None:
        with self.assertRaises(ShutdownSocketCleanupV2Error) as raised:
            prove_shutdown_socket_orphan_v2(plan=self.plan, shutdown=self.shutdown)

        self.assertEqual("SHUTDOWN_PROCESS_STILL_ACTIVE", raised.exception.code)

    def test_waiter_retries_only_transient_shutdown_completion_states(self) -> None:
        calls: list[str] = []
        sleeps: list[float] = []
        expected = object()

        def orphan_prover(**_arguments):
            calls.append("prove")
            if len(calls) == 1:
                raise ShutdownSocketCleanupV2Error(
                    "SHUTDOWN_PROCESS_STILL_ACTIVE",
                    "процесс завершает работу",
                )
            if len(calls) == 2:
                raise ShutdownSocketCleanupV2Error(
                    "SHUTDOWN_LOCK_NOT_EXCLUSIVE",
                    "блокировка ещё освобождается",
                )
            return expected

        observed = wait_for_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
            timeout_seconds=1.0,
            poll_interval_seconds=0.01,
            orphan_prover=orphan_prover,
            monotonic=lambda: 0.0,
            sleeper=sleeps.append,
        )

        self.assertIs(expected, observed)
        self.assertEqual(["prove", "prove", "prove"], calls)
        self.assertEqual([0.01, 0.01], sleeps)

    def test_waiter_does_not_retry_a_changed_socket(self) -> None:
        calls = 0

        def orphan_prover(**_arguments):
            nonlocal calls
            calls += 1
            raise ShutdownSocketCleanupV2Error(
                "SHUTDOWN_SOCKET_CHANGED",
                "сокет заменён",
            )

        with self.assertRaises(ShutdownSocketCleanupV2Error) as raised:
            wait_for_shutdown_socket_orphan_v2(
                plan=self.plan,
                shutdown=self.shutdown,
                timeout_seconds=1.0,
                orphan_prover=orphan_prover,
                monotonic=lambda: 0.0,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual("SHUTDOWN_SOCKET_CHANGED", raised.exception.code)
        self.assertEqual(1, calls)

    def test_waiter_stops_exactly_at_the_completion_deadline(self) -> None:
        calls = 0
        sleeps: list[float] = []
        clock = iter((0.0, 0.5, 1.0))

        def orphan_prover(**_arguments):
            nonlocal calls
            calls += 1
            raise ShutdownSocketCleanupV2Error(
                "SHUTDOWN_PROCESS_STILL_ACTIVE",
                "процесс ещё работает",
            )

        with self.assertRaises(ShutdownSocketCleanupV2Error) as raised:
            wait_for_shutdown_socket_orphan_v2(
                plan=self.plan,
                shutdown=self.shutdown,
                timeout_seconds=1.0,
                poll_interval_seconds=0.01,
                orphan_prover=orphan_prover,
                monotonic=lambda: next(clock),
                sleeper=sleeps.append,
            )

        self.assertEqual("SHUTDOWN_COMPLETION_TIMEOUT", raised.exception.code)
        self.assertEqual(2, calls)
        self.assertEqual([0.01], sleeps)

    def test_reused_pid_marker_is_accepted_without_signalling_process(self) -> None:
        reused = prove_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
            process_start_marker_provider=lambda _pid: "different-process-marker",
        )
        self._stop_process()
        absent = prove_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )

        self.assertTrue(reused.complete)
        self.assertEqual(
            reused.process_exit_proof_fingerprint,
            absent.process_exit_proof_fingerprint,
        )

    def test_cleanup_is_idempotent_and_returns_stable_actual_absence(self) -> None:
        self._stop_process()
        before = observe_shutdown_socket_cleanup_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )
        orphan = prove_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )

        first = apply_shutdown_socket_cleanup_v2(
            plan=self.plan,
            shutdown=self.shutdown,
            orphan=orphan,
        )
        second_orphan = prove_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )
        second = apply_shutdown_socket_cleanup_v2(
            plan=self.plan,
            shutdown=self.shutdown,
            orphan=second_orphan,
        )
        after = observe_shutdown_socket_cleanup_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )

        self.assertEqual("BEFORE", before.state.value)
        self.assertEqual("AFTER", after.state.value)
        self.assertFalse(os.path.lexists(self.socket_path))
        self.assertEqual(first.absence_projection, second.absence_projection)
        self.assertEqual(first.absence_projection, after.absence_projection)
        step = copy.deepcopy(
            self.lifecycle_vectors["fixtures"]["shutdownSocketCleanupStep"]
        )
        step["action"] = copy.deepcopy(dict(self.plan.action))
        step["observedAfter"] = first.absence_projection.to_document()
        errors = list(self.step_validator.iter_errors(step))
        self.assertEqual([], errors, errors[0].message if errors else "")
        self.assertEqual(
            orphan.process_exit_proof_fingerprint,
            second_orphan.process_exit_proof_fingerprint,
        )
        self.assertEqual(
            orphan.exclusive_lock_proof_fingerprint,
            second_orphan.exclusive_lock_proof_fingerprint,
        )

    def test_exclusive_lock_is_required(self) -> None:
        self._stop_process()
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

        with self.assertRaises(ShutdownSocketCleanupV2Error) as raised:
            prove_shutdown_socket_orphan_v2(plan=self.plan, shutdown=self.shutdown)

        self.assertEqual("SHUTDOWN_LOCK_NOT_EXCLUSIVE", raised.exception.code)

    def test_replaced_socket_is_rejected_without_unlink(self) -> None:
        self._stop_process()
        self.socket_path.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(replacement.close)
        replacement.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        orphan = prove_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )

        with self.assertRaises(ShutdownSocketCleanupV2Error) as raised:
            apply_shutdown_socket_cleanup_v2(
                plan=self.plan,
                shutdown=self.shutdown,
                orphan=orphan,
            )

        self.assertEqual("SHUTDOWN_SOCKET_CHANGED", raised.exception.code)
        self.assertTrue(os.path.lexists(self.socket_path))

    def test_replaced_parent_is_rejected_after_already_completed_unlink(self) -> None:
        self._stop_process()
        orphan = prove_shutdown_socket_orphan_v2(
            plan=self.plan,
            shutdown=self.shutdown,
        )
        apply_shutdown_socket_cleanup_v2(
            plan=self.plan,
            shutdown=self.shutdown,
            orphan=orphan,
        )
        original = self.state_home.with_name(self.state_home.name + "-original")
        self.state_home.rename(original)
        self.state_home.mkdir(mode=0o700)
        self.lock_path.write_bytes(b"")
        self.lock_path.chmod(0o600)

        with self.assertRaises(ShutdownSocketCleanupV2Error) as raised:
            prove_shutdown_socket_orphan_v2(plan=self.plan, shutdown=self.shutdown)

        self.assertEqual("SHUTDOWN_SOCKET_PARENT_CHANGED", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
