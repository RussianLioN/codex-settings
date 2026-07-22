from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.canonical_json import canonical_json_bytes  # noqa: E402
from codex_smart_subagents.controller_transition_rehydration_v2 import (  # noqa: E402
    ControllerShutdownCommandIdsV2,
    ControllerTransitionRehydrationV2Error,
    rehydrate_candidate_acceptance_proof_v2,
    rehydrate_controller_command_v2,
    rehydrate_controller_shutdown_proof_v2,
)
from codex_smart_subagents import controller_transition_rehydration_v2  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)
from codex_smart_subagents.sqlite_deadline_v2 import (  # noqa: E402
    DeadlineAwareConnectionV2,
)
from codex_smart_subagents.schema_projection import APPLICATION_ID  # noqa: E402
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
    LifecycleControllerProtocolV2Error,
    build_lifecycle_controller_request_v2,
)
from codex_smart_subagents.state_store_v2 import SmartStoreV2  # noqa: E402
from tests.smart_subagents.test_state_store_v2 import (  # noqa: E402
    controller,
    database_identity,
)


NOW = datetime(2026, 7, 19, 17, 0, 0, tzinfo=timezone.utc)
OPERATION_ID = "op2_" + "1" * 32
ACTIVATION_PROOF_FINGERPRINT = "a" * 64


class ControllerTransitionRehydrationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="csctr2-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.database_path = self.state_home / "databases" / "current.sqlite3"
        self.socket_path = self.state_home / "controller.sock"
        self.lock_path = self.state_home / "controller.lock"
        self.lock_path.write_bytes(b"")
        self.lock_path.chmod(0o600)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        socket_info = self.socket_path.lstat()
        self.identity = replace(
            database_identity(),
            activation_id="act2_" + database_identity().activation_fingerprint,
        )
        self.initial_controller = replace(
            controller(),
            controller_pid=os.getpid(),
            controller_process_start_marker=system_process_start_marker_v2(
                os.getpid()
            ),
            controller_process_group_id=os.getpgrp(),
            socket_path=str(self.socket_path),
            socket_device=socket_info.st_dev,
            socket_inode=socket_info.st_ino,
            socket_owner_uid=socket_info.st_uid,
            socket_owner_gid=socket_info.st_gid,
            activation_id=self.identity.activation_id,
            updated_at=NOW,
        )
        store = SmartStoreV2(
            self.database_path,
            database_identity=self.identity,
            controller=self.initial_controller,
        )
        store.close()
        self.protocol = LifecycleControllerProtocolV2(
            database_path=self.database_path,
            codex_home=self.codex_home,
            controller_lock_path=self.lock_path,
            clock=lambda: NOW,
        )
        self.shutdown_ids = ControllerShutdownCommandIdsV2(
            maintenance_begin="cc2_" + "a" * 32,
            maintenance_strengthen="cc2_" + "b" * 32,
            shutdown="cc2_" + "c" * 32,
        )

    def test_cleanup_failure_does_not_mask_primary_deadline(self) -> None:
        database = self.root / "cleanup-primary.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.execute("pragma user_version=2")
        finally:
            connection.close()
        database.chmod(0o600)
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="recover",
            phase="read-database",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )

        with mock.patch.object(
            DeadlineAwareConnectionV2,
            "rollback_for_cleanup_v2",
            side_effect=RuntimeError("cleanup failed"),
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                with controller_transition_rehydration_v2._read_exact_database(
                    database
                ):
                    raise original

        self.assertIs(original, caught.exception)
        self.assertTrue(
            any(
                "cleanup failed" in note
                for note in getattr(original, "__notes__", ())
            )
        )

    def test_close_failure_does_not_mask_primary_deadline(self) -> None:
        database = self.root / "close-primary.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.execute("pragma user_version=2")
        finally:
            connection.close()
        database.chmod(0o600)
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="recover",
            phase="read-database",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )

        def close_then_fail(value: DeadlineAwareConnectionV2) -> None:
            sqlite3.Connection.close(value)
            raise RuntimeError("close failed")

        with mock.patch.object(
            DeadlineAwareConnectionV2,
            "close",
            new=close_then_fail,
        ):
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                with controller_transition_rehydration_v2._read_exact_database(
                    database
                ):
                    raise original

        self.assertIs(original, caught.exception)
        self.assertTrue(
            any(
                "close failed" in note
                for note in getattr(original, "__notes__", ())
            )
        )

    def test_close_failure_after_successful_read_is_not_suppressed(self) -> None:
        database = self.root / "close-only.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.execute("pragma user_version=2")
        finally:
            connection.close()
        database.chmod(0o600)
        close_error = RuntimeError("close failed")

        def close_then_fail(value: DeadlineAwareConnectionV2) -> None:
            sqlite3.Connection.close(value)
            raise close_error

        with mock.patch.object(
            DeadlineAwareConnectionV2,
            "close",
            new=close_then_fail,
        ):
            with self.assertRaises(RuntimeError) as caught:
                with controller_transition_rehydration_v2._read_exact_database(
                    database
                ):
                    pass

        self.assertIs(close_error, caught.exception)

    def tearDown(self) -> None:
        self.listener.close()
        self.temporary.cleanup()

    def _request(
        self,
        method: str,
        *,
        epoch: int,
        command_id: str,
        params: dict[str, object] | None = None,
        instance_id: str | None | object = ...,
        controller_start_id: str | None | object = ...,
    ) -> dict[str, object]:
        return build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method=method,
            controller_identity=self.initial_controller.controller_identity,
            instance_id=(
                self.initial_controller.instance_id
                if instance_id is ...
                else instance_id
            ),
            controller_start_id=(
                self.initial_controller.controller_start_id
                if controller_start_id is ...
                else controller_start_id
            ),
            command_id=command_id,
            expected_control_epoch=epoch,
            operation_id=OPERATION_ID,
            params={} if params is None else params,
        )

    def _enter_shutdown(self) -> None:
        begun = self.protocol.handle(
            self._request(
                "maintenance_begin",
                epoch=7,
                command_id=self.shutdown_ids.maintenance_begin,
                params={"reasonCode": "UPGRADE"},
            )
        )
        strengthened = self.protocol.handle(
            self._request(
                "maintenance_strengthen",
                epoch=int(begun["controlEpoch"]),
                command_id=self.shutdown_ids.maintenance_strengthen,
                params={"mode": "freeze"},
            )
        )
        self.protocol.handle(
            self._request(
                "shutdown",
                epoch=int(strengthened["controlEpoch"]),
                command_id=self.shutdown_ids.shutdown,
            )
        )

    def _rehydrate_shutdown(self):
        return rehydrate_controller_shutdown_proof_v2(
            database_path=self.database_path,
            activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
            operation_id=OPERATION_ID,
            command_ids=self.shutdown_ids,
        )

    def _prepare_candidate_database(self) -> tuple[Path, Path, socket.socket]:
        candidate_home = self.root / "candidate-codex-home"
        candidate_home.mkdir(mode=0o700)
        state_home = candidate_home / "state" / "codex-smart-subagents-v2"
        state_home.mkdir(parents=True, mode=0o700)
        database_path = state_home / "databases" / "candidate.sqlite3"
        socket_path = state_home / "controller.sock"
        lock_path = state_home / "controller.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        store = SmartStoreV2(
            database_path,
            database_identity=self.identity,
            controller=replace(
                controller(),
                controller_pid=os.getpid(),
                controller_process_start_marker=system_process_start_marker_v2(
                    os.getpid()
                ),
                controller_process_group_id=os.getpgrp(),
                socket_path=str(socket_path),
                socket_device=socket_path.lstat().st_dev,
                socket_inode=socket_path.lstat().st_ino,
                socket_owner_uid=os.getuid(),
                socket_owner_gid=os.getgid(),
                activation_id=self.identity.activation_id,
                control_epoch=1,
                updated_at=NOW,
            ),
        )
        store.close()
        with closing(sqlite3.connect(database_path)) as connection:
            connection.execute(
                "update controller_state set state='MAINTENANCE',"
                "maintenance_mode='FREEZE',reason_code='AWAITING_CONTROLLER_ACCEPT',"
                "operation_id=?,instance_id=null,controller_start_id=null,"
                "controller_pid=null,controller_process_start_marker=null,"
                "controller_process_group_id=null,socket_path=null,socket_device=null,"
                "socket_inode=null,socket_owner_uid=null,socket_owner_gid=null,"
                "socket_mode=null,lock_held=0,accepting_new_routes=0,quiescent=1 "
                "where singleton=1",
                (OPERATION_ID,),
            )
            connection.commit()
        return database_path, lock_path, listener

    def _enter_candidate(self) -> tuple[Path, str, socket.socket, dict[str, object]]:
        database_path, lock_path, listener = self._prepare_candidate_database()
        self.addCleanup(listener.close)
        candidate_home = database_path.parents[3]
        protocol = LifecycleControllerProtocolV2(
            database_path=database_path,
            codex_home=candidate_home,
            controller_lock_path=lock_path,
            clock=lambda: NOW,
        )
        command_id = "cc2_" + "d" * 32
        accepted = protocol.handle(
            build_lifecycle_controller_request_v2(
                codex_home=candidate_home,
                shell_session_id="installer-v2",
                method="controller_accept",
                controller_identity=self.initial_controller.controller_identity,
                instance_id=None,
                controller_start_id="cs2_" + "9" * 32,
                command_id=command_id,
                expected_control_epoch=1,
                operation_id=OPERATION_ID,
                params={
                    "activationId": self.identity.activation_id,
                    "databaseId": self.identity.database_id,
                    "pid": os.getpid(),
                    "processStartMarker": system_process_start_marker_v2(
                        os.getpid()
                    ),
                    "processGroupId": os.getpgrp(),
                },
            )
        )
        return database_path, command_id, listener, accepted

    def _resume_candidate(
        self,
        *,
        database_path: Path,
        accepted: dict[str, object],
    ) -> None:
        candidate_home = database_path.parents[3]
        protocol = LifecycleControllerProtocolV2(
            database_path=database_path,
            codex_home=candidate_home,
            controller_lock_path=database_path.parents[1] / "controller.lock",
            clock=lambda: NOW,
        )
        protocol.handle(
            build_lifecycle_controller_request_v2(
                codex_home=candidate_home,
                shell_session_id="installer-v2",
                method="maintenance_resume",
                controller_identity=self.initial_controller.controller_identity,
                instance_id=str(accepted["payload"]["instanceId"]),
                controller_start_id="cs2_" + "9" * 32,
                command_id="cc2_" + "e" * 32,
                expected_control_epoch=int(accepted["controlEpoch"]),
                operation_id=OPERATION_ID,
                params={},
            )
        )

    def test_rehydrates_complete_shutdown_proof_from_exact_receipts(self) -> None:
        self._enter_shutdown()

        proof = self._rehydrate_shutdown()

        self.assertTrue(proof.complete)
        self.assertEqual(OPERATION_ID, proof.operation_id)
        self.assertTrue(proof.quiescence.quiescent)
        self.assertEqual(
            str(self.socket_path), proof.shutdown.payload["socketIntent"]["path"]
        )
        self.assertEqual(7, proof.maintenance_begin.previous_control_epoch)
        self.assertEqual(10, proof.shutdown.new_control_epoch)

    def test_rehydrates_one_historical_command_with_canonical_request(self) -> None:
        self._enter_shutdown()

        command = rehydrate_controller_command_v2(
            database_path=self.database_path,
            operation_id=OPERATION_ID,
            command_id=self.shutdown_ids.maintenance_begin,
            method="maintenance_begin",
        )

        self.assertEqual("UPGRADE", command.request["params"]["reasonCode"])
        self.assertEqual(7, command.proof.previous_control_epoch)
        self.assertEqual(8, command.proof.new_control_epoch)
        self.assertEqual(
            self.initial_controller.instance_id,
            command.row["resulting_instance_id"],
        )

    def test_protocol_persists_canonical_exact_request_with_receipt(self) -> None:
        request = self._request(
            "maintenance_begin",
            epoch=7,
            command_id=self.shutdown_ids.maintenance_begin,
            params={"reasonCode": "UPGRADE"},
        )

        self.protocol.handle(request)

        with closing(sqlite3.connect(self.database_path)) as connection:
            stored = connection.execute(
                "select request_json from controller_command_receipts "
                "where command_id=?",
                (self.shutdown_ids.maintenance_begin,),
            ).fetchone()[0]
        self.assertEqual(canonical_json_bytes(request).decode("utf-8"), stored)

    def test_protocol_replay_closes_on_noncanonical_stored_request(self) -> None:
        request = self._request(
            "maintenance_begin",
            epoch=7,
            command_id=self.shutdown_ids.maintenance_begin,
            params={"reasonCode": "UPGRADE"},
        )
        self.protocol.handle(request)
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "update controller_command_receipts set request_json=? "
                "where command_id=?",
                (
                    '{"unsafeInteger":9007199254740992}',
                    self.shutdown_ids.maintenance_begin,
                ),
            )
            connection.commit()

        with self.assertRaises(LifecycleControllerProtocolV2Error) as raised:
            self.protocol.handle(request)

        self.assertEqual("DATABASE_UNAVAILABLE", raised.exception.code)

    def test_rejects_changed_request_fingerprint(self) -> None:
        self._enter_shutdown()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "update controller_command_receipts set request_fingerprint=? "
                "where command_id=?",
                ("f" * 64, self.shutdown_ids.maintenance_strengthen),
            )
            connection.commit()

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            self._rehydrate_shutdown()

        self.assertEqual(
            "REHYDRATION_REQUEST_FINGERPRINT_MISMATCH", raised.exception.code
        )

    def test_rejects_changed_epoch_even_when_database_constraints_are_bypassed(self) -> None:
        self._enter_shutdown()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute("pragma ignore_check_constraints=ON")
            connection.execute(
                "update controller_command_receipts set before_epoch=before_epoch+1 "
                "where command_id=?",
                (self.shutdown_ids.maintenance_strengthen,),
            )
            connection.commit()

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            self._rehydrate_shutdown()

        self.assertEqual("REHYDRATION_EPOCH_MISMATCH", raised.exception.code)

    def test_rejects_changed_shutdown_socket_intent(self) -> None:
        self._enter_shutdown()
        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                "select socket_intent_json from controller_command_receipts "
                "where command_id=?",
                (self.shutdown_ids.shutdown,),
            ).fetchone()
            intent = json.loads(row[0])
            intent["inode"] += 1
            connection.execute(
                "update controller_command_receipts set socket_intent_json=? "
                "where command_id=?",
                (json.dumps(intent, sort_keys=True, separators=(",", ":")), self.shutdown_ids.shutdown),
            )
            connection.commit()

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            self._rehydrate_shutdown()

        self.assertEqual("REHYDRATION_SOCKET_INTENT_INVALID", raised.exception.code)

    def test_rejects_database_identity_not_addressed_by_activation_fingerprint(
        self,
    ) -> None:
        self._enter_shutdown()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "update database_identity set activation_fingerprint=? where singleton=1",
                ("f" * 64,),
            )
            connection.execute(
                "update controller_state set activation_fingerprint=? where singleton=1",
                ("f" * 64,),
            )
            connection.commit()

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            self._rehydrate_shutdown()

        self.assertEqual(
            "REHYDRATION_DATABASE_IDENTITY_MISMATCH", raised.exception.code
        )

    def test_rehydrates_candidate_acceptance_and_checks_exact_database_identity(
        self,
    ) -> None:
        self._enter_shutdown()
        shutdown = self._rehydrate_shutdown()
        database_path, command_id, _listener, _accepted = self._enter_candidate()

        acceptance = rehydrate_candidate_acceptance_proof_v2(
            database_path=database_path,
            activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
            shutdown_proof_fingerprint=shutdown.proof_fingerprint,
            operation_id=OPERATION_ID,
            activation_id=self.identity.activation_id,
            database_id=self.identity.database_id,
            command_id=command_id,
        )

        self.assertTrue(acceptance.complete)
        self.assertEqual(self.identity.activation_id, acceptance.activation_id)
        self.assertEqual(1, acceptance.candidate_accept.previous_control_epoch)
        self.assertEqual(2, acceptance.candidate_accept.new_control_epoch)

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            rehydrate_candidate_acceptance_proof_v2(
                database_path=database_path,
                activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
                shutdown_proof_fingerprint=shutdown.proof_fingerprint,
                operation_id=OPERATION_ID,
                activation_id=self.identity.activation_id,
                database_id="db2_" + "9" * 32,
                command_id=command_id,
            )
        self.assertEqual(
            "REHYDRATION_DATABASE_IDENTITY_MISMATCH", raised.exception.code
        )

    def test_rejects_changed_candidate_process_marker_in_request_json(self) -> None:
        self._enter_shutdown()
        shutdown = self._rehydrate_shutdown()
        database_path, command_id, _listener, _accepted = self._enter_candidate()
        with closing(sqlite3.connect(database_path)) as connection:
            row = connection.execute(
                "select request_json from controller_command_receipts "
                "where command_id=?",
                (command_id,),
            ).fetchone()
            request = json.loads(row[0])
            request["params"]["processStartMarker"] = "another-process-incarnation"
            connection.execute(
                "update controller_command_receipts set request_json=? "
                "where command_id=?",
                (canonical_json_bytes(request).decode("utf-8"), command_id),
            )
            connection.commit()

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            rehydrate_candidate_acceptance_proof_v2(
                database_path=database_path,
                activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
                shutdown_proof_fingerprint=shutdown.proof_fingerprint,
                operation_id=OPERATION_ID,
                activation_id=self.identity.activation_id,
                database_id=self.identity.database_id,
                command_id=command_id,
            )

        self.assertEqual(
            "REHYDRATION_REQUEST_FINGERPRINT_MISMATCH", raised.exception.code
        )

    def test_rehydrates_historical_acceptance_after_resume_and_socket_exit(
        self,
    ) -> None:
        self._enter_shutdown()
        shutdown = self._rehydrate_shutdown()
        database_path, command_id, listener, accepted = self._enter_candidate()
        self._resume_candidate(database_path=database_path, accepted=accepted)
        listener.close()
        socket_path = database_path.parents[1] / "controller.sock"
        socket_path.unlink()

        acceptance = rehydrate_candidate_acceptance_proof_v2(
            database_path=database_path,
            activation_proof_fingerprint=ACTIVATION_PROOF_FINGERPRINT,
            shutdown_proof_fingerprint=shutdown.proof_fingerprint,
            operation_id=OPERATION_ID,
            activation_id=self.identity.activation_id,
            database_id=self.identity.database_id,
            command_id=command_id,
        )

        self.assertTrue(acceptance.complete)
        self.assertEqual(command_id, acceptance.candidate_accept.command_id)

    def test_rehydrates_accept_and_resume_as_individual_historical_commands(
        self,
    ) -> None:
        database_path, command_id, _listener, accepted = self._enter_candidate()
        self._resume_candidate(database_path=database_path, accepted=accepted)

        accepted_command = rehydrate_controller_command_v2(
            database_path=database_path,
            operation_id=OPERATION_ID,
            command_id=command_id,
            method="controller_accept",
        )
        resumed_command = rehydrate_controller_command_v2(
            database_path=database_path,
            operation_id=OPERATION_ID,
            command_id="cc2_" + "e" * 32,
            method="maintenance_resume",
        )

        self.assertEqual(
            os.getpid(), accepted_command.request["params"]["pid"]
        )
        self.assertEqual(
            accepted_command.proof.payload["instanceId"],
            resumed_command.request["instanceId"],
        )
        self.assertEqual("MAINTENANCE_RESUMED", resumed_command.proof.status)

    def test_rejects_tampered_canonical_request_json(self) -> None:
        self._enter_shutdown()
        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                "select request_json from controller_command_receipts "
                "where command_id=?",
                (self.shutdown_ids.maintenance_begin,),
            ).fetchone()
            request = json.loads(row[0])
            request["params"]["reasonCode"] = "ROLLBACK"
            connection.execute(
                "update controller_command_receipts set request_json=? "
                "where command_id=?",
                (
                    canonical_json_bytes(request).decode("utf-8"),
                    self.shutdown_ids.maintenance_begin,
                ),
            )
            connection.commit()

        with self.assertRaises(ControllerTransitionRehydrationV2Error) as raised:
            self._rehydrate_shutdown()

        self.assertEqual(
            "REHYDRATION_REQUEST_FINGERPRINT_MISMATCH", raised.exception.code
        )


if __name__ == "__main__":
    unittest.main()
