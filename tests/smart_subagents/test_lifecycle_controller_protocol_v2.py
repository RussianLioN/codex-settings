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

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
    LifecycleControllerProtocolV2Error,
    build_lifecycle_controller_request_v2,
    build_lifecycle_controller_status_request_v2,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.state_store_v2 import SmartStoreV2  # noqa: E402
from tests.smart_subagents.test_state_store_v2 import (  # noqa: E402
    controller,
    database_identity,
)


NOW = datetime(2026, 7, 19, 15, 0, 0, tzinfo=timezone.utc)
OPERATION_ID = "op2_" + "1" * 32


class LifecycleControllerProtocolV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="cslcp2-"
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
        self.controller = replace(
            controller(),
            controller_pid=os.getpid(),
            controller_process_start_marker=system_process_start_marker_v2(os.getpid()),
            controller_process_group_id=os.getpgrp(),
            socket_path=str(self.socket_path),
            socket_device=socket_info.st_dev,
            socket_inode=socket_info.st_ino,
            socket_owner_uid=socket_info.st_uid,
            socket_owner_gid=socket_info.st_gid,
            updated_at=NOW,
        )
        store = SmartStoreV2(
            self.database_path,
            database_identity=database_identity(),
            controller=self.controller,
        )
        store.close()
        self.schema = json.loads(
            (
                ROOT
                / "docs"
                / "contracts"
                / "schemas"
                / "controller-protocol-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.validator = Draft202012Validator(self.schema)
        self.protocol = self.make_protocol()

    def tearDown(self) -> None:
        self.listener.close()
        self.temporary.cleanup()

    def make_protocol(self, *, quiescence_reader=None):
        return LifecycleControllerProtocolV2(
            database_path=self.database_path,
            codex_home=self.codex_home,
            controller_lock_path=self.lock_path,
            clock=lambda: NOW,
            quiescence_reader=quiescence_reader,
        )

    def request(
        self,
        method: str,
        *,
        epoch: int,
        command_hex: str | None,
        params: dict[str, object] | None = None,
        operation_id: str | None = OPERATION_ID,
        controller_identity: str | None = None,
        instance_id: str | None = None,
        controller_start_id: str | None = None,
    ) -> dict[str, object]:
        return build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method=method,
            controller_identity=(
                controller_identity
                if controller_identity is not None
                else self.controller.controller_identity
            ),
            instance_id=(
                instance_id if instance_id is not None else self.controller.instance_id
            ),
            controller_start_id=(
                controller_start_id
                if controller_start_id is not None
                else self.controller.controller_start_id
            ),
            command_id=(None if command_hex is None else "cc2_" + command_hex * 32),
            expected_control_epoch=epoch,
            operation_id=operation_id,
            params={} if params is None else params,
        )

    def assert_contract(self, document: dict[str, object]) -> None:
        errors = sorted(
            self.validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        self.assertEqual([], [error.message for error in errors])

    def controller_row(self) -> dict[str, object]:
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            return dict(
                connection.execute("select * from controller_state").fetchone()
            )

    def receipt_count(self) -> int:
        with closing(sqlite3.connect(self.database_path)) as connection:
            return int(
                connection.execute(
                    "select count(*) from controller_command_receipts"
                ).fetchone()[0]
            )

    def enter_shutdown_state(self) -> dict[str, object]:
        begun = self.protocol.handle(
            self.request(
                "maintenance_begin",
                epoch=7,
                command_hex="a",
                params={"reasonCode": "UPGRADE"},
            )
        )
        frozen = self.protocol.handle(
            self.request(
                "maintenance_strengthen",
                epoch=int(begun["controlEpoch"]),
                command_hex="b",
                params={"mode": "freeze"},
            )
        )
        return self.protocol.handle(
            self.request(
                "shutdown",
                epoch=int(frozen["controlEpoch"]),
                command_hex="c",
            )
        )

    def bind_candidate_socket(self) -> os.stat_result:
        self.listener.close()
        self.socket_path.unlink()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        return self.socket_path.lstat()

    def test_begin_is_durable_before_gate_closes_and_exact_replay_is_receipt(self) -> None:
        request = self.request(
            "maintenance_begin",
            epoch=7,
            command_hex="1",
            params={"reasonCode": "UPGRADE"},
        )

        first = self.protocol.handle(request)
        replayed = self.make_protocol().handle(request)

        self.assert_contract(request)
        self.assert_contract(first)
        self.assert_contract(replayed)
        self.assertEqual("SUCCESS", first["responseKind"])
        self.assertEqual("MAINTENANCE_BEGUN", first["payload"]["status"])
        self.assertEqual(8, first["controlEpoch"])
        self.assertEqual("REPLAY_RECEIPT", replayed["responseKind"])
        self.assertEqual(
            first["responseFingerprint"],
            replayed["payload"]["originalResponseFingerprint"],
        )
        self.assertEqual(
            first["controlEpoch"],
            replayed["payload"]["originalControlEpoch"],
        )
        self.assertEqual(
            first["payload"], replayed["payload"]["originalPayload"]
        )
        self.assertEqual(
            first["payload"]["commandReceipt"],
            replayed["payload"]["commandReceipt"],
        )
        self.assertEqual(1, self.receipt_count())
        row = self.controller_row()
        self.assertEqual("MAINTENANCE", row["state"])
        self.assertEqual("DRAIN", row["maintenance_mode"])
        self.assertEqual(OPERATION_ID, row["operation_id"])
        self.assertEqual(0, row["accepting_new_routes"])
        self.assertEqual(1, row["quiescent"])

    def test_same_command_id_with_changed_request_is_rejected_without_mutation(self) -> None:
        first = self.request(
            "maintenance_begin",
            epoch=7,
            command_hex="2",
            params={"reasonCode": "UPGRADE"},
        )
        self.protocol.handle(first)
        before = self.controller_row()
        changed = self.request(
            "maintenance_begin",
            epoch=7,
            command_hex="2",
            params={"reasonCode": "ROLLBACK"},
        )

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.make_protocol().handle(changed)

        self.assertEqual("COMMAND_REPLAY_CONFLICT", captured.exception.code)
        self.assertEqual(before, self.controller_row())
        self.assertEqual(1, self.receipt_count())

    def test_strengthen_requires_proven_quiescence(self) -> None:
        busy_counts = {
            "nonterminalRoutes": 1,
            "nonterminalNodes": 0,
            "activeAttempts": 0,
            "activeLeases": 0,
            "openIntents": 0,
            "inflightLaunchPermits": 0,
            "activeRuntimeArtifacts": 0,
            "pendingCandidatePublications": 0,
            "activeEvidenceJobs": 0,
            "queuedEvidenceJobs": 0,
        }
        protocol = self.make_protocol(
            quiescence_reader=lambda _connection: busy_counts
        )
        begun = protocol.handle(
            self.request(
                "maintenance_begin",
                epoch=7,
                command_hex="3",
                params={"reasonCode": "UPGRADE"},
            )
        )
        self.assertEqual("DRAINING", self.controller_row()["state"])
        before = self.controller_row()

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            protocol.handle(
                self.request(
                    "maintenance_strengthen",
                    epoch=int(begun["controlEpoch"]),
                    command_hex="4",
                    params={"mode": "freeze"},
                )
            )

        self.assertEqual("EXTERNAL_PROCESS_STILL_RUNNING", captured.exception.code)
        self.assertEqual(before, self.controller_row())
        self.assertEqual(1, self.receipt_count())

    def test_resume_reopens_routes_after_drain_timeout_with_active_work(self) -> None:
        busy_counts = {
            "nonterminalRoutes": 1,
            "nonterminalNodes": 0,
            "activeAttempts": 0,
            "activeLeases": 0,
            "openIntents": 0,
            "inflightLaunchPermits": 0,
            "activeRuntimeArtifacts": 0,
            "pendingCandidatePublications": 0,
            "activeEvidenceJobs": 0,
            "queuedEvidenceJobs": 0,
        }
        protocol = self.make_protocol(
            quiescence_reader=lambda _connection: busy_counts
        )
        begun = protocol.handle(
            self.request(
                "maintenance_begin",
                epoch=7,
                command_hex="3",
                params={"reasonCode": "UPGRADE"},
            )
        )

        resumed = protocol.handle(
            self.request(
                "maintenance_resume",
                epoch=int(begun["controlEpoch"]),
                command_hex="4",
            )
        )

        self.assert_contract(resumed)
        self.assertEqual("MAINTENANCE_RESUMED", resumed["payload"]["status"])
        self.assertEqual(9, resumed["controlEpoch"])
        row = self.controller_row()
        self.assertEqual("ACCEPTING", row["state"])
        self.assertEqual("NONE", row["maintenance_mode"])
        self.assertIsNone(row["operation_id"])
        self.assertEqual(1, row["accepting_new_routes"])
        self.assertEqual(0, row["quiescent"])
        self.assertEqual(2, self.receipt_count())

    def test_freeze_and_shutdown_publish_durable_receipts_and_socket_intent(self) -> None:
        begun = self.protocol.handle(
            self.request(
                "maintenance_begin",
                epoch=7,
                command_hex="5",
                params={"reasonCode": "UPGRADE"},
            )
        )
        frozen = self.protocol.handle(
            self.request(
                "maintenance_strengthen",
                epoch=int(begun["controlEpoch"]),
                command_hex="6",
                params={"mode": "freeze"},
            )
        )
        shutdown_request = self.request(
            "shutdown",
            epoch=int(frozen["controlEpoch"]),
            command_hex="7",
        )
        stopped = self.protocol.handle(shutdown_request)
        replayed = self.make_protocol().handle(shutdown_request)

        self.assert_contract(frozen)
        self.assert_contract(stopped)
        self.assertEqual("MAINTENANCE_STRENGTHENED", frozen["payload"]["status"])
        self.assertEqual("SHUTDOWN_COMMITTED", stopped["payload"]["status"])
        intent = stopped["payload"]["socketIntent"]
        self.assertEqual(str(self.socket_path), intent["path"])
        self.assertEqual(str(self.lock_path), intent["lockPath"])
        self.assertTrue(intent["processExitRequired"])
        self.assertTrue(intent["exclusiveLockRequired"])
        self.assertEqual(intent, replayed["payload"]["originalPayload"]["socketIntent"])
        self.assertEqual(
            stopped["responseFingerprint"],
            replayed["payload"]["originalResponseFingerprint"],
        )
        self.assertEqual(3, self.receipt_count())
        row = self.controller_row()
        self.assertEqual("MAINTENANCE", row["state"])
        self.assertEqual("FREEZE", row["maintenance_mode"])
        self.assertEqual("AWAITING_CONTROLLER_ACCEPT", row["reason_code"])
        self.assertIsNone(row["instance_id"])
        self.assertIsNone(row["socket_path"])
        self.assertEqual(0, row["lock_held"])

    def test_foreign_controller_fence_is_rejected_without_receipt(self) -> None:
        request = self.request(
            "maintenance_begin",
            epoch=7,
            command_hex="8",
            params={"reasonCode": "UPGRADE"},
            controller_identity="9" * 64,
        )

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.protocol.handle(request)

        self.assertEqual("CONTROLLER_INSTANCE_MISMATCH", captured.exception.code)
        self.assertEqual(0, self.receipt_count())
        self.assertEqual("ACCEPTING", self.controller_row()["state"])

    def test_incomplete_or_rewritten_request_fingerprint_is_rejected(self) -> None:
        request = self.request(
            "maintenance_begin",
            epoch=7,
            command_hex="9",
            params={"reasonCode": "UPGRADE"},
        )
        request["requestFingerprint"] = "0" * 64

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.protocol.handle(request)

        self.assertEqual("INVALID_REQUEST", captured.exception.code)
        self.assertEqual(0, self.receipt_count())

    def test_candidate_accept_then_resume_uses_inherited_controller_socket(self) -> None:
        stopped = self.enter_shutdown_state()
        socket_info = self.bind_candidate_socket()
        candidate_start_id = "cs2_" + "d" * 32
        accepted_request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="controller_accept",
            controller_identity=self.controller.controller_identity,
            instance_id=None,
            controller_start_id=candidate_start_id,
            command_id="cc2_" + "d" * 32,
            expected_control_epoch=int(stopped["controlEpoch"]),
            operation_id=OPERATION_ID,
            params={
                "activationId": self.controller.activation_id,
                "databaseId": database_identity().database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
                "expectedOrphanOperationId": None,
            },
        )

        accepted = self.protocol.handle(accepted_request)
        accepted_row = self.controller_row()
        resumed_request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="maintenance_resume",
            controller_identity=self.controller.controller_identity,
            instance_id=str(accepted["payload"]["instanceId"]),
            controller_start_id=candidate_start_id,
            command_id="cc2_" + "e" * 32,
            expected_control_epoch=int(accepted["controlEpoch"]),
            operation_id=OPERATION_ID,
            params={},
        )
        resumed = self.protocol.handle(resumed_request)
        replayed_accept = self.make_protocol().handle(accepted_request)

        self.assert_contract(accepted_request)
        self.assert_contract(accepted)
        self.assert_contract(resumed)
        self.assert_contract(replayed_accept)
        self.assertEqual("CONTROLLER_ACCEPTED", accepted["payload"]["status"])
        self.assertEqual("MAINTENANCE", accepted_row["state"])
        self.assertEqual("FREEZE", accepted_row["maintenance_mode"])
        self.assertEqual(socket_info.st_ino, accepted_row["socket_inode"])
        self.assertEqual("MAINTENANCE_RESUMED", resumed["payload"]["status"])
        resumed_row = self.controller_row()
        self.assertEqual("ACCEPTING", resumed_row["state"])
        self.assertEqual(0, resumed_row["quiescent"])
        self.assertEqual("REPLAY_RECEIPT", replayed_accept["responseKind"])
        self.assertEqual(5, self.receipt_count())

    def test_candidate_accept_rebinds_exact_stopped_orphan_to_new_operation(self) -> None:
        stopped = self.enter_shutdown_state()
        old_row = self.controller_row()
        self.bind_candidate_socket()
        next_operation_id = "op2_" + "2" * 32
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="rollback-v2",
            method="controller_accept",
            controller_identity=self.controller.controller_identity,
            instance_id=None,
            controller_start_id="cs2_" + "f" * 32,
            command_id="cc2_" + "0" * 32,
            expected_control_epoch=int(stopped["controlEpoch"]),
            operation_id=next_operation_id,
            params={
                "activationId": self.controller.activation_id,
                "databaseId": database_identity().database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
                "expectedOrphanOperationId": OPERATION_ID,
            },
        )

        accepted = self.protocol.handle(request)

        self.assert_contract(request)
        self.assert_contract(accepted)
        self.assertEqual(OPERATION_ID, old_row["operation_id"])
        self.assertEqual("CONTROLLER_ACCEPTED", accepted["payload"]["status"])
        self.assertEqual(int(stopped["controlEpoch"]) + 1, accepted["controlEpoch"])
        self.assertEqual(next_operation_id, self.controller_row()["operation_id"])
        self.assertEqual(4, self.receipt_count())

    def test_candidate_accept_cannot_rebind_without_exact_orphan_operation(self) -> None:
        stopped = self.enter_shutdown_state()
        self.bind_candidate_socket()
        before = self.controller_row()
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="rollback-v2",
            method="controller_accept",
            controller_identity=self.controller.controller_identity,
            instance_id=None,
            controller_start_id="cs2_" + "f" * 32,
            command_id="cc2_" + "0" * 32,
            expected_control_epoch=int(stopped["controlEpoch"]),
            operation_id="op2_" + "2" * 32,
            params={
                "activationId": self.controller.activation_id,
                "databaseId": database_identity().database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
                "expectedOrphanOperationId": None,
            },
        )

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.protocol.handle(request)

        self.assertEqual("CONTROLLER_INSTANCE_MISMATCH", captured.exception.code)
        self.assertEqual(before, self.controller_row())
        self.assertEqual(3, self.receipt_count())

    def test_candidate_operation_rebind_keeps_exact_epoch_fence(self) -> None:
        stopped = self.enter_shutdown_state()
        self.bind_candidate_socket()
        before = self.controller_row()
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="rollback-v2",
            method="controller_accept",
            controller_identity=self.controller.controller_identity,
            instance_id=None,
            controller_start_id="cs2_" + "f" * 32,
            command_id="cc2_" + "0" * 32,
            expected_control_epoch=int(stopped["controlEpoch"]) - 1,
            operation_id="op2_" + "2" * 32,
            params={
                "activationId": self.controller.activation_id,
                "databaseId": database_identity().database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
            },
        )

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.protocol.handle(request)

        self.assertEqual("CONTROL_EPOCH_MISMATCH", captured.exception.code)
        self.assertEqual(before, self.controller_row())
        self.assertEqual(3, self.receipt_count())

    def test_candidate_recover_cannot_rebind_another_operation(self) -> None:
        stopped = self.enter_shutdown_state()
        self.bind_candidate_socket()
        before = self.controller_row()
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="recovery-v2",
            method="controller_recover",
            controller_identity=self.controller.controller_identity,
            instance_id=None,
            controller_start_id="cs2_" + "f" * 32,
            command_id="cc2_" + "0" * 32,
            expected_control_epoch=int(stopped["controlEpoch"]),
            operation_id="op2_" + "2" * 32,
            params={
                "activationId": self.controller.activation_id,
                "databaseId": database_identity().database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
            },
        )

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.protocol.handle(request)

        self.assertEqual("CONTROLLER_INSTANCE_MISMATCH", captured.exception.code)
        self.assertEqual(before, self.controller_row())
        self.assertEqual(3, self.receipt_count())

    def test_candidate_accept_rejects_another_activation_without_receipt(self) -> None:
        stopped = self.enter_shutdown_state()
        self.bind_candidate_socket()
        before = self.controller_row()
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="controller_accept",
            controller_identity=self.controller.controller_identity,
            instance_id=None,
            controller_start_id="cs2_" + "e" * 32,
            command_id="cc2_" + "f" * 32,
            expected_control_epoch=int(stopped["controlEpoch"]),
            operation_id=OPERATION_ID,
            params={
                "activationId": "act2_" + "0" * 64,
                "databaseId": database_identity().database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
            },
        )

        with self.assertRaises(LifecycleControllerProtocolV2Error) as captured:
            self.protocol.handle(request)

        self.assertEqual("CONTROLLER_INSTANCE_MISMATCH", captured.exception.code)
        self.assertEqual(before, self.controller_row())
        self.assertEqual(3, self.receipt_count())

    def test_maintenance_status_is_read_only_and_reports_current_fence(self) -> None:
        begun = self.protocol.handle(
            self.request(
                "maintenance_begin",
                epoch=7,
                command_hex="0",
                params={"reasonCode": "UPGRADE"},
            )
        )
        request = build_lifecycle_controller_status_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            controller_identity=self.controller.controller_identity,
            instance_id=self.controller.instance_id,
            controller_start_id=self.controller.controller_start_id,
            expected_control_epoch=int(begun["controlEpoch"]),
        )

        response = self.protocol.handle(request)

        self.assert_contract(request)
        self.assert_contract(response)
        self.assertEqual("SUCCESS", response["responseKind"])
        self.assertEqual("maintenance_status", response["method"])
        self.assertIsNone(response["commandId"])
        self.assertEqual("MAINTENANCE", response["payload"]["state"])
        self.assertEqual("drain", response["payload"]["maintenanceMode"])
        self.assertTrue(response["payload"]["quiescent"])
        self.assertEqual(1, self.receipt_count())

    def test_status_promotes_naturally_drained_controller_without_epoch_change(self) -> None:
        busy = {
            "nonterminalRoutes": 1,
            "nonterminalNodes": 0,
            "activeAttempts": 0,
            "activeLeases": 0,
            "openIntents": 0,
            "inflightLaunchPermits": 0,
            "activeRuntimeArtifacts": 0,
            "pendingCandidatePublications": 0,
            "activeEvidenceJobs": 0,
            "queuedEvidenceJobs": 0,
        }
        drained = {name: 0 for name in busy}
        observations = iter((busy, drained))
        protocol = self.make_protocol(
            quiescence_reader=lambda _connection: next(observations)
        )
        begun = protocol.handle(
            self.request(
                "maintenance_begin",
                epoch=7,
                command_hex="9",
                params={"reasonCode": "UPGRADE"},
            )
        )
        self.assertEqual("DRAINING", self.controller_row()["state"])
        request = build_lifecycle_controller_status_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            controller_identity=self.controller.controller_identity,
            instance_id=self.controller.instance_id,
            controller_start_id=self.controller.controller_start_id,
            expected_control_epoch=int(begun["controlEpoch"]),
        )

        response = protocol.handle(request)

        self.assert_contract(response)
        self.assertEqual(int(begun["controlEpoch"]), response["controlEpoch"])
        self.assertEqual("MAINTENANCE", response["payload"]["state"])
        self.assertTrue(response["payload"]["quiescent"])
        row = self.controller_row()
        self.assertEqual("MAINTENANCE", row["state"])
        self.assertEqual(1, row["quiescent"])
        self.assertEqual(int(begun["controlEpoch"]), row["control_epoch"])
        self.assertEqual(1, self.receipt_count())


if __name__ == "__main__":
    unittest.main()
