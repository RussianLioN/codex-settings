from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.candidate_ready_channel_v2 import (  # noqa: E402
    CandidateReadyChannelV2Error,
    CandidateDispatchIntentReceiptV2,
    CandidateSpawnActionV2,
    CandidateSpawnAuthorizationV2,
    _open_database_lease,
    build_controller_candidate_spawn_step_port_v2,
    candidate_controller_argv_v2,
    candidate_dispatch_intent_receipt_path_v2,
    candidate_registration_receipt_path_v2,
    create_candidate_dispatch_intent_receipt_v2,
    await_candidate_ownership_gate_v2,
    load_candidate_ready_bootstrap_v2,
    load_candidate_dispatch_intent_receipt_v2,
    load_durable_candidate_spawn_action_v2,
    reconnect_candidate_ready_channel_v2,
    spawn_candidate_controller_process_v2,
    start_candidate_ready_channel_v2,
)
from codex_smart_subagents import (  # noqa: E402
    candidate_ready_channel_v2 as candidate_module,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
    build_lifecycle_controller_request_v2,
)
from codex_smart_subagents.schema_projection import APPLICATION_ID  # noqa: E402
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    SmartStoreV2,
)
from codex_smart_subagents.lifecycle_operation_v2 import (  # noqa: E402
    ExecutionPlanV2,
    FailurePointV2,
    InjectedCrashV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    build_operation_journal_validator_v2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)
from codex_smart_subagents.operation_process_group_supervisor_v2 import (  # noqa: E402
    DurableProcessOwnershipCallbackErrorV2,
    OperationProcessGroupSupervisorV2,
    TransientProcessLeaseV2,
    scoped_current_process_group_supervisor_v2,
)
from codex_smart_subagents.durable_process_ownership_v2 import (  # noqa: E402
    DurableProcessOwnershipStoreV2,
)


class _JournalClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 19, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(microseconds=1)
        return result


class _CandidateDeadlineClock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += int(seconds * 1_000_000_000)


class _JournalIds:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}_{self.value:032x}"


def _empty_state_bundle() -> StateBundleV2:
    return StateBundleV2(
        file_objects=(),
        tree_objects=(),
        symlinks=(),
        manifest=None,
        activation=None,
        database=None,
        controller=None,
        controller_candidates=(),
        watchdogs=(),
        registry=None,
        launchers=None,
        legacy_processes=None,
        quiescence=None,
        external_commands=(),
        receipts=(),
        absence_proofs=(),
    )


class CandidateReadyChannelV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="candidate-ready-v2-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.state_home = self.root / "state"
        self.state_home.mkdir(mode=0o700)
        self.database_id = "db2_" + "1" * 32
        self.database_path = self.state_home / "candidate.sqlite3"
        connection = sqlite3.connect(self.database_path)
        try:
            journal_mode = connection.execute("pragma journal_mode=WAL").fetchone()[0]
            self.assertEqual("wal", str(journal_mode).lower())
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.execute("pragma user_version=2")
            connection.execute(
                "create table database_identity("
                "singleton integer primary key, database_id text not null, "
                "schema_version integer not null, activation_id text not null, "
                "activation_fingerprint text not null)"
            )
            connection.execute(
                "insert into database_identity values(1, ?, 2, ?, ?)",
                (
                    self.database_id,
                    "act2_" + "2" * 64,
                    "2" * 64,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        self.database_path.chmod(0o600)

        self.controller_socket_path = self.state_home / "controller.sock"
        self.controller_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.controller_listener.bind(str(self.controller_socket_path))
        self.controller_socket_path.chmod(0o600)
        self.controller_listener.listen(1)
        controller_socket = os.lstat(self.controller_socket_path)

        self.token = "ready-token-" + "9" * 48
        self.readiness_window_ms = 10_000
        self.candidate_argv = [
            "/private/runtime/python3",
            "/private/activation/controller/server.py",
            "--serve-candidate-v2",
        ]
        self.action = {
            "actionKind": "controller-candidate-spawn",
            "candidateId": "cand2_" + "3" * 32,
            "controllerIdentity": "4" * 64,
            "controllerStartId": "cs2_" + "5" * 32,
            "operationId": "op2_" + "6" * 32,
            "activationId": "act2_" + "2" * 64,
            "activationFingerprint": "2" * 64,
            "databaseId": self.database_id,
            "argv": list(self.candidate_argv),
            "argvFingerprint": domain_fingerprint(
                "codex-smart/controller-candidate-argv/v2",
                {"argv": self.candidate_argv},
            ),
            "snapshotFingerprint": "8" * 64,
            "privateReadyChannelPath": str(self.state_home / "candidate.ready"),
            "readinessTokenHash": hashlib.sha256(
                self.token.encode("utf-8")
            ).hexdigest(),
            "readinessWindowMs": self.readiness_window_ms,
            "processGroupPolicy": "NEW_PRIVATE_GROUP",
        }
        self.controller = SimpleNamespace(
            controller_identity=self.action["controllerIdentity"],
            controller_start_id=self.action["controllerStartId"],
            controller_pid=4100,
            controller_process_start_marker="test-marker-current-process",
            controller_process_group_id=4100,
            activation_id=self.action["activationId"],
            activation_fingerprint=self.action["activationFingerprint"],
            socket_path=str(self.controller_socket_path),
            socket_device=controller_socket.st_dev,
            socket_inode=controller_socket.st_ino,
            socket_owner_uid=controller_socket.st_uid,
            socket_owner_gid=controller_socket.st_gid,
            socket_mode="0600",
        )
        self.channels = []
        self.dispatch_intent: CandidateDispatchIntentReceiptV2 | None = None

    def _dispatch(
        self,
        *,
        action=None,
        created_at_monotonic_ms: int | None = None,
    ) -> CandidateDispatchIntentReceiptV2:
        parsed = CandidateSpawnActionV2.from_mapping(
            self.action if action is None else action
        )
        created_at = (
            int(time.monotonic() * 1000)
            if created_at_monotonic_ms is None
            else created_at_monotonic_ms
        )
        receipt = CandidateDispatchIntentReceiptV2.create(
            action=parsed,
            created_at_monotonic_ms=created_at,
        )
        self.dispatch_intent = receipt
        return receipt

    def _write_operation_journal(self, *, steps=None) -> Path:
        manifests = self.root / "codex-home" / "install-manifests"
        manifests.mkdir(parents=True, mode=0o700, exist_ok=True)
        (self.root / "codex-home").chmod(0o700)
        action_fingerprint = domain_fingerprint(
            "codex-smart/step-action/v2", {"action": self.action}
        )
        journal = {
            "schemaVersion": 2,
            "operationId": self.action["operationId"],
            "phase": "EXECUTING",
            "steps": (
                [
                    {
                        "stepId": "st2_" + "a" * 32,
                        "kind": "controller_candidate_spawn",
                        "state": "INTENT_DURABLE",
                        "action": dict(self.action),
                        "actionFingerprint": action_fingerprint,
                    }
                ]
                if steps is None
                else steps
            ),
        }
        journal["journalFingerprint"] = domain_fingerprint(
            "codex-smart/operation-journal/v2", journal
        )
        path = manifests / "codex-smart-subagents-v2.transaction.json"
        path.write_bytes(canonical_json_bytes(journal))
        path.chmod(0o600)
        return path

    def _make_retired_partition(
        self,
        *,
        operation_id: str | None = None,
        candidate_id: str | None = None,
    ) -> Path:
        parent = self.root / "codex-home" / "install-manifests"
        for name in (
            "candidate-dispatch-retired-v2",
            operation_id or self.action["operationId"],
            candidate_id or self.action["candidateId"],
        ):
            parent = parent / name
            parent.mkdir(mode=0o700, exist_ok=True)
            parent.chmod(0o700)
        return parent

    def _projection(
        self,
        schema_id: str,
        value: dict[str, object],
        domain: str,
    ) -> ProjectionV2:
        schema_sha256 = "f" * 64
        envelope = {
            "schemaId": schema_id,
            "schemaSha256": schema_sha256,
            "value": value,
        }
        return ProjectionV2(
            schema_id=schema_id,
            schema_sha256=schema_sha256,
            value=value,
            value_fingerprint=domain_fingerprint(domain, envelope),
        )

    def _spawn_definition(self) -> StepDefinitionV2:
        parent = self.state_home.stat()
        absence_seed = {
            "installationId": "ins2_" + "7" * 32,
            "operationId": self.action["operationId"],
            "entries": [
                {
                    "path": self.action["privateReadyChannelPath"],
                    "basename": Path(self.action["privateReadyChannelPath"]).name,
                    "parentDevice": parent.st_dev,
                    "parentInode": parent.st_ino,
                    "absent": True,
                }
            ],
        }
        absence_value = {
            "proofId": "ap2_" + "7" * 32,
            **absence_seed,
            "directorySyncCompleted": True,
        }
        absence_value["proofFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof/v2", absence_value
        )
        before = self._projection(
            "absence-proof-v2",
            absence_value,
            "codex-smart/absence-proof-projection/v2",
        )
        expected_value = {
            **{
                name: value
                for name, value in self.action.items()
                if name not in {"actionKind", "argv"}
            },
            "privateReadyChannel": None,
            "pid": None,
            "processStartMarker": None,
            "processGroupId": None,
            "registrationFingerprint": None,
            "databaseLeaseProofFingerprint": None,
            "databaseOpened": False,
            "workingSocketPublished": False,
            "acceptingNewRoutes": False,
            "status": "EXPECTED_REGISTRATION",
            "exitProofFingerprint": None,
        }
        expected_after = self._projection(
            "controller-candidate-v2",
            expected_value,
            "codex-smart/controller-candidate/v2",
        )
        return StepDefinitionV2(
            kind="controller_candidate_spawn",
            command_id=None,
            action=dict(self.action),
            before=before,
            expected_after=expected_after,
        )

    def _journal_step(
        self,
        definition: StepDefinitionV2,
        *,
        state: str,
        observed_after: ProjectionV2 | None = None,
    ) -> dict[str, object]:
        return {
            "stepId": "st2_" + "a" * 32,
            "kind": definition.kind,
            "state": state,
            "action": dict(definition.action),
            "actionFingerprint": definition.action_fingerprint,
            "before": definition.before.to_document(),
            "expectedAfter": definition.expected_after.to_document(),
            "observedAfter": (
                None if observed_after is None else observed_after.to_document()
            ),
        }

    def tearDown(self) -> None:
        for channel in reversed(self.channels):
            channel.close()
        self.controller_listener.close()
        try:
            self.controller_socket_path.unlink()
        except FileNotFoundError:
            pass
        self.temporary.cleanup()

    def _start(self, **overrides):
        action = overrides.get("action", self.action)
        dispatch_intent = overrides.get("dispatch_intent")
        if dispatch_intent is None:
            dispatch_intent = self._dispatch(action=action)
        arguments = {
            "action": action,
            "dispatch_intent": dispatch_intent,
            "readiness_token": self.token,
            "database_path": self.database_path,
            "controller": self.controller,
            "process_identity_provider": lambda: (
                4100,
                "test-marker-current-process",
                4100,
            ),
            "actual_argv_provider": lambda: tuple(self.candidate_argv),
        }
        arguments.update(overrides)
        channel = start_candidate_ready_channel_v2(**arguments)
        self.channels.append(channel)
        return channel

    def _reconnect(self, *, action=None, **overrides):
        selected_action = self.action if action is None else action
        dispatch_intent = overrides.pop("dispatch_intent", self.dispatch_intent)
        if dispatch_intent is None:
            dispatch_intent = self._dispatch(action=selected_action)
        arguments = {
            "action": selected_action,
            "dispatch_intent": dispatch_intent,
            "timeout_seconds": 1.0,
            "process_start_marker_provider": lambda pid: (
                "test-marker-current-process" if pid == 4100 else "wrong"
            ),
        }
        arguments.update(overrides)
        return reconnect_candidate_ready_channel_v2(**arguments)

    def test_reconnect_recomputes_one_deadline_before_each_socket_block(
        self,
    ) -> None:
        clock = _CandidateDeadlineClock()
        response = {
            "registration": {"candidateId": self.action["candidateId"]},
            "databaseLease": {},
            "workingControllerSocket": {},
        }

        class TimedSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []
                self.responses = iter((canonical_json_bytes(response), b""))

            def settimeout(self, timeout: float) -> None:
                self.timeouts.append(timeout)

            def connect(self, _path: str) -> None:
                clock.advance(0.35)

            def sendall(self, _payload: bytes) -> None:
                clock.advance(0.35)

            def recv(self, _maximum: int) -> bytes:
                clock.advance(0.05)
                return next(self.responses)

            def shutdown(self, _how: int) -> None:
                return None

            def close(self) -> None:
                return None

        connection = TimedSocket()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1.0,
            timeout_code="ROOT_OPERATION_EXPIRED",
            monotonic_ns=clock,
        )
        with (
            scoped_current_deadline_v2(deadline),
            patch.object(
                candidate_module.socket,
                "socket",
                return_value=connection,
            ),
            patch.object(
                candidate_module,
                "_socket_identity",
                return_value={"stable": True},
            ),
            patch.object(candidate_module, "_peer_uid", return_value=os.getuid()),
            patch.object(candidate_module, "_verify_response", return_value=None),
        ):
            result = self._reconnect(timeout_seconds=2.0)

        self.assertEqual(
            self.action["candidateId"],
            result.registration["candidateId"],
        )
        self.assertGreaterEqual(len(connection.timeouts), 3)
        self.assertAlmostEqual(1.0, connection.timeouts[0], places=6)
        self.assertLessEqual(connection.timeouts[1], 0.650001)
        self.assertLessEqual(connection.timeouts[2], 0.300001)

    def test_standalone_reconnect_keeps_local_timeout_in_channel_category(
        self,
    ) -> None:
        clock = _CandidateDeadlineClock()
        local_deadline = OperationDeadlineV2.start(
            operation="candidate-ready-reconnect",
            timeout_seconds=1.0,
            timeout_code="CANDIDATE_READY_RECONNECT_TIMEOUT",
            monotonic_ns=clock,
        )

        class TimedOutSocket:
            def settimeout(self, _timeout: float) -> None:
                return None

            def connect(self, _path: str) -> None:
                clock.advance(0.6)

            def sendall(self, _payload: bytes) -> None:
                clock.advance(0.5)

            def shutdown(self, _how: int) -> None:
                return None

            def close(self) -> None:
                return None

        with (
            patch.object(
                candidate_module.operation_deadline_v2.OperationDeadlineV2,
                "start",
                return_value=local_deadline,
            ),
            patch.object(
                candidate_module.socket,
                "socket",
                return_value=TimedOutSocket(),
            ),
            patch.object(
                candidate_module,
                "_socket_identity",
                return_value={"stable": True},
            ),
            patch.object(candidate_module, "_peer_uid", return_value=os.getuid()),
            self.assertRaises(CandidateReadyChannelV2Error) as caught,
        ):
            self._reconnect(timeout_seconds=2.0)

        self.assertEqual(
            "CANDIDATE_READY_AUTHENTICATION_FAILED",
            caught.exception.code,
        )

    def test_registration_is_exact_bounded_canonical_and_restart_reconnectable(
        self,
    ) -> None:
        channel = self._start()

        first = self._reconnect()
        second = self._reconnect()

        self.assertTrue(channel.wait_until_registered(1.0))
        self.assertEqual(first.registration, second.registration)
        self.assertEqual(first.database_lease, second.database_lease)
        self.assertEqual(
            first.working_controller_socket, second.working_controller_socket
        )
        self.assertLessEqual(len(first.response_bytes), 64 * 1024)
        self.assertEqual(canonical_json_bytes(first.response), first.response_bytes)

        expected_registration_keys = {
            "candidateId",
            "controllerIdentity",
            "controllerStartId",
            "operationId",
            "activationId",
            "activationFingerprint",
            "databaseId",
            "argvFingerprint",
            "snapshotFingerprint",
            "privateReadyChannelPath",
            "privateReadyChannel",
            "readinessTokenHash",
            "readinessWindowMs",
            "processGroupPolicy",
            "pid",
            "processStartMarker",
            "processGroupId",
            "registrationFingerprint",
            "databaseLeaseProofFingerprint",
            "databaseOpened",
            "workingSocketPublished",
            "acceptingNewRoutes",
            "status",
            "exitProofFingerprint",
        }
        self.assertEqual(expected_registration_keys, set(first.registration))
        for name in (
            "candidateId",
            "controllerIdentity",
            "controllerStartId",
            "operationId",
            "activationId",
            "activationFingerprint",
            "databaseId",
            "argvFingerprint",
            "snapshotFingerprint",
            "privateReadyChannelPath",
            "readinessTokenHash",
            "readinessWindowMs",
            "processGroupPolicy",
        ):
            self.assertEqual(self.action[name], first.registration[name])
        self.assertEqual(4100, first.registration["pid"])
        self.assertEqual(4100, first.registration["processGroupId"])
        self.assertEqual("REGISTERED_READY", first.registration["status"])
        self.assertTrue(first.registration["databaseOpened"])
        self.assertFalse(first.registration["workingSocketPublished"])
        self.assertFalse(first.registration["acceptingNewRoutes"])
        self.assertIsNone(first.registration["exitProofFingerprint"])

        lease_projection = dict(first.database_lease)
        lease_fingerprint = lease_projection.pop("proofFingerprint")
        self.assertEqual(
            domain_fingerprint(
                "codex-smart/sqlite-read-only-lease/v2", lease_projection
            ),
            lease_fingerprint,
        )
        self.assertEqual(
            lease_fingerprint,
            first.registration["databaseLeaseProofFingerprint"],
        )
        self.assertTrue(first.database_lease["queryOnly"])
        self.assertTrue(first.database_lease["transactionOpen"])
        self.assertEqual("wal", first.database_lease["journalMode"])

    def test_delete_mode_database_is_rejected_before_ready_registration(self) -> None:
        with closing(
            sqlite3.connect(self.database_path, isolation_level=None)
        ) as connection:
            journal_mode = connection.execute("pragma journal_mode=DELETE").fetchone()[0]
        self.assertEqual("delete", str(journal_mode).lower())

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            self._start()

        self.assertEqual(
            "CANDIDATE_DATABASE_JOURNAL_MODE_INVALID",
            caught.exception.code,
        )

    def test_database_lease_connect_preserves_exact_root_deadline(self) -> None:
        deadline_error = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="candidate-database-lease",
            deadline_kind="operation",
            configured_timeout_nanoseconds=600_000_000_000,
            elapsed_monotonic_nanoseconds=600_000_000_000,
        )

        with (
            patch.object(
                candidate_module,
                "connect_sqlite_with_deadline_v2",
                side_effect=deadline_error,
            ),
            self.assertRaises(OperationDeadlineExceededV2) as raised,
        ):
            _open_database_lease(
                self.database_path,
                action=CandidateSpawnActionV2.from_mapping(self.action),
            )

        self.assertIs(deadline_error, raised.exception)
        self.assertEqual(
            "MUTATING_OPERATION_DEADLINE_TIMEOUT", raised.exception.code
        )

    def test_database_lease_deadline_after_begin_uses_cleanup_rollback(self) -> None:
        deadline_error = OperationDeadlineExceededV2(
            code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            operation="apply",
            phase="candidate-database-lease",
            deadline_kind="operation",
            configured_timeout_nanoseconds=600_000_000_000,
            elapsed_monotonic_nanoseconds=600_000_000_000,
        )
        events: list[str] = []

        class Cursor:
            def __init__(self, value: object) -> None:
                self.value = value

            def fetchone(self) -> object:
                return self.value

        class Connection:
            in_transaction = False

            def execute(self, statement: str) -> Cursor:
                if statement == "pragma query_only=on":
                    return Cursor(None)
                if statement == "pragma journal_mode":
                    return Cursor(("wal",))
                if statement == "begin":
                    self.in_transaction = True
                    return Cursor(None)
                raise deadline_error

            def rollback_for_cleanup_v2(self) -> None:
                events.append("rollback")
                self.in_transaction = False

            def close(self) -> None:
                events.append("close")

        with (
            patch.object(
                candidate_module,
                "connect_sqlite_with_deadline_v2",
                return_value=Connection(),
            ),
            self.assertRaises(OperationDeadlineExceededV2) as raised,
        ):
            _open_database_lease(
                self.database_path,
                action=CandidateSpawnActionV2.from_mapping(self.action),
            )

        self.assertIs(deadline_error, raised.exception)
        self.assertEqual(["rollback", "close"], events)

    def test_held_wal_lease_allows_real_controller_accept_commit(self) -> None:
        self.database_path.unlink()
        codex_home = self.root / "codex-home"
        codex_home.mkdir(mode=0o700)
        lock_path = self.state_home / "controller.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        socket_info = self.controller_socket_path.lstat()
        now = datetime(2026, 7, 19, tzinfo=timezone.utc)
        pid = os.getpid()
        process_start_marker = system_process_start_marker_v2(pid)
        process_group_id = os.getpgrp()
        identity = DatabaseIdentityV2(
            database_id=self.database_id,
            activation_binding_nonce="0" * 64,
            activation_id=self.action["activationId"],
            activation_fingerprint=self.action["activationFingerprint"],
            created_operation_id=self.action["operationId"],
            created_at=now,
        )
        controller = AcceptingControllerV2(
            controller_identity=self.action["controllerIdentity"],
            instance_id="ci2_" + "1" * 32,
            controller_start_id=self.action["controllerStartId"],
            controller_pid=pid,
            controller_process_start_marker=process_start_marker,
            controller_process_group_id=process_group_id,
            control_epoch=1,
            activation_id=self.action["activationId"],
            activation_fingerprint=self.action["activationFingerprint"],
            compatibility_fingerprint="a" * 64,
            routing_policy_fingerprint="b" * 64,
            bundled_catalog_fingerprint="c" * 64,
            socket_path=str(self.controller_socket_path),
            socket_device=socket_info.st_dev,
            socket_inode=socket_info.st_ino,
            socket_owner_uid=socket_info.st_uid,
            socket_owner_gid=socket_info.st_gid,
            socket_mode="0600",
            updated_at=now,
        )
        store = SmartStoreV2(
            self.database_path,
            database_identity=identity,
            controller=controller,
        )
        store.close()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "update controller_state set instance_id=null,controller_start_id=null,"
                "controller_pid=null,controller_process_start_marker=null,"
                "controller_process_group_id=null,control_epoch=1,state='MAINTENANCE',"
                "maintenance_mode='FREEZE',reason_code='AWAITING_CONTROLLER_ACCEPT',"
                "operation_id=?,socket_path=null,socket_device=null,socket_inode=null,"
                "socket_owner_uid=null,socket_owner_gid=null,socket_mode=null,"
                "lock_held=0,accepting_new_routes=0,quiescent=1 where singleton=1",
                (self.action["operationId"],),
            )
            connection.commit()

        action = CandidateSpawnActionV2.from_mapping(self.action)
        lease, lease_connection = _open_database_lease(
            self.database_path,
            action=action,
        )
        try:
            protocol = LifecycleControllerProtocolV2(
                database_path=self.database_path,
                codex_home=codex_home,
                controller_lock_path=lock_path,
                clock=lambda: now,
            )
            request = build_lifecycle_controller_request_v2(
                codex_home=codex_home,
                shell_session_id="installer-v2",
                method="controller_accept",
                controller_identity=self.action["controllerIdentity"],
                instance_id=None,
                controller_start_id=self.action["controllerStartId"],
                command_id="cc2_" + "2" * 32,
                expected_control_epoch=1,
                operation_id=self.action["operationId"],
                params={
                    "activationId": self.action["activationId"],
                    "databaseId": self.database_id,
                    "pid": pid,
                    "processStartMarker": process_start_marker,
                    "processGroupId": process_group_id,
                },
            )

            started_at = time.monotonic()
            response = protocol.handle(request)
            elapsed = time.monotonic() - started_at
        finally:
            if lease_connection.in_transaction:
                lease_connection.execute("rollback")
            lease_connection.close()

        self.assertEqual("wal", lease["journalMode"])
        self.assertEqual("CONTROLLER_ACCEPTED", response["payload"]["status"])
        self.assertEqual(2, response["controlEpoch"])
        self.assertLess(elapsed, 1.0)
        with closing(sqlite3.connect(self.database_path)) as connection:
            receipt_count = connection.execute(
                "select count(*) from controller_command_receipts"
            ).fetchone()[0]
        self.assertEqual(1, receipt_count)

    def test_actual_candidate_argv_must_match_durable_action(self) -> None:
        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            self._start(
                actual_argv_provider=lambda: (
                    self.candidate_argv[0],
                    self.candidate_argv[1],
                    "--serve-v2",
                )
            )

        self.assertEqual("CANDIDATE_ARGV_MISMATCH", caught.exception.code)
        self.assertFalse(Path(self.action["privateReadyChannelPath"]).exists())

    def test_canonical_candidate_argv_has_interpreter_entrypoint_and_mode(self) -> None:
        interpreter = self.root / "python3"
        interpreter.write_bytes(b"#!/bin/sh\n")
        interpreter.chmod(0o700)
        entrypoint = self.root / "server.py"
        entrypoint.write_bytes(b"pass\n")
        entrypoint.chmod(0o600)

        argv = candidate_controller_argv_v2(
            interpreter=interpreter,
            server_entrypoint=entrypoint,
        )

        self.assertEqual(
            (str(interpreter), str(entrypoint), "--serve-candidate-v2"),
            argv,
        )
        action = dict(self.action)
        action["argv"] = list(argv)
        action["argvFingerprint"] = domain_fingerprint(
            "codex-smart/controller-candidate-argv/v2",
            {"argv": list(argv)},
        )
        parsed = CandidateSpawnActionV2.from_mapping(action)
        self.assertEqual(argv, parsed.argv)
        changed = dict(action)
        changed["argv"] = [argv[0], str(self.root / "other.py"), argv[2]]
        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            CandidateSpawnActionV2.from_mapping(changed)
        self.assertEqual("CANDIDATE_ACTION_INVALID", caught.exception.code)

    def test_action_is_time_independent_and_dispatch_receipt_is_private_canonical(
        self,
    ) -> None:
        parsed = CandidateSpawnActionV2.from_mapping(self.action)
        self._write_operation_journal()
        codex_home = self.root / "codex-home"

        receipt = create_candidate_dispatch_intent_receipt_v2(
            action=parsed,
            codex_home=codex_home,
            monotonic_ms=lambda: 123_456,
        )
        path = candidate_dispatch_intent_receipt_path_v2(
            codex_home=codex_home,
            action=parsed,
        )
        info = os.lstat(path)

        self.assertNotIn("absoluteDeadlineMonotonicMs", parsed.to_document())
        self.assertEqual(10_000, parsed.readiness_window_ms)
        self.assertEqual(123_456, receipt.created_at_monotonic_ms)
        self.assertEqual(133_456, receipt.absolute_deadline_monotonic_ms)
        self.assertEqual(parsed.action_fingerprint, receipt.action_fingerprint)
        self.assertEqual(parsed.readiness_token_hash, receipt.readiness_token_hash)
        self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        self.assertEqual(os.getuid(), info.st_uid)
        self.assertEqual(1, info.st_nlink)
        self.assertEqual(canonical_json_bytes(receipt.to_document()), path.read_bytes())
        self.assertEqual(
            receipt,
            load_candidate_dispatch_intent_receipt_v2(
                codex_home=codex_home,
                action=parsed,
            ),
        )
        with self.assertRaises(CandidateReadyChannelV2Error) as replay:
            create_candidate_dispatch_intent_receipt_v2(
                action=parsed,
                codex_home=codex_home,
                monotonic_ms=lambda: 123_456,
            )
        self.assertEqual("CANDIDATE_DISPATCH_ALREADY_EXISTS", replay.exception.code)

    def test_port_can_be_built_long_before_dispatch_without_expiring_action(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="PLANNED")]
        )
        clock_calls: list[int] = []

        def clock() -> int:
            clock_calls.append(500_000)
            return 500_000

        dispatched: list[CandidateDispatchIntentReceiptV2] = []
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=clock,
            spawn_primitive=lambda **arguments: dispatched.append(
                arguments["dispatch_intent"]
            ),
        )

        self.assertEqual([], clock_calls)
        self.assertEqual(definition.before, port.observe(definition))
        self.assertEqual([], clock_calls)
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        self.assertEqual(definition.before, port.observe(definition))
        port.apply(definition)

        self.assertEqual([500_000], clock_calls)
        self.assertEqual(510_000, dispatched[0].absolute_deadline_monotonic_ms)

    def test_durable_action_is_rehydrated_and_environment_token_is_consumed(
        self,
    ) -> None:
        self._write_operation_journal()
        codex_home = self.root / "codex-home"
        codex_home.chmod(0o755)
        dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=codex_home,
        )
        environment = {"CODEX_V2_CANDIDATE_READINESS_TOKEN": self.token}

        action = load_durable_candidate_spawn_action_v2(
            codex_home=codex_home,
            operation_id=self.action["operationId"],
            controller_start_id=self.action["controllerStartId"],
        )
        bootstrap = load_candidate_ready_bootstrap_v2(
            codex_home=codex_home,
            environment=environment,
            operation_id=self.action["operationId"],
            controller_start_id=self.action["controllerStartId"],
        )

        self.assertEqual(self.action, action.to_document())
        self.assertEqual(action, bootstrap.action)
        self.assertEqual(dispatch_intent, bootstrap.dispatch_intent)
        self.assertEqual(self.token, bootstrap.readiness_token)
        self.assertNotIn("CODEX_V2_CANDIDATE_READINESS_TOKEN", environment)

        consumed_action, consumed_token = bootstrap.consume()
        self.assertIs(bootstrap.action, consumed_action)
        self.assertEqual(self.token, consumed_token)
        self.assertEqual("", bootstrap.readiness_token)
        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            bootstrap.consume()
        self.assertEqual("CANDIDATE_READY_TOKEN_CONSUMED", caught.exception.code)

    def test_durable_action_loader_rejects_action_fingerprint_tamper(self) -> None:
        path = self._write_operation_journal()
        journal = __import__("json").loads(path.read_text(encoding="utf-8"))
        journal["steps"][0]["action"]["candidateId"] = "cand2_" + "b" * 32
        projection = dict(journal)
        projection.pop("journalFingerprint")
        journal["journalFingerprint"] = domain_fingerprint(
            "codex-smart/operation-journal/v2", projection
        )
        path.write_bytes(canonical_json_bytes(journal))

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            load_durable_candidate_spawn_action_v2(
                codex_home=self.root / "codex-home",
                operation_id=self.action["operationId"],
                controller_start_id=self.action["controllerStartId"],
            )

        self.assertEqual("CANDIDATE_JOURNAL_INVALID", caught.exception.code)

    def test_child_bootstrap_rejects_already_completed_spawn_action(self) -> None:
        action_fingerprint = domain_fingerprint(
            "codex-smart/step-action/v2", {"action": self.action}
        )
        self._write_operation_journal(
            steps=[
                {
                    "stepId": "st2_" + "a" * 32,
                    "kind": "controller_candidate_spawn",
                    "state": "COMPLETED",
                    "action": dict(self.action),
                    "actionFingerprint": action_fingerprint,
                }
            ]
        )
        codex_home = self.root / "codex-home"
        create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=codex_home,
        )
        recovered = load_durable_candidate_spawn_action_v2(
            codex_home=codex_home,
            operation_id=self.action["operationId"],
            controller_start_id=self.action["controllerStartId"],
        )
        self.assertEqual(self.action, recovered.to_document())

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            load_candidate_ready_bootstrap_v2(
                codex_home=codex_home,
                environment={"CODEX_V2_CANDIDATE_READINESS_TOKEN": self.token},
                operation_id=self.action["operationId"],
                controller_start_id=self.action["controllerStartId"],
            )

        self.assertEqual("CANDIDATE_JOURNAL_INVALID", caught.exception.code)

    def test_parent_crash_reconnects_using_persisted_dispatch_deadline(
        self,
    ) -> None:
        self._write_operation_journal()
        dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
        )
        action = load_durable_candidate_spawn_action_v2(
            codex_home=self.root / "codex-home",
            operation_id=self.action["operationId"],
            controller_start_id=self.action["controllerStartId"],
        )
        channel = self._start(action=action, dispatch_intent=dispatch_intent)

        recovered_parent = self._reconnect(
            action=action,
            dispatch_intent=dispatch_intent,
        )

        self.assertTrue(channel.wait_until_registered(1.0))
        self.assertEqual(
            self.action["operationId"], recovered_parent.registration["operationId"]
        )
        self.assertEqual(
            dispatch_intent.readiness_window_ms,
            recovered_parent.registration["readinessWindowMs"],
        )
        self.assertNotIn(
            "absoluteDeadlineMonotonicMs",
            recovered_parent.registration,
        )

    def test_parent_crash_after_ready_before_accept_reconnects_exactly(self) -> None:
        channel = self._start()
        first_parent = self._reconnect()
        self.assertTrue(channel.wait_until_registered(1.0))

        recovered_parent = self._reconnect()

        self.assertEqual(first_parent.registration, recovered_parent.registration)
        self.assertEqual(first_parent.database_lease, recovered_parent.database_lease)
        self.assertEqual("LISTENING", channel.state)

    def test_wrong_token_hash_challenge_is_rejected_without_killing_channel(
        self,
    ) -> None:
        self._start()
        original_dispatch = self.dispatch_intent
        wrong_action = dict(self.action)
        wrong_action["readinessTokenHash"] = "a" * 64
        wrong_dispatch = self._dispatch(action=wrong_action)

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            self._reconnect(action=wrong_action, dispatch_intent=wrong_dispatch)

        self.assertEqual("CANDIDATE_READY_AUTHENTICATION_FAILED", caught.exception.code)
        recovered = self._reconnect(dispatch_intent=original_dispatch)
        self.assertEqual("REGISTERED_READY", recovered.registration["status"])

    def test_wrong_peer_uid_is_rejected_and_socket_is_private(self) -> None:
        self._start(peer_uid_provider=lambda _connection: os.getuid() + 1)
        ready_path = Path(self.action["privateReadyChannelPath"])
        info = os.lstat(ready_path)
        self.assertTrue(stat.S_ISSOCK(info.st_mode))
        self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        self.assertEqual(os.getuid(), info.st_uid)

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            self._reconnect()

        self.assertEqual("CANDIDATE_READY_AUTHENTICATION_FAILED", caught.exception.code)

    def test_non_private_ready_parent_is_rejected_before_bind(self) -> None:
        self.state_home.chmod(0o755)

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            self._start()

        self.assertEqual("CANDIDATE_READY_PARENT_UNSAFE", caught.exception.code)
        self.assertFalse(Path(self.action["privateReadyChannelPath"]).exists())

    def test_deadline_closes_lease_and_removes_ready_socket_before_accept(self) -> None:
        action = dict(self.action)
        action["readinessWindowMs"] = 80
        self.action = action
        channel = self._start()

        self.assertTrue(channel.wait_until_expired(2.0))
        self.assertFalse(Path(action["privateReadyChannelPath"]).exists())
        self.assertEqual("EXPIRED", channel.state)
        with self.assertRaises(CandidateReadyChannelV2Error):
            self._reconnect(action=action, timeout_seconds=0.2)

    def test_controller_socket_tamper_is_detected_fail_closed(self) -> None:
        channel = self._start()
        self._reconnect()
        self.controller_listener.close()
        self.controller_socket_path.unlink()
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            replacement.bind(str(self.controller_socket_path))
            self.controller_socket_path.chmod(0o600)
            replacement.listen(1)

            with self.assertRaises(CandidateReadyChannelV2Error) as caught:
                self._reconnect()

            self.assertEqual("CANDIDATE_READY_RESPONSE_INVALID", caught.exception.code)
            self.assertTrue(channel.wait_until_failed(1.0))
            self.assertFalse(Path(self.action["privateReadyChannelPath"]).exists())
        finally:
            replacement.close()

    def test_spawn_primitive_uses_exact_argv_closed_environment_and_one_shot_token(
        self,
    ) -> None:
        entrypoint = self.root / "candidate.py"
        entrypoint.write_text("pass\n", encoding="utf-8")
        entrypoint.chmod(0o600)
        wrapper = self.root / "wrapper"
        wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper.chmod(0o700)
        argv = candidate_controller_argv_v2(
            interpreter=Path(sys.executable).resolve(),
            server_entrypoint=entrypoint,
        )
        action_document = dict(self.action)
        action_document["argv"] = list(argv)
        action_document["argvFingerprint"] = domain_fingerprint(
            "codex-smart/controller-candidate-argv/v2",
            {"argv": list(argv)},
        )
        action = CandidateSpawnActionV2.from_mapping(action_document)
        codex_home = self.root / "spawn-home"
        codex_home.mkdir(mode=0o700)
        (codex_home / "install-manifests").mkdir(mode=0o700)
        codex_home.chmod(0o755)
        dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
            action=action,
            codex_home=codex_home,
        )
        captured: dict[str, object] = {}

        class FakeProcess:
            def wait(self) -> int:
                captured["waited"] = True
                return 0

        class FakeSupervisor:
            def spawn_transient(self, **options):
                captured["arguments"] = list(options["argv"])
                captured["options"] = options
                captured["gate_reader"] = os.dup(options["pass_fds"][0])
                return TransientProcessLeaseV2(
                    lease_id="transient-" + "a" * 32,
                    label=str(options["label"]),
                    pid=8123,
                    process_group_id=8123,
                    session_id=8123,
                    process_start_marker="candidate-gate-marker",
                    process=FakeProcess(),
                )

        supervisor = FakeSupervisor()

        authorization = CandidateSpawnAuthorizationV2.create(
            action=action,
            readiness_token=self.token,
        )
        receipt = spawn_candidate_controller_process_v2(
            action=action,
            dispatch_intent=dispatch_intent,
            authorization=authorization,
            codex_home=codex_home,
            state_home=self.state_home,
            wrapper_path=wrapper,
            runtime_environment={
                "HOME": "/private/test-home",
                "LANG": "C",
                "PATH": "/must/not/leak",
                "UNRELATED_SECRET": "must-not-leak",
            },
            process_supervisor=supervisor,
        )

        self.assertEqual(list(argv), captured["arguments"])
        options = captured["options"]
        self.assertEqual("/", options["cwd"])
        self.assertEqual(0o077, options["umask"])
        self.assertEqual("candidate-controller", options["label"])
        self.assertEqual(1, len(options["pass_fds"]))
        self.assertEqual(
            {
                "schemaVersion": 2,
                "contextKind": "candidate-dispatch-v2",
                "operationId": action.operation_id,
                "candidateId": action.candidate_id,
                "controllerStartId": action.controller_start_id,
                "actionFingerprint": action.action_fingerprint,
                "dispatchReceiptFingerprint": dispatch_intent.receipt_fingerprint,
            },
            options["ownership_context"],
        )
        environment = options["env"]
        self.assertEqual(
            {
                "HOME",
                "LANG",
                "CODEX_HOME",
                "CODEX_V2_STATE_HOME",
                "CODEX_V2_WRAPPER_PATH",
                "CODEX_V2_CANDIDATE_OPERATION_ID",
                "CODEX_V2_CANDIDATE_CONTROLLER_START_ID",
                "CODEX_V2_CANDIDATE_READINESS_TOKEN",
                "CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONNOUSERSITE",
                "PYTHONUNBUFFERED",
            },
            set(environment),
        )
        self.assertEqual("1", environment["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual("1", environment["PYTHONNOUSERSITE"])
        self.assertEqual("1", environment["PYTHONUNBUFFERED"])
        self.assertNotIn("PATH", environment)
        self.assertNotIn("UNRELATED_SECRET", environment)
        gate_reader = int(captured["gate_reader"])
        try:
            self.assertEqual(b"1", os.read(gate_reader, 2))
            self.assertEqual(b"", os.read(gate_reader, 1))
        finally:
            os.close(gate_reader)
        records = DurableProcessOwnershipStoreV2(codex_home).load_all()
        self.assertEqual(1, len(records))
        self.assertEqual(options["ownership_context"], records[0].context)
        self.assertNotIn("pid", receipt.to_document())
        self.assertNotIn(self.token, repr(authorization))
        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            spawn_candidate_controller_process_v2(
                action=action,
                dispatch_intent=dispatch_intent,
                authorization=authorization,
                codex_home=codex_home,
                state_home=self.state_home,
                wrapper_path=wrapper,
                runtime_environment={},
                process_supervisor=supervisor,
            )
        self.assertEqual("CANDIDATE_SPAWN_TOKEN_CONSUMED", caught.exception.code)

    def test_spawn_rejects_group_or_other_writable_codex_home(self) -> None:
        entrypoint = self.root / "unsafe-home-candidate.py"
        entrypoint.write_text("pass\n", encoding="utf-8")
        entrypoint.chmod(0o600)
        wrapper = self.root / "unsafe-home-wrapper"
        wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper.chmod(0o700)
        argv = candidate_controller_argv_v2(
            interpreter=Path(sys.executable).resolve(),
            server_entrypoint=entrypoint,
        )
        document = {
            **self.action,
            "argv": list(argv),
            "argvFingerprint": domain_fingerprint(
                "codex-smart/controller-candidate-argv/v2",
                {"argv": list(argv)},
            ),
        }
        action = CandidateSpawnActionV2.from_mapping(document)
        codex_home = self.root / "unsafe-home"
        codex_home.mkdir(mode=0o700)
        (codex_home / "install-manifests").mkdir(mode=0o700)
        dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
            action=action,
            codex_home=codex_home,
        )
        codex_home.chmod(0o775)

        with self.assertRaises(CandidateReadyChannelV2Error) as caught:
            spawn_candidate_controller_process_v2(
                action=action,
                dispatch_intent=dispatch_intent,
                authorization=CandidateSpawnAuthorizationV2.create(
                    action=action,
                    readiness_token=self.token,
                ),
                codex_home=codex_home,
                state_home=self.state_home,
                wrapper_path=wrapper,
                popen_factory=lambda *_args, **_kwargs: self.fail("Popen must not run"),
            )

        self.assertIn(
            caught.exception.code,
            {
                "CANDIDATE_DISPATCH_RECEIPT_INVALID",
                "CANDIDATE_SPAWN_CODEX_HOME_INVALID",
            },
        )

    def test_spawn_primitive_creates_real_private_process_group_without_handle_truth(
        self,
    ) -> None:
        observed_path = self.state_home / "spawn-observed.json"
        entrypoint = self.root / "candidate-process.py"
        entrypoint.write_text(
            "import hashlib, json, os, pathlib, sys, time\n"
            "assert sys.argv[1:] == ['--serve-candidate-v2']\n"
            "target = pathlib.Path(os.environ['CODEX_V2_STATE_HOME']) / "
            "'spawn-observed.json'\n"
            "value = {'pid': os.getpid(), 'pgid': os.getpgrp(), "
            "'cwd': os.getcwd(), 'keys': sorted(os.environ), "
            "'tokenHash': hashlib.sha256(os.environ["
            "'CODEX_V2_CANDIDATE_READINESS_TOKEN'].encode()).hexdigest()}\n"
            "target.write_text(json.dumps(value), encoding='utf-8')\n"
            "target.chmod(0o600)\n"
            "while True: time.sleep(0.05)\n",
            encoding="utf-8",
        )
        entrypoint.chmod(0o600)
        wrapper = self.root / "wrapper-real"
        wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper.chmod(0o700)
        codex_home = self.root / "real-home"
        codex_home.mkdir(mode=0o700)
        (codex_home / "install-manifests").mkdir(mode=0o700)
        argv = candidate_controller_argv_v2(
            interpreter=Path(sys.executable).resolve(),
            server_entrypoint=entrypoint,
        )
        action_document = dict(self.action)
        action_document["argv"] = list(argv)
        action_document["argvFingerprint"] = domain_fingerprint(
            "codex-smart/controller-candidate-argv/v2", {"argv": list(argv)}
        )
        action = CandidateSpawnActionV2.from_mapping(action_document)
        authorization = CandidateSpawnAuthorizationV2.create(
            action=action,
            readiness_token=self.token,
        )
        dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
            action=action,
            codex_home=codex_home,
        )
        pid = None
        try:
            supervisor = OperationProcessGroupSupervisorV2()
            with scoped_current_process_group_supervisor_v2(supervisor):
                receipt = spawn_candidate_controller_process_v2(
                    action=action,
                    dispatch_intent=dispatch_intent,
                    authorization=authorization,
                    codex_home=codex_home,
                    state_home=self.state_home,
                    wrapper_path=wrapper,
                    runtime_environment={"PATH": "/must/not/leak"},
                )
            deadline = time.monotonic() + 3.0
            while not observed_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(observed_path.exists())
            observed = json.loads(observed_path.read_text(encoding="utf-8"))
            pid = int(observed["pid"])
            self.assertEqual(pid, observed["pgid"])
            self.assertEqual("/", observed["cwd"])
            self.assertNotIn("PATH", observed["keys"])
            self.assertEqual(action.readiness_token_hash, observed["tokenHash"])
            self.assertNotIn("pid", receipt.to_document())
        finally:
            if pid is not None:
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    def test_child_ownership_gate_accepts_one_release_byte_and_consumes_fd(self) -> None:
        reader, writer = os.pipe()
        environment = {"CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD": str(reader)}
        os.write(writer, b"1")
        os.close(writer)

        await_candidate_ownership_gate_v2(environment)

        self.assertNotIn("CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD", environment)
        with self.assertRaises(OSError):
            os.fstat(reader)

    def test_child_ownership_gate_rejects_parent_death_before_release(self) -> None:
        reader, writer = os.pipe()
        environment = {"CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD": str(reader)}
        os.close(writer)

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            await_candidate_ownership_gate_v2(environment)

        self.assertEqual("CANDIDATE_OWNERSHIP_GATE_NOT_RELEASED", raised.exception.code)
        self.assertNotIn("CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD", environment)

    def test_child_ownership_gate_rejects_wrong_release_byte(self) -> None:
        reader, writer = os.pipe()
        environment = {"CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD": str(reader)}
        os.write(writer, b"0")
        os.close(writer)

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            await_candidate_ownership_gate_v2(environment)

        self.assertEqual("CANDIDATE_OWNERSHIP_GATE_NOT_RELEASED", raised.exception.code)

    def test_publisher_failure_closes_gate_without_release_byte(self) -> None:
        entrypoint = self.root / "publisher-failure-candidate.py"
        entrypoint.write_text("pass\n", encoding="utf-8")
        entrypoint.chmod(0o600)
        wrapper = self.root / "publisher-failure-wrapper"
        wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper.chmod(0o700)
        argv = candidate_controller_argv_v2(
            interpreter=Path(sys.executable).resolve(),
            server_entrypoint=entrypoint,
        )
        action = CandidateSpawnActionV2.from_mapping(
            {
                **self.action,
                "argv": list(argv),
                "argvFingerprint": domain_fingerprint(
                    "codex-smart/controller-candidate-argv/v2",
                    {"argv": list(argv)},
                ),
            }
        )
        codex_home = self.root / "publisher-failure-home"
        codex_home.mkdir(mode=0o700)
        (codex_home / "install-manifests").mkdir(mode=0o700)
        dispatch_intent = create_candidate_dispatch_intent_receipt_v2(
            action=action,
            codex_home=codex_home,
        )
        captured: dict[str, int] = {}

        class FailingSupervisor:
            def spawn_transient(self, **options):
                captured["gate_reader"] = os.dup(options["pass_fds"][0])
                raise DurableProcessOwnershipCallbackErrorV2(
                    lease_id="transient-" + "e" * 32,
                    outcome="publish",
                )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            spawn_candidate_controller_process_v2(
                action=action,
                dispatch_intent=dispatch_intent,
                authorization=CandidateSpawnAuthorizationV2.create(
                    action=action,
                    readiness_token=self.token,
                ),
                codex_home=codex_home,
                state_home=self.state_home,
                wrapper_path=wrapper,
                process_supervisor=FailingSupervisor(),
            )

        self.assertEqual("CANDIDATE_SPAWN_FAILED", raised.exception.code)
        gate_reader = captured["gate_reader"]
        try:
            self.assertEqual(b"", os.read(gate_reader, 1))
        finally:
            os.close(gate_reader)
        self.assertEqual((), DurableProcessOwnershipStoreV2(codex_home).load_all())

    def test_spawn_port_recovers_after_parent_crash_without_replaying_popen(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="PLANNED")]
        )
        spawned: list[str] = []

        def fake_spawn(*, action, dispatch_intent, authorization, **_arguments):
            spawned.append(action.candidate_id)
            token = authorization.consume_for(action)
            self._start(
                action=action,
                dispatch_intent=dispatch_intent,
                readiness_token=token,
            )

        common = {
            "candidate_spawn_action": self.action,
            "codex_home": self.root / "codex-home",
            "state_home": self.state_home,
            "wrapper_path": self.root / "unused-wrapper",
            "spawn_primitive": fake_spawn,
            "process_start_marker_provider": lambda pid: (
                "test-marker-current-process" if pid == 4100 else "wrong"
            ),
        }
        fresh = build_controller_candidate_spawn_step_port_v2(
            readiness_token=self.token,
            **common,
        )
        self.assertEqual(definition.before, fresh.observe(definition))
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        fresh.apply(definition)
        first = fresh.observe(definition)
        self.assertTrue(fresh.matches_after(first, definition))

        recovered = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            **common,
        )
        second = recovered.observe(definition)

        self.assertEqual(first, second)
        self.assertEqual([self.action["candidateId"]], spawned)

    def test_crash_after_intent_before_apply_recovers_and_spawns_exactly_once(
        self,
    ) -> None:
        definition = self._spawn_definition()
        codex_home = self.root / "codex-home"
        manifests = codex_home / "install-manifests"
        manifests.mkdir(parents=True, mode=0o700)
        codex_home.chmod(0o700)
        journal_path = manifests / "codex-smart-subagents-v2.transaction.json"
        plan = ExecutionPlanV2(
            plan_id="pl2_" + "9" * 32,
            machine_id="apply",
            selected_branch_id="update-matched-active",
            composed_step_kinds=("gate_close", "controller_candidate_spawn"),
        )
        parent = manifests.stat()
        gate_absence_value = {
            "proofId": "ap2_" + "9" * 32,
            "installationId": "ins2_" + "7" * 32,
            "operationId": self.action["operationId"],
            "entries": [
                {
                    "path": str(journal_path),
                    "basename": journal_path.name,
                    "parentDevice": parent.st_dev,
                    "parentInode": parent.st_ino,
                    "absent": True,
                }
            ],
            "directorySyncCompleted": True,
        }
        gate_absence_value["proofFingerprint"] = domain_fingerprint(
            "codex-smart/absence-proof/v2",
            gate_absence_value,
        )
        gate_before = self._projection(
            "absence-proof-v2",
            gate_absence_value,
            "codex-smart/absence-proof-projection/v2",
        )
        gate_after = self._projection(
            "journal-state-v2",
            {
                "path": str(journal_path),
                "journalKind": "operation",
                "ownerId": self.action["operationId"],
                "phase": "DISCOVERED",
                "recoveryPolicy": "REVERSIBLE",
                "executionPlanDefinitionFingerprint": (
                    plan.plan_definition_fingerprint
                ),
                "contentGeneration": 1,
                "frozen": False,
            },
            "codex-smart/controller-candidate/v2",
        )
        gate = StepDefinitionV2(
            kind="gate_close",
            command_id=None,
            action={
                "actionKind": "journal-transition",
                "transition": "gate-close",
                "journalPath": str(journal_path),
                "durability": "FSYNC_FILE_AND_PARENT",
            },
            before=gate_before,
            expected_after=gate_after,
        )
        operation = OperationDefinitionV2(
            kind="activation",
            installation_id="ins2_" + "7" * 32,
            operation_id=self.action["operationId"],
            operation="apply",
            execution_plan=plan,
            discovery_before=_empty_state_bundle(),
            fenced_before=_empty_state_bundle(),
            desired=_empty_state_bundle(),
            gate_close=gate,
            mutable_steps=(definition,),
        )
        executor = OperationExecutorV2(
            store=OperationJournalStoreV2(
                journal_path=journal_path,
                lock_path=manifests / "candidate-operation.lock",
                validate_document=build_operation_journal_validator_v2(
                    ROOT / "docs" / "contracts" / "schemas"
                ),
            ),
            now=_JournalClock(),
            id_factory=_JournalIds(),
        )
        spawned: list[str] = []

        crashed_executor_port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=codex_home,
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            spawn_primitive=lambda **_arguments: spawned.append("stale"),
        )
        crashed_callbacks = StepCallbacksV2(
            observe=crashed_executor_port.observe,
            apply=crashed_executor_port.apply,
            matches_before=crashed_executor_port.matches_before,
            matches_after=crashed_executor_port.matches_after,
        )

        def crash(point: FailurePointV2, kind: str) -> None:
            if (
                point is FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION
                and kind == "controller_candidate_spawn"
            ):
                raise InjectedCrashV2(point, kind)

        with self.assertRaises(InjectedCrashV2):
            executor.execute(
                operation,
                callbacks=crashed_callbacks,
                failure_injector=crash,
            )
        self.assertEqual([], spawned)
        interrupted = executor.store.read()
        candidate_step = next(
            step
            for step in interrupted["steps"]
            if step["kind"] == "controller_candidate_spawn"
        )
        self.assertEqual("INTENT_DURABLE", candidate_step["state"])

        def recovered_spawn(*, authorization, action, dispatch_intent, **_arguments):
            token = authorization.consume_for(action)
            spawned.append(action.candidate_id)
            self._start(
                action=action,
                dispatch_intent=dispatch_intent,
                readiness_token=token,
            )

        recovered_port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=codex_home,
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            spawn_primitive=recovered_spawn,
            process_start_marker_provider=lambda pid: (
                "test-marker-current-process" if pid == 4100 else "wrong"
            ),
        )
        resumed = executor.execute(
            operation,
            callbacks=StepCallbacksV2(
                observe=recovered_port.observe,
                apply=recovered_port.apply,
                matches_before=recovered_port.matches_before,
                matches_after=recovered_port.matches_after,
            ),
        )

        receipt = load_candidate_dispatch_intent_receipt_v2(
            codex_home=codex_home,
            action=self.action,
        )

        self.assertEqual("MUTABLE_COMPLETED", resumed.status)
        self.assertEqual([self.action["candidateId"]], spawned)
        self.assertEqual(self.action["readinessWindowMs"], receipt.readiness_window_ms)

    def test_crash_after_durable_dispatch_before_popen_retires_and_respawns(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        clock = iter((50_000, 60_000))
        calls: list[str] = []

        def crash_before_popen(**_arguments):
            calls.append("spawn-primitive-entered")
            raise RuntimeError("crash after durable dispatch")

        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            spawn_primitive=crash_before_popen,
            monotonic_ms=lambda: next(clock),
        )
        self.assertEqual(definition.before, port.observe(definition))
        with self.assertRaisesRegex(RuntimeError, "durable dispatch"):
            port.apply(definition)
        receipt_path = candidate_dispatch_intent_receipt_path_v2(
            codex_home=self.root / "codex-home",
            action=self.action,
        )
        self.assertTrue(receipt_path.exists())
        expired = load_candidate_dispatch_intent_receipt_v2(
            codex_home=self.root / "codex-home",
            action=self.action,
        )

        recovered = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            spawn_primitive=lambda **_arguments: calls.append("duplicate"),
            monotonic_ms=lambda: 60_000,
            sleeper=lambda _seconds: None,
        )
        self.assertEqual(definition.before, recovered.observe(definition))
        self.assertTrue(receipt_path.exists(), "observe must not mutate receipts")
        synced_directories: list[Path] = []
        real_fsync_directory = candidate_module._fsync_directory_v2

        def record_fsync(path: Path) -> None:
            synced_directories.append(path)
            real_fsync_directory(path)

        with patch.object(
            candidate_module,
            "_fsync_directory_v2",
            side_effect=record_fsync,
        ):
            recovered.apply(definition)

        fresh = load_candidate_dispatch_intent_receipt_v2(
            codex_home=self.root / "codex-home",
            action=self.action,
        )
        retired_root = (
            self.root
            / "codex-home"
            / "install-manifests"
            / "candidate-dispatch-retired-v2"
        )
        retired_operation_root = retired_root / self.action["operationId"]
        retired_partition = (
            retired_operation_root / self.action["candidateId"]
        )
        retired_receipts = list(retired_partition.glob("*.json"))
        self.assertEqual(1, len(retired_receipts))
        self.assertEqual(
            [self.action["operationId"]],
            sorted(path.name for path in retired_root.iterdir()),
        )
        self.assertEqual(
            [self.action["candidateId"]],
            sorted(path.name for path in retired_operation_root.iterdir()),
        )
        self.assertEqual(
            f"{expired.receipt_fingerprint}.json",
            retired_receipts[0].name,
        )
        self.assertEqual(0o700, stat.S_IMODE(retired_root.stat().st_mode))
        self.assertEqual(
            0o700,
            stat.S_IMODE(retired_operation_root.stat().st_mode),
        )
        self.assertEqual(0o700, stat.S_IMODE(retired_partition.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(retired_receipts[0].stat().st_mode))
        self.assertIn(retired_root.parent, synced_directories)
        self.assertIn(retired_root, synced_directories)
        self.assertIn(retired_operation_root, synced_directories)
        self.assertIn(retired_partition, synced_directories)
        self.assertEqual(
            canonical_json_bytes(expired.to_document()),
            retired_receipts[0].read_bytes(),
        )
        self.assertEqual(
            50_000,
            json.loads(retired_receipts[0].read_text(encoding="utf-8"))[
                "createdAtMonotonicMs"
            ],
        )
        self.assertEqual(60_000, fresh.created_at_monotonic_ms)
        self.assertEqual(
            ["spawn-primitive-entered", "duplicate"],
            calls,
        )

    def test_retirement_move_never_overwrites_existing_target(self) -> None:
        source = self.root / "retirement-source.json"
        target = self.root / "retirement-target.json"
        source.write_bytes(b"source")
        target.write_bytes(b"target")
        source.chmod(0o600)
        target.chmod(0o600)

        self.assertFalse(candidate_module._rename_no_replace_v2(source, target))

        self.assertEqual(b"source", source.read_bytes())
        self.assertEqual(b"target", target.read_bytes())

    def test_crash_after_retirement_before_fresh_receipt_is_recoverable(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        expired = create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        candidate_module._retire_candidate_dispatch_intent_receipt_v2(
            codex_home=self.root / "codex-home",
            action=CandidateSpawnActionV2.from_mapping(self.action),
            dispatch_intent=expired,
        )
        spawned: list[int] = []
        recovered = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            spawn_primitive=lambda **arguments: spawned.append(
                arguments["dispatch_intent"].created_at_monotonic_ms
            ),
            monotonic_ms=lambda: 60_000,
        )

        self.assertEqual(definition.before, recovered.observe(definition))
        recovered.apply(definition)

        self.assertEqual([60_000], spawned)
        self.assertEqual(
            60_000,
            load_candidate_dispatch_intent_receipt_v2(
                codex_home=self.root / "codex-home",
                action=self.action,
            ).created_at_monotonic_ms,
        )

    def test_retry_is_blocked_by_ready_path(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.action["privateReadyChannelPath"])
        self.addCleanup(listener.close)
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.observe(definition)

        self.assertEqual("CANDIDATE_SPAWN_BEFORE_CHANGED", raised.exception.code)

    def test_retry_is_blocked_by_registration_receipt(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        receipt_path = candidate_registration_receipt_path_v2(
            codex_home=self.root / "codex-home",
            action=self.action,
        )
        receipt_path.parent.mkdir(mode=0o700)
        receipt_path.write_bytes(b"effect")
        receipt_path.chmod(0o600)
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.observe(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_RETRY_EFFECT_PRESENT",
            raised.exception.code,
        )

    def test_retry_is_blocked_by_durable_process_ownership(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        dispatch = create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        context = {
            "schemaVersion": 2,
            "contextKind": "candidate-dispatch-v2",
            "operationId": self.action["operationId"],
            "candidateId": self.action["candidateId"],
            "controllerStartId": self.action["controllerStartId"],
            "actionFingerprint": CandidateSpawnActionV2.from_mapping(
                self.action
            ).action_fingerprint,
            "dispatchReceiptFingerprint": dispatch.receipt_fingerprint,
        }
        DurableProcessOwnershipStoreV2(self.root / "codex-home").publish(
            TransientProcessLeaseV2(
                lease_id="transient-" + "9" * 32,
                label="candidate-controller",
                pid=8123,
                process_group_id=8123,
                session_id=8123,
                process_start_marker="owned-candidate",
                process=SimpleNamespace(),
            ),
            context,
        )
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.observe(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_OWNERSHIP_OUTSTANDING",
            raised.exception.code,
        )

    def test_retry_is_blocked_by_candidate_accept_intent(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[
                self._journal_step(definition, state="INTENT_DURABLE"),
                {
                    "stepId": "st2_" + "b" * 32,
                    "kind": "controller_accept",
                    "state": "INTENT_DURABLE",
                },
            ]
        )
        create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.observe(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_RETRY_EFFECT_PRESENT",
            raised.exception.code,
        )

    def test_corrupt_retirement_history_blocks_retry(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        retired_partition = self._make_retired_partition()
        corrupt = retired_partition / "unknown.json"
        corrupt.write_bytes(b"not-canonical-json")
        corrupt.chmod(0o600)
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.observe(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
            raised.exception.code,
        )

    def test_corrupt_unrelated_retirement_partition_does_not_block_retry(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        retired_root = (
            self.root
            / "codex-home"
            / "install-manifests"
            / "candidate-dispatch-retired-v2"
        )
        unrelated_partitions = (
            self._make_retired_partition(
                operation_id=self.action["operationId"],
                candidate_id="cand2_" + "8" * 32,
            ),
            self._make_retired_partition(
                operation_id="op2_" + "7" * 32,
                candidate_id=self.action["candidateId"],
            ),
        )
        for unrelated_partition in unrelated_partitions:
            corrupt = unrelated_partition / "unknown.json"
            corrupt.write_bytes(b"not-canonical-json")
            corrupt.chmod(0o600)
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
        )
        real_read = candidate_module._read_private_regular_file_bounded
        archive_reads: list[Path] = []

        def record_read(path: Path, **keywords):
            if path.is_relative_to(retired_root):
                archive_reads.append(path)
            return real_read(path, **keywords)

        with patch.object(
            candidate_module,
            "_read_private_regular_file_bounded",
            side_effect=record_read,
        ):
            self.assertEqual(definition.before, port.observe(definition))

        self.assertEqual([], archive_reads)

    def test_dispatch_attempt_limit_has_stable_error(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        parsed_action = CandidateSpawnActionV2.from_mapping(self.action)
        retired_partition = self._make_retired_partition()
        for created_at in range(8):
            receipt = CandidateDispatchIntentReceiptV2.create(
                action=parsed_action,
                created_at_monotonic_ms=created_at,
            )
            path = retired_partition / f"{receipt.receipt_fingerprint}.json"
            path.write_bytes(canonical_json_bytes(receipt.to_document()))
            path.chmod(0o600)
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.observe(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_RETRY_LIMIT_REACHED",
            raised.exception.code,
        )

    def test_oversized_selected_partition_fails_before_receipt_reads(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        parsed_action = CandidateSpawnActionV2.from_mapping(self.action)
        retired_partition = self._make_retired_partition()
        for created_at in range(9):
            receipt = CandidateDispatchIntentReceiptV2.create(
                action=parsed_action,
                created_at_monotonic_ms=created_at,
            )
            path = retired_partition / f"{receipt.receipt_fingerprint}.json"
            path.write_bytes(canonical_json_bytes(receipt.to_document()))
            path.chmod(0o600)
        real_read = candidate_module._read_private_regular_file_bounded
        archive_reads: list[Path] = []

        def record_read(path: Path, **keywords):
            if path.parent == retired_partition:
                archive_reads.append(path)
            return real_read(path, **keywords)

        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: 60_000,
        )

        with (
            patch.object(
                candidate_module,
                "_read_private_regular_file_bounded",
                side_effect=record_read,
            ),
            self.assertRaises(CandidateReadyChannelV2Error) as raised,
        ):
            port.observe(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_RETIREMENT_INVALID",
            raised.exception.code,
        )
        self.assertEqual([], archive_reads)

    def test_retry_requires_a_fresh_dispatch_receipt_fingerprint(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        original = create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        times = iter((60_000, 1))
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            monotonic_ms=lambda: next(times),
            spawn_primitive=lambda **_arguments: self.fail("must not spawn"),
        )

        with self.assertRaises(CandidateReadyChannelV2Error) as raised:
            port.apply(definition)

        self.assertEqual(
            "CANDIDATE_DISPATCH_FRESHNESS_UNPROVEN",
            raised.exception.code,
        )
        self.assertEqual(
            original,
            load_candidate_dispatch_intent_receipt_v2(
                codex_home=self.root / "codex-home",
                action=self.action,
            ),
        )
        self.assertFalse(
            (
                self.root
                / "codex-home"
                / "install-manifests"
                / "candidate-dispatch-retired-v2"
            ).exists()
        )

    def test_two_recoverers_create_only_one_fresh_attempt(self) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 1,
        )
        barrier = threading.Barrier(2)
        spawned: list[str] = []
        errors: list[str] = []

        def recover() -> None:
            port = build_controller_candidate_spawn_step_port_v2(
                candidate_spawn_action=self.action,
                codex_home=self.root / "codex-home",
                state_home=self.state_home,
                wrapper_path=self.root / "unused-wrapper",
                readiness_token=self.token,
                spawn_primitive=lambda **_arguments: spawned.append("spawn"),
                monotonic_ms=lambda: 60_000,
            )
            barrier.wait()
            try:
                port.apply(definition)
            except CandidateReadyChannelV2Error as exc:
                errors.append(exc.code)

        threads = [threading.Thread(target=recover) for _index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3.0)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(["spawn"], spawned)
        self.assertEqual(1, len(errors))
        self.assertEqual(
            1,
            len(
                list(
                    (
                        self.root
                        / "codex-home"
                        / "install-manifests"
                        / "candidate-dispatch-retired-v2"
                        / self.action["operationId"]
                        / self.action["candidateId"]
                    ).glob("*.json")
                )
            ),
        )

    def test_second_recoverer_cannot_expire_fresh_receipt_before_ownership(
        self,
    ) -> None:
        self.action["readinessWindowMs"] = 1
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        first_entered = threading.Event()
        release_first = threading.Event()
        second_entered_spawn = threading.Event()
        calls: list[str] = []
        errors: list[tuple[str, str]] = []

        def publish_first_ownership(
            *, authorization, action, dispatch_intent, **_arguments
        ) -> None:
            authorization.consume_for(action)
            calls.append("first")
            first_entered.set()
            if not release_first.wait(timeout=2.0):
                raise RuntimeError("test did not release first spawn")
            context = {
                "schemaVersion": 2,
                "contextKind": "candidate-dispatch-v2",
                "operationId": action.operation_id,
                "candidateId": action.candidate_id,
                "controllerStartId": action.controller_start_id,
                "actionFingerprint": action.action_fingerprint,
                "dispatchReceiptFingerprint": (
                    dispatch_intent.receipt_fingerprint
                ),
            }
            DurableProcessOwnershipStoreV2(
                self.root / "codex-home"
            ).publish(
                TransientProcessLeaseV2(
                    lease_id="transient-" + "8" * 32,
                    label="candidate-controller",
                    pid=8124,
                    process_group_id=8124,
                    session_id=8124,
                    process_start_marker="first-owned-candidate",
                    process=SimpleNamespace(),
                ),
                context,
            )

        def forbidden_second_spawn(
            *, authorization, action, **_arguments
        ) -> None:
            authorization.consume_for(action)
            calls.append("second")
            second_entered_spawn.set()

        common = {
            "candidate_spawn_action": self.action,
            "codex_home": self.root / "codex-home",
            "state_home": self.state_home,
            "wrapper_path": self.root / "unused-wrapper",
            "readiness_token": self.token,
        }
        first = build_controller_candidate_spawn_step_port_v2(
            **common,
            spawn_primitive=publish_first_ownership,
            monotonic_ms=lambda: 1_000,
        )
        second = build_controller_candidate_spawn_step_port_v2(
            **common,
            spawn_primitive=forbidden_second_spawn,
            monotonic_ms=lambda: 1_002,
        )

        def apply(label: str, port) -> None:
            try:
                port.apply(definition)
            except CandidateReadyChannelV2Error as error:
                errors.append((label, error.code))

        first_thread = threading.Thread(target=apply, args=("first", first))
        second_thread = threading.Thread(target=apply, args=("second", second))
        first_thread.start()
        self.assertTrue(first_entered.wait(timeout=2.0))
        second_thread.start()
        duplicate_reached_spawn = second_entered_spawn.wait(timeout=0.5)
        release_first.set()
        first_thread.join(timeout=3.0)
        second_thread.join(timeout=3.0)

        self.assertFalse(duplicate_reached_spawn)
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertEqual(["first"], calls)
        self.assertEqual(
            [("second", "CANDIDATE_DISPATCH_OWNERSHIP_OUTSTANDING")],
            errors,
        )

    def test_dispatch_thread_lock_preserves_exact_root_deadline_and_releases(
        self,
    ) -> None:
        self._write_operation_journal()
        action = CandidateSpawnActionV2.from_mapping(self.action)
        holder_entered = threading.Event()
        release_holder = threading.Event()
        holder_errors: list[BaseException] = []

        def hold_dispatch_section() -> None:
            try:
                with candidate_module._candidate_dispatch_critical_section_v2(
                    codex_home=self.root / "codex-home",
                    action=action,
                ):
                    holder_entered.set()
                    if not release_holder.wait(timeout=2.0):
                        raise RuntimeError("test did not release dispatch holder")
            except BaseException as error:
                holder_errors.append(error)

        holder = threading.Thread(target=hold_dispatch_section)
        holder.start()
        self.assertTrue(holder_entered.wait(timeout=2.0))
        deadline = OperationDeadlineV2.start(
            operation="recover",
            timeout_seconds=0.05,
            timeout_code="ROOT_DISPATCH_DEADLINE",
        )
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2) as caught:
                    with candidate_module._candidate_dispatch_critical_section_v2(
                        codex_home=self.root / "codex-home",
                        action=action,
                    ):
                        self.fail("expired waiter entered the critical section")
        finally:
            release_holder.set()
            holder.join(timeout=3.0)

        self.assertEqual("ROOT_DISPATCH_DEADLINE", caught.exception.code)
        self.assertFalse(holder.is_alive())
        self.assertEqual([], holder_errors)
        with candidate_module._candidate_dispatch_critical_section_v2(
            codex_home=self.root / "codex-home",
            action=action,
        ):
            pass

    def test_dispatch_lock_close_failure_does_not_mask_primary_or_stick(
        self,
    ) -> None:
        self._write_operation_journal()
        action = CandidateSpawnActionV2.from_mapping(self.action)
        real_open = os.open
        real_close = os.close
        lock_descriptor: list[int] = []
        close_failed = False

        def recording_open(path, flags, *arguments, **keywords):
            descriptor = real_open(path, flags, *arguments, **keywords)
            if str(path).endswith(".lock") and flags & os.O_RDWR:
                lock_descriptor[:] = [descriptor]
            return descriptor

        def close_with_one_failure(descriptor: int) -> None:
            nonlocal close_failed
            if lock_descriptor == [descriptor] and not close_failed:
                close_failed = True
                real_close(descriptor)
                raise OSError("injected dispatch lock close failure")
            real_close(descriptor)

        with (
            patch.object(candidate_module.os, "open", side_effect=recording_open),
            patch.object(candidate_module.os, "close", side_effect=close_with_one_failure),
        ):
            with self.assertRaisesRegex(RuntimeError, "primary dispatch failure") as caught:
                with candidate_module._candidate_dispatch_critical_section_v2(
                    codex_home=self.root / "codex-home",
                    action=action,
                ):
                    raise RuntimeError("primary dispatch failure")

        self.assertTrue(close_failed)
        self.assertTrue(
            any(
                "dispatch lock descriptor close also failed" in note
                for note in getattr(caught.exception, "__notes__", ())
            )
        )
        with candidate_module._candidate_dispatch_critical_section_v2(
            codex_home=self.root / "codex-home",
            action=action,
        ):
            pass

    def test_monotonic_epoch_rollback_closes_attempt_without_extended_wait(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        create_candidate_dispatch_intent_receipt_v2(
            action=self.action,
            codex_home=self.root / "codex-home",
            monotonic_ms=lambda: 45_000,
        )
        sleeps: list[float] = []
        spawned: list[int] = []
        port = build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=self.action,
            codex_home=self.root / "codex-home",
            state_home=self.state_home,
            wrapper_path=self.root / "unused-wrapper",
            readiness_token=self.token,
            spawn_primitive=lambda **arguments: spawned.append(
                arguments["dispatch_intent"].created_at_monotonic_ms
            ),
            monotonic_ms=lambda: 1,
            sleeper=sleeps.append,
        )

        self.assertEqual(definition.before, port.observe(definition))
        port.apply(definition)

        self.assertEqual([], sleeps)
        self.assertEqual([1], spawned)
        self.assertEqual(
            1,
            load_candidate_dispatch_intent_receipt_v2(
                codex_home=self.root / "codex-home",
                action=self.action,
            ).created_at_monotonic_ms,
        )

    def test_completed_spawn_rehydrates_exact_receipt_after_accept_removed_ready_socket(
        self,
    ) -> None:
        definition = self._spawn_definition()
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="PLANNED")]
        )

        def fake_spawn(*, action, dispatch_intent, authorization, **_arguments):
            token = authorization.consume_for(action)
            self._start(
                action=action,
                dispatch_intent=dispatch_intent,
                readiness_token=token,
            )

        arguments = {
            "candidate_spawn_action": self.action,
            "codex_home": self.root / "codex-home",
            "state_home": self.state_home,
            "wrapper_path": self.root / "unused-wrapper",
            "spawn_primitive": fake_spawn,
            "process_start_marker_provider": lambda pid: (
                "test-marker-current-process" if pid == 4100 else "wrong"
            ),
        }
        port = build_controller_candidate_spawn_step_port_v2(
            readiness_token=self.token,
            **arguments,
        )
        port.observe(definition)
        self._write_operation_journal(
            steps=[self._journal_step(definition, state="INTENT_DURABLE")]
        )
        port.apply(definition)
        observed = port.observe(definition)
        receipt_path = candidate_registration_receipt_path_v2(
            codex_home=self.root / "codex-home",
            action=CandidateSpawnActionV2.from_mapping(self.action),
        )
        self.assertTrue(receipt_path.exists())

        receipt_document = json.loads(receipt_path.read_text(encoding="utf-8"))
        accept_after = self._projection(
            "controller-state-v2",
            {
                "controllerIdentity": observed.value["controllerIdentity"],
                "instanceId": "ci2_" + "c" * 32,
                "controllerStartId": observed.value["controllerStartId"],
                "pid": observed.value["pid"],
                "processStartMarker": observed.value["processStartMarker"],
                "processGroupId": observed.value["processGroupId"],
                "controlEpoch": 2,
                "state": "MAINTENANCE",
                "maintenanceMode": "freeze",
                "operationId": self.action["operationId"],
                "activationId": observed.value["activationId"],
                "activationFingerprint": observed.value[
                    "activationFingerprint"
                ],
                "databaseId": observed.value["databaseId"],
                "socket": receipt_document["workingControllerSocket"],
                "lockHeld": True,
                "acceptingNewRoutes": False,
                "quiescent": True,
            },
            "codex-smart/controller-state/v2",
        )
        accept_action = {
            "actionKind": "controller-command",
            "method": "controller_accept",
            "operationId": self.action["operationId"],
            "expectedControlEpoch": 1,
        }
        accept_step = {
            "stepId": "st2_" + "b" * 32,
            "kind": "controller_accept",
            "state": "INTENT_DURABLE",
            "action": accept_action,
            "actionFingerprint": domain_fingerprint(
                "codex-smart/step-action/v2", {"action": accept_action}
            ),
            "before": definition.expected_after.to_document(),
            "expectedAfter": accept_after.to_document(),
            "observedAfter": None,
        }
        self._write_operation_journal(
            steps=[
                self._journal_step(
                    definition,
                    state="COMPLETED",
                    observed_after=observed,
                ),
                accept_step,
            ]
        )
        self.channels[-1].mark_accepted()
        self.assertFalse(Path(self.action["privateReadyChannelPath"]).exists())

        missing_accept_recovery = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            accepted_controller_observer=lambda: None,
            **arguments,
        )
        with self.assertRaises(CandidateReadyChannelV2Error) as missing_error:
            missing_accept_recovery.observe(definition)
        self.assertEqual(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            missing_error.exception.code,
        )

        mismatched_value = dict(accept_after.value)
        mismatched_socket = dict(mismatched_value["socket"])
        mismatched_socket["inode"] = int(mismatched_socket["inode"]) + 1
        mismatched_value["socket"] = mismatched_socket
        mismatched_accept_after = self._projection(
            "controller-state-v2",
            mismatched_value,
            "codex-smart/controller-state/v2",
        )
        mismatched_recovery = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            accepted_controller_observer=lambda: mismatched_accept_after,
            **arguments,
        )
        with self.assertRaises(CandidateReadyChannelV2Error) as mismatch_error:
            mismatched_recovery.observe(definition)
        self.assertEqual(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            mismatch_error.exception.code,
        )

        foreign_identity_value = dict(accept_after.value)
        foreign_identity_value["controllerStartId"] = "cs2_" + "d" * 32
        foreign_identity = self._projection(
            "controller-state-v2",
            foreign_identity_value,
            "codex-smart/controller-state/v2",
        )
        foreign_recovery = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            accepted_controller_observer=lambda: foreign_identity,
            **arguments,
        )
        with self.assertRaises(CandidateReadyChannelV2Error) as foreign_error:
            foreign_recovery.observe(definition)
        self.assertEqual(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            foreign_error.exception.code,
        )

        bad_fingerprint = ProjectionV2(
            schema_id=accept_after.schema_id,
            schema_sha256=accept_after.schema_sha256,
            value=dict(accept_after.value),
            value_fingerprint="0" * 64,
        )
        fingerprint_recovery = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            accepted_controller_observer=lambda: bad_fingerprint,
            **arguments,
        )
        with self.assertRaises(CandidateReadyChannelV2Error) as fingerprint_error:
            fingerprint_recovery.observe(definition)
        self.assertEqual(
            "CANDIDATE_ACCEPTED_SUCCESSOR_INVALID",
            fingerprint_error.exception.code,
        )

        recovered = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            accepted_controller_observer=lambda: accept_after,
            **arguments,
        )
        historical = recovered.observe(definition)

        self.assertEqual(observed, historical)
        self.assertEqual(
            observed.to_document(),
            json.loads(receipt_path.read_text(encoding="utf-8"))[
                "registrationProjection"
            ],
        )

        accept_step["state"] = "COMPLETED"
        accept_step["observedAfter"] = accept_after.to_document()
        self._write_operation_journal(
            steps=[
                self._journal_step(
                    definition,
                    state="COMPLETED",
                    observed_after=observed,
                ),
                accept_step,
            ]
        )
        completed_recovery = build_controller_candidate_spawn_step_port_v2(
            readiness_token=None,
            **arguments,
        )
        self.assertEqual(observed, completed_recovery.observe(definition))


if __name__ == "__main__":
    unittest.main()
