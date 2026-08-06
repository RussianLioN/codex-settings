from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    _unix_controller_probe,
    _validate_health_response,
)
from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    system_process_start_marker_v2,
)
from codex_smart_subagents.controller_health_v2 import (  # noqa: E402
    _ACTIVE_SOCKETS,
    MAX_MESSAGE_BYTES,
    ControllerHealthServerV2,
    ControllerHealthV2Error,
    ControllerRegistrationReceiptV2,
)
from codex_smart_subagents.coordinator_selection_v2 import (  # noqa: E402
    collect_coordinator_selection_v2,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerProtocolV2,
    LifecycleControllerProtocolV2Error,
    build_lifecycle_controller_request_v2,
)
from codex_smart_subagents.lifecycle_controller_client_v2 import (  # noqa: E402
    LifecycleControllerClientV2,
    LifecycleControllerClientV2Error,
)
from codex_smart_subagents.model_catalog import ModelCatalogError  # noqa: E402
from codex_smart_subagents.state_store_v2 import (  # noqa: E402
    AcceptingControllerV2,
    DatabaseIdentityV2,
    SmartStoreV2,
)


NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)


class _LifecycleWaitingExecutor:
    """Моделирует принятого работника, ожидающего lifecycle-блокировку."""

    def __init__(self, lifecycle_lock: threading.RLock) -> None:
        self._lifecycle_lock = lifecycle_lock
        self.blocked_during_shutdown = False
        self.worker_finished = threading.Event()
        self._worker: threading.Thread | None = None

    def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
        if wait is not True or cancel_futures is not True:
            raise AssertionError("close должен ограниченно дождаться работников")

        def finish_inflight_request() -> None:
            with self._lifecycle_lock:
                self.worker_finished.set()

        self._worker = threading.Thread(target=finish_inflight_request)
        self._worker.start()
        self._worker.join(timeout=0.2)
        self.blocked_during_shutdown = self._worker.is_alive()

    def join_worker(self) -> None:
        if self._worker is not None:
            self._worker.join(timeout=1.0)


class ControllerHealthServerV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.socket_path = self.root / "controller.sock"
        self.lock_path = self.root / "controller.lock"
        self.database_path = self.root / "state-v2.sqlite3"
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.root / "state-home"
        self.state_home.mkdir(mode=0o700)
        self.database_identity = DatabaseIdentityV2(
            database_id="db2_" + "a" * 32,
            activation_binding_nonce="b" * 64,
            activation_id="act2_" + "c" * 64,
            activation_fingerprint="d" * 64,
            created_operation_id="op2_" + "e" * 32,
            created_at=NOW,
        )
        self.instance_id = "ci2_" + "f" * 32
        self.controller_start_id = "cs2_" + "1" * 32
        self.compatibility_fingerprint = "2" * 64
        self.routing_policy_fingerprint = "3" * 64
        self.bundled_catalog_fingerprint = "4" * 64
        self.coordinator_selection = collect_coordinator_selection_v2(
            selection="first-verified-available",
            candidates=(
                {
                    "model": "gpt-5.6-sol",
                    "reasoningEffort": "medium",
                },
            ),
            inspector=type(
                "_CoordinatorInspector",
                (),
                {
                    "inspect": lambda _self: {
                        "gpt-5.6-sol": frozenset({"medium"})
                    }
                },
            )(),
            active_context_fingerprint=self.database_identity.activation_fingerprint,
        )
        self.store: SmartStoreV2 | None = None
        self.server: ControllerHealthServerV2 | None = None
        self.thread: threading.Thread | None = None

    def tearDown(self) -> None:
        if self.server is not None:
            self.server.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        if self.store is not None:
            self.store.close()
        self.temporary.cleanup()

    def _registrar(
        self,
        controller: AcceptingControllerV2,
    ) -> ControllerRegistrationReceiptV2:
        self.store = SmartStoreV2(
            self.database_path,
            database_identity=self.database_identity,
            controller=controller,
        )
        return ControllerRegistrationReceiptV2(
            database_path=self.database_path,
            cleanup=self.store.close,
        )

    def _new_server(
        self,
        *,
        registrar=None,
        io_timeout_seconds: float = 1.0,
        control_epoch: int = 7,
    ):
        return ControllerHealthServerV2(
            socket_path=self.socket_path,
            lock_path=self.lock_path,
            codex_home=self.codex_home,
            state_home=self.state_home,
            database_id=self.database_identity.database_id,
            activation_id=self.database_identity.activation_id,
            activation_fingerprint=self.database_identity.activation_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
            routing_policy_fingerprint=self.routing_policy_fingerprint,
            bundled_catalog_fingerprint=self.bundled_catalog_fingerprint,
            coordinator_selection=self.coordinator_selection,
            instance_id=self.instance_id,
            controller_start_id=self.controller_start_id,
            control_epoch=control_epoch,
            registrar=registrar or self._registrar,
            clock=lambda: NOW,
            io_timeout_seconds=io_timeout_seconds,
        )

    def _start_server(self, *, registrar=None, io_timeout_seconds: float = 1.0):
        self.server = self._new_server(
            registrar=registrar,
            io_timeout_seconds=io_timeout_seconds,
        )
        controller = self.server.start()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.assertTrue(self.server.wait_until_ready(0.2))
        return controller

    def _health_request(self) -> dict[str, object]:
        projection: dict[str, object] = {
            "messageType": "request",
            "protocolVersion": 2,
            "release": "0.2.0",
            "codexHomeHash": hashlib.sha256(
                str(self.codex_home.resolve()).encode("utf-8")
            ).hexdigest(),
            "shellSessionId": "gateway-v2",
            "controllerIdentity": None,
            "instanceId": None,
            "controllerStartId": None,
            "commandId": None,
            "expectedControlEpoch": None,
            "operationId": None,
            "method": "health",
            "params": {},
        }
        return {
            **projection,
            "requestFingerprint": domain_fingerprint(
                "codex-smart/controller-request/v2", projection
            ),
            "extensions": {},
        }

    def _raw_exchange(self, value: bytes, *, timeout: float = 2.0) -> bytes:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(str(self.socket_path))
            connection.sendall(value)
            chunks: list[bytes] = []
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                if b"\n" in chunk:
                    return b"".join(chunks)

    def test_real_health_matches_gateway_probe_after_database_registration(
        self,
    ) -> None:
        controller = self._start_server()

        socket_info = self.socket_path.lstat()
        self.assertEqual(0o600, socket_info.st_mode & 0o777)
        self.assertEqual(os.getpid(), controller.controller_pid)
        self.assertEqual(
            system_process_start_marker_v2(os.getpid()),
            controller.controller_process_start_marker,
        )
        self.assertEqual(socket_info.st_dev, controller.socket_device)
        self.assertEqual(socket_info.st_ino, controller.socket_inode)

        request = self._health_request()
        started = time.monotonic()
        response = _unix_controller_probe(self.socket_path, request)
        self.assertLess(time.monotonic() - started, 0.5)
        _validate_health_response(response, request=request)

        self.assertEqual(7, response["controlEpoch"])
        payload = response["payload"]
        self.assertEqual(controller.controller_identity, payload["controllerIdentity"])
        self.assertEqual(self.database_identity.database_id, payload["databaseId"])
        self.assertEqual(self.instance_id, payload["instanceId"])
        self.assertEqual(self.controller_start_id, payload["controllerStartId"])
        self.assertFalse(payload["quiescent"])
        self.assertEqual(
            {
                "nonterminalRoutes": 0,
                "nonterminalNodes": 0,
                "activeAttempts": 0,
                "activeLeases": 0,
                "openIntents": 0,
                "inflightLaunchPermits": 0,
                "activeRuntimeArtifacts": 0,
                "pendingCandidatePublications": 0,
                "activeEvidenceJobs": 0,
                "queuedEvidenceJobs": 0,
            },
            payload["workCounts"],
        )
        self.assertEqual(
            self.coordinator_selection.to_document(),
            payload["coordinatorSelection"],
        )

        tampered = copy.deepcopy(response)
        tampered["payload"]["coordinatorSelection"]["candidateIndex"] = 1
        with self.assertRaisesRegex(
            ValueError,
            "health response fingerprint differs",
        ):
            _validate_health_response(tampered, request=request)

    def test_catalog_recovery_atomically_replaces_health_selection(self) -> None:
        self._start_server()
        recovered = collect_coordinator_selection_v2(
            selection="first-verified-available",
            candidates=(
                {"model": "gpt-5.6-terra", "reasoningEffort": "medium"},
            ),
            inspector=type(
                "_RecoveredInspector",
                (),
                {
                    "inspect": lambda _self: {
                        "gpt-5.6-terra": frozenset({"medium"})
                    }
                },
            )(),
            active_context_fingerprint=self.database_identity.activation_fingerprint,
        )

        assert self.server is not None
        self.server.publish_coordinator_selection(recovered)
        request = self._health_request()
        response = _unix_controller_probe(self.socket_path, request)
        _validate_health_response(response, request=request)

        self.assertEqual(
            recovered.to_document(),
            response["payload"]["coordinatorSelection"],
        )

    def test_catalog_refresh_diagnostics_share_one_atomic_health_snapshot(self) -> None:
        self._start_server()
        unavailable = collect_coordinator_selection_v2(
            selection="first-verified-available",
            candidates=(
                {"model": "gpt-5.6-sol", "reasoningEffort": "medium"},
            ),
            inspector=type(
                "_UnavailableInspector",
                (),
                {
                    "inspect": lambda _self: (_ for _ in ()).throw(
                        ModelCatalogError("MODEL_LIST_UNAVAILABLE", "temporary")
                    )
                },
            )(),
            active_context_fingerprint=self.database_identity.activation_fingerprint,
        )
        diagnostics = {
            "status": "UNAVAILABLE",
            "reasonCode": "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            "lastSuccessfulCheckAt": None,
            "nextAttemptAt": "2026-08-06T09:00:05.000000Z",
        }

        assert self.server is not None
        self.server.publish_coordinator_refresh(unavailable, diagnostics)
        request = self._health_request()
        response = _unix_controller_probe(self.socket_path, request)
        _validate_health_response(response, request=request)

        self.assertEqual(
            unavailable.to_document(),
            response["payload"]["coordinatorSelection"],
        )
        self.assertEqual(
            {"coordinatorRefresh": diagnostics},
            response["extensions"],
        )

    def test_gateway_rejects_unproven_catalog_refresh_extension(self) -> None:
        self._start_server()
        request = self._health_request()
        response = _unix_controller_probe(self.socket_path, request)
        response["extensions"] = {
            "coordinatorRefresh": {
                "status": "SELECTED",
                "reasonCode": "/private/tmp/catalog-error",
                "lastSuccessfulCheckAt": "not-a-time",
                "nextAttemptAt": None,
            }
        }

        with self.assertRaisesRegex(ValueError, "refresh diagnostics"):
            _validate_health_response(response, request=request)

    def test_owned_codex_home_mode_0755_is_accepted(self) -> None:
        self.codex_home.chmod(0o755)

        controller = self._start_server()

        self.assertEqual(self.instance_id, controller.instance_id)
        self.assertEqual(0o700, self.state_home.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.socket_path.lstat().st_mode & 0o777)

    def test_close_waits_for_workers_outside_lifecycle_lock(self) -> None:
        self.server = self._new_server()
        self.server.start()
        self.server._executor.shutdown(wait=True, cancel_futures=True)
        executor = _LifecycleWaitingExecutor(self.server._lifecycle_lock)
        self.server._executor = executor

        self.server.close()
        executor.join_worker()

        self.assertFalse(executor.blocked_during_shutdown)
        self.assertTrue(executor.worker_finished.is_set())
        self.assertFalse(self.socket_path.exists())

    def test_ready_is_withheld_when_reverse_database_binding_differs(self) -> None:
        cleanup_called = False

        def mismatched_registrar(
            controller: AcceptingControllerV2,
        ) -> ControllerRegistrationReceiptV2:
            nonlocal cleanup_called
            self.store = SmartStoreV2(
                self.database_path,
                database_identity=self.database_identity,
                controller=replace(controller, control_epoch=8),
            )

            def cleanup() -> None:
                nonlocal cleanup_called
                cleanup_called = True
                assert self.store is not None
                self.store.close()

            return ControllerRegistrationReceiptV2(
                database_path=self.database_path,
                cleanup=cleanup,
            )

        self.server = self._new_server(registrar=mismatched_registrar)
        with self.assertRaisesRegex(
            ControllerHealthV2Error,
            "CONTROLLER_BINDING_MISMATCH",
        ):
            self.server.start()

        self.assertFalse(self.server.wait_until_ready(0))
        self.assertFalse(self.socket_path.exists())
        self.assertTrue(cleanup_called)

    def test_ready_is_withheld_when_database_parent_becomes_shared(self) -> None:
        def shared_parent_registrar(
            controller: AcceptingControllerV2,
        ) -> ControllerRegistrationReceiptV2:
            receipt = self._registrar(controller)
            self.root.chmod(0o755)
            return receipt

        self.server = self._new_server(registrar=shared_parent_registrar)
        try:
            with self.assertRaisesRegex(ControllerHealthV2Error, "UNSAFE_DATABASE"):
                self.server.start()
        finally:
            self.root.chmod(0o700)

        self.assertFalse(self.server.wait_until_ready(0))

    def test_non_health_and_invalid_fingerprint_are_closed_without_response(
        self,
    ) -> None:
        self._start_server()
        request = self._health_request()
        request["method"] = "shutdown"
        request["requestFingerprint"] = "0" * 64
        self.assertEqual(
            b"",
            self._raw_exchange(canonical_json_bytes(request) + b"\n"),
        )

    def test_controller_socket_serves_durable_lifecycle_and_dynamic_health(
        self,
    ) -> None:
        controller = self._start_server()
        assert self.server is not None
        protocol = LifecycleControllerProtocolV2(
            database_path=self.database_path,
            codex_home=self.codex_home,
            controller_lock_path=self.lock_path,
            clock=lambda: NOW,
        )
        self.server.bind_lifecycle_handler(protocol.handle)
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="maintenance_begin",
            controller_identity=controller.controller_identity,
            instance_id=controller.instance_id,
            controller_start_id=controller.controller_start_id,
            command_id="cc2_" + "a" * 32,
            expected_control_epoch=controller.control_epoch,
            operation_id="op2_" + "b" * 32,
            params={"reasonCode": "UPGRADE"},
        )

        lifecycle_raw = self._raw_exchange(canonical_json_bytes(request) + b"\n")
        lifecycle = json.loads(lifecycle_raw)
        health = _unix_controller_probe(self.socket_path, self._health_request())

        self.assertEqual("SUCCESS", lifecycle["responseKind"])
        self.assertEqual("MAINTENANCE_BEGUN", lifecycle["payload"]["status"])
        self.assertEqual(8, lifecycle["controlEpoch"])
        self.assertEqual(8, health["controlEpoch"])
        self.assertEqual("MAINTENANCE", health["payload"]["state"])
        self.assertEqual("drain", health["payload"]["maintenanceMode"])
        self.assertEqual("op2_" + "b" * 32, health["payload"]["operationId"])
        self.assertFalse(health["payload"]["acceptingNewRoutes"])
        self.assertTrue(health["payload"]["quiescent"])

        request = self._health_request()
        request["requestFingerprint"] = "0" * 64
        self.assertEqual(
            b"",
            self._raw_exchange(canonical_json_bytes(request) + b"\n"),
        )

    def test_valid_lifecycle_rejection_returns_bound_structured_error(self) -> None:
        controller = self._start_server()
        assert self.server is not None
        protocol = LifecycleControllerProtocolV2(
            database_path=self.database_path,
            codex_home=self.codex_home,
            controller_lock_path=self.lock_path,
            clock=lambda: NOW,
        )
        self.server.bind_lifecycle_handler(protocol.handle)
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="maintenance_begin",
            controller_identity=controller.controller_identity,
            instance_id=controller.instance_id,
            controller_start_id=controller.controller_start_id,
            command_id="cc2_" + "d" * 32,
            expected_control_epoch=controller.control_epoch + 1,
            operation_id="op2_" + "e" * 32,
            params={"reasonCode": "UPGRADE"},
        )

        raw = self._raw_exchange(canonical_json_bytes(request) + b"\n")
        response = json.loads(raw)

        self.assertEqual("ERROR", response["responseKind"])
        self.assertEqual(request["method"], response["method"])
        self.assertEqual(request["commandId"], response["commandId"])
        self.assertEqual(
            request["requestFingerprint"], response["requestFingerprint"]
        )
        self.assertEqual(controller.control_epoch, response["controlEpoch"])
        self.assertEqual(
            {
                "category": "STALE",
                "code": "CONTROL_EPOCH_MISMATCH",
                "message": "эпоха управления изменилась",
                "retryable": True,
            },
            response["payload"],
        )
        projection = {
            key: item
            for key, item in response.items()
            if key not in {"responseFingerprint", "extensions"}
        }
        self.assertEqual(
            domain_fingerprint("codex-smart/controller-response/v2", projection),
            response["responseFingerprint"],
        )
        health = _unix_controller_probe(self.socket_path, self._health_request())
        self.assertEqual(controller.control_epoch, health["controlEpoch"])
        self.assertEqual("ACCEPTING", health["payload"]["state"])

        client = LifecycleControllerClientV2(
            socket_path=self.socket_path,
            codex_home=self.codex_home,
            shell_session_id="installer-client-v2",
            controller_identity=controller.controller_identity,
            instance_id=controller.instance_id,
            controller_start_id=controller.controller_start_id,
            control_epoch=controller.control_epoch + 1,
            connect_timeout_seconds=0.5,
            call_timeout_seconds=0.5,
        )
        with self.assertRaises(LifecycleControllerClientV2Error) as captured:
            client.maintenance_begin(
                operation_id="op2_" + "f" * 32,
                reason_code="UPGRADE",
            )
        self.assertEqual("CONTROL_EPOCH_MISMATCH", captured.exception.code)
        self.assertEqual("STALE", captured.exception.category)
        self.assertTrue(captured.exception.retryable)
        self.assertEqual(controller.control_epoch, captured.exception.control_epoch)

    def test_unlisted_protocol_failure_is_sanitized_as_internal_error(self) -> None:
        controller = self._start_server()
        assert self.server is not None

        def reject(_request):
            raise LifecycleControllerProtocolV2Error(
                code="DATABASE_UNAVAILABLE",
                message="private database detail",
                category="INTERNAL",
                retryable=True,
            )

        self.server.bind_lifecycle_handler(reject)
        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="maintenance_begin",
            controller_identity=controller.controller_identity,
            instance_id=controller.instance_id,
            controller_start_id=controller.controller_start_id,
            command_id="cc2_" + "7" * 32,
            expected_control_epoch=controller.control_epoch,
            operation_id="op2_" + "8" * 32,
            params={"reasonCode": "UPGRADE"},
        )

        response = json.loads(
            self._raw_exchange(canonical_json_bytes(request) + b"\n")
        )

        self.assertEqual("ERROR", response["responseKind"])
        self.assertEqual(
            {
                "category": "INTERNAL",
                "code": "INTERNAL_ERROR",
                "message": "внутренняя ошибка управляющего протокола",
                "retryable": False,
            },
            response["payload"],
        )
        self.assertNotIn("private database detail", json.dumps(response))

    def test_candidate_channel_becomes_ready_only_after_durable_accept(self) -> None:
        operation_id = "op2_" + "9" * 32
        projection = {
            "protocolVersion": 2,
            "release": "0.2.0",
            "namespace": "codex-smart-subagents-v2",
            "codexHomeHash": hashlib.sha256(
                str(self.codex_home.resolve()).encode("utf-8")
            ).hexdigest(),
            "stateHome": str(self.state_home),
            "activationFingerprint": self.database_identity.activation_fingerprint,
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "routingPolicyFingerprint": self.routing_policy_fingerprint,
            "bundledCatalogFingerprint": self.bundled_catalog_fingerprint,
            "databaseId": self.database_identity.database_id,
            "databaseSchemaVersion": 2,
        }
        controller_identity = domain_fingerprint(
            "codex-smart/controller-identity/v2", projection
        )
        provisional = AcceptingControllerV2(
            controller_identity=controller_identity,
            instance_id=self.instance_id,
            controller_start_id=self.controller_start_id,
            controller_pid=os.getpid(),
            controller_process_start_marker=system_process_start_marker_v2(os.getpid()),
            controller_process_group_id=os.getpgrp(),
            control_epoch=1,
            activation_id=self.database_identity.activation_id,
            activation_fingerprint=self.database_identity.activation_fingerprint,
            compatibility_fingerprint=self.compatibility_fingerprint,
            routing_policy_fingerprint=self.routing_policy_fingerprint,
            bundled_catalog_fingerprint=self.bundled_catalog_fingerprint,
            socket_path=str(self.socket_path),
            socket_device=0,
            socket_inode=0,
            socket_owner_uid=os.getuid(),
            socket_owner_gid=os.getgid(),
            socket_mode="0600",
            updated_at=NOW,
        )
        store = SmartStoreV2(
            self.database_path,
            database_identity=self.database_identity,
            controller=provisional,
        )
        store.close()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "update controller_state set state='MAINTENANCE',"
                "maintenance_mode='FREEZE',reason_code='AWAITING_CONTROLLER_ACCEPT',"
                "operation_id=?,instance_id=null,controller_start_id=null,"
                "controller_pid=null,controller_process_start_marker=null,"
                "controller_process_group_id=null,socket_path=null,socket_device=null,"
                "socket_inode=null,socket_owner_uid=null,socket_owner_gid=null,"
                "socket_mode=null,lock_held=0,accepting_new_routes=0,quiescent=1 "
                "where singleton=1",
                (operation_id,),
            )
            connection.commit()

        self.server = self._new_server(control_epoch=1)
        candidate = self.server.start_candidate(database_path=self.database_path)
        protocol = LifecycleControllerProtocolV2(
            database_path=self.database_path,
            codex_home=self.codex_home,
            controller_lock_path=self.lock_path,
            clock=lambda: NOW,
        )
        self.server.bind_lifecycle_handler(protocol.handle)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.assertFalse(self.server.wait_until_ready(0))

        request = build_lifecycle_controller_request_v2(
            codex_home=self.codex_home,
            shell_session_id="installer-v2",
            method="controller_accept",
            controller_identity=candidate.controller_identity,
            instance_id=None,
            controller_start_id=candidate.controller_start_id,
            command_id="cc2_" + "8" * 32,
            expected_control_epoch=1,
            operation_id=operation_id,
            params={
                "activationId": self.database_identity.activation_id,
                "databaseId": self.database_identity.database_id,
                "pid": os.getpid(),
                "processStartMarker": system_process_start_marker_v2(os.getpid()),
                "processGroupId": os.getpgrp(),
            },
        )
        response = json.loads(self._raw_exchange(canonical_json_bytes(request) + b"\n"))

        self.assertEqual("CONTROLLER_ACCEPTED", response["payload"]["status"])
        self.assertTrue(self.server.wait_until_ready(0.2))
        health = _unix_controller_probe(self.socket_path, self._health_request())
        self.assertEqual(2, health["controlEpoch"])
        self.assertEqual(
            response["payload"]["instanceId"], health["payload"]["instanceId"]
        )

    def test_shell_session_limit_uses_protocol_characters_not_utf8_bytes(self) -> None:
        self._start_server()
        request = self._health_request()
        request["shellSessionId"] = "я" * 256
        projection = {
            key: item
            for key, item in request.items()
            if key not in {"requestFingerprint", "extensions"}
        }
        request["requestFingerprint"] = domain_fingerprint(
            "codex-smart/controller-request/v2", projection
        )

        response = self._raw_exchange(canonical_json_bytes(request) + b"\n")

        self.assertTrue(response.endswith(b"\n"))

    def test_database_epoch_drift_is_detected_before_response(self) -> None:
        self._start_server()
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "update controller_state set control_epoch=8 where singleton=1"
            )
            connection.commit()

        self.assertEqual(
            b"",
            self._raw_exchange(canonical_json_bytes(self._health_request()) + b"\n"),
        )

    def test_partial_request_is_closed_at_bounded_read_deadline(self) -> None:
        self._start_server(io_timeout_seconds=0.05)
        started = time.monotonic()
        self.assertEqual(b"", self._raw_exchange(b'{"messageType":', timeout=1.0))
        self.assertLess(time.monotonic() - started, 0.5)

    def test_expensive_database_projection_is_interrupted_before_client_deadline(
        self,
    ) -> None:
        self._start_server()
        expensive = (
            "with recursive cnt(x) as (values(0) union all "
            "select x+1 from cnt where x<500000) select sum(x) from cnt"
        )
        with (
            patch(
                "codex_smart_subagents.controller_health_v2."
                "HEALTH_DATABASE_DEADLINE_SECONDS",
                0.005,
                create=True,
            ),
            patch.dict(
                "codex_smart_subagents.controller_health_v2._QUIESCENCE_QUERIES",
                {"nonterminalRoutes": expensive},
            ),
        ):
            started = time.monotonic()
            response = self._raw_exchange(
                canonical_json_bytes(self._health_request()) + b"\n",
                timeout=1.0,
            )

        self.assertEqual(b"", response)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_request_limit_includes_the_line_terminator(self) -> None:
        self._start_server()
        encoded = canonical_json_bytes(self._health_request())
        oversized = encoded + b" " * (MAX_MESSAGE_BYTES - len(encoded)) + b"\n"

        self.assertEqual(MAX_MESSAGE_BYTES + 1, len(oversized))
        self.assertEqual(b"", self._raw_exchange(oversized))

    def test_close_removes_only_owned_socket_and_releases_registration(self) -> None:
        cleanup_called = False

        def registrar(
            controller: AcceptingControllerV2,
        ) -> ControllerRegistrationReceiptV2:
            nonlocal cleanup_called
            receipt = self._registrar(controller)

            def cleanup() -> None:
                nonlocal cleanup_called
                cleanup_called = True
                receipt.cleanup()

            return ControllerRegistrationReceiptV2(
                database_path=receipt.database_path,
                cleanup=cleanup,
            )

        self._start_server(registrar=registrar)
        neighbour = self.root / "keep-me"
        neighbour.write_text("kept", encoding="utf-8")

        assert self.server is not None
        self.server.close()
        assert self.thread is not None
        self.thread.join(timeout=2)

        self.assertFalse(self.thread.is_alive())
        self.assertFalse(self.socket_path.exists())
        self.assertTrue(cleanup_called)
        self.assertEqual("kept", neighbour.read_text(encoding="utf-8"))

    def test_unsafe_existing_socket_path_is_preserved(self) -> None:
        self.socket_path.write_text("not a socket", encoding="utf-8")
        self.server = self._new_server()

        with self.assertRaisesRegex(ControllerHealthV2Error, "UNSAFE_EXISTING_SOCKET"):
            self.server.start()

        self.assertEqual("not a socket", self.socket_path.read_text(encoding="utf-8"))

    def test_failed_second_owner_does_not_release_the_first_owners_claim(self) -> None:
        self._start_server()
        second = self._new_server()
        try:
            with self.assertRaisesRegex(
                ControllerHealthV2Error,
                "CONTROLLER_ALREADY_RUNNING",
            ):
                second.start()
        finally:
            second.close()

        self.assertIn(str(self.socket_path), _ACTIVE_SOCKETS)
        response = _unix_controller_probe(self.socket_path, self._health_request())
        self.assertEqual("HEALTH", response["responseKind"])

    def test_failed_socket_claim_removes_the_socket_it_just_bound(self) -> None:
        self.server = self._new_server()
        with (
            patch(
                "codex_smart_subagents.controller_health_v2.os.chmod",
                side_effect=OSError("chmod failed"),
            ),
            self.assertRaisesRegex(OSError, "chmod failed"),
        ):
            self.server.start()

        self.assertFalse(os.path.lexists(self.socket_path))

    def test_runtime_path_accepts_a_platform_symlink_in_an_ancestor(self) -> None:
        real_parent = self.root / "a"
        real_parent.mkdir(mode=0o700)
        runtime = real_parent / "r"
        runtime.mkdir(mode=0o700)
        alias = self.root / "b"
        alias.symlink_to(real_parent, target_is_directory=True)
        self.socket_path = alias / "r" / "c.sock"
        self.lock_path = alias / "r" / "c.lock"

        controller = self._start_server()

        self.assertEqual(str(self.socket_path), controller.socket_path)
        self.assertTrue(self.socket_path.is_socket())


if __name__ == "__main__":
    unittest.main()
