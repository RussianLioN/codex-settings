from __future__ import annotations

import copy
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import (  # noqa: E402
    canonical_json_bytes,
    domain_fingerprint,
)
from codex_smart_subagents.lifecycle_controller_client_v2 import (  # noqa: E402
    LifecycleControllerClientV2,
    LifecycleControllerClientV2Error,
)
from codex_smart_subagents import (  # noqa: E402
    lifecycle_controller_client_v2 as client_module,
)
from codex_smart_subagents.lifecycle_controller_protocol_v2 import (  # noqa: E402
    LifecycleControllerQuiescenceV2,
    LifecycleControllerPortV2,
)
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)


OPERATION_ID = "op2_" + "1" * 32
CONTROLLER_IDENTITY = "2" * 64
INSTANCE_ID = "ci2_" + "3" * 32
CONTROLLER_START_ID = "cs2_" + "4" * 32
ACTIVATION_ID = "act2_" + "5" * 64
DATABASE_ID = "db2_" + "6" * 32
REQUEST_DOMAIN = "codex-smart/controller-request/v2"
RESULT_DOMAIN = "codex-smart/controller-command-result/v2"
RESPONSE_DOMAIN = "codex-smart/controller-response/v2"


class _ScriptedUnixServer:
    def __init__(self, path: Path, handler) -> None:
        self.path = path
        self.handler = handler
        self.requests: list[dict[str, object]] = []
        self.errors: list[BaseException] = []
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(path))
        os.chmod(path, 0o600)
        self._listener.listen(8)
        self._listener.settimeout(0.05)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                try:
                    raw = bytearray()
                    while b"\n" not in raw:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        raw.extend(chunk)
                    if not raw:
                        continue
                    request = __import__("json").loads(
                        bytes(raw).split(b"\n", 1)[0].decode("utf-8")
                    )
                    self.requests.append(request)
                    result = self.handler(copy.deepcopy(request), len(self.requests))
                    if result is None:
                        continue
                    encoded = (
                        result
                        if isinstance(result, bytes)
                        else canonical_json_bytes(result) + b"\n"
                    )
                    connection.sendall(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    continue
                except BaseException as exc:  # pragma: no cover - test diagnostics
                    self.errors.append(exc)

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)
        self.path.unlink(missing_ok=True)


def _response(
    request: dict[str, object],
    *,
    response_kind: str,
    control_epoch: int,
    payload: dict[str, object],
) -> dict[str, object]:
    projection = {
        "messageType": "response",
        "protocolVersion": 2,
        "release": "0.2.0",
        "method": request["method"],
        "responseKind": response_kind,
        "commandId": request["commandId"],
        "requestFingerprint": request["requestFingerprint"],
        "controlEpoch": control_epoch,
        "payload": copy.deepcopy(payload),
    }
    return {
        **projection,
        "responseFingerprint": domain_fingerprint(RESPONSE_DOMAIN, projection),
        "extensions": {},
    }


def _success(
    request: dict[str, object],
    *,
    status: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    previous = int(request["expectedControlEpoch"])
    base = {
        "status": status,
        "previousControlEpoch": previous,
        "newControlEpoch": previous + 1,
        **(extra or {}),
    }
    result_fingerprint = domain_fingerprint(
        RESULT_DOMAIN,
        {"method": request["method"], "payload": base},
    )
    payload = {
        **base,
        "commandReceipt": {
            "commandId": request["commandId"],
            "requestFingerprint": request["requestFingerprint"],
            "resultFingerprint": result_fingerprint,
            "controlEpoch": previous + 1,
        },
    }
    return _response(
        request,
        response_kind="SUCCESS",
        control_epoch=previous + 1,
        payload=payload,
    )


def _replay(
    request: dict[str, object],
    *,
    original: dict[str, object],
) -> dict[str, object]:
    original_payload = copy.deepcopy(original["payload"])
    return _response(
        request,
        response_kind="REPLAY_RECEIPT",
        control_epoch=int(original["controlEpoch"]),
        payload={
            "commandReceipt": copy.deepcopy(
                original_payload["commandReceipt"]
            ),
            "originalControlEpoch": original["controlEpoch"],
            "originalPayload": original_payload,
            "originalResponseFingerprint": original["responseFingerprint"],
        },
    )


def _status(
    request: dict[str, object],
    *,
    quiescent: bool,
    state: str | None = None,
) -> dict[str, object]:
    actual_state = state or ("MAINTENANCE" if quiescent else "DRAINING")
    return _response(
        request,
        response_kind="SUCCESS",
        control_epoch=int(request["expectedControlEpoch"]),
        payload={
            "state": actual_state,
            "maintenanceMode": "drain",
            "operationId": OPERATION_ID,
            "quiescent": quiescent,
        },
    )


def _socket_intent(socket_path: Path) -> dict[str, object]:
    return {
        "path": str(socket_path),
        "device": 1,
        "inode": 2,
        "ownerUid": os.getuid(),
        "ownerGid": os.getgid(),
        "mode": "0600",
        "controllerPid": os.getpid(),
        "controllerStartMarker": "marker",
        "controllerProcessGroupId": os.getpgrp(),
        "lockPath": str(socket_path.parent / "controller.lock"),
        "processExitRequired": True,
        "exclusiveLockRequired": True,
    }


class _FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class _DeadlineClock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += int(seconds * 1_000_000_000)


class LifecycleControllerClientV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cscc2-")
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.socket_path = self.root / "controller.sock"
        self.server: _ScriptedUnixServer | None = None

    def tearDown(self) -> None:
        if self.server is not None:
            self.server.close()
            self.assertEqual([], self.server.errors)
        self.temporary.cleanup()

    def _client(self, **overrides) -> LifecycleControllerClientV2:
        values = {
            "socket_path": self.socket_path,
            "codex_home": self.codex_home,
            "shell_session_id": "test-shell",
            "controller_identity": CONTROLLER_IDENTITY,
            "instance_id": INSTANCE_ID,
            "controller_start_id": CONTROLLER_START_ID,
            "control_epoch": 7,
            "connect_timeout_seconds": 0.5,
            "call_timeout_seconds": 0.5,
        }
        values.update(overrides)
        return LifecycleControllerClientV2(**values)

    def test_exchange_recomputes_one_call_deadline_before_every_socket_block(
        self,
    ) -> None:
        clock = _DeadlineClock()

        class TimedSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []
                self.responses = iter((b"{}", b"\n"))

            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def settimeout(self, timeout: float) -> None:
                self.timeouts.append(timeout)

            def connect(self, _path: str) -> None:
                clock.advance(0.4)

            def sendall(self, _payload: bytes) -> None:
                clock.advance(0.4)

            def recv(self, _maximum: int) -> bytes:
                clock.advance(0.05)
                return next(self.responses)

        connection = TimedSocket()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1.0,
            timeout_code="ROOT_OPERATION_EXPIRED",
            monotonic_ns=clock,
        )
        with (
            scoped_current_deadline_v2(deadline),
            patch.object(client_module, "_safe_socket", return_value=None),
            patch.object(client_module, "_peer_uid", return_value=os.getuid()),
            patch.object(client_module.socket, "socket", return_value=connection),
        ):
            client = self._client(
                connect_timeout_seconds=2.0,
                call_timeout_seconds=2.0,
            )
            self.assertEqual({}, client._exchange({"request": "status"}))

        self.assertGreaterEqual(len(connection.timeouts), 4)
        self.assertAlmostEqual(1.0, connection.timeouts[0], places=6)
        self.assertLessEqual(connection.timeouts[1], 0.600001)
        self.assertLessEqual(connection.timeouts[2], 0.200001)
        self.assertLessEqual(connection.timeouts[3], 0.150001)

    def test_exchange_rejects_response_completed_after_root_deadline(self) -> None:
        clock = _DeadlineClock()

        class LateSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args) -> None:
                return None

            def settimeout(self, _timeout: float) -> None:
                return None

            def connect(self, _path: str) -> None:
                clock.advance(0.3)

            def sendall(self, _payload: bytes) -> None:
                clock.advance(0.3)

            def recv(self, _maximum: int) -> bytes:
                clock.advance(0.5)
                return b"{}\n"

        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1.0,
            timeout_code="ROOT_OPERATION_EXPIRED",
            monotonic_ns=clock,
        )
        with (
            scoped_current_deadline_v2(deadline),
            patch.object(client_module, "_safe_socket", return_value=None),
            patch.object(client_module, "_peer_uid", return_value=os.getuid()),
            patch.object(client_module.socket, "socket", return_value=LateSocket()),
            self.assertRaises(OperationDeadlineExceededV2) as caught,
        ):
            client = self._client(
                connect_timeout_seconds=2.0,
                call_timeout_seconds=2.0,
            )
            client._exchange({"request": "status"})

        self.assertEqual(
            "ROOT_OPERATION_EXPIRED",
            getattr(caught.exception, "code", None),
        )

    def test_maintenance_begin_returns_strict_proof_and_advances_epoch(self) -> None:
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request, status="MAINTENANCE_BEGUN"
            ),
        )
        client = self._client()

        proof = client.maintenance_begin(
            operation_id=OPERATION_ID,
            reason_code="UPGRADE",
        )

        self.assertIsInstance(client, LifecycleControllerPortV2)
        self.assertEqual("maintenance_begin", proof.method)
        self.assertEqual("MAINTENANCE_BEGUN", proof.status)
        self.assertEqual(7, proof.previous_control_epoch)
        self.assertEqual(8, proof.new_control_epoch)
        self.assertEqual(8, client.control_epoch)
        self.assertRegex(proof.command_id, r"^cc2_[0-9a-f]{32}$")
        request = self.server.requests[0]
        self.assertEqual("UPGRADE", request["params"]["reasonCode"])
        projection = {
            key: request[key]
            for key in request
            if key not in {"requestFingerprint", "extensions"}
        }
        self.assertEqual(
            domain_fingerprint(REQUEST_DOMAIN, projection),
            request["requestFingerprint"],
        )

    def test_transport_ambiguity_reuses_random_command_id_and_rebuilds_proof(
        self,
    ) -> None:
        def handler(request, number):
            original = _success(request, status="MAINTENANCE_BEGUN")
            if number == 1:
                return None
            return _replay(request, original=original)

        self.server = _ScriptedUnixServer(self.socket_path, handler)
        client = self._client()

        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "TRANSPORT_FAILURE"
        ):
            client.maintenance_begin(
                operation_id=OPERATION_ID,
                reason_code="UPGRADE",
            )
        proof = client.maintenance_begin(
            operation_id=OPERATION_ID,
            reason_code="UPGRADE",
        )

        first, second = self.server.requests
        self.assertRegex(str(first["commandId"]), r"^cc2_[0-9a-f]{32}$")
        self.assertEqual(first["commandId"], second["commandId"])
        self.assertEqual(first["requestFingerprint"], second["requestFingerprint"])
        self.assertEqual("MAINTENANCE_BEGUN", proof.status)
        self.assertEqual(8, client.control_epoch)

    def test_shutdown_replay_preserves_socket_intent_and_clears_live_instance(
        self,
    ) -> None:
        def handler(request, number):
            original = _success(
                request,
                status="SHUTDOWN_COMMITTED",
                extra={"socketIntent": _socket_intent(self.socket_path)},
            )
            if number == 1:
                return None
            return _replay(request, original=original)

        self.server = _ScriptedUnixServer(self.socket_path, handler)
        client = self._client()

        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "TRANSPORT_FAILURE"
        ):
            client.shutdown(operation_id=OPERATION_ID)
        self.assertEqual(INSTANCE_ID, client.instance_id)

        proof = client.shutdown(operation_id=OPERATION_ID)

        self.assertEqual("SHUTDOWN_COMMITTED", proof.status)
        self.assertEqual(_socket_intent(self.socket_path), proof.payload["socketIntent"])
        self.assertIsNone(client.instance_id)
        self.assertEqual(8, client.control_epoch)

    def test_replay_with_tampered_original_payload_fails_closed(self) -> None:
        def handler(request, _number):
            original = _success(request, status="MAINTENANCE_BEGUN")
            replay = _replay(request, original=original)
            replay["payload"]["originalPayload"]["status"] = "MAINTENANCE_RESUMED"
            projection = {
                key: copy.deepcopy(value)
                for key, value in replay.items()
                if key not in {"responseFingerprint", "extensions"}
            }
            replay["responseFingerprint"] = domain_fingerprint(
                RESPONSE_DOMAIN, projection
            )
            return replay

        self.server = _ScriptedUnixServer(self.socket_path, handler)
        client = self._client()

        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "REPLAY_PROOF_UNAVAILABLE"
        ):
            client.maintenance_begin(
                operation_id=OPERATION_ID,
                reason_code="UPGRADE",
            )

        self.assertEqual(7, client.control_epoch)

    def test_restored_command_id_is_consumed_and_later_transition_gets_new_id(
        self,
    ) -> None:
        restored = "cc2_" + "9" * 32
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request, status="MAINTENANCE_RESUMED"
            ),
        )
        client = self._client(
            command_ids={(OPERATION_ID, "maintenance_resume"): restored}
        )

        first = client.maintenance_resume(operation_id=OPERATION_ID)
        second = client.maintenance_resume(operation_id=OPERATION_ID)

        self.assertEqual(restored, first.command_id)
        self.assertNotEqual(restored, second.command_id)
        self.assertNotEqual(first.command_id, second.command_id)
        self.assertEqual(9, client.control_epoch)

    def test_restored_command_id_does_not_invoke_factory_until_next_transition(
        self,
    ) -> None:
        restored = "cc2_" + "a" * 32
        generated = "cc2_" + "b" * 32
        calls: list[tuple[str, str]] = []

        def factory(operation_id: str, method: str) -> str:
            calls.append((operation_id, method))
            return generated

        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request, status="MAINTENANCE_RESUMED"
            ),
        )
        client = self._client(
            command_ids={(OPERATION_ID, "maintenance_resume"): restored},
            command_id_factory=factory,
        )

        first = client.maintenance_resume(operation_id=OPERATION_ID)
        self.assertEqual([], calls)
        second = client.maintenance_resume(operation_id=OPERATION_ID)

        self.assertEqual(restored, first.command_id)
        self.assertEqual(generated, second.command_id)
        self.assertEqual([(OPERATION_ID, "maintenance_resume")], calls)

    def test_wait_quiescent_polls_and_returns_observed_quiescent_status(self) -> None:
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, number: _status(request, quiescent=number >= 2),
        )
        clock = _FakeClock()
        client = self._client(
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
            poll_interval_seconds=0.05,
        )

        observed = client.wait_quiescent(
            operation_id=OPERATION_ID,
            timeout_seconds=0.2,
        )

        self.assertTrue(observed.quiescent)
        self.assertEqual("MAINTENANCE", observed.state)
        self.assertEqual("drain", observed.maintenance_mode)
        self.assertEqual(7, observed.control_epoch)
        self.assertEqual(2, len(self.server.requests))
        self.assertTrue(
            all(request["method"] == "maintenance_status" for request in self.server.requests)
        )
        self.assertTrue(all(request["commandId"] is None for request in self.server.requests))

    def test_wait_quiescent_returns_factual_last_status_at_timeout(self) -> None:
        clock = _FakeClock()
        client = self._client(
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
            poll_interval_seconds=0.05,
        )
        status = LifecycleControllerQuiescenceV2(
            operation_id=OPERATION_ID,
            state="DRAINING",
            maintenance_mode="drain",
            control_epoch=7,
            quiescent=False,
        )

        with patch.object(
            client,
            "_maintenance_status",
            return_value=status,
        ) as maintenance_status:
            observed = client.wait_quiescent(
                operation_id=OPERATION_ID,
                timeout_seconds=0.1,
            )

        self.assertFalse(observed.quiescent)
        self.assertEqual("DRAINING", observed.state)
        self.assertEqual(OPERATION_ID, observed.operation_id)
        self.assertGreaterEqual(maintenance_status.call_count, 2)

    def test_candidate_accept_updates_nullable_instance_fence(self) -> None:
        new_instance = "ci2_" + "c" * 32
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request,
                status="CONTROLLER_ACCEPTED",
                extra={
                    "controllerIdentity": CONTROLLER_IDENTITY,
                    "instanceId": new_instance,
                    "controllerStartId": CONTROLLER_START_ID,
                },
            ),
        )
        client = self._client(instance_id=None)

        proof = client.candidate_accept(
            operation_id=OPERATION_ID,
            activation_id=ACTIVATION_ID,
            database_id=DATABASE_ID,
            pid=os.getpid(),
            process_start_marker="marker",
            process_group_id=os.getpgrp(),
        )

        self.assertEqual(new_instance, client.instance_id)
        self.assertEqual(8, client.control_epoch)
        self.assertEqual(new_instance, proof.payload["instanceId"])
        self.assertIsNone(self.server.requests[0]["instanceId"])

    def test_candidate_recover_uses_distinct_method_and_updates_instance(self) -> None:
        new_instance = "ci2_" + "d" * 32
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request,
                status="CONTROLLER_RECOVERED",
                extra={
                    "controllerIdentity": CONTROLLER_IDENTITY,
                    "instanceId": new_instance,
                    "controllerStartId": CONTROLLER_START_ID,
                },
            ),
        )
        client = self._client(instance_id=None)

        proof = client.candidate_recover(
            operation_id=OPERATION_ID,
            activation_id=ACTIVATION_ID,
            database_id=DATABASE_ID,
            pid=os.getpid(),
            process_start_marker="marker",
            process_group_id=os.getpgrp(),
        )

        self.assertEqual("controller_recover", proof.method)
        self.assertEqual("CONTROLLER_RECOVERED", proof.status)
        self.assertEqual(new_instance, client.instance_id)
        self.assertEqual("controller_recover", self.server.requests[0]["method"])

    def test_candidate_recover_rebuilds_replayed_proof(self) -> None:
        new_instance = "ci2_" + "e" * 32

        def handler(request, number):
            original = _success(
                request,
                status="CONTROLLER_RECOVERED",
                extra={
                    "controllerIdentity": CONTROLLER_IDENTITY,
                    "instanceId": new_instance,
                    "controllerStartId": CONTROLLER_START_ID,
                },
            )
            if number == 1:
                return None
            return _replay(request, original=original)

        self.server = _ScriptedUnixServer(self.socket_path, handler)
        client = self._client(instance_id=None)
        arguments = {
            "operation_id": OPERATION_ID,
            "activation_id": ACTIVATION_ID,
            "database_id": DATABASE_ID,
            "pid": os.getpid(),
            "process_start_marker": "marker",
            "process_group_id": os.getpgrp(),
        }

        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "TRANSPORT_FAILURE"
        ):
            client.candidate_recover(**arguments)
        proof = client.candidate_recover(**arguments)

        self.assertEqual("CONTROLLER_RECOVERED", proof.status)
        self.assertEqual(new_instance, client.instance_id)
        self.assertEqual(
            self.server.requests[0]["commandId"],
            self.server.requests[1]["commandId"],
        )

    def test_candidate_recover_rejects_accept_status(self) -> None:
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request,
                status="CONTROLLER_ACCEPTED",
                extra={
                    "controllerIdentity": CONTROLLER_IDENTITY,
                    "instanceId": "ci2_" + "f" * 32,
                    "controllerStartId": CONTROLLER_START_ID,
                },
            ),
        )
        client = self._client(instance_id=None)

        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "INVALID_RESPONSE"
        ):
            client.candidate_recover(
                operation_id=OPERATION_ID,
                activation_id=ACTIVATION_ID,
                database_id=DATABASE_ID,
                pid=os.getpid(),
                process_start_marker="marker",
                process_group_id=os.getpgrp(),
            )

        self.assertIsNone(client.instance_id)
        self.assertEqual(7, client.control_epoch)

    def test_shutdown_requires_strict_socket_intent_before_clearing_instance(self) -> None:
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request,
                status="SHUTDOWN_COMMITTED",
                extra={"socketIntent": {"path": str(self.socket_path)}},
            ),
        )
        client = self._client()

        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "INVALID_RESPONSE"
        ):
            client.shutdown(operation_id=OPERATION_ID)

        self.assertEqual(INSTANCE_ID, client.instance_id)
        self.assertEqual(7, client.control_epoch)

    def test_remote_error_is_typed_and_invalid_category_code_pair_is_rejected(
        self,
    ) -> None:
        def handler(request, number):
            if number == 1:
                payload = {
                    "category": "UNAVAILABLE",
                    "code": "EXTERNAL_PROCESS_STILL_RUNNING",
                    "message": "ещё есть работа",
                    "retryable": True,
                }
            else:
                payload = {
                    "category": "INVALID",
                    "code": "CONTROL_EPOCH_MISMATCH",
                    "message": "ложная пара",
                    "retryable": False,
                }
            return _response(
                request,
                response_kind="ERROR",
                control_epoch=7,
                payload=payload,
            )

        self.server = _ScriptedUnixServer(self.socket_path, handler)
        client = self._client()

        with self.assertRaises(LifecycleControllerClientV2Error) as caught:
            client.maintenance_strengthen(operation_id=OPERATION_ID)
        self.assertEqual("EXTERNAL_PROCESS_STILL_RUNNING", caught.exception.code)
        self.assertEqual("UNAVAILABLE", caught.exception.category)
        self.assertTrue(caught.exception.retryable)
        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "INVALID_RESPONSE"
        ):
            client.maintenance_strengthen(operation_id=OPERATION_ID)

    def test_successful_strengthen_and_shutdown_advance_and_clear_live_fence(self) -> None:
        def handler(request, _number):
            if request["method"] == "maintenance_strengthen":
                return _success(request, status="MAINTENANCE_STRENGTHENED")
            return _success(
                request,
                status="SHUTDOWN_COMMITTED",
                extra={"socketIntent": _socket_intent(self.socket_path)},
            )

        self.server = _ScriptedUnixServer(self.socket_path, handler)
        client = self._client()

        strengthened = client.maintenance_strengthen(operation_id=OPERATION_ID)
        shutdown = client.shutdown(operation_id=OPERATION_ID)

        self.assertEqual((7, 8), (
            strengthened.previous_control_epoch,
            strengthened.new_control_epoch,
        ))
        self.assertEqual((8, 9), (
            shutdown.previous_control_epoch,
            shutdown.new_control_epoch,
        ))
        self.assertEqual(9, client.control_epoch)
        self.assertIsNone(client.instance_id)

    def test_command_id_factory_must_not_reuse_completed_command_id(self) -> None:
        duplicate = "cc2_" + "d" * 32
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request,
                status=(
                    "MAINTENANCE_BEGUN"
                    if request["method"] == "maintenance_begin"
                    else "MAINTENANCE_STRENGTHENED"
                ),
            ),
        )
        client = self._client(
            command_id_factory=lambda _operation_id, _method: duplicate
        )

        client.maintenance_begin(operation_id=OPERATION_ID, reason_code="UPGRADE")
        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "COMMAND_ID_SOURCE_INVALID"
        ):
            client.maintenance_strengthen(operation_id=OPERATION_ID)

        self.assertEqual(1, len(self.server.requests))

    def test_duplicate_restored_command_ids_are_rejected(self) -> None:
        duplicate = "cc2_" + "e" * 32
        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "COMMAND_ID_SOURCE_INVALID"
        ):
            self._client(
                command_ids={
                    (OPERATION_ID, "maintenance_begin"): duplicate,
                    (OPERATION_ID, "maintenance_strengthen"): duplicate,
                }
            )

    def test_local_request_validation_uses_client_error_contract(self) -> None:
        client = self._client()

        with self.assertRaises(LifecycleControllerClientV2Error) as caught:
            client.maintenance_begin(
                operation_id=OPERATION_ID,
                reason_code="",
            )

        self.assertEqual("INVALID_REQUEST", caught.exception.code)
        self.assertEqual("INVALID", caught.exception.category)

    def test_response_fingerprint_peer_uid_and_message_limit_fail_closed(self) -> None:
        def bad_fingerprint(request, _number):
            response = _success(request, status="MAINTENANCE_BEGUN")
            response["responseFingerprint"] = "0" * 64
            return response

        self.server = _ScriptedUnixServer(self.socket_path, bad_fingerprint)
        client = self._client()
        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "RESPONSE_FINGERPRINT_MISMATCH"
        ):
            client.maintenance_begin(operation_id=OPERATION_ID, reason_code="UPGRADE")
        self.server.close()
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda _request, _number: b"x" * (1024 * 1024 + 1),
        )
        client = self._client()
        with self.assertRaisesRegex(
            LifecycleControllerClientV2Error, "MESSAGE_TOO_LARGE"
        ):
            client.maintenance_begin(operation_id=OPERATION_ID, reason_code="UPGRADE")
        self.server.close()
        self.server = _ScriptedUnixServer(
            self.socket_path,
            lambda request, _number: _success(
                request, status="MAINTENANCE_BEGUN"
            ),
        )
        client = self._client()
        with patch(
            "codex_smart_subagents.lifecycle_controller_client_v2._peer_uid",
            return_value=os.getuid() + 1,
        ):
            with self.assertRaisesRegex(
                LifecycleControllerClientV2Error, "PEER_UID_MISMATCH"
            ):
                client.maintenance_begin(
                    operation_id=OPERATION_ID, reason_code="UPGRADE"
                )


if __name__ == "__main__":
    unittest.main()
