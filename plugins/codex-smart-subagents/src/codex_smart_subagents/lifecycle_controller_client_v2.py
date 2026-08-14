"""Закрытый Unix-клиент управляющего протокола контроллера версии 2."""

from __future__ import annotations

import copy
import ctypes
import json
import os
import re
import secrets
import socket
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .canonical_json import CanonicalJsonError, canonical_json_bytes, domain_fingerprint
from . import operation_deadline_v2
from .lifecycle_controller_protocol_v2 import (
    LifecycleControllerCommandProofV2,
    LifecycleControllerQuiescenceV2,
    LifecycleControllerProtocolV2Error,
    build_lifecycle_controller_request_v2,
    build_lifecycle_controller_status_request_v2,
)


_RELEASE = "0.2.0"
_RESPONSE_DOMAIN = "codex-smart/controller-response/v2"
_RESULT_DOMAIN = "codex-smart/controller-command-result/v2"
_MAX_MESSAGE_BYTES = 1024 * 1024
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_COMMAND_ID = re.compile(r"^cc2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_CONTROLLER_IDENTITY = re.compile(r"^[0-9a-f]{64}$")
_INSTANCE_ID = re.compile(r"^ci2_[0-9a-f]{32}$")
_CONTROLLER_START_ID = re.compile(r"^cs2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESPONSE_KEYS = {
    "messageType",
    "protocolVersion",
    "release",
    "method",
    "responseKind",
    "commandId",
    "requestFingerprint",
    "controlEpoch",
    "payload",
    "responseFingerprint",
    "extensions",
}
_COMMAND_STATUS = {
    "maintenance_begin": "MAINTENANCE_BEGUN",
    "maintenance_strengthen": "MAINTENANCE_STRENGTHENED",
    "shutdown": "SHUTDOWN_COMMITTED",
    "controller_accept": "CONTROLLER_ACCEPTED",
    "controller_recover": "CONTROLLER_RECOVERED",
    "maintenance_resume": "MAINTENANCE_RESUMED",
}
_REMOTE_CODES_BY_CATEGORY = {
    "CONFLICT": {
        "COMMAND_REPLAY_CONFLICT",
        "CONTROLLER_OPERATION_CONFLICT",
    },
    "STALE": {
        "CONTROL_EPOCH_MISMATCH",
        "CONTROLLER_INSTANCE_MISMATCH",
        "ACCOUNT_CONTEXT_CHANGED",
        "ACTIVATION_GATE_CHANGED",
        "START_REQUEST_STALE",
    },
    "UNAVAILABLE": {
        "ADAPTIVE_ACTIVATION_UNCOMMITTED",
        "ACCOUNT_EVIDENCE_UNAVAILABLE",
        "EXTERNAL_PROCESS_STILL_RUNNING",
    },
    "INVALID": {
        "INVALID_TRANSITION",
        "ACCOUNT_EVIDENCE_NOT_SUCCEEDED",
        "START_REQUEST_OWNERSHIP_MISMATCH",
    },
    "INTERNAL": {"INTERNAL_ERROR"},
}
_SOCKET_INTENT_KEYS = {
    "path",
    "device",
    "inode",
    "ownerUid",
    "ownerGid",
    "mode",
    "controllerPid",
    "controllerStartMarker",
    "controllerProcessGroupId",
    "lockPath",
    "processExitRequired",
    "exclusiveLockRequired",
}


@dataclass
class LifecycleControllerClientV2Error(RuntimeError):
    code: str
    message: str
    category: str = "INVALID"
    retryable: bool = False
    control_epoch: int | None = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class _PendingCommand:
    request: Mapping[str, object]


CommandIdFactoryV2 = Callable[[str, str], str]


class LifecycleControllerClientV2:
    """Хранит ограждение одного управляющего канала и строго проверяет ответы."""

    def __init__(
        self,
        *,
        socket_path: Path,
        codex_home: Path,
        shell_session_id: str,
        controller_identity: str,
        instance_id: str | None,
        controller_start_id: str,
        control_epoch: int,
        command_ids: Mapping[tuple[str, str], str] | None = None,
        command_id_factory: CommandIdFactoryV2 | None = None,
        connect_timeout_seconds: float = 1.0,
        call_timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        monotonic: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.socket_path = _absolute_path(socket_path, "SOCKET_PATH_INVALID")
        self.codex_home = _absolute_directory(codex_home)
        if not isinstance(shell_session_id, str) or not shell_session_id or len(shell_session_id) > 256:
            _fail("SHELL_SESSION_ID_INVALID", "shellSessionId неверен")
        _identifier(controller_identity, _CONTROLLER_IDENTITY, "CONTROLLER_IDENTITY_INVALID")
        if instance_id is not None:
            _identifier(instance_id, _INSTANCE_ID, "INSTANCE_ID_INVALID")
        _identifier(controller_start_id, _CONTROLLER_START_ID, "CONTROLLER_START_ID_INVALID")
        _epoch(control_epoch)
        _timeout(connect_timeout_seconds, 5.0, "CONNECT_TIMEOUT_INVALID")
        _timeout(call_timeout_seconds, 65.0, "CALL_TIMEOUT_INVALID")
        _timeout(poll_interval_seconds, 5.0, "POLL_INTERVAL_INVALID")
        if command_id_factory is not None and not callable(command_id_factory):
            raise TypeError("command_id_factory must be callable")
        if monotonic is not None and not callable(monotonic):
            raise TypeError("monotonic must be callable")
        if sleeper is not None and not callable(sleeper):
            raise TypeError("sleeper must be callable")
        restored: dict[tuple[str, str], str] = {}
        for key, value in dict(command_ids or {}).items():
            if (
                type(key) is not tuple
                or len(key) != 2
                or _OPERATION_ID.fullmatch(str(key[0])) is None
                or key[1] not in _COMMAND_STATUS
            ):
                _fail("COMMAND_ID_SOURCE_INVALID", "ключ восстановленного commandId неверен")
            restored_id = _identifier(
                value, _COMMAND_ID, "COMMAND_ID_SOURCE_INVALID"
            )
            if restored_id in restored.values():
                _fail(
                    "COMMAND_ID_SOURCE_INVALID",
                    "восстановленные commandId должны быть уникальны",
                )
            restored[(str(key[0]), str(key[1]))] = restored_id
        self.shell_session_id = shell_session_id
        self.controller_identity = controller_identity
        self.instance_id = instance_id
        self.controller_start_id = controller_start_id
        self.control_epoch = control_epoch
        self.connect_timeout_seconds = float(connect_timeout_seconds)
        self.call_timeout_seconds = float(call_timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self._command_ids = restored
        self._command_id_factory = command_id_factory or (
            lambda _operation_id, _method: "cc2_" + secrets.token_hex(16)
        )
        self._pending: dict[tuple[str, str], _PendingCommand] = {}
        self._used_command_ids: set[str] = set()
        self._monotonic = monotonic or time.monotonic
        self._sleeper = sleeper or time.sleep

    def maintenance_begin(
        self, *, operation_id: str, reason_code: str
    ) -> LifecycleControllerCommandProofV2:
        return self._command(
            operation_id=operation_id,
            method="maintenance_begin",
            params={"reasonCode": reason_code},
        )

    def maintenance_strengthen(
        self, *, operation_id: str
    ) -> LifecycleControllerCommandProofV2:
        return self._command(
            operation_id=operation_id,
            method="maintenance_strengthen",
            params={"mode": "freeze"},
        )

    def wait_quiescent(
        self, *, operation_id: str, timeout_seconds: float
    ) -> LifecycleControllerQuiescenceV2:
        operation_id = _identifier(
            operation_id, _OPERATION_ID, "OPERATION_ID_INVALID"
        )
        _timeout(timeout_seconds, 60.0, "QUIESCENCE_TIMEOUT_INVALID")
        operation_deadline = (
            operation_deadline_v2.current_operation_deadline_v2()
        )
        bounded_timeout = float(timeout_seconds)
        if operation_deadline is not None:
            bounded_timeout = operation_deadline.bounded_timeout_seconds(
                local_cap_seconds=bounded_timeout
            )
        deadline = self._monotonic() + bounded_timeout
        while True:
            if operation_deadline is not None:
                operation_deadline.checkpoint()
            remaining = max(deadline - self._monotonic(), 0.001)
            status = self._maintenance_status(timeout_seconds=remaining)
            if status.operation_id != operation_id:
                _fail(
                    "CONTROLLER_OPERATION_MISMATCH",
                    "контроллер сообщает другую операцию обслуживания",
                    category="STALE",
                    control_epoch=status.control_epoch,
                )
            if status.quiescent or self._monotonic() >= deadline:
                return status
            sleep_seconds = min(
                self.poll_interval_seconds,
                max(deadline - self._monotonic(), 0.0),
            )
            if operation_deadline is not None:
                operation_deadline.checkpoint()
                sleep_seconds = min(
                    sleep_seconds, operation_deadline.remaining_seconds()
                )
            self._sleeper(sleep_seconds)

    def shutdown(
        self, *, operation_id: str
    ) -> LifecycleControllerCommandProofV2:
        proof = self._command(
            operation_id=operation_id,
            method="shutdown",
            params={},
        )
        self.instance_id = None
        return proof

    def candidate_accept(
        self,
        *,
        operation_id: str,
        expected_orphan_operation_id: str | None = None,
        activation_id: str,
        database_id: str,
        pid: int,
        process_start_marker: str,
        process_group_id: int,
    ) -> LifecycleControllerCommandProofV2:
        return self._command(
            operation_id=operation_id,
            method="controller_accept",
            params={
                "activationId": activation_id,
                "databaseId": database_id,
                "pid": pid,
                "processStartMarker": process_start_marker,
                "processGroupId": process_group_id,
                "expectedOrphanOperationId": expected_orphan_operation_id,
            },
        )

    def candidate_recover(
        self,
        *,
        operation_id: str,
        activation_id: str,
        database_id: str,
        pid: int,
        process_start_marker: str,
        process_group_id: int,
    ) -> LifecycleControllerCommandProofV2:
        return self._command(
            operation_id=operation_id,
            method="controller_recover",
            params={
                "activationId": activation_id,
                "databaseId": database_id,
                "pid": pid,
                "processStartMarker": process_start_marker,
                "processGroupId": process_group_id,
            },
        )

    def maintenance_resume(
        self, *, operation_id: str
    ) -> LifecycleControllerCommandProofV2:
        return self._command(
            operation_id=operation_id,
            method="maintenance_resume",
            params={},
        )

    def _maintenance_status(
        self, *, timeout_seconds: float
    ) -> LifecycleControllerQuiescenceV2:
        if self.instance_id is None:
            _fail(
                "CONTROLLER_INSTANCE_MISSING",
                "опрос состояния требует живой instanceId",
                category="STALE",
            )
        try:
            request = build_lifecycle_controller_status_request_v2(
                codex_home=self.codex_home,
                shell_session_id=self.shell_session_id,
                controller_identity=self.controller_identity,
                instance_id=self.instance_id,
                controller_start_id=self.controller_start_id,
                expected_control_epoch=self.control_epoch,
            )
        except LifecycleControllerProtocolV2Error as exc:
            raise LifecycleControllerClientV2Error(
                exc.code, exc.message, exc.category, exc.retryable
            ) from exc
        response = _validate_response_envelope(
            self._exchange(request, timeout_seconds=timeout_seconds),
            request=request,
        )
        if response["responseKind"] == "ERROR":
            _raise_remote(response)
        if response["responseKind"] != "SUCCESS":
            _fail("INVALID_RESPONSE", "вид ответа maintenance_status неверен")
        payload = response["payload"]
        if type(payload) is not dict or set(payload) != {
            "state", "maintenanceMode", "operationId", "quiescent"
        }:
            _fail("INVALID_RESPONSE", "поля maintenance_status отличаются")
        state = payload["state"]
        mode = payload["maintenanceMode"]
        operation_id = payload["operationId"]
        valid_combination = (
            state == "ACCEPTING" and mode is None and operation_id is None
        ) or (
            state == "DRAINING"
            and mode == "drain"
            and type(operation_id) is str
            and _OPERATION_ID.fullmatch(operation_id) is not None
        ) or (
            state == "MAINTENANCE"
            and mode in {"drain", "freeze"}
            and type(operation_id) is str
            and _OPERATION_ID.fullmatch(operation_id) is not None
        )
        if (
            not valid_combination
            or type(payload["quiescent"]) is not bool
            or response["controlEpoch"] != self.control_epoch
        ):
            _fail("INVALID_RESPONSE", "maintenance_status нарушает договор")
        return LifecycleControllerQuiescenceV2(
            operation_id=str(operation_id or ""),
            state=str(state),
            maintenance_mode=str(mode or "NONE"),
            control_epoch=int(response["controlEpoch"]),
            quiescent=bool(payload["quiescent"]),
        )

    def _command(
        self,
        *,
        operation_id: str,
        method: str,
        params: Mapping[str, object],
    ) -> LifecycleControllerCommandProofV2:
        operation_id = _identifier(
            operation_id, _OPERATION_ID, "OPERATION_ID_INVALID"
        )
        key = (operation_id, method)
        pending = self._pending.get(key)
        if pending is None:
            if key in self._command_ids:
                command_id = self._command_ids.pop(key)
            else:
                command_id = self._command_id_factory(operation_id, method)
            command_id = _identifier(
                command_id, _COMMAND_ID, "COMMAND_ID_SOURCE_INVALID"
            )
            if (
                command_id in self._used_command_ids
                or command_id in self._command_ids.values()
            ):
                _fail(
                    "COMMAND_ID_SOURCE_INVALID",
                    "commandId уже использован или зарезервирован",
                )
            self._used_command_ids.add(command_id)
            try:
                request = build_lifecycle_controller_request_v2(
                    codex_home=self.codex_home,
                    shell_session_id=self.shell_session_id,
                    method=method,
                    controller_identity=self.controller_identity,
                    instance_id=self.instance_id,
                    controller_start_id=self.controller_start_id,
                    command_id=command_id,
                    expected_control_epoch=self.control_epoch,
                    operation_id=operation_id,
                    params=params,
                )
            except LifecycleControllerProtocolV2Error as exc:
                raise LifecycleControllerClientV2Error(
                    exc.code, exc.message, exc.category, exc.retryable
                ) from exc
            pending = _PendingCommand(request=copy.deepcopy(request))
            self._pending[key] = pending
        elif pending.request["params"] != dict(params):
            _fail(
                "COMMAND_RETRY_MISMATCH",
                "повтор незавершённой команды изменил параметры",
                category="CONFLICT",
            )
        request = dict(pending.request)
        response = self._exchange(request)
        proof = self._command_proof(request, response)
        self._pending.pop(key, None)
        self.control_epoch = proof.new_control_epoch
        if method in {"controller_accept", "controller_recover"}:
            self.instance_id = str(proof.payload["instanceId"])
        return proof

    def _command_proof(
        self,
        request: Mapping[str, object],
        response: Mapping[str, object],
    ) -> LifecycleControllerCommandProofV2:
        value = _validate_response_envelope(response, request=request)
        kind = value["responseKind"]
        replayed = False
        if kind == "ERROR":
            self._pending.pop(
                (str(request["operationId"]), str(request["method"])), None
            )
            _raise_remote(value)
        if kind == "REPLAY_RECEIPT":
            value = _reconstruct_replayed_success(value, request=request)
            kind = "SUCCESS"
            replayed = True
        if kind != "SUCCESS":
            _fail("INVALID_RESPONSE", "вид ответа управляющей команды неверен")
        try:
            payload = value["payload"]
            expected_status = _COMMAND_STATUS[str(request["method"])]
            expected_base = {
                "maintenance_begin": {
                    "status", "previousControlEpoch", "newControlEpoch", "commandReceipt"
                },
                "maintenance_strengthen": {
                    "status", "previousControlEpoch", "newControlEpoch", "commandReceipt"
                },
                "maintenance_resume": {
                    "status", "previousControlEpoch", "newControlEpoch", "commandReceipt"
                },
                "shutdown": {
                    "status", "previousControlEpoch", "newControlEpoch", "socketIntent", "commandReceipt"
                },
                "controller_accept": {
                    "status", "previousControlEpoch", "newControlEpoch", "controllerIdentity",
                    "instanceId", "controllerStartId", "commandReceipt"
                },
                "controller_recover": {
                    "status", "previousControlEpoch", "newControlEpoch", "controllerIdentity",
                    "instanceId", "controllerStartId", "commandReceipt"
                },
            }[str(request["method"])]
            if type(payload) is not dict or set(payload) != expected_base:
                _fail("INVALID_RESPONSE", "поля результата команды отличаются")
            previous = request["expectedControlEpoch"]
            if (
                payload["status"] != expected_status
                or payload["previousControlEpoch"] != previous
                or payload["newControlEpoch"] != int(previous) + 1
                or value["controlEpoch"] != int(previous) + 1
            ):
                _fail("INVALID_RESPONSE", "переход эпохи или статус ответа отличаются")
            _validate_receipt(payload["commandReceipt"], request=request, response=value)
            if request["method"] == "shutdown":
                _validate_socket_intent(payload["socketIntent"], socket_path=self.socket_path)
            if request["method"] in {"controller_accept", "controller_recover"}:
                if (
                    payload["controllerIdentity"] != self.controller_identity
                    or payload["controllerStartId"] != self.controller_start_id
                    or type(payload["instanceId"]) is not str
                    or _INSTANCE_ID.fullmatch(payload["instanceId"]) is None
                ):
                    _fail("INVALID_RESPONSE", "идентичность принятого контроллера отличается")
            return LifecycleControllerCommandProofV2(
                method=str(request["method"]),
                status=expected_status,
                command_id=str(request["commandId"]),
                request_fingerprint=str(request["requestFingerprint"]),
                response_fingerprint=str(value["responseFingerprint"]),
                previous_control_epoch=int(previous),
                new_control_epoch=int(value["controlEpoch"]),
                payload=copy.deepcopy(payload),
            )
        except LifecycleControllerClientV2Error as exc:
            if replayed:
                _replay_unavailable(
                    "восстановленный исходный ответ не прошёл строгую проверку",
                    control_epoch=int(value["controlEpoch"]),
                )
            raise exc

    def _exchange(
        self,
        request: Mapping[str, object],
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        encoded = canonical_json_bytes(dict(request)) + b"\n"
        if len(encoded) > _MAX_MESSAGE_BYTES:
            _fail("MESSAGE_TOO_LARGE", "запрос превышает 1 МиБ")
        _safe_socket(self.socket_path)
        call_timeout = self.call_timeout_seconds
        connect_timeout = self.connect_timeout_seconds
        if timeout_seconds is not None:
            call_timeout = min(call_timeout, max(timeout_seconds, 0.001))
            connect_timeout = min(connect_timeout, max(timeout_seconds, 0.001))
        operation_deadline = (
            operation_deadline_v2.current_operation_deadline_v2()
        )
        if operation_deadline is not None:
            operation_deadline.checkpoint()
            call_deadline = operation_deadline.child(
                phase="lifecycle-controller-exchange",
                max_seconds=call_timeout,
                timeout_code="CONTROLLER_TRANSPORT_TIMEOUT",
            )
        else:
            call_deadline = operation_deadline_v2.OperationDeadlineV2.start(
                operation="lifecycle-controller-exchange",
                timeout_seconds=call_timeout,
                timeout_code="CONTROLLER_TRANSPORT_TIMEOUT",
            )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                _set_socket_deadline_timeout(
                    connection,
                    deadline=call_deadline,
                    local_cap_seconds=connect_timeout,
                )
                connection.connect(str(self.socket_path))
                if _peer_uid(connection) != os.getuid():
                    _fail("PEER_UID_MISMATCH", "управляющий сокет принадлежит другому uid")
                _set_socket_deadline_timeout(
                    connection,
                    deadline=call_deadline,
                    local_cap_seconds=call_timeout,
                )
                connection.sendall(encoded)
                return _read_response(
                    connection,
                    deadline=call_deadline,
                    local_cap_seconds=call_timeout,
                )
        except LifecycleControllerClientV2Error:
            raise
        except TimeoutError as exc:
            if operation_deadline is not None:
                operation_deadline.checkpoint()
            raise LifecycleControllerClientV2Error(
                "TRANSPORT_TIMEOUT", "истёк срок ответа управляющего сокета",
                category="UNAVAILABLE", retryable=True,
            ) from exc
        except OSError as exc:
            raise LifecycleControllerClientV2Error(
                "TRANSPORT_FAILURE", "обмен с управляющим сокетом не завершён",
                category="UNAVAILABLE", retryable=True,
            ) from exc


def _validate_response_envelope(
    response: Mapping[str, object],
    *,
    request: Mapping[str, object],
) -> dict[str, object]:
    if type(response) is not dict or set(response) != _RESPONSE_KEYS:
        _fail("INVALID_RESPONSE", "набор полей ответа отличается")
    value = copy.deepcopy(dict(response))
    if (
        value["messageType"] != "response"
        or value["protocolVersion"] != 2
        or value["release"] != _RELEASE
        or value["method"] != request["method"]
        or value["commandId"] != request["commandId"]
        or value["requestFingerprint"] != request["requestFingerprint"]
        or value["responseKind"] not in {"SUCCESS", "ERROR", "REPLAY_RECEIPT"}
        or type(value["controlEpoch"]) is not int
        or not 1 <= int(value["controlEpoch"]) <= _MAX_SAFE_INTEGER
        or type(value["payload"]) is not dict
        or type(value["extensions"]) is not dict
        or len(value["extensions"]) > 128
        or type(value["responseFingerprint"]) is not str
        or _SHA256.fullmatch(value["responseFingerprint"]) is None
    ):
        _fail("INVALID_RESPONSE", "константы или привязка ответа отличаются")
    projection = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"responseFingerprint", "extensions"}
    }
    if value["responseFingerprint"] != domain_fingerprint(
        _RESPONSE_DOMAIN, projection
    ):
        _fail("RESPONSE_FINGERPRINT_MISMATCH", "responseFingerprint не совпал")
    return value


def _validate_receipt(
    receipt: object,
    *,
    request: Mapping[str, object],
    response: Mapping[str, object],
) -> None:
    if type(receipt) is not dict or set(receipt) != {
        "commandId", "requestFingerprint", "resultFingerprint", "controlEpoch"
    }:
        _fail("INVALID_RESPONSE", "поля квитанции команды отличаются")
    if (
        receipt["commandId"] != request["commandId"]
        or receipt["requestFingerprint"] != request["requestFingerprint"]
        or receipt["controlEpoch"] != response["controlEpoch"]
        or type(receipt["resultFingerprint"]) is not str
        or _SHA256.fullmatch(receipt["resultFingerprint"]) is None
    ):
        _fail("INVALID_RESPONSE", "привязка квитанции команды отличается")
    base = {
        key: copy.deepcopy(item)
        for key, item in response["payload"].items()
        if key != "commandReceipt"
    }
    expected = domain_fingerprint(
        _RESULT_DOMAIN, {"method": request["method"], "payload": base}
    )
    if receipt["resultFingerprint"] != expected:
        _fail("RESULT_FINGERPRINT_MISMATCH", "resultFingerprint не совпал")


def _reconstruct_replayed_success(
    response: Mapping[str, object], *, request: Mapping[str, object]
) -> dict[str, object]:
    payload = response["payload"]
    if type(payload) is not dict or set(payload) != {
        "commandReceipt",
        "originalControlEpoch",
        "originalPayload",
        "originalResponseFingerprint",
    }:
        _replay_unavailable(
            "поля квитанции повтора отличаются",
            control_epoch=int(response["controlEpoch"]),
        )
    receipt = payload["commandReceipt"]
    original_payload = payload["originalPayload"]
    if (
        type(receipt) is not dict
        or set(receipt) != {
            "commandId", "requestFingerprint", "resultFingerprint", "controlEpoch"
        }
        or receipt["commandId"] != request["commandId"]
        or receipt["requestFingerprint"] != request["requestFingerprint"]
        or receipt["controlEpoch"] != response["controlEpoch"]
        or payload["originalControlEpoch"] != response["controlEpoch"]
        or type(original_payload) is not dict
        or original_payload.get("commandReceipt") != receipt
        or type(receipt["resultFingerprint"]) is not str
        or _SHA256.fullmatch(receipt["resultFingerprint"]) is None
        or type(payload["originalResponseFingerprint"]) is not str
        or _SHA256.fullmatch(payload["originalResponseFingerprint"]) is None
    ):
        _replay_unavailable(
            "квитанция повтора не привязана к исходному ответу",
            control_epoch=int(response["controlEpoch"]),
        )
    projection = {
        "messageType": "response",
        "protocolVersion": 2,
        "release": _RELEASE,
        "method": request["method"],
        "responseKind": "SUCCESS",
        "commandId": request["commandId"],
        "requestFingerprint": request["requestFingerprint"],
        "controlEpoch": payload["originalControlEpoch"],
        "payload": copy.deepcopy(original_payload),
    }
    if domain_fingerprint(_RESPONSE_DOMAIN, projection) != payload[
        "originalResponseFingerprint"
    ]:
        _replay_unavailable(
            "отпечаток исходного ответа повтора не совпал",
            control_epoch=int(response["controlEpoch"]),
        )
    original = {
        **projection,
        "responseFingerprint": payload["originalResponseFingerprint"],
        "extensions": {},
    }
    try:
        return _validate_response_envelope(original, request=request)
    except LifecycleControllerClientV2Error:
        _replay_unavailable(
            "исходный ответ повтора нарушает envelope",
            control_epoch=int(response["controlEpoch"]),
        )


def _replay_unavailable(message: str, *, control_epoch: int) -> None:
    _fail(
        "REPLAY_PROOF_UNAVAILABLE",
        message,
        category="STALE",
        control_epoch=control_epoch,
    )


def _raise_remote(response: Mapping[str, object]) -> None:
    payload = response["payload"]
    if type(payload) is not dict or set(payload) != {
        "category", "code", "message", "retryable"
    }:
        _fail("INVALID_RESPONSE", "поля удалённой ошибки отличаются")
    if (
        payload["category"] not in _REMOTE_CODES_BY_CATEGORY
        or type(payload["code"]) is not str
        or payload["code"] not in _REMOTE_CODES_BY_CATEGORY.get(payload["category"], set())
        or type(payload["message"]) is not str
        or not 1 <= len(payload["message"]) <= 1024
        or type(payload["retryable"]) is not bool
    ):
        _fail("INVALID_RESPONSE", "удалённая ошибка неверна")
    raise LifecycleControllerClientV2Error(
        code=payload["code"],
        message=payload["message"],
        category=payload["category"],
        retryable=payload["retryable"],
        control_epoch=int(response["controlEpoch"]),
    )


def _validate_socket_intent(value: object, *, socket_path: Path) -> None:
    if type(value) is not dict or set(value) != _SOCKET_INTENT_KEYS:
        _fail("INVALID_RESPONSE", "поля намерения остановки отличаются")
    if (
        value["path"] != str(socket_path)
        or type(value["lockPath"]) is not str
        or not str(value["lockPath"]).startswith("/")
        or type(value["device"]) is not int
        or not 0 <= value["device"] <= _MAX_SAFE_INTEGER
        or type(value["inode"]) is not int
        or not 0 <= value["inode"] <= _MAX_SAFE_INTEGER
        or type(value["ownerUid"]) is not int
        or value["ownerUid"] != os.getuid()
        or type(value["ownerGid"]) is not int
        or value["ownerGid"] < 0
        or value["mode"] != "0600"
        or type(value["controllerPid"]) is not int
        or not 1 <= value["controllerPid"] <= 2_147_483_647
        or type(value["controllerStartMarker"]) is not str
        or not 1 <= len(value["controllerStartMarker"]) <= 256
        or type(value["controllerProcessGroupId"]) is not int
        or not 1 <= value["controllerProcessGroupId"] <= 2_147_483_647
        or value["processExitRequired"] is not True
        or value["exclusiveLockRequired"] is not True
    ):
        _fail("INVALID_RESPONSE", "намерение остановки не привязано к каналу")


def _read_response(
    connection: socket.socket,
    *,
    deadline: operation_deadline_v2.OperationDeadlineV2,
    local_cap_seconds: float,
) -> dict[str, object]:
    buffer = bytearray()
    while True:
        remaining = _MAX_MESSAGE_BYTES + 1 - len(buffer)
        if remaining <= 0:
            _fail("MESSAGE_TOO_LARGE", "ответ превышает 1 МиБ")
        _set_socket_deadline_timeout(
            connection,
            deadline=deadline,
            local_cap_seconds=local_cap_seconds,
        )
        chunk = connection.recv(min(65536, remaining))
        deadline.checkpoint()
        if not chunk:
            _fail("TRANSPORT_FAILURE", "ответ завершился до перевода строки", category="UNAVAILABLE")
        buffer.extend(chunk)
        if len(buffer) > _MAX_MESSAGE_BYTES:
            _fail("MESSAGE_TOO_LARGE", "ответ превышает 1 МиБ")
        newline = buffer.find(b"\n")
        if newline < 0:
            continue
        if newline != len(buffer) - 1:
            _fail("INVALID_RESPONSE", "после ответа обнаружены лишние байты")
        raw = bytes(buffer[:newline])
        break
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: _raise_json("дробные числа запрещены"),
            parse_constant=lambda _value: _raise_json("нечисловые константы запрещены"),
        )
        canonical_json_bytes(value)
    except (UnicodeDecodeError, json.JSONDecodeError, CanonicalJsonError, ValueError) as exc:
        raise LifecycleControllerClientV2Error(
            "INVALID_RESPONSE", str(exc)
        ) from exc
    if type(value) is not dict:
        _fail("INVALID_RESPONSE", "ответ должен быть объектом")
    return value


def _set_socket_deadline_timeout(
    connection: socket.socket,
    *,
    deadline: operation_deadline_v2.OperationDeadlineV2,
    local_cap_seconds: float,
) -> None:
    deadline.checkpoint()
    connection.settimeout(
        deadline.bounded_timeout_seconds(
            local_cap_seconds=local_cap_seconds,
        )
    )


def _safe_socket(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise LifecycleControllerClientV2Error(
            "TRANSPORT_FAILURE", "управляющий сокет недоступен",
            category="UNAVAILABLE", retryable=True,
        ) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("UNSAFE_SOCKET", "метаданные управляющего сокета небезопасны")


def _peer_uid(connection: socket.socket) -> int:
    if hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    library = ctypes.CDLL(None, use_errno=True)
    getpeereid = getattr(library, "getpeereid", None)
    if getpeereid is None:
        _fail("PEER_CREDENTIALS_UNAVAILABLE", "uid второй стороны недоступен")
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    if getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        _fail("PEER_CREDENTIALS_UNAVAILABLE", "uid второй стороны не прочитан")
    return int(uid.value)


def _absolute_path(value: Path, code: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        _fail(code, "путь должен быть абсолютным Path")
    return value


def _absolute_directory(value: Path) -> Path:
    path = _absolute_path(value, "CODEX_HOME_INVALID")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise LifecycleControllerClientV2Error("CODEX_HOME_INVALID", str(exc)) from exc
    if not stat.S_ISDIR(info.st_mode):
        _fail("CODEX_HOME_INVALID", "CODEX_HOME не является каталогом")
    return path


def _identifier(value: object, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор неверен")
    return value


def _epoch(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        _fail("CONTROL_EPOCH_INVALID", "эпоха управления неверна")
    return value


def _timeout(value: object, maximum: float, code: str) -> None:
    if type(value) not in {int, float} or type(value) is bool or not 0 < float(value) <= maximum:
        _fail(code, "срок должен быть положительным и ограниченным")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"повторяющийся ключ JSON: {key}")
        result[key] = value
    return result


def _raise_json(message: str) -> None:
    raise ValueError(message)


def _fail(
    code: str,
    message: str,
    *,
    category: str = "INVALID",
    retryable: bool = False,
    control_epoch: int | None = None,
) -> None:
    raise LifecycleControllerClientV2Error(
        code, message, category, retryable, control_epoch
    )
