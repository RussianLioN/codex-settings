"""Долговечные управляющие переходы контроллера версии 2.

Модуль обслуживает только закрытые методы жизненного цикла на
``controller.sock``. Рабочий ``command.sock`` и его четыре пользовательских
инструмента сюда намеренно не входят.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .canonical_json import canonical_json_bytes, domain_fingerprint
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .schema_projection import APPLICATION_ID
from .state_store_v2 import _QUIESCENCE_QUERIES


_RELEASE = "0.2.0"
_REQUEST_DOMAIN = "codex-smart/controller-request/v2"
_RESULT_DOMAIN = "codex-smart/controller-command-result/v2"
_RESPONSE_DOMAIN = "codex-smart/controller-response/v2"
_PREDICATES_DOMAIN = "codex-smart/database-predicates/v2"
_MAX_DOCUMENT_BYTES = 1024 * 1024
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIERS = {
    "controllerIdentity": re.compile(r"^[0-9a-f]{64}$"),
    "instanceId": re.compile(r"^ci2_[0-9a-f]{32}$"),
    "controllerStartId": re.compile(r"^cs2_[0-9a-f]{32}$"),
    "commandId": re.compile(r"^cc2_[0-9a-f]{32}$"),
    "operationId": re.compile(r"^op2_[0-9a-f]{32}$"),
}
_CONTROL_METHODS = frozenset(
    {
        "maintenance_begin",
        "maintenance_strengthen",
        "shutdown",
        "controller_accept",
        "controller_recover",
        "maintenance_resume",
    }
)
_READ_METHODS = frozenset({"maintenance_status"})
_IMPLEMENTED_METHODS = _CONTROL_METHODS | _READ_METHODS
_REQUEST_KEYS = frozenset(
    {
        "messageType",
        "protocolVersion",
        "release",
        "codexHomeHash",
        "shellSessionId",
        "controllerIdentity",
        "instanceId",
        "controllerStartId",
        "commandId",
        "expectedControlEpoch",
        "operationId",
        "method",
        "params",
        "requestFingerprint",
        "extensions",
    }
)


@dataclass
class LifecycleControllerProtocolV2Error(RuntimeError):
    code: str
    message: str
    category: str = "INVALID"
    retryable: bool = False

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


QuiescenceReaderV2 = Callable[[sqlite3.Connection], Mapping[str, int]]


@dataclass(frozen=True)
class LifecycleControllerCommandProofV2:
    method: str
    status: str
    command_id: str
    request_fingerprint: str
    response_fingerprint: str
    previous_control_epoch: int
    new_control_epoch: int
    payload: Mapping[str, object]


@dataclass(frozen=True)
class LifecycleControllerQuiescenceV2:
    operation_id: str
    state: str
    maintenance_mode: str
    control_epoch: int
    quiescent: bool


@runtime_checkable
class LifecycleControllerPortV2(Protocol):
    """Единственный разрешённый порт управления переходом активации."""

    def maintenance_begin(
        self, *, operation_id: str, reason_code: str
    ) -> LifecycleControllerCommandProofV2: ...

    def wait_quiescent(
        self, *, operation_id: str, timeout_seconds: float
    ) -> LifecycleControllerQuiescenceV2: ...

    def maintenance_strengthen(
        self, *, operation_id: str
    ) -> LifecycleControllerCommandProofV2: ...

    def shutdown(
        self, *, operation_id: str
    ) -> LifecycleControllerCommandProofV2: ...

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
    ) -> LifecycleControllerCommandProofV2: ...

    def candidate_recover(
        self,
        *,
        operation_id: str,
        activation_id: str,
        database_id: str,
        pid: int,
        process_start_marker: str,
        process_group_id: int,
    ) -> LifecycleControllerCommandProofV2: ...

    def maintenance_resume(
        self, *, operation_id: str
    ) -> LifecycleControllerCommandProofV2: ...


def build_lifecycle_controller_request_v2(
    *,
    codex_home: Path,
    shell_session_id: str,
    method: str,
    controller_identity: str,
    instance_id: str | None,
    controller_start_id: str,
    command_id: str,
    expected_control_epoch: int,
    operation_id: str,
    params: Mapping[str, object],
) -> dict[str, object]:
    """Строит строгий запрос изменяющей команды контроллера."""

    home = _absolute_directory(codex_home, "CODEX_HOME_INVALID")
    normalized_params = copy.deepcopy(dict(params))
    if method == "controller_accept":
        normalized_params.setdefault("expectedOrphanOperationId", None)
    projection: dict[str, object] = {
        "messageType": "request",
        "protocolVersion": 2,
        "release": _RELEASE,
        "codexHomeHash": hashlib.sha256(str(home).encode("utf-8")).hexdigest(),
        "shellSessionId": shell_session_id,
        "controllerIdentity": controller_identity,
        "instanceId": instance_id,
        "controllerStartId": controller_start_id,
        "commandId": command_id,
        "expectedControlEpoch": expected_control_epoch,
        "operationId": operation_id,
        "method": method,
        "params": normalized_params,
    }
    request = {
        **projection,
        "requestFingerprint": domain_fingerprint(_REQUEST_DOMAIN, projection),
        "extensions": {},
    }
    _validate_request_shape(request, expected_codex_home_hash=projection["codexHomeHash"])
    return request


def build_lifecycle_controller_status_request_v2(
    *,
    codex_home: Path,
    shell_session_id: str,
    controller_identity: str,
    instance_id: str,
    controller_start_id: str,
    expected_control_epoch: int,
) -> dict[str, object]:
    """Строит ограждённое чтение состояния обслуживания."""

    home = _absolute_directory(codex_home, "CODEX_HOME_INVALID")
    projection: dict[str, object] = {
        "messageType": "request",
        "protocolVersion": 2,
        "release": _RELEASE,
        "codexHomeHash": hashlib.sha256(str(home).encode("utf-8")).hexdigest(),
        "shellSessionId": shell_session_id,
        "controllerIdentity": controller_identity,
        "instanceId": instance_id,
        "controllerStartId": controller_start_id,
        "commandId": None,
        "expectedControlEpoch": expected_control_epoch,
        "operationId": None,
        "method": "maintenance_status",
        "params": {},
    }
    request = {
        **projection,
        "requestFingerprint": domain_fingerprint(_REQUEST_DOMAIN, projection),
        "extensions": {},
    }
    _validate_request_shape(request, expected_codex_home_hash=projection["codexHomeHash"])
    return request


class LifecycleControllerProtocolV2:
    """Применяет ограждённые переходы и пишет квитанцию в той же транзакции."""

    def __init__(
        self,
        *,
        database_path: Path,
        codex_home: Path,
        controller_lock_path: Path,
        clock: Callable[[], datetime] | None = None,
        quiescence_reader: QuiescenceReaderV2 | None = None,
    ) -> None:
        self.database_path = _absolute_path(database_path, "DATABASE_INVALID")
        self.codex_home = _absolute_directory(codex_home, "CODEX_HOME_INVALID")
        self.controller_lock_path = _absolute_path(
            controller_lock_path, "CONTROLLER_LOCK_INVALID"
        )
        if not self.database_path.is_relative_to(self.controller_lock_path.parent):
            _fail(
                "CONTROLLER_LOCK_INVALID",
                "блокировка и база должны принадлежать одному state_home",
            )
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if quiescence_reader is not None and not callable(quiescence_reader):
            raise TypeError("quiescence_reader must be callable")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.quiescence_reader = quiescence_reader or _read_quiescence_counts
        self.codex_home_hash = hashlib.sha256(
            str(self.codex_home).encode("utf-8")
        ).hexdigest()

    def handle(self, request: Mapping[str, object]) -> dict[str, object]:
        """Выполняет либо точно переигрывает одну управляющую команду."""

        document = _copy_mapping(request, "INVALID_REQUEST")
        _validate_request_shape(
            document,
            expected_codex_home_hash=self.codex_home_hash,
        )
        method = str(document["method"])
        before_file = _private_database(self.database_path)
        connection = sqlite3.connect(
            self.database_path,
            timeout=5,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            _configure_connection(connection)
            _verify_database_identity(connection)
            connection.execute("BEGIN IMMEDIATE")
            try:
                if method in _CONTROL_METHODS:
                    replay = self._load_replay(connection, document)
                    if replay is not None:
                        connection.execute("COMMIT")
                        return replay
                row = _controller_row(connection)
                if method in {"controller_accept", "controller_recover"}:
                    _validate_candidate_fence(row, document)
                else:
                    _validate_live_fence(row, document)
                if method == "maintenance_status":
                    response = self._maintenance_status(connection, row, document)
                    connection.execute("COMMIT")
                    return response
                if method == "maintenance_begin":
                    response, after_row, counts = self._maintenance_begin(
                        connection, row, document
                    )
                    socket_intent = None
                elif method == "maintenance_strengthen":
                    response, after_row, counts = self._maintenance_strengthen(
                        connection, row, document
                    )
                    socket_intent = None
                elif method == "shutdown":
                    response, after_row, counts, socket_intent = self._shutdown(
                        connection, row, document
                    )
                elif method in {"controller_accept", "controller_recover"}:
                    response, after_row, counts = self._candidate_start(
                        connection, row, document
                    )
                    socket_intent = None
                else:
                    response, after_row, counts = self._maintenance_resume(
                        connection, row, document
                    )
                    socket_intent = None
                self._store_receipt(
                    connection=connection,
                    request=document,
                    response=response,
                    before_row=row,
                    after_row=after_row,
                    counts=counts,
                    socket_intent=socket_intent,
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        except sqlite3.Error as exc:
            _fail("DATABASE_UNAVAILABLE", str(exc), category="INTERNAL")
        finally:
            connection.close()
        after_file = _private_database(self.database_path)
        if (before_file.st_dev, before_file.st_ino) != (
            after_file.st_dev,
            after_file.st_ino,
        ):
            _fail("DATABASE_CHANGED", "база была заменена во время команды")
        return response

    def _load_replay(
        self,
        connection: sqlite3.Connection,
        request: Mapping[str, object],
    ) -> dict[str, object] | None:
        row = connection.execute(
            "select * from controller_command_receipts where command_id=?",
            (request["commandId"],),
        ).fetchone()
        if row is None:
            return None
        if (
            row["operation_id"] != request["operationId"]
            or row["method"] != request["method"]
            or row["request_fingerprint"] != request["requestFingerprint"]
        ):
            _fail(
                "COMMAND_REPLAY_CONFLICT",
                "commandId уже связан с другим строгим запросом",
                category="CONFLICT",
            )
        try:
            stored_request = json.loads(str(row["request_json"]))
            original = json.loads(str(row["response_json"]))
            canonical_stored_request = canonical_json_bytes(stored_request).decode(
                "utf-8"
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            _fail("DATABASE_UNAVAILABLE", str(exc), category="INTERNAL")
        if (
            type(stored_request) is not dict
            or canonical_stored_request != row["request_json"]
            or stored_request != dict(request)
            or stored_request.get("requestFingerprint")
            != row["request_fingerprint"]
            or type(original) is not dict
            or original.get("responseFingerprint") != row["response_fingerprint"]
            or _response_fingerprint(original) != row["response_fingerprint"]
            or original.get("payload", {}).get("commandReceipt", {}).get(
                "resultFingerprint"
            )
            != row["result_fingerprint"]
        ):
            _fail(
                "DATABASE_UNAVAILABLE",
                "сохранённая квитанция ответа повреждена",
                category="INTERNAL",
            )
        command_receipt = copy.deepcopy(original["payload"]["commandReceipt"])
        payload = {
            "commandReceipt": command_receipt,
            "originalControlEpoch": original["controlEpoch"],
            "originalPayload": copy.deepcopy(original["payload"]),
            "originalResponseFingerprint": row["response_fingerprint"],
        }
        return _response(
            method=str(request["method"]),
            response_kind="REPLAY_RECEIPT",
            command_id=str(request["commandId"]),
            request_fingerprint=str(request["requestFingerprint"]),
            control_epoch=int(row["after_epoch"]),
            payload=payload,
        )

    def _maintenance_begin(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: Mapping[str, object],
    ) -> tuple[dict[str, object], sqlite3.Row, dict[str, int]]:
        if (
            row["state"] != "ACCEPTING"
            or row["maintenance_mode"] != "NONE"
            or row["operation_id"] is not None
            or row["accepting_new_routes"] != 1
        ):
            _fail(
                "CONTROLLER_OPERATION_CONFLICT",
                "контроллер уже обслуживает другую операцию",
                category="CONFLICT",
            )
        counts = _validated_counts(self.quiescence_reader(connection))
        quiescent = not any(counts.values())
        next_epoch = _next_epoch(int(row["control_epoch"]))
        # Положительный признак покоя действителен только за закрытым
        # барьером. Открытие новых маршрутов немедленно снимает это
        # утверждение, иначе первая работа сделает строку состояния ложной.
        connection.execute(
            "update controller_state set control_epoch=?,state=?,maintenance_mode='DRAIN',"
            "reason_code=?,operation_id=?,accepting_new_routes=0,quiescent=?,updated_at=? "
            "where singleton=1",
            (
                next_epoch,
                "MAINTENANCE" if quiescent else "DRAINING",
                str(request["params"]["reasonCode"]),
                request["operationId"],
                int(quiescent),
                _iso(self.clock()),
            ),
        )
        after = _controller_row(connection)
        response = _transition_response(
            request=request,
            status="MAINTENANCE_BEGUN",
            previous_epoch=int(row["control_epoch"]),
            new_epoch=next_epoch,
        )
        return response, after, counts

    def _maintenance_status(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: Mapping[str, object],
    ) -> dict[str, object]:
        counts = _validated_counts(self.quiescence_reader(connection))
        quiescent = not any(counts.values())
        if (
            quiescent
            and row["state"] == "DRAINING"
            and row["maintenance_mode"] == "DRAIN"
            and row["operation_id"] is not None
            and row["accepting_new_routes"] == 0
            and row["quiescent"] == 0
        ):
            connection.execute(
                "update controller_state set state='MAINTENANCE',quiescent=1,"
                "updated_at=? where singleton=1",
                (_iso(self.clock()),),
            )
            row = _controller_row(connection)
        if bool(row["quiescent"]) != quiescent:
            _fail(
                "CONTROLLER_OPERATION_CONFLICT",
                "флаг покоя расходится с фактическими предикатами",
                category="CONFLICT",
            )
        modes = {"NONE": None, "DRAIN": "drain", "FREEZE": "freeze"}
        mode = modes.get(str(row["maintenance_mode"]))
        if row["state"] not in {"ACCEPTING", "DRAINING", "MAINTENANCE"}:
            _fail("INVALID_TRANSITION", "состояние нельзя опубликовать")
        payload = {
            "state": str(row["state"]),
            "maintenanceMode": mode,
            "operationId": row["operation_id"],
            "quiescent": quiescent,
        }
        return _response(
            method="maintenance_status",
            response_kind="SUCCESS",
            command_id=None,
            request_fingerprint=str(request["requestFingerprint"]),
            control_epoch=int(row["control_epoch"]),
            payload=payload,
        )

    def _maintenance_strengthen(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: Mapping[str, object],
    ) -> tuple[dict[str, object], sqlite3.Row, dict[str, int]]:
        if (
            row["state"] not in {"DRAINING", "MAINTENANCE"}
            or row["maintenance_mode"] != "DRAIN"
            or row["operation_id"] != request["operationId"]
            or row["accepting_new_routes"] != 0
        ):
            _fail(
                "INVALID_TRANSITION",
                "усиление разрешено только для текущего режима drain",
            )
        counts = _validated_counts(self.quiescence_reader(connection))
        if any(counts.values()):
            _fail(
                "EXTERNAL_PROCESS_STILL_RUNNING",
                "состояние ещё не достигло покоя",
                category="UNAVAILABLE",
                retryable=True,
            )
        next_epoch = _next_epoch(int(row["control_epoch"]))
        connection.execute(
            "update controller_state set control_epoch=?,state='MAINTENANCE',"
            "maintenance_mode='FREEZE',quiescent=1,updated_at=? where singleton=1",
            (next_epoch, _iso(self.clock())),
        )
        after = _controller_row(connection)
        response = _transition_response(
            request=request,
            status="MAINTENANCE_STRENGTHENED",
            previous_epoch=int(row["control_epoch"]),
            new_epoch=next_epoch,
        )
        return response, after, counts

    def _shutdown(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: Mapping[str, object],
    ) -> tuple[
        dict[str, object], sqlite3.Row, dict[str, int], dict[str, object]
    ]:
        if (
            row["state"] != "MAINTENANCE"
            or row["maintenance_mode"] != "FREEZE"
            or row["operation_id"] != request["operationId"]
            or row["accepting_new_routes"] != 0
        ):
            _fail(
                "INVALID_TRANSITION",
                "shutdown требует замороженную текущую операцию",
            )
        counts = _validated_counts(self.quiescence_reader(connection))
        if any(counts.values()):
            _fail(
                "EXTERNAL_PROCESS_STILL_RUNNING",
                "shutdown запрещён до полного покоя",
                category="UNAVAILABLE",
                retryable=True,
            )
        socket_intent = _socket_intent(
            row,
            socket_path=Path(str(row["socket_path"])),
            lock_path=self.controller_lock_path,
        )
        next_epoch = _next_epoch(int(row["control_epoch"]))
        connection.execute(
            "update controller_state set control_epoch=?,state='MAINTENANCE',"
            "maintenance_mode='FREEZE',reason_code='AWAITING_CONTROLLER_ACCEPT',"
            "instance_id=null,controller_start_id=null,controller_pid=null,"
            "controller_process_start_marker=null,controller_process_group_id=null,"
            "socket_path=null,socket_device=null,socket_inode=null,socket_owner_uid=null,"
            "socket_owner_gid=null,socket_mode=null,lock_held=0,accepting_new_routes=0,"
            "quiescent=1,updated_at=? where singleton=1",
            (next_epoch, _iso(self.clock())),
        )
        after = _controller_row(connection)
        payload_base = {
            "status": "SHUTDOWN_COMMITTED",
            "previousControlEpoch": int(row["control_epoch"]),
            "newControlEpoch": next_epoch,
            "socketIntent": socket_intent,
        }
        response = _command_response(request=request, payload_base=payload_base)
        return response, after, counts, socket_intent

    def _candidate_start(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: Mapping[str, object],
    ) -> tuple[dict[str, object], sqlite3.Row, dict[str, int]]:
        params = request["params"]
        identity = connection.execute(
            "select database_id,activation_id from database_identity"
        ).fetchone()
        expected_orphan_operation_id = params.get("expectedOrphanOperationId")
        operation_matches = row["operation_id"] == request["operationId"]
        if (
            request["method"] == "controller_accept"
            and expected_orphan_operation_id is not None
        ):
            operation_matches = (
                expected_orphan_operation_id != request["operationId"]
                and row["operation_id"] == expected_orphan_operation_id
            )
        if (
            row["state"] != "MAINTENANCE"
            or row["maintenance_mode"] != "FREEZE"
            or row["reason_code"] != "AWAITING_CONTROLLER_ACCEPT"
            or not operation_matches
            or row["instance_id"] is not None
            or row["lock_held"] != 0
            or identity is None
            or params["activationId"] != identity["activation_id"]
            or params["databaseId"] != identity["database_id"]
            or params["activationId"] != row["activation_id"]
            or params["databaseId"] != row["database_id"]
        ):
            _fail(
                "CONTROLLER_INSTANCE_MISMATCH",
                "кандидат не совпадает с ожидающей базой",
                category="STALE",
            )
        try:
            observed_marker = system_process_start_marker_v2(int(params["pid"]))
        except (ChildGuardV2Error, TypeError, ValueError) as exc:
            _fail(
                "CONTROLLER_INSTANCE_MISMATCH",
                str(exc),
                category="STALE",
            )
        if (
            int(params["pid"]) != os.getpid()
            or observed_marker != params["processStartMarker"]
            or int(params["processGroupId"]) != os.getpgrp()
        ):
            _fail(
                "CONTROLLER_INSTANCE_MISMATCH",
                "процесс кандидата не является владельцем канала",
                category="STALE",
            )
        socket_binding = _candidate_socket_binding(
            socket_path=Path(str(self.controller_lock_path.parent / "controller.sock")),
            lock_path=self.controller_lock_path,
        )
        counts = _validated_counts(self.quiescence_reader(connection))
        if any(counts.values()):
            _fail(
                "EXTERNAL_PROCESS_STILL_RUNNING",
                "база кандидата не находится в покое",
                category="UNAVAILABLE",
                retryable=True,
            )
        next_epoch = _next_epoch(int(row["control_epoch"]))
        instance_id = "ci2_" + secrets.token_hex(16)
        connection.execute(
            "update controller_state set control_epoch=?,state='MAINTENANCE',"
            "maintenance_mode='FREEZE',reason_code='CANDIDATE_ACCEPTED',"
            "operation_id=?,instance_id=?,controller_start_id=?,controller_pid=?,"
            "controller_process_start_marker=?,controller_process_group_id=?,"
            "socket_path=?,socket_device=?,socket_inode=?,socket_owner_uid=?,"
            "socket_owner_gid=?,socket_mode=?,lock_held=1,accepting_new_routes=0,"
            "quiescent=1,updated_at=? where singleton=1",
            (
                next_epoch,
                request["operationId"],
                instance_id,
                request["controllerStartId"],
                params["pid"],
                params["processStartMarker"],
                params["processGroupId"],
                socket_binding["path"],
                socket_binding["device"],
                socket_binding["inode"],
                socket_binding["ownerUid"],
                socket_binding["ownerGid"],
                socket_binding["mode"],
                _iso(self.clock()),
            ),
        )
        after = _controller_row(connection)
        status = (
            "CONTROLLER_ACCEPTED"
            if request["method"] == "controller_accept"
            else "CONTROLLER_RECOVERED"
        )
        response = _command_response(
            request=request,
            payload_base={
                "status": status,
                "previousControlEpoch": int(row["control_epoch"]),
                "newControlEpoch": next_epoch,
                "controllerIdentity": request["controllerIdentity"],
                "instanceId": instance_id,
                "controllerStartId": request["controllerStartId"],
            },
        )
        return response, after, counts

    def _maintenance_resume(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: Mapping[str, object],
    ) -> tuple[dict[str, object], sqlite3.Row, dict[str, int]]:
        resume_after_candidate = (
            row["state"] == "MAINTENANCE"
            and row["maintenance_mode"] == "FREEZE"
            and row["reason_code"] == "CANDIDATE_ACCEPTED"
        )
        resume_after_drain = (
            row["state"] in {"DRAINING", "MAINTENANCE"}
            and row["maintenance_mode"] == "DRAIN"
        )
        if (
            not (resume_after_candidate or resume_after_drain)
            or row["operation_id"] != request["operationId"]
            or row["accepting_new_routes"] != 0
            or row["lock_held"] != 1
        ):
            _fail(
                "INVALID_TRANSITION",
                "resume требует текущего drain либо принятого кандидата",
            )
        counts = _validated_counts(self.quiescence_reader(connection))
        observed_quiescent = not any(counts.values())
        if resume_after_candidate and not observed_quiescent:
            _fail(
                "EXTERNAL_PROCESS_STILL_RUNNING",
                "resume принятого кандидата требует доказанного покоя",
                category="UNAVAILABLE",
                retryable=True,
            )
        next_epoch = _next_epoch(int(row["control_epoch"]))
        connection.execute(
            "update controller_state set control_epoch=?,state='ACCEPTING',"
            "maintenance_mode='NONE',reason_code='NONE',operation_id=null,"
            "accepting_new_routes=1,quiescent=0,updated_at=? where singleton=1",
            (next_epoch, _iso(self.clock())),
        )
        after = _controller_row(connection)
        response = _transition_response(
            request=request,
            status="MAINTENANCE_RESUMED",
            previous_epoch=int(row["control_epoch"]),
            new_epoch=next_epoch,
        )
        return response, after, counts

    def _store_receipt(
        self,
        *,
        connection: sqlite3.Connection,
        request: Mapping[str, object],
        response: Mapping[str, object],
        before_row: sqlite3.Row,
        after_row: sqlite3.Row,
        counts: Mapping[str, int],
        socket_intent: Mapping[str, object] | None,
    ) -> None:
        payload = response["payload"]
        receipt = payload["commandReceipt"]
        quiescence = None
        if request["method"] == "shutdown":
            quiescence = _quiescence_proof(counts)
        connection.execute(
            "insert into controller_command_receipts "
            "(command_id,operation_id,method,request_fingerprint,request_json,"
            "result_fingerprint,response_json,response_fingerprint,controller_identity,"
            "before_instance_id,resulting_instance_id,quiescence_proof_json,"
            "socket_intent_json,before_epoch,after_epoch,created_at) "
            "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request["commandId"],
                request["operationId"],
                request["method"],
                request["requestFingerprint"],
                canonical_json_bytes(request).decode("utf-8"),
                receipt["resultFingerprint"],
                canonical_json_bytes(response).decode("utf-8"),
                response["responseFingerprint"],
                before_row["controller_identity"],
                before_row["instance_id"],
                after_row["instance_id"],
                (
                    None
                    if quiescence is None
                    else canonical_json_bytes(quiescence).decode("utf-8")
                ),
                (
                    None
                    if socket_intent is None
                    else canonical_json_bytes(socket_intent).decode("utf-8")
                ),
                before_row["control_epoch"],
                after_row["control_epoch"],
                _iso(self.clock()),
            ),
        )


def _transition_response(
    *,
    request: Mapping[str, object],
    status: str,
    previous_epoch: int,
    new_epoch: int,
) -> dict[str, object]:
    return _command_response(
        request=request,
        payload_base={
            "status": status,
            "previousControlEpoch": previous_epoch,
            "newControlEpoch": new_epoch,
        },
    )


def _command_response(
    *,
    request: Mapping[str, object],
    payload_base: Mapping[str, object],
) -> dict[str, object]:
    result_projection = {
        "method": request["method"],
        "payload": copy.deepcopy(dict(payload_base)),
    }
    result_fingerprint = domain_fingerprint(_RESULT_DOMAIN, result_projection)
    control_epoch = int(payload_base["newControlEpoch"])
    command_receipt = {
        "commandId": request["commandId"],
        "requestFingerprint": request["requestFingerprint"],
        "resultFingerprint": result_fingerprint,
        "controlEpoch": control_epoch,
    }
    payload = {**copy.deepcopy(dict(payload_base)), "commandReceipt": command_receipt}
    return _response(
        method=str(request["method"]),
        response_kind="SUCCESS",
        command_id=str(request["commandId"]),
        request_fingerprint=str(request["requestFingerprint"]),
        control_epoch=control_epoch,
        payload=payload,
    )


def _response(
    *,
    method: str,
    response_kind: str,
    command_id: str | None,
    request_fingerprint: str,
    control_epoch: int,
    payload: Mapping[str, object],
) -> dict[str, object]:
    projection: dict[str, object] = {
        "messageType": "response",
        "protocolVersion": 2,
        "release": _RELEASE,
        "method": method,
        "responseKind": response_kind,
        "commandId": command_id,
        "requestFingerprint": request_fingerprint,
        "controlEpoch": control_epoch,
        "payload": copy.deepcopy(dict(payload)),
    }
    return {
        **projection,
        "responseFingerprint": domain_fingerprint(_RESPONSE_DOMAIN, projection),
        "extensions": {},
    }


def _response_fingerprint(response: Mapping[str, object]) -> str:
    projection = {
        key: copy.deepcopy(value)
        for key, value in response.items()
        if key not in {"responseFingerprint", "extensions"}
    }
    return domain_fingerprint(_RESPONSE_DOMAIN, projection)


def _validate_request_shape(
    request: Mapping[str, object],
    *,
    expected_codex_home_hash: object,
) -> None:
    if set(request) != _REQUEST_KEYS:
        _fail("INVALID_REQUEST", "набор полей запроса отличается")
    if (
        request["messageType"] != "request"
        or request["protocolVersion"] != 2
        or request["release"] != _RELEASE
        or request["codexHomeHash"] != expected_codex_home_hash
        or request["extensions"] != {}
    ):
        _fail("INVALID_REQUEST", "константы запроса отличаются")
    if (
        type(request["shellSessionId"]) is not str
        or not request["shellSessionId"]
        or len(str(request["shellSessionId"])) > 256
    ):
        _fail("INVALID_REQUEST", "shellSessionId неверен")
    method = request["method"]
    if type(method) is not str or method not in _IMPLEMENTED_METHODS:
        _fail("INVALID_REQUEST", "method неверен")
    for name in ("controllerIdentity", "instanceId", "controllerStartId"):
        value = request[name]
        if name == "instanceId" and value is None:
            continue
        pattern = _IDENTIFIERS[name]
        if type(value) is not str or pattern.fullmatch(value) is None:
            _fail("INVALID_REQUEST", f"{name} неверен")
    epoch = request["expectedControlEpoch"]
    if type(epoch) is not int or not 1 <= epoch <= _MAX_SAFE_INTEGER:
        _fail("INVALID_REQUEST", "expectedControlEpoch неверен")
    if method == "maintenance_status":
        if request["commandId"] is not None or request["operationId"] is not None:
            _fail("INVALID_REQUEST", "status не принимает commandId/operationId")
    else:
        for name in ("commandId", "operationId"):
            value = request[name]
            if type(value) is not str or _IDENTIFIERS[name].fullmatch(value) is None:
                _fail("INVALID_REQUEST", f"{name} неверен")
    if method in {"controller_accept", "controller_recover"}:
        if request["instanceId"] is not None:
            _fail("INVALID_REQUEST", "кандидат ещё не имеет instanceId")
    elif request["instanceId"] is None:
        _fail("INVALID_REQUEST", "живой метод требует instanceId")
    params = request["params"]
    if type(params) is not dict:
        _fail("INVALID_REQUEST", "params должен быть объектом")
    if method == "maintenance_begin":
        if set(params) != {"reasonCode"} or not _bounded_text(
            params.get("reasonCode"), 128
        ):
            _fail("INVALID_REQUEST", "reasonCode неверен")
    elif method == "maintenance_strengthen":
        if params != {"mode": "freeze"}:
            _fail("INVALID_REQUEST", "режим усиления неверен")
    elif method in {"shutdown", "maintenance_resume", "maintenance_status"} and params != {}:
        _fail("INVALID_REQUEST", "метод не принимает параметры")
    elif method in {"controller_accept", "controller_recover"}:
        required_params = {
            "activationId",
            "databaseId",
            "pid",
            "processStartMarker",
            "processGroupId",
        }
        if method == "controller_accept":
            required_params.add("expectedOrphanOperationId")
        if set(params) != required_params:
            _fail("INVALID_REQUEST", "параметры кандидата отличаются")
        expected_orphan_operation_id = params.get("expectedOrphanOperationId")
        if (
            type(params["activationId"]) is not str
            or re.fullmatch(r"act2_[0-9a-f]{64}", str(params["activationId"]))
            is None
            or type(params["databaseId"]) is not str
            or re.fullmatch(r"db2_[0-9a-f]{32}", str(params["databaseId"])) is None
            or type(params["pid"]) is not int
            or not 1 <= int(params["pid"]) <= 2_147_483_647
            or not _bounded_text(params["processStartMarker"], 256)
            or type(params["processGroupId"]) is not int
            or not 1 <= int(params["processGroupId"]) <= 2_147_483_647
            or (
                method == "controller_accept"
                and expected_orphan_operation_id is not None
                and (
                    type(expected_orphan_operation_id) is not str
                    or _IDENTIFIERS["operationId"].fullmatch(
                        expected_orphan_operation_id
                    )
                    is None
                    or expected_orphan_operation_id == request["operationId"]
                )
            )
        ):
            _fail("INVALID_REQUEST", "идентичность кандидата неверна")
    projection = {
        key: copy.deepcopy(request[key])
        for key in (
            "messageType",
            "protocolVersion",
            "release",
            "codexHomeHash",
            "shellSessionId",
            "controllerIdentity",
            "instanceId",
            "controllerStartId",
            "commandId",
            "expectedControlEpoch",
            "operationId",
            "method",
            "params",
        )
    }
    if (
        type(request["requestFingerprint"]) is not str
        or _SHA256.fullmatch(str(request["requestFingerprint"])) is None
        or request["requestFingerprint"]
        != domain_fingerprint(_REQUEST_DOMAIN, projection)
    ):
        _fail("INVALID_REQUEST", "requestFingerprint не совпал")
    try:
        size = len(canonical_json_bytes(request))
    except (TypeError, ValueError) as exc:
        _fail("INVALID_REQUEST", str(exc))
    if size > _MAX_DOCUMENT_BYTES:
        _fail("INVALID_REQUEST", "запрос слишком велик")


def _validate_live_fence(
    row: sqlite3.Row,
    request: Mapping[str, object],
) -> None:
    if (
        row["controller_identity"] != request["controllerIdentity"]
        or row["instance_id"] != request["instanceId"]
        or row["controller_start_id"] != request["controllerStartId"]
    ):
        _fail(
            "CONTROLLER_INSTANCE_MISMATCH",
            "команда относится к другому экземпляру контроллера",
            category="STALE",
        )
    if row["control_epoch"] != request["expectedControlEpoch"]:
        _fail(
            "CONTROL_EPOCH_MISMATCH",
            "эпоха управления изменилась",
            category="STALE",
            retryable=True,
        )
    pid = row["controller_pid"]
    marker = row["controller_process_start_marker"]
    if type(pid) is not int or type(marker) is not str:
        _fail("CONTROLLER_INSTANCE_MISMATCH", "владелец контроллера отсутствует")
    try:
        observed = system_process_start_marker_v2(pid)
    except ChildGuardV2Error as exc:
        _fail(
            "CONTROLLER_INSTANCE_MISMATCH",
            str(exc),
            category="STALE",
        )
    if observed != marker:
        _fail(
            "CONTROLLER_INSTANCE_MISMATCH",
            "системный маркер процесса изменился",
            category="STALE",
        )


def _validate_candidate_fence(
    row: sqlite3.Row,
    request: Mapping[str, object],
) -> None:
    if (
        row["controller_identity"] != request["controllerIdentity"]
        or request["instanceId"] is not None
        or row["instance_id"] is not None
        or row["controller_start_id"] is not None
    ):
        _fail(
            "CONTROLLER_INSTANCE_MISMATCH",
            "унаследованный канал не ожидает этого кандидата",
            category="STALE",
        )
    if row["control_epoch"] != request["expectedControlEpoch"]:
        _fail(
            "CONTROL_EPOCH_MISMATCH",
            "эпоха управления кандидата изменилась",
            category="STALE",
            retryable=True,
        )


def _candidate_socket_binding(
    *,
    socket_path: Path,
    lock_path: Path,
) -> dict[str, object]:
    try:
        socket_info = os.lstat(socket_path)
        lock_info = os.lstat(lock_path)
    except OSError as exc:
        _fail("CONTROLLER_INSTANCE_MISMATCH", str(exc), category="STALE")
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != os.getuid()
        or socket_info.st_nlink != 1
        or stat.S_IMODE(socket_info.st_mode) != 0o600
        or not stat.S_ISREG(lock_info.st_mode)
        or stat.S_ISLNK(lock_info.st_mode)
        or lock_info.st_uid != os.getuid()
        or lock_info.st_nlink != 1
        or stat.S_IMODE(lock_info.st_mode) != 0o600
    ):
        _fail(
            "CONTROLLER_INSTANCE_MISMATCH",
            "канал кандидата имеет небезопасные метаданные",
            category="STALE",
        )
    return {
        "path": str(socket_path),
        "device": socket_info.st_dev,
        "inode": socket_info.st_ino,
        "ownerUid": socket_info.st_uid,
        "ownerGid": socket_info.st_gid,
        "mode": f"0{stat.S_IMODE(socket_info.st_mode):03o}",
    }


def _socket_intent(
    row: sqlite3.Row,
    *,
    socket_path: Path,
    lock_path: Path,
) -> dict[str, object]:
    try:
        socket_info = os.lstat(socket_path)
        lock_info = os.lstat(lock_path)
    except OSError as exc:
        _fail("CONTROLLER_INSTANCE_MISMATCH", str(exc), category="STALE")
    observed = (
        socket_info.st_dev,
        socket_info.st_ino,
        socket_info.st_uid,
        socket_info.st_gid,
        f"0{stat.S_IMODE(socket_info.st_mode):03o}",
    )
    expected = (
        row["socket_device"],
        row["socket_inode"],
        row["socket_owner_uid"],
        row["socket_owner_gid"],
        row["socket_mode"],
    )
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_nlink != 1
        or observed != expected
        or not stat.S_ISREG(lock_info.st_mode)
        or stat.S_ISLNK(lock_info.st_mode)
        or lock_info.st_uid != os.getuid()
        or lock_info.st_nlink != 1
        or stat.S_IMODE(lock_info.st_mode) != 0o600
    ):
        _fail(
            "CONTROLLER_INSTANCE_MISMATCH",
            "сокет или блокировка контроллера изменились",
            category="STALE",
        )
    return {
        "path": str(socket_path),
        "device": socket_info.st_dev,
        "inode": socket_info.st_ino,
        "ownerUid": socket_info.st_uid,
        "ownerGid": socket_info.st_gid,
        "mode": f"0{stat.S_IMODE(socket_info.st_mode):03o}",
        "controllerPid": row["controller_pid"],
        "controllerStartMarker": row["controller_process_start_marker"],
        "controllerProcessGroupId": row["controller_process_group_id"],
        "lockPath": str(lock_path),
        "processExitRequired": True,
        "exclusiveLockRequired": True,
    }


def _quiescence_proof(counts: Mapping[str, int]) -> dict[str, object]:
    projection = {
        "predicates": [
            {
                "name": name,
                "sql": _QUIESCENCE_QUERIES[name],
                "parameters": [],
                "result": counts[name],
            }
            for name in _QUIESCENCE_QUERIES
        ]
    }
    return {
        "workCounts": dict(counts),
        "databasePredicatesFingerprint": domain_fingerprint(
            _PREDICATES_DOMAIN, projection
        ),
        "barrierHeld": True,
        "quiescent": not any(counts.values()),
    }


def _read_quiescence_counts(
    connection: sqlite3.Connection,
) -> dict[str, int]:
    return {
        name: int(connection.execute(statement).fetchone()[0])
        for name, statement in _QUIESCENCE_QUERIES.items()
    }


def _validated_counts(value: Mapping[str, int]) -> dict[str, int]:
    if type(value) is not dict or set(value) != set(_QUIESCENCE_QUERIES):
        _fail("DATABASE_UNAVAILABLE", "набор предикатов покоя отличается")
    copied: dict[str, int] = {}
    for name in _QUIESCENCE_QUERIES:
        item = value[name]
        if type(item) is not int or item < 0:
            _fail("DATABASE_UNAVAILABLE", "результат предиката покоя неверен")
        copied[name] = item
    return copied


def _configure_connection(connection: sqlite3.Connection) -> None:
    connection.execute("pragma foreign_keys=ON")
    connection.execute("pragma trusted_schema=OFF")
    connection.execute("pragma synchronous=FULL")
    connection.execute("pragma busy_timeout=5000")


def _verify_database_identity(connection: sqlite3.Connection) -> None:
    if (
        int(connection.execute("pragma application_id").fetchone()[0])
        != APPLICATION_ID
        or int(connection.execute("pragma user_version").fetchone()[0]) != 2
    ):
        _fail("DATABASE_UNAVAILABLE", "метаданные базы отличаются")
    quick = [tuple(row) for row in connection.execute("pragma quick_check")]
    if quick != [("ok",)]:
        _fail("DATABASE_UNAVAILABLE", "quick_check не прошёл")


def _controller_row(connection: sqlite3.Connection) -> sqlite3.Row:
    rows = connection.execute("select * from controller_state").fetchall()
    if len(rows) != 1:
        _fail("DATABASE_UNAVAILABLE", "строка контроллера не единственна")
    return rows[0]


def _private_database(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        _fail("DATABASE_INVALID", str(exc))
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("DATABASE_INVALID", "база имеет небезопасные метаданные")
    return info


def _absolute_directory(path: Path, code: str) -> Path:
    value = _absolute_path(path, code)
    try:
        info = value.lstat()
    except OSError as exc:
        _fail(code, str(exc))
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        _fail(code, "каталог имеет небезопасные метаданные")
    return value


def _absolute_path(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "требуется абсолютный Path")
    return path.expanduser().absolute()


def _next_epoch(value: int) -> int:
    if type(value) is not int or not 1 <= value < _MAX_SAFE_INTEGER:
        _fail("INVALID_TRANSITION", "эпоха управления исчерпана")
    return value + 1


def _copy_mapping(value: Mapping[str, object], code: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        _fail(code, "ожидался объект")
    try:
        copied = copy.deepcopy(dict(value))
    except (TypeError, ValueError) as exc:
        _fail(code, str(exc))
    return copied


def _bounded_text(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value.encode("utf-8")) <= maximum
        and "\0" not in value
    )


def _iso(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _fail("INVALID_TIME", "clock должен вернуть aware datetime")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _fail(
    code: str,
    message: str,
    *,
    category: str = "INVALID",
    retryable: bool = False,
) -> None:
    raise LifecycleControllerProtocolV2Error(
        code=code,
        message=message[:1024],
        category=category,
        retryable=retryable,
    )


__all__ = [
    "LifecycleControllerCommandProofV2",
    "LifecycleControllerPortV2",
    "LifecycleControllerProtocolV2",
    "LifecycleControllerProtocolV2Error",
    "LifecycleControllerQuiescenceV2",
    "build_lifecycle_controller_request_v2",
    "build_lifecycle_controller_status_request_v2",
]
