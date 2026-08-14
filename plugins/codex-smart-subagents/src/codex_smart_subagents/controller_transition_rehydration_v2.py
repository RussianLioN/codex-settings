"""Повторное построение доказательств перехода только из точной SQLite-базы.

Модуль не принимает ранее созданные объекты командных доказательств. Он заново
читает долговечные ``controller_command_receipts``, перепроверяет все доступные
криптографические связи и только после этого создаёт публичные доказательства
перехода активации.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from .activation_transition_v2 import (
    CandidateAcceptanceProofV2,
    ControllerShutdownProofV2,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .lifecycle_controller_protocol_v2 import (
    LifecycleControllerCommandProofV2,
    LifecycleControllerQuiescenceV2,
)
from .schema_projection import APPLICATION_ID
from .state_store_v2 import _QUIESCENCE_QUERIES
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2


_REQUEST_DOMAIN = "codex-smart/controller-request/v2"
_RESULT_DOMAIN = "codex-smart/controller-command-result/v2"
_RESPONSE_DOMAIN = "codex-smart/controller-response/v2"
_PREDICATES_DOMAIN = "codex-smart/database-predicates/v2"
_SHUTDOWN_DOMAIN = "codex-smart/controller-shutdown-transition/v2"
_ACCEPTANCE_DOMAIN = "codex-smart/candidate-acceptance-transition/v2"
_RELEASE = "0.2.0"
_MAX_DOCUMENT_BYTES = 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMAND_ID = re.compile(r"^cc2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_INSTANCE_ID = re.compile(r"^ci2_[0-9a-f]{32}$")
_CONTROLLER_START_ID = re.compile(r"^cs2_[0-9a-f]{32}$")
_MODE = re.compile(r"^0[0-7]{3}$")
_RECEIPT_COLUMNS = frozenset(
    {
        "command_id",
        "operation_id",
        "method",
        "request_fingerprint",
        "request_json",
        "result_fingerprint",
        "response_json",
        "response_fingerprint",
        "controller_identity",
        "before_instance_id",
        "resulting_instance_id",
        "quiescence_proof_json",
        "socket_intent_json",
        "before_epoch",
        "after_epoch",
        "created_at",
    }
)
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
_RESPONSE_KEYS = frozenset(
    {
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
)
_RECEIPT_PAYLOAD_KEYS = frozenset(
    {"commandId", "requestFingerprint", "resultFingerprint", "controlEpoch"}
)
_STATUS_BY_METHOD = {
    "maintenance_begin": "MAINTENANCE_BEGUN",
    "maintenance_strengthen": "MAINTENANCE_STRENGTHENED",
    "shutdown": "SHUTDOWN_COMMITTED",
    "controller_accept": "CONTROLLER_ACCEPTED",
    "controller_recover": "CONTROLLER_RECOVERED",
    "maintenance_resume": "MAINTENANCE_RESUMED",
}
_PAYLOAD_KEYS_BY_METHOD = {
    "maintenance_begin": frozenset(
        {"status", "previousControlEpoch", "newControlEpoch", "commandReceipt"}
    ),
    "maintenance_strengthen": frozenset(
        {"status", "previousControlEpoch", "newControlEpoch", "commandReceipt"}
    ),
    "shutdown": frozenset(
        {
            "status",
            "previousControlEpoch",
            "newControlEpoch",
            "socketIntent",
            "commandReceipt",
        }
    ),
    "controller_accept": frozenset(
        {
            "status",
            "previousControlEpoch",
            "newControlEpoch",
            "controllerIdentity",
            "instanceId",
            "controllerStartId",
            "commandReceipt",
        }
    ),
    "controller_recover": frozenset(
        {
            "status",
            "previousControlEpoch",
            "newControlEpoch",
            "controllerIdentity",
            "instanceId",
            "controllerStartId",
            "commandReceipt",
        }
    ),
    "maintenance_resume": frozenset(
        {"status", "previousControlEpoch", "newControlEpoch", "commandReceipt"}
    ),
}
_SOCKET_INTENT_KEYS = frozenset(
    {
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
)


@dataclass
class ControllerTransitionRehydrationV2Error(RuntimeError):
    """Закрытый отказ повторного построения с устойчивым машинным кодом."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ControllerShutdownCommandIdsV2:
    """Точные идентификаторы единственной цепочки остановки."""

    maintenance_begin: str
    maintenance_strengthen: str
    shutdown: str

    def __post_init__(self) -> None:
        values = (
            self.maintenance_begin,
            self.maintenance_strengthen,
            self.shutdown,
        )
        if (
            any(type(value) is not str or _COMMAND_ID.fullmatch(value) is None for value in values)
            or len(set(values)) != len(values)
        ):
            _fail(
                "REHYDRATION_ARGUMENT_INVALID",
                "идентификаторы команд остановки неверны либо повторяются",
            )


@dataclass(frozen=True)
class RehydratedControllerCommandV2:
    """Историческая квитанция с пересчитанными request/response fingerprints."""

    row: Mapping[str, Any]
    request: Mapping[str, Any]
    response: Mapping[str, Any]
    proof: LifecycleControllerCommandProofV2

    def __post_init__(self) -> None:
        object.__setattr__(self, "row", copy.deepcopy(dict(self.row)))
        object.__setattr__(self, "request", copy.deepcopy(dict(self.request)))
        object.__setattr__(self, "response", copy.deepcopy(dict(self.response)))


_ReceiptObservationV2 = RehydratedControllerCommandV2


def rehydrate_controller_command_v2(
    *,
    database_path: Path,
    operation_id: str,
    command_id: str,
    method: str,
) -> RehydratedControllerCommandV2:
    """Прочитать одну точную управляющую квитанцию без требования live-состояния."""

    operation_id = _identifier(operation_id, _OPERATION_ID)
    command_id = _identifier(command_id, _COMMAND_ID)
    if type(method) is not str or method not in _STATUS_BY_METHOD:
        _fail("REHYDRATION_ARGUMENT_INVALID", "метод команды не поддерживается")
    with _read_exact_database(database_path) as connection:
        _database_identity(connection)
        return _read_receipt(
            connection,
            command_id=command_id,
            operation_id=operation_id,
            method=method,
        )


def rehydrate_controller_shutdown_proof_v2(
    *,
    database_path: Path,
    activation_proof_fingerprint: str,
    operation_id: str,
    command_ids: ControllerShutdownCommandIdsV2,
) -> ControllerShutdownProofV2:
    """Заново доказать ``begin → quiescent → strengthen → shutdown``."""

    activation_proof_fingerprint = _identifier(
        activation_proof_fingerprint, _SHA256
    )
    operation_id = _identifier(operation_id, _OPERATION_ID)
    if not isinstance(command_ids, ControllerShutdownCommandIdsV2):
        _fail(
            "REHYDRATION_ARGUMENT_INVALID",
            "требуется ControllerShutdownCommandIdsV2",
        )
    with _read_exact_database(database_path) as connection:
        identity, controller = _database_identity(connection)
        begin = _read_receipt(
            connection,
            command_id=command_ids.maintenance_begin,
            operation_id=operation_id,
            method="maintenance_begin",
        )
        strengthen = _read_receipt(
            connection,
            command_id=command_ids.maintenance_strengthen,
            operation_id=operation_id,
            method="maintenance_strengthen",
        )
        shutdown = _read_receipt(
            connection,
            command_id=command_ids.shutdown,
            operation_id=operation_id,
            method="shutdown",
        )
        _require_exact_shutdown_receipt_set(
            connection,
            operation_id=operation_id,
            command_ids=command_ids,
        )
        _verify_shutdown_epoch_chain(begin, strengthen, shutdown)
        _verify_shutdown_request_chain(begin, strengthen, shutdown)
        quiescence = _read_shutdown_quiescence(
            shutdown.row,
            operation_id=operation_id,
            control_epoch=begin.proof.new_control_epoch,
        )
        _read_shutdown_socket_intent(shutdown)
        _verify_shutdown_database_state(
            identity=identity,
            controller=controller,
            operation_id=operation_id,
            receipts=(begin, strengthen, shutdown),
        )
    result = ControllerShutdownProofV2(
        activation_proof_fingerprint=activation_proof_fingerprint,
        operation_id=operation_id,
        maintenance_begin=begin.proof,
        quiescence=quiescence,
        maintenance_strengthen=strengthen.proof,
        shutdown=shutdown.proof,
        proof_fingerprint="0" * 64,
    )
    result = ControllerShutdownProofV2(
        activation_proof_fingerprint=result.activation_proof_fingerprint,
        operation_id=result.operation_id,
        maintenance_begin=result.maintenance_begin,
        quiescence=result.quiescence,
        maintenance_strengthen=result.maintenance_strengthen,
        shutdown=result.shutdown,
        proof_fingerprint=_shutdown_fingerprint(result),
    )
    if not result.complete:
        _fail("REHYDRATION_PROOF_INVALID", "доказательство остановки неполно")
    return result


def rehydrate_candidate_acceptance_proof_v2(
    *,
    database_path: Path,
    activation_proof_fingerprint: str,
    shutdown_proof_fingerprint: str,
    operation_id: str,
    activation_id: str,
    database_id: str,
    command_id: str,
) -> CandidateAcceptanceProofV2:
    """Заново доказать принятие точного кандидата его собственной базой."""

    activation_proof_fingerprint = _identifier(
        activation_proof_fingerprint, _SHA256
    )
    shutdown_proof_fingerprint = _identifier(shutdown_proof_fingerprint, _SHA256)
    operation_id = _identifier(operation_id, _OPERATION_ID)
    activation_id = _identifier(activation_id, _ACTIVATION_ID)
    database_id = _identifier(database_id, _DATABASE_ID)
    command_id = _identifier(command_id, _COMMAND_ID)
    with _read_exact_database(database_path) as connection:
        identity, _controller = _database_identity(connection)
        if (
            identity["activation_id"] != activation_id
            or identity["database_id"] != database_id
        ):
            _fail(
                "REHYDRATION_DATABASE_IDENTITY_MISMATCH",
                "база не принадлежит ожидаемому кандидату",
            )
        acceptance = _read_receipt(
            connection,
            command_id=command_id,
            operation_id=operation_id,
            method="controller_accept",
        )
        if (
            acceptance.proof.previous_control_epoch != 1
            or acceptance.proof.new_control_epoch != 2
        ):
            _fail(
                "REHYDRATION_EPOCH_MISMATCH",
                "принятие кандидата не началось с нормативной эпохи 1",
            )
        _verify_historical_candidate_acceptance(
            identity=identity,
            operation_id=operation_id,
            activation_id=activation_id,
            database_id=database_id,
            acceptance=acceptance,
        )
    result = CandidateAcceptanceProofV2(
        activation_proof_fingerprint=activation_proof_fingerprint,
        shutdown_proof_fingerprint=shutdown_proof_fingerprint,
        operation_id=operation_id,
        activation_id=activation_id,
        database_id=database_id,
        candidate_accept=acceptance.proof,
        proof_fingerprint="0" * 64,
    )
    result = CandidateAcceptanceProofV2(
        activation_proof_fingerprint=result.activation_proof_fingerprint,
        shutdown_proof_fingerprint=result.shutdown_proof_fingerprint,
        operation_id=result.operation_id,
        activation_id=result.activation_id,
        database_id=result.database_id,
        candidate_accept=result.candidate_accept,
        proof_fingerprint=_acceptance_fingerprint(result),
    )
    if not result.complete:
        _fail("REHYDRATION_PROOF_INVALID", "принятие кандидата неполно")
    return result


@contextmanager
def _read_exact_database(path: Path) -> Iterator[sqlite3.Connection]:
    database_path = _absolute_path(path)
    before = _private_database(database_path)
    try:
        connection = connect_sqlite_with_deadline_v2(
            f"file:{database_path}?mode=ro",
            uri=True,
            timeout=5,
            isolation_level=None,
        )
    except sqlite3.Error as exc:
        primary = ControllerTransitionRehydrationV2Error(
            "REHYDRATION_DATABASE_INVALID",
            str(exc),
        )
        raise primary from exc
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("pragma query_only=ON")
        connection.execute("pragma trusted_schema=OFF")
        connection.execute("BEGIN")
        if int(connection.execute("pragma application_id").fetchone()[0]) != APPLICATION_ID:
            _fail(
                "REHYDRATION_DATABASE_INVALID", "application_id базы отличается"
            )
        if int(connection.execute("pragma user_version").fetchone()[0]) != 2:
            _fail("REHYDRATION_DATABASE_INVALID", "user_version базы отличается")
        if [tuple(row) for row in connection.execute("pragma quick_check")] != [("ok",)]:
            _fail("REHYDRATION_DATABASE_INVALID", "quick_check базы не прошёл")
        if list(connection.execute("pragma foreign_key_check")):
            _fail(
                "REHYDRATION_DATABASE_INVALID", "целостность внешних ключей нарушена"
            )
        yield connection
    except sqlite3.Error as exc:
        _fail("REHYDRATION_DATABASE_INVALID", str(exc))
    finally:
        primary = sys.exception()
        cleanup_to_raise: BaseException | None = None
        try:
            if connection.in_transaction:
                connection.rollback_for_cleanup_v2()
        except BaseException as cleanup_error:
            if primary is None:
                primary = cleanup_error
                cleanup_to_raise = cleanup_error
            else:
                primary.add_note(
                    "SQLite rehydration cleanup rollback also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        try:
            connection.close()
        except BaseException as cleanup_error:
            if primary is None:
                primary = cleanup_error
                cleanup_to_raise = cleanup_error
            else:
                primary.add_note(
                    "SQLite rehydration close also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        if cleanup_to_raise is not None:
            raise cleanup_to_raise
    after = _private_database(database_path)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        _fail(
            "REHYDRATION_DATABASE_CHANGED",
            "путь базы сменил физический файл во время чтения",
        )


def _read_receipt(
    connection: sqlite3.Connection,
    *,
    command_id: str,
    operation_id: str,
    method: str,
) -> _ReceiptObservationV2:
    rows = connection.execute(
        "select * from controller_command_receipts where command_id=?",
        (command_id,),
    ).fetchall()
    if not rows:
        _fail(
            "REHYDRATION_RECEIPT_MISSING",
            f"квитанция {method} с точным commandId отсутствует",
        )
    if len(rows) != 1:
        _fail(
            "REHYDRATION_RECEIPT_CONFLICT", f"квитанция {method} не единственна"
        )
    row = dict(rows[0])
    if set(row) != _RECEIPT_COLUMNS:
        _fail(
            "REHYDRATION_RECEIPT_INVALID", f"поля квитанции {method} отличаются"
        )
    if (
        row["command_id"] != command_id
        or row["operation_id"] != operation_id
        or row["method"] != method
        or type(row["controller_identity"]) is not str
        or _SHA256.fullmatch(row["controller_identity"]) is None
    ):
        _fail(
            "REHYDRATION_RECEIPT_CONFLICT",
            f"квитанция {method} связана с другой командой или операцией",
        )
    request = _canonical_object(
        row["request_json"], code="REHYDRATION_REQUEST_FINGERPRINT_MISMATCH"
    )
    _validate_stored_request(
        request,
        row=row,
        command_id=command_id,
        operation_id=operation_id,
        method=method,
    )
    response = _canonical_object(
        row["response_json"], code="REHYDRATION_RECEIPT_INVALID"
    )
    if set(response) != _RESPONSE_KEYS:
        _fail(
            "REHYDRATION_RECEIPT_INVALID", f"поля ответа {method} отличаются"
        )
    payload = response.get("payload")
    if (
        response.get("messageType") != "response"
        or response.get("protocolVersion") != 2
        or response.get("release") != _RELEASE
        or response.get("method") != method
        or response.get("responseKind") != "SUCCESS"
        or response.get("commandId") != command_id
        or response.get("extensions") != {}
        or type(payload) is not dict
        or set(payload) != _PAYLOAD_KEYS_BY_METHOD[method]
        or payload.get("status") != _STATUS_BY_METHOD[method]
    ):
        _fail(
            "REHYDRATION_RECEIPT_INVALID", f"ответ {method} не является точным успехом"
        )
    request_fingerprint = row["request_fingerprint"]
    command_receipt = payload.get("commandReceipt")
    if (
        type(request_fingerprint) is not str
        or _SHA256.fullmatch(request_fingerprint) is None
        or response.get("requestFingerprint") != request_fingerprint
        or type(command_receipt) is not dict
        or set(command_receipt) != _RECEIPT_PAYLOAD_KEYS
        or command_receipt.get("requestFingerprint") != request_fingerprint
    ):
        _fail(
            "REHYDRATION_REQUEST_FINGERPRINT_MISMATCH",
            f"requestFingerprint квитанции {method} расходится",
        )
    if command_receipt.get("commandId") != command_id:
        _fail(
            "REHYDRATION_RECEIPT_CONFLICT",
            f"commandId вложенной квитанции {method} расходится",
        )
    response_fingerprint = response.get("responseFingerprint")
    if (
        type(response_fingerprint) is not str
        or _SHA256.fullmatch(response_fingerprint) is None
        or row["response_fingerprint"] != response_fingerprint
        or response_fingerprint != _response_fingerprint(response)
    ):
        _fail(
            "REHYDRATION_RESPONSE_FINGERPRINT_MISMATCH",
            f"responseFingerprint квитанции {method} расходится",
        )
    payload_base = {
        key: copy.deepcopy(value)
        for key, value in payload.items()
        if key != "commandReceipt"
    }
    expected_result = domain_fingerprint(
        _RESULT_DOMAIN,
        {"method": method, "payload": payload_base},
    )
    if (
        row["result_fingerprint"] != expected_result
        or command_receipt.get("resultFingerprint") != expected_result
    ):
        _fail(
            "REHYDRATION_RESULT_FINGERPRINT_MISMATCH",
            f"resultFingerprint квитанции {method} расходится",
        )
    before_epoch = row["before_epoch"]
    after_epoch = row["after_epoch"]
    if (
        type(before_epoch) is not int
        or type(after_epoch) is not int
        or before_epoch < 1
        or after_epoch != before_epoch + 1
        or payload.get("previousControlEpoch") != before_epoch
        or payload.get("newControlEpoch") != after_epoch
        or response.get("controlEpoch") != after_epoch
        or command_receipt.get("controlEpoch") != after_epoch
    ):
        _fail(
            "REHYDRATION_EPOCH_MISMATCH", f"эпохи квитанции {method} расходятся"
        )
    _validate_instance_id(row["before_instance_id"], nullable=True)
    _validate_instance_id(row["resulting_instance_id"], nullable=True)
    proof = LifecycleControllerCommandProofV2(
        method=method,
        status=_STATUS_BY_METHOD[method],
        command_id=command_id,
        request_fingerprint=request_fingerprint,
        response_fingerprint=response_fingerprint,
        previous_control_epoch=before_epoch,
        new_control_epoch=after_epoch,
        payload=copy.deepcopy(payload),
    )
    return _ReceiptObservationV2(
        row=row,
        request=request,
        response=response,
        proof=proof,
    )


def _validate_stored_request(
    request: Mapping[str, Any],
    *,
    row: Mapping[str, Any],
    command_id: str,
    operation_id: str,
    method: str,
) -> None:
    params = request.get("params")
    instance_id = request.get("instanceId")
    if (
        set(request) != _REQUEST_KEYS
        or request.get("messageType") != "request"
        or request.get("protocolVersion") != 2
        or request.get("release") != _RELEASE
        or request.get("extensions") != {}
        or request.get("commandId") != command_id
        or request.get("operationId") != operation_id
        or request.get("method") != method
        or request.get("controllerIdentity") != row["controller_identity"]
        or type(request.get("codexHomeHash")) is not str
        or _SHA256.fullmatch(str(request["codexHomeHash"])) is None
        or type(request.get("shellSessionId")) is not str
        or not request["shellSessionId"]
        or len(request["shellSessionId"]) > 256
        or type(request.get("controllerStartId")) is not str
        or _CONTROLLER_START_ID.fullmatch(str(request["controllerStartId"])) is None
        or type(params) is not dict
    ):
        _request_mismatch(method)
    if request.get("expectedControlEpoch") != row["before_epoch"]:
        _fail(
            "REHYDRATION_EPOCH_MISMATCH",
            f"эпоха сохранённого запроса {method} расходится с квитанцией",
        )
    if method in {"controller_accept", "controller_recover"}:
        if instance_id is not None:
            _request_mismatch(method)
    elif (
        type(instance_id) is not str
        or _INSTANCE_ID.fullmatch(instance_id) is None
        or instance_id != row["before_instance_id"]
    ):
        _request_mismatch(method)
    if method == "maintenance_begin":
        reason = params.get("reasonCode")
        if (
            set(params) != {"reasonCode"}
            or type(reason) is not str
            or not reason
            or len(reason) > 128
        ):
            _request_mismatch(method)
    elif method == "maintenance_strengthen":
        if params != {"mode": "freeze"}:
            _request_mismatch(method)
    elif method in {"shutdown", "maintenance_resume"}:
        if params != {}:
            _request_mismatch(method)
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
            _request_mismatch(method)
        expected_orphan_operation_id = params.get("expectedOrphanOperationId")
        if (
            type(params.get("activationId")) is not str
            or _ACTIVATION_ID.fullmatch(str(params["activationId"])) is None
            or type(params.get("databaseId")) is not str
            or _DATABASE_ID.fullmatch(str(params["databaseId"])) is None
            or not _positive_integer(params.get("pid"))
            or int(params["pid"]) > 2_147_483_647
            or type(params.get("processStartMarker")) is not str
            or not params["processStartMarker"]
            or len(params["processStartMarker"]) > 256
            or not _positive_integer(params.get("processGroupId"))
            or int(params["processGroupId"]) > 2_147_483_647
            or (
                method == "controller_accept"
                and expected_orphan_operation_id is not None
                and (
                    type(expected_orphan_operation_id) is not str
                    or _OPERATION_ID.fullmatch(expected_orphan_operation_id) is None
                    or expected_orphan_operation_id == operation_id
                )
            )
        ):
            _request_mismatch(method)
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
    expected_fingerprint = domain_fingerprint(_REQUEST_DOMAIN, projection)
    if (
        request.get("requestFingerprint") != expected_fingerprint
        or row["request_fingerprint"] != expected_fingerprint
    ):
        _request_mismatch(method)


def _request_mismatch(method: str) -> None:
    _fail(
        "REHYDRATION_REQUEST_FINGERPRINT_MISMATCH",
        f"сохранённый запрос {method} не совпал с requestFingerprint",
    )


def _require_exact_shutdown_receipt_set(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    command_ids: ControllerShutdownCommandIdsV2,
) -> None:
    rows = connection.execute(
        "select command_id,method from controller_command_receipts "
        "where operation_id=? and method in "
        "('maintenance_begin','maintenance_strengthen','shutdown')",
        (operation_id,),
    ).fetchall()
    expected = {
        (command_ids.maintenance_begin, "maintenance_begin"),
        (command_ids.maintenance_strengthen, "maintenance_strengthen"),
        (command_ids.shutdown, "shutdown"),
    }
    if {(row["command_id"], row["method"]) for row in rows} != expected or len(rows) != 3:
        _fail(
            "REHYDRATION_RECEIPT_CONFLICT",
            "набор квитанций операции не совпал с точной цепочкой остановки",
        )


def _verify_shutdown_epoch_chain(
    begin: _ReceiptObservationV2,
    strengthen: _ReceiptObservationV2,
    shutdown: _ReceiptObservationV2,
) -> None:
    rows = (begin.row, strengthen.row, shutdown.row)
    instance_id = rows[0]["before_instance_id"]
    if (
        begin.proof.new_control_epoch != strengthen.proof.previous_control_epoch
        or strengthen.proof.new_control_epoch != shutdown.proof.previous_control_epoch
        or instance_id is None
        or rows[0]["resulting_instance_id"] != instance_id
        or rows[1]["before_instance_id"] != instance_id
        or rows[1]["resulting_instance_id"] != instance_id
        or rows[2]["before_instance_id"] != instance_id
        or rows[2]["resulting_instance_id"] is not None
        or len({row["controller_identity"] for row in rows}) != 1
    ):
        _fail(
            "REHYDRATION_EPOCH_MISMATCH",
            "цепочка эпох или экземпляров остановки разорвана",
        )


def _verify_shutdown_request_chain(
    begin: _ReceiptObservationV2,
    strengthen: _ReceiptObservationV2,
    shutdown: _ReceiptObservationV2,
) -> None:
    requests = (begin.request, strengthen.request, shutdown.request)
    if (
        len({request["controllerIdentity"] for request in requests}) != 1
        or len({request["instanceId"] for request in requests}) != 1
        or len({request["controllerStartId"] for request in requests}) != 1
        or len({request["codexHomeHash"] for request in requests}) != 1
    ):
        _fail(
            "REHYDRATION_RECEIPT_CONFLICT",
            "сохранённые запросы остановки относятся к разным контроллерам",
        )


def _read_shutdown_quiescence(
    row: Mapping[str, Any],
    *,
    operation_id: str,
    control_epoch: int,
) -> LifecycleControllerQuiescenceV2:
    document = _canonical_object(
        row.get("quiescence_proof_json"), code="REHYDRATION_QUIESCENCE_INVALID"
    )
    counts = document.get("workCounts")
    if (
        set(document)
        != {
            "workCounts",
            "databasePredicatesFingerprint",
            "barrierHeld",
            "quiescent",
        }
        or type(counts) is not dict
        or set(counts) != set(_QUIESCENCE_QUERIES)
        or any(type(counts[name]) is not int or counts[name] != 0 for name in counts)
        or document.get("barrierHeld") is not True
        or document.get("quiescent") is not True
    ):
        _fail(
            "REHYDRATION_QUIESCENCE_INVALID", "сохранённое доказательство покоя неверно"
        )
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
    if document.get("databasePredicatesFingerprint") != domain_fingerprint(
        _PREDICATES_DOMAIN, projection
    ):
        _fail(
            "REHYDRATION_QUIESCENCE_INVALID",
            "fingerprint предикатов покоя расходится",
        )
    return LifecycleControllerQuiescenceV2(
        operation_id=operation_id,
        state="MAINTENANCE",
        maintenance_mode="DRAIN",
        control_epoch=control_epoch,
        quiescent=True,
    )


def _read_shutdown_socket_intent(
    shutdown: _ReceiptObservationV2,
) -> dict[str, Any]:
    intent = _canonical_object(
        shutdown.row.get("socket_intent_json"),
        code="REHYDRATION_SOCKET_INTENT_INVALID",
    )
    if (
        set(intent) != _SOCKET_INTENT_KEYS
        or shutdown.proof.payload.get("socketIntent") != intent
        or not _absolute_string_path(intent.get("path"))
        or not _absolute_string_path(intent.get("lockPath"))
        or Path(str(intent["path"])).parent != Path(str(intent["lockPath"])).parent
        or not _nonnegative_integer(intent.get("device"))
        or not _nonnegative_integer(intent.get("inode"))
        or not _nonnegative_integer(intent.get("ownerUid"))
        or not _nonnegative_integer(intent.get("ownerGid"))
        or intent.get("ownerUid") != os.getuid()
        or type(intent.get("mode")) is not str
        or _MODE.fullmatch(str(intent["mode"])) is None
        or not _positive_integer(intent.get("controllerPid"))
        or not _positive_integer(intent.get("controllerProcessGroupId"))
        or type(intent.get("controllerStartMarker")) is not str
        or not intent["controllerStartMarker"]
        or intent.get("processExitRequired") is not True
        or intent.get("exclusiveLockRequired") is not True
    ):
        _fail(
            "REHYDRATION_SOCKET_INTENT_INVALID", "socketIntent остановки расходится"
        )
    return intent


def _database_identity(
    connection: sqlite3.Connection,
) -> tuple[dict[str, Any], dict[str, Any]]:
    identity_rows = connection.execute("select * from database_identity").fetchall()
    controller_rows = connection.execute("select * from controller_state").fetchall()
    if len(identity_rows) != 1 or len(controller_rows) != 1:
        _fail(
            "REHYDRATION_DATABASE_IDENTITY_MISMATCH",
            "строки идентичности базы или контроллера не единственны",
        )
    identity = dict(identity_rows[0])
    controller = dict(controller_rows[0])
    if (
        identity.get("singleton") != 1
        or identity.get("schema_version") != 2
        or type(identity.get("database_id")) is not str
        or _DATABASE_ID.fullmatch(identity["database_id"]) is None
        or type(identity.get("activation_id")) is not str
        or _ACTIVATION_ID.fullmatch(identity["activation_id"]) is None
        or type(identity.get("activation_fingerprint")) is not str
        or _SHA256.fullmatch(identity["activation_fingerprint"]) is None
        or identity["activation_id"]
        != "act2_" + identity["activation_fingerprint"]
        or controller.get("singleton") != 1
        or controller.get("database_id") != identity["database_id"]
        or controller.get("activation_id") != identity["activation_id"]
        or controller.get("activation_fingerprint")
        != identity["activation_fingerprint"]
    ):
        _fail(
            "REHYDRATION_DATABASE_IDENTITY_MISMATCH",
            "database_identity и controller_state не образуют точную связь",
        )
    return identity, controller


def _verify_shutdown_database_state(
    *,
    identity: Mapping[str, Any],
    controller: Mapping[str, Any],
    operation_id: str,
    receipts: tuple[_ReceiptObservationV2, ...],
) -> None:
    shutdown = receipts[-1]
    cleared = (
        "instance_id",
        "controller_start_id",
        "controller_pid",
        "controller_process_start_marker",
        "controller_process_group_id",
        "socket_path",
        "socket_device",
        "socket_inode",
        "socket_owner_uid",
        "socket_owner_gid",
        "socket_mode",
    )
    if (
        controller.get("controller_identity") != shutdown.row["controller_identity"]
        or any(
            receipt.row["controller_identity"] != controller["controller_identity"]
            for receipt in receipts
        )
        or controller.get("control_epoch") != shutdown.proof.new_control_epoch
        or controller.get("state") != "MAINTENANCE"
        or controller.get("maintenance_mode") != "FREEZE"
        or controller.get("reason_code") != "AWAITING_CONTROLLER_ACCEPT"
        or controller.get("operation_id") != operation_id
        or any(controller.get(name) is not None for name in cleared)
        or controller.get("lock_held") != 0
        or controller.get("accepting_new_routes") != 0
        or controller.get("quiescent") != 1
        or identity.get("database_id") != controller.get("database_id")
    ):
        _fail(
            "REHYDRATION_CONTROLLER_STATE_MISMATCH",
            "текущее состояние базы не подтверждает завершённый shutdown",
        )


def _verify_historical_candidate_acceptance(
    *,
    identity: Mapping[str, Any],
    operation_id: str,
    activation_id: str,
    database_id: str,
    acceptance: _ReceiptObservationV2,
) -> None:
    payload = acceptance.proof.payload
    request = acceptance.request
    params = request["params"]
    if (
        acceptance.row["before_instance_id"] is not None
        or acceptance.row["resulting_instance_id"] != payload.get("instanceId")
        or request.get("operationId") != operation_id
        or request.get("controllerIdentity")
        != acceptance.row["controller_identity"]
        or payload.get("controllerIdentity") != request.get("controllerIdentity")
        or type(payload.get("instanceId")) is not str
        or _INSTANCE_ID.fullmatch(str(payload["instanceId"])) is None
        or payload.get("controllerStartId") != request.get("controllerStartId")
        or type(payload.get("controllerStartId")) is not str
        or _CONTROLLER_START_ID.fullmatch(str(payload["controllerStartId"])) is None
        or params.get("activationId") != activation_id
        or params.get("databaseId") != database_id
        or identity.get("activation_id") != activation_id
        or identity.get("database_id") != database_id
    ):
        _fail(
            "REHYDRATION_RECEIPT_CONFLICT",
            "историческая квитанция принятия не связана с точным кандидатом",
        )


def _response_fingerprint(response: Mapping[str, Any]) -> str:
    projection = {
        key: copy.deepcopy(value)
        for key, value in response.items()
        if key not in {"responseFingerprint", "extensions"}
    }
    return domain_fingerprint(_RESPONSE_DOMAIN, projection)


def _command_projection(value: LifecycleControllerCommandProofV2) -> dict[str, Any]:
    return {
        "method": value.method,
        "status": value.status,
        "commandId": value.command_id,
        "requestFingerprint": value.request_fingerprint,
        "responseFingerprint": value.response_fingerprint,
        "previousControlEpoch": value.previous_control_epoch,
        "newControlEpoch": value.new_control_epoch,
        "payload": copy.deepcopy(dict(value.payload)),
    }


def _shutdown_fingerprint(value: ControllerShutdownProofV2) -> str:
    return domain_fingerprint(
        _SHUTDOWN_DOMAIN,
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "operationId": value.operation_id,
            "maintenanceBegin": _command_projection(value.maintenance_begin),
            "quiescence": {
                "operationId": value.quiescence.operation_id,
                "state": value.quiescence.state,
                "maintenanceMode": value.quiescence.maintenance_mode,
                "controlEpoch": value.quiescence.control_epoch,
                "quiescent": value.quiescence.quiescent,
            },
            "maintenanceStrengthen": _command_projection(
                value.maintenance_strengthen
            ),
            "shutdown": _command_projection(value.shutdown),
        },
    )


def _acceptance_fingerprint(value: CandidateAcceptanceProofV2) -> str:
    return domain_fingerprint(
        _ACCEPTANCE_DOMAIN,
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "shutdownProofFingerprint": value.shutdown_proof_fingerprint,
            "operationId": value.operation_id,
            "activationId": value.activation_id,
            "databaseId": value.database_id,
            "candidateAccept": _command_projection(value.candidate_accept),
        },
    )


def _canonical_object(value: Any, *, code: str) -> dict[str, Any]:
    if type(value) is not str or len(value.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        _fail(code, "сохранённый JSON отсутствует либо слишком велик")
    try:
        document = json.loads(value, object_pairs_hook=_unique_object)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        _fail(code, str(exc))
    if type(document) is not dict:
        _fail(code, "сохранённый JSON не является объектом")
    try:
        canonical = canonical_json_bytes(document).decode("utf-8")
    except (TypeError, ValueError) as exc:
        _fail(code, str(exc))
    if canonical != value:
        _fail(code, "сохранённый JSON не имеет каноническую форму")
    return document


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("повторяющийся ключ JSON")
        result[key] = value
    return result


def _private_database(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        _fail("REHYDRATION_DATABASE_INVALID", str(exc))
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail(
            "REHYDRATION_DATABASE_INVALID",
            "база должна быть частным обычным файлом текущего пользователя",
        )
    return info


def _absolute_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("REHYDRATION_ARGUMENT_INVALID", "путь базы должен быть абсолютным")
    return path


def _identifier(value: Any, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail("REHYDRATION_ARGUMENT_INVALID", "идентификатор имеет неверную форму")
    return value


def _validate_instance_id(value: Any, *, nullable: bool) -> None:
    if value is None and nullable:
        return
    if type(value) is not str or _INSTANCE_ID.fullmatch(value) is None:
        _fail("REHYDRATION_RECEIPT_INVALID", "instanceId квитанции неверен")


def _absolute_string_path(value: Any) -> bool:
    return type(value) is str and bool(value) and Path(value).is_absolute()


def _positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def _nonnegative_integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def _fail(code: str, message: str) -> None:
    raise ControllerTransitionRehydrationV2Error(code, message)


__all__ = [
    "ControllerShutdownCommandIdsV2",
    "ControllerTransitionRehydrationV2Error",
    "RehydratedControllerCommandV2",
    "rehydrate_candidate_acceptance_proof_v2",
    "rehydrate_controller_command_v2",
    "rehydrate_controller_shutdown_proof_v2",
]
