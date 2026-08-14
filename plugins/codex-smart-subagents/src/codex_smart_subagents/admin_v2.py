"""Ограниченный административный интерфейс принятой активации версии 2."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any, Mapping, TextIO

from .admin_state_v2 import (
    AdminConfigV2,
    AdminV2Error,
    ProvenAdminStateV2,
    exclusive_controller_lock_v2 as _exclusive_controller_lock,
    load_proven_state_v2 as _load_proven_state,
    open_readonly_database_v2 as _open_readonly_database,
    open_runtime_store_v2 as _open_runtime_store,
    probe_live_controller_v2 as _probe_live_controller,
    require_controller_stopped_v2 as _require_controller_stopped,
    stop_live_controller_v2 as _stop_live_controller,
)
from .candidate_recovery_v2 import CandidateRecoveryV2Error
from .execution_recovery_v2 import ExecutionRecoveryV2Error
from .runtime_recovery_v2 import (
    RuntimeRecoveryReportV2,
    RuntimeRecoveryV2Error,
    prepare_attempts_root_v2,
)
from .recovery_suite_v2 import RecoverySuiteReportV2, RecoverySuiteV2


EXIT_OK = 0
EXIT_WARNING = 1
EXIT_ARGUMENT = 2
EXIT_NOT_FOUND = 3
EXIT_UNSAFE = 4
EXIT_INTERNAL = 5
_COMMANDS = frozenset({"status", "doctor", "inspect", "recover", "stop"})
_ROUTE_ID = re.compile(r"^route2_[0-9a-f]{32}$")
_MAX_INSPECT_LIMIT = 200
_RECOVERY_ERRORS = (
    CandidateRecoveryV2Error,
    ExecutionRecoveryV2Error,
    RuntimeRecoveryV2Error,
)


@dataclass(frozen=True)
class CommandResultV2:
    exit_code: int
    ok: bool
    code: str
    message: str
    data: dict[str, Any]


class _ReadonlyRecoveryStoreV2:
    """Минимальная проекция хранилища для гарантированно пробного плана."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def runtime_artifacts(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "select * from runtime_artifacts order by created_at,artifact_id"
        ).fetchall()
        return [
            {
                "artifactId": str(row["artifact_id"]),
                "routeId": str(row["route_id"]),
                "nodeId": str(row["node_id"]),
                "kind": str(row["kind"]),
                "path": str(row["path"]),
                "allowedRoot": str(row["allowed_root"]),
                "state": str(row["state"]),
                "device": None if row["device"] is None else int(row["device"]),
                "inode": None if row["inode"] is None else int(row["inode"]),
                "createdAt": str(row["created_at"]),
                "updatedAt": str(row["updated_at"]),
            }
            for row in rows
        ]

    def seal_runtime_artifact(
        self,
        artifact_id: str,
        *,
        terminal: bool,
    ) -> Mapping[str, Any]:
        del artifact_id, terminal
        raise RuntimeError("пробное хранилище запрещает изменения")

    def stranded_attempts(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "select attempt_id,route_id,node_id,state,pid,process_start_marker "
            "from attempts where state in ('STARTING','RUNNING') "
            "order by started_at,attempt_id"
        ).fetchall()
        return [
            {
                "attemptId": str(row["attempt_id"]),
                "routeId": str(row["route_id"]),
                "nodeId": str(row["node_id"]),
                "state": str(row["state"]),
                "pid": int(row["pid"]),
                "processStartMarker": str(row["process_start_marker"]),
            }
            for row in rows
        ]

    def stranded_launch_permits(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "select permit_id,route_id,node_id,state,guard_pid,guard_start_marker "
            "from node_launch_permits where state in ('RESERVED','GUARDED') "
            "order by reserved_at,permit_id"
        ).fetchall()
        return [
            {
                "permitId": str(row["permit_id"]),
                "routeId": str(row["route_id"]),
                "nodeId": str(row["node_id"]),
                "state": str(row["state"]),
                "guardPid": (
                    None if row["guard_pid"] is None else int(row["guard_pid"])
                ),
                "guardStartMarker": (
                    None
                    if row["guard_start_marker"] is None
                    else str(row["guard_start_marker"])
                ),
            }
            for row in rows
        ]

    def quarantine_repositories(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "select * from quarantine_repositories where state='ACTIVE' "
            "order by repository_id"
        ).fetchall()
        return [
            {
                "repositoryId": str(row["repository_id"]),
                "sourceRoot": str(row["source_root"]),
                "stateRoot": str(row["state_root"]),
                "gitDir": str(row["git_dir"]),
                "state": str(row["state"]),
                "createdAt": str(row["created_at"]),
                "updatedAt": str(row["updated_at"]),
            }
            for row in rows
        ]

    def pending_candidate_publications(
        self,
        repository_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = "select * from candidate_publication_intents where state='PENDING'"
        parameters: tuple[str, ...] = ()
        if repository_id is not None:
            query += " and repository_id=?"
            parameters = (repository_id,)
        query += " order by created_at,intent_id"
        return [self._candidate_intent(row) for row in self.connection.execute(query, parameters)]

    def candidate_intent(self, intent_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "select * from candidate_publication_intents where intent_id=?",
            (intent_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("candidate intent does not exist")
        return self._candidate_intent(row)

    @staticmethod
    def _candidate_intent(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "intentId": str(row["intent_id"]),
            "routeId": str(row["route_id"]),
            "nodeId": str(row["node_id"]),
            "repositoryId": str(row["repository_id"]),
            "artifactId": str(row["artifact_id"]),
            "ref": str(row["ref"]),
            "baseSourceSha": str(row["base_source_sha"]),
            "baseCommitSha": str(row["base_commit_sha"]),
            "baseTreeSha": str(row["base_tree_sha"]),
            "commitSha": str(row["commit_sha"]),
            "treeSha": str(row["tree_sha"]),
            "validationProofSha256": (
                None
                if row["validation_proof_sha256"] is None
                else str(row["validation_proof_sha256"])
            ),
            "state": str(row["state"]),
            "createdAt": str(row["created_at"]),
            "updatedAt": str(row["updated_at"]),
            "completedAt": (
                None if row["completed_at"] is None else str(row["completed_at"])
            ),
        }

    def __getattr__(self, name: str) -> Any:
        if name in {
            "begin_stranded_attempt_recovery",
            "complete_stranded_attempt_recovery",
            "begin_stranded_permit_recovery",
            "complete_stranded_permit_recovery",
            "recover_candidate_publication",
            "abort_candidate_publication",
            "quarantine_mismatched_publication",
        }:
            return self._forbid_write
        raise AttributeError(name)

    @staticmethod
    def _forbid_write(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        del args, kwargs
        raise RuntimeError("пробное хранилище запрещает изменения")


class _EmptyRuntimeRecoveryV2:
    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    def run(self, *, apply: bool) -> RuntimeRecoveryReportV2:
        return RuntimeRecoveryReportV2(
            ok=True,
            applied=False,
            actions=(),
            blockers=(),
        )


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    output = sys.stdout if stdout is None else stdout
    command = arguments[0] if arguments and arguments[0] in _COMMANDS else "unknown"
    try:
        command, options = _parse_arguments(arguments)
        config = AdminConfigV2.from_environ(os.environ if environ is None else environ)
        proven = _load_proven_state(config)
        result = _dispatch(command, options, proven)
    except AdminV2Error as exc:
        result = CommandResultV2(
            exit_code=exc.exit_code,
            ok=False,
            code=exc.code,
            message=exc.message,
            data=exc.data,
        )
    except Exception:
        result = CommandResultV2(
            exit_code=EXIT_INTERNAL,
            ok=False,
            code="INTERNAL_ERROR",
            message="Внутренняя ошибка административной команды версии 2.",
            data={},
        )
    output.write(
        json.dumps(
            {
                "schemaVersion": 2,
                "ok": result.ok,
                "command": command,
                "code": result.code,
                "message": result.message,
                "data": result.data,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return result.exit_code


def _parse_arguments(arguments: list[str]) -> tuple[str, dict[str, Any]]:
    if arguments == ["status"]:
        return "status", {}
    if arguments == ["doctor"]:
        return "doctor", {}
    if arguments == ["stop"]:
        return "stop", {}
    if arguments[:1] == ["inspect"] and len(arguments) in {2, 4}:
        route_id = arguments[1]
        if _ROUTE_ID.fullmatch(route_id) is None:
            raise AdminV2Error(
                EXIT_ARGUMENT,
                "INVALID_ROUTE_ID",
                "Идентификатор маршрута не относится к версии 2.",
                {},
            )
        limit = 100
        if len(arguments) == 4:
            if arguments[2] != "--limit":
                raise AdminV2Error(
                    EXIT_ARGUMENT,
                    "INVALID_ARGUMENTS",
                    "Неверные аргументы команды inspect.",
                    {},
                )
            try:
                limit = int(arguments[3])
            except ValueError as exc:
                raise AdminV2Error(
                    EXIT_ARGUMENT,
                    "INVALID_ARGUMENTS",
                    "Предел inspect должен быть целым числом.",
                    {},
                ) from exc
            if not 1 <= limit <= _MAX_INSPECT_LIMIT:
                raise AdminV2Error(
                    EXIT_ARGUMENT,
                    "INVALID_ARGUMENTS",
                    "Предел inspect находится вне допустимого диапазона.",
                    {},
                )
        return "inspect", {"route_id": route_id, "limit": limit}
    if (
        len(arguments) == 2
        and arguments[0] == "recover"
        and arguments[1] in {"--dry-run", "--apply"}
    ):
        return "recover", {"apply": arguments[1] == "--apply"}
    raise AdminV2Error(
        EXIT_ARGUMENT,
        "INVALID_ARGUMENTS",
        "Неверные аргументы административной команды версии 2.",
        {},
    )


def _dispatch(
    command: str,
    options: Mapping[str, Any],
    proven: ProvenAdminStateV2,
) -> CommandResultV2:
    if command == "status":
        return _status(proven)
    if command == "inspect":
        return _inspect(
            proven,
            route_id=str(options["route_id"]),
            limit=int(options["limit"]),
        )
    if command == "doctor":
        return _doctor(proven)
    if command == "stop":
        return _stop(proven)
    if command == "recover":
        return _recover(proven, apply=bool(options["apply"]))
    raise AdminV2Error(
        EXIT_INTERNAL,
        "DISPATCH_INVARIANT_FAILED",
        "Нарушен внутренний договор диспетчеризации версии 2.",
        {},
    )


def _status(proven: ProvenAdminStateV2) -> CommandResultV2:
    with _open_readonly_database(proven) as connection:
        counts = {
            "routeStates": _state_counts(connection, "routes"),
            "attemptStates": _state_counts(connection, "attempts"),
            "runtimeArtifactStates": _state_counts(
                connection,
                "runtime_artifacts",
            ),
        }
    live, reason = _probe_live_controller(proven)
    binding = proven.binding
    controller = binding.controller_row
    return CommandResultV2(
        exit_code=EXIT_OK if live else EXIT_WARNING,
        ok=True,
        code="READY" if live else "PERSISTED_READY",
        message=(
            "Активация версии 2 и живой контроллер подтверждены."
            if live
            else "Активация версии 2 подтверждена, живой контроллер не подтверждён."
        ),
        data={
            "activationId": binding.activation_id,
            "databaseId": binding.database_identity_row["database_id"],
            "controlEpoch": binding.control_epoch,
            "controller": {
                "state": controller["state"],
                "live": live,
                "reasonCode": reason,
            },
            "counts": counts,
        },
    )


def _inspect(
    proven: ProvenAdminStateV2,
    *,
    route_id: str,
    limit: int,
) -> CommandResultV2:
    with _open_readonly_database(proven) as connection:
        route = connection.execute(
            "select route_id,state,disposition,startable,catalog_generation,"
            "algorithm_version,created_at,updated_at,expires_at from routes "
            "where route_id=?",
            (route_id,),
        ).fetchone()
        if route is None:
            raise AdminV2Error(
                EXIT_NOT_FOUND,
                "ROUTE_NOT_FOUND",
                "Маршрут версии 2 не найден.",
                {"routeId": route_id},
            )
        nodes = connection.execute(
            "select node_id,ordinal,role,state,selected_model,reasoning_effort,"
            "permission_profile_id,disposition,attempt_count,admission_state,updated_at "
            "from nodes where route_id=? order by ordinal,node_id limit ?",
            (route_id, limit),
        ).fetchall()
        attempts = connection.execute(
            "select attempt_id,node_id,state,model,reasoning_effort,permission_profile_id,"
            "started_at,ended_at,error_code,evidence_kind from attempts "
            "where route_id=? order by started_at,attempt_id limit ?",
            (route_id, limit),
        ).fetchall()
        events = connection.execute(
            "select sequence,node_id,event,state,code,created_at from "
            "(select sequence,node_id,event,state,code,created_at from events "
            "where route_id=? order by sequence desc limit ?) order by sequence",
            (route_id, limit),
        ).fetchall()
        artifacts = connection.execute(
            "select artifact_id,node_id,kind,state,created_at,updated_at "
            "from runtime_artifacts where route_id=? "
            "order by created_at,artifact_id limit ?",
            (route_id, limit),
        ).fetchall()
        candidates = connection.execute(
            "select candidate_id,node_id,state,validation_state,trusted,created_at,updated_at "
            "from candidate_registry where route_id=? "
            "order by created_at,candidate_id limit ?",
            (route_id, limit),
        ).fetchall()
    return CommandResultV2(
        exit_code=EXIT_OK,
        ok=True,
        code="ROUTE_INSPECTED",
        message="Операционное состояние маршрута версии 2 прочитано.",
        data={
            "route": {
                "routeId": route["route_id"],
                "state": route["state"],
                "disposition": route["disposition"],
                "startable": bool(route["startable"]),
                "catalogGeneration": route["catalog_generation"],
                "algorithmVersion": route["algorithm_version"],
                "createdAt": route["created_at"],
                "updatedAt": route["updated_at"],
                "expiresAt": route["expires_at"],
            },
            "nodes": [
                {
                    "nodeId": row["node_id"],
                    "ordinal": row["ordinal"],
                    "role": row["role"],
                    "state": row["state"],
                    "model": row["selected_model"],
                    "reasoningEffort": row["reasoning_effort"],
                    "permissionProfileId": row["permission_profile_id"],
                    "disposition": row["disposition"],
                    "attemptCount": row["attempt_count"],
                    "admissionState": row["admission_state"],
                    "updatedAt": row["updated_at"],
                }
                for row in nodes
            ],
            "attempts": [
                {
                    "attemptId": row["attempt_id"],
                    "nodeId": row["node_id"],
                    "state": row["state"],
                    "model": row["model"],
                    "reasoningEffort": row["reasoning_effort"],
                    "permissionProfileId": row["permission_profile_id"],
                    "startedAt": row["started_at"],
                    "endedAt": row["ended_at"],
                    "errorCode": row["error_code"],
                    "evidenceKind": row["evidence_kind"],
                }
                for row in attempts
            ],
            "events": [
                {
                    "sequence": row["sequence"],
                    "nodeId": row["node_id"],
                    "event": row["event"],
                    "state": row["state"],
                    "code": row["code"],
                    "createdAt": row["created_at"],
                }
                for row in events
            ],
            "runtimeArtifacts": [
                {
                    "artifactId": row["artifact_id"],
                    "nodeId": row["node_id"],
                    "kind": row["kind"],
                    "state": row["state"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                }
                for row in artifacts
            ],
            "candidates": [
                {
                    "candidateId": row["candidate_id"],
                    "nodeId": row["node_id"],
                    "state": row["state"],
                    "validationState": row["validation_state"],
                    "trusted": bool(row["trusted"]),
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                }
                for row in candidates
            ],
            "limit": limit,
        },
    )


def _doctor(proven: ProvenAdminStateV2) -> CommandResultV2:
    recovery = _plan_recovery_suite(proven)
    recovery_data = _recovery_data(recovery)
    if recovery.blockers:
        return CommandResultV2(
            exit_code=EXIT_UNSAFE,
            ok=False,
            code="RECOVERY_BLOCKED",
            message="Восстановление версии 2 заблокировано неизвестным состоянием.",
            data={"recovery": recovery_data},
        )
    if recovery.actions:
        return CommandResultV2(
            exit_code=EXIT_WARNING,
            ok=True,
            code="RECOVERY_REQUIRED",
            message="Обнаружены подтверждённые остатки попыток версии 2.",
            data={"recovery": recovery_data},
        )
    live, reason = _probe_live_controller(proven)
    return CommandResultV2(
        exit_code=EXIT_OK if live else EXIT_WARNING,
        ok=True,
        code="READY" if live else "CONTROLLER_UNAVAILABLE",
        message=(
            "Проверка версии 2 завершена успешно."
            if live
            else "Постоянное состояние подтверждено, контроллер недоступен."
        ),
        data={
            "controller": {"live": live, "reasonCode": reason},
            "recovery": recovery_data,
        },
    )


def _stop(proven: ProvenAdminStateV2) -> CommandResultV2:
    report = _stop_live_controller(proven)
    already_stopped = report.reason_code == "CONTROLLER_ALREADY_STOPPED"
    return CommandResultV2(
        exit_code=EXIT_OK,
        ok=True,
        code=report.reason_code,
        message=(
            "Контроллер уже остановлен."
            if already_stopped
            else "Подтверждённый процесс контроллера остановлен."
        ),
        data={
            "pid": report.pid,
            "stopped": report.stopped,
            "signaled": report.signaled,
        },
    )


def _recover(
    proven: ProvenAdminStateV2,
    *,
    apply: bool,
) -> CommandResultV2:
    if not apply:
        report = _plan_recovery_suite(proven)
        return _recovery_result(report, applied_request=False)
    _require_controller_stopped(proven)
    with _exclusive_controller_lock(proven):
        _require_controller_stopped(proven)
        with _open_readonly_database(proven):
            pass
        report = _apply_recovery_suite(proven)
    return _recovery_result(report, applied_request=True)


def _recovery_result(
    report: RecoverySuiteReportV2,
    *,
    applied_request: bool,
) -> CommandResultV2:
    data = {
        "mode": "apply" if applied_request else "dry-run",
        "recovery": _recovery_data(report),
    }
    if report.blockers:
        return CommandResultV2(
            exit_code=EXIT_UNSAFE,
            ok=False,
            code="RECOVERY_BLOCKED",
            message="Восстановление заблокировано неизвестным состоянием.",
            data=data,
        )
    if not applied_request and report.actions:
        return CommandResultV2(
            exit_code=EXIT_WARNING,
            ok=True,
            code="RECOVERY_REQUIRED",
            message="План восстановления построен без изменений.",
            data=data,
        )
    if applied_request and report.actions:
        return CommandResultV2(
            exit_code=EXIT_OK,
            ok=True,
            code="RECOVERY_APPLIED",
            message="Подтверждённый план восстановления применён.",
            data=data,
        )
    return CommandResultV2(
        exit_code=EXIT_OK,
        ok=True,
        code="RECOVERY_NOT_REQUIRED",
        message="Подтверждённых действий восстановления нет.",
        data=data,
    )


def _plan_recovery_suite(proven: ProvenAdminStateV2) -> RecoverySuiteReportV2:
    attempts_root = proven.binding.state_home / "attempt-runtimes-v2"
    with _open_readonly_database(proven) as connection:
        store = _ReadonlyRecoveryStoreV2(connection)
        runtime_factory: Any = None
        if not os.path.lexists(attempts_root):
            _require_missing_attempts_root_safe(store)
            runtime_factory = _EmptyRuntimeRecoveryV2
        try:
            arguments: dict[str, Any] = {
                "store": store,
                "attempts_root": attempts_root,
            }
            if runtime_factory is not None:
                arguments["runtime_recovery_factory"] = runtime_factory
            return RecoverySuiteV2(
                **arguments,
            ).run(apply=False)
        except _RECOVERY_ERRORS as exc:
            raise AdminV2Error(
                EXIT_UNSAFE,
                "RECOVERY_BLOCKED",
                "Не удалось построить закрытый план восстановления.",
                {"reasonCode": exc.code},
            ) from exc


def _apply_recovery_suite(proven: ProvenAdminStateV2) -> RecoverySuiteReportV2:
    try:
        attempts_root = prepare_attempts_root_v2(proven.binding.state_home)
    except RuntimeRecoveryV2Error as exc:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "RECOVERY_BLOCKED",
            "Не удалось подготовить закрытый корень восстановления.",
            {"reasonCode": exc.code},
        ) from exc
    with _open_runtime_store(proven) as store:
        try:
            return RecoverySuiteV2(
                store=store,
                attempts_root=attempts_root,
            ).run(apply=True)
        except _RECOVERY_ERRORS as exc:
            raise AdminV2Error(
                EXIT_UNSAFE,
                "RECOVERY_BLOCKED",
                "Не удалось построить закрытый план восстановления.",
                {"reasonCode": exc.code},
            ) from exc


def _require_missing_attempts_root_safe(store: Any) -> None:
    records = store.runtime_artifacts()
    active = [
        item
        for item in records
        if item.get("state") in {"RESERVED", "ACTIVE"}
    ]
    if active:
        raise AdminV2Error(
            EXIT_UNSAFE,
            "RECOVERY_BLOCKED",
            "Корень попыток отсутствует при активных записях.",
            {"reasonCode": "ATTEMPTS_ROOT_MISSING"},
        )


def _recovery_data(report: RecoverySuiteReportV2) -> dict[str, Any]:
    domain_data: dict[str, Any] = {}
    actions: list[dict[str, Any]] = []
    for item in report.reports:
        serialized = [_recovery_action_data(item.domain, action) for action in item.report.actions]
        domain_data[item.domain] = {
            "mode": item.mode,
            "applied": bool(item.report.applied),
            "actions": serialized,
            "blockers": list(item.report.blockers),
        }
        actions.extend(serialized)
    return {
        "applied": report.applied,
        "actions": actions,
        "blockers": [
            value.split(":", 1)[1] if ":" in value else value
            for value in report.blockers
        ],
        "domains": domain_data,
    }


def _recovery_action_data(domain: str, action: Any) -> dict[str, Any]:
    if domain == "artifacts":
        return {
            "kind": action.kind,
            "artifactId": action.artifact_id,
            "attemptId": action.attempt_id,
        }
    if domain == "executions":
        return {
            "kind": action.kind,
            "attemptId": action.attempt_id,
            "routeId": action.route_id,
            "nodeId": action.node_id,
        }
    if domain == "permits":
        return {
            "kind": action.kind,
            "permitId": action.permit_id,
            "routeId": action.route_id,
            "nodeId": action.node_id,
        }
    if domain == "candidates":
        return {
            "kind": action.kind,
            "intentId": action.intent_id,
            "repositoryId": action.repository_id,
            "ref": action.ref,
        }
    raise ValueError("unknown recovery domain")


def _state_counts(connection: sqlite3.Connection, table: str) -> dict[str, int]:
    if table not in {"routes", "attempts", "runtime_artifacts"}:
        raise ValueError("unknown state table")
    return {
        str(row["state"]): int(row["count"])
        for row in connection.execute(
            f"select state,count(*) as count from {table} group by state order by state"
        )
    }
