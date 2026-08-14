"""Безопасный административный интерфейс умных субагентов."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import socket
import sqlite3
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, TextIO

from .catalog import Catalog, CatalogError
from .candidate_recovery import (
    CandidateRecovery,
    CandidateRecoveryError,
    CandidateRecoveryReport,
)
from .controller import (
    PROTOCOL_VERSION,
    RELEASE,
    ControllerClient,
    RuntimePaths,
    WireProtocolError,
)
from .graph import ALLOWED_ROLES
from .identity import RequestContext, sha256_text
from .installation_rollback import (
    INSTALLATION_NAME,
    RollbackContext,
    RollbackError,
    apply_rollback,
    load_manifest,
    plan_rollback,
    probe_rollback_preflight,
)
from .state import RouteState, is_terminal
from .store import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    RouteNotFound,
    SmartStore,
    StoreError,
)


EXIT_OK = 0
EXIT_WARNING = 1
EXIT_ARGUMENT = 2
EXIT_NOT_FOUND = 3
EXIT_UNSAFE = 4
EXIT_INTERNAL = 5
MAX_INSPECT_LIMIT = 500
MAX_COORDINATION_BYTES = 1024 * 1024
ROUTE_ID = re.compile(r"rt1_[A-Za-z0-9_-]{43}\Z")
COORDINATION_STEM = re.compile(r"[0-9a-f]{32}\Z")
SAFE_SYMBOL = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SAFE_CODE = re.compile(r"[A-Z0-9_]{1,64}\Z")
ATTESTATION_FIELDS = frozenset(
    {
        "cliVersion",
        "requestedModel",
        "observedModel",
        "requestedEffort",
        "observedEffort",
        "conversationHash",
        "argvFingerprint",
        "permissionProbeId",
        "runFingerprint",
    }
)
COORDINATION_FIELDS = frozenset(
    {
        "schemaVersion",
        "shellSessionId",
        "sessionId",
        "turnId",
        "turnBinding",
        "catalogGeneration",
        "planCalled",
        "routeId",
        "disposition",
        "routeState",
        "afterSequence",
        "continuationCount",
    }
)
RUNTIME_KINDS = frozenset(
    {
        "reader_runtime",
        "writer_runtime",
        "validation_runtime",
        "validation_proof",
    }
)
KNOWN_MODELS = frozenset(
    {"gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"}
)
KNOWN_EFFORTS = frozenset(
    {"low", "medium", "high", "xhigh", "max"}
)
KNOWN_DISPOSITIONS = frozenset(
    {"direct", "delegate", "clarify"}
)
KNOWN_ATTEMPT_STATES = frozenset(
    {"RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "QUARANTINED"}
)
TOKEN_USAGE_KEYS = (
    "inputTokens",
    "cachedInputTokens",
    "outputTokens",
    "reasoningOutputTokens",
)
MAX_TOKEN_COUNT = 10**12
ADMIN_COMMANDS = frozenset(
    {
        "status",
        "inspect",
        "explain",
        "report",
        "metrics",
        "cancel",
        "doctor",
        "recover",
        "cleanup",
        "rollback",
    }
)


@dataclass
class AdminError(RuntimeError):
    exit_code: int
    code: str
    message: str
    data: dict[str, Any]

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class AdminConfig:
    codex_home: Path
    state_home: Path
    paths: RuntimePaths
    catalog_path: Path
    codex_home_hash: str
    environment: dict[str, str]

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> "AdminConfig":
        raw_codex_home = environ.get("CODEX_HOME")
        codex_home_input = (
            Path.home() / ".codex"
            if raw_codex_home is None
            else Path(raw_codex_home)
        )
        if not codex_home_input.is_absolute():
            raise AdminError(
                EXIT_ARGUMENT,
                "INVALID_ENVIRONMENT",
                "CODEX_HOME должен быть задан абсолютным путём.",
                {},
            )
        try:
            codex_home_info = os.lstat(codex_home_input)
        except FileNotFoundError as exc:
            raise AdminError(
                EXIT_ARGUMENT,
                "INVALID_ENVIRONMENT",
                "CODEX_HOME не существует.",
                {},
            ) from exc
        if (
            stat.S_ISLNK(codex_home_info.st_mode)
            or not stat.S_ISDIR(codex_home_info.st_mode)
            or codex_home_info.st_uid != os.getuid()
            or stat.S_IMODE(codex_home_info.st_mode) & 0o022
        ):
            raise _unsafe(
                "UNSAFE_CODEX_HOME",
                "CODEX_HOME имеет небезопасные свойства.",
            )
        raw_state_home = environ.get("XDG_STATE_HOME")
        if raw_state_home is not None and not Path(raw_state_home).is_absolute():
            raise AdminError(
                EXIT_ARGUMENT,
                "INVALID_ENVIRONMENT",
                "XDG_STATE_HOME должен быть абсолютным путём.",
                {},
            )
        codex_home = codex_home_input.resolve()
        state_home = (
            Path(raw_state_home).resolve()
            if raw_state_home is not None
            else (Path.home() / ".local" / "state").resolve()
        )
        raw_catalog = environ.get("CODEX_ADAPTIVE_CATALOG")
        if raw_catalog is not None and not Path(raw_catalog).is_absolute():
            raise AdminError(
                EXIT_ARGUMENT,
                "INVALID_ENVIRONMENT",
                "CODEX_ADAPTIVE_CATALOG должен быть абсолютным путём.",
                {},
            )
        plugin_root = Path(__file__).resolve().parents[2]
        catalog_path = (
            Path(raw_catalog).resolve()
            if raw_catalog is not None
            else plugin_root / "config" / "adaptive-subagents.toml"
        )
        paths = RuntimePaths.for_codex_home(
            str(codex_home),
            state_home=state_home,
        )
        return cls(
            codex_home=codex_home,
            state_home=state_home,
            paths=paths,
            catalog_path=catalog_path,
            codex_home_hash=sha256_text(str(codex_home)),
            environment=dict(environ),
        )

    @property
    def database(self) -> Path:
        return self.paths.namespace_dir / "state" / "smart-subagents.sqlite3"


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    ok: bool
    code: str
    message: str
    data: dict[str, Any]


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    now: datetime | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    output = sys.stdout if stdout is None else stdout
    command = (
        arguments[0]
        if arguments and arguments[0] in ADMIN_COMMANDS
        else "unknown"
    )
    try:
        parsed_command, options = _parse_arguments(arguments)
        command = parsed_command
        config = AdminConfig.from_environ(
            os.environ if environ is None else environ
        )
        timestamp = _aware_now(now)
        result = _dispatch(parsed_command, options, config, timestamp)
    except AdminError as exc:
        result = CommandResult(
            exit_code=exc.exit_code,
            ok=False,
            code=exc.code,
            message=exc.message,
            data=exc.data,
        )
    except Exception:
        result = CommandResult(
            exit_code=EXIT_INTERNAL,
            ok=False,
            code="INTERNAL_ERROR",
            message="Внутренняя ошибка административной команды.",
            data={},
        )
    envelope = {
        "schemaVersion": "1",
        "ok": result.ok,
        "command": command,
        "code": result.code,
        "message": result.message,
        "data": result.data,
    }
    output.write(
        json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    return result.exit_code


def _parse_arguments(arguments: list[str]) -> tuple[str, dict[str, Any]]:
    if not arguments:
        raise AdminError(
            EXIT_ARGUMENT,
            "INVALID_ARGUMENTS",
            "Не указана административная команда.",
            {},
        )
    command = arguments[0]
    tail = arguments[1:]
    if command in {"status", "doctor", "metrics"}:
        if tail:
            raise _argument_error(command)
        return command, {}
    if command == "cancel":
        if len(tail) != 1:
            raise _argument_error(command)
        _require_route_id(tail[0])
        return command, {"route_id": tail[0]}
    if command in {"inspect", "report"}:
        if not tail:
            raise _argument_error(command)
        route_id = tail[0]
        _require_route_id(route_id)
        limit = 100
        if len(tail) == 3 and tail[1] == "--limit":
            try:
                limit = int(tail[2])
            except ValueError as exc:
                raise _argument_error(command) from exc
            if limit <= 0 or limit > MAX_INSPECT_LIMIT:
                raise _argument_error(command)
        elif len(tail) != 1:
            raise _argument_error(command)
        return command, {"route_id": route_id, "limit": limit}
    if command == "explain":
        if len(tail) != 1:
            raise _argument_error(command)
        _require_route_id(tail[0])
        return command, {"route_id": tail[0]}
    if command in {"cleanup", "recover", "rollback"}:
        if len(tail) != 1 or tail[0] not in {"--dry-run", "--apply"}:
            raise _argument_error(command)
        return command, {"apply": tail[0] == "--apply"}
    raise AdminError(
        EXIT_ARGUMENT,
        "UNKNOWN_COMMAND",
        "Неизвестная административная команда.",
        {},
    )


def _argument_error(command: str) -> AdminError:
    return AdminError(
        EXIT_ARGUMENT,
        "INVALID_ARGUMENTS",
        f"Неверные аргументы команды {command}.",
        {},
    )


def _require_route_id(route_id: str) -> None:
    if ROUTE_ID.fullmatch(route_id) is None:
        raise AdminError(
            EXIT_ARGUMENT,
            "INVALID_ROUTE_ID",
            "Идентификатор маршрута имеет неверный формат.",
            {},
        )


def _dispatch(
    command: str,
    options: dict[str, Any],
    config: AdminConfig,
    now: datetime,
) -> CommandResult:
    if command == "status":
        return _status(config, now)
    if command == "inspect":
        return _inspect(
            config,
            options["route_id"],
            options["limit"],
            now,
        )
    if command == "explain":
        return _explain(config, options["route_id"])
    if command == "report":
        return _report(
            config,
            options["route_id"],
            options["limit"],
            now,
        )
    if command == "metrics":
        return _metrics(config)
    if command == "cancel":
        return _cancel(config, options["route_id"])
    if command == "doctor":
        return _doctor(config, now)
    if command == "recover":
        return _recover(config, apply=options["apply"])
    if command == "cleanup":
        return _cleanup(config, now, apply=options["apply"])
    if command == "rollback":
        return _rollback(config, apply=options["apply"])
    raise AssertionError("unreachable command")


def _status(config: AdminConfig, now: datetime) -> CommandResult:
    database = _locate_database(config)
    controller = _controller_status(config)
    if database is None:
        return CommandResult(
            EXIT_OK,
            True,
            "NOT_INITIALIZED",
            "Хранилище умных субагентов ещё не создано.",
            {
                "initialized": False,
                "controller": controller,
                "database": {"state": "missing"},
            },
        )
    with _open_database(config, readonly=True) as connection:
        _assert_namespace_rows(connection, config.codex_home_hash)
        _assert_known_states(connection)
        route_rows = connection.execute(
            """
            select state, count(*) as count
            from routes where codex_home_hash = ?
            group by state order by state
            """,
            (config.codex_home_hash,),
        ).fetchall()
        by_state = {
            str(row["state"]): int(row["count"]) for row in route_rows
        }
        terminal = sum(
            count
            for state, count in by_state.items()
            if is_terminal(RouteState(state))
        )
        total = sum(by_state.values())
        model_rows = connection.execute(
            """
            select selected_model, count(*) as count
            from nodes
            where route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            group by selected_model order by selected_model
            """,
            (config.codex_home_hash,),
        ).fetchall()
        effort_rows = connection.execute(
            """
            select reasoning_effort, count(*) as count
            from nodes
            where route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            group by reasoning_effort order by reasoning_effort
            """,
            (config.codex_home_hash,),
        ).fetchall()
        pending_intents = _scalar(
            connection,
            """
            select count(*) from intents
            where state = 'PENDING' and route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        )
        running_attempts = _scalar(
            connection,
            """
            select count(*) from attempts
            where state = 'RUNNING' and route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        )
        active_leases = _scalar(
            connection,
            """
            select count(*) from leases
            where expires_at >= ? and route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (_iso(now), config.codex_home_hash),
        )
        expired_leases = _scalar(
            connection,
            """
            select count(*) from leases
            where expires_at < ? and route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (_iso(now), config.codex_home_hash),
        )
        node_total = _scalar(
            connection,
            """
            select count(*) from nodes where route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        )
    warning = controller["state"] != "running" or expired_leases > 0
    return CommandResult(
        EXIT_WARNING if warning else EXIT_OK,
        True,
        "WARN" if warning else "OK",
        (
            "Состояние прочитано; обнаружены предупреждения."
            if warning
            else "Состояние прочитано."
        ),
        {
            "initialized": True,
            "controller": controller,
            "database": {
                "state": "ready",
                "schemaVersion": SCHEMA_VERSION,
            },
            "routes": {
                "total": total,
                "active": total - terminal,
                "terminal": terminal,
                "byState": by_state,
            },
            "nodes": {
                "total": node_total,
                "byModel": _bounded_aggregate(
                    model_rows,
                    "selected_model",
                    KNOWN_MODELS,
                ),
                "byReasoningEffort": _bounded_aggregate(
                    effort_rows,
                    "reasoning_effort",
                    KNOWN_EFFORTS,
                ),
            },
            "work": {
                "pendingIntents": pending_intents,
                "runningAttempts": running_attempts,
                "activeLeases": active_leases,
                "expiredLeases": expired_leases,
            },
        },
    )


def _inspect(
    config: AdminConfig,
    route_id: str,
    limit: int,
    now: datetime,
) -> CommandResult:
    if _locate_database(config) is None:
        raise _not_found()
    with _open_database(config, readonly=True) as connection:
        row = connection.execute(
            "select * from routes where route_id = ?",
            (route_id,),
        ).fetchone()
        if row is None:
            raise _not_found()
        if row["codex_home_hash"] != config.codex_home_hash:
            raise _unsafe(
                "CODEX_HOME_MISMATCH",
                "Маршрут принадлежит другому пространству CODEX_HOME.",
            )
        _assert_known_states(connection)
        nodes = connection.execute(
            """
            select * from nodes where route_id = ?
            order by ordinal, node_id
            """,
            (route_id,),
        ).fetchall()
        attempts, attempts_truncated = _bounded_rows(
            connection,
            """
            select * from attempts where route_id = ?
            order by started_at desc, attempt_id desc limit ?
            """,
            route_id,
            limit,
        )
        leases, leases_truncated = _bounded_rows(
            connection,
            """
            select node_id, expires_at, heartbeat_at
            from leases where route_id = ?
            order by expires_at, node_id limit ?
            """,
            route_id,
            limit,
        )
        intents, intents_truncated = _bounded_rows(
            connection,
            """
            select intent_id, node_id, kind, payload_hash, state,
                   created_at, completed_at
            from intents where route_id = ?
            order by created_at desc, intent_id desc limit ?
            """,
            route_id,
            limit,
        )
        events, events_truncated = _bounded_rows(
            connection,
            """
            select sequence, node_id, event, state, code, created_at
            from events where route_id = ?
            order by sequence desc limit ?
            """,
            route_id,
            limit,
        )
    return CommandResult(
        EXIT_OK,
        True,
        "OK",
        "Маршрут прочитан.",
        {
            "route": {
                "routeId": route_id,
                "state": str(row["state"]),
                "disposition": _known_value(
                    row["disposition"],
                    KNOWN_DISPOSITIONS,
                ),
                "startable": bool(row["startable"]),
                "runId": _safe_optional_symbol(row["run_id"]),
                "catalogGeneration": _safe_symbol(row["catalog_generation"]),
                "algorithmVersion": _safe_symbol(row["algorithm_version"]),
                "expiresAt": _safe_timestamp(row["expires_at"]),
                "createdAt": _safe_timestamp(row["created_at"]),
                "updatedAt": _safe_timestamp(row["updated_at"]),
                "terminal": is_terminal(RouteState(row["state"])),
            },
            "nodes": [_inspect_node(item) for item in nodes],
            "attempts": [_inspect_attempt(item) for item in attempts],
            "leases": [
                {
                    "nodeId": _safe_symbol(item["node_id"], allow_empty=True),
                    "expiresAt": _safe_timestamp(item["expires_at"]),
                    "heartbeatAt": _safe_timestamp(item["heartbeat_at"]),
                    "expired": _parse_time(item["expires_at"]) < now,
                }
                for item in leases
            ],
            "intents": [
                {
                    "intentId": _safe_symbol(item["intent_id"]),
                    "nodeId": _safe_symbol(item["node_id"], allow_empty=True),
                    "kind": _safe_symbol(item["kind"]),
                    "payloadHash": _safe_hash(item["payload_hash"]),
                    "state": _safe_symbol(item["state"]),
                    "createdAt": _safe_timestamp(item["created_at"]),
                    "completedAt": _safe_optional_timestamp(
                        item["completed_at"]
                    ),
                }
                for item in intents
            ],
            "events": [
                {
                    "sequence": int(item["sequence"]),
                    "nodeId": _safe_symbol(item["node_id"], allow_empty=True),
                    "event": _safe_symbol(item["event"]),
                    "state": _safe_symbol(item["state"]),
                    "code": _safe_error_code(item["code"]),
                    "createdAt": _safe_timestamp(item["created_at"]),
                }
                for item in events
            ],
            "truncated": {
                "attempts": attempts_truncated,
                "leases": leases_truncated,
                "intents": intents_truncated,
                "events": events_truncated,
            },
        },
    )


def _explain(config: AdminConfig, route_id: str) -> CommandResult:
    if _locate_database(config) is None:
        raise _not_found()
    with _open_database(config, readonly=True) as connection:
        row = connection.execute(
            """
            select route_id, codex_home_hash, state, disposition, startable,
                   catalog_generation, algorithm_version, plan_output_json
            from routes where route_id = ?
            """,
            (route_id,),
        ).fetchone()
        if row is None:
            raise _not_found()
        if row["codex_home_hash"] != config.codex_home_hash:
            raise _unsafe(
                "CODEX_HOME_MISMATCH",
                "Маршрут принадлежит другому пространству CODEX_HOME.",
            )
        nodes = connection.execute(
            """
            select node_id, role, assessment_json, risk_flags_json,
                   selected_model, reasoning_effort, permission_profile_id,
                   disposition
            from nodes where route_id = ?
            order by ordinal, node_id
            """,
            (route_id,),
        ).fetchall()
    reasons: dict[str, str] = {}
    try:
        plan = json.loads(row["plan_output_json"])
    except json.JSONDecodeError:
        plan = None
    if isinstance(plan, dict) and isinstance(plan.get("nodeDecisions"), list):
        for decision in plan["nodeDecisions"]:
            if not isinstance(decision, dict):
                continue
            node_id = decision.get("clientNodeId")
            reason = decision.get("reasonCode")
            if (
                isinstance(node_id, str)
                and isinstance(reason, str)
                and SAFE_SYMBOL.fullmatch(node_id)
                and SAFE_SYMBOL.fullmatch(reason)
            ):
                reasons[node_id] = reason
    rendered = []
    for node_row in nodes:
        node_id = _safe_symbol(node_row["node_id"])
        rendered.append(
            {
                "nodeId": node_id,
                "role": _known_value(node_row["role"], ALLOWED_ROLES),
                "disposition": _known_value(
                    node_row["disposition"],
                    KNOWN_DISPOSITIONS,
                ),
                "reasonCode": reasons.get(node_id, "UNRECOGNIZED"),
                "model": _known_value(
                    node_row["selected_model"],
                    KNOWN_MODELS,
                ),
                "reasoningEffort": _known_value(
                    node_row["reasoning_effort"],
                    KNOWN_EFFORTS,
                ),
                "permissionProfileId": _safe_symbol(
                    node_row["permission_profile_id"]
                ),
                "assessment": _safe_numeric_object(
                    node_row["assessment_json"]
                ),
                "riskFlags": _safe_symbol_list(
                    node_row["risk_flags_json"]
                ),
            }
        )
    return CommandResult(
        EXIT_OK,
        True,
        "OK",
        "Причины маршрутизации прочитаны.",
        {
            "routeId": route_id,
            "state": _safe_symbol(row["state"]),
            "overallDisposition": _known_value(
                row["disposition"],
                KNOWN_DISPOSITIONS,
            ),
            "startable": bool(row["startable"]),
            "catalogGeneration": _safe_symbol(row["catalog_generation"]),
            "algorithmVersion": _safe_symbol(row["algorithm_version"]),
            "nodes": rendered,
        },
    )


def _report(
    config: AdminConfig,
    route_id: str,
    limit: int,
    now: datetime,
) -> CommandResult:
    inspected = _inspect(config, route_id, limit, now)
    with _open_database(config, readonly=True) as connection:
        row = connection.execute(
            """
            select terminal_result_json from routes
            where route_id = ? and codex_home_hash = ?
            """,
            (route_id, config.codex_home_hash),
        ).fetchone()
        if row is None:
            raise _not_found()
        artifacts = connection.execute(
            """
            select artifact_id, node_id, kind, state, created_at, updated_at
            from runtime_artifacts where route_id = ?
            order by created_at, artifact_id limit ?
            """,
            (route_id, limit + 1),
        ).fetchall()
    terminal = _safe_terminal_result(row["terminal_result_json"])
    data = dict(inspected.data)
    data["terminalResult"] = terminal
    data["artifacts"] = [
        {
            "artifactId": _safe_symbol(item["artifact_id"]),
            "nodeId": _safe_symbol(item["node_id"], allow_empty=True),
            "kind": _safe_symbol(item["kind"]),
            "state": _safe_symbol(item["state"]),
            "createdAt": _safe_timestamp(item["created_at"]),
            "updatedAt": _safe_timestamp(item["updated_at"]),
        }
        for item in artifacts[:limit]
    ]
    data["truncated"] = {
        **data["truncated"],
        "artifacts": len(artifacts) > limit,
    }
    return CommandResult(
        EXIT_OK,
        True,
        "OK",
        "Обезличенный отчёт маршрута сформирован.",
        data,
    )


def _metrics(config: AdminConfig) -> CommandResult:
    if _locate_database(config) is None:
        return CommandResult(
            EXIT_OK,
            True,
            "NOT_INITIALIZED",
            "Хранилище умных субагентов ещё не создано.",
            {
                "routes": {"total": 0, "byState": {}, "byDisposition": {}},
                "nodes": {
                    "total": 0,
                    "byRole": {},
                    "byModel": {},
                    "byReasoningEffort": {},
                },
                "attempts": {
                    "total": 0,
                    "byState": {},
                    "byModel": {},
                    "byReasoningEffort": {},
                    "byErrorCode": {},
                    "duration": {
                        "completed": 0,
                        "totalMs": 0,
                        "maxMs": 0,
                    },
                    "usage": {
                        "reportedAttempts": 0,
                        **{key: 0 for key in TOKEN_USAGE_KEYS},
                    },
                },
            },
        )
    with _open_database(config, readonly=True) as connection:
        _assert_namespace_rows(connection, config.codex_home_hash)
        route_states = connection.execute(
            """
            select state, count(*) as count from routes
            where codex_home_hash = ? group by state order by state
            """,
            (config.codex_home_hash,),
        ).fetchall()
        route_dispositions = connection.execute(
            """
            select disposition, count(*) as count from routes
            where codex_home_hash = ? group by disposition order by disposition
            """,
            (config.codex_home_hash,),
        ).fetchall()
        node_rows = {
            field: connection.execute(
                f"""
                select {field}, count(*) as count from nodes
                where route_id in (
                  select route_id from routes where codex_home_hash = ?
                )
                group by {field} order by {field}
                """,
                (config.codex_home_hash,),
            ).fetchall()
            for field in ("role", "selected_model", "reasoning_effort")
        }
        attempt_rows = {
            field: connection.execute(
                f"""
                select {field}, count(*) as count from attempts
                where route_id in (
                  select route_id from routes where codex_home_hash = ?
                )
                group by {field} order by {field}
                """,
                (config.codex_home_hash,),
            ).fetchall()
            for field in ("state", "model", "reasoning_effort", "error_code")
        }
        durations = connection.execute(
            """
            select started_at, ended_at from attempts
            where ended_at is not null and route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        ).fetchall()
        usage_rows = connection.execute(
            """
            select result_json from attempts
            where result_json is not null and route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        ).fetchall()
        route_total = _scalar(
            connection,
            "select count(*) from routes where codex_home_hash = ?",
            (config.codex_home_hash,),
        )
        node_total = _scalar(
            connection,
            """
            select count(*) from nodes where route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        )
        attempt_total = _scalar(
            connection,
            """
            select count(*) from attempts where route_id in (
              select route_id from routes where codex_home_hash = ?
            )
            """,
            (config.codex_home_hash,),
        )
    duration_values = [
        _duration_ms(row["started_at"], row["ended_at"])
        for row in durations
    ]
    duration_values = [value for value in duration_values if value is not None]
    usage_values = [
        usage
        for row in usage_rows
        if (usage := _safe_attempt_usage(row["result_json"]))
    ]
    return CommandResult(
        EXIT_OK,
        True,
        "OK",
        "Ограниченные агрегаты рассчитаны.",
        {
            "routes": {
                "total": route_total,
                "byState": _bounded_aggregate(
                    route_states,
                    "state",
                    frozenset(state.value for state in RouteState),
                ),
                "byDisposition": _bounded_aggregate(
                    route_dispositions,
                    "disposition",
                    KNOWN_DISPOSITIONS,
                ),
            },
            "nodes": {
                "total": node_total,
                "byRole": _bounded_aggregate(
                    node_rows["role"],
                    "role",
                    ALLOWED_ROLES,
                ),
                "byModel": _bounded_aggregate(
                    node_rows["selected_model"],
                    "selected_model",
                    KNOWN_MODELS,
                ),
                "byReasoningEffort": _bounded_aggregate(
                    node_rows["reasoning_effort"],
                    "reasoning_effort",
                    KNOWN_EFFORTS,
                ),
            },
            "attempts": {
                "total": attempt_total,
                "byState": _bounded_aggregate(
                    attempt_rows["state"],
                    "state",
                    KNOWN_ATTEMPT_STATES,
                ),
                "byModel": _bounded_aggregate(
                    attempt_rows["model"],
                    "model",
                    KNOWN_MODELS,
                ),
                "byReasoningEffort": _bounded_aggregate(
                    attempt_rows["reasoning_effort"],
                    "reasoning_effort",
                    KNOWN_EFFORTS,
                ),
                "byErrorCode": _safe_code_aggregate(
                    attempt_rows["error_code"]
                ),
                "duration": {
                    "completed": len(duration_values),
                    "totalMs": sum(duration_values),
                    "maxMs": max(duration_values, default=0),
                },
                "usage": {
                    "reportedAttempts": len(usage_values),
                    **{
                        key: sum(
                            usage.get(key, 0)
                            for usage in usage_values
                        )
                        for key in TOKEN_USAGE_KEYS
                    },
                },
            },
        },
    )


def _cancel(config: AdminConfig, route_id: str) -> CommandResult:
    if _locate_database(config) is None:
        raise _not_found()
    store = SmartStore(config.database.parent)
    try:
        try:
            bundle = store.execution_bundle(route_id)
        except RouteNotFound as exc:
            raise _not_found() from exc
        if (
            sha256_text(bundle.context.codex_home) != config.codex_home_hash
            or bundle.route.context_hash != bundle.context.digest()
        ):
            raise _unsafe(
                "CODEX_HOME_MISMATCH",
                "Маршрут принадлежит другому пространству CODEX_HOME.",
            )
        before = bundle.route.state
        if is_terminal(before):
            return _cancel_result(
                "ALREADY_TERMINAL",
                route_id,
                before,
                before,
                False,
            )
        if before is RouteState.CANCELLING:
            return _cancel_result(
                "ALREADY_CANCELLING",
                route_id,
                before,
                before,
                False,
            )
        try:
            route, observed_before, accepted = store.request_cancel(
                route_id,
                bundle.context,
                "user_requested",
            )
        except (StoreError, ValueError):
            current = store.route_state(route_id)
            if is_terminal(current):
                return _cancel_result(
                    "ALREADY_TERMINAL",
                    route_id,
                    before,
                    current,
                    False,
                )
            if current is RouteState.CANCELLING:
                return _cancel_result(
                    "ALREADY_CANCELLING",
                    route_id,
                    before,
                    current,
                    False,
                )
            raise
        return _cancel_result(
            "CANCEL_REQUESTED",
            route_id,
            observed_before,
            route.state,
            accepted,
        )
    finally:
        store.close()


def _cancel_result(
    code: str,
    route_id: str,
    previous: RouteState,
    current: RouteState,
    accepted: bool,
) -> CommandResult:
    return CommandResult(
        EXIT_OK,
        True,
        code,
        (
            "Отмена запрошена."
            if code == "CANCEL_REQUESTED"
            else "Дополнительная отмена не требуется."
        ),
        {
            "routeId": route_id,
            "previousState": previous.value,
            "newState": current.value,
            "accepted": accepted,
        },
    )


def _recover(config: AdminConfig, *, apply: bool) -> CommandResult:
    if _locate_database(config) is None:
        return CommandResult(
            EXIT_OK,
            True,
            "NOT_INITIALIZED",
            "Хранилище умных субагентов ещё не создано.",
            {
                "mode": "apply" if apply else "dry-run",
                "ready": True,
                "controllerStopped": True,
                "recovery": _empty_recovery_data(),
            },
        )
    controller_stopped = _controller_lock_available(config)
    if apply and not controller_stopped:
        raise _unsafe(
            "CONTROLLER_ACTIVE",
            "Восстановление требует остановленного контроллера.",
        )
    store: SmartStore | None = None
    try:
        if apply:
            with _exclusive_controller_guard(config):
                store = SmartStore(config.database.parent)
                report = CandidateRecovery(store).apply(
                    controller_stopped=True,
                )
        else:
            store = SmartStore(config.database.parent)
            report = CandidateRecovery(store).plan(
                controller_stopped=controller_stopped,
            )
    except CandidateRecoveryError as exc:
        raise _unsafe(exc.code, "Восстановление не прошло проверку.") from exc
    finally:
        if store is not None:
            store.close()
    data = {
        "mode": "apply" if apply else "dry-run",
        "ready": controller_stopped and not report.errors,
        "controllerStopped": controller_stopped,
        "recovery": _safe_recovery_data(report),
    }
    warning = not data["ready"]
    return CommandResult(
        EXIT_WARNING if warning else EXIT_OK,
        True,
        "PARTIAL" if warning else "OK",
        (
            "Восстановление выполнено."
            if apply and not warning
            else (
                "Восстановление выполнено с изолированными ошибками."
                if apply
                else (
                    "План восстановления рассчитан."
                    if not warning
                    else "План восстановления требует остановки контроллера или проверки ошибок."
                )
            )
        ),
        data,
    )


def _empty_recovery_data() -> dict[str, Any]:
    return {
        "closedAttempts": 0,
        "closedIntents": 0,
        "abortedPublications": 0,
        "recoveredPublications": 0,
        "quarantinedPublications": 0,
        "orphanedRefs": 0,
        "quarantinedRecords": 0,
        "requeuedRoutes": 0,
        "errorCount": 0,
        "backupCreated": False,
    }


def _safe_recovery_data(report: CandidateRecoveryReport) -> dict[str, Any]:
    data = _empty_recovery_data()
    for target, value in (
        ("closedAttempts", report.closed_attempts),
        ("closedIntents", report.closed_intents),
        ("abortedPublications", report.aborted_publications),
        ("recoveredPublications", report.recovered_publications),
        ("quarantinedPublications", report.quarantined_publications),
        ("orphanedRefs", report.orphaned_refs),
        ("quarantinedRecords", report.quarantined_records),
        ("requeuedRoutes", report.requeued_routes),
    ):
        data[target] = (
            value
            if type(value) is int and 0 <= value <= 10**9
            else 0
        )
    data["errorCount"] = min(len(report.errors), 10**9)
    data["backupCreated"] = report.backup_path is not None
    return data


def _rollback(config: AdminConfig, *, apply: bool) -> CommandResult:
    manifest_path = (
        config.codex_home
        / "install-manifests"
        / f"{INSTALLATION_NAME}.json"
    )
    try:
        manifest = load_manifest(manifest_path)
        raw_binary = manifest.get("codexBinary")
        if (
            not isinstance(raw_binary, str)
            or not Path(raw_binary).is_absolute()
        ):
            raise RollbackError(
                "ROLLBACK_MANIFEST_INVALID",
                "в манифесте нет абсолютного пути Codex",
            )
        context = RollbackContext.from_installation(
            codex_home=config.codex_home,
            codex_binary=Path(raw_binary),
            state_home=config.state_home,
        )
        preflight = probe_rollback_preflight(
            context,
            environment=config.environment,
        )
        if apply:
            apply_rollback(
                context,
                preflight=preflight,
                extra_environment=config.environment,
            )
        else:
            plan_rollback(
                context,
                preflight=preflight,
                extra_environment=config.environment,
            )
    except RollbackError as exc:
        code = (
            exc.code
            if SAFE_CODE.fullmatch(exc.code) is not None
            else "ROLLBACK_FAILED"
        )
        raise AdminError(
            (
                EXIT_NOT_FOUND
                if code == "ROLLBACK_MANIFEST_MISSING"
                else EXIT_UNSAFE
            ),
            code,
            "Откат не прошёл проверку безопасности.",
            {},
        ) from exc

    data = {
        "mode": "apply" if apply else "dry-run",
        "ready": preflight.ready,
        "preflight": preflight.to_wire(),
        "actions": [
            "REMOVE_PLUGIN",
            "REMOVE_MARKETPLACE",
            "REMOVE_MANAGED_LAUNCHERS",
            "REMOVE_OWNED_TREE",
            "REMOVE_INSTALL_MANIFEST",
        ],
        "retained": {
            "database": context.database_path.exists(),
            "quarantine": context.quarantine_path.exists(),
            "backups": context.backups_path.exists(),
        },
    }
    warning = not preflight.ready
    return CommandResult(
        EXIT_WARNING if warning else EXIT_OK,
        True,
        "ROLLBACK_BLOCKED" if warning else "OK",
        (
            "Откат выполнен."
            if apply
            else (
                "План отката рассчитан."
                if not warning
                else "Откат заблокирован предварительной проверкой."
            )
        ),
        data,
    )


def _doctor(config: AdminConfig, now: datetime) -> CommandResult:
    issues: dict[tuple[str, str], int] = {}

    def issue(severity: str, code: str, count: int = 1) -> None:
        if count > 0:
            key = (severity, code)
            issues[key] = issues.get(key, 0) + count

    locate_failed = False
    try:
        database = _locate_database(config)
    except AdminError as exc:
        issue("block", exc.code)
        database = None
        locate_failed = True
    controller = _controller_status(config, strict=False)
    if controller["state"] != "running":
        issue(
            "block" if controller["state"] == "unsafe" else "warn",
            "CONTROLLER_" + controller["state"].upper(),
        )
    database_state = "missing"
    if database is None and not locate_failed:
        issue("warn", "NOT_INITIALIZED")
    elif locate_failed:
        database_state = "unsafe"
    else:
        database_state = "ready"
        try:
            with _open_database(config, readonly=True) as connection:
                integrity = str(
                    connection.execute(
                        "pragma integrity_check"
                    ).fetchone()[0]
                )
                if integrity != "ok":
                    issue("block", "INTEGRITY_CHECK_FAILED")
                foreign_keys = connection.execute(
                    "pragma foreign_key_check"
                ).fetchall()
                issue("block", "FOREIGN_KEY_VIOLATION", len(foreign_keys))
                mismatch = _scalar(
                    connection,
                    """
                    select count(*) from routes
                    where codex_home_hash != ?
                    """,
                    (config.codex_home_hash,),
                )
                issue("block", "CODEX_HOME_MISMATCH", mismatch)
                issue(
                    "block",
                    "CONTEXT_INCONSISTENT",
                    _context_inconsistency_count(
                        connection,
                        config.codex_home_hash,
                    ),
                )
                issue(
                    "block",
                    "UNKNOWN_ROUTE_STATE",
                    _unknown_state_count(connection, "routes"),
                )
                issue(
                    "block",
                    "UNKNOWN_NODE_STATE",
                    _unknown_state_count(connection, "nodes"),
                )
                terminal_values = tuple(
                    state.value for state in RouteState if is_terminal(state)
                )
                placeholders = ",".join("?" for _ in terminal_values)
                issue(
                    "block",
                    "TERMINAL_ROUTE_HAS_LEASE",
                    _scalar(
                        connection,
                        f"""
                        select count(*) from leases where route_id in (
                          select route_id from routes
                          where state in ({placeholders})
                        )
                        """,
                        terminal_values,
                    ),
                )
                issue(
                    "block",
                    "TERMINAL_ROUTE_HAS_PENDING_INTENT",
                    _scalar(
                        connection,
                        f"""
                        select count(*) from intents
                        where state = 'PENDING' and route_id in (
                          select route_id from routes
                          where state in ({placeholders})
                        )
                        """,
                        terminal_values,
                    ),
                )
                issue(
                    "block",
                    "TERMINAL_ROUTE_HAS_RUNNING_ATTEMPT",
                    _scalar(
                        connection,
                        f"""
                        select count(*) from attempts
                        where state = 'RUNNING' and route_id in (
                          select route_id from routes
                          where state in ({placeholders})
                        )
                        """,
                        terminal_values,
                    ),
                )
                issue(
                    "warn",
                    "EXPIRED_LEASE",
                    _scalar(
                        connection,
                        "select count(*) from leases where expires_at < ?",
                        (_iso(now),),
                    ),
                )
                coordination = _doctor_coordination(
                    config,
                    connection,
                )
                for severity, code, count in coordination:
                    issue(severity, code, count)
        except AdminError as exc:
            issue("block", exc.code)
            database_state = "unsafe"
        except (sqlite3.DatabaseError, ValueError, json.JSONDecodeError):
            issue("block", "DATABASE_CORRUPT")
            database_state = "unsafe"
    rendered = [
        {"severity": severity, "code": code, "count": count}
        for (severity, code), count in sorted(issues.items())
    ]
    blocked = any(item["severity"] == "block" for item in rendered)
    warned = any(item["severity"] == "warn" for item in rendered)
    if blocked:
        return CommandResult(
            EXIT_UNSAFE,
            False,
            "BLOCKED",
            "Проверка обнаружила небезопасное или несовместимое состояние.",
            {
                "database": {"state": database_state},
                "controller": controller,
                "issues": rendered,
            },
        )
    if warned:
        return CommandResult(
            EXIT_WARNING,
            True,
            "WARN",
            "Проверка завершена с предупреждениями.",
            {
                "database": {"state": database_state},
                "controller": controller,
                "issues": rendered,
            },
        )
    return CommandResult(
        EXIT_OK,
        True,
        "OK",
        "Проверка завершена без замечаний.",
        {
            "database": {"state": database_state},
            "controller": controller,
            "issues": [],
        },
    )


def _cleanup(
    config: AdminConfig,
    now: datetime,
    *,
    apply: bool,
) -> CommandResult:
    if _locate_database(config) is None:
        return CommandResult(
            EXIT_OK,
            True,
            "NOT_INITIALIZED",
            "Хранилище умных субагентов ещё не создано.",
            {
                "mode": "apply" if apply else "dry-run",
                "runtime": _cleanup_counts(),
                "coordination": _cleanup_counts(),
            },
        )
    try:
        catalog = Catalog.load(config.catalog_path)
    except CatalogError as exc:
        raise _unsafe(
            "CATALOG_INVALID",
            "Каталог политики очистки недоступен или несовместим.",
        ) from exc
    with _open_database(config, readonly=not apply) as connection:
        _assert_namespace_rows(connection, config.codex_home_hash)
        runtime = _cleanup_runtime(
            config,
            connection,
            catalog,
            now,
            apply=apply,
        )
        coordination = _cleanup_coordination(
            config,
            connection,
            catalog,
            now,
            apply=apply,
        )
        if apply:
            connection.commit()
    skipped = runtime["skipped"] + coordination["skipped"]
    return CommandResult(
        EXIT_WARNING if skipped else EXIT_OK,
        True,
        "PARTIAL" if skipped else "OK",
        (
            "Очистка завершена; часть объектов безопасно пропущена."
            if skipped
            else (
                "Очистка завершена."
                if apply
                else "План очистки рассчитан."
            )
        ),
        {
            "mode": "apply" if apply else "dry-run",
            "runtime": runtime,
            "coordination": coordination,
        },
    )


def _cleanup_runtime(
    config: AdminConfig,
    connection: sqlite3.Connection,
    catalog: Catalog,
    now: datetime,
    *,
    apply: bool,
) -> dict[str, int]:
    counts = _cleanup_counts()
    roots_by_kind = {
        "reader_runtime": config.paths.namespace_dir / "runtime",
        "writer_runtime": config.paths.namespace_dir / "runtime",
        "validation_runtime": config.paths.namespace_dir / "validation",
        "validation_proof": config.paths.namespace_dir / "validation",
    }
    rows = connection.execute(
        """
        select * from runtime_artifacts
        order by created_at, artifact_id
        """
    ).fetchall()
    for artifact_root in sorted(set(roots_by_kind.values())):
        registered_paths = {
            str(Path(str(row["path"])).resolve(strict=False))
            for row in rows
            if roots_by_kind.get(str(row["kind"])) == artifact_root
        }
        if not os.path.lexists(artifact_root):
            continue
        try:
            _require_private_directory(
                artifact_root,
                "UNSAFE_RUNTIME_ROOT",
            )
            for child in artifact_root.iterdir():
                if (
                    str(child.resolve(strict=False))
                    not in registered_paths
                ):
                    counts["skipped"] += 1
        except (AdminError, OSError):
            counts["skipped"] += 1
    for row in rows:
        counts["examined"] += 1
        if row["state"] != "TERMINAL":
            counts["retained"] += 1
            continue
        if str(row["kind"]) not in RUNTIME_KINDS:
            counts["skipped"] += 1
            continue
        artifact_root = roots_by_kind[str(row["kind"])]
        if not _route_cleanup_eligible(
            connection,
            str(row["route_id"]),
            catalog,
            now,
        ):
            counts["retained"] += 1
            continue
        try:
            snapshot = _validate_runtime_artifact(
                config,
                row,
                artifact_root,
            )
        except (AdminError, OSError):
            counts["skipped"] += 1
            continue
        counts["eligible"] += 1
        if not apply:
            continue
        try:
            _remove_validated_tree(snapshot)
        except (AdminError, OSError):
            counts["skipped"] += 1
            continue
        connection.execute(
            """
            update runtime_artifacts
            set state = 'MISSING', device = null, inode = null,
                updated_at = ?
            where artifact_id = ? and state = 'TERMINAL'
            """,
            (_iso(now), row["artifact_id"]),
        )
        counts["removed"] += 1
    return counts


def _cleanup_coordination(
    config: AdminConfig,
    connection: sqlite3.Connection,
    catalog: Catalog,
    now: datetime,
    *,
    apply: bool,
) -> dict[str, int]:
    counts = _cleanup_counts()
    directory = config.paths.namespace_dir / "coordination"
    if not os.path.lexists(directory):
        return counts
    try:
        _require_private_directory(directory, "UNSAFE_COORDINATION_DIR")
    except AdminError:
        counts["skipped"] += 1
        return counts
    entries = list(directory.iterdir())
    json_files = {
        path.stem: path
        for path in entries
        if path.suffix == ".json"
        and COORDINATION_STEM.fullmatch(path.stem)
    }
    lock_files = {
        path.stem: path
        for path in entries
        if path.suffix == ".lock"
        and COORDINATION_STEM.fullmatch(path.stem)
    }
    recognized = set(json_files.values()) | set(lock_files.values())
    counts["skipped"] += len(set(entries) - recognized)
    for stem, record in sorted(json_files.items()):
        counts["examined"] += 1
        lock = lock_files.get(stem)
        if lock is None:
            counts["skipped"] += 1
            continue
        try:
            record_info = _require_private_file(
                record,
                "UNSAFE_COORDINATION_RECORD",
            )
            _require_private_file(lock, "UNSAFE_COORDINATION_LOCK")
            if record_info.st_size > MAX_COORDINATION_BYTES:
                raise _unsafe(
                    "COORDINATION_TOO_LARGE",
                    "Запись координации превышает допустимый размер.",
                )
            raw_record = record.read_bytes()
            value = json.loads(raw_record)
            _validate_coordination(value, stem)
            route_id = value["routeId"]
            if not route_id or not _route_cleanup_eligible(
                connection,
                route_id,
                catalog,
                now,
            ):
                counts["retained"] += 1
                continue
            cutoff = _route_cutoff(connection, route_id, catalog, now)
            if datetime.fromtimestamp(
                record_info.st_mtime,
                timezone.utc,
            ) > cutoff:
                counts["retained"] += 1
                continue
            descriptor = _lock_nonblocking(lock)
        except (
            AdminError,
            OSError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            counts["skipped"] += 1
            continue
        try:
            current_record = os.lstat(record)
            current_lock = os.lstat(lock)
            locked_info = os.fstat(descriptor)
            if (
                (current_record.st_dev, current_record.st_ino)
                != (record_info.st_dev, record_info.st_ino)
                or current_record.st_mtime_ns != record_info.st_mtime_ns
                or current_record.st_size != record_info.st_size
                or record.read_bytes() != raw_record
                or not stat.S_ISREG(current_lock.st_mode)
                or current_lock.st_uid != os.getuid()
                or current_lock.st_nlink != 1
                or (current_lock.st_dev, current_lock.st_ino)
                != (locked_info.st_dev, locked_info.st_ino)
            ):
                counts["skipped"] += 1
                continue
            counts["eligible"] += 1
            if apply:
                os.unlink(record)
                counts["removed"] += 1
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
    return counts


def _doctor_coordination(
    config: AdminConfig,
    connection: sqlite3.Connection,
) -> list[tuple[str, str, int]]:
    directory = config.paths.namespace_dir / "coordination"
    if not os.path.lexists(directory):
        return []
    findings: dict[tuple[str, str], int] = {}

    def add(severity: str, code: str) -> None:
        key = (severity, code)
        findings[key] = findings.get(key, 0) + 1

    try:
        _require_private_directory(directory, "UNSAFE_COORDINATION_DIR")
    except AdminError:
        return [("block", "UNSAFE_COORDINATION_DIR", 1)]
    entries = list(directory.iterdir())
    json_files = {
        path.stem: path
        for path in entries
        if path.suffix == ".json"
        and COORDINATION_STEM.fullmatch(path.stem)
    }
    lock_files = {
        path.stem: path
        for path in entries
        if path.suffix == ".lock"
        and COORDINATION_STEM.fullmatch(path.stem)
    }
    recognized = set(json_files.values()) | set(lock_files.values())
    for _entry in set(entries) - recognized:
        add("warn", "COORDINATION_UNKNOWN_ENTRY")
    for stem, record in json_files.items():
        try:
            info = _require_private_file(
                record,
                "UNSAFE_COORDINATION_RECORD",
            )
            if info.st_size > MAX_COORDINATION_BYTES:
                raise ValueError
            value = json.loads(record.read_bytes())
            _validate_coordination(value, stem)
            route_id = value["routeId"]
            if route_id and connection.execute(
                "select 1 from routes where route_id = ?",
                (route_id,),
            ).fetchone() is None:
                add("block", "COORDINATION_ROUTE_MISSING")
        except (
            AdminError,
            OSError,
            ValueError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            add("block", "COORDINATION_INVALID")
        if stem not in lock_files:
            add("warn", "COORDINATION_LOCK_MISSING")
    for stem, lock in lock_files.items():
        try:
            _require_private_file(lock, "UNSAFE_COORDINATION_LOCK")
        except AdminError:
            add("block", "COORDINATION_LOCK_UNSAFE")
    return [
        (severity, code, count)
        for (severity, code), count in findings.items()
    ]


def _locate_database(config: AdminConfig) -> Path | None:
    managed = (
        config.paths.base_dir,
        config.paths.base_dir / "ns",
        config.paths.namespace_dir,
        config.database.parent,
    )
    for directory in managed:
        if not os.path.lexists(directory):
            return None
        _require_private_directory(directory, "UNSAFE_STATE_DIR")
    if not os.path.lexists(config.database):
        return None
    _require_database_file(config.database)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(config.database) + suffix)
        if os.path.lexists(sidecar):
            _require_private_file(sidecar, "UNSAFE_DATABASE_SIDECAR")
    return config.database


class _Database:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def __enter__(self) -> sqlite3.Connection:
        return self.connection

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        self.connection.close()


def _open_database(
    config: AdminConfig,
    *,
    readonly: bool,
) -> _Database:
    _require_database_file(config.database)
    connection: sqlite3.Connection | None = None
    try:
        if readonly:
            uri = config.database.resolve(strict=True).as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=5)
            connection.execute("pragma query_only=ON")
        else:
            connection = sqlite3.connect(config.database, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("pragma trusted_schema=OFF")
        connection.execute("pragma foreign_keys=ON")
        connection.execute("pragma busy_timeout=5000")
        application_id = int(
            connection.execute("pragma application_id").fetchone()[0]
        )
        user_version = int(
            connection.execute("pragma user_version").fetchone()[0]
        )
        if application_id != APPLICATION_ID or user_version != SCHEMA_VERSION:
            connection.close()
            raise _unsafe(
                "DATABASE_INCOMPATIBLE",
                "База состояния имеет несовместимую схему.",
            )
        return _Database(connection)
    except sqlite3.DatabaseError as exc:
        if connection is not None:
            connection.close()
        raise _unsafe(
            "DATABASE_CORRUPT",
            "База состояния повреждена или недоступна.",
        ) from exc


def _require_private_directory(path: Path, code: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise _unsafe(code, "Ожидаемый служебный каталог отсутствует.") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise _unsafe(code, "Служебный каталог имеет небезопасные свойства.")
    return info


def _require_private_file(path: Path, code: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise _unsafe(code, "Ожидаемый служебный файл отсутствует.") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise _unsafe(code, "Служебный файл имеет небезопасные свойства.")
    return info


def _require_database_file(path: Path) -> os.stat_result:
    return _require_private_file(path, "UNSAFE_DATABASE")


def _controller_status(
    config: AdminConfig,
    *,
    strict: bool = True,
) -> dict[str, Any]:
    socket_path = config.paths.socket_path
    try:
        if os.path.lexists(config.paths.run_dir):
            _require_private_directory(
                config.paths.run_dir,
                "UNSAFE_CONTROLLER_RUN_DIR",
            )
        if os.path.lexists(config.paths.lock_path):
            _require_private_file(
                config.paths.lock_path,
                "UNSAFE_CONTROLLER_LOCK",
            )
        if not os.path.lexists(socket_path):
            return {"state": "stopped"}
        info = os.lstat(socket_path)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise _unsafe(
                "UNSAFE_CONTROLLER_SOCKET",
                "Сокет контроллера имеет небезопасные свойства.",
            )
        client = ControllerClient(
            socket_path=socket_path,
            codex_home_hash=config.codex_home_hash,
            shell_session_id=f"admin-{config.paths.namespace}",
            timeout=1,
        )
        health = client.call("health", {})
        if (
            health.get("protocolVersion") != PROTOCOL_VERSION
            or health.get("release") != RELEASE
            or health.get("namespace") != config.paths.namespace
        ):
            raise _unsafe(
                "CONTROLLER_INCOMPATIBLE",
                "Контроллер вернул несовместимый ответ.",
            )
        return {
            "state": "running",
            "protocolVersion": PROTOCOL_VERSION,
            "release": RELEASE,
        }
    except AdminError:
        if strict:
            raise
        return {"state": "unsafe"}
    except (WireProtocolError, OSError, socket.error):
        return {"state": "stopped"}


def _controller_lock_available(config: AdminConfig) -> bool:
    if os.path.lexists(config.paths.socket_path):
        return False
    if not os.path.lexists(config.paths.run_dir):
        return True
    try:
        _require_private_directory(
            config.paths.run_dir,
            "UNSAFE_CONTROLLER_RUN_DIR",
        )
        if not os.path.lexists(config.paths.lock_path):
            return True
        _require_private_file(
            config.paths.lock_path,
            "UNSAFE_CONTROLLER_LOCK",
        )
        descriptor = os.open(
            config.paths.lock_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except (AdminError, OSError):
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True
    finally:
        os.close(descriptor)


@contextmanager
def _exclusive_controller_guard(config: AdminConfig):
    run_dir = config.paths.run_dir
    if not os.path.lexists(run_dir):
        try:
            os.mkdir(run_dir, 0o700)
        except FileExistsError:
            pass
    _require_private_directory(run_dir, "UNSAFE_CONTROLLER_RUN_DIR")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(config.paths.lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise _unsafe(
                "UNSAFE_CONTROLLER_LOCK",
                "Файл блокировки контроллера имеет небезопасные свойства.",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _unsafe(
                "CONTROLLER_ACTIVE",
                "Контроллер удерживает блокировку.",
            ) from exc
        if os.path.lexists(config.paths.socket_path):
            raise _unsafe(
                "CONTROLLER_ACTIVE",
                "Сокет контроллера ещё существует.",
            )
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _assert_namespace_rows(
    connection: sqlite3.Connection,
    codex_home_hash: str,
) -> None:
    mismatch = _scalar(
        connection,
        "select count(*) from routes where codex_home_hash != ?",
        (codex_home_hash,),
    )
    if mismatch:
        raise _unsafe(
            "CODEX_HOME_MISMATCH",
            "База содержит маршруты другого пространства CODEX_HOME.",
        )


def _assert_known_states(connection: sqlite3.Connection) -> None:
    if _unknown_state_count(connection, "routes"):
        raise _unsafe(
            "UNKNOWN_ROUTE_STATE",
            "База содержит неизвестное состояние маршрута.",
        )
    if _unknown_state_count(connection, "nodes"):
        raise _unsafe(
            "UNKNOWN_NODE_STATE",
            "База содержит неизвестное состояние узла.",
        )


def _unknown_state_count(
    connection: sqlite3.Connection,
    table: str,
) -> int:
    if table not in {"routes", "nodes"}:
        raise ValueError("unsupported state table")
    values = tuple(state.value for state in RouteState)
    placeholders = ",".join("?" for _ in values)
    return _scalar(
        connection,
        f"select count(*) from {table} where state not in ({placeholders})",
        values,
    )


def _context_inconsistency_count(
    connection: sqlite3.Connection,
    expected_codex_home_hash: str,
) -> int:
    count = 0
    rows = connection.execute(
        """
        select context_hash, context_json, shell_session_id, session_id,
               turn_id, codex_home_hash, repo_root_hash, base_sha,
               worktree_fingerprint
        from routes
        """
    ).fetchall()
    for row in rows:
        try:
            context = RequestContext.from_wire(json.loads(row["context_json"]))
        except (ValueError, TypeError, json.JSONDecodeError):
            count += 1
            continue
        if (
            context.digest() != row["context_hash"]
            or context.shell_session_id != row["shell_session_id"]
            or context.session_id != row["session_id"]
            or context.turn_id != row["turn_id"]
            or sha256_text(context.codex_home) != row["codex_home_hash"]
            or row["codex_home_hash"] != expected_codex_home_hash
            or sha256_text(context.repo_root) != row["repo_root_hash"]
            or context.base_sha != row["base_sha"]
            or context.worktree_fingerprint != row["worktree_fingerprint"]
        ):
            count += 1
    return count


def _inspect_node(row: sqlite3.Row) -> dict[str, Any]:
    summary: dict[str, Any] | None = None
    if row["result_json"] is not None:
        try:
            result = json.loads(row["result_json"])
        except json.JSONDecodeError:
            result = None
        if isinstance(result, dict) and isinstance(result.get("summary"), str):
            summary = _descriptor(result["summary"])
    return {
        "ordinal": int(row["ordinal"]),
        "nodeId": _safe_symbol(row["node_id"]),
        "role": _known_value(row["role"], ALLOWED_ROLES),
        "state": _safe_symbol(row["state"]),
        "model": _known_value(row["selected_model"], KNOWN_MODELS),
        "reasoningEffort": _known_value(
            row["reasoning_effort"],
            KNOWN_EFFORTS,
        ),
        "permissionProfileId": _safe_symbol(row["permission_profile_id"]),
        "disposition": _known_value(
            row["disposition"],
            KNOWN_DISPOSITIONS,
        ),
        "attemptCount": int(row["attempt_count"]),
        "dependencies": [
            _safe_symbol(item)
            for item in _safe_string_list(row["dependencies_json"])
        ],
        "mission": _descriptor(str(row["mission"])),
        "summary": summary,
    }


def _inspect_attempt(row: sqlite3.Row) -> dict[str, Any]:
    attestation: dict[str, str] = {}
    if row["attestation_json"] is not None:
        try:
            raw = json.loads(row["attestation_json"])
        except json.JSONDecodeError:
            raw = None
        if isinstance(raw, dict):
            for name in sorted(ATTESTATION_FIELDS):
                value = raw.get(name)
                if isinstance(value, str) and SAFE_SYMBOL.fullmatch(value):
                    attestation[name] = value
                elif (
                    isinstance(value, str)
                    and len(value) == 64
                    and re.fullmatch(r"[0-9a-f]{64}", value)
                ):
                    attestation[name] = value
    return {
        "attemptId": _safe_symbol(row["attempt_id"]),
        "nodeId": _safe_symbol(row["node_id"]),
        "state": _safe_symbol(row["state"]),
        "model": _known_value(row["model"], KNOWN_MODELS),
        "reasoningEffort": _known_value(
            row["reasoning_effort"],
            KNOWN_EFFORTS,
        ),
        "permissionProfileId": _safe_symbol(row["permission_profile_id"]),
        "argvFingerprint": _safe_hash(row["argv_fingerprint"]),
        "permissionProbeId": _safe_symbol(row["permission_probe_id"]),
        "errorCode": _safe_error_code(row["error_code"]),
        "startedAt": _safe_timestamp(row["started_at"]),
        "endedAt": _safe_optional_timestamp(row["ended_at"]),
        "durationMs": _duration_ms(row["started_at"], row["ended_at"]),
        "usage": _safe_attempt_usage(row["result_json"]),
        "attestation": attestation,
    }


def _bounded_rows(
    connection: sqlite3.Connection,
    query: str,
    route_id: str,
    limit: int,
) -> tuple[list[sqlite3.Row], bool]:
    rows = connection.execute(query, (route_id, limit + 1)).fetchall()
    return rows[:limit], len(rows) > limit


def _descriptor(value: str) -> dict[str, Any]:
    encoded = value.encode("utf-8")
    return {
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _safe_string_list(encoded: str) -> list[str]:
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _safe_numeric_object(encoded: Any) -> dict[str, Any]:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > 64 * 1024:
        return {}
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return {}
    budget = [128]

    def sanitize(item: Any, depth: int) -> Any:
        budget[0] -= 1
        if budget[0] < 0 or depth > 6:
            raise ValueError
        if type(item) is int and -1_000_000 <= item <= 1_000_000:
            return item
        if type(item) is bool:
            return item
        if isinstance(item, dict) and len(item) <= 32:
            result: dict[str, Any] = {}
            for key, nested in item.items():
                if not isinstance(key, str) or SAFE_SYMBOL.fullmatch(key) is None:
                    raise ValueError
                result[key] = sanitize(nested, depth + 1)
            return result
        if isinstance(item, list) and len(item) <= 32:
            return [sanitize(nested, depth + 1) for nested in item]
        raise ValueError

    try:
        safe = sanitize(value, 0)
    except ValueError:
        return {}
    return safe if isinstance(safe, dict) else {}


def _safe_symbol_list(encoded: Any) -> list[str]:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > 16 * 1024:
        return []
    try:
        values = json.loads(encoded)
    except json.JSONDecodeError:
        return []
    if not isinstance(values, list) or len(values) > 64:
        return []
    return [
        value
        for value in values
        if isinstance(value, str) and SAFE_SYMBOL.fullmatch(value)
    ]


def _safe_terminal_result(encoded: Any) -> dict[str, Any] | None:
    if encoded is None:
        return None
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > 64 * 1024:
        return {"state": "UNRECOGNIZED"}
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return {"state": "UNRECOGNIZED"}
    if not isinstance(value, dict):
        return {"state": "UNRECOGNIZED"}
    summary = value.get("summary")
    return {
        "artifactId": _safe_symbol(value.get("artifactId")),
        "fingerprint": _safe_hash(value.get("fingerprint")),
        "validationState": _known_value(
            value.get("validationState"),
            frozenset({"not_applicable", "passed", "failed", "quarantined"}),
        ),
        "summary": (
            _descriptor(summary)
            if isinstance(summary, str) and len(summary) <= 4000
            else None
        ),
        "usage": _safe_token_usage(value.get("usage")),
    }


def _safe_attempt_usage(encoded: Any) -> dict[str, int]:
    if not isinstance(encoded, str) or len(encoded.encode("utf-8")) > 64 * 1024:
        return {}
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    return _safe_token_usage(value.get("usage"))


def _safe_token_usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or not set(value) <= set(TOKEN_USAGE_KEYS):
        return {}
    usage: dict[str, int] = {}
    for key in TOKEN_USAGE_KEYS:
        count = value.get(key)
        if count is None:
            continue
        if (
            type(count) is not int
            or count < 0
            or count > MAX_TOKEN_COUNT
        ):
            return {}
        usage[key] = count
    return usage


def _safe_symbol(value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        return "UNRECOGNIZED"
    if allow_empty and value == "":
        return ""
    return value if SAFE_SYMBOL.fullmatch(value) else "UNRECOGNIZED"


def _safe_optional_symbol(value: Any) -> str | None:
    return None if value is None else _safe_symbol(value)


def _known_value(value: Any, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "UNRECOGNIZED"


def _bounded_aggregate(
    rows: list[sqlite3.Row],
    field: str,
    allowed: frozenset[str],
) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        name = _known_value(row[field], allowed)
        result[name] = result.get(name, 0) + int(row["count"])
    return result


def _safe_error_code(value: Any) -> str:
    if value is None or value == "":
        return ""
    return value if isinstance(value, str) and SAFE_CODE.fullmatch(value) else "UNRECOGNIZED"


def _safe_code_aggregate(rows: list[sqlite3.Row]) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows[:128]:
        code = _safe_error_code(row["error_code"]) or "NONE"
        result[code] = result.get(code, 0) + int(row["count"])
    return result


def _safe_hash(value: Any) -> str:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return value
    return ""


def _safe_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    try:
        _parse_time(value)
    except ValueError:
        return ""
    return value


def _safe_optional_timestamp(value: Any) -> str | None:
    return None if value is None else _safe_timestamp(value)


def _duration_ms(started: Any, ended: Any) -> int | None:
    if not isinstance(started, str) or not isinstance(ended, str):
        return None
    try:
        duration = _parse_time(ended) - _parse_time(started)
    except ValueError:
        return None
    milliseconds = int(duration.total_seconds() * 1000)
    return milliseconds if 0 <= milliseconds <= 31_536_000_000 else None


def _scalar(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[Any, ...] = (),
) -> int:
    return int(connection.execute(query, parameters).fetchone()[0])


def _route_cleanup_eligible(
    connection: sqlite3.Connection,
    route_id: str,
    catalog: Catalog,
    now: datetime,
) -> bool:
    row = connection.execute(
        "select state, updated_at from routes where route_id = ?",
        (route_id,),
    ).fetchone()
    if row is None:
        return False
    try:
        state = RouteState(row["state"])
    except ValueError:
        return False
    if not is_terminal(state):
        return False
    if _parse_time(row["updated_at"]) > _route_cutoff(
        connection,
        route_id,
        catalog,
        now,
    ):
        return False
    blockers = _scalar(
        connection,
        """
        select
          (select count(*) from leases where route_id = ?) +
          (select count(*) from intents
             where route_id = ? and state = 'PENDING') +
          (select count(*) from attempts
             where route_id = ? and state = 'RUNNING')
        """,
        (route_id, route_id, route_id),
    )
    return blockers == 0


def _route_cutoff(
    connection: sqlite3.Connection,
    route_id: str,
    catalog: Catalog,
    now: datetime,
) -> datetime:
    row = connection.execute(
        "select state from routes where route_id = ?",
        (route_id,),
    ).fetchone()
    if row is None:
        return now
    state = RouteState(row["state"])
    days = (
        catalog.retention["success_days"]
        if state in {RouteState.SUCCEEDED, RouteState.SKIPPED}
        else catalog.retention["failure_days"]
    )
    return now - timedelta(days=days)


@dataclass(frozen=True)
class TreeEntry:
    path: Path
    kind: str
    device: int
    inode: int


def _validate_runtime_artifact(
    config: AdminConfig,
    row: sqlite3.Row,
    artifact_root: Path,
) -> tuple[TreeEntry, ...]:
    if not artifact_root.is_absolute():
        raise _unsafe("UNSAFE_RUNTIME_ROOT", "Корень выполнения небезопасен.")
    _require_private_directory(artifact_root, "UNSAFE_RUNTIME_ROOT")
    root = artifact_root.resolve(strict=True)
    namespace_root = config.paths.namespace_dir.resolve(strict=True)
    permitted_roots = {
        namespace_root / "runtime",
        namespace_root / "validation",
    }
    if root not in permitted_roots:
        raise _unsafe("UNSAFE_RUNTIME_ROOT", "Корень выполнения не совпадает.")
    if str(row["allowed_root"]) != str(root):
        raise _unsafe("UNSAFE_ARTIFACT_ROOT", "Корень объекта не совпадает.")
    path = Path(str(row["path"]))
    if not path.is_absolute() or path.parent.resolve(strict=True) != root:
        raise _unsafe(
            "UNSAFE_ARTIFACT_PATH",
            "Объект выполнения находится вне разрешённого корня.",
        )
    top = os.lstat(path)
    if (
        not stat.S_ISDIR(top.st_mode)
        or stat.S_ISLNK(top.st_mode)
        or top.st_uid != os.getuid()
        or stat.S_IMODE(top.st_mode) != 0o700
        or row["device"] is None
        or row["inode"] is None
        or int(row["device"]) != top.st_dev
        or int(row["inode"]) != top.st_ino
    ):
        raise _unsafe(
            "ARTIFACT_IDENTITY_MISMATCH",
            "Объект выполнения не совпадает с записью базы.",
        )
    entries: list[TreeEntry] = []
    for current_root, directories, files in os.walk(
        path,
        topdown=False,
        followlinks=False,
    ):
        current = Path(current_root)
        for name in files:
            child = current / name
            info = os.lstat(child)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_dev != top.st_dev
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise _unsafe(
                    "UNSAFE_ARTIFACT_TREE",
                    "Объект выполнения содержит небезопасный файл.",
                )
            entries.append(
                TreeEntry(child, "file", info.st_dev, info.st_ino)
            )
        for name in directories:
            child = current / name
            info = os.lstat(child)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_dev != top.st_dev
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise _unsafe(
                    "UNSAFE_ARTIFACT_TREE",
                    "Объект выполнения содержит небезопасный каталог.",
                )
            entries.append(
                TreeEntry(child, "directory", info.st_dev, info.st_ino)
            )
    second = os.lstat(path)
    if (second.st_dev, second.st_ino) != (top.st_dev, top.st_ino):
        raise _unsafe(
            "ARTIFACT_CHANGED",
            "Объект выполнения изменился во время проверки.",
        )
    entries.append(TreeEntry(path, "directory", top.st_dev, top.st_ino))
    return tuple(entries)


def _remove_validated_tree(entries: tuple[TreeEntry, ...]) -> None:
    for entry in entries:
        info = os.lstat(entry.path)
        if (info.st_dev, info.st_ino) != (entry.device, entry.inode):
            raise _unsafe(
                "ARTIFACT_CHANGED",
                "Объект выполнения изменился перед удалением.",
            )
        if entry.kind == "file":
            if not stat.S_ISREG(info.st_mode):
                raise _unsafe(
                    "ARTIFACT_CHANGED",
                    "Тип файла изменился перед удалением.",
                )
            os.unlink(entry.path)
        else:
            if not stat.S_ISDIR(info.st_mode):
                raise _unsafe(
                    "ARTIFACT_CHANGED",
                    "Тип каталога изменился перед удалением.",
                )
            os.rmdir(entry.path)


def _validate_coordination(value: Any, stem: str) -> None:
    if not isinstance(value, dict) or set(value) != COORDINATION_FIELDS:
        raise ValueError("invalid coordination schema")
    if value["schemaVersion"] != 1:
        raise ValueError("invalid coordination version")
    strings = COORDINATION_FIELDS - {
        "schemaVersion",
        "planCalled",
        "afterSequence",
        "continuationCount",
    }
    if not all(isinstance(value[name], str) for name in strings):
        raise ValueError("invalid coordination strings")
    if type(value["planCalled"]) is not bool:
        raise ValueError("invalid coordination boolean")
    for name in ("afterSequence", "continuationCount"):
        if type(value[name]) is not int or value[name] < 0:
            raise ValueError("invalid coordination counter")
    route_id = value["routeId"]
    if route_id and ROUTE_ID.fullmatch(route_id) is None:
        raise ValueError("invalid coordination route")
    expected = hashlib.sha256(
        value["shellSessionId"].encode("utf-8")
    ).hexdigest()[:32]
    if stem != expected:
        raise ValueError("coordination filename mismatch")


def _lock_nonblocking(path: Path) -> int:
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise OSError("unsafe coordination lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _cleanup_counts() -> dict[str, int]:
    return {
        "examined": 0,
        "eligible": 0,
        "removed": 0,
        "retained": 0,
        "skipped": 0,
    }


def _not_found() -> AdminError:
    return AdminError(
        EXIT_NOT_FOUND,
        "ROUTE_NOT_FOUND",
        "Маршрут не найден.",
        {},
    )


def _unsafe(code: str, message: str) -> AdminError:
    return AdminError(EXIT_UNSAFE, code, message, {})


def _aware_now(value: datetime | None) -> datetime:
    selected = datetime.now(timezone.utc) if value is None else value
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise AdminError(
            EXIT_ARGUMENT,
            "INVALID_TIME",
            "Время должно содержать часовой пояс.",
            {},
        )
    return selected.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


if __name__ == "__main__":
    raise SystemExit(main())
