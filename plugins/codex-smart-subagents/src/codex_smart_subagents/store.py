"""Durable SQLite state for adaptive-subagent routes."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .identity import RequestContext, new_opaque_id, sha256_text
from .state import ALLOWED_TRANSITIONS, RouteState, assert_transition, is_terminal


APPLICATION_ID = 0x43534132
SCHEMA_VERSION = 1


@dataclass
class StoreError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class TurnBindingError(StoreError):
    pass


class RouteForbidden(StoreError):
    pass


class RouteNotFound(StoreError):
    pass


class IdempotencyConflict(StoreError):
    pass


class RouteExpired(StoreError):
    pass


class RouteNotStartable(StoreError):
    pass


@dataclass(frozen=True)
class RouteRecord:
    route_id: str
    request_key: str
    request_hash: str
    context_hash: str
    state: RouteState
    disposition: str
    startable: bool
    expires_at: datetime
    run_id: str | None
    plan_output: dict[str, Any]
    terminal_result: dict[str, Any] | None


class SmartStore:
    """One connection guarded by immediate transactions and a process lock."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir.expanduser()
        self._prepare_state_dir()
        self.path = self.state_dir / "smart-subagents.sqlite3"
        if self.path.is_symlink():
            raise StoreError("UNSAFE_DATABASE", "database path is a symlink")
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=5,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        os.chmod(self.path, 0o600)
        self._configure()
        self._migrate()
        self._verify_database_file()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def issue_turn_binding(
        self,
        request_context: RequestContext,
        *,
        ttl_seconds: int = 120,
    ) -> str:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        binding = new_opaque_id("tb1")
        token_hash = sha256_text(binding)
        now = _utc_now()
        expires_at = datetime.fromtimestamp(
            now.timestamp() + ttl_seconds,
            timezone.utc,
        )
        with self._transaction() as connection:
            connection.execute(
                """
                insert into turn_bindings
                  (token_hash, context_hash, context_json, created_at, expires_at)
                values (?, ?, ?, ?, ?)
                """,
                (
                    token_hash,
                    request_context.digest(),
                    _json(request_context.to_wire()),
                    _iso(now),
                    _iso(expires_at),
                ),
            )
        return binding

    def consume_turn_binding(
        self,
        binding: str,
        request_context: RequestContext,
    ) -> None:
        token_hash = sha256_text(binding)
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                """
                select context_hash, expires_at, consumed_at
                from turn_bindings
                where token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
            if row is None:
                raise TurnBindingError(
                    "TURN_BINDING_INVALID",
                    "turn binding does not exist",
                )
            if row["context_hash"] != request_context.digest():
                raise TurnBindingError(
                    "TURN_BINDING_FORBIDDEN",
                    "turn binding belongs to another context",
                )
            if row["consumed_at"] is not None:
                raise TurnBindingError(
                    "TURN_BINDING_USED",
                    "turn binding was already consumed",
                )
            if _parse(row["expires_at"]) < now:
                raise TurnBindingError(
                    "TURN_BINDING_EXPIRED",
                    "turn binding has expired",
                )
            connection.execute(
                "update turn_bindings set consumed_at = ? where token_hash = ?",
                (_iso(now), token_hash),
            )

    def context_for_turn_binding(
        self,
        binding: str,
        *,
        shell_session_id: str,
        codex_home_hash: str,
    ) -> RequestContext:
        with self._lock:
            row = self._connection.execute(
                """
                select context_json from turn_bindings
                where token_hash = ?
                """,
                (sha256_text(binding),),
            ).fetchone()
        if row is None:
            raise TurnBindingError(
                "TURN_BINDING_INVALID",
                "turn binding does not exist",
            )
        context = RequestContext.from_wire(json.loads(row["context_json"]))
        if (
            context.shell_session_id != shell_session_id
            or sha256_text(context.codex_home) != codex_home_hash
        ):
            raise TurnBindingError(
                "TURN_BINDING_FORBIDDEN",
                "turn binding belongs to another controller session",
            )
        return context

    def find_route_by_request_key(
        self,
        request_context: RequestContext,
        request_key: str,
    ) -> RouteRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                select * from routes
                where context_hash = ? and request_key = ?
                """,
                (request_context.digest(), request_key),
            ).fetchone()
        return None if row is None else _route_record(row)

    def create_route(
        self,
        *,
        request_context: RequestContext,
        request_key: str,
        request_hash: str,
        catalog_generation: str,
        algorithm_version: str,
        disposition: str,
        startable: bool,
        expires_at: datetime,
        plan_output: dict[str, Any],
        nodes: list[dict[str, Any]],
        route_id: str | None = None,
    ) -> str:
        route_id = route_id or new_opaque_id("rt1")
        now = _utc_now()
        context_hash = request_context.digest()
        with self._transaction() as connection:
            existing = connection.execute(
                """
                select route_id, request_hash from routes
                where context_hash = ? and request_key = ?
                """,
                (context_hash, request_key),
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise IdempotencyConflict(
                        "IDEMPOTENCY_CONFLICT",
                        "request key is already bound to another plan",
                    )
                return str(existing["route_id"])

            connection.execute(
                """
                insert into routes (
                  route_id, request_key, request_hash, context_hash,
                  context_json,
                  shell_session_id, session_id, turn_id,
                  codex_home_hash, repo_root_hash, base_sha,
                  worktree_fingerprint, catalog_generation, algorithm_version,
                  disposition, startable, state, expires_at,
                  plan_output_json, created_at, updated_at
                ) values (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    route_id,
                    request_key,
                    request_hash,
                    context_hash,
                    _json(request_context.to_wire()),
                    request_context.shell_session_id,
                    request_context.session_id,
                    request_context.turn_id,
                    sha256_text(request_context.codex_home),
                    sha256_text(request_context.repo_root),
                    request_context.base_sha,
                    request_context.worktree_fingerprint,
                    catalog_generation,
                    algorithm_version,
                    disposition,
                    int(startable),
                    RouteState.PLANNED.value,
                    _iso(expires_at),
                    _json(plan_output),
                    _iso(now),
                    _iso(now),
                ),
            )
            for ordinal, node in enumerate(nodes):
                connection.execute(
                    """
                    insert into nodes (
                      route_id, node_id, ordinal, role, mission,
                      dependencies_json, selected_model, reasoning_effort,
                      permission_profile_id, disposition, state
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        route_id,
                        node["clientNodeId"],
                        ordinal,
                        node["role"],
                        node["mission"],
                        _json(node["dependencyIds"]),
                        node["selectedModel"],
                        node["reasoningEffort"],
                        node["permissionProfileId"],
                        node["disposition"],
                        RouteState.PLANNED.value,
                    ),
                )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id="",
                event="route_planned",
                state=RouteState.PLANNED,
                code="PLANNED",
                message="",
            )
        return route_id

    def get_route(
        self,
        route_id: str,
        request_context: RequestContext,
    ) -> RouteRecord:
        with self._lock:
            row = self._connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
        if row is None:
            raise RouteNotFound("ROUTE_NOT_FOUND", "route does not exist")
        if row["context_hash"] != request_context.digest():
            raise RouteForbidden(
                "ROUTE_FORBIDDEN",
                "route belongs to another context",
            )
        return _route_record(row)

    def context_for_route(
        self,
        route_id: str,
        *,
        shell_session_id: str,
        codex_home_hash: str,
    ) -> RequestContext:
        with self._lock:
            row = self._connection.execute(
                """
                select context_json, shell_session_id, codex_home_hash
                from routes where route_id = ?
                """,
                (route_id,),
            ).fetchone()
        if row is None:
            raise RouteNotFound("ROUTE_NOT_FOUND", "route does not exist")
        if (
            row["shell_session_id"] != shell_session_id
            or row["codex_home_hash"] != codex_home_hash
        ):
            raise RouteForbidden(
                "ROUTE_FORBIDDEN",
                "route belongs to another controller session",
            )
        return RequestContext.from_wire(json.loads(row["context_json"]))

    def transition_route(
        self,
        route_id: str,
        request_context: RequestContext,
        new_state: RouteState,
        *,
        event: str,
        code: str,
        message: str,
    ) -> RouteRecord:
        with self._transaction() as connection:
            row = self._route_row(connection, route_id, request_context)
            before = RouteState(row["state"])
            assert_transition(before, new_state)
            now = _utc_now()
            connection.execute(
                "update routes set state = ?, updated_at = ? where route_id = ?",
                (new_state.value, _iso(now), route_id),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id="",
                event=event,
                state=new_state,
                code=code,
                message=message,
            )
            updated = connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
        return _route_record(updated)

    def start_route(
        self,
        route_id: str,
        request_context: RequestContext,
        *,
        now: datetime | None = None,
    ) -> RouteRecord:
        now = now or _utc_now()
        with self._transaction() as connection:
            row = self._route_row(connection, route_id, request_context)
            if row["run_id"]:
                return _route_record(row)
            if not bool(row["startable"]):
                raise RouteNotStartable(
                    "ROUTE_NOT_STARTABLE",
                    "route disposition cannot be started",
                )
            if _parse(row["expires_at"]) < now:
                raise RouteExpired("ROUTE_EXPIRED", "route expired before start")
            before = RouteState(row["state"])
            assert_transition(before, RouteState.QUEUED)
            run_id = new_opaque_id("run1")
            connection.execute(
                """
                update routes
                set state = ?, run_id = ?, updated_at = ?
                where route_id = ?
                """,
                (RouteState.QUEUED.value, run_id, _iso(now), route_id),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id="",
                event="route_queued",
                state=RouteState.QUEUED,
                code="QUEUED",
                message="",
            )
            updated = connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
        return _route_record(updated)

    def request_cancel(
        self,
        route_id: str,
        request_context: RequestContext,
        reason_code: str,
    ) -> tuple[RouteRecord, RouteState, bool]:
        with self._transaction() as connection:
            row = self._route_row(connection, route_id, request_context)
            before = RouteState(row["state"])
            if is_terminal(before):
                return _route_record(row), before, False
            now = _utc_now()
            if before in {
                RouteState.PLANNED,
                RouteState.BLOCKED,
                RouteState.QUEUED,
                RouteState.RETRYABLE,
            }:
                after = RouteState.CANCELLED
            else:
                after = RouteState.CANCELLING
            assert_transition(before, after)
            connection.execute(
                """
                update routes
                set state = ?, cancel_reason = ?, updated_at = ?
                where route_id = ?
                """,
                (after.value, reason_code, _iso(now), route_id),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id="",
                event="route_cancel_requested",
                state=after,
                code="CANCEL_REQUESTED",
                message=reason_code,
            )
            updated = connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
        return _route_record(updated), before, True

    def events_after(
        self,
        route_id: str,
        request_context: RequestContext,
        after_sequence: int,
        *,
        limit: int = 101,
    ) -> list[dict[str, Any]]:
        self.get_route(route_id, request_context)
        with self._lock:
            rows = self._connection.execute(
                """
                select sequence, event, state, node_id, code, message
                from events
                where route_id = ? and sequence > ?
                order by sequence
                limit ?
                """,
                (route_id, after_sequence, limit),
            ).fetchall()
        return [
            {
                "sequence": int(row["sequence"]),
                "event": str(row["event"]),
                "state": str(row["state"]),
                "nodeId": str(row["node_id"]),
                "code": str(row["code"]),
                "message": str(row["message"]),
            }
            for row in rows
        ]

    def record_lease(
        self,
        *,
        route_id: str,
        node_id: str,
        owner_id: str,
        token: str,
        pid: int,
        start_marker: str,
        expires_at: datetime,
    ) -> None:
        with self._transaction() as connection:
            connection.execute(
                """
                insert or replace into leases (
                  route_id, node_id, owner_id, token_hash,
                  pid, start_marker, expires_at, heartbeat_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    route_id,
                    node_id,
                    owner_id,
                    sha256_text(token),
                    pid,
                    start_marker,
                    _iso(expires_at),
                    _iso(_utc_now()),
                ),
            )

    def recover_stale_leases(self, *, now: datetime) -> list[str]:
        recovered: list[str] = []
        with self._transaction() as connection:
            rows = connection.execute(
                """
                select distinct route_id from leases
                where expires_at < ?
                order by route_id
                """,
                (_iso(now),),
            ).fetchall()
            for lease in rows:
                route_id = str(lease["route_id"])
                route = connection.execute(
                    "select state from routes where route_id = ?",
                    (route_id,),
                ).fetchone()
                if route is None:
                    continue
                before = RouteState(route["state"])
                if RouteState.RECOVERING not in ALLOWED_TRANSITIONS[before]:
                    continue
                connection.execute(
                    """
                    update routes set state = ?, updated_at = ?
                    where route_id = ?
                    """,
                    (RouteState.RECOVERING.value, _iso(now), route_id),
                )
                self._insert_event(
                    connection,
                    route_id=route_id,
                    node_id="",
                    event="route_recovering",
                    state=RouteState.RECOVERING,
                    code="LEASE_EXPIRED",
                    message="",
                )
                connection.execute(
                    "delete from leases where route_id = ?",
                    (route_id,),
                )
                recovered.append(route_id)
        return recovered

    def backup(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, sqlite3.connect(destination) as target:
            self._connection.backup(target)
        os.chmod(destination, 0o600)

    def integrity_check(self) -> str:
        with self._lock:
            return str(
                self._connection.execute("pragma integrity_check").fetchone()[0]
            )

    def _prepare_state_dir(self) -> None:
        if self.state_dir.is_symlink():
            raise StoreError("UNSAFE_STATE_DIR", "state directory is a symlink")
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state_dir, 0o700)
        info = self.state_dir.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise StoreError(
                "UNSAFE_STATE_DIR",
                "state directory has an unexpected owner or type",
            )

    def _configure(self) -> None:
        self._connection.execute("pragma journal_mode=WAL")
        self._connection.execute("pragma synchronous=FULL")
        self._connection.execute("pragma foreign_keys=ON")
        self._connection.execute("pragma trusted_schema=OFF")
        self._connection.execute("pragma busy_timeout=5000")
        self._connection.execute("pragma secure_delete=FAST")
        self._connection.execute(f"pragma application_id={APPLICATION_ID}")

    def _migrate(self) -> None:
        version = int(
            self._connection.execute("pragma user_version").fetchone()[0]
        )
        if version not in {0, SCHEMA_VERSION}:
            raise StoreError(
                "UNSUPPORTED_DATABASE",
                f"unsupported database user_version: {version}",
            )
        if version == SCHEMA_VERSION:
            return
        with self._transaction() as connection:
            connection.executescript(
                """
                create table turn_bindings (
                  token_hash text primary key,
                  context_hash text not null,
                  context_json text not null,
                  created_at text not null,
                  expires_at text not null,
                  consumed_at text
                );

                create table routes (
                  route_id text primary key,
                  request_key text not null,
                  request_hash text not null,
                  context_hash text not null,
                  context_json text not null,
                  shell_session_id text not null,
                  session_id text not null,
                  turn_id text not null,
                  codex_home_hash text not null,
                  repo_root_hash text not null,
                  base_sha text not null,
                  worktree_fingerprint text not null,
                  catalog_generation text not null,
                  algorithm_version text not null,
                  disposition text not null,
                  startable integer not null check(startable in (0, 1)),
                  state text not null,
                  expires_at text not null,
                  run_id text,
                  cancel_reason text,
                  plan_output_json text not null,
                  terminal_result_json text,
                  created_at text not null,
                  updated_at text not null,
                  unique(context_hash, request_key)
                );

                create table nodes (
                  route_id text not null references routes(route_id) on delete cascade,
                  node_id text not null,
                  ordinal integer not null,
                  role text not null,
                  mission text not null,
                  dependencies_json text not null,
                  selected_model text not null,
                  reasoning_effort text not null,
                  permission_profile_id text not null,
                  disposition text not null,
                  state text not null,
                  primary key(route_id, node_id)
                );

                create table events (
                  sequence integer primary key autoincrement,
                  route_id text not null references routes(route_id) on delete cascade,
                  node_id text not null,
                  event text not null,
                  state text not null,
                  code text not null,
                  message text not null,
                  created_at text not null
                );

                create index events_route_sequence
                  on events(route_id, sequence);

                create table intents (
                  intent_id text primary key,
                  route_id text not null references routes(route_id) on delete cascade,
                  node_id text not null,
                  kind text not null,
                  payload_hash text not null,
                  state text not null,
                  created_at text not null,
                  completed_at text
                );

                create table leases (
                  route_id text not null references routes(route_id) on delete cascade,
                  node_id text not null,
                  owner_id text not null,
                  token_hash text not null,
                  pid integer not null,
                  start_marker text not null,
                  expires_at text not null,
                  heartbeat_at text not null,
                  primary key(route_id, node_id)
                );
                """
            )
            connection.execute(f"pragma user_version={SCHEMA_VERSION}")

    def _verify_database_file(self) -> None:
        info = self.path.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise StoreError(
                "UNSAFE_DATABASE",
                "database has an unexpected owner, type, or link count",
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("begin immediate")
            try:
                yield self._connection
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _route_row(
        self,
        connection: sqlite3.Connection,
        route_id: str,
        request_context: RequestContext,
    ) -> sqlite3.Row:
        row = connection.execute(
            "select * from routes where route_id = ?",
            (route_id,),
        ).fetchone()
        if row is None:
            raise RouteNotFound("ROUTE_NOT_FOUND", "route does not exist")
        if row["context_hash"] != request_context.digest():
            raise RouteForbidden(
                "ROUTE_FORBIDDEN",
                "route belongs to another context",
            )
        return row

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        *,
        route_id: str,
        node_id: str,
        event: str,
        state: RouteState,
        code: str,
        message: str,
    ) -> None:
        connection.execute(
            """
            insert into events (
              route_id, node_id, event, state, code, message, created_at
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                route_id,
                node_id,
                event,
                state.value,
                code,
                message,
                _iso(_utc_now()),
            ),
        )


def _route_record(row: sqlite3.Row) -> RouteRecord:
    terminal = row["terminal_result_json"]
    return RouteRecord(
        route_id=str(row["route_id"]),
        request_key=str(row["request_key"]),
        request_hash=str(row["request_hash"]),
        context_hash=str(row["context_hash"]),
        state=RouteState(row["state"]),
        disposition=str(row["disposition"]),
        startable=bool(row["startable"]),
        expires_at=_parse(row["expires_at"]),
        run_id=None if row["run_id"] is None else str(row["run_id"]),
        plan_output=json.loads(row["plan_output_json"]),
        terminal_result=None if terminal is None else json.loads(terminal),
    )


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
