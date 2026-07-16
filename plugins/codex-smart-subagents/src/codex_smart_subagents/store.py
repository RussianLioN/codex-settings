"""Durable SQLite state for adaptive-subagent routes."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


class LeaseForbidden(StoreError):
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


@dataclass(frozen=True)
class NodeRecord:
    route_id: str
    node_id: str
    ordinal: int
    role: str
    mission: str
    dependencies: tuple[str, ...]
    context_refs: tuple[str, ...]
    scope_id: str
    artifact_profile_id: str
    validation_profile_id: str
    assessment: dict[str, Any]
    risk_flags: tuple[str, ...]
    selected_model: str
    reasoning_effort: str
    permission_profile_id: str
    disposition: str
    state: RouteState
    result: dict[str, Any] | None


@dataclass(frozen=True)
class ExecutionBundle:
    route: RouteRecord
    context: RequestContext
    nodes: tuple[NodeRecord, ...]


@dataclass(frozen=True)
class ClaimedRoute:
    route: RouteRecord
    context: RequestContext
    nodes: tuple[NodeRecord, ...]
    lease_token: str
    lease_expires_at: datetime


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
        self._ensure_runtime_artifacts_schema()
        self._verify_database_file()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def active_node_count(self) -> int:
        terminal = tuple(
            state.value for state in RouteState if is_terminal(state)
        )
        placeholders = ",".join("?" for _ in terminal)
        with self._lock:
            row = self._connection.execute(
                f"""
                select count(*) as count
                from nodes
                where route_id in (
                  select route_id from routes
                  where startable = 1
                    and state not in ({placeholders})
                )
                """,
                terminal,
            ).fetchone()
        return int(row["count"])

    def reserve_runtime_artifact(
        self,
        *,
        route_id: str,
        node_id: str,
        kind: str,
        path: Path,
        allowed_root: Path,
    ) -> str:
        if (
            not kind
            or len(kind) > 64
            or not kind.replace("_", "").isalnum()
        ):
            raise ValueError("runtime artifact kind is invalid")
        root = allowed_root.expanduser().resolve(strict=True)
        if (
            not root.is_dir()
            or root.is_symlink()
            or root.stat().st_uid != os.getuid()
            or stat.S_IMODE(root.stat().st_mode) != 0o700
        ):
            raise ValueError("runtime artifact root is unsafe")
        if not path.is_absolute() or path.parent.resolve(strict=True) != root:
            raise ValueError("runtime artifact path must be a direct child")
        if os.path.lexists(path):
            raise ValueError("runtime artifact path must be fresh")
        artifact_id = new_opaque_id("ra1")
        now = _utc_now()
        with self._transaction() as connection:
            node = connection.execute(
                """
                select 1 from nodes
                where route_id = ? and node_id = ?
                """,
                (route_id, node_id),
            ).fetchone()
            if node is None:
                raise RouteNotFound(
                    "NODE_NOT_FOUND",
                    "route node does not exist",
                )
            connection.execute(
                """
                insert into runtime_artifacts (
                  artifact_id, route_id, node_id, kind, path, allowed_root,
                  state, device, inode, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, 'RESERVED', null, null, ?, ?)
                """,
                (
                    artifact_id,
                    route_id,
                    node_id,
                    kind,
                    os.fspath(path),
                    os.fspath(root),
                    _iso(now),
                    _iso(now),
                ),
            )
        return artifact_id

    def seal_runtime_artifact(
        self,
        artifact_id: str,
        *,
        terminal: bool,
    ) -> dict[str, Any]:
        with self._transaction() as connection:
            row = connection.execute(
                """
                select * from runtime_artifacts
                where artifact_id = ?
                """,
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise RouteNotFound(
                    "ARTIFACT_NOT_FOUND",
                    "runtime artifact does not exist",
                )
            path = Path(str(row["path"]))
            root = Path(str(row["allowed_root"]))
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                state = "MISSING"
                device = None
                inode = None
            else:
                if (
                    path.parent.resolve(strict=True) != root.resolve(strict=True)
                    or stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise StoreError(
                        "UNSAFE_RUNTIME_ARTIFACT",
                        "runtime artifact identity is unsafe",
                    )
                state = "TERMINAL" if terminal else "ACTIVE"
                device = int(metadata.st_dev)
                inode = int(metadata.st_ino)
            now = _utc_now()
            connection.execute(
                """
                update runtime_artifacts
                set state = ?, device = ?, inode = ?, updated_at = ?
                where artifact_id = ?
                """,
                (state, device, inode, _iso(now), artifact_id),
            )
            updated = connection.execute(
                """
                select * from runtime_artifacts
                where artifact_id = ?
                """,
                (artifact_id,),
            ).fetchone()
        return _runtime_artifact_record(updated)

    def runtime_artifacts(
        self,
        route_id: str | None = None,
    ) -> list[dict[str, Any]]:
        query = """
            select * from runtime_artifacts
        """
        parameters: tuple[str, ...] = ()
        if route_id is not None:
            query += " where route_id = ?"
            parameters = (route_id,)
        query += " order by created_at, artifact_id"
        with self._lock:
            rows = self._connection.execute(query, parameters).fetchall()
        return [_runtime_artifact_record(row) for row in rows]

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
                      dependencies_json, context_refs_json, scope_id,
                      artifact_profile_id, validation_profile_id,
                      assessment_json, risk_flags_json,
                      selected_model, reasoning_effort,
                      permission_profile_id, disposition, state,
                      updated_at
                    ) values (
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        route_id,
                        node["clientNodeId"],
                        ordinal,
                        node["role"],
                        node["mission"],
                        _json(node["dependencyIds"]),
                        _json(node["contextRefs"]),
                        node["scopeId"],
                        node["artifactProfileId"],
                        node["validationProfileId"],
                        _json(node["assessment"]),
                        _json(node["riskFlags"]),
                        node["selectedModel"],
                        node["reasoningEffort"],
                        node["permissionProfileId"],
                        node["disposition"],
                        RouteState.PLANNED.value,
                        _iso(now),
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
            connection.execute(
                """
                update nodes
                set state = ?, updated_at = ?
                where route_id = ? and disposition = ?
                """,
                (
                    RouteState.QUEUED.value,
                    _iso(now),
                    route_id,
                    "delegate",
                ),
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

    def claim_next_route(
        self,
        *,
        owner_id: str,
        pid: int,
        start_marker: str,
        now: datetime,
        lease_seconds: int,
    ) -> ClaimedRoute | None:
        if not owner_id or not start_marker or pid <= 0 or lease_seconds <= 0:
            raise ValueError("route lease identity and duration are invalid")
        now = _aware_utc(now)
        expires_at = now + timedelta(seconds=lease_seconds)
        lease_token = new_opaque_id("lease1")
        with self._transaction() as connection:
            row = connection.execute(
                """
                select * from routes
                where state = ?
                order by created_at, route_id
                limit 1
                """,
                (RouteState.QUEUED.value,),
            ).fetchone()
            if row is None:
                return None
            before = RouteState(row["state"])
            assert_transition(before, RouteState.LEASED)
            route_id = str(row["route_id"])
            connection.execute(
                """
                update routes set state = ?, updated_at = ?
                where route_id = ? and state = ?
                """,
                (
                    RouteState.LEASED.value,
                    _iso(now),
                    route_id,
                    RouteState.QUEUED.value,
                ),
            )
            connection.execute(
                """
                insert or replace into leases (
                  route_id, node_id, owner_id, token_hash,
                  pid, start_marker, expires_at, heartbeat_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    route_id,
                    "",
                    owner_id,
                    sha256_text(lease_token),
                    pid,
                    start_marker,
                    _iso(expires_at),
                    _iso(now),
                ),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id="",
                event="route_leased",
                state=RouteState.LEASED,
                code="LEASED",
                message="",
            )
            updated = connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
            node_rows = connection.execute(
                """
                select * from nodes
                where route_id = ?
                order by ordinal
                """,
                (route_id,),
            ).fetchall()
        return ClaimedRoute(
            route=_route_record(updated),
            context=RequestContext.from_wire(
                json.loads(updated["context_json"])
            ),
            nodes=tuple(_node_record(node) for node in node_rows),
            lease_token=lease_token,
            lease_expires_at=expires_at,
        )

    def heartbeat_route_lease(
        self,
        *,
        route_id: str,
        owner_id: str,
        lease_token: str,
        now: datetime,
        lease_seconds: int,
    ) -> datetime:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now = _aware_utc(now)
        expires_at = now + timedelta(seconds=lease_seconds)
        with self._transaction() as connection:
            row = connection.execute(
                """
                select owner_id, token_hash from leases
                where route_id = ? and node_id = ''
                """,
                (route_id,),
            ).fetchone()
            if (
                row is None
                or row["owner_id"] != owner_id
                or row["token_hash"] != sha256_text(lease_token)
            ):
                raise LeaseForbidden(
                    "LEASE_FORBIDDEN",
                    "route lease identity does not match",
                )
            connection.execute(
                """
                update leases
                set expires_at = ?, heartbeat_at = ?
                where route_id = ? and node_id = ''
                """,
                (_iso(expires_at), _iso(now), route_id),
            )
        return expires_at

    def release_route_lease(
        self,
        *,
        route_id: str,
        owner_id: str,
        lease_token: str,
    ) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                """
                select owner_id, token_hash from leases
                where route_id = ? and node_id = ''
                """,
                (route_id,),
            ).fetchone()
            if row is None:
                return
            if (
                row["owner_id"] != owner_id
                or row["token_hash"] != sha256_text(lease_token)
            ):
                raise LeaseForbidden(
                    "LEASE_FORBIDDEN",
                    "route lease identity does not match",
                )
            connection.execute(
                "delete from leases where route_id = ? and node_id = ''",
                (route_id,),
            )

    def execution_bundle(self, route_id: str) -> ExecutionBundle:
        with self._lock:
            route = self._connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
            nodes = self._connection.execute(
                """
                select * from nodes
                where route_id = ?
                order by ordinal
                """,
                (route_id,),
            ).fetchall()
        if route is None:
            raise RouteNotFound("ROUTE_NOT_FOUND", "route does not exist")
        return ExecutionBundle(
            route=_route_record(route),
            context=RequestContext.from_wire(json.loads(route["context_json"])),
            nodes=tuple(_node_record(node) for node in nodes),
        )

    def route_state(self, route_id: str) -> RouteState:
        with self._lock:
            row = self._connection.execute(
                "select state from routes where route_id = ?",
                (route_id,),
            ).fetchone()
        if row is None:
            raise RouteNotFound("ROUTE_NOT_FOUND", "route does not exist")
        return RouteState(row["state"])

    def transition_node(
        self,
        route_id: str,
        node_id: str,
        new_state: RouteState,
        *,
        event: str,
        code: str,
        message: str,
    ) -> NodeRecord:
        with self._transaction() as connection:
            row = connection.execute(
                """
                select * from nodes
                where route_id = ? and node_id = ?
                """,
                (route_id, node_id),
            ).fetchone()
            if row is None:
                raise RouteNotFound(
                    "NODE_NOT_FOUND",
                    "route node does not exist",
                )
            before = RouteState(row["state"])
            assert_transition(before, new_state)
            now = _utc_now()
            connection.execute(
                """
                update nodes set state = ?, updated_at = ?
                where route_id = ? and node_id = ?
                """,
                (new_state.value, _iso(now), route_id, node_id),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id=node_id,
                event=event,
                state=new_state,
                code=code,
                message=message,
            )
            updated = connection.execute(
                """
                select * from nodes
                where route_id = ? and node_id = ?
                """,
                (route_id, node_id),
            ).fetchone()
        return _node_record(updated)

    def complete_node(
        self,
        route_id: str,
        node_id: str,
        *,
        result: dict[str, Any],
    ) -> NodeRecord:
        with self._transaction() as connection:
            row = connection.execute(
                """
                select * from nodes
                where route_id = ? and node_id = ?
                """,
                (route_id, node_id),
            ).fetchone()
            if row is None:
                raise RouteNotFound(
                    "NODE_NOT_FOUND",
                    "route node does not exist",
                )
            before = RouteState(row["state"])
            assert_transition(before, RouteState.SUCCEEDED)
            now = _utc_now()
            connection.execute(
                """
                update nodes
                set state = ?, result_json = ?, updated_at = ?
                where route_id = ? and node_id = ?
                """,
                (
                    RouteState.SUCCEEDED.value,
                    _json(result),
                    _iso(now),
                    route_id,
                    node_id,
                ),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id=node_id,
                event="node_succeeded",
                state=RouteState.SUCCEEDED,
                code="SUCCEEDED",
                message="",
            )
            updated = connection.execute(
                """
                select * from nodes
                where route_id = ? and node_id = ?
                """,
                (route_id, node_id),
            ).fetchone()
        return _node_record(updated)

    def record_intent(
        self,
        *,
        route_id: str,
        node_id: str,
        kind: str,
        payload: dict[str, Any],
    ) -> str:
        if not kind:
            raise ValueError("intent kind must be non-empty")
        intent_id = new_opaque_id("intent1")
        encoded = _json(payload)
        with self._transaction() as connection:
            connection.execute(
                """
                insert into intents (
                  intent_id, route_id, node_id, kind,
                  payload_hash, payload_json, state, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    intent_id,
                    route_id,
                    node_id,
                    kind,
                    sha256_text(encoded),
                    encoded,
                    "PENDING",
                    _iso(_utc_now()),
                ),
            )
        return intent_id

    def complete_intent(self, intent_id: str) -> None:
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                update intents
                set state = 'COMPLETED', completed_at = ?
                where intent_id = ? and state = 'PENDING'
                """,
                (_iso(_utc_now()), intent_id),
            )
            if cursor.rowcount != 1:
                raise StoreError(
                    "INTENT_NOT_PENDING",
                    "intent does not exist or is already complete",
                )

    def pending_intents(self, route_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                select intent_id, node_id, kind, payload_hash,
                       payload_json, created_at
                from intents
                where route_id = ? and state = 'PENDING'
                order by created_at, intent_id
                """,
                (route_id,),
            ).fetchall()
        return [
            {
                "intentId": str(row["intent_id"]),
                "nodeId": str(row["node_id"]),
                "kind": str(row["kind"]),
                "payloadHash": str(row["payload_hash"]),
                "payload": json.loads(row["payload_json"]),
                "createdAt": str(row["created_at"]),
            }
            for row in rows
        ]

    def begin_attempt(
        self,
        *,
        route_id: str,
        node_id: str,
        model: str,
        reasoning_effort: str,
        permission_profile_id: str,
        pid: int,
        argv_fingerprint: str,
        permission_probe_id: str,
    ) -> str:
        attempt_id = new_opaque_id("att1")
        with self._transaction() as connection:
            connection.execute(
                """
                insert into attempts (
                  attempt_id, route_id, node_id, state,
                  model, reasoning_effort, permission_profile_id,
                  pid, argv_fingerprint, permission_probe_id,
                  started_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    route_id,
                    node_id,
                    "RUNNING",
                    model,
                    reasoning_effort,
                    permission_profile_id,
                    pid,
                    argv_fingerprint,
                    permission_probe_id,
                    _iso(_utc_now()),
                ),
            )
            connection.execute(
                """
                update nodes
                set attempt_count = attempt_count + 1, updated_at = ?
                where route_id = ? and node_id = ?
                """,
                (_iso(_utc_now()), route_id, node_id),
            )
        return attempt_id

    def complete_attempt(
        self,
        attempt_id: str,
        *,
        state: str,
        result: dict[str, Any] | None,
        attestation: dict[str, Any] | None,
        argv_fingerprint: str | None = None,
        permission_probe_id: str | None = None,
        error_code: str = "",
        error_message: str = "",
    ) -> None:
        if state not in {"SUCCEEDED", "FAILED", "CANCELLED", "QUARANTINED"}:
            raise ValueError("attempt terminal state is invalid")
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                update attempts
                set state = ?, result_json = ?, attestation_json = ?,
                    argv_fingerprint = coalesce(?, argv_fingerprint),
                    permission_probe_id = coalesce(?, permission_probe_id),
                    error_code = ?, error_message = ?, ended_at = ?
                where attempt_id = ? and state = 'RUNNING'
                """,
                (
                    state,
                    None if result is None else _json(result),
                    None if attestation is None else _json(attestation),
                    argv_fingerprint,
                    permission_probe_id,
                    error_code,
                    error_message[:1000],
                    _iso(_utc_now()),
                    attempt_id,
                ),
            )
            if cursor.rowcount != 1:
                raise StoreError(
                    "ATTEMPT_NOT_RUNNING",
                    "attempt does not exist or is already terminal",
                )

    def attempts_for_route(self, route_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                select * from attempts
                where route_id = ?
                order by started_at, attempt_id
                """,
                (route_id,),
            ).fetchall()
        return [
            {
                "attemptId": str(row["attempt_id"]),
                "nodeId": str(row["node_id"]),
                "state": str(row["state"]),
                "model": str(row["model"]),
                "reasoningEffort": str(row["reasoning_effort"]),
                "permissionProfileId": str(row["permission_profile_id"]),
                "pid": int(row["pid"]),
                "argvFingerprint": str(row["argv_fingerprint"]),
                "permissionProbeId": str(row["permission_probe_id"]),
                "result": (
                    None
                    if row["result_json"] is None
                    else json.loads(row["result_json"])
                ),
                "attestation": (
                    None
                    if row["attestation_json"] is None
                    else json.loads(row["attestation_json"])
                ),
                "errorCode": str(row["error_code"] or ""),
                "errorMessage": str(row["error_message"] or ""),
            }
            for row in rows
        ]

    def finish_route(
        self,
        route_id: str,
        request_context: RequestContext,
        new_state: RouteState,
        *,
        terminal_result: dict[str, Any],
        event: str,
        code: str,
        message: str,
    ) -> RouteRecord:
        if not is_terminal(new_state):
            raise ValueError("finish_route requires a terminal state")
        with self._transaction() as connection:
            row = self._route_row(connection, route_id, request_context)
            before = RouteState(row["state"])
            assert_transition(before, new_state)
            now = _utc_now()
            connection.execute(
                """
                update routes
                set state = ?, terminal_result_json = ?, updated_at = ?
                where route_id = ?
                """,
                (
                    new_state.value,
                    _json(terminal_result),
                    _iso(now),
                    route_id,
                ),
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
            connection.execute(
                "delete from leases where route_id = ?",
                (route_id,),
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

    def requeue_recovering(self, route_id: str) -> RouteRecord:
        with self._transaction() as connection:
            row = connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
            if row is None:
                raise RouteNotFound(
                    "ROUTE_NOT_FOUND",
                    "route does not exist",
                )
            before = RouteState(row["state"])
            assert_transition(before, RouteState.QUEUED)
            now = _utc_now()
            connection.execute(
                """
                update routes set state = ?, updated_at = ?
                where route_id = ?
                """,
                (RouteState.QUEUED.value, _iso(now), route_id),
            )
            connection.execute(
                """
                update nodes
                set state = ?, updated_at = ?
                where route_id = ? and state in (?, ?, ?, ?, ?)
                """,
                (
                    RouteState.QUEUED.value,
                    _iso(now),
                    route_id,
                    RouteState.LEASED.value,
                    RouteState.PREPARING.value,
                    RouteState.RUNNING.value,
                    RouteState.RETRYABLE.value,
                    RouteState.RECOVERING.value,
                ),
            )
            self._insert_event(
                connection,
                route_id=route_id,
                node_id="",
                event="route_requeued",
                state=RouteState.QUEUED,
                code="RECOVERED",
                message="",
            )
            updated = connection.execute(
                "select * from routes where route_id = ?",
                (route_id,),
            ).fetchone()
        return _route_record(updated)

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
                  context_refs_json text not null,
                  scope_id text not null,
                  artifact_profile_id text not null,
                  validation_profile_id text not null,
                  assessment_json text not null,
                  risk_flags_json text not null,
                  selected_model text not null,
                  reasoning_effort text not null,
                  permission_profile_id text not null,
                  disposition text not null,
                  state text not null,
                  attempt_count integer not null default 0,
                  result_json text,
                  updated_at text not null,
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
                  payload_json text not null,
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

                create table attempts (
                  attempt_id text primary key,
                  route_id text not null references routes(route_id) on delete cascade,
                  node_id text not null,
                  state text not null,
                  model text not null,
                  reasoning_effort text not null,
                  permission_profile_id text not null,
                  pid integer not null,
                  argv_fingerprint text not null,
                  permission_probe_id text not null,
                  attestation_json text,
                  result_json text,
                  error_code text,
                  error_message text,
                  started_at text not null,
                  ended_at text
                );

                create index attempts_route_started
                  on attempts(route_id, started_at);
                """
            )
            connection.execute(f"pragma user_version={SCHEMA_VERSION}")

    def _ensure_runtime_artifacts_schema(self) -> None:
        with self._transaction() as connection:
            connection.executescript(
                """
                create table if not exists runtime_artifacts (
                  artifact_id text primary key,
                  route_id text not null references routes(route_id) on delete cascade,
                  node_id text not null,
                  kind text not null,
                  path text not null unique,
                  allowed_root text not null,
                  state text not null,
                  device integer,
                  inode integer,
                  created_at text not null,
                  updated_at text not null
                );

                create index if not exists runtime_artifacts_route
                  on runtime_artifacts(route_id, created_at);
                """
            )

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


def _node_record(row: sqlite3.Row) -> NodeRecord:
    result = row["result_json"]
    return NodeRecord(
        route_id=str(row["route_id"]),
        node_id=str(row["node_id"]),
        ordinal=int(row["ordinal"]),
        role=str(row["role"]),
        mission=str(row["mission"]),
        dependencies=tuple(json.loads(row["dependencies_json"])),
        context_refs=tuple(json.loads(row["context_refs_json"])),
        scope_id=str(row["scope_id"]),
        artifact_profile_id=str(row["artifact_profile_id"]),
        validation_profile_id=str(row["validation_profile_id"]),
        assessment=json.loads(row["assessment_json"]),
        risk_flags=tuple(json.loads(row["risk_flags_json"])),
        selected_model=str(row["selected_model"]),
        reasoning_effort=str(row["reasoning_effort"]),
        permission_profile_id=str(row["permission_profile_id"]),
        disposition=str(row["disposition"]),
        state=RouteState(row["state"]),
        result=None if result is None else json.loads(result),
    )


def _runtime_artifact_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "artifactId": str(row["artifact_id"]),
        "routeId": str(row["route_id"]),
        "nodeId": str(row["node_id"]),
        "kind": str(row["kind"]),
        "path": str(row["path"]),
        "allowedRoot": str(row["allowed_root"]),
        "state": str(row["state"]),
        "device": (
            None if row["device"] is None else int(row["device"])
        ),
        "inode": None if row["inode"] is None else int(row["inode"]),
        "createdAt": str(row["created_at"]),
        "updatedAt": str(row["updated_at"]),
    }


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


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)
