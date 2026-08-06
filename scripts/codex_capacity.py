#!/usr/bin/env python3
"""Shared user-level Codex subagent capacity queue."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import shlex
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


DEFAULT_CAPACITY = 6
MAX_CAPACITY = 20
SCHEMA_VERSION = 3
MAX_OPERATION_SECONDS = 0.45
OPERATION_BUDGET_ENV = "CODEX_CAPACITY_MAX_OPERATION_SECONDS"
SQLITE_BUSY_TIMEOUT_MS = 1
DEFAULT_RETRY_DELAY_MS = 250
CLEANUP_TTL_SECONDS = 30
PROVISIONAL_TTL_SECONDS = 30
ROOT_RECOVERY_STAGE_SECONDS = 10
MAX_PENDING_PER_SESSION = 20
MAX_PENDING_PER_USER = 512
ACTIVE_LEASE_STATES = {"PROVISIONAL", "ACTIVE", "SUSPECT", "RECOVERING", "CLEANUP_REQUIRED"}
TERMINAL_LEASE_STATES = {"RELEASED"}
MANAGED_FILE_NAMES = {"capacity.sqlite3", "capacity.sqlite3-wal", "capacity.sqlite3-shm", "capacity.lock", "events.jsonl"}
INITIAL_SCHEMA_STATEMENTS = (
    """
    create table if not exists meta (
      key text primary key,
      value text not null
    )
    """,
    """
    create table if not exists requests (
      request_id text primary key,
      session_id text not null,
      turn_id text not null,
      ticket_id text,
      lease_id text,
      created_at real not null,
      updated_at real not null
    )
    """,
    """
    create table if not exists tickets (
      ticket_id text primary key,
      request_id text not null unique references requests(request_id),
      session_id text not null,
      turn_id text not null,
      state text not null check (state in ('PENDING', 'READY', 'CANCELED')),
      created_at real not null,
      ready_at real,
      consumed_at real,
      updated_at real not null
    )
    """,
    """
    create table if not exists leases (
      lease_id text primary key,
      request_id text not null references requests(request_id),
      ticket_id text references tickets(ticket_id),
      session_id text not null,
      turn_id text not null,
      state text not null check (
        state in ('PROVISIONAL', 'ACTIVE', 'SUSPECT', 'RECOVERING', 'CLEANUP_REQUIRED', 'RELEASED')
      ),
      fencing_epoch integer not null,
      agent_id text,
      created_at real not null,
      updated_at real not null,
      cleanup_after real,
      released_at real
    )
    """,
    """
    create unique index if not exists leases_active_request
      on leases(request_id)
      where state != 'RELEASED'
    """,
    """
    create table if not exists events (
      id integer primary key autoincrement,
      created_at real not null,
      event text not null,
      payload_json text not null
    )
    """,
    """
    create table if not exists managed_roots (
      session_id text primary key,
      root_pid integer not null,
      root_start_marker text not null,
      root_state text not null default 'ACTIVE' check (root_state in ('ACTIVE', 'SUSPECT', 'RECOVERING')),
      created_at real not null,
      updated_at real not null,
      cleanup_after real
    )
    """,
    """
    create index if not exists managed_roots_identity
      on managed_roots(root_pid, root_start_marker)
    """,
)
_INITIALIZED_DATABASES: Dict[Path, Tuple[int, int]] = {}
_INITIALIZE_LOCK = threading.Lock()


class CapacityError(Exception):
    def __init__(self, reason: str, *, exit_code: int = 1) -> None:
        super().__init__(reason)
        self.reason = reason
        self.exit_code = exit_code


class CapacityStore:
    def __init__(
        self,
        *,
        home: Optional[Path] = None,
        state_dir: Optional[Path] = None,
        capacity: int = DEFAULT_CAPACITY,
        cleanup_ttl_seconds: float = CLEANUP_TTL_SECONDS,
        provisional_ttl_seconds: float = PROVISIONAL_TTL_SECONDS,
        max_operation_seconds: Optional[float] = None,
    ) -> None:
        self.home = Path(home or Path.home()).expanduser()
        self.state_dir = Path(state_dir or self.home / ".local" / "state" / "codex-capacity-v1").expanduser()
        self.db_path = self.state_dir / "capacity.sqlite3"
        self.lock_path = self.state_dir / "capacity.lock"
        self.log_path = self.state_dir / "events.jsonl"
        self.capacity = int(capacity)
        self.cleanup_ttl_seconds = max(0.0, float(cleanup_ttl_seconds))
        self.provisional_ttl_seconds = max(0.0, float(provisional_ttl_seconds))
        self.max_operation_seconds = operation_budget_seconds(max_operation_seconds)
        self.invalid_reason = None
        if self.capacity < 0 or self.capacity > MAX_CAPACITY:
            self.invalid_reason = f"invalid_capacity: capacity must be between 0 and {MAX_CAPACITY}"
        if not math.isfinite(self.max_operation_seconds) or self.max_operation_seconds < 0:
            self.invalid_reason = "invalid_operation_budget: must be a finite non-negative number"

    def acquire_or_queue(
        self,
        *,
        session_id: str,
        turn_id: str,
        task_name: str,
        wave_limit: Optional[int] = None,
        root_pid: Optional[int] = None,
        root_start_marker: Optional[str] = None,
    ) -> dict[str, Any]:
        request_id = request_hash(session_id, turn_id, task_name)
        root_identity = normalize_root_identity(root_pid, root_start_marker)
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_stale_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            if root_identity is not None:
                self._register_managed_root(conn, session_id=session_id, root_identity=root_identity, now=now)
            existing = self._request_row(conn, request_id)
            if existing:
                return self._existing_request_result(conn, existing, now, wave_limit=wave_limit)
            pending_session = self._count(
                conn,
                "select count(*) from tickets where session_id = ? and state = 'PENDING'",
                (session_id,),
            )
            if pending_session >= MAX_PENDING_PER_SESSION:
                return {"state": "ERROR", "reason": "session_queue_full", "request_id": request_id}
            pending_user = self._count(conn, "select count(*) from tickets where state = 'PENDING'")
            if pending_user >= MAX_PENDING_PER_USER:
                return {"state": "ERROR", "reason": "user_queue_full", "request_id": request_id}

            conn.execute(
                """
                insert into requests (request_id, session_id, turn_id, created_at, updated_at)
                values (?, ?, ?, ?, ?)
                """,
                (request_id, session_id, turn_id, now, now),
            )
            if (
                self._reserved_count(conn) < self.capacity
                and self._waiting_ticket_count(conn) == 0
                and self._wave_reserved_count(conn, session_id=session_id, turn_id=turn_id) < self._normalized_wave_limit(wave_limit)
            ):
                lease_id, epoch = self._create_lease(conn, request_id, session_id, turn_id, now, ticket_id=None)
                self._log(conn, now, "acquire", request_id=request_id, lease_id=lease_id)
                return lease_result(request_id, lease_id, epoch, "PROVISIONAL")

            ticket_id = self._create_ticket(conn, request_id, session_id, turn_id, now, "PENDING")
            self._log(conn, now, "queue", request_id=request_id, ticket_id=ticket_id)
            return self._ticket_result_from_row(conn, self._ticket_by_id(conn, ticket_id))

        return self._write(work)

    def activate(self, *, lease_id: str, fencing_epoch: int, agent_id: Optional[str] = None) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_stale_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            row = self._lease_by_id(conn, lease_id)
            if row is None:
                return {"state": "STALE", "reason": "lease_not_found", "lease_id": lease_id}
            if int(row["fencing_epoch"]) != int(fencing_epoch):
                return {"state": "STALE", "reason": "fencing_epoch_mismatch", "lease_id": lease_id}
            if row["state"] in TERMINAL_LEASE_STATES:
                return self._lease_result_from_row(row, state="STALE", reason="lease_released")
            if row["state"] == "CLEANUP_REQUIRED":
                return self._lease_result_from_row(row, state="STALE", reason="cleanup_required")
            if row["state"] != "ACTIVE":
                conn.execute(
                    """
                    update leases
                    set state = 'ACTIVE', agent_id = coalesce(?, agent_id), updated_at = ?
                    where lease_id = ? and fencing_epoch = ? and state != 'RELEASED'
                    """,
                    (agent_id, now, lease_id, fencing_epoch),
                )
                self._log(conn, now, "activate", lease_id=lease_id)
            return self._lease_result_from_row(self._lease_by_id(conn, lease_id))

        return self._write(work)

    def activate_next(self, *, session_id: str, turn_id: str, agent_id: str) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_stale_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            existing = conn.execute(
                """
                select * from leases
                where session_id = ? and agent_id = ?
                order by updated_at desc, created_at desc, lease_id
                limit 1
                """,
                (session_id, agent_id),
            ).fetchone()
            if existing:
                return self._lease_result_from_row(existing)
            row = conn.execute(
                """
                select * from leases
                where session_id = ? and turn_id = ? and agent_id is null and state = 'PROVISIONAL'
                order by created_at, lease_id
                limit 1
                """,
                (session_id, turn_id),
            ).fetchone()
            if row is None:
                return {"state": "NOOP", "reason": "no_unbound_provisional_lease"}
            conn.execute(
                """
                update leases
                set state = 'ACTIVE', agent_id = ?, updated_at = ?
                where lease_id = ? and state = 'PROVISIONAL' and agent_id is null
                """,
                (agent_id, now, row["lease_id"]),
            )
            self._log(conn, now, "activate-next", lease_id=row["lease_id"], agent_id=agent_id)
            return self._lease_result_from_row(self._lease_by_id(conn, row["lease_id"]))

        return self._write(work)

    def release_agent(self, *, session_id: str, agent_id: str) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_stale_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            row = conn.execute(
                """
                select * from leases
                where session_id = ? and agent_id = ?
                order by case when state = 'RELEASED' then 1 else 0 end, updated_at desc, lease_id
                limit 1
                """,
                (session_id, agent_id),
            ).fetchone()
            if row is None:
                return {"state": "NOOP", "reason": "agent_lease_not_found", "session_id": session_id, "agent_id": agent_id}
            if row["state"] == "RELEASED":
                return self._lease_result_from_row(row)
            if row["state"] == "CLEANUP_REQUIRED":
                return self._lease_result_from_row(row, state="STALE", reason="cleanup_required")
            conn.execute(
                """
                update leases
                set state = 'RELEASED', released_at = ?, updated_at = ?
                where lease_id = ? and state != 'RELEASED'
                """,
                (now, now, row["lease_id"]),
            )
            self._log(conn, now, "release-agent", lease_id=row["lease_id"], agent_id=agent_id)
            self._promote_pending(conn, now, limit=1)
            return self._lease_result_from_row(self._lease_by_id(conn, row["lease_id"]))

        return self._write(work)

    def release(self, *, lease_id: str, fencing_epoch: int) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_stale_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            row = self._lease_by_id(conn, lease_id)
            if row is None:
                return {"state": "STALE", "reason": "lease_not_found", "lease_id": lease_id}
            if int(row["fencing_epoch"]) != int(fencing_epoch):
                return {"state": "STALE", "reason": "fencing_epoch_mismatch", "lease_id": lease_id}
            if row["state"] == "RELEASED":
                return self._lease_result_from_row(row)
            conn.execute(
                """
                update leases
                set state = 'RELEASED', released_at = ?, updated_at = ?
                where lease_id = ? and fencing_epoch = ?
                """,
                (now, now, lease_id, fencing_epoch),
            )
            self._log(conn, now, "release", lease_id=lease_id)
            self._promote_pending(conn, now, limit=1)
            return self._lease_result_from_row(self._lease_by_id(conn, lease_id))

        return self._write(work)

    def release_request(self, request_id: str, expected_state: str = "PROVISIONAL") -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_stale_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            row = conn.execute(
                """
                select * from leases
                where request_id = ?
                order by created_at desc, lease_id
                limit 1
                """,
                (request_id,),
            ).fetchone()
            if row is None:
                return {"state": "NOOP", "reason": "request_lease_not_found", "request_id": request_id}
            if row["state"] == "RELEASED":
                return self._lease_result_from_row(row)
            if row["state"] != expected_state:
                return self._lease_result_from_row(row, state="STALE", reason="unexpected_lease_state")
            if row["state"] != "PROVISIONAL" or row["agent_id"] is not None:
                return self._lease_result_from_row(row, state="STALE", reason="bound_or_non_provisional_lease")
            conn.execute(
                """
                update leases
                set state = 'RELEASED', released_at = ?, updated_at = ?
                where lease_id = ? and state = 'PROVISIONAL' and agent_id is null
                """,
                (now, now, row["lease_id"]),
            )
            self._log(conn, now, "release-request", request_id=request_id, lease_id=row["lease_id"])
            self._promote_pending(conn, now, limit=1)
            return self._lease_result_from_row(self._lease_by_id(conn, row["lease_id"]))

        return self._write(work)

    def cancel_turn(self, *, session_id: str, turn_id: str) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            ready_canceled = self._count(
                conn,
                """
                select count(*) from tickets
                where session_id = ? and turn_id = ? and state = 'READY' and consumed_at is null
                """,
                (session_id, turn_id),
            )
            changed = conn.execute(
                """
                update tickets
                set state = 'CANCELED', updated_at = ?
                where session_id = ? and turn_id = ?
                  and (state = 'PENDING' or (state = 'READY' and consumed_at is null))
                """,
                (now, session_id, turn_id),
            ).rowcount
            if ready_canceled:
                self._promote_pending(conn, now, limit=ready_canceled)
            self._log(conn, now, "cancel-turn", session_id=session_id, turn_id=turn_id, canceled=changed)
            return {
                "state": "OK",
                "canceled": changed,
                "ready_canceled": ready_canceled,
                "session_id": session_id,
                "turn_id": turn_id,
            }

        return self._write(work)

    def cancel_session(self, *, session_id: str) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            ready_canceled = self._count(
                conn,
                """
                select count(*) from tickets
                where session_id = ? and state = 'READY' and consumed_at is null
                """,
                (session_id,),
            )
            tickets = conn.execute(
                """
                update tickets
                set state = 'CANCELED', updated_at = ?
                where session_id = ?
                  and (state = 'PENDING' or (state = 'READY' and consumed_at is null))
                """,
                (now, session_id),
            ).rowcount
            leases = conn.execute(
                f"""
                update leases
                set state = 'CLEANUP_REQUIRED', cleanup_after = ?, updated_at = ?
                where session_id = ? and state in ({placeholders(ACTIVE_LEASE_STATES - {'CLEANUP_REQUIRED'})})
                """,
                (now + self.cleanup_ttl_seconds, now, session_id, *sorted(ACTIVE_LEASE_STATES - {"CLEANUP_REQUIRED"})),
            ).rowcount
            roots = self._unregister_managed_root(conn, session_id=session_id)
            if ready_canceled:
                self._promote_pending(conn, now, limit=ready_canceled)
            self._log(conn, now, "cancel-session", session_id=session_id, tickets=tickets, leases=leases, roots=roots)
            return {
                "state": "OK",
                "session_id": session_id,
                "canceled_tickets": tickets,
                "ready_canceled": ready_canceled,
                "leases_marked": leases,
                "managed_roots_unregistered": roots,
            }

        return self._write(work)

    def recover(self, *, lease_id: str, fencing_epoch: int) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            result = self._recover_cleanup_lease(conn, now, lease_id=lease_id, fencing_epoch=fencing_epoch)
            if result.get("lease_state") == "RELEASED":
                self._promote_pending(conn, now, limit=1)
            return result

        return self._write(work)

    def reconcile(
        self,
        *,
        session_id: Optional[str] = None,
        lease_id: Optional[str] = None,
        fencing_epoch: Optional[int] = None,
    ) -> dict[str, Any]:
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            explicit_release = None
            if lease_id is not None and fencing_epoch is not None:
                explicit_release = self._recover_cleanup_lease(conn, now, lease_id=lease_id, fencing_epoch=fencing_epoch)
            if session_id:
                tickets = conn.execute(
                    """
                    update tickets
                    set state = 'CANCELED', updated_at = ?
                    where session_id = ? and state in ('PENDING', 'READY')
                    """,
                    (now, session_id),
                ).rowcount
                leases = conn.execute(
                    f"""
                    update leases
                    set state = 'CLEANUP_REQUIRED', cleanup_after = ?, updated_at = ?
                    where session_id = ? and state in ({placeholders(ACTIVE_LEASE_STATES - {'CLEANUP_REQUIRED'})})
                    """,
                    (now + self.cleanup_ttl_seconds, now, session_id, *sorted(ACTIVE_LEASE_STATES - {"CLEANUP_REQUIRED"})),
                ).rowcount
            else:
                tickets = 0
                leases = 0
            ttl_released = self._expire_stale_leases(conn, now)
            self._log(
                conn,
                now,
                "reconcile",
                session_id=session_id or "",
                tickets=tickets,
                leases=leases,
                ttl_released=ttl_released,
            )
            promote_limit = ttl_released
            if explicit_release and explicit_release.get("lease_state") == "RELEASED":
                promote_limit += 1
            if promote_limit:
                self._promote_pending(conn, now, limit=promote_limit)
            result: dict[str, Any] = {
                "state": "OK",
                "tickets_canceled": tickets,
                "leases_marked": leases,
                "ttl_released": ttl_released,
            }
            if explicit_release is not None:
                result["explicit_release"] = explicit_release
            return result

        return self._write(work)

    def wait(self, ticket_id: str) -> dict[str, Any]:
        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            row = conn.execute(
                "select * from tickets where ticket_id = ?",
                (ticket_id,),
            ).fetchone()
            if row is None:
                return {"state": "ERROR", "reason": "ticket_not_found", "ticket_id": ticket_id}
            return self._ticket_result_from_row(conn, row)

        return self._read(work)

    def snapshot(self) -> dict[str, Any]:
        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            leases = [dict(row) for row in conn.execute("select * from leases order by created_at, lease_id")]
            tickets = [dict(row) for row in conn.execute("select * from tickets order by ready_at, created_at, ticket_id")]
            return {
                "state": "OK",
                "capacity": self.capacity,
                "active_count": self._active_lease_count(conn),
                "reserved_count": self._reserved_count(conn),
                "managed_root_count": self._managed_root_count(conn),
                "managed_root_session_count": self._managed_root_session_count(conn),
                "leases": leases,
                "tickets": tickets,
            }

        return self._read(work)

    def managed_root_identities(self) -> list[tuple[int, str]]:
        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            rows = conn.execute(
                """
                select root_pid, root_start_marker
                from managed_roots
                group by root_pid, root_start_marker
                order by root_pid, root_start_marker
                """
            ).fetchall()
            return {"state": "OK", "identities": [(int(row["root_pid"]), str(row["root_start_marker"])) for row in rows]}

        result = self._read(work)
        if result.get("state") == "ERROR":
            raise CapacityError(str(result.get("reason") or "managed_root_registry_error"))
        return list(result.get("identities") or [])

    def reconcile_managed_roots(
        self,
        *,
        live_root_identities: Iterable[tuple[int, str]],
        proof_started_at: float,
        stage_seconds: float = ROOT_RECOVERY_STAGE_SECONDS,
    ) -> dict[str, Any]:
        now = current_time()
        try:
            proof = normalize_proof_started_at(proof_started_at)
            live = normalize_root_identity_set_strict(live_root_identities)
            stage = max(0.0, float(stage_seconds))
        except CapacityError as exc:
            return {"state": "ERROR", "reason": exc.reason}

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            roots = [
                dict(row)
                for row in conn.execute(
                    """
                    select session_id, root_pid, root_start_marker, updated_at
                         , root_state, cleanup_after
                    from managed_roots
                    order by session_id
                    """
                )
            ]
            root_by_session = {
                str(root["session_id"]): (int(root["root_pid"]), str(root["root_start_marker"]))
                for root in roots
                if float(root["updated_at"]) <= proof
            }
            present_sessions = {
                session_id
                for session_id, identity in root_by_session.items()
                if identity in live
            }
            missing_sessions = set(root_by_session) - present_sessions

            restored = self._restore_present_managed_roots(conn, now, proof, present_sessions)
            restored_roots = self._restore_present_root_records(conn, now, proof, present_sessions)
            suspected = self._advance_missing_managed_roots(
                conn,
                now,
                proof,
                missing_sessions,
                from_state="ACTIVE",
                to_state="SUSPECT",
                stage_seconds=stage,
            )
            recovering = self._advance_missing_managed_roots(
                conn,
                now,
                proof,
                missing_sessions,
                from_state="SUSPECT",
                to_state="RECOVERING",
                stage_seconds=stage,
                require_due=True,
                updated_before=now,
            )
            suspected_roots = self._advance_missing_root_records(
                conn,
                now,
                proof,
                missing_sessions,
                from_state="ACTIVE",
                to_state="SUSPECT",
                stage_seconds=stage,
            )
            recovering_roots = self._advance_missing_root_records(
                conn,
                now,
                proof,
                missing_sessions,
                from_state="SUSPECT",
                to_state="RECOVERING",
                stage_seconds=stage,
                require_due=True,
                updated_before=now,
            )
            release_result = self._release_recovering_missing_roots(conn, now, proof, missing_sessions, updated_before=now)
            released = int(release_result["released_leases"])
            canceled_tickets = int(release_result["canceled_tickets"])
            ready_canceled = int(release_result["ready_tickets_canceled"])
            root_cancel_result = self._cancel_recovering_root_tickets(conn, now, proof, missing_sessions, updated_before=now)
            canceled_tickets += int(root_cancel_result["canceled_tickets"])
            ready_canceled += int(root_cancel_result["ready_tickets_canceled"])
            promote_limit = released + ready_canceled
            if promote_limit:
                self._promote_pending(conn, now, limit=promote_limit)
            for session_id in sorted(missing_sessions):
                self._unregister_managed_root_if_terminal(conn, session_id=session_id)
            active_count = self._active_lease_count(conn)
            reserved_count = self._reserved_count(conn)
            self._log(
                conn,
                now,
                "managed-root-reconcile",
                roots_checked=len(root_by_session),
                present=len(present_sessions),
                missing=len(missing_sessions),
                restored=restored,
                restored_roots=restored_roots,
                suspected=suspected,
                recovering=recovering,
                suspected_roots=suspected_roots,
                recovering_roots=recovering_roots,
                released=released,
                canceled_tickets=canceled_tickets,
            )
            return {
                "state": "OK",
                "roots_checked": len(root_by_session),
                "present_roots": len(present_sessions),
                "missing_roots": len(missing_sessions),
                "restored_leases": restored,
                "restored_roots": restored_roots,
                "suspect_leases": suspected,
                "recovering_leases": recovering,
                "suspect_roots": suspected_roots,
                "recovering_roots": recovering_roots,
                "released_leases": released,
                "canceled_tickets": canceled_tickets,
                "active_count": active_count,
                "reserved_count": reserved_count,
            }

        return self._write(work)

    def is_managed_root(self, *, root_pid: int, root_start_marker: str) -> bool:
        identity = normalize_root_identity(root_pid, root_start_marker)
        if identity is None:
            return False

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            row = conn.execute(
                """
                select 1 from managed_roots
                where root_pid = ? and root_start_marker = ?
                limit 1
                """,
                identity,
            ).fetchone()
            return {"state": "OK", "managed": row is not None}

        result = self._read(work)
        return bool(result.get("managed")) if result.get("state") != "ERROR" else False

    def _write(self, callback: Callable[[sqlite3.Connection], dict[str, Any]]) -> dict[str, Any]:
        try:
            return self._with_connection(callback, write=True)
        except CapacityError as exc:
            return {"state": "ERROR", "reason": exc.reason}

    def _read(self, callback: Callable[[sqlite3.Connection], dict[str, Any]]) -> dict[str, Any]:
        try:
            return self._with_connection(callback, write=False)
        except CapacityError as exc:
            return {"state": "ERROR", "reason": exc.reason}

    def _with_connection(
        self,
        callback: Callable[[sqlite3.Connection], dict[str, Any]],
        *,
        write: bool,
    ) -> dict[str, Any]:
        try:
            if self.invalid_reason:
                raise CapacityError(self.invalid_reason)
            if self.max_operation_seconds <= 0:
                raise CapacityError("operation_timeout")
            deadline = time.monotonic() + self.max_operation_seconds
            self._prepare_state_dir()
            conn = sqlite3.connect(
                self.db_path,
                timeout=0.05,
                isolation_level=None,
            )
            conn.row_factory = sqlite3.Row
            conn.execute(f"pragma busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            self._initialize_database(conn, deadline)
            if time.monotonic() > deadline:
                raise CapacityError("operation_timeout")
            if write:
                self._begin_immediate(conn, deadline)
            try:
                self._pending_log_lines: list[str] = []
                result = callback(conn)
            except Exception:
                if write:
                    conn.rollback()
                raise
            if write:
                conn.commit()
                self._flush_pending_logs()
            self._chmod_state_files()
            return result
        except sqlite3.DatabaseError as exc:
            raise CapacityError(f"database_error: {exc}") from exc
        except sqlite3.OperationalError as exc:
            raise CapacityError(f"database_error: {exc}") from exc
        except OSError as exc:
            raise CapacityError(f"state_path_error: {exc}") from exc
        finally:
            try:
                conn.close()  # type: ignore[possibly-undefined]
            except Exception:
                pass

    def _prepare_state_dir(self) -> None:
        self._verify_parent_chain()
        self.state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.state_dir.exists() or self.state_dir.is_symlink():
            state = self.state_dir.lstat()
            if stat.S_ISLNK(state.st_mode):
                raise CapacityError("unsafe_state_dir_symlink")
            if not stat.S_ISDIR(state.st_mode):
                raise CapacityError("unsafe_state_dir_type")
            if state.st_uid != os.geteuid():
                raise CapacityError("unsafe_state_dir_owner")
            self._chmod_if_needed(self.state_dir, state.st_mode, 0o700)
        for path in (self.db_path, self.lock_path, self.log_path):
            self._verify_state_file(path, allow_missing=True)
        if not self.db_path.exists():
            flags = os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.db_path, flags, 0o600)
            os.close(descriptor)
        for path in (self.lock_path, self.log_path):
            flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            os.close(descriptor)
            self._verify_state_file(path, allow_missing=False)
            self._chmod_if_needed(path, path.lstat().st_mode, 0o600)
        self._verify_state_file(self.db_path, allow_missing=False)

    def _chmod_state_files(self) -> None:
        for path in self._managed_file_paths():
            if path.exists() or path.is_symlink():
                self._verify_state_file(path, allow_missing=False)
                self._chmod_if_needed(path, path.lstat().st_mode, 0o600)

    def _chmod_if_needed(self, path: Path, current_mode: int, expected_mode: int) -> None:
        if stat.S_IMODE(current_mode) != expected_mode:
            os.chmod(path, expected_mode)

    def _managed_file_paths(self) -> List[Path]:
        return [self.state_dir / name for name in sorted(MANAGED_FILE_NAMES)]

    def _verify_parent_chain(self) -> None:
        try:
            relative = self.state_dir.absolute().relative_to(self.home.absolute())
        except ValueError:
            return
        current = self.home.absolute()
        for part in relative.parts[:-1]:
            current = current / part
            if current.exists() or current.is_symlink():
                state = current.lstat()
                if stat.S_ISLNK(state.st_mode):
                    raise CapacityError("unsafe_state_parent_symlink")

    def _verify_state_file(self, path: Path, *, allow_missing: bool) -> None:
        if not path.exists() and not path.is_symlink():
            if allow_missing:
                return
            raise CapacityError("unsafe_state_file_missing")
        state = path.lstat()
        if stat.S_ISLNK(state.st_mode):
            raise CapacityError("unsafe_state_file_symlink")
        if not stat.S_ISREG(state.st_mode):
            raise CapacityError("unsafe_state_file_type")
        if state.st_nlink != 1:
            raise CapacityError("unsafe_state_file_nlink")
        real_state = os.stat(path)
        if real_state.st_uid != os.geteuid():
            raise CapacityError("unsafe_state_file_owner")

    def _initialize_database(self, conn: sqlite3.Connection, deadline: float) -> None:
        resolved = self.db_path.resolve(strict=False)
        identity = self._database_identity()
        if _INITIALIZED_DATABASES.get(resolved) == identity and self._schema_ready(conn):
            self._chmod_state_files()
            return
        with _INITIALIZE_LOCK:
            identity = self._database_identity()
            if _INITIALIZED_DATABASES.get(resolved) == identity and self._schema_ready(conn):
                self._chmod_state_files()
                return
            if self._schema_ready(conn):
                self._chmod_state_files()
                _INITIALIZED_DATABASES[resolved] = identity
                return
            lock_fd = self._acquire_initialization_lock(deadline)
            try:
                identity = self._database_identity()
                if self._schema_ready(conn):
                    self._chmod_state_files()
                    _INITIALIZED_DATABASES[resolved] = identity
                    return
                self._run_initialization_transaction(conn, deadline)
                self._chmod_state_files()
                _INITIALIZED_DATABASES[resolved] = self._database_identity()
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)

    def _acquire_initialization_lock(self, deadline: float) -> int:
        lock_fd = os.open(self.lock_path, os.O_RDWR)
        delay = 0.001
        while time.monotonic() < deadline:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return lock_fd
            except BlockingIOError:
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
                delay = min(delay * 2, 0.01)
        os.close(lock_fd)
        raise CapacityError("database_error: initialization_lock_timeout")

    def _run_initialization_transaction(self, conn: sqlite3.Connection, deadline: float) -> None:
        last_error: Optional[sqlite3.OperationalError] = None
        delay = 0.001
        while time.monotonic() < deadline:
            try:
                conn.execute("pragma journal_mode = wal")
                self._begin_immediate(conn, deadline)
                try:
                    self._migrate(conn)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                return
            except sqlite3.OperationalError as exc:
                last_error = exc
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
                delay = min(delay * 2, 0.01)
        raise CapacityError(f"database_error: {last_error or 'initialization_timeout'}")

    def _database_identity(self) -> Tuple[int, int]:
        state = os.stat(self.db_path)
        return (int(state.st_dev), int(state.st_ino))

    def _schema_ready(self, conn: sqlite3.Connection) -> bool:
        try:
            version = conn.execute("pragma user_version").fetchone()[0]
            if int(version) != SCHEMA_VERSION:
                return False
            row = conn.execute("select name from sqlite_master where type = 'table' and name = 'leases'").fetchone()
            roots = conn.execute("select name from sqlite_master where type = 'table' and name = 'managed_roots'").fetchone()
            return row is not None and roots is not None
        except sqlite3.DatabaseError:
            return False

    def _begin_immediate(self, conn: sqlite3.Connection, deadline: float) -> None:
        delay = 0.001
        last_error: Optional[sqlite3.OperationalError] = None
        while time.monotonic() < deadline:
            try:
                conn.execute("begin immediate")
                return
            except sqlite3.OperationalError as exc:
                last_error = exc
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
                delay = min(delay * 2, 0.01)
        raise CapacityError(f"database_error: {last_error or 'begin_immediate_timeout'}")

    def _migrate(self, conn: sqlite3.Connection) -> None:
        for statement in INITIAL_SCHEMA_STATEMENTS:
            conn.execute(statement)
        conn.execute("insert or ignore into meta (key, value) values ('next_epoch', '1')")
        conn.execute("insert or ignore into meta (key, value) values ('fair_cursor', '')")
        self._ensure_column(conn, "leases", "cleanup_after", "real")
        self._ensure_column(conn, "tickets", "consumed_at", "real")
        self._ensure_column(conn, "managed_roots", "root_state", "text not null default 'ACTIVE'")
        self._ensure_column(conn, "managed_roots", "cleanup_after", "real")
        conn.execute(f"pragma user_version = {SCHEMA_VERSION}")

    def _register_managed_root(
        self,
        conn: sqlite3.Connection,
        *,
        session_id: str,
        root_identity: tuple[int, str],
        now: float,
    ) -> None:
        root_pid, root_start_marker = root_identity
        conn.execute(
            """
            insert into managed_roots (session_id, root_pid, root_start_marker, created_at, updated_at)
            values (?, ?, ?, ?, ?)
            on conflict(session_id) do update set
              root_pid = excluded.root_pid,
              root_start_marker = excluded.root_start_marker,
              root_state = 'ACTIVE',
              cleanup_after = null,
              updated_at = excluded.updated_at
            """,
            (session_id, root_pid, root_start_marker, now, now),
        )

    def _unregister_managed_root(self, conn: sqlite3.Connection, *, session_id: str) -> int:
        return conn.execute("delete from managed_roots where session_id = ?", (session_id,)).rowcount

    def _unregister_managed_root_if_terminal(self, conn: sqlite3.Connection, *, session_id: str) -> int:
        active_leases = self._count(
            conn,
            f"""
            select count(*) from leases
            where session_id = ? and state in ({placeholders(ACTIVE_LEASE_STATES)})
            """,
            (session_id, *sorted(ACTIVE_LEASE_STATES)),
        )
        live_tickets = self._count(
            conn,
            """
            select count(*) from tickets
            where session_id = ? and state in ('PENDING', 'READY')
            """,
            (session_id,),
        )
        if active_leases or live_tickets:
            return 0
        return self._unregister_managed_root(conn, session_id=session_id)

    def _restore_present_managed_roots(
        self,
        conn: sqlite3.Connection,
        now: float,
        proof: float,
        present_sessions: set[str],
    ) -> int:
        if not present_sessions:
            return 0
        return conn.execute(
            f"""
            update leases
            set state = 'ACTIVE', cleanup_after = null, updated_at = ?
            where session_id in ({placeholders(present_sessions)})
              and state in ('SUSPECT', 'RECOVERING')
              and updated_at <= ?
            """,
            (now, *sorted(present_sessions), proof),
        ).rowcount

    def _restore_present_root_records(
        self,
        conn: sqlite3.Connection,
        now: float,
        proof: float,
        present_sessions: set[str],
    ) -> int:
        if not present_sessions:
            return 0
        return conn.execute(
            f"""
            update managed_roots
            set root_state = 'ACTIVE', cleanup_after = null, updated_at = ?
            where session_id in ({placeholders(present_sessions)})
              and root_state in ('SUSPECT', 'RECOVERING')
              and updated_at <= ?
            """,
            (now, *sorted(present_sessions), proof),
        ).rowcount

    def _advance_missing_managed_roots(
        self,
        conn: sqlite3.Connection,
        now: float,
        proof: float,
        missing_sessions: set[str],
        *,
        from_state: str,
        to_state: str,
        stage_seconds: float,
        require_due: bool = False,
        updated_before: Optional[float] = None,
    ) -> int:
        if not missing_sessions:
            return 0
        due_clause = "and cleanup_after is not null and cleanup_after <= ?" if require_due else ""
        params: tuple[Any, ...] = (to_state, now + stage_seconds, now, *sorted(missing_sessions), from_state, proof)
        if require_due:
            params = (*params, now)
        before_clause = ""
        if updated_before is not None:
            before_clause = "and updated_at < ?"
            params = (*params, updated_before)
        return conn.execute(
            f"""
            update leases
            set state = ?, cleanup_after = ?, updated_at = ?
            where session_id in ({placeholders(missing_sessions)})
              and state = ?
              and updated_at <= ?
              {due_clause}
              {before_clause}
            """,
            params,
        ).rowcount

    def _advance_missing_root_records(
        self,
        conn: sqlite3.Connection,
        now: float,
        proof: float,
        missing_sessions: set[str],
        *,
        from_state: str,
        to_state: str,
        stage_seconds: float,
        require_due: bool = False,
        updated_before: Optional[float] = None,
    ) -> int:
        if not missing_sessions:
            return 0
        due_clause = "and cleanup_after is not null and cleanup_after <= ?" if require_due else ""
        params: tuple[Any, ...] = (to_state, now + stage_seconds, now, *sorted(missing_sessions), from_state, proof)
        if require_due:
            params = (*params, now)
        before_clause = ""
        if updated_before is not None:
            before_clause = "and updated_at < ?"
            params = (*params, updated_before)
        return conn.execute(
            f"""
            update managed_roots
            set root_state = ?, cleanup_after = ?, updated_at = ?
            where session_id in ({placeholders(missing_sessions)})
              and root_state = ?
              and updated_at <= ?
              {due_clause}
              {before_clause}
            """,
            params,
        ).rowcount

    def _release_recovering_missing_roots(
        self,
        conn: sqlite3.Connection,
        now: float,
        proof: float,
        missing_sessions: set[str],
        *,
        updated_before: Optional[float] = None,
    ) -> dict[str, int]:
        if not missing_sessions:
            return {"released_leases": 0, "canceled_tickets": 0, "ready_tickets_canceled": 0}
        before_clause = ""
        params: tuple[Any, ...] = (*sorted(missing_sessions), now, proof)
        if updated_before is not None:
            before_clause = "and updated_at < ?"
            params = (*params, updated_before)
        released_rows = [
            dict(row)
            for row in conn.execute(
                f"""
                select lease_id, session_id
                from leases
                where session_id in ({placeholders(missing_sessions)})
                  and state = 'RECOVERING'
                  and cleanup_after is not null
                  and cleanup_after <= ?
                  and updated_at <= ?
                  {before_clause}
                order by lease_id
                """,
                params,
            )
        ]
        if not released_rows:
            return {"released_leases": 0, "canceled_tickets": 0, "ready_tickets_canceled": 0}
        lease_ids = [str(row["lease_id"]) for row in released_rows]
        sessions = {str(row["session_id"]) for row in released_rows}
        conn.execute(
            f"""
            update leases
            set state = 'RELEASED', released_at = ?, updated_at = ?
            where lease_id in ({placeholders(lease_ids)})
              and state = 'RECOVERING'
            """,
            (now, now, *lease_ids),
        )
        ready_tickets = self._ready_ticket_count_for_sessions_before_proof(conn, sessions, proof)
        canceled = conn.execute(
            f"""
            update tickets
            set state = 'CANCELED', updated_at = ?
            where session_id in ({placeholders(sessions)})
              and state in ('PENDING', 'READY')
              and updated_at <= ?
            """,
            (now, *sorted(sessions), proof),
        ).rowcount
        return {
            "released_leases": len(lease_ids),
            "canceled_tickets": canceled,
            "ready_tickets_canceled": ready_tickets,
        }

    def _cancel_recovering_root_tickets(
        self,
        conn: sqlite3.Connection,
        now: float,
        proof: float,
        missing_sessions: set[str],
        *,
        updated_before: Optional[float] = None,
    ) -> dict[str, int]:
        if not missing_sessions:
            return {"canceled_tickets": 0, "ready_tickets_canceled": 0}
        before_clause = ""
        params: tuple[Any, ...] = (*sorted(missing_sessions), now, proof)
        if updated_before is not None:
            before_clause = "and updated_at < ?"
            params = (*params, updated_before)
        sessions = {
            str(row["session_id"])
            for row in conn.execute(
                f"""
                select session_id
                from managed_roots
                where session_id in ({placeholders(missing_sessions)})
                  and root_state = 'RECOVERING'
                  and cleanup_after is not null
                  and cleanup_after <= ?
                  and updated_at <= ?
                  {before_clause}
                order by session_id
                """,
                params,
            )
        }
        if not sessions:
            return {"canceled_tickets": 0, "ready_tickets_canceled": 0}
        ready_tickets = self._ready_ticket_count_for_sessions_before_proof(conn, sessions, proof)
        canceled = conn.execute(
            f"""
            update tickets
            set state = 'CANCELED', updated_at = ?
            where session_id in ({placeholders(sessions)})
              and state in ('PENDING', 'READY')
              and updated_at <= ?
            """,
            (now, *sorted(sessions), proof),
        ).rowcount
        return {"canceled_tickets": canceled, "ready_tickets_canceled": ready_tickets}

    def _ready_ticket_count_for_sessions_before_proof(
        self,
        conn: sqlite3.Connection,
        sessions: set[str],
        proof: float,
    ) -> int:
        if not sessions:
            return 0
        return self._count(
            conn,
            f"""
            select count(*) from tickets
            where session_id in ({placeholders(sessions)})
              and state = 'READY'
              and consumed_at is null
              and updated_at <= ?
            """,
            (*sorted(sessions), proof),
        )

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        columns = {row["name"] for row in conn.execute(f"pragma table_info({table})")}
        if column not in columns:
            conn.execute(f"alter table {table} add column {column} {declaration}")

    def _existing_request_result(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        now: float,
        *,
        wave_limit: Optional[int],
    ) -> dict[str, Any]:
        if row["lease_id"]:
            lease = self._lease_by_id(conn, row["lease_id"])
            if lease and lease["state"] != "RELEASED":
                return self._lease_result_from_row(lease)
        if row["ticket_id"]:
            ticket = conn.execute(
                "select * from tickets where ticket_id = ?",
                (row["ticket_id"],),
            ).fetchone()
            if ticket and ticket["state"] == "READY":
                if self._active_lease_count(conn) >= self.capacity:
                    conn.execute(
                        """
                        update tickets
                        set state = 'PENDING', ready_at = null, updated_at = ?
                        where ticket_id = ? and state = 'READY'
                        """,
                        (now, ticket["ticket_id"]),
                    )
                    self._log(conn, now, "ready-requeued", request_id=row["request_id"], ticket_id=ticket["ticket_id"])
                    return self._ticket_result_from_row(conn, self._ticket_by_id(conn, ticket["ticket_id"]))
                lease_id, epoch = self._create_lease(
                    conn,
                    row["request_id"],
                    ticket["session_id"],
                    ticket["turn_id"],
                    now,
                    ticket_id=ticket["ticket_id"],
                )
                conn.execute(
                    "update tickets set consumed_at = ?, updated_at = ? where ticket_id = ? and state = 'READY'",
                    (now, now, ticket["ticket_id"]),
                )
                self._log(conn, now, "consume-ready", request_id=row["request_id"], lease_id=lease_id)
                return lease_result(row["request_id"], lease_id, epoch, "PROVISIONAL")
            if ticket:
                return self._ticket_result_from_row(conn, ticket)
        if (
            self._reserved_count(conn) < self.capacity
            and self._waiting_ticket_count(conn) == 0
            and self._wave_reserved_count(conn, session_id=row["session_id"], turn_id=row["turn_id"]) < self._normalized_wave_limit(wave_limit)
        ):
            lease_id, epoch = self._create_lease(
                conn,
                row["request_id"],
                row["session_id"],
                row["turn_id"],
                now,
                ticket_id=None,
            )
            self._log(conn, now, "reacquire", request_id=row["request_id"], lease_id=lease_id)
            return lease_result(row["request_id"], lease_id, epoch, "PROVISIONAL")
        ticket_id = self._create_ticket(conn, row["request_id"], row["session_id"], row["turn_id"], now, "PENDING")
        self._log(conn, now, "requeue-released", request_id=row["request_id"], ticket_id=ticket_id)
        return self._ticket_result_from_row(conn, self._ticket_by_id(conn, ticket_id))

    def _promote_pending(self, conn: sqlite3.Connection, now: float, *, limit: Optional[int] = None) -> None:
        available = max(0, self.capacity - self._reserved_count(conn))
        if limit is not None:
            available = min(available, max(0, limit))
        for _ in range(available):
            ticket = self._next_pending_ticket(conn)
            if ticket is None:
                return
            conn.execute(
                "update tickets set state = 'READY', ready_at = ?, updated_at = ? where ticket_id = ? and state = 'PENDING'",
                (now, now, ticket["ticket_id"]),
            )
            conn.execute("update meta set value = ? where key = 'fair_cursor'", (ticket["session_id"],))
            self._log(conn, now, "ready", ticket_id=ticket["ticket_id"], session_id=ticket["session_id"])

    def _next_pending_ticket(self, conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
        sessions = [
            row["session_id"]
            for row in conn.execute(
                """
                select session_id, min(created_at) as first_created
                from tickets
                where state = 'PENDING'
                group by session_id
                order by first_created, session_id
                """
            )
        ]
        if not sessions:
            return None
        cursor = self._meta(conn, "fair_cursor")
        if cursor in sessions:
            index = sessions.index(cursor) + 1
            sessions = sessions[index:] + sessions[:index]
        session_id = sessions[0]
        return conn.execute(
            """
            select * from tickets
            where state = 'PENDING' and session_id = ?
            order by created_at, ticket_id
            limit 1
            """,
            (session_id,),
        ).fetchone()

    def _create_ticket(
        self,
        conn: sqlite3.Connection,
        request_id: str,
        session_id: str,
        turn_id: str,
        now: float,
        state: str,
    ) -> str:
        ticket_id = uuid.uuid4().hex
        conn.execute(
            """
            insert into tickets (ticket_id, request_id, session_id, turn_id, state, created_at, ready_at, consumed_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?, null, ?)
            """,
            (ticket_id, request_id, session_id, turn_id, state, now, now if state == "READY" else None, now),
        )
        conn.execute(
            "update requests set ticket_id = ?, updated_at = ? where request_id = ?",
            (ticket_id, now, request_id),
        )
        return ticket_id

    def _create_lease(
        self,
        conn: sqlite3.Connection,
        request_id: str,
        session_id: str,
        turn_id: str,
        now: float,
        *,
        ticket_id: Optional[str],
    ) -> tuple[str, int]:
        lease_id = uuid.uuid4().hex
        epoch = int(self._meta(conn, "next_epoch"))
        conn.execute("update meta set value = ? where key = 'next_epoch'", (str(epoch + 1),))
        conn.execute(
            """
            insert into leases
              (lease_id, request_id, ticket_id, session_id, turn_id, state, fencing_epoch, created_at, updated_at)
            values (?, ?, ?, ?, ?, 'PROVISIONAL', ?, ?, ?)
            """,
            (lease_id, request_id, ticket_id, session_id, turn_id, epoch, now, now),
        )
        conn.execute(
            "update requests set lease_id = ?, updated_at = ? where request_id = ?",
            (lease_id, now, request_id),
        )
        return lease_id, epoch

    def _reserved_count(self, conn: sqlite3.Connection) -> int:
        return self._active_lease_count(conn) + self._ready_ticket_count(conn)

    def _ready_ticket_count(self, conn: sqlite3.Connection) -> int:
        return self._count(conn, "select count(*) from tickets where state = 'READY' and consumed_at is null")

    def _waiting_ticket_count(self, conn: sqlite3.Connection) -> int:
        return self._count(
            conn,
            """
            select count(*) from tickets
            where state = 'PENDING' or (state = 'READY' and consumed_at is null)
            """,
        )

    def _wave_reserved_count(self, conn: sqlite3.Connection, *, session_id: str, turn_id: str) -> int:
        leases = self._count(
            conn,
            f"""
            select count(*) from leases
            where session_id = ? and turn_id = ? and state in ({placeholders(ACTIVE_LEASE_STATES)})
            """,
            (session_id, turn_id, *sorted(ACTIVE_LEASE_STATES)),
        )
        ready = self._count(
            conn,
            """
            select count(*) from tickets
            where session_id = ? and turn_id = ? and state = 'READY' and consumed_at is null
            """,
            (session_id, turn_id),
        )
        return leases + ready

    def _normalized_wave_limit(self, wave_limit: Optional[int]) -> int:
        if wave_limit is None:
            return MAX_CAPACITY
        return max(0, min(MAX_CAPACITY, int(wave_limit)))

    def _active_lease_count(self, conn: sqlite3.Connection) -> int:
        return self._count(
            conn,
            f"select count(*) from leases where state in ({placeholders(ACTIVE_LEASE_STATES)})",
            tuple(sorted(ACTIVE_LEASE_STATES)),
        )

    def _managed_root_count(self, conn: sqlite3.Connection) -> int:
        return self._count(
            conn,
            "select count(*) from (select 1 from managed_roots group by root_pid, root_start_marker)",
        )

    def _managed_root_session_count(self, conn: sqlite3.Connection) -> int:
        return self._count(conn, "select count(*) from managed_roots")

    def _request_row(self, conn: sqlite3.Connection, request_id: str) -> Optional[sqlite3.Row]:
        return conn.execute("select * from requests where request_id = ?", (request_id,)).fetchone()

    def _lease_by_id(self, conn: sqlite3.Connection, lease_id: str) -> Optional[sqlite3.Row]:
        return conn.execute("select * from leases where lease_id = ?", (lease_id,)).fetchone()

    def _ticket_by_id(self, conn: sqlite3.Connection, ticket_id: str) -> Optional[sqlite3.Row]:
        return conn.execute("select * from tickets where ticket_id = ?", (ticket_id,)).fetchone()

    def _ticket_result_from_row(self, conn: sqlite3.Connection, row: Optional[sqlite3.Row]) -> dict[str, Any]:
        if row is None:
            return {"state": "ERROR", "reason": "ticket_not_found"}
        state = str(row["state"])
        result = {
            "state": "CAPACITY_QUEUED" if state == "PENDING" else state,
            "request_id": row["request_id"],
            "ticket_id": row["ticket_id"],
            "ticket_state": state,
            "session_id": row["session_id"],
            "turn_id": row["turn_id"],
        }
        if state == "PENDING":
            result["ticket_position"] = self._count(
                conn,
                """
                select count(*) from tickets
                where state = 'PENDING' and (created_at < ? or (created_at = ? and ticket_id <= ?))
                """,
                (row["created_at"], row["created_at"], row["ticket_id"]),
            )
            result["retry_delay_ms"] = DEFAULT_RETRY_DELAY_MS
            result["wait_command"] = self._wait_command(row["ticket_id"])
        return result

    def _wait_command(self, ticket_id: str) -> str:
        return shlex.join(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--state-dir",
                str(self.state_dir),
                "wait",
                "--ticket-id",
                ticket_id,
            ]
        )

    def _recover_cleanup_lease(
        self,
        conn: sqlite3.Connection,
        now: float,
        *,
        lease_id: str,
        fencing_epoch: int,
    ) -> dict[str, Any]:
        row = self._lease_by_id(conn, lease_id)
        if row is None:
            return {"state": "STALE", "reason": "lease_not_found", "lease_id": lease_id}
        if int(row["fencing_epoch"]) != int(fencing_epoch):
            return {"state": "STALE", "reason": "fencing_epoch_mismatch", "lease_id": lease_id}
        if row["state"] != "CLEANUP_REQUIRED":
            return self._lease_result_from_row(row, state="STALE", reason="not_cleanup_required")
        conn.execute(
            """
            update leases
            set state = 'RELEASED', released_at = ?, updated_at = ?
            where lease_id = ? and fencing_epoch = ? and state = 'CLEANUP_REQUIRED'
            """,
            (now, now, lease_id, fencing_epoch),
        )
        self._log(conn, now, "recover", lease_id=lease_id)
        return self._lease_result_from_row(self._lease_by_id(conn, lease_id))

    def _expire_cleanup_leases(self, conn: sqlite3.Connection, now: float) -> int:
        return conn.execute(
            """
            update leases
            set state = 'RELEASED', released_at = ?, updated_at = ?
            where state = 'CLEANUP_REQUIRED' and cleanup_after is not null and cleanup_after <= ?
            """,
            (now, now, now),
        ).rowcount

    def _expire_unbound_provisional_leases(self, conn: sqlite3.Connection, now: float) -> int:
        cutoff = now - self.provisional_ttl_seconds
        return conn.execute(
            """
            update leases
            set state = 'RELEASED', released_at = ?, updated_at = ?
            where state = 'PROVISIONAL' and agent_id is null and created_at <= ?
            """,
            (now, now, cutoff),
        ).rowcount

    def _expire_stale_leases(self, conn: sqlite3.Connection, now: float) -> int:
        return (
            self._expire_cleanup_leases(conn, now)
            + self._expire_unbound_provisional_leases(conn, now)
        )

    def _lease_result_from_row(
        self,
        row: Optional[sqlite3.Row],
        *,
        state: str = "LEASED",
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        if row is None:
            return {"state": "ERROR", "reason": "lease_not_found"}
        result = lease_result(row["request_id"], row["lease_id"], int(row["fencing_epoch"]), row["state"])
        result["state"] = state
        if reason:
            result["reason"] = reason
        return result

    def _count(self, conn: sqlite3.Connection, query: str, params: Iterable[Any] = ()) -> int:
        row = conn.execute(query, tuple(params)).fetchone()
        return int(row[0])

    def _meta(self, conn: sqlite3.Connection, key: str) -> str:
        row = conn.execute("select value from meta where key = ?", (key,)).fetchone()
        if row is None:
            raise CapacityError(f"missing_meta_{key}")
        return str(row["value"])

    def _log(self, conn: sqlite3.Connection, now: float, event: str, **payload: Any) -> None:
        del conn
        line = json.dumps({"created_at": now, "event": event, **payload}, sort_keys=True) + "\n"
        if hasattr(self, "_pending_log_lines"):
            self._pending_log_lines.append(line)
        else:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)

    def _flush_pending_logs(self) -> None:
        lines = getattr(self, "_pending_log_lines", [])
        if not lines:
            return
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.writelines(lines)
        self._pending_log_lines = []


def request_hash(session_id: str, turn_id: str, task_name: str) -> str:
    payload = [
        ["session_id", len(session_id), session_id],
        ["turn_id", len(turn_id), turn_id],
        ["task_name", len(task_name), task_name],
    ]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_root_identity(root_pid: Optional[int], root_start_marker: Optional[str]) -> Optional[tuple[int, str]]:
    if root_pid is None or root_start_marker in (None, ""):
        return None
    try:
        pid = int(root_pid)
    except (TypeError, ValueError):
        return None
    marker = str(root_start_marker).strip()
    if pid <= 0 or not marker:
        return None
    return pid, marker


def normalize_root_identity_set_strict(values: Iterable[tuple[int, str]]) -> set[tuple[int, str]]:
    identities: set[tuple[int, str]] = set()
    for value in values:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise CapacityError("invalid_root_identity_proof")
        identity = normalize_root_identity(value[0], value[1])
        if identity is None:
            raise CapacityError("invalid_root_identity_proof")
        identities.add(identity)
    return identities


def normalize_proof_started_at(value: float) -> float:
    try:
        proof = float(value)
    except (TypeError, ValueError) as exc:
        raise CapacityError("invalid_root_identity_proof") from exc
    if not math.isfinite(proof) or proof < 0:
        raise CapacityError("invalid_root_identity_proof")
    return proof


def current_time() -> float:
    return time.time()


def operation_budget_seconds(value: Optional[float]) -> float:
    if value is not None:
        return float(value)
    raw = os.environ.get(OPERATION_BUDGET_ENV)
    if raw is None or raw == "":
        return MAX_OPERATION_SECONDS
    try:
        return float(raw)
    except ValueError as exc:
        raise CapacityError("invalid_operation_budget: must be numeric") from exc


def placeholders(values: Iterable[Any]) -> str:
    items = list(values)
    if not items:
        return "null"
    return ", ".join("?" for _ in items)


def lease_result(request_id: str, lease_id: str, fencing_epoch: int, lease_state: str) -> dict[str, Any]:
    return {
        "state": "LEASED",
        "request_id": request_id,
        "lease_id": lease_id,
        "fencing_epoch": fencing_epoch,
        "lease_state": lease_state,
    }


def ticket_result(request_id: str, ticket_id: str, session_id: str, turn_id: str, ticket_state: str) -> dict[str, Any]:
    return {
        "state": "QUEUED" if ticket_state == "PENDING" else ticket_state,
        "request_id": request_id,
        "ticket_id": ticket_id,
        "ticket_state": ticket_state,
        "session_id": session_id,
        "turn_id": turn_id,
    }


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise CapacityError("snapshot_json_must_be_object")
    return payload


def default_manifest_validator() -> Path:
    return Path(__file__).resolve().parent / "validate_wide_wave_manifest.py"


def test_mode_enabled() -> bool:
    return os.environ.get("CODEX_CAPACITY_TEST_MODE") == "1"


def default_trusted_registry() -> Path:
    codex_home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").expanduser()
    installed = codex_home / "config" / "trusted-wide-wave-skills.json"
    if installed.is_file():
        return installed
    return Path(__file__).resolve().parents[1] / "config" / "trusted-wide-wave-skills.json"


def validator_reasons(output: str) -> list[str]:
    for line in output.splitlines():
        if line.startswith("reasons="):
            raw = line.split("=", 1)[1]
            if raw == "none" or not raw:
                return []
            return [item for item in raw.split(",") if item]
    return []


def validate_wide_wave_trust(
    *,
    requested_wave_size: int,
    skill_id: Optional[str],
    skill_file: Optional[Path],
    manifest: Optional[Path],
    trusted_registry: Optional[Path],
    manifest_validator: Optional[Path],
) -> dict[str, Any]:
    supplied = [skill_id, skill_file, manifest, trusted_registry]
    if not any(supplied):
        return {"trusted": False, "reason": "wide_wave_trust_not_requested", "validator_reasons": []}
    if not skill_id or skill_file is None or manifest is None:
        return {"trusted": False, "reason": "wide_wave_requires_trust_manifest", "validator_reasons": []}
    if not test_mode_enabled() and (trusted_registry is not None or manifest_validator is not None):
        return {"trusted": False, "reason": "wide_wave_trust_override_forbidden", "validator_reasons": []}
    registry = trusted_registry if test_mode_enabled() and trusted_registry is not None else default_trusted_registry()
    validator = manifest_validator if test_mode_enabled() and manifest_validator is not None else default_manifest_validator()
    if not validator.is_file():
        return {"trusted": False, "reason": "wide_wave_manifest_validator_missing", "validator_reasons": []}
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(validator),
                "--manifest",
                str(manifest),
                "--skill-id",
                skill_id,
                "--skill-file",
                str(skill_file),
                "--trusted-registry",
                str(registry),
                "--expected-wave-size",
                str(requested_wave_size),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=MAX_OPERATION_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"trusted": False, "reason": "wide_wave_manifest_validator_timeout", "validator_reasons": []}
    reasons = validator_reasons(completed.stdout)
    if completed.returncode != 0:
        return {"trusted": False, "reason": "wide_wave_manifest_untrusted", "validator_reasons": reasons}
    return {"trusted": True, "reason": "wide_wave_manifest_trusted", "validator_reasons": reasons}


def net_observer_admission(
    *,
    observation: dict[str, Any],
    capacity_cap: int,
    external_roots: int,
) -> int:
    admission = max(0, min(MAX_CAPACITY, int(observation.get("admission_capacity") or 0)))
    capped_admission = min(admission, int(capacity_cap))
    return max(0, capped_admission - external_roots)


def prepare_wave(
    store: CapacityStore,
    *,
    requested_wave_size: int,
    observer_snapshot_json: Optional[Path] = None,
    observer_state_dir: Optional[Path] = None,
    workload_class: str = "normal",
    wide_wave_skill_id: Optional[str] = None,
    wide_wave_skill_file: Optional[Path] = None,
    wide_wave_manifest: Optional[Path] = None,
    wide_wave_trusted_registry: Optional[Path] = None,
    wide_wave_manifest_validator: Optional[Path] = None,
) -> dict[str, Any]:
    if requested_wave_size < 0 or requested_wave_size > MAX_CAPACITY:
        return {"state": "ERROR", "reason": f"invalid_wave_size: must be in 0..{MAX_CAPACITY}"}

    from codex_capacity_observer import observe  # Imported lazily to keep the hot queue path small.

    snapshot_result = store.snapshot()
    if snapshot_result.get("state") == "ERROR":
        return snapshot_result
    managed_active = int(snapshot_result.get("active_count") or 0)
    managed_reserved = int(snapshot_result.get("reserved_count") or managed_active)
    managed_slots = max(managed_active, managed_reserved)
    snapshot = load_json_object(observer_snapshot_json) if observer_snapshot_json else None
    if snapshot is not None:
        snapshot["active_slots"] = managed_slots
    observation = observe(
        snapshot=snapshot,
        state_dir=observer_state_dir or store.state_dir,
        workload_class=workload_class,
        active_slots=managed_slots,
        managed_root_identities=store.managed_root_identities(),
    )
    measurements = observation.get("measurements") if isinstance(observation.get("measurements"), dict) else {}
    external_roots = max(0, int(float(measurements.get("external_codex_roots") or 0)))
    observer_admission_capacity = int(observation.get("admission_capacity") or 0)
    mode = str(observation.get("capacity_mode") or "")
    status = str(observation.get("status") or "RED")
    trust = validate_wide_wave_trust(
        requested_wave_size=requested_wave_size,
        skill_id=wide_wave_skill_id,
        skill_file=wide_wave_skill_file,
        manifest=wide_wave_manifest,
        trusted_registry=wide_wave_trusted_registry,
        manifest_validator=wide_wave_manifest_validator,
    )
    partial_trust = any([wide_wave_skill_id, wide_wave_skill_file, wide_wave_manifest, wide_wave_trusted_registry]) and not trust["trusted"]
    if status == "RED":
        max_wave_size = 0
        available_capacity = 0
    elif status == "YELLOW":
        admission_capacity = net_observer_admission(
            observation=observation,
            capacity_cap=DEFAULT_CAPACITY,
            external_roots=external_roots,
        )
        max_wave_size = min(2, int(observation.get("max_wave_size") or 0), DEFAULT_CAPACITY, admission_capacity)
        available_capacity = admission_capacity
    else:
        trust_cap = MAX_CAPACITY if trust["trusted"] else DEFAULT_CAPACITY
        admission_capacity = net_observer_admission(
            observation=observation,
            capacity_cap=trust_cap,
            external_roots=external_roots,
        )
        max_wave_size = min(int(observation.get("max_wave_size") or 0), trust_cap, admission_capacity)
        available_capacity = admission_capacity
    if requested_wave_size > DEFAULT_CAPACITY and partial_trust:
        allowed = 0
    else:
        allowed = max(0, min(requested_wave_size, max_wave_size, available_capacity))
    decision = "ALLOW" if allowed == requested_wave_size and status == "GREEN" else "DEGRADED" if allowed > 0 else "BLOCK"
    return {
        "state": "OK",
        "decision": decision,
        "requested_wave_size": requested_wave_size,
        "allowed_wave_size": allowed,
        "observer_status": status,
        "observer_reasons": observation.get("reasons") or [],
        "capacity_mode": mode,
        "admission_capacity": observer_admission_capacity,
        "max_wave_size": max_wave_size,
        "external_codex_roots": external_roots,
        "managed_active_count": managed_active,
        "managed_reserved_count": managed_reserved,
        "wide_wave_trusted": bool(trust["trusted"]),
        "wide_wave_trust_reason": trust["reason"],
        "wide_wave_validator_reasons": trust["validator_reasons"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--capacity", type=int, default=None, dest="global_capacity")
    parser.add_argument("--max-operation-seconds", type=float, default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    acquire = sub.add_parser("acquire-or-queue")
    add_request_arguments(acquire)
    add_capacity_argument(acquire)

    activate = sub.add_parser("activate")
    activate.add_argument("--lease-id", required=True)
    activate.add_argument("--fencing-epoch", required=True, type=int)
    activate.add_argument("--agent-id")
    add_capacity_argument(activate)

    activate_next = sub.add_parser("activate-next")
    activate_next.add_argument("--session-id", required=True)
    activate_next.add_argument("--turn-id", required=True)
    activate_next.add_argument("--agent-id", required=True)
    add_capacity_argument(activate_next)

    release = sub.add_parser("release")
    release.add_argument("--lease-id", required=True)
    release.add_argument("--fencing-epoch", required=True, type=int)
    add_capacity_argument(release)

    release_agent = sub.add_parser("release-agent")
    release_agent.add_argument("--session-id", required=True)
    release_agent.add_argument("--agent-id", required=True)
    add_capacity_argument(release_agent)

    release_request = sub.add_parser("release-request")
    release_request.add_argument("--request-id", required=True)
    release_request.add_argument("--expected-state", default="PROVISIONAL")
    add_capacity_argument(release_request)

    recover = sub.add_parser("recover")
    recover.add_argument("--lease-id", required=True)
    recover.add_argument("--fencing-epoch", required=True, type=int)
    add_capacity_argument(recover)

    cancel_turn = sub.add_parser("cancel-turn")
    cancel_turn.add_argument("--session-id", required=True)
    cancel_turn.add_argument("--turn-id", required=True)
    add_capacity_argument(cancel_turn)

    cancel_session = sub.add_parser("cancel-session")
    cancel_session.add_argument("--session-id", required=True)
    add_capacity_argument(cancel_session)

    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument("--session-id")
    reconcile.add_argument("--lease-id")
    reconcile.add_argument("--fencing-epoch", type=int)
    add_capacity_argument(reconcile)

    wait = sub.add_parser("wait")
    wait.add_argument("--ticket-id", required=True)
    add_capacity_argument(wait)

    snapshot = sub.add_parser("snapshot")
    add_capacity_argument(snapshot)

    prepare = sub.add_parser("prepare-wave")
    prepare.add_argument("--wave-size", "--requested-size", required=True, type=int)
    prepare.add_argument("--observer-snapshot-json", type=Path)
    prepare.add_argument("--observer-state-dir", type=Path)
    prepare.add_argument("--workload-class", default="normal")
    prepare.add_argument("--wide-wave-skill-id")
    prepare.add_argument("--wide-wave-skill-file", type=Path)
    prepare.add_argument("--wide-wave-manifest", type=Path)
    prepare.add_argument("--wide-wave-trusted-registry", type=Path)
    prepare.add_argument("--wide-wave-manifest-validator", type=Path)
    add_capacity_argument(prepare)
    return parser


def add_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--turn-id", required=True)
    parser.add_argument("--task-name", required=True)
    parser.add_argument("--root-pid", type=int)
    parser.add_argument("--root-start-marker")


def add_capacity_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--capacity", type=int, default=None, dest="local_capacity")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    capacity = args.local_capacity if args.local_capacity is not None else args.global_capacity
    if capacity is None:
        capacity = DEFAULT_CAPACITY
    try:
        store = CapacityStore(state_dir=args.state_dir, capacity=capacity, max_operation_seconds=args.max_operation_seconds)
        if args.command == "acquire-or-queue":
            result = store.acquire_or_queue(
                session_id=args.session_id,
                turn_id=args.turn_id,
                task_name=args.task_name,
                root_pid=args.root_pid,
                root_start_marker=args.root_start_marker,
            )
            print_json(result)
            return exit_for_result(result)
        if args.command == "activate":
            result = store.activate(lease_id=args.lease_id, fencing_epoch=args.fencing_epoch, agent_id=args.agent_id)
            print_json(result)
            return exit_for_result(result)
        if args.command == "activate-next":
            result = store.activate_next(session_id=args.session_id, turn_id=args.turn_id, agent_id=args.agent_id)
            print_json(result)
            return exit_for_result(result)
        if args.command == "release":
            result = store.release(lease_id=args.lease_id, fencing_epoch=args.fencing_epoch)
            print_json(result)
            return exit_for_result(result)
        if args.command == "release-agent":
            result = store.release_agent(session_id=args.session_id, agent_id=args.agent_id)
            print_json(result)
            return exit_for_result(result)
        if args.command == "release-request":
            result = store.release_request(args.request_id, expected_state=args.expected_state)
            print_json(result)
            return exit_for_result(result)
        if args.command == "recover":
            result = store.recover(lease_id=args.lease_id, fencing_epoch=args.fencing_epoch)
            print_json(result)
            return exit_for_result(result)
        if args.command == "cancel-turn":
            result = store.cancel_turn(session_id=args.session_id, turn_id=args.turn_id)
            print_json(result)
            return exit_for_result(result)
        if args.command == "cancel-session":
            result = store.cancel_session(session_id=args.session_id)
            print_json(result)
            return exit_for_result(result)
        if args.command == "reconcile":
            result = store.reconcile(
                session_id=args.session_id,
                lease_id=args.lease_id,
                fencing_epoch=args.fencing_epoch,
            )
            print_json(result)
            return exit_for_result(result)
        if args.command == "wait":
            result = store.wait(args.ticket_id)
            print_json(result)
            if result.get("ticket_state") == "READY":
                return 0
            if result.get("ticket_state") == "PENDING":
                return 75
            return 1
        if args.command == "snapshot":
            result = store.snapshot()
            print_json(result)
            return exit_for_result(result)
        if args.command == "prepare-wave":
            result = prepare_wave(
                store,
                requested_wave_size=args.wave_size,
                observer_snapshot_json=args.observer_snapshot_json,
                observer_state_dir=args.observer_state_dir,
                workload_class=args.workload_class,
                wide_wave_skill_id=args.wide_wave_skill_id,
                wide_wave_skill_file=args.wide_wave_skill_file,
                wide_wave_manifest=args.wide_wave_manifest,
                wide_wave_trusted_registry=args.wide_wave_trusted_registry,
                wide_wave_manifest_validator=args.wide_wave_manifest_validator,
            )
            print_json(result)
            return exit_for_result(result)
    except CapacityError as exc:
        print_json({"state": "ERROR", "reason": exc.reason})
        return exc.exit_code
    raise AssertionError(args.command)


def exit_for_result(result: dict[str, Any]) -> int:
    return 1 if result.get("state") == "ERROR" else 0


if __name__ == "__main__":
    sys.exit(main())
