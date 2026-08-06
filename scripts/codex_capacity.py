#!/usr/bin/env python3
"""Shared user-level Codex subagent capacity queue."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shlex
import sqlite3
import stat
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


DEFAULT_CAPACITY = 6
MAX_CAPACITY = 20
MAX_OPERATION_SECONDS = 0.45
SQLITE_BUSY_TIMEOUT_MS = 20
DEFAULT_RETRY_DELAY_MS = 250
CLEANUP_TTL_SECONDS = 30
MAX_PENDING_PER_SESSION = 20
MAX_PENDING_PER_USER = 512
ACTIVE_LEASE_STATES = {"PROVISIONAL", "ACTIVE", "SUSPECT", "RECOVERING", "CLEANUP_REQUIRED"}
TERMINAL_LEASE_STATES = {"RELEASED"}
MANAGED_FILE_NAMES = {"capacity.sqlite3", "capacity.sqlite3-wal", "capacity.sqlite3-shm", "capacity.lock", "events.jsonl"}
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
    ) -> None:
        self.home = Path(home or Path.home()).expanduser()
        self.state_dir = Path(state_dir or self.home / ".local" / "state" / "codex-capacity-v1").expanduser()
        self.db_path = self.state_dir / "capacity.sqlite3"
        self.lock_path = self.state_dir / "capacity.lock"
        self.log_path = self.state_dir / "events.jsonl"
        self.capacity = int(capacity)
        self.cleanup_ttl_seconds = max(0.0, float(cleanup_ttl_seconds))
        self.invalid_reason = None
        if self.capacity < 0 or self.capacity > MAX_CAPACITY:
            self.invalid_reason = f"invalid_capacity: capacity must be between 0 and {MAX_CAPACITY}"

    def acquire_or_queue(self, *, session_id: str, turn_id: str, task_name: str) -> dict[str, Any]:
        request_id = request_hash(session_id, turn_id, task_name)
        now = current_time()

        def work(conn: sqlite3.Connection) -> dict[str, Any]:
            released = self._expire_cleanup_leases(conn, now)
            if released:
                self._promote_pending(conn, now, limit=released)
            existing = self._request_row(conn, request_id)
            if existing:
                return self._existing_request_result(conn, existing, now)
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
            if self._reserved_count(conn) < self.capacity and self._waiting_ticket_count(conn) == 0:
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
            if ready_canceled:
                self._promote_pending(conn, now, limit=ready_canceled)
            self._log(conn, now, "cancel-session", session_id=session_id, tickets=tickets, leases=leases)
            return {
                "state": "OK",
                "session_id": session_id,
                "canceled_tickets": tickets,
                "ready_canceled": ready_canceled,
                "leases_marked": leases,
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
            ttl_released = self._expire_cleanup_leases(conn, now)
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
                "leases": leases,
                "tickets": tickets,
            }

        return self._read(work)

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
        deadline = time.monotonic() + MAX_OPERATION_SECONDS
        try:
            if self.invalid_reason:
                raise CapacityError(self.invalid_reason)
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
                result = callback(conn)
            except Exception:
                if write:
                    conn.rollback()
                raise
            if write:
                conn.commit()
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
        os.chmod(self.state_dir, 0o700)
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
            os.chmod(path, 0o600)
            self._verify_state_file(path, allow_missing=False)
        self._verify_state_file(self.db_path, allow_missing=False)

    def _chmod_state_files(self) -> None:
        for path in self._managed_file_paths():
            if path.exists() or path.is_symlink():
                self._verify_state_file(path, allow_missing=False)
                os.chmod(path, 0o600)

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
        delay = 0.005
        while time.monotonic() < deadline:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return lock_fd
            except BlockingIOError:
                time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
                delay = min(delay * 2, 0.04)
        os.close(lock_fd)
        raise CapacityError("database_error: initialization_lock_timeout")

    def _run_initialization_transaction(self, conn: sqlite3.Connection, deadline: float) -> None:
        last_error: Optional[sqlite3.OperationalError] = None
        delay = 0.005
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
                delay = min(delay * 2, 0.04)
        raise CapacityError(f"database_error: {last_error or 'initialization_timeout'}")

    def _database_identity(self) -> Tuple[int, int]:
        state = os.stat(self.db_path)
        return (int(state.st_dev), int(state.st_ino))

    def _schema_ready(self, conn: sqlite3.Connection) -> bool:
        try:
            version = conn.execute("pragma user_version").fetchone()[0]
            if int(version) != 1:
                return False
            row = conn.execute("select name from sqlite_master where type = 'table' and name = 'leases'").fetchone()
            return row is not None
        except sqlite3.DatabaseError:
            return False

    def _begin_immediate(self, conn: sqlite3.Connection, deadline: float) -> None:
        delay = 0.005
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
                delay = min(delay * 2, 0.04)
        raise CapacityError(f"database_error: {last_error or 'begin_immediate_timeout'}")

    def _migrate(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            create table if not exists meta (
              key text primary key,
              value text not null
            );
            create table if not exists requests (
              request_id text primary key,
              session_id text not null,
              turn_id text not null,
              ticket_id text,
              lease_id text,
              created_at real not null,
              updated_at real not null
            );
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
            );
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
            );
            create unique index if not exists leases_active_request
              on leases(request_id)
              where state != 'RELEASED';
            create table if not exists events (
              id integer primary key autoincrement,
              created_at real not null,
              event text not null,
              payload_json text not null
            );
            """
        )
        conn.execute("insert or ignore into meta (key, value) values ('next_epoch', '1')")
        conn.execute("insert or ignore into meta (key, value) values ('fair_cursor', '')")
        self._ensure_column(conn, "leases", "cleanup_after", "real")
        self._ensure_column(conn, "tickets", "consumed_at", "real")
        conn.execute("pragma user_version = 1")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        columns = {row["name"] for row in conn.execute(f"pragma table_info({table})")}
        if column not in columns:
            conn.execute(f"alter table {table} add column {column} {declaration}")

    def _existing_request_result(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        now: float,
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
        return {"state": "ERROR", "reason": "request_without_ticket_or_lease", "request_id": row["request_id"]}

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

    def _active_lease_count(self, conn: sqlite3.Connection) -> int:
        return self._count(
            conn,
            f"select count(*) from leases where state in ({placeholders(ACTIVE_LEASE_STATES)})",
            tuple(sorted(ACTIVE_LEASE_STATES)),
        )

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
        conn.execute(
            "insert into events (created_at, event, payload_json) values (?, ?, ?)",
            (now, event, json.dumps(payload, sort_keys=True, separators=(",", ":"))),
        )
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"created_at": now, "event": event, **payload}, sort_keys=True) + "\n")


def request_hash(session_id: str, turn_id: str, task_name: str) -> str:
    payload = [
        ["session_id", len(session_id), session_id],
        ["turn_id", len(turn_id), turn_id],
        ["task_name", len(task_name), task_name],
    ]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def current_time() -> float:
    return time.time()


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--capacity", type=int, default=None, dest="global_capacity")
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
    return parser


def add_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--turn-id", required=True)
    parser.add_argument("--task-name", required=True)


def add_capacity_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--capacity", type=int, default=None, dest="local_capacity")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    capacity = args.local_capacity if args.local_capacity is not None else args.global_capacity
    if capacity is None:
        capacity = DEFAULT_CAPACITY
    store = CapacityStore(state_dir=args.state_dir, capacity=capacity)
    try:
        if args.command == "acquire-or-queue":
            result = store.acquire_or_queue(
                session_id=args.session_id,
                turn_id=args.turn_id,
                task_name=args.task_name,
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
    except CapacityError as exc:
        print_json({"state": "ERROR", "reason": exc.reason})
        return exc.exit_code
    raise AssertionError(args.command)


def exit_for_result(result: dict[str, Any]) -> int:
    return 1 if result.get("state") == "ERROR" else 0


if __name__ == "__main__":
    sys.exit(main())
