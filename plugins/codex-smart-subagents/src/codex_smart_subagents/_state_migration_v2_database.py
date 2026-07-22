"""Проверка закреплённых форм и кандидата миграции SQLite версии 2."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import quote

from . import state_migration_v2 as core
from .canonical_json import canonical_json_v1
from .operation_deadline_v2 import (
    checkpoint_current_operation_deadline_if_scoped_v2,
)
from .schema_projection import (
    APPLICATION_ID,
    database_schema_fingerprint,
    sha256_file,
)
from .sqlite_deadline_v2 import (
    DeadlineAwareConnectionV2,
    connect_sqlite_with_deadline_v2,
)

_fail = core._fail
_TERMINAL_ROUTE_STATES = core._TERMINAL_ROUTE_STATES
_VIRTUAL_ROUTE_STATES = core._VIRTUAL_ROUTE_STATES
_ALL_ROUTE_STATES = core._ALL_ROUTE_STATES
_TERMINAL_ATTEMPT_STATES = core._TERMINAL_ATTEMPT_STATES
_CANDIDATE_TABLES = core._CANDIDATE_TABLES
_SCHEMA_PATH = core._SCHEMA_PATH
_MANIFEST_PATH = core._MANIFEST_PATH
MigrationV2Error = core.MigrationV2Error
LegacyDatabaseInspectionV2 = core.LegacyDatabaseInspectionV2
_absolute = core._absolute
_verify_private_file = core._verify_private_file
_file_projection = core._file_projection
_verify_no_sidecars = core._verify_no_sidecars
_create_exclusive_file = core._create_exclusive_file
_sync_file = core._sync_file
_sync_directory = core._sync_directory

def inspect_legacy_database(path: Path) -> LegacyDatabaseInspectionV2:
    """Распознать одну закреплённую форму и проверить её предикат пустоты."""

    source = _absolute(path)
    _verify_private_file(source, expected_mode=0o600)
    manifest = load_manifest()
    with _read_only_database(source) as connection:
        _verify_sqlite_integrity(connection)
        application_id = int(connection.execute("pragma application_id").fetchone()[0])
        user_version = int(connection.execute("pragma user_version").fetchone()[0])
        if application_id != APPLICATION_ID:
            _fail("UNSUPPORTED_DATABASE", "legacy application_id does not match")
        if user_version not in (0, 1):
            _fail("UNSUPPORTED_DATABASE", "legacy user_version must be 0 or 1")
        fingerprint = database_schema_fingerprint(connection, version=1)
        group = "userVersion0" if user_version == 0 else "userVersion1"
        matches = [
            item
            for item in manifest["legacyShapes"][group]
            if item["fingerprint"] == fingerprint.fingerprint
        ]
        if len(matches) != 1:
            _fail("UNKNOWN_V1_SCHEMA", "database is not one pinned legacy shape")
        shape = matches[0]
        if fingerprint.canonical_size != shape["canonicalSize"]:
            _fail("UNKNOWN_V1_SCHEMA", "legacy canonical schema size differs")
        _verify_shape_data_predicate(connection, shape["dataPredicate"], user_version)
    return LegacyDatabaseInspectionV2(
        source_shape=str(shape["name"]),
        user_version=user_version,
        schema_fingerprint=fingerprint.fingerprint,
        schema_canonical_size=fingerprint.canonical_size,
        data_predicate=str(shape["dataPredicate"]),
    )
def verify_legacy_quiescence(path: Path) -> None:
    with _read_only_database(path) as connection:
        tables = _application_tables(connection)
        routes = _rows(connection, "routes", ("route_id", "state")) if "routes" in tables else []
        nodes = (
            _rows(connection, "nodes", ("route_id", "node_id", "state"))
            if "nodes" in tables
            else []
        )
        for row in routes:
            if row["state"] not in _ALL_ROUTE_STATES:
                _fail("CORRUPT_LEGACY_DATA", "legacy route has an unknown state")
        for row in nodes:
            if row["state"] not in _ALL_ROUTE_STATES:
                _fail("CORRUPT_LEGACY_DATA", "legacy node has an unknown state")

        virtual_routes = {
            str(row["route_id"])
            for row in routes
            if row["state"] in _VIRTUAL_ROUTE_STATES
        }
        node_states_by_route: dict[str, list[str]] = {}
        for row in nodes:
            node_states_by_route.setdefault(str(row["route_id"]), []).append(str(row["state"]))
        for route_id in virtual_routes:
            if any(
                state not in _VIRTUAL_ROUTE_STATES
                for state in node_states_by_route.get(route_id, [])
            ):
                _fail("ACTIVE_WORK_REMAINS", "virtual route has a non-virtual node")

        attempts = (
            _rows(connection, "attempts", ("attempt_id", "route_id", "state", "ended_at"))
            if "attempts" in tables
            else []
        )
        for row in attempts:
            if row["state"] not in _TERMINAL_ATTEMPT_STATES:
                _fail("ACTIVE_WORK_REMAINS", "legacy attempt is nonterminal")
            if row["ended_at"] is None:
                _fail("CORRUPT_LEGACY_DATA", "terminal legacy attempt has no ended_at")
            if str(row["route_id"]) in virtual_routes:
                _fail("ACTIVE_WORK_REMAINS", "virtual route has an attempt")

        if "leases" in tables and _count(connection, "leases") != 0:
            _fail("ACTIVE_WORK_REMAINS", "legacy leases remain")
        if "intents" in tables:
            intents = _rows(connection, "intents", ("route_id", "state"))
            if any(row["state"] not in {"PENDING", "COMPLETED"} for row in intents):
                _fail("CORRUPT_LEGACY_DATA", "legacy intent has an unknown state")
            if any(row["state"] == "PENDING" for row in intents):
                _fail("ACTIVE_WORK_REMAINS", "pending legacy intent remains")
            if any(str(row["route_id"]) in virtual_routes for row in intents):
                _fail("ACTIVE_WORK_REMAINS", "virtual route has an intent")
        if "runtime_artifacts" in tables:
            artifacts = _rows(connection, "runtime_artifacts", ("route_id", "state"))
            if any(row["state"] not in {"RESERVED", "ACTIVE", "TERMINAL", "MISSING"} for row in artifacts):
                _fail("CORRUPT_LEGACY_DATA", "legacy artifact has an unknown state")
            if any(row["state"] in {"RESERVED", "ACTIVE"} for row in artifacts):
                _fail("ACTIVE_WORK_REMAINS", "active legacy runtime artifact remains")
            if any(str(row["route_id"]) in virtual_routes for row in artifacts):
                _fail("ACTIVE_WORK_REMAINS", "virtual route has a runtime artifact")
        if "candidate_publication_intents" in tables:
            publications = _rows(
                connection,
                "candidate_publication_intents",
                ("route_id", "state"),
            )
            allowed = {"PENDING", "COMPLETED", "RECOVERED", "ABORTED", "QUARANTINED"}
            if any(row["state"] not in allowed for row in publications):
                _fail("CORRUPT_LEGACY_DATA", "candidate intent has an unknown state")
            if any(row["state"] == "PENDING" for row in publications):
                _fail("ACTIVE_WORK_REMAINS", "pending candidate publication remains")
            if any(
                row["state"] == "PENDING" and str(row["route_id"]) in virtual_routes
                for row in publications
            ):
                _fail("ACTIVE_WORK_REMAINS", "virtual route has an open publication")

        for row in routes:
            state = str(row["state"])
            if state in _VIRTUAL_ROUTE_STATES:
                continue
            if state not in _TERMINAL_ROUTE_STATES:
                _fail("ACTIVE_WORK_REMAINS", "legacy route is nonterminal")
        for row in nodes:
            route_id = str(row["route_id"])
            state = str(row["state"])
            if route_id in virtual_routes and state in _VIRTUAL_ROUTE_STATES:
                continue
            if state not in _TERMINAL_ROUTE_STATES:
                _fail("ACTIVE_WORK_REMAINS", "legacy node is nonterminal")
        _read_legacy_sequence(connection)


def _read_legacy_sequence(connection: sqlite3.Connection) -> int | None:
    if not _table_exists(connection, "sqlite_sequence"):
        return None
    rows = connection.execute("select name,seq,typeof(seq) from sqlite_sequence").fetchall()
    if len(rows) > 1 or (rows and rows[0][0] != "events"):
        _fail("CORRUPT_LEGACY_DATA", "legacy sqlite_sequence has foreign rows")
    maximum = 0
    if _table_exists(connection, "events"):
        maximum = int(
            connection.execute("select coalesce(max(sequence),0) from events").fetchone()[0]
        )
    if not rows:
        if maximum:
            _fail("CORRUPT_LEGACY_DATA", "legacy events have no sequence high-water mark")
        return None
    if rows[0][2] != "integer" or type(rows[0][1]) is not int or int(rows[0][1]) < maximum:
        _fail("CORRUPT_LEGACY_DATA", "legacy event sequence high-water mark is invalid")
    return int(rows[0][1])
def verify_completed_candidate(
    *,
    path: Path,
    checkpoint: Mapping[str, Any],
    request: LegacyMigrationRequestV2,
    inspection: LegacyDatabaseInspectionV2,
) -> None:
    _verify_private_file(path, expected_mode=0o600)
    _verify_no_sidecars(path)
    manifest = load_manifest()
    connection = _open_read_only_database(path)
    try:
        _verify_sqlite_integrity(connection)
        if int(connection.execute("pragma application_id").fetchone()[0]) != APPLICATION_ID:
            _fail("TARGET_DATABASE_INVALID", "target application_id differs")
        if int(connection.execute("pragma user_version").fetchone()[0]) != 2:
            _fail("TARGET_DATABASE_INVALID", "target user_version differs")
        schema = database_schema_fingerprint(connection, version=2)
        if (
            schema.fingerprint != manifest["schemaFingerprint"]
            or schema.canonical_size != manifest["schemaCanonicalSize"]
        ):
            _fail("TARGET_DATABASE_INVALID", "target schema differs")
        identities = connection.execute(
            "select database_id,source_shape,source_schema_fingerprint,source_backup_sha256 "
            "from database_identity"
        ).fetchall()
        if len(identities) != 1:
            _fail("TARGET_DATABASE_INVALID", "database_identity cardinality differs")
        identity = identities[0]
        if (
            identity["database_id"] != checkpoint["candidate"]["databaseId"]
            or identity["source_shape"] != inspection.source_shape
            or identity["source_schema_fingerprint"] != inspection.schema_fingerprint
            or identity["source_backup_sha256"] != checkpoint["backup"]["sha256"]
        ):
            _fail("TARGET_DATABASE_INVALID", "database_identity differs")
        controllers = connection.execute(
            "select state,maintenance_mode,reason_code,operation_id,quiescent,"
            "accepting_new_routes,lock_held from controller_state"
        ).fetchall()
        if len(controllers) != 1 or tuple(controllers[0]) != (
            "MAINTENANCE",
            "FREEZE",
            "AWAITING_CONTROLLER_ACCEPT",
            request.operation_id,
            1,
            0,
            0,
        ):
            _fail("TARGET_DATABASE_INVALID", "controller maintenance state differs")
        migrations = connection.execute(
            "select operation_id,database_id,from_version,to_version,source_shape,"
            "source_schema_fingerprint,source_backup_sha256,target_schema_fingerprint,"
            "target_database_projection_schema_id,target_database_projection_locator,"
            "legacy_quiescence_proof_json,applied_at from schema_migrations"
        ).fetchall()
        if len(migrations) != 1:
            _fail("TARGET_DATABASE_INVALID", "schema_migrations cardinality differs")
        migration = migrations[0]
        expected = (
            request.operation_id,
            checkpoint["candidate"]["databaseId"],
            inspection.user_version,
            2,
            inspection.source_shape,
            inspection.schema_fingerprint,
            checkpoint["backup"]["sha256"],
            manifest["schemaFingerprint"],
            "database-object-v2",
            _database_projection_locator(
                request.operation_id, str(checkpoint["candidate"]["databaseId"])
            ),
            canonical_json_v1(dict(request.legacy_quiescence_proof)),
            checkpoint["appliedAt"],
        )
        if tuple(migration) != expected:
            _fail("TARGET_DATABASE_INVALID", "schema_migrations row differs")
        _verify_target_quiescence(connection)
        _read_target_sequence(connection)
        checkpoint_current_operation_deadline_if_scoped_v2()
    except sqlite3.OperationalError as error:
        checkpoint_current_operation_deadline_if_scoped_v2()
        raise error
    finally:
        _close_connections_preserving_primary_v2(
            (("candidate verification", connection),),
            primary=sys.exception(),
        )
    target_record = checkpoint["candidate"].get("targetFile")
    if checkpoint["status"] == "COMPLETE":
        actual = _file_projection(path, include_sha=True)
        if target_record != actual:
            _fail("TARGET_DATABASE_CHANGED", "completed target file differs")


def _verify_target_quiescence(connection: sqlite3.Connection) -> None:
    terminal_routes = tuple(sorted(_TERMINAL_ROUTE_STATES | {"DIRECT", "CLARIFY"}))
    terminal_attempts = tuple(sorted(_TERMINAL_ATTEMPT_STATES))
    route_placeholders = ",".join("?" for _ in terminal_routes)
    attempt_placeholders = ",".join("?" for _ in terminal_attempts)
    checks: tuple[tuple[str, tuple[Any, ...]], ...] = (
        (f"select count(*) from routes where state not in ({route_placeholders})", terminal_routes),
        (f"select count(*) from nodes where state not in ({route_placeholders})", terminal_routes),
        (f"select count(*) from attempts where state not in ({attempt_placeholders})", terminal_attempts),
        ("select count(*) from leases", ()),
        ("select count(*) from intents where state='PENDING'", ()),
        (
            "select count(*) from node_launch_permits where state in "
            "('RESERVED','GUARDED','COMMIT_AUTHORIZED')",
            (),
        ),
        ("select count(*) from runtime_artifacts where state in ('RESERVED','ACTIVE')", ()),
        ("select count(*) from candidate_publication_intents where state='PENDING'", ()),
        ("select count(*) from account_evidence_jobs where state in ('RUNNING','CANCEL_REQUESTED')", ()),
        ("select count(*) from account_evidence_jobs where state='QUEUED'", ()),
    )
    for query, parameters in checks:
        if int(connection.execute(query, parameters).fetchone()[0]) != 0:
            _fail("TARGET_DATABASE_ACTIVE", "target database is not quiescent")


def _read_target_sequence(connection: sqlite3.Connection) -> int | None:
    rows = connection.execute("select name,seq,typeof(seq) from sqlite_sequence").fetchall()
    if len(rows) > 1 or (rows and rows[0][0] != "events"):
        _fail("TARGET_DATABASE_INVALID", "target sqlite_sequence has foreign rows")
    maximum = int(connection.execute("select coalesce(max(sequence),0) from events").fetchone()[0])
    if not rows:
        if maximum:
            _fail("TARGET_DATABASE_INVALID", "target event sequence is absent")
        return None
    if rows[0][2] != "integer" or int(rows[0][1]) < maximum:
        _fail("TARGET_DATABASE_INVALID", "target event sequence is below events")
    return int(rows[0][1])


def _database_projection_locator(operation_id: str, database_id: str) -> str:
    return f"codex-smart://state-migration/v2/{operation_id}/{database_id}"


def _verify_shape_data_predicate(
    connection: sqlite3.Connection, predicate: str, user_version: int
) -> None:
    if user_version == 0 or predicate == "all-application-tables-empty":
        names = _application_tables(connection)
    elif predicate == "runtime-artifacts-empty":
        names = {"runtime_artifacts"} & _application_tables(connection)
    elif predicate == "candidate-prefix-empty":
        names = _CANDIDATE_TABLES & _application_tables(connection)
    elif predicate == "legacy-quiescence-v2":
        names = set()
    else:
        _fail("UNKNOWN_V1_SCHEMA", "legacy data predicate is unknown")
    if any(_count(connection, name) for name in names):
        _fail(
            "LEGACY_PARTIAL_SCHEMA_HAS_DATA",
            "legacy partial or unfinished shape contains data",
        )


def _verify_sqlite_integrity(connection: sqlite3.Connection) -> None:
    if [tuple(row) for row in connection.execute("pragma quick_check").fetchall()] != [("ok",)]:
        _fail("DATABASE_INTEGRITY_FAILED", "quick_check failed")
    if [tuple(row) for row in connection.execute("pragma integrity_check").fetchall()] != [("ok",)]:
        _fail("DATABASE_INTEGRITY_FAILED", "integrity_check failed")
    if connection.execute("pragma foreign_key_check").fetchall():
        _fail("DATABASE_INTEGRITY_FAILED", "foreign_key_check failed")


def _configure_target(connection: sqlite3.Connection) -> None:
    connection.execute("pragma foreign_keys=ON")
    connection.execute("pragma trusted_schema=OFF")
    connection.execute("pragma synchronous=FULL")
    connection.execute("pragma secure_delete=FAST")
    _timeout_seconds, busy_timeout_ms = _bounded_database_limits()
    connection.execute(f"pragma busy_timeout={busy_timeout_ms}")
    _install_deadline_progress_handler(connection)
    mode = str(connection.execute("pragma journal_mode=DELETE").fetchone()[0]).lower()
    if mode != "delete":
        _fail("TARGET_DATABASE_INVALID", "target journal mode is not DELETE")


def sqlite_backup(source: Path, destination: Path) -> None:
    timeout_seconds, busy_timeout_ms = _bounded_database_limits()
    _create_exclusive_file(destination, mode=0o600)
    source_connection = connect_sqlite_with_deadline_v2(
        _read_only_uri(source),
        uri=True,
        isolation_level=None,
        timeout=timeout_seconds,
    )
    try:
        destination_connection = connect_sqlite_with_deadline_v2(
            destination,
            isolation_level=None,
            timeout=timeout_seconds,
        )
    except BaseException as primary:
        _close_connections_preserving_primary_v2(
            (("source", source_connection),),
            primary=primary,
        )
        raise
    try:
        _install_deadline_progress_handler(source_connection)
        _install_deadline_progress_handler(destination_connection)
        source_connection.execute("pragma query_only=ON")
        source_connection.execute(f"pragma busy_timeout={busy_timeout_ms}")
        destination_connection.execute("pragma synchronous=FULL")
        source_connection.backup(
            destination_connection,
            pages=64,
            progress=_sqlite_backup_deadline_progress,
        )
        checkpoint_current_operation_deadline_if_scoped_v2()
        mode = str(
            destination_connection.execute("pragma journal_mode=DELETE").fetchone()[0]
        ).lower()
        if mode != "delete":
            _fail("BACKUP_STABILIZATION_FAILED", "backup journal mode is not DELETE")
        destination_connection.execute("pragma synchronous=FULL")
        destination_connection.execute("pragma foreign_keys=ON")
        _verify_sqlite_integrity(destination_connection)
    except sqlite3.OperationalError as error:
        checkpoint_current_operation_deadline_if_scoped_v2()
        raise error
    finally:
        _close_connections_preserving_primary_v2(
            (
                ("destination", destination_connection),
                ("source", source_connection),
            ),
            primary=sys.exception(),
        )
    _verify_no_sidecars(destination)
    _sync_file(destination)
    _sync_directory(destination.parent)


def _close_connections_preserving_primary_v2(
    connections: Sequence[tuple[str, sqlite3.Connection]],
    *,
    primary: BaseException | None,
) -> None:
    failure = primary
    for name, connection in connections:
        try:
            connection.close()
        except BaseException as close_error:
            if failure is None:
                failure = close_error
            else:
                failure.add_note(
                    f"SQLite migration {name} close also failed: "
                    f"{type(close_error).__name__}: {close_error}"
                )
    if primary is None and failure is not None:
        raise failure


@contextmanager
def _read_only_database(path: Path) -> Iterator[sqlite3.Connection]:
    connection = _open_read_only_database(path)
    try:
        try:
            yield connection
        except sqlite3.OperationalError as error:
            checkpoint_current_operation_deadline_if_scoped_v2()
            raise error
        checkpoint_current_operation_deadline_if_scoped_v2()
    finally:
        _close_connections_preserving_primary_v2(
            (("read-only", connection),),
            primary=sys.exception(),
        )


def _open_read_only_database(path: Path) -> sqlite3.Connection:
    timeout_seconds, busy_timeout_ms = _bounded_database_limits()
    connection = connect_sqlite_with_deadline_v2(
        _read_only_uri(path),
        uri=True,
        isolation_level=None,
        timeout=timeout_seconds,
    )
    try:
        connection.row_factory = sqlite3.Row
        _install_deadline_progress_handler(connection)
        connection.execute("pragma query_only=ON")
        connection.execute("pragma foreign_keys=ON")
        connection.execute("pragma trusted_schema=OFF")
        connection.execute(f"pragma busy_timeout={busy_timeout_ms}")
    except sqlite3.OperationalError as error:
        try:
            checkpoint_current_operation_deadline_if_scoped_v2()
        except BaseException as primary:
            _close_connections_preserving_primary_v2(
                (("read-only setup", connection),),
                primary=primary,
            )
            raise
        _close_connections_preserving_primary_v2(
            (("read-only setup", connection),),
            primary=error,
        )
        raise
    except BaseException as primary:
        _close_connections_preserving_primary_v2(
            (("read-only setup", connection),),
            primary=primary,
        )
        raise
    return connection


def _bounded_database_limits() -> tuple[float, int]:
    operation_deadline = (
        checkpoint_current_operation_deadline_if_scoped_v2()
    )
    timeout_seconds = 5.0
    busy_timeout_ms = 5_000
    if operation_deadline is not None:
        timeout_seconds = operation_deadline.bounded_timeout_seconds(
            local_cap_seconds=timeout_seconds
        )
        busy_timeout_ms = operation_deadline.bounded_timeout_ms(
            local_cap_ms=busy_timeout_ms
        )
    return timeout_seconds, busy_timeout_ms


def _install_deadline_progress_handler(
    connection: sqlite3.Connection,
) -> None:
    if isinstance(connection, DeadlineAwareConnectionV2):
        return
    if checkpoint_current_operation_deadline_if_scoped_v2() is None:
        return

    def progress() -> int:
        try:
            checkpoint_current_operation_deadline_if_scoped_v2()
        except BaseException:
            return 1
        return 0

    connection.set_progress_handler(progress, 1_000)


def _sqlite_backup_deadline_progress(
    _status: int,
    _remaining: int,
    _total: int,
) -> None:
    checkpoint_current_operation_deadline_if_scoped_v2()


def _read_only_uri(path: Path) -> str:
    return "file:" + quote(os.fspath(path), safe="/") + "?mode=ro"


def load_manifest() -> dict[str, Any]:
    try:
        manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationV2Error("INVALID_SCHEMA_MANIFEST", "manifest is not JSON") from error
    if (
        type(manifest) is not dict
        or manifest.get("schemaVersion") != 2
        or manifest.get("applicationId") != APPLICATION_ID
        or manifest.get("stateSqlSha256") != sha256_file(_SCHEMA_PATH)
    ):
        _fail("INVALID_SCHEMA_MANIFEST", "schema manifest differs")
    canonical_json_v1(manifest)
    return manifest
def _application_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "select name from sqlite_schema where type='table' and name not glob 'sqlite_*'"
        )
    }


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "select 1 from sqlite_schema where type='table' and name=?", (table,)
    ).fetchone() is not None


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    if not table.replace("_", "").isalnum():
        raise AssertionError("unsafe internal table name")
    return {str(row[1]) for row in connection.execute(f"pragma table_info({table})")}


def _rows(
    connection: sqlite3.Connection, table: str, columns: Sequence[str]
) -> list[sqlite3.Row]:
    if not table.replace("_", "").isalnum() or any(
        not column.replace("_", "").isalnum() for column in columns
    ):
        raise AssertionError("unsafe internal migration identifier")
    existing = _table_columns(connection, table)
    if any(column not in existing for column in columns):
        _fail("UNKNOWN_V1_SCHEMA", f"legacy table {table} has missing columns")
    return connection.execute(
        f"select {','.join(columns)} from {table}"
    ).fetchall()


def _count(connection: sqlite3.Connection, table: str) -> int:
    if not table.replace("_", "").isalnum():
        raise AssertionError("unsafe internal table name")
    return int(connection.execute(f"select count(*) from {table}").fetchone()[0])
