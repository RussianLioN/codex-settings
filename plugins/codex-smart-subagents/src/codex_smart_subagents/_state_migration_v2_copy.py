"""Явные преобразования строк старой SQLite в нормативную схему версии 2."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import state_migration_v2 as core
from . import _state_migration_v2_database as database
from .canonical_json import canonical_json_v1, domain_fingerprint
from .operation_deadline_v2 import (
    checkpoint_current_operation_deadline_if_scoped_v2,
)
from .schema_projection import APPLICATION_ID, read_schema_artifact
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2

UNKNOWN_LEGACY_V1 = core.UNKNOWN_LEGACY_V1
_SCHEMA_PATH = core._SCHEMA_PATH
_TERMINAL_ATTEMPT_STATES = core._TERMINAL_ATTEMPT_STATES
_VIRTUAL_ROUTE_STATES = core._VIRTUAL_ROUTE_STATES
_COPY_TARGET_TABLES = core._COPY_TARGET_TABLES
MigrationV2Error = core.MigrationV2Error
_fail = core._fail
_text_sha256 = core._text_sha256
_require_sha256 = core._require_sha256
_verify_no_sidecars = core._verify_no_sidecars
_read_only_uri = database._read_only_uri
_open_read_only_database = database._open_read_only_database
_bounded_database_limits = database._bounded_database_limits
_install_deadline_progress_handler = database._install_deadline_progress_handler
_configure_target = database._configure_target
_application_tables = database._application_tables
_load_manifest = database.load_manifest
_table_exists = database._table_exists
_table_columns = database._table_columns
_rows = database._rows
_count = database._count
_read_legacy_sequence = database._read_legacy_sequence

def build_candidate_database(
    *,
    source_path: Path,
    target_path: Path,
    checkpoint: Mapping[str, Any],
    request: LegacyMigrationRequestV2,
    inspection: LegacyDatabaseInspectionV2,
) -> None:
    checkpoint_current_operation_deadline_if_scoped_v2()
    schema_text = read_schema_artifact(_SCHEMA_PATH)
    source = _open_read_only_database(source_path)
    timeout_seconds, _busy_timeout_ms = _bounded_database_limits()
    try:
        target = connect_sqlite_with_deadline_v2(
            target_path,
            isolation_level=None,
            timeout=timeout_seconds,
        )
    except BaseException as primary:
        database._close_connections_preserving_primary_v2(
            (("source", source),),
            primary=primary,
        )
        raise
    target.row_factory = sqlite3.Row
    try:
        _install_deadline_progress_handler(target)
        _configure_target(target)
        if _application_tables(target):
            _fail("AMBIGUOUS_PARTIAL_CANDIDATE", "reserved candidate is not empty")
        target.executescript(schema_text)
        manifest = _load_manifest()
        target.execute("BEGIN IMMEDIATE")
        try:
            _insert_database_identity(
                target,
                checkpoint=checkpoint,
                request=request,
                inspection=inspection,
                manifest=manifest,
            )
            virtual_routes = _copy_routes(target, source)
            _copy_nodes(target, source, virtual_routes=virtual_routes)
            _copy_turn_bindings(
                target,
                source,
                migration_time=str(checkpoint["appliedAt"]),
            )
            source_sequence = _copy_events(target, source)
            _copy_same_columns(
                target,
                source,
                "intents",
                (
                    "intent_id",
                    "route_id",
                    "node_id",
                    "kind",
                    "payload_hash",
                    "payload_json",
                    "state",
                    "created_at",
                    "completed_at",
                ),
            )
            if _table_exists(source, "leases") and _count(source, "leases"):
                _fail("ACTIVE_WORK_REMAINS", "legacy leases remain")
            _copy_same_columns(
                target,
                source,
                "runtime_artifacts",
                (
                    "artifact_id",
                    "route_id",
                    "node_id",
                    "kind",
                    "path",
                    "allowed_root",
                    "state",
                    "device",
                    "inode",
                    "created_at",
                    "updated_at",
                ),
            )
            _copy_same_columns(
                target,
                source,
                "quarantine_repositories",
                (
                    "repository_id",
                    "source_root",
                    "state_root",
                    "git_dir",
                    "state",
                    "created_at",
                    "updated_at",
                ),
            )
            _copy_same_columns(
                target,
                source,
                "candidate_publication_intents",
                (
                    "intent_id",
                    "route_id",
                    "node_id",
                    "repository_id",
                    "artifact_id",
                    "ref",
                    "base_source_sha",
                    "base_commit_sha",
                    "base_tree_sha",
                    "commit_sha",
                    "tree_sha",
                    "state",
                    "created_at",
                    "updated_at",
                    "completed_at",
                ),
            )
            _copy_same_columns(
                target,
                source,
                "candidate_registry",
                (
                    "candidate_id",
                    "route_id",
                    "node_id",
                    "repository_id",
                    "intent_id",
                    "artifact_id",
                    "ref",
                    "base_source_sha",
                    "base_commit_sha",
                    "base_tree_sha",
                    "commit_sha",
                    "tree_sha",
                    "observed_commit_sha",
                    "observed_tree_sha",
                    "state",
                    "validation_state",
                    "proof_hash",
                    "trusted",
                    "created_at",
                    "updated_at",
                ),
            )
            target.execute(
                "update candidate_publication_intents as publication "
                "set validation_proof_sha256=("
                "select candidate.proof_hash from candidate_registry as candidate "
                "where candidate.intent_id=publication.intent_id "
                "and candidate.state='VERIFIED' "
                "and candidate.validation_state='passed' "
                "and candidate.trusted=1) "
                "where publication.state='COMPLETED' and exists("
                "select 1 from candidate_registry as candidate "
                "where candidate.intent_id=publication.intent_id "
                "and candidate.state='VERIFIED' "
                "and candidate.validation_state='passed' "
                "and candidate.trusted=1)"
            )
            _copy_legacy_attempts(
                target,
                source,
                source_backup_sha256=str(checkpoint["backup"]["sha256"]),
            )
            _restore_sequence(target, source_sequence)
            _insert_stale_events(
                target,
                source,
                virtual_routes=virtual_routes,
                migration_time=str(checkpoint["appliedAt"]),
            )
            _insert_controller_state(target, checkpoint=checkpoint, request=request)
            target.execute(
                "insert into schema_migrations "
                "(operation_id,database_id,from_version,to_version,source_shape,"
                "source_schema_fingerprint,source_backup_sha256,target_schema_fingerprint,"
                "target_database_projection_schema_id,target_database_projection_locator,"
                "legacy_quiescence_proof_json,applied_at) values(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
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
                ),
            )
            target.execute(f"pragma application_id={APPLICATION_ID}")
            target.execute("pragma user_version=2")
            target.execute("COMMIT")
        except BaseException as primary:
            if target.in_transaction:
                try:
                    target.rollback_for_cleanup_v2()
                except BaseException as cleanup_error:
                    primary.add_note(
                        "SQLite migration cleanup rollback also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            raise
    except sqlite3.Error as error:
        checkpoint_current_operation_deadline_if_scoped_v2()
        raise MigrationV2Error("LEGACY_DATA_MIGRATION_FAILED", str(error)) from error
    finally:
        database._close_connections_preserving_primary_v2(
            (("target", target), ("source", source)),
            primary=sys.exception(),
        )
    os.chmod(target_path, 0o600)
    checkpoint_current_operation_deadline_if_scoped_v2()
    _verify_no_sidecars(target_path)


def _insert_database_identity(
    connection: sqlite3.Connection,
    *,
    checkpoint: Mapping[str, Any],
    request: LegacyMigrationRequestV2,
    inspection: LegacyDatabaseInspectionV2,
    manifest: Mapping[str, Any],
) -> None:
    connection.execute(
        "insert into database_identity "
        "(singleton,database_id,schema_version,schema_fingerprint,schema_artifact_sha256,"
        "activation_binding_nonce,activation_id,activation_fingerprint,source_shape,"
        "source_schema_fingerprint,source_backup_sha256,created_operation_id,created_at) "
        "values(1,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            checkpoint["candidate"]["databaseId"],
            2,
            manifest["schemaFingerprint"],
            manifest["stateSqlSha256"],
            request.activation_binding_nonce,
            request.activation_id,
            request.activation_fingerprint,
            inspection.source_shape,
            inspection.schema_fingerprint,
            checkpoint["backup"]["sha256"],
            request.operation_id,
            checkpoint["appliedAt"],
        ),
    )


def _copy_routes(
    target: sqlite3.Connection, source: sqlite3.Connection
) -> set[str]:
    columns = (
        "route_id",
        "request_key",
        "request_hash",
        "context_hash",
        "context_json",
        "shell_session_id",
        "session_id",
        "turn_id",
        "codex_home_hash",
        "repo_root_hash",
        "base_sha",
        "worktree_fingerprint",
        "catalog_generation",
        "algorithm_version",
        "disposition",
        "startable",
        "state",
        "expires_at",
        "run_id",
        "cancel_reason",
        "plan_output_json",
        "terminal_result_json",
        "created_at",
        "updated_at",
    )
    if not _table_exists(source, "routes"):
        return set()
    rows = _rows(source, "routes", columns)
    virtual = {
        str(row["route_id"])
        for row in rows
        if str(row["state"]) in _VIRTUAL_ROUTE_STATES
    }
    insert_columns = columns + ("activation_fingerprint", "compatibility_fingerprint")
    for row in rows:
        context_json, context_hash, context = _convert_legacy_context(
            str(row["context_json"]), str(row["context_hash"])
        )
        expected = {
            "shell_session_id": context["shellSessionId"],
            "session_id": context["sessionId"],
            "turn_id": context["turnId"],
            "codex_home_hash": _text_sha256(context["codexHome"]),
            "repo_root_hash": _text_sha256(context["repoRoot"]),
            "base_sha": context["baseSha"],
            "worktree_fingerprint": context["worktreeFingerprint"],
        }
        if any(str(row[name]) != value for name, value in expected.items()):
            _fail("CORRUPT_LEGACY_DATA", "route context columns differ")
        state = "STALE" if str(row["route_id"]) in virtual else str(row["state"])
        startable = 0 if str(row["route_id"]) in virtual else int(row["startable"])
        values = [row[name] for name in columns]
        values[columns.index("context_hash")] = context_hash
        values[columns.index("context_json")] = context_json
        values[columns.index("state")] = state
        values[columns.index("startable")] = startable
        values.extend((UNKNOWN_LEGACY_V1, UNKNOWN_LEGACY_V1))
        _insert_values(target, "routes", insert_columns, values)
    return virtual


def _copy_nodes(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    *,
    virtual_routes: set[str],
) -> None:
    columns = (
        "route_id",
        "node_id",
        "ordinal",
        "role",
        "mission",
        "dependencies_json",
        "context_refs_json",
        "scope_id",
        "artifact_profile_id",
        "validation_profile_id",
        "assessment_json",
        "risk_flags_json",
        "selected_model",
        "reasoning_effort",
        "permission_profile_id",
        "disposition",
        "state",
        "attempt_count",
        "result_json",
        "updated_at",
    )
    if not _table_exists(source, "nodes"):
        return
    insert_columns = columns + (
        "activation_fingerprint",
        "account_context_fingerprint",
        "account_catalog_fingerprint",
        "evidence_job_id",
        "admission_id",
        "admission_state",
        "admission_manifest_semantic_fingerprint",
        "admission_activation_receipt_fingerprint",
        "admission_journal_absence_proof_json",
        "admission_gate_fingerprint",
    )
    for row in _rows(source, "nodes", columns):
        values = [row[name] for name in columns]
        if str(row["route_id"]) in virtual_routes:
            values[columns.index("state")] = "STALE"
        values.extend((UNKNOWN_LEGACY_V1, None, None, None, None, None, None, None, None, None))
        _insert_values(target, "nodes", insert_columns, values)


def _copy_turn_bindings(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    *,
    migration_time: str,
) -> None:
    if not _table_exists(source, "turn_bindings"):
        return
    existing = _table_columns(source, "turn_bindings")
    base = (
        "token_hash",
        "context_hash",
        "context_json",
        "created_at",
        "expires_at",
        "consumed_at",
    )
    optional = tuple(name for name in ("request_key", "request_hash") if name in existing)
    for row in _rows(source, "turn_bindings", base + optional):
        context_json, context_hash, _ = _convert_legacy_context(
            str(row["context_json"]), str(row["context_hash"])
        )
        values = (
            row["token_hash"],
            context_hash,
            context_json,
            row["created_at"],
            row["expires_at"],
            row["consumed_at"] if row["consumed_at"] is not None else migration_time,
            row["request_key"] if "request_key" in optional else None,
            row["request_hash"] if "request_hash" in optional else None,
            UNKNOWN_LEGACY_V1,
            UNKNOWN_LEGACY_V1,
            0,
        )
        _insert_values(
            target,
            "turn_bindings",
            (
                "token_hash",
                "context_hash",
                "context_json",
                "created_at",
                "expires_at",
                "consumed_at",
                "request_key",
                "request_hash",
                "activation_fingerprint",
                "compatibility_fingerprint",
                "issued_control_epoch",
            ),
            values,
        )


def _copy_events(
    target: sqlite3.Connection, source: sqlite3.Connection
) -> int | None:
    sequence = _read_legacy_sequence(source)
    _copy_same_columns(
        target,
        source,
        "events",
        (
            "sequence",
            "route_id",
            "node_id",
            "event",
            "state",
            "code",
            "message",
            "created_at",
        ),
    )
    return sequence


def _copy_legacy_attempts(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    *,
    source_backup_sha256: str,
) -> None:
    columns = (
        "attempt_id",
        "route_id",
        "node_id",
        "state",
        "model",
        "reasoning_effort",
        "permission_profile_id",
        "pid",
        "argv_fingerprint",
        "permission_probe_id",
        "attestation_json",
        "result_json",
        "error_code",
        "error_message",
        "started_at",
        "ended_at",
    )
    if not _table_exists(source, "attempts"):
        return
    for row in _rows(source, "attempts", columns):
        if row["state"] not in _TERMINAL_ATTEMPT_STATES or row["ended_at"] is None:
            _fail("ACTIVE_WORK_REMAINS", "legacy attempt is not terminal")
        identity = {
            "sourceBackupSha256": source_backup_sha256,
            "attemptId": str(row["attempt_id"]),
        }
        permit_fingerprint = domain_fingerprint(
            "codex-smart/legacy-launch-permit/v2", identity
        )
        permit_id = "lp2_" + permit_fingerprint[:32]
        permit_values = (
            permit_id,
            None,
            row["route_id"],
            row["node_id"],
            UNKNOWN_LEGACY_V1,
            UNKNOWN_LEGACY_V1,
            UNKNOWN_LEGACY_V1,
            None,
            None,
            None,
            None,
            UNKNOWN_LEGACY_V1,
            "UNKNOWN_LEGACY_V1",
            0,
            row["model"],
            row["reasoning_effort"],
            row["permission_profile_id"],
            row["argv_fingerprint"],
            UNKNOWN_LEGACY_V1,
            UNKNOWN_LEGACY_V1,
            permit_fingerprint,
            "LEGACY_IMPORTED",
            None,
            None,
            row["pid"],
            None,
            None,
            None,
            source_backup_sha256,
            row["attempt_id"],
            row["started_at"],
            row["ended_at"],
            "LEGACY_V1",
        )
        _insert_values(
            target,
            "node_launch_permits",
            (
                "permit_id",
                "admission_id",
                "route_id",
                "node_id",
                "activation_fingerprint",
                "account_context_fingerprint",
                "account_catalog_fingerprint",
                "manifest_semantic_fingerprint",
                "activation_receipt_fingerprint",
                "journal_absence_proof_json",
                "activation_gate_fingerprint",
                "controller_identity",
                "controller_instance_id",
                "reserved_control_epoch",
                "model",
                "reasoning_effort",
                "permission_profile_id",
                "argv_fingerprint",
                "compatibility_fingerprint",
                "codex_snapshot_sha256",
                "permit_evidence_fingerprint",
                "state",
                "guard_pid",
                "guard_start_marker",
                "pid",
                "start_marker",
                "one_time_token_hash",
                "snapshot_identity_fingerprint",
                "legacy_source_backup_sha256",
                "legacy_attempt_id",
                "reserved_at",
                "resolved_at",
                "failure_code",
            ),
            permit_values,
        )
        attempt_values = tuple(row[name] for name in columns) + (
            permit_id,
            UNKNOWN_LEGACY_V1,
            UNKNOWN_LEGACY_V1,
            UNKNOWN_LEGACY_V1,
            0,
            UNKNOWN_LEGACY_V1,
            "UNKNOWN_LEGACY_V1",
            "V1_LEGACY",
            None,
            None,
            UNKNOWN_LEGACY_V1,
            None,
            permit_fingerprint,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        _insert_values(
            target,
            "attempts",
            columns
            + (
                "launch_permit_id",
                "activation_fingerprint",
                "account_context_fingerprint",
                "account_catalog_fingerprint",
                "launch_control_epoch",
                "controller_identity",
                "controller_instance_id",
                "evidence_kind",
                "codex_binary_sha256",
                "codex_snapshot_sha256",
                "compatibility_fingerprint",
                "snapshot_identity_fingerprint",
                "permit_evidence_fingerprint",
                "admission_id",
                "manifest_semantic_fingerprint",
                "activation_receipt_fingerprint",
                "journal_absence_proof_json",
                "activation_gate_fingerprint",
                "process_start_marker",
            ),
            attempt_values,
        )


def _insert_stale_events(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    *,
    virtual_routes: set[str],
    migration_time: str,
) -> None:
    if not virtual_routes:
        return
    for route_id in sorted(virtual_routes, key=lambda value: value.encode("utf-8")):
        target.execute(
            "insert into events(route_id,node_id,event,state,code,message,created_at) "
            "values(?,?,'legacy_route_stale','STALE','LEGACY_V1_STALE','',?)",
            (route_id, "", migration_time),
        )
        if _table_exists(source, "nodes"):
            node_rows = source.execute(
                "select node_id from nodes where route_id=? order by ordinal,node_id",
                (route_id,),
            ).fetchall()
            for row in node_rows:
                target.execute(
                    "insert into events(route_id,node_id,event,state,code,message,created_at) "
                    "values(?,?,'legacy_node_stale','STALE','LEGACY_V1_STALE','',?)",
                    (route_id, row["node_id"], migration_time),
                )


def _insert_controller_state(
    connection: sqlite3.Connection,
    *,
    checkpoint: Mapping[str, Any],
    request: LegacyMigrationRequestV2,
) -> None:
    connection.execute(
        "insert into controller_state "
        "(singleton,database_id,protocol_version,release,controller_identity,instance_id,"
        "controller_start_id,controller_pid,controller_process_start_marker,"
        "controller_process_group_id,control_epoch,state,maintenance_mode,reason_code,"
        "operation_id,activation_id,activation_fingerprint,compatibility_fingerprint,"
        "routing_policy_fingerprint,bundled_catalog_fingerprint,socket_path,socket_device,"
        "socket_inode,socket_owner_uid,socket_owner_gid,socket_mode,lock_held,"
        "accepting_new_routes,quiescent,updated_at) "
        "values(1,?,2,'0.2.0',?,null,null,null,null,null,1,'MAINTENANCE','FREEZE',"
        "'AWAITING_CONTROLLER_ACCEPT',?,?,?,?,?, ?,null,null,null,null,null,null,0,0,1,?)",
        (
            checkpoint["candidate"]["databaseId"],
            request.controller_identity,
            request.operation_id,
            request.activation_id,
            request.activation_fingerprint,
            request.compatibility_fingerprint,
            request.routing_policy_fingerprint,
            request.bundled_catalog_fingerprint,
            checkpoint["appliedAt"],
        ),
    )


def _restore_sequence(connection: sqlite3.Connection, sequence: int | None) -> None:
    connection.execute("delete from sqlite_sequence where name='events'")
    if sequence is not None:
        connection.execute(
            "insert into sqlite_sequence(name,seq) values('events',?)", (sequence,)
        )


def _convert_legacy_context(raw: str, expected_hash: str) -> tuple[str, str, dict[str, str]]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationV2Error("CORRUPT_LEGACY_DATA", "legacy context is not JSON") from error
    names = {
        "shellSessionId",
        "sessionId",
        "turnId",
        "codexHome",
        "repoRoot",
        "baseSha",
        "worktreeFingerprint",
    }
    if type(value) is not dict or set(value) != names:
        _fail("CORRUPT_LEGACY_DATA", "legacy context fields differ")
    if not all(type(value[name]) is str and value[name] for name in names):
        _fail("CORRUPT_LEGACY_DATA", "legacy context has an empty field")
    if any(len(value[name].encode("utf-8")) > 4096 for name in names):
        _fail("CORRUPT_LEGACY_DATA", "legacy context field is too long")
    _require_sha256(str(value["worktreeFingerprint"]), "worktreeFingerprint")
    old_projection = {
        "shellSessionId": value["shellSessionId"],
        "sessionId": value["sessionId"],
        "turnId": value["turnId"],
        "codexHomeHash": _text_sha256(value["codexHome"]),
        "repoRootHash": _text_sha256(value["repoRoot"]),
        "baseSha": value["baseSha"],
        "worktreeFingerprint": value["worktreeFingerprint"],
    }
    old_hash = hashlib.sha256(
        json.dumps(
            old_projection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if expected_hash != old_hash:
        _fail("CORRUPT_LEGACY_DATA", "legacy context hash differs")
    context: dict[str, Any] = {
        "schemaVersion": 2,
        "shellSessionId": value["shellSessionId"],
        "sessionId": value["sessionId"],
        "turnId": value["turnId"],
        "codexHome": value["codexHome"],
        "repoRoot": value["repoRoot"],
        "baseSha": value["baseSha"],
        "worktreeFingerprint": value["worktreeFingerprint"],
        "activationFingerprint": UNKNOWN_LEGACY_V1,
        "compatibilityFingerprint": UNKNOWN_LEGACY_V1,
        "issuedControlEpoch": 0,
    }
    projection = dict(context)
    projection["codexHome"] = _text_sha256(value["codexHome"])
    projection["repoRoot"] = _text_sha256(value["repoRoot"])
    return (
        canonical_json_v1(context),
        domain_fingerprint("codex-smart/request-context/v2", projection),
        value,
    )


def _copy_same_columns(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
) -> None:
    if not _table_exists(source, table):
        return
    for row in _rows(source, table, columns):
        _insert_values(target, table, columns, tuple(row[name] for name in columns))


def _insert_values(
    connection: sqlite3.Connection,
    table: str,
    columns: Sequence[str],
    values: Sequence[Any],
) -> None:
    checkpoint_current_operation_deadline_if_scoped_v2()
    if len(columns) != len(values):
        raise AssertionError(f"column/value mismatch for {table}")
    if table not in _COPY_TARGET_TABLES:
        raise AssertionError(f"unclosed migration table: {table}")
    if any(not name.replace("_", "").isalnum() for name in columns):
        raise AssertionError(f"unsafe migration column for {table}")
    names = ",".join(columns)
    placeholders = ",".join("?" for _ in columns)
    connection.execute(f"insert into {table}({names}) values({placeholders})", tuple(values))


def _database_projection_locator(operation_id: str, database_id: str) -> str:
    return f"codex-smart://state-migration/v2/{operation_id}/{database_id}"
