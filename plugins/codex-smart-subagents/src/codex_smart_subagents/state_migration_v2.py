"""Закрытый перенос исторической базы SQLite в отдельную базу версии 2.

Модуль намеренно не открывает рабочее хранилище версии 2 и никогда не
изменяет исходную базу. Он создаёт частный снимок SQLite Backup API,
распознаёт только закреплённые формы и строит новый уникальный кандидат.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from .canonical_json import canonical_json_v1, domain_fingerprint
from . import finite_file_lock_v2
from .schema_projection import sha256_file


UNKNOWN_LEGACY_V1 = hashlib.sha256(
    b"codex-smart-subagents-db-v1-legacy"
).hexdigest()
_SCHEMA_DIR = Path(__file__).with_name("schema")
_SCHEMA_PATH = _SCHEMA_DIR / "state-v2.sql"
_MANIFEST_PATH = _SCHEMA_DIR / "state-v2.manifest.json"
_TERMINAL_ROUTE_STATES = {
    "SUCCEEDED",
    "CANDIDATE_READY",
    "QUARANTINED",
    "CANCELLED",
    "FAILED",
    "STALE",
    "SKIPPED",
}
_VIRTUAL_ROUTE_STATES = {"PLANNED", "BLOCKED"}
_ALL_ROUTE_STATES = _TERMINAL_ROUTE_STATES | _VIRTUAL_ROUTE_STATES | {
    "QUEUED",
    "LEASED",
    "PREPARING",
    "RUNNING",
    "COLLECTING",
    "ATTESTING",
    "VALIDATING",
    "CANDIDATE_BUILDING",
    "RETRYABLE",
    "RECOVERING",
    "CANCELLING",
    "SPLIT",
}
_TERMINAL_ATTEMPT_STATES = {"SUCCEEDED", "FAILED", "CANCELLED", "QUARANTINED"}
_CANDIDATE_TABLES = {
    "quarantine_repositories",
    "candidate_publication_intents",
    "candidate_registry",
}
_COPY_TARGET_TABLES = {
    "database_identity",
    "controller_state",
    "turn_bindings",
    "routes",
    "nodes",
    "events",
    "intents",
    "node_launch_permits",
    "attempts",
    "runtime_artifacts",
    "quarantine_repositories",
    "candidate_publication_intents",
    "candidate_registry",
    "schema_migrations",
}


@dataclass
class MigrationV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class LegacyDatabaseInspectionV2:
    source_shape: str
    user_version: int
    schema_fingerprint: str
    schema_canonical_size: int
    data_predicate: str


@dataclass(frozen=True)
class LegacyMigrationRequestV2:
    state_home: Path
    source_path: Path
    operation_id: str
    activation_binding_nonce: str
    activation_id: str
    activation_fingerprint: str
    controller_identity: str
    compatibility_fingerprint: str
    routing_policy_fingerprint: str
    bundled_catalog_fingerprint: str
    legacy_quiescence_proof: Mapping[str, Any]
    migration_time: datetime


@dataclass(frozen=True)
class LegacyMigrationResultV2:
    operation_id: str
    source_shape: str
    source_schema_fingerprint: str
    source_backup_sha256: str
    backup_path: Path
    database_id: str
    database_path: Path
    target_schema_fingerprint: str
    reused: bool


def inspect_legacy_database(path: Path) -> LegacyDatabaseInspectionV2:
    """Распознать одну из 38 закреплённых исторических форм."""

    from ._state_migration_v2_database import inspect_legacy_database as inspect

    return inspect(path)


def migrate_legacy_database(
    request: LegacyMigrationRequestV2,
) -> LegacyMigrationResultV2:
    """Создать или доказанно переиспользовать один кандидат версии 2."""

    normalized = _validate_request(request)
    state_home = normalized.state_home
    source = normalized.source_path
    operation_dir = _prepare_operation_directory(state_home, normalized.operation_id)
    with _operation_lock(operation_dir):
        checkpoint_path = operation_dir / "migration-v2.json"
        checkpoint = _read_checkpoint(checkpoint_path) if checkpoint_path.exists() else None
        request_fingerprint = _request_fingerprint(normalized)
        if checkpoint is None:
            unexpected = {
                item.name for item in operation_dir.iterdir()
                if item.name != "migration.lock"
            }
            if unexpected:
                _fail(
                    "AMBIGUOUS_MIGRATION_RECOVERY",
                    "operation directory has data without a checkpoint",
                )
            checkpoint = _create_snapshot_checkpoint(
                request=normalized,
                operation_dir=operation_dir,
                request_fingerprint=request_fingerprint,
            )
            _write_checkpoint(checkpoint_path, checkpoint)
        else:
            _verify_checkpoint_request(checkpoint, normalized, request_fingerprint)

        operation_entries = {item.name for item in operation_dir.iterdir()}
        if operation_entries - {"migration.lock", "migration-v2.json", "source-v1.sqlite3"}:
            _fail("AMBIGUOUS_MIGRATION_RECOVERY", "operation directory has foreign entries")

        inspection = _verify_recorded_snapshot(checkpoint)
        _verify_legacy_quiescence(Path(checkpoint["backup"]["path"]))
        completed, reused = _complete_or_recover_candidate(
            request=normalized,
            checkpoint_path=checkpoint_path,
            checkpoint=checkpoint,
            inspection=inspection,
        )
        return LegacyMigrationResultV2(
            operation_id=normalized.operation_id,
            source_shape=inspection.source_shape,
            source_schema_fingerprint=inspection.schema_fingerprint,
            source_backup_sha256=str(completed["backup"]["sha256"]),
            backup_path=Path(completed["backup"]["path"]),
            database_id=str(completed["candidate"]["databaseId"]),
            database_path=Path(completed["candidate"]["finalPath"]),
            target_schema_fingerprint=str(_load_manifest()["schemaFingerprint"]),
            reused=reused,
        )


def _validate_request(request: LegacyMigrationRequestV2) -> LegacyMigrationRequestV2:
    if not isinstance(request, LegacyMigrationRequestV2):
        _fail("INVALID_MIGRATION_REQUEST", "request has another type")
    state_home = _absolute(request.state_home)
    source = _absolute(request.source_path)
    _verify_private_directory(state_home, expected_mode=0o700)
    _verify_private_file(source, expected_mode=0o600)
    if source.parent != state_home:
        _fail("INVALID_MIGRATION_REQUEST", "legacy database must be inside STATE_HOME")
    _require_id(request.operation_id, "op2_", 32)
    _require_id(request.activation_id, "act2_", 64)
    for name in (
        "activation_binding_nonce",
        "activation_fingerprint",
        "controller_identity",
        "compatibility_fingerprint",
        "routing_policy_fingerprint",
        "bundled_catalog_fingerprint",
    ):
        _require_sha256(getattr(request, name), name)
    migration_time = request.migration_time
    if not isinstance(migration_time, datetime) or migration_time.tzinfo is None:
        _fail("INVALID_MIGRATION_REQUEST", "migration_time must be timezone-aware")
    proof = _validate_quiescence_projection(
        request.legacy_quiescence_proof,
        state_home=state_home,
        source=source,
    )
    return LegacyMigrationRequestV2(
        state_home=state_home,
        source_path=source,
        operation_id=request.operation_id,
        activation_binding_nonce=request.activation_binding_nonce,
        activation_id=request.activation_id,
        activation_fingerprint=request.activation_fingerprint,
        controller_identity=request.controller_identity,
        compatibility_fingerprint=request.compatibility_fingerprint,
        routing_policy_fingerprint=request.routing_policy_fingerprint,
        bundled_catalog_fingerprint=request.bundled_catalog_fingerprint,
        legacy_quiescence_proof=proof,
        migration_time=migration_time.astimezone(timezone.utc),
    )


def _validate_quiescence_projection(
    value: Mapping[str, Any], *, state_home: Path, source: Path
) -> dict[str, Any]:
    from ._state_migration_v2_contract import validate_quiescence_projection

    return validate_quiescence_projection(
        value,
        state_home=state_home,
        source=source,
        fail=_fail,
        file_projection=_file_projection,
    )


def _request_fingerprint(request: LegacyMigrationRequestV2) -> str:
    value = {
        "stateHome": os.fspath(request.state_home),
        "sourcePath": os.fspath(request.source_path),
        "operationId": request.operation_id,
        "activationBindingNonce": request.activation_binding_nonce,
        "activationId": request.activation_id,
        "activationFingerprint": request.activation_fingerprint,
        "controllerIdentity": request.controller_identity,
        "compatibilityFingerprint": request.compatibility_fingerprint,
        "routingPolicyFingerprint": request.routing_policy_fingerprint,
        "bundledCatalogFingerprint": request.bundled_catalog_fingerprint,
        "legacyQuiescenceProof": request.legacy_quiescence_proof,
    }
    return domain_fingerprint("codex-smart/legacy-migration-request/v2", value)


def _create_snapshot_checkpoint(
    *,
    request: LegacyMigrationRequestV2,
    operation_dir: Path,
    request_fingerprint: str,
) -> dict[str, Any]:
    source_before = _file_projection(request.source_path, include_sha=True)
    backup_path = operation_dir / "source-v1.sqlite3"
    _sqlite_backup(request.source_path, backup_path)
    source_after = _file_projection(request.source_path, include_sha=True)
    if source_after != source_before:
        _fail("SOURCE_DATABASE_CHANGED", "legacy database changed during backup")
    inspection = inspect_legacy_database(backup_path)
    _verify_no_sidecars(backup_path)
    backup = _file_projection(backup_path, include_sha=True)
    backup.update(
        {
            "sourceShape": inspection.source_shape,
            "userVersion": inspection.user_version,
            "schemaFingerprint": inspection.schema_fingerprint,
            "schemaCanonicalSize": inspection.schema_canonical_size,
        }
    )
    databases_root = request.state_home / "databases"
    _ensure_private_directory(databases_root)
    while True:
        database_id = "db2_" + secrets.token_hex(16)
        database_dir = databases_root / database_id
        if not os.path.lexists(database_dir):
            break
    body: dict[str, Any] = {
        "schemaVersion": 2,
        "operationId": request.operation_id,
        "requestFingerprint": request_fingerprint,
        "appliedAt": _iso(request.migration_time),
        "status": "SNAPSHOT_READY",
        "source": source_before,
        "backup": backup,
        "candidate": {
            "databaseId": database_id,
            "directory": os.fspath(database_dir),
            "temporaryPath": os.fspath(database_dir / "candidate.sqlite3.tmp"),
            "finalPath": os.fspath(database_dir / "state.sqlite3"),
            "reservedFile": None,
            "targetFile": None,
        },
    }
    return _seal_checkpoint(body)


def _verify_recorded_snapshot(
    checkpoint: Mapping[str, Any],
) -> LegacyDatabaseInspectionV2:
    backup = checkpoint["backup"]
    path = Path(backup["path"])
    actual = _file_projection(path, include_sha=True)
    for name in (
        "path",
        "device",
        "inode",
        "ownerUid",
        "ownerGid",
        "mode",
        "linkCount",
        "size",
        "sha256",
    ):
        if backup[name] != actual[name]:
            _fail("RECORDED_BACKUP_CHANGED", f"recorded backup {name} differs")
    _verify_no_sidecars(path)
    inspection = inspect_legacy_database(path)
    expected = (
        backup["sourceShape"],
        backup["userVersion"],
        backup["schemaFingerprint"],
        backup["schemaCanonicalSize"],
    )
    observed = (
        inspection.source_shape,
        inspection.user_version,
        inspection.schema_fingerprint,
        inspection.schema_canonical_size,
    )
    if expected != observed:
        _fail("RECORDED_BACKUP_CHANGED", "recorded backup schema differs")
    return inspection


def _verify_checkpoint_request(
    checkpoint: Mapping[str, Any],
    request: LegacyMigrationRequestV2,
    request_fingerprint: str,
) -> None:
    if checkpoint["operationId"] != request.operation_id:
        _fail("MIGRATION_REPLAY_CONFLICT", "operation id differs")
    if checkpoint["requestFingerprint"] != request_fingerprint:
        _fail("MIGRATION_REPLAY_CONFLICT", "migration request differs")
    source = checkpoint["source"]
    actual = _file_projection(request.source_path, include_sha=True)
    if source != actual:
        _fail("SOURCE_DATABASE_CHANGED", "legacy source identity changed")


def _complete_or_recover_candidate(
    *,
    request: LegacyMigrationRequestV2,
    checkpoint_path: Path,
    checkpoint: dict[str, Any],
    inspection: LegacyDatabaseInspectionV2,
) -> tuple[dict[str, Any], bool]:
    candidate = checkpoint["candidate"]
    database_dir = Path(candidate["directory"])
    temporary_path = Path(candidate["temporaryPath"])
    final_path = Path(candidate["finalPath"])
    expected_dir = request.state_home / "databases" / candidate["databaseId"]
    if database_dir != expected_dir or temporary_path.parent != database_dir or final_path.parent != database_dir:
        _fail("INVALID_MIGRATION_CHECKPOINT", "candidate paths are not canonical")

    if checkpoint["status"] == "COMPLETE":
        _verify_private_directory(database_dir, expected_mode=0o700)
        if temporary_path.exists():
            _fail("AMBIGUOUS_PARTIAL_CANDIDATE", "completed candidate has a temporary file")
        if {item.name for item in database_dir.iterdir()} != {final_path.name}:
            _fail("AMBIGUOUS_PARTIAL_CANDIDATE", "completed candidate directory differs")
        _verify_completed_candidate(
            path=final_path,
            checkpoint=checkpoint,
            request=request,
            inspection=inspection,
        )
        return checkpoint, True

    if checkpoint["status"] not in {"SNAPSHOT_READY", "CANDIDATE_RESERVED"}:
        _fail("INVALID_MIGRATION_CHECKPOINT", "candidate status is unknown")

    if final_path.exists():
        if checkpoint["status"] != "CANDIDATE_RESERVED" or temporary_path.exists():
            _fail("AMBIGUOUS_PARTIAL_CANDIDATE", "unrecorded final candidate exists")
        _verify_completed_candidate(
            path=final_path,
            checkpoint=checkpoint,
            request=request,
            inspection=inspection,
        )
        completed = _checkpoint_completed(checkpoint, final_path)
        _write_checkpoint(checkpoint_path, completed)
        return completed, True

    if not database_dir.exists():
        database_dir.mkdir(mode=0o700)
        _sync_directory(database_dir.parent)
    _verify_private_directory(database_dir, expected_mode=0o700)
    allowed = {temporary_path.name} if temporary_path.exists() else set()
    unexpected = {item.name for item in database_dir.iterdir()} - allowed
    if unexpected:
        _fail("AMBIGUOUS_PARTIAL_CANDIDATE", "candidate directory has foreign entries")

    if checkpoint["status"] == "SNAPSHOT_READY":
        if temporary_path.exists():
            _verify_private_file(temporary_path, expected_mode=0o600)
            if temporary_path.stat().st_size != 0:
                _fail(
                    "AMBIGUOUS_PARTIAL_CANDIDATE",
                    "unrecorded candidate is not empty",
                )
        else:
            _create_exclusive_file(temporary_path, mode=0o600)
        reserved = _file_projection(temporary_path, include_sha=False)
        checkpoint = _checkpoint_with_candidate_reserved(checkpoint, reserved)
        _write_checkpoint(checkpoint_path, checkpoint)
    else:
        _verify_reserved_candidate(temporary_path, checkpoint["candidate"]["reservedFile"])

    if temporary_path.stat().st_size:
        try:
            _verify_completed_candidate(
                path=temporary_path,
                checkpoint=checkpoint,
                request=request,
                inspection=inspection,
            )
        except MigrationV2Error as error:
            raise MigrationV2Error(
                "AMBIGUOUS_PARTIAL_CANDIDATE",
                f"non-empty candidate is not complete: {error}",
            ) from error
    else:
        _build_candidate_database(
            source_path=Path(checkpoint["backup"]["path"]),
            target_path=temporary_path,
            checkpoint=checkpoint,
            request=request,
            inspection=inspection,
        )
        _verify_completed_candidate(
            path=temporary_path,
            checkpoint=checkpoint,
            request=request,
            inspection=inspection,
        )

    _sync_file(temporary_path)
    os.replace(temporary_path, final_path)
    _sync_directory(database_dir)
    _verify_completed_candidate(
        path=final_path,
        checkpoint=checkpoint,
        request=request,
        inspection=inspection,
    )
    completed = _checkpoint_completed(checkpoint, final_path)
    _write_checkpoint(checkpoint_path, completed)
    return completed, False


def _checkpoint_with_candidate_reserved(
    checkpoint: Mapping[str, Any], reserved: Mapping[str, Any]
) -> dict[str, Any]:
    body = _checkpoint_body(checkpoint)
    body["status"] = "CANDIDATE_RESERVED"
    body["candidate"] = dict(body["candidate"])
    body["candidate"]["reservedFile"] = dict(reserved)
    return _seal_checkpoint(body)


def _checkpoint_completed(
    checkpoint: Mapping[str, Any], final_path: Path
) -> dict[str, Any]:
    body = _checkpoint_body(checkpoint)
    body["status"] = "COMPLETE"
    body["candidate"] = dict(body["candidate"])
    body["candidate"]["targetFile"] = _file_projection(final_path, include_sha=True)
    return _seal_checkpoint(body)


def _seal_checkpoint(body: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(body)
    value.pop("checkpointFingerprint", None)
    value["checkpointFingerprint"] = domain_fingerprint(
        "codex-smart/legacy-migration-checkpoint/v2", value
    )
    return value


def _checkpoint_body(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in checkpoint.items() if name != "checkpointFingerprint"}


def _read_checkpoint(path: Path) -> dict[str, Any]:
    _verify_private_file(path, expected_mode=0o600)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationV2Error("INVALID_MIGRATION_CHECKPOINT", "checkpoint is not JSON") from error
    if type(value) is not dict:
        _fail("INVALID_MIGRATION_CHECKPOINT", "checkpoint root is not an object")
    required = {
        "schemaVersion",
        "operationId",
        "requestFingerprint",
        "appliedAt",
        "status",
        "source",
        "backup",
        "candidate",
        "checkpointFingerprint",
    }
    if set(value) != required or value["schemaVersion"] != 2:
        _fail("INVALID_MIGRATION_CHECKPOINT", "checkpoint fields differ")
    fingerprint = value.pop("checkpointFingerprint")
    expected = domain_fingerprint("codex-smart/legacy-migration-checkpoint/v2", value)
    value["checkpointFingerprint"] = fingerprint
    if fingerprint != expected:
        _fail("INVALID_MIGRATION_CHECKPOINT", "checkpoint fingerprint differs")
    _validate_checkpoint_structure(value)
    canonical_json_v1(value)
    return value


def _write_checkpoint(path: Path, checkpoint: Mapping[str, Any]) -> None:
    payload = (canonical_json_v1(dict(checkpoint)) + "\n").encode("utf-8")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
        _full_fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _sync_directory(path.parent)


def _validate_checkpoint_structure(value: Mapping[str, Any]) -> None:
    file_fields = {
        "path",
        "device",
        "inode",
        "ownerUid",
        "ownerGid",
        "mode",
        "linkCount",
        "size",
    }
    source = value["source"]
    backup = value["backup"]
    candidate = value["candidate"]
    if type(source) is not dict or set(source) != file_fields | {"sha256"}:
        _fail("INVALID_MIGRATION_CHECKPOINT", "source projection fields differ")
    if type(backup) is not dict or set(backup) != file_fields | {
        "sha256",
        "sourceShape",
        "userVersion",
        "schemaFingerprint",
        "schemaCanonicalSize",
    }:
        _fail("INVALID_MIGRATION_CHECKPOINT", "backup projection fields differ")
    if type(candidate) is not dict or set(candidate) != {
        "databaseId",
        "directory",
        "temporaryPath",
        "finalPath",
        "reservedFile",
        "targetFile",
    }:
        _fail("INVALID_MIGRATION_CHECKPOINT", "candidate fields differ")
    status = value["status"]
    if status == "SNAPSHOT_READY":
        if candidate["reservedFile"] is not None or candidate["targetFile"] is not None:
            _fail("INVALID_MIGRATION_CHECKPOINT", "snapshot checkpoint carries a candidate")
    elif status == "CANDIDATE_RESERVED":
        if (
            type(candidate["reservedFile"]) is not dict
            or set(candidate["reservedFile"]) != file_fields
            or candidate["targetFile"] is not None
        ):
            _fail("INVALID_MIGRATION_CHECKPOINT", "reserved candidate projection differs")
    elif status == "COMPLETE":
        if (
            type(candidate["reservedFile"]) is not dict
            or set(candidate["reservedFile"]) != file_fields
            or type(candidate["targetFile"]) is not dict
            or set(candidate["targetFile"]) != file_fields | {"sha256"}
        ):
            _fail("INVALID_MIGRATION_CHECKPOINT", "complete candidate projection differs")
    else:
        _fail("INVALID_MIGRATION_CHECKPOINT", "checkpoint status differs")
    _require_id(value["operationId"], "op2_", 32)
    _require_id(candidate["databaseId"], "db2_", 32)
    _require_sha256(value["requestFingerprint"], "requestFingerprint")
    _require_sha256(value["checkpointFingerprint"], "checkpointFingerprint")
    _require_sha256(backup["sha256"], "backup.sha256")
    _require_sha256(backup["schemaFingerprint"], "backup.schemaFingerprint")
    if backup["userVersion"] not in (0, 1):
        _fail("INVALID_MIGRATION_CHECKPOINT", "backup user version differs")
    for projection in (source, backup, candidate.get("reservedFile"), candidate.get("targetFile")):
        if projection is None:
            continue
        if type(projection.get("path")) is not str or not Path(projection["path"]).is_absolute():
            _fail("INVALID_MIGRATION_CHECKPOINT", "checkpoint path is not absolute")


def _verify_reserved_candidate(path: Path, expected: Mapping[str, Any]) -> None:
    actual = _file_projection(path, include_sha=False)
    stable_names = ("path", "device", "inode", "ownerUid", "ownerGid", "mode", "linkCount")
    if any(actual[name] != expected[name] for name in stable_names):
        _fail("AMBIGUOUS_PARTIAL_CANDIDATE", "reserved candidate identity changed")


def _verify_legacy_quiescence(path: Path) -> None:
    from ._state_migration_v2_database import verify_legacy_quiescence

    verify_legacy_quiescence(path)


def _build_candidate_database(**arguments: Any) -> None:
    from ._state_migration_v2_copy import build_candidate_database

    build_candidate_database(**arguments)


def _verify_completed_candidate(**arguments: Any) -> None:
    from ._state_migration_v2_database import verify_completed_candidate

    verify_completed_candidate(**arguments)


def _sqlite_backup(source: Path, destination: Path) -> None:
    from ._state_migration_v2_database import sqlite_backup

    sqlite_backup(source, destination)


def _load_manifest() -> dict[str, Any]:
    from ._state_migration_v2_database import load_manifest

    return load_manifest()


def _prepare_operation_directory(state_home: Path, operation_id: str) -> Path:
    backups = state_home / "backups"
    _ensure_private_directory(backups)
    operation = backups / operation_id
    if not operation.exists():
        operation.mkdir(mode=0o700)
        _sync_directory(backups)
    _verify_private_directory(operation, expected_mode=0o700)
    return operation


@contextmanager
def _operation_lock(operation_dir: Path) -> Iterator[None]:
    path = operation_dir / "migration.lock"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    acquired = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            _fail("UNSAFE_MIGRATION_LOCK", "migration lock is not private")
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=(
                    finite_file_lock_v2.LOCAL_FILE_LOCK_TIMEOUT_SECONDS
                ),
                timeout_code="MIGRATION_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as error:
            raise MigrationV2Error(
                error.code,
                "migration lock remained busy until its deadline",
            ) from error
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _ensure_private_directory(path: Path) -> None:
    if not path.exists():
        path.mkdir(mode=0o700)
        _sync_directory(path.parent)
    _verify_private_directory(path, expected_mode=0o700)


def _verify_private_directory(path: Path, *, expected_mode: int) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as error:
        raise MigrationV2Error("UNSAFE_STATE_PATH", f"directory is absent: {path}") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        _fail("UNSAFE_STATE_PATH", f"directory is not private: {path}")


def _verify_private_file(path: Path, *, expected_mode: int) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as error:
        raise MigrationV2Error("UNSAFE_DATABASE", f"file is absent: {path}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_nlink != 1
    ):
        _fail("UNSAFE_DATABASE", f"file is not private: {path}")


def _file_projection(path: Path, *, include_sha: bool) -> dict[str, Any]:
    _verify_private_file(path, expected_mode=0o600)
    metadata = os.lstat(path)
    value: dict[str, Any] = {
        "path": os.fspath(path),
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "ownerUid": int(metadata.st_uid),
        "ownerGid": int(metadata.st_gid),
        "mode": f"0{stat.S_IMODE(metadata.st_mode):03o}",
        "linkCount": int(metadata.st_nlink),
        "size": int(metadata.st_size),
    }
    if include_sha:
        value["sha256"] = sha256_file(path)
        after = os.lstat(path)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _fail("DATABASE_CHANGED_DURING_HASH", f"file changed while hashing: {path}")
    return value


def _create_exclusive_file(path: Path, *, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    os.close(descriptor)
    _sync_directory(path.parent)


def _verify_no_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        if os.path.lexists(os.fspath(path) + suffix):
            _fail("DATABASE_SIDECAR_PRESENT", f"unexpected SQLite sidecar: {suffix}")


def _sync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _full_fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _full_fsync(descriptor)
    finally:
        os.close(descriptor)


def _full_fsync(descriptor: int) -> None:
    os.fsync(descriptor)
    if sys.platform == "darwin":
        try:
            fcntl.fcntl(descriptor, 51)
        except OSError as error:
            _fail("FILESYSTEM_SYNC_FAILED", f"F_FULLFSYNC failed: {error}")


def _absolute(path: Path) -> Path:
    if not isinstance(path, Path):
        _fail("INVALID_MIGRATION_REQUEST", "path must be pathlib.Path")
    value = path.expanduser().absolute()
    if not value.is_absolute():
        _fail("INVALID_MIGRATION_REQUEST", "path must be absolute")
    return value


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: Any, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail("INVALID_MIGRATION_REQUEST", f"{name} must be 64 lowercase hex")


def _require_id(value: Any, prefix: str, suffix_length: int) -> None:
    if (
        type(value) is not str
        or len(value) != len(prefix) + suffix_length
        or not value.startswith(prefix)
        or any(character not in "0123456789abcdef" for character in value[len(prefix) :])
    ):
        _fail("INVALID_MIGRATION_REQUEST", f"identifier must use {prefix}<hex>")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _fail(code: str, message: str) -> None:
    raise MigrationV2Error(code, message)
