from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_SRC = REPO / "plugins" / "codex-smart-subagents" / "src"
SCHEMA_DIR = PLUGIN_SRC / "codex_smart_subagents" / "schema"
sys.path.insert(0, str(PLUGIN_SRC))


def _load_shape_generator():
    path = REPO / "scripts" / "validate_state_schema_artifacts.py"
    spec = importlib.util.spec_from_file_location("state_shape_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHAPES = _load_shape_generator()
MANIFEST = SHAPES.load_manifest(SCHEMA_DIR / "state-v2.manifest.json")
SOURCES = {
    name: SHAPES.git_source(commit, MANIFEST["sourcePath"])
    for name, commit in MANIFEST["sourceCommits"].items()
}
BASE_SCRIPTS = {
    "executionBase": SHAPES.split_sql_statements(
        SHAPES.extract_executescript(SOURCES["executionBase"], "_migrate")
    ),
    "candidateRegistry": SHAPES.split_sql_statements(
        SHAPES.extract_executescript(SOURCES["candidateRegistry"], "_migrate")
    ),
}
BINDING_ALTERS = SHAPES.extract_binding_alters(SOURCES["candidateRegistry"])
RUNTIME_SCRIPTS = SHAPES.split_sql_statements(
    SHAPES.extract_executescript(
        SOURCES["runtimeArtifacts"], "_ensure_runtime_artifacts_schema"
    )
)
CANDIDATE_SCRIPTS = SHAPES.split_sql_statements(
    SHAPES.extract_executescript(
        SOURCES["candidateRegistry"], "_ensure_candidate_registry_schema"
    )
)


def _shape(name: str) -> dict:
    return next(
        item
        for group in MANIFEST["legacyShapes"].values()
        for item in group
        if item["name"] == name
    )


def _legacy_file(path: Path, name: str) -> None:
    memory = SHAPES.generate_legacy_shape(
        _shape(name)["recipe"],
        base_scripts=BASE_SCRIPTS,
        binding_alters=BINDING_ALTERS,
        runtime_scripts=RUNTIME_SCRIPTS,
        candidate_scripts=CANDIDATE_SCRIPTS,
    )
    disk = sqlite3.connect(path)
    try:
        memory.backup(disk)
    finally:
        disk.close()
        memory.close()
    os.chmod(path, 0o600)


def _projection(path: Path) -> dict:
    from codex_smart_subagents.canonical_json import domain_fingerprint

    stat_result = path.stat()
    schema_path = REPO / "docs" / "contracts" / "schemas" / "lifecycle-projection-v2.schema.json"
    projection = {
        "schemaId": "quiescence-proof-v2",
        "schemaSha256": __import__("hashlib").sha256(schema_path.read_bytes()).hexdigest(),
        "value": {
            "proofKind": "legacy-migration",
            "legacyStateHome": os.fspath(path.parent),
            "legacyProcessSetFingerprint": "2" * 64,
            "targetProcess": {
                "pid": 4200,
                "processStartMarker": "darwin:101:1",
                "processGroupId": 4200,
                "ownerUid": os.getuid(),
            },
            "armedWatchdog": {
                "watchdogId": "wd2_" + "3" * 32,
                "pid": 4300,
                "processStartMarker": "darwin:102:1",
                "processGroupId": 4300,
                "state": "ARMED",
                "proofFingerprint": "4" * 64,
            },
            "gatewayFenceProofFingerprint": "5" * 64,
            "bridgeFenceProofFingerprint": "6" * 64,
            "databaseFile": {
                "path": os.fspath(path),
                "device": stat_result.st_dev,
                "inode": stat_result.st_ino,
                "ownerUid": stat_result.st_uid,
                "ownerGid": stat_result.st_gid,
                "mode": "0600",
                "linkCount": stat_result.st_nlink,
                "size": stat_result.st_size,
                "sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
            },
            "databaseIdentityFingerprint": "7" * 64,
            "databaseSnapshotFingerprint": "8" * 64,
            "exclusiveDatabaseLeaseProofFingerprint": "9" * 64,
            "externalBarrierProofFingerprint": "a" * 64,
            "workCounts": {
                "nonterminalRoutes": 0,
                "nonterminalNodes": 0,
                "activeAttempts": 0,
                "activeLeases": 0,
                "openIntents": 0,
                "inflightLaunchPermits": 0,
                "activeRuntimeArtifacts": 0,
                "pendingCandidatePublications": 0,
                "activeEvidenceJobs": 0,
                "queuedEvidenceJobs": 0,
            },
            "quiescent": True,
        },
        "valueFingerprint": "",
    }
    projection["valueFingerprint"] = domain_fingerprint(
        "codex-smart/journal-state/v2",
        {name: projection[name] for name in ("schemaId", "schemaSha256", "value")},
    )
    return projection


def _request(state_home: Path, source: Path):
    from codex_smart_subagents.state_migration_v2 import LegacyMigrationRequestV2

    return LegacyMigrationRequestV2(
        state_home=state_home,
        source_path=source,
        operation_id="op2_" + "1" * 32,
        activation_binding_nonce="2" * 64,
        activation_id="act2_" + "3" * 64,
        activation_fingerprint="4" * 64,
        controller_identity="5" * 64,
        compatibility_fingerprint="6" * 64,
        routing_policy_fingerprint="7" * 64,
        bundled_catalog_fingerprint="8" * 64,
        legacy_quiescence_proof=_projection(source),
        migration_time=datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc),
    )


class StateMigrationV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state_home = Path(self.temporary.name).resolve()
        os.chmod(self.state_home, 0o700)
        self.source = self.state_home / "smart-subagents.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_classifier_accepts_exactly_all_38_pinned_shapes(self) -> None:
        from codex_smart_subagents.state_migration_v2 import inspect_legacy_database

        for group_name, items in MANIFEST["legacyShapes"].items():
            for item in items:
                with self.subTest(group=group_name, shape=item["name"]):
                    path = self.state_home / f"{item['name']}.sqlite3"
                    _legacy_file(path, item["name"])
                    inspected = inspect_legacy_database(path)
                    self.assertEqual(item["name"], inspected.source_shape)
                    self.assertEqual(item["fingerprint"], inspected.schema_fingerprint)

    def test_quiescence_validation_works_from_an_isolated_installed_tree(self) -> None:
        _legacy_file(self.source, "v0-empty")
        isolated = self.state_home / "installed"
        shutil.copytree(
            PLUGIN_SRC / "codex_smart_subagents",
            isolated / "codex_smart_subagents",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        proof_path = self.state_home / "proof.json"
        proof_path.write_text(json.dumps(_projection(self.source)), encoding="utf-8")
        program = """
import builtins
import json
import sys
from pathlib import Path

real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "jsonschema" or name.startswith("jsonschema."):
        raise ImportError("jsonschema is unavailable in the installed runtime")
    return real_import(name, *args, **kwargs)

builtins.__import__ = guarded_import
sys.path.insert(0, sys.argv[1])
from codex_smart_subagents.state_migration_v2 import _validate_quiescence_projection

source = Path(sys.argv[2])
proof = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
_validate_quiescence_projection(proof, state_home=source.parent, source=source)
"""
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                program,
                os.fspath(isolated),
                os.fspath(self.source),
                os.fspath(proof_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_all_38_empty_pinned_shapes_build_a_v2_candidate(self) -> None:
        from codex_smart_subagents.state_migration_v2 import migrate_legacy_database

        for items in MANIFEST["legacyShapes"].values():
            for item in items:
                with self.subTest(shape=item["name"]):
                    state_home = self.state_home / item["name"]
                    state_home.mkdir(mode=0o700)
                    source = state_home / "smart-subagents.sqlite3"
                    _legacy_file(source, item["name"])
                    result = migrate_legacy_database(_request(state_home, source))
                    self.assertEqual(item["name"], result.source_shape)
                    with closing(sqlite3.connect(result.database_path)) as connection:
                        self.assertEqual(
                            (item["name"], item["fingerprint"]),
                            connection.execute(
                                "select source_shape,source_schema_fingerprint from database_identity"
                            ).fetchone(),
                        )

    def test_empty_v0_migration_is_private_atomic_and_idempotent(self) -> None:
        from codex_smart_subagents.schema_projection import database_schema_fingerprint
        from codex_smart_subagents.state_migration_v2 import migrate_legacy_database

        _legacy_file(self.source, "v0-empty")
        original = self.source.read_bytes()
        request = _request(self.state_home, self.source)
        first = migrate_legacy_database(request)
        second = migrate_legacy_database(replace(request, migration_time=datetime.now(timezone.utc)))

        self.assertFalse(first.reused)
        self.assertTrue(second.reused)
        self.assertEqual(first.database_id, second.database_id)
        self.assertEqual(first.database_path, second.database_path)
        self.assertEqual(original, self.source.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(first.database_path.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(first.backup_path.stat().st_mode))
        self.assertFalse(Path(os.fspath(first.backup_path) + "-wal").exists())
        self.assertFalse(Path(os.fspath(first.backup_path) + "-shm").exists())
        with closing(sqlite3.connect(first.database_path)) as connection, connection:
            self.assertEqual(2, connection.execute("pragma user_version").fetchone()[0])
            self.assertEqual(MANIFEST["schemaFingerprint"], database_schema_fingerprint(connection, version=2).fingerprint)
            self.assertEqual(1, connection.execute("select count(*) from schema_migrations").fetchone()[0])

    def test_nonempty_v0_and_unknown_schema_fail_closed(self) -> None:
        from codex_smart_subagents.state_migration_v2 import MigrationV2Error, migrate_legacy_database

        _legacy_file(self.source, "v0-old-base-p1")
        with closing(sqlite3.connect(self.source)) as connection, connection:
            connection.execute(
                "insert into turn_bindings(token_hash,context_hash,context_json,created_at,expires_at,consumed_at) values(?,?,?,?,?,?)",
                ("t", "h", "{}", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", None),
            )
        with self.assertRaises(MigrationV2Error) as caught:
            migrate_legacy_database(_request(self.state_home, self.source))
        self.assertEqual("LEGACY_PARTIAL_SCHEMA_HAS_DATA", caught.exception.code)

        self.source.unlink()
        _legacy_file(self.source, "v0-empty")
        with closing(sqlite3.connect(self.source)) as connection, connection:
            connection.execute("create table foreign_table(value text)")
        with self.assertRaises(MigrationV2Error) as caught:
            migrate_legacy_database(
                replace(
                    _request(self.state_home, self.source),
                    operation_id="op2_" + "2" * 32,
                )
            )
        self.assertEqual("UNKNOWN_V1_SCHEMA", caught.exception.code)

    def test_proof_checkpoint_and_recorded_backup_are_closed_contracts(self) -> None:
        from codex_smart_subagents.state_migration_v2 import MigrationV2Error, migrate_legacy_database

        _legacy_file(self.source, "v0-empty")
        request = _request(self.state_home, self.source)
        invalid_proof = dict(request.legacy_quiescence_proof)
        invalid_proof.pop("valueFingerprint")
        with self.assertRaises(MigrationV2Error) as caught:
            migrate_legacy_database(replace(request, legacy_quiescence_proof=invalid_proof))
        self.assertEqual("INVALID_QUIESCENCE_PROOF", caught.exception.code)

        result = migrate_legacy_database(
            replace(request, operation_id="op2_" + "3" * 32)
        )
        with result.backup_path.open("ab") as stream:
            stream.write(b"foreign")
        with self.assertRaises(MigrationV2Error) as caught:
            migrate_legacy_database(
                replace(request, operation_id="op2_" + "3" * 32)
            )
        self.assertEqual("RECORDED_BACKUP_CHANGED", caught.exception.code)

        other_home = self.state_home / "checkpoint"
        other_home.mkdir(mode=0o700)
        other_source = other_home / "smart-subagents.sqlite3"
        _legacy_file(other_source, "v0-empty")
        other_request = replace(
            _request(other_home, other_source), operation_id="op2_" + "4" * 32
        )
        migrate_legacy_database(other_request)
        checkpoint = other_home / "backups" / other_request.operation_id / "migration-v2.json"
        value = json.loads(checkpoint.read_text(encoding="utf-8"))
        value["status"] = "SNAPSHOT_READY"
        checkpoint.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(checkpoint, 0o600)
        with self.assertRaises(MigrationV2Error) as caught:
            migrate_legacy_database(other_request)
        self.assertEqual("INVALID_MIGRATION_CHECKPOINT", caught.exception.code)

    def test_sqlite_backup_reads_wal_without_changing_the_legacy_database(self) -> None:
        from codex_smart_subagents.state_migration_v2 import migrate_legacy_database

        _legacy_file(self.source, "execution-alter-binding-v1")
        writer = sqlite3.connect(self.source)
        try:
            self.assertEqual("wal", writer.execute("pragma journal_mode=WAL").fetchone()[0])
            writer.execute(
                "insert into turn_bindings values(?,?,?,?,?,?,?,?)",
                ("temporary", "hash", "{}", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", None, None, None),
            )
            writer.execute("delete from turn_bindings where token_hash='temporary'")
            writer.commit()
            source_before = self.source.read_bytes()
            wal_path = Path(os.fspath(self.source) + "-wal")
            wal_before = wal_path.read_bytes()
            result = migrate_legacy_database(_request(self.state_home, self.source))
            self.assertEqual("execution-alter-binding-v1", result.source_shape)
            self.assertEqual(source_before, self.source.read_bytes())
            self.assertEqual(wal_before, wal_path.read_bytes())
        finally:
            writer.close()

    def test_sqlite_backup_checks_the_shared_deadline_through_progress(self) -> None:
        from codex_smart_subagents import _state_migration_v2_database as database

        _legacy_file(self.source, "v0-empty")
        destination = self.state_home / "backup.sqlite3"

        with mock.patch.object(
            database,
            "checkpoint_current_operation_deadline_if_scoped_v2",
            return_value=None,
        ) as checkpoint:
            database.sqlite_backup(self.source, destination)

        self.assertGreaterEqual(checkpoint.call_count, 1)
        self.assertTrue(destination.is_file())

    def test_sqlite_backup_close_failures_do_not_mask_primary(self) -> None:
        from codex_smart_subagents import _state_migration_v2_database as database

        primary = RuntimeError("backup failed")
        destination_close_error = RuntimeError("destination close failed")
        source_close_error = RuntimeError("source close failed")

        class FakeConnection:
            def __init__(
                self,
                *,
                backup_error: BaseException | None = None,
                close_error: BaseException | None = None,
            ) -> None:
                self.backup_error = backup_error
                self.close_error = close_error
                self.close_calls = 0

            def execute(self, _sql: str):
                return self

            def fetchone(self):
                return ("delete",)

            def backup(self, _target, **_kwargs: object) -> None:
                if self.backup_error is not None:
                    raise self.backup_error

            def close(self) -> None:
                self.close_calls += 1
                if self.close_error is not None:
                    raise self.close_error

        source = FakeConnection(
            backup_error=primary,
            close_error=source_close_error,
        )
        destination = FakeConnection(close_error=destination_close_error)
        with (
            mock.patch.object(database, "_create_exclusive_file"),
            mock.patch.object(
                database,
                "_bounded_database_limits",
                return_value=(1.0, 1_000),
            ),
            mock.patch.object(
                database,
                "connect_sqlite_with_deadline_v2",
                side_effect=(source, destination),
            ),
            mock.patch.object(database, "_install_deadline_progress_handler"),
        ):
            with self.assertRaises(RuntimeError) as caught:
                database.sqlite_backup(Path("/source"), Path("/destination"))

        self.assertIs(primary, caught.exception)
        self.assertEqual(1, destination.close_calls)
        self.assertEqual(1, source.close_calls)
        notes = getattr(primary, "__notes__", ())
        self.assertTrue(any("destination close failed" in note for note in notes))
        self.assertTrue(any("source close failed" in note for note in notes))

    def test_sqlite_backup_raises_close_failure_after_closing_both_sides(
        self,
    ) -> None:
        from codex_smart_subagents import _state_migration_v2_database as database

        close_error = RuntimeError("destination close failed")

        class FakeConnection:
            def __init__(self, *, close_error: BaseException | None = None) -> None:
                self.close_error = close_error
                self.close_calls = 0

            def execute(self, _sql: str):
                return self

            def fetchone(self):
                return ("delete",)

            def backup(self, _target, **_kwargs: object) -> None:
                return None

            def close(self) -> None:
                self.close_calls += 1
                if self.close_error is not None:
                    raise self.close_error

        source = FakeConnection()
        destination = FakeConnection(close_error=close_error)
        with (
            mock.patch.object(database, "_create_exclusive_file"),
            mock.patch.object(
                database,
                "_bounded_database_limits",
                return_value=(1.0, 1_000),
            ),
            mock.patch.object(
                database,
                "connect_sqlite_with_deadline_v2",
                side_effect=(source, destination),
            ),
            mock.patch.object(database, "_install_deadline_progress_handler"),
            mock.patch.object(database, "_verify_sqlite_integrity"),
        ):
            with self.assertRaises(RuntimeError) as caught:
                database.sqlite_backup(Path("/source"), Path("/destination"))

        self.assertIs(close_error, caught.exception)
        self.assertEqual(1, destination.close_calls)
        self.assertEqual(1, source.close_calls)

    def test_read_only_database_close_does_not_mask_exact_primary(self) -> None:
        from codex_smart_subagents import _state_migration_v2_database as database

        primary = RuntimeError("read failed")
        close_error = RuntimeError("read-only close failed")

        class FakeConnection:
            def close(self) -> None:
                raise close_error

        with (
            mock.patch.object(
                database,
                "_open_read_only_database",
                return_value=FakeConnection(),
            ),
            self.assertRaises(RuntimeError) as caught,
        ):
            with database._read_only_database(Path("/source")):
                raise primary

        self.assertIs(primary, caught.exception)
        self.assertTrue(
            any(
                "read-only close failed" in note
                for note in getattr(primary, "__notes__", ())
            )
        )

    def test_read_only_database_close_failure_is_primary_without_read_error(
        self,
    ) -> None:
        from codex_smart_subagents import _state_migration_v2_database as database

        close_error = RuntimeError("read-only close failed")

        class FakeConnection:
            def close(self) -> None:
                raise close_error

        with (
            mock.patch.object(
                database,
                "_open_read_only_database",
                return_value=FakeConnection(),
            ),
            mock.patch.object(
                database,
                "checkpoint_current_operation_deadline_if_scoped_v2",
                return_value=None,
            ),
            self.assertRaises(RuntimeError) as caught,
        ):
            with database._read_only_database(Path("/source")):
                pass

        self.assertIs(close_error, caught.exception)

    def test_read_only_setup_close_does_not_mask_exact_read_error(self) -> None:
        from codex_smart_subagents import _state_migration_v2_database as database

        primary = sqlite3.OperationalError("read setup failed")
        close_error = RuntimeError("read-only setup close failed")

        class FakeConnection:
            row_factory = None

            def execute(self, _statement: str):
                raise primary

            def close(self) -> None:
                raise close_error

        with (
            mock.patch.object(
                database,
                "_bounded_database_limits",
                return_value=(1.0, 1_000),
            ),
            mock.patch.object(
                database,
                "connect_sqlite_with_deadline_v2",
                return_value=FakeConnection(),
            ),
            mock.patch.object(
                database,
                "checkpoint_current_operation_deadline_if_scoped_v2",
                return_value=None,
            ),
            mock.patch.object(database, "_install_deadline_progress_handler"),
            self.assertRaises(sqlite3.OperationalError) as caught,
        ):
            database._open_read_only_database(Path("/source"))

        self.assertIs(primary, caught.exception)
        self.assertTrue(
            any(
                "read-only setup close failed" in note
                for note in getattr(primary, "__notes__", ())
            )
        )

    def test_candidate_close_failures_do_not_mask_primary(self) -> None:
        from codex_smart_subagents import _state_migration_v2_copy as copy

        primary = RuntimeError("candidate build failed")
        target_close_error = RuntimeError("target close failed")
        source_close_error = RuntimeError("source close failed")

        class FakeConnection:
            row_factory = None

            def __init__(self, close_error: BaseException) -> None:
                self.close_error = close_error
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1
                raise self.close_error

        source = FakeConnection(source_close_error)
        target = FakeConnection(target_close_error)
        with (
            mock.patch.object(
                copy,
                "checkpoint_current_operation_deadline_if_scoped_v2",
            ),
            mock.patch.object(copy, "read_schema_artifact", return_value=""),
            mock.patch.object(copy, "_open_read_only_database", return_value=source),
            mock.patch.object(
                copy,
                "_bounded_database_limits",
                return_value=(1.0, 1_000),
            ),
            mock.patch.object(
                copy,
                "connect_sqlite_with_deadline_v2",
                return_value=target,
            ),
            mock.patch.object(copy, "_install_deadline_progress_handler"),
            mock.patch.object(copy, "_configure_target", side_effect=primary),
        ):
            with self.assertRaises(RuntimeError) as caught:
                copy.build_candidate_database(
                    source_path=Path("/source"),
                    target_path=Path("/target"),
                    checkpoint={},
                    request=mock.Mock(),
                    inspection=mock.Mock(),
                )

        self.assertIs(primary, caught.exception)
        self.assertEqual(1, target.close_calls)
        self.assertEqual(1, source.close_calls)
        notes = getattr(primary, "__notes__", ())
        self.assertTrue(any("target close failed" in note for note in notes))
        self.assertTrue(any("source close failed" in note for note in notes))

    def test_terminal_history_and_sequence_are_migrated_explicitly(self) -> None:
        from codex_smart_subagents.state_migration_v2 import (
            UNKNOWN_LEGACY_V1,
            migrate_legacy_database,
        )

        _legacy_file(self.source, "candidate-alter-p5")
        context = {
            "shellSessionId": "shell",
            "sessionId": "session",
            "turnId": "turn",
            "codexHome": "/private/codex",
            "repoRoot": "/private/repo",
            "baseSha": "c" * 40,
            "worktreeFingerprint": "d" * 64,
        }
        old_context = json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        old_projection = dict(context)
        old_projection["codexHomeHash"] = __import__("hashlib").sha256(context["codexHome"].encode()).hexdigest()
        old_projection["repoRootHash"] = __import__("hashlib").sha256(context["repoRoot"].encode()).hexdigest()
        old_projection.pop("codexHome")
        old_projection.pop("repoRoot")
        old_hash = __import__("hashlib").sha256(
            json.dumps(old_projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with closing(sqlite3.connect(self.source)) as connection, connection:
            connection.execute(
                "insert into turn_bindings values(?,?,?,?,?,?,?,?)",
                ("token", old_hash, old_context, "2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z", None, "request", "e" * 64),
            )
            connection.execute(
                "insert into routes values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "route1", "request", "e" * 64, old_hash, old_context, "shell", "session", "turn",
                    old_projection["codexHomeHash"], old_projection["repoRootHash"], "c" * 40, "d" * 64,
                    "catalog", "algorithm", "delegate", 1, "SUCCEEDED", "2026-01-01T01:00:00Z", "run1", None,
                    "{}", "{}", "2026-01-01T00:00:00Z", "2026-01-01T00:10:00Z",
                ),
            )
            connection.execute(
                "insert into nodes values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("route1", "node1", 0, "reader", "mission", "[]", "[]", "scope", "artifact", "validation", "{}", "[]", "gpt", "high", "read", "delegate", "SUCCEEDED", 1, "{}", "2026-01-01T00:10:00Z"),
            )
            connection.execute(
                "insert into events(sequence,route_id,node_id,event,state,code,message,created_at) values(?,?,?,?,?,?,?,?)",
                (41, "route1", "node1", "node_succeeded", "SUCCEEDED", "OK", "", "2026-01-01T00:10:00Z"),
            )
            connection.execute("delete from sqlite_sequence where name='events'")
            connection.execute("insert into sqlite_sequence(name,seq) values('events',80)")
            connection.execute(
                "insert into attempts values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("attempt1", "route1", "node1", "SUCCEEDED", "gpt", "high", "read", 1234, "a" * 64, "probe", None, "{}", None, None, "2026-01-01T00:01:00Z", "2026-01-01T00:09:00Z"),
            )
            connection.execute(
                "insert into intents values(?,?,?,?,?,?,?,?,?)",
                ("intent1", "route1", "node1", "audit", "f" * 64, "{}", "COMPLETED", "2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z"),
            )
            connection.execute(
                "insert into runtime_artifacts values(?,?,?,?,?,?,?,?,?,?,?)",
                ("runtime1", "route1", "node1", "workspace", "/private/artifact", "/private", "TERMINAL", 1, 2, "2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z"),
            )
            repository_id = "qr1_" + "1" * 43
            publication_id = "cpi1_" + "2" * 43
            artifact_id = "art1_" + "3" * 43
            candidate_id = "cand1_" + "4" * 43
            connection.execute(
                "insert into quarantine_repositories values(?,?,?,?,?,?,?)",
                (repository_id, "/private/source", "/private/state", "/private/git", "ACTIVE", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            connection.execute(
                "insert into candidate_publication_intents values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (publication_id, "route1", "node1", repository_id, artifact_id, "refs/codex/candidate", "1"*40, "2"*40, "3"*40, "4"*40, "5"*40, "COMPLETED", "2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z", "2026-01-01T00:02:00Z"),
            )
            connection.execute(
                "insert into candidate_registry values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (candidate_id, "route1", "node1", repository_id, publication_id, artifact_id, "refs/codex/candidate", "1"*40, "2"*40, "3"*40, "4"*40, "5"*40, "4"*40, "5"*40, "VERIFIED", "passed", "6"*64, 1, "2026-01-01T00:02:00Z", "2026-01-01T00:02:00Z"),
            )
        result = migrate_legacy_database(_request(self.state_home, self.source))
        with closing(sqlite3.connect(result.database_path)) as connection, connection:
            connection.row_factory = sqlite3.Row
            route = connection.execute("select * from routes").fetchone()
            binding = connection.execute("select * from turn_bindings").fetchone()
            attempt = connection.execute("select * from attempts").fetchone()
            permit = connection.execute("select * from node_launch_permits").fetchone()
            candidate_intent = connection.execute(
                "select * from candidate_publication_intents"
            ).fetchone()
            self.assertEqual(UNKNOWN_LEGACY_V1, route["activation_fingerprint"])
            self.assertEqual(route["context_hash"], binding["context_hash"])
            self.assertIsNotNone(binding["consumed_at"])
            self.assertEqual("V1_LEGACY", attempt["evidence_kind"])
            self.assertEqual("LEGACY_IMPORTED", permit["state"])
            self.assertEqual(attempt["launch_permit_id"], permit["permit_id"])
            self.assertEqual(
                "6" * 64,
                candidate_intent["validation_proof_sha256"],
            )
            self.assertEqual(80, connection.execute("select seq from sqlite_sequence where name='events'").fetchone()[0])
            for table in (
                "intents",
                "runtime_artifacts",
                "quarantine_repositories",
                "candidate_publication_intents",
                "candidate_registry",
            ):
                self.assertEqual(1, connection.execute(f"select count(*) from {table}").fetchone()[0])

    def test_virtual_planned_route_becomes_stale_but_active_route_is_rejected(self) -> None:
        from codex_smart_subagents.state_migration_v2 import MigrationV2Error, migrate_legacy_database

        for state, succeeds in (("PLANNED", True), ("RUNNING", False)):
            with self.subTest(state=state):
                path = self.state_home / f"{state}.sqlite3"
                _legacy_file(path, "execution-alter-binding-v1")
                context = {"shellSessionId":"s","sessionId":"x","turnId":"t","codexHome":"/c","repoRoot":"/r","baseSha":"a"*40,"worktreeFingerprint":"b"*64}
                raw = json.dumps(context, sort_keys=True, separators=(",", ":"))
                projection = {"shellSessionId":"s","sessionId":"x","turnId":"t","codexHomeHash":__import__("hashlib").sha256(b"/c").hexdigest(),"repoRootHash":__import__("hashlib").sha256(b"/r").hexdigest(),"baseSha":"a"*40,"worktreeFingerprint":"b"*64}
                old_hash = __import__("hashlib").sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        "insert into routes values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        ("r", "q", "c"*64, old_hash, raw, "s", "x", "t", projection["codexHomeHash"], projection["repoRootHash"], "a"*40, "b"*64, "cat", "alg", "delegate", 1, state, "2026-01-01T01:00:00Z", None, None, "{}", None, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
                    )
                    connection.execute(
                        "insert into nodes values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        ("r","n",0,"reader","m","[]","[]","s","a","v","{}","[]","gpt","low","read","delegate",state,0,None,"2026-01-01T00:00:00Z"),
                    )
                request = replace(_request(self.state_home, path), operation_id="op2_" + ("a" if succeeds else "b") * 32)
                if succeeds:
                    result = migrate_legacy_database(request)
                    with closing(sqlite3.connect(result.database_path)) as connection, connection:
                        self.assertEqual("STALE", connection.execute("select state from routes").fetchone()[0])
                        self.assertEqual("STALE", connection.execute("select state from nodes").fetchone()[0])
                        self.assertEqual(2, connection.execute("select count(*) from events").fetchone()[0])
                else:
                    with self.assertRaises(MigrationV2Error) as caught:
                        migrate_legacy_database(request)
                    self.assertEqual("ACTIVE_WORK_REMAINS", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
