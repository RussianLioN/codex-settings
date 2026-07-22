from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.canonical_json import domain_fingerprint  # noqa: E402
from codex_smart_subagents.lifecycle_operation_v2 import ProjectionV2  # noqa: E402
from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
)
from codex_smart_subagents.prepared_database_v2 import (  # noqa: E402
    PreparedDatabaseServiceIdentityV2,
    PreparedDatabaseStateV2,
    PreparedDatabaseV2Error,
    observe_prepared_database_v2,
    prepare_database_v2,
)
from codex_smart_subagents.schema_projection import APPLICATION_ID  # noqa: E402


LIFECYCLE_SCHEMA_SHA256 = (
    "f9f03f8bd7437b48c65e027e582caf574cd1b85932941929d9a49ef30d91795d"
)
DATABASE_ID = "db2_" + "1" * 32
ACTIVATION_ID = "act2_" + "2" * 64
ACTIVATION_FINGERPRINT = "3" * 64
ACTIVATION_NONCE = "4" * 64
OPERATION_ID = "op2_" + "5" * 32
CONTROLLER_IDENTITY = "6" * 64
COMPATIBILITY_FINGERPRINT = "7" * 64
ROUTING_POLICY_FINGERPRINT = "8" * 64
BUNDLED_CATALOG_FINGERPRINT = "9" * 64
SERVICE_IDENTITY = PreparedDatabaseServiceIdentityV2(
    operation_id=OPERATION_ID,
    controller_identity=CONTROLLER_IDENTITY,
    compatibility_fingerprint=COMPATIBILITY_FINGERPRINT,
    routing_policy_fingerprint=ROUTING_POLICY_FINGERPRINT,
    bundled_catalog_fingerprint=BUNDLED_CATALOG_FINGERPRINT,
)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SCHEMA_PATH = PLUGIN_SRC / "codex_smart_subagents" / "schema" / "state-v2.sql"
SCHEMA_MANIFEST_PATH = SCHEMA_PATH.with_name("state-v2.manifest.json")


def _projection(
    schema_id: str,
    value: dict[str, object],
    domain: str,
) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=LIFECYCLE_SCHEMA_SHA256,
        value=value,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _empty_file_projection(path: Path) -> ProjectionV2:
    info = path.lstat()
    return _projection(
        "file-object-v2",
        {
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
            "linkCount": info.st_nlink,
            "size": info.st_size,
            "sha256": EMPTY_SHA256,
        },
        "codex-smart/file-object/v2",
    )


def _binding_projection(path: Path) -> ProjectionV2:
    info = path.lstat()
    manifest = json.loads(SCHEMA_MANIFEST_PATH.read_text(encoding="utf-8"))
    identity = {
        "databaseId": DATABASE_ID,
        "activationBindingNonce": ACTIVATION_NONCE,
        "activationId": ACTIVATION_ID,
        "activationFingerprint": ACTIVATION_FINGERPRINT,
    }
    value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": "0600",
        "linkCount": 1,
        "databaseId": DATABASE_ID,
        "databaseIdentity": identity,
        "databaseIdentityFingerprint": domain_fingerprint(
            "codex-smart/database-identity/v2", identity
        ),
        "activationIdentity": {
            "activationId": ACTIVATION_ID,
            "activationFingerprint": ACTIVATION_FINGERPRINT,
        },
        "databaseVersion": "0.2.0",
        "schemaVersion": 2,
        "userVersion": 2,
        "schemaFingerprint": manifest["schemaFingerprint"],
        "schemaArtifactSha256": manifest["stateSqlSha256"],
    }
    return _projection(
        "database-binding-v2",
        value,
        "codex-smart/database-binding/v2",
    )


def _initializer(
    *,
    activation_nonce: str = ACTIVATION_NONCE,
    after: Callable[[Path], None] | None = None,
) -> Callable[[Path], None]:
    manifest = json.loads(SCHEMA_MANIFEST_PATH.read_text(encoding="utf-8"))

    def initialize(path: Path) -> None:
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            journal_mode = connection.execute("pragma journal_mode=WAL").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "wal":
                raise RuntimeError("test database did not enter WAL mode")
            connection.executescript(
                "BEGIN IMMEDIATE;\n" + SCHEMA_PATH.read_text(encoding="utf-8")
            )
            connection.execute(f"pragma application_id={APPLICATION_ID}")
            connection.execute("pragma user_version=2")
            connection.execute(
                "insert into database_identity "
                "(singleton,database_id,schema_version,schema_fingerprint,"
                "schema_artifact_sha256,activation_binding_nonce,activation_id,"
                "activation_fingerprint,source_shape,source_schema_fingerprint,"
                "source_backup_sha256,created_operation_id,created_at) "
                "values(1,?,?,?,?,?,?,?,'fresh-v2',null,null,?,?)",
                (
                    DATABASE_ID,
                    2,
                    manifest["schemaFingerprint"],
                    manifest["stateSqlSha256"],
                    activation_nonce,
                    ACTIVATION_ID,
                    ACTIVATION_FINGERPRINT,
                    OPERATION_ID,
                    "2026-07-19T12:00:00.000000Z",
                ),
            )
            connection.execute(
                "insert into controller_state "
                "(singleton,database_id,protocol_version,release,controller_identity,"
                "instance_id,controller_start_id,controller_pid,"
                "controller_process_start_marker,controller_process_group_id,"
                "control_epoch,state,maintenance_mode,reason_code,operation_id,"
                "activation_id,activation_fingerprint,compatibility_fingerprint,"
                "routing_policy_fingerprint,bundled_catalog_fingerprint,socket_path,"
                "socket_device,socket_inode,socket_owner_uid,socket_owner_gid,"
                "socket_mode,lock_held,accepting_new_routes,quiescent,updated_at) "
                "values(1,?,2,'0.2.0',?,null,null,null,null,null,1,'MAINTENANCE',"
                "'FREEZE','AWAITING_CONTROLLER_ACCEPT',?,?,?, ?,?,?,null,null,null,"
                "null,null,null,0,0,1,?)",
                (
                    DATABASE_ID,
                    CONTROLLER_IDENTITY,
                    OPERATION_ID,
                    ACTIVATION_ID,
                    ACTIVATION_FINGERPRINT,
                    COMPATIBILITY_FINGERPRINT,
                    ROUTING_POLICY_FINGERPRINT,
                    BUNDLED_CATALOG_FINGERPRINT,
                    "2026-07-19T12:00:00.000000Z",
                ),
            )
            connection.execute("COMMIT")
            checkpoint = connection.execute(
                "pragma wal_checkpoint(TRUNCATE)"
            ).fetchone()
            if (
                checkpoint is None
                or len(checkpoint) != 3
                or checkpoint[0] != 0
                or checkpoint[1] != checkpoint[2]
            ):
                raise RuntimeError("test database WAL checkpoint did not complete")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        if after is not None:
            after(path)

    return initialize


class PreparedDatabaseV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.database_path = self.root / "smart-subagents.sqlite3"
        descriptor = os.open(
            self.database_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600,
        )
        os.close(descriptor)
        self.empty = _empty_file_projection(self.database_path)
        self.binding = _binding_projection(self.database_path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _assert_recovery_rejects_service_mutation(
        self,
        statement: str,
        value: str,
    ) -> None:
        prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(statement, (value,))
            connection.commit()
        finally:
            connection.close()
        calls = 0

        def forbidden_initializer(path: Path) -> None:
            del path
            nonlocal calls
            calls += 1

        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=forbidden_initializer,
            )

        self.assertEqual("DATABASE_SERVICE_IDENTITY_MISMATCH", captured.exception.code)
        self.assertEqual(0, calls)

    def test_initializer_preserves_the_exact_operation_deadline(self) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_OPERATION_EXPIRED",
            operation="apply",
            phase="database-initializer",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )

        with self.assertRaises(OperationDeadlineExceededV2) as caught:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=lambda _path: (_ for _ in ()).throw(original),
            )

        self.assertIs(original, caught.exception)

    def test_initializer_populates_the_precreated_inode(self) -> None:
        before = self.database_path.stat()
        calls = 0

        def initialize(path: Path) -> None:
            nonlocal calls
            calls += 1
            _initializer()(path)

        result = prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=initialize,
        )

        after = self.database_path.stat()
        self.assertIs(result, self.binding)
        self.assertEqual(1, calls)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertGreater(after.st_size, 0)
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())

    def test_closed_wal_database_rechecks_without_creating_sidecars(self) -> None:
        prepared = prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
        )
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())
        first_state, first_observed = observe_prepared_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
        )
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())
        second_state, second_observed = observe_prepared_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
        )

        self.assertIs(prepared, self.binding)
        self.assertEqual(PreparedDatabaseStateV2.PREPARED, first_state)
        self.assertEqual(PreparedDatabaseStateV2.PREPARED, second_state)
        self.assertEqual(self.binding, first_observed)
        self.assertEqual(self.binding, second_observed)
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())

    def test_database_switched_back_to_delete_is_not_prepared(self) -> None:
        prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
        )
        with closing(sqlite3.connect(self.database_path, isolation_level=None)) as connection:
            journal_mode = connection.execute(
                "pragma journal_mode=DELETE"
            ).fetchone()
        self.assertEqual("delete", str(journal_mode[0]).lower())
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())

        with self.assertRaises(PreparedDatabaseV2Error) as observed:
            observe_prepared_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
            )
        self.assertEqual("DATABASE_JOURNAL_MODE_INVALID", observed.exception.code)

        calls = 0

        def forbidden_initializer(path: Path) -> None:
            del path
            nonlocal calls
            calls += 1

        with self.assertRaises(PreparedDatabaseV2Error) as prepared:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=forbidden_initializer,
            )
        self.assertEqual("DATABASE_JOURNAL_MODE_INVALID", prepared.exception.code)
        self.assertEqual(0, calls)

    def test_already_complete_database_is_proved_without_reinitializing(self) -> None:
        prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
        )
        before = self.database_path.read_bytes()
        calls = 0

        def forbidden_initializer(path: Path) -> None:
            del path
            nonlocal calls
            calls += 1
            raise AssertionError("initializer must not run during recovery")

        result = prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=forbidden_initializer,
        )

        self.assertIs(result, self.binding)
        self.assertEqual(0, calls)
        self.assertEqual(before, self.database_path.read_bytes())

    def test_initializer_replacing_the_precreated_inode_is_rejected(self) -> None:
        def replace_then_initialize(path: Path) -> None:
            path.unlink()
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
            _initializer()(path)

        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=replace_then_initialize,
            )

        self.assertEqual("DATABASE_FILE_REPLACED", captured.exception.code)

    def test_wrong_empty_file_proof_is_rejected_before_initializer(self) -> None:
        wrong_value = {**self.empty.value, "sha256": "f" * 64}
        wrong = _projection(
            "file-object-v2",
            wrong_value,
            "codex-smart/file-object/v2",
        )
        calls = 0

        def initialize(path: Path) -> None:
            del path
            nonlocal calls
            calls += 1

        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=wrong,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=initialize,
            )

        self.assertEqual("DATABASE_EMPTY_PROOF_INVALID", captured.exception.code)
        self.assertEqual(0, calls)
        self.assertEqual(0, self.database_path.stat().st_size)

    def test_wrong_database_identity_is_rejected(self) -> None:
        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=_initializer(activation_nonce="a" * 64),
            )

        self.assertEqual("DATABASE_BINDING_MISMATCH", captured.exception.code)

    def test_foreign_created_operation_is_rejected(self) -> None:
        self._assert_recovery_rejects_service_mutation(
            "update database_identity set created_operation_id=? where singleton=1",
            "op2_" + "a" * 32,
        )

    def test_foreign_controller_operation_is_rejected(self) -> None:
        self._assert_recovery_rejects_service_mutation(
            "update controller_state set operation_id=? where singleton=1",
            "op2_" + "a" * 32,
        )

    def test_foreign_controller_identity_is_rejected(self) -> None:
        self._assert_recovery_rejects_service_mutation(
            "update controller_state set controller_identity=? where singleton=1",
            "a" * 64,
        )

    def test_foreign_compatibility_fingerprint_is_rejected(self) -> None:
        self._assert_recovery_rejects_service_mutation(
            "update controller_state set compatibility_fingerprint=? where singleton=1",
            "a" * 64,
        )

    def test_partial_sqlite_file_is_ambiguous_and_not_reinitialized(self) -> None:
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("create table partial(value text)")
            connection.commit()
        finally:
            connection.close()
        calls = 0

        def initialize(path: Path) -> None:
            del path
            nonlocal calls
            calls += 1

        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=initialize,
            )

        self.assertEqual("DATABASE_PREPARE_AMBIGUOUS", captured.exception.code)
        self.assertEqual(0, calls)

    def test_leftover_sqlite_sidecar_is_rejected(self) -> None:
        def create_sidecar(path: Path) -> None:
            sidecar = Path(f"{path}-wal")
            sidecar.write_bytes(b"unexpected")
            os.chmod(sidecar, 0o600)

        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=_initializer(after=create_sidecar),
            )

        self.assertEqual("DATABASE_SIDECAR_PRESENT", captured.exception.code)

    def test_interrupted_wal_transaction_is_observed_and_recovered_after_intent(
        self,
    ) -> None:
        before = self.database_path.stat()
        interrupted = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import os,sqlite3,sys;"
                    "connection=sqlite3.connect(sys.argv[1],isolation_level=None);"
                    "connection.execute('pragma journal_mode=WAL');"
                    "connection.execute('BEGIN IMMEDIATE');"
                    "connection.execute('create table interrupted(value text)');"
                    "os._exit(91)"
                ),
                str(self.database_path),
            ],
            check=False,
        )
        self.assertEqual(91, interrupted.returncode)
        self.assertTrue(Path(f"{self.database_path}-wal").exists())

        state, observed = observe_prepared_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
        )
        self.assertEqual(PreparedDatabaseStateV2.RECOVERABLE, state)
        self.assertEqual("file-object-v2", observed.schema_id)
        self.assertGreater(observed.value["size"], 0)

        result = prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
            recover_interrupted=True,
        )

        after = self.database_path.stat()
        self.assertIs(self.binding, result)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())

    def test_committed_wal_is_checkpointed_instead_of_reinitialized(self) -> None:
        prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
        )
        interrupted = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                (
                    "import os,sqlite3,sys;"
                    "connection=sqlite3.connect(sys.argv[1],isolation_level=None);"
                    "connection.execute(\"update controller_state "
                    "set updated_at='2026-07-19T12:00:00.000000Z' "
                    "where singleton=1\");"
                    "os._exit(92)"
                ),
                str(self.database_path),
            ],
            check=False,
        )
        self.assertEqual(92, interrupted.returncode)
        self.assertTrue(Path(f"{self.database_path}-wal").exists())
        calls = 0

        def forbidden_initializer(_path: Path) -> None:
            nonlocal calls
            calls += 1

        result = prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=forbidden_initializer,
            recover_interrupted=True,
        )

        self.assertIs(self.binding, result)
        self.assertEqual(0, calls)
        self.assertFalse(Path(f"{self.database_path}-wal").exists())
        self.assertFalse(Path(f"{self.database_path}-shm").exists())

    def test_recovery_never_truncates_a_committed_service_identity_mismatch(
        self,
    ) -> None:
        prepare_database_v2(
            database_path=self.database_path,
            database_empty_file=self.empty,
            database_binding_target=self.binding,
            expected_service_identity=SERVICE_IDENTITY,
            initializer=_initializer(),
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "update controller_state set controller_identity=? where singleton=1",
                ("a" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        before = self.database_path.read_bytes()

        with self.assertRaises(PreparedDatabaseV2Error) as captured:
            prepare_database_v2(
                database_path=self.database_path,
                database_empty_file=self.empty,
                database_binding_target=self.binding,
                expected_service_identity=SERVICE_IDENTITY,
                initializer=lambda _path: self.fail("must not reinitialize"),
                recover_interrupted=True,
            )

        self.assertEqual(
            "DATABASE_SERVICE_IDENTITY_MISMATCH",
            captured.exception.code,
        )
        self.assertEqual(before, self.database_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
