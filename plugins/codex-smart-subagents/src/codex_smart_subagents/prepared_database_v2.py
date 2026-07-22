"""Заполнение заранее созданного файла базы без замены его inode.

Примитив обслуживает шаг ``database_prepare`` внешнего журнала. Историческая
проекция пустого файла разрешает ровно один запуск инициализатора, а стабильная
``database-binding-v2`` позволяет безопасно распознать уже завершённый шаг.
Размер и SHA-256 заполненной SQLite-базы намеренно не входят в живую привязку.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote

from .canonical_json import domain_fingerprint
from .lifecycle_operation_v2 import ProjectionV2
from .operation_deadline_v2 import OperationDeadlineExceededV2
from .schema_projection import APPLICATION_ID, database_schema_fingerprint
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2


DatabaseInitializerV2 = Callable[[Path], None]
_LIFECYCLE_SCHEMA_SHA256 = (
    "f9f03f8bd7437b48c65e027e582caf574cd1b85932941929d9a49ef30d91795d"
)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_SAFE_INTEGER_MAX = 9_007_199_254_740_991
_SQLITE_HEADER_PREFIX = b"SQLite format 3\x00"
_SQLITE_WAL_FORMAT = b"\x02\x02"
_FILE_KEYS = {
    "path",
    "device",
    "inode",
    "ownerUid",
    "ownerGid",
    "mode",
    "linkCount",
    "size",
    "sha256",
}
_BINDING_KEYS = {
    "path",
    "device",
    "inode",
    "ownerUid",
    "ownerGid",
    "mode",
    "linkCount",
    "databaseId",
    "databaseIdentity",
    "databaseIdentityFingerprint",
    "activationIdentity",
    "databaseVersion",
    "schemaVersion",
    "userVersion",
    "schemaFingerprint",
    "schemaArtifactSha256",
}
_DATABASE_IDENTITY_KEYS = {
    "databaseId",
    "activationBindingNonce",
    "activationId",
    "activationFingerprint",
}
_ACTIVATION_IDENTITY_KEYS = {"activationId", "activationFingerprint"}


@dataclass(frozen=True)
class PreparedDatabaseServiceIdentityV2:
    """Ожидаемая служебная идентичность базы до приёмки контроллера."""

    operation_id: str
    controller_identity: str
    compatibility_fingerprint: str
    routing_policy_fingerprint: str
    bundled_catalog_fingerprint: str


@dataclass
class PreparedDatabaseV2Error(RuntimeError):
    """Закрытый отказ шага ``database_prepare`` с машинным кодом."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class PreparedDatabaseStateV2(str, Enum):
    EMPTY = "EMPTY"
    RECOVERABLE = "RECOVERABLE"
    PREPARED = "PREPARED"


def observe_prepared_database_v2(
    *,
    database_path: Path,
    database_empty_file: ProjectionV2,
    database_binding_target: ProjectionV2,
    expected_service_identity: PreparedDatabaseServiceIdentityV2,
) -> tuple[PreparedDatabaseStateV2, ProjectionV2]:
    """Без записи различить точный пустой inode и полную готовую базу."""

    path = _validate_inputs(
        database_path=database_path,
        database_empty_file=database_empty_file,
        database_binding_target=database_binding_target,
        expected_service_identity=expected_service_identity,
        initializer=lambda _path: None,
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_FILE_UNAVAILABLE",
            "не удалось открыть ожидаемый файл базы без перехода по ссылке",
        ) from error
    try:
        observed = _verify_pinned_file(
            path,
            descriptor,
            expected=database_binding_target.value,
        )
        if observed.st_size == 0:
            _verify_live_empty_file(
                path,
                descriptor,
                database_empty_file=database_empty_file,
            )
            return PreparedDatabaseStateV2.EMPTY, database_empty_file
        if _sidecars_present(path):
            return (
                PreparedDatabaseStateV2.RECOVERABLE,
                _recoverable_file_projection(path, descriptor),
            )
        try:
            _verify_sqlite_binding(
                path,
                descriptor,
                database_binding_target=database_binding_target,
                expected_service_identity=expected_service_identity,
            )
        except PreparedDatabaseV2Error as error:
            if error.code != "DATABASE_PREPARE_AMBIGUOUS":
                raise
            return (
                PreparedDatabaseStateV2.RECOVERABLE,
                _recoverable_file_projection(path, descriptor),
            )
        _reject_sidecars(path)
        _verify_pinned_file(
            path,
            descriptor,
            expected=database_binding_target.value,
            replacement_code="DATABASE_FILE_REPLACED",
        )
        return PreparedDatabaseStateV2.PREPARED, database_binding_target
    finally:
        os.close(descriptor)


def prepare_database_v2(
    *,
    database_path: Path,
    database_empty_file: ProjectionV2,
    database_binding_target: ProjectionV2,
    expected_service_identity: PreparedDatabaseServiceIdentityV2,
    initializer: DatabaseInitializerV2,
    recover_interrupted: bool = False,
) -> ProjectionV2:
    """Заполнить доказанно пустой inode либо доказать завершённый результат.

    Инициализатор получает тот же абсолютный путь, обязан выполнить создание
    схемы и обеих строк-синглтонов одной SQLite-транзакцией, а затем закрыть
    все соединения до возврата. Он не должен использовать ``SmartStoreV2``:
    тот считает заранее существующий пустой файл уже созданной базой.

    Инициализатор вызывается только когда закреплённый inode всё ещё пуст.
    Уже заполненная база не изменяется и принимается лишь при полном совпадении
    со стабильной ``database-binding-v2``. Промежуточный непустой SQLite-файл
    по умолчанию неоднозначен. Только вызывающий слой с уже долговечным intent
    может включить ``recover_interrupted``: тогда SQLite сначала согласует WAL,
    а к пустому состоянию возвращается лишь тот же закреплённый inode без
    зафиксированных служебных таблиц.
    """

    path = _validate_inputs(
        database_path=database_path,
        database_empty_file=database_empty_file,
        database_binding_target=database_binding_target,
        expected_service_identity=expected_service_identity,
        initializer=initializer,
    )
    if type(recover_interrupted) is not bool:
        _fail(
            "INVALID_DATABASE_RECOVERY_MODE",
            "recover_interrupted должен быть логическим значением",
        )
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_FILE_UNAVAILABLE",
            "не удалось открыть ожидаемый файл базы без перехода по ссылке",
        ) from error

    try:
        before = _verify_pinned_file(
            path,
            descriptor,
            expected=database_binding_target.value,
        )
        should_initialize = before.st_size == 0
        if before.st_size != 0 and recover_interrupted:
            recovered = _recover_interrupted_database(
                path,
                descriptor,
                database_binding_target=database_binding_target,
                expected_service_identity=expected_service_identity,
            )
            if recovered is PreparedDatabaseStateV2.PREPARED:
                should_initialize = False
            elif recovered is PreparedDatabaseStateV2.EMPTY:
                should_initialize = True
            else:  # pragma: no cover - замкнуто внутренним перечислением
                _fail(
                    "DATABASE_RECOVERY_INVALID",
                    "восстановление вернуло недопустимое состояние",
                )
        if should_initialize:
            _verify_live_empty_file(
                path,
                descriptor,
                database_empty_file=database_empty_file,
            )
            try:
                initializer(path)
            except OperationDeadlineExceededV2:
                raise
            except Exception as error:
                raise PreparedDatabaseV2Error(
                    "DATABASE_INITIALIZER_FAILED",
                    "инициализатор базы завершился отказом",
                ) from error

            _verify_pinned_file(
                path,
                descriptor,
                expected=database_binding_target.value,
                replacement_code="DATABASE_FILE_REPLACED",
            )

        _sync_file_and_directory(path, descriptor)
        _reject_sidecars(path)
        _verify_sqlite_binding(
            path,
            descriptor,
            database_binding_target=database_binding_target,
            expected_service_identity=expected_service_identity,
        )
        _reject_sidecars(path)
        _verify_pinned_file(
            path,
            descriptor,
            expected=database_binding_target.value,
            replacement_code="DATABASE_FILE_REPLACED",
        )
        return database_binding_target
    finally:
        os.close(descriptor)


def _validate_inputs(
    *,
    database_path: Path,
    database_empty_file: ProjectionV2,
    database_binding_target: ProjectionV2,
    expected_service_identity: PreparedDatabaseServiceIdentityV2,
    initializer: DatabaseInitializerV2,
) -> Path:
    if not isinstance(database_path, Path) or not database_path.is_absolute():
        _fail("INVALID_DATABASE_PATH", "database_path должен быть абсолютным Path")
    if "\0" in str(database_path) or len(str(database_path).encode("utf-8")) > 4096:
        _fail("INVALID_DATABASE_PATH", "database_path имеет недопустимый вид")
    if not callable(initializer):
        _fail("INVALID_DATABASE_INITIALIZER", "initializer должен быть вызываемым")
    _validate_service_identity(expected_service_identity)

    _validate_projection(
        database_empty_file,
        schema_id="file-object-v2",
        domain="codex-smart/file-object/v2",
        code="DATABASE_EMPTY_PROOF_INVALID",
    )
    empty = database_empty_file.value
    _exact_keys(empty, _FILE_KEYS, "DATABASE_EMPTY_PROOF_INVALID")
    _validate_file_coordinates(empty, code="DATABASE_EMPTY_PROOF_INVALID")
    if (
        empty["path"] != str(database_path)
        or empty["mode"] != "0600"
        or empty["linkCount"] != 1
        or empty["size"] != 0
        or empty["sha256"] != _EMPTY_SHA256
        or empty["ownerUid"] != os.getuid()
    ):
        _fail(
            "DATABASE_EMPTY_PROOF_INVALID",
            "проекция не описывает точный пустой частный файл базы",
        )

    _validate_projection(
        database_binding_target,
        schema_id="database-binding-v2",
        domain="codex-smart/database-binding/v2",
        code="DATABASE_BINDING_TARGET_INVALID",
    )
    binding = database_binding_target.value
    _exact_keys(binding, _BINDING_KEYS, "DATABASE_BINDING_TARGET_INVALID")
    _validate_binding_value(binding)
    for name in (
        "path",
        "device",
        "inode",
        "ownerUid",
        "ownerGid",
        "mode",
        "linkCount",
    ):
        if binding[name] != empty[name]:
            _fail(
                "DATABASE_BINDING_TARGET_INVALID",
                "пустая проекция и целевая привязка закрепляют разные файлы",
            )
    if binding["path"] != str(database_path):
        _fail(
            "DATABASE_BINDING_TARGET_INVALID",
            "целевая привязка указывает на другой путь",
        )
    return database_path


def _validate_projection(
    projection: ProjectionV2,
    *,
    schema_id: str,
    domain: str,
    code: str,
) -> None:
    if not isinstance(projection, ProjectionV2):
        _fail(code, "передан иной тип проекции")
    if (
        projection.schema_id != schema_id
        or projection.schema_sha256 != _LIFECYCLE_SCHEMA_SHA256
        or type(projection.value) is not dict
        or type(projection.value_fingerprint) is not str
        or _SHA256.fullmatch(projection.value_fingerprint) is None
    ):
        _fail(code, "идентичность типизированной проекции не совпадает")
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    try:
        expected = domain_fingerprint(domain, envelope)
    except Exception as error:
        raise PreparedDatabaseV2Error(
            code, "значение проекции нельзя канонизировать"
        ) from error
    if projection.value_fingerprint != expected:
        _fail(code, "отпечаток типизированной проекции не совпадает")


def _validate_service_identity(value: PreparedDatabaseServiceIdentityV2) -> None:
    code = "DATABASE_SERVICE_IDENTITY_INVALID"
    if not isinstance(value, PreparedDatabaseServiceIdentityV2):
        _fail(code, "передан иной тип ожидаемой служебной идентичности")
    _identifier(value.operation_id, _OPERATION_ID, "operationId", code)
    _sha256(value.controller_identity, code)
    _sha256(value.compatibility_fingerprint, code)
    _sha256(value.routing_policy_fingerprint, code)
    _sha256(value.bundled_catalog_fingerprint, code)


def _validate_file_coordinates(value: Mapping[str, Any], *, code: str) -> None:
    path = value.get("path")
    if (
        type(path) is not str
        or not path
        or "\0" in path
        or len(path.encode("utf-8")) > 4096
        or not Path(path).is_absolute()
    ):
        _fail(code, "путь файловой проекции недопустим")
    for name in ("device", "inode", "ownerUid", "ownerGid", "linkCount", "size"):
        _safe_integer(value.get(name), name, code)
    mode = value.get("mode")
    if type(mode) is not str or re.fullmatch(r"0[0-7]{3}", mode) is None:
        _fail(code, "режим файловой проекции недопустим")
    if (
        type(value.get("sha256")) is not str
        or _SHA256.fullmatch(value["sha256"]) is None
    ):
        _fail(code, "SHA-256 файловой проекции недопустим")


def _validate_binding_value(binding: Mapping[str, Any]) -> None:
    code = "DATABASE_BINDING_TARGET_INVALID"
    path = binding.get("path")
    if (
        type(path) is not str
        or not path
        or "\0" in path
        or len(path.encode("utf-8")) > 4096
        or not Path(path).is_absolute()
    ):
        _fail(code, "путь привязки недопустим")
    for name in ("device", "inode", "ownerUid", "ownerGid", "linkCount"):
        _safe_integer(binding.get(name), name, code)
    if (
        binding.get("mode") != "0600"
        or binding.get("linkCount") != 1
        or binding.get("ownerUid") != os.getuid()
        or binding.get("databaseVersion") != "0.2.0"
        or binding.get("schemaVersion") != 2
        or binding.get("userVersion") != 2
    ):
        _fail(code, "стабильные параметры привязки недопустимы")
    _identifier(binding.get("databaseId"), _DATABASE_ID, "databaseId", code)
    _sha256(binding.get("databaseIdentityFingerprint"), code)
    _sha256(binding.get("schemaFingerprint"), code)
    _sha256(binding.get("schemaArtifactSha256"), code)

    identity = binding.get("databaseIdentity")
    _exact_keys(identity, _DATABASE_IDENTITY_KEYS, code)
    _identifier(identity.get("databaseId"), _DATABASE_ID, "databaseId", code)
    _sha256(identity.get("activationBindingNonce"), code)
    _identifier(identity.get("activationId"), _ACTIVATION_ID, "activationId", code)
    _sha256(identity.get("activationFingerprint"), code)
    activation = binding.get("activationIdentity")
    _exact_keys(activation, _ACTIVATION_IDENTITY_KEYS, code)
    _identifier(activation.get("activationId"), _ACTIVATION_ID, "activationId", code)
    _sha256(activation.get("activationFingerprint"), code)
    if (
        binding["databaseId"] != identity["databaseId"]
        or activation["activationId"] != identity["activationId"]
        or activation["activationFingerprint"] != identity["activationFingerprint"]
    ):
        _fail(code, "логические идентичности целевой привязки расходятся")
    if binding["databaseIdentityFingerprint"] != domain_fingerprint(
        "codex-smart/database-identity/v2", identity
    ):
        _fail(code, "отпечаток databaseIdentity не совпадает")


def _verify_live_empty_file(
    path: Path,
    descriptor: int,
    *,
    database_empty_file: ProjectionV2,
) -> None:
    info = _verify_pinned_file(path, descriptor, expected=database_empty_file.value)
    if info.st_size != 0 or _sha256_descriptor(descriptor) != _EMPTY_SHA256:
        _fail(
            "DATABASE_EMPTY_PROOF_MISMATCH",
            "закреплённый файл больше не совпадает с пустой проекцией",
        )


def _verify_pinned_file(
    path: Path,
    descriptor: int,
    *,
    expected: Mapping[str, Any],
    replacement_code: str = "DATABASE_FILE_IDENTITY_MISMATCH",
) -> os.stat_result:
    try:
        pinned = os.fstat(descriptor)
        current = os.lstat(path)
    except OSError as error:
        raise PreparedDatabaseV2Error(
            replacement_code, "ожидаемый путь базы исчез или недоступен"
        ) from error
    if (
        not stat.S_ISREG(pinned.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
    ):
        _fail(replacement_code, "путь базы больше не указывает на закреплённый inode")
    actual = {
        "path": str(path),
        "device": pinned.st_dev,
        "inode": pinned.st_ino,
        "ownerUid": pinned.st_uid,
        "ownerGid": pinned.st_gid,
        "mode": f"0{stat.S_IMODE(pinned.st_mode):03o}",
        "linkCount": pinned.st_nlink,
    }
    if any(actual[name] != expected[name] for name in actual):
        _fail(
            replacement_code,
            "тип, владелец, режим, число связей или inode базы изменились",
        )
    return pinned


def _sync_file_and_directory(path: Path, descriptor: int) -> None:
    try:
        os.fsync(descriptor)
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        parent_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_SYNC_FAILED", "не удалось синхронизировать файл базы"
        ) from error


def _sidecars_present(path: Path) -> bool:
    return any(os.path.lexists(f"{path}{suffix}") for suffix in ("-wal", "-shm"))


def _recoverable_file_projection(path: Path, descriptor: int) -> ProjectionV2:
    """Снять фактическую проекцию промежуточного закреплённого файла."""

    pinned = os.fstat(descriptor)
    info = _verify_pinned_file(
        path,
        descriptor,
        expected={
            "path": str(path),
            "device": pinned.st_dev,
            "inode": pinned.st_ino,
            "ownerUid": pinned.st_uid,
            "ownerGid": pinned.st_gid,
            "mode": f"0{stat.S_IMODE(pinned.st_mode):03o}",
            "linkCount": pinned.st_nlink,
        },
    )
    if (
        info.st_size <= 0
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        _fail(
            "DATABASE_RECOVERY_PROOF_INVALID",
            "промежуточный файл не является частным закреплённым файлом",
        )
    _validate_owned_sidecars(path)
    value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _sha256_descriptor(descriptor),
    }
    envelope = {
        "schemaId": "file-object-v2",
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    return ProjectionV2(
        schema_id="file-object-v2",
        schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
        value=value,
        value_fingerprint=domain_fingerprint(
            "codex-smart/file-object/v2", envelope
        ),
    )


def _recover_interrupted_database(
    path: Path,
    descriptor: int,
    *,
    database_binding_target: ProjectionV2,
    expected_service_identity: PreparedDatabaseServiceIdentityV2,
) -> PreparedDatabaseStateV2:
    """Согласовать только промежуточный результат уже долговечного intent."""

    _recoverable_file_projection(path, descriptor)
    try:
        connection = connect_sqlite_with_deadline_v2(
            path,
            isolation_level=None,
            timeout=5.0,
        )
        try:
            checkpoint = connection.execute(
                "pragma wal_checkpoint(TRUNCATE)"
            ).fetchone()
            if (
                checkpoint is None
                or len(checkpoint) != 3
                or int(checkpoint[0]) != 0
                or int(checkpoint[1]) != int(checkpoint[2])
            ):
                _fail(
                    "DATABASE_RECOVERY_BUSY",
                    "аварийный WAL нельзя полностью согласовать",
                )
        finally:
            connection.close()
    except PreparedDatabaseV2Error:
        raise
    except OperationDeadlineExceededV2:
        raise
    except (OSError, sqlite3.Error, ValueError) as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_RECOVERY_FAILED",
            "не удалось согласовать аварийное состояние SQLite",
        ) from error

    _unlink_checkpointed_sidecars(path)
    _verify_pinned_file(
        path,
        descriptor,
        expected=database_binding_target.value,
        replacement_code="DATABASE_FILE_REPLACED",
    )
    try:
        _verify_sqlite_binding(
            path,
            descriptor,
            database_binding_target=database_binding_target,
            expected_service_identity=expected_service_identity,
        )
    except PreparedDatabaseV2Error as error:
        if error.code != "DATABASE_PREPARE_AMBIGUOUS":
            raise
    else:
        return PreparedDatabaseStateV2.PREPARED

    if _database_contains_service_tables(path):
        _fail(
            "DATABASE_RECOVERY_AMBIGUOUS",
            "неполная база уже содержит служебные таблицы и не будет очищена",
        )
    try:
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
    except OSError as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_RECOVERY_FAILED",
            "не удалось вернуть закреплённый файл к пустой проекции",
        ) from error
    _sync_file_and_directory(path, descriptor)
    return PreparedDatabaseStateV2.EMPTY


def _database_contains_service_tables(path: Path) -> bool:
    try:
        connection = connect_sqlite_with_deadline_v2(
            f"file:{quote(str(path))}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
            timeout=1.0,
        )
        try:
            rows = connection.execute(
                "select name from sqlite_schema "
                "where type='table' and name in "
                "('database_identity','controller_state')"
            ).fetchall()
        finally:
            connection.close()
    except OperationDeadlineExceededV2:
        raise
    except (OSError, sqlite3.Error, ValueError) as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_RECOVERY_AMBIGUOUS",
            "промежуточную базу нельзя безопасно классифицировать",
        ) from error
    return bool(rows)


def _validate_owned_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not os.path.lexists(sidecar):
            continue
        try:
            info = sidecar.lstat()
        except OSError as error:
            raise PreparedDatabaseV2Error(
                "DATABASE_SIDECAR_INVALID",
                "служебный файл SQLite недоступен для проверки",
            ) from error
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            _fail(
                "DATABASE_SIDECAR_INVALID",
                "служебный файл SQLite не является частным обычным файлом",
            )


def _unlink_checkpointed_sidecars(path: Path) -> None:
    _validate_owned_sidecars(path)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not os.path.lexists(sidecar):
            continue
        try:
            sidecar.unlink()
        except OSError as error:
            raise PreparedDatabaseV2Error(
                "DATABASE_RECOVERY_FAILED",
                "не удалось убрать согласованный служебный файл SQLite",
            ) from error
    _reject_sidecars(path)


def _reject_sidecars(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        if os.path.lexists(f"{path}{suffix}"):
            _fail(
                "DATABASE_SIDECAR_PRESENT",
                f"после подготовки остался SQLite sidecar {suffix}",
            )


def _verify_sqlite_binding(
    path: Path,
    descriptor: int,
    *,
    database_binding_target: ProjectionV2,
    expected_service_identity: PreparedDatabaseServiceIdentityV2,
) -> None:
    target = database_binding_target.value
    before_verification = _verify_pinned_file(path, descriptor, expected=target)
    header_before = _read_sqlite_header(descriptor)
    try:
        # Этот путь вызывается только для закрытой подготовленной базы до её
        # публикации, пока эксклюзивная установочная операция исключает писателя.
        # immutable=1 не создаёт WAL sidecar при проверке, но его
        # ``pragma journal_mode`` сообщает DELETE даже для файла с постоянным
        # WAL. Поэтому режим читается из закреплённого SQLite-заголовка до и
        # после соединения. Так как immutable не отслеживает изменения,
        # закреплённый inode, размер и mtime тоже перепроверяются после закрытия.
        connection = connect_sqlite_with_deadline_v2(
            f"file:{quote(str(path))}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
            timeout=1.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("pragma query_only=ON")
            # SQLite schema_version — счётчик изменений схемы, а не прикладная
            # schemaVersion=2; поэтому закрепляем его неизменность вокруг
            # полного прикладного отпечатка схемы.
            sqlite_schema_version_before = _pragma_integer(connection, "schema_version")
            application_id = _pragma_integer(connection, "application_id")
            user_version = _pragma_integer(connection, "user_version")
            if [tuple(row) for row in connection.execute("pragma quick_check")] != [
                ("ok",)
            ]:
                _fail(
                    "DATABASE_INTEGRITY_FAILED",
                    "SQLite quick_check не вернул единственное значение ok",
                )
            if connection.execute("pragma foreign_key_check").fetchone() is not None:
                _fail(
                    "DATABASE_INTEGRITY_FAILED",
                    "SQLite foreign_key_check обнаружил нарушение",
                )
            schema = database_schema_fingerprint(connection, version=2)
            identity_rows = connection.execute(
                "select * from database_identity"
            ).fetchall()
            controller_rows = connection.execute(
                "select * from controller_state"
            ).fetchall()
            sqlite_schema_version_after = _pragma_integer(connection, "schema_version")
        finally:
            connection.close()
    except PreparedDatabaseV2Error:
        raise
    except OperationDeadlineExceededV2:
        raise
    except (OSError, sqlite3.Error, ValueError) as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_PREPARE_AMBIGUOUS",
            "непустой файл не является доказанной завершённой SQLite-базой",
        ) from error

    after_verification = _verify_pinned_file(path, descriptor, expected=target)
    header_after = _read_sqlite_header(descriptor)
    if (
        before_verification.st_size != after_verification.st_size
        or before_verification.st_mtime_ns != after_verification.st_mtime_ns
        or header_before != header_after
    ):
        _fail(
            "DATABASE_FILE_CHANGED",
            "подготовленная база изменилась во время immutable-проверки",
        )

    if (
        application_id != APPLICATION_ID
        or user_version != target["userVersion"]
        or sqlite_schema_version_before <= 0
        or sqlite_schema_version_after != sqlite_schema_version_before
        or schema.fingerprint != target["schemaFingerprint"]
    ):
        _fail(
            "DATABASE_PREPARE_AMBIGUOUS",
            "непустой файл имеет промежуточную версию или схему",
        )
    if len(identity_rows) != 1 or len(controller_rows) != 1:
        _fail(
            "DATABASE_PREPARE_AMBIGUOUS",
            "в непустой базе отсутствует завершённая пара строк-синглтонов",
        )

    identity_row = dict(identity_rows[0])
    controller_row = dict(controller_rows[0])
    identity = {
        "databaseId": identity_row.get("database_id"),
        "activationBindingNonce": identity_row.get("activation_binding_nonce"),
        "activationId": identity_row.get("activation_id"),
        "activationFingerprint": identity_row.get("activation_fingerprint"),
    }
    identity_fingerprint = domain_fingerprint(
        "codex-smart/database-identity/v2", identity
    )
    expected_identity_columns = {
        "singleton": 1,
        "database_id": target["databaseId"],
        "schema_version": target["schemaVersion"],
        "schema_fingerprint": target["schemaFingerprint"],
        "schema_artifact_sha256": target["schemaArtifactSha256"],
        "activation_binding_nonce": target["databaseIdentity"][
            "activationBindingNonce"
        ],
        "activation_id": target["activationIdentity"]["activationId"],
        "activation_fingerprint": target["activationIdentity"]["activationFingerprint"],
    }
    expected_controller_columns = {
        "singleton": 1,
        "database_id": target["databaseId"],
        "protocol_version": 2,
        "release": target["databaseVersion"],
        "activation_id": target["activationIdentity"]["activationId"],
        "activation_fingerprint": target["activationIdentity"]["activationFingerprint"],
    }
    if (
        any(
            identity_row.get(name) != value
            for name, value in expected_identity_columns.items()
        )
        or any(
            controller_row.get(name) != value
            for name, value in expected_controller_columns.items()
        )
        or identity != target["databaseIdentity"]
        or identity_fingerprint != target["databaseIdentityFingerprint"]
    ):
        _fail(
            "DATABASE_BINDING_MISMATCH",
            "database_identity или controller_state расходится с привязкой",
        )
    expected_database_service_columns = {
        "source_shape": "fresh-v2",
        "source_schema_fingerprint": None,
        "source_backup_sha256": None,
        "created_operation_id": expected_service_identity.operation_id,
    }
    expected_controller_service_columns = {
        "controller_identity": expected_service_identity.controller_identity,
        "instance_id": None,
        "controller_start_id": None,
        "controller_pid": None,
        "controller_process_start_marker": None,
        "controller_process_group_id": None,
        "control_epoch": 1,
        "state": "MAINTENANCE",
        "maintenance_mode": "FREEZE",
        "reason_code": "AWAITING_CONTROLLER_ACCEPT",
        "operation_id": expected_service_identity.operation_id,
        "compatibility_fingerprint": (
            expected_service_identity.compatibility_fingerprint
        ),
        "routing_policy_fingerprint": (
            expected_service_identity.routing_policy_fingerprint
        ),
        "bundled_catalog_fingerprint": (
            expected_service_identity.bundled_catalog_fingerprint
        ),
        "socket_path": None,
        "socket_device": None,
        "socket_inode": None,
        "socket_owner_uid": None,
        "socket_owner_gid": None,
        "socket_mode": None,
        "lock_held": 0,
        "accepting_new_routes": 0,
        "quiescent": 1,
    }
    if any(
        identity_row.get(name) != value
        for name, value in expected_database_service_columns.items()
    ) or any(
        controller_row.get(name) != value
        for name, value in expected_controller_service_columns.items()
    ):
        _fail(
            "DATABASE_SERVICE_IDENTITY_MISMATCH",
            "служебные строки базы не совпадают с намерением подготовки",
        )

    info = _verify_pinned_file(path, descriptor, expected=target)
    observed_value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "databaseId": identity_row["database_id"],
        "databaseIdentity": identity,
        "databaseIdentityFingerprint": identity_fingerprint,
        "activationIdentity": {
            "activationId": identity_row["activation_id"],
            "activationFingerprint": identity_row["activation_fingerprint"],
        },
        "databaseVersion": controller_row["release"],
        "schemaVersion": identity_row["schema_version"],
        "userVersion": user_version,
        "schemaFingerprint": schema.fingerprint,
        "schemaArtifactSha256": identity_row["schema_artifact_sha256"],
    }
    observed = {
        "schemaId": "database-binding-v2",
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": observed_value,
    }
    observed["valueFingerprint"] = domain_fingerprint(
        "codex-smart/database-binding/v2", observed
    )
    if observed != database_binding_target.to_document():
        _fail(
            "DATABASE_BINDING_MISMATCH",
            "собранная живая привязка не совпадает с целевой проекцией",
        )
    if header_after[18:20] != _SQLITE_WAL_FORMAT:
        _fail(
            "DATABASE_JOURNAL_MODE_INVALID",
            "подготовленная база не закреплена в режиме WAL",
        )


def _read_sqlite_header(descriptor: int) -> bytes:
    try:
        header = os.pread(descriptor, 20, 0)
    except OSError as error:
        raise PreparedDatabaseV2Error(
            "DATABASE_FILE_UNAVAILABLE",
            "не удалось прочитать закреплённый заголовок SQLite-базы",
        ) from error
    if len(header) != 20 or header[:16] != _SQLITE_HEADER_PREFIX:
        _fail(
            "DATABASE_PREPARE_AMBIGUOUS",
            "непустой файл не имеет полного заголовка SQLite",
        )
    return header


def _pragma_integer(connection: sqlite3.Connection, name: str) -> int:
    row = connection.execute(f"pragma {name}").fetchone()
    if row is None or type(row[0]) is not int:
        _fail("DATABASE_BINDING_MISMATCH", f"PRAGMA {name} не вернула целое")
    return int(row[0])


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def _exact_keys(value: Any, expected: set[str], code: str) -> None:
    if type(value) is not dict or set(value) != expected:
        _fail(code, "поля объекта не совпадают с закрытым контрактом")


def _safe_integer(value: Any, name: str, code: str) -> int:
    if type(value) is not int or not 0 <= value <= _SAFE_INTEGER_MAX:
        _fail(code, f"{name} не является безопасным неотрицательным целым")
    return value


def _sha256(value: Any, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code, "значение SHA-256 недопустимо")
    return value


def _identifier(value: Any, pattern: re.Pattern[str], name: str, code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, f"{name} имеет недопустимый вид")
    return value


def _fail(code: str, message: str) -> None:
    raise PreparedDatabaseV2Error(code, message)


__all__ = [
    "DatabaseInitializerV2",
    "PreparedDatabaseServiceIdentityV2",
    "PreparedDatabaseStateV2",
    "PreparedDatabaseV2Error",
    "observe_prepared_database_v2",
    "prepare_database_v2",
]
