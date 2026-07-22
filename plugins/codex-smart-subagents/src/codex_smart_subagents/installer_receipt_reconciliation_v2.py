"""Восстанавливаемое доведение квитанции установщика после commit версии 2.

Основная операция сначала фиксирует манифест, квитанцию активации и отсутствие
журнала. Отдельная квитанция установщика является производной от этого уже
зафиксированного состояния. Этот модуль заменяет её только при точном
совпадении прежней активации, новой commit-квитанции и внешней регистрации.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .canonical_json import canonical_json_bytes, domain_fingerprint
from .operation_deadline_v2 import (
    checkpoint_current_operation_deadline_if_scoped_v2,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_COMMIT_DOMAIN = "codex-smart/activation-commit-receipt/v2"
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_INSTALLER_KEYS = {
    "schemaVersion",
    "kind",
    "sourceDigest",
    "installationId",
    "activationId",
    "codexHome",
    "codexBinary",
    "stateHome",
    "marketplacePath",
    "registeredMarketplacePath",
    "links",
    "marketplaceName",
    "pluginId",
    "extensions",
}
_COMMIT_KEYS = {
    "schemaVersion",
    "receiptKind",
    "installationId",
    "operationId",
    "frozenJournalFingerprint",
    "manifest",
    "manifestDocument",
    "transitionLineage",
    "activation",
    "databaseBinding",
    "journalAbsenceTarget",
    "controllerIdentity",
    "completedStepIds",
    "completedAt",
    "receiptFingerprint",
}
_INSTALLER_MUTABLE_KEYS = {
    "sourceDigest",
    "activationId",
    "codexBinary",
    "registeredMarketplacePath",
}


@dataclass
class InstallerReceiptReconciliationV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class InstallerReceiptReconciliationResultV2:
    status: str
    installation_id: str
    operation_id: str
    activation_id: str
    source_digest: str


def reconcile_installer_receipt_v2(
    *,
    receipt_path: Path,
    manifest_path: Path,
    commit_receipt_path: Path,
    operation_journal_path: Path,
    expected_receipt: Mapping[str, Any],
    verify_external_state: Callable[[], object],
) -> InstallerReceiptReconciliationResultV2:
    """Точно заменить старую квитанцию или подтвердить уже доведённую.

    Вызывающая сторона должна удерживать общую установочную блокировку.
    ``verify_external_state`` обязан заново проверить рынок, подключаемый модуль
    и стабильные оболочки; ложное значение считается отказом.
    """

    for name, path in (
        ("receipt_path", receipt_path),
        ("manifest_path", manifest_path),
        ("commit_receipt_path", commit_receipt_path),
        ("operation_journal_path", operation_journal_path),
    ):
        _absolute(path, name)
    if not callable(verify_external_state):
        raise TypeError("verify_external_state must be callable")
    expected = _installer_receipt(expected_receipt, "EXPECTED_RECEIPT_INVALID")
    manifest_raw, manifest, manifest_info = _read_private_canonical(
        manifest_path, "COMMITTED_MANIFEST_INVALID"
    )
    commit_raw, commit, _commit_info = _read_private_canonical(
        commit_receipt_path, "COMMIT_RECEIPT_INVALID"
    )
    del commit_raw
    identity = _validate_committed_state(
        manifest_path=manifest_path,
        manifest_raw=manifest_raw,
        manifest_info=manifest_info,
        manifest=manifest,
        commit=commit,
        operation_journal_path=operation_journal_path,
        expected=expected,
    )

    external_result = verify_external_state()
    if external_result is False:
        _fail(
            "EXTERNAL_STATE_MISMATCH",
            "внешняя регистрация не совпала с зафиксированной активацией",
        )

    current_raw, current_document, current_info = _read_private_canonical(
        receipt_path, "INSTALLER_RECEIPT_CURRENT_INVALID"
    )
    current = _installer_receipt(
        current_document, "INSTALLER_RECEIPT_CURRENT_INVALID"
    )
    expected_raw = canonical_json_bytes(expected)
    if current_raw == expected_raw and current == expected:
        _fsync_directory(receipt_path.parent)
        return _result("ALREADY_RECONCILED", identity)

    _validate_previous_receipt(current=current, expected=expected, manifest=manifest)
    parent_before = _private_directory(receipt_path.parent)
    temporary_name = f".{receipt_path.name}.reconcile-{secrets.token_hex(16)}"
    parent_descriptor = os.open(
        receipt_path.parent,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor = -1
    try:
        opened_parent = os.fstat(parent_descriptor)
        if (
            _identity(opened_parent) != _identity(parent_before)
            or not stat.S_ISDIR(opened_parent.st_mode)
            or opened_parent.st_uid != os.getuid()
            or stat.S_IMODE(opened_parent.st_mode) != 0o700
        ):
            _fail(
                "INSTALLER_RECEIPT_PARENT_CHANGED",
                "открыт иной родитель квитанции",
            )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        view = memoryview(expected_raw)
        while view:
            checkpoint_current_operation_deadline_if_scoped_v2()
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        staged_raw, staged = _read_private_canonical_at(
            parent_descriptor,
            temporary_name,
            "INSTALLER_RECEIPT_STAGE_INVALID",
        )
        if staged_raw != expected_raw or staged != expected:
            _fail(
                "INSTALLER_RECEIPT_STAGE_INVALID",
                "временная квитанция отличается от ожидаемой",
            )
        _require_unchanged_current(
            receipt_path,
            raw=current_raw,
            document=current,
            information=current_info,
        )
        parent_now = _private_directory(receipt_path.parent)
        if _identity(parent_now) != _identity(parent_before):
            _fail(
                "INSTALLER_RECEIPT_PARENT_CHANGED",
                "родитель квитанции был заменён",
            )
        os.replace(
            temporary_name,
            receipt_path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        _fsync_directory_fd(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)

    observed_raw, observed, observed_info = _read_private_canonical(
        receipt_path, "INSTALLER_RECEIPT_RECONCILE_FAILED"
    )
    if (
        observed_raw != expected_raw
        or observed != expected
        or stat.S_IMODE(observed_info.st_mode) != 0o600
    ):
        _fail(
            "INSTALLER_RECEIPT_RECONCILE_FAILED",
            "опубликованная квитанция отличается от ожидаемой",
        )
    return _result("RECONCILED", identity)


def _validate_committed_state(
    *,
    manifest_path: Path,
    manifest_raw: bytes,
    manifest_info: os.stat_result,
    manifest: Mapping[str, Any],
    commit: Mapping[str, Any],
    operation_journal_path: Path,
    expected: Mapping[str, Any],
) -> dict[str, str]:
    active = manifest.get("activeActivation")
    previous = manifest.get("previousActivation")
    extensions = manifest.get("extensions")
    installation_id = manifest.get("installationId")
    operation_id = manifest.get("lastCommittedOperation")
    activation_id = None if type(active) is not dict else active.get("activationId")
    previous_id = (
        None if type(previous) is not dict else previous.get("activationId")
    )
    source_digest = (
        None
        if type(extensions) is not dict
        else extensions.get("installerSourceDigest")
    )
    source_locator = manifest.get("sourceLocator")
    lexical_codex = (
        source_locator.get("lexicalPath")
        if type(source_locator) is dict
        else None
    )
    if (
        manifest.get("schemaVersion") != 2
        or type(installation_id) is not str
        or _INSTALLATION_ID.fullmatch(installation_id) is None
        or type(operation_id) is not str
        or _OPERATION_ID.fullmatch(operation_id) is None
        or type(activation_id) is not str
        or _ACTIVATION_ID.fullmatch(activation_id) is None
        or type(previous_id) is not str
        or _ACTIVATION_ID.fullmatch(previous_id) is None
        or type(source_digest) is not str
        or _SHA256.fullmatch(source_digest) is None
        or expected["installationId"] != installation_id
        or expected["activationId"] != activation_id
        or expected["sourceDigest"] != source_digest
        or expected["codexBinary"] != lexical_codex
    ):
        _fail(
            "COMMITTED_MANIFEST_INVALID",
            "манифест не связывает ожидаемую квитанцию",
        )
    if set(commit) != _COMMIT_KEYS:
        _fail("COMMIT_RECEIPT_INVALID", "набор полей commit-квитанции неверен")
    unsigned = {
        name: copy.deepcopy(value)
        for name, value in commit.items()
        if name != "receiptFingerprint"
    }
    if (
        commit.get("schemaVersion") != 2
        or commit.get("receiptKind") != "activation-commit"
        or commit.get("installationId") != installation_id
        or commit.get("operationId") != operation_id
        or commit.get("receiptFingerprint")
        != domain_fingerprint(_COMMIT_DOMAIN, unsigned)
    ):
        _fail("COMMIT_RECEIPT_INVALID", "отпечаток или идентичность расходятся")
    manifest_projection = commit.get("manifest")
    activation_projection = commit.get("activation")
    if type(manifest_projection) is not dict or type(activation_projection) is not dict:
        _fail("COMMIT_RECEIPT_INVALID", "проекции commit-квитанции отсутствуют")
    manifest_value = manifest_projection.get("value")
    activation_value = activation_projection.get("value")
    file_value = None if type(manifest_value) is not dict else manifest_value.get("file")
    if (
        manifest_projection.get("schemaId") != "manifest-v2"
        or activation_projection.get("schemaId") != "activation-v2"
        or type(manifest_value) is not dict
        or type(activation_value) is not dict
        or type(file_value) is not dict
        or manifest_value.get("installationId") != installation_id
        or manifest_value.get("activeActivationId") != activation_id
        or manifest_value.get("previousActivationId") != previous_id
        or manifest_value.get("lastCommittedOperation") != operation_id
        or activation_value.get("activationId") != activation_id
        or not _file_projection_matches(
            file_value,
            path=manifest_path,
            raw=manifest_raw,
            information=manifest_info,
        )
    ):
        _fail(
            "COMMIT_RECEIPT_INVALID",
            "commit-квитанция не связана с текущим манифестом",
        )
    _verify_journal_absence(
        commit.get("journalAbsenceTarget"),
        path=operation_journal_path,
        installation_id=installation_id,
        operation_id=operation_id,
    )
    return {
        "installationId": installation_id,
        "operationId": operation_id,
        "activationId": activation_id,
        "sourceDigest": source_digest,
    }


def _validate_previous_receipt(
    *,
    current: Mapping[str, Any],
    expected: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    previous = manifest.get("previousActivation")
    previous_id = None if type(previous) is not dict else previous.get("activationId")
    immutable = _INSTALLER_KEYS.difference(_INSTALLER_MUTABLE_KEYS)
    if (
        current.get("installationId") != expected.get("installationId")
        or current.get("activationId") != previous_id
        or current.get("sourceDigest") == expected.get("sourceDigest")
        or any(current.get(name) != expected.get(name) for name in immutable)
    ):
        _fail(
            "INSTALLER_RECEIPT_CURRENT_MISMATCH",
            "текущая квитанция не принадлежит предыдущей активации",
        )


def _installer_receipt(value: Mapping[str, Any], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code, "квитанция должна быть объектом")
    document = copy.deepcopy(dict(value))
    links = document.get("links")
    if (
        set(document) != _INSTALLER_KEYS
        or document.get("schemaVersion") != 2
        or document.get("kind") != "codex-smart-installer-receipt/v2"
        or _SHA256.fullmatch(str(document.get("sourceDigest"))) is None
        or _INSTALLATION_ID.fullmatch(str(document.get("installationId"))) is None
        or _ACTIVATION_ID.fullmatch(str(document.get("activationId"))) is None
        or document.get("marketplaceName") != "codex-settings-adaptive"
        or document.get("pluginId")
        != "codex-smart-subagents@codex-settings-adaptive"
        or document.get("extensions") != {}
        or type(links) is not list
        or len(links) != 2
    ):
        _fail(code, "форма квитанции установщика неверна")
    for name in (
        "codexHome",
        "codexBinary",
        "stateHome",
        "marketplacePath",
        "registeredMarketplacePath",
    ):
        _absolute_string(document.get(name), code)
    for item in links:
        if type(item) is not dict or set(item) != {"path", "target"}:
            _fail(code, "описание стабильной оболочки неверно")
        _absolute_string(item.get("path"), code)
        _absolute_string(item.get("target"), code)
    return document


def _verify_journal_absence(
    projection: object,
    *,
    path: Path,
    installation_id: str,
    operation_id: str,
) -> None:
    if type(projection) is not dict or projection.get("schemaId") != "absence-proof-v2":
        _fail("COMMIT_RECEIPT_INVALID", "цель отсутствия журнала не задана")
    value = projection.get("value")
    entries = None if type(value) is not dict else value.get("entries")
    if (
        type(value) is not dict
        or value.get("installationId") != installation_id
        or value.get("operationId") != operation_id
        or value.get("directorySyncCompleted") is not True
        or type(entries) is not list
        or len(entries) != 1
        or type(entries[0]) is not dict
    ):
        _fail("COMMIT_RECEIPT_INVALID", "цель отсутствия журнала неполна")
    entry = entries[0]
    parent = _private_directory(path.parent)
    if (
        entry.get("path") != str(path)
        or entry.get("basename") != path.name
        or entry.get("parentDevice") != parent.st_dev
        or entry.get("parentInode") != parent.st_ino
        or entry.get("absent") is not True
        or os.path.lexists(path)
    ):
        _fail("OPERATION_NOT_COMMITTED", "журнал операции не доказан отсутствующим")
    _fsync_directory(path.parent)
    after = _private_directory(path.parent)
    if _identity(after) != _identity(parent) or os.path.lexists(path):
        _fail("OPERATION_NOT_COMMITTED", "отсутствие журнала изменилось")


def _require_unchanged_current(
    path: Path,
    *,
    raw: bytes,
    document: Mapping[str, Any],
    information: os.stat_result,
) -> None:
    observed_raw, observed, observed_info = _read_private_canonical(
        path, "INSTALLER_RECEIPT_CHANGED"
    )
    if (
        observed_raw != raw
        or observed != dict(document)
        or _identity(observed_info) != _identity(information)
    ):
        _fail("INSTALLER_RECEIPT_CHANGED", "квитанция изменилась перед заменой")


def _read_private_canonical(
    path: Path, code: str
) -> tuple[bytes, dict[str, Any], os.stat_result]:
    _absolute(path, "path")
    try:
        information = os.lstat(path)
        if (
            not stat.S_ISREG(information.st_mode)
            or stat.S_ISLNK(information.st_mode)
            or information.st_uid != os.getuid()
            or information.st_nlink != 1
            or stat.S_IMODE(information.st_mode) != 0o600
            or information.st_size > _MAX_DOCUMENT_BYTES
        ):
            _fail(code, f"небезопасный закрытый файл: {path}")
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except InstallerReceiptReconciliationV2Error:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallerReceiptReconciliationV2Error(
            code, f"не удалось прочитать {path}: {error}"
        ) from error
    if type(document) is not dict or canonical_json_bytes(document) != raw:
        _fail(code, "документ не является каноническим объектом JSON")
    return raw, document, information


def _read_private_canonical_at(
    parent_descriptor: int,
    name: str,
    code: str,
) -> tuple[bytes, dict[str, Any]]:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or information.st_nlink != 1
            or stat.S_IMODE(information.st_mode) != 0o600
            or information.st_size > _MAX_DOCUMENT_BYTES
        ):
            _fail(code, "временная квитанция имеет неверные метаданные")
        chunks: list[bytes] = []
        total = 0
        while True:
            checkpoint_current_operation_deadline_if_scoped_v2()
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > _MAX_DOCUMENT_BYTES:
                _fail(code, "временная квитанция слишком велика")
            chunks.append(block)
        raw = b"".join(chunks)
        document = json.loads(raw.decode("utf-8"))
    except InstallerReceiptReconciliationV2Error:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallerReceiptReconciliationV2Error(
            code, f"не удалось перечитать временную квитанцию: {error}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if type(document) is not dict or canonical_json_bytes(document) != raw:
        _fail(code, "временная квитанция не является каноническим JSON")
    return raw, document


def _file_projection_matches(
    value: Mapping[str, Any],
    *,
    path: Path,
    raw: bytes,
    information: os.stat_result,
) -> bool:
    return value == {
        "path": str(path),
        "device": information.st_dev,
        "inode": information.st_ino,
        "ownerUid": information.st_uid,
        "ownerGid": information.st_gid,
        "mode": f"0{stat.S_IMODE(information.st_mode):03o}",
        "linkCount": information.st_nlink,
        "size": information.st_size,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _private_directory(path: Path) -> os.stat_result:
    try:
        information = os.lstat(path)
    except OSError as error:
        raise InstallerReceiptReconciliationV2Error(
            "PRIVATE_DIRECTORY_INVALID", f"каталог недоступен: {path}"
        ) from error
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        _fail("PRIVATE_DIRECTORY_INVALID", f"каталог не является закрытым: {path}")
    return information


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory_fd(descriptor: int) -> None:
    os.fsync(descriptor)


def _result(
    status: str, identity: Mapping[str, str]
) -> InstallerReceiptReconciliationResultV2:
    return InstallerReceiptReconciliationResultV2(
        status=status,
        installation_id=identity["installationId"],
        operation_id=identity["operationId"],
        activation_id=identity["activationId"],
        source_digest=identity["sourceDigest"],
    )


def _absolute(path: Path, name: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError(f"{name} must be an absolute Path")


def _absolute_string(value: object, code: str) -> None:
    if (
        type(value) is not str
        or not value
        or "\0" in value
        or len(value) > 4096
        or not Path(value).is_absolute()
    ):
        _fail(code, "квитанция содержит не абсолютный путь")


def _identity(information: os.stat_result) -> tuple[int, int]:
    return information.st_dev, information.st_ino


def _fail(code: str, message: str) -> None:
    raise InstallerReceiptReconciliationV2Error(code, message)


__all__ = [
    "InstallerReceiptReconciliationResultV2",
    "InstallerReceiptReconciliationV2Error",
    "reconcile_installer_receipt_v2",
]
