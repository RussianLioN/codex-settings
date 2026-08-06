"""Безопасные читающие и удаляющие адаптеры установщика версии 2.

Модуль не зависит от сценария командной строки.  Все пути и внешние
регистрации передаются явно, а право удалить файловый объект выводится только
из совпавшей неизменяемой квитанции и свежей физической проекции.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .canonical_json import canonical_json_bytes, domain_fingerprint
from . import finite_file_lock_v2, operation_deadline_v2


JsonObject = dict[str, Any]
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_INSTALLATION_ID = re.compile(r"ins2_[0-9a-f]{32}\Z")
_ACTIVATION_ID = re.compile(r"act2_[0-9a-f]{64}\Z")
_OPERATION_ID = re.compile(r"op2_[0-9a-f]{32}\Z")
_CLEANUP_ID = re.compile(r"cl2_[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INSTALLER_RECEIPT_KEYS = {
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
_ACTIVATION_COMMIT_RECEIPT_KEYS = {
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
_UNINSTALL_RECEIPT_KEYS = {
    "schemaVersion",
    "receiptKind",
    "installationId",
    "operationId",
    "frozenJournalFingerprint",
    "dataRetentionMode",
    "retainedData",
    "removedState",
    "restoredOriginalBackup",
    "absenceProof",
    "receiptFingerprint",
    "completedAt",
}
_TOMBSTONE_KEYS = {
    "schemaVersion",
    "installationId",
    "operationId",
    "uninstallReceipt",
    "absenceProof",
    "completedAt",
    "tombstoneFingerprint",
}
_UNINSTALL_JOURNAL_KEYS = {
    "schemaVersion",
    "kind",
    "installationId",
    "operationId",
    "activeActivationId",
    "phase",
    "registrations",
    "launcherLinks",
    "marketplaceLink",
    "activationObjects",
    "manifestFile",
    "installerReceiptFile",
    "retainedData",
    "originalBackupPath",
    "completedActionIds",
    "receiptPath",
    "projectionSchemaSha256",
    "createdAt",
    "updatedAt",
    "terminalCompletedAt",
    "journalFingerprint",
}
_STATE_BUNDLE_KEYS = {
    "fileObjects",
    "treeObjects",
    "symlinks",
    "manifest",
    "activation",
    "database",
    "controller",
    "controllerCandidates",
    "watchdogs",
    "registry",
    "launchers",
    "legacyProcesses",
    "quiescence",
    "externalCommands",
    "receipts",
    "absenceProofs",
    "bundleFingerprint",
}


def _checkpoint_operation_deadline_if_scoped_v2() -> None:
    """Проверить общий срок, не создавая новый срок внутри адаптера."""

    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is not None:
        deadline.checkpoint()


class InstallerMaintenanceV2Error(RuntimeError):
    """Закрытая ошибка отказа до сомнительного внешнего эффекта."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class MaintenanceIssueV2:
    code: str
    path: Path
    message: str


@dataclass(frozen=True)
class RegistrationObservationV2:
    """Свежая точная запись внешнего реестра."""

    kind: str
    name: str
    target: Path

    def __post_init__(self) -> None:
        if self.kind not in {"marketplace", "plugin"}:
            raise ValueError("kind должен быть marketplace или plugin")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("name должен быть непустой строкой")
        if not isinstance(self.target, Path) or not self.target.is_absolute():
            raise ValueError("target должен быть абсолютным Path")
        object.__setattr__(self, "target", self.target.absolute())

    def to_document(self) -> JsonObject:
        return {"kind": self.kind, "name": self.name, "target": str(self.target)}


@dataclass(frozen=True)
class RegistrationCallbacksV2:
    """Читающая граница и точечное удаление одной доказанной записи."""

    observe: Callable[[str, str], RegistrationObservationV2 | None]
    remove: Callable[[RegistrationObservationV2], None]

    def __post_init__(self) -> None:
        if not callable(self.observe) or not callable(self.remove):
            raise TypeError("registration callbacks должны быть вызываемыми")


@dataclass(frozen=True)
class InstallerMaintenanceLayoutV2:
    """Все файловые границы обслуживания без неявных домашних каталогов."""

    codex_home: Path
    managed_root: Path
    activations_root: Path
    manifest_path: Path
    installer_receipt_path: Path
    marketplace_link: Path
    receipts_root: Path
    cleanup_journal_path: Path
    uninstall_journal_path: Path
    tombstone_path: Path
    lock_path: Path
    state_home: Path
    databases_root: Path
    backups_root: Path
    quarantine_root: Path
    recovery_entrypoint: Path

    def __post_init__(self) -> None:
        names = tuple(self.__dataclass_fields__)
        for name in names:
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} должен быть абсолютным Path")
            if "\0" in str(value):
                raise ValueError(f"{name} содержит нулевой байт")
            object.__setattr__(self, name, value.absolute())
        if self.activations_root.parent != self.managed_root:
            raise ValueError("activations_root должен непосредственно входить в managed_root")
        if self.marketplace_link.parent != self.managed_root:
            raise ValueError("marketplace_link должен непосредственно входить в managed_root")
        manifest_root = self.manifest_path.parent
        for name in (
            "installer_receipt_path",
            "receipts_root",
            "cleanup_journal_path",
            "uninstall_journal_path",
            "tombstone_path",
            "lock_path",
        ):
            path = getattr(self, name)
            if not _is_within(path, manifest_root):
                raise ValueError(f"{name} должен входить в каталог манифеста")
        if not _is_within(self.databases_root, self.state_home):
            raise ValueError("databases_root должен входить в state_home")
        for name in (
            "state_home",
            "databases_root",
            "backups_root",
            "quarantine_root",
            "recovery_entrypoint",
        ):
            if _is_within(getattr(self, name), self.managed_root):
                raise ValueError(f"сохраняемый {name} не может входить в managed_root")


@dataclass(frozen=True)
class OwnedActivationV2:
    activation_id: str
    operation_id: str
    directory: Path
    directory_projection: Mapping[str, Any]
    activation_projection: Mapping[str, Any]
    database_binding: Mapping[str, Any]
    receipt_path: Path
    receipt_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "directory_projection", copy.deepcopy(dict(self.directory_projection)))
        object.__setattr__(self, "activation_projection", copy.deepcopy(dict(self.activation_projection)))
        object.__setattr__(self, "database_binding", copy.deepcopy(dict(self.database_binding)))


@dataclass(frozen=True)
class MaintenanceInventoryV2:
    installation_id: str | None
    active_activation_id: str | None
    previous_activation_id: str | None
    protected_activation_ids: tuple[str, ...]
    cleanup_candidate_ids: tuple[str, ...]
    owned_activations: tuple[OwnedActivationV2, ...]
    retained_paths: tuple[Path, ...]
    manifest: Mapping[str, Any] | None
    installer_receipt: Mapping[str, Any] | None
    registrations: tuple[RegistrationObservationV2, ...]
    issues: tuple[MaintenanceIssueV2, ...]

    def __post_init__(self) -> None:
        if self.manifest is not None:
            object.__setattr__(self, "manifest", copy.deepcopy(dict(self.manifest)))
        if self.installer_receipt is not None:
            object.__setattr__(self, "installer_receipt", copy.deepcopy(dict(self.installer_receipt)))


@dataclass(frozen=True)
class MaintenanceResultV2:
    command: str
    status: str
    installation_id: str
    operation_id: str | None
    activation_ids: tuple[str, ...]
    removed_paths: tuple[Path, ...]
    retained_paths: tuple[Path, ...]
    receipt_path: Path | None = None
    tombstone_path: Path | None = None


def inspect_maintenance_inventory_v2(
    layout: InstallerMaintenanceLayoutV2,
    *,
    registrations: RegistrationCallbacksV2 | None = None,
) -> MaintenanceInventoryV2:
    """Собрать доказательства без создания каталогов, блокировок или файлов."""

    issues: list[MaintenanceIssueV2] = []
    manifest = _read_json_for_inventory(
        layout.manifest_path, "MANIFEST_INVALID", issues
    )
    installer = _read_json_for_inventory(
        layout.installer_receipt_path, "INSTALLER_RECEIPT_INVALID", issues
    )
    installation_id: str | None = None
    active_id: str | None = None
    previous_id: str | None = None
    if manifest is not None:
        candidate = manifest.get("installationId")
        if (
            manifest.get("schemaVersion") != 2
            or type(candidate) is not str
            or _INSTALLATION_ID.fullmatch(candidate) is None
            or manifest.get("stateHome") != str(layout.state_home)
        ):
            _issue(issues, "MANIFEST_INVALID", layout.manifest_path, "манифест не связан с layout")
        else:
            installation_id = candidate
            active_id = _manifest_activation_id(manifest.get("activeActivation"))
            raw_previous = manifest.get("previousActivation")
            previous_id = None if raw_previous is None else _manifest_activation_id(raw_previous)
            if active_id is None or (raw_previous is not None and previous_id is None):
                _issue(issues, "MANIFEST_INVALID", layout.manifest_path, "идентичность активаций неверна")
    if installer is not None:
        _validate_installer_receipt_for_inventory(
            installer,
            layout=layout,
            installation_id=installation_id,
            active_id=active_id,
            issues=issues,
        )

    owned_by_id: dict[str, OwnedActivationV2] = {}
    if installation_id is not None:
        owned_by_id = _load_owned_activations(layout, installation_id, issues)
    observed_activation_ids = _observe_activation_entries(layout, issues)
    for activation_id in observed_activation_ids:
        if activation_id not in owned_by_id:
            _issue(
                issues,
                "ACTIVATION_OWNERSHIP_AMBIGUOUS",
                layout.activations_root / activation_id,
                "для дерева нет совпавшей commit-квитанции",
            )
    for activation_id, owned in tuple(owned_by_id.items()):
        if activation_id not in observed_activation_ids:
            del owned_by_id[activation_id]
            continue
        try:
            observed = _tree_projection(owned.directory)
        except (OSError, InstallerMaintenanceV2Error) as exc:
            _issue(issues, "ACTIVATION_PROJECTION_CHANGED", owned.directory, str(exc))
            continue
        if not _durable_projection_matches(
            observed,
            owned.directory_projection,
        ):
            _issue(
                issues,
                "ACTIVATION_PROJECTION_CHANGED",
                owned.directory,
                "физическая проекция дерева изменилась",
            )

    protected = tuple(
        value for value in (active_id, previous_id) if value is not None
    )
    for activation_id in protected:
        if activation_id not in owned_by_id:
            _issue(
                issues,
                "PROTECTED_ACTIVATION_UNPROVEN",
                layout.activations_root / activation_id,
                "активная или предыдущая активация не доказана",
            )
    cleanup = tuple(
        sorted(set(owned_by_id).difference(protected), key=lambda value: value.encode("utf-8"))
    )

    observed_registrations: list[RegistrationObservationV2] = []
    if registrations is not None and installer is not None:
        expected = _expected_registrations(installer)
        for item in expected:
            try:
                observed = registrations.observe(item.kind, item.name)
            except Exception as exc:  # внешняя читающая граница
                _issue(issues, "REGISTRATION_OBSERVE_FAILED", item.target, str(exc))
                continue
            if observed is None or observed != item:
                _issue(
                    issues,
                    "REGISTRATION_OWNERSHIP_AMBIGUOUS",
                    item.target,
                    "внешняя регистрация отсутствует или указывает на иной объект",
                )
            else:
                observed_registrations.append(observed)

    active_owned = owned_by_id.get(active_id or "")
    if active_owned is not None:
        _validate_database_binding(
            active_owned.database_binding, layout=layout, issues=issues
        )
    _validate_retained_objects(layout, issues)

    retained = [
        layout.state_home,
        layout.databases_root,
        layout.backups_root,
        layout.quarantine_root,
        layout.recovery_entrypoint,
    ]
    if active_owned is not None:
        raw_database = active_owned.database_binding.get("value", {})
        path = raw_database.get("path") if isinstance(raw_database, Mapping) else None
        if type(path) is str and Path(path).is_absolute():
            retained.append(Path(path))
    return MaintenanceInventoryV2(
        installation_id=installation_id,
        active_activation_id=active_id,
        previous_activation_id=previous_id,
        protected_activation_ids=protected,
        cleanup_candidate_ids=cleanup,
        owned_activations=tuple(owned_by_id[key] for key in sorted(owned_by_id)),
        retained_paths=tuple(dict.fromkeys(retained)),
        manifest=manifest,
        installer_receipt=installer,
        registrations=tuple(observed_registrations),
        issues=tuple(issues),
    )


def _read_json_for_inventory(
    path: Path,
    code: str,
    issues: list[MaintenanceIssueV2],
) -> JsonObject | None:
    try:
        return _read_private_json(path, code)
    except InstallerMaintenanceV2Error as exc:
        _issue(issues, exc.code, path, exc.message)
        return None


def _read_private_json(path: Path, code: str) -> JsonObject:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise InstallerMaintenanceV2Error(code, f"файл недоступен: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise InstallerMaintenanceV2Error(
                code, f"небезопасный закрытый файл: {path}"
            )
        payload = _read_bounded(descriptor, _MAX_DOCUMENT_BYTES)
        final = path.lstat()
        if (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino):
            raise InstallerMaintenanceV2Error(code, f"файл заменён при чтении: {path}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise InstallerMaintenanceV2Error(code, f"некорректный JSON: {path}") from exc
    if type(value) is not dict:
        raise InstallerMaintenanceV2Error(code, "корневое значение должно быть объектом")
    if canonical_json_bytes(value) != payload:
        raise InstallerMaintenanceV2Error(code, "JSON не канонический")
    return value


def _validate_installer_receipt_for_inventory(
    receipt: Mapping[str, Any],
    *,
    layout: InstallerMaintenanceLayoutV2,
    installation_id: str | None,
    active_id: str | None,
    issues: list[MaintenanceIssueV2],
) -> None:
    if (
        set(receipt) != _INSTALLER_RECEIPT_KEYS
        or receipt.get("schemaVersion") != 2
        or receipt.get("kind") != "codex-smart-installer-receipt/v2"
        or _SHA256.fullmatch(str(receipt.get("sourceDigest"))) is None
        or receipt.get("installationId") != installation_id
        or receipt.get("activationId") != active_id
        or receipt.get("codexHome") != str(layout.codex_home)
        or receipt.get("stateHome") != str(layout.state_home)
        or receipt.get("marketplacePath") != str(layout.marketplace_link)
        or receipt.get("marketplaceName") != "codex-settings-adaptive"
        or receipt.get("pluginId") != "codex-smart-subagents@codex-settings-adaptive"
        or receipt.get("extensions") != {}
    ):
        _issue(
            issues,
            "INSTALLER_RECEIPT_INVALID",
            layout.installer_receipt_path,
            "закрытые поля квитанции не совпали",
        )
        return
    registered = receipt.get("registeredMarketplacePath")
    expected_registered = layout.activations_root / str(active_id) / "marketplace"
    if type(registered) is not str or Path(registered) != expected_registered:
        _issue(
            issues,
            "INSTALLER_RECEIPT_INVALID",
            layout.installer_receipt_path,
            "registeredMarketplacePath не принадлежит активной активации",
        )
    _validate_marketplace_link(receipt, layout=layout, issues=issues)
    _validate_launcher_links(receipt, layout=layout, issues=issues)


def _validate_marketplace_link(
    receipt: Mapping[str, Any],
    *,
    layout: InstallerMaintenanceLayoutV2,
    issues: list[MaintenanceIssueV2],
) -> None:
    try:
        info = layout.marketplace_link.lstat()
        target = os.readlink(layout.marketplace_link)
        resolved = layout.marketplace_link.resolve(strict=True)
    except OSError as exc:
        _issue(issues, "MARKETPLACE_LINK_AMBIGUOUS", layout.marketplace_link, str(exc))
        return
    registered = Path(str(receipt.get("registeredMarketplacePath")))
    expected_target = f"activations/{receipt.get('activationId')}/marketplace"
    if (
        not stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or target != expected_target
        or resolved != registered.resolve(strict=True)
    ):
        _issue(
            issues,
            "MARKETPLACE_LINK_AMBIGUOUS",
            layout.marketplace_link,
            "активная ссылка не совпала с квитанцией",
        )


def _validate_launcher_links(
    receipt: Mapping[str, Any],
    *,
    layout: InstallerMaintenanceLayoutV2,
    issues: list[MaintenanceIssueV2],
) -> None:
    links = receipt.get("links")
    if type(links) is not list or len(links) != 2:
        _issue(issues, "LAUNCHER_OWNERSHIP_AMBIGUOUS", layout.installer_receipt_path, "список загрузчиков неверен")
        return
    expected_names = {"codex-smart", "codex-smart-subagents-admin"}
    seen: set[str] = set()
    expected_bin = layout.marketplace_link / "plugins" / "codex-smart-subagents" / "bin"
    for item in links:
        if type(item) is not dict or set(item) != {"path", "target"}:
            _issue(issues, "LAUNCHER_OWNERSHIP_AMBIGUOUS", layout.installer_receipt_path, "запись загрузчика неверна")
            continue
        path = Path(str(item["path"]))
        target = Path(str(item["target"]))
        try:
            info = path.lstat()
            observed_target = os.readlink(path)
        except OSError as exc:
            _issue(issues, "LAUNCHER_OWNERSHIP_AMBIGUOUS", path, str(exc))
            continue
        if (
            not path.is_absolute()
            or path.name not in expected_names
            or path.name in seen
            or target != expected_bin / path.name
            or not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or observed_target != str(target)
        ):
            _issue(issues, "LAUNCHER_OWNERSHIP_AMBIGUOUS", path, "загрузчик изменён")
        seen.add(path.name)
    if seen != expected_names:
        _issue(issues, "LAUNCHER_OWNERSHIP_AMBIGUOUS", layout.installer_receipt_path, "набор загрузчиков неполон")


def _load_owned_activations(
    layout: InstallerMaintenanceLayoutV2,
    installation_id: str,
    issues: list[MaintenanceIssueV2],
) -> dict[str, OwnedActivationV2]:
    result: dict[str, OwnedActivationV2] = {}
    receipt_dir = layout.receipts_root / installation_id
    try:
        info = receipt_dir.lstat()
    except OSError as exc:
        _issue(issues, "ACTIVATION_RECEIPTS_MISSING", receipt_dir, str(exc))
        return result
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
        _issue(issues, "ACTIVATION_RECEIPTS_INVALID", receipt_dir, "каталог квитанций небезопасен")
        return result
    for path in sorted(receipt_dir.glob("*.commit.json"), key=lambda item: item.name):
        try:
            receipt = _read_private_json(path, "ACTIVATION_RECEIPT_INVALID")
            owned = _owned_activation_from_receipt(
                receipt,
                path=path,
                layout=layout,
                installation_id=installation_id,
            )
        except InstallerMaintenanceV2Error as exc:
            _issue(issues, exc.code, path, exc.message)
            continue
        if owned.activation_id in result:
            _issue(issues, "ACTIVATION_RECEIPT_DUPLICATE", path, "две квитанции претендуют на одну активацию")
            continue
        result[owned.activation_id] = owned
    return result


def _owned_activation_from_receipt(
    receipt: Mapping[str, Any],
    *,
    path: Path,
    layout: InstallerMaintenanceLayoutV2,
    installation_id: str,
) -> OwnedActivationV2:
    fingerprint = receipt.get("receiptFingerprint")
    unsigned = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "receiptFingerprint"}
    if (
        set(receipt) != _ACTIVATION_COMMIT_RECEIPT_KEYS
        or receipt.get("schemaVersion") != 2
        or receipt.get("receiptKind") != "activation-commit"
        or receipt.get("installationId") != installation_id
        or type(receipt.get("operationId")) is not str
        or _OPERATION_ID.fullmatch(str(receipt.get("operationId"))) is None
        or type(fingerprint) is not str
        or fingerprint != domain_fingerprint("codex-smart/activation-commit-receipt/v2", unsigned)
    ):
        raise InstallerMaintenanceV2Error("ACTIVATION_RECEIPT_INVALID", "отпечаток или идентичность commit-квитанции неверны")
    try:
        activation_projection = receipt["activation"]
        activation_value = activation_projection["value"]
        activation_id = activation_value["activationId"]
        directory_projection = activation_value["directory"]
        database_binding = receipt["databaseBinding"]
    except (KeyError, TypeError) as exc:
        raise InstallerMaintenanceV2Error("ACTIVATION_RECEIPT_INVALID", "commit-квитанция не содержит полную проекцию") from exc
    directory = layout.activations_root / str(activation_id)
    if (
        type(activation_id) is not str
        or _ACTIVATION_ID.fullmatch(activation_id) is None
        or type(directory_projection) is not dict
        or directory_projection.get("path") != str(directory)
        or type(activation_projection) is not dict
        or activation_projection.get("schemaId") != "activation-v2"
        or type(database_binding) is not dict
        or database_binding.get("schemaId") != "database-binding-v2"
    ):
        raise InstallerMaintenanceV2Error("ACTIVATION_RECEIPT_INVALID", "проекция активации указывает вне закрытого корня")
    return OwnedActivationV2(
        activation_id=activation_id,
        operation_id=str(receipt["operationId"]),
        directory=directory,
        directory_projection=directory_projection,
        activation_projection=activation_projection,
        database_binding=database_binding,
        receipt_path=path,
        receipt_fingerprint=fingerprint,
    )


def _verify_commit_ownership_reference(
    layout: InstallerMaintenanceLayoutV2,
    *,
    path: object,
    receipt_fingerprint: object,
    installation_id: str,
    activation_id: str,
    directory_projection: object,
) -> None:
    if (
        type(path) is not str
        or not _journal_path_is(
            path,
            layout.receipts_root / installation_id,
            suffix=".commit.json",
        )
        or type(receipt_fingerprint) is not str
        or _SHA256.fullmatch(receipt_fingerprint) is None
        or not isinstance(directory_projection, Mapping)
    ):
        raise InstallerMaintenanceV2Error(
            "ACTIVATION_RECEIPT_INVALID", "ссылка на commit-квитанцию неверна"
        )
    receipt_path = Path(path)
    receipt = _read_private_json(receipt_path, "ACTIVATION_RECEIPT_INVALID")
    owned = _owned_activation_from_receipt(
        receipt,
        path=receipt_path,
        layout=layout,
        installation_id=installation_id,
    )
    if (
        owned.receipt_fingerprint != receipt_fingerprint
        or owned.activation_id != activation_id
        or dict(owned.directory_projection) != dict(directory_projection)
    ):
        raise InstallerMaintenanceV2Error(
            "ACTIVATION_RECEIPT_INVALID", "commit-квитанция не доказывает дерево"
        )


def _observe_activation_entries(
    layout: InstallerMaintenanceLayoutV2,
    issues: list[MaintenanceIssueV2],
) -> set[str]:
    result: set[str] = set()
    try:
        root_info = layout.activations_root.lstat()
        entries = sorted(layout.activations_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        _issue(issues, "ACTIVATION_ROOT_INVALID", layout.activations_root, str(exc))
        return result
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != os.getuid()
        or stat.S_IMODE(root_info.st_mode) != 0o700
    ):
        _issue(issues, "ACTIVATION_ROOT_INVALID", layout.activations_root, "корень активаций небезопасен")
        return result
    for path in entries:
        try:
            info = path.lstat()
        except OSError as exc:
            _issue(issues, "ACTIVATION_OWNERSHIP_AMBIGUOUS", path, str(exc))
            continue
        if (
            _ACTIVATION_ID.fullmatch(path.name) is None
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in {0o500, 0o700}
        ):
            _issue(issues, "ACTIVATION_OWNERSHIP_AMBIGUOUS", path, "неизвестный путь или ссылка в корне активаций")
            continue
        result.add(path.name)
    return result


def _validate_database_binding(
    projection: Mapping[str, Any],
    *,
    layout: InstallerMaintenanceLayoutV2,
    issues: list[MaintenanceIssueV2],
) -> None:
    value = projection.get("value")
    if not isinstance(value, Mapping):
        _issue(issues, "DATABASE_BINDING_INVALID", layout.databases_root, "проекция базы отсутствует")
        return
    path_value = value.get("path")
    if type(path_value) is not str or not Path(path_value).is_absolute():
        _issue(issues, "DATABASE_BINDING_INVALID", layout.databases_root, "путь базы неверен")
        return
    path = Path(path_value)
    if not _is_within(path, layout.databases_root):
        _issue(issues, "DATABASE_BINDING_INVALID", path, "база находится вне databases_root")
        return
    try:
        info = path.lstat()
    except OSError as exc:
        _issue(issues, "DATABASE_BINDING_CHANGED", path, str(exc))
        return
    expected = (
        value.get("inode"),
        value.get("ownerUid"),
        value.get("ownerGid"),
        value.get("mode"),
        value.get("linkCount"),
    )
    observed = (
        info.st_ino,
        info.st_uid,
        info.st_gid,
        f"0{stat.S_IMODE(info.st_mode):03o}",
        info.st_nlink,
    )
    if (
        not stat.S_ISREG(info.st_mode)
        or not _captured_device_is_valid(value.get("device"))
        or expected != observed
    ):
        _issue(issues, "DATABASE_BINDING_CHANGED", path, "inode или метаданные базы изменились")


def _validate_retained_objects(
    layout: InstallerMaintenanceLayoutV2,
    issues: list[MaintenanceIssueV2],
) -> None:
    for path in (layout.state_home, layout.databases_root, layout.backups_root, layout.quarantine_root):
        try:
            info = path.lstat()
        except OSError as exc:
            _issue(issues, "RETAINED_DATA_INVALID", path, str(exc))
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
            _issue(issues, "RETAINED_DATA_INVALID", path, "сохраняемый каталог небезопасен")
    try:
        info = layout.recovery_entrypoint.lstat()
    except OSError as exc:
        _issue(issues, "RECOVERY_ENTRYPOINT_INVALID", layout.recovery_entrypoint, str(exc))
    else:
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            _issue(issues, "RECOVERY_ENTRYPOINT_INVALID", layout.recovery_entrypoint, "точка восстановления небезопасна")


def _expected_registrations(
    installer: Mapping[str, Any],
) -> tuple[RegistrationObservationV2, RegistrationObservationV2]:
    marketplace = Path(str(installer.get("registeredMarketplacePath")))
    return (
        RegistrationObservationV2(
            kind="marketplace",
            name=str(installer.get("marketplaceName")),
            target=marketplace,
        ),
        RegistrationObservationV2(
            kind="plugin",
            name=str(installer.get("pluginId")),
            target=marketplace / "plugins" / "codex-smart-subagents",
        ),
    )


def _tree_projection(path: Path) -> JsonObject:
    _checkpoint_operation_deadline_if_scoped_v2()
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) not in {0o500, 0o700}
    ):
        raise InstallerMaintenanceV2Error("ACTIVATION_PROJECTION_CHANGED", f"небезопасный каталог: {path}")
    entries: list[JsonObject] = []
    pending = [path]
    count = 0
    while pending:
        _checkpoint_operation_deadline_if_scoped_v2()
        directory = pending.pop()
        for child in sorted(directory.iterdir(), key=lambda item: item.name, reverse=True):
            _checkpoint_operation_deadline_if_scoped_v2()
            child_info = child.lstat()
            relative = child.relative_to(path).as_posix()
            if stat.S_ISLNK(child_info.st_mode):
                entries.append({"path": relative, "type": "symlink", "mode": stat.S_IMODE(child_info.st_mode), "target": os.readlink(child)})
            elif stat.S_ISDIR(child_info.st_mode):
                if (
                    child_info.st_uid != os.getuid()
                    or stat.S_IMODE(child_info.st_mode) not in {0o500, 0o700}
                ):
                    raise InstallerMaintenanceV2Error("ACTIVATION_PROJECTION_CHANGED", f"небезопасный подкаталог: {child}")
                entries.append({"path": relative, "type": "directory", "mode": stat.S_IMODE(child_info.st_mode)})
                count += 1
                pending.append(child)
            elif stat.S_ISREG(child_info.st_mode):
                if (
                    child_info.st_uid != os.getuid()
                    or child_info.st_nlink != 1
                    or stat.S_IMODE(child_info.st_mode)
                    not in {0o400, 0o500, 0o600}
                ):
                    raise InstallerMaintenanceV2Error("ACTIVATION_PROJECTION_CHANGED", f"небезопасный файл: {child}")
                entries.append({"path": relative, "type": "regular", "mode": stat.S_IMODE(child_info.st_mode), "size": child_info.st_size, "sha256": _sha256_file(child)})
                count += 1
            else:
                raise InstallerMaintenanceV2Error("ACTIVATION_PROJECTION_CHANGED", f"неподдерживаемый объект: {child}")
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "entryCount": count,
        "treeSha256": hashlib.sha256(canonical_json_bytes(entries)).hexdigest(),
    }


def _file_projection(path: Path) -> JsonObject:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise InstallerMaintenanceV2Error("FILE_PROJECTION_CHANGED", f"небезопасный файл: {path}")
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _sha256_file(path),
    }


def _captured_device_is_valid(value: object) -> bool:
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _durable_projection_matches(
    observed: Mapping[str, Any],
    captured: Mapping[str, Any],
) -> bool:
    if set(observed) != set(captured):
        return False
    if not _captured_device_is_valid(captured.get("device")):
        return False
    return all(
        key == "device" or observed[key] == captured[key]
        for key in observed
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        while True:
            _checkpoint_operation_deadline_if_scoped_v2()
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)
    finally:
        os.close(descriptor)


def _manifest_activation_id(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    candidate = value.get("activationId")
    if type(candidate) is str and _ACTIVATION_ID.fullmatch(candidate) is not None:
        return candidate
    return None


def _issue(
    issues: list[MaintenanceIssueV2],
    code: str,
    path: Path,
    message: str,
) -> None:
    issues.append(MaintenanceIssueV2(code=code, path=path, message=message[:2048]))


def _unique_object(pairs: list[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"повторяющийся ключ: {key}")
        result[key] = value
    return result


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _path_exists(path: Path) -> bool:
    return os.path.lexists(path)


def cleanup_inactive_activations_v2(
    layout: InstallerMaintenanceLayoutV2,
    *,
    execute: bool,
    now: Callable[[], str],
    id_factory: Callable[[str], str] | None = None,
    failure_injector: Callable[[str], None] | None = None,
) -> MaintenanceResultV2:
    """Удалить только доказанные неактивные поколения."""

    inject = failure_injector or (lambda _point: None)
    _checkpoint_operation_deadline_if_scoped_v2()
    if _path_exists(layout.uninstall_journal_path):
        raise InstallerMaintenanceV2Error(
            "OPERATION_IN_PROGRESS", "незавершённое удаление блокирует cleanup"
        )
    if _path_exists(layout.cleanup_journal_path):
        journal = _read_cleanup_journal(layout)
        if not execute:
            return _cleanup_result_from_journal(
                journal, status="planned", retained_paths=()
            )
        with _installation_lock(layout.lock_path):
            _checkpoint_operation_deadline_if_scoped_v2()
            return _execute_cleanup_journal(
                layout, journal, now=now, inject=inject
            )

    inventory = inspect_maintenance_inventory_v2(layout)
    _checkpoint_operation_deadline_if_scoped_v2()
    _raise_inventory_issues(inventory)
    installation_id = _required_installation_id(inventory.installation_id)
    if not inventory.cleanup_candidate_ids:
        return MaintenanceResultV2(
            command="cleanup",
            status="unchanged",
            installation_id=installation_id,
            operation_id=None,
            activation_ids=(),
            removed_paths=(),
            retained_paths=inventory.retained_paths,
        )
    if not execute:
        return MaintenanceResultV2(
            command="cleanup",
            status="planned",
            installation_id=installation_id,
            operation_id=None,
            activation_ids=inventory.cleanup_candidate_ids,
            removed_paths=(),
            retained_paths=inventory.retained_paths,
        )

    with _installation_lock(layout.lock_path):
        _checkpoint_operation_deadline_if_scoped_v2()
        if _path_exists(layout.uninstall_journal_path):
            raise InstallerMaintenanceV2Error(
                "OPERATION_IN_PROGRESS", "незавершённое удаление блокирует cleanup"
            )
        if _path_exists(layout.cleanup_journal_path):
            journal = _read_cleanup_journal(layout)
        else:
            fresh = inspect_maintenance_inventory_v2(layout)
            _raise_inventory_issues(fresh)
            if fresh.cleanup_candidate_ids != inventory.cleanup_candidate_ids:
                raise InstallerMaintenanceV2Error(
                    "CLEANUP_PLAN_CHANGED",
                    "список поколений изменился до создания журнала",
                )
            cleanup_id = _new_identifier("cl2", _CLEANUP_ID, id_factory)
            journal = _build_cleanup_journal(
                layout, fresh, cleanup_id=cleanup_id, now=now
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            _atomic_create_json(layout.cleanup_journal_path, journal)
            _checkpoint_operation_deadline_if_scoped_v2()
        return _execute_cleanup_journal(
            layout, journal, now=now, inject=inject
        )


def _build_cleanup_journal(
    layout: InstallerMaintenanceLayoutV2,
    inventory: MaintenanceInventoryV2,
    *,
    cleanup_id: str,
    now: Callable[[], str],
) -> JsonObject:
    installation_id = _required_installation_id(inventory.installation_id)
    owned = {item.activation_id: item for item in inventory.owned_activations}
    active = owned.get(inventory.active_activation_id or "")
    if active is None:
        raise InstallerMaintenanceV2Error(
            "PROTECTED_ACTIVATION_UNPROVEN", "нет базовой commit-квитанции"
        )
    receipt_path = (
        layout.receipts_root
        / installation_id
        / f"{cleanup_id}.cleanup.json"
    )
    objects = []
    for activation_id in inventory.cleanup_candidate_ids:
        item = owned[activation_id]
        objects.append(
            {
                "activationId": activation_id,
                "path": str(item.directory),
                "projection": copy.deepcopy(dict(item.directory_projection)),
                "receiptPath": str(item.receipt_path),
                "receiptFingerprint": item.receipt_fingerprint,
            }
        )
    projection: JsonObject = {
        "schemaVersion": 2,
        "kind": "installer-maintenance-cleanup",
        "cleanupId": cleanup_id,
        "installationId": installation_id,
        "phase": "MUTATING",
        "objects": objects,
        "completedActivationIds": [],
        "baseCommitReceipt": {
            "path": str(active.receipt_path),
            "receiptFingerprint": active.receipt_fingerprint,
            "operationId": active.operation_id,
        },
        "receiptPath": str(receipt_path),
        "createdAt": _timestamp(now),
        "updatedAt": _timestamp(now),
        "terminalCompletedAt": None,
    }
    return _with_fingerprint(
        projection,
        key="journalFingerprint",
        domain="codex-smart/installer-maintenance-cleanup-journal/v2",
    )


def _read_cleanup_journal(layout: InstallerMaintenanceLayoutV2) -> JsonObject:
    journal = _read_private_json(
        layout.cleanup_journal_path, "CLEANUP_JOURNAL_INVALID"
    )
    unsigned = {key: value for key, value in journal.items() if key != "journalFingerprint"}
    if (
        set(journal)
        != {
            "schemaVersion",
            "kind",
            "cleanupId",
            "installationId",
            "phase",
            "objects",
            "completedActivationIds",
            "baseCommitReceipt",
            "receiptPath",
            "createdAt",
            "updatedAt",
            "terminalCompletedAt",
            "journalFingerprint",
        }
        or journal.get("schemaVersion") != 2
        or journal.get("kind") != "installer-maintenance-cleanup"
        or _CLEANUP_ID.fullmatch(str(journal.get("cleanupId"))) is None
        or _INSTALLATION_ID.fullmatch(str(journal.get("installationId"))) is None
        or journal.get("phase") not in {"MUTATING", "TERMINAL_FROZEN"}
        or journal.get("journalFingerprint")
        != domain_fingerprint(
            "codex-smart/installer-maintenance-cleanup-journal/v2", unsigned
        )
        or not _journal_path_is(
            journal.get("receiptPath"),
            layout.receipts_root / str(journal.get("installationId")),
            suffix=".cleanup.json",
        )
    ):
        raise InstallerMaintenanceV2Error(
            "CLEANUP_JOURNAL_INVALID", "журнал cleanup не прошёл закрытую проверку"
        )
    objects = journal.get("objects")
    completed = journal.get("completedActivationIds")
    if (
        type(objects) is not list
        or not objects
        or len(objects) > 127
        or type(completed) is not list
        or len(completed) != len(set(completed))
    ):
        raise InstallerMaintenanceV2Error(
            "CLEANUP_JOURNAL_INVALID", "набор объектов cleanup неверен"
        )
    expected_ids: list[str] = []
    for item in objects:
        if type(item) is not dict or set(item) != {
            "activationId",
            "path",
            "projection",
            "receiptPath",
            "receiptFingerprint",
        }:
            raise InstallerMaintenanceV2Error(
                "CLEANUP_JOURNAL_INVALID", "объект cleanup имеет неверную форму"
            )
        activation_id = item["activationId"]
        expected_path = layout.activations_root / str(activation_id)
        if (
            type(activation_id) is not str
            or _ACTIVATION_ID.fullmatch(activation_id) is None
            or item["path"] != str(expected_path)
            or type(item["projection"]) is not dict
            or item["projection"].get("path") != str(expected_path)
            or _SHA256.fullmatch(str(item["receiptFingerprint"])) is None
        ):
            raise InstallerMaintenanceV2Error(
                "CLEANUP_JOURNAL_INVALID", "объект cleanup выходит за закрытый корень"
            )
        _verify_commit_ownership_reference(
            layout,
            path=item["receiptPath"],
            receipt_fingerprint=item["receiptFingerprint"],
            installation_id=str(journal["installationId"]),
            activation_id=activation_id,
            directory_projection=item["projection"],
        )
        expected_ids.append(activation_id)
    if len(expected_ids) != len(set(expected_ids)) or not set(completed).issubset(expected_ids):
        raise InstallerMaintenanceV2Error(
            "CLEANUP_JOURNAL_INVALID", "курсор cleanup не связан с планом"
        )
    base = journal.get("baseCommitReceipt")
    if (
        type(base) is not dict
        or set(base) != {"path", "receiptFingerprint", "operationId"}
        or _OPERATION_ID.fullmatch(str(base.get("operationId"))) is None
        or _SHA256.fullmatch(str(base.get("receiptFingerprint"))) is None
        or not _journal_path_is(
            base.get("path"),
            layout.receipts_root / str(journal["installationId"]),
            suffix=".commit.json",
        )
    ):
        raise InstallerMaintenanceV2Error(
            "CLEANUP_JOURNAL_INVALID", "базовая commit-квитанция имеет иной путь"
        )
    if journal["phase"] == "TERMINAL_FROZEN" and type(
        journal.get("terminalCompletedAt")
    ) is not str:
        raise InstallerMaintenanceV2Error(
            "CLEANUP_JOURNAL_INVALID", "замороженный cleanup не содержит время"
        )
    return journal


def _execute_cleanup_journal(
    layout: InstallerMaintenanceLayoutV2,
    journal: JsonObject,
    *,
    now: Callable[[], str],
    inject: Callable[[str], None],
) -> MaintenanceResultV2:
    _checkpoint_operation_deadline_if_scoped_v2()
    journal = _read_cleanup_journal(layout)
    completed = set(journal["completedActivationIds"])
    removed: list[Path] = []
    if journal["phase"] == "MUTATING":
        for item in journal["objects"]:
            _checkpoint_operation_deadline_if_scoped_v2()
            activation_id = str(item["activationId"])
            path = Path(str(item["path"]))
            if activation_id in completed:
                if _path_exists(path):
                    raise InstallerMaintenanceV2Error(
                        "CLEANUP_RECOVERY_AMBIGUOUS",
                        f"завершённый объект снова появился: {path}",
                    )
                continue
            if _path_exists(path):
                observed = _tree_projection(path)
                if not _durable_projection_matches(
                    observed,
                    item["projection"],
                ):
                    raise InstallerMaintenanceV2Error(
                        "ACTIVATION_PROJECTION_CHANGED",
                        f"объект cleanup изменился: {path}",
                    )
                _remove_tree_exact(path, item["projection"])
                removed.append(path)
                inject("cleanup_after_delete")
                _checkpoint_operation_deadline_if_scoped_v2()
            if _path_exists(path):
                raise InstallerMaintenanceV2Error(
                    "CLEANUP_DELETE_FAILED", f"каталог не исчез: {path}"
                )
            completed.add(activation_id)
            _checkpoint_operation_deadline_if_scoped_v2()
            journal = _replace_journal(
                layout.cleanup_journal_path,
                journal,
                {
                    **journal,
                    "completedActivationIds": sorted(completed),
                    "updatedAt": _timestamp(now),
                },
                domain="codex-smart/installer-maintenance-cleanup-journal/v2",
            )
        terminal_at = _timestamp(now)
        _checkpoint_operation_deadline_if_scoped_v2()
        journal = _replace_journal(
            layout.cleanup_journal_path,
            journal,
            {
                **journal,
                "phase": "TERMINAL_FROZEN",
                "terminalCompletedAt": terminal_at,
                "updatedAt": terminal_at,
            },
            domain="codex-smart/installer-maintenance-cleanup-journal/v2",
        )

    _checkpoint_operation_deadline_if_scoped_v2()
    receipt = _build_cleanup_receipt(
        layout, journal, completed_at=str(journal["terminalCompletedAt"])
    )
    receipt_path = Path(str(journal["receiptPath"]))
    _publish_or_verify_json(
        receipt_path, receipt, code="CLEANUP_RECEIPT_CONFLICT"
    )
    _checkpoint_operation_deadline_if_scoped_v2()
    inject("cleanup_after_receipt")
    _checkpoint_operation_deadline_if_scoped_v2()
    _verify_cleanup_absence(journal)
    _checkpoint_operation_deadline_if_scoped_v2()
    _delete_private_file(layout.cleanup_journal_path)
    return MaintenanceResultV2(
        command="cleanup",
        status="cleaned",
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["cleanupId"]),
        activation_ids=tuple(item["activationId"] for item in journal["objects"]),
        removed_paths=tuple(removed),
        retained_paths=(),
        receipt_path=receipt_path,
    )


def _build_cleanup_receipt(
    layout: InstallerMaintenanceLayoutV2,
    journal: Mapping[str, Any],
    *,
    completed_at: str,
) -> JsonObject:
    base = journal["baseCommitReceipt"]
    base_path = Path(str(base["path"]))
    base_document = _read_private_json(base_path, "CLEANUP_BASE_RECEIPT_INVALID")
    if (
        base_document.get("receiptKind") != "activation-commit"
        or base_document.get("receiptFingerprint") != base["receiptFingerprint"]
    ):
        raise InstallerMaintenanceV2Error(
            "CLEANUP_BASE_RECEIPT_INVALID", "базовая commit-квитанция изменилась"
        )
    schema_sha = str(base_document["activation"].get("schemaSha256"))
    base_receipt_projection = _projection_document(
        "receipt-object-v2",
        {
            "file": _file_projection(base_path),
            "receiptKind": "activation-commit",
            "installationId": journal["installationId"],
            "operationId": base["operationId"],
            "receiptFingerprint": base["receiptFingerprint"],
        },
        schema_sha=schema_sha,
        domain="codex-smart/receipt-object/v2",
    )
    removed_objects = [
        _projection_document(
            "tree-object-v2",
            copy.deepcopy(item["projection"]),
            schema_sha=schema_sha,
            domain="codex-smart/tree-object/v2",
        )
        for item in journal["objects"]
    ]
    absence = _absence_projection(
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["cleanupId"]),
        paths=tuple(Path(str(item["path"])) for item in journal["objects"]),
        schema_sha=schema_sha,
    )
    projection: JsonObject = {
        "schemaVersion": 2,
        "receiptKind": "cleanup",
        "cleanupId": journal["cleanupId"],
        "installationId": journal["installationId"],
        "frozenJournalFingerprint": journal["journalFingerprint"],
        "baseCommitReceipt": base_receipt_projection,
        "removedObjects": removed_objects,
        "absenceProof": absence,
        "completedAt": completed_at,
    }
    return _with_fingerprint(
        projection,
        key="receiptFingerprint",
        domain="codex-smart/cleanup-receipt/v2",
    )


def _cleanup_result_from_journal(
    journal: Mapping[str, Any],
    *,
    status: str,
    retained_paths: tuple[Path, ...],
) -> MaintenanceResultV2:
    return MaintenanceResultV2(
        command="cleanup",
        status=status,
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["cleanupId"]),
        activation_ids=tuple(item["activationId"] for item in journal["objects"]),
        removed_paths=(),
        retained_paths=retained_paths,
        receipt_path=Path(str(journal["receiptPath"])),
    )


def _raise_inventory_issues(inventory: MaintenanceInventoryV2) -> None:
    if not inventory.issues:
        return
    priority = {
        "ACTIVATION_OWNERSHIP_AMBIGUOUS": 0,
        "ACTIVATION_PROJECTION_CHANGED": 1,
        "REGISTRATION_OWNERSHIP_AMBIGUOUS": 2,
        "LAUNCHER_OWNERSHIP_AMBIGUOUS": 3,
    }
    issue = min(
        inventory.issues,
        key=lambda value: priority.get(value.code, 100),
    )
    raise InstallerMaintenanceV2Error(issue.code, issue.message)


def _required_installation_id(value: str | None) -> str:
    if value is None or _INSTALLATION_ID.fullmatch(value) is None:
        raise InstallerMaintenanceV2Error(
            "INSTALLATION_ID_UNPROVEN", "идентичность установки не доказана"
        )
    return value


def _new_identifier(
    prefix: str,
    pattern: re.Pattern[str],
    factory: Callable[[str], str] | None,
) -> str:
    value = (
        factory(prefix)
        if factory is not None
        else f"{prefix}_{secrets.token_hex(16)}"
    )
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise InstallerMaintenanceV2Error(
            "IDENTIFIER_FACTORY_INVALID", f"неверный идентификатор {prefix}"
        )
    return value


def _timestamp(now: Callable[[], str]) -> str:
    value = now()
    if type(value) is not str or not value or len(value) > 64:
        raise InstallerMaintenanceV2Error(
            "CLOCK_VALUE_INVALID", "часы должны вернуть непустую строку времени"
        )
    return value


def _with_fingerprint(
    projection: Mapping[str, Any],
    *,
    key: str,
    domain: str,
) -> JsonObject:
    unsigned = copy.deepcopy(dict(projection))
    unsigned.pop(key, None)
    return {**unsigned, key: domain_fingerprint(domain, unsigned)}


@contextmanager
def _installation_lock(path: Path) -> Iterator[None]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerMaintenanceV2Error(
            "INSTALLATION_LOCK_INVALID", f"файл блокировки недоступен: {path}"
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise InstallerMaintenanceV2Error(
            "INSTALLATION_LOCK_INVALID", f"файл блокировки небезопасен: {path}"
        )
    descriptor = os.open(
        path,
        os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    acquired = False
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise InstallerMaintenanceV2Error(
                "INSTALLATION_LOCK_CHANGED", "файл блокировки заменён"
            )
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=(
                    finite_file_lock_v2.INSTALLATION_LOCK_TIMEOUT_SECONDS
                ),
                timeout_code="INSTALLATION_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as error:
            raise InstallerMaintenanceV2Error(
                error.code,
                "установочная блокировка осталась занятой до истечения срока",
            ) from error
        acquired = True
        yield
    finally:
        try:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _atomic_create_json(path: Path, document: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(document)
    _verify_private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise InstallerMaintenanceV2Error(
            "IMMUTABLE_FILE_CONFLICT", f"файл уже существует: {path}"
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    _fsync_directory(path.parent)


def _atomic_replace_json(path: Path, document: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(document)
    _read_private_json(path, "JOURNAL_CHANGED")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    _fsync_directory(path.parent)


def _replace_journal(
    path: Path,
    previous: Mapping[str, Any],
    updated: Mapping[str, Any],
    *,
    domain: str,
) -> JsonObject:
    observed = _read_private_json(path, "JOURNAL_CHANGED")
    if canonical_json_bytes(observed) != canonical_json_bytes(previous):
        raise InstallerMaintenanceV2Error(
            "JOURNAL_CHANGED", "журнал изменён между шагами"
        )
    document = _with_fingerprint(
        updated, key="journalFingerprint", domain=domain
    )
    _atomic_replace_json(path, document)
    return document


def _publish_or_verify_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    code: str,
) -> None:
    if _path_exists(path):
        observed = _read_private_json(path, code)
        if canonical_json_bytes(observed) != canonical_json_bytes(document):
            raise InstallerMaintenanceV2Error(code, f"неизменяемый файл отличается: {path}")
        return
    try:
        _atomic_create_json(path, document)
    except InstallerMaintenanceV2Error as exc:
        if exc.code != "IMMUTABLE_FILE_CONFLICT":
            raise
        observed = _read_private_json(path, code)
        if canonical_json_bytes(observed) != canonical_json_bytes(document):
            raise InstallerMaintenanceV2Error(code, f"неизменяемый файл отличается: {path}") from exc


def _delete_private_file(path: Path) -> None:
    _read_private_json(path, "JOURNAL_CHANGED")
    path.unlink()
    _fsync_directory(path.parent)


def _remove_tree_exact(path: Path, expected: Mapping[str, Any]) -> None:
    observed = _tree_projection(path)
    if not _durable_projection_matches(observed, expected):
        raise InstallerMaintenanceV2Error(
            "ACTIVATION_PROJECTION_CHANGED", f"дерево изменилось перед удалением: {path}"
        )
    current_identity = (observed["device"], observed["inode"])
    parent_descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    tree_descriptor = -1
    try:
        tree_descriptor = os.open(
            path.name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(tree_descriptor)
        if (opened.st_dev, opened.st_ino) != current_identity:
            raise InstallerMaintenanceV2Error(
                "ACTIVATION_PROJECTION_CHANGED", "корневой inode заменён"
            )
        _remove_directory_contents(tree_descriptor)
        os.fsync(tree_descriptor)
        os.close(tree_descriptor)
        tree_descriptor = -1
        final = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            (final.st_dev, final.st_ino) != current_identity
            or not stat.S_ISDIR(final.st_mode)
        ):
            raise InstallerMaintenanceV2Error(
                "ACTIVATION_PROJECTION_CHANGED", "корень заменён во время удаления"
            )
        os.rmdir(path.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if tree_descriptor >= 0:
            os.close(tree_descriptor)
        os.close(parent_descriptor)


def _remove_directory_contents(descriptor: int) -> None:
    os.fchmod(descriptor, 0o700)
    for name in sorted(os.listdir(descriptor), key=lambda value: value.encode("utf-8")):
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(
                name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise InstallerMaintenanceV2Error(
                        "ACTIVATION_PROJECTION_CHANGED", "подкаталог заменён"
                    )
                _remove_directory_contents(child)
                os.fsync(child)
            finally:
                os.close(child)
            final = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino):
                raise InstallerMaintenanceV2Error(
                    "ACTIVATION_PROJECTION_CHANGED", "подкаталог заменён"
                )
            os.rmdir(name, dir_fd=descriptor)
        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            os.unlink(name, dir_fd=descriptor)
        else:
            raise InstallerMaintenanceV2Error(
                "ACTIVATION_PROJECTION_CHANGED", "в дереве появился особый файл"
            )
    os.fsync(descriptor)


def _verify_cleanup_absence(journal: Mapping[str, Any]) -> None:
    for item in journal["objects"]:
        if _path_exists(Path(str(item["path"]))):
            raise InstallerMaintenanceV2Error(
                "CLEANUP_DELETE_FAILED", f"объект снова появился: {item['path']}"
            )


def _projection_document(
    schema_id: str,
    value: Mapping[str, Any],
    *,
    schema_sha: str,
    domain: str,
) -> JsonObject:
    if _SHA256.fullmatch(schema_sha) is None:
        raise InstallerMaintenanceV2Error(
            "PROJECTION_SCHEMA_INVALID", "отпечаток схемы проекции неверен"
        )
    unsigned = {
        "schemaId": schema_id,
        "schemaSha256": schema_sha,
        "value": copy.deepcopy(dict(value)),
    }
    return {
        **unsigned,
        "valueFingerprint": domain_fingerprint(domain, unsigned),
    }


def _absence_projection(
    *,
    installation_id: str,
    operation_id: str,
    paths: tuple[Path, ...],
    schema_sha: str,
) -> JsonObject:
    entries = []
    for path in paths:
        if _path_exists(path):
            raise InstallerMaintenanceV2Error(
                "ABSENCE_PROOF_FAILED", f"объект существует: {path}"
            )
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise InstallerMaintenanceV2Error(
                "ABSENCE_PROOF_FAILED", f"родитель небезопасен: {path.parent}"
            )
        entries.append(
            {
                "path": str(path),
                "basename": path.name,
                "parentDevice": parent.st_dev,
                "parentInode": parent.st_ino,
                "absent": True,
            }
        )
    entries.sort(key=lambda value: str(value["path"]).encode("utf-8"))
    seed = {
        "installationId": installation_id,
        "operationId": operation_id,
        "entries": entries,
    }
    value: JsonObject = {
        "proofId": "ap2_" + domain_fingerprint("codex-smart/absence-proof-id/v2", seed)[:32],
        **seed,
        "directorySyncCompleted": True,
    }
    value["proofFingerprint"] = domain_fingerprint(
        "codex-smart/absence-proof/v2", value
    )
    return _projection_document(
        "absence-proof-v2",
        value,
        schema_sha=schema_sha,
        domain="codex-smart/absence-proof-projection/v2",
    )


def _journal_path_is(value: object, parent: Path, *, suffix: str) -> bool:
    if type(value) is not str:
        return False
    path = Path(value)
    return path.is_absolute() and path.parent == parent and path.name.endswith(suffix)


def _verify_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerMaintenanceV2Error(
            "PRIVATE_DIRECTORY_INVALID", f"каталог недоступен: {path}"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise InstallerMaintenanceV2Error(
            "PRIVATE_DIRECTORY_INVALID", f"каталог небезопасен: {path}"
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        _checkpoint_operation_deadline_if_scoped_v2()
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("короткая запись")
        offset += written


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        _checkpoint_operation_deadline_if_scoped_v2()
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise InstallerMaintenanceV2Error(
                "DOCUMENT_TOO_LARGE", "документ превысил допустимый размер"
            )


def uninstall_retain_data_v2(
    layout: InstallerMaintenanceLayoutV2,
    *,
    registrations: RegistrationCallbacksV2,
    execute: bool,
    retain_data: bool,
    now: Callable[[], str],
    id_factory: Callable[[str], str] | None = None,
    failure_injector: Callable[[str], None] | None = None,
) -> MaintenanceResultV2:
    """Удалить доказанную установку, сохранив рабочие данные и recovery-вход."""

    inject = failure_injector or (lambda _point: None)
    if not retain_data:
        raise InstallerMaintenanceV2Error(
            "RETAIN_DATA_REQUIRED",
            "в выпуске 0.2 поддерживается только uninstall --retain-data",
        )
    if _path_exists(layout.cleanup_journal_path):
        raise InstallerMaintenanceV2Error(
            "OPERATION_IN_PROGRESS", "незавершённый cleanup блокирует uninstall"
        )
    _reject_competing_uninstall_journals(layout)
    if _path_exists(layout.uninstall_journal_path):
        journal = _read_uninstall_journal(layout)
        if not execute:
            return _uninstall_result_from_journal(
                layout, journal, status="planned"
            )
        with _installation_lock(layout.lock_path):
            journal = _read_uninstall_journal(layout)
            return _execute_uninstall_journal(
                layout,
                journal,
                registrations=registrations,
                now=now,
                inject=inject,
            )
    if _path_exists(layout.tombstone_path):
        if _path_exists(layout.manifest_path) or _path_exists(
            layout.installer_receipt_path
        ):
            raise InstallerMaintenanceV2Error(
                "TOMBSTONE_CONFLICT",
                "надгробный указатель существует рядом с активной установкой",
            )
        return _verify_completed_uninstall(layout, registrations=registrations)

    inventory = inspect_maintenance_inventory_v2(
        layout, registrations=registrations
    )
    _raise_inventory_issues(inventory)
    installation_id = _required_installation_id(inventory.installation_id)
    _require_supported_original_backup(inventory)
    if not execute:
        return MaintenanceResultV2(
            command="uninstall",
            status="planned",
            installation_id=installation_id,
            operation_id=None,
            activation_ids=tuple(
                item.activation_id for item in inventory.owned_activations
            ),
            removed_paths=(),
            retained_paths=inventory.retained_paths,
        )
    with _installation_lock(layout.lock_path):
        if _path_exists(layout.cleanup_journal_path):
            raise InstallerMaintenanceV2Error(
                "OPERATION_IN_PROGRESS", "незавершённый cleanup блокирует uninstall"
            )
        _reject_competing_uninstall_journals(layout)
        if _path_exists(layout.uninstall_journal_path):
            journal = _read_uninstall_journal(layout)
        else:
            fresh = inspect_maintenance_inventory_v2(
                layout, registrations=registrations
            )
            _raise_inventory_issues(fresh)
            if (
                fresh.installation_id != inventory.installation_id
                or fresh.active_activation_id != inventory.active_activation_id
                or tuple(item.activation_id for item in fresh.owned_activations)
                != tuple(item.activation_id for item in inventory.owned_activations)
            ):
                raise InstallerMaintenanceV2Error(
                    "UNINSTALL_PLAN_CHANGED",
                    "установка изменилась до создания журнала",
                )
            _require_supported_original_backup(fresh)
            operation_id = _new_identifier("op2", _OPERATION_ID, id_factory)
            journal = _build_uninstall_journal(
                layout, fresh, operation_id=operation_id, now=now
            )
            _atomic_create_json(layout.uninstall_journal_path, journal)
        return _execute_uninstall_journal(
            layout,
            journal,
            registrations=registrations,
            now=now,
            inject=inject,
        )


def _uninstall_result_from_journal(
    layout: InstallerMaintenanceLayoutV2,
    journal: Mapping[str, Any],
    *,
    status: str,
) -> MaintenanceResultV2:
    retained = journal["retainedData"]
    database_path = Path(str(retained["databaseBinding"]["value"]["path"]))
    return MaintenanceResultV2(
        command="uninstall",
        status=status,
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["operationId"]),
        activation_ids=tuple(
            str(item["activationId"]) for item in journal["activationObjects"]
        ),
        removed_paths=(),
        retained_paths=(
            layout.state_home,
            layout.databases_root,
            database_path,
            layout.backups_root,
            layout.quarantine_root,
            layout.recovery_entrypoint,
        ),
        receipt_path=Path(str(journal["receiptPath"])),
        tombstone_path=layout.tombstone_path,
    )


def _reject_competing_uninstall_journals(
    layout: InstallerMaintenanceLayoutV2,
) -> None:
    competing = sorted(
        (
            path
            for path in layout.uninstall_journal_path.parent.glob(
                "*.transaction.json"
            )
            if path != layout.uninstall_journal_path and _path_exists(path)
        ),
        key=lambda path: str(path).encode("utf-8"),
    )
    if competing:
        raise InstallerMaintenanceV2Error(
            "OPERATION_IN_PROGRESS",
            "другой журнал блокирует uninstall: "
            + ", ".join(str(path) for path in competing),
        )


def _require_supported_original_backup(inventory: MaintenanceInventoryV2) -> None:
    manifest = inventory.manifest
    if not isinstance(manifest, Mapping):
        raise InstallerMaintenanceV2Error(
            "MANIFEST_INVALID", "манифест отсутствует"
        )
    original = manifest.get("originalBackup")
    if not isinstance(original, Mapping) or original.get("type") != "absent":
        raise InstallerMaintenanceV2Error(
            "ORIGINAL_BACKUP_RESTORE_INPUT_REQUIRED",
            "для непустой исходной копии нужен отдельный доказанный адаптер восстановления",
        )
    path = original.get("path")
    if type(path) is not str or not Path(path).is_absolute() or _path_exists(Path(path)):
        raise InstallerMaintenanceV2Error(
            "ORIGINAL_BACKUP_CHANGED", "доказанное исходное отсутствие изменилось"
        )


def _build_uninstall_journal(
    layout: InstallerMaintenanceLayoutV2,
    inventory: MaintenanceInventoryV2,
    *,
    operation_id: str,
    now: Callable[[], str],
) -> JsonObject:
    installation_id = _required_installation_id(inventory.installation_id)
    installer = inventory.installer_receipt
    manifest = inventory.manifest
    if not isinstance(installer, Mapping) or not isinstance(manifest, Mapping):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_INPUT_INVALID", "манифест или квитанция установщика отсутствуют"
        )
    active = next(
        (
            item
            for item in inventory.owned_activations
            if item.activation_id == inventory.active_activation_id
        ),
        None,
    )
    if active is None:
        raise InstallerMaintenanceV2Error(
            "PROTECTED_ACTIVATION_UNPROVEN", "активная активация не доказана"
        )
    schema_sha = str(active.activation_projection.get("schemaSha256"))
    if _SHA256.fullmatch(schema_sha) is None:
        raise InstallerMaintenanceV2Error(
            "PROJECTION_SCHEMA_INVALID", "commit-квитанция не содержит схему"
        )
    links = sorted(
        (copy.deepcopy(item) for item in installer["links"]),
        key=lambda item: str(item["path"]).encode("utf-8"),
    )
    registrations = sorted(
        (item.to_document() for item in inventory.registrations),
        key=lambda item: (0 if item["kind"] == "plugin" else 1),
    )
    activation_objects = [
        {
            "activationId": item.activation_id,
            "path": str(item.directory),
            "projection": _projection_document(
                "tree-object-v2",
                item.directory_projection,
                schema_sha=schema_sha,
                domain="codex-smart/tree-object/v2",
            ),
            "receiptPath": str(item.receipt_path),
            "receiptFingerprint": item.receipt_fingerprint,
        }
        for item in inventory.owned_activations
    ]
    original = manifest["originalBackup"]
    created_at = _timestamp(now)
    projection: JsonObject = {
        "schemaVersion": 2,
        "kind": "installer-maintenance-uninstall",
        "installationId": installation_id,
        "operationId": operation_id,
        "activeActivationId": active.activation_id,
        "phase": "MUTATING",
        "registrations": registrations,
        "launcherLinks": links,
        "marketplaceLink": _symlink_projection(
            layout.marketplace_link, schema_sha=schema_sha
        ),
        "activationObjects": activation_objects,
        "manifestFile": _projection_document(
            "file-object-v2",
            _file_projection(layout.manifest_path),
            schema_sha=schema_sha,
            domain="codex-smart/file-object/v2",
        ),
        "installerReceiptFile": _projection_document(
            "file-object-v2",
            _file_projection(layout.installer_receipt_path),
            schema_sha=schema_sha,
            domain="codex-smart/file-object/v2",
        ),
        "retainedData": {
            "databaseBinding": copy.deepcopy(dict(active.database_binding)),
            "backupsRoot": str(layout.backups_root),
            "quarantineRoot": str(layout.quarantine_root),
            "recoveryEntrypoint": _projection_document(
                "file-object-v2",
                _file_projection(layout.recovery_entrypoint),
                schema_sha=schema_sha,
                domain="codex-smart/file-object/v2",
            ),
        },
        "originalBackupPath": str(original["path"]),
        "completedActionIds": [],
        "receiptPath": str(
            layout.receipts_root
            / installation_id
            / f"{operation_id}.uninstall.json"
        ),
        "projectionSchemaSha256": schema_sha,
        "createdAt": created_at,
        "updatedAt": created_at,
        "terminalCompletedAt": None,
    }
    return _with_fingerprint(
        projection,
        key="journalFingerprint",
        domain="codex-smart/installer-maintenance-uninstall-journal/v2",
    )


def _symlink_projection(path: Path, *, schema_sha: str) -> JsonObject:
    try:
        info = path.lstat()
        parent = path.parent.lstat()
        target = os.readlink(path)
    except OSError as exc:
        raise InstallerMaintenanceV2Error(
            "SYMLINK_PROJECTION_CHANGED", f"ссылка недоступна: {path}"
        ) from exc
    if (
        not stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or Path(target).is_absolute()
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
    ):
        raise InstallerMaintenanceV2Error(
            "SYMLINK_PROJECTION_CHANGED", f"ссылка небезопасна: {path}"
        )
    value = {
        "path": str(path),
        "parentDevice": parent.st_dev,
        "parentInode": parent.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "target": target,
        "targetFingerprint": hashlib.sha256(target.encode("utf-8")).hexdigest(),
    }
    return _projection_document(
        "symlink-object-v2",
        value,
        schema_sha=schema_sha,
        domain="codex-smart/symlink-object/v2",
    )


def _uninstall_action_ids(journal: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        *(f"registration:{item['kind']}" for item in journal["registrations"]),
        *(f"launcher:{item['path']}" for item in journal["launcherLinks"]),
        "marketplace-link",
        *(
            f"activation:{item['activationId']}"
            for item in journal["activationObjects"]
        ),
        "manifest",
        "installer-receipt",
    )


def _removed_state_from_uninstall_journal(journal: Mapping[str, Any]) -> JsonObject:
    projection: JsonObject = {
        "fileObjects": [
            copy.deepcopy(journal["manifestFile"]),
            copy.deepcopy(journal["installerReceiptFile"]),
        ],
        "treeObjects": [
            copy.deepcopy(item["projection"])
            for item in journal["activationObjects"]
        ],
        "symlinks": [copy.deepcopy(journal["marketplaceLink"])],
        "manifest": None,
        "activation": None,
        "database": None,
        "controller": None,
        "controllerCandidates": [],
        "watchdogs": [],
        "registry": None,
        "launchers": None,
        "legacyProcesses": None,
        "quiescence": None,
        "externalCommands": [],
        "receipts": [],
        "absenceProofs": [],
    }
    return {
        **projection,
        "bundleFingerprint": domain_fingerprint(
            "codex-smart/state-bundle/v2", projection
        ),
    }


def _read_uninstall_journal(layout: InstallerMaintenanceLayoutV2) -> JsonObject:
    journal = _read_private_json(
        layout.uninstall_journal_path, "UNINSTALL_JOURNAL_INVALID"
    )
    unsigned = {
        key: value for key, value in journal.items() if key != "journalFingerprint"
    }
    installation_id = str(journal.get("installationId"))
    operation_id = str(journal.get("operationId"))
    active_id = str(journal.get("activeActivationId"))
    schema_sha = str(journal.get("projectionSchemaSha256"))
    if (
        set(journal) != _UNINSTALL_JOURNAL_KEYS
        or journal.get("schemaVersion") != 2
        or journal.get("kind") != "installer-maintenance-uninstall"
        or _INSTALLATION_ID.fullmatch(installation_id) is None
        or _OPERATION_ID.fullmatch(operation_id) is None
        or _ACTIVATION_ID.fullmatch(active_id) is None
        or _SHA256.fullmatch(schema_sha) is None
        or journal.get("phase") not in {"MUTATING", "TERMINAL_FROZEN"}
        or journal.get("journalFingerprint")
        != domain_fingerprint(
            "codex-smart/installer-maintenance-uninstall-journal/v2", unsigned
        )
        or not _journal_path_is(
            journal.get("receiptPath"),
            layout.receipts_root / installation_id,
            suffix=".uninstall.json",
        )
    ):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "журнал uninstall не прошёл проверку"
        )
    if Path(str(journal["receiptPath"])).name != f"{operation_id}.uninstall.json":
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "путь квитанции не связан с operationId"
        )
    _validate_uninstall_journal_objects(
        layout,
        journal,
        installation_id=installation_id,
        active_id=active_id,
        schema_sha=schema_sha,
    )
    completed = journal.get("completedActionIds")
    action_ids = _uninstall_action_ids(journal)
    if (
        type(completed) is not list
        or len(completed) != len(set(completed))
        or not set(completed).issubset(action_ids)
        or (journal["phase"] == "TERMINAL_FROZEN" and set(completed) != set(action_ids))
        or (
            journal["phase"] == "TERMINAL_FROZEN"
            and type(journal.get("terminalCompletedAt")) is not str
        )
        or (
            journal["phase"] == "MUTATING"
            and journal.get("terminalCompletedAt") is not None
        )
    ):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "курсор uninstall не связан с планом"
        )
    return journal


def _validate_uninstall_journal_objects(
    layout: InstallerMaintenanceLayoutV2,
    journal: Mapping[str, Any],
    *,
    installation_id: str,
    active_id: str,
    schema_sha: str,
) -> None:
    registrations = journal.get("registrations")
    if type(registrations) is not list or [
        item.get("kind") if isinstance(item, Mapping) else None
        for item in registrations
    ] != ["plugin", "marketplace"]:
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "набор регистраций неверен"
        )
    expected_marketplace = layout.activations_root / active_id / "marketplace"
    expected_registrations = {
        "plugin": (
            "codex-smart-subagents@codex-settings-adaptive",
            expected_marketplace / "plugins" / "codex-smart-subagents",
        ),
        "marketplace": ("codex-settings-adaptive", expected_marketplace),
    }
    for item in registrations:
        if type(item) is not dict or set(item) != {"kind", "name", "target"}:
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_JOURNAL_INVALID", "регистрация имеет неверную форму"
            )
        expected_name, expected_target = expected_registrations[item["kind"]]
        if item["name"] != expected_name or item["target"] != str(expected_target):
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_JOURNAL_INVALID", "регистрация вышла за установку"
            )
    links = journal.get("launcherLinks")
    expected_bin = (
        layout.marketplace_link / "plugins" / "codex-smart-subagents" / "bin"
    )
    if type(links) is not list or len(links) != 2:
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "набор загрузчиков неверен"
        )
    names: set[str] = set()
    for item in links:
        if type(item) is not dict or set(item) != {"path", "target"}:
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_JOURNAL_INVALID", "загрузчик имеет неверную форму"
            )
        path = Path(str(item["path"]))
        target = Path(str(item["target"]))
        if (
            not path.is_absolute()
            or path.name not in {"codex-smart", "codex-smart-subagents-admin"}
            or path.name in names
            or target != expected_bin / path.name
        ):
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_JOURNAL_INVALID", "загрузчик вышел за установку"
            )
        names.add(path.name)
    _verify_bound_projection(
        journal.get("marketplaceLink"),
        schema_id="symlink-object-v2",
        schema_sha=schema_sha,
        domain="codex-smart/symlink-object/v2",
        expected_path=layout.marketplace_link,
    )
    _verify_bound_projection(
        journal.get("manifestFile"),
        schema_id="file-object-v2",
        schema_sha=schema_sha,
        domain="codex-smart/file-object/v2",
        expected_path=layout.manifest_path,
    )
    _verify_bound_projection(
        journal.get("installerReceiptFile"),
        schema_id="file-object-v2",
        schema_sha=schema_sha,
        domain="codex-smart/file-object/v2",
        expected_path=layout.installer_receipt_path,
    )
    objects = journal.get("activationObjects")
    if type(objects) is not list or not objects:
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "активации отсутствуют"
        )
    observed_ids: set[str] = set()
    for item in objects:
        if type(item) is not dict or set(item) != {
            "activationId",
            "path",
            "projection",
            "receiptPath",
            "receiptFingerprint",
        }:
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_JOURNAL_INVALID", "активация имеет неверную форму"
            )
        activation_id = str(item["activationId"])
        path = layout.activations_root / activation_id
        if (
            _ACTIVATION_ID.fullmatch(activation_id) is None
            or activation_id in observed_ids
            or item["path"] != str(path)
        ):
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_JOURNAL_INVALID", "активация вышла за закрытый корень"
            )
        _verify_bound_projection(
            item["projection"],
            schema_id="tree-object-v2",
            schema_sha=schema_sha,
            domain="codex-smart/tree-object/v2",
            expected_path=path,
        )
        _verify_commit_ownership_reference(
            layout,
            path=item["receiptPath"],
            receipt_fingerprint=item["receiptFingerprint"],
            installation_id=installation_id,
            activation_id=activation_id,
            directory_projection=item["projection"]["value"],
        )
        observed_ids.add(activation_id)
    if active_id not in observed_ids:
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "активная активация отсутствует"
        )
    _verify_uninstall_retained_data(layout, journal["retainedData"])
    original = Path(str(journal.get("originalBackupPath")))
    if not original.is_absolute() or _path_exists(original):
        raise InstallerMaintenanceV2Error(
            "ORIGINAL_BACKUP_CHANGED", "исходное отсутствие больше не доказано"
        )


def _verify_bound_projection(
    projection: object,
    *,
    schema_id: str,
    schema_sha: str,
    domain: str,
    expected_path: Path,
) -> None:
    if not isinstance(projection, Mapping):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "проекция отсутствует"
        )
    unsigned = {
        "schemaId": projection.get("schemaId"),
        "schemaSha256": projection.get("schemaSha256"),
        "value": copy.deepcopy(projection.get("value")),
    }
    value = projection.get("value")
    if (
        set(projection) != {"schemaId", "schemaSha256", "value", "valueFingerprint"}
        or projection.get("schemaId") != schema_id
        or projection.get("schemaSha256") != schema_sha
        or not isinstance(value, Mapping)
        or value.get("path") != str(expected_path)
        or projection.get("valueFingerprint") != domain_fingerprint(domain, unsigned)
    ):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "проекция не связана с журналом"
        )


def _verify_uninstall_retained_data(
    layout: InstallerMaintenanceLayoutV2, retained: object
) -> None:
    if not isinstance(retained, Mapping) or set(retained) != {
        "databaseBinding",
        "backupsRoot",
        "quarantineRoot",
        "recoveryEntrypoint",
    }:
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_INVALID", "сохраняемые данные имеют неверную форму"
        )
    if retained["backupsRoot"] != str(layout.backups_root) or retained[
        "quarantineRoot"
    ] != str(layout.quarantine_root):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_INVALID", "сохраняемые каталоги изменились"
        )
    database = retained["databaseBinding"]
    recovery = retained["recoveryEntrypoint"]
    if (
        not isinstance(database, Mapping)
        or database.get("schemaId") != "database-binding-v2"
        or not isinstance(database.get("value"), Mapping)
        or not _is_within(Path(str(database["value"].get("path"))), layout.databases_root)
        or not _durable_file_binding_matches(
            Path(str(database["value"]["path"])),
            database["value"],
        )
        or not isinstance(recovery, Mapping)
        or recovery.get("schemaId") != "file-object-v2"
        or not isinstance(recovery.get("value"), Mapping)
        or not _durable_projection_matches(
            _file_projection(layout.recovery_entrypoint),
            recovery["value"],
        )
    ):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_CHANGED", "сохраняемые данные изменились"
        )
    for path in (
        layout.state_home,
        layout.databases_root,
        layout.backups_root,
        layout.quarantine_root,
    ):
        try:
            info = path.lstat()
        except OSError as exc:
            raise InstallerMaintenanceV2Error(
                "RETAINED_DATA_CHANGED", f"каталог недоступен: {path}"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
        ):
            raise InstallerMaintenanceV2Error(
                "RETAINED_DATA_CHANGED", f"каталог изменился: {path}"
            )


def _execute_uninstall_journal(
    layout: InstallerMaintenanceLayoutV2,
    journal: JsonObject,
    *,
    registrations: RegistrationCallbacksV2,
    now: Callable[[], str],
    inject: Callable[[str], None],
) -> MaintenanceResultV2:
    journal = _read_uninstall_journal(layout)
    removed: list[Path] = []
    if journal["phase"] == "MUTATING":
        for item in journal["registrations"]:
            action_id = f"registration:{item['kind']}"
            journal = _execute_registration_removal(
                layout,
                journal,
                action_id=action_id,
                document=item,
                registrations=registrations,
                now=now,
                inject=inject,
            )
        for item in journal["launcherLinks"]:
            path = Path(str(item["path"]))
            action_id = f"launcher:{path}"
            journal, changed = _execute_symlink_removal(
                layout,
                journal,
                action_id=action_id,
                path=path,
                expected_target=str(item["target"]),
                now=now,
                inject=inject,
            )
            if changed:
                removed.append(path)
        marketplace_value = journal["marketplaceLink"]["value"]
        journal, changed = _execute_symlink_removal(
            layout,
            journal,
            action_id="marketplace-link",
            path=layout.marketplace_link,
            expected_target=str(marketplace_value["target"]),
            now=now,
            inject=inject,
        )
        if changed:
            removed.append(layout.marketplace_link)
        for item in journal["activationObjects"]:
            path = Path(str(item["path"]))
            action_id = f"activation:{item['activationId']}"
            if action_id in journal["completedActionIds"]:
                if _path_exists(path):
                    raise InstallerMaintenanceV2Error(
                        "UNINSTALL_RECOVERY_AMBIGUOUS",
                        f"завершённая активация снова появилась: {path}",
                    )
                continue
            changed = False
            if _path_exists(path):
                projection = item["projection"]["value"]
                if not _durable_projection_matches(
                    _tree_projection(path),
                    projection,
                ):
                    raise InstallerMaintenanceV2Error(
                        "ACTIVATION_PROJECTION_CHANGED",
                        f"активация изменилась перед удалением: {path}",
                    )
                _remove_tree_exact(path, projection)
                changed = True
                inject("uninstall_after_path_remove")
            if _path_exists(path):
                raise InstallerMaintenanceV2Error(
                    "UNINSTALL_DELETE_FAILED", f"активация не удалена: {path}"
                )
            journal = _complete_uninstall_action(
                layout, journal, action_id=action_id, now=now
            )
            if changed:
                removed.append(path)
        for action_id, projection in (
            ("manifest", journal["manifestFile"]),
            ("installer-receipt", journal["installerReceiptFile"]),
        ):
            path = Path(str(projection["value"]["path"]))
            journal, changed = _execute_file_removal(
                layout,
                journal,
                action_id=action_id,
                path=path,
                expected=projection["value"],
                now=now,
                inject=inject,
            )
            if changed:
                removed.append(path)
        _verify_uninstall_effect_absence(layout, journal, registrations=registrations)
        terminal_at = _timestamp(now)
        journal = _replace_journal(
            layout.uninstall_journal_path,
            journal,
            {
                **journal,
                "phase": "TERMINAL_FROZEN",
                "terminalCompletedAt": terminal_at,
                "updatedAt": terminal_at,
            },
            domain="codex-smart/installer-maintenance-uninstall-journal/v2",
        )

    receipt = _build_uninstall_receipt(layout, journal)
    receipt_path = Path(str(journal["receiptPath"]))
    _publish_or_verify_json(
        receipt_path, receipt, code="UNINSTALL_RECEIPT_CONFLICT"
    )
    inject("uninstall_after_receipt")
    tombstone = _build_uninstall_tombstone(
        layout, journal, receipt=receipt, receipt_path=receipt_path
    )
    _publish_or_verify_json(
        layout.tombstone_path, tombstone, code="TOMBSTONE_CONFLICT"
    )
    inject("uninstall_after_tombstone")
    verified = _verify_completed_uninstall(layout, registrations=registrations)
    _delete_private_file(layout.uninstall_journal_path)
    return MaintenanceResultV2(
        command="uninstall",
        status="uninstalled",
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["operationId"]),
        activation_ids=verified.activation_ids,
        removed_paths=tuple(removed),
        retained_paths=verified.retained_paths,
        receipt_path=receipt_path,
        tombstone_path=layout.tombstone_path,
    )


def _execute_registration_removal(
    layout: InstallerMaintenanceLayoutV2,
    journal: JsonObject,
    *,
    action_id: str,
    document: Mapping[str, Any],
    registrations: RegistrationCallbacksV2,
    now: Callable[[], str],
    inject: Callable[[str], None],
) -> JsonObject:
    expected = RegistrationObservationV2(
        kind=str(document["kind"]),
        name=str(document["name"]),
        target=Path(str(document["target"])),
    )
    observed = registrations.observe(expected.kind, expected.name)
    if action_id in journal["completedActionIds"]:
        if observed is not None:
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_RECOVERY_AMBIGUOUS",
                f"удалённая регистрация снова появилась: {expected.kind}",
            )
        return journal
    if observed is not None:
        if observed != expected:
            raise InstallerMaintenanceV2Error(
                "REGISTRATION_OWNERSHIP_AMBIGUOUS",
                f"регистрация изменилась: {expected.kind}",
            )
        registrations.remove(expected)
        inject("uninstall_after_registration_remove")
    if registrations.observe(expected.kind, expected.name) is not None:
        raise InstallerMaintenanceV2Error(
            "REGISTRATION_REMOVE_FAILED",
            f"регистрация не удалена: {expected.kind}",
        )
    return _complete_uninstall_action(
        layout, journal, action_id=action_id, now=now
    )


def _execute_symlink_removal(
    layout: InstallerMaintenanceLayoutV2,
    journal: JsonObject,
    *,
    action_id: str,
    path: Path,
    expected_target: str,
    now: Callable[[], str],
    inject: Callable[[str], None],
) -> tuple[JsonObject, bool]:
    if action_id in journal["completedActionIds"]:
        if _path_exists(path):
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_RECOVERY_AMBIGUOUS",
                f"удалённая ссылка снова появилась: {path}",
            )
        return journal, False
    changed = False
    if _path_exists(path):
        try:
            info = path.lstat()
            target = os.readlink(path)
        except OSError as exc:
            raise InstallerMaintenanceV2Error(
                "SYMLINK_PROJECTION_CHANGED", f"ссылка недоступна: {path}"
            ) from exc
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or target != expected_target
        ):
            raise InstallerMaintenanceV2Error(
                "SYMLINK_PROJECTION_CHANGED", f"ссылка изменилась: {path}"
            )
        path.unlink()
        _fsync_directory(path.parent)
        changed = True
        inject("uninstall_after_path_remove")
    if _path_exists(path):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_DELETE_FAILED", f"ссылка не удалена: {path}"
        )
    journal = _complete_uninstall_action(
        layout, journal, action_id=action_id, now=now
    )
    return journal, changed


def _execute_file_removal(
    layout: InstallerMaintenanceLayoutV2,
    journal: JsonObject,
    *,
    action_id: str,
    path: Path,
    expected: Mapping[str, Any],
    now: Callable[[], str],
    inject: Callable[[str], None],
) -> tuple[JsonObject, bool]:
    if action_id in journal["completedActionIds"]:
        if _path_exists(path):
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_RECOVERY_AMBIGUOUS",
                f"удалённый файл снова появился: {path}",
            )
        return journal, False
    changed = False
    if _path_exists(path):
        if not _durable_projection_matches(
            _file_projection(path),
            expected,
        ):
            raise InstallerMaintenanceV2Error(
                "FILE_PROJECTION_CHANGED", f"файл изменился: {path}"
            )
        path.unlink()
        _fsync_directory(path.parent)
        changed = True
        inject("uninstall_after_path_remove")
    if _path_exists(path):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_DELETE_FAILED", f"файл не удалён: {path}"
        )
    journal = _complete_uninstall_action(
        layout, journal, action_id=action_id, now=now
    )
    return journal, changed


def _complete_uninstall_action(
    layout: InstallerMaintenanceLayoutV2,
    journal: JsonObject,
    *,
    action_id: str,
    now: Callable[[], str],
) -> JsonObject:
    if action_id in journal["completedActionIds"]:
        return journal
    return _replace_journal(
        layout.uninstall_journal_path,
        journal,
        {
            **journal,
            "completedActionIds": [*journal["completedActionIds"], action_id],
            "updatedAt": _timestamp(now),
        },
        domain="codex-smart/installer-maintenance-uninstall-journal/v2",
    )


def _uninstall_removed_paths(journal: Mapping[str, Any]) -> tuple[Path, ...]:
    return tuple(
        dict.fromkeys(
            [
                *(Path(str(item["path"])) for item in journal["launcherLinks"]),
                Path(str(journal["marketplaceLink"]["value"]["path"])),
                *(Path(str(item["path"])) for item in journal["activationObjects"]),
                Path(str(journal["manifestFile"]["value"]["path"])),
                Path(str(journal["installerReceiptFile"]["value"]["path"])),
            ]
        )
    )


def _verify_uninstall_effect_absence(
    layout: InstallerMaintenanceLayoutV2,
    journal: Mapping[str, Any],
    *,
    registrations: RegistrationCallbacksV2,
) -> None:
    for item in journal["registrations"]:
        if registrations.observe(str(item["kind"]), str(item["name"])) is not None:
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_RESIDUE", f"регистрация осталась: {item['kind']}"
            )
    for path in _uninstall_removed_paths(journal):
        if _path_exists(path):
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_RESIDUE", f"объект остался после удаления: {path}"
            )
    _verify_uninstall_retained_data(layout, journal["retainedData"])


def _build_uninstall_receipt(
    layout: InstallerMaintenanceLayoutV2,
    journal: Mapping[str, Any],
) -> JsonObject:
    if journal.get("phase") != "TERMINAL_FROZEN":
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_JOURNAL_INVALID", "квитанция требует замороженный журнал"
        )
    schema_sha = str(journal["projectionSchemaSha256"])
    absence = _absence_projection(
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["operationId"]),
        paths=_uninstall_removed_paths(journal),
        schema_sha=schema_sha,
    )
    restored_original = _absence_projection(
        installation_id=str(journal["installationId"]),
        operation_id=str(journal["operationId"]),
        paths=(Path(str(journal["originalBackupPath"])),),
        schema_sha=schema_sha,
    )
    projection: JsonObject = {
        "schemaVersion": 2,
        "receiptKind": "installation-uninstall",
        "installationId": journal["installationId"],
        "operationId": journal["operationId"],
        "frozenJournalFingerprint": journal["journalFingerprint"],
        "dataRetentionMode": "retain-data",
        "retainedData": copy.deepcopy(journal["retainedData"]),
        "removedState": _removed_state_from_uninstall_journal(journal),
        "restoredOriginalBackup": restored_original,
        "absenceProof": absence,
        "completedAt": journal["terminalCompletedAt"],
    }
    return _with_fingerprint(
        projection,
        key="receiptFingerprint",
        domain="codex-smart/installation-uninstall-receipt/v2",
    )


def _build_uninstall_tombstone(
    layout: InstallerMaintenanceLayoutV2,
    journal: Mapping[str, Any],
    *,
    receipt: Mapping[str, Any],
    receipt_path: Path,
) -> JsonObject:
    schema_sha = str(journal["projectionSchemaSha256"])
    receipt_projection = _projection_document(
        "receipt-object-v2",
        {
            "file": _file_projection(receipt_path),
            "receiptKind": "installation-uninstall",
            "installationId": journal["installationId"],
            "operationId": journal["operationId"],
            "receiptFingerprint": receipt["receiptFingerprint"],
        },
        schema_sha=schema_sha,
        domain="codex-smart/receipt-object/v2",
    )
    projection: JsonObject = {
        "schemaVersion": 2,
        "installationId": journal["installationId"],
        "operationId": journal["operationId"],
        "uninstallReceipt": receipt_projection,
        "absenceProof": copy.deepcopy(receipt["absenceProof"]),
        "completedAt": journal["terminalCompletedAt"],
    }
    return _with_fingerprint(
        projection,
        key="tombstoneFingerprint",
        domain="codex-smart/installation-tombstone/v2",
    )


def _verify_completed_uninstall(
    layout: InstallerMaintenanceLayoutV2,
    *,
    registrations: RegistrationCallbacksV2,
) -> MaintenanceResultV2:
    tombstone = _read_private_json(layout.tombstone_path, "TOMBSTONE_CONFLICT")
    unsigned_tombstone = {
        key: value for key, value in tombstone.items() if key != "tombstoneFingerprint"
    }
    installation_id = tombstone.get("installationId")
    operation_id = tombstone.get("operationId")
    receipt_projection = tombstone.get("uninstallReceipt")
    try:
        receipt_value = receipt_projection["value"]
        receipt_path = Path(str(receipt_value["file"]["path"]))
    except (KeyError, TypeError) as exc:
        raise InstallerMaintenanceV2Error(
            "TOMBSTONE_CONFLICT", "tombstone не содержит uninstall-квитанцию"
        ) from exc
    if (
        set(tombstone) != _TOMBSTONE_KEYS
        or tombstone.get("schemaVersion") != 2
        or not isinstance(receipt_projection, Mapping)
        or receipt_projection.get("schemaId") != "receipt-object-v2"
        or receipt_value.get("receiptKind") != "installation-uninstall"
        or _INSTALLATION_ID.fullmatch(str(installation_id)) is None
        or _OPERATION_ID.fullmatch(str(operation_id)) is None
        or tombstone.get("tombstoneFingerprint")
        != domain_fingerprint("codex-smart/installation-tombstone/v2", unsigned_tombstone)
        or not _journal_path_is(
            str(receipt_path),
            layout.receipts_root / str(installation_id),
            suffix=".uninstall.json",
        )
    ):
        raise InstallerMaintenanceV2Error(
            "TOMBSTONE_CONFLICT", "tombstone не прошёл закрытую проверку"
        )
    receipt = _read_private_json(receipt_path, "UNINSTALL_RECEIPT_CONFLICT")
    unsigned_receipt = {
        key: value for key, value in receipt.items() if key != "receiptFingerprint"
    }
    if (
        set(receipt) != _UNINSTALL_RECEIPT_KEYS
        or receipt.get("schemaVersion") != 2
        or receipt.get("receiptKind") != "installation-uninstall"
        or receipt.get("installationId") != installation_id
        or receipt.get("operationId") != operation_id
        or receipt.get("dataRetentionMode") != "retain-data"
        or receipt.get("receiptFingerprint")
        != domain_fingerprint(
            "codex-smart/installation-uninstall-receipt/v2", unsigned_receipt
        )
        or receipt_value.get("receiptFingerprint") != receipt.get("receiptFingerprint")
        or not isinstance(receipt_value.get("file"), Mapping)
        or not _durable_projection_matches(
            _file_projection(receipt_path),
            receipt_value["file"],
        )
        or canonical_json_bytes(tombstone.get("absenceProof"))
        != canonical_json_bytes(receipt.get("absenceProof"))
    ):
        raise InstallerMaintenanceV2Error(
            "UNINSTALL_RECEIPT_CONFLICT", "uninstall-квитанция изменилась"
        )
    _verify_absence_projection(receipt["absenceProof"])
    retained_paths = _verify_retained_receipt(layout, receipt["retainedData"])
    installer = receipt.get("removedState", {})
    for observation in (
        registrations.observe("marketplace", "codex-settings-adaptive"),
        registrations.observe(
            "plugin", "codex-smart-subagents@codex-settings-adaptive"
        ),
    ):
        if observation is not None:
            raise InstallerMaintenanceV2Error(
                "UNINSTALL_RESIDUE", "регистрация снова появилась"
            )
    activation_ids = tuple(
        Path(str(item["value"]["path"])).name
        for item in installer.get("treeObjects", [])
    )
    return MaintenanceResultV2(
        command="uninstall",
        status="unchanged",
        installation_id=str(installation_id),
        operation_id=str(operation_id),
        activation_ids=activation_ids,
        removed_paths=(),
        retained_paths=retained_paths,
        receipt_path=receipt_path,
        tombstone_path=layout.tombstone_path,
    )


def _verify_retained_receipt(
    layout: InstallerMaintenanceLayoutV2,
    retained: object,
) -> tuple[Path, ...]:
    if not isinstance(retained, Mapping):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_INVALID", "retainedData отсутствует"
        )
    if retained.get("backupsRoot") != str(layout.backups_root) or retained.get(
        "quarantineRoot"
    ) != str(layout.quarantine_root):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_INVALID", "пути сохранённых данных изменились"
        )
    database = retained.get("databaseBinding")
    recovery = retained.get("recoveryEntrypoint")
    if not isinstance(database, Mapping) or not isinstance(recovery, Mapping):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_INVALID", "проекции сохранённых данных отсутствуют"
        )
    database_value = database.get("value")
    recovery_value = recovery.get("value")
    if not isinstance(database_value, Mapping) or not isinstance(recovery_value, Mapping):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_INVALID", "значения проекций сохранённых данных неверны"
        )
    database_path = Path(str(database_value.get("path")))
    if (
        not _is_within(database_path, layout.databases_root)
        or not _durable_file_binding_matches(database_path, database_value)
        or not _durable_projection_matches(
            _file_projection(layout.recovery_entrypoint),
            recovery_value,
        )
    ):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_CHANGED", "сохранённый inode или точка восстановления изменены"
        )
    return (
        layout.state_home,
        layout.databases_root,
        database_path,
        layout.backups_root,
        layout.quarantine_root,
        layout.recovery_entrypoint,
    )


def _verify_absence_projection(projection: object) -> None:
    if not isinstance(projection, Mapping) or projection.get("schemaId") != "absence-proof-v2":
        raise InstallerMaintenanceV2Error(
            "ABSENCE_PROOF_FAILED", "проекция отсутствия имеет неверный вид"
        )
    value = projection.get("value")
    if not isinstance(value, Mapping):
        raise InstallerMaintenanceV2Error(
            "ABSENCE_PROOF_FAILED", "значение доказательства отсутствует"
        )
    unsigned = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "proofFingerprint"
    }
    if (
        value.get("directorySyncCompleted") is not True
        or value.get("proofFingerprint")
        != domain_fingerprint("codex-smart/absence-proof/v2", unsigned)
        or type(value.get("entries")) is not list
    ):
        raise InstallerMaintenanceV2Error(
            "ABSENCE_PROOF_FAILED", "отпечаток доказательства отсутствия неверен"
        )
    for entry in value["entries"]:
        if not isinstance(entry, Mapping):
            raise InstallerMaintenanceV2Error(
                "ABSENCE_PROOF_FAILED", "запись отсутствия неверна"
            )
        path = Path(str(entry.get("path")))
        if _path_exists(path):
            raise InstallerMaintenanceV2Error(
                "ABSENCE_PROOF_FAILED", f"объект снова существует: {path}"
            )
        try:
            parent = path.parent.lstat()
        except OSError as exc:
            raise InstallerMaintenanceV2Error(
                "ABSENCE_PROOF_FAILED", f"родитель недоступен: {path.parent}"
            ) from exc
        if (
            entry.get("basename") != path.name
            or not _captured_device_is_valid(entry.get("parentDevice"))
            or entry.get("parentInode") != parent.st_ino
            or entry.get("absent") is not True
        ):
            raise InstallerMaintenanceV2Error(
                "ABSENCE_PROOF_FAILED", f"родитель объекта изменился: {path}"
            )


def _binding_tuple(value: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        value.get("inode"),
        value.get("ownerUid"),
        value.get("ownerGid"),
        value.get("mode"),
        value.get("linkCount"),
    )


def _file_binding_observation(path: Path) -> tuple[object, ...]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_CHANGED", f"файл базы недоступен: {path}"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise InstallerMaintenanceV2Error(
            "RETAINED_DATA_CHANGED", f"путь базы не является файлом: {path}"
        )
    return (
        info.st_ino,
        info.st_uid,
        info.st_gid,
        f"0{stat.S_IMODE(info.st_mode):03o}",
        info.st_nlink,
    )


def _durable_file_binding_matches(
    path: Path,
    captured: Mapping[str, Any],
) -> bool:
    return (
        _captured_device_is_valid(captured.get("device"))
        and _file_binding_observation(path) == _binding_tuple(captured)
    )
