"""Материализация неизменяемой активации версии 2 до границы `health`.

Модуль намеренно не запускает и не изображает контроллер. Он собирает
замкнутую файловую проекцию и базу только для уже существующего кандидата,
но не публикует `marketplace-current`. Отдельная функция публикации сначала
доказывает всю активацию тем же :class:`ActivationResolver`, который
используют постоянные загрузчики.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import stat
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol
from urllib.parse import quote

from .activation_gateway_v2 import (
    ActivationResolver,
    GatewayDecision,
    GatewayLayout,
    GatewayState,
    _LIFECYCLE_SCHEMA_SHA256,
    _file_projection,
    _journal_projection,
    _tree_projection,
    _tree_sha256,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from . import finite_file_lock_v2
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .codex_binary_snapshot import (
    CodexBinarySnapshotter,
    SnapshotCommandExecutor,
)
from .interface_probe_v1 import probe_codex_interface_v1
from .operation_deadline_v2 import (
    OperationDeadlineExceededV2,
    checkpoint_current_operation_deadline_if_scoped_v2,
)
from .policy_bundle_v2 import PolicyBundleV2
from .state_store_v2 import (
    AcceptingControllerV2,
    DatabaseIdentityV2,
    SmartStoreV2,
)
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2


_RELEASE = "0.2.0"
_PLUGIN_NAME = "codex-smart-subagents"
_MARKETPLACE_NAME = "codex-settings-adaptive"
_POLICY_VECTOR_FILES = (
    "routing-policy-v2.json",
    "delegation-policy-v2.json",
    "role-template-v1.json",
    "child-profile-v1.json",
)
_RUNTIME_VECTOR_FILES = ("lifecycle-v2.json",)
_RUNTIME_SCHEMA_FILES = (
    "account-evidence-v1.schema.json",
    "activation-commit-receipt-v2.schema.json",
    "activation-preparation-journal-v2.schema.json",
    "activation-preparation-receipt-v2.schema.json",
    "activation-transition-proof-snapshot-v2.schema.json",
    "boundary-result-v1.schema.json",
    "child-attestation-v2.schema.json",
    "child-jsonl-v1.schema.json",
    "child-profile-v1.schema.json",
    "cleanup-journal-v2.schema.json",
    "cleanup-receipt-v2.schema.json",
    "config-requirements-normalized-v1.schema.json",
    "config-requirements-vector-case-v1.schema.json",
    "config-requirements-vector-recipe-v1.schema.json",
    "context-bundle-v1.schema.json",
    "controller-protocol-v2.schema.json",
    "delegation-policy-v2.schema.json",
    "installation-tombstone-v2.schema.json",
    "installation-uninstall-receipt-v2.schema.json",
    "installer-receipt-v2.schema.json",
    "interface-evidence-mutation-v1.schema.json",
    "interface-evidence-v1.schema.json",
    "lifecycle-automaton-v2.schema.json",
    "lifecycle-command-result-v2.schema.json",
    "lifecycle-fingerprint-registry-v2.schema.json",
    "lifecycle-projection-v2.schema.json",
    "lifecycle-vector-suite-v2.schema.json",
    "manifest-document-v2.schema.json",
    "operation-abort-receipt-v2.schema.json",
    "operation-journal-v2.schema.json",
    "operation-step-v2.schema.json",
    "otel-logs-v1.schema.json",
    "protocol-vector-suite-v2.schema.json",
    "reader-result-v1.schema.json",
    "role-template-v1.schema.json",
    "rollback-manifest-preparation-journal-v2.schema.json",
    "rollback-manifest-preparation-receipt-v2.schema.json",
    "routing-input-v2.schema.json",
    "routing-policy-v2.schema.json",
    "smart-turn-protocol-v2.schema.json",
    "task-facts-v1.schema.json",
    "writer-result-v1.schema.json",
)
_EXCLUDED_TREE_NAMES = frozenset({"__pycache__", ".DS_Store"})


@dataclass
class ActivationMaterializationV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ControllerCandidateV2:
    """Наблюдаемая идентичность уже запущенного кандидата контроллера."""

    instance_id: str
    controller_start_id: str
    pid: int
    process_start_marker: str
    process_group_id: int
    control_epoch: int
    socket_path: Path
    updated_at: datetime


@dataclass(frozen=True)
class ActivationMaterializationV2:
    status: str
    readiness: str
    codex_home: Path
    state_home: Path
    activation_id: str
    activation_fingerprint: str
    installation_id: str
    operation_id: str
    controller_identity: str
    activation_dir: Path
    snapshot_path: Path
    bundled_catalog_path: Path
    bundled_catalog: Mapping[str, Any]
    interface_evidence: Mapping[str, Any]
    receipt_path: Path
    expected_health_payload: Mapping[str, Any]


class _Snapshotter(Protocol):
    def materialize(
        self, source_locator: str | os.PathLike[str]
    ) -> dict[str, object]: ...

    def materialize_with_identity(self, source_locator: str | os.PathLike[str]): ...


@dataclass(frozen=True)
class _OwnedDirectoryV2:
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int


@dataclass(frozen=True)
class _OwnedRegularFileV2:
    path: Path
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    link_count: int
    size: int
    sha256: str


@dataclass(frozen=True)
class _OwnedTreeEntryV2:
    path: Path
    kind: str
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    link_count: int
    size: int
    content_identity: str | None


@dataclass(frozen=True)
class _StagingOwnershipV2:
    created_directories: tuple[_OwnedDirectoryV2, ...]
    lifecycle_lock: _OwnedRegularFileV2 | None
    snapshot_file: _OwnedRegularFileV2 | None
    snapshot_directory: _OwnedDirectoryV2 | None
    activation_tree: tuple[_OwnedTreeEntryV2, ...] = ()


@dataclass(frozen=True)
class StagedActivationV2:
    """Неизменяемая идентичность активации до появления контроллера."""

    status: str
    readiness: str
    source_root: Path
    codex_home: Path
    codex_binary: Path
    state_home: Path
    socket_path: Path
    controller_lock_path: Path
    installation_id: str
    operation_id: str
    database_id: str
    activation_binding_nonce: str
    activation_id: str
    activation_fingerprint: str
    controller_identity: str
    compatibility_fingerprint: str
    routing_policy_fingerprint: str
    bundled_catalog_fingerprint: str
    schema_fingerprint: str
    schema_artifact_sha256: str
    activation_dir: Path
    snapshot_path: Path
    database_path: Path
    bundled_catalog_path: Path
    identity: Mapping[str, Any]
    activation_document: Mapping[str, Any]
    source_locator: Mapping[str, Any]
    snapshot_locator: Mapping[str, Any]
    bundled_catalog: Mapping[str, Any]
    interface_evidence: Mapping[str, Any]
    completed_at: datetime
    staging_ownership: _StagingOwnershipV2 | None = None


@dataclass(frozen=True)
class ActivationFinalizationV2:
    """Результат регистрации фактического контроллера в staged activation."""

    materialization: ActivationMaterializationV2
    database_path: Path
    cleanup: Callable[[], None]
    created_fallback: _OwnedRegularFileV2 | None = None


@dataclass(frozen=True)
class AcceptedActivationCleanupV2:
    """Доказательство удаления одной остановленной принятой активации."""

    status: str
    installation_id: str
    activation_id: str
    removed_paths: tuple[Path, ...]


def stage_activation_identity_v2(
    *,
    source_root: Path,
    codex_home: Path,
    state_home: Path,
    codex_binary: Path,
    policy_bundle: PolicyBundleV2,
    snapshotter: _Snapshotter | None = None,
    interface_executor: SnapshotCommandExecutor | None = None,
    completed_at: datetime | None = None,
    first_install_operation_id: str | None = None,
    first_installation_id: str | None = None,
) -> StagedActivationV2:
    """Готовит идентичность, не создавая сокет, базу или публикацию."""

    source_root = source_root.expanduser().resolve()
    codex_home = codex_home.expanduser().absolute()
    state_home = normalize_state_home_v2(state_home)
    codex_binary = codex_binary.expanduser().absolute()
    captured_at = _aware(completed_at or datetime.now(timezone.utc))
    if (first_install_operation_id is None) != (first_installation_id is None):
        _fail(
            "FIRST_INSTALL_IDENTITY_INVALID",
            "идентификаторы первой установки должны передаваться вместе",
        )
    if first_install_operation_id is not None and (
        not _identifier(first_install_operation_id, "op2_")
        or not _identifier(first_installation_id, "ins2_")
    ):
        _fail(
            "FIRST_INSTALL_IDENTITY_INVALID",
            "идентификаторы первой установки имеют неверный формат",
        )
    layout = GatewayLayout.for_codex_home(codex_home)
    _validate_staging_inputs(
        source_root=source_root,
        codex_home=codex_home,
        codex_binary=codex_binary,
        state_home=state_home,
    )
    created_directories: list[_OwnedDirectoryV2] = []
    lifecycle_lock: _OwnedRegularFileV2 | None = None
    snapshot_file: _OwnedRegularFileV2 | None = None
    snapshot_directory: _OwnedDirectoryV2 | None = None
    activation_tree: tuple[_OwnedTreeEntryV2, ...] = ()

    def current_ownership() -> _StagingOwnershipV2:
        return _StagingOwnershipV2(
            created_directories=tuple(created_directories),
            lifecycle_lock=lifecycle_lock,
            snapshot_file=snapshot_file,
            snapshot_directory=snapshot_directory,
            activation_tree=activation_tree,
        )

    try:
        for directory in (
            layout.manifest_root,
            layout.managed_root,
            layout.managed_root / "activations",
            layout.managed_root / "codex-snapshots",
        ):
            owned = _ensure_private_directory_owned(directory)
            if owned is not None:
                created_directories.append(owned)
        if state_home.parent == codex_home / "state":
            owned = _ensure_private_directory_owned(codex_home / "state")
            if owned is not None:
                created_directories.append(owned)
        else:
            _validate_private_parent(state_home.parent, "STATE_HOME_PARENT_INVALID")
        for directory in (
            state_home,
            state_home / "databases",
            state_home / "backups",
            state_home / "quarantine",
        ):
            owned = _ensure_private_directory_owned(directory)
            if owned is not None:
                created_directories.append(owned)
        lifecycle_lock = _ensure_lock_file_owned(layout.lock_path)
    except BaseException:
        _rollback_staging_ownership_v2(current_ownership())
        raise

    with _exclusive_lock(layout.lock_path):
        if layout.manifest_path.exists():
            _rollback_staging_ownership_v2(current_ownership())
            _fail(
                "EXISTING_ACTIVATION_CONFLICT",
                "staging требует чистого CODEX_HOME без манифеста версии 2",
            )
        if layout.marketplace_link.exists() or layout.marketplace_link.is_symlink():
            _rollback_staging_ownership_v2(current_ownership())
            _fail(
                "EXISTING_ACTIVATION_CONFLICT",
                "marketplace-current уже существует без манифеста версии 2",
            )

        snapshotter = snapshotter or CodexBinarySnapshotter(
            snapshot_root=layout.managed_root / "codex-snapshots"
        )
        try:
            tracked_materialize = getattr(
                snapshotter, "materialize_with_identity", None
            )
            if not callable(tracked_materialize):
                _fail(
                    "SNAPSHOT_OWNERSHIP_UNAVAILABLE",
                    "snapshotter не сообщает created/reused identity",
                )
            publication = tracked_materialize(str(codex_binary))
            subject = publication.subject
        except OperationDeadlineExceededV2:
            _rollback_staging_ownership_v2(current_ownership())
            raise
        except Exception as exc:
            _rollback_staging_ownership_v2(current_ownership())
            _fail("SNAPSHOT_MATERIALIZATION_FAILED", str(exc))
        try:
            snapshot_path = _validate_snapshot_subject(
                subject,
                expected_root=layout.managed_root / "codex-snapshots",
                codex_binary=codex_binary,
            )
            snapshot_disposition = getattr(publication, "snapshot_disposition", None)
            directory_disposition = getattr(
                publication, "digest_directory_disposition", None
            )
            if snapshot_disposition not in {"created", "reused"} or (
                directory_disposition not in {"created", "reused"}
            ):
                _fail(
                    "SNAPSHOT_OWNERSHIP_INVALID",
                    "snapshotter вернул неверную created/reused identity",
                )
            if snapshot_disposition == "reused" and directory_disposition == "created":
                _fail(
                    "SNAPSHOT_OWNERSHIP_INVALID",
                    "переиспользованный снимок не может находиться в новом каталоге",
                )
            if snapshot_disposition == "created":
                snapshot_file = _capture_owned_regular_file_v2(snapshot_path)
            if directory_disposition == "created":
                snapshot_directory = _capture_owned_directory_v2(snapshot_path.parent)
        except BaseException:
            _rollback_staging_ownership_v2(current_ownership())
            raise
        try:
            observation = probe_codex_interface_v1(
                subject=subject,
                contract_root=source_root / "docs" / "contracts",
                policy_bundle=policy_bundle,
                executor=interface_executor,
            )
        except OperationDeadlineExceededV2:
            _rollback_staging_ownership_v2(current_ownership())
            raise
        except Exception as exc:
            _rollback_staging_ownership_v2(current_ownership())
            _fail("INTERFACE_PROBE_FAILED", str(exc))

        temporary_stage: Path | None = None
        activation_dir: Path | None = None
        try:
            temporary_stage = Path(
                tempfile.mkdtemp(
                    prefix=".activation-stage-",
                    dir=layout.managed_root / "activations",
                )
            )
            temporary_stage.chmod(0o700)
            marketplace = temporary_stage / "marketplace"
            plugin_root = marketplace / "plugins" / _PLUGIN_NAME
            _materialize_marketplace(
                source_root=source_root,
                marketplace=marketplace,
                plugin_root=plugin_root,
                bundled_catalog=observation.bundled_catalog.projection,
            )
            marketplace_sha = _tree_sha256(marketplace)
            generation_sha = _tree_sha256(plugin_root)

            installation_id = first_installation_id or (
                "ins2_" + secrets.token_hex(16)
            )
            operation_id = first_install_operation_id or (
                "op2_" + secrets.token_hex(16)
            )
            database_id = "db2_" + secrets.token_hex(16)
            activation_nonce = secrets.token_hex(32)
            database_path = (
                state_home / "databases" / database_id / "smart-subagents.sqlite3"
            )
            schema_manifest = _read_json(
                plugin_root
                / "src"
                / "codex_smart_subagents"
                / "schema"
                / "state-v2.manifest.json"
            )
            schema_artifact = (
                plugin_root
                / "src"
                / "codex_smart_subagents"
                / "schema"
                / "state-v2.sql"
            )
            schema_fingerprint = _required_sha256(
                schema_manifest.get("schemaFingerprint"),
                "schemaFingerprint",
            )
            schema_artifact_sha256 = _required_sha256(
                schema_manifest.get("stateSqlSha256"),
                "stateSqlSha256",
            )
            if _sha256_file(schema_artifact) != schema_artifact_sha256:
                _fail(
                    "SCHEMA_ARTIFACT_MISMATCH",
                    "state-v2.sql не совпадает с манифестом",
                )

            identity = {
                "schemaVersion": 2,
                "generationId": "gen2_" + generation_sha,
                "release": _RELEASE,
                "pluginId": _PLUGIN_NAME,
                "marketplaceTreeSha256": marketplace_sha,
                "generationTreeSha256": generation_sha,
                "database": {
                    "databaseId": database_id,
                    "absolutePath": str(database_path),
                    "schemaVersion": 2,
                    "schemaFingerprint": schema_fingerprint,
                    "schemaArtifactSha256": schema_artifact_sha256,
                    "activationBindingNonce": activation_nonce,
                },
                "codexSnapshot": {
                    "absolutePath": str(snapshot_path),
                    "sha256": str(subject["snapshotSha256"]),
                },
                "compatibilityFingerprint": observation.interface_evidence[
                    "compatibilityFingerprint"
                ],
                "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
                "bundledCatalogFingerprint": observation.bundled_catalog.fingerprint,
                "minimumGatewayVersion": _RELEASE,
            }
            activation_fingerprint = domain_fingerprint(
                "codex-smart/activation/v2", identity
            )
            activation_id = "act2_" + activation_fingerprint
            activation_dir = layout.managed_root / "activations" / activation_id
            if activation_dir.exists():
                _fail(
                    "ACTIVATION_ID_COLLISION",
                    "каталог вычисленной активации уже существует",
                )
            os.replace(temporary_stage, activation_dir)
            temporary_stage = None
            activation_document = {
                "schemaVersion": 2,
                "activationId": activation_id,
                "activationFingerprint": activation_fingerprint,
                "identity": identity,
            }
            _atomic_write_json(activation_dir / "activation.json", activation_document)
            _fsync_directory(activation_dir)
            _fsync_directory(layout.managed_root / "activations")
            activation_tree = _capture_owned_tree_v2(activation_dir)

            compatibility_fingerprint = str(
                observation.interface_evidence["compatibilityFingerprint"]
            )
            controller_identity = _controller_identity(
                codex_home=codex_home,
                state_home=state_home,
                activation_fingerprint=activation_fingerprint,
                compatibility_fingerprint=compatibility_fingerprint,
                routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
                bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
                database_id=database_id,
            )
            source_locator = {
                "lexicalPath": str(codex_binary),
                "resolvedPathAtCapture": str(codex_binary.resolve(strict=True)),
                "argv0Policy": "lexical",
                "sourceObservedSha256": str(subject["sourceObservedSha256"]),
            }
            snapshot_locator = {
                "absolutePath": str(snapshot_path),
                "sha256": str(subject["snapshotSha256"]),
            }
            return StagedActivationV2(
                status="IDENTITY_STAGED",
                readiness="AWAITING_CONTROLLER_BIND",
                source_root=source_root,
                codex_home=codex_home,
                codex_binary=codex_binary,
                state_home=state_home,
                socket_path=state_home / "controller.sock",
                controller_lock_path=state_home / "controller.lock",
                installation_id=installation_id,
                operation_id=operation_id,
                database_id=database_id,
                activation_binding_nonce=activation_nonce,
                activation_id=activation_id,
                activation_fingerprint=activation_fingerprint,
                controller_identity=controller_identity,
                compatibility_fingerprint=compatibility_fingerprint,
                routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
                bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
                schema_fingerprint=schema_fingerprint,
                schema_artifact_sha256=schema_artifact_sha256,
                activation_dir=activation_dir,
                snapshot_path=snapshot_path,
                database_path=database_path,
                bundled_catalog_path=(
                    activation_dir
                    / "marketplace"
                    / "plugins"
                    / _PLUGIN_NAME
                    / "config"
                    / "bundled-catalog-v1.json"
                ),
                identity=copy.deepcopy(identity),
                activation_document=copy.deepcopy(activation_document),
                source_locator=source_locator,
                snapshot_locator=snapshot_locator,
                bundled_catalog=copy.deepcopy(observation.bundled_catalog.projection),
                interface_evidence=copy.deepcopy(observation.interface_evidence),
                completed_at=captured_at,
                staging_ownership=current_ownership(),
            )
        except Exception:
            if activation_dir is not None and activation_dir.is_dir():
                shutil.rmtree(activation_dir)
            if temporary_stage is not None and temporary_stage.is_dir():
                shutil.rmtree(temporary_stage)
            _rollback_staging_ownership_v2(current_ownership())
            raise


def finalize_staged_activation_v2(
    *,
    staged: StagedActivationV2,
    controller: AcceptingControllerV2,
    allow_initialized_database_recovery: bool = False,
) -> ActivationFinalizationV2:
    """Финализирует staged activation только по фактическому сокету сервера."""

    layout = GatewayLayout.for_codex_home(staged.codex_home)
    _validate_staged_activation(
        staged=staged,
        layout=layout,
        allow_initialized_database_recovery=allow_initialized_database_recovery,
    )
    prepared_empty_database = (
        staged.database_path.exists()
        and staged.database_path.lstat().st_size == 0
    )
    _validate_accepting_controller(staged=staged, controller=controller)
    receipt_path = (
        layout.receipts_root
        / staged.installation_id
        / f"{staged.operation_id}.commit.json"
    )
    store: SmartStoreV2 | None = None
    store_closed = False
    created_fallback: _OwnedRegularFileV2 | None = None

    def close_store() -> None:
        nonlocal store_closed
        if store is not None and not store_closed:
            store_closed = True
            store.close()

    with _exclusive_lock(layout.lock_path):
        if layout.marketplace_link.exists() or layout.marketplace_link.is_symlink():
            _fail(
                "EXISTING_ACTIVATION_CONFLICT",
                "marketplace-current появился после подготовки кандидата",
            )
        try:
            database_identity = DatabaseIdentityV2(
                database_id=staged.database_id,
                activation_binding_nonce=staged.activation_binding_nonce,
                activation_id=staged.activation_id,
                activation_fingerprint=staged.activation_fingerprint,
                created_operation_id=staged.operation_id,
                created_at=staged.completed_at,
            )
            store = SmartStoreV2(
                staged.database_path,
                database_identity=database_identity,
                controller=controller,
                allow_prepared_empty_database=prepared_empty_database,
            )
            created_fallback = _publish_fallback(
                layout=layout,
                source_locator=staged.source_locator,
                snapshot_locator=staged.snapshot_locator,
            )
            original_backup_path = staged.codex_home / "original-codex-backup"
            if original_backup_path.exists() or original_backup_path.is_symlink():
                _fail(
                    "ORIGINAL_BACKUP_CONFLICT",
                    "путь исходной резервной копии уже занят",
                )
            manifest = {
                "schemaVersion": 2,
                "installationId": staged.installation_id,
                "release": _RELEASE,
                "pluginId": _PLUGIN_NAME,
                "marketplaceName": _MARKETPLACE_NAME,
                "stateHome": str(staged.state_home),
                "sourceLocator": copy.deepcopy(dict(staged.source_locator)),
                "codexSnapshot": copy.deepcopy(dict(staged.snapshot_locator)),
                "activeActivation": {
                    "activationId": staged.activation_id,
                    "activationFingerprint": staged.activation_fingerprint,
                    "symlinkTarget": (
                        f"activations/{staged.activation_id}/marketplace"
                    ),
                    "generationId": staged.identity["generationId"],
                    "databaseId": staged.database_id,
                },
                "previousActivation": None,
                "interfaceEvidence": copy.deepcopy(dict(staged.interface_evidence)),
                "routingPolicyFingerprint": staged.routing_policy_fingerprint,
                "bundledCatalogFingerprint": staged.bundled_catalog_fingerprint,
                "artifacts": _manifest_artifacts(
                    codex_home=staged.codex_home,
                    activation_dir=staged.activation_dir,
                    snapshot_path=staged.snapshot_path,
                    fallback_path=layout.fallback_path,
                    lock_path=layout.lock_path,
                ),
                "originalBackup": {
                    "type": "absent",
                    "path": str(original_backup_path),
                    "parentPath": str(staged.codex_home),
                    "name": original_backup_path.name,
                },
                "lastCommittedOperation": staged.operation_id,
                "databaseSchemaVersion": 2,
                "extensions": {},
            }
            if layout.manifest_path.exists():
                if _read_json(layout.manifest_path) != manifest:
                    _fail(
                        "EXISTING_ACTIVATION_CONFLICT",
                        "существующий манифест отличается от кандидата",
                    )
            else:
                _atomic_write_json(layout.manifest_path, manifest)
                _fsync_directory(layout.manifest_root)

            database_binding = _database_binding(
                database_path=staged.database_path,
                database_id=staged.database_id,
                activation_nonce=staged.activation_binding_nonce,
                activation_id=staged.activation_id,
                activation_fingerprint=staged.activation_fingerprint,
                schema_fingerprint=staged.schema_fingerprint,
                schema_artifact_sha256=staged.schema_artifact_sha256,
            )
            existing_receipt = (
                _read_json(receipt_path) if receipt_path.exists() else None
            )
            absence = (
                copy.deepcopy(existing_receipt["journalAbsenceTarget"])
                if existing_receipt is not None
                else _journal_absence_proof(
                    layout=layout,
                    installation_id=staged.installation_id,
                    operation_id=staged.operation_id,
                )
            )
            receipt = _activation_receipt(
                layout=layout,
                manifest=manifest,
                activation_document=dict(staged.activation_document),
                activation_dir=staged.activation_dir,
                database_binding=database_binding,
                absence=absence,
                controller_identity=controller.controller_identity,
                completed_at=staged.completed_at,
            )
            if existing_receipt is not None:
                if existing_receipt != receipt:
                    _fail(
                        "EXISTING_ACTIVATION_CONFLICT",
                        "существующая commit receipt отличается от кандидата",
                    )
            else:
                _ensure_private_directory(layout.receipts_root)
                _ensure_private_directory(receipt_path.parent)
                _atomic_write_json(receipt_path, receipt)
                _fsync_directory(receipt_path.parent)
                _fsync_directory(layout.receipts_root)

            materialization = _result(
                status="CANDIDATE_MATERIALIZED",
                layout=layout,
                state_home=staged.state_home,
                manifest=manifest,
                activation_document=staged.activation_document,
                bundled_catalog=staged.bundled_catalog,
                receipt_path=receipt_path,
                candidate=controller,
                controller_identity=controller.controller_identity,
            )
            return ActivationFinalizationV2(
                materialization=materialization,
                database_path=staged.database_path,
                cleanup=close_store,
                created_fallback=created_fallback,
            )
        except Exception:
            close_store()
            if allow_initialized_database_recovery:
                raise
            _cleanup_failed_materialization(
                layout=layout,
                stage=None,
                activation_dir=staged.activation_dir,
                database_path=staged.database_path,
                receipt_path=receipt_path,
            )
            _unlink_owned_regular_file_v2(created_fallback)
            raise


def discard_staged_activation_v2(
    staged: StagedActivationV2,
    *,
    finalization: ActivationFinalizationV2 | None = None,
) -> None:
    """Удаляет только точные артефакты непринятого staged-кандидата."""

    layout = GatewayLayout.for_codex_home(staged.codex_home)
    if not layout.lock_path.exists():
        return
    receipt_path = (
        layout.receipts_root
        / staged.installation_id
        / f"{staged.operation_id}.commit.json"
    )
    with _exclusive_lock(layout.lock_path):
        target = f"activations/{staged.activation_id}/marketplace"
        if layout.marketplace_link.is_symlink():
            try:
                if os.readlink(layout.marketplace_link) == target:
                    layout.marketplace_link.unlink()
            except OSError:
                pass
        if layout.manifest_path.exists():
            try:
                manifest = _read_json(layout.manifest_path)
            except ActivationMaterializationV2Error:
                manifest = {}
            active = manifest.get("activeActivation", {})
            if (
                manifest.get("installationId") == staged.installation_id
                and active.get("activationId") == staged.activation_id
            ):
                layout.manifest_path.unlink()
        if receipt_path.exists():
            receipt_path.unlink()
        if finalization is not None:
            _unlink_owned_regular_file_v2(finalization.created_fallback)
        for path in (
            staged.database_path,
            staged.database_path.with_name(staged.database_path.name + "-wal"),
            staged.database_path.with_name(staged.database_path.name + "-shm"),
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        for directory in (
            staged.database_path.parent,
            receipt_path.parent,
            layout.receipts_root,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass
        _fsync_directory(layout.managed_root)
        _fsync_directory(layout.manifest_root)
        if staged.staging_ownership is not None:
            _rollback_staging_ownership_v2(staged.staging_ownership)


def cleanup_accepted_activation_v2(
    *,
    codex_home: Path,
    installation_id: str,
    activation_id: str,
) -> AcceptedActivationCleanupV2:
    """Удаляет только точную первую активацию после остановки её владельца.

    API предназначен для компенсации неуспешной первоначальной установки.
    Он не является обновлением, общим uninstall или сборщиком мусора: наличие
    предыдущей активации, изменённого объекта или живого владельца закрывает
    операцию до первого удаления.
    """

    codex_home = codex_home.expanduser().absolute()
    if not _identifier(installation_id, "ins2_"):
        _fail("CLEANUP_IDENTITY_INVALID", "installationId неверен")
    if (
        type(activation_id) is not str
        or not activation_id.startswith("act2_")
        or len(activation_id) != len("act2_") + 64
        or any(
            character not in "0123456789abcdef"
            for character in activation_id.removeprefix("act2_")
        )
    ):
        _fail("CLEANUP_IDENTITY_INVALID", "activationId неверен")
    _validate_private_parent(codex_home, "CLEANUP_CODEX_HOME_INVALID")
    layout = GatewayLayout.for_codex_home(codex_home)
    _verify_cleanup_private_file_v2(
        layout.lock_path,
        code="CLEANUP_LOCK_INVALID",
    )

    removed: list[Path] = []
    with _exclusive_lock(layout.lock_path), ExitStack() as cleanup_stack:
        if layout.journal_path.exists() or layout.journal_path.is_symlink():
            _fail("CLEANUP_JOURNAL_PRESENT", "операция жизненного цикла не завершена")
        _verify_cleanup_private_file_v2(
            layout.manifest_path,
            code="CLEANUP_MANIFEST_CHANGED",
        )
        manifest = _read_json(layout.manifest_path)
        active = manifest.get("activeActivation")
        if (
            manifest.get("schemaVersion") != 2
            or manifest.get("installationId") != installation_id
            or type(active) is not dict
            or active.get("activationId") != activation_id
        ):
            _fail(
                "CLEANUP_IDENTITY_MISMATCH",
                "принятая активация отличается от ожидаемой",
            )
        if manifest.get("previousActivation") is not None:
            _fail(
                "CLEANUP_NOT_INITIAL_ACTIVATION",
                "компенсация не удаляет установку с предыдущей активацией",
            )
        operation_id = manifest.get("lastCommittedOperation")
        if not _identifier(operation_id, "op2_"):
            _fail("CLEANUP_MANIFEST_INVALID", "operationId манифеста неверен")
        receipt_path = (
            layout.receipts_root / installation_id / f"{operation_id}.commit.json"
        )
        _verify_cleanup_private_file_v2(
            receipt_path,
            code="CLEANUP_RECEIPT_INVALID",
        )
        receipt = _read_json(receipt_path)
        _validate_cleanup_receipt_v2(
            receipt=receipt,
            manifest=manifest,
            manifest_path=layout.manifest_path,
            installation_id=installation_id,
            activation_id=activation_id,
            operation_id=operation_id,
        )

        activation_dir = layout.managed_root / "activations" / activation_id
        expected_activation_projection = receipt["activation"]["value"]["directory"]
        try:
            observed_activation_projection = _tree_projection(activation_dir)
        except OperationDeadlineExceededV2:
            raise
        except Exception as exc:
            raise ActivationMaterializationV2Error(
                "CLEANUP_ACTIVATION_CHANGED",
                "не удалось доказать дерево активации",
            ) from exc
        if observed_activation_projection != expected_activation_projection:
            _fail(
                "CLEANUP_ACTIVATION_CHANGED",
                "дерево активации изменилось после принятия",
            )

        expected_link = f"activations/{activation_id}/marketplace"
        try:
            link_info = os.lstat(layout.marketplace_link)
            link_target = os.readlink(layout.marketplace_link)
        except OSError as exc:
            raise ActivationMaterializationV2Error(
                "CLEANUP_LINK_CHANGED",
                "активная ссылка отсутствует",
            ) from exc
        if (
            not stat.S_ISLNK(link_info.st_mode)
            or link_info.st_uid != os.getuid()
            or link_target != expected_link
            or active.get("symlinkTarget") != expected_link
        ):
            _fail("CLEANUP_LINK_CHANGED", "активная ссылка изменилась")

        database_binding = receipt["databaseBinding"]["value"]
        database_path = _cleanup_database_path_v2(
            database_binding=database_binding,
            state_home=Path(str(manifest.get("stateHome"))),
            activation_id=activation_id,
        )
        database_identity, controller_row = _cleanup_database_rows_v2(database_path)
        expected_identity = database_binding["databaseIdentity"]
        if database_identity != {
            "database_id": expected_identity["databaseId"],
            "activation_binding_nonce": expected_identity["activationBindingNonce"],
            "activation_id": expected_identity["activationId"],
            "activation_fingerprint": expected_identity["activationFingerprint"],
        }:
            _fail(
                "CLEANUP_DATABASE_CHANGED",
                "database_identity отличается от commit receipt",
            )
        if controller_row.get("activation_id") != activation_id or controller_row.get(
            "controller_identity"
        ) != receipt.get("controllerIdentity"):
            _fail(
                "CLEANUP_DATABASE_CHANGED",
                "controller_state отличается от commit receipt",
            )
        _require_cleanup_controller_stopped_v2(controller_row)

        state_home = Path(str(manifest["stateHome"]))
        controller_lock = state_home / "controller.lock"
        controller_lock_descriptor = _claim_cleanup_controller_lock_v2(controller_lock)
        cleanup_stack.callback(os.close, controller_lock_descriptor)
        socket_path = Path(str(controller_row.get("socket_path")))
        expected_socket = state_home / "controller.sock"
        if socket_path != expected_socket:
            _fail("CLEANUP_DATABASE_CHANGED", "путь сокета контроллера изменён")
        if socket_path.exists() or socket_path.is_symlink():
            _verify_cleanup_socket_v2(socket_path, controller_row)

        regular_artifacts = _cleanup_regular_artifacts_v2(
            manifest=manifest,
            codex_home=codex_home,
            lifecycle_lock=layout.lock_path,
        )
        database_sidecars = _cleanup_database_sidecars_v2(database_path)

        layout.marketplace_link.unlink()
        removed.append(layout.marketplace_link)
        if socket_path.exists() or socket_path.is_symlink():
            socket_path.unlink()
            removed.append(socket_path)
        for path in database_sidecars:
            path.unlink()
            removed.append(path)
        database_path.unlink()
        removed.append(database_path)
        receipt_path.unlink()
        removed.append(receipt_path)
        shutil.rmtree(activation_dir)
        removed.append(activation_dir)
        layout.manifest_path.unlink()
        removed.append(layout.manifest_path)
        for path in regular_artifacts:
            path.unlink()
            removed.append(path)
        controller_lock_info = os.fstat(controller_lock_descriptor)
        current_controller_lock_info = os.lstat(controller_lock)
        if (
            controller_lock_info.st_dev,
            controller_lock_info.st_ino,
        ) != (
            current_controller_lock_info.st_dev,
            current_controller_lock_info.st_ino,
        ):
            _fail(
                "CLEANUP_CONTROLLER_LOCK_CHANGED",
                "файл блокировки контроллера был заменён",
            )
        controller_lock.unlink()
        removed.append(controller_lock)
        _remove_empty_cleanup_directories_v2(
            paths=(
                database_path.parent,
                state_home / "databases",
                state_home,
                receipt_path.parent,
                layout.receipts_root,
                activation_dir.parent,
                layout.managed_root
                / "codex-snapshots"
                / Path(str(manifest["codexSnapshot"]["absolutePath"])).parent.name,
                layout.managed_root / "codex-snapshots",
                layout.managed_root,
            ),
            removed=removed,
        )
        _fsync_directory(layout.manifest_root)
    return AcceptedActivationCleanupV2(
        status="ACCEPTED_ACTIVATION_REMOVED",
        installation_id=installation_id,
        activation_id=activation_id,
        removed_paths=tuple(removed),
    )


def _validate_cleanup_receipt_v2(
    *,
    receipt: Mapping[str, Any],
    manifest: Mapping[str, Any],
    manifest_path: Path,
    installation_id: str,
    activation_id: str,
    operation_id: str,
) -> None:
    if (
        receipt.get("schemaVersion") != 2
        or receipt.get("receiptKind") != "activation-commit"
        or receipt.get("installationId") != installation_id
        or receipt.get("operationId") != operation_id
    ):
        _fail("CLEANUP_RECEIPT_INVALID", "идентичность commit receipt неверна")
    fingerprint = receipt.get("receiptFingerprint")
    if type(fingerprint) is not str:
        _fail("CLEANUP_RECEIPT_INVALID", "отпечаток commit receipt отсутствует")
    unsigned = {
        name: copy.deepcopy(value)
        for name, value in receipt.items()
        if name != "receiptFingerprint"
    }
    if fingerprint != domain_fingerprint(
        "codex-smart/activation-commit-receipt/v2", unsigned
    ):
        _fail("CLEANUP_RECEIPT_INVALID", "отпечаток commit receipt не совпал")
    try:
        manifest_value = receipt["manifest"]["value"]
        activation_value = receipt["activation"]["value"]
        database_value = receipt["databaseBinding"]["value"]
        observed_manifest_file = _file_projection(manifest_path)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_RECEIPT_INVALID",
            "commit receipt не содержит полную проекцию",
        ) from exc
    if manifest_value.get("file") != observed_manifest_file:
        _fail("CLEANUP_MANIFEST_CHANGED", "lifecycle-манифест изменился")
    if (
        manifest_value.get("installationId") != installation_id
        or manifest_value.get("activeActivationId") != activation_id
        or manifest_value.get("lastCommittedOperation") != operation_id
        or activation_value.get("activationId") != activation_id
        or database_value.get("activationIdentity", {}).get("activationId")
        != activation_id
        or manifest.get("activeActivation", {}).get("activationId") != activation_id
    ):
        _fail(
            "CLEANUP_RECEIPT_INVALID",
            "межобъектная привязка commit receipt не совпала",
        )


def _verify_cleanup_private_file_v2(path: Path, *, code: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ActivationMaterializationV2Error(
            code,
            f"закрытый файл недоступен: {path}",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail(code, f"закрытый файл небезопасен: {path}")


def _cleanup_database_path_v2(
    *,
    database_binding: Mapping[str, Any],
    state_home: Path,
    activation_id: str,
) -> Path:
    if not state_home.is_absolute():
        _fail("CLEANUP_DATABASE_CHANGED", "stateHome не абсолютен")
    try:
        database_path = Path(str(database_binding["path"]))
        database_id = str(database_binding["databaseId"])
        info = os.lstat(database_path)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_DATABASE_CHANGED",
            "база принятой активации недоступна",
        ) from exc
    expected = state_home / "databases" / database_id / "smart-subagents.sqlite3"
    if (
        not database_path.is_absolute()
        or database_path != expected
        or database_binding.get("activationIdentity", {}).get("activationId")
        != activation_id
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_dev != database_binding.get("device")
        or info.st_ino != database_binding.get("inode")
        or info.st_nlink != database_binding.get("linkCount")
        or f"0{stat.S_IMODE(info.st_mode):03o}" != database_binding.get("mode")
    ):
        _fail(
            "CLEANUP_DATABASE_CHANGED",
            "путь или метаданные базы отличаются от commit receipt",
        )
    return database_path


def _cleanup_database_rows_v2(
    database_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    uri = "file:" + quote(str(database_path), safe="/") + "?mode=ro"
    try:
        connection = connect_sqlite_with_deadline_v2(
            uri,
            uri=True,
            timeout=1.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            identity_rows = connection.execute(
                "select database_id, activation_binding_nonce, "
                "activation_id, activation_fingerprint from database_identity"
            ).fetchall()
            controller_rows = connection.execute(
                "select * from controller_state"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_DATABASE_CHANGED",
            "не удалось прочитать закрытую базу принятой активации",
        ) from exc
    if len(identity_rows) != 1 or len(controller_rows) != 1:
        _fail(
            "CLEANUP_DATABASE_CHANGED",
            "singleton-строки принятой базы отсутствуют",
        )
    return dict(identity_rows[0]), dict(controller_rows[0])


def _require_cleanup_controller_stopped_v2(
    controller_row: Mapping[str, Any],
) -> None:
    pid = controller_row.get("controller_pid")
    marker = controller_row.get("controller_process_start_marker")
    if type(pid) is not int or pid <= 0 or type(marker) is not str or not marker:
        _fail(
            "CLEANUP_CONTROLLER_IDENTITY_INVALID",
            "PID или системный маркер контроллера неверен",
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_CONTROLLER_LIVENESS_UNKNOWN",
            "нет права доказать остановку контроллера",
        ) from exc
    try:
        observed = system_process_start_marker_v2(pid)
    except ChildGuardV2Error as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_CONTROLLER_LIVENESS_UNKNOWN",
            "не удалось доказать системный маркер контроллера",
        ) from exc
    if observed == marker:
        _fail(
            "CLEANUP_CONTROLLER_ACTIVE",
            "владелец принятой активации всё ещё работает",
        )


def _claim_cleanup_controller_lock_v2(path: Path) -> int:
    try:
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            _fail(
                "CLEANUP_CONTROLLER_LOCK_INVALID",
                "файл блокировки контроллера небезопасен",
            )
        descriptor = os.open(
            path,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_CONTROLLER_LOCK_INVALID",
            "файл блокировки контроллера недоступен",
        ) from exc
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(descriptor)
        raise ActivationMaterializationV2Error(
            "CLEANUP_CONTROLLER_ACTIVE",
            "блокировка контроллера всё ещё занята",
        ) from exc
    return descriptor


def _verify_cleanup_socket_v2(
    path: Path,
    controller_row: Mapping[str, Any],
) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ActivationMaterializationV2Error(
            "CLEANUP_SOCKET_CHANGED", "сокет контроллера недоступен"
        ) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != controller_row.get("socket_owner_uid")
        or info.st_gid != controller_row.get("socket_owner_gid")
        or info.st_dev != controller_row.get("socket_device")
        or info.st_ino != controller_row.get("socket_inode")
        or f"0{stat.S_IMODE(info.st_mode):03o}" != controller_row.get("socket_mode")
    ):
        _fail("CLEANUP_SOCKET_CHANGED", "сокет контроллера был заменён")


def _cleanup_regular_artifacts_v2(
    *,
    manifest: Mapping[str, Any],
    codex_home: Path,
    lifecycle_lock: Path,
) -> tuple[Path, ...]:
    artifacts = manifest.get("artifacts")
    if type(artifacts) is not list:
        _fail("CLEANUP_MANIFEST_INVALID", "карта артефактов отсутствует")
    expected_regular = {
        Path(str(manifest["codexSnapshot"]["absolutePath"])),
        GatewayLayout.for_codex_home(codex_home).fallback_path,
        lifecycle_lock,
    }
    observed_regular: set[Path] = set()
    removable: list[Path] = []
    for artifact in artifacts:
        if type(artifact) is not dict or artifact.get("type") not in {
            "directory",
            "regular",
        }:
            _fail("CLEANUP_MANIFEST_INVALID", "описание артефакта неверно")
        if artifact["type"] == "directory":
            continue
        relative = Path(str(artifact.get("relativePath")))
        if relative.is_absolute() or ".." in relative.parts:
            _fail("CLEANUP_MANIFEST_INVALID", "путь артефакта небезопасен")
        path = codex_home / relative
        observed_regular.add(path)
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise ActivationMaterializationV2Error(
                "CLEANUP_ARTIFACT_CHANGED",
                "артефакт жизненного цикла отсутствует",
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or f"0{stat.S_IMODE(info.st_mode):03o}" != artifact.get("mode")
            or info.st_size != artifact.get("size")
            or _sha256_file(path) != artifact.get("sha256")
        ):
            _fail(
                "CLEANUP_ARTIFACT_CHANGED",
                "артефакт жизненного цикла был изменён",
            )
        if path != lifecycle_lock:
            removable.append(path)
    if observed_regular != expected_regular:
        _fail(
            "CLEANUP_MANIFEST_INVALID",
            "набор обычных артефактов жизненного цикла отличается",
        )
    return tuple(removable)


def _cleanup_database_sidecars_v2(database_path: Path) -> tuple[Path, ...]:
    result: list[Path] = []
    for suffix in ("-wal", "-shm", "-journal"):
        path = database_path.with_name(database_path.name + suffix)
        if not path.exists() and not path.is_symlink():
            continue
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            _fail(
                "CLEANUP_DATABASE_CHANGED",
                "побочный файл базы небезопасен",
            )
        result.append(path)
    return tuple(result)


def _remove_empty_cleanup_directories_v2(
    *,
    paths: tuple[Path, ...],
    removed: list[Path],
) -> None:
    seen: set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError:
            continue
        removed.append(path)


def materialize_activation_v2(
    *,
    source_root: Path,
    codex_home: Path,
    state_home: Path,
    codex_binary: Path,
    controller_candidate: ControllerCandidateV2,
    policy_bundle: PolicyBundleV2,
    snapshotter: _Snapshotter | None = None,
    interface_executor: SnapshotCommandExecutor | None = None,
    completed_at: datetime | None = None,
) -> ActivationMaterializationV2:
    """Материализует закрытого кандидата, не объявляя его `READY`."""

    source_root = source_root.expanduser().resolve()
    codex_home = codex_home.expanduser().absolute()
    state_home = normalize_state_home_v2(state_home)
    codex_binary = codex_binary.expanduser().absolute()
    layout = GatewayLayout.for_codex_home(codex_home)
    candidate_info = _validate_inputs(
        source_root=source_root,
        codex_home=codex_home,
        codex_binary=codex_binary,
        state_home=state_home,
        candidate=controller_candidate,
    )
    _ensure_private_directory(layout.manifest_root)
    _ensure_private_directory(layout.managed_root)
    _ensure_private_directory(layout.managed_root / "activations")
    _ensure_private_directory(layout.managed_root / "codex-snapshots")
    if state_home.parent == codex_home / "state":
        _ensure_private_directory(codex_home / "state")
    else:
        _validate_private_parent(state_home.parent, "STATE_HOME_PARENT_INVALID")
    _ensure_private_directory(state_home)
    _ensure_private_directory(state_home / "databases")
    _ensure_private_directory(state_home / "backups")
    _ensure_private_directory(state_home / "quarantine")
    _ensure_lock_file(layout.lock_path)

    with _exclusive_lock(layout.lock_path):
        if layout.manifest_path.exists():
            return _read_existing_materialization(
                layout=layout,
                codex_binary=codex_binary,
                state_home=state_home,
                candidate=controller_candidate,
                candidate_info=candidate_info,
            )
        if layout.marketplace_link.exists() or layout.marketplace_link.is_symlink():
            _fail(
                "EXISTING_ACTIVATION_CONFLICT",
                "marketplace-current уже существует без манифеста версии 2",
            )

        snapshotter = snapshotter or CodexBinarySnapshotter(
            snapshot_root=layout.managed_root / "codex-snapshots"
        )
        try:
            subject = snapshotter.materialize(str(codex_binary))
        except OperationDeadlineExceededV2:
            raise
        except Exception as exc:
            _fail("SNAPSHOT_MATERIALIZATION_FAILED", str(exc))
        snapshot_path = _validate_snapshot_subject(
            subject,
            expected_root=layout.managed_root / "codex-snapshots",
            codex_binary=codex_binary,
        )
        try:
            observation = probe_codex_interface_v1(
                subject=subject,
                contract_root=source_root / "docs" / "contracts",
                policy_bundle=policy_bundle,
                executor=interface_executor,
            )
        except OperationDeadlineExceededV2:
            raise
        except Exception as exc:
            _fail("INTERFACE_PROBE_FAILED", str(exc))

        stage: Path | None = None
        activation_dir: Path | None = None
        database_path: Path | None = None
        receipt_path: Path | None = None
        try:
            stage = Path(
                tempfile.mkdtemp(
                    prefix=".activation-stage-",
                    dir=layout.managed_root / "activations",
                )
            )
            stage.chmod(0o700)
            marketplace = stage / "marketplace"
            plugin_root = marketplace / "plugins" / _PLUGIN_NAME
            _materialize_marketplace(
                source_root=source_root,
                marketplace=marketplace,
                plugin_root=plugin_root,
                bundled_catalog=observation.bundled_catalog.projection,
            )
            marketplace_sha = _tree_sha256(marketplace)
            generation_sha = _tree_sha256(plugin_root)

            installation_id = "ins2_" + secrets.token_hex(16)
            operation_id = "op2_" + secrets.token_hex(16)
            database_id = "db2_" + secrets.token_hex(16)
            activation_nonce = secrets.token_hex(32)
            database_path = (
                state_home / "databases" / database_id / "smart-subagents.sqlite3"
            )
            schema_manifest = _read_json(
                plugin_root
                / "src"
                / "codex_smart_subagents"
                / "schema"
                / "state-v2.manifest.json"
            )
            schema_artifact = (
                plugin_root
                / "src"
                / "codex_smart_subagents"
                / "schema"
                / "state-v2.sql"
            )
            schema_fingerprint = _required_sha256(
                schema_manifest.get("schemaFingerprint"),
                "schemaFingerprint",
            )
            schema_artifact_sha256 = _required_sha256(
                schema_manifest.get("stateSqlSha256"),
                "stateSqlSha256",
            )
            if _sha256_file(schema_artifact) != schema_artifact_sha256:
                _fail(
                    "SCHEMA_ARTIFACT_MISMATCH", "state-v2.sql не совпадает с манифестом"
                )

            identity = {
                "schemaVersion": 2,
                "generationId": "gen2_" + generation_sha,
                "release": _RELEASE,
                "pluginId": _PLUGIN_NAME,
                "marketplaceTreeSha256": marketplace_sha,
                "generationTreeSha256": generation_sha,
                "database": {
                    "databaseId": database_id,
                    "absolutePath": str(database_path),
                    "schemaVersion": 2,
                    "schemaFingerprint": schema_fingerprint,
                    "schemaArtifactSha256": schema_artifact_sha256,
                    "activationBindingNonce": activation_nonce,
                },
                "codexSnapshot": {
                    "absolutePath": str(snapshot_path),
                    "sha256": str(subject["snapshotSha256"]),
                },
                "compatibilityFingerprint": observation.interface_evidence[
                    "compatibilityFingerprint"
                ],
                "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
                "bundledCatalogFingerprint": observation.bundled_catalog.fingerprint,
                "minimumGatewayVersion": _RELEASE,
            }
            activation_fingerprint = domain_fingerprint(
                "codex-smart/activation/v2", identity
            )
            activation_id = "act2_" + activation_fingerprint
            activation_dir = layout.managed_root / "activations" / activation_id
            if activation_dir.exists():
                _fail(
                    "ACTIVATION_ID_COLLISION",
                    "каталог вычисленной активации уже существует",
                )
            os.replace(stage, activation_dir)
            stage = None
            marketplace = activation_dir / "marketplace"
            plugin_root = marketplace / "plugins" / _PLUGIN_NAME
            activation_document = {
                "schemaVersion": 2,
                "activationId": activation_id,
                "activationFingerprint": activation_fingerprint,
                "identity": identity,
            }
            _atomic_write_json(
                activation_dir / "activation.json",
                activation_document,
            )
            _fsync_directory(activation_dir)
            _fsync_directory(layout.managed_root / "activations")

            controller_identity = _controller_identity(
                codex_home=codex_home,
                state_home=state_home,
                activation_fingerprint=activation_fingerprint,
                compatibility_fingerprint=str(
                    observation.interface_evidence["compatibilityFingerprint"]
                ),
                routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
                bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
                database_id=database_id,
            )
            database_identity = DatabaseIdentityV2(
                database_id=database_id,
                activation_binding_nonce=activation_nonce,
                activation_id=activation_id,
                activation_fingerprint=activation_fingerprint,
                created_operation_id=operation_id,
                created_at=_aware(completed_at or datetime.now(timezone.utc)),
            )
            accepting_controller = AcceptingControllerV2(
                controller_identity=controller_identity,
                instance_id=controller_candidate.instance_id,
                controller_start_id=controller_candidate.controller_start_id,
                controller_pid=controller_candidate.pid,
                controller_process_start_marker=controller_candidate.process_start_marker,
                controller_process_group_id=controller_candidate.process_group_id,
                control_epoch=controller_candidate.control_epoch,
                activation_id=activation_id,
                activation_fingerprint=activation_fingerprint,
                compatibility_fingerprint=str(
                    observation.interface_evidence["compatibilityFingerprint"]
                ),
                routing_policy_fingerprint=policy_bundle.router.policy_fingerprint,
                bundled_catalog_fingerprint=observation.bundled_catalog.fingerprint,
                socket_path=str(controller_candidate.socket_path),
                socket_device=candidate_info.st_dev,
                socket_inode=candidate_info.st_ino,
                socket_owner_uid=candidate_info.st_uid,
                socket_owner_gid=candidate_info.st_gid,
                socket_mode="0600",
                updated_at=_aware(controller_candidate.updated_at),
            )
            store = SmartStoreV2(
                database_path,
                database_identity=database_identity,
                controller=accepting_controller,
            )
            store.close()

            source_locator = {
                "lexicalPath": str(codex_binary),
                "resolvedPathAtCapture": str(codex_binary.resolve(strict=True)),
                "argv0Policy": "lexical",
                "sourceObservedSha256": str(subject["sourceObservedSha256"]),
            }
            snapshot_locator = {
                "absolutePath": str(snapshot_path),
                "sha256": str(subject["snapshotSha256"]),
            }
            _publish_fallback(
                layout=layout,
                source_locator=source_locator,
                snapshot_locator=snapshot_locator,
            )
            original_backup_path = codex_home / "original-codex-backup"
            if original_backup_path.exists() or original_backup_path.is_symlink():
                _fail(
                    "ORIGINAL_BACKUP_CONFLICT",
                    "путь исходной резервной копии уже занят",
                )
            manifest = {
                "schemaVersion": 2,
                "installationId": installation_id,
                "release": _RELEASE,
                "pluginId": _PLUGIN_NAME,
                "marketplaceName": _MARKETPLACE_NAME,
                "stateHome": str(state_home),
                "sourceLocator": source_locator,
                "codexSnapshot": snapshot_locator,
                "activeActivation": {
                    "activationId": activation_id,
                    "activationFingerprint": activation_fingerprint,
                    "symlinkTarget": f"activations/{activation_id}/marketplace",
                    "generationId": identity["generationId"],
                    "databaseId": database_id,
                },
                "previousActivation": None,
                "interfaceEvidence": copy.deepcopy(observation.interface_evidence),
                "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
                "bundledCatalogFingerprint": observation.bundled_catalog.fingerprint,
                "artifacts": _manifest_artifacts(
                    codex_home=codex_home,
                    activation_dir=activation_dir,
                    snapshot_path=snapshot_path,
                    fallback_path=layout.fallback_path,
                    lock_path=layout.lock_path,
                ),
                "originalBackup": {
                    "type": "absent",
                    "path": str(original_backup_path),
                    "parentPath": str(codex_home),
                    "name": original_backup_path.name,
                },
                "lastCommittedOperation": operation_id,
                "databaseSchemaVersion": 2,
                "extensions": {},
            }
            _atomic_write_json(layout.manifest_path, manifest)
            _fsync_directory(layout.manifest_root)

            database_binding = _database_binding(
                database_path=database_path,
                database_id=database_id,
                activation_nonce=activation_nonce,
                activation_id=activation_id,
                activation_fingerprint=activation_fingerprint,
                schema_fingerprint=schema_fingerprint,
                schema_artifact_sha256=schema_artifact_sha256,
            )
            absence = _journal_absence_proof(
                layout=layout,
                installation_id=installation_id,
                operation_id=operation_id,
            )
            receipt = _activation_receipt(
                layout=layout,
                manifest=manifest,
                activation_document=activation_document,
                activation_dir=activation_dir,
                database_binding=database_binding,
                absence=absence,
                controller_identity=controller_identity,
                completed_at=_aware(completed_at or datetime.now(timezone.utc)),
            )
            receipt_path = (
                layout.receipts_root / installation_id / f"{operation_id}.commit.json"
            )
            _ensure_private_directory(layout.receipts_root)
            _ensure_private_directory(receipt_path.parent)
            _atomic_write_json(receipt_path, receipt)
            _fsync_directory(receipt_path.parent)
            _fsync_directory(layout.receipts_root)

            return _result(
                status="CANDIDATE_MATERIALIZED",
                layout=layout,
                state_home=state_home,
                manifest=manifest,
                activation_document=activation_document,
                bundled_catalog=observation.bundled_catalog.projection,
                receipt_path=receipt_path,
                candidate=controller_candidate,
                controller_identity=controller_identity,
            )
        except ActivationMaterializationV2Error:
            _cleanup_failed_materialization(
                layout=layout,
                stage=stage,
                activation_dir=activation_dir,
                database_path=database_path,
                receipt_path=receipt_path,
            )
            raise
        except OperationDeadlineExceededV2:
            _cleanup_failed_materialization(
                layout=layout,
                stage=stage,
                activation_dir=activation_dir,
                database_path=database_path,
                receipt_path=receipt_path,
            )
            raise
        except Exception as exc:
            _cleanup_failed_materialization(
                layout=layout,
                stage=stage,
                activation_dir=activation_dir,
                database_path=database_path,
                receipt_path=receipt_path,
            )
            _fail("ACTIVATION_MATERIALIZATION_FAILED", str(exc))


def activate_materialized_v2(
    *,
    materialization: ActivationMaterializationV2,
    wrapper: Path,
    snapshot_verifier,
    controller_probe,
) -> GatewayDecision:
    """Публикует ссылку только на время полной проверки и оставляет её при READY."""

    layout = GatewayLayout.for_codex_home(materialization.codex_home)
    target = f"activations/{materialization.activation_id}/marketplace"
    _ensure_lock_file(layout.lock_path)
    created = False
    with _exclusive_lock(layout.lock_path):
        if layout.marketplace_link.exists() or layout.marketplace_link.is_symlink():
            if (
                not layout.marketplace_link.is_symlink()
                or os.readlink(layout.marketplace_link) != target
            ):
                _fail(
                    "ACTIVATION_LINK_CONFLICT",
                    "marketplace-current принадлежит другому состоянию",
                )
        else:
            temporary = layout.managed_root / (
                ".marketplace-current-" + secrets.token_hex(8)
            )
            os.symlink(target, temporary)
            os.replace(temporary, layout.marketplace_link)
            _fsync_directory(layout.managed_root)
            created = True
    try:
        decision = ActivationResolver(
            layout=layout,
            wrapper=wrapper,
            snapshot_verifier=snapshot_verifier,
            controller_probe=controller_probe,
        ).resolve()
        if decision.state is not GatewayState.READY:
            _fail(
                "CONTROLLER_HEALTH_NOT_READY",
                f"шлюз отклонил кандидата: {decision.reason_code}",
            )
        return decision
    except Exception:
        if created:
            with _exclusive_lock(layout.lock_path):
                if layout.marketplace_link.is_symlink():
                    try:
                        if os.readlink(layout.marketplace_link) == target:
                            layout.marketplace_link.unlink()
                            _fsync_directory(layout.managed_root)
                    except OSError:
                        pass
        raise


def _validate_staged_activation(
    *,
    staged: StagedActivationV2,
    layout: GatewayLayout,
    allow_initialized_database_recovery: bool = False,
) -> None:
    expected_state_home = staged.state_home
    expected_activation_dir = layout.managed_root / "activations" / staged.activation_id
    expected_database_path = (
        expected_state_home
        / "databases"
        / staged.database_id
        / "smart-subagents.sqlite3"
    )
    if (
        staged.status != "IDENTITY_STAGED"
        or staged.readiness != "AWAITING_CONTROLLER_BIND"
        or staged.state_home != expected_state_home
        or staged.socket_path != expected_state_home / "controller.sock"
        or staged.controller_lock_path != expected_state_home / "controller.lock"
        or staged.activation_dir != expected_activation_dir
        or staged.database_path != expected_database_path
        or staged.activation_id != "act2_" + staged.activation_fingerprint
        or staged.activation_document.get("activationId") != staged.activation_id
        or staged.activation_document.get("activationFingerprint")
        != staged.activation_fingerprint
        or staged.activation_document.get("identity") != staged.identity
        or staged.identity.get("database", {}).get("databaseId") != staged.database_id
        or staged.identity.get("database", {}).get("absolutePath")
        != str(staged.database_path)
        or staged.identity.get("database", {}).get("activationBindingNonce")
        != staged.activation_binding_nonce
    ):
        _fail("STAGED_ACTIVATION_INVALID", "идентичность staging расходится")
    if staged.database_path.exists():
        try:
            database_info = staged.database_path.lstat()
        except OSError as exc:
            _fail("STAGED_ACTIVATION_INVALID", str(exc))
        if (
            not stat.S_ISREG(database_info.st_mode)
            or stat.S_ISLNK(database_info.st_mode)
            or database_info.st_uid != os.getuid()
            or stat.S_IMODE(database_info.st_mode) != 0o600
            or database_info.st_nlink != 1
            or (
                database_info.st_size != 0
                and not allow_initialized_database_recovery
            )
        ):
            _fail(
                "STAGED_ACTIVATION_INVALID",
                "до регистрации допустим только закреплённый пустой файл базы",
            )
    try:
        activation_document = _read_json(staged.activation_dir / "activation.json")
    except ActivationMaterializationV2Error as exc:
        _fail("STAGED_ACTIVATION_INVALID", str(exc))
    if activation_document != staged.activation_document:
        _fail("STAGED_ACTIVATION_INVALID", "activation.json изменён после staging")
    marketplace = staged.activation_dir / "marketplace"
    plugin_root = marketplace / "plugins" / _PLUGIN_NAME
    if (
        _tree_sha256(marketplace) != staged.identity.get("marketplaceTreeSha256")
        or _tree_sha256(plugin_root) != staged.identity.get("generationTreeSha256")
        or _read_json(staged.bundled_catalog_path) != staged.bundled_catalog
    ):
        _fail("STAGED_ACTIVATION_INVALID", "дерево marketplace изменено после staging")


def _validate_accepting_controller(
    *,
    staged: StagedActivationV2,
    controller: AcceptingControllerV2,
) -> None:
    expected = {
        "controller_identity": staged.controller_identity,
        "activation_id": staged.activation_id,
        "activation_fingerprint": staged.activation_fingerprint,
        "compatibility_fingerprint": staged.compatibility_fingerprint,
        "routing_policy_fingerprint": staged.routing_policy_fingerprint,
        "bundled_catalog_fingerprint": staged.bundled_catalog_fingerprint,
        "socket_path": str(staged.socket_path),
        "socket_mode": "0600",
    }
    if any(getattr(controller, name) != value for name, value in expected.items()):
        _fail(
            "CONTROLLER_BINDING_MISMATCH",
            "контроллер не совпадает с подготовленной идентичностью",
        )
    if (
        not _identifier(controller.instance_id, "ci2_")
        or not _identifier(controller.controller_start_id, "cs2_")
        or type(controller.controller_pid) is not int
        or controller.controller_pid <= 0
        or type(controller.controller_process_group_id) is not int
        or controller.controller_process_group_id <= 0
        or type(controller.control_epoch) is not int
        or not 1 <= controller.control_epoch <= 9_007_199_254_740_991
        or not controller.controller_process_start_marker
    ):
        _fail("CONTROLLER_BINDING_MISMATCH", "runtime-идентичность неверна")
    _aware(controller.updated_at)
    try:
        socket_info = os.lstat(staged.socket_path)
    except OSError as exc:
        _fail("CONTROLLER_BINDING_MISMATCH", str(exc))
    if (
        not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != os.getuid()
        or stat.S_IMODE(socket_info.st_mode) != 0o600
        or socket_info.st_dev != controller.socket_device
        or socket_info.st_ino != controller.socket_inode
        or socket_info.st_uid != controller.socket_owner_uid
        or socket_info.st_gid != controller.socket_owner_gid
    ):
        _fail(
            "CONTROLLER_BINDING_MISMATCH",
            "фактический inode сокета не совпадает с контроллером",
        )


def _validate_inputs(
    *,
    source_root: Path,
    codex_home: Path,
    codex_binary: Path,
    state_home: Path,
    candidate: ControllerCandidateV2,
) -> os.stat_result:
    if not source_root.is_dir():
        _fail("SOURCE_ROOT_INVALID", "корень исходников отсутствует")
    _validate_source_catalog_identity_v2(source_root)
    _validate_private_parent(codex_home, "CODEX_HOME_INVALID")
    try:
        source_info = codex_binary.resolve(strict=True).stat()
    except OSError as exc:
        _fail("CODEX_BINARY_INVALID", str(exc))
    if not stat.S_ISREG(source_info.st_mode) or not os.access(codex_binary, os.X_OK):
        _fail("CODEX_BINARY_INVALID", "исходный Codex не является исполняемым файлом")
    expected_socket = state_home / "controller.sock"
    if candidate.socket_path.expanduser().absolute() != expected_socket:
        _fail("CONTROLLER_CANDIDATE_INVALID", "сокет кандидата имеет другой путь")
    if (
        not _identifier(candidate.instance_id, "ci2_")
        or not _identifier(candidate.controller_start_id, "cs2_")
        or type(candidate.pid) is not int
        or candidate.pid <= 0
        or type(candidate.process_group_id) is not int
        or candidate.process_group_id <= 0
        or type(candidate.control_epoch) is not int
        or not 1 <= candidate.control_epoch <= 9_007_199_254_740_991
        or not isinstance(candidate.process_start_marker, str)
        or not candidate.process_start_marker
    ):
        _fail("CONTROLLER_CANDIDATE_INVALID", "идентичность кандидата неверна")
    _aware(candidate.updated_at)
    try:
        info = os.lstat(expected_socket)
    except OSError as exc:
        _fail("CONTROLLER_CANDIDATE_INVALID", str(exc))
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("CONTROLLER_CANDIDATE_INVALID", "метаданные сокета кандидата неверны")
    return info


def _validate_staging_inputs(
    *,
    source_root: Path,
    codex_home: Path,
    codex_binary: Path,
    state_home: Path,
) -> None:
    if not source_root.is_dir():
        _fail("SOURCE_ROOT_INVALID", "корень исходников отсутствует")
    _validate_source_catalog_identity_v2(source_root)
    _validate_private_parent(codex_home, "CODEX_HOME_INVALID")
    normalize_state_home_v2(state_home)
    try:
        source_info = codex_binary.resolve(strict=True).stat()
    except OSError as exc:
        _fail("CODEX_BINARY_INVALID", str(exc))
    if not stat.S_ISREG(source_info.st_mode) or not os.access(codex_binary, os.X_OK):
        _fail("CODEX_BINARY_INVALID", "исходный Codex не является исполняемым файлом")


def _validate_snapshot_subject(
    subject: Mapping[str, object],
    *,
    expected_root: Path,
    codex_binary: Path,
) -> Path:
    try:
        digest = _required_sha256(subject["snapshotSha256"], "snapshotSha256")
        path = Path(str(subject["snapshotPath"]))
        expected = expected_root / digest / "codex"
        info = os.lstat(path)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        _fail("SNAPSHOT_SUBJECT_INVALID", str(exc))
    if (
        path != expected
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o500
        or info.st_nlink != 1
        or _sha256_file(path) != digest
        or subject.get("sourceLocator") != str(codex_binary)
        or subject.get("sourceObservedSha256") != digest
    ):
        _fail("SNAPSHOT_SUBJECT_INVALID", "снимок или его привязка неверны")
    return path


def _materialize_marketplace(
    *,
    source_root: Path,
    marketplace: Path,
    plugin_root: Path,
    bundled_catalog: Mapping[str, Any],
) -> None:
    _validate_source_catalog_identity_v2(source_root)
    _ensure_private_directory(marketplace)
    _ensure_private_directory(marketplace / ".agents" / "plugins")
    _ensure_private_directory(marketplace / ".claude-plugin")
    _ensure_private_directory(marketplace / "plugins")
    _copy_regular_file_with_deadline(
        source_root / ".agents" / "plugins" / "marketplace.json",
        marketplace / ".agents" / "plugins" / "marketplace.json",
    )
    _copy_regular_file_with_deadline(
        source_root / ".claude-plugin" / "marketplace.json",
        marketplace / ".claude-plugin" / "marketplace.json",
    )
    _copy_private_tree(source_root / "plugins" / _PLUGIN_NAME, plugin_root)
    _bind_python_entrypoints(plugin_root / "bin")
    config_root = plugin_root / "config"
    _ensure_private_directory(config_root)
    _copy_regular_file_with_deadline(
        source_root / ".codex" / "adaptive-subagents.toml",
        config_root / "adaptive-subagents.toml",
    )
    contract_root = config_root / "contracts"
    _ensure_private_directory(contract_root)
    for name in _POLICY_VECTOR_FILES:
        _copy_regular_file_with_deadline(
            source_root / "docs" / "contracts" / "vectors" / name,
            contract_root / name,
        )
    runtime_schema_root = marketplace / "docs" / "contracts" / "schemas"
    _ensure_private_directory(runtime_schema_root)
    for name in _RUNTIME_SCHEMA_FILES:
        source = source_root / "docs" / "contracts" / "schemas" / name
        destination = runtime_schema_root / name
        _copy_regular_file_with_deadline(source, destination)
        if destination.read_bytes() != source.read_bytes():
            _fail("RUNTIME_SCHEMA_COPY_MISMATCH", f"схема скопирована неверно: {name}")
    runtime_vector_root = marketplace / "docs" / "contracts" / "vectors"
    _ensure_private_directory(runtime_vector_root)
    for name in _RUNTIME_VECTOR_FILES:
        source = source_root / "docs" / "contracts" / "vectors" / name
        destination = runtime_vector_root / name
        _copy_regular_file_with_deadline(source, destination)
        if destination.read_bytes() != source.read_bytes():
            _fail(
                "RUNTIME_VECTOR_COPY_MISMATCH",
                f"вектор скопирован неверно: {name}",
            )
    _atomic_write_json(config_root / "bundled-catalog-v1.json", bundled_catalog)
    _normalize_private_tree(marketplace)


def _validate_source_catalog_identity_v2(source_root: Path) -> None:
    canonical = source_root / ".codex" / "adaptive-subagents.toml"
    config_root = source_root / "plugins" / _PLUGIN_NAME / "config"
    bundled = config_root / "adaptive-subagents.toml"
    for path in (
        config_root / "contracts",
        config_root / "bundled-catalog-v1.json",
    ):
        if os.path.lexists(path):
            _fail(
                "SOURCE_GENERATED_PATH_CONFLICT",
                f"исходное дерево занимает зарезервированный путь: {path}",
            )
    for path in (canonical, bundled):
        try:
            info = os.lstat(path)
        except OSError as exc:
            _fail("SOURCE_CATALOG_INVALID", str(exc))
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            _fail(
                "SOURCE_CATALOG_INVALID",
                "каталог моделей должен быть обычным исходным файлом",
            )
    if _sha256_file(canonical) != _sha256_file(bundled):
        _fail(
            "SOURCE_CATALOG_MISMATCH",
            "корневая и встроенная копии каталога моделей различаются",
        )


def _bind_python_entrypoints(bin_root: Path) -> None:
    """Привязывает исполняемые точки входа к проверенному Python активации."""

    try:
        interpreter = Path(sys.executable).resolve(strict=True)
        interpreter_info = interpreter.stat()
    except OSError as exc:
        _fail("PYTHON_RUNTIME_INVALID", str(exc))
    if (
        sys.version_info < (3, 11)
        or not stat.S_ISREG(interpreter_info.st_mode)
        or not os.access(interpreter, os.X_OK)
        or any(
            character in str(interpreter)
            for character in (" ", "\t", "\n", "\r")
        )
    ):
        _fail(
            "PYTHON_RUNTIME_INVALID",
            "для активации требуется обычный исполняемый Python не ниже 3.11",
        )
    shebang = f"#!{interpreter} -B\n".encode("utf-8")
    if len(shebang) > 120:
        _fail(
            "PYTHON_RUNTIME_PATH_TOO_LONG",
            "путь Python слишком длинный для переносимой точки входа",
        )
    portable = b"#!/usr/bin/env python3\n"
    found = False
    for entrypoint in sorted(
        bin_root.iterdir(), key=lambda item: item.name.encode("utf-8")
    ):
        info = entrypoint.lstat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR:
            continue
        found = True
        payload = entrypoint.read_bytes()
        if not payload.startswith(portable):
            _fail(
                "PYTHON_ENTRYPOINT_INVALID",
                f"неизвестная исполняемая точка входа: {entrypoint.name}",
            )
        entrypoint.chmod(0o700)
        entrypoint.write_bytes(shebang + payload[len(portable) :])
        entrypoint.chmod(0o500)
    if not found:
        _fail("PYTHON_ENTRYPOINT_INVALID", "точки входа Python отсутствуют")


def _copy_private_tree(source: Path, target: Path) -> None:
    checkpoint_current_operation_deadline_if_scoped_v2()
    if not source.is_dir() or source.is_symlink() or target.exists():
        _fail("UNSAFE_SOURCE_TREE", f"неверная цель или источник: {source}")
    target.mkdir(mode=0o700)
    for child in sorted(source.iterdir(), key=lambda item: item.name.encode("utf-8")):
        checkpoint_current_operation_deadline_if_scoped_v2()
        if child.name in _EXCLUDED_TREE_NAMES or child.suffix == ".pyc":
            continue
        info = child.lstat()
        destination = target / child.name
        if stat.S_ISDIR(info.st_mode):
            _copy_private_tree(child, destination)
        elif stat.S_ISREG(info.st_mode):
            _copy_regular_file_with_deadline(child, destination)
            destination.chmod(0o500 if info.st_mode & stat.S_IXUSR else 0o600)
        else:
            _fail("UNSAFE_SOURCE_TREE", f"особый объект в исходниках: {child}")


def _normalize_private_tree(root: Path) -> None:
    checkpoint_current_operation_deadline_if_scoped_v2()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        checkpoint_current_operation_deadline_if_scoped_v2()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            path.chmod(0o700)
        elif stat.S_ISREG(info.st_mode):
            path.chmod(0o500 if info.st_mode & stat.S_IXUSR else 0o600)
        else:
            _fail("UNSAFE_SOURCE_TREE", f"особый объект в установленном дереве: {path}")
    root.chmod(0o700)


def _publish_fallback(
    *,
    layout: GatewayLayout,
    source_locator: Mapping[str, object],
    snapshot_locator: Mapping[str, object],
) -> _OwnedRegularFileV2 | None:
    value = {
        "schemaVersion": 2,
        "sourceLocator": copy.deepcopy(dict(source_locator)),
        "backupSnapshot": copy.deepcopy(dict(snapshot_locator)),
        "extensions": {},
    }
    if layout.fallback_path.exists():
        if _read_json(layout.fallback_path) != value:
            _fail("FALLBACK_CONFLICT", "существующая аварийная капсула отличается")
        return None
    _atomic_write_json(layout.fallback_path, value)
    _fsync_directory(layout.manifest_root)
    return _capture_owned_regular_file_v2(layout.fallback_path)


def _manifest_artifacts(
    *,
    codex_home: Path,
    activation_dir: Path,
    snapshot_path: Path,
    fallback_path: Path,
    lock_path: Path,
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = [
        {
            "type": "directory",
            "relativePath": str(activation_dir.relative_to(codex_home)),
            "mode": "0700",
            "treeSha256": _tree_sha256(activation_dir),
        }
    ]
    for path in (snapshot_path, fallback_path, lock_path):
        info = os.lstat(path)
        artifacts.append(
            {
                "type": "regular",
                "relativePath": str(path.relative_to(codex_home)),
                "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
                "size": info.st_size,
                "sha256": _sha256_file(path),
            }
        )
    artifacts.sort(key=lambda item: str(item["relativePath"]).encode("utf-8"))
    return artifacts


def _controller_identity(
    *,
    codex_home: Path,
    state_home: Path,
    activation_fingerprint: str,
    compatibility_fingerprint: str,
    routing_policy_fingerprint: str,
    bundled_catalog_fingerprint: str,
    database_id: str,
) -> str:
    return domain_fingerprint(
        "codex-smart/controller-identity/v2",
        {
            "protocolVersion": 2,
            "release": _RELEASE,
            "namespace": "codex-smart-subagents-v2",
            "codexHomeHash": hashlib.sha256(
                str(codex_home.resolve()).encode("utf-8")
            ).hexdigest(),
            "stateHome": str(state_home),
            "activationFingerprint": activation_fingerprint,
            "compatibilityFingerprint": compatibility_fingerprint,
            "routingPolicyFingerprint": routing_policy_fingerprint,
            "bundledCatalogFingerprint": bundled_catalog_fingerprint,
            "databaseId": database_id,
            "databaseSchemaVersion": 2,
        },
    )


def _database_binding(
    *,
    database_path: Path,
    database_id: str,
    activation_nonce: str,
    activation_id: str,
    activation_fingerprint: str,
    schema_fingerprint: str,
    schema_artifact_sha256: str,
) -> dict[str, object]:
    info = os.lstat(database_path)
    database_identity = {
        "databaseId": database_id,
        "activationBindingNonce": activation_nonce,
        "activationId": activation_id,
        "activationFingerprint": activation_fingerprint,
    }
    database_identity_fingerprint = domain_fingerprint(
        "codex-smart/database-identity/v2", database_identity
    )
    value = {
        "path": str(database_path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": "0600",
        "linkCount": info.st_nlink,
        "databaseId": database_id,
        "databaseIdentity": database_identity,
        "databaseIdentityFingerprint": database_identity_fingerprint,
        "activationIdentity": {
            "activationId": activation_id,
            "activationFingerprint": activation_fingerprint,
        },
        "databaseVersion": _RELEASE,
        "schemaVersion": 2,
        "userVersion": 2,
        "schemaFingerprint": schema_fingerprint,
        "schemaArtifactSha256": schema_artifact_sha256,
    }
    projection = {
        "schemaId": "database-binding-v2",
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    projection["valueFingerprint"] = domain_fingerprint(
        "codex-smart/database-binding/v2", projection
    )
    return projection


def _journal_absence_proof(
    *,
    layout: GatewayLayout,
    installation_id: str,
    operation_id: str,
) -> dict[str, object]:
    if layout.journal_path.exists() or layout.journal_path.is_symlink():
        _fail("JOURNAL_PRESENT", "основной журнал ещё существует")
    _fsync_directory(layout.manifest_root)
    info = layout.manifest_root.lstat()
    value = {
        "proofId": "ap2_" + secrets.token_hex(16),
        "installationId": installation_id,
        "operationId": operation_id,
        "entries": [
            {
                "path": str(layout.journal_path),
                "basename": layout.journal_path.name,
                "parentDevice": info.st_dev,
                "parentInode": info.st_ino,
                "absent": True,
            }
        ],
        "directorySyncCompleted": True,
    }
    value["proofFingerprint"] = domain_fingerprint(
        "codex-smart/absence-proof/v2", value
    )
    projection = {
        "schemaId": "absence-proof-v2",
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    projection["valueFingerprint"] = domain_fingerprint(
        "codex-smart/absence-proof-projection/v2", projection
    )
    return projection


def _activation_receipt(
    *,
    layout: GatewayLayout,
    manifest: dict[str, object],
    activation_document: dict[str, object],
    activation_dir: Path,
    database_binding: dict[str, object],
    absence: dict[str, object],
    controller_identity: str,
    completed_at: datetime,
) -> dict[str, object]:
    active = manifest["activeActivation"]
    semantic_fingerprint = domain_fingerprint(
        "codex-smart/manifest-semantic/v2",
        {key: value for key, value in manifest.items() if key != "extensions"},
    )
    manifest_value = {
        "file": _file_projection(layout.manifest_path),
        "schemaVersion": 2,
        "installationId": manifest["installationId"],
        "release": _RELEASE,
        "pluginId": _PLUGIN_NAME,
        "stateHome": manifest["stateHome"],
        "activeActivationId": active["activationId"],
        "previousActivationId": None,
        "lastCommittedOperation": manifest["lastCommittedOperation"],
        "sourceLocatorFingerprint": hashlib.sha256(
            canonical_json_bytes(manifest["sourceLocator"])
        ).hexdigest(),
        "artifactsFingerprint": hashlib.sha256(
            canonical_json_bytes(manifest["artifacts"])
        ).hexdigest(),
        "semanticFingerprint": semantic_fingerprint,
    }
    identity = activation_document["identity"]
    activation_value = {
        "directory": _tree_projection(activation_dir),
        "activationFile": _file_projection(activation_dir / "activation.json"),
        "activationId": activation_document["activationId"],
        "activationFingerprint": activation_document["activationFingerprint"],
        "generationId": identity["generationId"],
        "release": _RELEASE,
        "databaseId": identity["database"]["databaseId"],
        "databaseIdentityFingerprint": database_binding["value"][
            "databaseIdentityFingerprint"
        ],
        "marketplaceTreeSha256": identity["marketplaceTreeSha256"],
        "generationTreeSha256": identity["generationTreeSha256"],
    }
    operation_id = str(manifest["lastCommittedOperation"])
    receipt = {
        "schemaVersion": 2,
        "receiptKind": "activation-commit",
        "installationId": manifest["installationId"],
        "operationId": operation_id,
        "frozenJournalFingerprint": domain_fingerprint(
            "codex-smart/materialization-intent/v2",
            {
                "installationId": manifest["installationId"],
                "operationId": operation_id,
                "activationId": activation_document["activationId"],
            },
        ),
        "manifest": _journal_projection("manifest-v2", manifest_value),
        "manifestDocument": copy.deepcopy(manifest),
        "transitionLineage": {
            "transitionKind": "initial",
            "sourceReceipt": None,
            "activationProofFingerprint": None,
            "shutdownCommandIds": None,
            "stoppedController": None,
        },
        "activation": _journal_projection("activation-v2", activation_value),
        "databaseBinding": database_binding,
        "journalAbsenceTarget": absence,
        "controllerIdentity": controller_identity,
        "completedStepIds": [
            "st2_"
            + domain_fingerprint(
                "codex-smart/materialization-step/v2",
                {"operationId": operation_id, "kind": "candidate-materialized"},
            )[:32]
        ],
        "completedAt": _iso(completed_at),
    }
    receipt["transitionLineage"]["lineageFingerprint"] = domain_fingerprint(
        "codex-smart/activation-transition-lineage/v2",
        receipt["transitionLineage"],
    )
    receipt["receiptFingerprint"] = domain_fingerprint(
        "codex-smart/activation-commit-receipt/v2", receipt
    )
    return receipt


def _result(
    *,
    status: str,
    layout: GatewayLayout,
    state_home: Path,
    manifest: Mapping[str, Any],
    activation_document: Mapping[str, Any],
    bundled_catalog: Mapping[str, Any],
    receipt_path: Path,
    candidate: ControllerCandidateV2 | AcceptingControllerV2,
    controller_identity: str,
) -> ActivationMaterializationV2:
    identity = activation_document["identity"]
    database_id = identity["database"]["databaseId"]
    zero_counts = {
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
    }
    if isinstance(candidate, AcceptingControllerV2):
        instance_id = candidate.instance_id
        controller_start_id = candidate.controller_start_id
        pid = candidate.controller_pid
        process_start_marker = candidate.controller_process_start_marker
        process_group_id = candidate.controller_process_group_id
    else:
        instance_id = candidate.instance_id
        controller_start_id = candidate.controller_start_id
        pid = candidate.pid
        process_start_marker = candidate.process_start_marker
        process_group_id = candidate.process_group_id
    health = {
        "namespace": "codex-smart-subagents-v2",
        "controllerIdentity": controller_identity,
        "instanceId": instance_id,
        "controllerStartId": controller_start_id,
        "pid": pid,
        "processStartMarker": process_start_marker,
        "processGroupId": process_group_id,
        "state": "ACCEPTING",
        "maintenanceMode": None,
        "operationId": None,
        "acceptingNewRoutes": True,
        "quiescent": False,
        "activationFingerprint": activation_document["activationFingerprint"],
        "compatibilityFingerprint": manifest["interfaceEvidence"][
            "compatibilityFingerprint"
        ],
        "routingPolicyFingerprint": manifest["routingPolicyFingerprint"],
        "bundledCatalogFingerprint": manifest["bundledCatalogFingerprint"],
        "databaseId": database_id,
        "databaseSchemaVersion": 2,
        "workCounts": zero_counts,
    }
    activation_id = str(activation_document["activationId"])
    activation_dir = layout.managed_root / "activations" / activation_id
    return ActivationMaterializationV2(
        status=status,
        readiness="AWAITING_CONTROLLER_HEALTH",
        codex_home=layout.codex_home,
        state_home=state_home,
        activation_id=activation_id,
        activation_fingerprint=str(activation_document["activationFingerprint"]),
        installation_id=str(manifest["installationId"]),
        operation_id=str(manifest["lastCommittedOperation"]),
        controller_identity=controller_identity,
        activation_dir=activation_dir,
        snapshot_path=Path(str(manifest["codexSnapshot"]["absolutePath"])),
        bundled_catalog_path=(
            activation_dir
            / "marketplace"
            / "plugins"
            / _PLUGIN_NAME
            / "config"
            / "bundled-catalog-v1.json"
        ),
        bundled_catalog=copy.deepcopy(dict(bundled_catalog)),
        interface_evidence=copy.deepcopy(dict(manifest["interfaceEvidence"])),
        receipt_path=receipt_path,
        expected_health_payload=health,
    )


def _read_existing_materialization(
    *,
    layout: GatewayLayout,
    codex_binary: Path,
    state_home: Path,
    candidate: ControllerCandidateV2,
    candidate_info: os.stat_result,
) -> ActivationMaterializationV2:
    try:
        manifest = _read_json(layout.manifest_path)
        if (
            manifest.get("schemaVersion") != 2
            or manifest.get("release") != _RELEASE
            or manifest.get("sourceLocator", {}).get("lexicalPath") != str(codex_binary)
            or manifest.get("stateHome") != str(state_home)
        ):
            _fail(
                "EXISTING_ACTIVATION_CONFLICT",
                "существующий манифест имеет другой смысл",
            )
        active = manifest["activeActivation"]
        activation_id = str(active["activationId"])
        expected_target = f"activations/{activation_id}/marketplace"
        if layout.marketplace_link.exists() or layout.marketplace_link.is_symlink():
            if (
                not layout.marketplace_link.is_symlink()
                or os.readlink(layout.marketplace_link) != expected_target
            ):
                _fail(
                    "EXISTING_ACTIVATION_CONFLICT",
                    "marketplace-current указывает на другое состояние",
                )
        activation_dir = layout.managed_root / "activations" / activation_id
        activation_document = _read_json(activation_dir / "activation.json")
        receipt_path = (
            layout.receipts_root
            / str(manifest["installationId"])
            / f"{manifest['lastCommittedOperation']}.commit.json"
        )
        _read_json(receipt_path)
        bundled_path = (
            activation_dir
            / "marketplace"
            / "plugins"
            / _PLUGIN_NAME
            / "config"
            / "bundled-catalog-v1.json"
        )
        bundled_catalog = _read_json(bundled_path)
        database_path = Path(
            str(activation_document["identity"]["database"]["absolutePath"])
        )
        connection = connect_sqlite_with_deadline_v2(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            row = dict(connection.execute("select * from controller_state").fetchone())
        finally:
            connection.close()
        expected = {
            "instance_id": candidate.instance_id,
            "controller_start_id": candidate.controller_start_id,
            "controller_pid": candidate.pid,
            "controller_process_start_marker": candidate.process_start_marker,
            "controller_process_group_id": candidate.process_group_id,
            "control_epoch": candidate.control_epoch,
            "socket_path": str(candidate.socket_path),
            "socket_device": candidate_info.st_dev,
            "socket_inode": candidate_info.st_ino,
        }
        if any(row[name] != value for name, value in expected.items()):
            _fail(
                "EXISTING_ACTIVATION_CONFLICT",
                "кандидат отличается от сохранённой базы",
            )
        return _result(
            status="UNCHANGED",
            layout=layout,
            state_home=Path(str(manifest["stateHome"])),
            manifest=manifest,
            activation_document=activation_document,
            bundled_catalog=bundled_catalog,
            receipt_path=receipt_path,
            candidate=candidate,
            controller_identity=str(row["controller_identity"]),
        )
    except ActivationMaterializationV2Error:
        raise
    except OperationDeadlineExceededV2:
        raise
    except Exception as exc:
        _fail("EXISTING_ACTIVATION_CONFLICT", str(exc))


def _cleanup_failed_materialization(
    *,
    layout: GatewayLayout,
    stage: Path | None,
    activation_dir: Path | None,
    database_path: Path | None,
    receipt_path: Path | None,
) -> None:
    if receipt_path is not None and receipt_path.exists():
        receipt_path.unlink()
    if layout.manifest_path.exists():
        layout.manifest_path.unlink()
    if activation_dir is not None and activation_dir.is_dir():
        shutil.rmtree(activation_dir)
    if stage is not None and stage.is_dir():
        shutil.rmtree(stage)
    if database_path is not None:
        for path in (
            database_path,
            database_path.with_name(database_path.name + "-wal"),
            database_path.with_name(database_path.name + "-shm"),
        ):
            if path.exists():
                path.unlink()
        try:
            database_path.parent.rmdir()
        except OSError:
            pass
    for directory in (
        receipt_path.parent if receipt_path is not None else None,
        layout.receipts_root,
    ):
        if directory is not None:
            try:
                directory.rmdir()
            except OSError:
                pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail("MATERIALIZED_JSON_INVALID", str(exc))
    if type(value) is not dict:
        _fail("MATERIALIZED_JSON_INVALID", f"корень не является объектом: {path}")
    return value


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    temporary = path.parent / ("." + path.name + "." + secrets.token_hex(8))
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        payload = canonical_json_bytes(value)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _ensure_private_directory(path: Path) -> None:
    if path.exists():
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            _fail("UNSAFE_DIRECTORY", f"небезопасный каталог: {path}")
        return
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)


def _ensure_private_directory_owned(path: Path) -> _OwnedDirectoryV2 | None:
    existed = os.path.lexists(path)
    _ensure_private_directory(path)
    if existed:
        return None
    return _capture_owned_directory_v2(path)


def _capture_owned_directory_v2(path: Path) -> _OwnedDirectoryV2:
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
    ):
        _fail("UNSAFE_DIRECTORY", f"небезопасный созданный каталог: {path}")
    return _OwnedDirectoryV2(
        path=path,
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
    )


def _capture_owned_regular_file_v2(path: Path) -> _OwnedRegularFileV2:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        _fail("UNSAFE_OWNED_FILE", f"небезопасный созданный файл: {path}")
    return _OwnedRegularFileV2(
        path=path,
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=stat.S_IMODE(info.st_mode),
        link_count=info.st_nlink,
        size=info.st_size,
        sha256=_sha256_file(path),
    )


def _owned_regular_file_matches_v2(owned: _OwnedRegularFileV2) -> bool:
    try:
        info = os.lstat(owned.path)
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_dev == owned.device
        and info.st_ino == owned.inode
        and info.st_uid == owned.owner_uid
        and info.st_gid == owned.owner_gid
        and stat.S_IMODE(info.st_mode) == owned.mode
        and info.st_nlink == owned.link_count
        and info.st_size == owned.size
        and _sha256_file(owned.path) == owned.sha256
    )


def _unlink_owned_regular_file_v2(owned: _OwnedRegularFileV2 | None) -> None:
    if owned is None or not _owned_regular_file_matches_v2(owned):
        return
    owned.path.unlink()


def _rmdir_owned_directory_v2(owned: _OwnedDirectoryV2 | None) -> None:
    if owned is None:
        return
    try:
        info = os.lstat(owned.path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_dev != owned.device
        or info.st_ino != owned.inode
        or info.st_uid != owned.owner_uid
        or stat.S_IMODE(info.st_mode) != owned.mode
    ):
        return
    try:
        owned.path.rmdir()
    except OSError:
        # Каталог с чужим или новым содержимым не принадлежит компенсации.
        return


def _rollback_staging_ownership_v2(ownership: _StagingOwnershipV2) -> None:
    _remove_owned_tree_v2(ownership.activation_tree)
    _unlink_owned_regular_file_v2(ownership.snapshot_file)
    _rmdir_owned_directory_v2(ownership.snapshot_directory)
    _unlink_owned_regular_file_v2(ownership.lifecycle_lock)
    for directory in reversed(ownership.created_directories):
        _rmdir_owned_directory_v2(directory)


def _capture_owned_tree_v2(root: Path) -> tuple[_OwnedTreeEntryV2, ...]:
    paths = [root, *root.rglob("*")]
    entries: list[_OwnedTreeEntryV2] = []
    for path in paths:
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            kind = "directory"
            content_identity = None
        elif stat.S_ISREG(info.st_mode):
            kind = "regular"
            content_identity = _sha256_file(path)
        elif stat.S_ISLNK(info.st_mode):
            kind = "symlink"
            content_identity = os.readlink(path)
        else:
            _fail("UNSAFE_OWNED_TREE", f"особый объект в созданном дереве: {path}")
        if info.st_uid != os.getuid():
            _fail("UNSAFE_OWNED_TREE", f"чужой объект в созданном дереве: {path}")
        entries.append(
            _OwnedTreeEntryV2(
                path=path,
                kind=kind,
                device=info.st_dev,
                inode=info.st_ino,
                owner_uid=info.st_uid,
                owner_gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode),
                link_count=info.st_nlink,
                size=info.st_size,
                content_identity=content_identity,
            )
        )
    entries.sort(key=lambda entry: str(entry.path).encode("utf-8"))
    return tuple(entries)


def _owned_tree_entry_matches_v2(entry: _OwnedTreeEntryV2) -> bool:
    try:
        info = os.lstat(entry.path)
    except FileNotFoundError:
        return False
    if (
        info.st_dev != entry.device
        or info.st_ino != entry.inode
        or info.st_uid != entry.owner_uid
        or info.st_gid != entry.owner_gid
        or stat.S_IMODE(info.st_mode) != entry.mode
        or info.st_nlink != entry.link_count
        or info.st_size != entry.size
    ):
        return False
    if entry.kind == "directory":
        return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    if entry.kind == "regular":
        return stat.S_ISREG(info.st_mode) and (
            _sha256_file(entry.path) == entry.content_identity
        )
    return stat.S_ISLNK(info.st_mode) and os.readlink(entry.path) == (
        entry.content_identity
    )


def _owned_tree_directory_identity_matches_v2(entry: _OwnedTreeEntryV2) -> bool:
    try:
        info = os.lstat(entry.path)
    except FileNotFoundError:
        return False
    return (
        entry.kind == "directory"
        and stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_dev == entry.device
        and info.st_ino == entry.inode
        and info.st_uid == entry.owner_uid
        and info.st_gid == entry.owner_gid
        and stat.S_IMODE(info.st_mode) == entry.mode
    )


def _remove_owned_tree_v2(entries: tuple[_OwnedTreeEntryV2, ...]) -> None:
    if not entries:
        return
    root = min(entries, key=lambda entry: len(entry.path.parts)).path
    try:
        observed_paths = {root, *root.rglob("*")}
    except FileNotFoundError:
        return
    expected_paths = {entry.path for entry in entries}
    if observed_paths != expected_paths or not all(
        _owned_tree_entry_matches_v2(entry) for entry in entries
    ):
        return
    ordered = sorted(
        entries,
        key=lambda entry: (entry.kind == "directory", -len(entry.path.parts)),
    )
    for entry in ordered:
        matches = (
            _owned_tree_directory_identity_matches_v2(entry)
            if entry.kind == "directory"
            else _owned_tree_entry_matches_v2(entry)
        )
        if not matches:
            continue
        try:
            if entry.kind == "directory":
                entry.path.rmdir()
            else:
                entry.path.unlink()
        except OSError:
            # Появившееся содержимое не принадлежит исходной квитанции.
            continue


def normalize_state_home_v2(state_home: Path) -> Path:
    """Проверяет неизменяемый абсолютный корень обоих локальных сокетов."""

    if not isinstance(state_home, Path) or not state_home.is_absolute():
        _fail("STATE_HOME_INVALID", "state_home должен быть абсолютным Path")
    normalized = state_home.expanduser().absolute()
    for name in ("controller.sock", "command.sock"):
        if len(os.fsencode(normalized / name)) >= 100:
            _fail(
                "STATE_HOME_SOCKET_PATH_TOO_LONG",
                "путь локального сокета должен занимать меньше 100 байт",
            )
    return normalized


def _validate_private_parent(path: Path, code: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        _fail(code, str(exc))
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        _fail(code, "каталог имеет небезопасные метаданные")


def _ensure_lock_file(path: Path) -> None:
    _ensure_private_directory(path.parent)
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            _fail("INSTALLATION_LOCK_INVALID", "файл блокировки небезопасен")
    finally:
        os.close(descriptor)


def _ensure_lock_file_owned(path: Path) -> _OwnedRegularFileV2 | None:
    existed = os.path.lexists(path)
    _ensure_lock_file(path)
    if existed:
        return None
    return _capture_owned_regular_file_v2(path)


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    acquired = False
    try:
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=(
                    finite_file_lock_v2.LOCAL_FILE_LOCK_TIMEOUT_SECONDS
                ),
                timeout_code="ACTIVATION_MATERIALIZATION_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as error:
            raise ActivationMaterializationV2Error(
                error.code,
                "блокировка материализации осталась занятой до истечения срока",
            ) from error
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_regular_file_with_deadline(source: Path, target: Path) -> None:
    """Копировать обычный файл блоками под общим сроком операции."""

    checkpoint_current_operation_deadline_if_scoped_v2()
    source_descriptor = os.open(
        source,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    target_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail("UNSAFE_SOURCE_TREE", f"источник не является файлом: {source}")
        target_descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        while True:
            checkpoint_current_operation_deadline_if_scoped_v2()
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                checkpoint_current_operation_deadline_if_scoped_v2()
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("короткая запись при копировании активации")
                view = view[written:]
        os.fsync(target_descriptor)
        after = os.fstat(source_descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            _fail("SOURCE_CHANGED", f"источник изменился при копировании: {source}")
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)
        os.close(source_descriptor)
    checkpoint_current_operation_deadline_if_scoped_v2()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            checkpoint_current_operation_deadline_if_scoped_v2()
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _required_sha256(value: object, name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail("HASH_INVALID", f"неверный SHA-256: {name}")
    return value


def _identifier(value: object, prefix: str) -> bool:
    return (
        type(value) is str
        and len(value) == len(prefix) + 32
        and value.startswith(prefix)
        and all(character in "0123456789abcdef" for character in value[len(prefix) :])
    )


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("TIMESTAMP_INVALID", "время должно содержать часовой пояс")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fail(code: str, message: str) -> None:
    raise ActivationMaterializationV2Error(code, message)
