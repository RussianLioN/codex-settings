"""Долговечная подготовка неактивной активации перед основным журналом.

Контур создаёт только два будущих объекта: неизменяемое дерево активации и
пустой inode базы. Первый долговечный объект операции — самонесущий журнал с
уже завершённой границей ``preparation_intent``. После заморозки журнал больше
не меняется: публикуется неизменяемая квитанция, затем журнал удаляется с
синхронизацией каталога.
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
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from .canonical_json import canonical_json_bytes, domain_fingerprint
from . import finite_file_lock_v2, operation_deadline_v2
from .activation_transition_rehydration_v2 import (
    ActivationTransitionProofSnapshotV2,
)
from .lifecycle_operation_v2 import ProjectionV2, StateBundleV2


JsonObject = dict[str, Any]
FailureInjectorV2 = Callable[["ActivationPreparationFailurePointV2", str | None], None]

_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_JOURNAL_DOMAIN = "codex-smart/activation-preparation-journal/v2"
_FROZEN_JOURNAL_DOMAIN = "codex-smart/activation-preparation-frozen-journal/v2"
_DEFINITION_DOMAIN = "codex-smart/activation-preparation-definition/v2"
_INTENT_DOMAIN = "codex-smart/activation-preparation-intent/v2"
_LOGICAL_OBJECT_DOMAIN = "codex-smart/preparation-logical-object/v2"
_STEP_DOMAIN = "codex-smart/activation-preparation-step/v2"
_STEP_ID_DOMAIN = "codex-smart/activation-preparation-step-id/v2"
_FILE_PROJECTION_DOMAIN = "codex-smart/file-object/v2"
_TREE_PROJECTION_DOMAIN = "codex-smart/tree-object/v2"
_DIRECTORY_BINDING_DOMAIN = "codex-smart/directory-binding/v2"
_DATABASE_TARGET_DOMAIN = "codex-smart/database-binding-target/v2"
_ACTIVATION_PROJECTION_DOMAIN = "codex-smart/activation/v2"
_RECEIPT_DOMAIN = "codex-smart/activation-preparation-receipt/v2"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODE = re.compile(r"^0[0-7]{3}$")
_IDENTIFIERS = {
    "installation_id": re.compile(r"^ins2_[0-9a-f]{32}$"),
    "operation_id": re.compile(r"^op2_[0-9a-f]{32}$"),
    "database_id": re.compile(r"^db2_[0-9a-f]{32}$"),
    "activation_id": re.compile(r"^act2_[0-9a-f]{64}$"),
}


def _checkpoint_operation_deadline_if_scoped_v2() -> None:
    """Проверить общий срок, если публичная граница его передала."""

    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is not None:
        deadline.checkpoint()


class ActivationPreparationV2Error(RuntimeError):
    """Базовая ошибка подготовительного контура."""


class ActivationPreparationIntegrityErrorV2(ActivationPreparationV2Error):
    """Вход или долговечный объект нарушает строгий договор."""


class ActivationPreparationAmbiguousV2(ActivationPreparationV2Error):
    """Наблюдаемое состояние не равно отсутствию или точному ожиданию."""


class ActivationPreparationConflictV2(ActivationPreparationV2Error):
    """Долговечный объект появился или изменился конкурентно."""


class ActivationPreparationLockTimeoutV2(ActivationPreparationV2Error):
    """Блокировка подготовки осталась занятой до предела операции."""

    def __init__(
        self, code: str = "ACTIVATION_PREPARATION_LOCK_TIMEOUT"
    ) -> None:
        self.code = code
        super().__init__(
            f"{self.code}: activation preparation lock deadline expired"
        )


class ActivationPreparationFailurePointV2(Enum):
    """Воспроизводимые границы всех внешних эффектов подготовки."""

    AFTER_PREPARATION_INTENT = "AFTER_PREPARATION_INTENT"
    AFTER_STEP_INTENT_BEFORE_EFFECT = "AFTER_STEP_INTENT_BEFORE_EFFECT"
    AFTER_EFFECT_BEFORE_STEP_COMPLETE = "AFTER_EFFECT_BEFORE_STEP_COMPLETE"
    BEFORE_PREPARATION_FREEZE = "BEFORE_PREPARATION_FREEZE"
    AFTER_PREPARATION_FREEZE = "AFTER_PREPARATION_FREEZE"
    BEFORE_RECEIPT_PUBLISH = "BEFORE_RECEIPT_PUBLISH"
    AFTER_RECEIPT_PUBLISH = "AFTER_RECEIPT_PUBLISH"


class InjectedActivationPreparationCrashV2(ActivationPreparationV2Error):
    """Явный сбой для проверки одного аварийного окна."""

    def __init__(
        self,
        point: ActivationPreparationFailurePointV2,
        step_kind: str | None,
    ) -> None:
        suffix = "" if step_kind is None else f": {step_kind}"
        super().__init__(
            f"injected activation preparation crash: {point.value}{suffix}"
        )
        self.point = point
        self.step_kind = step_kind


@dataclass(frozen=True)
class ActivationPreparationAbortV2:
    """Результат закрытия намерения, у которого не начался первый эффект."""

    installation_id: str
    operation_id: str
    status: str = "ABORTED_BEFORE_FIRST_EFFECT"

    def __post_init__(self) -> None:
        _identifier(self.installation_id, "installation_id")
        _identifier(self.operation_id, "operation_id")
        if self.status != "ABORTED_BEFORE_FIRST_EFFECT":
            _integrity("activation preparation abort status is invalid")


@dataclass(frozen=True)
class ActivationPreparationIntentV2:
    """Все данные для восстановления ``StagedActivationV2`` без новых ID."""

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

    def __post_init__(self) -> None:
        for field_name in (
            "source_root",
            "codex_home",
            "codex_binary",
            "state_home",
            "socket_path",
            "controller_lock_path",
            "activation_dir",
            "snapshot_path",
            "database_path",
            "bundled_catalog_path",
        ):
            _absolute_path(getattr(self, field_name), field_name)
        for field_name in (
            "installation_id",
            "operation_id",
            "database_id",
            "activation_id",
        ):
            _identifier(getattr(self, field_name), field_name)
        for field_name in (
            "activation_binding_nonce",
            "activation_fingerprint",
            "controller_identity",
            "compatibility_fingerprint",
            "routing_policy_fingerprint",
            "bundled_catalog_fingerprint",
            "schema_fingerprint",
            "schema_artifact_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        if self.activation_id != "act2_" + self.activation_fingerprint:
            _integrity("activation_id is not bound to activation_fingerprint")
        if self.socket_path != self.state_home / "controller.sock":
            _integrity("socket_path is not bound to state_home")
        if self.controller_lock_path != self.state_home / "controller.lock":
            _integrity("controller_lock_path is not bound to state_home")
        if self.activation_file_path != self.activation_dir / "activation.json":
            _integrity("activation file path is invalid")
        if not self.bundled_catalog_path.is_relative_to(self.activation_dir):
            _integrity("bundled_catalog_path must be inside activation_dir")
        _aware(self.completed_at, "completed_at")
        for field_name in (
            "identity",
            "activation_document",
            "source_locator",
            "snapshot_locator",
            "bundled_catalog",
            "interface_evidence",
        ):
            value = getattr(self, field_name)
            if type(value) is not dict:
                _integrity(f"{field_name} must be an object")
            object.__setattr__(self, field_name, copy.deepcopy(dict(value)))
        _exact_keys(
            self.identity,
            {
                "schemaVersion",
                "generationId",
                "release",
                "pluginId",
                "database",
                "codexSnapshot",
                "compatibilityFingerprint",
                "routingPolicyFingerprint",
                "bundledCatalogFingerprint",
                "minimumGatewayVersion",
                "marketplaceTreeSha256",
                "generationTreeSha256",
            },
            "identity",
        )
        if (
            self.identity.get("schemaVersion") != 2
            or self.identity.get("release") != "0.2.0"
            or self.identity.get("pluginId") != "codex-smart-subagents"
            or self.identity.get("minimumGatewayVersion") != "0.2.0"
        ):
            _integrity("identity constants are invalid")
        generation_id = self.identity.get("generationId")
        if (
            type(generation_id) is not str
            or re.fullmatch(r"gen2_[0-9a-f]{64}", generation_id) is None
        ):
            _integrity("identity generationId is invalid")
        _sha256(
            self.identity.get("marketplaceTreeSha256"),
            "identity.marketplaceTreeSha256",
        )
        _sha256(
            self.identity.get("generationTreeSha256"),
            "identity.generationTreeSha256",
        )
        _exact_keys(
            self.activation_document,
            {"schemaVersion", "activationId", "activationFingerprint", "identity"},
            "activationDocument",
        )
        if self.activation_document.get("schemaVersion") != 2:
            _integrity("activationDocument schemaVersion is invalid")
        _exact_keys(
            self.source_locator,
            {
                "lexicalPath",
                "resolvedPathAtCapture",
                "argv0Policy",
                "sourceObservedSha256",
            },
            "sourceLocator",
        )
        if self.source_locator.get("argv0Policy") != "lexical":
            _integrity("sourceLocator argv0Policy is invalid")
        _absolute_path(
            Path(
                _string(
                    self.source_locator.get("resolvedPathAtCapture"),
                    "sourceLocator.resolvedPathAtCapture",
                )
            ),
            "sourceLocator.resolvedPathAtCapture",
        )
        _sha256(
            self.source_locator.get("sourceObservedSha256"),
            "sourceLocator.sourceObservedSha256",
        )
        _exact_keys(
            self.snapshot_locator,
            {"absolutePath", "sha256"},
            "snapshotLocator",
        )
        if self.interface_evidence.get("schemaVersion") != 1:
            _integrity("interfaceEvidence schemaVersion is invalid")
        if self.activation_document.get("activationId") != self.activation_id:
            _integrity("activationDocument activationId differs")
        if (
            self.activation_document.get("activationFingerprint")
            != self.activation_fingerprint
        ):
            _integrity("activationDocument activationFingerprint differs")
        if self.activation_document.get("identity") != self.identity:
            _integrity("activationDocument identity differs")
        expected_activation_fingerprint = domain_fingerprint(
            "codex-smart/activation/v2", self.identity
        )
        if self.activation_fingerprint != expected_activation_fingerprint:
            _integrity("activationFingerprint is not bound to identity")
        if self.activation_dir.name != self.activation_id:
            _integrity("activationDir basename differs from activationId")
        database = self.identity.get("database")
        if type(database) is not dict:
            _integrity("identity.database must be an object")
        _exact_keys(
            database,
            {
                "databaseId",
                "absolutePath",
                "schemaVersion",
                "schemaFingerprint",
                "schemaArtifactSha256",
                "activationBindingNonce",
            },
            "identity.database",
        )
        if database.get("schemaVersion") != 2:
            _integrity("identity.database schemaVersion is invalid")
        expected_database = (
            self.database_id,
            str(self.database_path),
            self.activation_binding_nonce,
            self.schema_fingerprint,
            self.schema_artifact_sha256,
        )
        actual_database = (
            database.get("databaseId"),
            database.get("absolutePath"),
            database.get("activationBindingNonce"),
            database.get("schemaFingerprint"),
            database.get("schemaArtifactSha256"),
        )
        if actual_database != expected_database:
            _integrity("identity.database differs from activation intent")
        expected_identity_fingerprints = {
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "routingPolicyFingerprint": self.routing_policy_fingerprint,
            "bundledCatalogFingerprint": self.bundled_catalog_fingerprint,
        }
        for name, expected in expected_identity_fingerprints.items():
            if self.identity.get(name) != expected:
                _integrity(f"identity.{name} differs from activation intent")
        if (
            self.interface_evidence.get("compatibilityFingerprint")
            != self.compatibility_fingerprint
        ):
            _integrity("interfaceEvidence.compatibilityFingerprint differs from intent")
        if self.snapshot_locator.get("absolutePath") != str(self.snapshot_path):
            _integrity("snapshotLocator path differs")
        snapshot_sha256 = _sha256(
            self.snapshot_locator.get("sha256"), "snapshotLocator.sha256"
        )
        codex_snapshot = self.identity.get("codexSnapshot")
        if type(codex_snapshot) is not dict:
            _integrity("identity.codexSnapshot must be an object")
        _exact_keys(
            codex_snapshot,
            {"absolutePath", "sha256"},
            "identity.codexSnapshot",
        )
        if codex_snapshot != {
            "absolutePath": str(self.snapshot_path),
            "sha256": snapshot_sha256,
        }:
            _integrity("identity.codexSnapshot differs from snapshotLocator")
        if (
            domain_fingerprint("codex-smart/bundled-catalog/v1", self.bundled_catalog)
            != self.bundled_catalog_fingerprint
        ):
            _integrity("bundledCatalogFingerprint is not bound to bundledCatalog")
        if self.source_locator.get("lexicalPath") != str(self.codex_binary):
            _integrity("sourceLocator lexicalPath differs from codexBinary")
        expected_controller_identity = domain_fingerprint(
            "codex-smart/controller-identity/v2",
            {
                "protocolVersion": 2,
                "release": self.identity.get("release"),
                "namespace": "codex-smart-subagents-v2",
                "codexHomeHash": hashlib.sha256(
                    str(self.codex_home.resolve()).encode("utf-8")
                ).hexdigest(),
                "stateHome": str(self.state_home),
                "activationFingerprint": self.activation_fingerprint,
                "compatibilityFingerprint": self.compatibility_fingerprint,
                "routingPolicyFingerprint": self.routing_policy_fingerprint,
                "bundledCatalogFingerprint": self.bundled_catalog_fingerprint,
                "databaseId": self.database_id,
                "databaseSchemaVersion": 2,
            },
        )
        if self.controller_identity != expected_controller_identity:
            _integrity("controllerIdentity is not bound to activation intent")

    @property
    def activation_file_path(self) -> Path:
        return self.activation_dir / "activation.json"

    @property
    def intent_fingerprint(self) -> str:
        return domain_fingerprint(_INTENT_DOMAIN, self._projection())

    def _projection(self) -> JsonObject:
        return {
            "sourceRoot": str(self.source_root),
            "codexHome": str(self.codex_home),
            "codexBinary": str(self.codex_binary),
            "stateHome": str(self.state_home),
            "socketPath": str(self.socket_path),
            "controllerLockPath": str(self.controller_lock_path),
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "databaseId": self.database_id,
            "activationBindingNonce": self.activation_binding_nonce,
            "activationId": self.activation_id,
            "activationFingerprint": self.activation_fingerprint,
            "controllerIdentity": self.controller_identity,
            "compatibilityFingerprint": self.compatibility_fingerprint,
            "routingPolicyFingerprint": self.routing_policy_fingerprint,
            "bundledCatalogFingerprint": self.bundled_catalog_fingerprint,
            "schemaFingerprint": self.schema_fingerprint,
            "schemaArtifactSha256": self.schema_artifact_sha256,
            "activationDir": str(self.activation_dir),
            "snapshotPath": str(self.snapshot_path),
            "databasePath": str(self.database_path),
            "bundledCatalogPath": str(self.bundled_catalog_path),
            "identity": copy.deepcopy(dict(self.identity)),
            "activationDocument": copy.deepcopy(dict(self.activation_document)),
            "sourceLocator": copy.deepcopy(dict(self.source_locator)),
            "snapshotLocator": copy.deepcopy(dict(self.snapshot_locator)),
            "bundledCatalog": copy.deepcopy(dict(self.bundled_catalog)),
            "interfaceEvidence": copy.deepcopy(dict(self.interface_evidence)),
            "completedAt": _timestamp(self.completed_at),
        }

    def to_document(self) -> JsonObject:
        projection = self._projection()
        return {
            **projection,
            "activationIntentFingerprint": self.intent_fingerprint,
        }

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> ActivationPreparationIntentV2:
        keys = {
            "sourceRoot",
            "codexHome",
            "codexBinary",
            "stateHome",
            "socketPath",
            "controllerLockPath",
            "installationId",
            "operationId",
            "databaseId",
            "activationBindingNonce",
            "activationId",
            "activationFingerprint",
            "controllerIdentity",
            "compatibilityFingerprint",
            "routingPolicyFingerprint",
            "bundledCatalogFingerprint",
            "schemaFingerprint",
            "schemaArtifactSha256",
            "activationDir",
            "snapshotPath",
            "databasePath",
            "bundledCatalogPath",
            "identity",
            "activationDocument",
            "sourceLocator",
            "snapshotLocator",
            "bundledCatalog",
            "interfaceEvidence",
            "completedAt",
            "activationIntentFingerprint",
        }
        _exact_keys(document, keys, "activationIntent")
        result = cls(
            source_root=Path(_string(document["sourceRoot"], "sourceRoot")),
            codex_home=Path(_string(document["codexHome"], "codexHome")),
            codex_binary=Path(_string(document["codexBinary"], "codexBinary")),
            state_home=Path(_string(document["stateHome"], "stateHome")),
            socket_path=Path(_string(document["socketPath"], "socketPath")),
            controller_lock_path=Path(
                _string(document["controllerLockPath"], "controllerLockPath")
            ),
            installation_id=_string(document["installationId"], "installationId"),
            operation_id=_string(document["operationId"], "operationId"),
            database_id=_string(document["databaseId"], "databaseId"),
            activation_binding_nonce=_string(
                document["activationBindingNonce"], "activationBindingNonce"
            ),
            activation_id=_string(document["activationId"], "activationId"),
            activation_fingerprint=_string(
                document["activationFingerprint"], "activationFingerprint"
            ),
            controller_identity=_string(
                document["controllerIdentity"], "controllerIdentity"
            ),
            compatibility_fingerprint=_string(
                document["compatibilityFingerprint"], "compatibilityFingerprint"
            ),
            routing_policy_fingerprint=_string(
                document["routingPolicyFingerprint"], "routingPolicyFingerprint"
            ),
            bundled_catalog_fingerprint=_string(
                document["bundledCatalogFingerprint"], "bundledCatalogFingerprint"
            ),
            schema_fingerprint=_string(
                document["schemaFingerprint"], "schemaFingerprint"
            ),
            schema_artifact_sha256=_string(
                document["schemaArtifactSha256"], "schemaArtifactSha256"
            ),
            activation_dir=Path(_string(document["activationDir"], "activationDir")),
            snapshot_path=Path(_string(document["snapshotPath"], "snapshotPath")),
            database_path=Path(_string(document["databasePath"], "databasePath")),
            bundled_catalog_path=Path(
                _string(document["bundledCatalogPath"], "bundledCatalogPath")
            ),
            identity=_object(document["identity"], "identity"),
            activation_document=_object(
                document["activationDocument"], "activationDocument"
            ),
            source_locator=_object(document["sourceLocator"], "sourceLocator"),
            snapshot_locator=_object(document["snapshotLocator"], "snapshotLocator"),
            bundled_catalog=_object(document["bundledCatalog"], "bundledCatalog"),
            interface_evidence=_object(
                document["interfaceEvidence"], "interfaceEvidence"
            ),
            completed_at=_parse_timestamp(document["completedAt"], "completedAt"),
        )
        if document["activationIntentFingerprint"] != result.intent_fingerprint:
            _integrity("activationIntentFingerprint mismatch")
        return result


@dataclass(frozen=True)
class LogicalPreparationObjectV2:
    """Логическое ожидание, известное до появления физического объекта."""

    path: Path
    object_type: str
    mode: str
    content_sha256: str

    def __post_init__(self) -> None:
        _absolute_path(self.path, "logical path")
        if self.object_type not in {"directory", "regular-file"}:
            _integrity("logical object type is invalid")
        if type(self.mode) is not str or _MODE.fullmatch(self.mode) is None:
            _integrity("logical object mode is invalid")
        _sha256(self.content_sha256, "logical content_sha256")

    @property
    def logical_fingerprint(self) -> str:
        return domain_fingerprint(_LOGICAL_OBJECT_DOMAIN, self._projection())

    def _projection(self) -> JsonObject:
        return {
            "path": str(self.path),
            "objectType": self.object_type,
            "mode": self.mode,
            "contentSha256": self.content_sha256,
        }

    def to_document(self) -> JsonObject:
        return {
            **self._projection(),
            "logicalFingerprint": self.logical_fingerprint,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> LogicalPreparationObjectV2:
        _exact_keys(
            document,
            {
                "path",
                "objectType",
                "mode",
                "contentSha256",
                "logicalFingerprint",
            },
            "expectedLogical",
        )
        result = cls(
            path=Path(_string(document["path"], "path")),
            object_type=_string(document["objectType"], "objectType"),
            mode=_string(document["mode"], "mode"),
            content_sha256=_string(document["contentSha256"], "contentSha256"),
        )
        if document["logicalFingerprint"] != result.logical_fingerprint:
            _integrity("logicalFingerprint mismatch")
        return result


@dataclass(frozen=True)
class ActivationPreparationDefinitionV2:
    """Полное неизменяемое определение одной подготовительной операции."""

    journal_path: Path
    receipt_path: Path
    lock_path: Path
    activation_intent: ActivationPreparationIntentV2
    desired_seed: StateBundleV2
    snapshot_file: ProjectionV2
    activation_tree_logical: LogicalPreparationObjectV2
    activation_file_logical: LogicalPreparationObjectV2
    database_empty_file_logical: LogicalPreparationObjectV2
    prepared_manifest_logical: LogicalPreparationObjectV2 | None = None
    transition_proof_snapshot: ActivationTransitionProofSnapshotV2 | None = None

    def __post_init__(self) -> None:
        for field_name in ("journal_path", "receipt_path", "lock_path"):
            _absolute_path(getattr(self, field_name), field_name)
        if len({self.journal_path, self.receipt_path, self.lock_path}) != 3:
            _integrity("journal, receipt and lock paths must differ")
        if not isinstance(self.activation_intent, ActivationPreparationIntentV2):
            _integrity("activation_intent has invalid type")
        if not isinstance(self.desired_seed, StateBundleV2):
            _integrity("desired_seed has invalid type")
        _verify_state_bundle_document(self.desired_seed.to_document())
        _verify_projection(
            self.snapshot_file,
            schema_id="file-object-v2",
            domain=_FILE_PROJECTION_DOMAIN,
        )
        if self.snapshot_file.value.get("path") != str(
            self.activation_intent.snapshot_path
        ):
            _integrity("snapshotFile path differs from activation intent")
        if self.snapshot_file.value.get(
            "sha256"
        ) != self.activation_intent.snapshot_locator.get("sha256"):
            _integrity("snapshotFile sha256 differs from snapshotLocator")
        if self.activation_tree_logical != LogicalPreparationObjectV2(
            path=self.activation_intent.activation_dir,
            object_type="directory",
            mode=self.activation_tree_logical.mode,
            content_sha256=self.activation_tree_logical.content_sha256,
        ):
            _integrity("activation tree target is invalid")
        if self.activation_tree_logical.mode not in {"0500", "0700"}:
            _integrity("activation tree must use a supported private mode")
        activation_file_mode = (
            "0400" if self.activation_tree_logical.mode == "0500" else "0600"
        )
        expected_activation_file = LogicalPreparationObjectV2(
            path=self.activation_intent.activation_file_path,
            object_type="regular-file",
            mode=activation_file_mode,
            content_sha256=hashlib.sha256(
                canonical_json_bytes(self.activation_intent.activation_document)
            ).hexdigest(),
        )
        if self.activation_file_logical != expected_activation_file:
            _integrity("activation file logical expectation is invalid")
        expected_database = LogicalPreparationObjectV2(
            path=self.activation_intent.database_path,
            object_type="regular-file",
            mode="0600",
            content_sha256=_EMPTY_SHA256,
        )
        if self.database_empty_file_logical != expected_database:
            _integrity("database empty-file logical expectation is invalid")
        if self.prepared_manifest_logical is not None:
            if (
                not isinstance(
                    self.prepared_manifest_logical,
                    LogicalPreparationObjectV2,
                )
                or self.prepared_manifest_logical.object_type != "regular-file"
                or self.prepared_manifest_logical.mode != "0600"
            ):
                _integrity("prepared manifest logical expectation is invalid")
        if (self.prepared_manifest_logical is None) != (
            self.transition_proof_snapshot is None
        ):
            _integrity("prepared manifest and transition proof snapshot must be paired")
        if self.transition_proof_snapshot is not None:
            snapshot = self.transition_proof_snapshot
            if not isinstance(snapshot, ActivationTransitionProofSnapshotV2):
                _integrity("transition proof snapshot has invalid type")
            if (
                not snapshot.complete
                or snapshot.operation_id != self.activation_intent.operation_id
                or snapshot.installation_id != self.activation_intent.installation_id
                or snapshot.codex_home != self.activation_intent.codex_home
                or snapshot.state_home != self.activation_intent.state_home
            ):
                _integrity("transition proof snapshot differs from activation intent")
        targets = {
            self.activation_intent.activation_dir,
            self.activation_intent.database_path,
        }
        if self.prepared_manifest_logical is not None:
            targets.add(self.prepared_manifest_logical.path)
        if targets & {self.journal_path, self.receipt_path, self.lock_path}:
            _integrity("control paths overlap prepared targets")

    @property
    def definition_fingerprint(self) -> str:
        return domain_fingerprint(_DEFINITION_DOMAIN, self.to_document())

    def to_document(self) -> JsonObject:
        document = {
            "journalPath": str(self.journal_path),
            "receiptPath": str(self.receipt_path),
            "lockPath": str(self.lock_path),
            "activationIntent": self.activation_intent.to_document(),
            "desiredSeed": self.desired_seed.to_document(),
            "snapshotFile": self.snapshot_file.to_document(),
            "activationTreeLogical": self.activation_tree_logical.to_document(),
            "activationFileLogical": self.activation_file_logical.to_document(),
            "databaseEmptyFileLogical": (
                self.database_empty_file_logical.to_document()
            ),
        }
        if self.prepared_manifest_logical is not None:
            document["preparedManifestLogical"] = (
                self.prepared_manifest_logical.to_document()
            )
        if self.transition_proof_snapshot is not None:
            document["transitionProofSnapshot"] = (
                self.transition_proof_snapshot.to_document()
            )
        return document


@dataclass(frozen=True)
class ActivationPreparationCallbacksV2:
    """Единственный внешний материализатор точного дерева активации."""

    materialize_activation_tree: Callable[[ActivationPreparationIntentV2], None]
    build_desired: Callable[
        ["PreparedActivationObjectsV2", StateBundleV2], StateBundleV2
    ]
    materialize_prepared_manifest: (
        Callable[[ActivationPreparationIntentV2, LogicalPreparationObjectV2], None]
        | None
    ) = None

    def __post_init__(self) -> None:
        if not callable(self.materialize_activation_tree):
            _integrity("materialize_activation_tree must be callable")
        if not callable(self.build_desired):
            _integrity("build_desired must be callable")
        if self.materialize_prepared_manifest is not None and not callable(
            self.materialize_prepared_manifest
        ):
            _integrity("materialize_prepared_manifest must be callable")


@dataclass(frozen=True)
class PreparedActivationObjectsV2:
    """Точные физические объекты, доступные только после обоих эффектов."""

    snapshot_file: ProjectionV2
    activation_tree: ProjectionV2
    activation_file: ProjectionV2
    database_empty_file: ProjectionV2
    database_binding_target: ProjectionV2
    activation: ProjectionV2
    prepared_manifest_file: ProjectionV2 | None = None
    prepared_manifest_parent: ProjectionV2 | None = None

    def __post_init__(self) -> None:
        _verify_projection(
            self.snapshot_file,
            schema_id="file-object-v2",
            domain=_FILE_PROJECTION_DOMAIN,
        )
        _verify_projection(
            self.activation_tree,
            schema_id="tree-object-v2",
            domain=_TREE_PROJECTION_DOMAIN,
        )
        for projection in (self.activation_file, self.database_empty_file):
            _verify_projection(
                projection,
                schema_id="file-object-v2",
                domain=_FILE_PROJECTION_DOMAIN,
            )
        _verify_projection(
            self.database_binding_target,
            schema_id="database-binding-target-v2",
            domain=_DATABASE_TARGET_DOMAIN,
        )
        _verify_projection(
            self.activation,
            schema_id="activation-v2",
            domain=_ACTIVATION_PROJECTION_DOMAIN,
        )
        if self.activation.value.get("directory") != self.activation_tree.value:
            _integrity("activation projection directory differs")
        if self.activation.value.get("activationFile") != self.activation_file.value:
            _integrity("activation projection activationFile differs")
        if self.prepared_manifest_file is not None:
            _verify_projection(
                self.prepared_manifest_file,
                schema_id="file-object-v2",
                domain=_FILE_PROJECTION_DOMAIN,
            )
        if self.prepared_manifest_parent is not None:
            _verify_projection(
                self.prepared_manifest_parent,
                schema_id="directory-binding-v2",
                domain=_DIRECTORY_BINDING_DOMAIN,
            )
        if (self.prepared_manifest_file is None) != (
            self.prepared_manifest_parent is None
        ):
            _integrity("prepared manifest file and parent must be paired")


@dataclass(frozen=True)
class ActivationPreparationReceiptV2:
    """Неизменяемое доказательство завершённой подготовки."""

    installation_id: str
    operation_id: str
    activation_intent: ActivationPreparationIntentV2
    snapshot_file: ProjectionV2
    activation_tree: ProjectionV2
    activation_file: ProjectionV2
    database_empty_file: ProjectionV2
    database_binding_target: ProjectionV2
    desired: StateBundleV2
    frozen_journal_fingerprint: str
    completed_at: datetime
    prepared_manifest_file: ProjectionV2 | None = None
    prepared_manifest_parent: ProjectionV2 | None = None
    transition_proof_snapshot: ActivationTransitionProofSnapshotV2 | None = None

    def __post_init__(self) -> None:
        _identifier(self.installation_id, "installation_id")
        _identifier(self.operation_id, "operation_id")
        if (
            self.installation_id != self.activation_intent.installation_id
            or self.operation_id != self.activation_intent.operation_id
        ):
            _integrity("receipt IDs differ from activationIntent")
        _verify_projection(
            self.snapshot_file,
            schema_id="file-object-v2",
            domain=_FILE_PROJECTION_DOMAIN,
        )
        _verify_projection(
            self.activation_tree,
            schema_id="tree-object-v2",
            domain=_TREE_PROJECTION_DOMAIN,
        )
        for projection in (self.activation_file, self.database_empty_file):
            _verify_projection(
                projection,
                schema_id="file-object-v2",
                domain=_FILE_PROJECTION_DOMAIN,
            )
        _verify_projection(
            self.database_binding_target,
            schema_id="database-binding-target-v2",
            domain=_DATABASE_TARGET_DOMAIN,
        )
        empty_value = self.database_empty_file.value
        binding_value = self.database_binding_target.value
        for name in (
            "path",
            "device",
            "inode",
            "ownerUid",
            "ownerGid",
            "mode",
            "linkCount",
        ):
            if empty_value.get(name) != binding_value.get(name):
                _integrity(f"database binding target differs at {name}")
        intent = self.activation_intent
        expected_binding = {
            "databaseId": intent.database_id,
            "activationBindingNonce": intent.activation_binding_nonce,
            "activationId": intent.activation_id,
            "activationFingerprint": intent.activation_fingerprint,
            "schemaFingerprint": intent.schema_fingerprint,
            "schemaArtifactSha256": intent.schema_artifact_sha256,
        }
        for name, expected in expected_binding.items():
            if binding_value.get(name) != expected:
                _integrity(f"database binding target differs at {name}")
        _verify_state_bundle_document(self.desired.to_document())
        _validate_full_desired(
            self.desired,
            self.prepared,
            seed=None,
        )
        if (self.prepared_manifest_file is None) != (
            self.prepared_manifest_parent is None
        ):
            _integrity("prepared manifest receipt projections must be paired")
        if (self.prepared_manifest_file is None) != (
            self.transition_proof_snapshot is None
        ):
            _integrity("prepared manifest and transition proof snapshot must be paired")
        if self.prepared_manifest_file is not None:
            _verify_projection(
                self.prepared_manifest_file,
                schema_id="file-object-v2",
                domain=_FILE_PROJECTION_DOMAIN,
            )
            _verify_projection(
                self.prepared_manifest_parent,
                schema_id="directory-binding-v2",
                domain=_DIRECTORY_BINDING_DOMAIN,
            )
            if self.prepared_manifest_file not in self.desired.file_objects:
                _integrity("desired omits receipt prepared manifest file")
        if self.transition_proof_snapshot is not None:
            snapshot = self.transition_proof_snapshot
            if (
                not isinstance(snapshot, ActivationTransitionProofSnapshotV2)
                or not snapshot.complete
                or snapshot.operation_id != self.operation_id
                or snapshot.installation_id != self.installation_id
                or snapshot.codex_home != self.activation_intent.codex_home
                or snapshot.state_home != self.activation_intent.state_home
            ):
                _integrity("receipt transition proof snapshot differs")
        _sha256(self.frozen_journal_fingerprint, "frozen_journal_fingerprint")
        _aware(self.completed_at, "completed_at")

    @property
    def prepared(self) -> PreparedActivationObjectsV2:
        activation = _activation_projection(
            activation_tree=self.activation_tree,
            activation_file=self.activation_file,
            database_binding_target=self.database_binding_target,
            intent=self.activation_intent,
        )
        return PreparedActivationObjectsV2(
            snapshot_file=self.snapshot_file,
            activation_tree=self.activation_tree,
            activation_file=self.activation_file,
            database_empty_file=self.database_empty_file,
            database_binding_target=self.database_binding_target,
            activation=activation,
            prepared_manifest_file=self.prepared_manifest_file,
            prepared_manifest_parent=self.prepared_manifest_parent,
        )

    def _projection(self) -> JsonObject:
        projection = {
            "schemaVersion": 2,
            "receiptKind": "activation-preparation",
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "activationIntent": self.activation_intent.to_document(),
            "snapshotFile": self.snapshot_file.to_document(),
            "activationTree": self.activation_tree.to_document(),
            "activationFile": self.activation_file.to_document(),
            "databaseEmptyFile": self.database_empty_file.to_document(),
            "databaseBindingTarget": self.database_binding_target.to_document(),
            "desired": self.desired.to_document(),
            "frozenJournalFingerprint": self.frozen_journal_fingerprint,
            "completedAt": _timestamp(self.completed_at),
        }
        if self.prepared_manifest_file is not None:
            projection["preparedManifestFile"] = (
                self.prepared_manifest_file.to_document()
            )
            projection["preparedManifestParent"] = (
                self.prepared_manifest_parent.to_document()
            )
        if self.transition_proof_snapshot is not None:
            projection["transitionProofSnapshot"] = (
                self.transition_proof_snapshot.to_document()
            )
        return projection

    @property
    def receipt_fingerprint(self) -> str:
        return domain_fingerprint(_RECEIPT_DOMAIN, self._projection())

    def to_document(self) -> JsonObject:
        return {**self._projection(), "receiptFingerprint": self.receipt_fingerprint}

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> ActivationPreparationReceiptV2:
        required_keys = {
            "schemaVersion",
            "receiptKind",
            "installationId",
            "operationId",
            "activationIntent",
            "snapshotFile",
            "activationTree",
            "activationFile",
            "databaseEmptyFile",
            "databaseBindingTarget",
            "desired",
            "frozenJournalFingerprint",
            "completedAt",
            "receiptFingerprint",
        }
        optional_keys = {
            "preparedManifestFile",
            "preparedManifestParent",
            "transitionProofSnapshot",
        }
        if not required_keys.issubset(document) or not set(document).issubset(
            required_keys | optional_keys
        ):
            _integrity("preparation receipt has unexpected keys")
        if ("preparedManifestFile" in document) != (
            "preparedManifestParent" in document
        ):
            _integrity("preparation receipt manifest projections are incomplete")
        if document["schemaVersion"] != 2:
            _integrity("preparation receipt schemaVersion is invalid")
        if document["receiptKind"] != "activation-preparation":
            _integrity("preparation receipt kind is invalid")
        desired_document = _object(document["desired"], "desired")
        desired = _verify_state_bundle_document(desired_document)
        result = cls(
            installation_id=_string(document["installationId"], "installationId"),
            operation_id=_string(document["operationId"], "operationId"),
            activation_intent=ActivationPreparationIntentV2.from_document(
                _object(document["activationIntent"], "activationIntent")
            ),
            snapshot_file=ProjectionV2.from_document(
                _object(document["snapshotFile"], "snapshotFile")
            ),
            activation_tree=ProjectionV2.from_document(
                _object(document["activationTree"], "activationTree")
            ),
            activation_file=ProjectionV2.from_document(
                _object(document["activationFile"], "activationFile")
            ),
            database_empty_file=ProjectionV2.from_document(
                _object(document["databaseEmptyFile"], "databaseEmptyFile")
            ),
            database_binding_target=ProjectionV2.from_document(
                _object(document["databaseBindingTarget"], "databaseBindingTarget")
            ),
            desired=desired,
            frozen_journal_fingerprint=_string(
                document["frozenJournalFingerprint"],
                "frozenJournalFingerprint",
            ),
            completed_at=_parse_timestamp(document["completedAt"], "completedAt"),
            prepared_manifest_file=(
                None
                if "preparedManifestFile" not in document
                else ProjectionV2.from_document(
                    _object(document["preparedManifestFile"], "preparedManifestFile")
                )
            ),
            prepared_manifest_parent=(
                None
                if "preparedManifestParent" not in document
                else ProjectionV2.from_document(
                    _object(
                        document["preparedManifestParent"],
                        "preparedManifestParent",
                    )
                )
            ),
            transition_proof_snapshot=(
                None
                if "transitionProofSnapshot" not in document
                else ActivationTransitionProofSnapshotV2.from_document(
                    _object(
                        document["transitionProofSnapshot"],
                        "transitionProofSnapshot",
                    )
                )
            ),
        )
        if document["receiptFingerprint"] != result.receipt_fingerprint:
            _integrity("receiptFingerprint mismatch")
        return result

    @classmethod
    def from_path(cls, path: Path) -> ActivationPreparationReceiptV2:
        _absolute_path(path, "receipt path")
        return cls.from_document(_read_canonical_private_json(path, "receipt"))


class ActivationPreparationExecutorV2:
    """Исполняет и восстанавливает одну подготовку под общей блокировкой."""

    def __init__(
        self,
        *,
        definition: ActivationPreparationDefinitionV2,
        callbacks: ActivationPreparationCallbacksV2,
        clock: Callable[[], datetime] | None = None,
        failure_injector: FailureInjectorV2 | None = None,
    ) -> None:
        if not isinstance(definition, ActivationPreparationDefinitionV2):
            _integrity("definition has invalid type")
        if not isinstance(callbacks, ActivationPreparationCallbacksV2):
            _integrity("callbacks have invalid type")
        self.definition = definition
        self.callbacks = callbacks
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._failure_injector = failure_injector
        if (definition.prepared_manifest_logical is None) != (
            callbacks.materialize_prepared_manifest is None
        ):
            _integrity(
                "prepared manifest definition and callback must be provided together"
            )
        _validate_private_directory(definition.journal_path.parent)
        _validate_private_directory(definition.receipt_path.parent)
        _validate_private_directory(definition.activation_intent.activation_dir.parent)
        _validate_private_directory(definition.activation_intent.database_path.parent)
        _ensure_private_lock_file(definition.lock_path)

    def execute(self) -> ActivationPreparationReceiptV2:
        """Завершает новую или прерванную подготовку идемпотентно."""

        _checkpoint_operation_deadline_if_scoped_v2()
        with _exclusive_lock(self.definition.lock_path):
            _checkpoint_operation_deadline_if_scoped_v2()
            journal_present = _lexists(self.definition.journal_path)
            receipt_present = _lexists(self.definition.receipt_path)
            if receipt_present:
                receipt = ActivationPreparationReceiptV2.from_path(
                    self.definition.receipt_path
                )
                self._verify_receipt_matches_definition(receipt)
                self._verify_live_receipt(receipt)
                _checkpoint_operation_deadline_if_scoped_v2()
                if journal_present:
                    journal = self._read_journal()
                    if journal["phase"] != "PREPARATION_FROZEN":
                        raise ActivationPreparationAmbiguousV2(
                            "receipt coexists with a non-frozen preparation journal"
                        )
                    if (
                        receipt.frozen_journal_fingerprint
                        != journal["frozenJournalFingerprint"]
                    ):
                        raise ActivationPreparationConflictV2(
                            "receipt and frozen journal fingerprints differ"
                        )
                    self._delete_exact_journal(journal)
                return receipt

            if not journal_present:
                self._require_unprepared_targets_absent()
                self._verify_snapshot_file()
                journal = self._initial_journal()
                _validate_journal_document(journal, self.definition)
                _checkpoint_operation_deadline_if_scoped_v2()
                _atomic_create_private_json(self.definition.journal_path, journal)
                self._inject(
                    ActivationPreparationFailurePointV2.AFTER_PREPARATION_INTENT,
                    None,
                )
                _checkpoint_operation_deadline_if_scoped_v2()
            else:
                journal = self._read_journal()

            if journal["phase"] == "PREPARING":
                journal = self._run_steps(journal)
                prepared = self._prepared_from_completed_journal(journal)
                desired = self.callbacks.build_desired(
                    prepared,
                    self.definition.desired_seed,
                )
                if not isinstance(desired, StateBundleV2):
                    _integrity("build_desired must return StateBundleV2")
                _validate_full_desired(
                    desired,
                    prepared,
                    seed=self.definition.desired_seed,
                )
                self._inject(
                    ActivationPreparationFailurePointV2.BEFORE_PREPARATION_FREEZE,
                    None,
                )
                _checkpoint_operation_deadline_if_scoped_v2()
                journal = self._freeze(journal, desired)
                self._inject(
                    ActivationPreparationFailurePointV2.AFTER_PREPARATION_FREEZE,
                    None,
                )
                _checkpoint_operation_deadline_if_scoped_v2()
            elif journal["phase"] != "PREPARATION_FROZEN":
                _integrity("preparation journal phase is invalid")

            self._verify_snapshot_file()
            receipt = self._receipt_from_frozen(journal)
            self._inject(
                ActivationPreparationFailurePointV2.BEFORE_RECEIPT_PUBLISH,
                None,
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            _atomic_create_private_json(
                self.definition.receipt_path, receipt.to_document()
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            published = ActivationPreparationReceiptV2.from_path(
                self.definition.receipt_path
            )
            if published.to_document() != receipt.to_document():
                raise ActivationPreparationConflictV2(
                    "published preparation receipt differs"
                )
            self._inject(
                ActivationPreparationFailurePointV2.AFTER_RECEIPT_PUBLISH,
                None,
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            self._delete_exact_journal(journal)
            return published

    recover = execute

    def abort_before_first_effect(self) -> ActivationPreparationAbortV2:
        """Удаляет только точное намерение до появления первого эффекта.

        Это узкая аварийная ветвь для случая, когда исходное дерево больше
        недоступно. Она никогда не удаляет дерево кандидата или файл базы:
        наличие любого подготовленного объекта закрывает abort как
        неоднозначный и оставляет журнал для точного продолжения.
        """

        _checkpoint_operation_deadline_if_scoped_v2()
        with _exclusive_lock(self.definition.lock_path):
            _checkpoint_operation_deadline_if_scoped_v2()
            if _lexists(self.definition.receipt_path):
                raise ActivationPreparationAmbiguousV2(
                    "published preparation receipt cannot be aborted"
                )
            if not _lexists(self.definition.journal_path):
                self._require_unprepared_targets_absent()
                self._verify_snapshot_file()
                return self._abort_result()

            journal = self._read_journal()
            if journal["phase"] != "PREPARING":
                raise ActivationPreparationAmbiguousV2(
                    "frozen preparation cannot be aborted before first effect"
                )
            steps = journal["steps"]
            first = steps[0]
            if first["state"] not in {"PLANNED", "INTENT_DURABLE"}:
                raise ActivationPreparationAmbiguousV2(
                    "activation tree effect is already journaled as complete"
                )
            first_expected = LogicalPreparationObjectV2.from_document(
                _object(first["expectedLogical"], "expectedLogical")
            )
            first_state, _, _ = self._observe_step("activation_tree", first_expected)
            if first_state != "ABSENT":
                raise ActivationPreparationAmbiguousV2(
                    "activation tree effect exists; early abort is forbidden"
                )
            for step in steps[1:]:
                if step["state"] != "PLANNED":
                    raise ActivationPreparationAmbiguousV2(
                        "a later preparation effect has durable intent"
                    )
                expected = LogicalPreparationObjectV2.from_document(
                    _object(step["expectedLogical"], "expectedLogical")
                )
                state, _, _ = self._observe_step(str(step["kind"]), expected)
                if state != "ABSENT":
                    raise ActivationPreparationAmbiguousV2(
                        "a later preparation target exists before its intent"
                    )
            self._verify_snapshot_file()
            self._delete_exact_journal(journal, required_phase="PREPARING")
            return self._abort_result()

    def _abort_result(self) -> ActivationPreparationAbortV2:
        intent = self.definition.activation_intent
        return ActivationPreparationAbortV2(
            installation_id=intent.installation_id,
            operation_id=intent.operation_id,
        )

    def _initial_journal(self) -> JsonObject:
        now = _timestamp(self._clock())
        steps = [
            _new_step_document(
                operation_id=self.definition.activation_intent.operation_id,
                ordinal=1,
                kind="activation_tree",
                expected=self.definition.activation_tree_logical,
            ),
            _new_step_document(
                operation_id=self.definition.activation_intent.operation_id,
                ordinal=2,
                kind="database_empty_file",
                expected=self.definition.database_empty_file_logical,
            ),
        ]
        if self.definition.prepared_manifest_logical is not None:
            steps.append(
                _new_step_document(
                    operation_id=self.definition.activation_intent.operation_id,
                    ordinal=3,
                    kind="prepared_manifest_file",
                    expected=self.definition.prepared_manifest_logical,
                )
            )
        projection = {
            "schemaVersion": 2,
            "journalKind": "activation-preparation",
            "installationId": self.definition.activation_intent.installation_id,
            "operationId": self.definition.activation_intent.operation_id,
            "phase": "PREPARING",
            "definitionFingerprint": self.definition.definition_fingerprint,
            "definition": self.definition.to_document(),
            "intentBoundary": {
                "kind": "preparation_intent",
                "state": "COMPLETED",
                "activationIntentFingerprint": (
                    self.definition.activation_intent.intent_fingerprint
                ),
                "desiredSeedFingerprint": self.definition.desired_seed.to_document()[
                    "bundleFingerprint"
                ],
                "completedAt": now,
            },
            "steps": steps,
            "contentGeneration": 0,
            "createdAt": now,
            "updatedAt": now,
            "frozenAt": None,
            "frozenJournalFingerprint": None,
            "desired": None,
        }
        return _with_journal_fingerprint(projection)

    def _run_steps(self, journal: JsonObject) -> JsonObject:
        for ordinal in range(1, len(journal["steps"]) + 1):
            journal = self._run_one_step(journal, ordinal)
        return journal

    def _run_one_step(self, journal: JsonObject, ordinal: int) -> JsonObject:
        _checkpoint_operation_deadline_if_scoped_v2()
        step = journal["steps"][ordinal - 1]
        kind = str(step["kind"])
        expected = LogicalPreparationObjectV2.from_document(
            _object(step["expectedLogical"], "expectedLogical")
        )
        state = str(step["state"])
        if state == "COMPLETED":
            _checkpoint_operation_deadline_if_scoped_v2()
            observed, primary, companions = self._observe_step(kind, expected)
            _checkpoint_operation_deadline_if_scoped_v2()
            if observed != "EXACT":
                raise ActivationPreparationAmbiguousV2(
                    f"completed preparation step diverged: {kind}"
                )
            if primary.to_document() != step["observedPhysical"]:
                raise ActivationPreparationAmbiguousV2(
                    f"physical identity changed after completion: {kind}"
                )
            if [item.to_document() for item in companions] != step[
                "observedCompanions"
            ]:
                raise ActivationPreparationAmbiguousV2(
                    f"physical companion changed after completion: {kind}"
                )
            return journal
        if state == "PLANNED":
            _checkpoint_operation_deadline_if_scoped_v2()
            observed, _, _ = self._observe_step(kind, expected)
            _checkpoint_operation_deadline_if_scoped_v2()
            if observed != "ABSENT":
                raise ActivationPreparationAmbiguousV2(
                    f"unjournaled preparation target exists: {kind}"
                )
            journal = self._replace_step(
                journal,
                ordinal,
                state="INTENT_DURABLE",
                intent_at=_timestamp(self._clock()),
            )
            step = journal["steps"][ordinal - 1]
        elif state != "INTENT_DURABLE":
            _integrity(f"unknown preparation step state: {state}")

        self._inject(
            ActivationPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT,
            kind,
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        observed, primary, companions = self._observe_step(kind, expected)
        _checkpoint_operation_deadline_if_scoped_v2()
        if observed == "ABSENT":
            self._apply_step(kind)
            _checkpoint_operation_deadline_if_scoped_v2()
            self._inject(
                ActivationPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE,
                kind,
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            observed, primary, companions = self._observe_step(kind, expected)
            _checkpoint_operation_deadline_if_scoped_v2()
        if observed != "EXACT" or primary is None:
            raise ActivationPreparationAmbiguousV2(
                f"preparation effect produced a third state: {kind}"
            )
        if kind == "prepared_manifest_file":
            before_sync = primary
            _checkpoint_operation_deadline_if_scoped_v2()
            _fsync_regular_file(expected.path)
            _fsync_directory(expected.path.parent)
            _checkpoint_operation_deadline_if_scoped_v2()
            observed, primary, companions = self._observe_step(kind, expected)
            if observed != "EXACT" or primary != before_sync:
                raise ActivationPreparationAmbiguousV2(
                    "prepared manifest changed while proving durability"
                )
        _checkpoint_operation_deadline_if_scoped_v2()
        return self._replace_step(
            journal,
            ordinal,
            state="COMPLETED",
            completed_at=_timestamp(self._clock()),
            observed_physical=primary,
            observed_companions=companions,
        )

    def _observe_step(
        self,
        kind: str,
        expected: LogicalPreparationObjectV2,
    ) -> tuple[str, ProjectionV2 | None, tuple[ProjectionV2, ...]]:
        if kind == "activation_tree":
            state = _logical_state(expected)
            if state != "EXACT":
                return state, None, ()
            activation_file_state = _logical_state(
                self.definition.activation_file_logical
            )
            if activation_file_state != "EXACT":
                return "OTHER", None, ()
            tree = capture_tree_projection_v2(
                expected.path,
                schema_sha256=self.definition.snapshot_file.schema_sha256,
            )
            activation_file = capture_file_projection_v2(
                self.definition.activation_file_logical.path,
                schema_sha256=self.definition.snapshot_file.schema_sha256,
            )
            return "EXACT", tree, (activation_file,)
        if kind == "database_empty_file":
            state = _logical_state(expected)
            if state != "EXACT":
                return state, None, ()
            file_projection = capture_file_projection_v2(
                expected.path,
                schema_sha256=self.definition.snapshot_file.schema_sha256,
            )
            return "EXACT", file_projection, ()
        if kind == "prepared_manifest_file":
            state = _logical_state(expected)
            if state != "EXACT":
                return state, None, ()
            file_projection = capture_file_projection_v2(
                expected.path,
                schema_sha256=self.definition.snapshot_file.schema_sha256,
            )
            parent_projection = capture_directory_binding_v2(
                expected.path.parent,
                schema_sha256=self.definition.snapshot_file.schema_sha256,
            )
            return "EXACT", file_projection, (parent_projection,)
        _integrity(f"unknown preparation step kind: {kind}")

    def _apply_step(self, kind: str) -> None:
        if kind == "activation_tree":
            self.callbacks.materialize_activation_tree(
                self.definition.activation_intent
            )
            _fsync_tree(self.definition.activation_intent.activation_dir)
            _fsync_directory(self.definition.activation_intent.activation_dir.parent)
            return
        if kind == "database_empty_file":
            _create_empty_private_file(self.definition.activation_intent.database_path)
            return
        if kind == "prepared_manifest_file":
            callback = self.callbacks.materialize_prepared_manifest
            expected = self.definition.prepared_manifest_logical
            if callback is None or expected is None:
                _integrity("prepared manifest callback is missing")
            callback(self.definition.activation_intent, expected)
            _fsync_regular_file(expected.path)
            _fsync_directory(expected.path.parent)
            return
        _integrity(f"unknown preparation step kind: {kind}")

    def _replace_step(
        self,
        journal: JsonObject,
        ordinal: int,
        *,
        state: str,
        intent_at: str | None = None,
        completed_at: str | None = None,
        observed_physical: ProjectionV2 | None = None,
        observed_companions: Sequence[ProjectionV2] = (),
    ) -> JsonObject:
        if journal["phase"] != "PREPARING":
            raise ActivationPreparationConflictV2(
                "frozen preparation journal is immutable"
            )
        updated = copy.deepcopy(journal)
        previous_fingerprint = str(journal["journalFingerprint"])
        step = updated["steps"][ordinal - 1]
        step["state"] = state
        if intent_at is not None:
            step["intentAt"] = intent_at
        if completed_at is not None:
            step["completedAt"] = completed_at
        if observed_physical is not None:
            step["observedPhysical"] = observed_physical.to_document()
            step["observedCompanions"] = [
                item.to_document() for item in observed_companions
            ]
        step["stepFingerprint"] = _step_fingerprint(step)
        updated["contentGeneration"] += 1
        updated["updatedAt"] = _timestamp(self._clock())
        updated.pop("journalFingerprint")
        updated = _with_journal_fingerprint(updated)
        _validate_journal_document(updated, self.definition)
        _checkpoint_operation_deadline_if_scoped_v2()
        _atomic_replace_private_json(
            self.definition.journal_path,
            updated,
            expected_fingerprint=previous_fingerprint,
        )
        return updated

    def _freeze(
        self,
        journal: JsonObject,
        desired: StateBundleV2,
    ) -> JsonObject:
        if any(step["state"] != "COMPLETED" for step in journal["steps"]):
            raise ActivationPreparationConflictV2(
                "preparation cannot freeze before all steps complete"
            )
        previous_fingerprint = str(journal["journalFingerprint"])
        updated = copy.deepcopy(journal)
        updated.pop("journalFingerprint")
        now = _timestamp(self._clock())
        updated["phase"] = "PREPARATION_FROZEN"
        updated["contentGeneration"] += 1
        updated["updatedAt"] = now
        updated["frozenAt"] = now
        updated["desired"] = desired.to_document()
        updated["frozenJournalFingerprint"] = None
        frozen_projection = copy.deepcopy(updated)
        updated["frozenJournalFingerprint"] = domain_fingerprint(
            _FROZEN_JOURNAL_DOMAIN, frozen_projection
        )
        updated = _with_journal_fingerprint(updated)
        _validate_journal_document(updated, self.definition)
        _checkpoint_operation_deadline_if_scoped_v2()
        _atomic_replace_private_json(
            self.definition.journal_path,
            updated,
            expected_fingerprint=previous_fingerprint,
        )
        return updated

    def _receipt_from_frozen(
        self, journal: JsonObject
    ) -> ActivationPreparationReceiptV2:
        if journal["phase"] != "PREPARATION_FROZEN":
            raise ActivationPreparationConflictV2(
                "receipt requires the exact frozen preparation journal"
            )
        activation_step, database_step = journal["steps"][:2]
        activation_tree = ProjectionV2.from_document(
            activation_step["observedPhysical"]
        )
        companions = activation_step["observedCompanions"]
        if type(companions) is not list or len(companions) != 1:
            _integrity("activation tree companion projection is missing")
        activation_file = ProjectionV2.from_document(companions[0])
        database_file = ProjectionV2.from_document(database_step["observedPhysical"])
        binding = _database_binding_target(
            database_file,
            self.definition.activation_intent,
        )
        desired = _verify_state_bundle_document(_object(journal["desired"], "desired"))
        prepared = self._prepared_from_completed_journal(journal)
        _validate_full_desired(
            desired,
            prepared,
            seed=self.definition.desired_seed,
        )
        return ActivationPreparationReceiptV2(
            installation_id=self.definition.activation_intent.installation_id,
            operation_id=self.definition.activation_intent.operation_id,
            activation_intent=self.definition.activation_intent,
            snapshot_file=self.definition.snapshot_file,
            activation_tree=activation_tree,
            activation_file=activation_file,
            database_empty_file=database_file,
            database_binding_target=binding,
            desired=desired,
            frozen_journal_fingerprint=str(journal["frozenJournalFingerprint"]),
            completed_at=_parse_timestamp(journal["frozenAt"], "frozenAt"),
            prepared_manifest_file=prepared.prepared_manifest_file,
            prepared_manifest_parent=prepared.prepared_manifest_parent,
            transition_proof_snapshot=(self.definition.transition_proof_snapshot),
        )

    def _prepared_from_completed_journal(
        self,
        journal: Mapping[str, Any],
    ) -> PreparedActivationObjectsV2:
        activation_step, database_step = journal["steps"][:2]
        if (
            activation_step["state"] != "COMPLETED"
            or database_step["state"] != "COMPLETED"
        ):
            raise ActivationPreparationConflictV2(
                "prepared objects require both completed steps"
            )
        activation_tree = ProjectionV2.from_document(
            activation_step["observedPhysical"]
        )
        companions = activation_step["observedCompanions"]
        if type(companions) is not list or len(companions) != 1:
            _integrity("activation file physical projection is missing")
        activation_file = ProjectionV2.from_document(companions[0])
        database_file = ProjectionV2.from_document(database_step["observedPhysical"])
        binding = _database_binding_target(
            database_file,
            self.definition.activation_intent,
        )
        activation = _activation_projection(
            activation_tree=activation_tree,
            activation_file=activation_file,
            database_binding_target=binding,
            intent=self.definition.activation_intent,
        )
        prepared_manifest_file = None
        prepared_manifest_parent = None
        if self.definition.prepared_manifest_logical is not None:
            manifest_step = journal["steps"][2]
            if manifest_step["state"] != "COMPLETED":
                raise ActivationPreparationConflictV2(
                    "prepared manifest step is incomplete"
                )
            prepared_manifest_file = ProjectionV2.from_document(
                manifest_step["observedPhysical"]
            )
            manifest_companions = manifest_step["observedCompanions"]
            if type(manifest_companions) is not list or len(manifest_companions) != 1:
                _integrity("prepared manifest parent projection is missing")
            prepared_manifest_parent = ProjectionV2.from_document(
                manifest_companions[0]
            )
        return PreparedActivationObjectsV2(
            snapshot_file=self.definition.snapshot_file,
            activation_tree=activation_tree,
            activation_file=activation_file,
            database_empty_file=database_file,
            database_binding_target=binding,
            activation=activation,
            prepared_manifest_file=prepared_manifest_file,
            prepared_manifest_parent=prepared_manifest_parent,
        )

    def _read_journal(self) -> JsonObject:
        journal = _read_canonical_private_json(
            self.definition.journal_path, "preparation journal"
        )
        _validate_journal_document(journal, self.definition)
        return journal

    def _verify_receipt_matches_definition(
        self, receipt: ActivationPreparationReceiptV2
    ) -> None:
        if receipt.activation_intent != self.definition.activation_intent:
            raise ActivationPreparationConflictV2(
                "receipt activationIntent differs from requested definition"
            )
        _validate_full_desired(
            receipt.desired,
            receipt.prepared,
            seed=self.definition.desired_seed,
        )
        if (self.definition.prepared_manifest_logical is None) != (
            receipt.prepared_manifest_file is None
        ):
            raise ActivationPreparationConflictV2(
                "receipt prepared manifest differs from requested definition"
            )
        if receipt.snapshot_file != self.definition.snapshot_file:
            raise ActivationPreparationConflictV2(
                "receipt snapshot differs from requested definition"
            )
        if (
            receipt.transition_proof_snapshot
            != self.definition.transition_proof_snapshot
        ):
            raise ActivationPreparationConflictV2(
                "receipt transition proof snapshot differs from definition"
            )

    def _verify_live_receipt(
        self,
        receipt: ActivationPreparationReceiptV2,
        *,
        database_may_be_initialized: bool = False,
    ) -> None:
        self._verify_snapshot_file()
        expected = (
            (receipt.activation_tree, capture_tree_projection_v2),
            (receipt.activation_file, capture_file_projection_v2),
        )
        if not database_may_be_initialized:
            expected = expected + (
                (receipt.database_empty_file, capture_file_projection_v2),
            )
        if self.definition.prepared_manifest_logical is not None:
            expected = expected + (
                (
                    receipt.prepared_manifest_file,
                    capture_file_projection_v2,
                ),
            )
        for projection, capture in expected:
            path = Path(str(projection.value["path"]))
            try:
                observed = capture(path, schema_sha256=projection.schema_sha256)
            except (OSError, ActivationPreparationV2Error) as exc:
                raise ActivationPreparationAmbiguousV2(
                    f"receipt target cannot be proven: {path}: {exc}"
                ) from exc
            if observed != projection:
                raise ActivationPreparationAmbiguousV2(
                    f"receipt target physical identity changed: {path}"
                )
        if database_may_be_initialized:
            expected_database = receipt.database_empty_file.value
            database_path = Path(str(expected_database["path"]))
            try:
                observed_database = capture_file_projection_v2(
                    database_path,
                    schema_sha256=receipt.database_empty_file.schema_sha256,
                ).value
            except (OSError, ActivationPreparationV2Error) as exc:
                raise ActivationPreparationAmbiguousV2(
                    "initialized receipt database cannot be proven"
                ) from exc
            stable_fields = (
                "path",
                "device",
                "inode",
                "ownerUid",
                "ownerGid",
                "mode",
                "linkCount",
            )
            if (
                any(
                    observed_database.get(name) != expected_database.get(name)
                    for name in stable_fields
                )
                or observed_database.get("size", 0) <= 0
            ):
                raise ActivationPreparationAmbiguousV2(
                    "initialized receipt database changed physical identity"
                )
        if receipt.prepared_manifest_parent is not None:
            parent_path = Path(str(receipt.prepared_manifest_parent.value["path"]))
            observed_parent = capture_directory_binding_v2(
                parent_path,
                schema_sha256=receipt.prepared_manifest_parent.schema_sha256,
            )
            if observed_parent != receipt.prepared_manifest_parent:
                raise ActivationPreparationAmbiguousV2(
                    "prepared manifest parent identity changed"
                )

    def _verify_snapshot_file(self) -> None:
        try:
            observed = capture_file_projection_v2(
                self.definition.activation_intent.snapshot_path,
                schema_sha256=self.definition.snapshot_file.schema_sha256,
            )
        except (OSError, ActivationPreparationV2Error) as exc:
            raise ActivationPreparationAmbiguousV2(
                f"attested snapshot cannot be proven: {exc}"
            ) from exc
        if observed != self.definition.snapshot_file:
            raise ActivationPreparationAmbiguousV2(
                "attested snapshot changed before or during preparation"
            )

    def _require_unprepared_targets_absent(self) -> None:
        for path in (
            self.definition.activation_intent.activation_dir,
            self.definition.activation_intent.database_path,
            *(
                ()
                if self.definition.prepared_manifest_logical is None
                else (self.definition.prepared_manifest_logical.path,)
            ),
        ):
            if _lexists(path):
                raise ActivationPreparationAmbiguousV2(
                    f"target exists without preparation journal or receipt: {path}"
                )

    def _delete_exact_journal(
        self,
        journal: JsonObject,
        *,
        required_phase: str = "PREPARATION_FROZEN",
    ) -> None:
        _checkpoint_operation_deadline_if_scoped_v2()
        current = self._read_journal()
        if (
            current["journalFingerprint"] != journal["journalFingerprint"]
            or current["phase"] != required_phase
        ):
            raise ActivationPreparationConflictV2(
                "only the exact preparation journal in the required phase may be deleted"
            )
        descriptor = os.open(
            self.definition.journal_path,
            os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
        )
        try:
            opened = os.fstat(descriptor)
            named = self.definition.journal_path.lstat()
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise ActivationPreparationConflictV2(
                    "preparation journal identity changed before unlink"
                )
            _checkpoint_operation_deadline_if_scoped_v2()
            os.unlink(self.definition.journal_path)
            _fsync_directory(self.definition.journal_path.parent)
            if _lexists(self.definition.journal_path):
                raise ActivationPreparationConflictV2(
                    "preparation journal reappeared after unlink"
                )
        finally:
            os.close(descriptor)

    def _inject(
        self,
        point: ActivationPreparationFailurePointV2,
        step_kind: str | None,
    ) -> None:
        if self._failure_injector is not None:
            self._failure_injector(point, step_kind)


def prepared_receipt_to_staged_activation_v2(
    receipt: ActivationPreparationReceiptV2 | Mapping[str, Any],
):
    """Восстанавливает ``StagedActivationV2`` только из квитанции."""

    if not isinstance(receipt, ActivationPreparationReceiptV2):
        receipt = ActivationPreparationReceiptV2.from_document(receipt)
    from .activation_materializer_v2 import StagedActivationV2

    intent = receipt.activation_intent
    return StagedActivationV2(
        status="IDENTITY_STAGED",
        readiness="AWAITING_CONTROLLER_BIND",
        source_root=intent.source_root,
        codex_home=intent.codex_home,
        codex_binary=intent.codex_binary,
        state_home=intent.state_home,
        socket_path=intent.socket_path,
        controller_lock_path=intent.controller_lock_path,
        installation_id=intent.installation_id,
        operation_id=intent.operation_id,
        database_id=intent.database_id,
        activation_binding_nonce=intent.activation_binding_nonce,
        activation_id=intent.activation_id,
        activation_fingerprint=intent.activation_fingerprint,
        controller_identity=intent.controller_identity,
        compatibility_fingerprint=intent.compatibility_fingerprint,
        routing_policy_fingerprint=intent.routing_policy_fingerprint,
        bundled_catalog_fingerprint=intent.bundled_catalog_fingerprint,
        schema_fingerprint=intent.schema_fingerprint,
        schema_artifact_sha256=intent.schema_artifact_sha256,
        activation_dir=intent.activation_dir,
        snapshot_path=intent.snapshot_path,
        database_path=intent.database_path,
        bundled_catalog_path=intent.bundled_catalog_path,
        identity=copy.deepcopy(dict(intent.identity)),
        activation_document=copy.deepcopy(dict(intent.activation_document)),
        source_locator=copy.deepcopy(dict(intent.source_locator)),
        snapshot_locator=copy.deepcopy(dict(intent.snapshot_locator)),
        bundled_catalog=copy.deepcopy(dict(intent.bundled_catalog)),
        interface_evidence=copy.deepcopy(dict(intent.interface_evidence)),
        completed_at=intent.completed_at,
    )


def capture_file_projection_v2(path: Path, *, schema_sha256: str) -> ProjectionV2:
    """Фиксирует точную физическую проекцию частного обычного файла."""

    _absolute_path(path, "file projection path")
    _sha256(schema_sha256, "schema_sha256")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
    ):
        _integrity(f"unsafe regular file: {path}")
    value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": _hash_file(path),
    }
    return _projection(
        "file-object-v2",
        schema_sha256,
        value,
        _FILE_PROJECTION_DOMAIN,
    )


def capture_tree_projection_v2(path: Path, *, schema_sha256: str) -> ProjectionV2:
    """Фиксирует точную физическую проекцию частного дерева."""

    _absolute_path(path, "tree projection path")
    _sha256(schema_sha256, "schema_sha256")
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
    ):
        _integrity(f"unsafe directory: {path}")
    value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "entryCount": sum(1 for item in path.rglob("*") if not item.is_symlink()),
        "treeSha256": tree_content_sha256_v2(path),
    }
    return _projection(
        "tree-object-v2",
        schema_sha256,
        value,
        _TREE_PROJECTION_DOMAIN,
    )


def capture_directory_binding_v2(path: Path, *, schema_sha256: str) -> ProjectionV2:
    """Фиксирует неизменяемую identity каталога без привязки к содержимому."""

    _absolute_path(path, "directory binding path")
    _sha256(schema_sha256, "schema_sha256")
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _integrity(f"unsafe private directory: {path}")
    value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
    }
    return _projection(
        "directory-binding-v2",
        schema_sha256,
        value,
        _DIRECTORY_BINDING_DOMAIN,
    )


def tree_content_sha256_v2(root: Path) -> str:
    """Возвращает переносимый хеш содержимого дерева без inode корня."""

    _absolute_path(root, "tree root")
    root_info = root.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != os.getuid()
        or stat.S_IMODE(root_info.st_mode) not in {0o500, 0o700}
    ):
        _integrity(f"tree root is not a private directory: {root}")
    root_mode = stat.S_IMODE(root_info.st_mode)
    entries: list[JsonObject] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        children = sorted(
            directory.iterdir(),
            key=lambda path: path.name.encode("utf-8"),
            reverse=True,
        )
        for child in children:
            info = child.lstat()
            relative = child.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "symlink",
                        "mode": stat.S_IMODE(info.st_mode),
                        "target": os.readlink(child),
                    }
                )
            elif stat.S_ISDIR(info.st_mode):
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != root_mode:
                    _integrity(f"tree directory is not private: {child}")
                entries.append(
                    {
                        "path": relative,
                        "type": "directory",
                        "mode": stat.S_IMODE(info.st_mode),
                    }
                )
                pending.append(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_uid != os.getuid() or info.st_nlink != 1:
                    _integrity(f"tree file is unsafe: {child}")
                if root_mode == 0o500 and stat.S_IMODE(info.st_mode) not in {
                    0o400,
                    0o500,
                }:
                    _integrity(f"sealed tree file remains writable: {child}")
                entries.append(
                    {
                        "path": relative,
                        "type": "regular",
                        "mode": stat.S_IMODE(info.st_mode),
                        "size": info.st_size,
                        "sha256": _hash_file(child),
                    }
                )
            else:
                _integrity(f"unsupported object in activation tree: {child}")
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def _new_step_document(
    *,
    operation_id: str,
    ordinal: int,
    kind: str,
    expected: LogicalPreparationObjectV2,
) -> JsonObject:
    step_id = (
        "pst2_"
        + domain_fingerprint(
            _STEP_ID_DOMAIN,
            {"operationId": operation_id, "ordinal": ordinal, "kind": kind},
        )[:32]
    )
    step = {
        "stepId": step_id,
        "ordinal": ordinal,
        "kind": kind,
        "state": "PLANNED",
        "expectedLogical": expected.to_document(),
        "observedPhysical": None,
        "observedCompanions": [],
        "intentAt": None,
        "completedAt": None,
    }
    step["stepFingerprint"] = _step_fingerprint(step)
    return step


def _step_fingerprint(step: Mapping[str, Any]) -> str:
    projection = {
        key: copy.deepcopy(value)
        for key, value in step.items()
        if key != "stepFingerprint"
    }
    return domain_fingerprint(_STEP_DOMAIN, projection)


def _with_journal_fingerprint(document: Mapping[str, Any]) -> JsonObject:
    result = copy.deepcopy(dict(document))
    result["journalFingerprint"] = domain_fingerprint(_JOURNAL_DOMAIN, result)
    return result


def _validate_journal_document(
    document: Mapping[str, Any], definition: ActivationPreparationDefinitionV2
) -> None:
    _exact_keys(
        document,
        {
            "schemaVersion",
            "journalKind",
            "installationId",
            "operationId",
            "phase",
            "definitionFingerprint",
            "definition",
            "intentBoundary",
            "steps",
            "contentGeneration",
            "createdAt",
            "updatedAt",
            "frozenAt",
            "frozenJournalFingerprint",
            "desired",
            "journalFingerprint",
        },
        "preparation journal",
    )
    if (
        document["schemaVersion"] != 2
        or document["journalKind"] != "activation-preparation"
    ):
        _integrity("preparation journal header is invalid")
    if document["installationId"] != definition.activation_intent.installation_id:
        _integrity("preparation journal installationId differs")
    if document["operationId"] != definition.activation_intent.operation_id:
        _integrity("preparation journal operationId differs")
    if document["definitionFingerprint"] != definition.definition_fingerprint:
        _integrity("preparation definition fingerprint differs")
    if document["definition"] != definition.to_document():
        _integrity("persisted preparation definition differs")
    boundary = _object(document["intentBoundary"], "intentBoundary")
    _exact_keys(
        boundary,
        {
            "kind",
            "state",
            "activationIntentFingerprint",
            "desiredSeedFingerprint",
            "completedAt",
        },
        "intentBoundary",
    )
    if (
        boundary["kind"] != "preparation_intent"
        or boundary["state"] != "COMPLETED"
        or boundary["activationIntentFingerprint"]
        != definition.activation_intent.intent_fingerprint
        or boundary["desiredSeedFingerprint"]
        != definition.desired_seed.to_document()["bundleFingerprint"]
    ):
        _integrity("preparation intent boundary differs")
    _parse_timestamp(boundary["completedAt"], "intentBoundary.completedAt")
    steps = document["steps"]
    expected_steps: tuple[tuple[int, str, LogicalPreparationObjectV2], ...] = (
        (1, "activation_tree", definition.activation_tree_logical),
        (2, "database_empty_file", definition.database_empty_file_logical),
    )
    if definition.prepared_manifest_logical is not None:
        expected_steps = expected_steps + (
            (3, "prepared_manifest_file", definition.prepared_manifest_logical),
        )
    if type(steps) is not list or len(steps) != len(expected_steps):
        _integrity("preparation journal contains an unexpected step count")
    completed_seen = True
    for step, (ordinal, kind, expected) in zip(steps, expected_steps, strict=True):
        _validate_step_document(
            step,
            ordinal,
            kind,
            expected,
            operation_id=definition.activation_intent.operation_id,
        )
        if step["state"] != "COMPLETED":
            completed_seen = False
        elif not completed_seen:
            _integrity("preparation steps completed out of order")
    phase = document["phase"]
    if phase not in {"PREPARING", "PREPARATION_FROZEN"}:
        _integrity("preparation journal phase is invalid")
    if (
        type(document["contentGeneration"]) is not int
        or document["contentGeneration"] < 0
    ):
        _integrity("contentGeneration is invalid")
    _parse_timestamp(document["createdAt"], "createdAt")
    _parse_timestamp(document["updatedAt"], "updatedAt")
    journal_projection = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key != "journalFingerprint"
    }
    if document["journalFingerprint"] != domain_fingerprint(
        _JOURNAL_DOMAIN, journal_projection
    ):
        _integrity("journalFingerprint mismatch")
    if phase == "PREPARING":
        if (
            document["frozenAt"] is not None
            or document["frozenJournalFingerprint"] is not None
            or document["desired"] is not None
        ):
            _integrity("preparing journal contains frozen fields")
    else:
        if any(step["state"] != "COMPLETED" for step in steps):
            _integrity("frozen journal contains incomplete steps")
        _parse_timestamp(document["frozenAt"], "frozenAt")
        frozen = document["frozenJournalFingerprint"]
        _sha256(frozen, "frozenJournalFingerprint")
        frozen_projection = copy.deepcopy(journal_projection)
        frozen_projection["frozenJournalFingerprint"] = None
        if frozen != domain_fingerprint(_FROZEN_JOURNAL_DOMAIN, frozen_projection):
            _integrity("frozenJournalFingerprint mismatch")
        desired = _verify_state_bundle_document(_object(document["desired"], "desired"))
        prepared = _prepared_from_journal_document(document, definition)
        _validate_full_desired(
            desired,
            prepared,
            seed=definition.desired_seed,
        )


def _validate_step_document(
    step: Mapping[str, Any],
    ordinal: int,
    kind: str,
    expected: LogicalPreparationObjectV2,
    *,
    operation_id: str,
) -> None:
    _exact_keys(
        step,
        {
            "stepId",
            "ordinal",
            "kind",
            "state",
            "expectedLogical",
            "observedPhysical",
            "observedCompanions",
            "intentAt",
            "completedAt",
            "stepFingerprint",
        },
        "preparation step",
    )
    expected_id = (
        "pst2_"
        + domain_fingerprint(
            _STEP_ID_DOMAIN,
            {
                "operationId": operation_id,
                "ordinal": ordinal,
                "kind": kind,
            },
        )[:32]
    )
    if step["ordinal"] != ordinal or step["kind"] != kind:
        _integrity("preparation step order or kind differs")
    if step["stepId"] != expected_id:
        _integrity("preparation stepId differs from operationId, ordinal and kind")
    if LogicalPreparationObjectV2.from_document(step["expectedLogical"]) != expected:
        _integrity("preparation expectedLogical differs")
    if step["stepFingerprint"] != _step_fingerprint(step):
        _integrity("preparation stepFingerprint mismatch")
    state = step["state"]
    if state == "PLANNED":
        if any(
            step[name] is not None
            for name in ("intentAt", "completedAt", "observedPhysical")
        ):
            _integrity("planned preparation step contains effect state")
        if step["observedCompanions"] != []:
            _integrity("planned preparation step contains companions")
    elif state == "INTENT_DURABLE":
        _parse_timestamp(step["intentAt"], "step.intentAt")
        if step["completedAt"] is not None or step["observedPhysical"] is not None:
            _integrity("intent preparation step contains completion state")
        if step["observedCompanions"] != []:
            _integrity("intent preparation step contains companions")
    elif state == "COMPLETED":
        _parse_timestamp(step["intentAt"], "step.intentAt")
        _parse_timestamp(step["completedAt"], "step.completedAt")
        projection = ProjectionV2.from_document(step["observedPhysical"])
        if kind == "activation_tree":
            _verify_projection(
                projection, schema_id="tree-object-v2", domain=_TREE_PROJECTION_DOMAIN
            )
            companions = step["observedCompanions"]
            if type(companions) is not list or len(companions) != 1:
                _integrity("activation tree must contain one physical companion")
            companion = ProjectionV2.from_document(companions[0])
            _verify_projection(
                companion, schema_id="file-object-v2", domain=_FILE_PROJECTION_DOMAIN
            )
        elif kind == "database_empty_file":
            _verify_projection(
                projection, schema_id="file-object-v2", domain=_FILE_PROJECTION_DOMAIN
            )
            if step["observedCompanions"] != []:
                _integrity("database step cannot contain companions")
        elif kind == "prepared_manifest_file":
            _verify_projection(
                projection,
                schema_id="file-object-v2",
                domain=_FILE_PROJECTION_DOMAIN,
            )
            companions = step["observedCompanions"]
            if type(companions) is not list or len(companions) != 1:
                _integrity("prepared manifest must bind its parent directory")
            companion = ProjectionV2.from_document(companions[0])
            _verify_projection(
                companion,
                schema_id="directory-binding-v2",
                domain=_DIRECTORY_BINDING_DOMAIN,
            )
        else:
            _integrity("unknown completed preparation step kind")
    else:
        _integrity("preparation step state is invalid")


def _prepared_from_journal_document(
    journal: Mapping[str, Any],
    definition: ActivationPreparationDefinitionV2,
) -> PreparedActivationObjectsV2:
    steps = journal["steps"]
    activation_step, database_step = steps[:2]
    activation_tree = ProjectionV2.from_document(
        _object(activation_step["observedPhysical"], "activation observedPhysical")
    )
    companions = activation_step["observedCompanions"]
    if type(companions) is not list or len(companions) != 1:
        _integrity("activation file physical projection is missing")
    activation_file = ProjectionV2.from_document(
        _object(companions[0], "activation observed companion")
    )
    database_file = ProjectionV2.from_document(
        _object(database_step["observedPhysical"], "database observedPhysical")
    )
    binding = _database_binding_target(
        database_file,
        definition.activation_intent,
    )
    activation = _activation_projection(
        activation_tree=activation_tree,
        activation_file=activation_file,
        database_binding_target=binding,
        intent=definition.activation_intent,
    )
    prepared_manifest_file = None
    prepared_manifest_parent = None
    if definition.prepared_manifest_logical is not None:
        prepared_manifest_file = ProjectionV2.from_document(
            _object(
                steps[2]["observedPhysical"],
                "prepared manifest observedPhysical",
            )
        )
        manifest_companions = steps[2]["observedCompanions"]
        if type(manifest_companions) is not list or len(manifest_companions) != 1:
            _integrity("prepared manifest parent projection is missing")
        prepared_manifest_parent = ProjectionV2.from_document(
            _object(
                manifest_companions[0],
                "prepared manifest parent companion",
            )
        )
    return PreparedActivationObjectsV2(
        snapshot_file=definition.snapshot_file,
        activation_tree=activation_tree,
        activation_file=activation_file,
        database_empty_file=database_file,
        database_binding_target=binding,
        activation=activation,
        prepared_manifest_file=prepared_manifest_file,
        prepared_manifest_parent=prepared_manifest_parent,
    )


def _prepared_manifest_from_desired(
    desired: StateBundleV2,
    definition: ActivationPreparationDefinitionV2,
) -> ProjectionV2:
    logical = definition.prepared_manifest_logical
    if logical is None:
        _integrity("prepared manifest logical expectation is absent")
    matches = tuple(
        item
        for item in desired.file_objects
        if item.value.get("path") == str(logical.path)
    )
    if len(matches) != 1:
        _integrity("desired does not contain one prepared manifest file")
    projection = matches[0]
    _verify_projection(
        projection,
        schema_id="file-object-v2",
        domain=_FILE_PROJECTION_DOMAIN,
    )
    if (
        projection.value.get("mode") != logical.mode
        or projection.value.get("sha256") != logical.content_sha256
    ):
        _integrity("prepared manifest projection differs from logical expectation")
    return projection


def _prepared_with_manifest_from_desired(
    prepared: PreparedActivationObjectsV2,
    desired: StateBundleV2,
    definition: ActivationPreparationDefinitionV2,
) -> PreparedActivationObjectsV2:
    if definition.prepared_manifest_logical is None:
        return prepared
    return PreparedActivationObjectsV2(
        snapshot_file=prepared.snapshot_file,
        activation_tree=prepared.activation_tree,
        activation_file=prepared.activation_file,
        database_empty_file=prepared.database_empty_file,
        database_binding_target=prepared.database_binding_target,
        activation=prepared.activation,
        prepared_manifest_file=_prepared_manifest_from_desired(
            desired,
            definition,
        ),
    )


def _activation_projection(
    *,
    activation_tree: ProjectionV2,
    activation_file: ProjectionV2,
    database_binding_target: ProjectionV2,
    intent: ActivationPreparationIntentV2,
) -> ProjectionV2:
    identity = intent.identity
    database_identity = {
        "databaseId": intent.database_id,
        "activationBindingNonce": intent.activation_binding_nonce,
        "activationId": intent.activation_id,
        "activationFingerprint": intent.activation_fingerprint,
    }
    value = {
        "directory": copy.deepcopy(dict(activation_tree.value)),
        "activationFile": copy.deepcopy(dict(activation_file.value)),
        "activationId": intent.activation_id,
        "activationFingerprint": intent.activation_fingerprint,
        "generationId": _string(identity.get("generationId"), "generationId"),
        "release": _string(identity.get("release"), "release"),
        "databaseId": intent.database_id,
        "databaseIdentityFingerprint": domain_fingerprint(
            "codex-smart/database-identity/v2", database_identity
        ),
        "marketplaceTreeSha256": _sha256(
            identity.get("marketplaceTreeSha256"), "marketplaceTreeSha256"
        ),
        "generationTreeSha256": _sha256(
            identity.get("generationTreeSha256"), "generationTreeSha256"
        ),
    }
    if (
        database_binding_target.value.get("databaseId") != intent.database_id
        or database_binding_target.value.get("activationId") != intent.activation_id
    ):
        _integrity("activation projection database target differs")
    return _projection(
        "activation-v2",
        activation_tree.schema_sha256,
        value,
        _ACTIVATION_PROJECTION_DOMAIN,
    )


def _validate_full_desired(
    desired: StateBundleV2,
    prepared: PreparedActivationObjectsV2,
    *,
    seed: StateBundleV2 | None,
) -> None:
    _verify_state_bundle_document(desired.to_document())
    if prepared.snapshot_file not in desired.file_objects:
        _integrity("full desired omits the attested snapshotFile")
    if desired.activation != prepared.activation:
        _integrity("full desired omits the exact activation-v2 projection")
    if desired.database != prepared.database_binding_target:
        _integrity("full desired omits the exact databaseBindingTarget")
    if (
        prepared.prepared_manifest_file is not None
        and prepared.prepared_manifest_file not in desired.file_objects
    ):
        _integrity("full desired omits the exact prepared manifest file")
    if seed is None:
        return
    array_fields = (
        "file_objects",
        "tree_objects",
        "symlinks",
        "controller_candidates",
        "watchdogs",
        "external_commands",
        "receipts",
        "absence_proofs",
    )
    for field_name in array_fields:
        full_items = getattr(desired, field_name)
        for item in getattr(seed, field_name):
            if item not in full_items:
                _integrity(f"full desired drops desired seed field: {field_name}")
    nullable_fields = (
        "manifest",
        "activation",
        "database",
        "controller",
        "registry",
        "launchers",
        "legacy_processes",
        "quiescence",
    )
    for field_name in nullable_fields:
        seed_value = getattr(seed, field_name)
        if seed_value is not None and getattr(desired, field_name) != seed_value:
            _integrity(f"full desired changes desired seed field: {field_name}")


def _database_binding_target(
    database_file: ProjectionV2,
    intent: ActivationPreparationIntentV2,
) -> ProjectionV2:
    file_value = database_file.value
    value = {
        "path": file_value["path"],
        "device": file_value["device"],
        "inode": file_value["inode"],
        "ownerUid": file_value["ownerUid"],
        "ownerGid": file_value["ownerGid"],
        "mode": file_value["mode"],
        "linkCount": file_value["linkCount"],
        "databaseId": intent.database_id,
        "activationBindingNonce": intent.activation_binding_nonce,
        "activationId": intent.activation_id,
        "activationFingerprint": intent.activation_fingerprint,
        "schemaFingerprint": intent.schema_fingerprint,
        "schemaArtifactSha256": intent.schema_artifact_sha256,
    }
    return _projection(
        "database-binding-target-v2",
        database_file.schema_sha256,
        value,
        _DATABASE_TARGET_DOMAIN,
    )


def _projection(
    schema_id: str,
    schema_sha256: str,
    value: Mapping[str, Any],
    domain: str,
) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": schema_sha256,
        "value": copy.deepcopy(dict(value)),
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=schema_sha256,
        value=envelope["value"],
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _verify_projection(
    projection: ProjectionV2,
    *,
    schema_id: str,
    domain: str,
) -> None:
    if not isinstance(projection, ProjectionV2):
        _integrity("projection has invalid type")
    _sha256(projection.schema_sha256, "projection schemaSha256")
    if projection.schema_id != schema_id:
        _integrity(f"projection schemaId differs: expected {schema_id}")
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    if projection.value_fingerprint != domain_fingerprint(domain, envelope):
        _integrity(f"projection valueFingerprint differs: {schema_id}")


def _verify_state_bundle_document(document: Mapping[str, Any]) -> StateBundleV2:
    try:
        bundle = StateBundleV2.from_document(document)
    except Exception as exc:
        raise ActivationPreparationIntegrityErrorV2(
            f"desired StateBundleV2 is invalid: {exc}"
        ) from exc
    if bundle.to_document() != document:
        _integrity("desired StateBundleV2 fingerprint differs")
    return bundle


def _logical_state(expected: LogicalPreparationObjectV2) -> str:
    if not _lexists(expected.path):
        return "ABSENT"
    try:
        info = expected.path.lstat()
        if expected.object_type == "regular-file":
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or f"0{stat.S_IMODE(info.st_mode):03o}" != expected.mode
                or _hash_file(expected.path) != expected.content_sha256
            ):
                return "OTHER"
            return "EXACT"
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or f"0{stat.S_IMODE(info.st_mode):03o}" != expected.mode
            or tree_content_sha256_v2(expected.path) != expected.content_sha256
        ):
            return "OTHER"
        return "EXACT"
    except (OSError, ActivationPreparationV2Error):
        return "OTHER"


def _create_empty_private_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        _sync_file(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _atomic_create_private_json(path: Path, document: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(dict(document))
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}"
    descriptor = -1
    linked = False
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | _flag("O_NOFOLLOW")
            | _flag("O_CLOEXEC"),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        _sync_file(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ActivationPreparationConflictV2(
                f"durable object appeared concurrently: {path}"
            ) from exc
        linked = True
        os.unlink(temporary)
        _fsync_directory(path.parent)
        if _read_private_bytes(path, _MAX_DOCUMENT_BYTES) != payload:
            raise ActivationPreparationConflictV2(
                f"persisted durable object differs: {path}"
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not linked or _lexists(temporary):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _atomic_replace_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    expected_fingerprint: str,
) -> None:
    current = _read_canonical_private_json(path, "preparation journal")
    if current.get("journalFingerprint") != expected_fingerprint:
        raise ActivationPreparationConflictV2(
            "preparation journal changed before replacement"
        )
    payload = canonical_json_bytes(dict(document))
    temporary = path.parent / f".{path.name}.{secrets.token_hex(16)}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | _flag("O_NOFOLLOW")
            | _flag("O_CLOEXEC"),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        _sync_file(descriptor)
        os.close(descriptor)
        descriptor = -1
        _validate_private_regular_file(path)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        if _read_private_bytes(path, _MAX_DOCUMENT_BYTES) != payload:
            raise ActivationPreparationConflictV2(
                "replaced preparation journal differs"
            )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_canonical_private_json(path: Path, label: str) -> JsonObject:
    payload = _read_private_bytes(path, _MAX_DOCUMENT_BYTES)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationPreparationIntegrityErrorV2(
            f"invalid JSON in {label}: {exc}"
        ) from exc
    if type(value) is not dict:
        _integrity(f"{label} root must be an object")
    if canonical_json_bytes(value) != payload:
        _integrity(f"{label} is not canonical-json-v1")
    return value


def _read_private_bytes(path: Path, limit: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
    )
    try:
        _validate_private_regular_descriptor(descriptor, path)
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            _checkpoint_operation_deadline_if_scoped_v2()
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        if len(payload) > limit:
            _integrity(f"durable JSON exceeds {limit} bytes: {path}")
        return payload
    finally:
        os.close(descriptor)


def _ensure_private_lock_file(path: Path) -> None:
    _validate_private_directory(path.parent)
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_RDWR
            | _flag("O_NOFOLLOW")
            | _flag("O_CLOEXEC"),
            0o600,
        )
    except FileExistsError:
        _validate_private_regular_file(path)
        return
    try:
        os.fchmod(descriptor, 0o600)
        _sync_file(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    descriptor = os.open(
        path,
        os.O_RDWR | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
    )
    acquired = False
    try:
        _validate_private_regular_descriptor(descriptor, path)
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=(
                    finite_file_lock_v2.LOCAL_FILE_LOCK_TIMEOUT_SECONDS
                ),
                timeout_code="ACTIVATION_PREPARATION_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as error:
            raise ActivationPreparationLockTimeoutV2(error.code) from error
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_private_directory(path: Path) -> None:
    _absolute_path(path, "private directory")
    try:
        info = path.lstat()
    except OSError as exc:
        raise ActivationPreparationIntegrityErrorV2(
            f"private directory is unavailable: {path}: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _integrity(f"unsafe private directory: {path}")


def _validate_private_regular_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
    )
    try:
        _validate_private_regular_descriptor(descriptor, path)
    finally:
        os.close(descriptor)


def _validate_private_regular_descriptor(descriptor: int, path: Path) -> None:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _integrity(f"unsafe private regular file: {path}")


def _fsync_tree(root: Path) -> None:
    directories: list[Path] = []
    for directory, _, filenames in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for filename in filenames:
            path = current / filename
            if path.is_symlink():
                continue
            descriptor = os.open(
                path,
                os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
            )
            try:
                _sync_file(descriptor)
            finally:
                os.close(descriptor)
        directories.append(current)
    for directory in directories:
        _fsync_directory(directory)


def _fsync_regular_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
    )
    try:
        _validate_private_regular_descriptor(descriptor, path)
        _sync_file(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_DIRECTORY") | _flag("O_NOFOLLOW"),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_file(descriptor: int) -> None:
    os.fsync(descriptor)
    full_sync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_sync is not None:
        fcntl.fcntl(descriptor, full_sync)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
    )
    try:
        while True:
            _checkpoint_operation_deadline_if_scoped_v2()
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        _checkpoint_operation_deadline_if_scoped_v2()
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while persisting preparation object")
        view = view[written:]


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            _integrity(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        _integrity(f"{label} must be an absolute normalized Path")
    if "\x00" in str(value):
        _integrity(f"{label} contains NUL")
    return value


def _identifier(value: object, label: str) -> str:
    pattern = _IDENTIFIERS[label]
    if type(value) is not str or pattern.fullmatch(value) is None:
        _integrity(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _integrity(f"{label} is not a SHA-256 value")
    return value


def _string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        _integrity(f"{label} must be a non-empty string")
    return value


def _object(value: object, label: str) -> JsonObject:
    if type(value) is not dict:
        _integrity(f"{label} must be an object")
    return copy.deepcopy(value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        _integrity(f"{label} has unexpected fields")


def _timestamp(value: datetime) -> str:
    return (
        _aware(value, "timestamp")
        .astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: object, label: str) -> datetime:
    text = _string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ActivationPreparationIntegrityErrorV2(
            f"{label} is not an RFC3339 timestamp"
        ) from exc
    return _aware(parsed, label)


def _aware(value: object, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _integrity(f"{label} must be an aware datetime")
    return value


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _flag(name: str) -> int:
    return int(getattr(os, name, 0))


def _integrity(message: str):
    raise ActivationPreparationIntegrityErrorV2(message)
