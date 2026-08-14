"""Долговечная подготовка source-манифеста для отката версии 2."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from .activation_preparation_v2 import (
    _atomic_create_private_json,
    _atomic_replace_private_json,
    _ensure_private_lock_file,
    _exclusive_lock,
    _fsync_directory,
    _fsync_regular_file,
    _lexists,
    _read_canonical_private_json,
    capture_directory_binding_v2,
    capture_file_projection_v2,
)
from .activation_transition_v2 import (
    PreparedManifestCommitV2,
    _manifest_projection,
    _prepared_manifest_fingerprint,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .installer_recovery_v2 import (
    InstallerRecoveryV2Error,
    RollbackEvidenceV2,
    _rollback_evidence_projection,
    _reverify_rollback_evidence,
)
from .lifecycle_operation_v2 import (
    ActivationTransitionLineageV2,
    ProjectionV2,
)
from . import operation_deadline_v2


_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_ID_DOMAIN = "codex-smart/rollback-operation-id/v2"
_INTENT_DOMAIN = "codex-smart/rollback-manifest-preparation-intent/v2"
_DEFINITION_DOMAIN = "codex-smart/rollback-manifest-preparation-definition/v2"
_JOURNAL_DOMAIN = "codex-smart/rollback-manifest-preparation-journal/v2"
_FROZEN_JOURNAL_DOMAIN = "codex-smart/rollback-manifest-preparation-frozen-journal/v2"
_STEP_DOMAIN = "codex-smart/rollback-manifest-preparation-step/v2"
_STEP_ID_DOMAIN = "codex-smart/rollback-manifest-preparation-step-id/v2"
_LOGICAL_DOMAIN = "codex-smart/rollback-manifest-preparation-logical/v2"
_RECEIPT_DOMAIN = "codex-smart/rollback-manifest-preparation-receipt/v2"
_JOURNAL_KIND = "rollback-manifest-preparation"
ROLLBACK_JOURNAL_KIND_V2 = _JOURNAL_KIND


def _checkpoint_operation_deadline_if_scoped_v2() -> None:
    """Проверить общий срок, если публичная граница его передала."""

    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is not None:
        deadline.checkpoint()


@dataclass
class RollbackManifestPreparationV2Error(RuntimeError):
    """Закрытый отказ подготовки с устойчивым машинным кодом."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class RollbackManifestPreparationFailurePointV2(Enum):
    """Аварийные границы всех внешних эффектов подготовки."""

    AFTER_PREPARATION_INTENT = "AFTER_PREPARATION_INTENT"
    AFTER_STEP_INTENT_BEFORE_EFFECT = "AFTER_STEP_INTENT_BEFORE_EFFECT"
    AFTER_EFFECT_BEFORE_STEP_COMPLETE = "AFTER_EFFECT_BEFORE_STEP_COMPLETE"
    BEFORE_PREPARATION_FREEZE = "BEFORE_PREPARATION_FREEZE"
    AFTER_PREPARATION_FREEZE = "AFTER_PREPARATION_FREEZE"
    BEFORE_RECEIPT_PUBLISH = "BEFORE_RECEIPT_PUBLISH"
    AFTER_RECEIPT_PUBLISH = "AFTER_RECEIPT_PUBLISH"


class InjectedRollbackManifestPreparationCrashV2(RollbackManifestPreparationV2Error):
    """Управляемый сбой узкого контура."""

    def __init__(self, point: RollbackManifestPreparationFailurePointV2) -> None:
        super().__init__(
            "ROLLBACK_PREPARATION_INJECTED_CRASH",
            f"injected rollback manifest preparation crash: {point.value}",
        )
        self.point = point


@dataclass(frozen=True)
class RollbackManifestPreparationIntentV2:
    """Самодостаточное неизменяемое намерение будущего манифеста."""

    installation_id: str
    operation_id: str
    current_operation_id: str
    previous_operation_id: str
    current_activation_id: str
    previous_activation_id: str
    evidence_fingerprint: str
    current_preparation_receipt_path: Path
    current_preparation_receipt_fingerprint: str
    current_preparation_receipt_sha256: str
    transition_proof_snapshot_fingerprint: str
    current_manifest_raw_sha256: str
    current_manifest_file_projection: Mapping[str, Any]
    projection_schema_sha256: str
    previous_activation_tree_sha256: str
    target_path: Path
    prepared_path: Path
    manifest_document: Mapping[str, Any]
    manifest_raw_sha256: str

    def __post_init__(self) -> None:
        identifiers = (
            (self.installation_id, _INSTALLATION_ID, "installationId"),
            (self.operation_id, _OPERATION_ID, "operationId"),
            (self.current_operation_id, _OPERATION_ID, "currentOperationId"),
            (self.previous_operation_id, _OPERATION_ID, "previousOperationId"),
            (self.current_activation_id, _ACTIVATION_ID, "currentActivationId"),
            (self.previous_activation_id, _ACTIVATION_ID, "previousActivationId"),
        )
        for value, pattern, label in identifiers:
            if pattern.fullmatch(value) is None:
                _fail("ROLLBACK_PREPARATION_INTENT_INVALID", f"{label} неверен")
        for value, label in (
            (self.evidence_fingerprint, "evidenceFingerprint"),
            (
                self.current_preparation_receipt_fingerprint,
                "currentPreparationReceiptFingerprint",
            ),
            (
                self.current_preparation_receipt_sha256,
                "currentPreparationReceiptSha256",
            ),
            (
                self.transition_proof_snapshot_fingerprint,
                "transitionProofSnapshotFingerprint",
            ),
            (self.current_manifest_raw_sha256, "currentManifestRawSha256"),
            (self.projection_schema_sha256, "projectionSchemaSha256"),
            (
                self.previous_activation_tree_sha256,
                "previousActivationTreeSha256",
            ),
            (self.manifest_raw_sha256, "manifestRawSha256"),
        ):
            if _SHA256.fullmatch(value) is None:
                _fail("ROLLBACK_PREPARATION_INTENT_INVALID", f"{label} неверен")
        for path, label in (
            (
                self.current_preparation_receipt_path,
                "currentPreparationReceiptPath",
            ),
            (self.target_path, "targetPath"),
            (self.prepared_path, "preparedPath"),
        ):
            _absolute_path(path, label)
        if type(self.current_manifest_file_projection) is not dict:
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "currentManifestFileProjection не является объектом",
            )
        if type(self.manifest_document) is not dict:
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "manifestDocument не является объектом",
            )
        object.__setattr__(
            self,
            "current_manifest_file_projection",
            copy.deepcopy(dict(self.current_manifest_file_projection)),
        )
        object.__setattr__(
            self,
            "manifest_document",
            copy.deepcopy(dict(self.manifest_document)),
        )
        if hashlib.sha256(_canonical(self.manifest_document)).hexdigest() != (
            self.manifest_raw_sha256
        ):
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "manifestRawSha256 не связан с manifestDocument",
            )
        if self.manifest_document.get("installationId") != self.installation_id:
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "manifestDocument принадлежит другой установке",
            )
        active = self.manifest_document.get("activeActivation")
        previous = self.manifest_document.get("previousActivation")
        if (
            type(active) is not dict
            or active.get("activationId") != self.previous_activation_id
            or type(previous) is not dict
            or previous.get("activationId") != self.current_activation_id
            or self.manifest_document.get("lastCommittedOperation") != self.operation_id
        ):
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "указатели manifestDocument не образуют точный откат",
            )
        expected_name = (
            f"{self.operation_id}.{self.manifest_raw_sha256}.rollback-manifest.json"
        )
        if self.prepared_path.name != expected_name:
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "preparedPath не адресован содержимым и operationId",
            )

    @property
    def intent_fingerprint(self) -> str:
        return domain_fingerprint(_INTENT_DOMAIN, self._projection())

    def _projection(self) -> dict[str, Any]:
        return {
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "currentOperationId": self.current_operation_id,
            "previousOperationId": self.previous_operation_id,
            "currentActivationId": self.current_activation_id,
            "previousActivationId": self.previous_activation_id,
            "evidenceFingerprint": self.evidence_fingerprint,
            "currentPreparationReceiptPath": str(self.current_preparation_receipt_path),
            "currentPreparationReceiptFingerprint": (
                self.current_preparation_receipt_fingerprint
            ),
            "currentPreparationReceiptSha256": (
                self.current_preparation_receipt_sha256
            ),
            "transitionProofSnapshotFingerprint": (
                self.transition_proof_snapshot_fingerprint
            ),
            "currentManifestRawSha256": self.current_manifest_raw_sha256,
            "currentManifestFileProjection": copy.deepcopy(
                dict(self.current_manifest_file_projection)
            ),
            "projectionSchemaSha256": self.projection_schema_sha256,
            "previousActivationTreeSha256": (self.previous_activation_tree_sha256),
            "targetPath": str(self.target_path),
            "preparedPath": str(self.prepared_path),
            "manifestDocument": copy.deepcopy(dict(self.manifest_document)),
            "manifestRawSha256": self.manifest_raw_sha256,
        }

    def to_document(self) -> dict[str, Any]:
        return {**self._projection(), "intentFingerprint": self.intent_fingerprint}

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> "RollbackManifestPreparationIntentV2":
        expected = {
            "installationId",
            "operationId",
            "currentOperationId",
            "previousOperationId",
            "currentActivationId",
            "previousActivationId",
            "evidenceFingerprint",
            "currentPreparationReceiptPath",
            "currentPreparationReceiptFingerprint",
            "currentPreparationReceiptSha256",
            "transitionProofSnapshotFingerprint",
            "currentManifestRawSha256",
            "currentManifestFileProjection",
            "projectionSchemaSha256",
            "previousActivationTreeSha256",
            "targetPath",
            "preparedPath",
            "manifestDocument",
            "manifestRawSha256",
            "intentFingerprint",
        }
        _exact_keys(document, expected, "activationIntent")
        result = cls(
            installation_id=_string(document["installationId"], "installationId"),
            operation_id=_string(document["operationId"], "operationId"),
            current_operation_id=_string(
                document["currentOperationId"], "currentOperationId"
            ),
            previous_operation_id=_string(
                document["previousOperationId"], "previousOperationId"
            ),
            current_activation_id=_string(
                document["currentActivationId"], "currentActivationId"
            ),
            previous_activation_id=_string(
                document["previousActivationId"], "previousActivationId"
            ),
            evidence_fingerprint=_string(
                document["evidenceFingerprint"], "evidenceFingerprint"
            ),
            current_preparation_receipt_path=Path(
                _string(
                    document["currentPreparationReceiptPath"],
                    "currentPreparationReceiptPath",
                )
            ),
            current_preparation_receipt_fingerprint=_string(
                document["currentPreparationReceiptFingerprint"],
                "currentPreparationReceiptFingerprint",
            ),
            current_preparation_receipt_sha256=_string(
                document["currentPreparationReceiptSha256"],
                "currentPreparationReceiptSha256",
            ),
            transition_proof_snapshot_fingerprint=_string(
                document["transitionProofSnapshotFingerprint"],
                "transitionProofSnapshotFingerprint",
            ),
            current_manifest_raw_sha256=_string(
                document["currentManifestRawSha256"],
                "currentManifestRawSha256",
            ),
            current_manifest_file_projection=_object(
                document["currentManifestFileProjection"],
                "currentManifestFileProjection",
            ),
            projection_schema_sha256=_string(
                document["projectionSchemaSha256"],
                "projectionSchemaSha256",
            ),
            previous_activation_tree_sha256=_string(
                document["previousActivationTreeSha256"],
                "previousActivationTreeSha256",
            ),
            target_path=Path(_string(document["targetPath"], "targetPath")),
            prepared_path=Path(_string(document["preparedPath"], "preparedPath")),
            manifest_document=_object(document["manifestDocument"], "manifestDocument"),
            manifest_raw_sha256=_string(
                document["manifestRawSha256"], "manifestRawSha256"
            ),
        )
        if document["intentFingerprint"] != result.intent_fingerprint:
            _fail(
                "ROLLBACK_PREPARATION_INTENT_INVALID",
                "intentFingerprint не совпал",
            )
        return result


@dataclass(frozen=True)
class RollbackManifestPreparationDefinitionV2:
    """Полное определение одного подготовительного журнала."""

    journal_path: Path
    receipt_path: Path
    lock_path: Path
    activation_intent: RollbackManifestPreparationIntentV2

    def __post_init__(self) -> None:
        for path, label in (
            (self.journal_path, "journalPath"),
            (self.receipt_path, "receiptPath"),
            (self.lock_path, "lockPath"),
        ):
            _absolute_path(path, label)
        if not isinstance(self.activation_intent, RollbackManifestPreparationIntentV2):
            _fail(
                "ROLLBACK_PREPARATION_DEFINITION_INVALID",
                "activationIntent имеет иной тип",
            )
        controls = {self.journal_path, self.receipt_path, self.lock_path}
        if self.activation_intent.prepared_path in controls:
            _fail(
                "ROLLBACK_PREPARATION_DEFINITION_INVALID",
                "служебный путь совпадает с preparedPath",
            )

    @property
    def definition_fingerprint(self) -> str:
        return domain_fingerprint(_DEFINITION_DOMAIN, self.to_document())

    def to_document(self) -> dict[str, Any]:
        return {
            "journalPath": str(self.journal_path),
            "receiptPath": str(self.receipt_path),
            "lockPath": str(self.lock_path),
            "activationIntent": self.activation_intent.to_document(),
        }

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> "RollbackManifestPreparationDefinitionV2":
        _exact_keys(
            document,
            {"journalPath", "receiptPath", "lockPath", "activationIntent"},
            "definition",
        )
        return cls(
            journal_path=Path(_string(document["journalPath"], "journalPath")),
            receipt_path=Path(_string(document["receiptPath"], "receiptPath")),
            lock_path=Path(_string(document["lockPath"], "lockPath")),
            activation_intent=RollbackManifestPreparationIntentV2.from_document(
                _object(document["activationIntent"], "activationIntent")
            ),
        )


@dataclass(frozen=True)
class RollbackManifestPreparationV2:
    """Чисто построенное намерение; создание объектов выполняет executor."""

    definition: RollbackManifestPreparationDefinitionV2


@dataclass(frozen=True)
class RollbackManifestPreparationPathsV2:
    journal_path: Path
    receipt_path: Path
    lock_path: Path
    prepared_root: Path

    def __post_init__(self) -> None:
        for path, label in (
            (self.journal_path, "journalPath"),
            (self.receipt_path, "receiptPath"),
            (self.lock_path, "lockPath"),
            (self.prepared_root, "preparedRoot"),
        ):
            _absolute_path(path, label)


@dataclass(frozen=True)
class RollbackManifestPreparationReceiptV2:
    """Неизменяемая граница передачи source-файла основной операции."""

    installation_id: str
    operation_id: str
    current_operation_id: str
    previous_operation_id: str
    current_activation_id: str
    previous_activation_id: str
    evidence_fingerprint: str
    preparation_intent_fingerprint: str
    current_preparation_receipt_path: Path
    current_preparation_receipt_fingerprint: str
    current_preparation_receipt_sha256: str
    transition_proof_snapshot_fingerprint: str
    target_path: Path
    prepared_path: Path
    prepared_manifest_file: ProjectionV2
    prepared_manifest_parent: ProjectionV2
    manifest_document: Mapping[str, Any]
    manifest_raw_sha256: str
    previous_activation_tree_sha256: str
    expected_after: ProjectionV2
    frozen_journal_fingerprint: str
    completed_at: datetime

    def __post_init__(self) -> None:
        identifiers = (
            (self.installation_id, _INSTALLATION_ID, "installationId"),
            (self.operation_id, _OPERATION_ID, "operationId"),
            (self.current_operation_id, _OPERATION_ID, "currentOperationId"),
            (self.previous_operation_id, _OPERATION_ID, "previousOperationId"),
            (self.current_activation_id, _ACTIVATION_ID, "currentActivationId"),
            (self.previous_activation_id, _ACTIVATION_ID, "previousActivationId"),
        )
        for value, pattern, label in identifiers:
            if pattern.fullmatch(value) is None:
                _fail("ROLLBACK_PREPARATION_RECEIPT_INVALID", f"{label} неверен")
        for value, label in (
            (self.evidence_fingerprint, "evidenceFingerprint"),
            (self.preparation_intent_fingerprint, "preparationIntentFingerprint"),
            (
                self.current_preparation_receipt_fingerprint,
                "currentPreparationReceiptFingerprint",
            ),
            (
                self.current_preparation_receipt_sha256,
                "currentPreparationReceiptSha256",
            ),
            (
                self.transition_proof_snapshot_fingerprint,
                "transitionProofSnapshotFingerprint",
            ),
            (self.manifest_raw_sha256, "manifestRawSha256"),
            (
                self.previous_activation_tree_sha256,
                "previousActivationTreeSha256",
            ),
            (self.frozen_journal_fingerprint, "frozenJournalFingerprint"),
        ):
            if _SHA256.fullmatch(value) is None:
                _fail("ROLLBACK_PREPARATION_RECEIPT_INVALID", f"{label} неверен")
        for path, label in (
            (
                self.current_preparation_receipt_path,
                "currentPreparationReceiptPath",
            ),
            (self.target_path, "targetPath"),
            (self.prepared_path, "preparedPath"),
        ):
            _absolute_path(path, label)
        for projection, schema_id, domain in (
            (
                self.prepared_manifest_file,
                "file-object-v2",
                "codex-smart/file-object/v2",
            ),
            (
                self.prepared_manifest_parent,
                "directory-binding-v2",
                "codex-smart/directory-binding/v2",
            ),
            (
                self.expected_after,
                "manifest-v2",
                "codex-smart/journal-state/v2",
            ),
        ):
            _validate_projection(projection, schema_id, domain)
        object.__setattr__(
            self,
            "manifest_document",
            copy.deepcopy(dict(self.manifest_document)),
        )
        if (
            hashlib.sha256(_canonical(self.manifest_document)).hexdigest()
            != self.manifest_raw_sha256
            or self.prepared_manifest_file.value.get("path") != str(self.prepared_path)
            or self.prepared_manifest_file.value.get("mode") != "0600"
            or self.prepared_manifest_file.value.get("linkCount") != 1
            or self.prepared_manifest_file.value.get("sha256")
            != self.manifest_raw_sha256
            or self.prepared_manifest_parent.value.get("path")
            != str(self.prepared_path.parent)
            or self.prepared_manifest_parent.value.get("mode") != "0700"
        ):
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "prepared manifest не связан с квитанцией",
            )
        expected_file = self.expected_after.value.get("file")
        if type(expected_file) is not dict:
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "expectedAfter не содержит file",
            )
        prepared_file = dict(self.prepared_manifest_file.value)
        prepared_file["path"] = str(self.target_path)
        if (
            expected_file != prepared_file
            or self.expected_after.value.get("activeActivationId")
            != self.previous_activation_id
            or self.expected_after.value.get("previousActivationId")
            != self.current_activation_id
            or self.expected_after.value.get("lastCommittedOperation")
            != self.operation_id
        ):
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "expectedAfter не связан с подготовленным inode",
            )
        if self.completed_at.tzinfo is None:
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "completedAt не содержит часовой пояс",
            )

    def _projection(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "receiptKind": _JOURNAL_KIND,
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "currentOperationId": self.current_operation_id,
            "previousOperationId": self.previous_operation_id,
            "currentActivationId": self.current_activation_id,
            "previousActivationId": self.previous_activation_id,
            "evidenceFingerprint": self.evidence_fingerprint,
            "preparationIntentFingerprint": self.preparation_intent_fingerprint,
            "currentPreparationReceiptPath": str(self.current_preparation_receipt_path),
            "currentPreparationReceiptFingerprint": (
                self.current_preparation_receipt_fingerprint
            ),
            "currentPreparationReceiptSha256": (
                self.current_preparation_receipt_sha256
            ),
            "transitionProofSnapshotFingerprint": (
                self.transition_proof_snapshot_fingerprint
            ),
            "targetPath": str(self.target_path),
            "preparedPath": str(self.prepared_path),
            "preparedManifestFile": self.prepared_manifest_file.to_document(),
            "preparedManifestParent": self.prepared_manifest_parent.to_document(),
            "manifestDocument": copy.deepcopy(dict(self.manifest_document)),
            "manifestRawSha256": self.manifest_raw_sha256,
            "previousActivationTreeSha256": (self.previous_activation_tree_sha256),
            "expectedAfter": self.expected_after.to_document(),
            "frozenJournalFingerprint": self.frozen_journal_fingerprint,
            "completedAt": _timestamp(self.completed_at),
        }

    @property
    def receipt_fingerprint(self) -> str:
        return domain_fingerprint(_RECEIPT_DOMAIN, self._projection())

    def to_document(self) -> dict[str, Any]:
        return {**self._projection(), "receiptFingerprint": self.receipt_fingerprint}

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> "RollbackManifestPreparationReceiptV2":
        expected = {
            "schemaVersion",
            "receiptKind",
            "installationId",
            "operationId",
            "currentOperationId",
            "previousOperationId",
            "currentActivationId",
            "previousActivationId",
            "evidenceFingerprint",
            "preparationIntentFingerprint",
            "currentPreparationReceiptPath",
            "currentPreparationReceiptFingerprint",
            "currentPreparationReceiptSha256",
            "transitionProofSnapshotFingerprint",
            "targetPath",
            "preparedPath",
            "preparedManifestFile",
            "preparedManifestParent",
            "manifestDocument",
            "manifestRawSha256",
            "previousActivationTreeSha256",
            "expectedAfter",
            "frozenJournalFingerprint",
            "completedAt",
            "receiptFingerprint",
        }
        _exact_keys(document, expected, "receipt")
        if document["schemaVersion"] != 2 or document["receiptKind"] != _JOURNAL_KIND:
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "заголовок квитанции неверен",
            )
        result = cls(
            installation_id=_string(document["installationId"], "installationId"),
            operation_id=_string(document["operationId"], "operationId"),
            current_operation_id=_string(
                document["currentOperationId"], "currentOperationId"
            ),
            previous_operation_id=_string(
                document["previousOperationId"], "previousOperationId"
            ),
            current_activation_id=_string(
                document["currentActivationId"], "currentActivationId"
            ),
            previous_activation_id=_string(
                document["previousActivationId"], "previousActivationId"
            ),
            evidence_fingerprint=_string(
                document["evidenceFingerprint"], "evidenceFingerprint"
            ),
            preparation_intent_fingerprint=_string(
                document["preparationIntentFingerprint"],
                "preparationIntentFingerprint",
            ),
            current_preparation_receipt_path=Path(
                _string(
                    document["currentPreparationReceiptPath"],
                    "currentPreparationReceiptPath",
                )
            ),
            current_preparation_receipt_fingerprint=_string(
                document["currentPreparationReceiptFingerprint"],
                "currentPreparationReceiptFingerprint",
            ),
            current_preparation_receipt_sha256=_string(
                document["currentPreparationReceiptSha256"],
                "currentPreparationReceiptSha256",
            ),
            transition_proof_snapshot_fingerprint=_string(
                document["transitionProofSnapshotFingerprint"],
                "transitionProofSnapshotFingerprint",
            ),
            target_path=Path(_string(document["targetPath"], "targetPath")),
            prepared_path=Path(_string(document["preparedPath"], "preparedPath")),
            prepared_manifest_file=ProjectionV2.from_document(
                _object(document["preparedManifestFile"], "preparedManifestFile")
            ),
            prepared_manifest_parent=ProjectionV2.from_document(
                _object(document["preparedManifestParent"], "preparedManifestParent")
            ),
            manifest_document=_object(document["manifestDocument"], "manifestDocument"),
            manifest_raw_sha256=_string(
                document["manifestRawSha256"], "manifestRawSha256"
            ),
            previous_activation_tree_sha256=_string(
                document["previousActivationTreeSha256"],
                "previousActivationTreeSha256",
            ),
            expected_after=ProjectionV2.from_document(
                _object(document["expectedAfter"], "expectedAfter")
            ),
            frozen_journal_fingerprint=_string(
                document["frozenJournalFingerprint"],
                "frozenJournalFingerprint",
            ),
            completed_at=_parse_timestamp(document["completedAt"], "completedAt"),
        )
        if document["receiptFingerprint"] != result.receipt_fingerprint:
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "receiptFingerprint не совпал",
            )
        return result

    @classmethod
    def from_path(cls, path: Path) -> "RollbackManifestPreparationReceiptV2":
        _absolute_path(path, "receipt path")
        return cls.from_document(_read_canonical_private_json(path, "receipt"))


class RollbackManifestPreparationExecutorV2:
    """Исполнить или продолжить один подготовительный журнал."""

    def __init__(
        self,
        *,
        definition: RollbackManifestPreparationDefinitionV2,
        clock: Callable[[], datetime] | None = None,
        failure_injector: Callable[[RollbackManifestPreparationFailurePointV2], None]
        | None = None,
    ) -> None:
        if not isinstance(definition, RollbackManifestPreparationDefinitionV2):
            raise TypeError(
                "definition must be RollbackManifestPreparationDefinitionV2"
            )
        self.definition = definition
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._failure_injector = failure_injector
        for directory, label in (
            (definition.journal_path.parent, "journal parent"),
            (definition.receipt_path.parent, "receipt parent"),
            (definition.lock_path.parent, "lock parent"),
            (definition.activation_intent.prepared_path.parent, "prepared parent"),
        ):
            _validate_private_directory(directory, label)

    def execute(self) -> RollbackManifestPreparationReceiptV2:
        return self.recover()

    def recover(self) -> RollbackManifestPreparationReceiptV2:
        _checkpoint_operation_deadline_if_scoped_v2()
        _ensure_private_lock_file(self.definition.lock_path)
        with _exclusive_lock(self.definition.lock_path):
            _checkpoint_operation_deadline_if_scoped_v2()
            return self._recover_locked()

    def _recover_locked(self) -> RollbackManifestPreparationReceiptV2:
        _checkpoint_operation_deadline_if_scoped_v2()
        journal_present = _lexists(self.definition.journal_path)
        receipt_present = _lexists(self.definition.receipt_path)
        if not journal_present and receipt_present:
            receipt = self._read_receipt()
            self._verify_receipt_binding(receipt, require_source=True)
            return receipt
        if not journal_present:
            self._verify_source_receipt_and_before()
            if _lexists(self.definition.activation_intent.prepared_path):
                _fail(
                    "ROLLBACK_PREPARATION_ORPHAN_SOURCE",
                    "prepared manifest существует без журнала или квитанции",
                )
            journal = self._initial_journal()
            _checkpoint_operation_deadline_if_scoped_v2()
            _atomic_create_private_json(self.definition.journal_path, journal)
            self._inject(
                RollbackManifestPreparationFailurePointV2.AFTER_PREPARATION_INTENT
            )
            _checkpoint_operation_deadline_if_scoped_v2()
        journal = self._read_journal()
        receipt_present = _lexists(self.definition.receipt_path)
        if journal["phase"] == "PREPARATION_FROZEN":
            receipt = self._receipt_from_frozen(journal)
            if receipt_present:
                persisted = self._read_receipt()
                if persisted.to_document() != receipt.to_document():
                    _fail(
                        "ROLLBACK_PREPARATION_RECEIPT_CONFLICT",
                        "опубликована иная квитанция подготовки",
                    )
            else:
                self._inject(
                    RollbackManifestPreparationFailurePointV2.BEFORE_RECEIPT_PUBLISH
                )
                _checkpoint_operation_deadline_if_scoped_v2()
                _atomic_create_private_json(
                    self.definition.receipt_path, receipt.to_document()
                )
                _checkpoint_operation_deadline_if_scoped_v2()
                self._inject(
                    RollbackManifestPreparationFailurePointV2.AFTER_RECEIPT_PUBLISH
                )
            _checkpoint_operation_deadline_if_scoped_v2()
            self._close_frozen_journal(journal)
            self._verify_receipt_binding(receipt, require_source=True)
            return receipt
        if receipt_present:
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_CONFLICT",
                "квитанция сосуществует с незамороженным журналом",
            )
        self._verify_source_receipt_and_before()
        step = journal["steps"][0]
        if step["state"] == "PLANNED":
            updated = copy.deepcopy(journal)
            now = self._now()
            updated["steps"][0] = _step_document(
                intent=self.definition.activation_intent,
                state="INTENT_DURABLE",
                intent_at=now,
                completed_at=None,
                observed=None,
                companions=(),
            )
            updated["contentGeneration"] += 1
            updated["updatedAt"] = _timestamp(now)
            updated = _with_journal_fingerprint(updated)
            _atomic_replace_private_json(
                self.definition.journal_path,
                updated,
                expected_fingerprint=journal["journalFingerprint"],
            )
            journal = updated
            self._inject(
                RollbackManifestPreparationFailurePointV2.AFTER_STEP_INTENT_BEFORE_EFFECT
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            step = journal["steps"][0]
        if step["state"] == "INTENT_DURABLE":
            _checkpoint_operation_deadline_if_scoped_v2()
            file_projection, parent_projection = self._materialize_or_verify()
            _checkpoint_operation_deadline_if_scoped_v2()
            self._inject(
                RollbackManifestPreparationFailurePointV2.AFTER_EFFECT_BEFORE_STEP_COMPLETE
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            updated = copy.deepcopy(journal)
            completed = self._now()
            updated["steps"][0] = _step_document(
                intent=self.definition.activation_intent,
                state="COMPLETED",
                intent_at=_parse_timestamp(step["intentAt"], "intentAt"),
                completed_at=completed,
                observed=file_projection,
                companions=(parent_projection,),
            )
            updated["contentGeneration"] += 1
            updated["updatedAt"] = _timestamp(completed)
            updated = _with_journal_fingerprint(updated)
            _checkpoint_operation_deadline_if_scoped_v2()
            _atomic_replace_private_json(
                self.definition.journal_path,
                updated,
                expected_fingerprint=journal["journalFingerprint"],
            )
            journal = updated
        self._inject(
            RollbackManifestPreparationFailurePointV2.BEFORE_PREPARATION_FREEZE
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        journal = self._freeze(journal)
        self._inject(RollbackManifestPreparationFailurePointV2.AFTER_PREPARATION_FREEZE)
        _checkpoint_operation_deadline_if_scoped_v2()
        receipt = self._receipt_from_frozen(journal)
        self._inject(RollbackManifestPreparationFailurePointV2.BEFORE_RECEIPT_PUBLISH)
        _checkpoint_operation_deadline_if_scoped_v2()
        _atomic_create_private_json(self.definition.receipt_path, receipt.to_document())
        _checkpoint_operation_deadline_if_scoped_v2()
        self._inject(RollbackManifestPreparationFailurePointV2.AFTER_RECEIPT_PUBLISH)
        _checkpoint_operation_deadline_if_scoped_v2()
        self._close_frozen_journal(journal)
        self._verify_receipt_binding(receipt, require_source=True)
        return receipt

    def _initial_journal(self) -> dict[str, Any]:
        now = self._now()
        intent = self.definition.activation_intent
        document = {
            "schemaVersion": 2,
            "journalKind": _JOURNAL_KIND,
            "installationId": intent.installation_id,
            "operationId": intent.operation_id,
            "phase": "PREPARING",
            "definitionFingerprint": self.definition.definition_fingerprint,
            "definition": self.definition.to_document(),
            "intentBoundary": {
                "kind": "preparation_intent",
                "state": "COMPLETED",
                "intentFingerprint": intent.intent_fingerprint,
                "completedAt": _timestamp(now),
            },
            "steps": [
                _step_document(
                    intent=intent,
                    state="PLANNED",
                    intent_at=None,
                    completed_at=None,
                    observed=None,
                    companions=(),
                )
            ],
            "contentGeneration": 0,
            "createdAt": _timestamp(now),
            "updatedAt": _timestamp(now),
            "frozenAt": None,
            "frozenJournalFingerprint": None,
            "journalFingerprint": "0" * 64,
        }
        return _with_journal_fingerprint(document)

    def _read_journal(self) -> dict[str, Any]:
        document = _read_canonical_private_json(
            self.definition.journal_path, "rollback preparation journal"
        )
        _validate_journal(self.definition, document)
        return document

    def _read_receipt(self) -> RollbackManifestPreparationReceiptV2:
        receipt = RollbackManifestPreparationReceiptV2.from_path(
            self.definition.receipt_path
        )
        self._verify_receipt_binding(receipt, require_source=False)
        return receipt

    def _verify_source_receipt_and_before(self) -> None:
        intent = self.definition.activation_intent
        try:
            source = _read_canonical_private_json(
                intent.current_preparation_receipt_path,
                "transition source receipt",
            )
        except Exception as exc:
            raise RollbackManifestPreparationV2Error(
                "ROLLBACK_PREPARATION_RECEIPT_CHANGED", str(exc)
            ) from exc
        source_raw = _canonical(source)
        if (
            source.get("receiptFingerprint")
            != intent.current_preparation_receipt_fingerprint
            or hashlib.sha256(source_raw).hexdigest()
            != intent.current_preparation_receipt_sha256
        ):
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_CHANGED",
                "prep-квитанция текущей операции изменилась",
            )
        target = _read_canonical_private_json(intent.target_path, "current manifest")
        current = capture_file_projection_v2(
            intent.target_path,
            schema_sha256=self._schema_sha256,
        )
        if hashlib.sha256(
            _canonical(target)
        ).hexdigest() != intent.current_manifest_raw_sha256 or current.value != dict(
            intent.current_manifest_file_projection
        ):
            _fail(
                "ROLLBACK_PREPARATION_CURRENT_MANIFEST_CHANGED",
                "текущий манифест изменился до handoff",
            )

    @property
    def _schema_sha256(self) -> str:
        return self.definition.activation_intent.projection_schema_sha256

    def _materialize_or_verify(self) -> tuple[ProjectionV2, ProjectionV2]:
        _checkpoint_operation_deadline_if_scoped_v2()
        intent = self.definition.activation_intent
        if not _lexists(intent.prepared_path):
            _atomic_create_private_json(intent.prepared_path, intent.manifest_document)
        else:
            _fsync_regular_file(intent.prepared_path)
            _fsync_directory(intent.prepared_path.parent)
        _checkpoint_operation_deadline_if_scoped_v2()
        return self._observe_prepared_source()

    def _observe_prepared_source(self) -> tuple[ProjectionV2, ProjectionV2]:
        intent = self.definition.activation_intent
        if not _lexists(intent.prepared_path):
            _fail(
                "ROLLBACK_PREPARATION_SOURCE_MISSING",
                "prepared source уже отсутствует",
            )
        observed = _read_canonical_private_json(
            intent.prepared_path, "prepared rollback manifest"
        )
        info = intent.prepared_path.lstat()
        if (
            observed != dict(intent.manifest_document)
            or not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            _fail(
                "ROLLBACK_PREPARATION_SOURCE_AMBIGUOUS",
                "preparedPath не является точным частным source-файлом",
            )
        file_projection = capture_file_projection_v2(
            intent.prepared_path, schema_sha256=self._schema_sha256
        )
        parent_projection = capture_directory_binding_v2(
            intent.prepared_path.parent, schema_sha256=self._schema_sha256
        )
        return file_projection, parent_projection

    def _freeze(self, journal: Mapping[str, Any]) -> dict[str, Any]:
        _checkpoint_operation_deadline_if_scoped_v2()
        document = copy.deepcopy(dict(journal))
        step = document["steps"][0]
        if step["state"] != "COMPLETED":
            _fail(
                "ROLLBACK_PREPARATION_FREEZE_INVALID",
                "заморозка до COMPLETED запрещена",
            )
        now = self._now()
        document["phase"] = "PREPARATION_FROZEN"
        document["frozenAt"] = _timestamp(now)
        document["updatedAt"] = _timestamp(now)
        document["contentGeneration"] += 1
        document["frozenJournalFingerprint"] = None
        document["journalFingerprint"] = "0" * 64
        frozen_projection = {
            key: copy.deepcopy(value)
            for key, value in document.items()
            if key != "journalFingerprint"
        }
        document["frozenJournalFingerprint"] = domain_fingerprint(
            _FROZEN_JOURNAL_DOMAIN, frozen_projection
        )
        document = _with_journal_fingerprint(document)
        _checkpoint_operation_deadline_if_scoped_v2()
        _atomic_replace_private_json(
            self.definition.journal_path,
            document,
            expected_fingerprint=journal["journalFingerprint"],
        )
        _validate_journal(self.definition, document)
        return document

    def _receipt_from_frozen(
        self, journal: Mapping[str, Any]
    ) -> RollbackManifestPreparationReceiptV2:
        step = journal["steps"][0]
        if journal["phase"] != "PREPARATION_FROZEN" or step["state"] != "COMPLETED":
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_INVALID",
                "квитанция требует замороженный COMPLETED-журнал",
            )
        file_projection = ProjectionV2.from_document(step["observedPhysical"])
        parent_projection = ProjectionV2.from_document(step["observedCompanions"][0])
        intent = self.definition.activation_intent
        expected_file = copy.deepcopy(dict(file_projection.value))
        expected_file["path"] = str(intent.target_path)
        expected_after = _manifest_projection(
            intent.target_path,
            intent.manifest_document,
            file_projection=expected_file,
        )
        return RollbackManifestPreparationReceiptV2(
            installation_id=intent.installation_id,
            operation_id=intent.operation_id,
            current_operation_id=intent.current_operation_id,
            previous_operation_id=intent.previous_operation_id,
            current_activation_id=intent.current_activation_id,
            previous_activation_id=intent.previous_activation_id,
            evidence_fingerprint=intent.evidence_fingerprint,
            preparation_intent_fingerprint=intent.intent_fingerprint,
            current_preparation_receipt_path=(intent.current_preparation_receipt_path),
            current_preparation_receipt_fingerprint=(
                intent.current_preparation_receipt_fingerprint
            ),
            current_preparation_receipt_sha256=(
                intent.current_preparation_receipt_sha256
            ),
            transition_proof_snapshot_fingerprint=(
                intent.transition_proof_snapshot_fingerprint
            ),
            target_path=intent.target_path,
            prepared_path=intent.prepared_path,
            prepared_manifest_file=file_projection,
            prepared_manifest_parent=parent_projection,
            manifest_document=intent.manifest_document,
            manifest_raw_sha256=intent.manifest_raw_sha256,
            previous_activation_tree_sha256=(intent.previous_activation_tree_sha256),
            expected_after=expected_after,
            frozen_journal_fingerprint=journal["frozenJournalFingerprint"],
            completed_at=_parse_timestamp(journal["frozenAt"], "frozenAt"),
        )

    def _verify_receipt_binding(
        self,
        receipt: RollbackManifestPreparationReceiptV2,
        *,
        require_source: bool,
    ) -> None:
        intent = self.definition.activation_intent
        if (
            receipt.installation_id != intent.installation_id
            or receipt.operation_id != intent.operation_id
            or receipt.preparation_intent_fingerprint != intent.intent_fingerprint
            or receipt.evidence_fingerprint != intent.evidence_fingerprint
            or receipt.manifest_document != dict(intent.manifest_document)
            or receipt.manifest_raw_sha256 != intent.manifest_raw_sha256
            or receipt.prepared_path != intent.prepared_path
            or receipt.target_path != intent.target_path
        ):
            _fail(
                "ROLLBACK_PREPARATION_RECEIPT_CONFLICT",
                "квитанция не связана с определением",
            )
        if require_source:
            observed_file, observed_parent = self._observe_prepared_source()
            if (
                observed_file != receipt.prepared_manifest_file
                or observed_parent != receipt.prepared_manifest_parent
            ):
                _fail(
                    "ROLLBACK_PREPARATION_SOURCE_CHANGED",
                    "source-файл изменился после подготовки",
                )

    def _close_frozen_journal(self, journal: Mapping[str, Any]) -> None:
        _checkpoint_operation_deadline_if_scoped_v2()
        current = self._read_journal()
        if current != dict(journal) or current["phase"] != "PREPARATION_FROZEN":
            _fail(
                "ROLLBACK_PREPARATION_JOURNAL_CHANGED",
                "закрывается не тот замороженный журнал",
            )
        descriptor = os.open(
            self.definition.journal_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            opened = os.fstat(descriptor)
            named = self.definition.journal_path.lstat()
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                _fail(
                    "ROLLBACK_PREPARATION_JOURNAL_CHANGED",
                    "inode журнала изменился перед unlink",
                )
            _checkpoint_operation_deadline_if_scoped_v2()
            os.unlink(self.definition.journal_path)
            _fsync_directory(self.definition.journal_path.parent)
            if _lexists(self.definition.journal_path):
                _fail(
                    "ROLLBACK_PREPARATION_JOURNAL_CHANGED",
                    "журнал вновь появился после unlink",
                )
        finally:
            os.close(descriptor)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail(
                "ROLLBACK_PREPARATION_CLOCK_INVALID",
                "clock должен возвращать aware datetime",
            )
        return value.astimezone(timezone.utc)

    def _inject(self, point: RollbackManifestPreparationFailurePointV2) -> None:
        if self._failure_injector is not None:
            self._failure_injector(point)


def rollback_operation_id_v2(evidence: RollbackEvidenceV2) -> str:
    """Детерминированно связать новую операцию со снимком отката."""

    if not isinstance(evidence, RollbackEvidenceV2):
        raise TypeError("evidence must be RollbackEvidenceV2")
    values = (
        (evidence.installation_id, _INSTALLATION_ID, "installationId"),
        (evidence.current_operation_id, _OPERATION_ID, "currentOperationId"),
        (evidence.previous_operation_id, _OPERATION_ID, "previousOperationId"),
        (evidence.current_activation_id, _ACTIVATION_ID, "currentActivationId"),
        (evidence.previous_activation_id, _ACTIVATION_ID, "previousActivationId"),
        (evidence.evidence_fingerprint, _SHA256, "evidenceFingerprint"),
    )
    for value, pattern, label in values:
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise ValueError(f"{label} is invalid")
    seed = domain_fingerprint(
        _OPERATION_ID_DOMAIN,
        {
            "installationId": evidence.installation_id,
            "currentOperationId": evidence.current_operation_id,
            "previousOperationId": evidence.previous_operation_id,
            "currentActivationId": evidence.current_activation_id,
            "previousActivationId": evidence.previous_activation_id,
            "evidenceFingerprint": evidence.evidence_fingerprint,
        },
    )
    return "op2_" + seed[:32]


def rollback_manifest_preparation_paths_v2(
    evidence: RollbackEvidenceV2,
) -> RollbackManifestPreparationPathsV2:
    """Вернуть единственные нормативные пути подготовительного контура."""

    operation_id = rollback_operation_id_v2(evidence)
    manifest_root = evidence.manifest_path.parent
    return RollbackManifestPreparationPathsV2(
        journal_path=(
            manifest_root
            / "codex-smart-subagents-v2.rollback-manifest-preparation.transaction.json"
        ),
        receipt_path=(
            evidence.receipts_root / f"{operation_id}.rollback-preparation.json"
        ),
        lock_path=manifest_root / "rollback-manifest-preparation.lock",
        prepared_root=manifest_root / "prepared-manifests",
    )


def build_rollback_manifest_preparation_v2(
    *,
    evidence: RollbackEvidenceV2,
    current_preparation_receipt_path: Path,
    journal_path: Path,
    receipt_path: Path,
    lock_path: Path,
    prepared_root: Path,
    installer_source_digest: str | None = None,
) -> RollbackManifestPreparationV2:
    """Построить точное намерение без создания служебных объектов."""

    if not isinstance(evidence, RollbackEvidenceV2):
        raise TypeError("evidence must be RollbackEvidenceV2")
    for path, label in (
        (current_preparation_receipt_path, "currentPreparationReceiptPath"),
        (journal_path, "journalPath"),
        (receipt_path, "receiptPath"),
        (lock_path, "lockPath"),
        (prepared_root, "preparedRoot"),
    ):
        _absolute_path(path, label)
    try:
        _reverify_rollback_evidence(evidence)
    except InstallerRecoveryV2Error as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREPARATION_EVIDENCE_CHANGED", str(exc)
        ) from exc
    try:
        lineage = ActivationTransitionLineageV2.from_document(
            evidence.current_receipt["transitionLineage"]
        )
    except Exception as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREVIOUS_MANIFEST_SOURCE_REQUIRED",
            f"current commit не содержит проверяемый transitionLineage: {exc}",
        ) from exc
    source = lineage.source_receipt
    stopped = lineage.stopped_controller
    if source is None or stopped is None:
        _fail(
            "ROLLBACK_PREVIOUS_MANIFEST_SOURCE_REQUIRED",
            "current commit не содержит переход с остановленным предшественником",
        )
    if (
        current_preparation_receipt_path != source.path
        or source.path.parent != evidence.receipts_root
    ):
        _fail(
            "ROLLBACK_PREPARATION_RECEIPT_PATH_INVALID",
            "источник transitionLineage не находится в receiptsRoot установки",
        )
    try:
        source_document = _read_canonical_private_json(
            current_preparation_receipt_path,
            "transition source receipt",
        )
    except Exception as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREPARATION_RECEIPT_INVALID", str(exc)
        ) from exc
    source_raw = _canonical(source_document)
    previous_manifest = evidence.previous_receipt.get("manifestDocument")
    current_manifest = evidence.current_receipt.get("manifestDocument")
    if (
        source_document.get("receiptFingerprint") != source.receipt_fingerprint
        or hashlib.sha256(source_raw).hexdigest() != source.raw_sha256
        or type(previous_manifest) is not dict
        or type(current_manifest) is not dict
        or current_manifest != dict(evidence.manifest_document)
        or previous_manifest.get("installationId") != evidence.installation_id
        or previous_manifest.get("activeActivation")
        != dict(evidence.previous_pointer)
        or previous_manifest.get("lastCommittedOperation")
        != evidence.previous_operation_id
        or stopped.operation_id != evidence.current_operation_id
        or stopped.activation_id != evidence.previous_activation_id
        or stopped.database_id
        != evidence.previous_database_binding.value.get("databaseId")
    ):
        _fail(
            "ROLLBACK_PREVIOUS_MANIFEST_SOURCE_MISMATCH",
            "commit-lineage не связан с доказанной previousActivation",
        )
    operation_id = rollback_operation_id_v2(evidence)
    manifest = copy.deepcopy(dict(previous_manifest))
    manifest["activeActivation"] = copy.deepcopy(dict(evidence.previous_pointer))
    manifest["previousActivation"] = copy.deepcopy(dict(evidence.current_pointer))
    manifest["lastCommittedOperation"] = operation_id
    if installer_source_digest is not None:
        if (
            type(installer_source_digest) is not str
            or _SHA256.fullmatch(installer_source_digest) is None
        ):
            _fail(
                "ROLLBACK_INSTALLER_SOURCE_DIGEST_INVALID",
                "отпечаток исходников предыдущей установки неверен",
            )
        extensions = manifest.get("extensions")
        if type(extensions) is not dict:
            _fail(
                "ROLLBACK_PREVIOUS_MANIFEST_SOURCE_MISMATCH",
                "предыдущий манифест не содержит extensions",
            )
        existing_digest = extensions.get("installerSourceDigest")
        if existing_digest is not None and existing_digest != installer_source_digest:
            _fail(
                "ROLLBACK_INSTALLER_SOURCE_DIGEST_MISMATCH",
                "архивная квитанция расходится с предыдущим манифестом",
            )
        manifest["extensions"] = {
            **copy.deepcopy(extensions),
            "installerSourceDigest": installer_source_digest,
        }
    manifest_raw_sha256 = hashlib.sha256(_canonical(manifest)).hexdigest()
    prepared_path = prepared_root / (
        f"{operation_id}.{manifest_raw_sha256}.rollback-manifest.json"
    )
    previous_tree = evidence.previous_activation_projection.value.get("directory")
    previous_tree_sha256 = (
        None if type(previous_tree) is not dict else previous_tree.get("treeSha256")
    )
    if (
        not isinstance(previous_tree_sha256, str)
        or _SHA256.fullmatch(previous_tree_sha256) is None
    ):
        _fail(
            "ROLLBACK_PREVIOUS_ACTIVATION_INCOMPLETE",
            "previousActivation не содержит treeSha256",
        )
    intent = RollbackManifestPreparationIntentV2(
        installation_id=evidence.installation_id,
        operation_id=operation_id,
        current_operation_id=evidence.current_operation_id,
        previous_operation_id=evidence.previous_operation_id,
        current_activation_id=evidence.current_activation_id,
        previous_activation_id=evidence.previous_activation_id,
        evidence_fingerprint=evidence.evidence_fingerprint,
        current_preparation_receipt_path=current_preparation_receipt_path,
        current_preparation_receipt_fingerprint=source.receipt_fingerprint,
        current_preparation_receipt_sha256=source.raw_sha256,
        transition_proof_snapshot_fingerprint=lineage.lineage_fingerprint,
        current_manifest_raw_sha256=hashlib.sha256(
            _canonical(evidence.manifest_document)
        ).hexdigest(),
        current_manifest_file_projection=evidence.manifest_file_projection,
        projection_schema_sha256=evidence.current_manifest_projection.schema_sha256,
        previous_activation_tree_sha256=previous_tree_sha256,
        target_path=evidence.manifest_path,
        prepared_path=prepared_path,
        manifest_document=manifest,
        manifest_raw_sha256=manifest_raw_sha256,
    )
    definition = RollbackManifestPreparationDefinitionV2(
        journal_path=journal_path,
        receipt_path=receipt_path,
        lock_path=lock_path,
        activation_intent=intent,
    )
    for directory, label in (
        (journal_path.parent, "journal parent"),
        (receipt_path.parent, "receipt parent"),
        (lock_path.parent, "lock parent"),
        (prepared_root, "prepared root"),
    ):
        _validate_private_directory(directory, label)
    return RollbackManifestPreparationV2(definition=definition)


def prepared_rollback_manifest_from_receipt_v2(
    receipt: RollbackManifestPreparationReceiptV2 | Mapping[str, Any] | Path,
    evidence: RollbackEvidenceV2,
) -> PreparedManifestCommitV2:
    """Восстановить общий primitive из квитанции до или после rename."""

    if isinstance(receipt, Path):
        receipt = RollbackManifestPreparationReceiptV2.from_path(receipt)
    elif not isinstance(receipt, RollbackManifestPreparationReceiptV2):
        receipt = RollbackManifestPreparationReceiptV2.from_document(receipt)
    if not isinstance(evidence, RollbackEvidenceV2):
        raise TypeError("evidence must be RollbackEvidenceV2")
    if evidence.evidence_fingerprint != domain_fingerprint(
        "codex-smart/rollback-evidence/v2",
        _rollback_evidence_projection(
            evidence,
            transition_proof_fingerprint=evidence.transition_proof_fingerprint,
        ),
    ):
        _fail(
            "ROLLBACK_PREPARATION_EVIDENCE_INVALID",
            "evidenceFingerprint не совпал со статическим доказательством",
        )
    if (
        receipt.installation_id != evidence.installation_id
        or receipt.current_operation_id != evidence.current_operation_id
        or receipt.previous_operation_id != evidence.previous_operation_id
        or receipt.current_activation_id != evidence.current_activation_id
        or receipt.previous_activation_id != evidence.previous_activation_id
        or receipt.evidence_fingerprint != evidence.evidence_fingerprint
        or receipt.target_path != evidence.manifest_path
        or receipt.operation_id != rollback_operation_id_v2(evidence)
    ):
        _fail(
            "ROLLBACK_PREPARATION_RECEIPT_EVIDENCE_MISMATCH",
            "квитанция принадлежит иному доказательству отката",
        )
    try:
        source_receipt = _read_canonical_private_json(
            receipt.current_preparation_receipt_path,
            "transition source receipt",
        )
    except Exception as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREPARATION_RECEIPT_CHANGED", str(exc)
        ) from exc
    try:
        lineage = ActivationTransitionLineageV2.from_document(
            evidence.current_receipt["transitionLineage"]
        )
    except Exception as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREPARATION_RECEIPT_CHANGED",
            f"current commit lineage повреждён: {exc}",
        ) from exc
    source = lineage.source_receipt
    if (
        source is None
        or source.path != receipt.current_preparation_receipt_path
        or source.receipt_fingerprint
        != receipt.current_preparation_receipt_fingerprint
        or hashlib.sha256(_canonical(source_receipt)).hexdigest()
        != receipt.current_preparation_receipt_sha256
        or source_receipt.get("receiptFingerprint")
        != receipt.current_preparation_receipt_fingerprint
        or lineage.lineage_fingerprint
        != receipt.transition_proof_snapshot_fingerprint
        or evidence.previous_receipt.get("manifestDocument", {}).get(
            "activeActivation"
        )
        != dict(evidence.previous_pointer)
    ):
        _fail(
            "ROLLBACK_PREPARATION_RECEIPT_CHANGED",
            "исходная prep-квитанция или её снимок изменились",
        )
    source_exists = _lexists(receipt.prepared_path)
    target_document = _read_canonical_private_json(
        receipt.target_path, "rollback manifest target"
    )
    target_file = capture_file_projection_v2(
        receipt.target_path,
        schema_sha256=receipt.expected_after.schema_sha256,
    )
    target_is_before = target_document == dict(
        evidence.manifest_document
    ) and target_file.value == dict(evidence.manifest_file_projection)
    target_is_after = (
        target_document == dict(receipt.manifest_document)
        and target_file.value == receipt.expected_after.value.get("file")
        and _manifest_projection(receipt.target_path, target_document)
        == receipt.expected_after
    )
    if source_exists and target_is_before:
        try:
            _reverify_rollback_evidence(evidence)
        except InstallerRecoveryV2Error as exc:
            raise RollbackManifestPreparationV2Error(
                "ROLLBACK_PREPARATION_EVIDENCE_CHANGED", str(exc)
            ) from exc
        observed_file = capture_file_projection_v2(
            receipt.prepared_path,
            schema_sha256=receipt.prepared_manifest_file.schema_sha256,
        )
        observed_parent = capture_directory_binding_v2(
            receipt.prepared_path.parent,
            schema_sha256=receipt.prepared_manifest_parent.schema_sha256,
        )
        if (
            observed_file != receipt.prepared_manifest_file
            or observed_parent != receipt.prepared_manifest_parent
            or _read_canonical_private_json(
                receipt.prepared_path, "prepared rollback manifest"
            )
            != dict(receipt.manifest_document)
        ):
            _fail(
                "ROLLBACK_PREPARATION_SOURCE_CHANGED",
                "prepared source изменился до manifest_restore",
            )
    elif not source_exists and target_is_after:
        # Атомарный rename сохраняет inode source в точном expectedAfter.
        pass
    else:
        _fail(
            "ROLLBACK_PREPARATION_TRANSITION_AMBIGUOUS",
            "source и target не равны допустимому BEFORE или AFTER",
        )
    prepared = PreparedManifestCommitV2(
        activation_proof_fingerprint=evidence.evidence_fingerprint,
        operation_id=receipt.operation_id,
        activation_id=evidence.previous_activation_id,
        activation_tree_sha256=receipt.previous_activation_tree_sha256,
        target_path=receipt.target_path,
        prepared_path=receipt.prepared_path,
        prepared_parent_device=int(receipt.prepared_manifest_parent.value["device"]),
        prepared_parent_inode=int(receipt.prepared_manifest_parent.value["inode"]),
        manifest_document=receipt.manifest_document,
        prepared_raw=_canonical(receipt.manifest_document),
        prepared_file_projection=receipt.prepared_manifest_file.value,
        prepared_file=receipt.prepared_manifest_file,
        expected_after=receipt.expected_after,
        preparation_fingerprint="0" * 64,
    )
    prepared = replace(
        prepared,
        preparation_fingerprint=_prepared_manifest_fingerprint(prepared),
    )
    if not prepared.complete:
        _fail(
            "ROLLBACK_PREPARATION_COMMIT_INVALID",
            "PreparedManifestCommitV2 не замкнут",
        )
    return prepared


def _logical_document(intent: RollbackManifestPreparationIntentV2) -> dict[str, Any]:
    projection = {
        "path": str(intent.prepared_path),
        "objectType": "regular-file",
        "mode": "0600",
        "contentSha256": intent.manifest_raw_sha256,
    }
    return {
        **projection,
        "logicalFingerprint": domain_fingerprint(_LOGICAL_DOMAIN, projection),
    }


def _step_document(
    *,
    intent: RollbackManifestPreparationIntentV2,
    state: str,
    intent_at: datetime | None,
    completed_at: datetime | None,
    observed: ProjectionV2 | None,
    companions: tuple[ProjectionV2, ...],
) -> dict[str, Any]:
    step_id = (
        "rpst2_"
        + domain_fingerprint(
            _STEP_ID_DOMAIN,
            {"operationId": intent.operation_id, "ordinal": 1},
        )[:32]
    )
    projection = {
        "stepId": step_id,
        "ordinal": 1,
        "kind": "rollback_manifest_file",
        "state": state,
        "expectedLogical": _logical_document(intent),
        "observedPhysical": None if observed is None else observed.to_document(),
        "observedCompanions": [item.to_document() for item in companions],
        "intentAt": None if intent_at is None else _timestamp(intent_at),
        "completedAt": (None if completed_at is None else _timestamp(completed_at)),
    }
    return {
        **projection,
        "stepFingerprint": domain_fingerprint(_STEP_DOMAIN, projection),
    }


def _with_journal_fingerprint(document: Mapping[str, Any]) -> dict[str, Any]:
    projection = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key != "journalFingerprint"
    }
    return {
        **projection,
        "journalFingerprint": domain_fingerprint(_JOURNAL_DOMAIN, projection),
    }


def _validate_journal(
    definition: RollbackManifestPreparationDefinitionV2,
    document: Mapping[str, Any],
) -> None:
    expected = {
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
        "journalFingerprint",
    }
    _exact_keys(document, expected, "journal")
    intent = definition.activation_intent
    if (
        document["schemaVersion"] != 2
        or document["journalKind"] != _JOURNAL_KIND
        or document["installationId"] != intent.installation_id
        or document["operationId"] != intent.operation_id
        or document["definitionFingerprint"] != definition.definition_fingerprint
        or document["definition"] != definition.to_document()
        or document["journalFingerprint"]
        != _with_journal_fingerprint(document)["journalFingerprint"]
    ):
        _fail(
            "ROLLBACK_PREPARATION_JOURNAL_INVALID",
            "заголовок или отпечаток журнала расходится",
        )
    boundary = document["intentBoundary"]
    if (
        type(boundary) is not dict
        or set(boundary) != {"kind", "state", "intentFingerprint", "completedAt"}
        or boundary.get("kind") != "preparation_intent"
        or boundary.get("state") != "COMPLETED"
        or boundary.get("intentFingerprint") != intent.intent_fingerprint
    ):
        _fail(
            "ROLLBACK_PREPARATION_JOURNAL_INVALID",
            "preparation_intent не совпал",
        )
    _parse_timestamp(boundary["completedAt"], "intentBoundary.completedAt")
    steps = document["steps"]
    if type(steps) is not list or len(steps) != 1 or type(steps[0]) is not dict:
        _fail("ROLLBACK_PREPARATION_JOURNAL_INVALID", "журнал должен иметь один шаг")
    step = steps[0]
    expected_step_keys = {
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
    }
    _exact_keys(step, expected_step_keys, "step")
    step_projection = {
        key: copy.deepcopy(value)
        for key, value in step.items()
        if key != "stepFingerprint"
    }
    expected_step_id = (
        "rpst2_"
        + domain_fingerprint(
            _STEP_ID_DOMAIN,
            {"operationId": intent.operation_id, "ordinal": 1},
        )[:32]
    )
    if (
        step["stepId"] != expected_step_id
        or step["ordinal"] != 1
        or step["kind"] != "rollback_manifest_file"
        or step["expectedLogical"] != _logical_document(intent)
        or step["stepFingerprint"] != domain_fingerprint(_STEP_DOMAIN, step_projection)
    ):
        _fail(
            "ROLLBACK_PREPARATION_JOURNAL_INVALID",
            "подготовительный шаг расходится",
        )
    state = step["state"]
    if state == "PLANNED":
        valid_state = (
            step["intentAt"] is None
            and step["completedAt"] is None
            and step["observedPhysical"] is None
            and step["observedCompanions"] == []
        )
    elif state == "INTENT_DURABLE":
        valid_state = (
            step["intentAt"] is not None
            and step["completedAt"] is None
            and step["observedPhysical"] is None
            and step["observedCompanions"] == []
        )
    elif state == "COMPLETED":
        valid_state = (
            step["intentAt"] is not None
            and step["completedAt"] is not None
            and type(step["observedPhysical"]) is dict
            and type(step["observedCompanions"]) is list
            and len(step["observedCompanions"]) == 1
        )
        if valid_state:
            _validate_projection(
                ProjectionV2.from_document(step["observedPhysical"]),
                "file-object-v2",
                "codex-smart/file-object/v2",
            )
            _validate_projection(
                ProjectionV2.from_document(step["observedCompanions"][0]),
                "directory-binding-v2",
                "codex-smart/directory-binding/v2",
            )
    else:
        valid_state = False
    if not valid_state:
        _fail("ROLLBACK_PREPARATION_JOURNAL_INVALID", "состояние шага неверно")
    if step["intentAt"] is not None:
        _parse_timestamp(step["intentAt"], "step.intentAt")
    if step["completedAt"] is not None:
        _parse_timestamp(step["completedAt"], "step.completedAt")
    phase = document["phase"]
    if phase == "PREPARING":
        valid_phase = (
            document["frozenAt"] is None
            and document["frozenJournalFingerprint"] is None
        )
    elif phase == "PREPARATION_FROZEN":
        frozen_projection = copy.deepcopy(dict(document))
        frozen_projection["frozenJournalFingerprint"] = None
        frozen_projection.pop("journalFingerprint", None)
        valid_phase = (
            state == "COMPLETED"
            and document["frozenAt"] is not None
            and document["frozenJournalFingerprint"]
            == domain_fingerprint(_FROZEN_JOURNAL_DOMAIN, frozen_projection)
        )
    else:
        valid_phase = False
    if not valid_phase:
        _fail("ROLLBACK_PREPARATION_JOURNAL_INVALID", "фаза журнала неверна")
    if (
        type(document["contentGeneration"]) is not int
        or document["contentGeneration"] < 0
    ):
        _fail(
            "ROLLBACK_PREPARATION_JOURNAL_INVALID",
            "contentGeneration неверен",
        )
    for name in ("createdAt", "updatedAt"):
        _parse_timestamp(document[name], name)
    if document["frozenAt"] is not None:
        _parse_timestamp(document["frozenAt"], "frozenAt")


def _validate_projection(projection: ProjectionV2, schema_id: str, domain: str) -> None:
    if not isinstance(projection, ProjectionV2) or projection.schema_id != schema_id:
        _fail(
            "ROLLBACK_PREPARATION_PROJECTION_INVALID",
            f"проекция {schema_id} имеет иной тип",
        )
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    if projection.value_fingerprint != domain_fingerprint(domain, envelope):
        _fail(
            "ROLLBACK_PREPARATION_PROJECTION_INVALID",
            f"valueFingerprint {schema_id} не совпал",
        )


def _canonical(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(dict(value))


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("ROLLBACK_PREPARATION_TIMESTAMP_INVALID", "timestamp не aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        _fail("ROLLBACK_PREPARATION_TIMESTAMP_INVALID", f"{label} не строка")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREPARATION_TIMESTAMP_INVALID", f"{label}: {exc}"
        ) from exc
    if parsed.tzinfo is None:
        _fail(
            "ROLLBACK_PREPARATION_TIMESTAMP_INVALID",
            f"{label} не содержит часовой пояс",
        )
    return parsed.astimezone(timezone.utc)


def _validate_private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RollbackManifestPreparationV2Error(
            "ROLLBACK_PREPARATION_DIRECTORY_INVALID",
            f"{label} недоступен: {exc}",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != __import__("os").getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail(
            "ROLLBACK_PREPARATION_DIRECTORY_INVALID",
            f"{label} не является частным каталогом 0700",
        )


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        _fail("ROLLBACK_PREPARATION_PATH_INVALID", f"{label} не абсолютный Path")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("ROLLBACK_PREPARATION_DOCUMENT_INVALID", f"{label} не строка")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("ROLLBACK_PREPARATION_DOCUMENT_INVALID", f"{label} не объект")
    return copy.deepcopy(value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(
            "ROLLBACK_PREPARATION_DOCUMENT_INVALID",
            f"поля {label} расходятся",
        )


def _fail(code: str, message: str):
    raise RollbackManifestPreparationV2Error(code, message)


__all__ = [
    "InjectedRollbackManifestPreparationCrashV2",
    "ROLLBACK_JOURNAL_KIND_V2",
    "RollbackManifestPreparationDefinitionV2",
    "RollbackManifestPreparationExecutorV2",
    "RollbackManifestPreparationFailurePointV2",
    "RollbackManifestPreparationIntentV2",
    "RollbackManifestPreparationPathsV2",
    "RollbackManifestPreparationReceiptV2",
    "RollbackManifestPreparationV2",
    "RollbackManifestPreparationV2Error",
    "build_rollback_manifest_preparation_v2",
    "prepared_rollback_manifest_from_receipt_v2",
    "rollback_manifest_preparation_paths_v2",
    "rollback_operation_id_v2",
]
