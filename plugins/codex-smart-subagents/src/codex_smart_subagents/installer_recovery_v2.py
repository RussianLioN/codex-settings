"""Строгие адаптеры отката и восстановления установщика версии 2.

Модуль не выбирает новые идентификаторы и не угадывает состояние. Откат
строится только из текущего манифеста, двух связанных квитанций фиксации и
физически неизменившейся предыдущей активации. Восстановление продолжает
ровно один найденный долговечный журнал через его штатный исполнитель.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, ContextManager, Mapping

from .activation_preparation_v2 import (
    ActivationPreparationV2Error,
    ActivationPreparationExecutorV2,
    capture_file_projection_v2,
    capture_tree_projection_v2,
)
from .activation_transition_v2 import (
    ActivationTransitionProofV2,
    reverify_activation_transition_proof_v2,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .lifecycle_controller_protocol_v2 import (
    LifecycleControllerCommandProofV2,
    LifecycleControllerPortV2,
)
from .lifecycle_operation_v2 import (
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    FailurePointV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationRunV2,
    ProjectionV2,
    StepCallbacksV2,
    TerminalCallbacksV2,
)
from .lifecycle_plan_v2 import LifecyclePlanRegistryV2


JsonObject = dict[str, Any]
FailureInjectorV2 = Callable[[FailurePointV2, str], None]
RollbackDefinitionFactoryV2 = Callable[
    ["RollbackEvidenceV2", Any], OperationDefinitionV2
]

_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_PLAN_ID = re.compile(r"^pl2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_COMMAND_ID = re.compile(r"^cc2_[0-9a-f]{32}$")
_STEP_ID = re.compile(r"^st2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_DOMAIN = "codex-smart/activation-commit-receipt/v2"
_EVIDENCE_DOMAIN = "codex-smart/rollback-evidence/v2"
_PROJECTION_DOMAINS = {
    "manifest-v2": "codex-smart/journal-state/v2",
    "activation-v2": "codex-smart/journal-state/v2",
    "database-binding-v2": "codex-smart/database-binding/v2",
    "absence-proof-v2": "codex-smart/absence-proof-projection/v2",
}
_RECEIPT_KEYS = {
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


@dataclass
class InstallerRecoveryV2Error(RuntimeError):
    """Отказ адаптера с устойчивым машинным кодом."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class RollbackEvidenceV2:
    """Замкнутое доказательство одной допустимой предыдущей активации."""

    manifest_path: Path
    receipts_root: Path
    activations_root: Path
    marketplace_link: Path
    installation_id: str
    current_operation_id: str
    previous_operation_id: str
    current_activation_id: str
    previous_activation_id: str
    current_pointer: Mapping[str, Any]
    previous_pointer: Mapping[str, Any]
    manifest_document: Mapping[str, Any]
    manifest_file_projection: Mapping[str, Any]
    current_receipt_path: Path
    previous_receipt_path: Path
    current_receipt: Mapping[str, Any]
    previous_receipt: Mapping[str, Any]
    current_manifest_projection: ProjectionV2
    current_activation_projection: ProjectionV2
    previous_activation_projection: ProjectionV2
    previous_database_binding: ProjectionV2
    evidence_fingerprint: str
    transition_proof_fingerprint: str | None = None
    transition_proof: ActivationTransitionProofV2 | None = None

    def __post_init__(self) -> None:
        for name in (
            "current_pointer",
            "previous_pointer",
            "manifest_document",
            "manifest_file_projection",
            "current_receipt",
            "previous_receipt",
        ):
            object.__setattr__(self, name, copy.deepcopy(dict(getattr(self, name))))


@dataclass(frozen=True)
class _RollbackCommitChainV2:
    """Каноническая пара current -> predecessor для одного отката."""

    current_operation_id: str
    previous_operation_id: str
    current_receipt_path: Path
    previous_receipt_path: Path
    current_receipt: Mapping[str, Any]
    previous_receipt: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "current_receipt",
            copy.deepcopy(dict(self.current_receipt)),
        )
        object.__setattr__(
            self,
            "previous_receipt",
            copy.deepcopy(dict(self.previous_receipt)),
        )


@dataclass(frozen=True)
class RollbackPlanV2:
    evidence: RollbackEvidenceV2
    definition: OperationDefinitionV2 | None
    step_kinds: tuple[str, ...]


@dataclass(frozen=True)
class RecoveryInspectionV2:
    journal_kind: str
    journal_path: Path | None
    installation_id: str | None
    operation_id: str | None
    document: Mapping[str, Any] | None
    document_sha256: str | None

    def __post_init__(self) -> None:
        if self.document is not None:
            object.__setattr__(self, "document", copy.deepcopy(dict(self.document)))


@dataclass(frozen=True)
class PreparationJournalRecoveryV2:
    executor: ActivationPreparationExecutorV2


@dataclass(frozen=True)
class ControllerRecoveryIntentV2:
    """Точная, ранее долговечно выбранная команда ``controller_recover``."""

    operation_id: str
    activation_id: str
    database_id: str
    expected_command_id: str
    pid: int
    process_start_marker: str
    process_group_id: int

    def __post_init__(self) -> None:
        _identifier(self.operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
        _identifier(self.activation_id, _ACTIVATION_ID, "ACTIVATION_ID_INVALID")
        _identifier(self.database_id, _DATABASE_ID, "DATABASE_ID_INVALID")
        _identifier(self.expected_command_id, _COMMAND_ID, "COMMAND_ID_INVALID")
        if type(self.pid) is not int or self.pid <= 0:
            _fail("PROCESS_IDENTITY_INVALID", "pid кандидата неверен")
        if type(self.process_group_id) is not int or self.process_group_id <= 0:
            _fail("PROCESS_IDENTITY_INVALID", "группа кандидата неверна")
        if (
            not isinstance(self.process_start_marker, str)
            or not self.process_start_marker
            or len(self.process_start_marker) > 256
        ):
            _fail("PROCESS_IDENTITY_INVALID", "маркер старта кандидата неверен")

    def execute(
        self, port: LifecycleControllerPortV2
    ) -> LifecycleControllerCommandProofV2:
        """Выполнить только отдельный recovery-метод с сохранённым commandId."""

        method = getattr(port, "candidate_recover", None)
        if not callable(method):
            _fail(
                "CONTROLLER_RECOVERY_PORT_REQUIRED",
                "порт не реализует candidate_recover",
            )
        _require_restored_controller_command_id(port, self)
        proof = method(
            operation_id=self.operation_id,
            activation_id=self.activation_id,
            database_id=self.database_id,
            pid=self.pid,
            process_start_marker=self.process_start_marker,
            process_group_id=self.process_group_id,
        )
        _validate_controller_recovery_proof(self, proof)
        return proof


@dataclass(frozen=True)
class MainJournalRecoveryV2:
    executor: OperationExecutorV2
    definition: OperationDefinitionV2
    callbacks: StepCallbacksV2
    installation_lock: Callable[[], ContextManager[None]]
    terminal_callbacks: TerminalCallbacksV2 | None = None
    controller_recovery: ControllerRecoveryIntentV2 | None = None
    controller_port: LifecycleControllerPortV2 | None = None
    execute_operation: Callable[..., Any] | None = None


@dataclass(frozen=True)
class RecoveryPlanV2:
    inspection: RecoveryInspectionV2
    preparation: PreparationJournalRecoveryV2 | None = None
    main: MainJournalRecoveryV2 | None = None


@dataclass(frozen=True)
class InstallerLifecycleAdapterResultV2:
    command: str
    status: str
    operation_id: str | None
    journal_kind: str | None
    run: OperationRunV2 | None = None


def read_rollback_v2(
    *,
    manifest_path: Path,
    receipts_root: Path,
    activations_root: Path,
    marketplace_link: Path,
) -> RollbackEvidenceV2:
    """Прочитать и физически доказать единственную цель отката."""

    manifest_path = _absolute_path(manifest_path, "MANIFEST_PATH_INVALID")
    receipts_root = _private_directory(receipts_root, "RECEIPTS_ROOT_INVALID")
    activations_root = _private_directory(activations_root, "ACTIVATIONS_ROOT_INVALID")
    marketplace_link = _absolute_path(marketplace_link, "MARKETPLACE_LINK_INVALID")
    manifest, manifest_raw = _read_private_canonical_json(
        manifest_path, "ROLLBACK_MANIFEST_INVALID"
    )
    if manifest.get("schemaVersion") != 2:
        _fail("ROLLBACK_MANIFEST_INVALID", "версия манифеста не равна 2")
    installation_id = _identifier(
        manifest.get("installationId"),
        _INSTALLATION_ID,
        "ROLLBACK_MANIFEST_INVALID",
    )
    current_operation_id = _identifier(
        manifest.get("lastCommittedOperation"),
        _OPERATION_ID,
        "ROLLBACK_MANIFEST_INVALID",
    )
    current_pointer = _activation_pointer(
        manifest.get("activeActivation"), "ROLLBACK_ACTIVE_POINTER_INVALID"
    )
    previous_pointer = _activation_pointer(
        manifest.get("previousActivation"), "ROLLBACK_PREVIOUS_MISSING"
    )
    current_activation_id = str(current_pointer["activationId"])
    previous_activation_id = str(previous_pointer["activationId"])
    if current_activation_id == previous_activation_id:
        _fail(
            "ROLLBACK_PREVIOUS_INVALID",
            "текущая и предыдущая активации совпадают",
        )
    _validate_pointer_target(current_pointer, activations_root)
    _validate_pointer_target(previous_pointer, activations_root)
    observed_target = _read_owned_symlink(marketplace_link)
    if observed_target != current_pointer["symlinkTarget"]:
        _fail(
            "ROLLBACK_ACTIVE_LINK_CHANGED",
            "рабочая ссылка не совпадает с activeActivation",
        )

    commit_chain = _load_canonical_rollback_commit_chain_v2(
        receipts_root=receipts_root,
        installation_id=installation_id,
        current_operation_id=current_operation_id,
        current_activation_id=current_activation_id,
        previous_activation_id=previous_activation_id,
    )
    previous_operation_id = commit_chain.previous_operation_id
    current_receipt_path = commit_chain.current_receipt_path
    previous_receipt_path = commit_chain.previous_receipt_path
    current_receipt = commit_chain.current_receipt
    previous_receipt = commit_chain.previous_receipt

    manifest_file = capture_file_projection_v2(
        manifest_path,
        schema_sha256=str(current_receipt["manifest"]["schemaSha256"]),
    )
    if current_receipt["manifest"]["value"].get("file") != manifest_file.value:
        _fail(
            "ROLLBACK_CURRENT_RECEIPT_CHANGED",
            "текущая квитанция не связывает наблюдаемый манифест",
        )
    _validate_receipt_activation_live(
        current_receipt,
        pointer=current_pointer,
        activations_root=activations_root,
    )
    _validate_receipt_activation_live(
        previous_receipt,
        pointer=previous_pointer,
        activations_root=activations_root,
    )

    current_manifest_projection = ProjectionV2.from_document(
        current_receipt["manifest"]
    )
    current_activation_projection = ProjectionV2.from_document(
        current_receipt["activation"]
    )
    previous_activation_projection = ProjectionV2.from_document(
        previous_receipt["activation"]
    )
    previous_database_binding = ProjectionV2.from_document(
        previous_receipt["databaseBinding"]
    )
    projection = {
        "installationId": installation_id,
        "currentOperationId": current_operation_id,
        "previousOperationId": previous_operation_id,
        "currentActivationId": current_activation_id,
        "previousActivationId": previous_activation_id,
        "manifestSha256": _sha256_bytes(manifest_raw),
        "currentReceiptFingerprint": current_receipt["receiptFingerprint"],
        "previousReceiptFingerprint": previous_receipt["receiptFingerprint"],
        "currentLinkTarget": observed_target,
    }
    return RollbackEvidenceV2(
        manifest_path=manifest_path,
        receipts_root=receipts_root,
        activations_root=activations_root,
        marketplace_link=marketplace_link,
        installation_id=installation_id,
        current_operation_id=current_operation_id,
        previous_operation_id=previous_operation_id,
        current_activation_id=current_activation_id,
        previous_activation_id=previous_activation_id,
        current_pointer=current_pointer,
        previous_pointer=previous_pointer,
        manifest_document=manifest,
        manifest_file_projection=manifest_file.value,
        current_receipt_path=current_receipt_path,
        previous_receipt_path=previous_receipt_path,
        current_receipt=current_receipt,
        previous_receipt=previous_receipt,
        current_manifest_projection=current_manifest_projection,
        current_activation_projection=current_activation_projection,
        previous_activation_projection=previous_activation_projection,
        previous_database_binding=previous_database_binding,
        evidence_fingerprint=domain_fingerprint(_EVIDENCE_DOMAIN, projection),
    )


def read_rollback_from_transition_v2(
    *, proof: ActivationTransitionProofV2
) -> RollbackEvidenceV2:
    """Предпочтительный вход: связать откат с полным снимком перехода."""

    if not isinstance(proof, ActivationTransitionProofV2):
        _fail(
            "ACTIVATION_TRANSITION_PROOF_REQUIRED",
            "требуется ActivationTransitionProofV2",
        )
    try:
        reverify_activation_transition_proof_v2(proof)
    except Exception as exc:
        raise InstallerRecoveryV2Error(
            "ACTIVATION_TRANSITION_PROOF_CHANGED", str(exc)
        ) from exc
    evidence = read_rollback_v2(
        manifest_path=proof.layout.manifest_path,
        receipts_root=proof.layout.receipts_root / proof.installation_id,
        activations_root=proof.layout.managed_root / "activations",
        marketplace_link=proof.layout.marketplace_link,
    )
    if (
        evidence.installation_id != proof.installation_id
        or evidence.current_operation_id != proof.current_operation_id
        or evidence.current_activation_id != proof.activation_id
        or evidence.current_receipt_path != proof.commit_receipt_path
        or evidence.current_receipt != dict(proof.commit_receipt_document)
        or evidence.current_manifest_projection != proof.manifest_projection
        or evidence.current_activation_projection != proof.activation_projection
    ):
        _fail(
            "ACTIVATION_TRANSITION_PROOF_MISMATCH",
            "снимок перехода и доказательства rollback расходятся",
        )
    projection = _rollback_evidence_projection(
        evidence, transition_proof_fingerprint=proof.proof_fingerprint
    )
    return replace(
        evidence,
        evidence_fingerprint=domain_fingerprint(_EVIDENCE_DOMAIN, projection),
        transition_proof_fingerprint=proof.proof_fingerprint,
        transition_proof=proof,
    )


def plan_rollback_v2(
    *,
    evidence: RollbackEvidenceV2,
    registry: LifecyclePlanRegistryV2,
    plan_id: str,
    build_definition: RollbackDefinitionFactoryV2 | None,
) -> RollbackPlanV2:
    """Построить чистый нормативный план, не создавая журнал и эффектов."""

    if not isinstance(evidence, RollbackEvidenceV2):
        _fail("ROLLBACK_EVIDENCE_REQUIRED", "доказательство отката отсутствует")
    if not isinstance(registry, LifecyclePlanRegistryV2):
        _fail("ROLLBACK_PLAN_REGISTRY_REQUIRED", "реестр планов версии 2 обязателен")
    _identifier(plan_id, _PLAN_ID, "ROLLBACK_PLAN_ID_INVALID")
    if build_definition is not None and not callable(build_definition):
        _fail("ROLLBACK_DEFINITION_REQUIRED", "сборщик определения отсутствует")
    _reverify_rollback_evidence(evidence)
    execution_plan = registry.select(
        machine_id="rollback",
        branch_id="rollback-matched-active",
        plan_id=plan_id,
    )
    definition = (
        None if build_definition is None else build_definition(evidence, execution_plan)
    )
    if definition is not None:
        _validate_rollback_definition(evidence, execution_plan, definition)
    return RollbackPlanV2(
        evidence=evidence,
        definition=definition,
        step_kinds=execution_plan.composed_step_kinds,
    )


def execute_rollback_v2(
    *,
    plan: RollbackPlanV2,
    preview: bool,
    executor: OperationExecutorV2 | None = None,
    callbacks: StepCallbacksV2 | None = None,
    terminal_callbacks: TerminalCallbacksV2 | None = None,
    installation_lock: Callable[[], ContextManager[None]] | None = None,
    failure_injector: FailureInjectorV2 | None = None,
) -> InstallerLifecycleAdapterResultV2:
    """Показать либо выполнить ровно уже построенный rollback-план."""

    if not isinstance(plan, RollbackPlanV2):
        _fail("ROLLBACK_PLAN_REQUIRED", "план отката отсутствует")
    if type(preview) is not bool:
        _fail("PREVIEW_MODE_INVALID", "preview должен быть логическим")
    if preview:
        return InstallerLifecycleAdapterResultV2(
            command="rollback",
            status="planned",
            operation_id=(
                None if plan.definition is None else plan.definition.operation_id
            ),
            journal_kind=None,
        )
    if plan.definition is None:
        _fail(
            "ROLLBACK_DEFINITION_REQUIRED",
            "применение требует подготовленного полного определения",
        )
    if (
        not isinstance(executor, OperationExecutorV2)
        or not isinstance(callbacks, StepCallbacksV2)
        or not isinstance(terminal_callbacks, TerminalCallbacksV2)
    ):
        _fail(
            "ROLLBACK_EXECUTION_CONTEXT_REQUIRED",
            "для применения нужны исполнитель и оба набора обработчиков",
        )
    if not callable(installation_lock):
        _fail(
            "INSTALLATION_LOCK_REQUIRED",
            "применение требует общей установочной блокировки",
        )
    with installation_lock():
        if executor.store.journal_path.exists():
            _fail(
                "ROLLBACK_JOURNAL_ALREADY_PRESENT",
                "новый откат не может принять существующий журнал; используйте recover",
            )
        _reverify_rollback_evidence(plan.evidence)
        run = executor.execute(
            plan.definition,
            callbacks=callbacks,
            terminal_callbacks=terminal_callbacks,
            failure_injector=failure_injector,
        )
    if run.status != "COMPLETED":
        _fail("ROLLBACK_NOT_COMPLETED", "откат не достиг терминальной квитанции")
    return InstallerLifecycleAdapterResultV2(
        command="rollback",
        status="rolled_back",
        operation_id=run.operation_id,
        journal_kind="main",
        run=run,
    )


def inspect_recovery_v2(
    *,
    journal_root: Path,
    preparation_journal_path: Path,
    rollback_preparation_journal_path: Path | None = None,
    operation_journal_path: Path,
) -> RecoveryInspectionV2:
    """Без записи классифицировать ровно один допустимый журнал."""

    journal_root = _private_directory(journal_root, "JOURNAL_ROOT_INVALID")
    preparation_journal_path = _absolute_path(
        preparation_journal_path, "PREPARATION_JOURNAL_PATH_INVALID"
    )
    operation_journal_path = _absolute_path(
        operation_journal_path, "OPERATION_JOURNAL_PATH_INVALID"
    )
    if rollback_preparation_journal_path is not None:
        rollback_preparation_journal_path = _absolute_path(
            rollback_preparation_journal_path,
            "ROLLBACK_PREPARATION_JOURNAL_PATH_INVALID",
        )
    paths = [preparation_journal_path, operation_journal_path]
    if rollback_preparation_journal_path is not None:
        paths.append(rollback_preparation_journal_path)
    if any(path.parent != journal_root for path in paths) or len(set(paths)) != len(
        paths
    ):
        _fail(
            "JOURNAL_LAYOUT_INVALID",
            "известные журналы должны различаться и лежать в journal_root",
        )
    known = set(paths)
    observed = {
        path
        for path in journal_root.glob("*.transaction.json")
        if path.exists() or path.is_symlink()
    }
    unknown = observed - known
    if unknown:
        _fail(
            "UNKNOWN_LIFECYCLE_JOURNAL",
            "найден неизвестный журнал: "
            + ", ".join(str(item) for item in sorted(unknown)),
        )
    present = [path for path in known if path.exists() or path.is_symlink()]
    if len(present) > 1:
        _fail(
            "MULTIPLE_LIFECYCLE_JOURNALS",
            "одновременно присутствуют основной и подготовительный журналы",
        )
    if not present:
        return RecoveryInspectionV2(
            journal_kind="none",
            journal_path=None,
            installation_id=None,
            operation_id=None,
            document=None,
            document_sha256=None,
        )
    path = present[0]
    document, raw = _read_private_canonical_json(path, "RECOVERY_JOURNAL_INVALID")
    if path == preparation_journal_path:
        fingerprint_domain = "codex-smart/activation-preparation-journal/v2"
    elif path == rollback_preparation_journal_path:
        fingerprint_domain = "codex-smart/rollback-manifest-preparation-journal/v2"
    else:
        fingerprint_domain = "codex-smart/operation-journal/v2"
    _validate_journal_fingerprint(document, fingerprint_domain)
    installation_id = _identifier(
        document.get("installationId"),
        _INSTALLATION_ID,
        "RECOVERY_JOURNAL_INVALID",
    )
    operation_id = _identifier(
        document.get("operationId"),
        _OPERATION_ID,
        "RECOVERY_JOURNAL_INVALID",
    )
    if path == preparation_journal_path:
        if document.get("journalKind") != "activation-preparation":
            _fail(
                "RECOVERY_JOURNAL_KIND_MISMATCH",
                "подготовительный путь содержит иной вид журнала",
            )
        kind = "preparation"
    elif path == rollback_preparation_journal_path:
        if document.get("journalKind") != "rollback-manifest-preparation":
            _fail(
                "RECOVERY_JOURNAL_KIND_MISMATCH",
                "путь подготовки отката содержит иной вид журнала",
            )
        kind = "rollback_preparation"
    else:
        if document.get("journalKind") == "activation-preparation" or not isinstance(
            document.get("kind"), str
        ):
            _fail(
                "RECOVERY_JOURNAL_KIND_MISMATCH",
                "основной путь содержит иной вид журнала",
            )
        kind = "main"
    return RecoveryInspectionV2(
        journal_kind=kind,
        journal_path=path,
        installation_id=installation_id,
        operation_id=operation_id,
        document=document,
        document_sha256=_sha256_bytes(raw),
    )


def plan_recovery_v2(
    *,
    inspection: RecoveryInspectionV2,
    preparation: PreparationJournalRecoveryV2 | None = None,
    main: MainJournalRecoveryV2 | None = None,
) -> RecoveryPlanV2:
    """Связать чтение с точным существующим исполнителем без новых ID."""

    if not isinstance(inspection, RecoveryInspectionV2):
        _fail("RECOVERY_INSPECTION_REQUIRED", "результат чтения отсутствует")
    if inspection.journal_kind == "none":
        if preparation is not None or main is not None:
            _fail(
                "RECOVERY_CONTEXT_WITHOUT_JOURNAL",
                "контекст передан без долговечного журнала",
            )
        return RecoveryPlanV2(inspection=inspection)
    if inspection.journal_kind in {"preparation", "rollback_preparation"}:
        if preparation is None or main is not None:
            _fail(
                "PREPARATION_RECOVERY_CONTEXT_REQUIRED",
                "нужен только исполнитель подготовки",
            )
        _validate_preparation_recovery(inspection, preparation)
        return RecoveryPlanV2(
            inspection=inspection,
            preparation=preparation,
        )
    if inspection.journal_kind == "main":
        if main is None or preparation is not None:
            _fail(
                "MAIN_RECOVERY_CONTEXT_REQUIRED",
                "нужен только исполнитель основного журнала",
            )
        _validate_main_recovery(inspection, main)
        return RecoveryPlanV2(inspection=inspection, main=main)
    _fail("RECOVERY_JOURNAL_UNKNOWN", "вид журнала неизвестен")


def execute_recovery_v2(
    *,
    plan: RecoveryPlanV2,
    preview: bool,
    failure_injector: FailureInjectorV2 | None = None,
) -> InstallerLifecycleAdapterResultV2:
    """Показать либо продолжить ровно журнал из ``inspection``."""

    if not isinstance(plan, RecoveryPlanV2):
        _fail("RECOVERY_PLAN_REQUIRED", "план восстановления отсутствует")
    if type(preview) is not bool:
        _fail("PREVIEW_MODE_INVALID", "preview должен быть логическим")
    inspection = plan.inspection
    if inspection.journal_kind == "none":
        return InstallerLifecycleAdapterResultV2(
            command="recover",
            status="unchanged",
            operation_id=None,
            journal_kind=None,
        )
    if preview:
        _reverify_inspection(inspection)
        return InstallerLifecycleAdapterResultV2(
            command="recover",
            status="planned",
            operation_id=inspection.operation_id,
            journal_kind=inspection.journal_kind,
        )
    if inspection.journal_kind in {"preparation", "rollback_preparation"}:
        _reverify_inspection(inspection)
        assert plan.preparation is not None
        receipt = plan.preparation.executor.recover()
        if (
            getattr(receipt, "installation_id", None) != inspection.installation_id
            or getattr(receipt, "operation_id", None) != inspection.operation_id
        ):
            _fail(
                "PREPARATION_RECOVERY_ID_CHANGED",
                "квитанция подготовки сменила долговечные идентификаторы",
            )
        return InstallerLifecycleAdapterResultV2(
            command="recover",
            status="recovered",
            operation_id=inspection.operation_id,
            journal_kind=inspection.journal_kind,
        )
    assert plan.main is not None
    with plan.main.installation_lock():
        _reverify_inspection(inspection)
        _validate_main_recovery(inspection, plan.main)
        if plan.main.controller_recovery is not None:
            assert plan.main.controller_port is not None
            plan.main.controller_recovery.execute(plan.main.controller_port)
        if plan.main.execute_operation is not None:
            run = plan.main.execute_operation(failure_injector=failure_injector)
        else:
            run = plan.main.executor.execute(
                plan.main.definition,
                callbacks=plan.main.callbacks,
                terminal_callbacks=plan.main.terminal_callbacks,
                failure_injector=failure_injector,
            )
    if run.operation_id != inspection.operation_id:
        _fail(
            "MAIN_RECOVERY_ID_CHANGED",
            "исполнитель сменил operationId существующего журнала",
        )
    return InstallerLifecycleAdapterResultV2(
        command="recover",
        status="recovered",
        operation_id=run.operation_id,
        journal_kind="main",
        run=run,
    )


def _validate_rollback_definition(
    evidence: RollbackEvidenceV2,
    execution_plan: Any,
    definition: OperationDefinitionV2,
) -> None:
    if not isinstance(definition, OperationDefinitionV2):
        _fail("ROLLBACK_DEFINITION_INVALID", "сборщик вернул иной тип")
    if (
        definition.kind != "rollback"
        or definition.operation != "rollback"
        or definition.installation_id != evidence.installation_id
        or definition.execution_plan != execution_plan
        or definition.operation_id
        in {evidence.current_operation_id, evidence.previous_operation_id}
    ):
        _fail(
            "ROLLBACK_DEFINITION_INVALID",
            "определение не связано с новым нормативным откатом",
        )
    _identifier(definition.operation_id, _OPERATION_ID, "ROLLBACK_DEFINITION_INVALID")
    if (
        definition.discovery_before.activation != evidence.current_activation_projection
        or definition.fenced_before is None
        or definition.fenced_before.activation != evidence.current_activation_projection
        or definition.desired is None
        or definition.desired.activation != evidence.previous_activation_projection
        or definition.terminal is None
        or definition.terminal.terminal_kind != "COMMIT"
    ):
        _fail(
            "ROLLBACK_DEFINITION_INVALID",
            "снимки отката не связывают текущую и previousActivation",
        )


def _validate_preparation_recovery(
    inspection: RecoveryInspectionV2,
    context: PreparationJournalRecoveryV2,
) -> None:
    executor = context.executor
    definition = getattr(executor, "definition", None)
    intent = getattr(definition, "activation_intent", None)
    reader = getattr(executor, "_read_journal", None)
    if (
        getattr(definition, "journal_path", None) != inspection.journal_path
        or getattr(intent, "installation_id", None) != inspection.installation_id
        or getattr(intent, "operation_id", None) != inspection.operation_id
        or not callable(getattr(executor, "recover", None))
        or not callable(reader)
    ):
        _fail(
            "PREPARATION_RECOVERY_CONTEXT_MISMATCH",
            "исполнитель подготовки не связан с найденным журналом",
        )
    try:
        stored = reader()
    except Exception as exc:
        raise InstallerRecoveryV2Error(
            "PREPARATION_RECOVERY_JOURNAL_INVALID", str(exc)
        ) from exc
    if stored != dict(inspection.document or {}):
        _fail(
            "PREPARATION_RECOVERY_CONTEXT_MISMATCH",
            "исполнитель прочитал иной подготовительный журнал",
        )


def _validate_main_recovery(
    inspection: RecoveryInspectionV2,
    context: MainJournalRecoveryV2,
) -> None:
    if (
        not isinstance(context.executor, OperationExecutorV2)
        or not isinstance(context.definition, OperationDefinitionV2)
        or not isinstance(context.callbacks, StepCallbacksV2)
        or not callable(context.installation_lock)
        or (
            context.execute_operation is not None
            and not callable(context.execute_operation)
        )
    ):
        _fail("MAIN_RECOVERY_CONTEXT_MISMATCH", "типы контекста неверны")
    if context.execute_operation is not None:
        operation = getattr(context.execute_operation, "__self__", None)
        if (
            getattr(operation, "executor", None) is not context.executor
            or getattr(operation, "definition", None) != context.definition
        ):
            _fail(
                "MAIN_RECOVERY_CONTEXT_MISMATCH",
                "контекстный исполнитель не связан с основным журналом",
            )
    document = dict(inspection.document or {})
    definition = context.definition
    try:
        stored = context.executor.store.read()
    except Exception as exc:
        raise InstallerRecoveryV2Error(
            "MAIN_RECOVERY_JOURNAL_INVALID", str(exc)
        ) from exc
    if stored != document:
        _fail(
            "MAIN_RECOVERY_CONTEXT_MISMATCH",
            "исполнитель прочитал иной основной журнал",
        )
    if (
        context.executor.store.journal_path != inspection.journal_path
        or definition.installation_id != inspection.installation_id
        or definition.operation_id != inspection.operation_id
        or document.get("kind") != definition.kind
        or document.get("operation") != definition.operation
    ):
        _fail(
            "MAIN_RECOVERY_CONTEXT_MISMATCH",
            "определение не связано с найденным основным журналом",
        )
    persisted_plan = document.get("executionPlan")
    if type(persisted_plan) is not dict:
        _fail("MAIN_RECOVERY_CONTEXT_MISMATCH", "в журнале нет executionPlan")
    expected = definition.execution_plan
    pairs = {
        "planId": expected.plan_id,
        "machineId": expected.machine_id,
        "selectedBranchId": expected.selected_branch_id,
        "selectionSource": expected.selection_source,
        "composedStepKinds": list(expected.composed_step_kinds),
        "planDefinitionFingerprint": expected.plan_definition_fingerprint,
    }
    if any(persisted_plan.get(name) != value for name, value in pairs.items()):
        _fail(
            "MAIN_RECOVERY_CONTEXT_MISMATCH",
            "замороженный план отличается от определения восстановления",
        )
    if (context.controller_recovery is None) != (context.controller_port is None):
        _fail(
            "CONTROLLER_RECOVERY_CONTEXT_INCOMPLETE",
            "намерение и порт должны присутствовать вместе",
        )
    if context.controller_recovery is not None:
        if context.controller_recovery.operation_id != inspection.operation_id:
            _fail(
                "CONTROLLER_RECOVERY_CONTEXT_MISMATCH",
                "controller_recover относится к другой операции",
            )
        plans = document.get("recoveryPlans")
        active = (
            plans[-1]
            if type(plans) is list and plans and type(plans[-1]) is dict
            else None
        )
        if (
            active is None
            or active.get("status") != "ACTIVE"
            or active.get("selectedRecoveryBranchId") != "controller-missing-proven"
            or active.get("overlayStepKinds")
            != [
                "controller_candidate_spawn",
                "controller_recover",
                "recovery_resume_operation",
            ]
        ):
            _fail(
                "CONTROLLER_RECOVERY_NOT_DURABLE",
                "в журнале нет точной активной ветви controller_recover",
            )
        _validate_durable_controller_recovery_steps(
            document,
            active=active,
            intent=context.controller_recovery,
        )


def _reverify_inspection(inspection: RecoveryInspectionV2) -> None:
    if inspection.journal_path is None or inspection.document is None:
        return
    document, raw = _read_private_canonical_json(
        inspection.journal_path, "RECOVERY_JOURNAL_CHANGED"
    )
    if (
        document != dict(inspection.document)
        or _sha256_bytes(raw) != inspection.document_sha256
    ):
        _fail(
            "RECOVERY_JOURNAL_CHANGED",
            "журнал изменился после построения плана; требуется новое чтение",
        )


def _reverify_rollback_evidence(evidence: RollbackEvidenceV2) -> None:
    if evidence.transition_proof is not None:
        if (
            not isinstance(evidence.transition_proof, ActivationTransitionProofV2)
            or evidence.transition_proof.proof_fingerprint
            != evidence.transition_proof_fingerprint
        ):
            _fail(
                "ACTIVATION_TRANSITION_PROOF_MISMATCH",
                "сохранён иной снимок перехода",
            )
        try:
            reverify_activation_transition_proof_v2(evidence.transition_proof)
        except Exception as exc:
            raise InstallerRecoveryV2Error(
                "ACTIVATION_TRANSITION_PROOF_CHANGED", str(exc)
            ) from exc
    if evidence.evidence_fingerprint != domain_fingerprint(
        _EVIDENCE_DOMAIN,
        _rollback_evidence_projection(
            evidence,
            transition_proof_fingerprint=evidence.transition_proof_fingerprint,
        ),
    ):
        _fail(
            "ROLLBACK_EVIDENCE_INVALID",
            "отпечаток доказательства rollback не совпал",
        )
    manifest, raw = _read_private_canonical_json(
        evidence.manifest_path, "ROLLBACK_EVIDENCE_CHANGED"
    )
    current, _ = _read_private_canonical_json(
        evidence.current_receipt_path, "ROLLBACK_EVIDENCE_CHANGED"
    )
    previous, _ = _read_private_canonical_json(
        evidence.previous_receipt_path, "ROLLBACK_EVIDENCE_CHANGED"
    )
    if (
        manifest != dict(evidence.manifest_document)
        or current != dict(evidence.current_receipt)
        or previous != dict(evidence.previous_receipt)
        or _read_owned_symlink(evidence.marketplace_link)
        != evidence.current_pointer["symlinkTarget"]
        or capture_file_projection_v2(
            evidence.manifest_path,
            schema_sha256=evidence.current_manifest_projection.schema_sha256,
        ).value
        != evidence.manifest_file_projection
        or _sha256_bytes(raw)
        != _sha256_bytes(canonical_json_bytes(evidence.manifest_document))
    ):
        _fail(
            "ROLLBACK_EVIDENCE_CHANGED",
            "доказательства отката изменились после чтения",
        )
    _validate_receipt_activation_live(
        current,
        pointer=evidence.current_pointer,
        activations_root=evidence.activations_root,
    )
    _validate_receipt_activation_live(
        previous,
        pointer=evidence.previous_pointer,
        activations_root=evidence.activations_root,
    )


def _rollback_evidence_projection(
    evidence: RollbackEvidenceV2,
    *,
    transition_proof_fingerprint: str | None,
) -> JsonObject:
    return {
        "installationId": evidence.installation_id,
        "currentOperationId": evidence.current_operation_id,
        "previousOperationId": evidence.previous_operation_id,
        "currentActivationId": evidence.current_activation_id,
        "previousActivationId": evidence.previous_activation_id,
        "manifestSha256": _sha256_bytes(
            canonical_json_bytes(evidence.manifest_document)
        ),
        "currentReceiptFingerprint": evidence.current_receipt["receiptFingerprint"],
        "previousReceiptFingerprint": evidence.previous_receipt["receiptFingerprint"],
        "currentLinkTarget": evidence.current_pointer["symlinkTarget"],
        **(
            {}
            if transition_proof_fingerprint is None
            else {"transitionProofFingerprint": transition_proof_fingerprint}
        ),
    }


def _validate_journal_fingerprint(document: Mapping[str, Any], domain: str) -> None:
    actual = document.get("journalFingerprint")
    if not isinstance(actual, str) or _SHA256.fullmatch(actual) is None:
        _fail(
            "RECOVERY_JOURNAL_INVALID",
            "journalFingerprint отсутствует или имеет неверный формат",
        )
    projection = {
        name: copy.deepcopy(value)
        for name, value in document.items()
        if name != "journalFingerprint"
    }
    if actual != domain_fingerprint(domain, projection):
        _fail(
            "RECOVERY_JOURNAL_INVALID",
            "journalFingerprint не совпал",
        )


def _validate_durable_controller_recovery_steps(
    document: Mapping[str, Any],
    *,
    active: Mapping[str, Any],
    intent: ControllerRecoveryIntentV2,
) -> None:
    steps = document.get("steps")
    plan_id = active.get("planId")
    candidate_id = active.get("candidateId")
    if type(steps) is not list or not isinstance(plan_id, str):
        _fail(
            "CONTROLLER_RECOVERY_NOT_DURABLE",
            "шаги recovery-плана отсутствуют",
        )
    candidate_steps = [
        step
        for step in steps
        if type(step) is dict
        and step.get("planId") == plan_id
        and step.get("kind") == "controller_candidate_spawn"
    ]
    recover_steps = [
        step
        for step in steps
        if type(step) is dict
        and step.get("planId") == plan_id
        and step.get("kind") == "controller_recover"
    ]
    if len(candidate_steps) != 1 or len(recover_steps) != 1:
        _fail(
            "CONTROLLER_RECOVERY_NOT_DURABLE",
            "нет единственной пары candidate_spawn/controller_recover",
        )
    candidate = candidate_steps[0]
    recover = recover_steps[0]
    candidate_action = candidate.get("action")
    observed = candidate.get("observedAfter")
    candidate_value = observed.get("value") if type(observed) is dict else None
    expected_candidate = {
        "operationId": intent.operation_id,
        "activationId": intent.activation_id,
        "databaseId": intent.database_id,
        "candidateId": candidate_id,
    }
    if (
        candidate.get("state") != "COMPLETED"
        or type(candidate_action) is not dict
        or type(candidate_value) is not dict
        or any(
            candidate_action.get(name) != value or candidate_value.get(name) != value
            for name, value in expected_candidate.items()
        )
        or candidate_value.get("pid") != intent.pid
        or candidate_value.get("processStartMarker") != intent.process_start_marker
        or candidate_value.get("processGroupId") != intent.process_group_id
    ):
        _fail(
            "CONTROLLER_RECOVERY_CANDIDATE_MISMATCH",
            "идентичность запущенного кандидата не совпала",
        )
    recover_action = recover.get("action")
    if (
        recover.get("state") not in {"PLANNED", "INTENT_DURABLE"}
        or recover.get("commandId") != intent.expected_command_id
        or type(recover_action) is not dict
        or recover_action.get("method") != "controller_recover"
        or any(
            recover_action.get(name) != value
            for name, value in {
                "operationId": intent.operation_id,
                "activationId": intent.activation_id,
                "databaseId": intent.database_id,
            }.items()
        )
    ):
        _fail(
            "CONTROLLER_RECOVERY_COMMAND_MISMATCH",
            "controller_recover не совпал с долговечным шагом",
        )


def _validate_commit_receipt(document: Mapping[str, Any]) -> JsonObject:
    receipt = copy.deepcopy(dict(document))
    if set(receipt) != _RECEIPT_KEYS:
        _fail("ROLLBACK_RECEIPT_INVALID", "поля commit-квитанции расходятся")
    if (
        receipt.get("schemaVersion") != 2
        or receipt.get("receiptKind") != "activation-commit"
    ):
        _fail("ROLLBACK_RECEIPT_INVALID", "вид commit-квитанции неверен")
    _identifier(
        receipt.get("installationId"),
        _INSTALLATION_ID,
        "ROLLBACK_RECEIPT_INVALID",
    )
    _identifier(receipt.get("operationId"), _OPERATION_ID, "ROLLBACK_RECEIPT_INVALID")
    _identifier(
        receipt.get("receiptFingerprint"),
        _SHA256,
        "ROLLBACK_RECEIPT_INVALID",
    )
    _identifier(
        receipt.get("frozenJournalFingerprint"),
        _SHA256,
        "ROLLBACK_RECEIPT_INVALID",
    )
    _identifier(
        receipt.get("controllerIdentity"),
        _SHA256,
        "ROLLBACK_RECEIPT_INVALID",
    )
    unsigned = {
        name: copy.deepcopy(value)
        for name, value in receipt.items()
        if name != "receiptFingerprint"
    }
    if receipt["receiptFingerprint"] != domain_fingerprint(_RECEIPT_DOMAIN, unsigned):
        _fail("ROLLBACK_RECEIPT_INVALID", "receiptFingerprint не совпал")
    expected_schemas = {
        "manifest": "manifest-v2",
        "activation": "activation-v2",
        "databaseBinding": "database-binding-v2",
        "journalAbsenceTarget": "absence-proof-v2",
    }
    projections: dict[str, ProjectionV2] = {}
    for field, schema_id in expected_schemas.items():
        value = receipt.get(field)
        if type(value) is not dict:
            _fail("ROLLBACK_RECEIPT_INVALID", f"{field} не является проекцией")
        try:
            projection = ProjectionV2.from_document(value)
        except Exception as exc:
            raise InstallerRecoveryV2Error(
                "ROLLBACK_RECEIPT_INVALID", f"{field} повреждён: {exc}"
            ) from exc
        if projection.schema_id != schema_id:
            _fail("ROLLBACK_RECEIPT_INVALID", f"схема {field} неверна")
        domain = _PROJECTION_DOMAINS[schema_id]
        envelope = {
            "schemaId": projection.schema_id,
            "schemaSha256": projection.schema_sha256,
            "value": copy.deepcopy(dict(projection.value)),
        }
        if projection.value_fingerprint != domain_fingerprint(domain, envelope):
            _fail(
                "ROLLBACK_RECEIPT_INVALID",
                f"valueFingerprint {field} не совпал",
            )
        projections[field] = projection

    try:
        ActivationCommitPayloadIntentV2(
            manifest=projections["manifest"],
            manifest_document=receipt["manifestDocument"],
            transition_lineage=ActivationTransitionLineageV2.from_document(
                receipt["transitionLineage"]
            ),
            activation=projections["activation"],
            database_binding=projections["databaseBinding"],
            journal_absence_target=projections["journalAbsenceTarget"],
            controller_identity=str(receipt["controllerIdentity"]),
        )
    except Exception as exc:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_RECEIPT_INVALID",
            f"manifestDocument или transitionLineage повреждены: {exc}",
        ) from exc

    manifest = projections["manifest"].value
    activation = projections["activation"].value
    database = projections["databaseBinding"].value
    absence = projections["journalAbsenceTarget"].value
    activation_identity = database.get("activationIdentity")
    completed_step_ids = receipt.get("completedStepIds")
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("installationId") != receipt["installationId"]
        or manifest.get("activeActivationId") != activation.get("activationId")
        or manifest.get("lastCommittedOperation") != receipt["operationId"]
        or database.get("databaseId") != activation.get("databaseId")
        or type(activation_identity) is not dict
        or activation_identity.get("activationId") != activation.get("activationId")
        or activation_identity.get("activationFingerprint")
        != activation.get("activationFingerprint")
        or absence.get("operationId") != receipt["operationId"]
        or type(completed_step_ids) is not list
        or not completed_step_ids
        or len(completed_step_ids) != len(set(completed_step_ids))
        or any(
            not isinstance(step_id, str) or _STEP_ID.fullmatch(step_id) is None
            for step_id in completed_step_ids
        )
    ):
        _fail(
            "ROLLBACK_RECEIPT_INVALID",
            "внутренние связи commit-квитанции расходятся",
        )
    return receipt


def _validate_receipt_activation_live(
    receipt: Mapping[str, Any],
    *,
    pointer: Mapping[str, Any],
    activations_root: Path,
) -> None:
    if receipt.get("installationId") is None:
        _fail("ROLLBACK_RECEIPT_INVALID", "installationId отсутствует")
    activation = receipt["activation"]["value"]
    if type(activation) is not dict:
        _fail("ROLLBACK_RECEIPT_INVALID", "activation.value неверен")
    expected = {
        "activationId": pointer["activationId"],
        "activationFingerprint": pointer["activationFingerprint"],
        "generationId": pointer["generationId"],
        "databaseId": pointer["databaseId"],
    }
    if any(activation.get(name) != value for name, value in expected.items()):
        _fail(
            "ROLLBACK_RECEIPT_INVALID",
            "указатель не совпадает с activation-проекцией квитанции",
        )
    activation_id = str(pointer["activationId"])
    activation_dir = activations_root / activation_id
    try:
        directory_projection = capture_tree_projection_v2(
            activation_dir,
            schema_sha256=str(receipt["activation"]["schemaSha256"]),
        )
        file_projection = capture_file_projection_v2(
            activation_dir / "activation.json",
            schema_sha256=str(receipt["activation"]["schemaSha256"]),
        )
    except (OSError, ActivationPreparationV2Error) as exc:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_ACTIVATION_CHANGED",
            f"активация не может быть доказана: {exc}",
        ) from exc
    if (
        activation.get("directory") != directory_projection.value
        or activation.get("activationFile") != file_projection.value
    ):
        _fail(
            "ROLLBACK_ACTIVATION_CHANGED",
            "физическая previousActivation не совпадает с квитанцией",
        )
    database = receipt["databaseBinding"]["value"]
    if (
        type(database) is not dict
        or database.get("databaseId") != pointer["databaseId"]
        or type(database.get("activationIdentity")) is not dict
        or database["activationIdentity"].get("activationId") != pointer["activationId"]
        or database["activationIdentity"].get("activationFingerprint")
        != pointer["activationFingerprint"]
    ):
        _fail(
            "ROLLBACK_RECEIPT_INVALID",
            "databaseBinding не связан с previousActivation",
        )
    _validate_database_binding_live(database)


def _activation_pointer(value: object, code: str) -> JsonObject:
    if type(value) is not dict or set(value) != {
        "activationId",
        "activationFingerprint",
        "symlinkTarget",
        "generationId",
        "databaseId",
    }:
        _fail(code, "указатель активации неполон")
    result = copy.deepcopy(value)
    _identifier(result["activationId"], _ACTIVATION_ID, code)
    _identifier(result["activationFingerprint"], _SHA256, code)
    if result["activationId"] != "act2_" + result["activationFingerprint"]:
        _fail(code, "activationId не связан с activationFingerprint")
    _identifier(result["databaseId"], _DATABASE_ID, code)
    generation = result["generationId"]
    if (
        not isinstance(generation, str)
        or re.fullmatch(r"^gen2_[0-9a-f]{64}$", generation) is None
    ):
        _fail(code, "generationId указателя неверен")
    if not isinstance(result["symlinkTarget"], str):
        _fail(code, "symlinkTarget указателя неверен")
    return result


def _validate_pointer_target(pointer: Mapping[str, Any], root: Path) -> None:
    activation_id = str(pointer["activationId"])
    expected = f"activations/{activation_id}/marketplace"
    if pointer["symlinkTarget"] != expected:
        _fail(
            "ROLLBACK_POINTER_TARGET_INVALID",
            "symlinkTarget не является закрытым относительным путём активации",
        )
    activation_dir = root / activation_id
    if not activation_dir.is_dir() or activation_dir.is_symlink():
        _fail(
            "ROLLBACK_ACTIVATION_MISSING",
            "каталог активации отсутствует или является ссылкой",
        )


def _receipt_activation_id(receipt: Mapping[str, Any]) -> str:
    try:
        value = receipt["activation"]["value"]["activationId"]
    except (KeyError, TypeError) as exc:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_RECEIPT_INVALID", "activationId в квитанции отсутствует"
        ) from exc
    return _identifier(value, _ACTIVATION_ID, "ROLLBACK_RECEIPT_INVALID")


def _require_unique_operation_receipt_path_v2(
    *,
    commit_paths: list[Path],
    operation_id: str,
    expected_path: Path,
    code: str,
) -> None:
    """Запретить вторую квитанцию того же operationId под иным именем."""

    matches: list[Path] = []
    for path in commit_paths:
        document, _raw = _read_private_canonical_json(
            path,
            "ROLLBACK_RECEIPT_INVALID",
        )
        if document.get("operationId") == operation_id:
            matches.append(path)
    if matches != [expected_path]:
        _fail(
            code,
            "для operationId нет единственной квитанции по каноническому пути",
        )


def _load_canonical_rollback_commit_chain_v2(
    *,
    receipts_root: Path,
    installation_id: str,
    current_operation_id: str,
    current_activation_id: str,
    previous_activation_id: str,
    expected_previous_operation_id: str | None = None,
) -> _RollbackCommitChainV2:
    """Загрузить точную текущую фиксацию и выведенного из lineage предшественника.

    Первичный откат и восстановление после перезапуска используют один путь,
    поэтому историческую квитанцию нельзя выбрать только по activationId либо
    по сохранённому вызывающим кодом previousOperationId.
    """

    receipts_root = _private_directory(
        receipts_root,
        "ROLLBACK_RECEIPTS_ROOT_INVALID",
    )
    installation_id = _identifier(
        installation_id,
        _INSTALLATION_ID,
        "ROLLBACK_RECEIPT_INVALID",
    )
    current_operation_id = _identifier(
        current_operation_id,
        _OPERATION_ID,
        "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
    )
    current_activation_id = _identifier(
        current_activation_id,
        _ACTIVATION_ID,
        "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
    )
    previous_activation_id = _identifier(
        previous_activation_id,
        _ACTIVATION_ID,
        "ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
    )
    if expected_previous_operation_id is not None:
        expected_previous_operation_id = _identifier(
            expected_previous_operation_id,
            _OPERATION_ID,
            "ROLLBACK_TRANSITION_LINEAGE_INVALID",
        )
    commit_paths = sorted(receipts_root.glob("*.commit.json"))
    if len(commit_paths) > 512:
        _fail(
            "ROLLBACK_RECEIPT_SET_TOO_LARGE",
            "слишком много commit-квитанций для однозначного отката",
        )

    current_receipt_path = receipts_root / f"{current_operation_id}.commit.json"
    _require_unique_operation_receipt_path_v2(
        commit_paths=commit_paths,
        operation_id=current_operation_id,
        expected_path=current_receipt_path,
        code="ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
    )
    try:
        current_document, _current_raw = _read_private_canonical_json(
            current_receipt_path,
            "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
        )
    except InstallerRecoveryV2Error as error:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
            "текущая commit-квитанция отсутствует",
        ) from error
    current_receipt = _validate_commit_receipt(current_document)
    if (
        current_receipt["operationId"] != current_operation_id
        or _receipt_activation_id(current_receipt) != current_activation_id
    ):
        _fail(
            "ROLLBACK_CURRENT_RECEIPT_AMBIGUOUS",
            "текущая commit-квитанция не связана с activeActivation",
        )

    previous_operation_id = _previous_operation_from_commit_lineage_v2(
        current_receipt=current_receipt,
        receipts_root=receipts_root,
        current_operation_id=current_operation_id,
        previous_activation_id=previous_activation_id,
        installation_id=installation_id,
    )
    if (
        expected_previous_operation_id is not None
        and previous_operation_id != expected_previous_operation_id
    ):
        _fail(
            "ROLLBACK_TRANSITION_LINEAGE_INVALID",
            "сохранённый previousOperationId не выведен из current commit-lineage",
        )
    previous_receipt_path = receipts_root / f"{previous_operation_id}.commit.json"
    _require_unique_operation_receipt_path_v2(
        commit_paths=commit_paths,
        operation_id=previous_operation_id,
        expected_path=previous_receipt_path,
        code="ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
    )
    try:
        previous_document, _previous_raw = _read_private_canonical_json(
            previous_receipt_path,
            "ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
        )
    except InstallerRecoveryV2Error as error:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
            "предыдущая commit-квитанция отсутствует",
        ) from error
    previous_receipt = _validate_commit_receipt(previous_document)
    if (
        previous_receipt["operationId"] != previous_operation_id
        or _receipt_activation_id(previous_receipt) != previous_activation_id
    ):
        _fail(
            "ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
            "предыдущая commit-квитанция не связана с previousActivation",
        )
    if (
        current_receipt["installationId"] != installation_id
        or previous_receipt["installationId"] != installation_id
    ):
        _fail(
            "ROLLBACK_RECEIPT_INVALID",
            "commit-квитанция принадлежит другой установке",
        )
    if previous_operation_id == current_operation_id:
        _fail(
            "ROLLBACK_PREVIOUS_RECEIPT_AMBIGUOUS",
            "предыдущая квитанция относится к текущей операции",
        )
    return _RollbackCommitChainV2(
        current_operation_id=current_operation_id,
        previous_operation_id=previous_operation_id,
        current_receipt_path=current_receipt_path,
        previous_receipt_path=previous_receipt_path,
        current_receipt=current_receipt,
        previous_receipt=previous_receipt,
    )


def _previous_operation_from_commit_lineage_v2(
    *,
    current_receipt: Mapping[str, Any],
    receipts_root: Path,
    current_operation_id: str,
    previous_activation_id: str,
    installation_id: str,
) -> str:
    """Вывести непосредственную предыдущую commit-квитанцию без поиска по версии."""

    try:
        lineage = ActivationTransitionLineageV2.from_document(
            current_receipt["transitionLineage"]
        )
    except Exception as error:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_TRANSITION_LINEAGE_INVALID",
            "current commit не содержит проверяемый transitionLineage",
        ) from error
    source = lineage.source_receipt
    stopped = lineage.stopped_controller
    expected_source_name = (
        f"{current_operation_id}.preparation.json"
        if lineage.transition_kind == "update"
        else f"{current_operation_id}.rollback-preparation.json"
    )
    if (
        lineage.transition_kind not in {"update", "rollback"}
        or source is None
        or stopped is None
        or source.path.parent != receipts_root
        or source.path.name != expected_source_name
        or stopped.operation_id != current_operation_id
        or stopped.activation_id != previous_activation_id
    ):
        _fail(
            "ROLLBACK_TRANSITION_LINEAGE_INVALID",
            "current commit-lineage не связан с previousActivation",
        )
    try:
        source_document, source_raw = _read_private_canonical_json(
            source.path,
            "ROLLBACK_TRANSITION_SOURCE_INVALID",
        )
    except InstallerRecoveryV2Error:
        raise
    if (
        source_document.get("schemaVersion") != 2
        or source_document.get("receiptKind") != source.receipt_kind
        or source_document.get("installationId") != installation_id
        or source_document.get("operationId") != current_operation_id
        or source_document.get("receiptFingerprint") != source.receipt_fingerprint
        or _sha256_bytes(source_raw) != source.raw_sha256
    ):
        _fail(
            "ROLLBACK_TRANSITION_SOURCE_INVALID",
            "source receipt не совпадает с current commit-lineage",
        )
    if lineage.transition_kind == "update":
        snapshot = source_document.get("transitionProofSnapshot")
        if (
            type(snapshot) is not dict
            or snapshot.get("installationId") != installation_id
            or snapshot.get("operationId") != current_operation_id
            or snapshot.get("activationId") != previous_activation_id
        ):
            _fail(
                "ROLLBACK_TRANSITION_SOURCE_INVALID",
                "update source не задаёт непосредственную предыдущую фиксацию",
            )
        candidate = snapshot.get("currentOperationId")
    else:
        if source_document.get("currentActivationId") != previous_activation_id:
            _fail(
                "ROLLBACK_TRANSITION_SOURCE_INVALID",
                "rollback source не задаёт непосредственную предыдущую фиксацию",
            )
        candidate = source_document.get("currentOperationId")
    return _identifier(
        candidate,
        _OPERATION_ID,
        "ROLLBACK_TRANSITION_SOURCE_INVALID",
    )


def _validate_controller_recovery_proof(
    intent: ControllerRecoveryIntentV2,
    proof: object,
) -> None:
    if not isinstance(proof, LifecycleControllerCommandProofV2):
        _fail("CONTROLLER_RECOVERY_PROOF_INVALID", "порт вернул иной тип")
    payload = proof.payload
    receipt = payload.get("commandReceipt") if isinstance(payload, Mapping) else None
    if (
        proof.method != "controller_recover"
        or proof.status != "CONTROLLER_RECOVERED"
        or proof.command_id != intent.expected_command_id
        or _SHA256.fullmatch(proof.request_fingerprint) is None
        or _SHA256.fullmatch(proof.response_fingerprint) is None
        or type(proof.previous_control_epoch) is not int
        or type(proof.new_control_epoch) is not int
        or proof.new_control_epoch != proof.previous_control_epoch + 1
        or type(payload) is not dict
        or payload.get("status") != "CONTROLLER_RECOVERED"
        or payload.get("previousControlEpoch") != proof.previous_control_epoch
        or payload.get("newControlEpoch") != proof.new_control_epoch
        or type(receipt) is not dict
        or receipt.get("commandId") != intent.expected_command_id
        or receipt.get("requestFingerprint") != proof.request_fingerprint
        or receipt.get("controlEpoch") != proof.new_control_epoch
        or _SHA256.fullmatch(str(receipt.get("resultFingerprint"))) is None
    ):
        _fail(
            "CONTROLLER_RECOVERY_PROOF_INVALID",
            "квитанция controller_recover не совпала с долговечным намерением",
        )


def _validate_database_binding_live(binding: Mapping[str, Any]) -> None:
    try:
        path = Path(str(binding["path"]))
        if not path.is_absolute():
            raise ValueError("database path is not absolute")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except (KeyError, OSError, ValueError) as exc:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_DATABASE_CHANGED", f"база недоступна: {exc}"
        ) from exc
    try:
        info = os.fstat(descriptor)
        try:
            named_info = path.lstat()
        except OSError as exc:
            raise InstallerRecoveryV2Error(
                "ROLLBACK_DATABASE_CHANGED",
                f"путь базы изменился во время проверки: {exc}",
            ) from exc
        expected = (
            binding.get("device"),
            binding.get("inode"),
            binding.get("ownerUid"),
            binding.get("ownerGid"),
            binding.get("mode"),
            binding.get("linkCount"),
            binding.get("schemaVersion"),
            binding.get("userVersion"),
        )
        observed = (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            f"0{stat.S_IMODE(info.st_mode):03o}",
            info.st_nlink,
            2,
            2,
        )
        if (
            (named_info.st_dev, named_info.st_ino) != (info.st_dev, info.st_ino)
            or not stat.S_ISREG(info.st_mode)
            or expected != observed
        ):
            _fail(
                "ROLLBACK_DATABASE_CHANGED",
                "inode или привязка базы не совпали с commit-квитанцией",
            )
    finally:
        os.close(descriptor)


def _require_restored_controller_command_id(
    port: LifecycleControllerPortV2,
    intent: ControllerRecoveryIntentV2,
) -> None:
    getter = getattr(port, "command_id_for", None)
    if callable(getter):
        restored = getter(intent.operation_id, "controller_recover")
    else:
        key = (intent.operation_id, "controller_recover")
        pending = getattr(port, "_pending", None)
        pending_value = pending.get(key) if isinstance(pending, Mapping) else None
        request = getattr(pending_value, "request", None)
        if isinstance(request, Mapping):
            restored = request.get("commandId")
        else:
            command_ids = getattr(port, "_command_ids", None)
            restored = (
                command_ids.get(key) if isinstance(command_ids, Mapping) else None
            )
    if restored != intent.expected_command_id:
        _fail(
            "CONTROLLER_COMMAND_ID_NOT_RESTORED",
            "controller_recover не связан с сохранённым commandId",
        )


def _read_private_canonical_json(path: Path, code: str) -> tuple[JsonObject, bytes]:
    path = _absolute_path(path, code)
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise InstallerRecoveryV2Error(code, f"файл недоступен: {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        try:
            named_info = path.lstat()
        except OSError as exc:
            raise InstallerRecoveryV2Error(
                code, f"путь изменился во время чтения: {path}: {exc}"
            ) from exc
        if (
            (named_info.st_dev, named_info.st_ino) != (info.st_dev, info.st_ino)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > _MAX_DOCUMENT_BYTES
        ):
            _fail(code, f"небезопасный частный файл: {path}")
        chunks: list[bytes] = []
        remaining = _MAX_DOCUMENT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_DOCUMENT_BYTES:
        _fail(code, f"частный документ слишком велик: {path}")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerRecoveryV2Error(code, f"неверный JSON: {path}: {exc}") from exc
    if type(document) is not dict or canonical_json_bytes(document) != raw:
        _fail(code, f"документ не является каноническим объектом: {path}")
    return document, raw


def _read_owned_symlink(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerRecoveryV2Error(
            "ROLLBACK_ACTIVE_LINK_CHANGED", f"ссылка недоступна: {exc}"
        ) from exc
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid():
        _fail("ROLLBACK_ACTIVE_LINK_CHANGED", "рабочий путь не является своей ссылкой")
    return os.readlink(path)


def _private_directory(path: Path, code: str) -> Path:
    path = _absolute_path(path, code)
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallerRecoveryV2Error(
            code, f"каталог недоступен: {path}: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        _fail(code, f"небезопасный частный каталог: {path}")
    return path


def _absolute_path(value: object, code: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        _fail(code, "требуется абсолютный Path")
    return value


def _identifier(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор имеет неверный формат")
    return value


def _sha256_bytes(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _fail(code: str, message: str):
    raise InstallerRecoveryV2Error(code, message)
