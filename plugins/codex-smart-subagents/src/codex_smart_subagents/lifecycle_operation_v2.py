"""Долговечный исполнитель операций жизненного цикла версии 2.

Модуль намеренно не знает, как именно меняются управляемые объекты. Он
фиксирует точный план и намерения, удерживает межпроцессную блокировку и
передаёт внешние эффекты вызывающей стороне только через проверяемые границы.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from .canonical_json import canonical_json_bytes, domain_fingerprint
from .closed_json_schema_v2 import (
    ClosedJsonSchemaV2Error,
    build_closed_json_schema_validator_v2,
)
from . import finite_file_lock_v2, operation_deadline_v2


JsonObject = dict[str, Any]
JournalValidatorV2 = Callable[[Mapping[str, Any]], None]
_JOURNAL_DOMAIN = "codex-smart/operation-journal/v2"
_PLAN_DOMAIN = "codex-smart/execution-plan-definition/v2"
_STATE_BUNDLE_DOMAIN = "codex-smart/state-bundle/v2"
_STEP_ACTION_DOMAIN = "codex-smart/step-action/v2"
_TERMINAL_STATE_DOMAIN = "codex-smart/terminal-state/v2"
_TERMINAL_DEFINITION_SNAPSHOT_DOMAIN = (
    "codex-smart/terminal-definition-snapshot/v2"
)
_ABSENCE_PROOF_DOMAIN = "codex-smart/absence-proof/v2"
_ABSENCE_PROJECTION_DOMAIN = "codex-smart/absence-proof-projection/v2"
_MAX_JOURNAL_BYTES = 16 * 1024 * 1024


def _checkpoint_operation_deadline_if_scoped_v2() -> None:
    """Проверить переданный сверху срок, не создавая запасной."""

    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is not None:
        deadline.checkpoint()


class LifecycleOperationV2Error(RuntimeError):
    """Базовая ошибка безопасного исполнения операции."""


class UnsafeLifecyclePathV2(LifecycleOperationV2Error):
    """Путь или его метаданные не удовлетворяют частной границе."""


class JournalConflictV2(LifecycleOperationV2Error):
    """Стабильный журнал уже существует или изменён другим владельцем."""


class JournalIntegrityErrorV2(LifecycleOperationV2Error):
    """Журнал не проходит схему, канонизацию или проверку отпечатков."""


class OperationJournalLockTimeoutV2(LifecycleOperationV2Error):
    """Блокировка журнала осталась занятой до общего предела операции."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class RecoveryStateAmbiguousV2(LifecycleOperationV2Error):
    """Наблюдаемое состояние не равно ни `before`, ни `expectedAfter`."""


class TerminalProofFailedV2(LifecycleOperationV2Error):
    """Послезамороженный эффект не подтверждён связанным доказательством."""


class FailurePointV2(Enum):
    """Нормативные аварийные окна изменяемого шага."""

    AFTER_INTENT_DURABLE_BEFORE_ACTION = "AFTER_INTENT_DURABLE_BEFORE_ACTION"
    AFTER_ACTION_BEFORE_COMPLETED = "AFTER_ACTION_BEFORE_COMPLETED"
    AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT = (
        "AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT"
    )
    AFTER_RECEIPT_BEFORE_JOURNAL_DELETE = (
        "AFTER_RECEIPT_BEFORE_JOURNAL_DELETE"
    )
    AFTER_TOMBSTONE_BEFORE_JOURNAL_DELETE = (
        "AFTER_TOMBSTONE_BEFORE_JOURNAL_DELETE"
    )


class InjectedCrashV2(LifecycleOperationV2Error):
    """Явный сбой для проверочного прохождения аварийного окна."""

    def __init__(self, point: FailurePointV2, step_kind: str) -> None:
        super().__init__(f"injected crash at {point.value}: {step_kind}")
        self.point = point
        self.step_kind = step_kind


@dataclass(frozen=True)
class ProjectionV2:
    """Одна закрытая проекция `lifecycle-projection-v2`."""

    schema_id: str
    schema_sha256: str
    value: Mapping[str, Any]
    value_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", copy.deepcopy(dict(self.value)))

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> ProjectionV2:
        _require_exact_keys(
            document,
            {"schemaId", "schemaSha256", "value", "valueFingerprint"},
            "projection",
        )
        value = document["value"]
        if type(value) is not dict:
            raise JournalIntegrityErrorV2("projection value must be an object")
        return cls(
            schema_id=_required_string(document["schemaId"], "schemaId"),
            schema_sha256=_required_sha256(
                document["schemaSha256"], "schemaSha256"
            ),
            value=value,
            value_fingerprint=_required_sha256(
                document["valueFingerprint"], "valueFingerprint"
            ),
        )

    def to_document(self) -> JsonObject:
        return {
            "schemaId": self.schema_id,
            "schemaSha256": self.schema_sha256,
            "value": copy.deepcopy(dict(self.value)),
            "valueFingerprint": self.value_fingerprint,
        }


@dataclass(frozen=True)
class StateBundleV2:
    """Полный типизированный набор состояния из журнала операции."""

    file_objects: tuple[ProjectionV2, ...]
    tree_objects: tuple[ProjectionV2, ...]
    symlinks: tuple[ProjectionV2, ...]
    manifest: ProjectionV2 | None
    activation: ProjectionV2 | None
    database: ProjectionV2 | None
    controller: ProjectionV2 | None
    controller_candidates: tuple[ProjectionV2, ...]
    watchdogs: tuple[ProjectionV2, ...]
    registry: ProjectionV2 | None
    launchers: ProjectionV2 | None
    legacy_processes: ProjectionV2 | None
    quiescence: ProjectionV2 | None
    external_commands: tuple[ProjectionV2, ...]
    receipts: tuple[ProjectionV2, ...]
    absence_proofs: tuple[ProjectionV2, ...]

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> StateBundleV2:
        _require_exact_keys(
            document,
            {
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
            },
            "state bundle",
        )

        def array(name: str) -> tuple[ProjectionV2, ...]:
            value = document[name]
            if type(value) is not list:
                raise JournalIntegrityErrorV2(f"{name} must be an array")
            return tuple(ProjectionV2.from_document(item) for item in value)

        def nullable(name: str) -> ProjectionV2 | None:
            value = document[name]
            return None if value is None else ProjectionV2.from_document(value)

        return cls(
            file_objects=array("fileObjects"),
            tree_objects=array("treeObjects"),
            symlinks=array("symlinks"),
            manifest=nullable("manifest"),
            activation=nullable("activation"),
            database=nullable("database"),
            controller=nullable("controller"),
            controller_candidates=array("controllerCandidates"),
            watchdogs=array("watchdogs"),
            registry=nullable("registry"),
            launchers=nullable("launchers"),
            legacy_processes=nullable("legacyProcesses"),
            quiescence=nullable("quiescence"),
            external_commands=array("externalCommands"),
            receipts=array("receipts"),
            absence_proofs=array("absenceProofs"),
        )

    def to_document(self) -> JsonObject:
        projection = {
            "fileObjects": [item.to_document() for item in self.file_objects],
            "treeObjects": [item.to_document() for item in self.tree_objects],
            "symlinks": [item.to_document() for item in self.symlinks],
            "manifest": _projection_document(self.manifest),
            "activation": _projection_document(self.activation),
            "database": _projection_document(self.database),
            "controller": _projection_document(self.controller),
            "controllerCandidates": [
                item.to_document() for item in self.controller_candidates
            ],
            "watchdogs": [item.to_document() for item in self.watchdogs],
            "registry": _projection_document(self.registry),
            "launchers": _projection_document(self.launchers),
            "legacyProcesses": _projection_document(self.legacy_processes),
            "quiescence": _projection_document(self.quiescence),
            "externalCommands": [
                item.to_document() for item in self.external_commands
            ],
            "receipts": [item.to_document() for item in self.receipts],
            "absenceProofs": [
                item.to_document() for item in self.absence_proofs
            ],
        }
        return {
            **projection,
            "bundleFingerprint": domain_fingerprint(
                _STATE_BUNDLE_DOMAIN, projection
            ),
        }


@dataclass(frozen=True)
class ExecutionPlanV2:
    """Неизменяемое определение выбранного прямого плана."""

    plan_id: str
    machine_id: str
    selected_branch_id: str | None
    composed_step_kinds: tuple[str, ...]
    selection_source: str = "DISCOVERY_BEFORE_FIRST_EFFECT"

    def __post_init__(self) -> None:
        _required_identifier(self.plan_id, "pl2", "plan_id")
        if not self.composed_step_kinds:
            raise JournalIntegrityErrorV2("execution plan must contain steps")
        object.__setattr__(
            self, "composed_step_kinds", tuple(self.composed_step_kinds)
        )

    @property
    def plan_definition_fingerprint(self) -> str:
        return domain_fingerprint(_PLAN_DOMAIN, self._definition_projection())

    def _definition_projection(self) -> JsonObject:
        return {
            "planId": self.plan_id,
            "machineId": self.machine_id,
            "selectedBranchId": self.selected_branch_id,
            "selectionSource": self.selection_source,
            "composedStepKinds": list(self.composed_step_kinds),
        }

    def to_document(self, first_incomplete_ordinal: int) -> JsonObject:
        return {
            **self._definition_projection(),
            "firstIncompleteOrdinal": first_incomplete_ordinal,
            "planDefinitionFingerprint": self.plan_definition_fingerprint,
        }


@dataclass(frozen=True)
class StepDefinitionV2:
    """Неизменяемая декларация одного шага выбранного плана."""

    kind: str
    command_id: str | None
    action: Mapping[str, Any]
    before: ProjectionV2
    expected_after: ProjectionV2

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", copy.deepcopy(dict(self.action)))

    @property
    def action_fingerprint(self) -> str:
        return domain_fingerprint(
            _STEP_ACTION_DOMAIN, {"action": copy.deepcopy(dict(self.action))}
        )


@dataclass(frozen=True)
class StepCallbacksV2:
    """Доказуемое наблюдение и внешний эффект обычного шага."""

    observe: Callable[[StepDefinitionV2], ProjectionV2]
    apply: Callable[[StepDefinitionV2], None]
    matches_before: Callable[[ProjectionV2, StepDefinitionV2], bool] | None = None
    matches_after: Callable[[ProjectionV2, StepDefinitionV2], bool] | None = None
    matches_intent_resume: (
        Callable[[ProjectionV2, StepDefinitionV2], bool] | None
    ) = None
    replay_safe_when_indistinguishable: (
        Callable[[ProjectionV2, StepDefinitionV2], bool] | None
    ) = None
    completed_current_matches: (
        Callable[[ProjectionV2, ProjectionV2, StepDefinitionV2], bool] | None
    ) = None

    def __post_init__(self) -> None:
        if not callable(self.observe) or not callable(self.apply):
            raise TypeError("step observe/apply callbacks must be callable")
        if self.matches_before is not None and not callable(self.matches_before):
            raise TypeError("matches_before must be callable or None")
        if self.matches_after is not None and not callable(self.matches_after):
            raise TypeError("matches_after must be callable or None")
        if (
            self.matches_intent_resume is not None
            and not callable(self.matches_intent_resume)
        ):
            raise TypeError("matches_intent_resume must be callable or None")
        if (
            self.replay_safe_when_indistinguishable is not None
            and not callable(self.replay_safe_when_indistinguishable)
        ):
            raise TypeError(
                "replay_safe_when_indistinguishable must be callable or None"
            )
        if (
            self.completed_current_matches is not None
            and not callable(self.completed_current_matches)
        ):
            raise TypeError("completed_current_matches must be callable or None")

    def accepts_before(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        matcher = self.matches_before
        return (
            _same_projection(observed, definition.before)
            if matcher is None
            else bool(matcher(observed, definition))
        )

    def accepts_after(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        matcher = self.matches_after
        return (
            _same_projection(observed, definition.expected_after)
            if matcher is None
            else bool(matcher(observed, definition))
        )

    def accepts_intent_resume(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        """Принять промежуточный эффект только после долговечного intent шага."""

        matcher = self.matches_intent_resume
        return False if matcher is None else bool(matcher(observed, definition))

    def permits_indistinguishable_replay(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        predicate = self.replay_safe_when_indistinguishable
        return False if predicate is None else bool(predicate(observed, definition))

    def accepts_completed_current(
        self,
        persisted_after: ProjectionV2,
        current_observed: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        """Принять точный результат либо явно доказанного позднего преемника."""

        predicate = self.completed_current_matches
        return (
            _same_projection(current_observed, persisted_after)
            if predicate is None
            else bool(predicate(persisted_after, current_observed, definition))
        )


@dataclass(frozen=True)
class TerminalContextV2:
    installation_id: str
    operation_id: str
    completed_step_ids: tuple[str, ...]
    frozen_at: str


@dataclass(frozen=True)
class TransitionSourceReceiptV2:
    """Неизменяемый источник доказательства перехода активации."""

    receipt_kind: str
    path: Path
    raw_sha256: str
    receipt_fingerprint: str

    def __post_init__(self) -> None:
        if self.receipt_kind not in {
            "activation-preparation",
            "rollback-manifest-preparation",
        }:
            raise JournalIntegrityErrorV2("invalid transition source receipt kind")
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise JournalIntegrityErrorV2("transition source receipt path is invalid")
        _required_sha256(self.raw_sha256, "transition source raw_sha256")
        _required_sha256(
            self.receipt_fingerprint,
            "transition source receipt_fingerprint",
        )

    def to_document(self) -> JsonObject:
        return {
            "receiptKind": self.receipt_kind,
            "path": str(self.path),
            "rawSha256": self.raw_sha256,
            "receiptFingerprint": self.receipt_fingerprint,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "TransitionSourceReceiptV2":
        value = _closed_mapping_v2(
            document,
            {
                "receiptKind",
                "path",
                "rawSha256",
                "receiptFingerprint",
            },
            "transition source receipt",
        )
        return cls(
            receipt_kind=str(value["receiptKind"]),
            path=Path(str(value["path"])),
            raw_sha256=str(value["rawSha256"]),
            receipt_fingerprint=str(value["receiptFingerprint"]),
        )


@dataclass(frozen=True)
class ControllerShutdownLineageV2:
    """Три точных commandId цепочки, остановившей предыдущий контроллер."""

    maintenance_begin: str
    maintenance_strengthen: str
    shutdown: str

    def __post_init__(self) -> None:
        for name in ("maintenance_begin", "maintenance_strengthen", "shutdown"):
            _required_identifier(getattr(self, name), "cc2", name)
        if len({self.maintenance_begin, self.maintenance_strengthen, self.shutdown}) != 3:
            raise JournalIntegrityErrorV2("shutdown command IDs must be unique")

    def to_document(self) -> JsonObject:
        return {
            "maintenanceBegin": self.maintenance_begin,
            "maintenanceStrengthen": self.maintenance_strengthen,
            "shutdown": self.shutdown,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "ControllerShutdownLineageV2":
        value = _closed_mapping_v2(
            document,
            {"maintenanceBegin", "maintenanceStrengthen", "shutdown"},
            "shutdown command IDs",
        )
        return cls(
            maintenance_begin=str(value["maintenanceBegin"]),
            maintenance_strengthen=str(value["maintenanceStrengthen"]),
            shutdown=str(value["shutdown"]),
        )


@dataclass(frozen=True)
class StoppedControllerLineageV2:
    """Точная идентичность остановленного предшественника."""

    operation_id: str
    activation_id: str
    database_id: str
    controller_identity: str
    control_epoch: int

    def __post_init__(self) -> None:
        _required_identifier(self.operation_id, "op2", "stopped operation_id")
        if (
            type(self.activation_id) is not str
            or not self.activation_id.startswith("act2_")
            or len(self.activation_id) != len("act2_") + 64
            or any(
                character not in "0123456789abcdef"
                for character in self.activation_id[len("act2_") :]
            )
        ):
            raise JournalIntegrityErrorV2("invalid stopped activation_id")
        _required_identifier(self.database_id, "db2", "stopped database_id")
        _required_sha256(self.controller_identity, "stopped controller_identity")
        if (
            type(self.control_epoch) is not int
            or not 1 <= self.control_epoch <= 9_007_199_254_740_991
        ):
            raise JournalIntegrityErrorV2("stopped control_epoch is invalid")

    def to_document(self) -> JsonObject:
        return {
            "operationId": self.operation_id,
            "activationId": self.activation_id,
            "databaseId": self.database_id,
            "controllerIdentity": self.controller_identity,
            "controlEpoch": self.control_epoch,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "StoppedControllerLineageV2":
        value = _closed_mapping_v2(
            document,
            {
                "operationId",
                "activationId",
                "databaseId",
                "controllerIdentity",
                "controlEpoch",
            },
            "stopped controller",
        )
        return cls(
            operation_id=str(value["operationId"]),
            activation_id=str(value["activationId"]),
            database_id=str(value["databaseId"]),
            controller_identity=str(value["controllerIdentity"]),
            control_epoch=value["controlEpoch"],
        )


@dataclass(frozen=True)
class ActivationTransitionLineageV2:
    """Закрытая самодостаточная история одного перехода активации."""

    transition_kind: str
    source_receipt: TransitionSourceReceiptV2 | None
    activation_proof_fingerprint: str | None
    shutdown_command_ids: ControllerShutdownLineageV2 | None
    stopped_controller: StoppedControllerLineageV2 | None

    def __post_init__(self) -> None:
        if self.transition_kind not in {"initial", "update", "rollback"}:
            raise JournalIntegrityErrorV2("invalid activation transition kind")
        values = (
            self.source_receipt,
            self.activation_proof_fingerprint,
            self.shutdown_command_ids,
            self.stopped_controller,
        )
        if self.transition_kind == "initial":
            if any(value is not None for value in values):
                raise JournalIntegrityErrorV2("initial lineage must not name a predecessor")
            return
        if any(value is None for value in values):
            raise JournalIntegrityErrorV2("transition lineage predecessor proof is incomplete")
        if not isinstance(self.source_receipt, TransitionSourceReceiptV2):
            raise JournalIntegrityErrorV2("transition source receipt has invalid type")
        if not isinstance(self.shutdown_command_ids, ControllerShutdownLineageV2):
            raise JournalIntegrityErrorV2("shutdown command lineage has invalid type")
        if not isinstance(self.stopped_controller, StoppedControllerLineageV2):
            raise JournalIntegrityErrorV2("stopped controller lineage has invalid type")
        _required_sha256(
            self.activation_proof_fingerprint,
            "activation_proof_fingerprint",
        )
        expected_kind = (
            "activation-preparation"
            if self.transition_kind == "update"
            else "rollback-manifest-preparation"
        )
        if self.source_receipt.receipt_kind != expected_kind:
            raise JournalIntegrityErrorV2("transition source receipt kind mismatch")

    @property
    def complete(self) -> bool:
        return True

    def _projection(self) -> JsonObject:
        return {
            "transitionKind": self.transition_kind,
            "sourceReceipt": (
                None if self.source_receipt is None else self.source_receipt.to_document()
            ),
            "activationProofFingerprint": self.activation_proof_fingerprint,
            "shutdownCommandIds": (
                None
                if self.shutdown_command_ids is None
                else self.shutdown_command_ids.to_document()
            ),
            "stoppedController": (
                None
                if self.stopped_controller is None
                else self.stopped_controller.to_document()
            ),
        }

    @property
    def lineage_fingerprint(self) -> str:
        return domain_fingerprint(
            "codex-smart/activation-transition-lineage/v2",
            self._projection(),
        )

    def to_document(self) -> JsonObject:
        return {**self._projection(), "lineageFingerprint": self.lineage_fingerprint}

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "ActivationTransitionLineageV2":
        value = _closed_mapping_v2(
            document,
            {
                "transitionKind",
                "sourceReceipt",
                "activationProofFingerprint",
                "shutdownCommandIds",
                "stoppedController",
                "lineageFingerprint",
            },
            "activation transition lineage",
        )
        result = cls(
            transition_kind=str(value["transitionKind"]),
            source_receipt=(
                None
                if value["sourceReceipt"] is None
                else TransitionSourceReceiptV2.from_document(value["sourceReceipt"])
            ),
            activation_proof_fingerprint=value["activationProofFingerprint"],
            shutdown_command_ids=(
                None
                if value["shutdownCommandIds"] is None
                else ControllerShutdownLineageV2.from_document(
                    value["shutdownCommandIds"]
                )
            ),
            stopped_controller=(
                None
                if value["stoppedController"] is None
                else StoppedControllerLineageV2.from_document(
                    value["stoppedController"]
                )
            ),
        )
        if value["lineageFingerprint"] != result.lineage_fingerprint:
            raise JournalIntegrityErrorV2("activation lineage fingerprint mismatch")
        return result


@dataclass(frozen=True)
class ActivationCommitPayloadIntentV2:
    """Полный вход `activation-commit` для замороженного намерения."""

    manifest: ProjectionV2
    manifest_document: Mapping[str, Any]
    transition_lineage: ActivationTransitionLineageV2
    activation: ProjectionV2
    database_binding: ProjectionV2
    journal_absence_target: ProjectionV2
    controller_identity: str

    def __post_init__(self) -> None:
        _require_projection_contract_v2(
            self.manifest,
            schema_id="manifest-v2",
            domain="codex-smart/journal-state/v2",
            label="activation-commit manifest",
        )
        if type(self.manifest_document) is not dict:
            raise JournalIntegrityErrorV2("manifest_document must be an object")
        manifest_document = copy.deepcopy(dict(self.manifest_document))
        object.__setattr__(self, "manifest_document", manifest_document)
        _validate_manifest_document_projection_v2(
            manifest_document,
            self.manifest,
        )
        if not isinstance(self.transition_lineage, ActivationTransitionLineageV2):
            raise JournalIntegrityErrorV2("transition_lineage has invalid type")
        stopped = self.transition_lineage.stopped_controller
        previous = manifest_document.get("previousActivation")
        if self.transition_lineage.transition_kind == "initial":
            if previous is not None:
                raise JournalIntegrityErrorV2(
                    "initial manifest must not name previous activation"
                )
        elif (
            stopped is None
            or stopped.operation_id
            != self.manifest.value.get("lastCommittedOperation")
            or type(previous) is not dict
            or stopped.activation_id != previous.get("activationId")
            or stopped.database_id != previous.get("databaseId")
        ):
            raise JournalIntegrityErrorV2(
                "stopped controller does not match previous activation"
            )
        _require_projection_contract_v2(
            self.activation,
            schema_id="activation-v2",
            domain="codex-smart/journal-state/v2",
            label="activation-commit activation",
        )
        _require_projection_contract_v2(
            self.database_binding,
            schema_id="database-binding-v2",
            domain="codex-smart/database-binding/v2",
            label="activation-commit database_binding",
        )
        _require_projection_contract_v2(
            self.journal_absence_target,
            schema_id="absence-proof-v2",
            domain="codex-smart/absence-proof-projection/v2",
            label="activation-commit journal_absence_target",
        )
        _required_sha256(self.controller_identity, "controller_identity")

    def to_document(self, context: TerminalContextV2) -> JsonObject:
        return {
            "payloadKind": "activation-commit",
            "installationId": context.installation_id,
            "operationId": context.operation_id,
            "manifest": self.manifest.to_document(),
            "manifestDocument": copy.deepcopy(dict(self.manifest_document)),
            "transitionLineage": self.transition_lineage.to_document(),
            "activation": self.activation.to_document(),
            "databaseBinding": self.database_binding.to_document(),
            "journalAbsenceTarget": self.journal_absence_target.to_document(),
            "controllerIdentity": self.controller_identity,
            "completedStepIds": list(context.completed_step_ids),
            "completedAt": context.frozen_at,
        }


def _require_projection_contract_v2(
    projection: object,
    *,
    schema_id: str,
    domain: str,
    label: str,
) -> None:
    if not isinstance(projection, ProjectionV2):
        raise JournalIntegrityErrorV2(f"{label} must be ProjectionV2")
    if projection.schema_id != schema_id:
        raise JournalIntegrityErrorV2(f"invalid schemaId: {label}")
    _required_sha256(projection.schema_sha256, f"{label}.schemaSha256")
    _required_sha256(projection.value_fingerprint, f"{label}.valueFingerprint")
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    if projection.value_fingerprint != domain_fingerprint(domain, envelope):
        raise JournalIntegrityErrorV2(f"invalid valueFingerprint: {label}")


def _closed_mapping_v2(
    document: object,
    expected_keys: set[str],
    label: str,
) -> JsonObject:
    if type(document) is not dict or set(document) != expected_keys:
        raise JournalIntegrityErrorV2(f"{label} has unexpected fields")
    return copy.deepcopy(dict(document))


def _validate_manifest_document_projection_v2(
    document: Mapping[str, Any],
    projection: ProjectionV2,
) -> None:
    try:
        if set(document) != {
            "schemaVersion",
            "installationId",
            "release",
            "pluginId",
            "marketplaceName",
            "stateHome",
            "sourceLocator",
            "codexSnapshot",
            "activeActivation",
            "previousActivation",
            "interfaceEvidence",
            "routingPolicyFingerprint",
            "bundledCatalogFingerprint",
            "artifacts",
            "originalBackup",
            "lastCommittedOperation",
            "databaseSchemaVersion",
            "extensions",
        }:
            raise ValueError("manifest fields")
        raw = canonical_json_bytes(document)
        active = document["activeActivation"]
        previous = document.get("previousActivation")
        file_value = projection.value["file"]
        pointer_keys = {
            "activationId",
            "activationFingerprint",
            "symlinkTarget",
            "generationId",
            "databaseId",
        }
        if (
            type(active) is not dict
            or set(active) != pointer_keys
            or (
                previous is not None
                and (type(previous) is not dict or set(previous) != pointer_keys)
            )
            or type(file_value) is not dict
            or type(document["sourceLocator"]) is not dict
            or type(document["artifacts"]) is not list
            or type(document["extensions"]) is not dict
        ):
            raise TypeError("manifest structure")
        if (
            file_value.get("sha256") != hashlib.sha256(raw).hexdigest()
            or file_value.get("size") != len(raw)
        ):
            raise ValueError("manifest file digest")
        expected = {
            "file": copy.deepcopy(dict(file_value)),
            "schemaVersion": document["schemaVersion"],
            "installationId": document["installationId"],
            "release": document["release"],
            "pluginId": document["pluginId"],
            "stateHome": document["stateHome"],
            "activeActivationId": active["activationId"],
            "previousActivationId": (
                None if previous is None else previous["activationId"]
            ),
            "lastCommittedOperation": document["lastCommittedOperation"],
            "sourceLocatorFingerprint": hashlib.sha256(
                canonical_json_bytes(document["sourceLocator"])
            ).hexdigest(),
            "artifactsFingerprint": hashlib.sha256(
                canonical_json_bytes(document["artifacts"])
            ).hexdigest(),
            "semanticFingerprint": domain_fingerprint(
                "codex-smart/manifest-semantic/v2",
                {
                    key: copy.deepcopy(value)
                    for key, value in document.items()
                    if key != "extensions"
                },
            ),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise JournalIntegrityErrorV2(
            "manifest_document is not bound to manifest projection"
        ) from exc
    if canonical_json_bytes(expected) != canonical_json_bytes(projection.value):
        raise JournalIntegrityErrorV2(
            "manifest_document does not recompute manifest projection"
        )


@dataclass(frozen=True)
class OperationAbortPayloadIntentV2:
    """Полный вход квитанции доказанного обратного плана."""

    restored_state: StateBundleV2
    journal_absence_target: ProjectionV2
    reason_code: str

    def to_document(self, context: TerminalContextV2) -> JsonObject:
        return {
            "payloadKind": "operation-abort",
            "installationId": context.installation_id,
            "operationId": context.operation_id,
            "restoredState": self.restored_state.to_document(),
            "journalAbsenceTarget": self.journal_absence_target.to_document(),
            "reasonCode": self.reason_code,
            "completedAt": context.frozen_at,
        }


@dataclass(frozen=True)
class InstallationUninstallPayloadIntentV2:
    """Полный вход квитанции удаления установки с сохранением данных."""

    removed_state: StateBundleV2
    restored_original_backup: ProjectionV2
    absence_proof: ProjectionV2
    retained_data: Mapping[str, Any]
    activation_proof_fingerprint: str

    def __post_init__(self) -> None:
        retained = copy.deepcopy(dict(self.retained_data))
        if set(retained) != {
            "databaseBinding",
            "backupsRoot",
            "quarantineRoot",
            "recoveryEntrypoint",
        }:
            raise JournalIntegrityErrorV2(
                "installation-uninstall retained_data has invalid fields"
            )
        object.__setattr__(self, "retained_data", retained)
        _required_sha256(
            self.activation_proof_fingerprint,
            "activation_proof_fingerprint",
        )

    def to_document(self, context: TerminalContextV2) -> JsonObject:
        return {
            "payloadKind": "installation-uninstall",
            "installationId": context.installation_id,
            "operationId": context.operation_id,
            "removedState": self.removed_state.to_document(),
            "restoredOriginalBackup": self.restored_original_backup.to_document(),
            "absenceProof": self.absence_proof.to_document(),
            "dataRetentionMode": "retain-data",
            "retainedData": copy.deepcopy(dict(self.retained_data)),
            "activationProofFingerprint": self.activation_proof_fingerprint,
            "completedAt": context.frozen_at,
        }


ReceiptPayloadIntentV2 = (
    ActivationCommitPayloadIntentV2
    | OperationAbortPayloadIntentV2
    | InstallationUninstallPayloadIntentV2
)


@dataclass(frozen=True)
class PriorInstallationEvidenceV2:
    before_file_projection_fingerprint: str

    def __post_init__(self) -> None:
        _required_sha256(
            self.before_file_projection_fingerprint,
            "before_file_projection_fingerprint",
        )

    def to_document(self) -> JsonObject:
        return {
            "priorTombstoneSchemaAndFingerprintValid": True,
            "priorEmbeddedUninstallReceiptAndImmutableFileValid": True,
            "installationIdRelation": (
                "PRIOR_DIFFERS_FROM_CURRENT_INSTALLATION"
            ),
            "beforeFileProjectionFingerprint": (
                self.before_file_projection_fingerprint
            ),
        }


@dataclass(frozen=True)
class TombstonePayloadIntentV2:
    path: Path
    before: ProjectionV2
    replacement_authorization: str
    prior_installation_evidence: PriorInstallationEvidenceV2 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise UnsafeLifecyclePathV2("tombstone path must be absolute")
        expected_evidence = (
            self.replacement_authorization
            == "REPLACE_VERIFIED_STALE_PRIOR_INSTALLATION"
        )
        if expected_evidence != (self.prior_installation_evidence is not None):
            raise JournalIntegrityErrorV2(
                "tombstone replacement evidence does not match authorization"
            )

    def to_document(self) -> JsonObject:
        return {
            "path": str(self.path),
            "before": self.before.to_document(),
            "replacementAuthorization": self.replacement_authorization,
            "priorInstallationEvidence": (
                None
                if self.prior_installation_evidence is None
                else self.prior_installation_evidence.to_document()
            ),
            "currentReceiptBinding": (
                "DERIVE_FROM_FROZEN_RECEIPT_PAYLOAD_AND_FROZEN_JOURNAL_FINGERPRINT"
            ),
            "reobserveBeforeWrite": True,
            "mismatchDisposition": "RECOVERY_STATE_AMBIGUOUS",
        }


@dataclass(frozen=True)
class TerminalDefinitionV2:
    """Самодостаточное намерение терминального атомарного замораживания."""

    terminal_kind: str
    receipt_kind: str
    receipt_path: Path
    freeze: StepDefinitionV2
    journal_absence_target: ProjectionV2
    receipt_payload: ReceiptPayloadIntentV2
    tombstone_payload: TombstonePayloadIntentV2 | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.receipt_path, Path)
            or not self.receipt_path.is_absolute()
        ):
            raise UnsafeLifecyclePathV2("receipt path must be absolute")
        if self.freeze.kind != "terminal_journal_freeze":
            raise JournalIntegrityErrorV2(
                "terminal definition requires terminal_journal_freeze"
            )
        expected = {
            "COMMIT": (
                "activation-commit",
                ActivationCommitPayloadIntentV2,
                False,
            ),
            "ABORT": (
                "operation-abort",
                OperationAbortPayloadIntentV2,
                False,
            ),
            "UNINSTALL": (
                "installation-uninstall",
                InstallationUninstallPayloadIntentV2,
                True,
            ),
        }.get(self.terminal_kind)
        if expected is None:
            raise JournalIntegrityErrorV2("unsupported terminal kind")
        receipt_kind, payload_type, needs_tombstone = expected
        if self.receipt_kind != receipt_kind or not isinstance(
            self.receipt_payload, payload_type
        ):
            raise JournalIntegrityErrorV2(
                "terminal receipt kind and payload type do not match"
            )
        if isinstance(self.receipt_payload, ActivationCommitPayloadIntentV2):
            lineage = self.receipt_payload.transition_lineage
            source = lineage.source_receipt
            if source is not None:
                operation_id = self.receipt_payload.manifest.value.get(
                    "lastCommittedOperation"
                )
                suffix = (
                    ".preparation.json"
                    if lineage.transition_kind == "update"
                    else ".rollback-preparation.json"
                )
                expected_path = self.receipt_path.parent / f"{operation_id}{suffix}"
                if source.path != expected_path:
                    raise JournalIntegrityErrorV2(
                        "transition source receipt path is not canonical"
                    )
        if needs_tombstone != (self.tombstone_payload is not None):
            raise JournalIntegrityErrorV2(
                "terminal tombstone requirement does not match terminal kind"
            )
        payload_absence_target = getattr(
            self.receipt_payload, "journal_absence_target", None
        )
        if payload_absence_target is not None and not _same_projection(
            payload_absence_target, self.journal_absence_target
        ):
            raise JournalIntegrityErrorV2(
                "receipt and terminal journal absence targets differ"
            )

    @property
    def post_freeze_action_kinds(self) -> tuple[str, ...]:
        return {
            "COMMIT": ("commit_receipt_publish", "gate_open"),
            "ABORT": ("abort_receipt_publish", "abort_journal_close"),
            "UNINSTALL": (
                "uninstall_receipt_publish",
                "uninstall_tombstone_publish",
                "uninstall_journal_close",
            ),
        }[self.terminal_kind]


def terminal_definition_snapshot_v2(
    terminal: TerminalDefinitionV2 | None,
) -> JsonObject | None:
    """Сериализовать всю статическую часть терминального намерения до эффектов."""

    if terminal is None:
        return None
    if not isinstance(terminal, TerminalDefinitionV2):
        raise TypeError("terminal must be TerminalDefinitionV2 or None")
    freeze = terminal.freeze
    projection = {
        "terminalKind": terminal.terminal_kind,
        "receiptKind": terminal.receipt_kind,
        "receiptPath": str(terminal.receipt_path),
        "freeze": {
            "kind": freeze.kind,
            "commandId": freeze.command_id,
            "action": copy.deepcopy(dict(freeze.action)),
            "actionFingerprint": freeze.action_fingerprint,
            "before": freeze.before.to_document(),
            "expectedAfter": freeze.expected_after.to_document(),
        },
        "journalAbsenceTarget": terminal.journal_absence_target.to_document(),
        "receiptPayloadStaticIntent": _receipt_payload_static_intent_v2(
            terminal.receipt_payload
        ),
        "tombstonePayloadIntent": (
            None
            if terminal.tombstone_payload is None
            else terminal.tombstone_payload.to_document()
        ),
        "postFreezeActionKinds": list(terminal.post_freeze_action_kinds),
    }
    return {
        **projection,
        "snapshotFingerprint": domain_fingerprint(
            _TERMINAL_DEFINITION_SNAPSHOT_DOMAIN,
            projection,
        ),
    }


def _receipt_payload_static_intent_v2(
    payload: ReceiptPayloadIntentV2,
) -> JsonObject:
    if isinstance(payload, ActivationCommitPayloadIntentV2):
        return {
            "payloadKind": "activation-commit",
            "manifest": payload.manifest.to_document(),
            "manifestDocument": copy.deepcopy(dict(payload.manifest_document)),
            "transitionLineage": payload.transition_lineage.to_document(),
            "activation": payload.activation.to_document(),
            "databaseBinding": payload.database_binding.to_document(),
            "journalAbsenceTarget": payload.journal_absence_target.to_document(),
            "controllerIdentity": payload.controller_identity,
        }
    if isinstance(payload, OperationAbortPayloadIntentV2):
        return {
            "payloadKind": "operation-abort",
            "restoredState": payload.restored_state.to_document(),
            "journalAbsenceTarget": payload.journal_absence_target.to_document(),
            "reasonCode": payload.reason_code,
        }
    if isinstance(payload, InstallationUninstallPayloadIntentV2):
        return {
            "payloadKind": "installation-uninstall",
            "removedState": payload.removed_state.to_document(),
            "restoredOriginalBackup": payload.restored_original_backup.to_document(),
            "absenceProof": payload.absence_proof.to_document(),
            "dataRetentionMode": "retain-data",
            "retainedData": copy.deepcopy(dict(payload.retained_data)),
            "activationProofFingerprint": payload.activation_proof_fingerprint,
        }
    raise TypeError("unsupported receipt payload intent")


@dataclass(frozen=True)
class TerminalCallbacksV2:
    """Послезамороженные эффекты и обязательные доказательства их результата."""

    receipt_matches: Callable[[JsonObject], bool]
    publish_receipt: Callable[[JsonObject], None]
    tombstone_matches: Callable[[JsonObject], bool] | None = None
    publish_tombstone: Callable[[JsonObject], None] | None = None


@dataclass(frozen=True)
class OperationDefinitionV2:
    """Все обязательные входы первого долговечного документа операции."""

    kind: str
    installation_id: str
    operation_id: str
    operation: str
    execution_plan: ExecutionPlanV2
    discovery_before: StateBundleV2
    fenced_before: StateBundleV2 | None
    desired: StateBundleV2 | None
    gate_close: StepDefinitionV2
    mutable_steps: tuple[StepDefinitionV2, ...]
    terminal: TerminalDefinitionV2 | None = None

    def __post_init__(self) -> None:
        _required_identifier(self.installation_id, "ins2", "installation_id")
        _required_identifier(self.operation_id, "op2", "operation_id")
        object.__setattr__(self, "mutable_steps", tuple(self.mutable_steps))
        kinds = (self.gate_close.kind,) + tuple(
            step.kind for step in self.mutable_steps
        )
        if self.terminal is not None:
            kinds += (self.terminal.freeze.kind,)
            kinds += self.terminal.post_freeze_action_kinds
        if kinds != self.execution_plan.composed_step_kinds:
            raise JournalIntegrityErrorV2(
                "step definitions do not match composedStepKinds"
            )
        if self.gate_close.kind != "gate_close":
            raise JournalIntegrityErrorV2("first definition must be gate_close")


@dataclass(frozen=True)
class OperationRunV2:
    status: str
    operation_id: str
    attempt_id: str


def build_operation_journal_validator_v2(
    schema_dir: Path,
) -> JournalValidatorV2:
    """Собрать проверяющий объект именно из нормативных схем проекта."""

    if not isinstance(schema_dir, Path) or not schema_dir.is_absolute():
        raise UnsafeLifecyclePathV2("schema_dir must be an absolute Path")
    try:
        validator = build_closed_json_schema_validator_v2(
            schema_dir,
            "operation-journal-v2.schema.json",
        )
    except ClosedJsonSchemaV2Error as error:
        raise JournalIntegrityErrorV2(
            f"normative operation journal schema invalid: {error.message}"
        ) from error

    def validate(document: Mapping[str, Any]) -> None:
        try:
            validator(copy.deepcopy(dict(document)))
        except ClosedJsonSchemaV2Error as error:
            pointer = "/" + "/".join(
                str(item).replace("~", "~0").replace("/", "~1")
                for item in error.path
            )
            raise JournalIntegrityErrorV2(
                f"operation journal schema violation at {pointer}: {error.message}"
            ) from error

    return validate


class OperationJournalStoreV2:
    """Частное атомарное хранилище одного основного журнала."""

    def __init__(
        self,
        *,
        journal_path: Path,
        lock_path: Path,
        validate_document: JournalValidatorV2,
    ) -> None:
        if (
            not isinstance(journal_path, Path)
            or not journal_path.is_absolute()
            or not isinstance(lock_path, Path)
            or not lock_path.is_absolute()
        ):
            raise UnsafeLifecyclePathV2("journal and lock paths must be absolute")
        if journal_path.parent != lock_path.parent:
            raise UnsafeLifecyclePathV2(
                "journal and lock must share one private directory"
            )
        self.journal_path = journal_path
        self.lock_path = lock_path
        self._validate_document = validate_document
        _ensure_private_directory(self.journal_path.parent)
        _ensure_lock_file(self.lock_path)

    @contextmanager
    def locked(self, *, exclusive: bool = True) -> Iterator[None]:
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
        )
        acquired = False
        try:
            _validate_private_regular_file(descriptor, self.lock_path)
            try:
                finite_file_lock_v2.acquire_flock_v2(
                    descriptor,
                    exclusive=exclusive,
                    timeout_seconds=(
                        finite_file_lock_v2.LOCAL_FILE_LOCK_TIMEOUT_SECONDS
                    ),
                    timeout_code="OPERATION_JOURNAL_LOCK_TIMEOUT",
                )
            except finite_file_lock_v2.FileLockTimeoutV2 as error:
                raise OperationJournalLockTimeoutV2(
                    error.code,
                    "operation journal lock remained busy until its deadline",
                ) from error
            acquired = True
            yield
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def read(self) -> JsonObject:
        with self.locked(exclusive=False):
            return self._read_unlocked()

    def _read_unlocked(self) -> JsonObject:
        descriptor = os.open(
            self.journal_path,
            os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
        )
        try:
            _validate_private_regular_file(descriptor, self.journal_path)
            payload = _read_bounded(descriptor, _MAX_JOURNAL_BYTES)
        finally:
            os.close(descriptor)
        document = _load_json_bytes(payload, label=str(self.journal_path))
        if canonical_json_bytes(document) != payload:
            raise JournalIntegrityErrorV2("journal bytes are not canonical-json-v1")
        self._validate_and_verify(document)
        return document

    def _create_unlocked(self, document: Mapping[str, Any]) -> None:
        if _path_exists_no_follow(self.journal_path):
            raise JournalConflictV2("operation journal already exists")
        self._validate_and_verify(document)
        payload = canonical_json_bytes(dict(document))
        _atomic_create_private(self.journal_path, payload)

    def _replace_unlocked(
        self,
        document: Mapping[str, Any],
        *,
        expected_journal_fingerprint: str,
    ) -> None:
        current = self._read_unlocked()
        if current["journalFingerprint"] != expected_journal_fingerprint:
            raise JournalConflictV2("operation journal changed before replacement")
        self._validate_and_verify(document)
        _atomic_replace_private(
            self.journal_path, canonical_json_bytes(dict(document))
        )

    def _delete_frozen_unlocked(
        self,
        document: Mapping[str, Any],
    ) -> None:
        current = self._read_unlocked()
        if (
            current["journalFingerprint"] != document["journalFingerprint"]
            or current["phase"] != "TERMINAL_FROZEN"
        ):
            raise JournalConflictV2(
                "only the exact terminal frozen journal may be deleted"
            )
        entry = _validate_journal_absence_target(
            self.journal_path,
            current["terminalDeleteIntent"]["journalAbsenceTarget"],
        )
        parent_descriptor = _open_verified_absence_parent(
            self.journal_path, entry
        )
        descriptor = -1
        try:
            descriptor = os.open(
                self.journal_path.name,
                os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
                dir_fd=parent_descriptor,
            )
            _validate_private_regular_file(descriptor, self.journal_path)
            opened = os.fstat(descriptor)
            named = os.stat(
                self.journal_path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise JournalConflictV2("journal identity changed before delete")
            os.unlink(self.journal_path.name, dir_fd=parent_descriptor)
            _require_absent_at(parent_descriptor, self.journal_path.name)
            os.fsync(parent_descriptor)
            _require_absent_at(parent_descriptor, self.journal_path.name)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_descriptor)

    def _validate_and_verify(self, document: Mapping[str, Any]) -> None:
        copied = copy.deepcopy(dict(document))
        self._validate_document(copied)
        _verify_journal_fingerprints(copied)


class OperationExecutorV2:
    """Координатор долговечных попыток одной операции."""

    def __init__(
        self,
        *,
        store: OperationJournalStoreV2,
        now: Callable[[], datetime],
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.store = store
        self._now = now
        self._id_factory = id_factory or _new_identifier

    def begin(self, definition: OperationDefinitionV2) -> OperationRunV2:
        """Атомарно создать первый журнал с уже завершённым `gate_close`."""

        _checkpoint_operation_deadline_if_scoped_v2()
        with self.store.locked(exclusive=True):
            _checkpoint_operation_deadline_if_scoped_v2()
            if _path_exists_no_follow(self.store.journal_path):
                raise JournalConflictV2("operation journal already exists")
            _checkpoint_operation_deadline_if_scoped_v2()
            document, attempt_id = self._create_initial_unlocked(definition)
            return OperationRunV2(
                status="STARTED",
                operation_id=document["operationId"],
                attempt_id=attempt_id,
            )

    def execute(
        self,
        definition: OperationDefinitionV2,
        *,
        callbacks: StepCallbacksV2,
        terminal_callbacks: TerminalCallbacksV2 | None = None,
        failure_injector: Callable[[FailurePointV2, str], None] | None = None,
    ) -> OperationRunV2:
        """Выполнить или возобновить изменяемый префикс точного плана."""

        inject = failure_injector or (lambda _point, _kind: None)
        _checkpoint_operation_deadline_if_scoped_v2()
        with self.store.locked(exclusive=True):
            _checkpoint_operation_deadline_if_scoped_v2()
            if _path_exists_no_follow(self.store.journal_path):
                journal = self.store._read_unlocked()
                _checkpoint_operation_deadline_if_scoped_v2()
                _verify_definition_matches(journal, definition)
                if journal["phase"] == "TERMINAL_FROZEN":
                    if definition.terminal is None or terminal_callbacks is None:
                        raise JournalConflictV2(
                            "terminal frozen journal requires terminal callbacks"
                        )
                    attempt_id = self._identifier("opa2")
                    return self._execute_terminal_unlocked(
                        journal,
                        attempt_id=attempt_id,
                        terminal=definition.terminal,
                        callbacks=terminal_callbacks,
                        failure_injector=inject,
                    )
                journal, attempt_id = self._append_attempt_unlocked(journal)
            else:
                journal, attempt_id = self._create_initial_unlocked(definition)

            for plan_ordinal, step_definition in enumerate(
                definition.mutable_steps, start=1
            ):
                _checkpoint_operation_deadline_if_scoped_v2()
                journal = self._execute_step_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    plan_ordinal=plan_ordinal,
                    definition=step_definition,
                    callbacks=callbacks,
                    failure_injector=inject,
                )
            if definition.terminal is not None:
                _checkpoint_operation_deadline_if_scoped_v2()
                if terminal_callbacks is None:
                    raise JournalConflictV2(
                        "terminal definition requires terminal callbacks"
                    )
                journal = self._freeze_terminal_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    terminal=definition.terminal,
                    plan_ordinal=1 + len(definition.mutable_steps),
                )
                inject(
                    FailurePointV2.AFTER_TERMINAL_FREEZE_BEFORE_RECEIPT,
                    "terminal_journal_freeze",
                )
                _checkpoint_operation_deadline_if_scoped_v2()
                return self._execute_terminal_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    terminal=definition.terminal,
                    callbacks=terminal_callbacks,
                    failure_injector=inject,
                )
            journal = self._finish_attempt_unlocked(
                journal, attempt_id=attempt_id, outcome="SUCCEEDED"
            )
            _checkpoint_operation_deadline_if_scoped_v2()
            return OperationRunV2(
                status="MUTABLE_COMPLETED",
                operation_id=journal["operationId"],
                attempt_id=attempt_id,
            )

    def _create_initial_unlocked(
        self, definition: OperationDefinitionV2
    ) -> tuple[JsonObject, str]:
        attempt_id = self._identifier("opa2")
        step_id = self._identifier("st2")
        created_at = _timestamp(self._now())
        completed_at = _timestamp(self._now())
        gate = definition.gate_close
        gate_step = {
            "stepId": step_id,
            "ordinal": 0,
            "planId": definition.execution_plan.plan_id,
            "planOrdinal": 0,
            "recordCarrier": "JOURNAL_ATOMIC_BOUNDARY",
            "kind": "gate_close",
            "state": "COMPLETED",
            "commandId": gate.command_id,
            "action": copy.deepcopy(dict(gate.action)),
            "actionFingerprint": gate.action_fingerprint,
            "before": gate.before.to_document(),
            "expectedAfter": gate.expected_after.to_document(),
            "observedAfter": gate.expected_after.to_document(),
            "intentAt": created_at,
            "completedAt": completed_at,
        }
        planned_steps = [
            _planned_step_document(
                step,
                step_id=self._identifier("st2"),
                ordinal=plan_ordinal,
                plan_id=definition.execution_plan.plan_id,
                plan_ordinal=plan_ordinal,
            )
            for plan_ordinal, step in enumerate(
                definition.mutable_steps, start=1
            )
        ]
        projection: JsonObject = {
            "schemaVersion": 2,
            "kind": definition.kind,
            "installationId": definition.installation_id,
            "operationId": definition.operation_id,
            "operation": definition.operation,
            "phase": "DISCOVERED",
            "recoveryPolicy": "REVERSIBLE",
            "executionPlan": definition.execution_plan.to_document(1),
            "abortPlan": None,
            "recoveryPlans": [],
            "discoveryBefore": definition.discovery_before.to_document(),
            "fencedBefore": _bundle_document(definition.fenced_before),
            "desired": _bundle_document(definition.desired),
            "attempts": [
                {
                    "attemptId": attempt_id,
                    "startedAt": created_at,
                    "finishedAt": None,
                    "outcome": "RUNNING",
                }
            ],
            "steps": [gate_step, *planned_steps],
            "changes": [],
            "terminalDefinitionSnapshot": terminal_definition_snapshot_v2(
                definition.terminal
            ),
            "terminalDeleteIntent": None,
            "createdAt": created_at,
            "updatedAt": completed_at,
        }
        document = _with_journal_fingerprint(projection)
        self.store._create_unlocked(document)
        return document, attempt_id

    def _append_attempt_unlocked(
        self, journal: JsonObject
    ) -> tuple[JsonObject, str]:
        if len(journal["attempts"]) >= 64:
            raise JournalConflictV2("operation journal attempt limit reached")
        updated = copy.deepcopy(journal)
        started_at = _timestamp(self._now())
        for attempt in updated["attempts"]:
            if attempt["outcome"] == "RUNNING":
                attempt["outcome"] = "FAILED"
                attempt["finishedAt"] = started_at
        attempt_id = self._identifier("opa2")
        updated["attempts"].append(
            {
                "attemptId": attempt_id,
                "startedAt": started_at,
                "finishedAt": None,
                "outcome": "RUNNING",
            }
        )
        updated = self._persist_unlocked(journal, updated, at=started_at)
        return updated, attempt_id

    def _execute_step_unlocked(
        self,
        journal: JsonObject,
        *,
        attempt_id: str,
        plan_ordinal: int,
        definition: StepDefinitionV2,
        callbacks: StepCallbacksV2,
        failure_injector: Callable[[FailurePointV2, str], None],
    ) -> JsonObject:
        _checkpoint_operation_deadline_if_scoped_v2()
        persisted = _find_plan_step(journal, plan_ordinal)
        if persisted is None:
            if journal["executionPlan"]["firstIncompleteOrdinal"] != plan_ordinal:
                raise JournalIntegrityErrorV2(
                    "missing step does not match first incomplete ordinal"
                )
            updated = copy.deepcopy(journal)
            updated["steps"].append(
                _planned_step_document(
                    definition,
                    step_id=self._identifier("st2"),
                    ordinal=len(updated["steps"]),
                    plan_id=updated["executionPlan"]["planId"],
                    plan_ordinal=plan_ordinal,
                )
            )
            journal = self._persist_unlocked(journal, updated)
            persisted = journal["steps"][-1]
        _verify_persisted_step(persisted, definition, plan_ordinal)
        if persisted["state"] == "COMPLETED":
            if journal["executionPlan"]["firstIncompleteOrdinal"] <= plan_ordinal:
                raise JournalIntegrityErrorV2(
                    "completed step is not behind the plan cursor"
                )
            if definition.kind == "recovery_forward_only":
                return journal
            try:
                persisted_after = ProjectionV2.from_document(
                    persisted["observedAfter"]
                )
            except (KeyError, TypeError, ValueError) as error:
                raise JournalIntegrityErrorV2(
                    "completed step has no valid observedAfter"
                ) from error
            _checkpoint_operation_deadline_if_scoped_v2()
            observed = callbacks.observe(definition)
            _checkpoint_operation_deadline_if_scoped_v2()
            if (
                not callbacks.accepts_after(persisted_after, definition)
                or not callbacks.accepts_completed_current(
                    persisted_after,
                    observed,
                    definition,
                )
            ):
                return self._raise_ambiguous_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    kind=definition.kind,
                )
            return journal
        if definition.kind == "recovery_forward_only":
            return self._execute_forward_only_unlocked(
                journal,
                attempt_id=attempt_id,
                plan_ordinal=plan_ordinal,
                definition=definition,
                failure_injector=failure_injector,
            )

        if persisted["state"] == "PLANNED":
            _checkpoint_operation_deadline_if_scoped_v2()
            observed = callbacks.observe(definition)
            _checkpoint_operation_deadline_if_scoped_v2()
            if not callbacks.accepts_before(observed, definition):
                return self._raise_ambiguous_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    kind=definition.kind,
                )
            journal = self._mark_intent_unlocked(
                journal, plan_ordinal=plan_ordinal
            )
        else:
            _checkpoint_operation_deadline_if_scoped_v2()
            observed = callbacks.observe(definition)
            _checkpoint_operation_deadline_if_scoped_v2()
            matches_before = callbacks.accepts_before(observed, definition)
            matches_after = callbacks.accepts_after(observed, definition)
            matches_intent_resume = callbacks.accepts_intent_resume(
                observed, definition
            )
            if matches_intent_resume and (matches_before or matches_after):
                return self._raise_ambiguous_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    kind=definition.kind,
                )
            if matches_before and matches_after:
                if not callbacks.permits_indistinguishable_replay(
                    observed, definition
                ):
                    return self._raise_ambiguous_unlocked(
                        journal,
                        attempt_id=attempt_id,
                        kind=definition.kind,
                    )
            elif matches_after:
                return self._mark_completed_unlocked(
                    journal,
                    plan_ordinal=plan_ordinal,
                    observed=observed,
                )
            elif not matches_before and not matches_intent_resume:
                return self._raise_ambiguous_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    kind=definition.kind,
                )

        failure_injector(
            FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION,
            definition.kind,
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        callbacks.apply(definition)
        _checkpoint_operation_deadline_if_scoped_v2()
        observed = callbacks.observe(definition)
        _checkpoint_operation_deadline_if_scoped_v2()
        if not callbacks.accepts_after(observed, definition):
            return self._raise_ambiguous_unlocked(
                journal,
                attempt_id=attempt_id,
                kind=definition.kind,
            )
        failure_injector(
            FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED,
            definition.kind,
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        return self._mark_completed_unlocked(
            journal, plan_ordinal=plan_ordinal, observed=observed
        )

    def _execute_forward_only_unlocked(
        self,
        journal: JsonObject,
        *,
        attempt_id: str,
        plan_ordinal: int,
        definition: StepDefinitionV2,
        failure_injector: Callable[[FailurePointV2, str], None],
    ) -> JsonObject:
        _checkpoint_operation_deadline_if_scoped_v2()
        persisted = _find_plan_step(journal, plan_ordinal)
        assert persisted is not None
        if persisted["state"] == "PLANNED":
            if journal["recoveryPolicy"] != "REVERSIBLE":
                return self._raise_ambiguous_unlocked(
                    journal,
                    attempt_id=attempt_id,
                    kind=definition.kind,
                )
            journal = self._mark_intent_unlocked(
                journal, plan_ordinal=plan_ordinal
            )
        elif journal["recoveryPolicy"] == "FORWARD_ONLY":
            return self._mark_completed_unlocked(
                journal,
                plan_ordinal=plan_ordinal,
                observed=definition.expected_after,
            )
        elif journal["recoveryPolicy"] != "REVERSIBLE":
            return self._raise_ambiguous_unlocked(
                journal,
                attempt_id=attempt_id,
                kind=definition.kind,
            )

        failure_injector(
            FailurePointV2.AFTER_INTENT_DURABLE_BEFORE_ACTION,
            definition.kind,
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        updated = copy.deepcopy(journal)
        updated["recoveryPolicy"] = "FORWARD_ONLY"
        journal = self._persist_unlocked(journal, updated)
        failure_injector(
            FailurePointV2.AFTER_ACTION_BEFORE_COMPLETED,
            definition.kind,
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        return self._mark_completed_unlocked(
            journal,
            plan_ordinal=plan_ordinal,
            observed=definition.expected_after,
        )

    def _freeze_terminal_unlocked(
        self,
        journal: JsonObject,
        *,
        attempt_id: str,
        terminal: TerminalDefinitionV2,
        plan_ordinal: int,
    ) -> JsonObject:
        """Одной заменой завершить попытку и навсегда заморозить журнал."""

        _checkpoint_operation_deadline_if_scoped_v2()
        if journal["phase"] == "TERMINAL_FROZEN":
            raise JournalIntegrityErrorV2(
                "terminal frozen journal must not be rewritten"
            )
        if journal["terminalDeleteIntent"] is not None:
            raise JournalIntegrityErrorV2(
                "mutable journal already has terminal delete intent"
            )
        if journal["executionPlan"]["firstIncompleteOrdinal"] != plan_ordinal:
            raise JournalIntegrityErrorV2(
                "terminal freeze does not match the plan cursor"
            )
        required_policy = (
            "REVERSIBLE" if terminal.terminal_kind == "ABORT" else "FORWARD_ONLY"
        )
        if journal["recoveryPolicy"] != required_policy:
            raise JournalConflictV2(
                "terminal kind does not match the durable recovery policy"
            )
        if any(step["state"] != "COMPLETED" for step in journal["steps"]):
            raise JournalIntegrityErrorV2(
                "terminal freeze requires a fully completed mutable prefix"
            )
        _validate_journal_absence_target(
            self.store.journal_path,
            terminal.journal_absence_target.to_document(),
        )

        frozen_at = _timestamp(self._now())
        updated = copy.deepcopy(journal)
        freeze_step = {
            "stepId": self._identifier("st2"),
            "ordinal": len(updated["steps"]),
            "planId": updated["executionPlan"]["planId"],
            "planOrdinal": plan_ordinal,
            "recordCarrier": "JOURNAL_ATOMIC_BOUNDARY",
            "kind": terminal.freeze.kind,
            "state": "COMPLETED",
            "commandId": terminal.freeze.command_id,
            "action": copy.deepcopy(dict(terminal.freeze.action)),
            "actionFingerprint": terminal.freeze.action_fingerprint,
            "before": terminal.freeze.before.to_document(),
            "expectedAfter": terminal.freeze.expected_after.to_document(),
            "observedAfter": terminal.freeze.expected_after.to_document(),
            "intentAt": frozen_at,
            "completedAt": frozen_at,
        }
        updated["steps"].append(freeze_step)
        updated["executionPlan"]["firstIncompleteOrdinal"] = plan_ordinal + 1
        updated["phase"] = "TERMINAL_FROZEN"

        attempts = [
            item
            for item in updated["attempts"]
            if item["attemptId"] == attempt_id
        ]
        if len(attempts) != 1 or attempts[0]["outcome"] != "RUNNING":
            raise JournalIntegrityErrorV2(
                "terminal freeze requires one running current attempt"
            )
        attempts[0]["outcome"] = "SUCCEEDED"
        attempts[0]["finishedAt"] = frozen_at

        completed_step_ids = tuple(
            step["stepId"] for step in updated["steps"]
        )
        context = TerminalContextV2(
            installation_id=updated["installationId"],
            operation_id=updated["operationId"],
            completed_step_ids=completed_step_ids,
            frozen_at=frozen_at,
        )
        terminal_projection = _terminal_projection(terminal, context)
        updated["terminalDeleteIntent"] = {
            **terminal_projection,
            "terminalStateFingerprint": domain_fingerprint(
                _TERMINAL_STATE_DOMAIN, terminal_projection
            ),
        }
        updated["updatedAt"] = frozen_at
        projection = copy.deepcopy(updated)
        projection.pop("journalFingerprint", None)
        frozen = _with_journal_fingerprint(projection)
        _checkpoint_operation_deadline_if_scoped_v2()
        self.store._replace_unlocked(
            frozen,
            expected_journal_fingerprint=journal["journalFingerprint"],
        )
        return frozen

    def _execute_terminal_unlocked(
        self,
        journal: JsonObject,
        *,
        attempt_id: str,
        terminal: TerminalDefinitionV2,
        callbacks: TerminalCallbacksV2,
        failure_injector: Callable[[FailurePointV2, str], None],
    ) -> OperationRunV2:
        """Исполнить только эффекты, заранее связанные замороженным журналом."""

        _checkpoint_operation_deadline_if_scoped_v2()
        _verify_terminal_definition_matches(journal, terminal)
        callback_journal = lambda: copy.deepcopy(journal)

        _checkpoint_operation_deadline_if_scoped_v2()
        if not callbacks.receipt_matches(callback_journal()):
            _checkpoint_operation_deadline_if_scoped_v2()
            callbacks.publish_receipt(callback_journal())
            _checkpoint_operation_deadline_if_scoped_v2()
            if not callbacks.receipt_matches(callback_journal()):
                raise TerminalProofFailedV2(
                    "published receipt does not match the frozen journal"
                )
        failure_injector(
            FailurePointV2.AFTER_RECEIPT_BEFORE_JOURNAL_DELETE,
            terminal.post_freeze_action_kinds[0],
        )
        _checkpoint_operation_deadline_if_scoped_v2()

        if terminal.terminal_kind == "UNINSTALL":
            if (
                callbacks.tombstone_matches is None
                or callbacks.publish_tombstone is None
            ):
                raise JournalConflictV2(
                    "uninstall terminal execution requires tombstone callbacks"
                )
            if not callbacks.tombstone_matches(callback_journal()):
                _checkpoint_operation_deadline_if_scoped_v2()
                callbacks.publish_tombstone(callback_journal())
                _checkpoint_operation_deadline_if_scoped_v2()
                if not callbacks.tombstone_matches(callback_journal()):
                    raise TerminalProofFailedV2(
                        "published tombstone does not match the frozen journal"
                    )
            failure_injector(
                FailurePointV2.AFTER_TOMBSTONE_BEFORE_JOURNAL_DELETE,
                terminal.post_freeze_action_kinds[1],
            )
            _checkpoint_operation_deadline_if_scoped_v2()

        if not callbacks.receipt_matches(callback_journal()):
            raise TerminalProofFailedV2(
                "receipt proof changed before frozen journal deletion"
            )
        if terminal.terminal_kind == "UNINSTALL":
            assert callbacks.tombstone_matches is not None
            if not callbacks.tombstone_matches(callback_journal()):
                raise TerminalProofFailedV2(
                    "tombstone proof changed before frozen journal deletion"
                )
        _checkpoint_operation_deadline_if_scoped_v2()
        self.store._delete_frozen_unlocked(journal)
        return OperationRunV2(
            status="COMPLETED",
            operation_id=journal["operationId"],
            attempt_id=attempt_id,
        )

    def _mark_intent_unlocked(
        self, journal: JsonObject, *, plan_ordinal: int
    ) -> JsonObject:
        updated = copy.deepcopy(journal)
        step = _required_plan_step(updated, plan_ordinal)
        if step["state"] != "PLANNED":
            raise JournalIntegrityErrorV2("only a planned step may gain intent")
        step["state"] = "INTENT_DURABLE"
        step["intentAt"] = _timestamp(self._now())
        return self._persist_unlocked(journal, updated)

    def _mark_completed_unlocked(
        self,
        journal: JsonObject,
        *,
        plan_ordinal: int,
        observed: ProjectionV2,
    ) -> JsonObject:
        updated = copy.deepcopy(journal)
        step = _required_plan_step(updated, plan_ordinal)
        if step["state"] != "INTENT_DURABLE":
            raise JournalIntegrityErrorV2(
                "only durable intent may become completed"
            )
        step["state"] = "COMPLETED"
        step["observedAfter"] = observed.to_document()
        step["completedAt"] = _timestamp(self._now())
        cursor = updated["executionPlan"]["firstIncompleteOrdinal"]
        if cursor != plan_ordinal:
            raise JournalIntegrityErrorV2("completed step does not match cursor")
        updated["executionPlan"]["firstIncompleteOrdinal"] = plan_ordinal + 1
        return self._persist_unlocked(journal, updated)

    def _raise_ambiguous_unlocked(
        self,
        journal: JsonObject,
        *,
        attempt_id: str,
        kind: str,
    ) -> JsonObject:
        self._finish_attempt_unlocked(
            journal, attempt_id=attempt_id, outcome="FAILED"
        )
        raise RecoveryStateAmbiguousV2(
            f"RECOVERY_STATE_AMBIGUOUS: {kind}"
        )

    def _finish_attempt_unlocked(
        self,
        journal: JsonObject,
        *,
        attempt_id: str,
        outcome: str,
    ) -> JsonObject:
        updated = copy.deepcopy(journal)
        attempts = [
            item for item in updated["attempts"] if item["attemptId"] == attempt_id
        ]
        if len(attempts) != 1:
            raise JournalIntegrityErrorV2("attempt is not unique in journal")
        attempt = attempts[0]
        if attempt["outcome"] == outcome and attempt["finishedAt"] is not None:
            return journal
        if attempt["outcome"] != "RUNNING":
            raise JournalIntegrityErrorV2("only a running attempt may finish")
        finished_at = _timestamp(self._now())
        attempt["outcome"] = outcome
        attempt["finishedAt"] = finished_at
        return self._persist_unlocked(journal, updated, at=finished_at)

    def _persist_unlocked(
        self,
        previous: JsonObject,
        updated: JsonObject,
        *,
        at: str | None = None,
    ) -> JsonObject:
        _checkpoint_operation_deadline_if_scoped_v2()
        projection = copy.deepcopy(updated)
        projection.pop("journalFingerprint", None)
        projection["updatedAt"] = at or _timestamp(self._now())
        document = _with_journal_fingerprint(projection)
        self.store._replace_unlocked(
            document,
            expected_journal_fingerprint=previous["journalFingerprint"],
        )
        _checkpoint_operation_deadline_if_scoped_v2()
        return document

    def _identifier(self, prefix: str) -> str:
        value = self._id_factory(prefix)
        _required_identifier(value, prefix, prefix)
        return value


def _verify_definition_matches(
    journal: Mapping[str, Any], definition: OperationDefinitionV2
) -> None:
    fixed_pairs = (
        ("kind", definition.kind),
        ("installationId", definition.installation_id),
        ("operationId", definition.operation_id),
        ("operation", definition.operation),
    )
    for name, expected in fixed_pairs:
        if journal[name] != expected:
            raise JournalConflictV2(f"immutable operation field changed: {name}")
    cursor = journal["executionPlan"]["firstIncompleteOrdinal"]
    if journal["executionPlan"] != definition.execution_plan.to_document(cursor):
        raise JournalConflictV2("immutable execution plan changed")
    bundle_pairs = (
        ("discoveryBefore", definition.discovery_before.to_document()),
        ("fencedBefore", _bundle_document(definition.fenced_before)),
        ("desired", _bundle_document(definition.desired)),
    )
    for name, expected in bundle_pairs:
        if canonical_json_bytes(journal[name]) != canonical_json_bytes(expected):
            raise JournalConflictV2(f"immutable state bundle changed: {name}")
    if journal.get("terminalDefinitionSnapshot") != (
        terminal_definition_snapshot_v2(definition.terminal)
    ):
        raise JournalConflictV2("immutable terminal definition changed")
    gate = journal["steps"][0]
    _verify_persisted_step(gate, definition.gate_close, 0)
    for plan_ordinal, step in enumerate(definition.mutable_steps, start=1):
        persisted = _find_plan_step(journal, plan_ordinal)
        if persisted is not None:
            _verify_persisted_step(persisted, step, plan_ordinal)


def _terminal_projection(
    terminal: TerminalDefinitionV2, context: TerminalContextV2
) -> JsonObject:
    return {
        "terminalKind": terminal.terminal_kind,
        "receiptKind": terminal.receipt_kind,
        "receiptPath": str(terminal.receipt_path),
        "completedStepIds": list(context.completed_step_ids),
        "postFreezeActionKinds": list(terminal.post_freeze_action_kinds),
        "receiptPayloadIntent": terminal.receipt_payload.to_document(context),
        "tombstonePayloadIntent": (
            None
            if terminal.tombstone_payload is None
            else terminal.tombstone_payload.to_document()
        ),
        "journalAbsenceTarget": terminal.journal_absence_target.to_document(),
        "frozenAt": context.frozen_at,
    }


def _verify_terminal_definition_matches(
    journal: Mapping[str, Any], terminal: TerminalDefinitionV2
) -> None:
    if journal["phase"] != "TERMINAL_FROZEN":
        raise JournalIntegrityErrorV2(
            "terminal executor requires a terminal frozen journal"
        )
    steps = journal["steps"]
    freeze_steps = [
        step for step in steps if step["kind"] == "terminal_journal_freeze"
    ]
    if len(freeze_steps) != 1 or freeze_steps[0] is not steps[-1]:
        raise JournalIntegrityErrorV2(
            "terminal freeze must be the final journal-carried step"
        )
    if any(step["state"] != "COMPLETED" for step in steps):
        raise JournalIntegrityErrorV2(
            "terminal frozen journal contains an incomplete step"
        )
    if any(
        step["recordCarrier"] == "FROZEN_TERMINAL_EXECUTOR"
        for step in steps
    ):
        raise JournalIntegrityErrorV2(
            "post-freeze steps must not be appended to the frozen journal"
        )
    freeze = freeze_steps[0]
    _verify_persisted_step(freeze, terminal.freeze, freeze["planOrdinal"])
    if journal["executionPlan"]["firstIncompleteOrdinal"] != (
        freeze["planOrdinal"] + 1
    ):
        raise JournalIntegrityErrorV2(
            "terminal frozen plan cursor does not follow the freeze step"
        )
    if any(attempt["outcome"] == "RUNNING" for attempt in journal["attempts"]):
        raise JournalIntegrityErrorV2(
            "terminal frozen journal contains a running attempt"
        )

    intent = journal["terminalDeleteIntent"]
    completed_step_ids = tuple(step["stepId"] for step in steps)
    context = TerminalContextV2(
        installation_id=journal["installationId"],
        operation_id=journal["operationId"],
        completed_step_ids=completed_step_ids,
        frozen_at=intent["frozenAt"],
    )
    expected = _terminal_projection(terminal, context)
    actual = {
        key: copy.deepcopy(value)
        for key, value in intent.items()
        if key != "terminalStateFingerprint"
    }
    if canonical_json_bytes(actual) != canonical_json_bytes(expected):
        raise JournalConflictV2("immutable terminal definition changed")


def _planned_step_document(
    definition: StepDefinitionV2,
    *,
    step_id: str,
    ordinal: int,
    plan_id: str,
    plan_ordinal: int,
) -> JsonObject:
    return {
        "stepId": step_id,
        "ordinal": ordinal,
        "planId": plan_id,
        "planOrdinal": plan_ordinal,
        "recordCarrier": "JOURNAL_MUTABLE",
        "kind": definition.kind,
        "state": "PLANNED",
        "commandId": definition.command_id,
        "action": copy.deepcopy(dict(definition.action)),
        "actionFingerprint": definition.action_fingerprint,
        "before": definition.before.to_document(),
        "expectedAfter": definition.expected_after.to_document(),
        "observedAfter": None,
        "intentAt": None,
        "completedAt": None,
    }


def _find_plan_step(
    journal: Mapping[str, Any], plan_ordinal: int
) -> JsonObject | None:
    plan_id = journal["executionPlan"]["planId"]
    matches = [
        item
        for item in journal["steps"]
        if item["planId"] == plan_id and item["planOrdinal"] == plan_ordinal
    ]
    if len(matches) > 1:
        raise JournalIntegrityErrorV2("plan ordinal appears more than once")
    return matches[0] if matches else None


def _required_plan_step(
    journal: Mapping[str, Any], plan_ordinal: int
) -> JsonObject:
    step = _find_plan_step(journal, plan_ordinal)
    if step is None:
        raise JournalIntegrityErrorV2("required durable step is missing")
    return step


def _verify_persisted_step(
    persisted: Mapping[str, Any],
    definition: StepDefinitionV2,
    plan_ordinal: int,
) -> None:
    expected = {
        "planOrdinal": plan_ordinal,
        "kind": definition.kind,
        "commandId": definition.command_id,
        "action": copy.deepcopy(dict(definition.action)),
        "actionFingerprint": definition.action_fingerprint,
        "before": definition.before.to_document(),
        "expectedAfter": definition.expected_after.to_document(),
    }
    for name, value in expected.items():
        if canonical_json_bytes(persisted[name]) != canonical_json_bytes(value):
            raise JournalConflictV2(
                f"immutable durable step field changed: {plan_ordinal}.{name}"
            )
    expected_carrier = (
        "JOURNAL_ATOMIC_BOUNDARY"
        if definition.kind in {"gate_close", "terminal_journal_freeze"}
        else "JOURNAL_MUTABLE"
    )
    if persisted["recordCarrier"] != expected_carrier:
        raise JournalConflictV2(
            f"immutable step carrier changed: {plan_ordinal}"
        )


def _same_projection(left: ProjectionV2, right: ProjectionV2) -> bool:
    return canonical_json_bytes(left.to_document()) == canonical_json_bytes(
        right.to_document()
    )


def _projection_document(value: ProjectionV2 | None) -> JsonObject | None:
    return None if value is None else value.to_document()


def _bundle_document(value: StateBundleV2 | None) -> JsonObject | None:
    return None if value is None else value.to_document()


def _with_journal_fingerprint(projection: Mapping[str, Any]) -> JsonObject:
    result = copy.deepcopy(dict(projection))
    result["journalFingerprint"] = domain_fingerprint(_JOURNAL_DOMAIN, result)
    return result


def _verify_journal_fingerprints(document: Mapping[str, Any]) -> None:
    projection = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key != "journalFingerprint"
    }
    expected = domain_fingerprint(_JOURNAL_DOMAIN, projection)
    if document.get("journalFingerprint") != expected:
        raise JournalIntegrityErrorV2("journalFingerprint mismatch")
    plan = document["executionPlan"]
    plan_projection = {
        key: copy.deepcopy(plan[key])
        for key in (
            "planId",
            "machineId",
            "selectedBranchId",
            "selectionSource",
            "composedStepKinds",
        )
    }
    if plan["planDefinitionFingerprint"] != domain_fingerprint(
        _PLAN_DOMAIN, plan_projection
    ):
        raise JournalIntegrityErrorV2("planDefinitionFingerprint mismatch")
    for step in document["steps"]:
        expected_action = domain_fingerprint(
            _STEP_ACTION_DOMAIN, {"action": copy.deepcopy(step["action"])}
        )
        if step["actionFingerprint"] != expected_action:
            raise JournalIntegrityErrorV2(
                f"actionFingerprint mismatch for {step['stepId']}"
            )
    for name in ("discoveryBefore", "fencedBefore", "desired"):
        bundle = document[name]
        if bundle is None:
            continue
        bundle_projection = {
            key: copy.deepcopy(value)
            for key, value in bundle.items()
            if key != "bundleFingerprint"
        }
        if bundle["bundleFingerprint"] != domain_fingerprint(
            _STATE_BUNDLE_DOMAIN, bundle_projection
        ):
            raise JournalIntegrityErrorV2(f"{name}.bundleFingerprint mismatch")
    terminal = document["terminalDeleteIntent"]
    if terminal is not None:
        terminal_projection = {
            key: copy.deepcopy(value)
            for key, value in terminal.items()
            if key != "terminalStateFingerprint"
        }
        if terminal["terminalStateFingerprint"] != domain_fingerprint(
            _TERMINAL_STATE_DOMAIN, terminal_projection
        ):
            raise JournalIntegrityErrorV2("terminalStateFingerprint mismatch")


def _ensure_private_directory(path: Path) -> None:
    try:
        information = path.lstat()
    except FileNotFoundError:
        parent = path.parent
        parent_information = parent.lstat()
        if not stat.S_ISDIR(parent_information.st_mode) or stat.S_ISLNK(
            parent_information.st_mode
        ):
            raise UnsafeLifecyclePathV2(f"unsafe parent directory: {parent}")
        path.mkdir(mode=0o700)
        information = path.lstat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        raise UnsafeLifecyclePathV2(f"unsafe private directory: {path}")


def _ensure_lock_file(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_CREAT
        | os.O_RDWR
        | _flag("O_NOFOLLOW")
        | _flag("O_CLOEXEC"),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        _validate_private_regular_file(descriptor, path)
        _sync_file(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _validate_private_regular_file(descriptor: int, path: Path) -> None:
    information = os.fstat(descriptor)
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o600
        or information.st_nlink != 1
    ):
        raise UnsafeLifecyclePathV2(f"unsafe private file: {path}")


def _atomic_create_private(path: Path, payload: bytes) -> None:
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
        except FileExistsError as error:
            raise JournalConflictV2("operation journal appeared concurrently") from error
        linked = True
        os.unlink(temporary)
        _fsync_directory(path.parent)
        _verify_persisted_payload(path, payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not linked or temporary.exists():
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _atomic_replace_private(path: Path, payload: bytes) -> None:
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
        existing = os.open(
            path,
            os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
        )
        try:
            _validate_private_regular_file(existing, path)
        finally:
            os.close(existing)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        _verify_persisted_payload(path, payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _verify_persisted_payload(path: Path, expected: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_NOFOLLOW") | _flag("O_CLOEXEC"),
    )
    try:
        _validate_private_regular_file(descriptor, path)
        actual = _read_bounded(descriptor, _MAX_JOURNAL_BYTES)
    finally:
        os.close(descriptor)
    if actual != expected:
        raise JournalIntegrityErrorV2("persisted journal differs from written bytes")


def _sync_file(descriptor: int) -> None:
    os.fsync(descriptor)
    full_sync = getattr(fcntl, "F_FULLFSYNC", None)
    if full_sync is not None:
        fcntl.fcntl(descriptor, full_sync)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | _flag("O_DIRECTORY") | _flag("O_NOFOLLOW"),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_journal_absence_target(
    journal_path: Path, projection_document: Mapping[str, Any]
) -> JsonObject:
    """Проверить неизменяемую цель отсутствия до удаления журнала."""

    projection = ProjectionV2.from_document(projection_document)
    if projection.schema_id != "absence-proof-v2":
        raise JournalIntegrityErrorV2(
            "journal absence target must be an absence-proof-v2 projection"
        )
    value = copy.deepcopy(dict(projection.value))
    proof_projection = {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key != "proofFingerprint"
    }
    if value.get("proofFingerprint") != domain_fingerprint(
        _ABSENCE_PROOF_DOMAIN, proof_projection
    ):
        raise JournalIntegrityErrorV2("absence proof fingerprint mismatch")
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": value,
    }
    if projection.value_fingerprint != domain_fingerprint(
        _ABSENCE_PROJECTION_DOMAIN, envelope
    ):
        raise JournalIntegrityErrorV2(
            "absence proof projection fingerprint mismatch"
        )
    if value.get("directorySyncCompleted") is not True:
        raise JournalIntegrityErrorV2(
            "journal absence target is not directory-synchronized"
        )
    entries = value.get("entries")
    if type(entries) is not list or len(entries) != 1:
        raise JournalIntegrityErrorV2(
            "journal absence target must contain exactly one entry"
        )
    entry = entries[0]
    if (
        entry["path"] != str(journal_path)
        or entry["basename"] != journal_path.name
    ):
        raise JournalIntegrityErrorV2(
            "journal absence target does not identify the journal"
        )
    descriptor = _open_verified_absence_parent(journal_path, entry)
    os.close(descriptor)
    return copy.deepcopy(entry)


def _open_verified_absence_parent(
    journal_path: Path, entry: Mapping[str, Any]
) -> int:
    descriptor = os.open(
        journal_path.parent,
        os.O_RDONLY
        | _flag("O_DIRECTORY")
        | _flag("O_NOFOLLOW")
        | _flag("O_CLOEXEC"),
    )
    try:
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_dev != entry["parentDevice"]
            or parent.st_ino != entry["parentInode"]
        ):
            raise JournalIntegrityErrorV2(
                "journal absence target parent identity changed"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _require_absent_at(directory_descriptor: int, basename: str) -> None:
    try:
        os.stat(
            basename,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise JournalConflictV2(
        "journal reappeared while proving synchronized absence"
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while persisting operation journal")
        view = view[written:]


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        block = os.read(descriptor, min(1024 * 1024, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise JournalIntegrityErrorV2("operation journal exceeds 16 MiB")
    return payload


def _load_json_bytes(payload: bytes, *, label: str) -> JsonObject:
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_unique_object
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise JournalIntegrityErrorV2(f"invalid JSON in {label}: {error}") from error
    if type(value) is not dict:
        raise JournalIntegrityErrorV2(f"JSON root is not an object: {label}")
    return value


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise JournalIntegrityErrorV2(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _path_exists_no_follow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise JournalIntegrityErrorV2("clock must return an aware datetime")
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _new_identifier(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(16)}"


def _required_identifier(value: object, prefix: str, label: str) -> str:
    expected_prefix = prefix + "_"
    if (
        type(value) is not str
        or not value.startswith(expected_prefix)
        or len(value) != len(expected_prefix) + 32
        or any(character not in "0123456789abcdef" for character in value[len(expected_prefix) :])
    ):
        raise JournalIntegrityErrorV2(f"invalid {label}")
    return value


def _required_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise JournalIntegrityErrorV2(f"invalid SHA-256: {label}")
    return value


def _required_string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise JournalIntegrityErrorV2(f"invalid string: {label}")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    if type(value) is not dict or set(value) != expected:
        raise JournalIntegrityErrorV2(f"{label} has unexpected fields")


def _flag(name: str) -> int:
    return int(getattr(os, name, 0))
