"""Производственная композиция обновления принятой активации версии 2.

Модуль связывает полное долговечное определение операции с физическими
портами.  Ни один внешний эффект не разрешается, пока источник подготовки и
снимок исполняемого файла Codex не подтверждены повторно.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, ContextManager, Mapping, Protocol

from .activation_gateway_v2 import _LIFECYCLE_SCHEMA_SHA256
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .installer_update_operation_v2 import (
    ActivationCommitReceiptStoreV2,
    UpdateMatchedActiveOperationV2,
    UpdateStepPortV2,
    UpdateStepPortsV2,
)
from .lifecycle_constraint_matcher_v2 import (
    matches_registry_constraint_v2,
    matches_shutdown_constraint_v2,
)
from .lifecycle_operation_v2 import (
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StepCallbacksV2,
    StepDefinitionV2,
    TerminalCallbacksV2,
)
from . import operation_deadline_v2
from . import operation_process_group_supervisor_v2
from . import supervised_subprocess_v2


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_REGISTRY_DOMAIN = "codex-smart/registry-state/v2"
_REGISTRY_PLAN_DOMAIN = "codex-smart/registry-update-plan/v2"
_REGISTRY_RECEIPT_DOMAIN = "codex-smart/registry-step-receipt/v2"
_REGISTRY_SUBRECEIPT_DOMAIN = "codex-smart/registry-substep-receipt/v2"
_FILE_DOMAIN = "codex-smart/file-object/v2"
_MARKETPLACE_IDENTITY_DOMAIN = "codex-smart/registry-marketplace-identity/v2"
_PLUGIN_IDENTITY_DOMAIN = "codex-smart/registry-plugin-identity/v2"
_CONFIG_SEMANTIC_DOMAIN = "codex-smart/registry-config-semantic/v2"
_MARKETPLACE_LIST_DOMAIN = "codex-smart/registry-marketplace-list/v2"
_PLUGIN_LIST_DOMAIN = "codex-smart/registry-plugin-list/v2"
_ARGV_DOMAIN = "codex-smart/registry-command-argv/v2"
_LAUNCHER_SET_DOMAIN = "codex-smart/launcher-set/v2"
_LAUNCHER_PROJECTION_DOMAIN = "codex-smart/launcher-set-projection/v2"
_LAUNCHER_ENTRY_DOMAIN = "codex-smart/launcher-entry/v2"
_LAUNCHER_PLAN_DOMAIN = "codex-smart/launcher-update-plan/v2"
_MARKETPLACE_NAME = "codex-settings-adaptive"
_PLUGIN_ID = "codex-smart-subagents@codex-settings-adaptive"
_PLUGIN_NAME = "codex-smart-subagents"
_MAX_RECEIPT_BYTES = 1024 * 1024
_CANDIDATE_AUTHORIZATION_DOMAIN = "codex-smart/candidate-spawn-authorization/v2"


class RegistryCommandRunnerV2(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_ms: int,
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class LauncherBindingV2:
    """Одна принадлежащая установке стабильная ссылка загрузчика."""

    name: str
    role: str
    path: Path
    target: Path
    expected_resolved_target: Path

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name or len(self.name) > 128:
            raise TypeError("name must be a non-empty bounded string")
        if self.role not in {
            "gateway",
            "admin",
            "highfd",
            "hook",
            "tool-server",
            "controller",
        }:
            raise TypeError("role is not a supported launcher role")
        for field_name in ("path", "target", "expected_resolved_target"):
            value = getattr(self, field_name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise TypeError(f"{field_name} must be an absolute Path")
        if self.path.name != self.name:
            raise TypeError("launcher name must equal the path basename")


@dataclass(frozen=True)
class LauncherUpdatePlanV2:
    """Снимок старых и ожидаемых новых файлов за стабильными ссылками."""

    installation_id: str
    operation_id: str
    bindings: tuple[LauncherBindingV2, ...]
    before: ProjectionV2
    expected_after: ProjectionV2
    plan_fingerprint: str

    def __post_init__(self) -> None:
        if _INSTALLATION_ID.fullmatch(self.installation_id) is None:
            raise TypeError("installation_id must be an ins2 identifier")
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise TypeError("operation_id must be an op2 identifier")
        object.__setattr__(self, "bindings", tuple(self.bindings))
        if not 1 <= len(self.bindings) <= 16:
            raise TypeError("bindings must contain between one and sixteen items")
        if len({item.name for item in self.bindings}) != len(self.bindings):
            raise TypeError("launcher names must be unique")
        if len({item.path for item in self.bindings}) != len(self.bindings):
            raise TypeError("launcher paths must be unique")
        if not all(isinstance(item, LauncherBindingV2) for item in self.bindings):
            raise TypeError("every binding must be LauncherBindingV2")
        if (
            not isinstance(self.before, ProjectionV2)
            or not isinstance(self.expected_after, ProjectionV2)
            or self.before.schema_id != "launcher-set-v2"
            or self.expected_after.schema_id != "launcher-set-v2"
        ):
            raise TypeError("launcher plan requires launcher-set projections")
        if self.plan_fingerprint != _launcher_plan_fingerprint(self):
            _fail("LAUNCHER_PLAN_INVALID", "отпечаток плана загрузчиков неверен")


def build_launcher_update_plan_v2(
    *,
    installation_id: str,
    operation_id: str,
    bindings: tuple[LauncherBindingV2, ...],
) -> LauncherUpdatePlanV2:
    """До журнала закрепить старый и уже материализованный новый набор."""

    copied = tuple(bindings)
    before = _observe_launcher_bindings(copied, expected=False)
    expected_after = _launcher_set_projection(
        copied,
        tuple(item.expected_resolved_target for item in copied),
    )
    draft = object.__new__(LauncherUpdatePlanV2)
    object.__setattr__(draft, "installation_id", installation_id)
    object.__setattr__(draft, "operation_id", operation_id)
    object.__setattr__(draft, "bindings", copied)
    object.__setattr__(draft, "before", before)
    object.__setattr__(draft, "expected_after", expected_after)
    object.__setattr__(draft, "plan_fingerprint", "0" * 64)
    return LauncherUpdatePlanV2(
        installation_id=installation_id,
        operation_id=operation_id,
        bindings=copied,
        before=before,
        expected_after=expected_after,
        plan_fingerprint=_launcher_plan_fingerprint(draft),
    )


def build_launcher_step_definition_v2(
    plan: LauncherUpdatePlanV2,
) -> StepDefinitionV2:
    """Построить типизированное намерение проверки стабильных ссылок."""

    if not isinstance(plan, LauncherUpdatePlanV2):
        raise TypeError("plan must be LauncherUpdatePlanV2")
    before_entries = _launcher_entries(plan.before)
    after_entries = _launcher_entries(plan.expected_after)
    operations = []
    for binding, before_entry, after_entry in zip(
        plan.bindings, before_entries, after_entries, strict=True
    ):
        operations.append(
            {
                "name": binding.name,
                "role": binding.role,
                "method": "write-replace",
                "targetPath": str(binding.path),
                "beforeFingerprint": _launcher_entry_fingerprint(before_entry),
                "expectedAfterFingerprint": _launcher_entry_fingerprint(after_entry),
            }
        )
    return StepDefinitionV2(
        kind="launchers",
        command_id=None,
        action={
            "actionKind": "launcher-set-mutation",
            "mode": "INSTALL_OR_REPLACE",
            "operations": operations,
            "durability": "FSYNC_EACH_FILE_AND_PARENT",
        },
        before=plan.before,
        expected_after=plan.expected_after,
    )


def build_launcher_step_port_v2(
    *,
    plan: LauncherUpdatePlanV2,
    definition: StepDefinitionV2,
) -> UpdateStepPortV2:
    """Проверить либо атомарно переиздать точные стабильные ссылки."""

    if not isinstance(plan, LauncherUpdatePlanV2):
        raise TypeError("plan must be LauncherUpdatePlanV2")
    expected_definition = build_launcher_step_definition_v2(plan)
    if definition != expected_definition:
        _fail(
            "LAUNCHER_STEP_DEFINITION_INVALID",
            "шаг launchers отличается от закреплённого плана",
        )

    def validate(received: StepDefinitionV2) -> None:
        if received != expected_definition:
            _fail(
                "LAUNCHER_STEP_DEFINITION_CHANGED",
                "исполнитель получил другое определение launchers",
            )

    def observe(received: StepDefinitionV2) -> ProjectionV2:
        validate(received)
        observed = _observe_launcher_bindings(plan.bindings, expected=False)
        if observed == plan.before or observed == plan.expected_after:
            return observed
        _fail(
            "LAUNCHER_STATE_AMBIGUOUS",
            "стабильные ссылки разрешаются не в old и не в candidate набор",
        )

    def apply(received: StepDefinitionV2) -> None:
        validate(received)
        current = observe(received)
        if current != plan.before and current != plan.expected_after:
            _fail("LAUNCHER_STATE_AMBIGUOUS", "набор загрузчиков изменился")
        for binding in plan.bindings:
            _atomic_replace_launcher_symlink(binding, plan.operation_id)
        observed = _observe_launcher_bindings(plan.bindings, expected=False)
        if observed != plan.expected_after:
            _fail(
                "LAUNCHER_APPLY_FAILED",
                "стабильные ссылки не разрешились в candidate файлы",
            )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, _definition: (
            observed == plan.before or observed == plan.expected_after
        ),
        matches_after=lambda observed, _definition: observed == plan.expected_after,
        replay_safe_when_indistinguishable=lambda observed, _definition: (
            observed == plan.expected_after
        ),
        completed_current_matches=lambda persisted, current, _definition: (
            persisted == current == plan.expected_after
        ),
    )


def build_shutdown_socket_cleanup_step_definition_v2(
    *,
    plan: Any,
    shutdown_constraint: ProjectionV2,
) -> StepDefinitionV2:
    """Связать файловую очистку с заранее записанным shutdown-intent."""

    from .shutdown_socket_cleanup_v2 import ShutdownSocketCleanupPlanV2

    if not isinstance(plan, ShutdownSocketCleanupPlanV2) or not plan.complete:
        raise TypeError("plan must be a complete ShutdownSocketCleanupPlanV2")
    if (
        not isinstance(shutdown_constraint, ProjectionV2)
        or shutdown_constraint.schema_id != "shutdown-intent-v2"
        or shutdown_constraint.value.get("status") != "EXPECTED_SHUTDOWN_PROOF"
    ):
        raise TypeError("shutdown_constraint must expect a shutdown proof")
    return StepDefinitionV2(
        kind="shutdown_socket_cleanup",
        command_id=None,
        action=plan.action,
        before=shutdown_constraint,
        expected_after=_shutdown_absence_projection(plan),
    )


def build_controller_shutdown_constraint_v2(
    *,
    codex_home: Path,
    shell_session_id: str,
    operation_id: str,
    command_id: str,
    controller_before: ProjectionV2,
    lock_path: Path,
) -> ProjectionV2:
    """Вычислить только детерминированные поля будущей shutdown-квитанции."""

    from .lifecycle_controller_protocol_v2 import (
        build_lifecycle_controller_request_v2,
    )

    if controller_before.schema_id != "controller-state-v2":
        raise TypeError("controller_before must be controller-state-v2")
    before = copy.deepcopy(dict(controller_before.value))
    if not isinstance(lock_path, Path) or not lock_path.is_absolute():
        raise TypeError("lock_path must be an absolute Path")
    epoch = before.get("controlEpoch")
    socket_value = before.get("socket")
    if (
        type(epoch) is not int
        or epoch < 1
        or type(socket_value) is not dict
        or type(before.get("instanceId")) is not str
        or type(before.get("pid")) is not int
        or type(before.get("processStartMarker")) is not str
        or type(before.get("processGroupId")) is not int
    ):
        _fail(
            "SHUTDOWN_CONSTRAINT_INVALID",
            "before не содержит фактическую идентичность контроллера",
        )
    request = build_lifecycle_controller_request_v2(
        codex_home=codex_home,
        shell_session_id=shell_session_id,
        method="shutdown",
        controller_identity=str(before["controllerIdentity"]),
        instance_id=str(before["instanceId"]),
        controller_start_id=str(before["controllerStartId"]),
        command_id=command_id,
        expected_control_epoch=epoch,
        operation_id=operation_id,
        params={},
    )
    next_epoch = epoch + 1
    socket_intent = {
        "path": socket_value["path"],
        "device": socket_value["device"],
        "inode": socket_value["inode"],
        "ownerUid": socket_value["ownerUid"],
        "ownerGid": socket_value["ownerGid"],
        "mode": socket_value["mode"],
        "controllerPid": before["pid"],
        "controllerStartMarker": before["processStartMarker"],
        "controllerProcessGroupId": before["processGroupId"],
        "lockPath": str(lock_path),
        "processExitRequired": True,
        "exclusiveLockRequired": True,
    }
    result_fingerprint = domain_fingerprint(
        "codex-smart/controller-command-result/v2",
        {
            "method": "shutdown",
            "payload": {
                "status": "SHUTDOWN_COMMITTED",
                "previousControlEpoch": epoch,
                "newControlEpoch": next_epoch,
                "socketIntent": socket_intent,
            },
        },
    )
    controller_after = {
        **before,
        "controlEpoch": next_epoch,
        "state": "STOPPED",
        "maintenanceMode": None,
        "operationId": None,
        "socket": None,
        "lockHeld": False,
        "acceptingNewRoutes": False,
        "quiescent": True,
    }
    value = {
        "controllerAfter": controller_after,
        "operationId": operation_id,
        "commandId": command_id,
        "requestFingerprint": request["requestFingerprint"],
        "commandReceiptFingerprint": result_fingerprint,
        "previousControlEpoch": epoch,
        "newControlEpoch": next_epoch,
        "targetPid": before["pid"],
        "targetStartMarker": before["processStartMarker"],
        "targetProcessGroupId": before["processGroupId"],
        "socket": socket_value,
        "lockPath": str(lock_path),
        "processExitProofFingerprint": None,
        "exclusiveLockProofFingerprint": None,
        "status": "EXPECTED_SHUTDOWN_PROOF",
    }
    return _projection(
        "shutdown-intent-v2",
        value,
        "codex-smart/shutdown-intent/v2",
    )


def build_shutdown_socket_cleanup_step_port_v2(
    *,
    plan: Any,
    definition: StepDefinitionV2,
    shutdown_proof_provider: Callable[[], Any],
    process_start_marker_provider: Callable[[int], str] | None = None,
) -> UpdateStepPortV2:
    """Собрать порт unlink только после свежих exit и exclusive-lock proofs."""

    from .child_guard_v2 import system_process_start_marker_v2
    from .shutdown_socket_cleanup_v2 import (
        ShutdownSocketCleanupPlanV2,
        ShutdownSocketCleanupStateV2,
        apply_shutdown_socket_cleanup_v2,
        observe_shutdown_socket_cleanup_v2,
    )

    if not isinstance(plan, ShutdownSocketCleanupPlanV2) or not plan.complete:
        raise TypeError("plan must be a complete ShutdownSocketCleanupPlanV2")
    expected = build_shutdown_socket_cleanup_step_definition_v2(
        plan=plan,
        shutdown_constraint=definition.before,
    )
    if definition != expected:
        _fail(
            "SHUTDOWN_CLEANUP_DEFINITION_INVALID",
            "определение очистки socket отличается от плана",
        )
    if not callable(shutdown_proof_provider):
        raise TypeError("shutdown_proof_provider must be callable")
    marker_provider = process_start_marker_provider or system_process_start_marker_v2
    if not callable(marker_provider):
        raise TypeError("process_start_marker_provider must be callable")

    def validate(received: StepDefinitionV2) -> None:
        if received != expected:
            _fail(
                "SHUTDOWN_CLEANUP_DEFINITION_CHANGED",
                "исполнитель получил другое определение очистки socket",
            )

    def observe(received: StepDefinitionV2) -> ProjectionV2:
        validate(received)
        shutdown = shutdown_proof_provider()
        observation = observe_shutdown_socket_cleanup_v2(
            plan=plan,
            shutdown=shutdown,
            process_start_marker_provider=marker_provider,
        )
        if observation.state is ShutdownSocketCleanupStateV2.AFTER:
            if observation.absence_projection != expected.expected_after:
                _fail(
                    "SHUTDOWN_CLEANUP_OBSERVATION_INVALID",
                    "absence socket отличается от долговечного expectedAfter",
                )
            return expected.expected_after
        return _shutdown_orphan_projection(
            expected.before,
            process_exit_fingerprint=(
                observation.orphan.process_exit_proof_fingerprint
            ),
            exclusive_lock_fingerprint=(
                observation.orphan.exclusive_lock_proof_fingerprint
            ),
        )

    def apply(received: StepDefinitionV2) -> None:
        validate(received)
        shutdown = shutdown_proof_provider()
        observation = observe_shutdown_socket_cleanup_v2(
            plan=plan,
            shutdown=shutdown,
            process_start_marker_provider=marker_provider,
        )
        if observation.state is ShutdownSocketCleanupStateV2.AFTER:
            return
        result = apply_shutdown_socket_cleanup_v2(
            plan=plan,
            shutdown=shutdown,
            orphan=observation.orphan,
            process_start_marker_provider=marker_provider,
        )
        if result.absence_projection != expected.expected_after:
            _fail(
                "SHUTDOWN_CLEANUP_APPLY_FAILED",
                "очистка вернула другое доказательство отсутствия",
            )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, received: (
            matches_shutdown_constraint_v2(
                observed,
                received.before,
                require_orphan_proof=True,
            )
            or observed == received.expected_after
        ),
        matches_after=lambda observed, received: observed == received.expected_after,
        replay_safe_when_indistinguishable=lambda observed, received: (
            observed == received.expected_after
        ),
        completed_current_matches=lambda persisted, current, received: (
            persisted == current == received.expected_after
        ),
    )


def build_verify_candidate_step_port_v2(
    *,
    definition: StepDefinitionV2,
    proof: Any,
    preparation_receipt: Any,
    acceptance_proof_provider: Callable[[], Any],
) -> UpdateStepPortV2:
    """Повторно доказать prepared activation и принятое управление кандидата."""

    from .activation_preparation_v2 import (
        ActivationPreparationReceiptV2,
        capture_file_projection_v2,
        capture_tree_projection_v2,
    )
    from .activation_transition_v2 import ActivationTransitionProofV2

    if not isinstance(proof, ActivationTransitionProofV2) or not proof.complete:
        raise TypeError("proof must be a complete ActivationTransitionProofV2")
    if not isinstance(preparation_receipt, ActivationPreparationReceiptV2):
        raise TypeError("preparation_receipt must be ActivationPreparationReceiptV2")
    activation = preparation_receipt.prepared.activation
    expected = StepDefinitionV2(
        kind="verify_candidate",
        command_id=None,
        action={
            "actionKind": "verify",
            "predicate": "candidate",
            "timeoutMs": 30_000,
        },
        before=activation,
        expected_after=activation,
    )
    if definition != expected:
        _fail(
            "VERIFY_CANDIDATE_DEFINITION_INVALID",
            "verify_candidate не связан с prep receipt",
        )
    if not callable(acceptance_proof_provider):
        raise TypeError("acceptance_proof_provider must be callable")

    def verify(received: StepDefinitionV2) -> ProjectionV2:
        if received != expected:
            _fail(
                "VERIFY_CANDIDATE_DEFINITION_CHANGED",
                "исполнитель получил другой verify_candidate",
            )
        receipt = preparation_receipt
        intent = receipt.activation_intent
        try:
            observed_tree = capture_tree_projection_v2(
                intent.activation_dir,
                schema_sha256=receipt.activation_tree.schema_sha256,
            )
            observed_activation_file = capture_file_projection_v2(
                intent.activation_file_path,
                schema_sha256=receipt.activation_file.schema_sha256,
            )
            link_info = os.lstat(proof.layout.marketplace_link)
            link_target = os.readlink(proof.layout.marketplace_link)
            resolved_marketplace = proof.layout.marketplace_link.resolve(strict=True)
        except (OSError, ValueError) as error:
            raise InstallerUpdateCompositionV2Error(
                "VERIFY_CANDIDATE_FAILED",
                "физические объекты кандидата недоступны",
            ) from error
        expected_target = f"activations/{intent.activation_id}/marketplace"
        if (
            observed_tree != receipt.activation_tree
            or observed_activation_file != receipt.activation_file
            or not stat.S_ISLNK(link_info.st_mode)
            or link_info.st_uid != os.getuid()
            or link_target != expected_target
            or resolved_marketplace
            != (intent.activation_dir / "marketplace").resolve(strict=True)
        ):
            _fail(
                "VERIFY_CANDIDATE_FAILED",
                "дерево или активная ссылка кандидата изменились",
            )
        acceptance = acceptance_proof_provider()
        if (
            getattr(acceptance, "complete", False) is not True
            or getattr(acceptance, "operation_id", None) != intent.operation_id
            or getattr(acceptance, "activation_id", None) != intent.activation_id
            or getattr(acceptance, "database_id", None) != intent.database_id
            or getattr(acceptance, "activation_proof_fingerprint", None)
            != proof.proof_fingerprint
        ):
            _fail(
                "VERIFY_CANDIDATE_ACCEPTANCE_INVALID",
                "acceptance proof относится к другому кандидату",
            )
        return activation

    return UpdateStepPortV2(
        observe=verify,
        apply=lambda received: verify(received),
        matches_before=lambda observed, received: observed == received.before,
        matches_after=lambda observed, received: observed == received.expected_after,
        replay_safe_when_indistinguishable=lambda observed, received: (
            observed == received.before == received.expected_after
        ),
        completed_current_matches=lambda persisted, current, received: (
            persisted == current == received.expected_after
        ),
    )


@dataclass
class InstallerUpdateCompositionV2Error(RuntimeError):
    """Закрытый отказ сборки производственной операции обновления."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class UpdateMatchedActiveDefinitionPlansV2:
    """Полное определение и чистые планы его физических переходов."""

    definition: OperationDefinitionV2
    staged: Any
    activation_link_plan: Any
    manifest_commit_plan: Any
    shutdown_cleanup_plan: Any
    candidate_action: Any
    controller_definitions: Mapping[str, StepDefinitionV2]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "controller_definitions",
            copy.deepcopy(dict(self.controller_definitions)),
        )


@dataclass(frozen=True)
class InstallerUpdateCompositionV2:
    """Готовая производственная операция и все её связанные объекты."""

    definition: OperationDefinitionV2
    operation: UpdateMatchedActiveOperationV2
    ports: UpdateStepPortsV2
    callbacks: StepCallbacksV2
    terminal_callbacks: TerminalCallbacksV2
    receipt_store: ActivationCommitReceiptStoreV2
    executor: OperationExecutorV2
    plans: UpdateMatchedActiveDefinitionPlansV2
    candidate_authorization_store: CandidateSpawnAuthorizationStoreV2

    def as_main_journal_recovery_v2(
        self,
        *,
        installation_lock: Callable[[], ContextManager[None]],
        controller_recovery: Any | None = None,
        controller_port: Any | None = None,
    ) -> Any:
        """Вернуть готовый контекст ``MainJournalRecoveryV2`` без догадок."""

        from .installer_recovery_v2 import MainJournalRecoveryV2

        return MainJournalRecoveryV2(
            executor=self.executor,
            definition=self.definition,
            callbacks=self.callbacks,
            terminal_callbacks=self.terminal_callbacks,
            installation_lock=installation_lock,
            controller_recovery=controller_recovery,
            controller_port=controller_port,
            execute_operation=self.operation.execute,
        )


@dataclass(frozen=True)
class InstallerUpdateRecoveryEvidenceV2:
    """Единый проверенный снимок main journal, definition, receipt и proof."""

    journal: Mapping[str, Any]
    definition: Any
    preparation_receipt: Any
    transition_proof: Any

    def __post_init__(self) -> None:
        object.__setattr__(self, "journal", copy.deepcopy(dict(self.journal)))


@dataclass(frozen=True)
class RegistryRuntimeBindingsV2:
    """Неперсистентные зависимости реестра, не выводимые из journal."""

    working_directory: Path
    plugin_relative_path: Path
    plugin_version: str
    install_policy: str
    auth_policy: str
    command_runner: RegistryCommandRunnerV2

    def __post_init__(self) -> None:
        if (
            not isinstance(self.working_directory, Path)
            or not self.working_directory.is_absolute()
        ):
            raise TypeError("working_directory must be an absolute Path")
        _require_directory(self.working_directory, private=False)
        if (
            not isinstance(self.plugin_relative_path, Path)
            or self.plugin_relative_path.is_absolute()
            or ".." in self.plugin_relative_path.parts
        ):
            raise TypeError("plugin_relative_path must be a safe relative Path")
        for name in ("plugin_version", "install_policy", "auth_policy"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value) > 256:
                raise TypeError(f"{name} must be a non-empty bounded string")
        if not callable(self.command_runner):
            raise TypeError("command_runner must be callable")


@dataclass(frozen=True)
class CandidateSpawnAuthorizationStoreV2:
    """Частное хранилище raw token до доказанной готовности кандидата."""

    path: Path
    installation_id: str
    operation_id: str
    action_fingerprint: str
    readiness_token_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise TypeError("path must be an absolute Path")
        if _INSTALLATION_ID.fullmatch(self.installation_id) is None:
            raise TypeError("installation_id must be an ins2 identifier")
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise TypeError("operation_id must be an op2 identifier")
        for name in ("action_fingerprint", "readiness_token_hash"):
            if _SHA256.fullmatch(getattr(self, name)) is None:
                raise TypeError(f"{name} must be a lowercase SHA-256")
        _require_directory(self.path.parent, private=True)

    def publish(self, readiness_token: str) -> None:
        document = self._document(readiness_token)
        payload = canonical_json_bytes(document)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        parent = self._open_parent()
        try:
            try:
                descriptor = os.open(
                    self.path.name,
                    flags,
                    0o600,
                    dir_fd=parent,
                )
            except FileExistsError:
                if self._read_at_parent(parent) != document:
                    _fail(
                        "CANDIDATE_AUTHORIZATION_CONFLICT",
                        "путь авторизации кандидата занят другим секретом",
                    )
                return
            try:
                view = memoryview(payload)
                while view:
                    operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short write")
                    view = view[written:]
                os.fsync(descriptor)
            except BaseException:
                try:
                    os.unlink(self.path.name, dir_fd=parent)
                except OSError:
                    pass
                raise
            finally:
                os.close(descriptor)
            os.fsync(parent)
        finally:
            os.close(parent)
        if self._read() != document:
            _fail(
                "CANDIDATE_AUTHORIZATION_PUBLISH_FAILED",
                "опубликована иная авторизация кандидата",
            )

    def ensure(self, readiness_token: str) -> str:
        """Идемпотентно опубликовать и вернуть ровно тот же связанный token."""

        self.publish(readiness_token)
        persisted = self.load()
        if persisted != readiness_token:
            _fail(
                "CANDIDATE_AUTHORIZATION_CONFLICT",
                "долговечная авторизация содержит другой token",
            )
        return persisted

    def load(self) -> str:
        document = self._read()
        token = document.get("readinessToken")
        if type(token) is not str:
            _fail(
                "CANDIDATE_AUTHORIZATION_INVALID",
                "авторизация не содержит raw token",
            )
        return token

    def load_if_present(self) -> str | None:
        if not os.path.lexists(self.path):
            return None
        return self.load()

    def remove_if_present(self) -> None:
        if not os.path.lexists(self.path):
            return
        parent = self._open_parent()
        try:
            self._read_at_parent(parent)
            named = os.stat(
                self.path.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(named.st_mode)
                or named.st_uid != os.getuid()
                or named.st_nlink != 1
                or stat.S_IMODE(named.st_mode) != 0o600
            ):
                _fail(
                    "CANDIDATE_AUTHORIZATION_INVALID",
                    "файл авторизации изменился перед удалением",
                )
            os.unlink(self.path.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        if os.path.lexists(self.path):
            _fail(
                "CANDIDATE_AUTHORIZATION_DELETE_FAILED",
                "авторизация кандидата осталась после удаления",
            )

    def _replace_for_pre_main_retry(self, readiness_token: str) -> str:
        """Заменить только целую авторизацию той же операции до main journal."""

        expected = self._document(readiness_token)
        parent = self._open_parent()
        try:
            if not os.path.lexists(self.path):
                persisted = None
            else:
                persisted = self._read_at_parent(
                    parent,
                    allow_action_mismatch=True,
                )
            if persisted == expected:
                return readiness_token
            if persisted is not None:
                named = os.stat(
                    self.path.name,
                    dir_fd=parent,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(named.st_mode)
                    or named.st_uid != os.getuid()
                    or named.st_nlink != 1
                    or stat.S_IMODE(named.st_mode) != 0o600
                ):
                    _fail(
                        "CANDIDATE_AUTHORIZATION_INVALID",
                        "файл авторизации изменился перед заменой",
                    )
                os.unlink(self.path.name, dir_fd=parent)
                os.fsync(parent)
        finally:
            os.close(parent)
        return self.ensure(readiness_token)

    def _document(self, readiness_token: str) -> dict[str, Any]:
        if (
            type(readiness_token) is not str
            or not 32 <= len(readiness_token) <= 256
            or "\0" in readiness_token
            or hashlib.sha256(readiness_token.encode("utf-8")).hexdigest()
            != self.readiness_token_hash
        ):
            _fail(
                "CANDIDATE_AUTHORIZATION_TOKEN_INVALID",
                "raw token не связан со spawn-action",
            )
        unsigned = {
            "schemaVersion": 2,
            "authorizationKind": "controller-candidate-spawn-v2",
            "installationId": self.installation_id,
            "operationId": self.operation_id,
            "actionFingerprint": self.action_fingerprint,
            "readinessTokenHash": self.readiness_token_hash,
            "readinessToken": readiness_token,
        }
        return {
            **unsigned,
            "authorizationFingerprint": domain_fingerprint(
                _CANDIDATE_AUTHORIZATION_DOMAIN,
                unsigned,
            ),
        }

    def _read(self) -> dict[str, Any]:
        parent = self._open_parent()
        try:
            return self._read_at_parent(parent)
        finally:
            os.close(parent)

    def _open_parent(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path.parent, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            os.close(descriptor)
            _fail(
                "CANDIDATE_AUTHORIZATION_INVALID",
                "каталог авторизации небезопасен",
            )
        return descriptor

    def _read_at_parent(
        self,
        parent: int,
        *,
        allow_action_mismatch: bool = False,
    ) -> dict[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(self.path.name, flags, dir_fd=parent)
            info = os.fstat(descriptor)
            named = os.stat(
                self.path.name,
                dir_fd=parent,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= _MAX_RECEIPT_BYTES
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise ValueError("unsafe authorization")
            chunks: list[bytes] = []
            remaining = _MAX_RECEIPT_BYTES + 1
            while remaining:
                operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) != info.st_size or len(payload) > _MAX_RECEIPT_BYTES:
                raise ValueError("authorization size changed")
            document = json.loads(payload.decode("utf-8"))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise InstallerUpdateCompositionV2Error(
                "CANDIDATE_AUTHORIZATION_INVALID",
                "авторизация кандидата недоступна",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        expected_keys = {
            "schemaVersion",
            "authorizationKind",
            "installationId",
            "operationId",
            "actionFingerprint",
            "readinessTokenHash",
            "readinessToken",
            "authorizationFingerprint",
        }
        if type(document) is not dict or payload != canonical_json_bytes(document):
            _fail(
                "CANDIDATE_AUTHORIZATION_INVALID",
                "авторизация не является canonical JSON",
            )
        token = document.get("readinessToken")
        token_hash = document.get("readinessTokenHash")
        action_fingerprint = document.get("actionFingerprint")
        unsigned = {
            name: copy.deepcopy(value)
            for name, value in document.items()
            if name != "authorizationFingerprint"
        }
        if (
            set(document) != expected_keys
            or document.get("schemaVersion") != 2
            or document.get("authorizationKind") != "controller-candidate-spawn-v2"
            or document.get("installationId") != self.installation_id
            or document.get("operationId") != self.operation_id
            or type(action_fingerprint) is not str
            or _SHA256.fullmatch(action_fingerprint) is None
            or type(token_hash) is not str
            or _SHA256.fullmatch(token_hash) is None
            or type(token) is not str
            or not 32 <= len(token) <= 256
            or "\0" in token
            or hashlib.sha256(token.encode("utf-8")).hexdigest() != token_hash
            or document.get("authorizationFingerprint")
            != domain_fingerprint(_CANDIDATE_AUTHORIZATION_DOMAIN, unsigned)
            or (
                not allow_action_mismatch
                and (
                    action_fingerprint != self.action_fingerprint
                    or token_hash != self.readiness_token_hash
                )
            )
        ):
            _fail(
                "CANDIDATE_AUTHORIZATION_INVALID",
                "авторизация изменена или относится к другой операции",
            )
        return document


@dataclass(frozen=True)
class RegistryUpdatePlanV2:
    """Полное неизменяемое намерение замены управляемой регистрации."""

    installation_id: str
    operation_id: str
    codex_binary: Path
    codex_home: Path
    working_directory: Path
    marketplace_path: Path
    previous_registered_marketplace_path: Path
    registered_marketplace_path: Path
    plugin_relative_path: Path
    plugin_version: str
    install_policy: str
    auth_policy: str
    receipt_directory: Path
    command_runner: RegistryCommandRunnerV2
    before_registry: ProjectionV2 | None = None
    timeout_ms: int = 30_000

    def __post_init__(self) -> None:
        if _INSTALLATION_ID.fullmatch(self.installation_id) is None:
            raise TypeError("installation_id must be an ins2 identifier")
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise TypeError("operation_id must be an op2 identifier")
        for name in (
            "codex_binary",
            "codex_home",
            "working_directory",
            "marketplace_path",
            "previous_registered_marketplace_path",
            "registered_marketplace_path",
            "receipt_directory",
        ):
            value = getattr(self, name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise TypeError(f"{name} must be an absolute Path")
        if (
            not isinstance(self.plugin_relative_path, Path)
            or self.plugin_relative_path.is_absolute()
            or ".." in self.plugin_relative_path.parts
        ):
            raise TypeError("plugin_relative_path must be a safe relative Path")
        for name in ("plugin_version", "install_policy", "auth_policy"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value) > 256:
                raise TypeError(f"{name} must be a non-empty bounded string")
        if not callable(self.command_runner):
            raise TypeError("command_runner must be callable")
        if type(self.timeout_ms) is not int or not 1 <= self.timeout_ms <= 30_000:
            raise TypeError("timeout_ms must be an integer in [1, 30000]")
        if self.before_registry is not None and not isinstance(
            self.before_registry, ProjectionV2
        ):
            raise TypeError("before_registry must be ProjectionV2 or None")
        _require_codex_home_directory_v2(self.codex_home)
        _require_directory(self.working_directory, private=False)
        _require_directory(self.receipt_directory, private=True)
        if not self.codex_binary.is_file():
            _fail("REGISTRY_PLAN_INVALID", "исполняемый файл Codex недоступен")
        for path in (
            self.previous_registered_marketplace_path,
            self.registered_marketplace_path,
        ):
            _require_directory(path, private=False)
            plugin = path / self.plugin_relative_path
            _require_directory(plugin, private=False)

    @property
    def command_environment(self) -> dict[str, str]:
        return {
            "CODEX_HOME": str(self.codex_home),
            "PATH": os.defpath,
            "PYTHONNOUSERSITE": "1",
        }

    @property
    def marketplace_command_id(self) -> str:
        return (
            "ec2_"
            + domain_fingerprint(
                "codex-smart/registry-command-id/v2",
                {"operationId": self.operation_id, "kind": "marketplace_registry"},
            )[:32]
        )

    @property
    def plugin_command_id(self) -> str:
        return (
            "ec2_"
            + domain_fingerprint(
                "codex-smart/registry-command-id/v2",
                {"operationId": self.operation_id, "kind": "plugin_registry"},
            )[:32]
        )

    @property
    def marketplace_commands(self) -> tuple[tuple[str, ...], ...]:
        binary = str(self.codex_binary)
        return (
            (binary, "plugin", "remove", _PLUGIN_ID),
            (binary, "plugin", "marketplace", "remove", _MARKETPLACE_NAME),
            (
                binary,
                "plugin",
                "marketplace",
                "add",
                str(self.marketplace_path),
            ),
        )

    @property
    def plugin_commands(self) -> tuple[tuple[str, ...], ...]:
        return ((str(self.codex_binary), "plugin", "add", _PLUGIN_ID),)

    @property
    def marketplace_constraint(self) -> ProjectionV2:
        return _registry_constraint(self, stage="NEW_MARKETPLACE")

    @property
    def plugin_constraint(self) -> ProjectionV2:
        return _registry_constraint(self, stage="NEW_PLUGIN")

    @property
    def marketplace_receipt_path(self) -> Path:
        return self.receipt_directory / (
            f"{self.operation_id}.marketplace_registry.registry.json"
        )

    @property
    def plugin_receipt_path(self) -> Path:
        return self.receipt_directory / (
            f"{self.operation_id}.plugin_registry.registry.json"
        )

    @property
    def plan_fingerprint(self) -> str:
        return domain_fingerprint(
            _REGISTRY_PLAN_DOMAIN,
            {
                "installationId": self.installation_id,
                "operationId": self.operation_id,
                "codexBinary": str(self.codex_binary),
                "codexHome": str(self.codex_home),
                "workingDirectory": str(self.working_directory),
                "marketplacePath": str(self.marketplace_path),
                "previousRegisteredMarketplacePath": str(
                    self.previous_registered_marketplace_path
                ),
                "registeredMarketplacePath": str(self.registered_marketplace_path),
                "pluginRelativePath": str(self.plugin_relative_path),
                "pluginVersion": self.plugin_version,
                "installPolicy": self.install_policy,
                "authPolicy": self.auth_policy,
                "timeoutMs": self.timeout_ms,
                "before": (
                    None
                    if self.before_registry is None
                    else self.before_registry.to_document()
                ),
                "marketplaceCommands": [
                    list(argv) for argv in self.marketplace_commands
                ],
                "pluginCommands": [list(argv) for argv in self.plugin_commands],
            },
        )


def build_registry_update_plan_v2(
    *,
    installation_id: str,
    operation_id: str,
    codex_binary: Path,
    codex_home: Path,
    working_directory: Path,
    marketplace_path: Path,
    previous_registered_marketplace_path: Path,
    registered_marketplace_path: Path,
    plugin_relative_path: Path,
    plugin_version: str,
    install_policy: str,
    auth_policy: str,
    receipt_directory: Path,
    command_runner: RegistryCommandRunnerV2 | None = None,
    timeout_ms: int = 30_000,
) -> RegistryUpdatePlanV2:
    """Снять точное исходное состояние управляемой регистрации."""

    plan = RegistryUpdatePlanV2(
        installation_id=installation_id,
        operation_id=operation_id,
        codex_binary=codex_binary,
        codex_home=codex_home,
        working_directory=working_directory,
        marketplace_path=marketplace_path,
        previous_registered_marketplace_path=previous_registered_marketplace_path,
        registered_marketplace_path=registered_marketplace_path,
        plugin_relative_path=plugin_relative_path,
        plugin_version=plugin_version,
        install_policy=install_policy,
        auth_policy=auth_policy,
        receipt_directory=receipt_directory,
        command_runner=command_runner or _run_registry_command_v2,
        timeout_ms=timeout_ms,
    )
    snapshot = _observe_registry_physical(plan)
    if snapshot.stage != "OLD_PLUGIN":
        _fail(
            "REGISTRY_BEFORE_CHANGED",
            "принятая установка не имеет точной прежней регистрации",
        )
    return RegistryUpdatePlanV2(
        **{
            name: getattr(plan, name)
            for name in plan.__dataclass_fields__
            if name != "before_registry"
        },
        before_registry=_registry_actual_projection(plan, snapshot),
    )


def build_registry_step_definitions_v2(
    plan: RegistryUpdatePlanV2,
) -> dict[str, StepDefinitionV2]:
    """Построить два внешних определения без будущих inode конфигурации."""

    if not isinstance(plan, RegistryUpdatePlanV2) or plan.before_registry is None:
        raise TypeError("plan must contain the observed before registry")
    marketplace_action = _external_action(
        command_id=plan.marketplace_command_id,
        method="marketplace-register",
        commands=plan.marketplace_commands,
        timeout_ms=plan.timeout_ms,
    )
    plugin_action = _external_action(
        command_id=plan.plugin_command_id,
        method="plugin-enable",
        commands=plan.plugin_commands,
        timeout_ms=plan.timeout_ms,
    )
    return {
        "marketplace_registry": StepDefinitionV2(
            kind="marketplace_registry",
            command_id=plan.marketplace_command_id,
            action=marketplace_action,
            before=plan.before_registry,
            expected_after=plan.marketplace_constraint,
        ),
        "plugin_registry": StepDefinitionV2(
            kind="plugin_registry",
            command_id=plan.plugin_command_id,
            action=plugin_action,
            before=plan.marketplace_constraint,
            expected_after=plan.plugin_constraint,
        ),
    }


def build_registry_step_ports_v2(
    *,
    plan: RegistryUpdatePlanV2,
    definitions: Mapping[str, StepDefinitionV2],
) -> dict[str, UpdateStepPortV2]:
    """Собрать restart-safe порты рынка и расширения."""

    expected = build_registry_step_definitions_v2(plan)
    copied = dict(definitions)
    if copied != expected:
        _fail(
            "REGISTRY_STEP_DEFINITIONS_INVALID",
            "определения реестра отличаются от точного плана",
        )

    def marketplace_observe(definition: StepDefinitionV2) -> ProjectionV2:
        _require_step(definition, expected["marketplace_registry"])
        receipt = _optional_registry_receipt(
            plan, kind="marketplace_registry", definition=definition
        )
        snapshot = _observe_registry_physical(plan)
        if receipt is not None:
            historical = ProjectionV2.from_document(receipt["observedAfter"])
            if snapshot.stage == "NEW_MARKETPLACE":
                current = _registry_actual_projection(plan, snapshot)
            elif snapshot.stage == "NEW_PLUGIN":
                current = _registry_actual_projection(plan, snapshot)
            else:
                _fail(
                    "REGISTRY_STATE_AMBIGUOUS",
                    "состояние после marketplace receipt не является преемником",
                )
            if not matches_registry_constraint_v2(
                historical, definition.expected_after
            ):
                _fail(
                    "REGISTRY_RECEIPT_CONFLICT",
                    "marketplace receipt не содержит точный immediate-after",
                )
            return current
        if snapshot.stage == "OLD_PLUGIN" and not _subreceipt_paths(
            plan, "marketplace_registry"
        ):
            return _registry_actual_projection(plan, snapshot)
        _reconcile_marketplace(plan)
        after = _registry_actual_projection(plan, _observe_registry_physical(plan))
        _ensure_registry_receipt(
            plan,
            kind="marketplace_registry",
            definition=definition,
            observed_after=after,
        )
        return after

    def marketplace_apply(definition: StepDefinitionV2) -> None:
        _require_step(definition, expected["marketplace_registry"])
        _reconcile_marketplace(plan)
        after = _registry_actual_projection(plan, _observe_registry_physical(plan))
        if not matches_registry_constraint_v2(after, definition.expected_after):
            _fail("REGISTRY_APPLY_FAILED", "рынок не достиг exact after")
        _ensure_registry_receipt(
            plan,
            kind="marketplace_registry",
            definition=definition,
            observed_after=after,
        )

    def plugin_observe(definition: StepDefinitionV2) -> ProjectionV2:
        _require_step(definition, expected["plugin_registry"])
        receipt = _optional_registry_receipt(
            plan, kind="plugin_registry", definition=definition
        )
        snapshot = _observe_registry_physical(plan)
        if receipt is not None:
            if snapshot.stage != "NEW_PLUGIN":
                _fail(
                    "REGISTRY_STATE_AMBIGUOUS",
                    "plugin receipt не подтверждён текущим реестром",
                )
            return _registry_actual_projection(plan, snapshot)
        if snapshot.stage == "NEW_MARKETPLACE":
            return _registry_actual_projection(plan, snapshot)
        if snapshot.stage == "NEW_PLUGIN":
            after = _registry_actual_projection(plan, snapshot)
            _ensure_registry_receipt(
                plan,
                kind="plugin_registry",
                definition=definition,
                observed_after=after,
            )
            return after
        _fail("REGISTRY_STATE_AMBIGUOUS", "расширение находится в третьем состоянии")

    def plugin_apply(definition: StepDefinitionV2) -> None:
        _require_step(definition, expected["plugin_registry"])
        snapshot = _observe_registry_physical(plan)
        if snapshot.stage == "NEW_MARKETPLACE":
            _execute_registry_command(plan, plan.plugin_commands[0])
            snapshot = _observe_registry_physical(plan)
        if snapshot.stage != "NEW_PLUGIN":
            _fail("REGISTRY_APPLY_FAILED", "расширение не достигло exact after")
        after = _registry_actual_projection(plan, snapshot)
        _ensure_registry_receipt(
            plan,
            kind="plugin_registry",
            definition=definition,
            observed_after=after,
        )

    def marketplace_completed(
        persisted: ProjectionV2,
        current: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        try:
            _require_step(definition, expected["marketplace_registry"])
            receipt = _require_registry_receipt(
                plan, kind="marketplace_registry", definition=definition
            )
            historical = ProjectionV2.from_document(receipt["observedAfter"])
            if historical != persisted or not matches_registry_constraint_v2(
                persisted, definition.expected_after
            ):
                return False
            if current == persisted:
                return True
            plugin_definition = expected["plugin_registry"]
            plugin_receipt = _require_registry_receipt(
                plan, kind="plugin_registry", definition=plugin_definition
            )
            plugin_after = ProjectionV2.from_document(plugin_receipt["observedAfter"])
            return bool(
                plugin_after == current
                and matches_registry_constraint_v2(
                    current, plugin_definition.expected_after
                )
            )
        except (KeyError, TypeError, ValueError, InstallerUpdateCompositionV2Error):
            return False

    def plugin_completed(
        persisted: ProjectionV2,
        current: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        try:
            receipt = _require_registry_receipt(
                plan, kind="plugin_registry", definition=definition
            )
            historical = ProjectionV2.from_document(receipt["observedAfter"])
            return historical == persisted == current
        except (KeyError, TypeError, ValueError, InstallerUpdateCompositionV2Error):
            return False

    return {
        "marketplace_registry": UpdateStepPortV2(
            observe=marketplace_observe,
            apply=marketplace_apply,
            matches_before=lambda observed, definition: observed == definition.before,
            matches_after=lambda observed, definition: matches_registry_constraint_v2(
                observed, definition.expected_after
            ),
            completed_current_matches=marketplace_completed,
        ),
        "plugin_registry": UpdateStepPortV2(
            observe=plugin_observe,
            apply=plugin_apply,
            matches_before=lambda observed, definition: matches_registry_constraint_v2(
                observed, definition.before
            ),
            matches_after=lambda observed, definition: matches_registry_constraint_v2(
                observed, definition.expected_after
            ),
            completed_current_matches=plugin_completed,
        ),
    }


@dataclass(frozen=True)
class _RegistryPhysicalSnapshotV2:
    stage: str
    config_file: ProjectionV2
    marketplace_document: Mapping[str, Any]
    plugin_document: Mapping[str, Any]


def _observe_registry_physical(
    plan: RegistryUpdatePlanV2,
) -> _RegistryPhysicalSnapshotV2:
    marketplace_document = _run_registry_json(
        plan,
        (str(plan.codex_binary), "plugin", "marketplace", "list", "--json"),
    )
    plugin_document = _run_registry_json(
        plan,
        (str(plan.codex_binary), "plugin", "list", "--json"),
    )
    marketplaces = marketplace_document.get("marketplaces")
    installed = plugin_document.get("installed")
    if type(marketplaces) is not list or type(installed) is not list:
        _fail("REGISTRY_OBSERVATION_INVALID", "Codex вернул неверные списки")
    target_marketplaces = [
        item
        for item in marketplaces
        if type(item) is dict and item.get("name") == _MARKETPLACE_NAME
    ]
    target_plugins = [
        item
        for item in installed
        if type(item) is dict and item.get("pluginId") == _PLUGIN_ID
    ]
    if len(target_marketplaces) > 1 or len(target_plugins) > 1:
        _fail("REGISTRY_OBSERVATION_INVALID", "целевая регистрация не уникальна")
    config_path = plan.codex_home / "config.toml"
    config_file = _capture_private_file(config_path)
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_CONFIG_INVALID", "config.toml нельзя разобрать"
        ) from error
    marketplace_configured = isinstance(
        config.get("marketplaces", {}).get(_MARKETPLACE_NAME), Mapping
    )
    plugin_section = config.get("plugins", {}).get(_PLUGIN_ID)
    plugin_configured = bool(
        isinstance(plugin_section, Mapping) and plugin_section.get("enabled") is True
    )
    marketplace = target_marketplaces[0] if target_marketplaces else None
    plugin = target_plugins[0] if target_plugins else None

    old_marketplace = _marketplace_entry_matches(
        marketplace, plan.previous_registered_marketplace_path
    )
    new_marketplace = _marketplace_entry_matches(
        marketplace, plan.registered_marketplace_path
    )
    old_plugin = _plugin_entry_matches(
        plugin, plan, plan.previous_registered_marketplace_path
    )
    new_plugin = _plugin_entry_matches(plugin, plan, plan.registered_marketplace_path)
    if old_marketplace and old_plugin and marketplace_configured and plugin_configured:
        stage = "OLD_PLUGIN"
    elif (
        old_marketplace
        and plugin is None
        and marketplace_configured
        and not plugin_configured
    ):
        stage = "OLD_MARKETPLACE"
    elif (
        marketplace is None
        and plugin is None
        and not marketplace_configured
        and not plugin_configured
    ):
        stage = "ABSENT"
    elif (
        new_marketplace
        and plugin is None
        and marketplace_configured
        and not plugin_configured
    ):
        stage = "NEW_MARKETPLACE"
    elif (
        new_marketplace and new_plugin and marketplace_configured and plugin_configured
    ):
        stage = "NEW_PLUGIN"
    else:
        _fail(
            "REGISTRY_STATE_AMBIGUOUS",
            "реестр, списки Codex и config.toml расходятся",
        )
    return _RegistryPhysicalSnapshotV2(
        stage=stage,
        config_file=config_file,
        marketplace_document=marketplace_document,
        plugin_document=plugin_document,
    )


def _registry_constraint(plan: RegistryUpdatePlanV2, *, stage: str) -> ProjectionV2:
    if stage not in {"NEW_MARKETPLACE", "NEW_PLUGIN"}:
        raise ValueError("unsupported registry constraint stage")
    plugin_enabled = stage == "NEW_PLUGIN"
    value = _registry_stable_value(
        plan,
        registered_path=plan.registered_marketplace_path,
        plugin_enabled=plugin_enabled,
    )
    value.update(
        {
            "status": (
                "EXPECTED_PLUGIN_ENABLED"
                if plugin_enabled
                else "EXPECTED_MARKETPLACE_REGISTERED"
            ),
            "configFile": None,
            "marketplaceListFingerprint": None,
            "pluginListFingerprint": None,
        }
    )
    return _projection("registry-state-v2", value, _REGISTRY_DOMAIN)


def _registry_actual_projection(
    plan: RegistryUpdatePlanV2,
    snapshot: _RegistryPhysicalSnapshotV2,
) -> ProjectionV2:
    stages = {
        "OLD_PLUGIN": (
            plan.previous_registered_marketplace_path,
            True,
            "PLUGIN_ENABLED",
        ),
        "OLD_MARKETPLACE": (
            plan.previous_registered_marketplace_path,
            False,
            "MARKETPLACE_REGISTERED",
        ),
        "NEW_MARKETPLACE": (
            plan.registered_marketplace_path,
            False,
            "MARKETPLACE_REGISTERED",
        ),
        "NEW_PLUGIN": (
            plan.registered_marketplace_path,
            True,
            "PLUGIN_ENABLED",
        ),
    }
    try:
        registered_path, enabled, status = stages[snapshot.stage]
    except KeyError as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_STATE_AMBIGUOUS",
            "состояние без регистрации нельзя выдать за registry projection",
        ) from error
    value = _registry_stable_value(
        plan,
        registered_path=registered_path,
        plugin_enabled=enabled,
    )
    value.update(
        {
            "status": status,
            "configFile": copy.deepcopy(dict(snapshot.config_file.value)),
            "marketplaceListFingerprint": domain_fingerprint(
                _MARKETPLACE_LIST_DOMAIN,
                copy.deepcopy(dict(snapshot.marketplace_document)),
            ),
            "pluginListFingerprint": domain_fingerprint(
                _PLUGIN_LIST_DOMAIN,
                copy.deepcopy(dict(snapshot.plugin_document)),
            ),
        }
    )
    return _projection("registry-state-v2", value, _REGISTRY_DOMAIN)


def _registry_stable_value(
    plan: RegistryUpdatePlanV2,
    *,
    registered_path: Path,
    plugin_enabled: bool,
) -> dict[str, Any]:
    marketplace_identity = {
        "name": _MARKETPLACE_NAME,
        "path": str(registered_path),
        "sourceType": "local",
    }
    plugin_identity = {
        "pluginId": _PLUGIN_ID,
        "name": _PLUGIN_NAME,
        "marketplaceName": _MARKETPLACE_NAME,
        "version": plan.plugin_version,
        "source": "local",
        "path": str(registered_path / plan.plugin_relative_path),
        "marketplacePath": str(registered_path),
        "installPolicy": plan.install_policy,
        "authPolicy": plan.auth_policy,
        "enabled": plugin_enabled,
    }
    semantic = {
        "marketplaceName": _MARKETPLACE_NAME,
        "marketplacePresent": True,
        "pluginId": _PLUGIN_ID,
        "pluginEnabled": plugin_enabled,
    }
    return {
        "marketplaceName": _MARKETPLACE_NAME,
        "marketplacePath": str(registered_path),
        "marketplaceFingerprint": domain_fingerprint(
            _MARKETPLACE_IDENTITY_DOMAIN, marketplace_identity
        ),
        "pluginId": _PLUGIN_ID,
        "pluginEnabled": plugin_enabled,
        "pluginFingerprint": domain_fingerprint(
            _PLUGIN_IDENTITY_DOMAIN, plugin_identity
        ),
        "configSemanticFingerprint": domain_fingerprint(
            _CONFIG_SEMANTIC_DOMAIN, semantic
        ),
    }


def _marketplace_entry_matches(value: Any, path: Path) -> bool:
    if not isinstance(value, Mapping):
        return False
    source = value.get("marketplaceSource")
    expected = str(path)
    return bool(
        value.get("name") == _MARKETPLACE_NAME
        and value.get("root") == expected
        and isinstance(source, Mapping)
        and source.get("sourceType") == "local"
        and source.get("source") == expected
    )


def _plugin_entry_matches(value: Any, plan: RegistryUpdatePlanV2, path: Path) -> bool:
    if not isinstance(value, Mapping):
        return False
    marketplace = value.get("marketplaceSource")
    source = value.get("source")
    expected_marketplace = str(path)
    return bool(
        value.get("pluginId") == _PLUGIN_ID
        and value.get("name") == _PLUGIN_NAME
        and value.get("marketplaceName") == _MARKETPLACE_NAME
        and value.get("version") == plan.plugin_version
        and value.get("installed") is True
        and value.get("enabled") is True
        and value.get("installPolicy") == plan.install_policy
        and value.get("authPolicy") == plan.auth_policy
        and isinstance(marketplace, Mapping)
        and marketplace.get("sourceType") == "local"
        and marketplace.get("source") == expected_marketplace
        and isinstance(source, Mapping)
        and source.get("source") == "local"
        and source.get("path") == str(path / plan.plugin_relative_path)
    )


def _reconcile_marketplace(plan: RegistryUpdatePlanV2) -> None:
    stages = ("OLD_PLUGIN", "OLD_MARKETPLACE", "ABSENT", "NEW_MARKETPLACE")
    commands = plan.marketplace_commands
    snapshot = _observe_registry_physical(plan)
    if snapshot.stage not in stages:
        _fail("REGISTRY_STATE_AMBIGUOUS", "рынок нельзя продолжить из этого состояния")
    index = stages.index(snapshot.stage)
    for completed_index in range(index):
        _require_subreceipt(plan, "marketplace_registry", completed_index + 1)
    if index and not _subreceipt_path(plan, "marketplace_registry", index).exists():
        _ensure_subreceipt(
            plan,
            kind="marketplace_registry",
            ordinal=index,
            argv=commands[index - 1],
            stage_after=stages[index],
        )
    while index < len(commands):
        argv = commands[index]
        _execute_registry_command(plan, argv)
        observed = _observe_registry_physical(plan)
        expected_stage = stages[index + 1]
        if observed.stage != expected_stage:
            _fail(
                "REGISTRY_APPLY_FAILED",
                f"подкоманда {index + 1} дала состояние {observed.stage}",
            )
        _ensure_subreceipt(
            plan,
            kind="marketplace_registry",
            ordinal=index + 1,
            argv=argv,
            stage_after=expected_stage,
        )
        index += 1


def _external_action(
    *,
    command_id: str,
    method: str,
    commands: tuple[tuple[str, ...], ...],
    timeout_ms: int,
) -> dict[str, Any]:
    return {
        "actionKind": "external-command",
        "commandRole": "codex-registry",
        "method": method,
        "externalCommandId": command_id,
        "argvFingerprint": domain_fingerprint(
            _ARGV_DOMAIN, {"argv": [list(argv) for argv in commands]}
        ),
        "timeoutMs": timeout_ms,
    }


def _execute_registry_command(
    plan: RegistryUpdatePlanV2, argv: tuple[str, ...]
) -> None:
    result = plan.command_runner(
        argv,
        cwd=plan.working_directory,
        env=plan.command_environment,
        timeout_ms=plan.timeout_ms,
    )
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        error = getattr(result, "stderr", "исполнитель не вернул результат")
        _fail("REGISTRY_COMMAND_FAILED", str(error)[:4096])


def _run_registry_json(
    plan: RegistryUpdatePlanV2, argv: tuple[str, ...]
) -> dict[str, Any]:
    result = plan.command_runner(
        argv,
        cwd=plan.working_directory,
        env=plan.command_environment,
        timeout_ms=plan.timeout_ms,
    )
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        _fail("REGISTRY_COMMAND_FAILED", str(getattr(result, "stderr", ""))[:4096])
    try:
        document = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_OBSERVATION_INVALID", "Codex вернул не JSON"
        ) from error
    if type(document) is not dict:
        _fail("REGISTRY_OBSERVATION_INVALID", "Codex вернул не объект JSON")
    return document


def _run_registry_command_v2(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_ms: int,
) -> subprocess.CompletedProcess[str]:
    try:
        deadline = operation_deadline_v2.current_operation_deadline_v2()
        if deadline is None:
            deadline = operation_deadline_v2.OperationDeadlineV2.start(
                operation="registry-command",
                timeout_seconds=(timeout_ms / 1000) + 1.0,
                timeout_code="REGISTRY_COMMAND_DEADLINE_TIMEOUT",
            )
        supervisor = (
            operation_process_group_supervisor_v2.
            current_process_group_supervisor_v2()
        )
        if supervisor is None:
            supervisor = (
                operation_process_group_supervisor_v2.
                OperationProcessGroupSupervisorV2()
            )
        result = supervised_subprocess_v2.run_supervised_command_v2(
            argv=argv,
            label="codex-registry-command",
            cwd=cwd,
            env=env,
            stdin=b"",
            local_timeout_seconds=timeout_ms / 1000,
            cleanup_wait_seconds=0.5,
            max_output_bytes=4 * 1024 * 1024,
            deadline=deadline,
            supervisor=supervisor,
        )
        return subprocess.CompletedProcess(
            args=list(result.argv),
            returncode=result.returncode,
            stdout=result.stdout.decode("utf-8", errors="replace"),
            stderr=result.stderr.decode("utf-8", errors="replace"),
        )
    except (OSError, supervised_subprocess_v2.SupervisedCommandV2Error) as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_COMMAND_FAILED", str(error)
        ) from error


def _ensure_registry_receipt(
    plan: RegistryUpdatePlanV2,
    *,
    kind: str,
    definition: StepDefinitionV2,
    observed_after: ProjectionV2,
) -> dict[str, Any]:
    path = _registry_receipt_path(plan, kind)
    projection = {
        "schemaVersion": 2,
        "receiptKind": "registry-step",
        "installationId": plan.installation_id,
        "operationId": plan.operation_id,
        "stepKind": kind,
        "commandId": definition.command_id,
        "planFingerprint": plan.plan_fingerprint,
        "actionFingerprint": definition.action_fingerprint,
        "observedAfter": observed_after.to_document(),
    }
    document = {
        **projection,
        "receiptFingerprint": domain_fingerprint(_REGISTRY_RECEIPT_DOMAIN, projection),
    }
    _publish_immutable_json(path, document)
    return _require_registry_receipt(plan, kind=kind, definition=definition)


def _optional_registry_receipt(
    plan: RegistryUpdatePlanV2,
    *,
    kind: str,
    definition: StepDefinitionV2,
) -> dict[str, Any] | None:
    path = _registry_receipt_path(plan, kind)
    if not os.path.lexists(path):
        return None
    return _require_registry_receipt(plan, kind=kind, definition=definition)


def _require_registry_receipt(
    plan: RegistryUpdatePlanV2,
    *,
    kind: str,
    definition: StepDefinitionV2,
) -> dict[str, Any]:
    document = _read_immutable_json(_registry_receipt_path(plan, kind))
    expected_keys = {
        "schemaVersion",
        "receiptKind",
        "installationId",
        "operationId",
        "stepKind",
        "commandId",
        "planFingerprint",
        "actionFingerprint",
        "observedAfter",
        "receiptFingerprint",
    }
    unsigned = {
        name: value for name, value in document.items() if name != "receiptFingerprint"
    }
    if (
        set(document) != expected_keys
        or document.get("schemaVersion") != 2
        or document.get("receiptKind") != "registry-step"
        or document.get("installationId") != plan.installation_id
        or document.get("operationId") != plan.operation_id
        or document.get("stepKind") != kind
        or document.get("commandId") != definition.command_id
        or document.get("planFingerprint") != plan.plan_fingerprint
        or document.get("actionFingerprint") != definition.action_fingerprint
        or document.get("receiptFingerprint")
        != domain_fingerprint(_REGISTRY_RECEIPT_DOMAIN, unsigned)
    ):
        _fail("REGISTRY_RECEIPT_CONFLICT", "registry receipt изменена или чужая")
    try:
        observed = ProjectionV2.from_document(document["observedAfter"])
    except (KeyError, TypeError, ValueError) as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_RECEIPT_CONFLICT", "registry receipt не содержит проекцию"
        ) from error
    if not matches_registry_constraint_v2(observed, definition.expected_after):
        _fail("REGISTRY_RECEIPT_CONFLICT", "registry receipt содержит иной after")
    return document


def _ensure_subreceipt(
    plan: RegistryUpdatePlanV2,
    *,
    kind: str,
    ordinal: int,
    argv: tuple[str, ...],
    stage_after: str,
) -> None:
    projection = {
        "schemaVersion": 2,
        "receiptKind": "registry-substep",
        "installationId": plan.installation_id,
        "operationId": plan.operation_id,
        "stepKind": kind,
        "substepOrdinal": ordinal,
        "planFingerprint": plan.plan_fingerprint,
        "argv": list(argv),
        "argvFingerprint": domain_fingerprint(_ARGV_DOMAIN, {"argv": [list(argv)]}),
        "stageAfter": stage_after,
    }
    document = {
        **projection,
        "receiptFingerprint": domain_fingerprint(
            _REGISTRY_SUBRECEIPT_DOMAIN, projection
        ),
    }
    path = _subreceipt_path(plan, kind, ordinal)
    _publish_immutable_json(path, document)
    _require_subreceipt(plan, kind, ordinal)


def _require_subreceipt(plan: RegistryUpdatePlanV2, kind: str, ordinal: int) -> None:
    if kind != "marketplace_registry" or ordinal not in {1, 2, 3}:
        _fail("REGISTRY_RECEIPT_CONFLICT", "вид или номер подшага неверен")
    path = _subreceipt_path(plan, kind, ordinal)
    if not os.path.lexists(path):
        _fail("REGISTRY_SUBRECEIPT_MISSING", f"нет квитанции подшага {ordinal}")
    document = _read_immutable_json(path)
    unsigned = {
        name: value for name, value in document.items() if name != "receiptFingerprint"
    }
    argv = plan.marketplace_commands[ordinal - 1]
    stage_after = ("OLD_MARKETPLACE", "ABSENT", "NEW_MARKETPLACE")[ordinal - 1]
    expected_keys = {
        "schemaVersion",
        "receiptKind",
        "installationId",
        "operationId",
        "stepKind",
        "substepOrdinal",
        "planFingerprint",
        "argv",
        "argvFingerprint",
        "stageAfter",
        "receiptFingerprint",
    }
    if (
        set(document) != expected_keys
        or document.get("schemaVersion") != 2
        or document.get("receiptKind") != "registry-substep"
        or document.get("installationId") != plan.installation_id
        or document.get("operationId") != plan.operation_id
        or document.get("stepKind") != kind
        or document.get("substepOrdinal") != ordinal
        or document.get("planFingerprint") != plan.plan_fingerprint
        or document.get("argv") != list(argv)
        or document.get("argvFingerprint")
        != domain_fingerprint(_ARGV_DOMAIN, {"argv": [list(argv)]})
        or document.get("stageAfter") != stage_after
        or document.get("receiptFingerprint")
        != domain_fingerprint(_REGISTRY_SUBRECEIPT_DOMAIN, unsigned)
    ):
        _fail("REGISTRY_RECEIPT_CONFLICT", "квитанция подшага изменена или чужая")


def _subreceipt_paths(plan: RegistryUpdatePlanV2, kind: str) -> tuple[Path, ...]:
    return tuple(
        path
        for ordinal in range(1, 4)
        if (path := _subreceipt_path(plan, kind, ordinal)).exists()
    )


def _subreceipt_path(plan: RegistryUpdatePlanV2, kind: str, ordinal: int) -> Path:
    return plan.receipt_directory / (
        f"{plan.operation_id}.{kind}.{ordinal:02d}.registry-substep.json"
    )


def _registry_receipt_path(plan: RegistryUpdatePlanV2, kind: str) -> Path:
    if kind == "marketplace_registry":
        return plan.marketplace_receipt_path
    if kind == "plugin_registry":
        return plan.plugin_receipt_path
    raise ValueError("unsupported registry kind")


def _publish_immutable_json(path: Path, document: Mapping[str, Any]) -> None:
    payload = canonical_json_bytes(dict(document))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if _read_immutable_json(path) == dict(document):
            return
        _fail("REGISTRY_RECEIPT_CONFLICT", f"путь квитанции занят: {path}")
    try:
        view = memoryview(payload)
        while view:
            operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _read_immutable_json(path: Path) -> dict[str, Any]:
    try:
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_RECEIPT_BYTES
        ):
            raise ValueError("unsafe receipt")
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_RECEIPT_CONFLICT", f"квитанция недоступна: {path}"
        ) from error
    if type(document) is not dict or raw != canonical_json_bytes(document):
        _fail("REGISTRY_RECEIPT_CONFLICT", "квитанция не является canonical JSON")
    return document


def _capture_private_file(path: Path) -> ProjectionV2:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_CONFIG_INVALID", "config.toml отсутствует"
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        _fail("REGISTRY_CONFIG_INVALID", "config.toml не является частным файлом")
    value = {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    return _projection("file-object-v2", value, _FILE_DOMAIN)


def _observe_launcher_bindings(
    bindings: tuple[LauncherBindingV2, ...],
    *,
    expected: bool,
) -> ProjectionV2:
    resolved: list[Path] = []
    for binding in bindings:
        try:
            parent = os.lstat(binding.path.parent)
            link = os.lstat(binding.path)
            target = os.readlink(binding.path)
            actual = binding.path.resolve(strict=True)
        except OSError as error:
            raise InstallerUpdateCompositionV2Error(
                "LAUNCHER_STATE_AMBIGUOUS",
                f"загрузчик недоступен: {binding.path}",
            ) from error
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != os.getuid()
            or not stat.S_ISLNK(link.st_mode)
            or link.st_uid != os.getuid()
            or target != str(binding.target)
        ):
            _fail(
                "LAUNCHER_STATE_AMBIGUOUS",
                f"загрузчик не является принадлежащей ссылкой: {binding.path}",
            )
        expected_path = binding.expected_resolved_target.resolve(strict=True)
        if expected and actual != expected_path:
            _fail(
                "LAUNCHER_STATE_AMBIGUOUS",
                f"загрузчик ещё не разрешается в candidate: {binding.path}",
            )
        resolved.append(actual)
    return _launcher_set_projection(bindings, tuple(resolved))


def _launcher_set_projection(
    bindings: tuple[LauncherBindingV2, ...],
    resolved_paths: tuple[Path, ...],
) -> ProjectionV2:
    if len(bindings) != len(resolved_paths):
        raise TypeError("bindings and resolved_paths must have equal length")
    launchers = []
    for binding, resolved in zip(bindings, resolved_paths, strict=True):
        launchers.append(
            {
                "name": binding.name,
                "role": binding.role,
                "file": _launcher_file_value(binding.path, resolved),
            }
        )
    value: dict[str, Any] = {"launchers": launchers}
    value["setFingerprint"] = domain_fingerprint(_LAUNCHER_SET_DOMAIN, value)
    return _projection(
        "launcher-set-v2",
        value,
        _LAUNCHER_PROJECTION_DOMAIN,
    )


def _launcher_file_value(logical_path: Path, physical_path: Path) -> dict[str, Any]:
    try:
        info = os.lstat(physical_path)
        payload = physical_path.read_bytes()
    except OSError as error:
        raise InstallerUpdateCompositionV2Error(
            "LAUNCHER_TARGET_INVALID",
            f"целевой файл загрузчика недоступен: {physical_path}",
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or len(payload) != info.st_size
    ):
        _fail(
            "LAUNCHER_TARGET_INVALID",
            f"целевой файл загрузчика небезопасен: {physical_path}",
        )
    return {
        "path": str(logical_path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _launcher_entries(projection: ProjectionV2) -> tuple[Mapping[str, Any], ...]:
    value = projection.value.get("launchers")
    if type(value) is not list or not value:
        _fail("LAUNCHER_PLAN_INVALID", "launcher-set не содержит записи")
    if any(not isinstance(item, Mapping) for item in value):
        _fail("LAUNCHER_PLAN_INVALID", "launcher-set содержит неверную запись")
    return tuple(value)


def _launcher_entry_fingerprint(entry: Mapping[str, Any]) -> str:
    return domain_fingerprint(_LAUNCHER_ENTRY_DOMAIN, copy.deepcopy(dict(entry)))


def _launcher_plan_fingerprint(plan: LauncherUpdatePlanV2) -> str:
    return domain_fingerprint(
        _LAUNCHER_PLAN_DOMAIN,
        {
            "installationId": plan.installation_id,
            "operationId": plan.operation_id,
            "bindings": [
                {
                    "name": item.name,
                    "role": item.role,
                    "path": str(item.path),
                    "target": str(item.target),
                    "expectedResolvedTarget": str(item.expected_resolved_target),
                }
                for item in plan.bindings
            ],
            "before": plan.before.to_document(),
            "expectedAfter": plan.expected_after.to_document(),
        },
    )


def _shutdown_absence_projection(plan: Any) -> ProjectionV2:
    seed = {
        "installationId": plan.installation_id,
        "operationId": plan.operation_id,
        "entries": [
            {
                "path": str(plan.socket_path),
                "basename": plan.socket_path.name,
                "parentDevice": plan.socket_parent_device,
                "parentInode": plan.socket_parent_inode,
                "absent": True,
            }
        ],
    }
    value = {
        "proofId": "ap2_"
        + domain_fingerprint("codex-smart/absence-proof-id/v2", seed)[:32],
        **seed,
        "directorySyncCompleted": True,
    }
    value["proofFingerprint"] = domain_fingerprint(
        "codex-smart/absence-proof/v2", value
    )
    return _projection(
        "absence-proof-v2",
        value,
        "codex-smart/absence-proof-projection/v2",
    )


def _shutdown_orphan_projection(
    constraint: ProjectionV2,
    *,
    process_exit_fingerprint: str,
    exclusive_lock_fingerprint: str,
) -> ProjectionV2:
    value = copy.deepcopy(dict(constraint.value))
    value.update(
        {
            "processExitProofFingerprint": process_exit_fingerprint,
            "exclusiveLockProofFingerprint": exclusive_lock_fingerprint,
            "status": "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
        }
    )
    return _projection(
        "shutdown-intent-v2",
        value,
        "codex-smart/shutdown-intent/v2",
    )


def _atomic_replace_launcher_symlink(
    binding: LauncherBindingV2,
    operation_id: str,
) -> None:
    temporary = binding.path.parent / f".{binding.name}.{operation_id}.next"
    if os.path.lexists(temporary):
        try:
            info = os.lstat(temporary)
            target = os.readlink(temporary)
        except OSError as error:
            raise InstallerUpdateCompositionV2Error(
                "LAUNCHER_TEMP_CONFLICT", f"временная ссылка занята: {temporary}"
            ) from error
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or target != str(binding.target)
        ):
            _fail("LAUNCHER_TEMP_CONFLICT", f"временный путь занят: {temporary}")
        temporary.unlink()
    try:
        os.symlink(str(binding.target), temporary)
        created = os.lstat(temporary)
        if not stat.S_ISLNK(created.st_mode) or created.st_uid != os.getuid():
            _fail("LAUNCHER_APPLY_FAILED", "создана небезопасная временная ссылка")
        os.replace(temporary, binding.path)
        _fsync_directory(binding.path.parent)
    except BaseException:
        try:
            if os.path.lexists(temporary):
                temporary.unlink()
        except OSError:
            pass
        raise


def _projection(schema_id: str, value: Mapping[str, Any], domain: str) -> ProjectionV2:
    copied = copy.deepcopy(dict(value))
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": copied,
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
        value=copied,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _activation_commit_projection_v2(
    prepared: ProjectionV2,
) -> ProjectionV2:
    """Перевести подготовительную activation-проекцию в домен commit-журнала."""

    envelope = {
        "schemaId": prepared.schema_id,
        "schemaSha256": prepared.schema_sha256,
        "value": copy.deepcopy(dict(prepared.value)),
    }
    if (
        prepared.schema_id != "activation-v2"
        or prepared.value_fingerprint
        != domain_fingerprint("codex-smart/activation/v2", envelope)
    ):
        _fail(
            "UPDATE_PREPARATION_ACTIVATION_INVALID",
            "подготовительная activation-проекция имеет неверный домен",
        )
    return ProjectionV2(
        schema_id=prepared.schema_id,
        schema_sha256=prepared.schema_sha256,
        value=envelope["value"],
        value_fingerprint=domain_fingerprint(
            "codex-smart/journal-state/v2",
            envelope,
        ),
    )


def _derived_identifier(prefix: str, operation_id: str, purpose: str) -> str:
    return (
        prefix
        + "_"
        + domain_fingerprint(
            "codex-smart/update-derived-id/v2",
            {"operationId": operation_id, "purpose": purpose},
        )[:32]
    )


def _controller_projection(value: Mapping[str, Any]) -> ProjectionV2:
    return _projection(
        "controller-state-v2",
        value,
        "codex-smart/controller-state/v2",
    )


def _candidate_expected_projection(action: Any) -> ProjectionV2:
    document = action.to_document()
    value = {
        **{
            name: item
            for name, item in document.items()
            if name not in {"actionKind", "argv"}
        },
        "privateReadyChannel": None,
        "pid": None,
        "processStartMarker": None,
        "processGroupId": None,
        "registrationFingerprint": None,
        "databaseLeaseProofFingerprint": None,
        "databaseOpened": False,
        "workingSocketPublished": False,
        "acceptingNewRoutes": False,
        "status": "EXPECTED_REGISTRATION",
        "exitProofFingerprint": None,
    }
    return _projection(
        "controller-candidate-v2",
        value,
        "codex-smart/controller-candidate/v2",
    )


def _absence_projection_for_path_v2(
    *,
    path: Path,
    installation_id: str,
    operation_id: str,
) -> ProjectionV2:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError("absence path must be an absolute Path")
    if os.path.lexists(path):
        _fail("EXPECTED_ABSENCE_CONFLICT", f"путь уже существует: {path}")
    parent = _require_directory(path.parent, private=True)
    seed = {
        "installationId": installation_id,
        "operationId": operation_id,
        "entries": [
            {
                "path": str(path),
                "basename": path.name,
                "parentDevice": parent.st_dev,
                "parentInode": parent.st_ino,
                "absent": True,
            }
        ],
    }
    value = {
        "proofId": "ap2_"
        + domain_fingerprint("codex-smart/absence-proof-id/v2", seed)[:32],
        **seed,
        "directorySyncCompleted": True,
    }
    value["proofFingerprint"] = domain_fingerprint(
        "codex-smart/absence-proof/v2", value
    )
    return _projection(
        "absence-proof-v2",
        value,
        "codex-smart/absence-proof-projection/v2",
    )


def _journal_state_projection_v2(
    *,
    path: Path,
    operation_id: str,
    phase: str,
    recovery_policy: str,
    plan_fingerprint: str,
    generation: int,
    frozen: bool,
) -> ProjectionV2:
    return _projection(
        "journal-state-v2",
        {
            "path": str(path),
            "journalKind": "operation",
            "ownerId": operation_id,
            "phase": phase,
            "recoveryPolicy": recovery_policy,
            "executionPlanDefinitionFingerprint": plan_fingerprint,
            "contentGeneration": generation,
            "frozen": frozen,
        },
        "codex-smart/journal-state/v2",
    )


def _require_step(received: StepDefinitionV2, expected: StepDefinitionV2) -> None:
    if not isinstance(received, StepDefinitionV2) or received != expected:
        _fail("REGISTRY_STEP_DEFINITION_CHANGED", "получено другое определение шага")


def _require_directory(path: Path, *, private: bool) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_PATH_INVALID", f"каталог недоступен: {path}"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or (private and stat.S_IMODE(info.st_mode) != 0o700)
    ):
        _fail("UPDATE_PATH_INVALID", f"каталог небезопасен: {path}")
    return info


def _require_codex_home_directory_v2(path: Path) -> os.stat_result:
    """Accept the two owned CODEX_HOME modes used by supported installations."""

    info = _require_directory(path, private=False)
    if stat.S_IMODE(info.st_mode) not in {0o700, 0o755}:
        _fail("UPDATE_PATH_INVALID", f"CODEX_HOME имеет небезопасный режим: {path}")
    return info


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_candidate_spawn_action_v2(
    *,
    preparation_receipt: Any,
    readiness_token: str,
    interpreter: Path,
    server_entrypoint: Path,
    private_ready_channel_path: Path,
    readiness_window_ms: int = 30_000,
) -> Any:
    """Детерминированно вывести spawn-action, оставив секрет вне журнала."""

    from .activation_preparation_v2 import ActivationPreparationReceiptV2
    from .candidate_ready_channel_v2 import (
        CandidateSpawnActionV2,
        candidate_controller_argv_v2,
    )

    if not isinstance(preparation_receipt, ActivationPreparationReceiptV2):
        raise TypeError("preparation_receipt must be ActivationPreparationReceiptV2")
    if (
        type(readiness_token) is not str
        or not readiness_token
        or "\0" in readiness_token
    ):
        raise TypeError("readiness_token must be a non-empty safe string")
    if (
        not isinstance(private_ready_channel_path, Path)
        or not private_ready_channel_path.is_absolute()
    ):
        raise TypeError("private_ready_channel_path must be an absolute Path")
    _require_directory(private_ready_channel_path.parent, private=True)
    if os.path.lexists(private_ready_channel_path):
        _fail(
            "CANDIDATE_READY_PATH_CONFLICT",
            "ready-путь уже существует до долговечного intent",
        )
    if type(readiness_window_ms) is not int or not 1 <= readiness_window_ms <= 30_000:
        raise TypeError("readiness_window_ms must be in [1, 30000]")
    intent = preparation_receipt.activation_intent
    argv = candidate_controller_argv_v2(
        interpreter=interpreter,
        server_entrypoint=server_entrypoint,
    )
    candidate_id = _derived_identifier(
        "cand2",
        intent.operation_id,
        "candidate",
    )
    controller_start_id = _derived_identifier(
        "cs2",
        intent.operation_id,
        "controller-start",
    )
    document = {
        "actionKind": "controller-candidate-spawn",
        "candidateId": candidate_id,
        "controllerIdentity": intent.controller_identity,
        "controllerStartId": controller_start_id,
        "operationId": intent.operation_id,
        "activationId": intent.activation_id,
        "activationFingerprint": intent.activation_fingerprint,
        "databaseId": intent.database_id,
        "argv": list(argv),
        "argvFingerprint": domain_fingerprint(
            "codex-smart/controller-candidate-argv/v2",
            {"argv": list(argv)},
        ),
        "snapshotFingerprint": str(intent.snapshot_locator["sha256"]),
        "privateReadyChannelPath": str(private_ready_channel_path),
        "readinessTokenHash": hashlib.sha256(
            readiness_token.encode("utf-8")
        ).hexdigest(),
        "readinessWindowMs": readiness_window_ms,
        "processGroupPolicy": "NEW_PRIVATE_GROUP",
    }
    return CandidateSpawnActionV2.from_mapping(document)


def build_update_controller_step_definitions_v2(
    *,
    proof: Any,
    preparation_receipt: Any,
    candidate_action: Any,
    controller_before: ProjectionV2,
    shell_session_id: str = "installer-v2",
    quiescence_timeout_ms: int = 30_000,
) -> dict[str, StepDefinitionV2]:
    """Построить шесть шагов с динамическим итогом ``maintenance_begin``."""

    from .activation_preparation_v2 import ActivationPreparationReceiptV2
    from .activation_transition_v2 import ActivationTransitionProofV2
    from .candidate_ready_channel_v2 import CandidateSpawnActionV2
    from .state_store_v2 import _QUIESCENCE_QUERIES

    if not isinstance(proof, ActivationTransitionProofV2) or not proof.complete:
        raise TypeError("proof must be a complete ActivationTransitionProofV2")
    if not isinstance(preparation_receipt, ActivationPreparationReceiptV2):
        raise TypeError("preparation_receipt must be ActivationPreparationReceiptV2")
    action = (
        candidate_action
        if isinstance(candidate_action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(candidate_action)
    )
    if controller_before.schema_id != "controller-state-v2":
        raise TypeError("controller_before must be controller-state-v2")
    old = copy.deepcopy(dict(controller_before.value))
    epoch = old.get("controlEpoch")
    if (
        type(epoch) is not int
        or old.get("state") != "ACCEPTING"
        or old.get("maintenanceMode") is not None
        or old.get("operationId") is not None
        or old.get("acceptingNewRoutes") is not True
        or old.get("activationId") != proof.activation_id
        or old.get("activationFingerprint") != proof.activation_fingerprint
    ):
        _fail(
            "CONTROLLER_BEFORE_INVALID",
            "old controller не является точным MATCHED_ACTIVE состоянием",
        )
    operation_id = preparation_receipt.operation_id
    begin_after_value = {
        **old,
        "controlEpoch": epoch + 1,
        "state": "EXPECTED_DRAIN_OR_MAINTENANCE",
        "maintenanceMode": "drain",
        "operationId": operation_id,
        "acceptingNewRoutes": False,
        "quiescent": False,
    }
    begin_after = _controller_projection(begin_after_value)
    drain_quiescent_value = {
        **begin_after_value,
        "state": "MAINTENANCE",
        "quiescent": True,
    }
    drain_quiescent = _controller_projection(drain_quiescent_value)
    predicate_document = {
        "predicates": [
            {
                "name": name,
                "sql": _QUIESCENCE_QUERIES[name],
                "parameters": [],
                "result": 0,
            }
            for name in _QUIESCENCE_QUERIES
        ]
    }
    quiescence = _projection(
        "quiescence-proof-v2",
        {
            "proofKind": "runtime-v2",
            "controllerIdentity": old["controllerIdentity"],
            "instanceId": old["instanceId"],
            "controlEpoch": epoch + 1,
            "workCounts": {name: 0 for name in _QUIESCENCE_QUERIES},
            "databasePredicatesFingerprint": domain_fingerprint(
                "codex-smart/database-predicates/v2",
                predicate_document,
            ),
            "barrierHeld": True,
            "quiescent": True,
        },
        "codex-smart/quiescence-proof/v2",
    )
    strengthen_after_value = {
        **drain_quiescent_value,
        "controlEpoch": epoch + 2,
        "maintenanceMode": "freeze",
    }
    strengthen_after = _controller_projection(strengthen_after_value)
    command_ids = {
        kind: _derived_identifier("cc2", operation_id, kind)
        for kind in (
            "maintenance_begin",
            "maintenance_strengthen",
            "controller_shutdown",
            "controller_accept",
            "maintenance_resume",
        )
    }
    shutdown_constraint = build_controller_shutdown_constraint_v2(
        codex_home=proof.codex_home,
        shell_session_id=shell_session_id,
        operation_id=operation_id,
        command_id=command_ids["controller_shutdown"],
        controller_before=strengthen_after,
        lock_path=preparation_receipt.activation_intent.controller_lock_path,
    )
    expected_candidate = _candidate_expected_projection(action)
    intent = preparation_receipt.activation_intent
    accepted_constraint_value = {
        "controllerIdentity": intent.controller_identity,
        "instanceId": None,
        "controllerStartId": action.controller_start_id,
        "pid": None,
        "processStartMarker": None,
        "processGroupId": None,
        "controlEpoch": 2,
        "state": "EXPECTED_MAINTENANCE",
        "maintenanceMode": "freeze",
        "operationId": operation_id,
        "activationId": intent.activation_id,
        "activationFingerprint": intent.activation_fingerprint,
        "databaseId": intent.database_id,
        "socket": None,
        "lockHeld": True,
        "acceptingNewRoutes": False,
        "quiescent": True,
    }
    accepted_constraint = _controller_projection(accepted_constraint_value)
    resumed_constraint = _controller_projection(
        {
            **accepted_constraint_value,
            "controlEpoch": 3,
            "state": "EXPECTED_ACCEPTING",
            "maintenanceMode": None,
            "operationId": None,
            "acceptingNewRoutes": True,
            "quiescent": False,
        }
    )

    def controller_step(
        kind: str,
        *,
        method: str,
        before: ProjectionV2,
        after: ProjectionV2,
        expected_epoch: int,
    ) -> StepDefinitionV2:
        return StepDefinitionV2(
            kind=kind,
            command_id=command_ids[kind],
            action={
                "actionKind": "controller-command",
                "method": method,
                "operationId": operation_id,
                "expectedControlEpoch": expected_epoch,
            },
            before=before,
            expected_after=after,
        )

    return {
        "maintenance_begin": controller_step(
            "maintenance_begin",
            method="maintenance_begin",
            before=controller_before,
            after=begin_after,
            expected_epoch=epoch,
        ),
        "wait_runtime_quiescent": StepDefinitionV2(
            kind="wait_runtime_quiescent",
            command_id=None,
            action={
                "actionKind": "verify",
                "predicate": "runtime-quiescent",
                "timeoutMs": quiescence_timeout_ms,
            },
            before=begin_after,
            expected_after=quiescence,
        ),
        "maintenance_strengthen": controller_step(
            "maintenance_strengthen",
            method="maintenance_strengthen",
            before=drain_quiescent,
            after=strengthen_after,
            expected_epoch=epoch + 1,
        ),
        "controller_shutdown": controller_step(
            "controller_shutdown",
            method="shutdown",
            before=strengthen_after,
            after=shutdown_constraint,
            expected_epoch=epoch + 2,
        ),
        "controller_accept": controller_step(
            "controller_accept",
            method="controller_accept",
            before=expected_candidate,
            after=accepted_constraint,
            expected_epoch=1,
        ),
        "maintenance_resume": controller_step(
            "maintenance_resume",
            method="maintenance_resume",
            before=accepted_constraint,
            after=resumed_constraint,
            expected_epoch=2,
        ),
    }


def build_update_matched_active_definition_v2(
    *,
    registry: Any,
    proof: Any,
    preparation: Any,
    preparation_receipt: Any,
    registry_plan: RegistryUpdatePlanV2,
    launcher_plan: LauncherUpdatePlanV2,
    candidate_action: Any,
    shell_session_id: str = "installer-v2",
    quiescence_timeout_ms: int = 30_000,
) -> UpdateMatchedActiveDefinitionPlansV2:
    """Собрать заранее все двадцать типизированных шагов ветви обновления."""

    from .activation_preparation_v2 import (
        ActivationPreparationReceiptV2,
        prepared_receipt_to_staged_activation_v2,
    )
    from .activation_transition_v2 import (
        ActivationTransitionProofV2,
        build_activation_link_plan_v2,
        build_manifest_commit_plan_v2,
    )
    from .candidate_ready_channel_v2 import CandidateSpawnActionV2
    from .installer_update_controller_ports_v2 import (
        observe_controller_database_v2,
    )
    from .installer_update_operation_v2 import UPDATE_MATCHED_ACTIVE_STEPS_V2
    from .installer_upgrade_v2 import (
        UpgradePreparationV2,
        build_upgrade_database_binding_v2,
        prepared_manifest_from_upgrade_receipt_v2,
    )
    from .lifecycle_operation_v2 import (
        ActivationCommitPayloadIntentV2,
        ActivationTransitionLineageV2,
        ControllerShutdownLineageV2,
        OperationDefinitionV2,
        StateBundleV2,
        StoppedControllerLineageV2,
        TerminalDefinitionV2,
        TransitionSourceReceiptV2,
    )
    from .lifecycle_plan_v2 import LifecyclePlanRegistryV2
    from .shutdown_socket_cleanup_v2 import (
        build_shutdown_socket_cleanup_plan_v2,
    )

    if not isinstance(registry, LifecyclePlanRegistryV2):
        raise TypeError("registry must be LifecyclePlanRegistryV2")
    if not isinstance(proof, ActivationTransitionProofV2) or not proof.complete:
        raise TypeError("proof must be a complete ActivationTransitionProofV2")
    if not isinstance(preparation, UpgradePreparationV2):
        raise TypeError("preparation must be UpgradePreparationV2")
    if not isinstance(preparation_receipt, ActivationPreparationReceiptV2):
        raise TypeError("preparation_receipt must be ActivationPreparationReceiptV2")
    if not isinstance(registry_plan, RegistryUpdatePlanV2):
        raise TypeError("registry_plan must be RegistryUpdatePlanV2")
    if not isinstance(launcher_plan, LauncherUpdatePlanV2):
        raise TypeError("launcher_plan must be LauncherUpdatePlanV2")
    candidate_action = (
        candidate_action
        if isinstance(candidate_action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(candidate_action)
    )
    operation_id = preparation_receipt.operation_id
    installation_id = preparation_receipt.installation_id
    if (
        proof.installation_id != installation_id
        or registry_plan.installation_id != installation_id
        or registry_plan.operation_id != operation_id
        or launcher_plan.installation_id != installation_id
        or launcher_plan.operation_id != operation_id
        or candidate_action.operation_id != operation_id
    ):
        _fail(
            "UPDATE_COMPOSITION_BINDING_INVALID",
            "планы композиции относятся к разным операциям",
        )
    staged = prepared_receipt_to_staged_activation_v2(preparation_receipt)
    activation_link_plan = build_activation_link_plan_v2(
        proof=proof,
        staged=staged,
    )
    prepared_manifest = prepared_manifest_from_upgrade_receipt_v2(
        proof=proof,
        preparation=preparation,
        receipt=preparation_receipt,
    )
    manifest_commit_plan = build_manifest_commit_plan_v2(
        proof=proof,
        staged=staged,
        prepared=prepared_manifest,
    )
    database_binding = build_upgrade_database_binding_v2(preparation_receipt)
    controller_before = observe_controller_database_v2(proof.database_path)
    controller_definitions = build_update_controller_step_definitions_v2(
        proof=proof,
        preparation_receipt=preparation_receipt,
        candidate_action=candidate_action,
        controller_before=controller_before,
        shell_session_id=shell_session_id,
        quiescence_timeout_ms=quiescence_timeout_ms,
    )
    shutdown_definition = controller_definitions["controller_shutdown"]
    shutdown_cleanup_plan = build_shutdown_socket_cleanup_plan_v2(
        installation_id=installation_id,
        activation_proof_fingerprint=proof.proof_fingerprint,
        operation_id=operation_id,
        shutdown_command_id=str(shutdown_definition.command_id),
        state_home=proof.state_home,
        controller_state=proof.controller_row,
    )
    shutdown_cleanup_definition = build_shutdown_socket_cleanup_step_definition_v2(
        plan=shutdown_cleanup_plan,
        shutdown_constraint=shutdown_definition.expected_after,
    )
    registry_definitions = build_registry_step_definitions_v2(registry_plan)
    launcher_definition = build_launcher_step_definition_v2(launcher_plan)
    candidate_before = _absence_projection_for_path_v2(
        path=candidate_action.private_ready_channel_path,
        installation_id=installation_id,
        operation_id=operation_id,
    )
    candidate_definition = StepDefinitionV2(
        kind="controller_candidate_spawn",
        command_id=None,
        action=candidate_action.to_document(),
        before=candidate_before,
        expected_after=_candidate_expected_projection(candidate_action),
    )
    verify_definition = StepDefinitionV2(
        kind="verify_candidate",
        command_id=None,
        action={
            "actionKind": "verify",
            "predicate": "candidate",
            "timeoutMs": 30_000,
        },
        before=preparation_receipt.prepared.activation,
        expected_after=preparation_receipt.prepared.activation,
    )
    plan_id = _derived_identifier("pl2", operation_id, "apply-plan")
    execution_plan = registry.select(
        machine_id="apply",
        branch_id="update-matched-active",
        plan_id=plan_id,
    )
    if execution_plan.composed_step_kinds != UPDATE_MATCHED_ACTIVE_STEPS_V2:
        _fail("UPDATE_PLAN_INVALID", "реестр вернул не двадцать ожидаемых шагов")
    journal_path = proof.layout.journal_path
    journal_absence = _absence_projection_for_path_v2(
        path=journal_path,
        installation_id=installation_id,
        operation_id=operation_id,
    )
    gate_after = _journal_state_projection_v2(
        path=journal_path,
        operation_id=operation_id,
        phase="DISCOVERED",
        recovery_policy="REVERSIBLE",
        plan_fingerprint=execution_plan.plan_definition_fingerprint,
        generation=1,
        frozen=False,
    )
    gate = StepDefinitionV2(
        kind="gate_close",
        command_id=None,
        action={
            "actionKind": "journal-transition",
            "transition": "gate-close",
            "journalPath": str(journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        },
        before=journal_absence,
        expected_after=gate_after,
    )
    recovery_before = _journal_state_projection_v2(
        path=journal_path,
        operation_id=operation_id,
        phase="APPLYING",
        recovery_policy="REVERSIBLE",
        plan_fingerprint=execution_plan.plan_definition_fingerprint,
        generation=16,
        frozen=False,
    )
    recovery_after = _journal_state_projection_v2(
        path=journal_path,
        operation_id=operation_id,
        phase="APPLYING",
        recovery_policy="FORWARD_ONLY",
        plan_fingerprint=execution_plan.plan_definition_fingerprint,
        generation=17,
        frozen=False,
    )
    recovery_forward = StepDefinitionV2(
        kind="recovery_forward_only",
        command_id=None,
        action={
            "actionKind": "journal-transition",
            "transition": "forward-only",
            "journalPath": str(journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        },
        before=recovery_before,
        expected_after=recovery_after,
    )
    database_definition = StepDefinitionV2(
        kind="database_prepare",
        command_id=None,
        action={
            "actionKind": "database-mutation",
            "method": "prepare",
            "databaseId": staged.database_id,
            "path": str(staged.database_path),
            "expectedSchemaFingerprint": staged.schema_fingerprint,
        },
        before=preparation_receipt.database_empty_file,
        expected_after=database_binding,
    )
    activation_link_definition = StepDefinitionV2(
        kind="activation_link",
        command_id=None,
        action=activation_link_plan.action,
        before=activation_link_plan.before,
        expected_after=activation_link_plan.expected_after,
    )
    manifest_definition = StepDefinitionV2(
        kind="manifest_commit",
        command_id=None,
        action=manifest_commit_plan.action,
        before=manifest_commit_plan.before,
        expected_after=manifest_commit_plan.expected_after,
    )
    mutable_by_kind = {
        **controller_definitions,
        "shutdown_socket_cleanup": shutdown_cleanup_definition,
        "database_prepare": database_definition,
        "activation_link": activation_link_definition,
        "recovery_forward_only": recovery_forward,
        **registry_definitions,
        "launchers": launcher_definition,
        "controller_candidate_spawn": candidate_definition,
        "verify_candidate": verify_definition,
        "manifest_commit": manifest_definition,
    }
    mutable_kinds = UPDATE_MATCHED_ACTIVE_STEPS_V2[1:17]
    if set(mutable_by_kind) != set(mutable_kinds):
        _fail("UPDATE_DEFINITION_INCOMPLETE", "mutable steps неполны")
    freeze_before = _journal_state_projection_v2(
        path=journal_path,
        operation_id=operation_id,
        phase="COMMITTING",
        recovery_policy="FORWARD_ONLY",
        plan_fingerprint=execution_plan.plan_definition_fingerprint,
        generation=34,
        frozen=False,
    )
    freeze_after = _journal_state_projection_v2(
        path=journal_path,
        operation_id=operation_id,
        phase="TERMINAL_FROZEN",
        recovery_policy="FORWARD_ONLY",
        plan_fingerprint=execution_plan.plan_definition_fingerprint,
        generation=35,
        frozen=True,
    )
    freeze = StepDefinitionV2(
        kind="terminal_journal_freeze",
        command_id=None,
        action={
            "actionKind": "journal-transition",
            "transition": "freeze-delete-intent",
            "journalPath": str(journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        },
        before=freeze_before,
        expected_after=freeze_after,
    )
    receipt_path = (
        proof.layout.receipts_root / installation_id / f"{operation_id}.commit.json"
    )
    terminal = TerminalDefinitionV2(
        terminal_kind="COMMIT",
        receipt_kind="activation-commit",
        receipt_path=receipt_path,
        freeze=freeze,
        journal_absence_target=journal_absence,
        receipt_payload=ActivationCommitPayloadIntentV2(
            manifest=manifest_commit_plan.expected_after,
            manifest_document=prepared_manifest.manifest_document,
            transition_lineage=ActivationTransitionLineageV2(
                transition_kind="update",
                source_receipt=TransitionSourceReceiptV2(
                    receipt_kind="activation-preparation",
                    path=(
                        proof.layout.receipts_root
                        / installation_id
                        / f"{operation_id}.preparation.json"
                    ),
                    raw_sha256=hashlib.sha256(
                        canonical_json_bytes(preparation_receipt.to_document())
                    ).hexdigest(),
                    receipt_fingerprint=preparation_receipt.receipt_fingerprint,
                ),
                activation_proof_fingerprint=(
                    preparation_receipt.transition_proof_snapshot.activation_proof_fingerprint
                ),
                shutdown_command_ids=ControllerShutdownLineageV2(
                    maintenance_begin=str(
                        controller_definitions["maintenance_begin"].command_id
                    ),
                    maintenance_strengthen=str(
                        controller_definitions["maintenance_strengthen"].command_id
                    ),
                    shutdown=str(
                        controller_definitions["controller_shutdown"].command_id
                    ),
                ),
                stopped_controller=StoppedControllerLineageV2(
                    operation_id=operation_id,
                    activation_id=str(controller_before.value["activationId"]),
                    database_id=str(controller_before.value["databaseId"]),
                    controller_identity=str(
                        controller_before.value["controllerIdentity"]
                    ),
                    control_epoch=int(
                        shutdown_definition.expected_after.value["newControlEpoch"]
                    ),
                ),
            ),
            activation=_activation_commit_projection_v2(
                preparation_receipt.prepared.activation
            ),
            database_binding=database_binding,
            journal_absence_target=journal_absence,
            controller_identity=preparation_receipt.activation_intent.controller_identity,
        ),
    )
    discovery = StateBundleV2(
        file_objects=(proof.installer_receipt_projection,),
        tree_objects=(proof.activation_tree_projection,),
        symlinks=(proof.link_projection,),
        manifest=proof.manifest_projection,
        activation=proof.activation_projection,
        database=None,
        controller=controller_before,
        controller_candidates=(),
        watchdogs=(),
        registry=registry_plan.before_registry,
        launchers=launcher_plan.before,
        legacy_processes=None,
        quiescence=None,
        external_commands=(),
        receipts=(proof.commit_receipt_projection,),
        absence_proofs=(),
    )
    accepted_controller = controller_definitions["maintenance_resume"].expected_after
    desired = StateBundleV2(
        file_objects=preparation_receipt.desired.file_objects,
        tree_objects=(preparation_receipt.activation_tree,),
        symlinks=(activation_link_plan.expected_after,),
        manifest=manifest_commit_plan.expected_after,
        activation=preparation_receipt.prepared.activation,
        database=preparation_receipt.database_binding_target,
        controller=accepted_controller,
        controller_candidates=(),
        watchdogs=(),
        registry=registry_plan.plugin_constraint,
        launchers=launcher_plan.expected_after,
        legacy_processes=None,
        quiescence=None,
        external_commands=(),
        receipts=(),
        absence_proofs=(journal_absence,),
    )
    definition = OperationDefinitionV2(
        kind="activation",
        installation_id=installation_id,
        operation_id=operation_id,
        operation="apply",
        execution_plan=execution_plan,
        discovery_before=discovery,
        fenced_before=discovery,
        desired=desired,
        gate_close=gate,
        mutable_steps=tuple(mutable_by_kind[kind] for kind in mutable_kinds),
        terminal=terminal,
    )
    return UpdateMatchedActiveDefinitionPlansV2(
        definition=definition,
        staged=staged,
        activation_link_plan=activation_link_plan,
        manifest_commit_plan=manifest_commit_plan,
        shutdown_cleanup_plan=shutdown_cleanup_plan,
        candidate_action=candidate_action,
        controller_definitions=controller_definitions,
    )


@dataclass(frozen=True)
class UpdateSourceBindingV2:
    """Повторно наблюдаемая связь запроса, источника и снимка Codex."""

    expected_source_digest: str
    expected_codex_sha256: str
    observe_source_digest: Callable[[], str]

    def __post_init__(self) -> None:
        for value, name in (
            (self.expected_source_digest, "expected_source_digest"),
            (self.expected_codex_sha256, "expected_codex_sha256"),
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise TypeError(f"{name} must be a lowercase SHA-256")
        if not callable(self.observe_source_digest):
            raise TypeError("observe_source_digest must be callable")


def verify_update_source_binding_v2(
    *,
    binding: UpdateSourceBindingV2,
    preparation: Any,
    preparation_receipt: Any,
) -> UpdateSourceBindingV2:
    """Закрыто перепроверить источник непосредственно перед композицией."""

    if not isinstance(binding, UpdateSourceBindingV2):
        raise TypeError("binding must be UpdateSourceBindingV2")
    observed = binding.observe_source_digest()
    if observed != binding.expected_source_digest:
        _fail(
            "UPDATE_SOURCE_CHANGED",
            "состав источника изменился после подготовки активации",
        )
    _verify_prepared_source_binding_v2(
        binding=binding,
        preparation=preparation,
    )
    _verify_update_receipt_codex_binding_v2(
        binding=binding,
        preparation_receipt=preparation_receipt,
    )
    return binding


def _verify_prepared_source_binding_v2(
    *,
    binding: UpdateSourceBindingV2,
    preparation: Any,
) -> None:
    """Сверить persisted манифест без повторного чтения рабочего дерева."""

    try:
        prepared_manifest = preparation.prepared_manifest_plan.manifest_document
        extensions = prepared_manifest["extensions"]
        prepared_source_digest = extensions["installerSourceDigest"]
    except (AttributeError, KeyError, TypeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_PREPARATION_INVALID",
            "подготовленный манифест не содержит отпечаток источника",
        ) from error
    if (
        type(prepared_source_digest) is not str
        or _SHA256.fullmatch(prepared_source_digest) is None
    ):
        _fail(
            "UPDATE_PREPARATION_INVALID",
            "отпечаток источника в подготовленном манифесте неверен",
        )
    if prepared_source_digest != binding.expected_source_digest:
        _fail(
            "UPDATE_PREPARED_SOURCE_MISMATCH",
            "запрос обновления не связан с подготовленным манифестом",
        )


def _verify_update_receipt_codex_binding_v2(
    *,
    binding: UpdateSourceBindingV2,
    preparation_receipt: Any,
) -> None:
    if not isinstance(binding, UpdateSourceBindingV2):
        raise TypeError("binding must be UpdateSourceBindingV2")
    try:
        prepared_codex_sha256 = preparation_receipt.activation_intent.source_locator[
            "sourceObservedSha256"
        ]
    except (AttributeError, KeyError, TypeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_PREPARATION_INVALID",
            "квитанция подготовки не содержит отпечаток Codex",
        ) from error
    if prepared_codex_sha256 != binding.expected_codex_sha256:
        _fail(
            "UPDATE_CODEX_SNAPSHOT_CHANGED",
            "подготовка связана с другим снимком Codex",
        )


def _verify_update_registry_binding_v2(
    *,
    proof: Any,
    preparation_receipt: Any,
    registry_plan: RegistryUpdatePlanV2,
) -> None:
    """Bind every registry effect to the accepted and prepared activations."""

    if not isinstance(registry_plan, RegistryUpdatePlanV2):
        _fail(
            "UPDATE_REGISTRY_BINDING_INVALID",
            "план реестра имеет неверный тип",
        )
    try:
        intent = preparation_receipt.activation_intent
        installer_receipt = proof.installer_receipt_document
        lexical_codex = Path(str(intent.source_locator["lexicalPath"]))
        expected_source_sha256 = str(
            intent.source_locator["sourceObservedSha256"]
        )
        snapshot_codex = Path(str(intent.snapshot_locator["absolutePath"]))
        expected_snapshot_sha256 = str(intent.snapshot_locator["sha256"])
        installed_codex = Path(str(installer_receipt["codexBinary"]))
        installed_marketplace = Path(
            str(installer_receipt["registeredMarketplacePath"])
        )
        lexical_marketplace = Path(str(installer_receipt["marketplacePath"]))
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_REGISTRY_BINDING_INVALID",
            "proof или preparation receipt не содержит связь реестра",
        ) from error
    expected_receipts = proof.layout.receipts_root / proof.installation_id
    expected_candidate_marketplace = intent.activation_dir / "marketplace"
    if (
        registry_plan.installation_id != proof.installation_id
        or registry_plan.installation_id != preparation_receipt.installation_id
        or registry_plan.operation_id != preparation_receipt.operation_id
        or registry_plan.codex_home != proof.codex_home
        or registry_plan.codex_home != intent.codex_home
        or intent.codex_binary != lexical_codex
        or intent.codex_binary != installed_codex
        or registry_plan.codex_binary != intent.snapshot_path
        or registry_plan.codex_binary != snapshot_codex
        or expected_snapshot_sha256 != expected_source_sha256
        or registry_plan.marketplace_path != proof.layout.marketplace_link
        or registry_plan.marketplace_path != lexical_marketplace
        or registry_plan.previous_registered_marketplace_path != installed_marketplace
        or registry_plan.previous_registered_marketplace_path
        != proof.activation_dir / "marketplace"
        or registry_plan.registered_marketplace_path != expected_candidate_marketplace
        or registry_plan.receipt_directory != expected_receipts
        or registry_plan.plugin_relative_path != Path("plugins/codex-smart-subagents")
        or registry_plan.plugin_version != "0.2.0"
        or registry_plan.install_policy != "AVAILABLE"
        or registry_plan.auth_policy != "ON_INSTALL"
    ):
        _fail(
            "UPDATE_REGISTRY_BINDING_INVALID",
            "план реестра не связан с proof и preparation receipt",
        )
    try:
        if registry_plan.codex_binary.resolve(strict=True) != snapshot_codex:
            _fail(
                "UPDATE_REGISTRY_BINDING_INVALID",
                "путь Codex не является неизменяемым снимком подготовки",
            )
        observed_codex_sha256 = _sha256_regular_file_v2(registry_plan.codex_binary)
    except OSError as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_REGISTRY_BINDING_INVALID",
            "исполняемый файл Codex недоступен для повторной проверки",
        ) from error
    if observed_codex_sha256 != expected_snapshot_sha256:
        _fail(
            "UPDATE_REGISTRY_BINDING_INVALID",
            "содержимое снимка Codex отличается от preparation receipt",
        )


def _sha256_regular_file_v2(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR:
            raise OSError("not an executable regular file")
        digest = hashlib.sha256()
        while True:
            operation_deadline_v2.checkpoint_current_operation_deadline_if_scoped_v2()
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _verify_update_launcher_binding_v2(
    *,
    proof: Any,
    preparation_receipt: Any,
    launcher_plan: LauncherUpdatePlanV2,
) -> None:
    """Bind launcher paths and both targets to the ownership receipt."""

    if not isinstance(launcher_plan, LauncherUpdatePlanV2):
        _fail(
            "UPDATE_LAUNCHER_BINDING_INVALID",
            "план загрузчиков имеет неверный тип",
        )
    try:
        links = proof.installer_receipt_document["links"]
        candidate_marketplace = (
            preparation_receipt.activation_intent.activation_dir / "marketplace"
        )
    except (AttributeError, KeyError, TypeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_LAUNCHER_BINDING_INVALID",
            "proof или preparation receipt не содержит связь загрузчиков",
        ) from error
    if (
        type(links) is not list
        or launcher_plan.installation_id != proof.installation_id
        or launcher_plan.installation_id != preparation_receipt.installation_id
        or launcher_plan.operation_id != preparation_receipt.operation_id
        or launcher_plan.plan_fingerprint != _launcher_plan_fingerprint(launcher_plan)
        or len(launcher_plan.bindings) != len(links)
    ):
        _fail(
            "UPDATE_LAUNCHER_BINDING_INVALID",
            "набор загрузчиков не связан с квитанцией установщика",
        )
    roles = {
        "codex-smart": "gateway",
        "codex-smart-subagents-admin": "admin",
    }
    expected_bin = candidate_marketplace / "plugins/codex-smart-subagents/bin"
    for binding, item in zip(launcher_plan.bindings, links, strict=True):
        if type(item) is not dict or set(item) != {"path", "target"}:
            _fail(
                "UPDATE_LAUNCHER_BINDING_INVALID",
                "квитанция установщика содержит неверную ссылку",
            )
        path = Path(str(item["path"]))
        name = path.name
        if (
            name not in roles
            or binding.name != name
            or binding.role != roles[name]
            or binding.path != path
            or binding.target != Path(str(item["target"]))
            or binding.expected_resolved_target != expected_bin / name
        ):
            _fail(
                "UPDATE_LAUNCHER_BINDING_INVALID",
                "загрузчик отличается от старой или подготовленной активации",
            )


def _verify_update_candidate_binding_v2(
    *,
    proof: Any,
    preparation_receipt: Any,
    candidate_action: Any,
    readiness_token: str,
) -> None:
    """Bind the candidate action to one exact prepared activation intent."""

    from .candidate_ready_channel_v2 import (
        CandidateReadyChannelV2Error,
        CandidateSpawnActionV2,
        candidate_controller_argv_v2,
    )

    if not isinstance(candidate_action, CandidateSpawnActionV2):
        _fail(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            "действие кандидата имеет неверный тип",
        )
    if (
        type(readiness_token) is not str
        or not 32 <= len(readiness_token) <= 256
        or "\0" in readiness_token
    ):
        _fail(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            "raw token кандидата имеет неверную форму",
        )
    try:
        checked = CandidateSpawnActionV2.from_mapping(candidate_action.to_document())
        intent = preparation_receipt.activation_intent
        expected_server = (
            intent.activation_dir
            / "marketplace/plugins/codex-smart-subagents/controller/server.py"
        )
        expected_argv = candidate_controller_argv_v2(
            interpreter=Path(sys.executable),
            server_entrypoint=expected_server,
        )
        expected_token_hash = hashlib.sha256(
            readiness_token.encode("utf-8")
        ).hexdigest()
        expected_snapshot = str(intent.snapshot_locator["sha256"])
    except (
        CandidateReadyChannelV2Error,
        AttributeError,
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            "действие кандидата нельзя связать с preparation receipt",
        ) from error
    if (
        checked != candidate_action
        or proof.installation_id != preparation_receipt.installation_id
        or candidate_action.operation_id != preparation_receipt.operation_id
        or candidate_action.candidate_id
        != _derived_identifier("cand2", intent.operation_id, "candidate")
        or candidate_action.controller_start_id
        != _derived_identifier("cs2", intent.operation_id, "controller-start")
        or candidate_action.activation_id != intent.activation_id
        or candidate_action.activation_fingerprint != intent.activation_fingerprint
        or candidate_action.database_id != intent.database_id
        or candidate_action.controller_identity != intent.controller_identity
        or candidate_action.snapshot_fingerprint != expected_snapshot
        or candidate_action.argv != expected_argv
        or candidate_action.private_ready_channel_path.parent != intent.state_home
        or candidate_action.readiness_token_hash != expected_token_hash
        or os.path.lexists(candidate_action.private_ready_channel_path)
    ):
        _fail(
            "UPDATE_CANDIDATE_BINDING_INVALID",
            "действие кандидата отличается от activation intent",
        )


def _verify_update_wrapper_binding_v2(
    *,
    preparation_receipt: Any,
    wrapper_path: Path,
) -> None:
    """Require the exact owned executable from the prepared candidate tree."""

    from .activation_preparation_v2 import (
        ActivationPreparationV2Error,
        capture_tree_projection_v2,
    )

    try:
        intent = preparation_receipt.activation_intent
        expected_path = (
            intent.activation_dir
            / "marketplace/plugins/codex-smart-subagents/bin/codex-smart"
        )
        if not isinstance(wrapper_path, Path) or wrapper_path != expected_path:
            _fail(
                "UPDATE_WRAPPER_BINDING_INVALID",
                "обёртка не является лексическим файлом candidate activation",
            )
        info = os.lstat(wrapper_path)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o500, 0o700}
            or not os.access(wrapper_path, os.X_OK)
        ):
            _fail(
                "UPDATE_WRAPPER_BINDING_INVALID",
                "обёртка candidate activation имеет небезопасные метаданные",
            )
        observed_tree = capture_tree_projection_v2(
            intent.activation_dir,
            schema_sha256=preparation_receipt.activation_tree.schema_sha256,
        )
    except InstallerUpdateCompositionV2Error:
        raise
    except (ActivationPreparationV2Error, OSError, AttributeError, TypeError) as error:
        raise InstallerUpdateCompositionV2Error(
            "UPDATE_WRAPPER_BINDING_INVALID",
            "обёртка candidate activation недоступна или изменена",
        ) from error
    if observed_tree != preparation_receipt.activation_tree:
        _fail(
            "UPDATE_WRAPPER_BINDING_INVALID",
            "дерево с обёрткой отличается от preparation receipt",
        )


def _ensure_pre_main_candidate_authorization_v2(
    *,
    journal_store: OperationJournalStoreV2,
    authorization_store: CandidateSpawnAuthorizationStoreV2,
    readiness_token: str,
    commit_receipt_path: Path,
    codex_home: Path,
) -> str:
    """Согласовать pre-main sidecar под той же блокировкой main journal."""

    if not isinstance(journal_store, OperationJournalStoreV2):
        raise TypeError("journal_store must be OperationJournalStoreV2")
    if not isinstance(authorization_store, CandidateSpawnAuthorizationStoreV2):
        raise TypeError(
            "authorization_store must be CandidateSpawnAuthorizationStoreV2"
        )
    for name, path in (
        ("commit_receipt_path", commit_receipt_path),
        ("codex_home", codex_home),
    ):
        if not isinstance(path, Path) or not path.is_absolute():
            raise TypeError(f"{name} must be an absolute Path")
    operation_id = authorization_store.operation_id
    effect_directories = tuple(
        codex_home / "install-manifests" / name
        for name in (
            "candidate-dispatch-intents-v2",
            "candidate-registrations-v2",
        )
    )
    with journal_store.locked(exclusive=True):
        if os.path.lexists(journal_store.journal_path):
            _fail(
                "UPDATE_MAIN_JOURNAL_ALREADY_EXISTS",
                "main journal появился во время согласования авторизации",
            )
        if os.path.lexists(commit_receipt_path):
            _fail(
                "CANDIDATE_PRE_MAIN_COMMIT_PRESENT",
                "завершённая операция не допускает новую авторизацию кандидата",
            )
        for directory in effect_directories:
            if not os.path.lexists(directory):
                continue
            _require_directory(directory, private=True)
            prefix = f"{operation_id}."
            try:
                effect_present = any(
                    name.startswith(prefix) and name.endswith(".json")
                    for name in os.listdir(directory)
                )
            except OSError as error:
                raise InstallerUpdateCompositionV2Error(
                    "CANDIDATE_PRE_MAIN_EFFECT_INVALID",
                    "не удалось проверить квитанции запуска кандидата",
                ) from error
            if effect_present:
                _fail(
                    "CANDIDATE_PRE_MAIN_EFFECT_PRESENT",
                    "эффект запуска кандидата существует без main journal",
                )
        return authorization_store._replace_for_pre_main_retry(readiness_token)


def build_update_matched_active_composition_v2(
    *,
    registry: Any,
    proof: Any,
    preparation: Any,
    preparation_receipt: Any,
    source_binding: UpdateSourceBindingV2,
    registry_plan: RegistryUpdatePlanV2,
    launcher_plan: LauncherUpdatePlanV2,
    candidate_action: Any,
    readiness_token: str,
    wrapper_path: Path,
    schema_directory: Path,
    shell_session_id: str = "installer-v2",
    quiescence_timeout_ms: int = 30_000,
    runtime_environment: Mapping[str, str] | None = None,
    now: Callable[[], datetime] | None = None,
    id_factory: Callable[[str], str] | None = None,
    controller_port_options: Mapping[str, Any] | None = None,
    candidate_port_options: Mapping[str, Any] | None = None,
    shutdown_cleanup_port_options: Mapping[str, Any] | None = None,
    port_overrides: Mapping[str, UpdateStepPortV2] | None = None,
) -> InstallerUpdateCompositionV2:
    """Собрать свежую производственную операцию до появления main journal."""

    from .candidate_ready_channel_v2 import CandidateSpawnActionV2
    from .lifecycle_operation_v2 import build_operation_journal_validator_v2

    if not isinstance(schema_directory, Path) or not schema_directory.is_absolute():
        raise TypeError("schema_directory must be an absolute Path")
    candidate = (
        candidate_action
        if isinstance(candidate_action, CandidateSpawnActionV2)
        else CandidateSpawnActionV2.from_mapping(candidate_action)
    )
    if os.path.lexists(proof.layout.journal_path):
        _fail(
            "UPDATE_MAIN_JOURNAL_ALREADY_EXISTS",
            "существующий main journal требует recovery composition",
        )
    if os.path.lexists(preparation.definition.journal_path):
        _fail(
            "UPDATE_PREPARATION_HANDOFF_INCOMPLETE",
            "подготовительный journal не удалён перед main journal",
        )
    verify_update_source_binding_v2(
        binding=source_binding,
        preparation=preparation,
        preparation_receipt=preparation_receipt,
    )
    _verify_update_registry_binding_v2(
        proof=proof,
        preparation_receipt=preparation_receipt,
        registry_plan=registry_plan,
    )
    _verify_update_launcher_binding_v2(
        proof=proof,
        preparation_receipt=preparation_receipt,
        launcher_plan=launcher_plan,
    )
    _verify_update_candidate_binding_v2(
        proof=proof,
        preparation_receipt=preparation_receipt,
        candidate_action=candidate,
        readiness_token=readiness_token,
    )
    _verify_update_wrapper_binding_v2(
        preparation_receipt=preparation_receipt,
        wrapper_path=wrapper_path,
    )
    store = OperationJournalStoreV2(
        journal_path=proof.layout.journal_path,
        lock_path=proof.layout.lock_path,
        validate_document=build_operation_journal_validator_v2(schema_directory),
    )
    authorization_store = _candidate_authorization_store_v2(
        proof=proof,
        operation_id=preparation_receipt.operation_id,
        candidate_action=candidate,
    )
    persisted_readiness_token = _ensure_pre_main_candidate_authorization_v2(
        journal_store=store,
        authorization_store=authorization_store,
        readiness_token=readiness_token,
        commit_receipt_path=(
            proof.layout.receipts_root
            / proof.installation_id
            / f"{preparation_receipt.operation_id}.commit.json"
        ),
        codex_home=proof.codex_home,
    )
    plans = build_update_matched_active_definition_v2(
        registry=registry,
        proof=proof,
        preparation=preparation,
        preparation_receipt=preparation_receipt,
        registry_plan=registry_plan,
        launcher_plan=launcher_plan,
        candidate_action=candidate,
        shell_session_id=shell_session_id,
        quiescence_timeout_ms=quiescence_timeout_ms,
    )
    return _assemble_update_matched_active_composition_v2(
        registry=registry,
        proof=proof,
        preparation=preparation,
        preparation_receipt=preparation_receipt,
        source_binding=source_binding,
        plans=plans,
        registry_plan=registry_plan,
        launcher_plan=launcher_plan,
        candidate_action=candidate,
        candidate_authorization_store=authorization_store,
        readiness_token=persisted_readiness_token,
        wrapper_path=wrapper_path,
        store=store,
        recovery_journal=None,
        shell_session_id=shell_session_id,
        runtime_environment=runtime_environment,
        now=now,
        id_factory=id_factory,
        controller_port_options=controller_port_options,
        candidate_port_options=candidate_port_options,
        shutdown_cleanup_port_options=shutdown_cleanup_port_options,
        port_overrides=port_overrides,
    )


def load_update_matched_active_recovery_evidence_v2(
    *,
    store: OperationJournalStoreV2,
    preparation: Any,
    preparation_receipt_path: Path,
    source_binding: UpdateSourceBindingV2,
) -> InstallerUpdateRecoveryEvidenceV2:
    """В строгом порядке восстановить единый снимок main recovery."""

    from .activation_preparation_v2 import ActivationPreparationReceiptV2
    from .activation_transition_rehydration_v2 import (
        rehydrate_activation_transition_proof_v2,
    )
    from .operation_definition_rehydration_v2 import (
        operation_definition_from_journal_v2,
    )

    if not isinstance(store, OperationJournalStoreV2):
        raise TypeError("store must be OperationJournalStoreV2")
    if (
        not isinstance(preparation_receipt_path, Path)
        or not preparation_receipt_path.is_absolute()
    ):
        raise TypeError("preparation_receipt_path must be an absolute Path")
    journal = store.read()
    definition = operation_definition_from_journal_v2(journal)
    receipt = ActivationPreparationReceiptV2.from_path(preparation_receipt_path)
    _verify_prepared_source_binding_v2(
        binding=source_binding,
        preparation=preparation,
    )
    _verify_update_receipt_codex_binding_v2(
        binding=source_binding,
        preparation_receipt=receipt,
    )
    snapshot = receipt.transition_proof_snapshot
    if snapshot is None:
        _fail(
            "UPDATE_TRANSITION_SNAPSHOT_MISSING",
            "prep receipt не содержит transition proof snapshot",
        )
    proof = rehydrate_activation_transition_proof_v2(snapshot, journal=journal)
    _verify_update_receipt_codex_binding_v2(
        binding=source_binding,
        preparation_receipt=receipt,
    )
    if (
        definition.installation_id != receipt.installation_id
        or definition.operation_id != receipt.operation_id
        or proof.installation_id != definition.installation_id
    ):
        _fail(
            "UPDATE_RECOVERY_BINDING_INVALID",
            "journal, prep receipt и transition proof относятся к разным операциям",
        )
    return InstallerUpdateRecoveryEvidenceV2(
        journal=journal,
        definition=definition,
        preparation_receipt=receipt,
        transition_proof=proof,
    )


def recover_update_matched_active_composition_v2(
    *,
    registry: Any,
    store: OperationJournalStoreV2,
    preparation: Any,
    preparation_receipt_path: Path,
    source_binding: UpdateSourceBindingV2,
    registry_runtime: RegistryRuntimeBindingsV2,
    launcher_bindings: tuple[LauncherBindingV2, ...],
    wrapper_path: Path,
    shell_session_id: str = "installer-v2",
    runtime_environment: Mapping[str, str] | None = None,
    now: Callable[[], datetime] | None = None,
    id_factory: Callable[[str], str] | None = None,
    controller_port_options: Mapping[str, Any] | None = None,
    candidate_port_options: Mapping[str, Any] | None = None,
    shutdown_cleanup_port_options: Mapping[str, Any] | None = None,
    port_overrides: Mapping[str, UpdateStepPortV2] | None = None,
) -> InstallerUpdateCompositionV2:
    """Собрать готовые recovery callbacks только из persisted definition."""

    from .activation_preparation_v2 import (
        prepared_receipt_to_staged_activation_v2,
    )
    from .activation_transition_v2 import (
        build_activation_link_plan_v2,
        build_manifest_commit_plan_v2,
    )
    from .candidate_ready_channel_v2 import CandidateSpawnActionV2
    from .installer_upgrade_v2 import prepared_manifest_from_upgrade_receipt_v2

    evidence = load_update_matched_active_recovery_evidence_v2(
        store=store,
        preparation=preparation,
        preparation_receipt_path=preparation_receipt_path,
        source_binding=source_binding,
    )
    definition = evidence.definition
    receipt = evidence.preparation_receipt
    proof = evidence.transition_proof
    definitions = _mutable_definitions_by_kind_v2(definition)
    candidate = CandidateSpawnActionV2.from_mapping(
        definitions["controller_candidate_spawn"].action
    )
    registry_plan = _rehydrate_registry_update_plan_v2(
        definition=definition,
        proof=proof,
        preparation_receipt=receipt,
        bindings=registry_runtime,
    )
    launcher_plan = _rehydrate_launcher_update_plan_v2(
        definition=definition,
        bindings=tuple(launcher_bindings),
    )
    staged = prepared_receipt_to_staged_activation_v2(receipt)
    activation_link_plan = build_activation_link_plan_v2(
        proof=proof,
        staged=staged,
    )
    prepared_manifest = prepared_manifest_from_upgrade_receipt_v2(
        proof=proof,
        preparation=preparation,
        receipt=receipt,
    )
    manifest_commit_plan = build_manifest_commit_plan_v2(
        proof=proof,
        staged=staged,
        prepared=prepared_manifest,
    )
    shutdown_cleanup_plan = _rehydrate_shutdown_cleanup_plan_v2(
        definition=definition,
        proof=proof,
    )
    plans = UpdateMatchedActiveDefinitionPlansV2(
        definition=definition,
        staged=staged,
        activation_link_plan=activation_link_plan,
        manifest_commit_plan=manifest_commit_plan,
        shutdown_cleanup_plan=shutdown_cleanup_plan,
        candidate_action=candidate,
        controller_definitions={
            kind: definitions[kind]
            for kind in (
                "maintenance_begin",
                "wait_runtime_quiescent",
                "maintenance_strengthen",
                "controller_shutdown",
                "controller_accept",
                "maintenance_resume",
            )
        },
    )
    _validate_rehydrated_plans_v2(
        plans=plans,
        registry_plan=registry_plan,
        launcher_plan=launcher_plan,
    )
    authorization_store = _candidate_authorization_store_v2(
        proof=proof,
        operation_id=definition.operation_id,
        candidate_action=candidate,
    )
    candidate_state = _persisted_step_state_v2(
        evidence.journal,
        "controller_candidate_spawn",
    )
    readiness_token = authorization_store.load_if_present()
    if candidate_state == "PLANNED" and readiness_token is None:
        _fail(
            "CANDIDATE_AUTHORIZATION_MISSING",
            "PLANNED candidate spawn не имеет долговечной авторизации",
        )
    return _assemble_update_matched_active_composition_v2(
        registry=registry,
        proof=proof,
        preparation=preparation,
        preparation_receipt=receipt,
        source_binding=source_binding,
        plans=plans,
        registry_plan=registry_plan,
        launcher_plan=launcher_plan,
        candidate_action=candidate,
        candidate_authorization_store=authorization_store,
        readiness_token=readiness_token,
        wrapper_path=wrapper_path,
        store=store,
        recovery_journal=evidence.journal,
        shell_session_id=shell_session_id,
        runtime_environment=runtime_environment,
        now=now,
        id_factory=id_factory,
        controller_port_options=controller_port_options,
        candidate_port_options=candidate_port_options,
        shutdown_cleanup_port_options=shutdown_cleanup_port_options,
        port_overrides=port_overrides,
    )


def _assemble_update_matched_active_composition_v2(
    *,
    registry: Any,
    proof: Any,
    preparation: Any,
    preparation_receipt: Any,
    source_binding: UpdateSourceBindingV2,
    plans: UpdateMatchedActiveDefinitionPlansV2,
    registry_plan: RegistryUpdatePlanV2,
    launcher_plan: LauncherUpdatePlanV2,
    candidate_action: Any,
    candidate_authorization_store: CandidateSpawnAuthorizationStoreV2,
    readiness_token: str | None,
    wrapper_path: Path,
    store: OperationJournalStoreV2,
    recovery_journal: Mapping[str, Any] | None,
    shell_session_id: str,
    runtime_environment: Mapping[str, str] | None,
    now: Callable[[], datetime] | None,
    id_factory: Callable[[str], str] | None,
    controller_port_options: Mapping[str, Any] | None,
    candidate_port_options: Mapping[str, Any] | None,
    shutdown_cleanup_port_options: Mapping[str, Any] | None,
    port_overrides: Mapping[str, UpdateStepPortV2] | None,
) -> InstallerUpdateCompositionV2:
    from .candidate_ready_channel_v2 import (
        build_controller_candidate_spawn_step_port_v2,
    )
    from .installer_update_controller_ports_v2 import (
        build_update_controller_step_ports_v2,
    )
    from .installer_update_operation_v2 import (
        PreparationReceiptGateV2,
        build_activation_link_step_port_v2,
        build_manifest_commit_step_port_v2,
        build_rehydrating_controller_proof_providers_v2,
        build_upgrade_database_step_port_v2,
        build_upgrade_preparation_gate_v2,
    )
    from .shutdown_socket_cleanup_v2 import wait_for_shutdown_socket_orphan_v2

    definition = plans.definition
    definitions = _mutable_definitions_by_kind_v2(definition)
    base_gate = build_upgrade_preparation_gate_v2(
        proof=proof,
        preparation=preparation,
        expected_receipt=preparation_receipt,
    )
    if recovery_journal is None:
        gate = PreparationReceiptGateV2(
            expected=base_gate.expected,
            verify_before_journal=lambda: _verify_fresh_handoff_v2(
                source_binding=source_binding,
                preparation=preparation,
                preparation_receipt=preparation_receipt,
                gate=base_gate,
            ),
            verify_resume=base_gate.verify_resume_exact,
        )
    else:
        base_gate.verify_resume_exact(recovery_journal)
        gate = base_gate
    proof_providers = build_rehydrating_controller_proof_providers_v2(
        definition=definition,
        proof=proof,
        preparation_receipt=preparation_receipt,
    )
    shutdown_options = _port_options_v2(
        shutdown_cleanup_port_options,
        forbidden={"plan", "definition", "shutdown_proof_provider"},
        label="shutdown_cleanup_port_options",
    )

    def prove_shutdown_orphan(shutdown: Any) -> Any:
        marker_provider = shutdown_options.get("process_start_marker_provider")
        marker_arguments = (
            {}
            if marker_provider is None
            else {"process_start_marker_provider": marker_provider}
        )
        return wait_for_shutdown_socket_orphan_v2(
            plan=plans.shutdown_cleanup_plan,
            shutdown=shutdown,
            **marker_arguments,
        )

    controller_options = _port_options_v2(
        controller_port_options,
        forbidden={
            "operation_id",
            "activation_proof_fingerprint",
            "shutdown_cleanup_plan_fingerprint",
            "codex_home",
            "current_database_path",
            "candidate_database_path",
            "definitions",
            "candidate_spawn_action",
            "expected_orphan_operation_id",
            "maintenance_reason_code",
            "shell_session_id",
            "shutdown_orphan_prover",
        },
        label="controller_port_options",
    )
    ports: dict[str, UpdateStepPortV2] = build_update_controller_step_ports_v2(
        operation_id=definition.operation_id,
        activation_proof_fingerprint=proof.proof_fingerprint,
        shutdown_cleanup_plan_fingerprint=(
            plans.shutdown_cleanup_plan.plan_fingerprint
        ),
        codex_home=proof.codex_home,
        current_database_path=proof.database_path,
        candidate_database_path=preparation_receipt.activation_intent.database_path,
        definitions=plans.controller_definitions,
        candidate_spawn_action=candidate_action,
        expected_orphan_operation_id=None,
        maintenance_reason_code="UPGRADE",
        shell_session_id=shell_session_id,
        shutdown_orphan_prover=prove_shutdown_orphan,
        **controller_options,
    )
    ports["shutdown_socket_cleanup"] = build_shutdown_socket_cleanup_step_port_v2(
        plan=plans.shutdown_cleanup_plan,
        definition=definitions["shutdown_socket_cleanup"],
        shutdown_proof_provider=proof_providers.shutdown,
        **shutdown_options,
    )
    ports["database_prepare"] = build_upgrade_database_step_port_v2(preparation_receipt)
    ports["activation_link"] = build_activation_link_step_port_v2(
        plan=plans.activation_link_plan,
        proof=proof,
        staged=plans.staged,
        proof_providers=proof_providers,
    )
    ports.update(
        build_registry_step_ports_v2(
            plan=registry_plan,
            definitions={
                kind: definitions[kind]
                for kind in ("marketplace_registry", "plugin_registry")
            },
        )
    )
    ports["launchers"] = build_launcher_step_port_v2(
        plan=launcher_plan,
        definition=definitions["launchers"],
    )
    candidate_options = _port_options_v2(
        candidate_port_options,
        forbidden={
            "candidate_spawn_action",
            "codex_home",
            "state_home",
            "wrapper_path",
            "readiness_token",
            "runtime_environment",
            "accepted_controller_observer",
        },
        label="candidate_port_options",
    )

    def observe_accepted_controller() -> ProjectionV2:
        definition = definitions["controller_accept"]
        port = ports["controller_accept"]
        observed = port.observe(definition)
        if not port.matches_after(observed, definition):
            _fail(
                "CANDIDATE_SUCCESSOR_INVALID",
                "controller_accept не доказал принятого преемника",
            )
        return observed

    candidate_port = build_controller_candidate_spawn_step_port_v2(
        candidate_spawn_action=candidate_action,
        codex_home=proof.codex_home,
        state_home=preparation_receipt.activation_intent.state_home,
        wrapper_path=wrapper_path,
        readiness_token=readiness_token,
        accepted_controller_observer=observe_accepted_controller,
        runtime_environment=(
            None if runtime_environment is None else dict(runtime_environment)
        ),
        **candidate_options,
    )
    ports["controller_candidate_spawn"] = _wrap_candidate_authorization_port_v2(
        port=candidate_port,
        store=candidate_authorization_store,
    )
    ports["verify_candidate"] = build_verify_candidate_step_port_v2(
        definition=definitions["verify_candidate"],
        proof=proof,
        preparation_receipt=preparation_receipt,
        acceptance_proof_provider=proof_providers.acceptance,
    )
    ports["manifest_commit"] = build_manifest_commit_step_port_v2(
        plan=plans.manifest_commit_plan,
        proof=proof,
        staged=plans.staged,
        proof_providers=proof_providers,
    )
    if port_overrides is not None:
        for kind, port in dict(port_overrides).items():
            if (
                kind not in ports
                or kind == "controller_candidate_spawn"
                or not isinstance(port, UpdateStepPortV2)
            ):
                _fail(
                    "UPDATE_PORT_OVERRIDE_INVALID",
                    f"неверная подмена порта {kind}",
                )
            ports[kind] = port
    for historical_kind in ("controller_shutdown", "shutdown_socket_cleanup"):
        ports[historical_kind] = (
            _wrap_completed_port_with_candidate_successor_v2(
                port=ports[historical_kind],
                candidate_port=ports["controller_candidate_spawn"],
                candidate_definition=definitions["controller_candidate_spawn"],
                accept_port=ports["controller_accept"],
                accept_definition=definitions["controller_accept"],
            )
        )
    typed_ports = UpdateStepPortsV2(ports)
    callbacks = _step_callbacks_for_ports_v2(typed_ports)
    executor = OperationExecutorV2(
        store=store,
        now=now or (lambda: datetime.now(timezone.utc)),
        id_factory=id_factory,
    )
    receipt_store = ActivationCommitReceiptStoreV2(definition=definition)
    terminal_callbacks = receipt_store.callbacks()
    operation = UpdateMatchedActiveOperationV2(
        registry=registry,
        executor=executor,
        definition=definition,
        preparation=gate,
        ports=typed_ports,
        receipt_store=receipt_store,
    )
    return InstallerUpdateCompositionV2(
        definition=definition,
        operation=operation,
        ports=typed_ports,
        callbacks=callbacks,
        terminal_callbacks=terminal_callbacks,
        receipt_store=receipt_store,
        executor=executor,
        plans=plans,
        candidate_authorization_store=candidate_authorization_store,
    )


def _verify_fresh_handoff_v2(
    *,
    source_binding: UpdateSourceBindingV2,
    preparation: Any,
    preparation_receipt: Any,
    gate: Any,
) -> Any:
    verify_update_source_binding_v2(
        binding=source_binding,
        preparation=preparation,
        preparation_receipt=preparation_receipt,
    )
    return gate.verify_before_journal_exact()


def _step_callbacks_for_ports_v2(ports: UpdateStepPortsV2) -> StepCallbacksV2:
    return StepCallbacksV2(
        observe=lambda definition: ports.require(definition.kind).observe(definition),
        apply=lambda definition: ports.require(definition.kind).apply(definition),
        matches_before=lambda observed, definition: ports.require(
            definition.kind
        ).matches_before(observed, definition),
        matches_after=lambda observed, definition: ports.require(
            definition.kind
        ).matches_after(observed, definition),
        matches_intent_resume=lambda observed, definition: ports.require(
            definition.kind
        ).matches_intent_resume(observed, definition),
        replay_safe_when_indistinguishable=lambda observed, definition: ports.require(
            definition.kind
        ).replay_safe_when_indistinguishable(observed, definition),
        completed_current_matches=lambda persisted, current, definition: ports.require(
            definition.kind
        ).completed_current_matches(persisted, current, definition),
    )


def _wrap_candidate_authorization_port_v2(
    *,
    port: UpdateStepPortV2,
    store: CandidateSpawnAuthorizationStoreV2,
) -> UpdateStepPortV2:
    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        observed = port.observe(definition)
        if port.matches_after(observed, definition):
            store.remove_if_present()
        return observed

    def apply(definition: StepDefinitionV2) -> None:
        port.apply(definition)

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=port.matches_before,
        matches_after=port.matches_after,
        matches_intent_resume=port.matches_intent_resume,
        replay_safe_when_indistinguishable=(port.replay_safe_when_indistinguishable),
        completed_current_matches=port.completed_current_matches,
    )


def _wrap_completed_port_with_candidate_successor_v2(
    *,
    port: UpdateStepPortV2,
    candidate_port: UpdateStepPortV2,
    candidate_definition: StepDefinitionV2,
    accept_port: UpdateStepPortV2,
    accept_definition: StepDefinitionV2,
) -> UpdateStepPortV2:
    """Не перепроверять старый lock, когда точный кандидат уже преемник."""

    from .candidate_ready_channel_v2 import CandidateReadyChannelV2Error

    for value, name in (
        (port, "port"),
        (candidate_port, "candidate_port"),
        (accept_port, "accept_port"),
    ):
        if not isinstance(value, UpdateStepPortV2):
            raise TypeError(f"{name} must be UpdateStepPortV2")
    if (
        not isinstance(candidate_definition, StepDefinitionV2)
        or candidate_definition.kind != "controller_candidate_spawn"
        or not isinstance(accept_definition, StepDefinitionV2)
        or accept_definition.kind
        not in {"controller_accept", "controller_previous_accept"}
    ):
        raise TypeError("candidate and accept definitions are invalid")

    def observe_successor() -> ProjectionV2 | None:
        try:
            candidate = candidate_port.observe(candidate_definition)
        except CandidateReadyChannelV2Error as error:
            if error.code != "CANDIDATE_SPAWN_COMPLETED_UNOBSERVABLE":
                raise
            accepted = accept_port.observe(accept_definition)
            if not accept_port.matches_after(accepted, accept_definition):
                _fail(
                    "CANDIDATE_SUCCESSOR_INVALID",
                    "закрытый ready-канал не подтверждён принятой командой",
                )
            return accepted
        if candidate_port.matches_after(candidate, candidate_definition):
            return candidate
        return None

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        successor = observe_successor()
        return port.observe(definition) if successor is None else successor

    def completed_current_matches(
        persisted: ProjectionV2,
        current: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        if not port.matches_after(persisted, definition):
            return False
        successor = observe_successor()
        if successor is not None:
            return current == successor
        return port.completed_current_matches(persisted, current, definition)

    return UpdateStepPortV2(
        observe=observe,
        apply=port.apply,
        matches_before=port.matches_before,
        matches_after=port.matches_after,
        replay_safe_when_indistinguishable=(
            port.replay_safe_when_indistinguishable
        ),
        completed_current_matches=completed_current_matches,
    )


def _candidate_authorization_store_v2(
    *,
    proof: Any,
    operation_id: str,
    candidate_action: Any,
) -> CandidateSpawnAuthorizationStoreV2:
    return CandidateSpawnAuthorizationStoreV2(
        path=(
            proof.layout.receipts_root
            / proof.installation_id
            / f"{operation_id}.candidate-spawn.authorization.json"
        ),
        installation_id=proof.installation_id,
        operation_id=operation_id,
        action_fingerprint=candidate_action.action_fingerprint,
        readiness_token_hash=candidate_action.readiness_token_hash,
    )


def _mutable_definitions_by_kind_v2(
    definition: OperationDefinitionV2,
) -> dict[str, StepDefinitionV2]:
    if not isinstance(definition, OperationDefinitionV2):
        raise TypeError("definition must be OperationDefinitionV2")
    result = {step.kind: step for step in definition.mutable_steps}
    if len(result) != len(definition.mutable_steps):
        _fail("UPDATE_DEFINITION_INVALID", "виды mutable steps не уникальны")
    return result


def _port_options_v2(
    options: Mapping[str, Any] | None,
    *,
    forbidden: set[str],
    label: str,
) -> dict[str, Any]:
    if options is None:
        return {}
    if not isinstance(options, Mapping) or any(
        type(name) is not str for name in options
    ):
        raise TypeError(f"{label} must be a string-keyed mapping")
    copied = dict(options)
    overlap = sorted(set(copied).intersection(forbidden))
    if overlap:
        raise TypeError(f"{label} cannot override bound arguments: {overlap}")
    return copied


def _persisted_step_state_v2(journal: Mapping[str, Any], kind: str) -> str:
    matches = [
        step
        for step in journal.get("steps", [])
        if isinstance(step, Mapping) and step.get("kind") == kind
    ]
    if len(matches) != 1 or matches[0].get("state") not in {
        "PLANNED",
        "INTENT_DURABLE",
        "COMPLETED",
    }:
        _fail(
            "UPDATE_RECOVERY_JOURNAL_INVALID",
            f"journal не содержит единственный шаг {kind}",
        )
    return str(matches[0]["state"])


def _rehydrate_registry_update_plan_v2(
    *,
    definition: OperationDefinitionV2,
    proof: Any,
    preparation_receipt: Any,
    bindings: RegistryRuntimeBindingsV2,
) -> RegistryUpdatePlanV2:
    if not isinstance(bindings, RegistryRuntimeBindingsV2):
        raise TypeError("registry_runtime must be RegistryRuntimeBindingsV2")
    steps = _mutable_definitions_by_kind_v2(definition)
    marketplace = steps["marketplace_registry"]
    plugin = steps["plugin_registry"]
    try:
        previous_path = Path(str(marketplace.before.value["marketplacePath"]))
        registered_path = Path(str(marketplace.expected_after.value["marketplacePath"]))
        timeout_ms = marketplace.action["timeoutMs"]
    except (KeyError, TypeError, ValueError) as error:
        raise InstallerUpdateCompositionV2Error(
            "REGISTRY_RECOVERY_DEFINITION_INVALID",
            "persisted registry definition неполно",
        ) from error
    if (
        not previous_path.is_absolute()
        or not registered_path.is_absolute()
        or type(timeout_ms) is not int
        or plugin.action.get("timeoutMs") != timeout_ms
    ):
        _fail(
            "REGISTRY_RECOVERY_DEFINITION_INVALID",
            "persisted registry paths или timeout неверны",
        )
    plan = RegistryUpdatePlanV2(
        installation_id=definition.installation_id,
        operation_id=definition.operation_id,
        codex_binary=preparation_receipt.activation_intent.snapshot_path,
        codex_home=proof.codex_home,
        working_directory=bindings.working_directory,
        marketplace_path=proof.layout.marketplace_link,
        previous_registered_marketplace_path=previous_path,
        registered_marketplace_path=registered_path,
        plugin_relative_path=bindings.plugin_relative_path,
        plugin_version=bindings.plugin_version,
        install_policy=bindings.install_policy,
        auth_policy=bindings.auth_policy,
        receipt_directory=(proof.layout.receipts_root / definition.installation_id),
        command_runner=bindings.command_runner,
        before_registry=marketplace.before,
        timeout_ms=timeout_ms,
    )
    if build_registry_step_definitions_v2(plan) != {
        "marketplace_registry": marketplace,
        "plugin_registry": plugin,
    }:
        _fail(
            "REGISTRY_RECOVERY_DEFINITION_INVALID",
            "runtime bindings не воспроизводят persisted registry definition",
        )
    return plan


def _rehydrate_launcher_update_plan_v2(
    *,
    definition: OperationDefinitionV2,
    bindings: tuple[LauncherBindingV2, ...],
) -> LauncherUpdatePlanV2:
    steps = _mutable_definitions_by_kind_v2(definition)
    persisted = steps["launchers"]
    copied = tuple(bindings)
    if not copied or not all(isinstance(item, LauncherBindingV2) for item in copied):
        raise TypeError("launcher_bindings must contain LauncherBindingV2 items")
    expected_after = _launcher_set_projection(
        copied,
        tuple(item.expected_resolved_target for item in copied),
    )
    if expected_after != persisted.expected_after:
        _fail(
            "LAUNCHER_RECOVERY_BINDING_INVALID",
            "launcher bindings не воспроизводят persisted expectedAfter",
        )
    draft = object.__new__(LauncherUpdatePlanV2)
    object.__setattr__(draft, "installation_id", definition.installation_id)
    object.__setattr__(draft, "operation_id", definition.operation_id)
    object.__setattr__(draft, "bindings", copied)
    object.__setattr__(draft, "before", persisted.before)
    object.__setattr__(draft, "expected_after", persisted.expected_after)
    object.__setattr__(draft, "plan_fingerprint", "0" * 64)
    plan = LauncherUpdatePlanV2(
        installation_id=definition.installation_id,
        operation_id=definition.operation_id,
        bindings=copied,
        before=persisted.before,
        expected_after=persisted.expected_after,
        plan_fingerprint=_launcher_plan_fingerprint(draft),
    )
    if build_launcher_step_definition_v2(plan) != persisted:
        _fail(
            "LAUNCHER_RECOVERY_BINDING_INVALID",
            "launcher bindings не воспроизводят persisted action",
        )
    current = _observe_launcher_bindings(copied, expected=False)
    if current not in (persisted.before, persisted.expected_after):
        _fail(
            "LAUNCHER_RECOVERY_BINDING_INVALID",
            "текущие launchers не являются before/after persisted шага",
        )
    return plan


def _rehydrate_shutdown_cleanup_plan_v2(
    *,
    definition: OperationDefinitionV2,
    proof: Any,
) -> Any:
    from .shutdown_socket_cleanup_v2 import ShutdownSocketCleanupPlanV2

    step = _mutable_definitions_by_kind_v2(definition)["shutdown_socket_cleanup"]
    action = copy.deepcopy(dict(step.action))
    try:
        if (
            action["actionKind"] != "socket-cleanup"
            or action["method"] != "unlink-proven-orphan"
            or action["proofSource"] != "CONTROLLER_SHUTDOWN_INTENT"
        ):
            raise ValueError("unsupported cleanup action")
        plan = ShutdownSocketCleanupPlanV2(
            installation_id=definition.installation_id,
            activation_proof_fingerprint=proof.proof_fingerprint,
            operation_id=definition.operation_id,
            shutdown_command_id=str(action["proofSourceId"]),
            socket_path=Path(str(action["socketPath"])),
            socket_device=int(action["socketDevice"]),
            socket_inode=int(action["socketInode"]),
            socket_owner_uid=int(action["socketOwnerUid"]),
            socket_owner_gid=int(action["socketOwnerGid"]),
            socket_mode=str(action["socketMode"]),
            socket_parent_device=int(action["socketParentDevice"]),
            socket_parent_inode=int(action["socketParentInode"]),
            target_pid=int(action["targetPid"]),
            target_start_marker=str(action["targetStartMarker"]),
            target_process_group_id=int(action["targetProcessGroupId"]),
            lock_path=Path(str(action["lockPath"])),
            action=action,
            plan_fingerprint="0" * 64,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise InstallerUpdateCompositionV2Error(
            "SHUTDOWN_CLEANUP_RECOVERY_DEFINITION_INVALID",
            "persisted cleanup definition неполно",
        ) from error
    fingerprint = domain_fingerprint(
        "codex-smart/shutdown-socket-cleanup-plan/v2",
        {
            "installationId": plan.installation_id,
            "activationProofFingerprint": plan.activation_proof_fingerprint,
            "operationId": plan.operation_id,
            "shutdownCommandId": plan.shutdown_command_id,
            "action": action,
        },
    )
    plan = ShutdownSocketCleanupPlanV2(
        **{
            name: getattr(plan, name)
            for name in plan.__dataclass_fields__
            if name != "plan_fingerprint"
        },
        plan_fingerprint=fingerprint,
    )
    if (
        not plan.complete
        or build_shutdown_socket_cleanup_step_definition_v2(
            plan=plan,
            shutdown_constraint=step.before,
        )
        != step
    ):
        _fail(
            "SHUTDOWN_CLEANUP_RECOVERY_DEFINITION_INVALID",
            "cleanup plan не воспроизводит persisted definition",
        )
    return plan


def _validate_rehydrated_plans_v2(
    *,
    plans: UpdateMatchedActiveDefinitionPlansV2,
    registry_plan: RegistryUpdatePlanV2,
    launcher_plan: LauncherUpdatePlanV2,
) -> None:
    steps = _mutable_definitions_by_kind_v2(plans.definition)
    if (
        StepDefinitionV2(
            kind="activation_link",
            command_id=None,
            action=plans.activation_link_plan.action,
            before=plans.activation_link_plan.before,
            expected_after=plans.activation_link_plan.expected_after,
        )
        != steps["activation_link"]
        or StepDefinitionV2(
            kind="manifest_commit",
            command_id=None,
            action=plans.manifest_commit_plan.action,
            before=plans.manifest_commit_plan.before,
            expected_after=plans.manifest_commit_plan.expected_after,
        )
        != steps["manifest_commit"]
        or build_registry_step_definitions_v2(registry_plan)
        != {
            "marketplace_registry": steps["marketplace_registry"],
            "plugin_registry": steps["plugin_registry"],
        }
        or build_launcher_step_definition_v2(launcher_plan) != steps["launchers"]
    ):
        _fail(
            "UPDATE_RECOVERY_PLAN_INVALID",
            "rehydrated планы не совпадают с persisted definition",
        )


def _fail(code: str, message: str) -> None:
    raise InstallerUpdateCompositionV2Error(code, message)


__all__ = [
    "CandidateSpawnAuthorizationStoreV2",
    "InstallerUpdateCompositionV2",
    "InstallerUpdateCompositionV2Error",
    "InstallerUpdateRecoveryEvidenceV2",
    "LauncherBindingV2",
    "LauncherUpdatePlanV2",
    "RegistryRuntimeBindingsV2",
    "RegistryUpdatePlanV2",
    "UpdateMatchedActiveDefinitionPlansV2",
    "UpdateSourceBindingV2",
    "build_candidate_spawn_action_v2",
    "build_launcher_step_definition_v2",
    "build_launcher_step_port_v2",
    "build_launcher_update_plan_v2",
    "build_controller_shutdown_constraint_v2",
    "build_registry_step_definitions_v2",
    "build_registry_step_ports_v2",
    "build_registry_update_plan_v2",
    "build_shutdown_socket_cleanup_step_definition_v2",
    "build_shutdown_socket_cleanup_step_port_v2",
    "build_update_controller_step_definitions_v2",
    "build_update_matched_active_composition_v2",
    "build_update_matched_active_definition_v2",
    "build_verify_candidate_step_port_v2",
    "load_update_matched_active_recovery_evidence_v2",
    "recover_update_matched_active_composition_v2",
    "verify_update_source_binding_v2",
]
