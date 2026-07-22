"""Производственная композиция ветви ``rollback-matched-active`` версии 2.

Модуль принимает только уже доказанные внешние порты контроллера, реестра и
загрузчиков. Файловые переходы ссылки и манифеста строятся здесь из
``RollbackEvidenceV2`` и отдельной долговечной подготовки rollback-manifest.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .activation_gateway_v2 import _LIFECYCLE_SCHEMA_SHA256
from .activation_transition_v2 import PreparedManifestCommitV2
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .installer_recovery_v2 import RollbackEvidenceV2
from .installer_update_operation_v2 import (
    ActivationCommitReceiptStoreV2,
    UpdateStepPortV2,
)
from .lifecycle_operation_v2 import (
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    ControllerShutdownLineageV2,
    OperationDefinitionV2,
    ProjectionV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    StoppedControllerLineageV2,
    TerminalCallbacksV2,
    TerminalDefinitionV2,
    TransitionSourceReceiptV2,
)
from .rollback_manifest_preparation_v2 import (
    RollbackManifestPreparationReceiptV2,
    prepared_rollback_manifest_from_receipt_v2,
    rollback_operation_id_v2,
)


ROLLBACK_MATCHED_ACTIVE_STEPS_V2 = (
    "gate_close",
    "maintenance_begin",
    "wait_runtime_quiescent",
    "maintenance_strengthen",
    "controller_shutdown",
    "shutdown_socket_cleanup",
    "activation_link_restore",
    "recovery_forward_only",
    "registry_restore",
    "launchers_restore",
    "controller_candidate_spawn",
    "controller_previous_accept",
    "verify_candidate",
    "manifest_restore",
    "maintenance_resume",
    "terminal_journal_freeze",
    "commit_receipt_publish",
    "gate_open",
)
_DERIVED_MUTABLE_STEPS = {
    "activation_link_restore",
    "recovery_forward_only",
    "manifest_restore",
}
_EXTERNAL_STEP_KINDS = frozenset(ROLLBACK_MATCHED_ACTIVE_STEPS_V2[1:15]).difference(
    _DERIVED_MUTABLE_STEPS
)
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024


@dataclass
class InstallerRollbackCompositionV2Error(RuntimeError):
    """Закрытый отказ подготовки либо композиции отката."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class RollbackStepBindingV2:
    """Одно неизменяемое определение и его производственный порт."""

    definition: StepDefinitionV2
    port: UpdateStepPortV2

    def __post_init__(self) -> None:
        if not isinstance(self.definition, StepDefinitionV2):
            raise TypeError("definition must be StepDefinitionV2")
        if not isinstance(self.port, UpdateStepPortV2):
            raise TypeError("port must be UpdateStepPortV2")


class RollbackExternalStepBindingsV2:
    """Закрытый набор внешних шагов, не выводимых из commit-квитанций."""

    def __init__(self, bindings: Mapping[str, RollbackStepBindingV2]) -> None:
        copied = dict(bindings)
        if set(copied) != _EXTERNAL_STEP_KINDS:
            missing = sorted(_EXTERNAL_STEP_KINDS.difference(copied))
            extra = sorted(set(copied).difference(_EXTERNAL_STEP_KINDS))
            _fail(
                "ROLLBACK_EXTERNAL_BINDINGS_INVALID",
                f"неверный набор внешних шагов: missing={missing}, extra={extra}",
            )
        for kind, binding in copied.items():
            if not isinstance(binding, RollbackStepBindingV2):
                raise TypeError("every binding must be RollbackStepBindingV2")
            if binding.definition.kind != kind:
                _fail(
                    "ROLLBACK_EXTERNAL_BINDINGS_INVALID",
                    f"ключ {kind} не совпадает с определением",
                )
        self._bindings = copied

    def require(self, kind: str) -> RollbackStepBindingV2:
        try:
            return self._bindings[kind]
        except KeyError as error:  # pragma: no cover - закрыто конструктором
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_EXTERNAL_BINDING_MISSING",
                f"нет внешнего шага {kind}",
            ) from error


@dataclass(frozen=True)
class RollbackLauncherBindingV2:
    """Одна стабильная launcher-ссылка из текущей installer receipt."""

    path: Path
    target: Path
    relative_marketplace_target: Path


@dataclass(frozen=True)
class RollbackExternalArtifactsV2:
    """Физически перепроверенные внешние пути одной установленной версии."""

    installer_receipt_path: Path
    installer_receipt: Mapping[str, Any]
    installer_receipt_file: ProjectionV2
    current_registered_marketplace: Path
    previous_registered_marketplace: Path
    launchers: tuple[RollbackLauncherBindingV2, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "installer_receipt", copy.deepcopy(dict(self.installer_receipt))
        )
        object.__setattr__(self, "launchers", tuple(self.launchers))


@dataclass(frozen=True)
class RollbackCompositionV2:
    """Готовые входы ``execute_rollback_v2`` для одной операции."""

    definition: OperationDefinitionV2
    callbacks: StepCallbacksV2
    terminal_callbacks: TerminalCallbacksV2
    prepared_manifest: PreparedManifestCommitV2
    preparation_receipt_fingerprint: str


def read_rollback_external_artifacts_v2(
    *,
    evidence: RollbackEvidenceV2,
    installer_receipt_path: Path,
) -> RollbackExternalArtifactsV2:
    """Связать installer receipt, canonical marketplace и стабильные launchers."""

    _require_evidence(evidence)
    if not isinstance(installer_receipt_path, Path) or not (
        installer_receipt_path.is_absolute()
    ):
        raise TypeError("installer_receipt_path must be an absolute Path")
    _raw, receipt = _read_private_canonical_json(installer_receipt_path)
    required = {
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
    links = receipt.get("links")
    if (
        set(receipt) != required
        or receipt.get("schemaVersion") != 2
        or receipt.get("kind") != "codex-smart-installer-receipt/v2"
        or receipt.get("installationId") != evidence.installation_id
        or receipt.get("activationId") != evidence.current_activation_id
        or receipt.get("marketplacePath") != str(evidence.marketplace_link)
        or receipt.get("marketplaceName") != "codex-settings-adaptive"
        or receipt.get("pluginId") != "codex-smart-subagents@codex-settings-adaptive"
        or receipt.get("extensions") != {}
        or type(receipt.get("sourceDigest")) is not str
        or _SHA256.fullmatch(str(receipt.get("sourceDigest"))) is None
        or type(links) is not list
        or len(links) != 2
    ):
        _fail(
            "ROLLBACK_INSTALLER_RECEIPT_INVALID",
            "installer receipt не имеет точной формы текущей установки",
        )
    for name in ("codexHome", "codexBinary", "stateHome"):
        value = receipt.get(name)
        if type(value) is not str or not Path(value).is_absolute():
            _fail(
                "ROLLBACK_INSTALLER_RECEIPT_INVALID",
                f"{name} не является абсолютным путём",
            )
    current = (
        evidence.activations_root / evidence.current_activation_id / "marketplace"
    ).resolve(strict=True)
    previous = (
        evidence.activations_root / evidence.previous_activation_id / "marketplace"
    ).resolve(strict=True)
    registered = receipt.get("registeredMarketplacePath")
    if type(registered) is not str or Path(registered) != current:
        _fail(
            "ROLLBACK_INSTALLER_RECEIPT_INVALID",
            "registeredMarketplacePath не является current canonical path",
        )
    result: list[RollbackLauncherBindingV2] = []
    seen: set[tuple[str, str]] = set()
    for item in links:
        if type(item) is not dict or set(item) != {"path", "target"}:
            _fail(
                "ROLLBACK_INSTALLER_RECEIPT_INVALID",
                "launcher binding имеет неверную форму",
            )
        raw_path = item.get("path")
        raw_target = item.get("target")
        if (
            type(raw_path) is not str
            or type(raw_target) is not str
            or not Path(raw_path).is_absolute()
            or not Path(raw_target).is_absolute()
            or (raw_path, raw_target) in seen
        ):
            _fail(
                "ROLLBACK_INSTALLER_RECEIPT_INVALID",
                "launcher paths не являются уникальными абсолютными путями",
            )
        seen.add((raw_path, raw_target))
        path = Path(raw_path)
        target = Path(raw_target)
        try:
            relative = target.relative_to(evidence.marketplace_link)
            info = path.lstat()
            observed_target = os.readlink(path)
            resolved_target = target.resolve(strict=True)
            current_target = (current / relative).resolve(strict=True)
            previous_target = (previous / relative).resolve(strict=True)
        except (OSError, ValueError) as error:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_LAUNCHER_BINDING_CHANGED",
                f"launcher binding недоступен: {path}",
            ) from error
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or observed_target != raw_target
            or resolved_target not in (current_target, previous_target)
            or not previous_target.is_file()
            or previous_target.is_symlink()
        ):
            _fail(
                "ROLLBACK_LAUNCHER_BINDING_CHANGED",
                f"launcher не совпадает с installer receipt: {path}",
            )
        result.append(
            RollbackLauncherBindingV2(
                path=path,
                target=target,
                relative_marketplace_target=relative,
            )
        )
    return RollbackExternalArtifactsV2(
        installer_receipt_path=installer_receipt_path,
        installer_receipt=receipt,
        installer_receipt_file=_file_projection(installer_receipt_path),
        current_registered_marketplace=current,
        previous_registered_marketplace=previous,
        launchers=tuple(result),
    )


def build_rollback_registry_binding_v2(*, plan: Any) -> RollbackStepBindingV2:
    """Свернуть два restart-safe registry-порта в один rollback-шаг."""

    from .installer_update_composition_v2 import (
        RegistryUpdatePlanV2,
        build_registry_step_definitions_v2,
        build_registry_step_ports_v2,
    )

    if not isinstance(plan, RegistryUpdatePlanV2) or plan.before_registry is None:
        raise TypeError("plan must be a complete RegistryUpdatePlanV2")
    inner_definitions = build_registry_step_definitions_v2(plan)
    inner_ports = build_registry_step_ports_v2(plan=plan, definitions=inner_definitions)
    marketplace_definition = inner_definitions["marketplace_registry"]
    plugin_definition = inner_definitions["plugin_registry"]
    marketplace_port = inner_ports["marketplace_registry"]
    plugin_port = inner_ports["plugin_registry"]
    command_id = (
        "ec2_"
        + domain_fingerprint(
            "codex-smart/rollback-registry-command-id/v2",
            {"operationId": plan.operation_id},
        )[:32]
    )
    definition = StepDefinitionV2(
        kind="registry_restore",
        command_id=command_id,
        action={
            "actionKind": "external-command",
            "commandRole": "codex-registry",
            "method": "registry-restore",
            "externalCommandId": command_id,
            "argvFingerprint": domain_fingerprint(
                "codex-smart/rollback-registry-argv/v2",
                {
                    "marketplaceCommands": [
                        list(argv) for argv in plan.marketplace_commands
                    ],
                    "pluginCommands": [list(argv) for argv in plan.plugin_commands],
                },
            ),
            "timeoutMs": plan.timeout_ms,
        },
        before=plan.before_registry,
        expected_after=plan.plugin_constraint,
    )

    def validate(received: StepDefinitionV2) -> None:
        if received != definition:
            _fail(
                "ROLLBACK_REGISTRY_DEFINITION_CHANGED",
                "исполнитель получил другое registry_restore",
            )

    def observe(received: StepDefinitionV2) -> ProjectionV2:
        validate(received)
        observed = marketplace_port.observe(marketplace_definition)
        if observed == definition.before:
            return observed
        if plugin_port.matches_after(observed, plugin_definition):
            return observed
        if not marketplace_port.matches_after(observed, marketplace_definition):
            _fail(
                "ROLLBACK_REGISTRY_STATE_AMBIGUOUS",
                "реестр не равен current, промежуточному или previous",
            )
        # INTENT уже долговечен: завершаем доказанный второй подшаг.
        plugin_port.apply(plugin_definition)
        observed = plugin_port.observe(plugin_definition)
        if not plugin_port.matches_after(observed, plugin_definition):
            _fail(
                "ROLLBACK_REGISTRY_APPLY_FAILED",
                "реестр не достиг previous plugin",
            )
        return observed

    def apply(received: StepDefinitionV2) -> None:
        validate(received)
        marketplace_port.apply(marketplace_definition)
        plugin_port.apply(plugin_definition)

    port = UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, _received: observed == definition.before,
        matches_after=lambda observed, _received: plugin_port.matches_after(
            observed, plugin_definition
        ),
        completed_current_matches=lambda persisted, current, _received: (
            plugin_port.completed_current_matches(persisted, current, plugin_definition)
        ),
    )
    return RollbackStepBindingV2(definition=definition, port=port)


def build_rollback_launcher_binding_v2(*, plan: Any) -> RollbackStepBindingV2:
    """Адаптировать production launcher-порт к повторному доказательству previous."""

    from .installer_update_composition_v2 import (
        LauncherUpdatePlanV2,
        build_launcher_step_definition_v2,
        build_launcher_step_port_v2,
    )

    if not isinstance(plan, LauncherUpdatePlanV2):
        raise TypeError("plan must be LauncherUpdatePlanV2")
    inner_definition = build_launcher_step_definition_v2(plan)
    inner_port = build_launcher_step_port_v2(plan=plan, definition=inner_definition)
    entries = plan.expected_after.value.get("launchers")
    if not isinstance(entries, list) or len(entries) != len(plan.bindings):
        _fail(
            "ROLLBACK_LAUNCHER_PLAN_INVALID",
            "expectedAfter не содержит точный launcher-set",
        )
    operations = []
    for binding, entry in zip(plan.bindings, entries, strict=True):
        fingerprint = domain_fingerprint("codex-smart/launcher-entry/v2", entry)
        operations.append(
            {
                "name": binding.name,
                "role": binding.role,
                "method": "write-replace",
                "targetPath": str(binding.path),
                "beforeFingerprint": fingerprint,
                "expectedAfterFingerprint": fingerprint,
            }
        )
    definition = StepDefinitionV2(
        kind="launchers_restore",
        command_id=None,
        action={
            "actionKind": "launcher-set-mutation",
            "mode": "RESTORE_PREVIOUS",
            "operations": operations,
            "durability": "FSYNC_EACH_FILE_AND_PARENT",
        },
        before=plan.expected_after,
        expected_after=plan.expected_after,
    )

    def validate(received: StepDefinitionV2) -> None:
        if received != definition:
            _fail(
                "ROLLBACK_LAUNCHER_DEFINITION_CHANGED",
                "исполнитель получил другое launchers_restore",
            )

    def observe(received: StepDefinitionV2) -> ProjectionV2:
        validate(received)
        observed = inner_port.observe(inner_definition)
        if observed != plan.expected_after:
            _fail(
                "ROLLBACK_LAUNCHER_STATE_AMBIGUOUS",
                "после link restore загрузчики не разрешаются в previous",
            )
        return observed

    def apply(received: StepDefinitionV2) -> None:
        validate(received)
        inner_port.apply(inner_definition)

    port = UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, _received: observed == plan.expected_after,
        matches_after=lambda observed, _received: observed == plan.expected_after,
        replay_safe_when_indistinguishable=lambda observed, _received: (
            observed == plan.expected_after
        ),
        completed_current_matches=lambda persisted, current, _received: (
            inner_port.completed_current_matches(persisted, current, inner_definition)
        ),
    )
    return RollbackStepBindingV2(definition=definition, port=port)


def build_rollback_shutdown_cleanup_binding_v2(
    *,
    plan: Any,
    shutdown_constraint: ProjectionV2,
    shutdown_proof_provider: Any,
    process_start_marker_provider: Any | None = None,
) -> RollbackStepBindingV2:
    """Собрать точный production-порт удаления доказанного orphan socket."""

    from .installer_update_composition_v2 import (
        build_shutdown_socket_cleanup_step_definition_v2,
        build_shutdown_socket_cleanup_step_port_v2,
    )

    definition = build_shutdown_socket_cleanup_step_definition_v2(
        plan=plan, shutdown_constraint=shutdown_constraint
    )
    kwargs = {
        "plan": plan,
        "definition": definition,
        "shutdown_proof_provider": shutdown_proof_provider,
    }
    if process_start_marker_provider is not None:
        kwargs["process_start_marker_provider"] = process_start_marker_provider
    port = build_shutdown_socket_cleanup_step_port_v2(**kwargs)
    return RollbackStepBindingV2(definition=definition, port=port)


def build_rollback_verify_candidate_binding_v2(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    acceptance_proof_provider: Any,
) -> RollbackStepBindingV2:
    """Повторно доказать previous activation, link и acceptance receipt."""

    from .activation_preparation_v2 import (
        capture_file_projection_v2,
        capture_tree_projection_v2,
    )

    _require_evidence(evidence)
    if operation_id != rollback_operation_id_v2(evidence):
        _fail(
            "ROLLBACK_OPERATION_ID_INVALID",
            "verify_candidate относится к другой операции",
        )
    if not callable(acceptance_proof_provider):
        raise TypeError("acceptance_proof_provider must be callable")
    activation = evidence.previous_activation_projection
    definition = StepDefinitionV2(
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

    def verify(received: StepDefinitionV2) -> ProjectionV2:
        if received != definition:
            _fail(
                "ROLLBACK_VERIFY_CANDIDATE_DEFINITION_CHANGED",
                "исполнитель получил другой verify_candidate",
            )
        directory = activation.value.get("directory")
        activation_file = activation.value.get("activationFile")
        if type(directory) is not dict or type(activation_file) is not dict:
            _fail(
                "ROLLBACK_PREVIOUS_ACTIVATION_INVALID",
                "previous activation не содержит физических проекций",
            )
        observed_tree = capture_tree_projection_v2(
            Path(str(directory["path"])),
            schema_sha256=activation.schema_sha256,
        )
        observed_file = capture_file_projection_v2(
            Path(str(activation_file["path"])),
            schema_sha256=activation.schema_sha256,
        )
        if (
            observed_tree.value != directory
            or observed_file.value != activation_file
            or os.readlink(evidence.marketplace_link)
            != evidence.previous_pointer.get("symlinkTarget")
            or evidence.marketplace_link.resolve(strict=True)
            != (
                evidence.activations_root
                / evidence.previous_activation_id
                / "marketplace"
            ).resolve(strict=True)
        ):
            _fail(
                "ROLLBACK_VERIFY_CANDIDATE_FAILED",
                "previous activation или активная ссылка изменились",
            )
        acceptance = acceptance_proof_provider()
        if (
            getattr(acceptance, "complete", False) is not True
            or getattr(acceptance, "operation_id", None) != operation_id
            or getattr(acceptance, "activation_id", None)
            != evidence.previous_activation_id
            or getattr(acceptance, "database_id", None)
            != evidence.previous_database_binding.value.get("databaseId")
            or getattr(acceptance, "activation_proof_fingerprint", None)
            != evidence.evidence_fingerprint
        ):
            _fail(
                "ROLLBACK_VERIFY_CANDIDATE_ACCEPTANCE_INVALID",
                "acceptance proof относится к другому previous candidate",
            )
        return activation

    port = UpdateStepPortV2(
        observe=verify,
        apply=lambda received: verify(received),
        matches_before=lambda observed, _received: observed == activation,
        matches_after=lambda observed, _received: observed == activation,
        replay_safe_when_indistinguishable=lambda observed, _received: (
            observed == activation
        ),
        completed_current_matches=lambda persisted, current, _received: (
            persisted == current == activation
        ),
    )
    return RollbackStepBindingV2(definition=definition, port=port)


def build_rollback_external_step_bindings_v2(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    controller_bindings: Mapping[str, RollbackStepBindingV2],
    shutdown_socket_cleanup: RollbackStepBindingV2,
    registry_restore: RollbackStepBindingV2,
    launchers_restore: RollbackStepBindingV2,
    controller_candidate_spawn: RollbackStepBindingV2,
    verify_candidate: RollbackStepBindingV2,
) -> RollbackExternalStepBindingsV2:
    """Собрать именованные production bindings и проверить общую цепь."""

    _require_evidence(evidence)
    if operation_id != rollback_operation_id_v2(evidence):
        _fail(
            "ROLLBACK_OPERATION_ID_INVALID",
            "external bindings относятся к другой операции",
        )
    expected_controller = {
        "maintenance_begin",
        "wait_runtime_quiescent",
        "maintenance_strengthen",
        "controller_shutdown",
        "controller_previous_accept",
        "maintenance_resume",
    }
    copied = dict(controller_bindings)
    if set(copied) != expected_controller:
        _fail(
            "ROLLBACK_CONTROLLER_BINDINGS_INVALID",
            "набор controller bindings не является точной rollback-цепью",
        )
    copied.update(
        {
            "shutdown_socket_cleanup": shutdown_socket_cleanup,
            "registry_restore": registry_restore,
            "launchers_restore": launchers_restore,
            "controller_candidate_spawn": controller_candidate_spawn,
            "verify_candidate": verify_candidate,
        }
    )
    result = RollbackExternalStepBindingsV2(copied)
    _verify_external_control_chain(
        evidence=evidence,
        operation_id=operation_id,
        bindings=result,
    )
    return result


def build_rollback_controller_bindings_v2(
    *,
    definitions: Mapping[str, StepDefinitionV2],
    ports: Mapping[str, UpdateStepPortV2],
) -> dict[str, RollbackStepBindingV2]:
    """Типизировать внешний rollback-controller слой без update-семантики."""

    expected = {
        "maintenance_begin",
        "wait_runtime_quiescent",
        "maintenance_strengthen",
        "controller_shutdown",
        "controller_previous_accept",
        "maintenance_resume",
    }
    copied_definitions = dict(definitions)
    copied_ports = dict(ports)
    if set(copied_definitions) != expected or set(copied_ports) != expected:
        _fail(
            "ROLLBACK_CONTROLLER_BINDINGS_INVALID",
            "controller definitions и ports должны содержать ровно шесть шагов",
        )
    result: dict[str, RollbackStepBindingV2] = {}
    for kind in expected:
        definition = copied_definitions[kind]
        port = copied_ports[kind]
        if not isinstance(definition, StepDefinitionV2) or definition.kind != kind:
            _fail(
                "ROLLBACK_CONTROLLER_BINDINGS_INVALID",
                f"определение {kind} имеет другой kind",
            )
        result[kind] = RollbackStepBindingV2(
            definition=definition,
            port=port,
        )
    return result


def build_rollback_candidate_spawn_binding_v2(
    *,
    definition: StepDefinitionV2,
    candidate_spawn_action: Mapping[str, Any] | Any,
    port: UpdateStepPortV2,
) -> RollbackStepBindingV2:
    """Связать внешний production spawn-порт с точным долговечным action."""

    action = (
        candidate_spawn_action.to_document()
        if callable(getattr(candidate_spawn_action, "to_document", None))
        else copy.deepcopy(dict(candidate_spawn_action))
    )
    if (
        not isinstance(definition, StepDefinitionV2)
        or definition.kind != "controller_candidate_spawn"
        or definition.command_id is not None
        or canonical_json_bytes(definition.action) != canonical_json_bytes(action)
        or definition.before.schema_id != "absence-proof-v2"
        or definition.expected_after.schema_id != "controller-candidate-v2"
        or definition.expected_after.value.get("status") != "EXPECTED_REGISTRATION"
    ):
        _fail(
            "ROLLBACK_CANDIDATE_BINDING_INVALID",
            "spawn binding не связан с точным action и expected candidate",
        )
    return RollbackStepBindingV2(definition=definition, port=port)


def build_rollback_composition_v2(
    *,
    evidence: RollbackEvidenceV2,
    execution_plan: Any,
    operation_id: str,
    journal_path: Path,
    prepared_manifest: PreparedManifestCommitV2,
    preparation_receipt: RollbackManifestPreparationReceiptV2,
    external_bindings: RollbackExternalStepBindingsV2,
    external_artifacts: RollbackExternalArtifactsV2,
) -> RollbackCompositionV2:
    """Собрать полное определение, порты и terminal callbacks отката."""

    _require_evidence(evidence)
    _identifier(operation_id, _OPERATION_ID, "ROLLBACK_OPERATION_ID_INVALID")
    if operation_id != rollback_operation_id_v2(evidence):
        _fail(
            "ROLLBACK_OPERATION_ID_INVALID",
            "operationId не связан с полным evidenceFingerprint",
        )
    if not isinstance(journal_path, Path) or not journal_path.is_absolute():
        raise TypeError("journal_path must be an absolute Path")
    if not isinstance(prepared_manifest, PreparedManifestCommitV2):
        raise TypeError("prepared_manifest must be PreparedManifestCommitV2")
    if not isinstance(
        preparation_receipt, RollbackManifestPreparationReceiptV2
    ):
        raise TypeError(
            "preparation_receipt must be RollbackManifestPreparationReceiptV2"
        )
    if (
        preparation_receipt.operation_id != operation_id
        or preparation_receipt.evidence_fingerprint != evidence.evidence_fingerprint
    ):
        _fail(
            "ROLLBACK_PREPARATION_RECEIPT_FINGERPRINT_INVALID",
            "prep-квитанция не связана с операцией отката",
        )
    if not isinstance(external_bindings, RollbackExternalStepBindingsV2):
        raise TypeError("external_bindings must be RollbackExternalStepBindingsV2")
    if not isinstance(external_artifacts, RollbackExternalArtifactsV2):
        raise TypeError("external_artifacts must be RollbackExternalArtifactsV2")
    _verify_external_artifacts(
        evidence=evidence,
        artifacts=external_artifacts,
        bindings=external_bindings,
    )
    _verify_external_control_chain(
        evidence=evidence,
        operation_id=operation_id,
        bindings=external_bindings,
    )
    if tuple(getattr(execution_plan, "composed_step_kinds", ())) != (
        ROLLBACK_MATCHED_ACTIVE_STEPS_V2
    ):
        _fail("ROLLBACK_PLAN_INVALID", "план не равен rollback-matched-active")
    if (
        getattr(execution_plan, "machine_id", None) != "rollback"
        or getattr(execution_plan, "selected_branch_id", None)
        != "rollback-matched-active"
    ):
        _fail("ROLLBACK_PLAN_INVALID", "выбрана другая ветвь автомата")
    _verify_prepared_manifest(
        evidence=evidence,
        operation_id=operation_id,
        prepared=prepared_manifest,
        allow_applied=False,
    )

    link_definition, link_port = _activation_link_restore_binding(
        evidence=evidence,
        operation_id=operation_id,
    )
    forward_definition = _forward_only_definition(
        journal_path=journal_path,
        operation_id=operation_id,
        plan_fingerprint=execution_plan.plan_definition_fingerprint,
    )
    manifest_definition, manifest_port = _manifest_restore_binding(
        evidence=evidence,
        operation_id=operation_id,
        prepared=prepared_manifest,
    )
    by_kind = {
        kind: external_bindings.require(kind).definition
        for kind in _EXTERNAL_STEP_KINDS
    }
    by_kind.update(
        {
            "activation_link_restore": link_definition,
            "recovery_forward_only": forward_definition,
            "manifest_restore": manifest_definition,
        }
    )
    mutable_steps = tuple(
        by_kind[kind] for kind in ROLLBACK_MATCHED_ACTIVE_STEPS_V2[1:15]
    )
    absence = _absence_projection(
        journal_path,
        installation_id=evidence.installation_id,
        operation_id=operation_id,
    )
    gate = StepDefinitionV2(
        kind="gate_close",
        command_id=None,
        action=_journal_action("gate-close", journal_path),
        before=absence,
        expected_after=_journal_projection(
            journal_path,
            operation_id=operation_id,
            plan_fingerprint=execution_plan.plan_definition_fingerprint,
            phase="DISCOVERED",
            recovery_policy="REVERSIBLE",
            generation=1,
            frozen=False,
        ),
    )
    freeze = StepDefinitionV2(
        kind="terminal_journal_freeze",
        command_id=None,
        action=_journal_action("freeze-delete-intent", journal_path),
        before=_journal_projection(
            journal_path,
            operation_id=operation_id,
            plan_fingerprint=execution_plan.plan_definition_fingerprint,
            phase="COMMITTING",
            recovery_policy="FORWARD_ONLY",
            generation=16,
            frozen=False,
        ),
        expected_after=_journal_projection(
            journal_path,
            operation_id=operation_id,
            plan_fingerprint=execution_plan.plan_definition_fingerprint,
            phase="TERMINAL_FROZEN",
            recovery_policy="FORWARD_ONLY",
            generation=17,
            frozen=True,
        ),
    )
    controller_identity = _previous_controller_identity(evidence)
    terminal = TerminalDefinitionV2(
        terminal_kind="COMMIT",
        receipt_kind="activation-commit",
        receipt_path=evidence.receipts_root / f"{operation_id}.commit.json",
        freeze=freeze,
        journal_absence_target=absence,
        receipt_payload=ActivationCommitPayloadIntentV2(
            manifest=prepared_manifest.expected_after,
            manifest_document=prepared_manifest.manifest_document,
            transition_lineage=ActivationTransitionLineageV2(
                transition_kind="rollback",
                source_receipt=TransitionSourceReceiptV2(
                    receipt_kind="rollback-manifest-preparation",
                    path=(
                        evidence.receipts_root
                        / f"{operation_id}.rollback-preparation.json"
                    ),
                    raw_sha256=hashlib.sha256(
                        canonical_json_bytes(preparation_receipt.to_document())
                    ).hexdigest(),
                    receipt_fingerprint=preparation_receipt.receipt_fingerprint,
                ),
                activation_proof_fingerprint=evidence.evidence_fingerprint,
                shutdown_command_ids=ControllerShutdownLineageV2(
                    maintenance_begin=str(by_kind["maintenance_begin"].command_id),
                    maintenance_strengthen=str(
                        by_kind["maintenance_strengthen"].command_id
                    ),
                    shutdown=str(by_kind["controller_shutdown"].command_id),
                ),
                stopped_controller=StoppedControllerLineageV2(
                    operation_id=operation_id,
                    activation_id=str(
                        by_kind["maintenance_begin"].before.value["activationId"]
                    ),
                    database_id=str(
                        by_kind["maintenance_begin"].before.value["databaseId"]
                    ),
                    controller_identity=str(
                        by_kind["maintenance_begin"].before.value[
                            "controllerIdentity"
                        ]
                    ),
                    control_epoch=int(
                        by_kind["controller_shutdown"].expected_after.value[
                            "newControlEpoch"
                        ]
                    ),
                ),
            ),
            activation=evidence.previous_activation_projection,
            database_binding=evidence.previous_database_binding,
            journal_absence_target=absence,
            controller_identity=controller_identity,
        ),
    )
    discovery = _bundle(
        activation=evidence.current_activation_projection,
        manifest=evidence.current_manifest_projection,
        database=None,
        registry=by_kind["registry_restore"].before,
        launchers=by_kind["launchers_restore"].before,
        controller=by_kind["maintenance_begin"].before,
    )
    desired = _bundle(
        activation=evidence.previous_activation_projection,
        manifest=prepared_manifest.expected_after,
        database=None,
        registry=by_kind["registry_restore"].expected_after,
        launchers=by_kind["launchers_restore"].expected_after,
        controller=by_kind["maintenance_resume"].expected_after,
    )
    definition = OperationDefinitionV2(
        kind="rollback",
        installation_id=evidence.installation_id,
        operation_id=operation_id,
        operation="rollback",
        execution_plan=execution_plan,
        discovery_before=discovery,
        fenced_before=discovery,
        desired=desired,
        gate_close=gate,
        mutable_steps=mutable_steps,
        terminal=terminal,
    )
    ports = {
        kind: external_bindings.require(kind).port for kind in _EXTERNAL_STEP_KINDS
    }
    ports.update(
        {
            "activation_link_restore": link_port,
            "manifest_restore": manifest_port,
        }
    )

    def port_for(definition: StepDefinitionV2) -> UpdateStepPortV2:
        try:
            return ports[definition.kind]
        except KeyError as error:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_STEP_PORT_MISSING",
                f"нет порта шага {definition.kind}",
            ) from error

    callbacks = StepCallbacksV2(
        observe=lambda step: port_for(step).observe(step),
        apply=lambda step: port_for(step).apply(step),
        matches_before=lambda observed, step: port_for(step).matches_before(
            observed, step
        ),
        matches_after=lambda observed, step: port_for(step).matches_after(
            observed, step
        ),
        matches_intent_resume=lambda observed, step: port_for(
            step
        ).matches_intent_resume(observed, step),
        replay_safe_when_indistinguishable=lambda observed, step: port_for(
            step
        ).replay_safe_when_indistinguishable(observed, step),
        completed_current_matches=lambda persisted, current, step: port_for(
            step
        ).completed_current_matches(persisted, current, step),
    )
    receipt_store = ActivationCommitReceiptStoreV2(definition=definition)
    return RollbackCompositionV2(
        definition=definition,
        callbacks=callbacks,
        terminal_callbacks=receipt_store.callbacks(),
        prepared_manifest=prepared_manifest,
        preparation_receipt_fingerprint=preparation_receipt.receipt_fingerprint,
    )


def build_rollback_composition_from_preparation_receipt_v2(
    *,
    evidence: RollbackEvidenceV2,
    execution_plan: Any,
    journal_path: Path,
    preparation_receipt: (
        RollbackManifestPreparationReceiptV2 | Mapping[str, Any] | Path
    ),
    external_bindings: RollbackExternalStepBindingsV2,
    external_artifacts: RollbackExternalArtifactsV2,
) -> RollbackCompositionV2:
    """Собрать свежую операцию только через проверенную prep-квитанцию."""

    receipt = _rollback_preparation_receipt(preparation_receipt)
    prepared = prepared_rollback_manifest_from_receipt_v2(receipt, evidence)
    return build_rollback_composition_v2(
        evidence=evidence,
        execution_plan=execution_plan,
        operation_id=receipt.operation_id,
        journal_path=journal_path,
        prepared_manifest=prepared,
        preparation_receipt=receipt,
        external_bindings=external_bindings,
        external_artifacts=external_artifacts,
    )


def build_rollback_recovery_composition_v2(
    *,
    evidence: RollbackEvidenceV2,
    definition: OperationDefinitionV2,
    prepared_manifest: PreparedManifestCommitV2,
    preparation_receipt_fingerprint: str,
    external_bindings: RollbackExternalStepBindingsV2,
    external_artifacts: RollbackExternalArtifactsV2,
) -> RollbackCompositionV2:
    """Восстановить порты только из сохранённого определения main journal.

    Функция не переснимает ``before``. Ссылка и manifest-переход принимают
    только проекции, уже записанные в ``definition``; внешние определения
    обязаны побайтно совпасть с теми же сохранёнными шагами.
    """

    _require_evidence(evidence)
    if not isinstance(definition, OperationDefinitionV2):
        raise TypeError("definition must be OperationDefinitionV2")
    if not isinstance(prepared_manifest, PreparedManifestCommitV2):
        raise TypeError("prepared_manifest must be PreparedManifestCommitV2")
    _identifier(
        preparation_receipt_fingerprint,
        _SHA256,
        "ROLLBACK_PREPARATION_RECEIPT_FINGERPRINT_INVALID",
    )
    if not isinstance(external_bindings, RollbackExternalStepBindingsV2):
        raise TypeError("external_bindings must be RollbackExternalStepBindingsV2")
    if not isinstance(external_artifacts, RollbackExternalArtifactsV2):
        raise TypeError("external_artifacts must be RollbackExternalArtifactsV2")
    _verify_external_artifacts(
        evidence=evidence,
        artifacts=external_artifacts,
        bindings=external_bindings,
    )
    _verify_external_control_chain(
        evidence=evidence,
        operation_id=definition.operation_id,
        bindings=external_bindings,
    )
    if (
        definition.kind != "rollback"
        or definition.operation != "rollback"
        or definition.installation_id != evidence.installation_id
        or definition.operation_id != prepared_manifest.operation_id
        or definition.execution_plan.machine_id != "rollback"
        or definition.execution_plan.selected_branch_id != "rollback-matched-active"
        or definition.execution_plan.composed_step_kinds
        != ROLLBACK_MATCHED_ACTIVE_STEPS_V2
    ):
        _fail(
            "ROLLBACK_RECOVERY_DEFINITION_INVALID",
            "сохранённое определение не является точным rollback",
        )
    by_kind = {step.kind: step for step in definition.mutable_steps}
    if (
        tuple(step.kind for step in definition.mutable_steps)
        != (ROLLBACK_MATCHED_ACTIVE_STEPS_V2[1:15])
    ):
        _fail(
            "ROLLBACK_RECOVERY_DEFINITION_INVALID",
            "порядок изменяемых шагов отличается от автомата",
        )
    for kind in _EXTERNAL_STEP_KINDS:
        if external_bindings.require(kind).definition != by_kind[kind]:
            _fail(
                "ROLLBACK_RECOVERY_BINDING_CHANGED",
                f"внешнее определение {kind} отличается от журнала",
            )
    terminal = definition.terminal
    if (
        terminal is None
        or terminal.terminal_kind != "COMMIT"
        or terminal.receipt_path
        != evidence.receipts_root / f"{definition.operation_id}.commit.json"
        or not isinstance(terminal.receipt_payload, ActivationCommitPayloadIntentV2)
        or terminal.receipt_payload.manifest != prepared_manifest.expected_after
        or terminal.receipt_payload.activation
        != evidence.previous_activation_projection
        or terminal.receipt_payload.database_binding
        != evidence.previous_database_binding
        or terminal.receipt_payload.controller_identity
        != _previous_controller_identity(evidence)
    ):
        _fail(
            "ROLLBACK_RECOVERY_TERMINAL_INVALID",
            "terminal snapshot не связан с previous receipt",
        )
    _verify_prepared_manifest(
        evidence=evidence,
        operation_id=definition.operation_id,
        prepared=prepared_manifest,
        allow_applied=True,
    )
    link_port = _activation_link_restore_port(
        evidence=evidence,
        operation_id=definition.operation_id,
        definition=by_kind["activation_link_restore"],
    )
    manifest_port = _manifest_restore_port(
        evidence=evidence,
        operation_id=definition.operation_id,
        prepared=prepared_manifest,
        definition=by_kind["manifest_restore"],
    )
    ports = {
        kind: external_bindings.require(kind).port for kind in _EXTERNAL_STEP_KINDS
    }
    ports.update(
        {
            "activation_link_restore": link_port,
            "manifest_restore": manifest_port,
        }
    )
    callbacks = _callbacks_from_ports(ports)
    receipt_store = ActivationCommitReceiptStoreV2(definition=definition)
    return RollbackCompositionV2(
        definition=definition,
        callbacks=callbacks,
        terminal_callbacks=receipt_store.callbacks(),
        prepared_manifest=prepared_manifest,
        preparation_receipt_fingerprint=preparation_receipt_fingerprint,
    )


def build_rollback_recovery_composition_from_receipt_v2(
    *,
    evidence: RollbackEvidenceV2,
    definition: OperationDefinitionV2,
    preparation_receipt: (
        RollbackManifestPreparationReceiptV2 | Mapping[str, Any] | Path
    ),
    external_bindings: RollbackExternalStepBindingsV2,
    external_artifacts: RollbackExternalArtifactsV2,
) -> RollbackCompositionV2:
    """Восстановить main-порты с повторной проверкой receipt → prepared."""

    receipt = _rollback_preparation_receipt(preparation_receipt)
    prepared = prepared_rollback_manifest_from_receipt_v2(receipt, evidence)
    return build_rollback_recovery_composition_v2(
        evidence=evidence,
        definition=definition,
        prepared_manifest=prepared,
        preparation_receipt_fingerprint=receipt.receipt_fingerprint,
        external_bindings=external_bindings,
        external_artifacts=external_artifacts,
    )


def _callbacks_from_ports(
    ports: Mapping[str, UpdateStepPortV2],
) -> StepCallbacksV2:
    copied = dict(ports)

    def port_for(definition: StepDefinitionV2) -> UpdateStepPortV2:
        try:
            return copied[definition.kind]
        except KeyError as error:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_STEP_PORT_MISSING",
                f"нет порта шага {definition.kind}",
            ) from error

    return StepCallbacksV2(
        observe=lambda step: port_for(step).observe(step),
        apply=lambda step: port_for(step).apply(step),
        matches_before=lambda observed, step: port_for(step).matches_before(
            observed, step
        ),
        matches_after=lambda observed, step: port_for(step).matches_after(
            observed, step
        ),
        matches_intent_resume=lambda observed, step: port_for(
            step
        ).matches_intent_resume(observed, step),
        replay_safe_when_indistinguishable=lambda observed, step: port_for(
            step
        ).replay_safe_when_indistinguishable(observed, step),
        completed_current_matches=lambda persisted, current, step: port_for(
            step
        ).completed_current_matches(persisted, current, step),
    )


def _verify_external_control_chain(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    bindings: RollbackExternalStepBindingsV2,
) -> None:
    definitions = {
        kind: bindings.require(kind).definition for kind in _EXTERNAL_STEP_KINDS
    }
    begin = definitions["maintenance_begin"]
    wait = definitions["wait_runtime_quiescent"]
    strengthen = definitions["maintenance_strengthen"]
    shutdown = definitions["controller_shutdown"]
    cleanup = definitions["shutdown_socket_cleanup"]
    spawn = definitions["controller_candidate_spawn"]
    accept = definitions["controller_previous_accept"]
    verify = definitions["verify_candidate"]
    resume = definitions["maintenance_resume"]
    controller_steps = (begin, strengthen, shutdown, accept, resume)
    command_ids = [step.command_id for step in controller_steps]
    current_database_id = evidence.current_activation_projection.value.get("databaseId")
    previous_database_id = evidence.previous_database_binding.value.get("databaseId")
    if (
        any(step.action.get("operationId") != operation_id for step in controller_steps)
        or any(type(value) is not str for value in command_ids)
        or len(set(command_ids)) != len(command_ids)
        or begin.before.schema_id != "controller-state-v2"
        or begin.before.value.get("activationId") != evidence.current_activation_id
        or begin.before.value.get("databaseId") != current_database_id
        or wait.before != begin.expected_after
        or wait.action.get("predicate") != "runtime-quiescent"
        or strengthen.before.schema_id != "controller-state-v2"
        or strengthen.before.value.get("activationId") != evidence.current_activation_id
        or strengthen.before.value.get("databaseId") != current_database_id
        or shutdown.before != strengthen.expected_after
        or cleanup.before != shutdown.expected_after
        or cleanup.action.get("proofSource") != "CONTROLLER_SHUTDOWN_INTENT"
        or cleanup.action.get("proofSourceId") != shutdown.command_id
        or spawn.action.get("operationId") != operation_id
        or spawn.action.get("activationId") != evidence.previous_activation_id
        or spawn.action.get("databaseId") != previous_database_id
        or spawn.expected_after.schema_id != "controller-candidate-v2"
        or spawn.expected_after.value.get("status") != "EXPECTED_REGISTRATION"
        or accept.before.schema_id != "controller-candidate-v2"
        or accept.before.value.get("status") != "EXPECTED_REGISTRATION"
        or accept.expected_after.schema_id != "controller-state-v2"
        or accept.expected_after.value.get("activationId")
        != evidence.previous_activation_id
        or accept.expected_after.value.get("databaseId") != previous_database_id
        or verify.before != evidence.previous_activation_projection
        or verify.expected_after != evidence.previous_activation_projection
        or resume.before != accept.expected_after
        or resume.expected_after.value.get("activationId")
        != evidence.previous_activation_id
        or resume.expected_after.value.get("databaseId") != previous_database_id
    ):
        _fail(
            "ROLLBACK_EXTERNAL_CONTROL_CHAIN_INVALID",
            "controller, candidate, cleanup или verify не образуют rollback-цепь",
        )
    dynamic_candidate = {
        "privateReadyChannel",
        "pid",
        "processStartMarker",
        "processGroupId",
        "registrationFingerprint",
        "databaseLeaseProofFingerprint",
        "databaseOpened",
        "status",
    }
    expected_candidate = spawn.expected_after.value
    registered_candidate = accept.before.value
    for name, value in expected_candidate.items():
        if name in dynamic_candidate:
            continue
        if registered_candidate.get(name) != value:
            _fail(
                "ROLLBACK_EXTERNAL_CONTROL_CHAIN_INVALID",
                f"previous candidate расходится по {name}",
            )
        if name in spawn.action and spawn.action.get(name) != value:
            _fail(
                "ROLLBACK_EXTERNAL_CONTROL_CHAIN_INVALID",
                f"spawn action расходится по {name}",
            )


def _verify_external_artifacts(
    *,
    evidence: RollbackEvidenceV2,
    artifacts: RollbackExternalArtifactsV2,
    bindings: RollbackExternalStepBindingsV2,
) -> None:
    observed = read_rollback_external_artifacts_v2(
        evidence=evidence,
        installer_receipt_path=artifacts.installer_receipt_path,
    )
    if observed != artifacts:
        _fail(
            "ROLLBACK_EXTERNAL_ARTIFACTS_CHANGED",
            "installer receipt, canonical marketplace или launchers изменились",
        )
    registry = bindings.require("registry_restore").definition
    if (
        registry.command_id is None
        or registry.command_id != registry.action.get("externalCommandId")
        or registry.action.get("actionKind") != "external-command"
        or registry.action.get("commandRole") != "codex-registry"
        or registry.action.get("method") != "registry-restore"
        or registry.before.schema_id != "registry-state-v2"
        or registry.expected_after.schema_id != "registry-state-v2"
        or registry.before.value.get("status") != "PLUGIN_ENABLED"
        or registry.expected_after.value.get("status")
        not in {"PLUGIN_ENABLED", "EXPECTED_PLUGIN_ENABLED"}
        or registry.before.value.get("marketplaceName")
        != artifacts.installer_receipt["marketplaceName"]
        or registry.expected_after.value.get("marketplaceName")
        != artifacts.installer_receipt["marketplaceName"]
        or registry.before.value.get("pluginId")
        != artifacts.installer_receipt["pluginId"]
        or registry.expected_after.value.get("pluginId")
        != artifacts.installer_receipt["pluginId"]
        or registry.before.value.get("marketplacePath")
        != str(artifacts.current_registered_marketplace)
        or registry.expected_after.value.get("marketplacePath")
        != str(artifacts.previous_registered_marketplace)
    ):
        _fail(
            "ROLLBACK_REGISTRY_BINDING_INVALID",
            "registry_restore не переводит current canonical в previous canonical",
        )
    launchers = bindings.require("launchers_restore").definition
    launcher_entries = launchers.before.value.get("launchers")
    expected_entries: list[dict[str, Any]] = []
    expected_operations: list[dict[str, Any]] = []
    if isinstance(launcher_entries, list) and len(launcher_entries) == len(
        artifacts.launchers
    ):
        for artifact, entry in zip(artifacts.launchers, launcher_entries, strict=True):
            if not isinstance(entry, Mapping):
                break
            role = entry.get("role")
            if role not in {
                "gateway",
                "admin",
                "highfd",
                "hook",
                "tool-server",
                "controller",
            }:
                break
            expected_entry = {
                "name": artifact.path.name,
                "role": role,
                "file": _launcher_file_value(
                    artifact.path,
                    artifacts.previous_registered_marketplace
                    / artifact.relative_marketplace_target,
                ),
            }
            expected_entries.append(expected_entry)
            fingerprint = domain_fingerprint(
                "codex-smart/launcher-entry/v2", expected_entry
            )
            expected_operations.append(
                {
                    "name": artifact.path.name,
                    "role": role,
                    "method": "write-replace",
                    "targetPath": str(artifact.path),
                    "beforeFingerprint": fingerprint,
                    "expectedAfterFingerprint": fingerprint,
                }
            )
    expected_launcher_value: dict[str, Any] = {"launchers": expected_entries}
    expected_launcher_value["setFingerprint"] = domain_fingerprint(
        "codex-smart/launcher-set/v2", expected_launcher_value
    )
    expected_launcher_projection = _projection(
        "launcher-set-v2",
        expected_launcher_value,
        "codex-smart/launcher-set-projection/v2",
    )
    if (
        launchers.command_id is not None
        or launchers.before != expected_launcher_projection
        or launchers.expected_after != launchers.before
        or launchers.action
        != {
            "actionKind": "launcher-set-mutation",
            "mode": "RESTORE_PREVIOUS",
            "operations": expected_operations,
            "durability": "FSYNC_EACH_FILE_AND_PARENT",
        }
    ):
        _fail(
            "ROLLBACK_LAUNCHER_BINDING_INVALID",
            "launchers_restore не доказывает стабильные receipt links",
        )


def _activation_link_restore_binding(
    *, evidence: RollbackEvidenceV2, operation_id: str
) -> tuple[StepDefinitionV2, UpdateStepPortV2]:
    before = _observe_symlink(evidence.marketplace_link)
    if before.value.get("target") != evidence.current_pointer.get("symlinkTarget"):
        _fail("ROLLBACK_ACTIVE_LINK_CHANGED", "рабочая ссылка уже не является current")
    target = str(evidence.previous_pointer["symlinkTarget"])
    expected_value = copy.deepcopy(dict(before.value))
    expected_value["target"] = target
    expected_value["targetFingerprint"] = hashlib.sha256(
        target.encode("utf-8")
    ).hexdigest()
    expected = _projection(
        "symlink-object-v2", expected_value, "codex-smart/symlink-object/v2"
    )
    definition = StepDefinitionV2(
        kind="activation_link_restore",
        command_id=None,
        action={
            "actionKind": "symlink-mutation",
            "method": "restore",
            "path": str(evidence.marketplace_link),
            "target": target,
            "durability": "FSYNC_PARENT",
        },
        before=before,
        expected_after=expected,
    )

    return definition, _activation_link_restore_port(
        evidence=evidence,
        operation_id=operation_id,
        definition=definition,
    )


def _activation_link_restore_port(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    definition: StepDefinitionV2,
) -> UpdateStepPortV2:
    if (
        definition.kind != "activation_link_restore"
        or definition.command_id is not None
        or definition.action
        != {
            "actionKind": "symlink-mutation",
            "method": "restore",
            "path": str(evidence.marketplace_link),
            "target": str(evidence.previous_pointer["symlinkTarget"]),
            "durability": "FSYNC_PARENT",
        }
        or definition.before.schema_id != "symlink-object-v2"
        or definition.expected_after.schema_id != "symlink-object-v2"
        or definition.before.value.get("path") != str(evidence.marketplace_link)
        or definition.before.value.get("target")
        != evidence.current_pointer.get("symlinkTarget")
        or definition.expected_after.value.get("path") != str(evidence.marketplace_link)
        or definition.expected_after.value.get("target")
        != evidence.previous_pointer.get("symlinkTarget")
    ):
        _fail(
            "ROLLBACK_LINK_DEFINITION_INVALID",
            "определение ссылки не связано с current/previous pointers",
        )
    before = definition.before
    expected = definition.expected_after
    target = str(evidence.previous_pointer["symlinkTarget"])

    def validate(received: StepDefinitionV2) -> None:
        if received != definition:
            _fail("ROLLBACK_LINK_DEFINITION_CHANGED", "определение ссылки изменено")

    def observe(received: StepDefinitionV2) -> ProjectionV2:
        validate(received)
        observed = _observe_symlink(evidence.marketplace_link)
        if observed != before and observed != expected:
            _fail("ROLLBACK_LINK_AMBIGUOUS", "ссылка не равна before/after")
        return observed

    def apply(received: StepDefinitionV2) -> None:
        validate(received)
        observed = observe(received)
        if observed == expected:
            return
        _atomic_replace_symlink(
            evidence.marketplace_link,
            target=target,
            operation_id=operation_id,
        )
        if observe(received) != expected:
            _fail("ROLLBACK_LINK_APPLY_FAILED", "ссылка не стала previous")

    return UpdateStepPortV2(observe=observe, apply=apply)


def _manifest_restore_binding(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    prepared: PreparedManifestCommitV2,
) -> tuple[StepDefinitionV2, UpdateStepPortV2]:
    definition = StepDefinitionV2(
        kind="manifest_restore",
        command_id=None,
        action={
            "actionKind": "file-mutation",
            "method": "atomic-prepared-manifest-replace",
            "sourcePath": str(prepared.prepared_path),
            "targetPath": str(evidence.manifest_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        },
        before=evidence.current_manifest_projection,
        expected_after=prepared.expected_after,
    )

    return definition, _manifest_restore_port(
        evidence=evidence,
        operation_id=operation_id,
        prepared=prepared,
        definition=definition,
    )


def _manifest_restore_port(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    prepared: PreparedManifestCommitV2,
    definition: StepDefinitionV2,
) -> UpdateStepPortV2:
    if (
        definition.kind != "manifest_restore"
        or definition.command_id is not None
        or definition.action
        != {
            "actionKind": "file-mutation",
            "method": "atomic-prepared-manifest-replace",
            "sourcePath": str(prepared.prepared_path),
            "targetPath": str(evidence.manifest_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        }
        or definition.before != evidence.current_manifest_projection
        or definition.expected_after != prepared.expected_after
    ):
        _fail(
            "ROLLBACK_MANIFEST_DEFINITION_INVALID",
            "manifest_restore не связан с current и prepared previous",
        )

    def validate(received: StepDefinitionV2) -> None:
        if received != definition:
            _fail(
                "ROLLBACK_MANIFEST_DEFINITION_CHANGED",
                "определение manifest_restore изменено",
            )

    def observe(received: StepDefinitionV2) -> ProjectionV2:
        validate(received)
        observed_raw, observed_document = _read_private_canonical_json(
            evidence.manifest_path
        )
        observed = _manifest_projection(evidence.manifest_path, observed_document)
        if observed == definition.before:
            _verify_prepared_manifest(
                evidence=evidence,
                operation_id=operation_id,
                prepared=prepared,
                allow_applied=False,
            )
            return observed
        if (
            observed == definition.expected_after
            and observed_raw == prepared.prepared_raw
        ):
            if _lexists(prepared.prepared_path):
                _fail(
                    "ROLLBACK_MANIFEST_TRANSITION_AMBIGUOUS",
                    "target уже after, но prepared source ещё существует",
                )
            return observed
        _fail(
            "ROLLBACK_MANIFEST_TRANSITION_AMBIGUOUS",
            "manifest не равен before/after",
        )

    def apply(received: StepDefinitionV2) -> None:
        validate(received)
        observed = observe(received)
        if observed == definition.expected_after:
            return
        os.replace(prepared.prepared_path, evidence.manifest_path)
        _fsync_directory(evidence.manifest_path.parent)
        if observe(received) != definition.expected_after:
            _fail("ROLLBACK_MANIFEST_APPLY_FAILED", "manifest не стал previous")

    return UpdateStepPortV2(observe=observe, apply=apply)


def _forward_only_definition(
    *, journal_path: Path, operation_id: str, plan_fingerprint: str
) -> StepDefinitionV2:
    return StepDefinitionV2(
        kind="recovery_forward_only",
        command_id=None,
        action=_journal_action("forward-only", journal_path),
        before=_journal_projection(
            journal_path,
            operation_id=operation_id,
            plan_fingerprint=plan_fingerprint,
            phase="APPLYING",
            recovery_policy="REVERSIBLE",
            generation=8,
            frozen=False,
        ),
        expected_after=_journal_projection(
            journal_path,
            operation_id=operation_id,
            plan_fingerprint=plan_fingerprint,
            phase="APPLYING",
            recovery_policy="FORWARD_ONLY",
            generation=9,
            frozen=False,
        ),
    )


def _verify_prepared_manifest(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    prepared: PreparedManifestCommitV2,
    allow_applied: bool,
) -> None:
    previous_tree = evidence.previous_activation_projection.value.get("directory")
    previous_tree_sha256 = (
        previous_tree.get("treeSha256") if type(previous_tree) is dict else None
    )
    manifest = dict(prepared.manifest_document)
    target_file = copy.deepcopy(dict(prepared.prepared_file_projection))
    target_file["path"] = str(evidence.manifest_path)
    if (
        not prepared.complete
        or prepared.operation_id != operation_id
        or operation_id != rollback_operation_id_v2(evidence)
        or prepared.activation_proof_fingerprint != evidence.evidence_fingerprint
        or prepared.activation_id != evidence.previous_activation_id
        or prepared.activation_tree_sha256 != previous_tree_sha256
        or prepared.target_path != evidence.manifest_path
        or prepared.prepared_file.value != dict(prepared.prepared_file_projection)
        or prepared.prepared_file.value.get("path") != str(prepared.prepared_path)
        or prepared.prepared_file.value.get("mode") != "0600"
        or prepared.prepared_file.value.get("linkCount") != 1
        or prepared.prepared_raw != canonical_json_bytes(manifest)
        or manifest.get("schemaVersion") != 2
        or manifest.get("installationId") != evidence.installation_id
        or manifest.get("activeActivation") != dict(evidence.previous_pointer)
        or manifest.get("previousActivation") != dict(evidence.current_pointer)
        or manifest.get("lastCommittedOperation") != operation_id
        or prepared.expected_after
        != _manifest_projection(
            evidence.manifest_path,
            manifest,
            file_projection=target_file,
        )
    ):
        _fail(
            "ROLLBACK_PREPARED_MANIFEST_INVALID",
            "подготовка не связана с evidence и operationId",
        )
    if _lexists(prepared.prepared_path):
        parent = _private_directory(prepared.prepared_path.parent)
        raw, document = _read_private_canonical_json(prepared.prepared_path)
        target_raw, target_document = _read_private_canonical_json(
            evidence.manifest_path
        )
        if (
            parent.st_dev != prepared.prepared_parent_device
            or parent.st_ino != prepared.prepared_parent_inode
            or raw != prepared.prepared_raw
            or document != manifest
            or _file_projection(prepared.prepared_path) != prepared.prepared_file
            or target_raw != canonical_json_bytes(evidence.manifest_document)
            or target_document != dict(evidence.manifest_document)
            or _manifest_projection(evidence.manifest_path, target_document)
            != evidence.current_manifest_projection
        ):
            _fail("ROLLBACK_PREPARED_MANIFEST_CHANGED", "prepared source изменён")
        return
    if not allow_applied:
        _fail("ROLLBACK_PREPARED_MANIFEST_MISSING", "prepared source отсутствует")
    raw, document = _read_private_canonical_json(evidence.manifest_path)
    if (
        raw != prepared.prepared_raw
        or document != dict(prepared.manifest_document)
        or _manifest_projection(evidence.manifest_path, document)
        != prepared.expected_after
    ):
        _fail(
            "ROLLBACK_PREPARED_MANIFEST_MISSING",
            "prepared source отсутствует без точного applied target",
        )


def _bundle(
    *,
    activation: ProjectionV2,
    manifest: ProjectionV2,
    database: ProjectionV2 | None,
    registry: ProjectionV2,
    launchers: ProjectionV2,
    controller: ProjectionV2,
) -> StateBundleV2:
    return StateBundleV2(
        file_objects=(),
        tree_objects=(),
        symlinks=(),
        manifest=manifest,
        activation=activation,
        database=database,
        controller=controller,
        controller_candidates=(),
        watchdogs=(),
        registry=registry,
        launchers=launchers,
        legacy_processes=None,
        quiescence=None,
        external_commands=(),
        receipts=(),
        absence_proofs=(),
    )


def _previous_controller_identity(evidence: RollbackEvidenceV2) -> str:
    value = evidence.previous_receipt.get("controllerIdentity")
    return _identifier(value, _SHA256, "ROLLBACK_CONTROLLER_IDENTITY_INVALID")


def _observe_symlink(path: Path) -> ProjectionV2:
    try:
        parent = path.parent.lstat()
        info = path.lstat()
        target = os.readlink(path)
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_LINK_AMBIGUOUS", str(error)
        ) from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.getuid()
        or not stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
    ):
        _fail("ROLLBACK_LINK_AMBIGUOUS", "ссылка или parent небезопасны")
    return _projection(
        "symlink-object-v2",
        {
            "path": str(path),
            "parentDevice": parent.st_dev,
            "parentInode": parent.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
            "target": target,
            "targetFingerprint": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        },
        "codex-smart/symlink-object/v2",
    )


def _atomic_replace_symlink(path: Path, *, target: str, operation_id: str) -> None:
    temporary = path.parent / f".{path.name}.{operation_id}.next"
    if _lexists(temporary):
        try:
            info = temporary.lstat()
            observed_target = os.readlink(temporary)
        except OSError as error:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_LINK_TEMP_CONFLICT", str(error)
            ) from error
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or observed_target != target
        ):
            _fail("ROLLBACK_LINK_TEMP_CONFLICT", "temporary link занят")
        temporary.unlink()
    try:
        os.symlink(target, temporary)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            if _lexists(temporary):
                temporary.unlink()
        except OSError:
            pass
        raise


def _manifest_projection(
    path: Path,
    manifest: Mapping[str, Any],
    *,
    file_projection: Mapping[str, Any] | None = None,
) -> ProjectionV2:
    try:
        active = manifest["activeActivation"]
        previous = manifest.get("previousActivation")
        value = {
            "file": (
                copy.deepcopy(dict(file_projection))
                if file_projection is not None
                else copy.deepcopy(dict(_file_projection(path).value))
            ),
            "schemaVersion": 2,
            "installationId": manifest["installationId"],
            "release": manifest["release"],
            "pluginId": manifest["pluginId"],
            "stateHome": manifest["stateHome"],
            "activeActivationId": active["activationId"],
            "previousActivationId": (
                None if previous is None else previous["activationId"]
            ),
            "lastCommittedOperation": manifest["lastCommittedOperation"],
            "sourceLocatorFingerprint": hashlib.sha256(
                canonical_json_bytes(manifest["sourceLocator"])
            ).hexdigest(),
            "artifactsFingerprint": hashlib.sha256(
                canonical_json_bytes(manifest["artifacts"])
            ).hexdigest(),
            "semanticFingerprint": domain_fingerprint(
                "codex-smart/manifest-semantic/v2",
                {
                    key: copy.deepcopy(item)
                    for key, item in manifest.items()
                    if key != "extensions"
                },
            ),
        }
    except (KeyError, TypeError) as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_MANIFEST_INVALID", "manifest не имеет нормативной формы"
        ) from error
    return _projection("manifest-v2", value, "codex-smart/journal-state/v2")


def _file_projection(path: Path) -> ProjectionV2:
    try:
        info = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_FILE_INVALID", str(error)
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or len(payload) != info.st_size
    ):
        _fail("ROLLBACK_FILE_INVALID", f"небезопасный файл: {path}")
    return _projection(
        "file-object-v2",
        {
            "path": str(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "ownerUid": info.st_uid,
            "ownerGid": info.st_gid,
            "mode": "0600",
            "linkCount": info.st_nlink,
            "size": info.st_size,
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
        "codex-smart/file-object/v2",
    )


def _launcher_file_value(logical_path: Path, physical_path: Path) -> dict[str, Any]:
    try:
        info = physical_path.lstat()
        payload = physical_path.read_bytes()
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_LAUNCHER_TARGET_INVALID", str(error)
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_size > _MAX_DOCUMENT_BYTES
        or len(payload) != info.st_size
    ):
        _fail(
            "ROLLBACK_LAUNCHER_TARGET_INVALID",
            f"небезопасный файл загрузчика: {physical_path}",
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


def _absence_projection(
    path: Path, *, installation_id: str, operation_id: str
) -> ProjectionV2:
    parent = _private_directory(path.parent)
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


def _journal_projection(
    path: Path,
    *,
    operation_id: str,
    plan_fingerprint: str,
    phase: str,
    recovery_policy: str,
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


def _journal_action(transition: str, path: Path) -> dict[str, object]:
    return {
        "actionKind": "journal-transition",
        "transition": transition,
        "journalPath": str(path),
        "durability": "FSYNC_FILE_AND_PARENT",
    }


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


def _read_private_canonical_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise ValueError("unsafe file")
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_DOCUMENT_INVALID", f"документ недоступен: {path}"
        ) from error
    if type(document) is not dict or raw != canonical_json_bytes(document):
        _fail("ROLLBACK_DOCUMENT_INVALID", f"документ не canonical JSON: {path}")
    return raw, document


def _private_directory(path: Path) -> os.stat_result:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError("private directory path must be absolute")
    try:
        info = path.lstat()
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_DIRECTORY_INVALID", str(error)
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail("ROLLBACK_DIRECTORY_INVALID", f"небезопасный каталог: {path}")
    return info


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_evidence(evidence: RollbackEvidenceV2) -> None:
    if not isinstance(evidence, RollbackEvidenceV2):
        raise TypeError("evidence must be RollbackEvidenceV2")


def _rollback_preparation_receipt(
    value: RollbackManifestPreparationReceiptV2 | Mapping[str, Any] | Path,
) -> RollbackManifestPreparationReceiptV2:
    if isinstance(value, RollbackManifestPreparationReceiptV2):
        return value
    if isinstance(value, Path):
        return RollbackManifestPreparationReceiptV2.from_path(value)
    if isinstance(value, Mapping):
        return RollbackManifestPreparationReceiptV2.from_document(value)
    raise TypeError("preparation_receipt has an unsupported type")


def _identifier(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор имеет неверную форму")
    return value


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _fail(code: str, message: str) -> None:
    raise InstallerRollbackCompositionV2Error(code, message)


__all__ = [
    "ROLLBACK_MATCHED_ACTIVE_STEPS_V2",
    "InstallerRollbackCompositionV2Error",
    "RollbackCompositionV2",
    "RollbackExternalArtifactsV2",
    "RollbackExternalStepBindingsV2",
    "RollbackLauncherBindingV2",
    "RollbackStepBindingV2",
    "build_rollback_candidate_spawn_binding_v2",
    "build_rollback_composition_v2",
    "build_rollback_composition_from_preparation_receipt_v2",
    "build_rollback_controller_bindings_v2",
    "build_rollback_external_step_bindings_v2",
    "build_rollback_launcher_binding_v2",
    "build_rollback_recovery_composition_from_receipt_v2",
    "build_rollback_recovery_composition_v2",
    "build_rollback_registry_binding_v2",
    "build_rollback_shutdown_cleanup_binding_v2",
    "build_rollback_verify_candidate_binding_v2",
    "read_rollback_external_artifacts_v2",
]
