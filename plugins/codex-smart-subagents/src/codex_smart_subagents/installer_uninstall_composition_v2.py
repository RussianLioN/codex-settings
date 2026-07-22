"""Поэтапная производственная композиция удаления установки версии 2.

Свежая операция использует основной журнал: каждый вид внешнего или файлового
эффекта принадлежит ровно одному нормативному шагу. Старый пакетный журнал
обслуживается только прежним совместимым восстановителем.
"""

from __future__ import annotations

import copy
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .activation_gateway_v2 import _LIFECYCLE_SCHEMA_SHA256
from .activation_transition_v2 import ActivationTransitionProofV2
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .controller_transition_rehydration_v2 import (
    ControllerShutdownCommandIdsV2,
    rehydrate_controller_shutdown_proof_v2,
)
from .installer_maintenance_v2 import (
    InstallerMaintenanceLayoutV2,
    MaintenanceInventoryV2,
    MaintenanceResultV2,
    RegistrationCallbacksV2,
    RegistrationObservationV2,
    _build_uninstall_journal,
    _file_projection,
    _fsync_directory,
    _publish_or_verify_json,
    _remove_tree_exact,
    _removed_state_from_uninstall_journal,
    _raise_inventory_issues,
    _require_supported_original_backup,
    _tree_projection,
)
from .installer_update_composition_v2 import (
    LauncherBindingV2,
    _observe_launcher_bindings,
    build_controller_shutdown_constraint_v2,
    build_shutdown_socket_cleanup_step_definition_v2,
    build_shutdown_socket_cleanup_step_port_v2,
)
from .installer_update_controller_ports_v2 import (
    build_shutdown_controller_step_ports_v2,
    observe_controller_database_v2,
)
from .installer_update_operation_v2 import UpdateStepPortV2
from .lifecycle_constraint_matcher_v2 import matches_registry_constraint_v2
from .lifecycle_operation_v2 import (
    InstallationUninstallPayloadIntentV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    OperationJournalStoreV2,
    OperationRunV2,
    ProjectionV2,
    StateBundleV2,
    StepCallbacksV2,
    StepDefinitionV2,
    TerminalCallbacksV2,
    TerminalDefinitionV2,
    TombstonePayloadIntentV2,
)
from .lifecycle_plan_v2 import LifecyclePlanRegistryV2
from .shutdown_socket_cleanup_v2 import (
    ShutdownSocketCleanupPlanV2,
    build_shutdown_socket_cleanup_plan_v2,
    wait_for_shutdown_socket_orphan_v2,
)
from .state_store_v2 import _QUIESCENCE_QUERIES


_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_MARKETPLACE_NAME = "codex-settings-adaptive"
_PLUGIN_ID = "codex-smart-subagents@codex-settings-adaptive"
_PLUGIN_NAME = "codex-smart-subagents"
_REGISTRY_DOMAIN = "codex-smart/registry-state/v2"
_UNINSTALL_RECEIPT_DOMAIN = "codex-smart/installation-uninstall-receipt/v2"
_TOMBSTONE_DOMAIN = "codex-smart/installation-tombstone/v2"

UNINSTALL_ACTIVE_STEPS_V2 = (
    "gate_close",
    "maintenance_begin",
    "wait_runtime_quiescent",
    "maintenance_strengthen",
    "controller_shutdown",
    "shutdown_socket_cleanup",
    "recovery_forward_only",
    "uninstall_plugin_remove",
    "uninstall_marketplace_remove",
    "uninstall_launchers_restore",
    "uninstall_activation_link_remove",
    "uninstall_activation_remove",
    "uninstall_manifest_remove",
    "terminal_journal_freeze",
    "uninstall_receipt_publish",
    "uninstall_tombstone_publish",
    "uninstall_journal_close",
)


@dataclass
class InstallerUninstallCompositionV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class InstallerUninstallCompositionV2:
    definition: OperationDefinitionV2
    executor: OperationExecutorV2
    callbacks: StepCallbacksV2
    terminal_callbacks: TerminalCallbacksV2
    ports: Mapping[str, UpdateStepPortV2]
    maintenance_layout: InstallerMaintenanceLayoutV2

    def execute(
        self,
        *,
        failure_injector: Callable[[Any, str], None] | None = None,
    ) -> tuple[OperationRunV2, MaintenanceResultV2]:
        run = self.executor.execute(
            self.definition,
            callbacks=self.callbacks,
            terminal_callbacks=self.terminal_callbacks,
            failure_injector=failure_injector,
        )
        return run, uninstall_maintenance_result_v2(
            self.definition,
            self.maintenance_layout,
            status="uninstalled",
        )


def uninstall_operation_id_v2(proof: ActivationTransitionProofV2) -> str:
    """Стабильно адресовать uninstall текущей принятой активации."""

    if not isinstance(proof, ActivationTransitionProofV2) or not proof.complete:
        raise TypeError("proof must be a complete ActivationTransitionProofV2")
    value = domain_fingerprint(
        "codex-smart/uninstall-operation-id/v2",
        {
            "installationId": proof.installation_id,
            "currentOperationId": proof.current_operation_id,
            "activationId": proof.activation_id,
            "activationFingerprint": proof.activation_fingerprint,
        },
    )
    return "op2_" + value[:32]


def build_active_uninstall_composition_v2(
    *,
    registry: LifecyclePlanRegistryV2,
    proof: ActivationTransitionProofV2,
    maintenance_layout: InstallerMaintenanceLayoutV2,
    inventory: MaintenanceInventoryV2,
    registrations: RegistrationCallbacksV2,
    store: OperationJournalStoreV2,
    operation_id: str | None = None,
    now: Callable[[], datetime] | None = None,
    id_factory: Callable[[str], str] | None = None,
    shell_session_id: str = "installer-v2",
    controller_port_options: Mapping[str, Any] | None = None,
    shutdown_cleanup_port_options: Mapping[str, Any] | None = None,
    port_overrides: Mapping[str, UpdateStepPortV2] | None = None,
) -> InstallerUninstallCompositionV2:
    """До первого эффекта собрать полное определение активной ветви."""

    if not isinstance(registry, LifecyclePlanRegistryV2):
        raise TypeError("registry must be LifecyclePlanRegistryV2")
    if not isinstance(proof, ActivationTransitionProofV2) or not proof.complete:
        raise TypeError("proof must be a complete ActivationTransitionProofV2")
    if not isinstance(maintenance_layout, InstallerMaintenanceLayoutV2):
        raise TypeError("maintenance_layout must be InstallerMaintenanceLayoutV2")
    if not isinstance(inventory, MaintenanceInventoryV2):
        raise TypeError("inventory must be MaintenanceInventoryV2")
    if not isinstance(registrations, RegistrationCallbacksV2):
        raise TypeError("registrations must be RegistrationCallbacksV2")
    if not isinstance(getattr(store, "journal_path", None), Path):
        raise TypeError("store must expose an absolute journal_path")
    operation_id = operation_id or uninstall_operation_id_v2(proof)
    _identifier(operation_id, _OPERATION_ID, "UNINSTALL_OPERATION_ID_INVALID")
    if (
        inventory.installation_id != proof.installation_id
        or inventory.active_activation_id != proof.activation_id
        or proof.codex_home != maintenance_layout.codex_home
        or proof.state_home != maintenance_layout.state_home
        or proof.layout.journal_path != store.journal_path
    ):
        _fail(
            "UNINSTALL_OWNERSHIP_BINDING_INVALID",
            "inventory, proof, layout и основной журнал относятся к разным установкам",
        )
    _raise_inventory_issues(inventory)
    _require_supported_original_backup(inventory)
    snapshot = _build_uninstall_journal(
        maintenance_layout,
        inventory,
        operation_id=operation_id,
        now=lambda: "2026-01-01T00:00:00.000000Z",
    )
    definition, shutdown_plan = _build_definition(
        registry=registry,
        proof=proof,
        maintenance_layout=maintenance_layout,
        snapshot=snapshot,
        operation_id=operation_id,
        shell_session_id=shell_session_id,
    )
    return _assemble_composition(
        registry=registry,
        definition=definition,
        maintenance_layout=maintenance_layout,
        registrations=registrations,
        store=store,
        shutdown_plan=shutdown_plan,
        now=now,
        id_factory=id_factory,
        shell_session_id=shell_session_id,
        controller_port_options=controller_port_options,
        shutdown_cleanup_port_options=shutdown_cleanup_port_options,
        port_overrides=port_overrides,
    )


def recover_active_uninstall_composition_v2(
    *,
    registry: LifecyclePlanRegistryV2,
    definition: OperationDefinitionV2,
    maintenance_layout: InstallerMaintenanceLayoutV2,
    registrations: RegistrationCallbacksV2,
    store: OperationJournalStoreV2,
    now: Callable[[], datetime] | None = None,
    id_factory: Callable[[str], str] | None = None,
    shell_session_id: str = "installer-v2",
    controller_port_options: Mapping[str, Any] | None = None,
    shutdown_cleanup_port_options: Mapping[str, Any] | None = None,
    port_overrides: Mapping[str, UpdateStepPortV2] | None = None,
) -> InstallerUninstallCompositionV2:
    """Восстановить порты только из неизменяемого main journal и retained data."""

    _validate_definition(registry, definition)
    payload = _uninstall_payload(definition)
    shutdown_step = _mutable_by_kind(definition)["shutdown_socket_cleanup"]
    shutdown_plan = _rehydrate_shutdown_plan(
        definition=definition,
        step=shutdown_step,
        activation_proof_fingerprint=payload.activation_proof_fingerprint,
    )
    return _assemble_composition(
        registry=registry,
        definition=definition,
        maintenance_layout=maintenance_layout,
        registrations=registrations,
        store=store,
        shutdown_plan=shutdown_plan,
        now=now,
        id_factory=id_factory,
        shell_session_id=shell_session_id,
        controller_port_options=controller_port_options,
        shutdown_cleanup_port_options=shutdown_cleanup_port_options,
        port_overrides=port_overrides,
    )


def _build_definition(
    *,
    registry: LifecyclePlanRegistryV2,
    proof: ActivationTransitionProofV2,
    maintenance_layout: InstallerMaintenanceLayoutV2,
    snapshot: Mapping[str, Any],
    operation_id: str,
    shell_session_id: str,
) -> tuple[OperationDefinitionV2, ShutdownSocketCleanupPlanV2]:
    execution_plan = registry.select(
        machine_id="uninstall",
        branch_id="active-matched-controller",
        plan_id=_derived_identifier("pl2", operation_id, "uninstall-active"),
    )
    if execution_plan.composed_step_kinds != UNINSTALL_ACTIVE_STEPS_V2:
        _fail("UNINSTALL_PLAN_INVALID", "реестр вернул другую активную ветвь")
    journal_path = proof.layout.journal_path
    gate_before = _expected_absence(
        (journal_path,), proof.installation_id, operation_id
    )
    gate_after = _journal_state(
        journal_path,
        operation_id,
        execution_plan.plan_definition_fingerprint,
        phase="DISCOVERED",
        recovery_policy="REVERSIBLE",
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
        before=gate_before,
        expected_after=gate_after,
    )

    controller_before = observe_controller_database_v2(proof.database_path)
    controller = _controller_definitions(
        proof=proof,
        operation_id=operation_id,
        controller_before=controller_before,
        shell_session_id=shell_session_id,
    )
    shutdown_plan = build_shutdown_socket_cleanup_plan_v2(
        installation_id=proof.installation_id,
        activation_proof_fingerprint=proof.proof_fingerprint,
        operation_id=operation_id,
        shutdown_command_id=str(controller["controller_shutdown"].command_id),
        state_home=proof.state_home,
        controller_state=proof.controller_row,
    )
    socket_cleanup = build_shutdown_socket_cleanup_step_definition_v2(
        plan=shutdown_plan,
        shutdown_constraint=controller["controller_shutdown"].expected_after,
    )
    forward_only = StepDefinitionV2(
        kind="recovery_forward_only",
        command_id=None,
        action={
            "actionKind": "journal-transition",
            "transition": "forward-only",
            "journalPath": str(journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        },
        before=_journal_state(
            journal_path,
            operation_id,
            execution_plan.plan_definition_fingerprint,
            phase="APPLYING",
            recovery_policy="REVERSIBLE",
            generation=12,
            frozen=False,
        ),
        expected_after=_journal_state(
            journal_path,
            operation_id,
            execution_plan.plan_definition_fingerprint,
            phase="APPLYING",
            recovery_policy="FORWARD_ONLY",
            generation=14,
            frozen=False,
        ),
    )
    filesystem = _uninstall_step_definitions(
        proof=proof,
        maintenance_layout=maintenance_layout,
        snapshot=snapshot,
        operation_id=operation_id,
    )
    mutable_by_kind = {
        **controller,
        "shutdown_socket_cleanup": socket_cleanup,
        "recovery_forward_only": forward_only,
        **filesystem,
    }
    mutable_kinds = UNINSTALL_ACTIVE_STEPS_V2[1:13]
    if set(mutable_by_kind) != set(mutable_kinds):
        _fail("UNINSTALL_DEFINITION_INCOMPLETE", "набор mutable-шагов неполон")

    removed_state = StateBundleV2.from_document(
        _removed_state_from_uninstall_journal(snapshot)
    )
    removed_paths = _removed_paths_from_snapshot(snapshot, maintenance_layout)
    terminal_absence = _expected_absence(
        removed_paths, proof.installation_id, operation_id
    )
    original_absence = _expected_absence(
        (Path(str(snapshot["originalBackupPath"])),),
        proof.installation_id,
        operation_id,
    )
    journal_absence = _expected_absence(
        (journal_path,), proof.installation_id, operation_id
    )
    receipt_path = Path(str(snapshot["receiptPath"]))
    tombstone_before = _expected_absence(
        (maintenance_layout.tombstone_path,), proof.installation_id, operation_id
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
        before=_journal_state(
            journal_path,
            operation_id,
            execution_plan.plan_definition_fingerprint,
            phase="COMMITTING",
            recovery_policy="FORWARD_ONLY",
            generation=27,
            frozen=False,
        ),
        expected_after=_journal_state(
            journal_path,
            operation_id,
            execution_plan.plan_definition_fingerprint,
            phase="TERMINAL_FROZEN",
            recovery_policy="FORWARD_ONLY",
            generation=28,
            frozen=True,
        ),
    )
    terminal = TerminalDefinitionV2(
        terminal_kind="UNINSTALL",
        receipt_kind="installation-uninstall",
        receipt_path=receipt_path,
        freeze=freeze,
        journal_absence_target=journal_absence,
        receipt_payload=InstallationUninstallPayloadIntentV2(
            removed_state=removed_state,
            restored_original_backup=original_absence,
            absence_proof=terminal_absence,
            retained_data=copy.deepcopy(dict(snapshot["retainedData"])),
            activation_proof_fingerprint=proof.proof_fingerprint,
        ),
        tombstone_payload=TombstonePayloadIntentV2(
            path=maintenance_layout.tombstone_path,
            before=tombstone_before,
            replacement_authorization="CREATE_IF_ABSENT",
        ),
    )
    definition = OperationDefinitionV2(
        kind="uninstall",
        installation_id=proof.installation_id,
        operation_id=operation_id,
        operation="uninstall",
        execution_plan=execution_plan,
        discovery_before=removed_state,
        fenced_before=removed_state,
        desired=removed_state,
        gate_close=gate,
        mutable_steps=tuple(mutable_by_kind[kind] for kind in mutable_kinds),
        terminal=terminal,
    )
    _validate_definition(registry, definition)
    return definition, shutdown_plan


def _controller_definitions(
    *,
    proof: ActivationTransitionProofV2,
    operation_id: str,
    controller_before: ProjectionV2,
    shell_session_id: str,
) -> dict[str, StepDefinitionV2]:
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
        _fail("UNINSTALL_CONTROLLER_BEFORE_INVALID", "контроллер не MATCHED_ACTIVE")
    begin_value = {
        **old,
        "controlEpoch": epoch + 1,
        "state": "EXPECTED_DRAIN_OR_MAINTENANCE",
        "maintenanceMode": "drain",
        "operationId": operation_id,
        "acceptingNewRoutes": False,
        "quiescent": False,
    }
    begin_after = _projection(
        "controller-state-v2", begin_value, "codex-smart/controller-state/v2"
    )
    quiescent_controller = {
        **begin_value,
        "state": "MAINTENANCE",
        "quiescent": True,
    }
    predicates = {
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
                "codex-smart/database-predicates/v2", predicates
            ),
            "barrierHeld": True,
            "quiescent": True,
        },
        "codex-smart/quiescence-proof/v2",
    )
    strengthen_after = _projection(
        "controller-state-v2",
        {
            **quiescent_controller,
            "controlEpoch": epoch + 2,
            "maintenanceMode": "freeze",
        },
        "codex-smart/controller-state/v2",
    )
    command_ids = {
        kind: _derived_identifier("cc2", operation_id, kind)
        for kind in (
            "maintenance_begin",
            "maintenance_strengthen",
            "controller_shutdown",
        )
    }
    shutdown_after = build_controller_shutdown_constraint_v2(
        codex_home=proof.codex_home,
        shell_session_id=shell_session_id,
        operation_id=operation_id,
        command_id=command_ids["controller_shutdown"],
        controller_before=strengthen_after,
        lock_path=proof.state_home / "controller.lock",
    )

    def command(
        kind: str,
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
        "maintenance_begin": command(
            "maintenance_begin",
            "maintenance_begin",
            controller_before,
            begin_after,
            epoch,
        ),
        "wait_runtime_quiescent": StepDefinitionV2(
            kind="wait_runtime_quiescent",
            command_id=None,
            action={
                "actionKind": "verify",
                "predicate": "runtime-quiescent",
                "timeoutMs": 30_000,
            },
            before=begin_after,
            expected_after=quiescence,
        ),
        "maintenance_strengthen": command(
            "maintenance_strengthen",
            "maintenance_strengthen",
            _projection(
                "controller-state-v2",
                quiescent_controller,
                "codex-smart/controller-state/v2",
            ),
            strengthen_after,
            epoch + 1,
        ),
        "controller_shutdown": command(
            "controller_shutdown",
            "shutdown",
            strengthen_after,
            shutdown_after,
            epoch + 2,
        ),
    }


def _uninstall_step_definitions(
    *,
    proof: ActivationTransitionProofV2,
    maintenance_layout: InstallerMaintenanceLayoutV2,
    snapshot: Mapping[str, Any],
    operation_id: str,
) -> dict[str, StepDefinitionV2]:
    plugin_before = _registry_actual(
        maintenance_layout,
        snapshot,
        plugin_enabled=True,
    )
    marketplace_constraint = _registry_constraint(snapshot, plugin_enabled=False)
    registry_absence = _expected_absence(
        (maintenance_layout.state_home / ".registry-codex-settings-adaptive.absent",),
        proof.installation_id,
        operation_id,
    )
    launcher_bindings = _launcher_bindings(maintenance_layout, snapshot)
    launchers_before = _observe_launcher_bindings(launcher_bindings, expected=False)
    launcher_absence = _expected_absence(
        tuple(binding.path for binding in launcher_bindings),
        proof.installation_id,
        operation_id,
    )
    marketplace_link = ProjectionV2.from_document(snapshot["marketplaceLink"])
    link_path = Path(str(marketplace_link.value["path"]))
    link_absence = _expected_absence(
        (link_path,), proof.installation_id, operation_id
    )
    activations_before = _projection(
        "tree-object-v2",
        _tree_projection(maintenance_layout.activations_root),
        "codex-smart/tree-object/v2",
    )
    activations_absence = _expected_absence(
        (maintenance_layout.activations_root,),
        proof.installation_id,
        operation_id,
    )
    manifest_absence = _expected_absence(
        (
            maintenance_layout.manifest_path,
            maintenance_layout.installer_receipt_path,
        ),
        proof.installation_id,
        operation_id,
    )
    plugin_id = _derived_identifier("ec2", operation_id, "uninstall-plugin")
    marketplace_id = _derived_identifier(
        "ec2", operation_id, "uninstall-marketplace"
    )
    launchers = []
    for binding, entry in zip(
        launcher_bindings,
        launchers_before.value["launchers"],
        strict=True,
    ):
        launchers.append(
            {
                "name": binding.name,
                "role": binding.role,
                "method": "unlink",
                "targetPath": str(binding.path),
                "beforeFingerprint": domain_fingerprint(
                    "codex-smart/launcher-entry/v2", entry
                ),
                "expectedAfterFingerprint": None,
            }
        )
    return {
        "uninstall_plugin_remove": StepDefinitionV2(
            kind="uninstall_plugin_remove",
            command_id=plugin_id,
            action=_external_action(
                plugin_id,
                "plugin-disable",
                ("plugin", "remove", _PLUGIN_ID),
            ),
            before=plugin_before,
            expected_after=marketplace_constraint,
        ),
        "uninstall_marketplace_remove": StepDefinitionV2(
            kind="uninstall_marketplace_remove",
            command_id=marketplace_id,
            action=_external_action(
                marketplace_id,
                "marketplace-remove",
                ("plugin", "marketplace", "remove", _MARKETPLACE_NAME),
            ),
            before=marketplace_constraint,
            expected_after=registry_absence,
        ),
        "uninstall_launchers_restore": StepDefinitionV2(
            kind="uninstall_launchers_restore",
            command_id=None,
            action={
                "actionKind": "launcher-set-mutation",
                "mode": "REMOVE_CREATED",
                "operations": launchers,
                "durability": "FSYNC_EACH_FILE_AND_PARENT",
            },
            before=launchers_before,
            expected_after=launcher_absence,
        ),
        "uninstall_activation_link_remove": StepDefinitionV2(
            kind="uninstall_activation_link_remove",
            command_id=None,
            action={
                "actionKind": "symlink-mutation",
                "method": "remove",
                "path": str(link_path),
                "target": str(marketplace_link.value["target"]),
                "durability": "FSYNC_PARENT",
            },
            before=marketplace_link,
            expected_after=link_absence,
        ),
        "uninstall_activation_remove": StepDefinitionV2(
            kind="uninstall_activation_remove",
            command_id=None,
            action={
                "actionKind": "owned-object-delete",
                "objectKind": "activation",
                "path": str(maintenance_layout.activations_root),
                "ownershipFingerprint": activations_before.value_fingerprint,
                "durability": "UNLINKAT_FSYNC_PARENT",
            },
            before=activations_before,
            expected_after=activations_absence,
        ),
        "uninstall_manifest_remove": StepDefinitionV2(
            kind="uninstall_manifest_remove",
            command_id=None,
            action={
                "actionKind": "owned-object-delete",
                "objectKind": "manifest",
                "path": str(maintenance_layout.manifest_path),
                "installerReceiptPath": str(
                    maintenance_layout.installer_receipt_path
                ),
                "ownershipFingerprint": domain_fingerprint(
                    "codex-smart/uninstall-manifest-ownership/v2",
                    {
                        "manifest": snapshot["manifestFile"],
                        "installerReceipt": snapshot["installerReceiptFile"],
                    },
                ),
                "durability": "UNLINKAT_FSYNC_PARENT",
            },
            before=proof.manifest_projection,
            expected_after=manifest_absence,
        ),
    }


def _assemble_composition(
    *,
    registry: LifecyclePlanRegistryV2,
    definition: OperationDefinitionV2,
    maintenance_layout: InstallerMaintenanceLayoutV2,
    registrations: RegistrationCallbacksV2,
    store: OperationJournalStoreV2,
    shutdown_plan: ShutdownSocketCleanupPlanV2,
    now: Callable[[], datetime] | None,
    id_factory: Callable[[str], str] | None,
    shell_session_id: str,
    controller_port_options: Mapping[str, Any] | None,
    shutdown_cleanup_port_options: Mapping[str, Any] | None,
    port_overrides: Mapping[str, UpdateStepPortV2] | None,
) -> InstallerUninstallCompositionV2:
    _validate_definition(registry, definition)
    definitions = _mutable_by_kind(definition)
    payload = _uninstall_payload(definition)
    database_path = Path(
        str(payload.retained_data["databaseBinding"]["value"]["path"])
    )
    controller_options = _port_options(
        controller_port_options,
        forbidden={
            "operation_id",
            "activation_proof_fingerprint",
            "shutdown_cleanup_plan_fingerprint",
            "codex_home",
            "current_database_path",
            "definitions",
            "maintenance_reason_code",
            "shell_session_id",
        },
    )

    def prove_orphan(shutdown: Any) -> Any:
        options = dict(shutdown_cleanup_port_options or {})
        marker = options.get("process_start_marker_provider")
        arguments = {} if marker is None else {"process_start_marker_provider": marker}
        return wait_for_shutdown_socket_orphan_v2(
            plan=shutdown_plan,
            shutdown=shutdown,
            **arguments,
        )

    controller_kinds = (
        "maintenance_begin",
        "wait_runtime_quiescent",
        "maintenance_strengthen",
        "controller_shutdown",
    )
    orphan_prover = controller_options.pop(
        "shutdown_orphan_prover",
        prove_orphan,
    )
    ports = build_shutdown_controller_step_ports_v2(
        operation_id=definition.operation_id,
        activation_proof_fingerprint=payload.activation_proof_fingerprint,
        shutdown_cleanup_plan_fingerprint=shutdown_plan.plan_fingerprint,
        codex_home=maintenance_layout.codex_home,
        current_database_path=database_path,
        definitions={kind: definitions[kind] for kind in controller_kinds},
        shutdown_orphan_prover=orphan_prover,
        maintenance_reason_code="UNINSTALL",
        shell_session_id=shell_session_id,
        **controller_options,
    )
    command_ids = ControllerShutdownCommandIdsV2(
        maintenance_begin=str(definitions["maintenance_begin"].command_id),
        maintenance_strengthen=str(
            definitions["maintenance_strengthen"].command_id
        ),
        shutdown=str(definitions["controller_shutdown"].command_id),
    )

    def shutdown_proof() -> Any:
        return rehydrate_controller_shutdown_proof_v2(
            database_path=database_path,
            activation_proof_fingerprint=payload.activation_proof_fingerprint,
            operation_id=definition.operation_id,
            command_ids=command_ids,
        )

    cleanup_options = _port_options(
        shutdown_cleanup_port_options,
        forbidden={"plan", "definition", "shutdown_proof_provider"},
    )
    ports["shutdown_socket_cleanup"] = build_shutdown_socket_cleanup_step_port_v2(
        plan=shutdown_plan,
        definition=definitions["shutdown_socket_cleanup"],
        shutdown_proof_provider=shutdown_proof,
        **cleanup_options,
    )
    ports.update(
        _filesystem_ports(
            definition=definition,
            maintenance_layout=maintenance_layout,
            registrations=registrations,
        )
    )
    if port_overrides is not None:
        for kind, port in dict(port_overrides).items():
            if kind not in ports or not isinstance(port, UpdateStepPortV2):
                _fail("UNINSTALL_PORT_OVERRIDE_INVALID", f"неверный порт {kind}")
            ports[kind] = port

    def require_port(step: StepDefinitionV2) -> UpdateStepPortV2:
        try:
            return ports[step.kind]
        except KeyError as error:
            raise InstallerUninstallCompositionV2Error(
                "UNINSTALL_STEP_PORT_MISSING", step.kind
            ) from error

    callbacks = StepCallbacksV2(
        observe=lambda step: require_port(step).observe(step),
        apply=lambda step: require_port(step).apply(step),
        matches_before=lambda observed, step: require_port(step).matches_before(
            observed, step
        ),
        matches_after=lambda observed, step: require_port(step).matches_after(
            observed, step
        ),
        matches_intent_resume=lambda observed, step: require_port(
            step
        ).matches_intent_resume(observed, step),
        replay_safe_when_indistinguishable=lambda observed, step: require_port(
            step
        ).replay_safe_when_indistinguishable(observed, step),
        completed_current_matches=lambda persisted, current, step: require_port(
            step
        ).completed_current_matches(persisted, current, step),
    )
    executor = OperationExecutorV2(
        store=store,
        now=now or (lambda: datetime.now(timezone.utc)),
        id_factory=id_factory,
    )
    terminal_callbacks = _terminal_callbacks(definition, maintenance_layout)
    return InstallerUninstallCompositionV2(
        definition=definition,
        executor=executor,
        callbacks=callbacks,
        terminal_callbacks=terminal_callbacks,
        ports=copy.copy(ports),
        maintenance_layout=maintenance_layout,
    )


def _filesystem_ports(
    *,
    definition: OperationDefinitionV2,
    maintenance_layout: InstallerMaintenanceLayoutV2,
    registrations: RegistrationCallbacksV2,
) -> dict[str, UpdateStepPortV2]:
    definitions = _mutable_by_kind(definition)
    plugin = definitions["uninstall_plugin_remove"]
    marketplace = definitions["uninstall_marketplace_remove"]

    def registry_observe(step: StepDefinitionV2) -> ProjectionV2:
        plugin_observed = registrations.observe("plugin", _PLUGIN_ID)
        marketplace_observed = registrations.observe(
            "marketplace", _MARKETPLACE_NAME
        )
        if plugin_observed is not None:
            _verify_registration_target(plugin_observed, plugin.before)
            return _registry_actual_from_template(
                maintenance_layout,
                plugin.before,
                plugin_enabled=True,
            )
        if marketplace_observed is not None:
            _verify_registration_target(marketplace_observed, plugin.expected_after)
            return _registry_actual_from_template(
                maintenance_layout,
                plugin.expected_after,
                plugin_enabled=False,
            )
        return marketplace.expected_after

    def plugin_apply(step: StepDefinitionV2) -> None:
        _require_step(step, plugin)
        observed = registrations.observe("plugin", _PLUGIN_ID)
        if observed is not None:
            _verify_registration_target(observed, plugin.before)
            registrations.remove(observed)

    def marketplace_apply(step: StepDefinitionV2) -> None:
        _require_step(step, marketplace)
        observed = registrations.observe("marketplace", _MARKETPLACE_NAME)
        if observed is not None:
            _verify_registration_target(observed, marketplace.before)
            registrations.remove(observed)

    launchers = definitions["uninstall_launchers_restore"]
    launcher_bindings = _launcher_bindings_from_definition(
        maintenance_layout, launchers
    )

    def launcher_observe(step: StepDefinitionV2) -> ProjectionV2:
        _require_step(step, launchers)
        present = [os.path.lexists(binding.path) for binding in launcher_bindings]
        if not any(present):
            return launchers.expected_after
        if not all(present):
            _fail("UNINSTALL_LAUNCHER_STATE_AMBIGUOUS", "частичный набор загрузчиков")
        return _observe_launcher_bindings(launcher_bindings, expected=False)

    def launcher_apply(step: StepDefinitionV2) -> None:
        _require_step(step, launchers)
        observed = launcher_observe(step)
        if observed == launchers.expected_after:
            return
        if observed != launchers.before:
            _fail("UNINSTALL_LAUNCHER_CHANGED", "загрузчики изменились")
        for binding in launcher_bindings:
            binding.path.unlink()
            _fsync_directory(binding.path.parent)

    link = definitions["uninstall_activation_link_remove"]

    def link_observe(step: StepDefinitionV2) -> ProjectionV2:
        _require_step(step, link)
        path = Path(str(link.action["path"]))
        if not os.path.lexists(path):
            return link.expected_after
        try:
            info = path.lstat()
            target = os.readlink(path)
            parent = path.parent.lstat()
        except OSError as error:
            raise InstallerUninstallCompositionV2Error(
                "UNINSTALL_LINK_CHANGED", str(error)
            ) from error
        value = link.before.value
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or target != value.get("target")
            or parent.st_dev != value.get("parentDevice")
            or parent.st_ino != value.get("parentInode")
        ):
            _fail("UNINSTALL_LINK_CHANGED", "ссылка активации изменилась")
        return link.before

    def link_apply(step: StepDefinitionV2) -> None:
        _require_step(step, link)
        if link_observe(step) == link.expected_after:
            return
        path = Path(str(link.action["path"]))
        path.unlink()
        _fsync_directory(path.parent)

    activation = definitions["uninstall_activation_remove"]

    def activation_observe(step: StepDefinitionV2) -> ProjectionV2:
        _require_step(step, activation)
        path = Path(str(activation.action["path"]))
        if not os.path.lexists(path):
            return activation.expected_after
        return _projection(
            "tree-object-v2",
            _tree_projection(path),
            "codex-smart/tree-object/v2",
        )

    def activation_apply(step: StepDefinitionV2) -> None:
        _require_step(step, activation)
        observed = activation_observe(step)
        if observed == activation.expected_after:
            return
        if observed != activation.before:
            _fail("UNINSTALL_ACTIVATION_CHANGED", "дерево активаций изменилось")
        _remove_tree_exact(
            Path(str(activation.action["path"])), activation.before.value
        )

    manifest = definitions["uninstall_manifest_remove"]
    removed_files = _uninstall_payload(definition).removed_state.file_objects
    removed_file_projections = {
        Path(str(item.value["path"])): item for item in removed_files
    }
    manifest_paths = (
        Path(str(manifest.action["path"])),
        Path(str(manifest.action["installerReceiptPath"])),
    )
    if (
        len(set(manifest_paths)) != 2
        or set(removed_file_projections) != set(manifest_paths)
        or manifest.before.value.get("file")
        != removed_file_projections[manifest_paths[0]].value
        or manifest.action.get("ownershipFingerprint")
        != domain_fingerprint(
            "codex-smart/uninstall-manifest-ownership/v2",
            {
                "manifest": removed_file_projections[
                    manifest_paths[0]
                ].to_document(),
                "installerReceipt": removed_file_projections[
                    manifest_paths[1]
                ].to_document(),
            },
        )
    ):
        _fail(
            "UNINSTALL_MANIFEST_BINDING_INVALID",
            "действие не связано с точной парой манифеста и installer receipt",
        )
    expected_files = {
        path: copy.deepcopy(dict(removed_file_projections[path].value))
        for path in manifest_paths
    }
    partial_observations = tuple(
        _absence_observation(
            (path,),
            definition.installation_id,
            definition.operation_id,
        )
        for path in manifest_paths
    )

    def manifest_observe(step: StepDefinitionV2) -> ProjectionV2:
        _require_step(step, manifest)
        present = {
            path: os.path.lexists(path) for path in manifest_paths
        }
        if not any(present.values()):
            return manifest.expected_after
        for path, exists in present.items():
            if exists and _file_projection(path) != expected_files[path]:
                _fail("UNINSTALL_MANIFEST_CHANGED", f"файл изменился: {path}")
        if all(present.values()):
            return manifest.before
        absent = tuple(path for path in manifest_paths if not present[path])
        return _absence_observation(
            absent,
            definition.installation_id,
            definition.operation_id,
        )

    def manifest_apply(step: StepDefinitionV2) -> None:
        _require_step(step, manifest)
        observed = manifest_observe(step)
        if observed == manifest.expected_after:
            return
        if observed != manifest.before and observed not in partial_observations:
            _fail(
                "UNINSTALL_MANIFEST_STATE_AMBIGUOUS",
                "пара файлов установки не принадлежит текущему шагу",
            )
        for path in manifest_paths:
            if os.path.lexists(path):
                if _file_projection(path) != expected_files[path]:
                    _fail("UNINSTALL_MANIFEST_CHANGED", f"файл изменился: {path}")
                path.unlink()
                _fsync_directory(path.parent)

    return {
        "uninstall_plugin_remove": UpdateStepPortV2(
            observe=registry_observe,
            apply=plugin_apply,
            matches_before=lambda observed, _step: observed == plugin.before,
            matches_after=lambda observed, _step: matches_registry_constraint_v2(
                observed, plugin.expected_after
            ),
            completed_current_matches=lambda persisted, current, _step: bool(
                matches_registry_constraint_v2(persisted, plugin.expected_after)
                and (
                    matches_registry_constraint_v2(current, plugin.expected_after)
                    or current == marketplace.expected_after
                )
            ),
        ),
        "uninstall_marketplace_remove": UpdateStepPortV2(
            observe=registry_observe,
            apply=marketplace_apply,
            matches_before=lambda observed, _step: matches_registry_constraint_v2(
                observed, marketplace.before
            ),
            matches_after=lambda observed, _step: observed == marketplace.expected_after,
            completed_current_matches=lambda persisted, current, _step: (
                persisted == current == marketplace.expected_after
            ),
        ),
        "uninstall_launchers_restore": _simple_port(
            launchers, launcher_observe, launcher_apply
        ),
        "uninstall_activation_link_remove": _simple_port(
            link, link_observe, link_apply
        ),
        "uninstall_activation_remove": _simple_port(
            activation, activation_observe, activation_apply
        ),
        "uninstall_manifest_remove": UpdateStepPortV2(
            observe=manifest_observe,
            apply=manifest_apply,
            matches_before=lambda observed, step: observed == step.before,
            matches_after=lambda observed, step: observed == step.expected_after,
            matches_intent_resume=lambda observed, _step: (
                observed in partial_observations
            ),
            completed_current_matches=lambda persisted, current, step: (
                persisted == current == step.expected_after
            ),
        ),
    }


def _simple_port(
    definition: StepDefinitionV2,
    observe: Callable[[StepDefinitionV2], ProjectionV2],
    apply: Callable[[StepDefinitionV2], None],
) -> UpdateStepPortV2:
    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, step: observed == step.before,
        matches_after=lambda observed, step: observed == step.expected_after,
        replay_safe_when_indistinguishable=lambda observed, step: (
            observed == step.expected_after
        ),
        completed_current_matches=lambda persisted, current, step: (
            persisted == current == step.expected_after
        ),
    )


def _terminal_callbacks(
    definition: OperationDefinitionV2,
    layout: InstallerMaintenanceLayoutV2,
) -> TerminalCallbacksV2:
    terminal = definition.terminal
    assert terminal is not None

    def receipt(journal: Mapping[str, Any]) -> dict[str, Any]:
        payload = _frozen_payload(journal)
        projection = {
            "schemaVersion": 2,
            "receiptKind": "installation-uninstall",
            "installationId": journal["installationId"],
            "operationId": journal["operationId"],
            "frozenJournalFingerprint": journal["journalFingerprint"],
            "dataRetentionMode": payload["dataRetentionMode"],
            "retainedData": copy.deepcopy(payload["retainedData"]),
            "removedState": copy.deepcopy(payload["removedState"]),
            "restoredOriginalBackup": copy.deepcopy(
                payload["restoredOriginalBackup"]
            ),
            "absenceProof": copy.deepcopy(payload["absenceProof"]),
            "completedAt": payload["completedAt"],
        }
        return {
            **projection,
            "receiptFingerprint": domain_fingerprint(
                _UNINSTALL_RECEIPT_DOMAIN, projection
            ),
        }

    def receipt_matches(journal: Mapping[str, Any]) -> bool:
        return _json_file_matches(terminal.receipt_path, receipt(journal))

    def publish_receipt(journal: Mapping[str, Any]) -> None:
        _publish_or_verify_json(
            terminal.receipt_path,
            receipt(journal),
            code="UNINSTALL_RECEIPT_CONFLICT",
        )

    def tombstone(journal: Mapping[str, Any]) -> dict[str, Any]:
        current_receipt = receipt(journal)
        receipt_projection = _projection(
            "receipt-object-v2",
            {
                "file": _file_projection(terminal.receipt_path),
                "receiptKind": "installation-uninstall",
                "installationId": journal["installationId"],
                "operationId": journal["operationId"],
                "receiptFingerprint": current_receipt["receiptFingerprint"],
            },
            "codex-smart/receipt-object/v2",
        )
        projection = {
            "schemaVersion": 2,
            "installationId": journal["installationId"],
            "operationId": journal["operationId"],
            "uninstallReceipt": receipt_projection.to_document(),
            "absenceProof": copy.deepcopy(current_receipt["absenceProof"]),
            "completedAt": current_receipt["completedAt"],
        }
        return {
            **projection,
            "tombstoneFingerprint": domain_fingerprint(
                _TOMBSTONE_DOMAIN, projection
            ),
        }

    def tombstone_matches(journal: Mapping[str, Any]) -> bool:
        return _json_file_matches(layout.tombstone_path, tombstone(journal))

    def publish_tombstone(journal: Mapping[str, Any]) -> None:
        _publish_or_verify_json(
            layout.tombstone_path,
            tombstone(journal),
            code="TOMBSTONE_CONFLICT",
        )

    return TerminalCallbacksV2(
        receipt_matches=receipt_matches,
        publish_receipt=publish_receipt,
        tombstone_matches=tombstone_matches,
        publish_tombstone=publish_tombstone,
    )


def _registry_actual(
    layout: InstallerMaintenanceLayoutV2,
    snapshot: Mapping[str, Any],
    *,
    plugin_enabled: bool,
) -> ProjectionV2:
    template = _registry_constraint(snapshot, plugin_enabled=plugin_enabled)
    return _registry_actual_from_template(
        layout, template, plugin_enabled=plugin_enabled
    )


def _registry_constraint(
    snapshot: Mapping[str, Any], *, plugin_enabled: bool
) -> ProjectionV2:
    registrations = {item["kind"]: item for item in snapshot["registrations"]}
    marketplace_path = Path(str(registrations["marketplace"]["target"]))
    plugin_path = Path(str(registrations["plugin"]["target"]))
    stable = _registry_stable_value(
        marketplace_path=marketplace_path,
        plugin_path=plugin_path,
        plugin_enabled=plugin_enabled,
    )
    return _projection(
        "registry-state-v2",
        {
            **stable,
            "status": (
                "EXPECTED_PLUGIN_ENABLED"
                if plugin_enabled
                else "EXPECTED_MARKETPLACE_REGISTERED"
            ),
            "configFile": None,
            "marketplaceListFingerprint": None,
            "pluginListFingerprint": None,
        },
        _REGISTRY_DOMAIN,
    )


def _registry_actual_from_template(
    layout: InstallerMaintenanceLayoutV2,
    template: ProjectionV2,
    *,
    plugin_enabled: bool,
) -> ProjectionV2:
    value = copy.deepcopy(dict(template.value))
    value.update(
        {
            "status": "PLUGIN_ENABLED" if plugin_enabled else "MARKETPLACE_REGISTERED",
            "configFile": _file_projection(layout.codex_home / "config.toml"),
            "marketplaceListFingerprint": domain_fingerprint(
                "codex-smart/registry-marketplace-list/v2",
                {
                    "name": _MARKETPLACE_NAME,
                    "path": value["marketplacePath"],
                },
            ),
            "pluginListFingerprint": domain_fingerprint(
                "codex-smart/registry-plugin-list/v2",
                {"pluginId": _PLUGIN_ID, "enabled": plugin_enabled},
            ),
        }
    )
    return _projection("registry-state-v2", value, _REGISTRY_DOMAIN)


def _registry_stable_value(
    *, marketplace_path: Path, plugin_path: Path, plugin_enabled: bool
) -> dict[str, Any]:
    marketplace_identity = {
        "name": _MARKETPLACE_NAME,
        "path": str(marketplace_path),
        "sourceType": "local",
    }
    plugin_identity = {
        "pluginId": _PLUGIN_ID,
        "name": _PLUGIN_NAME,
        "marketplaceName": _MARKETPLACE_NAME,
        "version": "0.2.0",
        "source": "local",
        "path": str(plugin_path),
        "marketplacePath": str(marketplace_path),
        "installPolicy": "AVAILABLE",
        "authPolicy": "ON_INSTALL",
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
        "marketplacePath": str(marketplace_path),
        "marketplaceFingerprint": domain_fingerprint(
            "codex-smart/registry-marketplace-identity/v2", marketplace_identity
        ),
        "pluginId": _PLUGIN_ID,
        "pluginEnabled": plugin_enabled,
        "pluginFingerprint": domain_fingerprint(
            "codex-smart/registry-plugin-identity/v2", plugin_identity
        ),
        "configSemanticFingerprint": domain_fingerprint(
            "codex-smart/registry-config-semantic/v2", semantic
        ),
    }


def _verify_registration_target(
    observation: RegistrationObservationV2, template: ProjectionV2
) -> None:
    expected_marketplace = Path(str(template.value["marketplacePath"]))
    expected = (
        expected_marketplace / "plugins" / _PLUGIN_NAME
        if observation.kind == "plugin"
        else expected_marketplace
    )
    if observation.target != expected:
        _fail("UNINSTALL_REGISTRY_CHANGED", f"изменена регистрация {observation.kind}")


def _launcher_bindings(
    layout: InstallerMaintenanceLayoutV2,
    snapshot: Mapping[str, Any],
) -> tuple[LauncherBindingV2, ...]:
    values = []
    for item in snapshot["launcherLinks"]:
        path = Path(str(item["path"]))
        target = Path(str(item["target"]))
        values.append(
            LauncherBindingV2(
                name=path.name,
                role="admin" if path.name.endswith("-admin") else "gateway",
                path=path,
                target=target,
                expected_resolved_target=target.resolve(strict=True),
            )
        )
    return tuple(values)


def _launcher_bindings_from_definition(
    layout: InstallerMaintenanceLayoutV2,
    definition: StepDefinitionV2,
) -> tuple[LauncherBindingV2, ...]:
    result = []
    for operation in definition.action["operations"]:
        path = Path(str(operation["targetPath"]))
        target = (
            layout.marketplace_link / "plugins" / _PLUGIN_NAME / "bin" / path.name
        )
        result.append(
            LauncherBindingV2(
                name=str(operation["name"]),
                role=str(operation["role"]),
                path=path,
                target=target,
                expected_resolved_target=target,
            )
        )
    return tuple(result)


def _rehydrate_shutdown_plan(
    *,
    definition: OperationDefinitionV2,
    step: StepDefinitionV2,
    activation_proof_fingerprint: str,
) -> ShutdownSocketCleanupPlanV2:
    action = copy.deepcopy(dict(step.action))
    try:
        draft = ShutdownSocketCleanupPlanV2(
            installation_id=definition.installation_id,
            activation_proof_fingerprint=activation_proof_fingerprint,
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
        raise InstallerUninstallCompositionV2Error(
            "UNINSTALL_SHUTDOWN_PLAN_INVALID", str(error)
        ) from error
    fingerprint = domain_fingerprint(
        "codex-smart/shutdown-socket-cleanup-plan/v2",
        {
            "installationId": draft.installation_id,
            "activationProofFingerprint": draft.activation_proof_fingerprint,
            "operationId": draft.operation_id,
            "shutdownCommandId": draft.shutdown_command_id,
            "action": action,
        },
    )
    plan = ShutdownSocketCleanupPlanV2(
        **{
            name: getattr(draft, name)
            for name in draft.__dataclass_fields__
            if name != "plan_fingerprint"
        },
        plan_fingerprint=fingerprint,
    )
    if (
        not plan.complete
        or build_shutdown_socket_cleanup_step_definition_v2(
            plan=plan, shutdown_constraint=step.before
        )
        != step
    ):
        _fail("UNINSTALL_SHUTDOWN_PLAN_INVALID", "cleanup definition не совпала")
    return plan


def uninstall_maintenance_result_v2(
    definition: OperationDefinitionV2,
    layout: InstallerMaintenanceLayoutV2,
    *,
    status: str,
) -> MaintenanceResultV2:
    """Спроецировать один и тот же durable intent в preview или итог команды."""

    if status not in {"planned", "uninstalled", "unchanged"}:
        raise ValueError("unsupported uninstall maintenance result status")
    payload = _uninstall_payload(definition)
    retained = payload.retained_data
    database_path = Path(str(retained["databaseBinding"]["value"]["path"]))
    activation_ids = tuple(
        Path(str(item.value["path"])).name for item in payload.removed_state.tree_objects
    )
    return MaintenanceResultV2(
        command="uninstall",
        status=status,
        installation_id=definition.installation_id,
        operation_id=definition.operation_id,
        activation_ids=activation_ids,
        removed_paths=(
            tuple(
                Path(str(entry["path"]))
                for entry in payload.absence_proof.value["entries"]
            )
            if status == "uninstalled"
            else ()
        ),
        retained_paths=(
            layout.state_home,
            layout.databases_root,
            database_path,
            layout.backups_root,
            layout.quarantine_root,
            layout.recovery_entrypoint,
        ),
        receipt_path=definition.terminal.receipt_path if definition.terminal else None,
        tombstone_path=layout.tombstone_path,
    )


def _removed_paths_from_snapshot(
    snapshot: Mapping[str, Any], layout: InstallerMaintenanceLayoutV2
) -> tuple[Path, ...]:
    return tuple(
        dict.fromkeys(
            [
                *(Path(str(item["path"])) for item in snapshot["launcherLinks"]),
                Path(str(snapshot["marketplaceLink"]["value"]["path"])),
                layout.activations_root,
                Path(str(snapshot["manifestFile"]["value"]["path"])),
                Path(str(snapshot["installerReceiptFile"]["value"]["path"])),
            ]
        )
    )


def _expected_absence(
    paths: tuple[Path, ...], installation_id: str, operation_id: str
) -> ProjectionV2:
    entries = []
    for path in sorted(paths, key=lambda item: str(item).encode("utf-8")):
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            _fail("UNINSTALL_ABSENCE_PARENT_INVALID", str(path.parent))
        entries.append(
            {
                "path": str(path),
                "basename": path.name,
                "parentDevice": parent.st_dev,
                "parentInode": parent.st_ino,
                "absent": True,
            }
        )
    seed = {
        "installationId": installation_id,
        "operationId": operation_id,
        "entries": entries,
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


def _absence_observation(
    paths: tuple[Path, ...], installation_id: str, operation_id: str
) -> ProjectionV2:
    """Описать несинхронизированную частичную утрату без файлового эффекта."""

    entries = []
    for path in sorted(paths, key=lambda item: str(item).encode("utf-8")):
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            _fail("UNINSTALL_ABSENCE_PARENT_INVALID", str(path.parent))
        entries.append(
            {
                "path": str(path),
                "basename": path.name,
                "parentDevice": parent.st_dev,
                "parentInode": parent.st_ino,
                "absent": True,
            }
        )
    seed = {
        "installationId": installation_id,
        "operationId": operation_id,
        "entries": entries,
    }
    value = {
        "observationId": "ao2_"
        + domain_fingerprint("codex-smart/absence-observation-id/v2", seed)[:32],
        **seed,
        "directorySyncCompleted": False,
    }
    value["observationFingerprint"] = domain_fingerprint(
        "codex-smart/absence-observation/v2", value
    )
    return _projection(
        "absence-observation-v2",
        value,
        "codex-smart/absence-observation-projection/v2",
    )


def _journal_state(
    path: Path,
    operation_id: str,
    plan_fingerprint: str,
    *,
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


def _external_action(
    command_id: str, method: str, argv: tuple[str, ...]
) -> dict[str, Any]:
    return {
        "actionKind": "external-command",
        "commandRole": "codex-registry",
        "method": method,
        "externalCommandId": command_id,
        "argvFingerprint": domain_fingerprint(
            "codex-smart/registry-command-argv/v2", {"argv": [list(argv)]}
        ),
        "timeoutMs": 30_000,
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


def _derived_identifier(prefix: str, operation_id: str, purpose: str) -> str:
    return prefix + "_" + domain_fingerprint(
        "codex-smart/uninstall-derived-id/v2",
        {"operationId": operation_id, "purpose": purpose},
    )[:32]


def _mutable_by_kind(
    definition: OperationDefinitionV2,
) -> dict[str, StepDefinitionV2]:
    result = {step.kind: step for step in definition.mutable_steps}
    if len(result) != len(definition.mutable_steps):
        _fail("UNINSTALL_DEFINITION_INVALID", "повторяющиеся mutable-шаги")
    return result


def _uninstall_payload(
    definition: OperationDefinitionV2,
) -> InstallationUninstallPayloadIntentV2:
    terminal = definition.terminal
    if terminal is None or not isinstance(
        terminal.receipt_payload, InstallationUninstallPayloadIntentV2
    ):
        _fail("UNINSTALL_TERMINAL_INVALID", "нет uninstall payload")
    return terminal.receipt_payload


def _validate_definition(
    registry: LifecyclePlanRegistryV2, definition: OperationDefinitionV2
) -> None:
    expected = registry.select(
        machine_id="uninstall",
        branch_id="active-matched-controller",
        plan_id=definition.execution_plan.plan_id,
    )
    if (
        definition.kind != "uninstall"
        or definition.operation != "uninstall"
        or definition.execution_plan != expected
        or expected.composed_step_kinds != UNINSTALL_ACTIVE_STEPS_V2
    ):
        _fail("UNINSTALL_PLAN_INVALID", "definition не равен нормативной ветви")


def _require_step(received: StepDefinitionV2, expected: StepDefinitionV2) -> None:
    if received != expected:
        _fail("UNINSTALL_STEP_CHANGED", expected.kind)


def _frozen_payload(journal: Mapping[str, Any]) -> Mapping[str, Any]:
    intent = journal.get("terminalDeleteIntent")
    payload = intent.get("receiptPayloadIntent") if isinstance(intent, Mapping) else None
    if (
        journal.get("phase") != "TERMINAL_FROZEN"
        or not isinstance(payload, Mapping)
        or payload.get("payloadKind") != "installation-uninstall"
    ):
        _fail("UNINSTALL_FROZEN_JOURNAL_INVALID", "нет замороженного payload")
    return payload


def _json_file_matches(path: Path, expected: Mapping[str, Any]) -> bool:
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError:
        return False
    return bool(
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
        and raw == canonical_json_bytes(expected)
    )


def _port_options(
    value: Mapping[str, Any] | None, *, forbidden: set[str]
) -> dict[str, Any]:
    options = dict(value or {})
    overlap = forbidden.intersection(options)
    if overlap:
        _fail("UNINSTALL_PORT_OPTIONS_INVALID", ",".join(sorted(overlap)))
    return options


def _identifier(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор неверен")
    return value


def _fail(code: str, message: str) -> None:
    raise InstallerUninstallCompositionV2Error(code, message)


__all__ = [
    "InstallerUninstallCompositionV2",
    "InstallerUninstallCompositionV2Error",
    "UNINSTALL_ACTIVE_STEPS_V2",
    "build_active_uninstall_composition_v2",
    "recover_active_uninstall_composition_v2",
    "uninstall_maintenance_result_v2",
    "uninstall_operation_id_v2",
]
