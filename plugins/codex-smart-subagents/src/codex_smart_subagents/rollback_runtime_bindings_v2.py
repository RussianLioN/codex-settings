"""Производственная сборка внешних портов отката версии 2.

Фабрика не принимает идентичности кандидата и управляемые пути от вызывающего
кода. Они выводятся из доказательства отката, текущей installer-квитанции и
физически проверенной предыдущей активации. Единственный внешний исполняемый
путь — интерпретатор текущего процесса установки.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from .activation_gateway_v2 import GatewayLayout, _LIFECYCLE_SCHEMA_SHA256
from .activation_preparation_v2 import (
    capture_directory_binding_v2,
    capture_file_projection_v2,
)
from .candidate_ready_channel_v2 import (
    CandidateSpawnActionV2,
    build_controller_candidate_spawn_step_port_v2,
    candidate_controller_argv_v2,
    candidate_dispatch_intent_receipt_path_v2,
    load_candidate_dispatch_intent_receipt_v2,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .controller_transition_rehydration_v2 import (
    ControllerShutdownCommandIdsV2,
    ControllerTransitionRehydrationV2Error,
    rehydrate_candidate_acceptance_proof_v2,
    rehydrate_controller_shutdown_proof_v2,
)
from .installer_recovery_v2 import (
    InstallerRecoveryV2Error,
    RollbackEvidenceV2,
    _load_canonical_rollback_commit_chain_v2,
    _read_private_canonical_json as _read_recovery_private_canonical_json,
    _validate_receipt_activation_live,
)
from .installer_rollback_composition_v2 import (
    ROLLBACK_MATCHED_ACTIVE_STEPS_V2,
    InstallerRollbackCompositionV2Error,
    RollbackStepBindingV2,
    RollbackExternalArtifactsV2,
    RollbackExternalStepBindingsV2,
    _manifest_projection as _rollback_manifest_projection,
    _observe_symlink as _observe_rollback_symlink,
    build_rollback_candidate_spawn_binding_v2,
    build_rollback_controller_bindings_v2,
    build_rollback_external_step_bindings_v2,
    build_rollback_launcher_binding_v2,
    build_rollback_registry_binding_v2,
    build_rollback_shutdown_cleanup_binding_v2,
    build_rollback_verify_candidate_binding_v2,
    read_rollback_external_artifacts_v2,
)
from .operation_deadline_v2 import (
    checkpoint_current_operation_deadline_if_scoped_v2,
)
from .installer_update_composition_v2 import (
    CandidateSpawnAuthorizationStoreV2,
    InstallerUpdateCompositionV2Error,
    LauncherBindingV2,
    RegistryUpdatePlanV2,
    _ensure_pre_main_candidate_authorization_v2,
    _wrap_completed_port_with_candidate_successor_v2,
    build_controller_shutdown_constraint_v2,
    build_launcher_update_plan_v2,
    build_registry_update_plan_v2,
)
from .installer_update_controller_ports_v2 import (
    InstallerUpdateControllerPortsV2Error,
    build_update_controller_step_ports_v2,
    observe_controller_database_v2,
    observe_stopped_controller_database_v2,
)
from .installer_update_operation_v2 import UpdateStepPortV2
from .lifecycle_operation_v2 import (
    ActivationCommitPayloadIntentV2,
    ActivationTransitionLineageV2,
    OperationDefinitionV2,
    OperationJournalStoreV2,
    ProjectionV2,
    StepDefinitionV2,
)
from .operation_definition_rehydration_v2 import operation_definition_from_journal_v2
from .rollback_manifest_preparation_v2 import (
    RollbackManifestPreparationReceiptV2,
    rollback_operation_id_v2,
)
from .shutdown_socket_cleanup_v2 import (
    ShutdownSocketCleanupPlanV2,
    _plan_fingerprint as _shutdown_plan_fingerprint,
    build_shutdown_socket_cleanup_plan_v2,
    wait_for_shutdown_socket_orphan_v2,
)
from .state_store_v2 import _QUIESCENCE_QUERIES


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_GENERATION_ID = re.compile(r"^gen2_[0-9a-f]{64}$")
_PLUGIN_RELATIVE_PATH = Path("plugins/codex-smart-subagents")
_LAUNCHER_ROLES = {
    "codex-smart": "gateway",
    "codex-smart-subagents-admin": "admin",
}
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_CODEX_BINARY_BYTES = 1024 * 1024 * 1024
_ROLLBACK_EXTERNAL_KINDS = frozenset(
    {
        "maintenance_begin",
        "wait_runtime_quiescent",
        "maintenance_strengthen",
        "controller_shutdown",
        "shutdown_socket_cleanup",
        "registry_restore",
        "launchers_restore",
        "controller_candidate_spawn",
        "controller_previous_accept",
        "verify_candidate",
        "maintenance_resume",
    }
)


def _rehydrate_predecessor_shutdown_lineage_v2(
    *,
    evidence: RollbackEvidenceV2,
    previous_database: Path,
) -> ActivationTransitionLineageV2:
    """Доказать, какой переход оставил previous DB остановленным orphan."""

    try:
        lineage = ActivationTransitionLineageV2.from_document(
            evidence.current_receipt["transitionLineage"]
        )
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_PREDECESSOR_LINEAGE_INVALID",
            "current commit не содержит проверяемый transitionLineage",
        ) from error
    command_ids = lineage.shutdown_command_ids
    stopped = lineage.stopped_controller
    if (
        lineage.transition_kind not in {"update", "rollback"}
        or lineage.activation_proof_fingerprint is None
        or command_ids is None
        or stopped is None
        or stopped.operation_id != evidence.current_operation_id
        or stopped.activation_id != evidence.previous_activation_id
        or stopped.database_id
        != evidence.previous_database_binding.value.get("databaseId")
        or stopped.controller_identity
        != evidence.previous_receipt.get("controllerIdentity")
    ):
        _fail(
            "ROLLBACK_RUNTIME_PREDECESSOR_LINEAGE_INVALID",
            "transitionLineage не связан с previous activation",
        )
    try:
        stopped_database = observe_stopped_controller_database_v2(previous_database)
    except InstallerUpdateControllerPortsV2Error as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_PREDECESSOR_SHUTDOWN_INVALID",
            "previous DB не содержит точный остановленный orphan",
        ) from error
    if (
        stopped_database.value.get("controllerIdentity")
        != stopped.controller_identity
        or stopped_database.value.get("operationId") != stopped.operation_id
        or stopped_database.value.get("activationId") != stopped.activation_id
        or stopped_database.value.get("activationFingerprint")
        != evidence.previous_activation_projection.value.get(
            "activationFingerprint"
        )
        or stopped_database.value.get("databaseId") != stopped.database_id
        or stopped_database.value.get("controlEpoch") != stopped.control_epoch
    ):
        _fail(
            "ROLLBACK_RUNTIME_PREDECESSOR_SHUTDOWN_INVALID",
            "остановленный orphan previous DB расходится с commit-lineage",
        )
    try:
        proof = rehydrate_controller_shutdown_proof_v2(
            database_path=previous_database,
            activation_proof_fingerprint=lineage.activation_proof_fingerprint,
            operation_id=stopped.operation_id,
            command_ids=ControllerShutdownCommandIdsV2(
                maintenance_begin=command_ids.maintenance_begin,
                maintenance_strengthen=command_ids.maintenance_strengthen,
                shutdown=command_ids.shutdown,
            ),
        )
    except ControllerTransitionRehydrationV2Error as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_PREDECESSOR_SHUTDOWN_INVALID",
            "квитанции previous DB не подтверждают commit-lineage",
        ) from error
    if (
        not proof.complete
        or proof.operation_id != stopped.operation_id
        or proof.shutdown.new_control_epoch != stopped.control_epoch
    ):
        _fail(
            "ROLLBACK_RUNTIME_PREDECESSOR_SHUTDOWN_INVALID",
            "квитанции previous DB не доказывают остановку из commit-lineage",
        )
    return lineage


def rehydrate_rollback_evidence_v2(
    *,
    definition: OperationDefinitionV2,
    journal: Mapping[str, Any],
    preparation_receipt_path: Path,
) -> RollbackEvidenceV2:
    """Восстановить исходное rollback-evidence после частичного main-эффекта.

    Исходные ``before`` не переснимаются из живого манифеста или ссылки. Полный
    current manifest берётся из неизменяемой commit-квитанции текущей версии,
    а затем обязан совпасть с зафиксированными SHA, проекцией main definition,
    commit-lineage и ``evidenceFingerprint`` rollback-preparation receipt.
    Живые ссылка и манифест допускаются только в точных состояниях before/after,
    разрешённых состоянием соответствующего шага основного журнала.
    """

    if not isinstance(definition, OperationDefinitionV2):
        raise TypeError("definition must be OperationDefinitionV2")
    if not isinstance(journal, Mapping):
        raise TypeError("journal must be a mapping")
    if not isinstance(preparation_receipt_path, Path):
        raise TypeError("preparation_receipt_path must be a Path")
    try:
        persisted_definition = operation_definition_from_journal_v2(journal)
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_JOURNAL_INVALID",
            "основной journal нельзя строго разобрать",
        ) from error
    if persisted_definition != definition:
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "переданное определение отличается от main journal",
        )
    if (
        definition.kind != "rollback"
        or definition.operation != "rollback"
        or definition.execution_plan.machine_id != "rollback"
        or definition.execution_plan.selected_branch_id != "rollback-matched-active"
        or definition.execution_plan.composed_step_kinds
        != ROLLBACK_MATCHED_ACTIVE_STEPS_V2
        or tuple(step.kind for step in definition.mutable_steps)
        != ROLLBACK_MATCHED_ACTIVE_STEPS_V2[1:15]
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "main definition не является нормативным rollback-matched-active",
        )
    by_kind = {step.kind: step for step in definition.mutable_steps}
    if len(by_kind) != len(definition.mutable_steps):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "main definition содержит повторяющийся вид шага",
        )

    preparation_receipt_path = preparation_receipt_path.expanduser().absolute()
    receipt = _load_rollback_preparation_receipt(preparation_receipt_path)
    layout = GatewayLayout.for_codex_home(receipt.target_path.parent.parent)
    receipts_root = layout.receipts_root / receipt.installation_id
    activations_root = layout.managed_root / "activations"
    expected_rollback_receipt_path = (
        receipts_root / f"{receipt.operation_id}.rollback-preparation.json"
    )
    expected_prepared_path = (
        layout.manifest_root
        / "prepared-manifests"
        / (
            f"{receipt.operation_id}.{receipt.manifest_raw_sha256}.rollback-manifest.json"
        )
    )
    if (
        preparation_receipt_path.expanduser().absolute()
        != expected_rollback_receipt_path
        or receipt.prepared_path != expected_prepared_path
        or receipt.target_path != layout.manifest_path
        or definition.installation_id != receipt.installation_id
        or definition.operation_id != receipt.operation_id
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_ARTIFACT_INVALID",
            "rollback-preparation receipt не связан с GatewayLayout",
        )
    try:
        commit_chain = _load_canonical_rollback_commit_chain_v2(
            receipts_root=receipts_root,
            installation_id=receipt.installation_id,
            current_operation_id=receipt.current_operation_id,
            current_activation_id=receipt.current_activation_id,
            previous_activation_id=receipt.previous_activation_id,
            expected_previous_operation_id=receipt.previous_operation_id,
        )
    except InstallerRecoveryV2Error as error:
        if error.code in {
            "ROLLBACK_TRANSITION_LINEAGE_INVALID",
            "ROLLBACK_TRANSITION_SOURCE_INVALID",
        }:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_EVIDENCE_RECOVERY_LINEAGE_INVALID",
                str(error),
            ) from error
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_COMMIT_CHAIN_INVALID",
            str(error),
        ) from error

    current_receipt_path = commit_chain.current_receipt_path
    previous_receipt_path = commit_chain.previous_receipt_path
    current_receipt = commit_chain.current_receipt
    previous_receipt = commit_chain.previous_receipt
    _validate_main_layout_binding(
        definition=definition,
        by_kind=by_kind,
        layout=layout,
    )

    try:
        lineage = ActivationTransitionLineageV2.from_document(
            current_receipt["transitionLineage"]
        )
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_LINEAGE_INVALID",
            "current commit не содержит проверяемый transitionLineage",
        ) from error
    source = lineage.source_receipt
    stopped = lineage.stopped_controller
    expected_source_name = (
        f"{receipt.current_operation_id}.preparation.json"
        if lineage.transition_kind == "update"
        else f"{receipt.current_operation_id}.rollback-preparation.json"
    )
    if (
        lineage.transition_kind not in {"update", "rollback"}
        or source is None
        or stopped is None
        or source.path.parent != receipts_root
        or source.path.name != expected_source_name
        or receipt.current_preparation_receipt_path != source.path
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_LINEAGE_INVALID",
            "transitionLineage не задаёт канонический источник текущего перехода",
        )
    source_receipt, source_raw = _load_transition_source_receipt(source.path)
    if (
        source_receipt.get("installationId") != receipt.installation_id
        or source_receipt.get("operationId") != receipt.current_operation_id
        or source_receipt.get("receiptFingerprint") != source.receipt_fingerprint
        or hashlib.sha256(source_raw).hexdigest() != source.raw_sha256
        or receipt.current_preparation_receipt_fingerprint
        != source.receipt_fingerprint
        or receipt.current_preparation_receipt_sha256 != source.raw_sha256
        or receipt.transition_proof_snapshot_fingerprint
        != lineage.lineage_fingerprint
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_LINEAGE_INVALID",
            "rollback-preparation receipt расходится с источником commit-lineage",
        )

    current_manifest = ProjectionV2.from_document(current_receipt["manifest"])
    current_activation = ProjectionV2.from_document(current_receipt["activation"])
    previous_activation = ProjectionV2.from_document(previous_receipt["activation"])
    previous_database = ProjectionV2.from_document(previous_receipt["databaseBinding"])
    frozen_manifest_document = copy.deepcopy(
        dict(current_receipt["manifestDocument"])
    )
    previous_manifest_document = copy.deepcopy(
        dict(previous_receipt["manifestDocument"])
    )
    frozen_manifest_file = current_manifest.value.get("file")
    if (
        current_receipt["installationId"] != receipt.installation_id
        or previous_receipt["installationId"] != receipt.installation_id
        or current_receipt["operationId"] != receipt.current_operation_id
        or previous_receipt["operationId"] != receipt.previous_operation_id
        or type(frozen_manifest_file) is not dict
        or _rollback_manifest_projection(
            layout.manifest_path,
            frozen_manifest_document,
            file_projection=frozen_manifest_file,
        )
        != current_manifest
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_ARTIFACT_INVALID",
            "commit-квитанции расходятся с frozen manifest evidence",
        )

    link_definition = by_kind["activation_link_restore"]
    manifest_definition = by_kind["manifest_restore"]
    current_pointer = _pointer_from_activation(
        current_activation,
        target=link_definition.before.value.get("target"),
        activations_root=activations_root,
        code="ROLLBACK_EVIDENCE_RECOVERY_CURRENT_POINTER_INVALID",
    )
    previous_pointer = _pointer_from_activation(
        previous_activation,
        target=link_definition.expected_after.value.get("target"),
        activations_root=activations_root,
        code="ROLLBACK_EVIDENCE_RECOVERY_PREVIOUS_POINTER_INVALID",
    )
    if (
        current_activation.value.get("activationId") != receipt.current_activation_id
        or previous_activation.value.get("activationId")
        != receipt.previous_activation_id
        or frozen_manifest_document.get("installationId") != receipt.installation_id
        or frozen_manifest_document.get("activeActivation") != current_pointer
        or frozen_manifest_document.get("previousActivation") != previous_pointer
        or frozen_manifest_document.get("lastCommittedOperation")
        != receipt.current_operation_id
        or previous_manifest_document.get("installationId")
        != receipt.installation_id
        or previous_manifest_document.get("activeActivation") != previous_pointer
        or previous_manifest_document.get("lastCommittedOperation")
        != receipt.previous_operation_id
        or stopped.operation_id != receipt.current_operation_id
        or stopped.activation_id != receipt.previous_activation_id
        or stopped.database_id != previous_database.value.get("databaseId")
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_ARTIFACT_INVALID",
            "current/previous commit и transitionLineage расходятся",
        )
    _validate_link_definition_for_rehydration(
        definition=link_definition,
        path=layout.marketplace_link,
        current_pointer=current_pointer,
        previous_pointer=previous_pointer,
    )

    evidence_projection = {
        "installationId": receipt.installation_id,
        "currentOperationId": receipt.current_operation_id,
        "previousOperationId": receipt.previous_operation_id,
        "currentActivationId": receipt.current_activation_id,
        "previousActivationId": receipt.previous_activation_id,
        "manifestSha256": hashlib.sha256(
            canonical_json_bytes(frozen_manifest_document)
        ).hexdigest(),
        "currentReceiptFingerprint": current_receipt["receiptFingerprint"],
        "previousReceiptFingerprint": previous_receipt["receiptFingerprint"],
        "currentLinkTarget": current_pointer["symlinkTarget"],
    }
    if (
        domain_fingerprint("codex-smart/rollback-evidence/v2", evidence_projection)
        != receipt.evidence_fingerprint
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_FROZEN_MISMATCH",
            "evidenceFingerprint не связан с commit-lineage",
        )
    evidence = RollbackEvidenceV2(
        manifest_path=layout.manifest_path,
        receipts_root=receipts_root,
        activations_root=activations_root,
        marketplace_link=layout.marketplace_link,
        installation_id=receipt.installation_id,
        current_operation_id=receipt.current_operation_id,
        previous_operation_id=receipt.previous_operation_id,
        current_activation_id=receipt.current_activation_id,
        previous_activation_id=receipt.previous_activation_id,
        current_pointer=current_pointer,
        previous_pointer=previous_pointer,
        manifest_document=frozen_manifest_document,
        manifest_file_projection=frozen_manifest_file,
        current_receipt_path=current_receipt_path,
        previous_receipt_path=previous_receipt_path,
        current_receipt=current_receipt,
        previous_receipt=previous_receipt,
        current_manifest_projection=current_manifest,
        current_activation_projection=current_activation,
        previous_activation_projection=previous_activation,
        previous_database_binding=previous_database,
        evidence_fingerprint=receipt.evidence_fingerprint,
    )
    if (
        rollback_operation_id_v2(evidence) != definition.operation_id
        or manifest_definition.before != current_manifest
        or manifest_definition.expected_after != receipt.expected_after
        or manifest_definition.action
        != {
            "actionKind": "file-mutation",
            "method": "atomic-prepared-manifest-replace",
            "sourcePath": str(receipt.prepared_path),
            "targetPath": str(layout.manifest_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        }
        or receipt.previous_activation_tree_sha256
        != previous_activation.value.get("directory", {}).get("treeSha256")
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "link/manifest steps не связаны с замороженным evidence",
        )
    _validate_rollback_receipt_manifest(
        receipt=receipt,
        previous_manifest=previous_manifest_document,
        current_pointer=current_pointer,
        previous_pointer=previous_pointer,
    )
    _validate_definition_bundles(
        definition=definition,
        evidence=evidence,
        expected_manifest=receipt.expected_after,
    )
    try:
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
    except InstallerRecoveryV2Error as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_ACTIVATION_CHANGED",
            str(error),
        ) from error
    _validate_rehydrated_live_state(
        journal=journal,
        link_definition=link_definition,
        manifest_definition=manifest_definition,
        evidence=evidence,
        preparation_receipt=receipt,
    )
    return evidence


def build_rollback_runtime_external_bindings_v2(
    *,
    evidence: RollbackEvidenceV2,
    external_artifacts: RollbackExternalArtifactsV2,
    operation_id: str,
    readiness_token: str,
    codex_home: Path,
    state_home: Path,
    interpreter: Path,
    registry_command_runner: Any,
    readiness_window_ms: int = 30_000,
    shell_session_id: str = "rollback-v2",
    quiescence_timeout_ms: int = 30_000,
    runtime_environment: Mapping[str, str] | None = None,
    controller_port_options: Mapping[str, Any] | None = None,
    candidate_port_options: Mapping[str, Any] | None = None,
    process_start_marker_provider: Any | None = None,
) -> RollbackExternalStepBindingsV2:
    """Собрать все внешние rollback-порты без фиктивных проекций.

    Сборка выполняется до создания основного журнала. Повторная сборка после
    сбоя воспроизводит то же действие кандидата; долговечная dispatch-квитанция
    в ``CODEX_HOME`` не позволяет порту повторить ``Popen``.
    """

    if not isinstance(evidence, RollbackEvidenceV2):
        raise TypeError("evidence must be RollbackEvidenceV2")
    if not isinstance(external_artifacts, RollbackExternalArtifactsV2):
        raise TypeError("external_artifacts must be RollbackExternalArtifactsV2")
    if operation_id != rollback_operation_id_v2(evidence):
        _fail(
            "ROLLBACK_RUNTIME_OPERATION_ID_INVALID",
            "operationId не является детерминированным идентификатором отката",
        )
    if (
        type(readiness_token) is not str
        or not 32 <= len(readiness_token) <= 256
        or "\0" in readiness_token
        or len(readiness_token.encode("utf-8")) > 1024
    ):
        raise TypeError("readiness_token must be a safe string of length [32, 256]")
    if type(readiness_window_ms) is not int or not 1 <= readiness_window_ms <= 30_000:
        raise TypeError("readiness_window_ms must be in [1, 30000]")
    if (
        type(quiescence_timeout_ms) is not int
        or not 1 <= quiescence_timeout_ms <= 60_000
    ):
        raise TypeError("quiescence_timeout_ms must be in [1, 60000]")
    if (
        type(shell_session_id) is not str
        or not shell_session_id
        or len(shell_session_id) > 256
    ):
        raise TypeError("shell_session_id must be a non-empty bounded string")
    if not callable(registry_command_runner):
        raise TypeError("registry_command_runner must be callable")

    observed_artifacts = read_rollback_external_artifacts_v2(
        evidence=evidence,
        installer_receipt_path=external_artifacts.installer_receipt_path,
    )
    if observed_artifacts != external_artifacts:
        _fail(
            "ROLLBACK_RUNTIME_ARTIFACTS_CHANGED",
            "installer-квитанция либо внешние пути изменились после чтения",
        )
    receipt = external_artifacts.installer_receipt
    codex_home = _owned_directory(
        codex_home,
        allowed_modes={0o700, 0o755},
        code="ROLLBACK_RUNTIME_CODEX_HOME_INVALID",
    )
    state_home = _owned_directory(
        state_home,
        allowed_modes={0o700},
        code="ROLLBACK_RUNTIME_STATE_HOME_INVALID",
    )
    if (
        receipt.get("codexHome") != str(codex_home)
        or receipt.get("stateHome") != str(state_home)
        or evidence.manifest_document.get("stateHome") != str(state_home)
    ):
        _fail(
            "ROLLBACK_RUNTIME_ROOT_BINDING_INVALID",
            "CODEX_HOME или stateHome расходится с долговечными документами",
        )
    interpreter = _absolute_path(interpreter, "ROLLBACK_RUNTIME_INTERPRETER_INVALID")
    _require_executable(interpreter, "ROLLBACK_RUNTIME_INTERPRETER_INVALID")

    current_database = _database_binding_from_document(
        evidence.current_receipt.get("databaseBinding"),
        activation=evidence.current_activation_projection,
        state_home=state_home,
        code="ROLLBACK_RUNTIME_CURRENT_DATABASE_INVALID",
    )
    previous_database = _database_binding_path(
        evidence.previous_database_binding,
        activation=evidence.previous_activation_projection,
        state_home=state_home,
        code="ROLLBACK_RUNTIME_PREVIOUS_DATABASE_INVALID",
    )
    previous_runtime = _previous_activation_runtime(
        evidence=evidence,
        artifacts=external_artifacts,
        previous_database=previous_database,
    )

    registry_plan = build_registry_update_plan_v2(
        installation_id=evidence.installation_id,
        operation_id=operation_id,
        codex_binary=previous_runtime["snapshot_path"],
        codex_home=codex_home,
        working_directory=codex_home,
        marketplace_path=evidence.marketplace_link,
        previous_registered_marketplace_path=(
            external_artifacts.current_registered_marketplace
        ),
        registered_marketplace_path=(
            external_artifacts.previous_registered_marketplace
        ),
        plugin_relative_path=previous_runtime["plugin_relative_path"],
        plugin_version=previous_runtime["plugin_version"],
        install_policy=previous_runtime["install_policy"],
        auth_policy=previous_runtime["auth_policy"],
        receipt_directory=evidence.receipts_root,
        command_runner=registry_command_runner,
    )
    registry_binding = build_rollback_registry_binding_v2(plan=registry_plan)

    launcher_plan = build_launcher_update_plan_v2(
        installation_id=evidence.installation_id,
        operation_id=operation_id,
        bindings=_launcher_bindings(
            artifacts=external_artifacts,
            plugin_relative_path=previous_runtime["plugin_relative_path"],
        ),
    )
    launcher_binding = build_rollback_launcher_binding_v2(plan=launcher_plan)

    candidate_action = _candidate_action(
        evidence=evidence,
        operation_id=operation_id,
        readiness_token=readiness_token,
        readiness_window_ms=readiness_window_ms,
        interpreter=interpreter,
        server_entrypoint=previous_runtime["server_entrypoint"],
        state_home=state_home,
        snapshot_fingerprint=previous_runtime["snapshot_fingerprint"],
    )
    candidate_definition = StepDefinitionV2(
        kind="controller_candidate_spawn",
        command_id=None,
        action=candidate_action.to_document(),
        before=_absence_projection(
            path=candidate_action.private_ready_channel_path,
            installation_id=evidence.installation_id,
            operation_id=operation_id,
        ),
        expected_after=_candidate_expected_projection(candidate_action),
    )
    authorization_store = _candidate_authorization_store(
        evidence=evidence,
        operation_id=operation_id,
        action=candidate_action,
    )

    controller_before = observe_controller_database_v2(current_database)
    try:
        previous_controller_before = observe_stopped_controller_database_v2(
            previous_database
        )
    except InstallerUpdateControllerPortsV2Error as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_PREVIOUS_CONTROLLER_INVALID",
            "previous база не содержит доказанный остановленный orphan",
        ) from error
    predecessor_lineage = _rehydrate_predecessor_shutdown_lineage_v2(
        evidence=evidence,
        previous_database=previous_database,
    )
    rollback_controller_definitions = _controller_definitions(
        evidence=evidence,
        operation_id=operation_id,
        codex_home=codex_home,
        state_home=state_home,
        controller_before=controller_before,
        previous_controller_before=previous_controller_before,
        candidate_action=candidate_action,
        shell_session_id=shell_session_id,
        quiescence_timeout_ms=quiescence_timeout_ms,
    )
    update_controller_definitions, update_accept_definition = (
        _update_controller_definitions(rollback_controller_definitions)
    )
    shutdown_definition = rollback_controller_definitions["controller_shutdown"]
    shutdown_plan = build_shutdown_socket_cleanup_plan_v2(
        installation_id=evidence.installation_id,
        activation_proof_fingerprint=evidence.evidence_fingerprint,
        operation_id=operation_id,
        shutdown_command_id=str(shutdown_definition.command_id),
        state_home=state_home,
        controller_state=_shutdown_controller_state(controller_before),
    )

    def prove_shutdown_orphan(shutdown: Any) -> Any:
        marker_arguments = (
            {}
            if process_start_marker_provider is None
            else {"process_start_marker_provider": process_start_marker_provider}
        )
        return wait_for_shutdown_socket_orphan_v2(
            plan=shutdown_plan,
            shutdown=shutdown,
            **marker_arguments,
        )

    controller_options = _port_options(
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
            "maintenance_reason_code",
            "expected_orphan_operation_id",
            "shell_session_id",
            "shutdown_orphan_prover",
        },
        label="controller_port_options",
    )
    update_controller_ports = build_update_controller_step_ports_v2(
        operation_id=operation_id,
        activation_proof_fingerprint=evidence.evidence_fingerprint,
        shutdown_cleanup_plan_fingerprint=shutdown_plan.plan_fingerprint,
        codex_home=codex_home,
        current_database_path=current_database,
        candidate_database_path=previous_database,
        definitions=update_controller_definitions,
        candidate_spawn_action=candidate_action,
        maintenance_reason_code="ROLLBACK",
        expected_orphan_operation_id=(
            predecessor_lineage.stopped_controller.operation_id
        ),
        shell_session_id=shell_session_id,
        shutdown_orphan_prover=prove_shutdown_orphan,
        **controller_options,
    )
    rollback_controller_ports = {
        kind: update_controller_ports[kind]
        for kind in (
            "maintenance_begin",
            "wait_runtime_quiescent",
            "maintenance_strengthen",
            "controller_shutdown",
            "maintenance_resume",
        )
    }
    rollback_controller_ports["controller_previous_accept"] = _renamed_step_port(
        source=update_controller_ports["controller_accept"],
        source_definition=update_accept_definition,
        target_definition=rollback_controller_definitions["controller_previous_accept"],
    )
    shutdown_ids = ControllerShutdownCommandIdsV2(
        maintenance_begin=str(
            rollback_controller_definitions["maintenance_begin"].command_id
        ),
        maintenance_strengthen=str(
            rollback_controller_definitions["maintenance_strengthen"].command_id
        ),
        shutdown=str(rollback_controller_definitions["controller_shutdown"].command_id),
    )

    def shutdown_proof_provider() -> Any:
        return rehydrate_controller_shutdown_proof_v2(
            database_path=current_database,
            activation_proof_fingerprint=evidence.evidence_fingerprint,
            operation_id=operation_id,
            command_ids=shutdown_ids,
        )

    accept_definition = rollback_controller_definitions["controller_previous_accept"]

    def acceptance_proof_provider() -> Any:
        shutdown = shutdown_proof_provider()
        return rehydrate_candidate_acceptance_proof_v2(
            database_path=previous_database,
            activation_proof_fingerprint=evidence.evidence_fingerprint,
            shutdown_proof_fingerprint=shutdown.proof_fingerprint,
            operation_id=operation_id,
            activation_id=evidence.previous_activation_id,
            database_id=str(evidence.previous_database_binding.value["databaseId"]),
            command_id=str(accept_definition.command_id),
        )

    shutdown_binding = build_rollback_shutdown_cleanup_binding_v2(
        plan=shutdown_plan,
        shutdown_constraint=shutdown_definition.expected_after,
        shutdown_proof_provider=shutdown_proof_provider,
        process_start_marker_provider=process_start_marker_provider,
    )

    candidate_options = _port_options(
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
    persisted_readiness_token = _persist_fresh_candidate_authorization(
        evidence=evidence,
        codex_home=codex_home,
        operation_id=operation_id,
        store=authorization_store,
        readiness_token=readiness_token,
    )

    def observe_accepted_controller() -> ProjectionV2:
        definition = rollback_controller_definitions["controller_previous_accept"]
        port = rollback_controller_ports["controller_previous_accept"]
        observed = port.observe(definition)
        if not port.matches_after(observed, definition):
            _fail(
                "ROLLBACK_CANDIDATE_SUCCESSOR_INVALID",
                "controller_previous_accept не доказал принятого преемника",
            )
        return observed

    candidate_port = _wrap_candidate_authorization_port(
        port=build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=candidate_action,
            codex_home=codex_home,
            state_home=state_home,
            wrapper_path=previous_runtime["wrapper_path"],
            readiness_token=persisted_readiness_token,
            accepted_controller_observer=observe_accepted_controller,
            runtime_environment=(
                None if runtime_environment is None else dict(runtime_environment)
            ),
            **candidate_options,
        ),
        store=authorization_store,
    )
    rollback_controller_ports["controller_shutdown"] = (
        _wrap_completed_port_with_candidate_successor_v2(
            port=rollback_controller_ports["controller_shutdown"],
            candidate_port=candidate_port,
            candidate_definition=candidate_definition,
            accept_port=rollback_controller_ports["controller_previous_accept"],
            accept_definition=rollback_controller_definitions[
                "controller_previous_accept"
            ],
        )
    )
    controller_bindings = build_rollback_controller_bindings_v2(
        definitions=rollback_controller_definitions,
        ports=rollback_controller_ports,
    )
    shutdown_binding = RollbackStepBindingV2(
        definition=shutdown_binding.definition,
        port=_wrap_completed_port_with_candidate_successor_v2(
            port=shutdown_binding.port,
            candidate_port=candidate_port,
            candidate_definition=candidate_definition,
            accept_port=rollback_controller_ports["controller_previous_accept"],
            accept_definition=rollback_controller_definitions[
                "controller_previous_accept"
            ],
        ),
    )
    candidate_binding = build_rollback_candidate_spawn_binding_v2(
        definition=candidate_definition,
        candidate_spawn_action=candidate_action,
        port=candidate_port,
    )
    verify_binding = build_rollback_verify_candidate_binding_v2(
        evidence=evidence,
        operation_id=operation_id,
        acceptance_proof_provider=acceptance_proof_provider,
    )
    return build_rollback_external_step_bindings_v2(
        evidence=evidence,
        operation_id=operation_id,
        controller_bindings=controller_bindings,
        shutdown_socket_cleanup=shutdown_binding,
        registry_restore=registry_binding,
        launchers_restore=launcher_binding,
        controller_candidate_spawn=candidate_binding,
        verify_candidate=verify_binding,
    )


def recover_rollback_runtime_external_bindings_v2(
    *,
    evidence: RollbackEvidenceV2,
    external_artifacts: RollbackExternalArtifactsV2,
    definition: OperationDefinitionV2,
    readiness_token: str | None,
    codex_home: Path,
    state_home: Path,
    registry_command_runner: Any,
    shell_session_id: str = "rollback-v2",
    runtime_environment: Mapping[str, str] | None = None,
    controller_port_options: Mapping[str, Any] | None = None,
    candidate_port_options: Mapping[str, Any] | None = None,
    process_start_marker_provider: Any | None = None,
) -> RollbackExternalStepBindingsV2:
    """Восстановить внешние порты только из сохранённого main definition.

    После долговечной dispatch-квитанции сырой секрет запрещён и в
    candidate-порт передаётся ``None``. Существующий ready-сокет в этом режиме
    является допустимым последующим эффектом и проверяется самим reconnect.
    """

    if not isinstance(evidence, RollbackEvidenceV2):
        raise TypeError("evidence must be RollbackEvidenceV2")
    if not isinstance(external_artifacts, RollbackExternalArtifactsV2):
        raise TypeError("external_artifacts must be RollbackExternalArtifactsV2")
    if not isinstance(definition, OperationDefinitionV2):
        raise TypeError("definition must be OperationDefinitionV2")
    operation_id = rollback_operation_id_v2(evidence)
    if (
        definition.kind != "rollback"
        or definition.operation != "rollback"
        or definition.installation_id != evidence.installation_id
        or definition.operation_id != operation_id
    ):
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_DEFINITION_INVALID",
            "сохранённое определение не является точным откатом",
        )
    persisted = {step.kind: step for step in definition.mutable_steps}
    if len(persisted) != len(definition.mutable_steps) or not (
        _ROLLBACK_EXTERNAL_KINDS.issubset(persisted)
    ):
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_DEFINITION_INVALID",
            "main definition не содержит единственный полный внешний набор",
        )
    observed_artifacts = read_rollback_external_artifacts_v2(
        evidence=evidence,
        installer_receipt_path=external_artifacts.installer_receipt_path,
    )
    if observed_artifacts != external_artifacts:
        _fail(
            "ROLLBACK_RUNTIME_ARTIFACTS_CHANGED",
            "installer-квитанция либо внешние пути изменились после чтения",
        )
    receipt = external_artifacts.installer_receipt
    codex_home = _owned_directory(
        codex_home,
        allowed_modes={0o700, 0o755},
        code="ROLLBACK_RUNTIME_CODEX_HOME_INVALID",
    )
    state_home = _owned_directory(
        state_home,
        allowed_modes={0o700},
        code="ROLLBACK_RUNTIME_STATE_HOME_INVALID",
    )
    if (
        receipt.get("codexHome") != str(codex_home)
        or receipt.get("stateHome") != str(state_home)
        or evidence.manifest_document.get("stateHome") != str(state_home)
    ):
        _fail(
            "ROLLBACK_RUNTIME_ROOT_BINDING_INVALID",
            "CODEX_HOME или stateHome расходится с долговечными документами",
        )
    current_database = _database_binding_from_document(
        evidence.current_receipt.get("databaseBinding"),
        activation=evidence.current_activation_projection,
        state_home=state_home,
        code="ROLLBACK_RUNTIME_CURRENT_DATABASE_INVALID",
    )
    previous_database = _database_binding_path(
        evidence.previous_database_binding,
        activation=evidence.previous_activation_projection,
        state_home=state_home,
        code="ROLLBACK_RUNTIME_PREVIOUS_DATABASE_INVALID",
    )
    previous_runtime = _previous_activation_runtime(
        evidence=evidence,
        artifacts=external_artifacts,
        previous_database=previous_database,
    )

    candidate_definition = persisted["controller_candidate_spawn"]
    try:
        candidate_action = CandidateSpawnActionV2.from_mapping(
            candidate_definition.action
        )
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_RECOVERY_CANDIDATE_INVALID",
            "сохранённый candidate action повреждён",
        ) from error
    _validate_recovery_candidate_action(
        action=candidate_action,
        definition=candidate_definition,
        evidence=evidence,
        state_home=state_home,
        server_entrypoint=previous_runtime["server_entrypoint"],
        snapshot_fingerprint=previous_runtime["snapshot_fingerprint"],
    )
    authorization_store = _candidate_authorization_store(
        evidence=evidence,
        operation_id=operation_id,
        action=candidate_action,
    )
    candidate_runtime_token = _recover_candidate_authorization(
        codex_home=codex_home,
        action=candidate_action,
        store=authorization_store,
        supplied_readiness_token=readiness_token,
    )

    registry_definition = persisted["registry_restore"]
    registry_plan = RegistryUpdatePlanV2(
        installation_id=evidence.installation_id,
        operation_id=operation_id,
        codex_binary=previous_runtime["snapshot_path"],
        codex_home=codex_home,
        working_directory=codex_home,
        marketplace_path=evidence.marketplace_link,
        previous_registered_marketplace_path=(
            external_artifacts.current_registered_marketplace
        ),
        registered_marketplace_path=(
            external_artifacts.previous_registered_marketplace
        ),
        plugin_relative_path=previous_runtime["plugin_relative_path"],
        plugin_version=previous_runtime["plugin_version"],
        install_policy=previous_runtime["install_policy"],
        auth_policy=previous_runtime["auth_policy"],
        receipt_directory=evidence.receipts_root,
        command_runner=registry_command_runner,
        before_registry=registry_definition.before,
        timeout_ms=int(registry_definition.action.get("timeoutMs", 0)),
    )
    registry_binding = build_rollback_registry_binding_v2(plan=registry_plan)
    if registry_binding.definition != registry_definition:
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_BINDING_CHANGED",
            "runtime registry plan не воспроизводит сохранённый шаг",
        )

    launcher_plan = build_launcher_update_plan_v2(
        installation_id=evidence.installation_id,
        operation_id=operation_id,
        bindings=_launcher_bindings(
            artifacts=external_artifacts,
            plugin_relative_path=previous_runtime["plugin_relative_path"],
        ),
    )
    launcher_binding = build_rollback_launcher_binding_v2(plan=launcher_plan)
    if launcher_binding.definition != persisted["launchers_restore"]:
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_BINDING_CHANGED",
            "runtime launcher plan не воспроизводит сохранённый шаг",
        )

    controller_definitions = {
        kind: persisted[kind]
        for kind in (
            "maintenance_begin",
            "wait_runtime_quiescent",
            "maintenance_strengthen",
            "controller_shutdown",
            "controller_previous_accept",
            "maintenance_resume",
        )
    }
    predecessor_lineage = _rehydrate_predecessor_shutdown_lineage_v2(
        evidence=evidence,
        previous_database=previous_database,
    )
    update_definitions, update_accept_definition = _update_controller_definitions(
        controller_definitions
    )
    shutdown_plan = _rehydrate_shutdown_plan(
        evidence=evidence,
        operation_id=operation_id,
        definition=persisted["shutdown_socket_cleanup"],
    )

    def prove_shutdown_orphan(shutdown: Any) -> Any:
        marker_arguments = (
            {}
            if process_start_marker_provider is None
            else {"process_start_marker_provider": process_start_marker_provider}
        )
        return wait_for_shutdown_socket_orphan_v2(
            plan=shutdown_plan,
            shutdown=shutdown,
            **marker_arguments,
        )

    controller_options = _port_options(
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
            "maintenance_reason_code",
            "expected_orphan_operation_id",
            "shell_session_id",
            "shutdown_orphan_prover",
        },
        label="controller_port_options",
    )
    update_ports = build_update_controller_step_ports_v2(
        operation_id=operation_id,
        activation_proof_fingerprint=evidence.evidence_fingerprint,
        shutdown_cleanup_plan_fingerprint=shutdown_plan.plan_fingerprint,
        codex_home=codex_home,
        current_database_path=current_database,
        candidate_database_path=previous_database,
        definitions=update_definitions,
        candidate_spawn_action=candidate_action,
        maintenance_reason_code="ROLLBACK",
        expected_orphan_operation_id=(
            predecessor_lineage.stopped_controller.operation_id
        ),
        shell_session_id=shell_session_id,
        shutdown_orphan_prover=prove_shutdown_orphan,
        **controller_options,
    )
    controller_ports = {
        kind: update_ports[kind]
        for kind in (
            "maintenance_begin",
            "wait_runtime_quiescent",
            "maintenance_strengthen",
            "controller_shutdown",
            "maintenance_resume",
        )
    }
    controller_ports["controller_previous_accept"] = _renamed_step_port(
        source=update_ports["controller_accept"],
        source_definition=update_accept_definition,
        target_definition=controller_definitions["controller_previous_accept"],
    )
    shutdown_ids = ControllerShutdownCommandIdsV2(
        maintenance_begin=str(controller_definitions["maintenance_begin"].command_id),
        maintenance_strengthen=str(
            controller_definitions["maintenance_strengthen"].command_id
        ),
        shutdown=str(controller_definitions["controller_shutdown"].command_id),
    )

    def shutdown_proof_provider() -> Any:
        return rehydrate_controller_shutdown_proof_v2(
            database_path=current_database,
            activation_proof_fingerprint=evidence.evidence_fingerprint,
            operation_id=operation_id,
            command_ids=shutdown_ids,
        )

    accept_definition = controller_definitions["controller_previous_accept"]

    def acceptance_proof_provider() -> Any:
        shutdown = shutdown_proof_provider()
        return rehydrate_candidate_acceptance_proof_v2(
            database_path=previous_database,
            activation_proof_fingerprint=evidence.evidence_fingerprint,
            shutdown_proof_fingerprint=shutdown.proof_fingerprint,
            operation_id=operation_id,
            activation_id=evidence.previous_activation_id,
            database_id=str(evidence.previous_database_binding.value["databaseId"]),
            command_id=str(accept_definition.command_id),
        )

    shutdown_binding = build_rollback_shutdown_cleanup_binding_v2(
        plan=shutdown_plan,
        shutdown_constraint=controller_definitions[
            "controller_shutdown"
        ].expected_after,
        shutdown_proof_provider=shutdown_proof_provider,
        process_start_marker_provider=process_start_marker_provider,
    )
    if shutdown_binding.definition != persisted["shutdown_socket_cleanup"]:
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_BINDING_CHANGED",
            "runtime cleanup plan не воспроизводит сохранённый шаг",
        )

    candidate_options = _port_options(
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
        definition = controller_definitions["controller_previous_accept"]
        port = controller_ports["controller_previous_accept"]
        observed = port.observe(definition)
        if not port.matches_after(observed, definition):
            _fail(
                "ROLLBACK_CANDIDATE_SUCCESSOR_INVALID",
                "controller_previous_accept не доказал принятого преемника",
            )
        return observed

    candidate_port = _wrap_candidate_authorization_port(
        port=build_controller_candidate_spawn_step_port_v2(
            candidate_spawn_action=candidate_action,
            codex_home=codex_home,
            state_home=state_home,
            wrapper_path=previous_runtime["wrapper_path"],
            readiness_token=candidate_runtime_token,
            accepted_controller_observer=observe_accepted_controller,
            runtime_environment=(
                None if runtime_environment is None else dict(runtime_environment)
            ),
            **candidate_options,
        ),
        store=authorization_store,
    )
    controller_ports["controller_shutdown"] = (
        _wrap_completed_port_with_candidate_successor_v2(
            port=controller_ports["controller_shutdown"],
            candidate_port=candidate_port,
            candidate_definition=candidate_definition,
            accept_port=controller_ports["controller_previous_accept"],
            accept_definition=controller_definitions["controller_previous_accept"],
        )
    )
    controller_bindings = build_rollback_controller_bindings_v2(
        definitions=controller_definitions,
        ports=controller_ports,
    )
    shutdown_binding = RollbackStepBindingV2(
        definition=shutdown_binding.definition,
        port=_wrap_completed_port_with_candidate_successor_v2(
            port=shutdown_binding.port,
            candidate_port=candidate_port,
            candidate_definition=candidate_definition,
            accept_port=controller_ports["controller_previous_accept"],
            accept_definition=controller_definitions["controller_previous_accept"],
        ),
    )
    candidate_binding = build_rollback_candidate_spawn_binding_v2(
        definition=candidate_definition,
        candidate_spawn_action=candidate_action,
        port=candidate_port,
    )
    verify_binding = build_rollback_verify_candidate_binding_v2(
        evidence=evidence,
        operation_id=operation_id,
        acceptance_proof_provider=acceptance_proof_provider,
    )
    if verify_binding.definition != persisted["verify_candidate"]:
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_BINDING_CHANGED",
            "verify binding не воспроизводит сохранённый шаг",
        )
    recovered = build_rollback_external_step_bindings_v2(
        evidence=evidence,
        operation_id=operation_id,
        controller_bindings=controller_bindings,
        shutdown_socket_cleanup=shutdown_binding,
        registry_restore=registry_binding,
        launchers_restore=launcher_binding,
        controller_candidate_spawn=candidate_binding,
        verify_candidate=verify_binding,
    )
    for kind in _ROLLBACK_EXTERNAL_KINDS:
        if recovered.require(kind).definition != persisted[kind]:
            _fail(
                "ROLLBACK_RUNTIME_RECOVERY_BINDING_CHANGED",
                f"runtime binding {kind} отличается от main definition",
            )
    return recovered


def _load_rollback_preparation_receipt(
    path: Path,
) -> RollbackManifestPreparationReceiptV2:
    absolute = path.expanduser().absolute()
    try:
        return RollbackManifestPreparationReceiptV2.from_path(absolute)
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_PREPARATION_RECEIPT_INVALID",
            "rollback-preparation receipt недоступна либо повреждена",
        ) from error


def _load_transition_source_receipt(
    path: Path,
) -> tuple[dict[str, Any], bytes]:
    try:
        document, raw = _read_recovery_private_canonical_json(
            path,
            "ROLLBACK_EVIDENCE_RECOVERY_TRANSITION_SOURCE_INVALID",
        )
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_TRANSITION_SOURCE_INVALID",
            "квитанция-источник текущего перехода недоступна либо повреждена",
        ) from error
    return document, raw


def _pointer_from_activation(
    activation: ProjectionV2,
    *,
    target: Any,
    activations_root: Path,
    code: str,
) -> dict[str, Any]:
    value = activation.value
    activation_id = value.get("activationId")
    activation_fingerprint = value.get("activationFingerprint")
    generation_id = value.get("generationId")
    database_id = value.get("databaseId")
    expected_target = f"activations/{activation_id}/marketplace"
    directory = value.get("directory")
    if (
        activation.schema_id != "activation-v2"
        or type(activation_id) is not str
        or _ACTIVATION_ID.fullmatch(activation_id) is None
        or type(activation_fingerprint) is not str
        or _SHA256.fullmatch(activation_fingerprint) is None
        or activation_id != "act2_" + activation_fingerprint
        or type(generation_id) is not str
        or _GENERATION_ID.fullmatch(generation_id) is None
        or type(database_id) is not str
        or _DATABASE_ID.fullmatch(database_id) is None
        or target != expected_target
        or type(directory) is not dict
        or directory.get("path") != str(activations_root / activation_id)
    ):
        _fail(code, "activation projection не задаёт единственный pointer")
    return {
        "activationId": activation_id,
        "activationFingerprint": activation_fingerprint,
        "symlinkTarget": expected_target,
        "generationId": generation_id,
        "databaseId": database_id,
    }


def _validate_main_layout_binding(
    *,
    definition: OperationDefinitionV2,
    by_kind: Mapping[str, StepDefinitionV2],
    layout: GatewayLayout,
) -> None:
    terminal = definition.terminal
    gate_entries = definition.gate_close.before.value.get("entries")
    terminal_entries = (
        None
        if terminal is None
        else terminal.journal_absence_target.value.get("entries")
    )
    if (
        definition.gate_close.action
        != {
            "actionKind": "journal-transition",
            "transition": "gate-close",
            "journalPath": str(layout.journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        }
        or type(gate_entries) is not list
        or len(gate_entries) != 1
        or type(gate_entries[0]) is not dict
        or gate_entries[0].get("path") != str(layout.journal_path)
        or by_kind["recovery_forward_only"].action
        != {
            "actionKind": "journal-transition",
            "transition": "forward-only",
            "journalPath": str(layout.journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        }
        or terminal is None
        or terminal.freeze.action
        != {
            "actionKind": "journal-transition",
            "transition": "freeze-delete-intent",
            "journalPath": str(layout.journal_path),
            "durability": "FSYNC_FILE_AND_PARENT",
        }
        or type(terminal_entries) is not list
        or len(terminal_entries) != 1
        or type(terminal_entries[0]) is not dict
        or terminal_entries[0].get("path") != str(layout.journal_path)
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "main definition не связан с нормативным journal GatewayLayout",
        )


def _validate_link_definition_for_rehydration(
    *,
    definition: StepDefinitionV2,
    path: Path,
    current_pointer: Mapping[str, Any],
    previous_pointer: Mapping[str, Any],
) -> None:
    if (
        definition.kind != "activation_link_restore"
        or definition.command_id is not None
        or definition.before.schema_id != "symlink-object-v2"
        or definition.expected_after.schema_id != "symlink-object-v2"
        or definition.before.value.get("path") != str(path)
        or definition.expected_after.value.get("path") != str(path)
        or definition.before.value.get("target") != current_pointer["symlinkTarget"]
        or definition.expected_after.value.get("target")
        != previous_pointer["symlinkTarget"]
        or definition.action
        != {
            "actionKind": "symlink-mutation",
            "method": "restore",
            "path": str(path),
            "target": previous_pointer["symlinkTarget"],
            "durability": "FSYNC_PARENT",
        }
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "activation_link_restore не содержит точные frozen before/after",
        )


def _validate_rollback_receipt_manifest(
    *,
    receipt: RollbackManifestPreparationReceiptV2,
    previous_manifest: Mapping[str, Any],
    current_pointer: Mapping[str, Any],
    previous_pointer: Mapping[str, Any],
) -> None:
    base = copy.deepcopy(dict(previous_manifest))
    base["activeActivation"] = copy.deepcopy(dict(previous_pointer))
    base["previousActivation"] = copy.deepcopy(dict(current_pointer))
    base["lastCommittedOperation"] = receipt.operation_id
    candidates = [base]
    extensions = receipt.manifest_document.get("extensions")
    digest = (
        None
        if type(extensions) is not dict
        else extensions.get("installerSourceDigest")
    )
    if type(digest) is str and _SHA256.fullmatch(digest) is not None:
        base_extensions = base.get("extensions")
        if type(base_extensions) is dict:
            with_digest = copy.deepcopy(base)
            with_digest["extensions"] = {
                **copy.deepcopy(base_extensions),
                "installerSourceDigest": digest,
            }
            candidates.append(with_digest)
    if not any(candidate == receipt.manifest_document for candidate in candidates):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_PREPARATION_RECEIPT_INVALID",
            "rollback manifest не выводится из previous commit manifestDocument",
        )


def _validate_definition_bundles(
    *,
    definition: OperationDefinitionV2,
    evidence: RollbackEvidenceV2,
    expected_manifest: ProjectionV2,
) -> None:
    terminal = definition.terminal
    payload = None if terminal is None else terminal.receipt_payload
    if (
        definition.discovery_before.manifest != evidence.current_manifest_projection
        or definition.discovery_before.activation
        != evidence.current_activation_projection
        or definition.fenced_before != definition.discovery_before
        or definition.desired is None
        or definition.desired.manifest != expected_manifest
        or definition.desired.activation != evidence.previous_activation_projection
        or terminal is None
        or terminal.terminal_kind != "COMMIT"
        or terminal.receipt_kind != "activation-commit"
        or terminal.receipt_path
        != evidence.receipts_root / f"{definition.operation_id}.commit.json"
        or not isinstance(payload, ActivationCommitPayloadIntentV2)
        or payload.manifest != expected_manifest
        or payload.activation != evidence.previous_activation_projection
        or payload.database_binding != evidence.previous_database_binding
        or payload.controller_identity
        != evidence.previous_receipt.get("controllerIdentity")
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_DEFINITION_INVALID",
            "discovery/desired/terminal не связывают current и previous evidence",
        )


def _validate_rehydrated_live_state(
    *,
    journal: Mapping[str, Any],
    link_definition: StepDefinitionV2,
    manifest_definition: StepDefinitionV2,
    evidence: RollbackEvidenceV2,
    preparation_receipt: RollbackManifestPreparationReceiptV2,
) -> None:
    try:
        observed_link = _observe_rollback_symlink(evidence.marketplace_link)
        live_manifest, live_raw = _read_recovery_private_canonical_json(
            evidence.manifest_path,
            "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
        )
        observed_manifest = _rollback_manifest_projection(
            evidence.manifest_path,
            live_manifest,
        )
    except InstallerRollbackCompositionV2Error:
        raise
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
            "живые link/manifest не доказаны как frozen before/after",
        ) from error
    records = {
        step.get("kind"): step
        for step in journal.get("steps", [])
        if isinstance(step, Mapping)
    }
    if len(records) != len(journal.get("steps", [])):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_JOURNAL_INVALID",
            "journal содержит повторяющиеся либо повреждённые шаги",
        )
    _validate_live_step_state(
        record=records.get("activation_link_restore"),
        observed=observed_link,
        definition=link_definition,
    )
    _validate_live_step_state(
        record=records.get("manifest_restore"),
        observed=observed_manifest,
        definition=manifest_definition,
    )
    current_raw = canonical_json_bytes(evidence.manifest_document)
    prepared_raw = canonical_json_bytes(preparation_receipt.manifest_document)
    if observed_manifest == manifest_definition.before:
        if live_raw != current_raw:
            _fail(
                "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
                "manifest before имеет иной канонический документ",
            )
        if not os.path.lexists(preparation_receipt.prepared_path):
            _fail(
                "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
                "manifest before существует без prepared source",
            )
        try:
            prepared_document, observed_prepared_raw = (
                _read_recovery_private_canonical_json(
                    preparation_receipt.prepared_path,
                    "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
                )
            )
            observed_prepared_file = capture_file_projection_v2(
                preparation_receipt.prepared_path,
                schema_sha256=(
                    preparation_receipt.prepared_manifest_file.schema_sha256
                ),
            )
            observed_prepared_parent = capture_directory_binding_v2(
                preparation_receipt.prepared_path.parent,
                schema_sha256=(
                    preparation_receipt.prepared_manifest_parent.schema_sha256
                ),
            )
        except Exception as error:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
                "prepared source нельзя физически доказать",
            ) from error
        if (
            prepared_document != dict(preparation_receipt.manifest_document)
            or observed_prepared_raw != prepared_raw
            or observed_prepared_file != preparation_receipt.prepared_manifest_file
            or observed_prepared_parent != preparation_receipt.prepared_manifest_parent
        ):
            _fail(
                "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
                "prepared source изменён после rollback preparation",
            )
    elif observed_manifest == manifest_definition.expected_after:
        if live_raw != prepared_raw or os.path.lexists(
            preparation_receipt.prepared_path
        ):
            _fail(
                "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
                "manifest after неоднозначен с prepared source",
            )
    else:
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
            "manifest не равен frozen before/after",
        )
    if (
        observed_manifest == manifest_definition.expected_after
        and observed_link != link_definition.expected_after
    ):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
            "manifest after невозможен до activation link after",
        )


def _validate_live_step_state(
    *,
    record: Any,
    observed: ProjectionV2,
    definition: StepDefinitionV2,
) -> None:
    if not isinstance(record, Mapping):
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_JOURNAL_INVALID",
            f"journal не содержит шаг {definition.kind}",
        )
    state = record.get("state")
    if state == "PLANNED":
        accepted = observed == definition.before
    elif state == "INTENT_DURABLE":
        accepted = observed in (definition.before, definition.expected_after)
    elif state == "COMPLETED":
        try:
            persisted_after = ProjectionV2.from_document(record["observedAfter"])
        except Exception as error:
            raise InstallerRollbackCompositionV2Error(
                "ROLLBACK_EVIDENCE_RECOVERY_JOURNAL_INVALID",
                f"completed {definition.kind} не содержит observedAfter",
            ) from error
        accepted = (
            observed == definition.expected_after
            and persisted_after == definition.expected_after
        )
    else:
        accepted = False
    if not accepted:
        _fail(
            "ROLLBACK_EVIDENCE_RECOVERY_LIVE_STATE_AMBIGUOUS",
            f"живое состояние {definition.kind} расходится с journal state",
        )


def _validate_recovery_candidate_action(
    *,
    action: CandidateSpawnActionV2,
    definition: StepDefinitionV2,
    evidence: RollbackEvidenceV2,
    state_home: Path,
    server_entrypoint: Path,
    snapshot_fingerprint: str,
) -> None:
    try:
        interpreter = Path(action.argv[0])
        expected_argv = candidate_controller_argv_v2(
            interpreter=interpreter,
            server_entrypoint=server_entrypoint,
        )
        expected_candidate = _derived_identifier(
            "cand2", action.operation_id, "candidate"
        )
        expected_start = _derived_identifier(
            "cs2", action.operation_id, "controller-start"
        )
        action.private_ready_channel_path.relative_to(state_home)
    except (OSError, TypeError, ValueError) as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_RECOVERY_CANDIDATE_INVALID",
            "runtime-пути сохранённого candidate action неверны",
        ) from error
    _require_executable(interpreter, "ROLLBACK_RUNTIME_INTERPRETER_INVALID")
    if (
        definition.kind != "controller_candidate_spawn"
        or definition.command_id is not None
        or definition.action != action.to_document()
        or definition.before.schema_id != "absence-proof-v2"
        or definition.expected_after != _candidate_expected_projection(action)
        or action.operation_id != rollback_operation_id_v2(evidence)
        or action.candidate_id != expected_candidate
        or action.controller_start_id != expected_start
        or action.controller_identity
        != evidence.previous_receipt.get("controllerIdentity")
        or action.activation_id != evidence.previous_activation_id
        or action.activation_fingerprint
        != evidence.previous_activation_projection.value.get("activationFingerprint")
        or action.database_id
        != evidence.previous_database_binding.value.get("databaseId")
        or action.argv != expected_argv
        or action.snapshot_fingerprint != snapshot_fingerprint
        or action.private_ready_channel_path.parent != state_home
    ):
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_CANDIDATE_INVALID",
            "сохранённый candidate action не связан с previous activation",
        )


def _validate_recovery_readiness_token(
    value: str | None,
    *,
    expected_hash: str,
) -> None:
    if (
        type(value) is not str
        or not 32 <= len(value) <= 256
        or "\0" in value
        or len(value.encode("utf-8")) > 1024
        or hashlib.sha256(value.encode("utf-8")).hexdigest() != expected_hash
    ):
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_AUTHORIZATION_REQUIRED",
            "повторному dispatch нужен сохранённый readiness token",
        )


def _candidate_authorization_store(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    action: CandidateSpawnActionV2,
) -> CandidateSpawnAuthorizationStoreV2:
    try:
        return CandidateSpawnAuthorizationStoreV2(
            path=(
                evidence.receipts_root
                / f"{operation_id}.candidate-spawn.authorization.json"
            ),
            installation_id=evidence.installation_id,
            operation_id=operation_id,
            action_fingerprint=action.action_fingerprint,
            readiness_token_hash=action.readiness_token_hash,
        )
    except InstallerUpdateCompositionV2Error as error:
        _raise_authorization_error(error)


def _main_journal_store(codex_home: Path) -> OperationJournalStoreV2:
    layout = GatewayLayout.for_codex_home(codex_home)
    try:
        return OperationJournalStoreV2(
            journal_path=layout.journal_path,
            lock_path=layout.lock_path,
            validate_document=lambda _document: None,
        )
    except Exception as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_MAIN_JOURNAL_INVALID",
            "не удалось открыть основной журнал под общей блокировкой",
        ) from error


def _persist_fresh_candidate_authorization(
    *,
    evidence: RollbackEvidenceV2,
    codex_home: Path,
    operation_id: str,
    store: CandidateSpawnAuthorizationStoreV2,
    readiness_token: str,
) -> str:
    try:
        return _ensure_pre_main_candidate_authorization_v2(
            journal_store=_main_journal_store(codex_home),
            authorization_store=store,
            readiness_token=readiness_token,
            commit_receipt_path=evidence.receipts_root / f"{operation_id}.commit.json",
            codex_home=codex_home,
        )
    except InstallerUpdateCompositionV2Error as error:
        _raise_authorization_error(error)


def _recover_candidate_authorization(
    *,
    codex_home: Path,
    action: CandidateSpawnActionV2,
    store: CandidateSpawnAuthorizationStoreV2,
    supplied_readiness_token: str | None,
) -> str | None:
    journal_store = _main_journal_store(codex_home)
    try:
        with journal_store.locked(exclusive=True):
            if not os.path.lexists(journal_store.journal_path):
                _fail(
                    "ROLLBACK_RUNTIME_RECOVERY_JOURNAL_MISSING",
                    "recovery требует существующий основной journal",
                )
            dispatch_path = candidate_dispatch_intent_receipt_path_v2(
                codex_home=codex_home,
                action=action,
            )
            if os.path.lexists(dispatch_path):
                load_candidate_dispatch_intent_receipt_v2(
                    codex_home=codex_home,
                    action=action,
                )
                if supplied_readiness_token is not None:
                    _fail(
                        "ROLLBACK_RUNTIME_RECOVERY_TOKEN_FORBIDDEN",
                        "после dispatch сырой readiness token не принимается",
                    )
                persisted = store.load_if_present()
                if persisted is None:
                    # Совместимость со старыми журналами: reconnect разрешён,
                    # но новый dispatch без сохранённого token невозможен.
                    return None
                _validate_recovery_readiness_token(
                    persisted,
                    expected_hash=action.readiness_token_hash,
                )
                return persisted
            if os.path.lexists(action.private_ready_channel_path):
                _fail(
                    "ROLLBACK_RUNTIME_RECOVERY_EFFECT_WITHOUT_DISPATCH",
                    "ready-путь существует без долговечной dispatch-квитанции",
                )
            persisted = store.load_if_present()
            if persisted is None:
                _fail(
                    "ROLLBACK_RUNTIME_RECOVERY_AUTHORIZATION_REQUIRED",
                    "до dispatch отсутствует долговечная одноразовая авторизация",
                )
            _validate_recovery_readiness_token(
                persisted,
                expected_hash=action.readiness_token_hash,
            )
            if supplied_readiness_token is not None:
                _validate_recovery_readiness_token(
                    supplied_readiness_token,
                    expected_hash=action.readiness_token_hash,
                )
                if supplied_readiness_token != persisted:
                    _fail(
                        "ROLLBACK_RUNTIME_RECOVERY_AUTHORIZATION_CONFLICT",
                        "переданный token отличается от долговечной авторизации",
                    )
            return persisted
    except InstallerUpdateCompositionV2Error as error:
        _raise_authorization_error(error)


def _wrap_candidate_authorization_port(
    *,
    port: UpdateStepPortV2,
    store: CandidateSpawnAuthorizationStoreV2,
) -> UpdateStepPortV2:
    def remove_authorization() -> None:
        try:
            store.remove_if_present()
        except InstallerUpdateCompositionV2Error as error:
            _raise_authorization_error(error)

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        observed = port.observe(definition)
        if port.matches_after(observed, definition):
            remove_authorization()
        return observed

    def apply(definition: StepDefinitionV2) -> None:
        port.apply(definition)

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=port.matches_before,
        matches_after=port.matches_after,
        matches_intent_resume=port.matches_intent_resume,
        replay_safe_when_indistinguishable=port.replay_safe_when_indistinguishable,
        completed_current_matches=port.completed_current_matches,
    )


def _raise_authorization_error(error: InstallerUpdateCompositionV2Error) -> None:
    raise InstallerRollbackCompositionV2Error(error.code, error.message) from error


def _rehydrate_shutdown_plan(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    definition: StepDefinitionV2,
) -> ShutdownSocketCleanupPlanV2:
    action = dict(definition.action)
    try:
        if (
            definition.kind != "shutdown_socket_cleanup"
            or action["actionKind"] != "socket-cleanup"
            or action["method"] != "unlink-proven-orphan"
            or action["proofSource"] != "CONTROLLER_SHUTDOWN_INTENT"
        ):
            raise ValueError("unsupported cleanup definition")
        draft = ShutdownSocketCleanupPlanV2(
            installation_id=evidence.installation_id,
            activation_proof_fingerprint=evidence.evidence_fingerprint,
            operation_id=operation_id,
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
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_RECOVERY_CLEANUP_INVALID",
            "сохранённый shutdown cleanup неполон",
        ) from error
    plan = ShutdownSocketCleanupPlanV2(
        **{
            name: getattr(draft, name)
            for name in draft.__dataclass_fields__
            if name != "plan_fingerprint"
        },
        plan_fingerprint=_shutdown_plan_fingerprint(draft),
    )
    if not plan.complete:
        _fail(
            "ROLLBACK_RUNTIME_RECOVERY_CLEANUP_INVALID",
            "не удалось восстановить fingerprint shutdown cleanup",
        )
    return plan


def _controller_definitions(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    codex_home: Path,
    state_home: Path,
    controller_before: ProjectionV2,
    previous_controller_before: ProjectionV2,
    candidate_action: CandidateSpawnActionV2,
    shell_session_id: str,
    quiescence_timeout_ms: int,
) -> dict[str, StepDefinitionV2]:
    if controller_before.schema_id != "controller-state-v2":
        _fail(
            "ROLLBACK_RUNTIME_CONTROLLER_INVALID",
            "текущая база не вернула controller-state-v2",
        )
    old = copy.deepcopy(dict(controller_before.value))
    epoch = old.get("controlEpoch")
    previous = copy.deepcopy(dict(previous_controller_before.value))
    previous_epoch = previous.get("controlEpoch")
    current_database_id = evidence.current_activation_projection.value.get("databaseId")
    current_controller_identity = evidence.current_receipt.get("controllerIdentity")
    previous_database_id = str(evidence.previous_database_binding.value["databaseId"])
    previous_controller_identity = _sha256(
        evidence.previous_receipt.get("controllerIdentity"),
        "ROLLBACK_RUNTIME_PREVIOUS_CONTROLLER_INVALID",
    )
    if (
        controller_before.schema_sha256 != _LIFECYCLE_SCHEMA_SHA256
        or type(epoch) is not int
        or epoch < 1
        or old.get("state") != "ACCEPTING"
        or old.get("maintenanceMode") is not None
        or old.get("operationId") is not None
        or old.get("acceptingNewRoutes") is not True
        or old.get("activationId") != evidence.current_activation_id
        or old.get("activationFingerprint")
        != evidence.current_activation_projection.value.get("activationFingerprint")
        or old.get("databaseId") != current_database_id
        or old.get("controllerIdentity") != current_controller_identity
    ):
        _fail(
            "ROLLBACK_RUNTIME_CONTROLLER_INVALID",
            "живой контроллер не является точным MATCHED_ACTIVE",
        )
    if (
        previous_controller_before.schema_id != "controller-state-v2"
        or previous_controller_before.schema_sha256 != _LIFECYCLE_SCHEMA_SHA256
        or type(previous_epoch) is not int
        or not 1 <= previous_epoch <= 9_007_199_254_740_989
        or previous.get("state") != "MAINTENANCE"
        or previous.get("maintenanceMode") != "freeze"
        or previous.get("operationId") != evidence.current_operation_id
        or previous.get("instanceId") is not None
        or previous.get("controllerStartId") is not None
        or previous.get("pid") is not None
        or previous.get("processStartMarker") is not None
        or previous.get("processGroupId") is not None
        or previous.get("socket") is not None
        or previous.get("lockHeld") is not False
        or previous.get("acceptingNewRoutes") is not False
        or previous.get("quiescent") is not True
        or previous.get("activationId") != evidence.previous_activation_id
        or previous.get("activationFingerprint")
        != evidence.previous_activation_projection.value.get(
            "activationFingerprint"
        )
        or previous.get("databaseId") != previous_database_id
        or previous.get("controllerIdentity") != previous_controller_identity
    ):
        _fail(
            "ROLLBACK_RUNTIME_PREVIOUS_CONTROLLER_INVALID",
            "остановленный orphan не связан с previous receipt и базой",
        )
    begin_value = {
        **old,
        "controlEpoch": epoch + 1,
        "state": "EXPECTED_DRAIN_OR_MAINTENANCE",
        "maintenanceMode": "drain",
        "operationId": operation_id,
        "acceptingNewRoutes": False,
        "quiescent": False,
    }
    begin_after = _controller_projection(begin_value)
    drain_quiescent = _controller_projection(
        {**begin_value, "state": "MAINTENANCE", "quiescent": True}
    )
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
                "codex-smart/database-predicates/v2", predicate_document
            ),
            "barrierHeld": True,
            "quiescent": True,
        },
        "codex-smart/quiescence-proof/v2",
    )
    frozen = _controller_projection(
        {
            **drain_quiescent.value,
            "controlEpoch": epoch + 2,
            "maintenanceMode": "freeze",
        }
    )
    command_ids = {
        kind: _derived_identifier("cc2", operation_id, kind)
        for kind in (
            "maintenance_begin",
            "maintenance_strengthen",
            "controller_shutdown",
            "controller_previous_accept",
            "maintenance_resume",
        )
    }
    shutdown = build_controller_shutdown_constraint_v2(
        codex_home=codex_home,
        shell_session_id=shell_session_id,
        operation_id=operation_id,
        command_id=command_ids["controller_shutdown"],
        controller_before=frozen,
        lock_path=state_home / "controller.lock",
    )
    accepted_value = {
        "controllerIdentity": previous_controller_identity,
        "instanceId": None,
        "controllerStartId": candidate_action.controller_start_id,
        "pid": None,
        "processStartMarker": None,
        "processGroupId": None,
        "controlEpoch": previous_epoch + 1,
        "state": "EXPECTED_MAINTENANCE",
        "maintenanceMode": "freeze",
        "operationId": operation_id,
        "activationId": evidence.previous_activation_id,
        "activationFingerprint": evidence.previous_activation_projection.value[
            "activationFingerprint"
        ],
        "databaseId": previous_database_id,
        "socket": None,
        "lockHeld": True,
        "acceptingNewRoutes": False,
        "quiescent": True,
    }
    accepted = _controller_projection(accepted_value)
    resumed = _controller_projection(
        {
            **accepted_value,
            "controlEpoch": previous_epoch + 2,
            "state": "EXPECTED_ACCEPTING",
            "maintenanceMode": None,
            "operationId": None,
            "acceptingNewRoutes": True,
            "quiescent": False,
        }
    )

    def command_step(
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
        "maintenance_begin": command_step(
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
        "maintenance_strengthen": command_step(
            "maintenance_strengthen",
            method="maintenance_strengthen",
            before=drain_quiescent,
            after=frozen,
            expected_epoch=epoch + 1,
        ),
        "controller_shutdown": command_step(
            "controller_shutdown",
            method="shutdown",
            before=frozen,
            after=shutdown,
            expected_epoch=epoch + 2,
        ),
        "controller_previous_accept": command_step(
            "controller_previous_accept",
            method="controller_accept",
            before=_candidate_expected_projection(candidate_action),
            after=accepted,
            expected_epoch=previous_epoch,
        ),
        "maintenance_resume": command_step(
            "maintenance_resume",
            method="maintenance_resume",
            before=accepted,
            after=resumed,
            expected_epoch=previous_epoch + 1,
        ),
    }


def _update_controller_definitions(
    rollback: Mapping[str, StepDefinitionV2],
) -> tuple[dict[str, StepDefinitionV2], StepDefinitionV2]:
    copied = dict(rollback)
    previous = copied.pop("controller_previous_accept")
    update_accept = StepDefinitionV2(
        kind="controller_accept",
        command_id=previous.command_id,
        action=previous.action,
        before=previous.before,
        expected_after=previous.expected_after,
    )
    copied["controller_accept"] = update_accept
    return copied, update_accept


def _renamed_step_port(
    *,
    source: UpdateStepPortV2,
    source_definition: StepDefinitionV2,
    target_definition: StepDefinitionV2,
) -> UpdateStepPortV2:
    def translated(received: StepDefinitionV2) -> StepDefinitionV2:
        if received != target_definition:
            _fail(
                "ROLLBACK_RUNTIME_CONTROLLER_DEFINITION_CHANGED",
                "controller_previous_accept изменён после сборки",
            )
        return source_definition

    return UpdateStepPortV2(
        observe=lambda received: source.observe(translated(received)),
        apply=lambda received: source.apply(translated(received)),
        matches_before=lambda observed, received: source.matches_before(
            observed, translated(received)
        ),
        matches_after=lambda observed, received: source.matches_after(
            observed, translated(received)
        ),
        replay_safe_when_indistinguishable=lambda observed, received: (
            source.replay_safe_when_indistinguishable(observed, translated(received))
        ),
        completed_current_matches=lambda persisted, current, received: (
            source.completed_current_matches(persisted, current, translated(received))
        ),
    )


def _candidate_action(
    *,
    evidence: RollbackEvidenceV2,
    operation_id: str,
    readiness_token: str,
    readiness_window_ms: int,
    interpreter: Path,
    server_entrypoint: Path,
    state_home: Path,
    snapshot_fingerprint: str,
) -> CandidateSpawnActionV2:
    argv = candidate_controller_argv_v2(
        interpreter=interpreter,
        server_entrypoint=server_entrypoint,
    )
    ready_path = state_home / (
        ".r-" + operation_id.removeprefix("op2_")[-12:] + ".sock"
    )
    if os.path.lexists(ready_path):
        _fail(
            "ROLLBACK_RUNTIME_READY_PATH_CONFLICT",
            "путь ready-сокета уже существует до долговечного intent",
        )
    document = {
        "actionKind": "controller-candidate-spawn",
        "candidateId": _derived_identifier("cand2", operation_id, "candidate"),
        "controllerIdentity": _sha256(
            evidence.previous_receipt.get("controllerIdentity"),
            "ROLLBACK_RUNTIME_PREVIOUS_CONTROLLER_INVALID",
        ),
        "controllerStartId": _derived_identifier(
            "cs2", operation_id, "controller-start"
        ),
        "operationId": operation_id,
        "activationId": evidence.previous_activation_id,
        "activationFingerprint": evidence.previous_activation_projection.value[
            "activationFingerprint"
        ],
        "databaseId": evidence.previous_database_binding.value["databaseId"],
        "argv": list(argv),
        "argvFingerprint": domain_fingerprint(
            "codex-smart/controller-candidate-argv/v2", {"argv": list(argv)}
        ),
        "snapshotFingerprint": snapshot_fingerprint,
        "privateReadyChannelPath": str(ready_path),
        "readinessTokenHash": hashlib.sha256(
            readiness_token.encode("utf-8")
        ).hexdigest(),
        "readinessWindowMs": readiness_window_ms,
        "processGroupPolicy": "NEW_PRIVATE_GROUP",
    }
    return CandidateSpawnActionV2.from_mapping(document)


def _previous_activation_runtime(
    *,
    evidence: RollbackEvidenceV2,
    artifacts: RollbackExternalArtifactsV2,
    previous_database: Path,
) -> dict[str, Any]:
    activation = evidence.previous_activation_projection
    directory_value = activation.value.get("directory")
    file_value = activation.value.get("activationFile")
    if type(directory_value) is not dict or type(file_value) is not dict:
        _fail(
            "ROLLBACK_RUNTIME_PREVIOUS_ACTIVATION_INVALID",
            "previous activation не содержит физических проекций",
        )
    activation_dir = _absolute_path_from_document(
        directory_value.get("path"),
        code="ROLLBACK_RUNTIME_PREVIOUS_ACTIVATION_INVALID",
    )
    expected_activation_dir = (
        evidence.activations_root / evidence.previous_activation_id
    )
    activation_file = _absolute_path_from_document(
        file_value.get("path"),
        code="ROLLBACK_RUNTIME_PREVIOUS_ACTIVATION_INVALID",
    )
    if (
        activation_dir != expected_activation_dir
        or activation_file != activation_dir / "activation.json"
        or artifacts.previous_registered_marketplace
        != (activation_dir / "marketplace").resolve(strict=True)
    ):
        _fail(
            "ROLLBACK_RUNTIME_PREVIOUS_ACTIVATION_INVALID",
            "пути previous activation расходятся с evidence",
        )
    document = _read_json_file(
        activation_file,
        code="ROLLBACK_RUNTIME_PREVIOUS_ACTIVATION_INVALID",
        exact_mode=0o600,
    )
    observed_file = _regular_file_value(activation_file)
    identity = document.get("identity")
    database = identity.get("database") if type(identity) is dict else None
    snapshot = identity.get("codexSnapshot") if type(identity) is dict else None
    if (
        observed_file != file_value
        or document.get("schemaVersion") != 2
        or document.get("activationId") != evidence.previous_activation_id
        or document.get("activationFingerprint")
        != activation.value.get("activationFingerprint")
        or type(database) is not dict
        or database.get("databaseId")
        != evidence.previous_database_binding.value.get("databaseId")
        or database.get("absolutePath") != str(previous_database)
        or type(snapshot) is not dict
        or set(snapshot) != {"absolutePath", "sha256"}
    ):
        _fail(
            "ROLLBACK_RUNTIME_PREVIOUS_ACTIVATION_INVALID",
            "activation.json не связывает previous database и snapshot",
        )
    snapshot_fingerprint = _sha256(
        snapshot.get("sha256"),
        "ROLLBACK_RUNTIME_PREVIOUS_SNAPSHOT_INVALID",
    )
    snapshot_path = _immutable_codex_snapshot(
        evidence=evidence,
        locator=snapshot,
        expected_sha256=snapshot_fingerprint,
    )
    marketplace_contract = _read_json_file(
        artifacts.previous_registered_marketplace / ".agents/plugins/marketplace.json",
        code="ROLLBACK_RUNTIME_MARKETPLACE_INVALID",
    )
    plugin_entry = _single_plugin_entry(marketplace_contract)
    source = plugin_entry.get("source")
    policy = plugin_entry.get("policy")
    if (
        marketplace_contract.get("name") != "codex-settings-adaptive"
        or type(source) is not dict
        or source.get("source") != "local"
        or source.get("path") != "./plugins/codex-smart-subagents"
        or type(policy) is not dict
        or set(policy) != {"installation", "authentication"}
    ):
        _fail(
            "ROLLBACK_RUNTIME_MARKETPLACE_INVALID",
            "previous marketplace не содержит точный локальный договор",
        )
    install_policy = policy.get("installation")
    auth_policy = policy.get("authentication")
    if any(
        type(value) is not str or not value or len(value) > 256
        for value in (install_policy, auth_policy)
    ):
        _fail(
            "ROLLBACK_RUNTIME_MARKETPLACE_INVALID",
            "политики previous marketplace имеют неверную форму",
        )
    plugin_root = artifacts.previous_registered_marketplace / _PLUGIN_RELATIVE_PATH
    try:
        if plugin_root.resolve(strict=True) != plugin_root:
            raise OSError("plugin root is not canonical")
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(
            "ROLLBACK_RUNTIME_MARKETPLACE_INVALID",
            "previous plugin root недоступен",
        ) from error
    plugin_manifest = _read_json_file(
        plugin_root / ".codex-plugin/plugin.json",
        code="ROLLBACK_RUNTIME_PLUGIN_INVALID",
    )
    plugin_version = plugin_manifest.get("version")
    if (
        plugin_manifest.get("name") != "codex-smart-subagents"
        or type(plugin_version) is not str
        or not plugin_version
        or len(plugin_version) > 256
    ):
        _fail(
            "ROLLBACK_RUNTIME_PLUGIN_INVALID",
            "previous plugin manifest имеет неверную идентичность",
        )
    server = plugin_root / "controller/server.py"
    wrapper = plugin_root / "bin/codex-smart"
    _require_owned_regular(server, "ROLLBACK_RUNTIME_SERVER_INVALID")
    _require_wrapper(wrapper)
    return {
        "plugin_relative_path": _PLUGIN_RELATIVE_PATH,
        "plugin_version": plugin_version,
        "install_policy": install_policy,
        "auth_policy": auth_policy,
        "server_entrypoint": server,
        "wrapper_path": wrapper,
        "snapshot_path": snapshot_path,
        "snapshot_fingerprint": snapshot_fingerprint,
    }


def _single_plugin_entry(document: Mapping[str, Any]) -> Mapping[str, Any]:
    plugins = document.get("plugins")
    matches = (
        [item for item in plugins if isinstance(item, Mapping)]
        if type(plugins) is list
        else []
    )
    if len(matches) != 1 or matches[0].get("name") != "codex-smart-subagents":
        _fail(
            "ROLLBACK_RUNTIME_MARKETPLACE_INVALID",
            "previous marketplace не содержит единственный управляемый plugin",
        )
    return matches[0]


def _immutable_codex_snapshot(
    *,
    evidence: RollbackEvidenceV2,
    locator: Mapping[str, Any],
    expected_sha256: str,
) -> Path:
    code = "ROLLBACK_RUNTIME_PREVIOUS_SNAPSHOT_INVALID"
    snapshot_root = _owned_directory(
        evidence.activations_root.parent / "codex-snapshots",
        allowed_modes={0o700},
        code=code,
    )
    snapshot_directory = _owned_directory(
        snapshot_root / expected_sha256,
        allowed_modes={0o700},
        code=code,
    )
    path = _absolute_path_from_document(locator.get("absolutePath"), code=code)
    if path != snapshot_directory / "codex":
        _fail(code, "snapshot не связан с content-addressed previous activation")
    info = _regular_file_info(path, code)
    if (
        stat.S_IMODE(info.st_mode) != 0o500
        or info.st_size <= 0
        or info.st_size > _MAX_CODEX_BINARY_BYTES
    ):
        _fail(code, "snapshot должен быть непустым частным файлом режима 0500")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            _fail(code, "snapshot изменился перед чтением")
        digest = hashlib.sha256()
        total = 0
        while True:
            checkpoint_current_operation_deadline_if_scoped_v2()
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_CODEX_BINARY_BYTES:
                _fail(code, "snapshot превысил допустимый размер")
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(code, str(error)) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    named = _regular_file_info(path, code)
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if (
        identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
        or total != info.st_size
        or digest.hexdigest() != expected_sha256
    ):
        _fail(code, "snapshot изменился либо не совпал с activation.json")
    return path


def _launcher_bindings(
    *,
    artifacts: RollbackExternalArtifactsV2,
    plugin_relative_path: Path,
) -> tuple[LauncherBindingV2, ...]:
    result: list[LauncherBindingV2] = []
    seen_roles: set[str] = set()
    for artifact in artifacts.launchers:
        name = artifact.path.name
        role = _LAUNCHER_ROLES.get(name)
        expected_relative = plugin_relative_path / "bin" / name
        expected_target = artifacts.previous_registered_marketplace / expected_relative
        if (
            role is None
            or role in seen_roles
            or artifact.relative_marketplace_target != expected_relative
            or not expected_target.is_file()
            or expected_target.is_symlink()
        ):
            _fail(
                "ROLLBACK_RUNTIME_LAUNCHER_INVALID",
                "launcher не связан с previous plugin bin",
            )
        seen_roles.add(role)
        result.append(
            LauncherBindingV2(
                name=name,
                role=role,
                path=artifact.path,
                target=artifact.target,
                expected_resolved_target=expected_target,
            )
        )
    if seen_roles != {"gateway", "admin"}:
        _fail(
            "ROLLBACK_RUNTIME_LAUNCHER_INVALID",
            "требуются точные gateway и admin launchers",
        )
    return tuple(result)


def _database_binding_from_document(
    document: Any,
    *,
    activation: ProjectionV2,
    state_home: Path,
    code: str,
) -> Path:
    try:
        projection = ProjectionV2.from_document(document)
    except (TypeError, ValueError) as error:
        raise InstallerRollbackCompositionV2Error(
            code, "databaseBinding в commit-квитанции повреждён"
        ) from error
    return _database_binding_path(
        projection,
        activation=activation,
        state_home=state_home,
        code=code,
    )


def _database_binding_path(
    projection: ProjectionV2,
    *,
    activation: ProjectionV2,
    state_home: Path,
    code: str,
) -> Path:
    if projection.schema_id != "database-binding-v2":
        _fail(code, "проекция не является database-binding-v2")
    value = projection.value
    path = _absolute_path_from_document(value.get("path"), code=code)
    try:
        path.relative_to(state_home)
    except ValueError:
        _fail(code, "база находится вне stateHome")
    info = _regular_file_info(path, code)
    expected = (
        value.get("device"),
        value.get("inode"),
        value.get("ownerUid"),
        value.get("ownerGid"),
        value.get("mode"),
        value.get("linkCount"),
    )
    observed = (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        f"0{stat.S_IMODE(info.st_mode):03o}",
        info.st_nlink,
    )
    identity = value.get("activationIdentity")
    if (
        expected != observed
        or value.get("mode") != "0600"
        or type(identity) is not dict
        or identity.get("activationId") != activation.value.get("activationId")
        or identity.get("activationFingerprint")
        != activation.value.get("activationFingerprint")
        or value.get("databaseId") != activation.value.get("databaseId")
    ):
        _fail(code, "физическая база не совпадает с commit-квитанцией")
    return path


def _shutdown_controller_state(controller: ProjectionV2) -> dict[str, Any]:
    value = controller.value
    socket = value.get("socket")
    if type(socket) is not dict:
        _fail(
            "ROLLBACK_RUNTIME_CONTROLLER_INVALID",
            "живой контроллер не содержит socket identity",
        )
    return {
        "socket_path": socket.get("path"),
        "socket_device": socket.get("device"),
        "socket_inode": socket.get("inode"),
        "socket_owner_uid": socket.get("ownerUid"),
        "socket_owner_gid": socket.get("ownerGid"),
        "socket_mode": socket.get("mode"),
        "controller_pid": value.get("pid"),
        "controller_process_start_marker": value.get("processStartMarker"),
        "controller_process_group_id": value.get("processGroupId"),
    }


def _candidate_expected_projection(action: CandidateSpawnActionV2) -> ProjectionV2:
    value = {
        **{
            name: item
            for name, item in action.to_document().items()
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


def _controller_projection(value: Mapping[str, Any]) -> ProjectionV2:
    return _projection(
        "controller-state-v2",
        value,
        "codex-smart/controller-state/v2",
    )


def _absence_projection(
    *, path: Path, installation_id: str, operation_id: str
) -> ProjectionV2:
    if os.path.lexists(path):
        _fail(
            "ROLLBACK_RUNTIME_READY_PATH_CONFLICT",
            "ready-путь уже существует до запуска кандидата",
        )
    parent = _owned_directory(
        path.parent,
        allowed_modes={0o700},
        code="ROLLBACK_RUNTIME_STATE_HOME_INVALID",
    ).lstat()
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
    return (
        prefix
        + "_"
        + domain_fingerprint(
            "codex-smart/rollback-derived-id/v2",
            {"operationId": operation_id, "purpose": purpose},
        )[:32]
    )


def _port_options(
    value: Mapping[str, Any] | None,
    *,
    forbidden: set[str],
    label: str,
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or any(type(name) is not str for name in value):
        raise TypeError(f"{label} must be a string-keyed mapping")
    copied = dict(value)
    overlap = sorted(set(copied).intersection(forbidden))
    if overlap:
        raise TypeError(f"{label} cannot override bound arguments: {overlap}")
    return copied


def _read_json_file(
    path: Path,
    *,
    code: str,
    exact_mode: int | None = None,
) -> dict[str, Any]:
    info = _regular_file_info(path, code)
    if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
        _fail(code, f"файл имеет неверный режим: {path}")
    if info.st_size > _MAX_JSON_BYTES:
        _fail(code, f"файл слишком велик: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallerRollbackCompositionV2Error(code, str(error)) from error
    if type(document) is not dict:
        _fail(code, f"JSON не является объектом: {path}")
    return document


def _regular_file_value(path: Path) -> dict[str, Any]:
    info = _regular_file_info(path, "ROLLBACK_RUNTIME_FILE_INVALID")
    payload = path.read_bytes()
    return {
        "path": str(path),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
        "linkCount": info.st_nlink,
        "size": info.st_size,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _regular_file_info(path: Path, code: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(code, str(error)) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
    ):
        _fail(code, f"файл имеет неверную физическую идентичность: {path}")
    return info


def _require_owned_regular(path: Path, code: str) -> None:
    _regular_file_info(path, code)


def _require_wrapper(path: Path) -> None:
    info = _regular_file_info(path, "ROLLBACK_RUNTIME_WRAPPER_INVALID")
    if stat.S_IMODE(info.st_mode) not in {0o500, 0o700} or not os.access(path, os.X_OK):
        _fail(
            "ROLLBACK_RUNTIME_WRAPPER_INVALID",
            "previous wrapper должен иметь режим 0500 либо 0700",
        )


def _require_executable(path: Path, code: str) -> None:
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(code, str(error)) from error
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        _fail(code, f"исполняемый файл недоступен: {path}")


def _owned_directory(
    path: Path,
    *,
    allowed_modes: set[int],
    code: str,
) -> Path:
    path = _absolute_path(path, code)
    try:
        info = path.lstat()
    except OSError as error:
        raise InstallerRollbackCompositionV2Error(code, str(error)) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) not in allowed_modes
    ):
        _fail(code, f"каталог имеет неверную идентичность или режим: {path}")
    return path


def _absolute_path(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "путь должен быть абсолютным Path")
    return path


def _absolute_path_from_document(value: Any, *, code: str) -> Path:
    if type(value) is not str:
        _fail(code, "документ не содержит абсолютный путь")
    return _absolute_path(Path(value), code)


def _sha256(value: Any, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code, "значение не является SHA-256")
    return value


def _fail(code: str, message: str) -> None:
    raise InstallerRollbackCompositionV2Error(code, message)


__all__ = [
    "build_rollback_runtime_external_bindings_v2",
    "recover_rollback_runtime_external_bindings_v2",
    "rehydrate_rollback_evidence_v2",
]
