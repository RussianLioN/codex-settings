"""Безопасные примитивы перехода между доказанными активациями версии 2.

Снимок принятой активации создаётся до появления основного журнала только
через :meth:`ActivationResolver.resolve_persisted_activation`. После
атомарного закрытия шлюза снимок перепроверяется без повторного запуска
шлюза: наличие журнала в этот момент является ожидаемым состоянием.

Модуль не посылает сигналы процессам и не изменяет SQLite напрямую. Граница
контроллера подключается ниже отдельным типизированным портом.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .activation_gateway_v2 import (
    ActivationResolver,
    GatewayLayout,
    GatewayState,
    _LIFECYCLE_SCHEMA_SHA256,
    _file_projection,
    _tree_projection,
    _tree_sha256,
)
from .activation_materializer_v2 import (
    StagedActivationV2,
    _atomic_write_json,
    _controller_identity,
    _ensure_lock_file,
    _ensure_private_directory,
    _exclusive_lock,
    _fsync_directory,
    _manifest_artifacts,
    _materialize_marketplace,
    _normalize_private_tree,
    _read_json,
    _required_sha256,
    _sha256_file,
    _validate_snapshot_subject,
    _validate_source_catalog_identity_v2,
    normalize_state_home_v2,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .codex_binary_snapshot import CodexBinarySnapshotter, SnapshotCommandExecutor
from .interface_probe_v1 import probe_codex_interface_v1
from .lifecycle_operation_v2 import ProjectionV2
from .lifecycle_controller_protocol_v2 import (
    LifecycleControllerCommandProofV2,
    LifecycleControllerPortV2,
    LifecycleControllerQuiescenceV2,
)
from .policy_bundle_v2 import PolicyBundleV2


_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CONTROL_BYTES = 16 * 1024 * 1024
_INSTALLER_RECEIPT_NAME = "codex-smart-subagents-v2.installer.json"
_PLUGIN_NAME = "codex-smart-subagents"
_RELEASE = "0.2.0"


@dataclass
class ActivationTransitionV2Error(RuntimeError):
    """Отказ перехода с устойчивым машинным кодом."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ActivationTransitionProofV2:
    """Замкнутый снимок одной принятой и принадлежащей установке активации."""

    codex_home: Path
    layout: GatewayLayout
    installation_id: str
    activation_id: str
    activation_fingerprint: str
    current_operation_id: str
    state_home: Path
    database_path: Path
    activation_dir: Path
    manifest_raw: bytes
    manifest_document: Mapping[str, Any]
    manifest_file_projection: Mapping[str, Any]
    manifest_projection: ProjectionV2
    active_pointer: Mapping[str, Any]
    link_target: str
    link_device: int
    link_inode: int
    link_projection: ProjectionV2
    activation_raw: bytes
    activation_document: Mapping[str, Any]
    activation_tree_projection: ProjectionV2
    activation_projection: ProjectionV2
    commit_receipt_path: Path
    commit_receipt_raw: bytes
    commit_receipt_document: Mapping[str, Any]
    commit_receipt_file_projection: Mapping[str, Any]
    commit_receipt_projection: ProjectionV2
    database_binding: ProjectionV2
    database_identity_row: Mapping[str, Any]
    controller_row: Mapping[str, Any]
    controller_identity: str
    installer_receipt_path: Path
    installer_receipt_raw: bytes
    installer_receipt_document: Mapping[str, Any]
    installer_receipt_file_projection: Mapping[str, Any]
    installer_receipt_projection: ProjectionV2
    proof_fingerprint: str

    def __post_init__(self) -> None:
        for name in (
            "manifest_document",
            "manifest_file_projection",
            "active_pointer",
            "activation_document",
            "commit_receipt_document",
            "commit_receipt_file_projection",
            "database_identity_row",
            "controller_row",
            "installer_receipt_document",
            "installer_receipt_file_projection",
        ):
            object.__setattr__(self, name, copy.deepcopy(dict(getattr(self, name))))

    @property
    def complete(self) -> bool:
        try:
            _validate_proof_shape(self)
        except ActivationTransitionV2Error:
            return False
        return self.proof_fingerprint == _proof_fingerprint(self)


@dataclass(frozen=True)
class ControllerShutdownProofV2:
    """Доказанная цепочка остановки текущего контроллера."""

    activation_proof_fingerprint: str
    operation_id: str
    maintenance_begin: LifecycleControllerCommandProofV2
    quiescence: LifecycleControllerQuiescenceV2
    maintenance_strengthen: LifecycleControllerCommandProofV2
    shutdown: LifecycleControllerCommandProofV2
    proof_fingerprint: str

    @property
    def complete(self) -> bool:
        try:
            return self.proof_fingerprint == _shutdown_fingerprint(self)
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class CandidateAcceptanceProofV2:
    """Принятие точного кандидата после доказанной остановки."""

    activation_proof_fingerprint: str
    shutdown_proof_fingerprint: str
    operation_id: str
    activation_id: str
    database_id: str
    candidate_accept: LifecycleControllerCommandProofV2
    proof_fingerprint: str

    @property
    def complete(self) -> bool:
        try:
            return self.proof_fingerprint == _acceptance_fingerprint(self)
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class ActivationMutationPrimitiveV2:
    """Один атомарный файловый обработчик журналируемого шага."""

    kind: str
    operation_id: str
    activation_id: str
    target_path: Path
    before: ProjectionV2
    expected_after: ProjectionV2
    action: Mapping[str, Any]
    authorization_fingerprint: str
    primitive_fingerprint: str
    before_device: int | None = None
    before_inode: int | None = None
    prepared_path: Path | None = None
    prepared_raw: bytes | None = None
    prepared_file_projection: Mapping[str, Any] | None = None
    manifest_document: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", copy.deepcopy(dict(self.action)))
        if self.prepared_file_projection is not None:
            object.__setattr__(
                self,
                "prepared_file_projection",
                copy.deepcopy(dict(self.prepared_file_projection)),
            )
        if self.manifest_document is not None:
            object.__setattr__(
                self,
                "manifest_document",
                copy.deepcopy(dict(self.manifest_document)),
            )


@dataclass(frozen=True)
class ActivationMutationResultV2:
    kind: str
    operation_id: str
    before: ProjectionV2
    expected_after: ProjectionV2
    observed_after: ProjectionV2


class PreparedManifestTransitionStateV2(str, Enum):
    """Однозначное физическое состояние атомарного перехода манифеста."""

    BEFORE = "BEFORE"
    AFTER = "AFTER"


@dataclass(frozen=True)
class PreparedManifestPlanV2:
    """Чистое логическое намерение будущего source-файла манифеста."""

    activation_proof_fingerprint: str
    operation_id: str
    activation_id: str
    activation_tree_sha256: str
    target_path: Path
    prepared_path: Path
    manifest_document: Mapping[str, Any]
    prepared_raw: bytes
    plan_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manifest_document",
            copy.deepcopy(dict(self.manifest_document)),
        )

    @property
    def complete(self) -> bool:
        try:
            return (
                self.prepared_raw == canonical_json_bytes(self.manifest_document)
                and self.plan_fingerprint == _prepared_manifest_plan_fingerprint(self)
            )
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class ActivationLinkPlanV2:
    """Чистое, не авторизованное доказательством остановки намерение ссылки."""

    activation_proof_fingerprint: str
    operation_id: str
    activation_id: str
    target_path: Path
    before: ProjectionV2
    expected_after: ProjectionV2
    action: Mapping[str, Any]
    before_device: int
    before_inode: int
    plan_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", copy.deepcopy(dict(self.action)))

    @property
    def complete(self) -> bool:
        try:
            return self.plan_fingerprint == _activation_link_plan_fingerprint(self)
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class ManifestCommitPlanV2:
    """Чистое намерение переноса уже подготовленного inode в манифест."""

    activation_proof_fingerprint: str
    operation_id: str
    activation_id: str
    target_path: Path
    before: ProjectionV2
    expected_after: ProjectionV2
    action: Mapping[str, Any]
    prepared: PreparedManifestCommitV2
    plan_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", copy.deepcopy(dict(self.action)))

    @property
    def complete(self) -> bool:
        try:
            return (
                isinstance(self.prepared, PreparedManifestCommitV2)
                and self.prepared.complete
                and self.plan_fingerprint == _manifest_commit_plan_fingerprint(self)
            )
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class PreparedManifestCommitV2:
    """Физически закреплённый источник будущей атомарной замены манифеста."""

    activation_proof_fingerprint: str
    operation_id: str
    activation_id: str
    activation_tree_sha256: str
    target_path: Path
    prepared_path: Path
    prepared_parent_device: int
    prepared_parent_inode: int
    manifest_document: Mapping[str, Any]
    prepared_raw: bytes
    prepared_file_projection: Mapping[str, Any]
    prepared_file: ProjectionV2
    expected_after: ProjectionV2
    preparation_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manifest_document",
            copy.deepcopy(dict(self.manifest_document)),
        )
        object.__setattr__(
            self,
            "prepared_file_projection",
            copy.deepcopy(dict(self.prepared_file_projection)),
        )

    @property
    def complete(self) -> bool:
        try:
            return (
                self.prepared_raw == canonical_json_bytes(self.manifest_document)
                and self.prepared_file.value
                == dict(self.prepared_file_projection)
                and self.expected_after.value.get("file", {}).get("path")
                == str(self.target_path)
                and self.preparation_fingerprint
                == _prepared_manifest_fingerprint(self)
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return False


def shutdown_current_activation_v2(
    *,
    proof: ActivationTransitionProofV2,
    operation_id: str,
    controller_port: LifecycleControllerPortV2,
    timeout_seconds: float = 60.0,
    reason_code: str = "UPGRADE",
) -> ControllerShutdownProofV2:
    """Выполнить только типизированную цепочку drain → freeze → shutdown."""

    operation_id = _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    if not isinstance(controller_port, LifecycleControllerPortV2):
        _fail("CONTROLLER_PORT_REQUIRED", "требуется LifecycleControllerPortV2")
    if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 60:
        _fail(
            "QUIESCENCE_TIMEOUT_INVALID", "срок ожидания должен быть от 0 до 60 секунд"
        )
    reverify_activation_transition_proof_v2(
        proof, operation_id=operation_id, require_journal=True
    )
    initial_epoch = proof.controller_row.get("control_epoch")
    if type(initial_epoch) is not int or initial_epoch < 1:
        _fail("ACTIVATION_PROOF_INCOMPLETE", "эпоха контроллера не доказана")
    begin = controller_port.maintenance_begin(
        operation_id=operation_id,
        reason_code=reason_code,
    )
    _validate_command_proof(
        begin,
        method="maintenance_begin",
        status="MAINTENANCE_BEGUN",
        previous_epoch=initial_epoch,
    )
    quiescence = controller_port.wait_quiescent(
        operation_id=operation_id,
        timeout_seconds=float(timeout_seconds),
    )
    _validate_quiescence(
        quiescence,
        operation_id=operation_id,
        control_epoch=begin.new_control_epoch,
    )
    if not quiescence.quiescent:
        try:
            resumed = controller_port.maintenance_resume(operation_id=operation_id)
            _validate_command_proof(
                resumed,
                method="maintenance_resume",
                status="MAINTENANCE_RESUMED",
                previous_epoch=begin.new_control_epoch,
            )
        except Exception as exc:
            _fail(
                "ACTIVE_WORK_RESUME_FAILED",
                f"активная работа обнаружена, но drain-resume не доказан: {exc}",
            )
        _fail("ACTIVE_WORK", "контроллер не достиг естественного покоя")
    strengthened = controller_port.maintenance_strengthen(operation_id=operation_id)
    _validate_command_proof(
        strengthened,
        method="maintenance_strengthen",
        status="MAINTENANCE_STRENGTHENED",
        previous_epoch=begin.new_control_epoch,
    )
    shutdown = controller_port.shutdown(operation_id=operation_id)
    _validate_command_proof(
        shutdown,
        method="shutdown",
        status="SHUTDOWN_COMMITTED",
        previous_epoch=strengthened.new_control_epoch,
    )
    result = ControllerShutdownProofV2(
        activation_proof_fingerprint=proof.proof_fingerprint,
        operation_id=operation_id,
        maintenance_begin=begin,
        quiescence=quiescence,
        maintenance_strengthen=strengthened,
        shutdown=shutdown,
        proof_fingerprint="0" * 64,
    )
    result = ControllerShutdownProofV2(
        activation_proof_fingerprint=result.activation_proof_fingerprint,
        operation_id=result.operation_id,
        maintenance_begin=result.maintenance_begin,
        quiescence=result.quiescence,
        maintenance_strengthen=result.maintenance_strengthen,
        shutdown=result.shutdown,
        proof_fingerprint=_shutdown_fingerprint(result),
    )
    if not result.complete:
        _fail("CONTROLLER_PROOF_INVALID", "цепочка остановки неполна")
    return result


def accept_upgrade_candidate_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    shutdown: ControllerShutdownProofV2,
    controller_port: LifecycleControllerPortV2,
    pid: int,
    process_start_marker: str,
    process_group_id: int,
) -> CandidateAcceptanceProofV2:
    """Принять точный процесс кандидата через тот же типизированный порт."""

    _validate_shutdown_authorization(proof, staged, shutdown)
    if not isinstance(controller_port, LifecycleControllerPortV2):
        _fail("CONTROLLER_PORT_REQUIRED", "требуется LifecycleControllerPortV2")
    expected_target = f"activations/{staged.activation_id}/marketplace"
    _current, _info, target = _observe_link(proof.layout.marketplace_link)
    if target != expected_target:
        _fail("CANDIDATE_LINK_NOT_PUBLISHED", "ссылка ещё не указывает на кандидата")
    if (
        type(pid) is not int
        or pid <= 0
        or type(process_group_id) is not int
        or process_group_id <= 0
        or not isinstance(process_start_marker, str)
        or not process_start_marker
    ):
        _fail("CONTROLLER_CANDIDATE_INVALID", "идентичность процесса неполна")
    accepted = controller_port.candidate_accept(
        operation_id=staged.operation_id,
        activation_id=staged.activation_id,
        database_id=staged.database_id,
        pid=pid,
        process_start_marker=process_start_marker,
        process_group_id=process_group_id,
    )
    _validate_command_proof(
        accepted,
        method="controller_accept",
        status="CONTROLLER_ACCEPTED",
        # The candidate is served from the newly prepared database, whose
        # normative initial controller epoch is 1.  The shutdown proof belongs
        # to the old database and must not fence commands in the new one.
        previous_epoch=1,
    )
    result = CandidateAcceptanceProofV2(
        activation_proof_fingerprint=proof.proof_fingerprint,
        shutdown_proof_fingerprint=shutdown.proof_fingerprint,
        operation_id=staged.operation_id,
        activation_id=staged.activation_id,
        database_id=staged.database_id,
        candidate_accept=accepted,
        proof_fingerprint="0" * 64,
    )
    result = CandidateAcceptanceProofV2(
        activation_proof_fingerprint=result.activation_proof_fingerprint,
        shutdown_proof_fingerprint=result.shutdown_proof_fingerprint,
        operation_id=result.operation_id,
        activation_id=result.activation_id,
        database_id=result.database_id,
        candidate_accept=result.candidate_accept,
        proof_fingerprint=_acceptance_fingerprint(result),
    )
    if not result.complete:
        _fail("CONTROLLER_PROOF_INVALID", "принятие кандидата неполно")
    return result


def build_activation_link_plan_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
) -> ActivationLinkPlanV2:
    """Построить точный план ссылки без внешнего эффекта и авторизации."""

    _validate_staged_manifest_subject(proof, staged)
    target = f"activations/{staged.activation_id}/marketplace"
    expected = _expected_link_projection_from_before_v2(
        proof.link_projection,
        path=proof.layout.marketplace_link,
        target=target,
    )
    action = {
        "actionKind": "symlink-mutation",
        "method": "activate",
        "path": str(proof.layout.marketplace_link),
        "target": target,
        "durability": "FSYNC_PARENT",
    }
    plan = ActivationLinkPlanV2(
        activation_proof_fingerprint=proof.proof_fingerprint,
        operation_id=staged.operation_id,
        activation_id=staged.activation_id,
        target_path=proof.layout.marketplace_link,
        before=proof.link_projection,
        expected_after=expected,
        action=action,
        before_device=proof.link_device,
        before_inode=proof.link_inode,
        plan_fingerprint="0" * 64,
    )
    return ActivationLinkPlanV2(
        activation_proof_fingerprint=plan.activation_proof_fingerprint,
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        target_path=plan.target_path,
        before=plan.before,
        expected_after=plan.expected_after,
        action=plan.action,
        before_device=plan.before_device,
        before_inode=plan.before_inode,
        plan_fingerprint=_activation_link_plan_fingerprint(plan),
    )


def authorize_activation_link_plan_v2(
    *,
    plan: ActivationLinkPlanV2,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    shutdown: ControllerShutdownProofV2,
) -> ActivationMutationPrimitiveV2:
    """Связать неизменяемый план с восстановимым доказательством остановки."""

    _validate_shutdown_authorization(proof, staged, shutdown)
    _validate_gate_journal(proof, staged.operation_id)
    expected_plan = build_activation_link_plan_v2(proof=proof, staged=staged)
    if (
        not isinstance(plan, ActivationLinkPlanV2)
        or not plan.complete
        or plan != expected_plan
    ):
        _fail("ACTIVATION_LINK_PLAN_CHANGED", "план ссылки не совпадает со снимком")
    observe_activation_link_plan_v2(plan)
    primitive = ActivationMutationPrimitiveV2(
        kind="activation_link",
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        target_path=plan.target_path,
        before=plan.before,
        expected_after=plan.expected_after,
        action=plan.action,
        authorization_fingerprint=shutdown.proof_fingerprint,
        primitive_fingerprint="0" * 64,
        before_device=plan.before_device,
        before_inode=plan.before_inode,
    )
    return _replace_primitive_fingerprint(primitive, _primitive_fingerprint(primitive))


def build_activation_link_primitive_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    shutdown: ControllerShutdownProofV2,
) -> ActivationMutationPrimitiveV2:
    """Совместимый путь: построить чистый план и отдельно авторизовать его."""

    plan = build_activation_link_plan_v2(proof=proof, staged=staged)
    return authorize_activation_link_plan_v2(
        plan=plan,
        proof=proof,
        staged=staged,
        shutdown=shutdown,
    )


def observe_activation_link_plan_v2(
    plan: ActivationLinkPlanV2,
) -> ProjectionV2:
    """Вернуть точное before/after либо закрыть неоднозначное состояние ссылки."""

    if not isinstance(plan, ActivationLinkPlanV2) or not plan.complete:
        _fail("ACTIVATION_LINK_PLAN_INVALID", "план ссылки неполон")
    observed, info, _target = _observe_link(plan.target_path)
    if observed == plan.expected_after:
        return observed
    if (
        observed == plan.before
        and info.st_dev == plan.before_device
        and info.st_ino == plan.before_inode
    ):
        return observed
    _fail(
        "ACTIVE_LINK_CHANGED",
        "ссылка не совпадает ни с доказанным before, ни с expectedAfter",
    )


def apply_activation_link_primitive_v2(
    primitive: ActivationMutationPrimitiveV2,
    *,
    shutdown: ControllerShutdownProofV2,
) -> ActivationMutationResultV2:
    """Обработчик шага `activation_link`, пригодный для долговечного исполнителя."""

    _validate_primitive(primitive, kind="activation_link")
    if (
        not shutdown.complete
        or primitive.authorization_fingerprint != shutdown.proof_fingerprint
        or primitive.operation_id != shutdown.operation_id
    ):
        _fail("CONTROLLER_PROOF_REQUIRED", "остановка контроллера не доказана")
    observed, info, _target = _observe_link(primitive.target_path)
    if observed == primitive.expected_after:
        return _mutation_result(primitive, observed)
    if (
        observed != primitive.before
        or info.st_dev != primitive.before_device
        or info.st_ino != primitive.before_inode
    ):
        _fail("ACTIVE_LINK_CHANGED", "ссылка не совпадает с before")
    target = str(primitive.expected_after.value["target"])
    temporary = primitive.target_path.parent / (
        ".marketplace-current-" + secrets.token_hex(16)
    )
    try:
        os.symlink(target, temporary)
        staged_projection, _staged_info, _staged_target = _observe_link(temporary)
        staged_value = dict(staged_projection.value)
        staged_value["path"] = str(primitive.target_path)
        staged_projection = _projection(
            "symlink-object-v2",
            staged_value,
            "codex-smart/symlink-object/v2",
        )
        if staged_projection != primitive.expected_after:
            _fail("ACTIVE_LINK_PREPARE_FAILED", "временная ссылка имеет иные свойства")
        os.replace(temporary, primitive.target_path)
        _fsync_directory(primitive.target_path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    observed, _info, _target = _observe_link(primitive.target_path)
    if observed != primitive.expected_after:
        _fail(
            "ACTIVE_LINK_COMMIT_FAILED",
            "наблюдаемая ссылка отличается от expectedAfter",
        )
    return _mutation_result(primitive, observed)


def build_prepared_manifest_plan_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    activation_tree_sha256: str,
    installer_source_digest: str | None = None,
) -> PreparedManifestPlanV2:
    """Построить без записи точное логическое намерение source-манифеста."""

    if _lexists(proof.layout.journal_path):
        reverify_activation_transition_proof_v2(
            proof,
            operation_id=staged.operation_id,
            require_journal=True,
        )
    else:
        reverify_activation_transition_proof_v2(proof)
    _validate_staged_manifest_subject(proof, staged)
    activation_tree_sha256 = _sha256(
        activation_tree_sha256,
        "ACTIVATION_TREE_SHA256_INVALID",
    )
    _verify_original_manifest_and_owned_receipts(proof)
    return _build_prepared_manifest_plan_from_verified_proof_v2(
        proof=proof,
        staged=staged,
        activation_tree_sha256=activation_tree_sha256,
        installer_source_digest=installer_source_digest,
    )


def _build_prepared_manifest_plan_from_verified_proof_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    activation_tree_sha256: str,
    installer_source_digest: str | None = None,
) -> PreparedManifestPlanV2:
    """Чисто построить план из уже проверенного переходного снимка."""

    _validate_staged_manifest_subject(proof, staged)
    activation_tree_sha256 = _sha256(
        activation_tree_sha256,
        "ACTIVATION_TREE_SHA256_INVALID",
    )
    manifest = _updated_manifest_document(
        proof,
        staged,
        activation_tree_sha256=activation_tree_sha256,
        installer_source_digest=installer_source_digest,
    )
    prepared_raw = canonical_json_bytes(manifest)
    content_sha256 = hashlib.sha256(prepared_raw).hexdigest()
    prepared_path = proof.layout.manifest_root / "prepared-manifests" / (
        f"{staged.operation_id}.{content_sha256}.manifest.json"
    )
    plan = PreparedManifestPlanV2(
        activation_proof_fingerprint=proof.proof_fingerprint,
        operation_id=staged.operation_id,
        activation_id=staged.activation_id,
        activation_tree_sha256=activation_tree_sha256,
        target_path=proof.layout.manifest_path,
        prepared_path=prepared_path,
        manifest_document=manifest,
        prepared_raw=prepared_raw,
        plan_fingerprint="0" * 64,
    )
    return PreparedManifestPlanV2(
        activation_proof_fingerprint=plan.activation_proof_fingerprint,
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        activation_tree_sha256=plan.activation_tree_sha256,
        target_path=plan.target_path,
        prepared_path=plan.prepared_path,
        manifest_document=plan.manifest_document,
        prepared_raw=plan.prepared_raw,
        plan_fingerprint=_prepared_manifest_plan_fingerprint(plan),
    )


def materialize_prepared_manifest_plan_v2(
    *,
    plan: PreparedManifestPlanV2,
    preparation_journal_path: Path,
) -> PreparedManifestCommitV2:
    """Материализовать source только после долговечного намерения prep-step."""

    if not isinstance(plan, PreparedManifestPlanV2) or not plan.complete:
        _fail("MANIFEST_PREPARED_INVALID", "логическое намерение манифеста неполно")
    _raw, journal = _read_private_json_bytes(
        preparation_journal_path,
        code="MANIFEST_PREPARATION_JOURNAL_INVALID",
        require_canonical=True,
    )
    steps = journal.get("steps")
    matches = (
        []
        if type(steps) is not list
        else [step for step in steps if step.get("kind") == "prepared_manifest_file"]
    )
    expected = None if len(matches) != 1 else matches[0].get("expectedLogical")
    if (
        journal.get("journalKind") != "activation-preparation"
        or journal.get("operationId") != plan.operation_id
        or len(matches) != 1
        or matches[0].get("state") != "INTENT_DURABLE"
        or type(expected) is not dict
        or expected.get("path") != str(plan.prepared_path)
        or expected.get("objectType") != "regular-file"
        or expected.get("mode") != "0600"
        or expected.get("contentSha256")
        != hashlib.sha256(plan.prepared_raw).hexdigest()
    ):
        _fail(
            "MANIFEST_PREPARATION_INTENT_REQUIRED",
            "prepared manifest effect has no exact durable prep intent",
        )
    _materialize_prepared_manifest_plan_v2(plan)
    return prepared_manifest_commit_from_plan_v2(plan)


def _materialize_prepared_manifest_plan_v2(plan: PreparedManifestPlanV2) -> None:
    _ensure_private_directory(plan.prepared_path.parent)
    _create_or_verify_prepared_manifest(
        plan.prepared_path,
        plan.prepared_raw,
        plan.manifest_document,
    )


def prepared_manifest_commit_from_plan_v2(
    plan: PreparedManifestPlanV2,
) -> PreparedManifestCommitV2:
    """Связать логическое намерение с уже созданным точным source inode."""

    if not isinstance(plan, PreparedManifestPlanV2) or not plan.complete:
        _fail("MANIFEST_PREPARED_INVALID", "логическое намерение манифеста неполно")
    raw, document = _read_private_json_bytes(
        plan.prepared_path,
        code="MANIFEST_PREPARED_CHANGED",
        require_canonical=True,
    )
    if raw != plan.prepared_raw or document != dict(plan.manifest_document):
        _fail("MANIFEST_PREPARED_CHANGED", "prepared manifest source changed")
    prepared_file_projection = _file_projection(plan.prepared_path)
    prepared_parent = plan.prepared_path.parent.lstat()
    prepared_file = _projection(
        "file-object-v2",
        prepared_file_projection,
        "codex-smart/file-object/v2",
    )
    expected_file = copy.deepcopy(prepared_file_projection)
    expected_file["path"] = str(plan.target_path)
    expected_after = _manifest_projection(
        plan.target_path,
        plan.manifest_document,
        file_projection=expected_file,
    )
    prepared = PreparedManifestCommitV2(
        activation_proof_fingerprint=plan.activation_proof_fingerprint,
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        activation_tree_sha256=plan.activation_tree_sha256,
        target_path=plan.target_path,
        prepared_path=plan.prepared_path,
        prepared_parent_device=prepared_parent.st_dev,
        prepared_parent_inode=prepared_parent.st_ino,
        manifest_document=plan.manifest_document,
        prepared_raw=plan.prepared_raw,
        prepared_file_projection=prepared_file_projection,
        prepared_file=prepared_file,
        expected_after=expected_after,
        preparation_fingerprint="0" * 64,
    )
    return PreparedManifestCommitV2(
        activation_proof_fingerprint=prepared.activation_proof_fingerprint,
        operation_id=prepared.operation_id,
        activation_id=prepared.activation_id,
        activation_tree_sha256=prepared.activation_tree_sha256,
        target_path=prepared.target_path,
        prepared_path=prepared.prepared_path,
        prepared_parent_device=prepared.prepared_parent_device,
        prepared_parent_inode=prepared.prepared_parent_inode,
        manifest_document=prepared.manifest_document,
        prepared_raw=prepared.prepared_raw,
        prepared_file_projection=prepared.prepared_file_projection,
        prepared_file=prepared.prepared_file,
        expected_after=prepared.expected_after,
        preparation_fingerprint=_prepared_manifest_fingerprint(prepared),
    )


def prepared_manifest_commit_from_receipt_v2(
    *,
    plan: PreparedManifestPlanV2,
    prepared_file: ProjectionV2,
    prepared_parent: ProjectionV2,
) -> PreparedManifestCommitV2:
    """Восстановить primitive binding без требования существующего source."""

    if not isinstance(plan, PreparedManifestPlanV2) or not plan.complete:
        _fail("MANIFEST_PREPARED_INVALID", "логическое намерение манифеста неполно")
    if (
        not isinstance(prepared_file, ProjectionV2)
        or prepared_file.schema_id != "file-object-v2"
        or prepared_file
        != _projection(
            "file-object-v2",
            prepared_file.value,
            "codex-smart/file-object/v2",
        )
        or prepared_file.value.get("path") != str(plan.prepared_path)
        or prepared_file.value.get("mode") != "0600"
        or prepared_file.value.get("sha256")
        != hashlib.sha256(plan.prepared_raw).hexdigest()
        or not isinstance(prepared_parent, ProjectionV2)
        or prepared_parent.schema_id != "directory-binding-v2"
        or prepared_parent
        != _projection(
            "directory-binding-v2",
            prepared_parent.value,
            "codex-smart/directory-binding/v2",
        )
        or prepared_parent.value.get("path") != str(plan.prepared_path.parent)
        or prepared_parent.value.get("mode") != "0700"
    ):
        _fail(
            "MANIFEST_PREPARATION_RECEIPT_INVALID",
            "prep receipt does not bind the manifest source and parent",
        )
    expected_file = copy.deepcopy(dict(prepared_file.value))
    expected_file["path"] = str(plan.target_path)
    expected_after = _manifest_projection(
        plan.target_path,
        plan.manifest_document,
        file_projection=expected_file,
    )
    prepared = PreparedManifestCommitV2(
        activation_proof_fingerprint=plan.activation_proof_fingerprint,
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        activation_tree_sha256=plan.activation_tree_sha256,
        target_path=plan.target_path,
        prepared_path=plan.prepared_path,
        prepared_parent_device=int(prepared_parent.value["device"]),
        prepared_parent_inode=int(prepared_parent.value["inode"]),
        manifest_document=plan.manifest_document,
        prepared_raw=plan.prepared_raw,
        prepared_file_projection=prepared_file.value,
        prepared_file=prepared_file,
        expected_after=expected_after,
        preparation_fingerprint="0" * 64,
    )
    return PreparedManifestCommitV2(
        activation_proof_fingerprint=prepared.activation_proof_fingerprint,
        operation_id=prepared.operation_id,
        activation_id=prepared.activation_id,
        activation_tree_sha256=prepared.activation_tree_sha256,
        target_path=prepared.target_path,
        prepared_path=prepared.prepared_path,
        prepared_parent_device=prepared.prepared_parent_device,
        prepared_parent_inode=prepared.prepared_parent_inode,
        manifest_document=prepared.manifest_document,
        prepared_raw=prepared.prepared_raw,
        prepared_file_projection=prepared.prepared_file_projection,
        prepared_file=prepared.prepared_file,
        expected_after=prepared.expected_after,
        preparation_fingerprint=_prepared_manifest_fingerprint(prepared),
    )


def prepare_manifest_file_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    activation_tree_sha256: str,
) -> PreparedManifestCommitV2:
    """Совместимый путь только под уже существующим основным журналом."""

    if not _lexists(proof.layout.journal_path):
        _fail(
            "MANIFEST_PREPARATION_JOURNAL_REQUIRED",
            "создание source-файла запрещено до долговечного журнала",
        )
    plan = build_prepared_manifest_plan_v2(
        proof=proof,
        staged=staged,
        activation_tree_sha256=activation_tree_sha256,
    )
    _materialize_prepared_manifest_plan_v2(plan)
    prepared = prepared_manifest_commit_from_plan_v2(plan)
    verify_prepared_manifest_file_v2(
        proof=proof,
        staged=staged,
        prepared=prepared,
    )
    return prepared


def verify_prepared_manifest_file_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    prepared: PreparedManifestCommitV2,
) -> PreparedManifestCommitV2:
    """Повторно доказать содержимое и физическую идентичность source inode."""

    if not isinstance(prepared, PreparedManifestCommitV2) or not prepared.complete:
        _fail("MANIFEST_PREPARED_INVALID", "подготовка манифеста неполна")
    _validate_complete_proof(proof)
    _validate_staged_manifest_subject(proof, staged)
    if (
        prepared.activation_proof_fingerprint != proof.proof_fingerprint
        or prepared.operation_id != staged.operation_id
        or prepared.activation_id != staged.activation_id
        or prepared.target_path != proof.layout.manifest_path
        or prepared.manifest_document
        != _updated_manifest_document(
            proof,
            staged,
            activation_tree_sha256=prepared.activation_tree_sha256,
            installer_source_digest=_installer_source_digest_from_manifest(
                prepared.manifest_document
            ),
        )
    ):
        _fail(
            "MANIFEST_PREPARED_INVALID",
            "подготовка манифеста не связана со снимком и кандидатом",
        )
    raw, document = _read_private_json_bytes(
        prepared.prepared_path,
        code="MANIFEST_PREPARED_CHANGED",
        require_canonical=True,
    )
    if (
        raw != prepared.prepared_raw
        or document != dict(prepared.manifest_document)
        or not _durable_filesystem_projection_matches(
            prepared.prepared_file_projection,
            _file_projection(prepared.prepared_path),
        )
        or prepared.prepared_file.value
        != dict(prepared.prepared_file_projection)
    ):
        _fail("MANIFEST_PREPARED_CHANGED", "prepared manifest source changed")
    expected_file = copy.deepcopy(dict(prepared.prepared_file_projection))
    expected_file["path"] = str(prepared.target_path)
    expected_after = _manifest_projection(
        prepared.target_path,
        prepared.manifest_document,
        file_projection=expected_file,
    )
    if expected_after != prepared.expected_after:
        _fail("MANIFEST_PREPARED_INVALID", "ожидаемая проекция манифеста изменилась")
    if staged.activation_dir.exists():
        if (
            _tree_sha256(staged.activation_dir)
            != prepared.activation_tree_sha256
            or _manifest_artifacts(
                codex_home=proof.codex_home,
                activation_dir=staged.activation_dir,
                snapshot_path=staged.snapshot_path,
                fallback_path=proof.layout.fallback_path,
                lock_path=proof.layout.lock_path,
            )
            != prepared.manifest_document.get("artifacts")
        ):
            _fail(
                "MANIFEST_PREPARED_CHANGED",
                "prepared manifest differs from the materialized activation tree",
            )
    return prepared


def observe_prepared_manifest_transition_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    prepared: PreparedManifestCommitV2,
) -> PreparedManifestTransitionStateV2:
    """Однозначно различить состояние до или после атомарного ``os.replace``."""

    if not isinstance(prepared, PreparedManifestCommitV2) or not prepared.complete:
        _fail("MANIFEST_PREPARED_INVALID", "подготовка манифеста неполна")
    _validate_complete_proof(proof)
    _validate_staged_manifest_subject(proof, staged)
    if (
        prepared.activation_proof_fingerprint != proof.proof_fingerprint
        or prepared.operation_id != staged.operation_id
        or prepared.activation_id != staged.activation_id
        or prepared.target_path != proof.layout.manifest_path
        or prepared.manifest_document
        != _updated_manifest_document(
            proof,
            staged,
            activation_tree_sha256=prepared.activation_tree_sha256,
            installer_source_digest=_installer_source_digest_from_manifest(
                prepared.manifest_document
            ),
        )
    ):
        _fail(
            "MANIFEST_PREPARED_INVALID",
            "подготовка манифеста не связана со снимком и кандидатом",
        )
    try:
        parent = prepared.prepared_path.parent.lstat()
    except OSError as exc:
        _fail("MANIFEST_TRANSITION_AMBIGUOUS", str(exc))
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or not _captured_device_is_valid(prepared.prepared_parent_device)
        or parent.st_ino != prepared.prepared_parent_inode
    ):
        _fail(
            "MANIFEST_TRANSITION_AMBIGUOUS",
            "родитель подготовленного манифеста заменён",
        )

    target_raw, target_document = _read_private_json_bytes(
        prepared.target_path,
        code="MANIFEST_TRANSITION_AMBIGUOUS",
        require_canonical=True,
    )
    if (
        target_raw == proof.manifest_raw
        and target_document == dict(proof.manifest_document)
        and _durable_manifest_projection_matches(
            proof.manifest_projection,
            _manifest_projection(prepared.target_path, target_document),
        )
    ):
        if not _lexists(prepared.prepared_path):
            _fail(
                "MANIFEST_TRANSITION_AMBIGUOUS",
                "target остался before, но подготовленный source отсутствует",
            )
        verify_prepared_manifest_file_v2(
            proof=proof,
            staged=staged,
            prepared=prepared,
        )
        return PreparedManifestTransitionStateV2.BEFORE

    if (
        target_raw == prepared.prepared_raw
        and target_document == dict(prepared.manifest_document)
        and _durable_manifest_projection_matches(
            prepared.expected_after,
            _manifest_projection(prepared.target_path, target_document),
        )
    ):
        if _lexists(prepared.prepared_path):
            _fail(
                "MANIFEST_TRANSITION_AMBIGUOUS",
                "target уже after, но source одновременно существует",
            )
        return PreparedManifestTransitionStateV2.AFTER

    _fail(
        "MANIFEST_TRANSITION_AMBIGUOUS",
        "пара source/target не совпадает ни с before, ни с after",
    )


def build_manifest_commit_plan_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    prepared: PreparedManifestCommitV2,
) -> ManifestCommitPlanV2:
    """Построить намерение commit без проверки живого source/target."""

    _validate_staged_manifest_subject(proof, staged)
    if not isinstance(prepared, PreparedManifestCommitV2) or not prepared.complete:
        _fail(
            "MANIFEST_PREPARATION_RECEIPT_REQUIRED",
            "manifest_commit требует source inode из подготовительной квитанции",
        )
    if (
        prepared.activation_proof_fingerprint != proof.proof_fingerprint
        or prepared.operation_id != staged.operation_id
        or prepared.activation_id != staged.activation_id
        or prepared.target_path != proof.layout.manifest_path
        or prepared.manifest_document
        != _updated_manifest_document(
            proof,
            staged,
            activation_tree_sha256=prepared.activation_tree_sha256,
            installer_source_digest=_installer_source_digest_from_manifest(
                prepared.manifest_document
            ),
        )
    ):
        _fail(
            "MANIFEST_PREPARED_INVALID",
            "подготовка манифеста не связана со снимком и кандидатом",
        )
    action = {
        "actionKind": "file-mutation",
        "method": "atomic-prepared-manifest-replace",
        "sourcePath": str(prepared.prepared_path),
        "targetPath": str(proof.layout.manifest_path),
        "durability": "FSYNC_FILE_AND_PARENT",
    }
    plan = ManifestCommitPlanV2(
        activation_proof_fingerprint=proof.proof_fingerprint,
        operation_id=staged.operation_id,
        activation_id=staged.activation_id,
        target_path=proof.layout.manifest_path,
        before=proof.manifest_projection,
        expected_after=prepared.expected_after,
        action=action,
        prepared=prepared,
        plan_fingerprint="0" * 64,
    )
    return ManifestCommitPlanV2(
        activation_proof_fingerprint=plan.activation_proof_fingerprint,
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        target_path=plan.target_path,
        before=plan.before,
        expected_after=plan.expected_after,
        action=plan.action,
        prepared=plan.prepared,
        plan_fingerprint=_manifest_commit_plan_fingerprint(plan),
    )


def authorize_manifest_commit_plan_v2(
    *,
    plan: ManifestCommitPlanV2,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    acceptance: CandidateAcceptanceProofV2,
) -> ActivationMutationPrimitiveV2:
    """Связать план commit с исторически восстановимым принятием кандидата."""

    _validate_acceptance_authorization(proof, staged, acceptance)
    _validate_gate_journal(proof, staged.operation_id)
    expected_plan = build_manifest_commit_plan_v2(
        proof=proof,
        staged=staged,
        prepared=plan.prepared if isinstance(plan, ManifestCommitPlanV2) else None,
    )
    if (
        not isinstance(plan, ManifestCommitPlanV2)
        or not plan.complete
        or plan != expected_plan
    ):
        _fail("MANIFEST_COMMIT_PLAN_CHANGED", "план манифеста не совпадает")
    _require_candidate_link(proof.layout, staged.activation_id)
    observe_prepared_manifest_transition_v2(
        proof=proof,
        staged=staged,
        prepared=plan.prepared,
    )
    primitive = ActivationMutationPrimitiveV2(
        kind="manifest_commit",
        operation_id=plan.operation_id,
        activation_id=plan.activation_id,
        target_path=plan.target_path,
        before=plan.before,
        expected_after=plan.expected_after,
        action=plan.action,
        authorization_fingerprint=acceptance.proof_fingerprint,
        primitive_fingerprint="0" * 64,
        prepared_path=plan.prepared.prepared_path,
        prepared_raw=plan.prepared.prepared_raw,
        prepared_file_projection=plan.prepared.prepared_file_projection,
        manifest_document=plan.prepared.manifest_document,
    )
    return _replace_primitive_fingerprint(primitive, _primitive_fingerprint(primitive))


def prepare_manifest_commit_primitive_v2(
    *,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    acceptance: CandidateAcceptanceProofV2,
    prepared: PreparedManifestCommitV2 | None = None,
) -> ActivationMutationPrimitiveV2:
    """Совместимый путь: построить чистый план и отдельно авторизовать его."""

    if prepared is None:
        _fail(
            "MANIFEST_PREPARATION_RECEIPT_REQUIRED",
            "manifest_commit требует source inode из подготовительной квитанции",
        )
    plan = build_manifest_commit_plan_v2(
        proof=proof,
        staged=staged,
        prepared=prepared,
    )
    return authorize_manifest_commit_plan_v2(
        plan=plan,
        proof=proof,
        staged=staged,
        acceptance=acceptance,
    )


def apply_manifest_commit_primitive_v2(
    primitive: ActivationMutationPrimitiveV2,
    *,
    acceptance: CandidateAcceptanceProofV2,
) -> ActivationMutationResultV2:
    """Обработчик `manifest_commit` с атомарной заменой подготовленного inode."""

    _validate_primitive(primitive, kind="manifest_commit")
    if (
        not acceptance.complete
        or primitive.authorization_fingerprint != acceptance.proof_fingerprint
        or primitive.operation_id != acceptance.operation_id
        or primitive.activation_id != acceptance.activation_id
    ):
        _fail("CANDIDATE_ACCEPTANCE_REQUIRED", "кандидат не доказан портом")
    if primitive.manifest_document is None:
        _fail("MANIFEST_PRIMITIVE_INVALID", "нет документа манифеста")
    _live_raw, live_document = _read_private_json_bytes(
        primitive.target_path,
        code="MANIFEST_CHANGED",
        require_canonical=True,
    )
    observed = _manifest_projection(primitive.target_path, live_document)
    if _durable_manifest_projection_matches(primitive.expected_after, observed):
        return _mutation_result(primitive, primitive.expected_after)
    if not _durable_manifest_projection_matches(primitive.before, observed):
        _fail("MANIFEST_CHANGED", "живой манифест не совпадает с before")
    if (
        primitive.prepared_path is None
        or primitive.prepared_raw is None
        or primitive.prepared_file_projection is None
    ):
        _fail("MANIFEST_PRIMITIVE_INVALID", "подготовленный файл не доказан")
    raw, document = _read_private_json_bytes(
        primitive.prepared_path,
        code="MANIFEST_PREPARED_CHANGED",
        require_canonical=True,
    )
    if (
        raw != primitive.prepared_raw
        or document != dict(primitive.manifest_document)
        or not _durable_filesystem_projection_matches(
            primitive.prepared_file_projection,
            _file_projection(primitive.prepared_path),
        )
    ):
        _fail("MANIFEST_PREPARED_CHANGED", "подготовленный inode заменён")
    os.replace(primitive.prepared_path, primitive.target_path)
    _fsync_directory(primitive.target_path.parent)
    observed = _manifest_projection(primitive.target_path, primitive.manifest_document)
    if not _durable_manifest_projection_matches(
        primitive.expected_after,
        observed,
    ):
        _fail("MANIFEST_COMMIT_FAILED", "observedAfter отличается от expectedAfter")
    return _mutation_result(primitive, primitive.expected_after)


def capture_activation_transition_proof_v2(
    *,
    codex_home: Path,
    wrapper: Path,
    installer_receipt_path: Path | None = None,
    snapshot_verifier=None,
) -> ActivationTransitionProofV2:
    """Доказать текущую принятую активацию до создания журнала перехода."""

    codex_home = _absolute_path(codex_home, "CODEX_HOME_INVALID")
    wrapper = _absolute_path(wrapper, "WRAPPER_INVALID")
    layout = GatewayLayout.for_codex_home(codex_home)
    if _lexists(layout.journal_path):
        _fail(
            "OPERATION_JOURNAL_PRESENT",
            "снимок перехода разрешён только до появления основного журнала",
        )
    try:
        decision = ActivationResolver(
            layout=layout,
            wrapper=wrapper,
            snapshot_verifier=snapshot_verifier,
        ).resolve_persisted_activation()
    except Exception as exc:
        _fail(
            str(getattr(exc, "code", "ACTIVATION_PROOF_FAILED")),
            f"принятая активация не доказана: {exc}",
        )
    binding = decision.runtime_binding
    if decision.state is not GatewayState.READY or binding is None:
        _fail(
            "ACTIVATION_PROOF_INCOMPLETE",
            "шлюз не вернул полную привязку принятой активации",
        )
    if _lexists(layout.journal_path):
        _fail(
            "OPERATION_JOURNAL_PRESENT",
            "журнал появился во время захвата снимка",
        )

    manifest_raw, manifest = _read_private_json_bytes(
        layout.manifest_path,
        code="MANIFEST_CHANGED",
        require_canonical=True,
    )
    active = manifest.get("activeActivation")
    if type(active) is not dict or active.get("activationId") != binding.activation_id:
        _fail("ACTIVE_POINTER_CHANGED", "активный указатель расходится со шлюзом")
    installation_id = _identifier(
        manifest.get("installationId"), _INSTALLATION_ID, "INSTALLATION_ID_INVALID"
    )
    current_operation_id = _identifier(
        manifest.get("lastCommittedOperation"),
        _OPERATION_ID,
        "COMMIT_OPERATION_INVALID",
    )
    activation_id = _identifier(
        active.get("activationId"), _ACTIVATION_ID, "ACTIVE_POINTER_CHANGED"
    )
    activation_fingerprint = _sha256(
        active.get("activationFingerprint"), "ACTIVE_POINTER_CHANGED"
    )
    if activation_id != "act2_" + activation_fingerprint:
        _fail("ACTIVE_POINTER_CHANGED", "идентичность активной активации расходится")

    expected_target = f"activations/{activation_id}/marketplace"
    link_projection, link_info, link_target = _observe_link(layout.marketplace_link)
    if (
        active.get("symlinkTarget") != expected_target
        or link_target != expected_target
        or layout.marketplace_link.resolve(strict=True)
        != binding.marketplace_path.resolve(strict=True)
    ):
        _fail("ACTIVE_LINK_CHANGED", "ссылка не принадлежит активной активации")

    activation_dir = layout.managed_root / "activations" / activation_id
    activation_path = activation_dir / "activation.json"
    activation_raw, activation = _read_private_json_bytes(
        activation_path,
        code="ACTIVE_TREE_CHANGED",
        require_canonical=True,
    )
    if (
        activation.get("activationId") != activation_id
        or activation.get("activationFingerprint") != activation_fingerprint
        or activation.get("identity") != dict(binding.activation_identity)
    ):
        _fail("ACTIVE_TREE_CHANGED", "activation.json расходится со шлюзом")
    activation_tree = _projection(
        "tree-object-v2",
        _tree_projection(activation_dir),
        "codex-smart/tree-object/v2",
    )

    receipt_path = (
        layout.receipts_root / installation_id / f"{current_operation_id}.commit.json"
    )
    commit_raw, commit = _read_private_json_bytes(
        receipt_path,
        code="COMMIT_RECEIPT_CHANGED",
        require_canonical=True,
    )
    if (
        commit.get("receiptKind") != "activation-commit"
        or commit.get("installationId") != installation_id
        or commit.get("operationId") != current_operation_id
        or commit.get("controllerIdentity")
        != binding.controller_row.get("controller_identity")
        or commit.get("databaseBinding") is None
    ):
        _fail("COMMIT_RECEIPT_CHANGED", "квитанция фиксации расходится со шлюзом")
    try:
        manifest_projection = ProjectionV2.from_document(commit["manifest"])
        activation_projection = ProjectionV2.from_document(commit["activation"])
        database_binding = ProjectionV2.from_document(commit["databaseBinding"])
    except Exception as exc:
        _fail("COMMIT_RECEIPT_CHANGED", f"проекции квитанции неполны: {exc}")
    if (
        not _durable_filesystem_projection_matches(
            manifest_projection.value.get("file"),
            _file_projection(layout.manifest_path),
        )
        or not _durable_filesystem_projection_matches(
            activation_projection.value.get("directory"),
            activation_tree.value,
        )
        or database_binding.to_document() != commit["databaseBinding"]
        or database_binding.value.get("path") != str(binding.database_path)
        or database_binding.value.get("activationIdentity", {}).get("activationId")
        != activation_id
    ):
        _fail("COMMIT_RECEIPT_CHANGED", "живые объекты расходятся с квитанцией")

    installer_path = (
        layout.manifest_root / _INSTALLER_RECEIPT_NAME
        if installer_receipt_path is None
        else _absolute_path(installer_receipt_path, "INSTALLER_RECEIPT_INVALID")
    )
    try:
        installer_raw, installer = _read_private_json_bytes(
            installer_path,
            code="INSTALLER_RECEIPT_INVALID",
            require_canonical=False,
        )
    except FileNotFoundError:
        _fail("INSTALLER_RECEIPT_MISSING", "квитанция владения установщика отсутствует")
    _validate_installer_receipt(
        installer,
        codex_home=codex_home,
        layout=layout,
        installation_id=installation_id,
        binding=binding,
        executable=decision.executable,
    )

    manifest_file = _file_projection(layout.manifest_path)
    receipt_file = _file_projection(receipt_path)
    installer_file = _file_projection(installer_path)
    proof = ActivationTransitionProofV2(
        codex_home=codex_home,
        layout=layout,
        installation_id=installation_id,
        activation_id=activation_id,
        activation_fingerprint=activation_fingerprint,
        current_operation_id=current_operation_id,
        state_home=Path(binding.state_home),
        database_path=Path(binding.database_path),
        activation_dir=activation_dir,
        manifest_raw=manifest_raw,
        manifest_document=manifest,
        manifest_file_projection=manifest_file,
        manifest_projection=manifest_projection,
        active_pointer=active,
        link_target=link_target,
        link_device=link_info.st_dev,
        link_inode=link_info.st_ino,
        link_projection=link_projection,
        activation_raw=activation_raw,
        activation_document=activation,
        activation_tree_projection=activation_tree,
        activation_projection=activation_projection,
        commit_receipt_path=receipt_path,
        commit_receipt_raw=commit_raw,
        commit_receipt_document=commit,
        commit_receipt_file_projection=receipt_file,
        commit_receipt_projection=_receipt_projection(receipt_path, commit),
        database_binding=database_binding,
        database_identity_row=dict(binding.database_identity_row),
        controller_row=dict(binding.controller_row),
        controller_identity=str(binding.controller_row["controller_identity"]),
        installer_receipt_path=installer_path,
        installer_receipt_raw=installer_raw,
        installer_receipt_document=installer,
        installer_receipt_file_projection=installer_file,
        installer_receipt_projection=_projection(
            "file-object-v2",
            installer_file,
            "codex-smart/file-object/v2",
        ),
        proof_fingerprint="0" * 64,
    )
    proof = _replace_proof_fingerprint(proof, _proof_fingerprint(proof))
    if not proof.complete:
        _fail("ACTIVATION_PROOF_INCOMPLETE", "снимок перехода не замкнут")
    if _lexists(layout.journal_path):
        _fail("OPERATION_JOURNAL_PRESENT", "журнал появился во время захвата снимка")
    return proof


def reverify_activation_transition_proof_v2(
    proof: ActivationTransitionProofV2,
    *,
    operation_id: str | None = None,
    require_journal: bool = False,
) -> ActivationTransitionProofV2:
    """Повторно сверить снимок, в том числе после атомарного `gate_close`."""

    _validate_complete_proof(proof)
    if require_journal:
        if operation_id is None:
            _fail("OPERATION_ID_INVALID", "для журнала требуется operationId")
        _validate_gate_journal(proof, operation_id)
    elif _lexists(proof.layout.journal_path):
        _fail("OPERATION_JOURNAL_PRESENT", "неожиданный основной журнал")

    manifest_raw, manifest = _read_private_json_bytes(
        proof.layout.manifest_path,
        code="MANIFEST_CHANGED",
        require_canonical=True,
    )
    if (
        manifest_raw != proof.manifest_raw
        or manifest != dict(proof.manifest_document)
        or _file_projection(proof.layout.manifest_path)
        != dict(proof.manifest_file_projection)
    ):
        _fail("MANIFEST_CHANGED", "манифест изменён после захвата снимка")

    link_projection, link_info, link_target = _observe_link(
        proof.layout.marketplace_link
    )
    if (
        link_info.st_dev != proof.link_device
        or link_info.st_ino != proof.link_inode
        or link_target != proof.link_target
        or link_projection != proof.link_projection
    ):
        _fail("ACTIVE_LINK_CHANGED", "активная ссылка заменена после снимка")

    activation_raw, activation = _read_private_json_bytes(
        proof.activation_dir / "activation.json",
        code="ACTIVE_TREE_CHANGED",
        require_canonical=True,
    )
    try:
        tree = _projection(
            "tree-object-v2",
            _tree_projection(proof.activation_dir),
            "codex-smart/tree-object/v2",
        )
    except Exception as exc:
        _fail("ACTIVE_TREE_CHANGED", str(exc))
    if (
        activation_raw != proof.activation_raw
        or activation != dict(proof.activation_document)
        or tree != proof.activation_tree_projection
    ):
        _fail("ACTIVE_TREE_CHANGED", "дерево активной активации изменено")

    commit_raw, commit = _read_private_json_bytes(
        proof.commit_receipt_path,
        code="COMMIT_RECEIPT_CHANGED",
        require_canonical=True,
    )
    if (
        commit_raw != proof.commit_receipt_raw
        or commit != dict(proof.commit_receipt_document)
        or _file_projection(proof.commit_receipt_path)
        != dict(proof.commit_receipt_file_projection)
    ):
        _fail("COMMIT_RECEIPT_CHANGED", "квитанция фиксации заменена")

    installer_raw, installer = _read_private_json_bytes(
        proof.installer_receipt_path,
        code="INSTALLER_RECEIPT_CHANGED",
        require_canonical=False,
    )
    if (
        installer_raw != proof.installer_receipt_raw
        or installer != dict(proof.installer_receipt_document)
        or _file_projection(proof.installer_receipt_path)
        != dict(proof.installer_receipt_file_projection)
    ):
        _fail("INSTALLER_RECEIPT_CHANGED", "квитанция владения заменена")
    _validate_installer_links(
        installer,
        layout=proof.layout,
        registered_marketplace=Path(str(installer["registeredMarketplacePath"])),
    )
    _validate_database_file_identity(proof.database_binding)
    return proof


def stage_upgrade_activation_v2(
    *,
    proof: ActivationTransitionProofV2,
    operation_id: str,
    source_root: Path,
    codex_binary: Path,
    policy_bundle: PolicyBundleV2,
    snapshotter=None,
    interface_executor: SnapshotCommandExecutor | None = None,
    completed_at: datetime | None = None,
) -> StagedActivationV2:
    """Создать неизменяемого кандидата рядом с принятой активацией.

    Текущий манифест, ссылка и регистрационные объекты не изменяются. Перед и
    после материализации заново сверяются все объекты исходного снимка.
    """

    operation_id = _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    if operation_id == proof.current_operation_id:
        _fail("OPERATION_ID_REUSED", "обновление требует новый operationId")
    _validate_complete_proof(proof)
    reverify_activation_transition_proof_v2(
        proof, operation_id=operation_id, require_journal=True
    )
    source_root = source_root.expanduser().resolve()
    codex_binary = _absolute_path(codex_binary, "CODEX_BINARY_INVALID")
    state_home = normalize_state_home_v2(proof.state_home)
    captured_at = _aware(completed_at or datetime.now(timezone.utc))
    layout = proof.layout
    if not source_root.is_dir():
        _fail("SOURCE_ROOT_INVALID", "корень исходников отсутствует")
    _validate_source_catalog_identity_v2(source_root)
    try:
        source_info = codex_binary.resolve(strict=True).stat()
    except OSError as exc:
        _fail("CODEX_BINARY_INVALID", str(exc))
    if not stat.S_ISREG(source_info.st_mode) or not os.access(codex_binary, os.X_OK):
        _fail("CODEX_BINARY_INVALID", "исходный Codex не исполняемый файл")

    _ensure_private_directory(layout.managed_root / "activations")
    _ensure_private_directory(layout.managed_root / "codex-snapshots")
    _ensure_private_directory(state_home)
    _ensure_private_directory(state_home / "databases")
    _ensure_lock_file(layout.lock_path)
    temporary_stage: Path | None = None
    activation_dir: Path | None = None
    with _exclusive_lock(layout.lock_path):
        reverify_activation_transition_proof_v2(
            proof, operation_id=operation_id, require_journal=True
        )
        snapshotter = snapshotter or CodexBinarySnapshotter(
            snapshot_root=layout.managed_root / "codex-snapshots"
        )
        try:
            subject = snapshotter.materialize(str(codex_binary))
            snapshot_path = _validate_snapshot_subject(
                subject,
                expected_root=layout.managed_root / "codex-snapshots",
                codex_binary=codex_binary,
            )
            observation = probe_codex_interface_v1(
                subject=subject,
                contract_root=source_root / "docs" / "contracts",
                policy_bundle=policy_bundle,
                executor=interface_executor,
            )
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
            _normalize_private_tree(temporary_stage)
            marketplace_sha = _tree_sha256(marketplace)
            generation_sha = _tree_sha256(plugin_root)
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
                schema_manifest.get("schemaFingerprint"), "schemaFingerprint"
            )
            schema_artifact_sha256 = _required_sha256(
                schema_manifest.get("stateSqlSha256"), "stateSqlSha256"
            )
            if _sha256_file(schema_artifact) != schema_artifact_sha256:
                _fail("SCHEMA_ARTIFACT_MISMATCH", "файл схемы кандидата изменён")
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
            if _lexists(activation_dir):
                _fail("ACTIVATION_ID_COLLISION", "кандидат уже существует")
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
            compatibility_fingerprint = str(
                observation.interface_evidence["compatibilityFingerprint"]
            )
            controller_identity = _controller_identity(
                codex_home=proof.codex_home,
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
            staged = StagedActivationV2(
                status="IDENTITY_STAGED",
                readiness="AWAITING_CONTROLLER_BIND",
                source_root=source_root,
                codex_home=proof.codex_home,
                codex_binary=codex_binary,
                state_home=state_home,
                socket_path=state_home / "controller.sock",
                controller_lock_path=state_home / "controller.lock",
                installation_id=proof.installation_id,
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
            )
            reverify_activation_transition_proof_v2(
                proof, operation_id=operation_id, require_journal=True
            )
            return staged
        except Exception:
            if activation_dir is not None and activation_dir.is_dir():
                shutil.rmtree(activation_dir)
                _fsync_directory(layout.managed_root / "activations")
            if temporary_stage is not None and temporary_stage.is_dir():
                shutil.rmtree(temporary_stage)
                _fsync_directory(layout.managed_root / "activations")
            raise


def _validate_command_proof(
    value: LifecycleControllerCommandProofV2,
    *,
    method: str,
    status: str,
    previous_epoch: int,
) -> None:
    if not isinstance(value, LifecycleControllerCommandProofV2):
        _fail("CONTROLLER_PROOF_INVALID", f"{method} вернул иной тип")
    payload = value.payload
    receipt = payload.get("commandReceipt") if isinstance(payload, Mapping) else None
    if (
        value.method != method
        or value.status != status
        or re.fullmatch(r"cc2_[0-9a-f]{32}", value.command_id) is None
        or _SHA256.fullmatch(value.request_fingerprint) is None
        or _SHA256.fullmatch(value.response_fingerprint) is None
        or type(value.previous_control_epoch) is not int
        or type(value.new_control_epoch) is not int
        or value.previous_control_epoch != previous_epoch
        or value.new_control_epoch != previous_epoch + 1
        or type(payload) is not dict
        or payload.get("status") != status
        or payload.get("previousControlEpoch") != previous_epoch
        or payload.get("newControlEpoch") != previous_epoch + 1
        or type(receipt) is not dict
        or receipt.get("commandId") != value.command_id
        or receipt.get("requestFingerprint") != value.request_fingerprint
        or _SHA256.fullmatch(str(receipt.get("resultFingerprint"))) is None
        or receipt.get("controlEpoch") != value.new_control_epoch
    ):
        _fail("CONTROLLER_PROOF_INVALID", f"квитанция {method} расходится")


def _validate_quiescence(
    value: LifecycleControllerQuiescenceV2,
    *,
    operation_id: str,
    control_epoch: int,
) -> None:
    if (
        not isinstance(value, LifecycleControllerQuiescenceV2)
        or value.operation_id != operation_id
        or value.control_epoch != control_epoch
        or value.state not in {"DRAINING", "MAINTENANCE"}
        or str(value.maintenance_mode).upper() != "DRAIN"
        or type(value.quiescent) is not bool
        or (value.quiescent and value.state != "MAINTENANCE")
    ):
        _fail("QUIESCENCE_PROOF_INVALID", "доказательство покоя расходится")


def _command_projection(value: LifecycleControllerCommandProofV2) -> dict[str, Any]:
    return {
        "method": value.method,
        "status": value.status,
        "commandId": value.command_id,
        "requestFingerprint": value.request_fingerprint,
        "responseFingerprint": value.response_fingerprint,
        "previousControlEpoch": value.previous_control_epoch,
        "newControlEpoch": value.new_control_epoch,
        "payload": copy.deepcopy(dict(value.payload)),
    }


def _shutdown_fingerprint(value: ControllerShutdownProofV2) -> str:
    projection = {
        "activationProofFingerprint": value.activation_proof_fingerprint,
        "operationId": value.operation_id,
        "maintenanceBegin": _command_projection(value.maintenance_begin),
        "quiescence": {
            "operationId": value.quiescence.operation_id,
            "state": value.quiescence.state,
            "maintenanceMode": value.quiescence.maintenance_mode,
            "controlEpoch": value.quiescence.control_epoch,
            "quiescent": value.quiescence.quiescent,
        },
        "maintenanceStrengthen": _command_projection(value.maintenance_strengthen),
        "shutdown": _command_projection(value.shutdown),
    }
    return domain_fingerprint(
        "codex-smart/controller-shutdown-transition/v2", projection
    )


def _acceptance_fingerprint(value: CandidateAcceptanceProofV2) -> str:
    return domain_fingerprint(
        "codex-smart/candidate-acceptance-transition/v2",
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "shutdownProofFingerprint": value.shutdown_proof_fingerprint,
            "operationId": value.operation_id,
            "activationId": value.activation_id,
            "databaseId": value.database_id,
            "candidateAccept": _command_projection(value.candidate_accept),
        },
    )


def _validate_staged_manifest_subject(
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
) -> None:
    _validate_complete_proof(proof)
    if (
        not isinstance(staged, StagedActivationV2)
        or staged.status != "IDENTITY_STAGED"
        or staged.installation_id != proof.installation_id
        or staged.codex_home != proof.codex_home
        or staged.operation_id == proof.current_operation_id
        or _OPERATION_ID.fullmatch(staged.operation_id) is None
        or _ACTIVATION_ID.fullmatch(staged.activation_id) is None
        or staged.activation_dir
        != proof.layout.managed_root / "activations" / staged.activation_id
        or not staged.state_home.is_absolute()
        or not staged.snapshot_path.is_absolute()
    ):
        _fail(
            "MANIFEST_PREPARED_INVALID",
            "кандидат не связан с принятой установкой",
        )


def _updated_manifest_document(
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    *,
    activation_tree_sha256: str,
    installer_source_digest: str | None = None,
) -> dict[str, Any]:
    _validate_staged_manifest_subject(proof, staged)
    activation_tree_sha256 = _sha256(
        activation_tree_sha256,
        "ACTIVATION_TREE_SHA256_INVALID",
    )
    manifest = copy.deepcopy(dict(proof.manifest_document))
    manifest.update(
        {
            "stateHome": str(staged.state_home),
            "sourceLocator": copy.deepcopy(dict(staged.source_locator)),
            "codexSnapshot": copy.deepcopy(dict(staged.snapshot_locator)),
            "activeActivation": _activation_pointer(staged),
            "previousActivation": copy.deepcopy(dict(proof.active_pointer)),
            "interfaceEvidence": copy.deepcopy(dict(staged.interface_evidence)),
            "routingPolicyFingerprint": staged.routing_policy_fingerprint,
            "bundledCatalogFingerprint": staged.bundled_catalog_fingerprint,
            "artifacts": _manifest_artifacts_for_preparation(
                codex_home=proof.codex_home,
                activation_dir=staged.activation_dir,
                activation_tree_sha256=activation_tree_sha256,
                snapshot_path=staged.snapshot_path,
                fallback_path=proof.layout.fallback_path,
                lock_path=proof.layout.lock_path,
            ),
            "lastCommittedOperation": staged.operation_id,
        }
    )
    if installer_source_digest is not None:
        source_digest = _sha256(
            installer_source_digest,
            "INSTALLER_SOURCE_DIGEST_INVALID",
        )
        extensions = manifest.get("extensions")
        if type(extensions) is not dict:
            _fail("MANIFEST_CHANGED", "extensions манифеста имеет неверный тип")
        extensions = copy.deepcopy(extensions)
        extensions["installerSourceDigest"] = source_digest
        if len(extensions) > 128:
            _fail("MANIFEST_CHANGED", "extensions манифеста переполнен")
        manifest["extensions"] = extensions
    if manifest.get("installationId") != proof.installation_id:
        _fail("MANIFEST_CHANGED", "installationId нельзя менять при обновлении")
    return manifest


def _installer_source_digest_from_manifest(
    manifest: Mapping[str, Any],
) -> str | None:
    extensions = manifest.get("extensions")
    if type(extensions) is not dict:
        _fail("MANIFEST_PREPARED_INVALID", "extensions манифеста имеет неверный тип")
    value = extensions.get("installerSourceDigest")
    if value is None:
        return None
    return _sha256(value, "INSTALLER_SOURCE_DIGEST_INVALID")


def _manifest_artifacts_for_preparation(
    *,
    codex_home: Path,
    activation_dir: Path,
    activation_tree_sha256: str,
    snapshot_path: Path,
    fallback_path: Path,
    lock_path: Path,
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = [
        {
            "type": "directory",
            "relativePath": str(activation_dir.relative_to(codex_home)),
            "mode": "0700",
            "treeSha256": activation_tree_sha256,
        }
    ]
    for path in (snapshot_path, fallback_path, lock_path):
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            _fail(
                "MANIFEST_ARTIFACT_INVALID",
                f"объект манифеста не является закрытым обычным файлом: {path}",
            )
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


def _create_or_verify_prepared_manifest(
    path: Path,
    raw: bytes,
    document: Mapping[str, Any],
) -> None:
    descriptor = -1
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_CREAT
            | os.O_EXCL
            | os.O_WRONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except FileExistsError:
        pass
    except BaseException:
        if created:
            try:
                path.unlink()
                _fsync_directory(path.parent)
            except FileNotFoundError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    observed_raw, observed = _read_private_json_bytes(
        path,
        code="MANIFEST_PREPARED_CONFLICT",
        require_canonical=True,
    )
    if observed_raw != raw or observed != dict(document):
        _fail(
            "MANIFEST_PREPARED_CONFLICT",
            "адресуемый файл манифеста содержит другое значение",
        )
    before_sync = _file_projection(path)
    _fsync_directory(path.parent)
    confirmed_raw, confirmed = _read_private_json_bytes(
        path,
        code="MANIFEST_PREPARED_CONFLICT",
        require_canonical=True,
    )
    if (
        confirmed_raw != raw
        or confirmed != dict(document)
        or _file_projection(path) != before_sync
    ):
        _fail(
            "MANIFEST_PREPARED_CONFLICT",
            "адресуемый файл изменился при подтверждении долговечности",
        )


def _prepared_manifest_plan_fingerprint(value: PreparedManifestPlanV2) -> str:
    return domain_fingerprint(
        "codex-smart/prepared-manifest-plan/v2",
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "operationId": value.operation_id,
            "activationId": value.activation_id,
            "activationTreeSha256": value.activation_tree_sha256,
            "targetPath": str(value.target_path),
            "preparedPath": str(value.prepared_path),
            "manifestSha256": hashlib.sha256(value.prepared_raw).hexdigest(),
        },
    )


def _activation_link_plan_fingerprint(value: ActivationLinkPlanV2) -> str:
    return domain_fingerprint(
        "codex-smart/activation-link-plan/v2",
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "operationId": value.operation_id,
            "activationId": value.activation_id,
            "targetPath": str(value.target_path),
            "before": value.before.to_document(),
            "expectedAfter": value.expected_after.to_document(),
            "action": copy.deepcopy(dict(value.action)),
            "beforeDevice": value.before_device,
            "beforeInode": value.before_inode,
        },
    )


def _manifest_commit_plan_fingerprint(value: ManifestCommitPlanV2) -> str:
    return domain_fingerprint(
        "codex-smart/manifest-commit-plan/v2",
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "operationId": value.operation_id,
            "activationId": value.activation_id,
            "targetPath": str(value.target_path),
            "before": value.before.to_document(),
            "expectedAfter": value.expected_after.to_document(),
            "action": copy.deepcopy(dict(value.action)),
            "preparationFingerprint": value.prepared.preparation_fingerprint,
        },
    )


def _prepared_manifest_fingerprint(value: PreparedManifestCommitV2) -> str:
    return domain_fingerprint(
        "codex-smart/prepared-manifest-commit/v2",
        {
            "activationProofFingerprint": value.activation_proof_fingerprint,
            "operationId": value.operation_id,
            "activationId": value.activation_id,
            "activationTreeSha256": value.activation_tree_sha256,
            "targetPath": str(value.target_path),
            "preparedPath": str(value.prepared_path),
            "preparedParentDevice": value.prepared_parent_device,
            "preparedParentInode": value.prepared_parent_inode,
            "manifestSha256": hashlib.sha256(value.prepared_raw).hexdigest(),
            "preparedFile": copy.deepcopy(dict(value.prepared_file_projection)),
            "expectedAfter": value.expected_after.to_document(),
        },
    )


def _validate_shutdown_authorization(
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    shutdown: ControllerShutdownProofV2,
) -> None:
    _validate_complete_proof(proof)
    if (
        not isinstance(staged, StagedActivationV2)
        or staged.status != "IDENTITY_STAGED"
        or staged.installation_id != proof.installation_id
        or staged.codex_home != proof.codex_home
        or staged.operation_id == proof.current_operation_id
        or not isinstance(shutdown, ControllerShutdownProofV2)
        or not shutdown.complete
        or shutdown.activation_proof_fingerprint != proof.proof_fingerprint
        or shutdown.operation_id != staged.operation_id
    ):
        _fail("CONTROLLER_PROOF_INVALID", "остановка не связана с кандидатом")


def _validate_acceptance_authorization(
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    acceptance: CandidateAcceptanceProofV2,
) -> None:
    _validate_complete_proof(proof)
    if (
        not isinstance(acceptance, CandidateAcceptanceProofV2)
        or not acceptance.complete
        or acceptance.activation_proof_fingerprint != proof.proof_fingerprint
        or acceptance.operation_id != staged.operation_id
        or acceptance.activation_id != staged.activation_id
        or acceptance.database_id != staged.database_id
    ):
        _fail("CANDIDATE_ACCEPTANCE_REQUIRED", "принятие не связано с кандидатом")


def _expected_link_projection_from_before_v2(
    before: ProjectionV2,
    *,
    path: Path,
    target: str,
) -> ProjectionV2:
    if (
        not isinstance(before, ProjectionV2)
        or before.schema_id != "symlink-object-v2"
        or before.value.get("path") != str(path)
    ):
        _fail("ACTIVATION_LINK_PLAN_INVALID", "before не является активной ссылкой")
    value = copy.deepcopy(dict(before.value))
    value["target"] = target
    value["targetFingerprint"] = hashlib.sha256(target.encode("utf-8")).hexdigest()
    return _projection("symlink-object-v2", value, "codex-smart/symlink-object/v2")


def _activation_pointer(staged: StagedActivationV2) -> dict[str, Any]:
    return {
        "activationId": staged.activation_id,
        "activationFingerprint": staged.activation_fingerprint,
        "symlinkTarget": f"activations/{staged.activation_id}/marketplace",
        "generationId": staged.identity["generationId"],
        "databaseId": staged.database_id,
    }


def _require_candidate_link(layout: GatewayLayout, activation_id: str) -> None:
    _projection_value, _info, target = _observe_link(layout.marketplace_link)
    if target != f"activations/{activation_id}/marketplace":
        _fail("CANDIDATE_LINK_NOT_PUBLISHED", "ссылка не совпадает с кандидатом")


def _verify_original_manifest_and_owned_receipts(
    proof: ActivationTransitionProofV2,
) -> None:
    manifest_raw, manifest = _read_private_json_bytes(
        proof.layout.manifest_path,
        code="MANIFEST_CHANGED",
        require_canonical=True,
    )
    if (
        manifest_raw != proof.manifest_raw
        or manifest != dict(proof.manifest_document)
        or _file_projection(proof.layout.manifest_path)
        != dict(proof.manifest_file_projection)
    ):
        _fail("MANIFEST_CHANGED", "манифест изменён до фиксации")
    activation_raw, activation = _read_private_json_bytes(
        proof.activation_dir / "activation.json",
        code="ACTIVE_TREE_CHANGED",
        require_canonical=True,
    )
    if (
        activation_raw != proof.activation_raw
        or activation != dict(proof.activation_document)
        or _projection(
            "tree-object-v2",
            _tree_projection(proof.activation_dir),
            "codex-smart/tree-object/v2",
        )
        != proof.activation_tree_projection
    ):
        _fail("ACTIVE_TREE_CHANGED", "предыдущая активация изменена")
    for path, raw, document, file_projection, code in (
        (
            proof.commit_receipt_path,
            proof.commit_receipt_raw,
            proof.commit_receipt_document,
            proof.commit_receipt_file_projection,
            "COMMIT_RECEIPT_CHANGED",
        ),
        (
            proof.installer_receipt_path,
            proof.installer_receipt_raw,
            proof.installer_receipt_document,
            proof.installer_receipt_file_projection,
            "INSTALLER_RECEIPT_CHANGED",
        ),
    ):
        observed_raw, observed_document = _read_private_json_bytes(
            path,
            code=code,
            require_canonical=(code == "COMMIT_RECEIPT_CHANGED"),
        )
        if (
            observed_raw != raw
            or observed_document != dict(document)
            or _file_projection(path) != dict(file_projection)
        ):
            _fail(code, "квитанция заменена до фиксации")
    _validate_database_file_identity(proof.database_binding)


def _manifest_projection(
    path: Path,
    manifest: Mapping[str, Any],
    *,
    file_projection: Mapping[str, Any] | None = None,
) -> ProjectionV2:
    active = manifest["activeActivation"]
    previous = manifest.get("previousActivation")
    semantic = domain_fingerprint(
        "codex-smart/manifest-semantic/v2",
        {
            key: copy.deepcopy(value)
            for key, value in manifest.items()
            if key != "extensions"
        },
    )
    value = {
        "file": (
            copy.deepcopy(dict(file_projection))
            if file_projection is not None
            else _file_projection(path)
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
        "semanticFingerprint": semantic,
    }
    return _projection("manifest-v2", value, "codex-smart/journal-state/v2")


def _primitive_projection(value: ActivationMutationPrimitiveV2) -> dict[str, Any]:
    return {
        "kind": value.kind,
        "operationId": value.operation_id,
        "activationId": value.activation_id,
        "targetPath": str(value.target_path),
        "before": value.before.to_document(),
        "expectedAfter": value.expected_after.to_document(),
        "action": copy.deepcopy(dict(value.action)),
        "authorizationFingerprint": value.authorization_fingerprint,
        "beforeDevice": value.before_device,
        "beforeInode": value.before_inode,
        "preparedPath": (
            None if value.prepared_path is None else str(value.prepared_path)
        ),
        "preparedRawSha256": (
            None
            if value.prepared_raw is None
            else hashlib.sha256(value.prepared_raw).hexdigest()
        ),
        "preparedFileProjection": (
            None
            if value.prepared_file_projection is None
            else copy.deepcopy(dict(value.prepared_file_projection))
        ),
        "manifestDocument": (
            None
            if value.manifest_document is None
            else copy.deepcopy(dict(value.manifest_document))
        ),
    }


def _primitive_fingerprint(value: ActivationMutationPrimitiveV2) -> str:
    return domain_fingerprint(
        "codex-smart/activation-mutation-primitive/v2",
        _primitive_projection(value),
    )


def _replace_primitive_fingerprint(
    value: ActivationMutationPrimitiveV2,
    fingerprint: str,
) -> ActivationMutationPrimitiveV2:
    fields = {
        name: getattr(value, name)
        for name in value.__dataclass_fields__
        if name != "primitive_fingerprint"
    }
    return ActivationMutationPrimitiveV2(
        **fields,
        primitive_fingerprint=fingerprint,
    )


def _validate_primitive(
    value: ActivationMutationPrimitiveV2,
    *,
    kind: str,
) -> None:
    if (
        not isinstance(value, ActivationMutationPrimitiveV2)
        or value.kind != kind
        or value.primitive_fingerprint != _primitive_fingerprint(value)
    ):
        _fail("MUTATION_PRIMITIVE_INVALID", f"примитив {kind} неполон")


def _mutation_result(
    primitive: ActivationMutationPrimitiveV2,
    observed: ProjectionV2,
) -> ActivationMutationResultV2:
    return ActivationMutationResultV2(
        kind=primitive.kind,
        operation_id=primitive.operation_id,
        before=primitive.before,
        expected_after=primitive.expected_after,
        observed_after=observed,
    )


def _validate_gate_journal(
    proof: ActivationTransitionProofV2,
    operation_id: str,
) -> None:
    operation_id = _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    try:
        raw, document = _read_private_json_bytes(
            proof.layout.journal_path,
            code="OPERATION_JOURNAL_INVALID",
            require_canonical=True,
        )
    except FileNotFoundError:
        _fail("OPERATION_JOURNAL_MISSING", "основной журнал ещё не создан")
    del raw
    steps = document.get("steps")
    projection = {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key != "journalFingerprint"
    }
    if (
        document.get("schemaVersion") != 2
        or document.get("kind") != "activation"
        or document.get("installationId") != proof.installation_id
        or document.get("operationId") != operation_id
        or document.get("operation") != "apply"
        or type(steps) is not list
        or not steps
        or steps[0].get("kind") != "gate_close"
        or steps[0].get("state") != "COMPLETED"
        or document.get("journalFingerprint")
        != domain_fingerprint("codex-smart/operation-journal/v2", projection)
    ):
        _fail("OPERATION_JOURNAL_INVALID", "журнал не доказывает gate_close")


def _validate_installer_receipt(
    value: Mapping[str, Any],
    *,
    codex_home: Path,
    layout: GatewayLayout,
    installation_id: str,
    binding,
    executable: Path,
) -> None:
    expected_keys = {
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
    if (
        set(value) != expected_keys
        or value.get("schemaVersion") != 2
        or value.get("kind") != "codex-smart-installer-receipt/v2"
        or _SHA256.fullmatch(str(value.get("sourceDigest"))) is None
        or value.get("installationId") != installation_id
        or value.get("activationId") != binding.activation_id
        or value.get("codexHome") != str(codex_home)
        or value.get("stateHome") != str(binding.state_home)
        or value.get("marketplacePath") != str(layout.marketplace_link)
        or value.get("registeredMarketplacePath") != str(binding.marketplace_path)
        or value.get("marketplaceName") != "codex-settings-adaptive"
        or value.get("pluginId") != "codex-smart-subagents@codex-settings-adaptive"
        or value.get("extensions") != {}
    ):
        _fail("INSTALLER_RECEIPT_INVALID", "квитанция владения имеет иную форму")
    try:
        if Path(str(value["codexBinary"])).resolve(strict=True) != executable.resolve(
            strict=True
        ) or layout.marketplace_link.resolve(strict=True) != Path(
            str(value["registeredMarketplacePath"])
        ).resolve(strict=True):
            _fail("INSTALLER_RECEIPT_FOREIGN", "квитанция принадлежит иной установке")
    except OSError as exc:
        _fail("INSTALLER_RECEIPT_INVALID", str(exc))
    _validate_installer_links(
        value,
        layout=layout,
        registered_marketplace=Path(str(value["registeredMarketplacePath"])),
    )


def _validate_installer_links(
    value: Mapping[str, Any],
    *,
    layout: GatewayLayout,
    registered_marketplace: Path,
) -> None:
    links = value.get("links")
    if type(links) is not list or len(links) != 2:
        _fail("INSTALLER_RECEIPT_INVALID", "список ссылок установщика неполон")
    expected_names = {"codex-smart", "codex-smart-subagents-admin"}
    observed: set[str] = set()
    lexical_bin = layout.marketplace_link / "plugins" / _PLUGIN_NAME / "bin"
    registered_bin = registered_marketplace / "plugins" / _PLUGIN_NAME / "bin"
    for item in links:
        if type(item) is not dict or set(item) != {"path", "target"}:
            _fail("INSTALLER_RECEIPT_INVALID", "описание ссылки неверно")
        path = _absolute_path(Path(str(item["path"])), "INSTALLER_RECEIPT_INVALID")
        target = _absolute_path(Path(str(item["target"])), "INSTALLER_RECEIPT_INVALID")
        if (
            path.name not in expected_names
            or path.name in observed
            or target != lexical_bin / path.name
        ):
            _fail("INSTALLER_RECEIPT_FOREIGN", "квитанция содержит чужую ссылку")
        try:
            info = path.lstat()
            target_info = target.lstat()
            if (
                not stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid()
                or os.readlink(path) != str(target)
                or not stat.S_ISREG(target_info.st_mode)
                or target_info.st_uid != os.getuid()
                or not os.access(target, os.X_OK)
                or target.resolve(strict=True).parent
                != registered_bin.resolve(strict=True)
            ):
                _fail("INSTALLER_RECEIPT_FOREIGN", "установленная ссылка изменена")
        except OSError as exc:
            _fail("INSTALLER_RECEIPT_FOREIGN", str(exc))
        observed.add(path.name)
    if observed != expected_names:
        _fail("INSTALLER_RECEIPT_INVALID", "список ссылок установщика неполон")


def _validate_database_file_identity(binding: ProjectionV2) -> None:
    value = binding.value
    path = Path(str(value.get("path")))
    try:
        info = path.lstat()
    except OSError as exc:
        _fail("DATABASE_BINDING_CHANGED", str(exc))
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
        _fail("DATABASE_BINDING_CHANGED", "файл базы больше не принадлежит снимку")


def _captured_device_is_valid(value: object) -> bool:
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _durable_filesystem_projection_matches(
    captured: object,
    observed: Mapping[str, Any],
) -> bool:
    if not isinstance(captured, Mapping) or set(captured) != set(observed):
        return False
    if not _captured_device_is_valid(captured.get("device")):
        return False
    return all(
        key == "device" or captured[key] == observed[key]
        for key in observed
    )


def _durable_manifest_projection_matches(
    captured: ProjectionV2,
    observed: ProjectionV2,
) -> bool:
    if (
        captured.schema_id != observed.schema_id
        or captured.schema_sha256 != observed.schema_sha256
        or not _projection_value_fingerprint_matches(
            captured,
            "codex-smart/journal-state/v2",
        )
        or set(captured.value) != set(observed.value)
    ):
        return False
    captured_file = captured.value.get("file")
    observed_file = observed.value.get("file")
    if not isinstance(observed_file, Mapping):
        return False
    if not _durable_filesystem_projection_matches(
        captured_file,
        observed_file,
    ):
        return False
    return all(
        key == "file" or captured.value[key] == observed.value[key]
        for key in observed.value
    )


def _projection_value_fingerprint_matches(
    projection: ProjectionV2,
    domain: str,
) -> bool:
    envelope = {
        "schemaId": projection.schema_id,
        "schemaSha256": projection.schema_sha256,
        "value": copy.deepcopy(dict(projection.value)),
    }
    return projection.value_fingerprint == domain_fingerprint(domain, envelope)


def _observe_link(path: Path) -> tuple[ProjectionV2, os.stat_result, str]:
    try:
        info = path.lstat()
        parent = path.parent.lstat()
        target = os.readlink(path)
    except OSError as exc:
        _fail("ACTIVE_LINK_CHANGED", str(exc))
    if (
        not stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.getuid()
        or target.startswith("/")
    ):
        _fail("ACTIVE_LINK_CHANGED", "ссылка имеет небезопасные свойства")
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
    return (
        _projection("symlink-object-v2", value, "codex-smart/symlink-object/v2"),
        info,
        target,
    )


def _receipt_projection(path: Path, receipt: Mapping[str, Any]) -> ProjectionV2:
    value = {
        "file": _file_projection(path),
        "receiptKind": receipt["receiptKind"],
        "installationId": receipt["installationId"],
        "operationId": receipt["operationId"],
        "receiptFingerprint": receipt["receiptFingerprint"],
    }
    return _projection("receipt-object-v2", value, "codex-smart/receipt-object/v2")


def _projection(schema_id: str, value: Mapping[str, Any], domain: str) -> ProjectionV2:
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": copy.deepcopy(dict(value)),
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
        value=envelope["value"],
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _proof_projection(proof: ActivationTransitionProofV2) -> dict[str, Any]:
    return {
        "installationId": proof.installation_id,
        "activationId": proof.activation_id,
        "activationFingerprint": proof.activation_fingerprint,
        "currentOperationId": proof.current_operation_id,
        "stateHome": str(proof.state_home),
        "databasePath": str(proof.database_path),
        "manifestRawSha256": hashlib.sha256(proof.manifest_raw).hexdigest(),
        "manifestFile": copy.deepcopy(dict(proof.manifest_file_projection)),
        "activePointer": copy.deepcopy(dict(proof.active_pointer)),
        "link": proof.link_projection.to_document(),
        "linkDevice": proof.link_device,
        "linkInode": proof.link_inode,
        "activationRawSha256": hashlib.sha256(proof.activation_raw).hexdigest(),
        "activationTree": proof.activation_tree_projection.to_document(),
        "activation": proof.activation_projection.to_document(),
        "commitReceiptRawSha256": hashlib.sha256(proof.commit_receipt_raw).hexdigest(),
        "commitReceipt": proof.commit_receipt_projection.to_document(),
        "databaseBinding": proof.database_binding.to_document(),
        "databaseIdentityRow": copy.deepcopy(dict(proof.database_identity_row)),
        "controllerRow": copy.deepcopy(dict(proof.controller_row)),
        "controllerIdentity": proof.controller_identity,
        "installerReceiptRawSha256": hashlib.sha256(
            proof.installer_receipt_raw
        ).hexdigest(),
        "installerReceiptFile": copy.deepcopy(
            dict(proof.installer_receipt_file_projection)
        ),
        "installerReceipt": copy.deepcopy(dict(proof.installer_receipt_document)),
    }


def _proof_fingerprint(proof: ActivationTransitionProofV2) -> str:
    return domain_fingerprint(
        "codex-smart/activation-transition-proof/v2", _proof_projection(proof)
    )


def _replace_proof_fingerprint(
    proof: ActivationTransitionProofV2, fingerprint: str
) -> ActivationTransitionProofV2:
    values = {
        field: getattr(proof, field)
        for field in proof.__dataclass_fields__
        if field != "proof_fingerprint"
    }
    return ActivationTransitionProofV2(**values, proof_fingerprint=fingerprint)


def _validate_proof_shape(proof: ActivationTransitionProofV2) -> None:
    if not isinstance(proof, ActivationTransitionProofV2):
        _fail("ACTIVATION_PROOF_INCOMPLETE", "передан иной тип доказательства")
    if (
        _INSTALLATION_ID.fullmatch(proof.installation_id) is None
        or _ACTIVATION_ID.fullmatch(proof.activation_id) is None
        or _SHA256.fullmatch(proof.activation_fingerprint) is None
        or proof.activation_id != "act2_" + proof.activation_fingerprint
        or _OPERATION_ID.fullmatch(proof.current_operation_id) is None
        or _SHA256.fullmatch(proof.controller_identity) is None
        or not proof.manifest_raw
        or not proof.activation_raw
        or not proof.commit_receipt_raw
        or not proof.installer_receipt_raw
    ):
        _fail("ACTIVATION_PROOF_INCOMPLETE", "доказательство не содержит все связи")


def _validate_complete_proof(proof: ActivationTransitionProofV2) -> None:
    _validate_proof_shape(proof)
    if proof.proof_fingerprint != _proof_fingerprint(proof):
        _fail("ACTIVATION_PROOF_INCOMPLETE", "отпечаток доказательства расходится")


def _read_private_json_bytes(
    path: Path,
    *,
    code: str,
    require_canonical: bool,
) -> tuple[bytes, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > _MAX_CONTROL_BYTES
        ):
            _fail(code, f"небезопасный управляющий файл: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size):
            _fail(code, f"управляющий файл изменён при чтении: {path}")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        _fail(code, f"неверный JSON: {exc}")
    if type(document) is not dict:
        _fail(code, "корень управляющего документа не является объектом")
    if require_canonical and canonical_json_bytes(document) != raw:
        _fail(code, "управляющий документ не является каноническим JSON")
    return raw, document


def _unique_object(pairs):
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise json.JSONDecodeError("duplicate object key", key, 0)
        result[key] = value
    return result


def _absolute_path(value: Path, code: str) -> Path:
    if not isinstance(value, Path):
        _fail(code, "ожидался Path")
    path = value.expanduser()
    if not path.is_absolute() or "\x00" in str(path):
        _fail(code, "путь должен быть абсолютным")
    return path.absolute()


def _identifier(value: object, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор имеет неверную форму")
    return value


def _sha256(value: object, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code, "ожидался полный SHA-256")
    return value


def _aware(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("TIMESTAMP_INVALID", "время должно содержать часовой пояс")
    return value.astimezone(timezone.utc)


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _fail(code: str, message: str) -> None:
    raise ActivationTransitionV2Error(code, message)


__all__ = [
    "ActivationLinkPlanV2",
    "ActivationMutationPrimitiveV2",
    "ActivationMutationResultV2",
    "ActivationTransitionProofV2",
    "ActivationTransitionV2Error",
    "CandidateAcceptanceProofV2",
    "ControllerShutdownProofV2",
    "ManifestCommitPlanV2",
    "PreparedManifestCommitV2",
    "PreparedManifestPlanV2",
    "PreparedManifestTransitionStateV2",
    "accept_upgrade_candidate_v2",
    "apply_activation_link_primitive_v2",
    "apply_manifest_commit_primitive_v2",
    "authorize_activation_link_plan_v2",
    "authorize_manifest_commit_plan_v2",
    "build_activation_link_plan_v2",
    "build_activation_link_primitive_v2",
    "build_manifest_commit_plan_v2",
    "build_prepared_manifest_plan_v2",
    "capture_activation_transition_proof_v2",
    "materialize_prepared_manifest_plan_v2",
    "observe_activation_link_plan_v2",
    "observe_prepared_manifest_transition_v2",
    "prepared_manifest_commit_from_plan_v2",
    "prepared_manifest_commit_from_receipt_v2",
    "prepare_manifest_file_v2",
    "prepare_manifest_commit_primitive_v2",
    "reverify_activation_transition_proof_v2",
    "shutdown_current_activation_v2",
    "stage_upgrade_activation_v2",
    "verify_prepared_manifest_file_v2",
]
