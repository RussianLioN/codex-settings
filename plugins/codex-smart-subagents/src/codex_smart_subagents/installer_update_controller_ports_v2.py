"""Производственные порты управляющих шагов обновления версии 2.

Каждая изменяющая команда получает только ``commandId`` из уже долговечного
``StepDefinitionV2``. После перезапуска порт сначала читает точную квитанцию
из SQLite и не полагается на внутрипроцессное состояние клиента. Ограничения
``EXPECTED_*`` сопоставляются с фактическими проекциями отдельно: ограничение
никогда не записывается в ``observedAfter`` как будто оно было наблюдением.
"""

from __future__ import annotations

import copy
import os
import re
import sqlite3
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote

from .activation_gateway_v2 import _LIFECYCLE_SCHEMA_SHA256
from .candidate_ready_channel_v2 import (
    CandidateSpawnActionV2,
    load_candidate_dispatch_intent_receipt_v2,
    reconnect_candidate_ready_channel_v2,
)
from .canonical_json import domain_fingerprint
from .controller_transition_rehydration_v2 import (
    ControllerShutdownCommandIdsV2,
    ControllerTransitionRehydrationV2Error,
    RehydratedControllerCommandV2,
    rehydrate_candidate_acceptance_proof_v2,
    rehydrate_controller_command_v2,
    rehydrate_controller_shutdown_proof_v2,
)
from .durable_process_ownership_v2 import (
    DurableProcessOwnershipStoreV2,
    DurableProcessOwnershipV2Error,
)
from .installer_update_operation_v2 import UpdateStepPortV2
from .lifecycle_constraint_matcher_v2 import matches_shutdown_constraint_v2
from .lifecycle_controller_client_v2 import LifecycleControllerClientV2
from .lifecycle_controller_protocol_v2 import (
    LifecycleControllerCommandProofV2,
    LifecycleControllerQuiescenceV2,
)
from .lifecycle_operation_v2 import ProjectionV2, StepDefinitionV2
from . import operation_deadline_v2, operation_process_group_supervisor_v2
from .schema_projection import APPLICATION_ID
from .shutdown_socket_cleanup_v2 import ShutdownSocketOrphanProofV2
from .sqlite_deadline_v2 import connect_sqlite_with_deadline_v2
from .state_store_v2 import _QUIESCENCE_QUERIES


_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_COMMAND_ID = re.compile(r"^cc2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_INSTANCE_ID = re.compile(r"^ci2_[0-9a-f]{32}$")
_CONTROLLER_START_ID = re.compile(r"^cs2_[0-9a-f]{32}$")
_REQUIRED_KINDS = frozenset(
    {
        "maintenance_begin",
        "wait_runtime_quiescent",
        "maintenance_strengthen",
        "controller_shutdown",
        "controller_accept",
        "maintenance_resume",
    }
)
_REQUIRED_SHUTDOWN_KINDS = frozenset(
    {
        "maintenance_begin",
        "wait_runtime_quiescent",
        "maintenance_strengthen",
        "controller_shutdown",
    }
)
_METHOD_BY_KIND = {
    "maintenance_begin": "maintenance_begin",
    "maintenance_strengthen": "maintenance_strengthen",
    "controller_shutdown": "shutdown",
    "controller_accept": "controller_accept",
    "maintenance_resume": "maintenance_resume",
}
_STATUS_BY_METHOD = {
    "maintenance_begin": "MAINTENANCE_BEGUN",
    "maintenance_strengthen": "MAINTENANCE_STRENGTHENED",
    "shutdown": "SHUTDOWN_COMMITTED",
    "controller_accept": "CONTROLLER_ACCEPTED",
    "maintenance_resume": "MAINTENANCE_RESUMED",
}
_CONTROLLER_DOMAIN = "codex-smart/controller-state/v2"
_CANDIDATE_DOMAIN = "codex-smart/controller-candidate/v2"
_QUIESCENCE_DOMAIN = "codex-smart/quiescence-proof/v2"
_SHUTDOWN_DOMAIN = "codex-smart/shutdown-intent/v2"
_DATABASE_PREDICATES_DOMAIN = "codex-smart/database-predicates/v2"


@dataclass
class InstallerUpdateControllerPortsV2Error(RuntimeError):
    """Закрытый отказ сборки или исполнения управляющего порта."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class _ControllerDatabaseObservationV2:
    controller: ProjectionV2
    row: Mapping[str, Any]
    counts: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "row", copy.deepcopy(dict(self.row)))
        object.__setattr__(self, "counts", copy.deepcopy(dict(self.counts)))


@dataclass(frozen=True)
class _PortContextV2:
    operation_id: str
    expected_orphan_operation_id: str | None
    activation_proof_fingerprint: str
    shutdown_cleanup_plan_fingerprint: str
    codex_home: Path
    current_database_path: Path
    candidate_database_path: Path
    definitions: Mapping[str, StepDefinitionV2]
    candidate_action: CandidateSpawnActionV2
    maintenance_reason_code: str
    shell_session_id: str
    candidate_ready_timeout_seconds: float
    client_factory: Callable[..., Any]
    command_rehydrator: Callable[..., Any]
    shutdown_rehydrator: Callable[..., Any]
    acceptance_rehydrator: Callable[..., Any]
    candidate_reconnect: Callable[..., Any]
    dispatch_intent_loader: Callable[..., Any]
    shutdown_orphan_prover: Callable[[Any], Any]
    controller_observer: Callable[[Path], ProjectionV2]
    quiescence_observer: Callable[[Path, str], ProjectionV2 | None]


def build_update_controller_step_ports_v2(
    *,
    operation_id: str,
    activation_proof_fingerprint: str,
    shutdown_cleanup_plan_fingerprint: str,
    codex_home: Path,
    current_database_path: Path,
    candidate_database_path: Path,
    definitions: Mapping[str, StepDefinitionV2],
    candidate_spawn_action: Mapping[str, Any] | CandidateSpawnActionV2,
    shutdown_orphan_prover: Callable[[Any], Any],
    expected_orphan_operation_id: str | None = None,
    maintenance_reason_code: str = "UPGRADE",
    shell_session_id: str = "installer-v2",
    candidate_ready_timeout_seconds: float = 1.0,
    client_factory: Callable[..., Any] = LifecycleControllerClientV2,
    command_rehydrator: Callable[..., Any] = rehydrate_controller_command_v2,
    shutdown_rehydrator: Callable[..., Any] = rehydrate_controller_shutdown_proof_v2,
    acceptance_rehydrator: Callable[..., Any] = rehydrate_candidate_acceptance_proof_v2,
    candidate_reconnect: Callable[..., Any] = reconnect_candidate_ready_channel_v2,
    dispatch_intent_loader: Callable[..., Any] = (
        load_candidate_dispatch_intent_receipt_v2
    ),
    controller_observer: Callable[[Path], ProjectionV2] | None = None,
    quiescence_observer: Callable[[Path, str], ProjectionV2 | None] | None = None,
) -> dict[str, UpdateStepPortV2]:
    """Собрать шесть портов обновления из одного полного набора определений."""

    _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    if expected_orphan_operation_id is not None:
        _identifier(
            expected_orphan_operation_id,
            _OPERATION_ID,
            "EXPECTED_ORPHAN_OPERATION_ID_INVALID",
        )
        if expected_orphan_operation_id == operation_id:
            _fail(
                "EXPECTED_ORPHAN_OPERATION_ID_INVALID",
                "предыдущая операция должна отличаться от новой",
            )
    _identifier(
        activation_proof_fingerprint,
        _SHA256,
        "ACTIVATION_PROOF_FINGERPRINT_INVALID",
    )
    _identifier(
        shutdown_cleanup_plan_fingerprint,
        _SHA256,
        "SHUTDOWN_CLEANUP_PLAN_FINGERPRINT_INVALID",
    )
    codex_home = _absolute_path(codex_home, "CODEX_HOME_INVALID")
    current_database_path = _absolute_path(
        current_database_path, "CURRENT_DATABASE_PATH_INVALID"
    )
    candidate_database_path = _absolute_path(
        candidate_database_path, "CANDIDATE_DATABASE_PATH_INVALID"
    )
    if current_database_path == candidate_database_path:
        _fail(
            "CONTROLLER_DATABASE_BINDING_INVALID",
            "старая и кандидатная базы должны быть разными путями",
        )
    if (
        type(shell_session_id) is not str
        or not shell_session_id
        or len(shell_session_id) > 256
    ):
        _fail("SHELL_SESSION_ID_INVALID", "shell_session_id неверен")
    if maintenance_reason_code not in {"UPGRADE", "ROLLBACK"}:
        _fail(
            "MAINTENANCE_REASON_CODE_INVALID",
            "maintenance_reason_code должен быть UPGRADE или ROLLBACK",
        )
    if (maintenance_reason_code == "ROLLBACK") != (
        expected_orphan_operation_id is not None
    ):
        _fail(
            "CONTROLLER_ORPHAN_REBIND_POLICY_INVALID",
            "перепривязка orphan допустима только для ROLLBACK с ожидаемой операцией",
        )
    if (
        type(candidate_ready_timeout_seconds) not in {int, float}
        or type(candidate_ready_timeout_seconds) is bool
        or not 0 < float(candidate_ready_timeout_seconds) <= 5.0
    ):
        _fail(
            "CANDIDATE_READY_TIMEOUT_INVALID",
            "срок повторного подключения должен быть в диапазоне (0, 5]",
        )
    for value, name in (
        (client_factory, "client_factory"),
        (command_rehydrator, "command_rehydrator"),
        (shutdown_rehydrator, "shutdown_rehydrator"),
        (acceptance_rehydrator, "acceptance_rehydrator"),
        (candidate_reconnect, "candidate_reconnect"),
        (dispatch_intent_loader, "dispatch_intent_loader"),
        (shutdown_orphan_prover, "shutdown_orphan_prover"),
    ):
        if not callable(value):
            raise TypeError(f"{name} must be callable")
    copied_definitions = copy.deepcopy(dict(definitions))
    if set(copied_definitions) != _REQUIRED_KINDS:
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            "требуются ровно шесть управляющих определений обновления",
        )
    for kind, definition in copied_definitions.items():
        _validate_definition_shape(
            definition,
            kind=kind,
            operation_id=operation_id,
        )
    command_ids = [
        _command_id(definition)
        for kind, definition in copied_definitions.items()
        if kind != "wait_runtime_quiescent"
    ]
    if len(set(command_ids)) != len(command_ids):
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            "commandId управляющих шагов должны быть уникальны",
        )
    try:
        candidate_action = (
            candidate_spawn_action
            if isinstance(candidate_spawn_action, CandidateSpawnActionV2)
            else CandidateSpawnActionV2.from_mapping(candidate_spawn_action)
        )
    except Exception as error:
        raise InstallerUpdateControllerPortsV2Error(
            "CANDIDATE_ACTION_INVALID", str(error)
        ) from error
    if candidate_action.operation_id != operation_id:
        _fail(
            "CANDIDATE_ACTION_INVALID",
            "действие кандидата относится к другой операции",
        )
    if not _matches_candidate_constraint(
        _candidate_projection(
            copied_definitions["controller_accept"].before,
            _expected_candidate_value(candidate_action),
        ),
        copied_definitions["controller_accept"].before,
        allow_expected_observation=True,
    ):
        _fail(
            "CANDIDATE_ACTION_INVALID",
            "ограничение controller_accept не связано с действием запуска",
        )
    controller_observer = controller_observer or observe_controller_database_v2
    if quiescence_observer is None:
        quiescence_observer = observe_runtime_quiescence_database_v2
    if not callable(controller_observer) or not callable(quiescence_observer):
        raise TypeError("database observers must be callable")
    context = _PortContextV2(
        operation_id=operation_id,
        expected_orphan_operation_id=expected_orphan_operation_id,
        activation_proof_fingerprint=activation_proof_fingerprint,
        shutdown_cleanup_plan_fingerprint=shutdown_cleanup_plan_fingerprint,
        codex_home=codex_home,
        current_database_path=current_database_path,
        candidate_database_path=candidate_database_path,
        definitions=copied_definitions,
        candidate_action=candidate_action,
        maintenance_reason_code=maintenance_reason_code,
        shell_session_id=shell_session_id,
        candidate_ready_timeout_seconds=float(candidate_ready_timeout_seconds),
        client_factory=client_factory,
        command_rehydrator=command_rehydrator,
        shutdown_rehydrator=shutdown_rehydrator,
        acceptance_rehydrator=acceptance_rehydrator,
        candidate_reconnect=candidate_reconnect,
        dispatch_intent_loader=dispatch_intent_loader,
        shutdown_orphan_prover=shutdown_orphan_prover,
        controller_observer=controller_observer,
        quiescence_observer=quiescence_observer,
    )
    return {
        "maintenance_begin": _build_controller_command_port(
            context,
            kind="maintenance_begin",
            database_path=current_database_path,
        ),
        "wait_runtime_quiescent": _build_quiescence_port(context),
        "maintenance_strengthen": _build_controller_command_port(
            context,
            kind="maintenance_strengthen",
            database_path=current_database_path,
        ),
        "controller_shutdown": _build_shutdown_port(context),
        "controller_accept": _build_accept_port(context),
        "maintenance_resume": _build_controller_command_port(
            context,
            kind="maintenance_resume",
            database_path=candidate_database_path,
        ),
    }


def build_shutdown_controller_step_ports_v2(
    *,
    operation_id: str,
    activation_proof_fingerprint: str,
    shutdown_cleanup_plan_fingerprint: str,
    codex_home: Path,
    current_database_path: Path,
    definitions: Mapping[str, StepDefinitionV2],
    shutdown_orphan_prover: Callable[[Any], Any],
    maintenance_reason_code: str = "UNINSTALL",
    shell_session_id: str = "installer-v2",
    client_factory: Callable[..., Any] = LifecycleControllerClientV2,
    command_rehydrator: Callable[..., Any] = rehydrate_controller_command_v2,
    shutdown_rehydrator: Callable[..., Any] = rehydrate_controller_shutdown_proof_v2,
    controller_observer: Callable[[Path], ProjectionV2] | None = None,
    quiescence_observer: Callable[[Path, str], ProjectionV2 | None] | None = None,
) -> dict[str, UpdateStepPortV2]:
    """Переиспользовать производственные порты только для цепочки остановки."""

    _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    _identifier(
        activation_proof_fingerprint,
        _SHA256,
        "ACTIVATION_PROOF_FINGERPRINT_INVALID",
    )
    _identifier(
        shutdown_cleanup_plan_fingerprint,
        _SHA256,
        "SHUTDOWN_CLEANUP_PLAN_FINGERPRINT_INVALID",
    )
    codex_home = _absolute_path(codex_home, "CODEX_HOME_INVALID")
    current_database_path = _absolute_path(
        current_database_path, "CURRENT_DATABASE_PATH_INVALID"
    )
    if (
        type(shell_session_id) is not str
        or not shell_session_id
        or len(shell_session_id) > 256
    ):
        _fail("SHELL_SESSION_ID_INVALID", "shell_session_id неверен")
    if maintenance_reason_code not in {"UPGRADE", "ROLLBACK", "UNINSTALL"}:
        _fail(
            "MAINTENANCE_REASON_CODE_INVALID",
            "maintenance_reason_code должен быть UPGRADE, ROLLBACK или UNINSTALL",
        )
    for value, name in (
        (client_factory, "client_factory"),
        (command_rehydrator, "command_rehydrator"),
        (shutdown_rehydrator, "shutdown_rehydrator"),
        (shutdown_orphan_prover, "shutdown_orphan_prover"),
    ):
        if not callable(value):
            raise TypeError(f"{name} must be callable")
    copied_definitions = copy.deepcopy(dict(definitions))
    if set(copied_definitions) != _REQUIRED_SHUTDOWN_KINDS:
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            "требуются ровно четыре определения цепочки остановки",
        )
    for kind, definition in copied_definitions.items():
        _validate_definition_shape(
            definition,
            kind=kind,
            operation_id=operation_id,
        )
    command_ids = [
        _command_id(definition)
        for kind, definition in copied_definitions.items()
        if kind != "wait_runtime_quiescent"
    ]
    if len(set(command_ids)) != len(command_ids):
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            "commandId шагов остановки должны быть уникальны",
        )
    controller_observer = controller_observer or observe_controller_database_v2
    quiescence_observer = (
        quiescence_observer or observe_runtime_quiescence_database_v2
    )
    if not callable(controller_observer) or not callable(quiescence_observer):
        raise TypeError("database observers must be callable")

    # Остальные поля контекста принадлежат кандидатной половине update и ни один
    # из четырёх возвращаемых портов их не читает. Один общий тип сохраняет
    # единственную реализацию повторного наблюдения управляющих квитанций.
    context = _PortContextV2(
        operation_id=operation_id,
        expected_orphan_operation_id=None,
        activation_proof_fingerprint=activation_proof_fingerprint,
        shutdown_cleanup_plan_fingerprint=shutdown_cleanup_plan_fingerprint,
        codex_home=codex_home,
        current_database_path=current_database_path,
        candidate_database_path=current_database_path,
        definitions=copied_definitions,
        candidate_action=None,  # type: ignore[arg-type]
        maintenance_reason_code=maintenance_reason_code,
        shell_session_id=shell_session_id,
        candidate_ready_timeout_seconds=1.0,
        client_factory=client_factory,
        command_rehydrator=command_rehydrator,
        shutdown_rehydrator=shutdown_rehydrator,
        acceptance_rehydrator=rehydrate_candidate_acceptance_proof_v2,
        candidate_reconnect=reconnect_candidate_ready_channel_v2,
        dispatch_intent_loader=load_candidate_dispatch_intent_receipt_v2,
        shutdown_orphan_prover=shutdown_orphan_prover,
        controller_observer=controller_observer,
        quiescence_observer=quiescence_observer,
    )
    return {
        "maintenance_begin": _build_controller_command_port(
            context,
            kind="maintenance_begin",
            database_path=current_database_path,
        ),
        "wait_runtime_quiescent": _build_quiescence_port(context),
        "maintenance_strengthen": _build_controller_command_port(
            context,
            kind="maintenance_strengthen",
            database_path=current_database_path,
        ),
        "controller_shutdown": _build_shutdown_port(context),
    }


def _build_controller_command_port(
    context: _PortContextV2,
    *,
    kind: str,
    database_path: Path,
) -> UpdateStepPortV2:
    expected_definition = context.definitions[kind]
    method = _METHOD_BY_KIND[kind]

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        _require_definition(definition, expected_definition)
        command = _optional_command(
            context,
            database_path=database_path,
            definition=definition,
            method=method,
        )
        if command is None:
            return _observe_controller(context, database_path)
        observed = (
            _observe_controller(context, database_path)
            if method == "maintenance_resume"
            else None
        )
        _validate_rehydrated_command(
            command,
            definition=definition,
            method=method,
            expected_params=_expected_params(method, context.maintenance_reason_code),
            controller_fence=observed,
        )
        if method in {"maintenance_begin", "maintenance_strengthen"}:
            shutdown = _observe_shutdown_successor(context)
            if shutdown is not None:
                return shutdown
        if observed is None:
            observed = _observe_controller(context, database_path)
        if method == "maintenance_begin":
            strengthen_definition = context.definitions["maintenance_strengthen"]
            strengthen = _optional_command(
                context,
                database_path=context.current_database_path,
                definition=strengthen_definition,
                method="maintenance_strengthen",
            )
            if strengthen is not None:
                _validate_rehydrated_command(
                    strengthen,
                    definition=strengthen_definition,
                    method="maintenance_strengthen",
                    expected_params={"mode": "freeze"},
                )
                _require_epoch_successor(command.proof, strengthen.proof)
                _bind_controller_to_command(observed, strengthen.proof)
                return observed
        _bind_controller_to_command(observed, command.proof)
        return observed

    def apply(definition: StepDefinitionV2) -> None:
        _require_definition(definition, expected_definition)
        controller_before = definition.before
        if method == "maintenance_resume":
            controller_before = _observe_controller(context, database_path)
            if not _matches_controller_constraint(controller_before, definition.before):
                _fail(
                    "CONTROLLER_COMMAND_STATE_MISMATCH",
                    "фактический кандидат не удовлетворяет ограничению resume",
                )
            accept_definition = context.definitions["controller_accept"]
            accept = _load_command(
                context,
                database_path=context.candidate_database_path,
                definition=accept_definition,
                method="controller_accept",
            )
            _validate_rehydrated_command(
                accept,
                definition=accept_definition,
                method="controller_accept",
                expected_params={
                    "activationId": controller_before.value.get("activationId"),
                    "databaseId": controller_before.value.get("databaseId"),
                    "pid": controller_before.value.get("pid"),
                    "processStartMarker": controller_before.value.get(
                        "processStartMarker"
                    ),
                    "processGroupId": controller_before.value.get("processGroupId"),
                    "expectedOrphanOperationId": (
                        context.expected_orphan_operation_id
                    ),
                },
            )
            _bind_controller_to_command(controller_before, accept.proof)
            if accept.proof.new_control_epoch != definition.action.get(
                "expectedControlEpoch"
            ):
                _fail(
                    "CONTROLLER_COMMAND_CHAIN_MISMATCH",
                    "resume не продолжает эпоху долговечной квитанции accept",
                )
        client = _client_from_controller(
            context,
            definition=definition,
            projection=controller_before,
            method=method,
        )
        if method == "maintenance_begin":
            proof = client.maintenance_begin(
                operation_id=context.operation_id,
                reason_code=context.maintenance_reason_code,
            )
        elif method == "maintenance_strengthen":
            proof = client.maintenance_strengthen(operation_id=context.operation_id)
        elif method == "maintenance_resume":
            proof = client.maintenance_resume(operation_id=context.operation_id)
        else:  # pragma: no cover - закрыто сборщиком
            raise AssertionError(method)
        _validate_command_proof(
            proof,
            definition=definition,
            method=method,
        )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=(
            _matches_controller_constraint_before
            if kind == "maintenance_resume"
            else _matches_controller_before
        ),
        matches_after=_matches_controller_after,
        completed_current_matches=_controller_command_completed_matcher(
            context,
            kind=kind,
        ),
    )


def _build_quiescence_port(context: _PortContextV2) -> UpdateStepPortV2:
    expected_definition = context.definitions["wait_runtime_quiescent"]

    def matches_before(
        observed: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        # При нулевой нагрузке maintenance_begin может одновременно перевести
        # контроллер в drain и уже зафиксировать покой. Шаг ожидания является
        # чистой идемпотентной проверкой, поэтому готовое доказательство служит
        # допустимым исходным состоянием и всё равно повторно проверяется apply.
        return _matches_controller_constraint_before(
            observed, definition
        ) or _matches_quiescence_after(observed, definition)

    def replay_safe_when_indistinguishable(
        observed: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        return _matches_quiescence_after(observed, definition)

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        _require_definition(definition, expected_definition)
        shutdown = _observe_shutdown_successor(context)
        if shutdown is not None:
            return shutdown
        strengthen_definition = context.definitions["maintenance_strengthen"]
        strengthen = _optional_command(
            context,
            database_path=context.current_database_path,
            definition=strengthen_definition,
            method="maintenance_strengthen",
        )
        if strengthen is not None:
            _validate_rehydrated_command(
                strengthen,
                definition=strengthen_definition,
                method="maintenance_strengthen",
                expected_params={"mode": "freeze"},
            )
            observed = _observe_controller(context, context.current_database_path)
            _bind_controller_to_command(observed, strengthen.proof)
            return observed
        factual = context.quiescence_observer(
            context.current_database_path,
            context.operation_id,
        )
        if factual is not None:
            if not isinstance(factual, ProjectionV2):
                _fail(
                    "QUIESCENCE_OBSERVATION_INVALID",
                    "наблюдатель покоя вернул иной тип",
                )
            return factual
        return _observe_controller(context, context.current_database_path)

    def apply(definition: StepDefinitionV2) -> None:
        _require_definition(definition, expected_definition)
        timeout_ms = definition.action.get("timeoutMs")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60_000:
            _fail(
                "QUIESCENCE_TIMEOUT_INVALID",
                "управляющий клиент поддерживает timeoutMs от 1 до 60000",
            )
        client = _client_from_controller(
            context,
            definition=definition,
            projection=definition.before,
            method=None,
        )
        result = client.wait_quiescent(
            operation_id=context.operation_id,
            timeout_seconds=timeout_ms / 1000.0,
        )
        if (
            not isinstance(result, LifecycleControllerQuiescenceV2)
            or result.operation_id != context.operation_id
            or result.control_epoch != definition.before.value.get("controlEpoch")
            or result.state != "MAINTENANCE"
            or str(result.maintenance_mode).lower() != "drain"
            or result.quiescent is not True
        ):
            _fail(
                "RUNTIME_QUIESCENCE_NOT_REACHED",
                "контроллер не подтвердил покой до установленного срока",
            )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=matches_before,
        matches_after=_matches_quiescence_after,
        replay_safe_when_indistinguishable=replay_safe_when_indistinguishable,
        completed_current_matches=lambda persisted, current, definition: (
            _completed_quiescence_matches(
                context,
                persisted=persisted,
                current=current,
                definition=definition,
            )
        ),
    )


def _build_shutdown_port(context: _PortContextV2) -> UpdateStepPortV2:
    expected_definition = context.definitions["controller_shutdown"]
    shutdown_ids = ControllerShutdownCommandIdsV2(
        maintenance_begin=_command_id(context.definitions["maintenance_begin"]),
        maintenance_strengthen=_command_id(
            context.definitions["maintenance_strengthen"]
        ),
        shutdown=_command_id(expected_definition),
    )

    def load_shutdown() -> Any:
        return context.shutdown_rehydrator(
            database_path=context.current_database_path,
            activation_proof_fingerprint=context.activation_proof_fingerprint,
            operation_id=context.operation_id,
            command_ids=shutdown_ids,
        )

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        _require_definition(definition, expected_definition)
        try:
            command = _load_command(
                context,
                database_path=context.current_database_path,
                definition=definition,
                method="shutdown",
            )
        except ControllerTransitionRehydrationV2Error as error:
            if error.code != "REHYDRATION_RECEIPT_MISSING":
                raise
            return _observe_controller(context, context.current_database_path)
        _validate_rehydrated_command(
            command,
            definition=definition,
            method="shutdown",
            expected_params={},
        )
        shutdown = load_shutdown()
        if (
            getattr(shutdown, "complete", False) is not True
            or getattr(shutdown, "operation_id", None) != context.operation_id
            or getattr(shutdown, "activation_proof_fingerprint", None)
            != context.activation_proof_fingerprint
            or getattr(getattr(shutdown, "shutdown", None), "command_id", None)
            != definition.command_id
        ):
            _fail(
                "CONTROLLER_SHUTDOWN_PROOF_INVALID",
                "восстановленная цепочка остановки не связана с шагом",
            )
        orphan = context.shutdown_orphan_prover(shutdown)
        return _shutdown_completion_projection(
            definition,
            shutdown,
            orphan,
            expected_plan_fingerprint=(
                context.shutdown_cleanup_plan_fingerprint
            ),
        )

    def apply(definition: StepDefinitionV2) -> None:
        _require_definition(definition, expected_definition)
        client = _client_from_controller(
            context,
            definition=definition,
            projection=definition.before,
            method="shutdown",
        )
        proof = client.shutdown(operation_id=context.operation_id)
        _validate_command_proof(
            proof,
            definition=definition,
            method="shutdown",
        )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=_matches_controller_before,
        matches_after=_matches_shutdown_after,
        completed_current_matches=lambda persisted, current, _definition: (
            persisted == current
        ),
    )


def _build_accept_port(context: _PortContextV2) -> UpdateStepPortV2:
    expected_definition = context.definitions["controller_accept"]
    shutdown_ids = ControllerShutdownCommandIdsV2(
        maintenance_begin=_command_id(context.definitions["maintenance_begin"]),
        maintenance_strengthen=_command_id(
            context.definitions["maintenance_strengthen"]
        ),
        shutdown=_command_id(context.definitions["controller_shutdown"]),
    )

    def reconnect() -> Any:
        dispatch_intent = context.dispatch_intent_loader(
            codex_home=context.codex_home,
            action=context.candidate_action,
        )
        result = context.candidate_reconnect(
            action=context.candidate_action,
            dispatch_intent=dispatch_intent,
            timeout_seconds=context.candidate_ready_timeout_seconds,
        )
        registration = getattr(result, "registration", None)
        working_socket = getattr(result, "working_controller_socket", None)
        if type(registration) is not dict or type(working_socket) is not dict:
            _fail(
                "CANDIDATE_RECONNECT_INVALID",
                "канал готовности не вернул регистрацию и рабочий сокет",
            )
        observed = _candidate_projection(expected_definition.before, registration)
        if not _matches_candidate_constraint(observed, expected_definition.before):
            _fail(
                "CANDIDATE_RECONNECT_INVALID",
                "регистрация не удовлетворяет долговечному ограничению",
            )
        _socket_value(working_socket, "CANDIDATE_WORKING_SOCKET_INVALID")
        return result

    def load_shutdown() -> Any:
        return context.shutdown_rehydrator(
            database_path=context.current_database_path,
            activation_proof_fingerprint=context.activation_proof_fingerprint,
            operation_id=context.operation_id,
            command_ids=shutdown_ids,
        )

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        _require_definition(definition, expected_definition)
        command = _optional_command(
            context,
            database_path=context.candidate_database_path,
            definition=definition,
            method="controller_accept",
        )
        if command is None:
            result = reconnect()
            return _candidate_projection(
                definition.before, getattr(result, "registration")
            )
        observed = _observe_controller(context, context.candidate_database_path)
        expected_params = {
            "activationId": observed.value.get("activationId"),
            "databaseId": observed.value.get("databaseId"),
            "pid": observed.value.get("pid"),
            "processStartMarker": observed.value.get("processStartMarker"),
            "processGroupId": observed.value.get("processGroupId"),
            "expectedOrphanOperationId": context.expected_orphan_operation_id,
        }
        _validate_rehydrated_command(
            command,
            definition=definition,
            method="controller_accept",
            expected_params=expected_params,
        )
        shutdown = load_shutdown()
        shutdown_fingerprint = getattr(shutdown, "proof_fingerprint", None)
        if (
            getattr(shutdown, "complete", False) is not True
            or type(shutdown_fingerprint) is not str
            or _SHA256.fullmatch(shutdown_fingerprint) is None
        ):
            _fail(
                "CONTROLLER_SHUTDOWN_PROOF_INVALID",
                "принятие кандидата не связано с полной остановкой",
            )
        acceptance = context.acceptance_rehydrator(
            database_path=context.candidate_database_path,
            activation_proof_fingerprint=context.activation_proof_fingerprint,
            shutdown_proof_fingerprint=shutdown_fingerprint,
            operation_id=context.operation_id,
            activation_id=str(observed.value["activationId"]),
            database_id=str(observed.value["databaseId"]),
            command_id=_command_id(definition),
        )
        if (
            getattr(acceptance, "complete", False) is not True
            or getattr(
                getattr(acceptance, "candidate_accept", None),
                "command_id",
                None,
            )
            != definition.command_id
        ):
            _fail(
                "CANDIDATE_ACCEPTANCE_PROOF_INVALID",
                "восстановленное принятие не связано с шагом",
            )
        resume_definition = context.definitions["maintenance_resume"]
        resume = _optional_command(
            context,
            database_path=context.candidate_database_path,
            definition=resume_definition,
            method="maintenance_resume",
        )
        if resume is None:
            _bind_controller_to_command(observed, command.proof)
        else:
            _validate_rehydrated_command(
                resume,
                definition=resume_definition,
                method="maintenance_resume",
                expected_params={},
                controller_fence=observed,
            )
            _require_epoch_successor(command.proof, resume.proof)
            _bind_controller_to_command(observed, resume.proof)
        _release_durable_candidate_ownership_v2(
            context,
            observed.value,
        )
        return observed

    def apply(definition: StepDefinitionV2) -> None:
        _require_definition(definition, expected_definition)
        result = reconnect()
        registration = getattr(result, "registration")
        working_socket = getattr(result, "working_controller_socket")
        action = definition.action
        client = context.client_factory(
            socket_path=Path(str(working_socket["path"])),
            codex_home=context.codex_home,
            shell_session_id=context.shell_session_id,
            controller_identity=str(registration["controllerIdentity"]),
            instance_id=None,
            controller_start_id=str(registration["controllerStartId"]),
            control_epoch=int(action["expectedControlEpoch"]),
            command_ids={
                (context.operation_id, "controller_accept"): _command_id(definition)
            },
        )
        proof = client.candidate_accept(
            operation_id=context.operation_id,
            expected_orphan_operation_id=context.expected_orphan_operation_id,
            activation_id=str(registration["activationId"]),
            database_id=str(registration["databaseId"]),
            pid=int(registration["pid"]),
            process_start_marker=str(registration["processStartMarker"]),
            process_group_id=int(registration["processGroupId"]),
        )
        _validate_command_proof(
            proof,
            definition=definition,
            method="controller_accept",
        )
        supervisor = (
            operation_process_group_supervisor_v2.
            current_process_group_supervisor_v2()
        )
        if supervisor is not None:
            supervisor.release_after_acceptance_identity(
                pid=int(registration["pid"]),
                process_group_id=int(registration["processGroupId"]),
                process_start_marker=str(
                    registration["processStartMarker"]
                ),
            )
        _release_durable_candidate_ownership_v2(
            context,
            registration,
        )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_before=lambda observed, definition: _matches_candidate_constraint(
            observed, definition.before
        ),
        matches_after=_matches_controller_after,
        completed_current_matches=lambda persisted, current, definition: (
            _completed_accept_matches(
                context,
                persisted=persisted,
                current=current,
                definition=definition,
            )
        ),
    )


def _release_durable_candidate_ownership_v2(
    context: _PortContextV2,
    controller: Mapping[str, Any],
) -> None:
    """Удалить временное владение только после проверенного accept-proof."""

    if not isinstance(context, _PortContextV2) or type(controller) is not dict:
        raise TypeError("accepted candidate binding has invalid types")
    try:
        DurableProcessOwnershipStoreV2(
            context.codex_home
        ).release_accepted_candidate_identity(
            operation_id=context.operation_id,
            candidate_id=context.candidate_action.candidate_id,
            controller_start_id=context.candidate_action.controller_start_id,
            pid=controller["pid"],
            process_group_id=controller["processGroupId"],
            process_start_marker=controller["processStartMarker"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise InstallerUpdateControllerPortsV2Error(
            "DURABLE_OWNERSHIP_BINDING_MISMATCH",
            "принятый контроллер не содержит полную личность",
        ) from exc
    except DurableProcessOwnershipV2Error as exc:
        raise InstallerUpdateControllerPortsV2Error(
            exc.code,
            exc.message,
        ) from exc


def observe_controller_database_v2(database_path: Path) -> ProjectionV2:
    """Получить фактическую проекцию живого контроллера из точной SQLite-базы."""

    return _read_controller_database(database_path).controller


def observe_stopped_controller_database_v2(database_path: Path) -> ProjectionV2:
    """Получить точный остановленный orphan, ожидающий нового кандидата."""

    return _read_controller_database(
        database_path,
        require_stopped_orphan=True,
    ).controller


def observe_runtime_quiescence_database_v2(
    database_path: Path,
    operation_id: str,
) -> ProjectionV2 | None:
    """Вернуть доказательство покоя только для фактического нулевого drain."""

    _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    observation = _read_controller_database(database_path)
    row = observation.row
    if (
        row.get("state") != "MAINTENANCE"
        or row.get("maintenance_mode") != "DRAIN"
        or row.get("operation_id") != operation_id
        or row.get("quiescent") != 1
        or any(observation.counts.values())
    ):
        return None
    predicates = {
        "predicates": [
            {
                "name": name,
                "sql": _QUIESCENCE_QUERIES[name],
                "parameters": [],
                "result": observation.counts[name],
            }
            for name in _QUIESCENCE_QUERIES
        ]
    }
    value = {
        "proofKind": "runtime-v2",
        "controllerIdentity": row["controller_identity"],
        "instanceId": row["instance_id"],
        "controlEpoch": row["control_epoch"],
        "workCounts": copy.deepcopy(dict(observation.counts)),
        "databasePredicatesFingerprint": domain_fingerprint(
            _DATABASE_PREDICATES_DOMAIN, predicates
        ),
        "barrierHeld": True,
        "quiescent": True,
    }
    return _projection(
        "quiescence-proof-v2",
        value,
        _QUIESCENCE_DOMAIN,
        schema_sha256=observation.controller.schema_sha256,
    )


def _optional_command(
    context: _PortContextV2,
    *,
    database_path: Path,
    definition: StepDefinitionV2,
    method: str,
) -> RehydratedControllerCommandV2 | None:
    try:
        return _load_command(
            context,
            database_path=database_path,
            definition=definition,
            method=method,
        )
    except ControllerTransitionRehydrationV2Error as error:
        if error.code == "REHYDRATION_RECEIPT_MISSING":
            return None
        raise


def _observe_shutdown_successor(
    context: _PortContextV2,
) -> ProjectionV2 | None:
    definition = context.definitions["controller_shutdown"]
    command = _optional_command(
        context,
        database_path=context.current_database_path,
        definition=definition,
        method="shutdown",
    )
    if command is None:
        return None
    _validate_rehydrated_command(
        command,
        definition=definition,
        method="shutdown",
        expected_params={},
    )
    shutdown = context.shutdown_rehydrator(
        database_path=context.current_database_path,
        activation_proof_fingerprint=context.activation_proof_fingerprint,
        operation_id=context.operation_id,
        command_ids=ControllerShutdownCommandIdsV2(
            maintenance_begin=_command_id(context.definitions["maintenance_begin"]),
            maintenance_strengthen=_command_id(
                context.definitions["maintenance_strengthen"]
            ),
            shutdown=_command_id(definition),
        ),
    )
    if (
        getattr(shutdown, "complete", False) is not True
        or getattr(shutdown, "operation_id", None) != context.operation_id
        or getattr(shutdown, "activation_proof_fingerprint", None)
        != context.activation_proof_fingerprint
        or getattr(getattr(shutdown, "shutdown", None), "command_id", None)
        != definition.command_id
    ):
        _fail(
            "CONTROLLER_SHUTDOWN_PROOF_INVALID",
            "восстановленный преемник остановки не связан с шагом",
        )
    return _shutdown_projection(definition, shutdown.shutdown)


def _controller_command_completed_matcher(
    context: _PortContextV2,
    *,
    kind: str,
) -> Callable[[ProjectionV2, ProjectionV2, StepDefinitionV2], bool]:
    def matches(
        persisted: ProjectionV2,
        current: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        _require_definition(definition, context.definitions[kind])
        method = _METHOD_BY_KIND[kind]
        command = _optional_command(
            context,
            database_path=(
                context.candidate_database_path
                if kind == "maintenance_resume"
                else context.current_database_path
            ),
            definition=definition,
            method=method,
        )
        if command is None:
            return False
        _validate_rehydrated_command(
            command,
            definition=definition,
            method=method,
            expected_params=_expected_params(method, context.maintenance_reason_code),
            controller_fence=(persisted if kind == "maintenance_resume" else None),
        )
        if kind == "maintenance_resume":
            try:
                _bind_controller_to_command(persisted, command.proof)
            except InstallerUpdateControllerPortsV2Error:
                return False
            return (
                _matches_controller_constraint(persisted, definition.expected_after)
                and persisted == current
            )
        if not _exact_controller_command_after(
            persisted,
            definition=definition,
            proof=command.proof,
            method=method,
        ):
            return False
        if persisted == current:
            return True
        shutdown = _observe_shutdown_successor(context)
        if shutdown is not None and current == shutdown:
            return True
        if kind != "maintenance_begin" or current.schema_id != "controller-state-v2":
            return False
        strengthen_definition = context.definitions["maintenance_strengthen"]
        strengthen = _optional_command(
            context,
            database_path=context.current_database_path,
            definition=strengthen_definition,
            method="maintenance_strengthen",
        )
        if strengthen is not None:
            _validate_rehydrated_command(
                strengthen,
                definition=strengthen_definition,
                method="maintenance_strengthen",
                expected_params={"mode": "freeze"},
            )
            _require_epoch_successor(command.proof, strengthen.proof)
            return _exact_controller_command_after(
                current,
                definition=strengthen_definition,
                proof=strengthen.proof,
                method="maintenance_strengthen",
            )
        quiescence = context.quiescence_observer(
            context.current_database_path,
            context.operation_id,
        )
        return bool(
            quiescence is not None
            and _quiescence_binds_controller(
                quiescence,
                controller=persisted,
                control_epoch=command.proof.new_control_epoch,
            )
            and _controller_is_drain_quiescent_successor(persisted, current)
        )

    return matches


def _completed_quiescence_matches(
    context: _PortContextV2,
    *,
    persisted: ProjectionV2,
    current: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    _require_definition(definition, context.definitions["wait_runtime_quiescent"])
    if persisted != definition.expected_after:
        return False
    if persisted == current:
        return True
    strengthen_definition = context.definitions["maintenance_strengthen"]
    strengthen = _optional_command(
        context,
        database_path=context.current_database_path,
        definition=strengthen_definition,
        method="maintenance_strengthen",
    )
    if strengthen is None:
        return False
    _validate_rehydrated_command(
        strengthen,
        definition=strengthen_definition,
        method="maintenance_strengthen",
        expected_params={"mode": "freeze"},
    )
    if not _quiescence_binds_controller(
        persisted,
        controller=strengthen_definition.before,
        control_epoch=strengthen.proof.previous_control_epoch,
    ):
        return False
    shutdown = _observe_shutdown_successor(context)
    if shutdown is not None and current == shutdown:
        return True
    return _exact_controller_command_after(
        current,
        definition=strengthen_definition,
        proof=strengthen.proof,
        method="maintenance_strengthen",
    )


def _completed_accept_matches(
    context: _PortContextV2,
    *,
    persisted: ProjectionV2,
    current: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    _require_definition(definition, context.definitions["controller_accept"])
    command = _optional_command(
        context,
        database_path=context.candidate_database_path,
        definition=definition,
        method="controller_accept",
    )
    if command is None or not _matches_controller_constraint(
        persisted, definition.expected_after
    ):
        return False
    expected_params = {
        "activationId": persisted.value.get("activationId"),
        "databaseId": persisted.value.get("databaseId"),
        "pid": persisted.value.get("pid"),
        "processStartMarker": persisted.value.get("processStartMarker"),
        "processGroupId": persisted.value.get("processGroupId"),
        "expectedOrphanOperationId": context.expected_orphan_operation_id,
    }
    _validate_rehydrated_command(
        command,
        definition=definition,
        method="controller_accept",
        expected_params=expected_params,
    )
    try:
        _bind_controller_to_command(persisted, command.proof)
    except InstallerUpdateControllerPortsV2Error:
        return False
    if persisted == current:
        return True
    resume_definition = context.definitions["maintenance_resume"]
    resume = _optional_command(
        context,
        database_path=context.candidate_database_path,
        definition=resume_definition,
        method="maintenance_resume",
    )
    if resume is None:
        return False
    _validate_rehydrated_command(
        resume,
        definition=resume_definition,
        method="maintenance_resume",
        expected_params={},
        controller_fence=current,
    )
    _require_epoch_successor(command.proof, resume.proof)
    try:
        _bind_controller_to_command(current, resume.proof)
    except InstallerUpdateControllerPortsV2Error:
        return False
    stable = {
        "controllerIdentity",
        "instanceId",
        "controllerStartId",
        "pid",
        "processStartMarker",
        "processGroupId",
        "activationId",
        "activationFingerprint",
        "databaseId",
        "socket",
        "lockHeld",
    }
    return bool(
        _matches_controller_constraint(current, resume_definition.expected_after)
        and all(persisted.value.get(name) == current.value.get(name) for name in stable)
    )


def _exact_controller_command_after(
    observed: ProjectionV2,
    *,
    definition: StepDefinitionV2,
    proof: LifecycleControllerCommandProofV2,
    method: str,
) -> bool:
    if method == "maintenance_begin":
        if not _matches_controller_constraint(observed, definition.expected_after):
            return False
    elif observed != definition.expected_after:
        return False
    try:
        _bind_controller_to_command(observed, proof)
    except InstallerUpdateControllerPortsV2Error:
        return False
    before = definition.before.value
    after = observed.value
    stable = {
        "controllerIdentity",
        "instanceId",
        "controllerStartId",
        "pid",
        "processStartMarker",
        "processGroupId",
        "activationId",
        "activationFingerprint",
        "databaseId",
        "socket",
        "lockHeld",
    }
    if any(before.get(name) != after.get(name) for name in stable):
        return False
    if method == "maintenance_begin":
        return bool(
            after.get("state") in {"DRAINING", "MAINTENANCE"}
            and after.get("maintenanceMode") == "drain"
            and after.get("operationId") == definition.action.get("operationId")
            and after.get("acceptingNewRoutes") is False
            and after.get("quiescent") is (after.get("state") == "MAINTENANCE")
        )
    if method == "maintenance_strengthen":
        return bool(
            after.get("state") == "MAINTENANCE"
            and after.get("maintenanceMode") == "freeze"
            and after.get("operationId") == definition.action.get("operationId")
            and after.get("acceptingNewRoutes") is False
            and after.get("quiescent") is True
        )
    return False


def _quiescence_binds_controller(
    observed: ProjectionV2,
    *,
    controller: ProjectionV2,
    control_epoch: int,
) -> bool:
    counts = observed.value.get("workCounts")
    return bool(
        observed.schema_id == "quiescence-proof-v2"
        and observed.schema_sha256 == controller.schema_sha256
        and observed.value.get("proofKind") == "runtime-v2"
        and observed.value.get("controllerIdentity")
        == controller.value.get("controllerIdentity")
        and observed.value.get("instanceId") == controller.value.get("instanceId")
        and observed.value.get("controlEpoch") == control_epoch
        and type(counts) is dict
        and set(counts) == set(_QUIESCENCE_QUERIES)
        and all(type(value) is int and value == 0 for value in counts.values())
        and observed.value.get("barrierHeld") is True
        and observed.value.get("quiescent") is True
    )


def _controller_is_drain_quiescent_successor(
    before: ProjectionV2,
    after: ProjectionV2,
) -> bool:
    if (
        before.schema_id != "controller-state-v2"
        or after.schema_id != "controller-state-v2"
        or before.schema_sha256 != after.schema_sha256
    ):
        return False
    changed = {"state", "quiescent"}
    return bool(
        before.value.get("state") == "DRAINING"
        and before.value.get("quiescent") is False
        and after.value.get("state") == "MAINTENANCE"
        and after.value.get("maintenanceMode") == "drain"
        and after.value.get("quiescent") is True
        and all(
            before.value.get(name) == value
            for name, value in after.value.items()
            if name not in changed
        )
    )


def _require_epoch_successor(
    before: LifecycleControllerCommandProofV2,
    after: LifecycleControllerCommandProofV2,
) -> None:
    if after.previous_control_epoch != before.new_control_epoch:
        _fail(
            "CONTROLLER_COMMAND_CHAIN_MISMATCH",
            "эпохи последовательных управляющих квитанций не образуют цепочку",
        )


def _read_controller_database(
    database_path: Path,
    *,
    require_stopped_orphan: bool = False,
) -> _ControllerDatabaseObservationV2:
    path = _absolute_path(database_path, "CONTROLLER_DATABASE_PATH_INVALID")
    before = _private_database(path)
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    try:
        connection = connect_sqlite_with_deadline_v2(
            uri,
            uri=True,
            timeout=5,
            busy_timeout_ms=5_000,
            isolation_level=None,
        )
    except operation_deadline_v2.OperationDeadlineExceededV2:
        raise
    except sqlite3.Error as error:
        raise InstallerUpdateControllerPortsV2Error(
            "CONTROLLER_DATABASE_UNAVAILABLE", str(error)
        ) from error
    connection.row_factory = sqlite3.Row
    try:
        try:
            connection.execute("pragma query_only=ON")
            connection.execute("pragma trusted_schema=OFF")
            connection.execute("BEGIN")
            if (
                int(connection.execute("pragma application_id").fetchone()[0])
                != APPLICATION_ID
            ):
                _fail(
                    "CONTROLLER_DATABASE_INVALID",
                    "application_id базы отличается",
                )
            if int(connection.execute("pragma user_version").fetchone()[0]) != 2:
                _fail("CONTROLLER_DATABASE_INVALID", "user_version базы отличается")
            if [tuple(row) for row in connection.execute("pragma quick_check")] != [
                ("ok",)
            ]:
                _fail("CONTROLLER_DATABASE_INVALID", "quick_check базы не прошёл")
            if list(connection.execute("pragma foreign_key_check")):
                _fail(
                    "CONTROLLER_DATABASE_INVALID",
                    "целостность внешних ключей нарушена",
                )
            controllers = connection.execute(
                "select * from controller_state"
            ).fetchall()
            identities = connection.execute(
                "select * from database_identity"
            ).fetchall()
            counts = {
                name: int(connection.execute(statement).fetchone()[0])
                for name, statement in _QUIESCENCE_QUERIES.items()
            }
            if len(controllers) != 1 or len(identities) != 1:
                _fail(
                    "CONTROLLER_DATABASE_INVALID",
                    "singleton-строки базы имеют неверную кратность",
                )
            row = dict(controllers[0])
            identity = dict(identities[0])
            if (
                identity.get("database_id") != row.get("database_id")
                or identity.get("activation_id") != row.get("activation_id")
                or identity.get("activation_fingerprint")
                != row.get("activation_fingerprint")
            ):
                _fail(
                    "CONTROLLER_DATABASE_IDENTITY_MISMATCH",
                    "controller_state не связан с database_identity",
                )
            if require_stopped_orphan and any(counts.values()):
                _fail(
                    "CONTROLLER_STATE_INVALID",
                    "остановленная база содержит незавершённую работу",
                )
        except operation_deadline_v2.OperationDeadlineExceededV2:
            raise
        except sqlite3.Error as error:
            raise InstallerUpdateControllerPortsV2Error(
                "CONTROLLER_DATABASE_INVALID", str(error)
            ) from error
    except BaseException as primary:
        if connection.in_transaction:
            try:
                connection.rollback_for_cleanup_v2()
            except BaseException as cleanup_error:
                primary.add_note(
                    "SQLite controller observation cleanup rollback also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        raise
    else:
        if connection.in_transaction:
            connection.rollback_for_cleanup_v2()
    finally:
        _close_controller_database_preserving_primary_v2(
            connection,
            primary=sys.exception(),
        )
    after = _private_database(path)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        _fail(
            "CONTROLLER_DATABASE_CHANGED",
            "путь базы сменил физический файл во время чтения",
        )
    controller = (
        _stopped_controller_projection_from_row(row)
        if require_stopped_orphan
        else _controller_projection_from_row(row)
    )
    return _ControllerDatabaseObservationV2(
        controller=controller,
        row=row,
        counts=counts,
    )


def _close_controller_database_preserving_primary_v2(
    connection: sqlite3.Connection,
    *,
    primary: BaseException | None,
) -> None:
    try:
        connection.close()
    except BaseException as close_error:
        if primary is None:
            raise
        primary.add_note(
            "SQLite controller observation close also failed: "
            f"{type(close_error).__name__}: {close_error}"
        )


def _controller_projection_from_row(row: Mapping[str, Any]) -> ProjectionV2:
    state = row.get("state")
    mode = {"NONE": None, "DRAIN": "drain", "FREEZE": "freeze"}.get(
        row.get("maintenance_mode")
    )
    if (
        state not in {"ACCEPTING", "DRAINING", "MAINTENANCE"}
        or row.get("maintenance_mode") not in {"NONE", "DRAIN", "FREEZE"}
        or type(row.get("instance_id")) is not str
        or _INSTANCE_ID.fullmatch(str(row["instance_id"])) is None
        or type(row.get("controller_start_id")) is not str
        or _CONTROLLER_START_ID.fullmatch(str(row["controller_start_id"])) is None
        or not _positive_integer(row.get("controller_pid"))
        or not _positive_integer(row.get("controller_process_group_id"))
        or type(row.get("controller_process_start_marker")) is not str
        or not row["controller_process_start_marker"]
    ):
        _fail(
            "CONTROLLER_STATE_INVALID",
            "база не содержит фактический живой контроллер",
        )
    socket = {
        "path": row.get("socket_path"),
        "device": row.get("socket_device"),
        "inode": row.get("socket_inode"),
        "ownerUid": row.get("socket_owner_uid"),
        "ownerGid": row.get("socket_owner_gid"),
        "mode": row.get("socket_mode"),
    }
    socket = _socket_value(socket, "CONTROLLER_SOCKET_INVALID")
    try:
        info = os.lstat(Path(str(socket["path"])))
    except OSError as error:
        raise InstallerUpdateControllerPortsV2Error(
            "CONTROLLER_SOCKET_INVALID", str(error)
        ) from error
    observed_socket = {
        "path": str(socket["path"]),
        "device": info.st_dev,
        "inode": info.st_ino,
        "ownerUid": info.st_uid,
        "ownerGid": info.st_gid,
        "mode": f"0{stat.S_IMODE(info.st_mode):03o}",
    }
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_nlink != 1
        or observed_socket != socket
    ):
        _fail(
            "CONTROLLER_SOCKET_INVALID",
            "живой сокет отличается от controller_state",
        )
    value = {
        "controllerIdentity": row["controller_identity"],
        "instanceId": row["instance_id"],
        "controllerStartId": row["controller_start_id"],
        "pid": row["controller_pid"],
        "processStartMarker": row["controller_process_start_marker"],
        "processGroupId": row["controller_process_group_id"],
        "controlEpoch": row["control_epoch"],
        "state": state,
        "maintenanceMode": mode,
        "operationId": row["operation_id"],
        "activationId": row["activation_id"],
        "activationFingerprint": row["activation_fingerprint"],
        "databaseId": row["database_id"],
        "socket": socket,
        "lockHeld": bool(row["lock_held"]),
        "acceptingNewRoutes": bool(row["accepting_new_routes"]),
        "quiescent": bool(row["quiescent"]),
    }
    return _projection(
        "controller-state-v2",
        value,
        _CONTROLLER_DOMAIN,
        schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
    )


def _stopped_controller_projection_from_row(
    row: Mapping[str, Any],
) -> ProjectionV2:
    cleared = (
        "instance_id",
        "controller_start_id",
        "controller_pid",
        "controller_process_start_marker",
        "controller_process_group_id",
        "socket_path",
        "socket_device",
        "socket_inode",
        "socket_owner_uid",
        "socket_owner_gid",
        "socket_mode",
    )
    epoch = row.get("control_epoch")
    if (
        row.get("state") != "MAINTENANCE"
        or row.get("maintenance_mode") != "FREEZE"
        or row.get("reason_code") != "AWAITING_CONTROLLER_ACCEPT"
        or type(row.get("operation_id")) is not str
        or _OPERATION_ID.fullmatch(str(row["operation_id"])) is None
        or type(row.get("controller_identity")) is not str
        or _SHA256.fullmatch(str(row["controller_identity"])) is None
        or type(row.get("activation_id")) is not str
        or _ACTIVATION_ID.fullmatch(str(row["activation_id"])) is None
        or type(row.get("activation_fingerprint")) is not str
        or _SHA256.fullmatch(str(row["activation_fingerprint"])) is None
        or type(row.get("database_id")) is not str
        or _DATABASE_ID.fullmatch(str(row["database_id"])) is None
        or type(epoch) is not int
        or not 1 <= epoch <= 9_007_199_254_740_989
        or any(row.get(name) is not None for name in cleared)
        or row.get("lock_held") != 0
        or row.get("accepting_new_routes") != 0
        or row.get("quiescent") != 1
    ):
        _fail(
            "CONTROLLER_STATE_INVALID",
            "база не содержит точный остановленный orphan контроллера",
        )
    value = {
        "controllerIdentity": row["controller_identity"],
        "instanceId": None,
        "controllerStartId": None,
        "pid": None,
        "processStartMarker": None,
        "processGroupId": None,
        "controlEpoch": epoch,
        "state": "MAINTENANCE",
        "maintenanceMode": "freeze",
        "operationId": row["operation_id"],
        "activationId": row["activation_id"],
        "activationFingerprint": row["activation_fingerprint"],
        "databaseId": row["database_id"],
        "socket": None,
        "lockHeld": False,
        "acceptingNewRoutes": False,
        "quiescent": True,
    }
    return _projection(
        "controller-state-v2",
        value,
        _CONTROLLER_DOMAIN,
        schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
    )


def _load_command(
    context: _PortContextV2,
    *,
    database_path: Path,
    definition: StepDefinitionV2,
    method: str,
) -> RehydratedControllerCommandV2:
    result = context.command_rehydrator(
        database_path=database_path,
        operation_id=context.operation_id,
        command_id=_command_id(definition),
        method=method,
    )
    if not isinstance(result, RehydratedControllerCommandV2):
        _fail(
            "CONTROLLER_COMMAND_REHYDRATION_INVALID",
            "восстановитель команды вернул иной тип",
        )
    return result


def _client_from_controller(
    context: _PortContextV2,
    *,
    definition: StepDefinitionV2,
    projection: ProjectionV2,
    method: str | None,
) -> Any:
    if projection.schema_id != "controller-state-v2":
        _fail(
            "CONTROLLER_STEP_DEFINITION_INVALID",
            "команда требует фактическое состояние контроллера в before",
        )
    value = projection.value
    socket = _socket_value(value.get("socket"), "CONTROLLER_SOCKET_INVALID")
    instance_id = value.get("instanceId")
    controller_start_id = value.get("controllerStartId")
    epoch = definition.action.get("expectedControlEpoch")
    if method is None:
        epoch = value.get("controlEpoch")
    if (
        type(instance_id) is not str
        or _INSTANCE_ID.fullmatch(instance_id) is None
        or type(controller_start_id) is not str
        or _CONTROLLER_START_ID.fullmatch(controller_start_id) is None
        or type(epoch) is not int
        or epoch != value.get("controlEpoch")
    ):
        _fail(
            "CONTROLLER_FENCE_INVALID",
            "before не содержит точное ограждение управляющего клиента",
        )
    command_ids = (
        {}
        if method is None
        else {(context.operation_id, method): _command_id(definition)}
    )
    return context.client_factory(
        socket_path=Path(str(socket["path"])),
        codex_home=context.codex_home,
        shell_session_id=context.shell_session_id,
        controller_identity=str(value["controllerIdentity"]),
        instance_id=instance_id,
        controller_start_id=controller_start_id,
        control_epoch=int(epoch),
        command_ids=command_ids,
    )


def _validate_rehydrated_command(
    command: RehydratedControllerCommandV2,
    *,
    definition: StepDefinitionV2,
    method: str,
    expected_params: Mapping[str, Any],
    controller_fence: ProjectionV2 | None = None,
) -> None:
    request = command.request
    before = (
        controller_fence.value
        if controller_fence is not None
        else definition.before.value
    )
    if (
        controller_fence is not None
        and controller_fence.schema_id != "controller-state-v2"
    ):
        _fail(
            "CONTROLLER_COMMAND_STATE_MISMATCH",
            "фактическое ограждение команды имеет неверную проекцию",
        )
    expected_instance_id = (
        None if method == "controller_accept" else before.get("instanceId")
    )
    if (
        request.get("operationId") != definition.action.get("operationId")
        or request.get("commandId") != definition.command_id
        or request.get("method") != method
        or request.get("controllerIdentity") != before.get("controllerIdentity")
        or request.get("instanceId") != expected_instance_id
        or request.get("controllerStartId") != before.get("controllerStartId")
        or request.get("expectedControlEpoch")
        != definition.action.get("expectedControlEpoch")
        or request.get("params") != dict(expected_params)
    ):
        _fail(
            "CONTROLLER_COMMAND_RECEIPT_MISMATCH",
            "сохранённый запрос отличается от долговечного шага",
        )
    _validate_command_proof(command.proof, definition=definition, method=method)


def _validate_command_proof(
    proof: Any,
    *,
    definition: StepDefinitionV2,
    method: str,
) -> None:
    action_epoch = definition.action.get("expectedControlEpoch")
    receipt = (
        proof.payload.get("commandReceipt")
        if isinstance(getattr(proof, "payload", None), Mapping)
        else None
    )
    if (
        not isinstance(proof, LifecycleControllerCommandProofV2)
        or proof.method != method
        or proof.status != _STATUS_BY_METHOD[method]
        or proof.command_id != definition.command_id
        or proof.previous_control_epoch != action_epoch
        or proof.new_control_epoch != action_epoch + 1
        or type(receipt) is not dict
        or receipt.get("commandId") != definition.command_id
        or receipt.get("requestFingerprint") != proof.request_fingerprint
        or receipt.get("controlEpoch") != proof.new_control_epoch
        or type(receipt.get("resultFingerprint")) is not str
        or _SHA256.fullmatch(str(receipt["resultFingerprint"])) is None
    ):
        _fail(
            "CONTROLLER_COMMAND_PROOF_INVALID",
            f"квитанция {method} не связана с долговечным шагом",
        )


def _bind_controller_to_command(
    observed: ProjectionV2,
    proof: LifecycleControllerCommandProofV2,
) -> None:
    if (
        observed.schema_id != "controller-state-v2"
        or observed.value.get("controlEpoch") != proof.new_control_epoch
    ):
        _fail(
            "CONTROLLER_COMMAND_STATE_MISMATCH",
            "фактическое состояние не связано с эпохой квитанции",
        )
    if proof.method == "controller_accept" and (
        observed.value.get("instanceId") != proof.payload.get("instanceId")
        or observed.value.get("controllerIdentity")
        != proof.payload.get("controllerIdentity")
        or observed.value.get("controllerStartId")
        != proof.payload.get("controllerStartId")
    ):
        _fail(
            "CONTROLLER_COMMAND_STATE_MISMATCH",
            "принятый экземпляр отличается от квитанции",
        )


def _shutdown_projection(
    definition: StepDefinitionV2,
    proof: LifecycleControllerCommandProofV2,
) -> ProjectionV2:
    _validate_command_proof(proof, definition=definition, method="shutdown")
    before = copy.deepcopy(dict(definition.before.value))
    intent = proof.payload.get("socketIntent")
    if type(intent) is not dict:
        _fail(
            "CONTROLLER_SHUTDOWN_PROOF_INVALID",
            "shutdown не содержит socketIntent",
        )
    socket = _socket_value(
        {
            "path": intent.get("path"),
            "device": intent.get("device"),
            "inode": intent.get("inode"),
            "ownerUid": intent.get("ownerUid"),
            "ownerGid": intent.get("ownerGid"),
            "mode": intent.get("mode"),
        },
        "CONTROLLER_SHUTDOWN_PROOF_INVALID",
    )
    if (
        before.get("socket") != socket
        or before.get("pid") != intent.get("controllerPid")
        or before.get("processStartMarker") != intent.get("controllerStartMarker")
        or before.get("processGroupId") != intent.get("controllerProcessGroupId")
        or intent.get("processExitRequired") is not True
        or intent.get("exclusiveLockRequired") is not True
        or type(intent.get("lockPath")) is not str
        or not Path(str(intent["lockPath"])).is_absolute()
    ):
        _fail(
            "CONTROLLER_SHUTDOWN_PROOF_INVALID",
            "socketIntent расходится с before",
        )
    receipt = proof.payload["commandReceipt"]
    controller_after = {
        **before,
        "controlEpoch": proof.new_control_epoch,
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
        "operationId": definition.action["operationId"],
        "commandId": definition.command_id,
        "requestFingerprint": proof.request_fingerprint,
        "commandReceiptFingerprint": receipt["resultFingerprint"],
        "previousControlEpoch": proof.previous_control_epoch,
        "newControlEpoch": proof.new_control_epoch,
        "targetPid": intent["controllerPid"],
        "targetStartMarker": intent["controllerStartMarker"],
        "targetProcessGroupId": intent["controllerProcessGroupId"],
        "socket": socket,
        "lockPath": intent["lockPath"],
        "processExitProofFingerprint": None,
        "exclusiveLockProofFingerprint": None,
        "status": "SHUTDOWN_COMMITTED",
    }
    return _projection(
        "shutdown-intent-v2",
        value,
        _SHUTDOWN_DOMAIN,
        schema_sha256=definition.expected_after.schema_sha256,
    )


def _shutdown_completion_projection(
    definition: StepDefinitionV2,
    shutdown: Any,
    orphan: Any,
    *,
    expected_plan_fingerprint: str,
) -> ProjectionV2:
    """Связать shutdown-квитанцию со свежими exit и exclusive-lock proofs."""

    proof = getattr(shutdown, "shutdown", None)
    shutdown_proof_fingerprint = getattr(shutdown, "proof_fingerprint", None)
    committed = _shutdown_projection(definition, proof)
    process_exit = getattr(orphan, "process_exit_proof_fingerprint", None)
    exclusive_lock = getattr(orphan, "exclusive_lock_proof_fingerprint", None)
    if (
        not isinstance(orphan, ShutdownSocketOrphanProofV2)
        or orphan.complete is not True
        or orphan.plan_fingerprint != expected_plan_fingerprint
        or orphan.shutdown_proof_fingerprint != shutdown_proof_fingerprint
        or type(process_exit) is not str
        or _SHA256.fullmatch(process_exit) is None
        or type(exclusive_lock) is not str
        or _SHA256.fullmatch(exclusive_lock) is None
    ):
        _fail(
            "CONTROLLER_SHUTDOWN_ORPHAN_PROOF_INVALID",
            "доказательства выхода процесса и освобождения блокировки неполны",
        )
    value = copy.deepcopy(dict(committed.value))
    value.update(
        {
            "processExitProofFingerprint": process_exit,
            "exclusiveLockProofFingerprint": exclusive_lock,
            "status": "SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN",
        }
    )
    completed = _projection(
        "shutdown-intent-v2",
        value,
        _SHUTDOWN_DOMAIN,
        schema_sha256=definition.expected_after.schema_sha256,
    )
    if not matches_shutdown_constraint_v2(
        completed,
        definition.expected_after,
        require_orphan_proof=True,
    ):
        _fail(
            "CONTROLLER_SHUTDOWN_ORPHAN_PROOF_INVALID",
            "конечное доказательство shutdown расходится с expectedAfter",
        )
    return completed


def _expected_params(method: str, maintenance_reason_code: str) -> dict[str, Any]:
    if method == "maintenance_begin":
        return {"reasonCode": maintenance_reason_code}
    if method == "maintenance_strengthen":
        return {"mode": "freeze"}
    return {}


def _observe_controller(context: _PortContextV2, path: Path) -> ProjectionV2:
    observed = context.controller_observer(path)
    if not isinstance(observed, ProjectionV2):
        _fail(
            "CONTROLLER_OBSERVATION_INVALID",
            "наблюдатель контроллера вернул иной тип",
        )
    return observed


def _candidate_projection(
    template: ProjectionV2,
    value: Mapping[str, Any],
) -> ProjectionV2:
    if template.schema_id != "controller-candidate-v2":
        _fail(
            "CANDIDATE_CONSTRAINT_INVALID",
            "before controller_accept не является кандидатом",
        )
    return _projection(
        "controller-candidate-v2",
        value,
        _CANDIDATE_DOMAIN,
        schema_sha256=template.schema_sha256,
    )


def _expected_candidate_value(action: CandidateSpawnActionV2) -> dict[str, Any]:
    return {
        **{
            name: value
            for name, value in action.to_document().items()
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


def _matches_controller_before(
    observed: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    return _same_projection_value(observed, definition.before)


def _matches_controller_constraint_before(
    observed: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    return _matches_controller_constraint(observed, definition.before)


def _matches_controller_after(
    observed: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    return _matches_controller_constraint(observed, definition.expected_after)


def _matches_controller_constraint(
    observed: ProjectionV2,
    expected: ProjectionV2,
) -> bool:
    try:
        if not _same_projection_header(observed, expected, "controller-state-v2"):
            return False
        actual = dict(observed.value)
        constraint = dict(expected.value)
        expected_state = constraint.get("state")
        if expected_state == "EXPECTED_DRAIN_OR_MAINTENANCE":
            if (
                constraint.get("quiescent") is not False
                or actual.get("state") not in {"DRAINING", "MAINTENANCE"}
                or actual.get("quiescent") is not (actual.get("state") == "MAINTENANCE")
            ):
                return False
            return all(
                actual.get(name) == value
                for name, value in constraint.items()
                if name not in {"state", "quiescent"}
            )
        state_map = {
            "EXPECTED_MAINTENANCE": "MAINTENANCE",
            "EXPECTED_ACCEPTING": "ACCEPTING",
        }
        if expected_state not in state_map:
            return actual == constraint
        if actual.get("state") != state_map[expected_state]:
            return False
        dynamic = {
            "instanceId",
            "pid",
            "processStartMarker",
            "processGroupId",
            "socket",
        }
        if any(constraint.get(name) is not None for name in dynamic):
            return False
        if (
            type(actual.get("instanceId")) is not str
            or _INSTANCE_ID.fullmatch(str(actual["instanceId"])) is None
            or not _positive_integer(actual.get("pid"))
            or type(actual.get("processStartMarker")) is not str
            or not actual["processStartMarker"]
            or not _positive_integer(actual.get("processGroupId"))
        ):
            return False
        _socket_value(actual.get("socket"), "CONTROLLER_SOCKET_INVALID")
        return all(
            actual.get(name) == value
            for name, value in constraint.items()
            if name not in dynamic and name != "state"
        )
    except (KeyError, TypeError, ValueError, InstallerUpdateControllerPortsV2Error):
        return False


def _matches_candidate_constraint(
    observed: ProjectionV2,
    expected: ProjectionV2,
    *,
    allow_expected_observation: bool = False,
) -> bool:
    try:
        if not _same_projection_header(observed, expected, "controller-candidate-v2"):
            return False
        actual = dict(observed.value)
        constraint = dict(expected.value)
        if constraint.get("status") == "REGISTERED_READY":
            return actual == constraint
        if constraint.get("status") != "EXPECTED_REGISTRATION":
            return False
        if actual.get("status") == "EXPECTED_REGISTRATION":
            return allow_expected_observation and actual == constraint
        if actual.get("status") != "REGISTERED_READY":
            return False
        dynamic = {
            "privateReadyChannel",
            "pid",
            "processStartMarker",
            "processGroupId",
            "registrationFingerprint",
            "databaseLeaseProofFingerprint",
            "databaseOpened",
            "status",
        }
        if any(
            constraint.get(name) is not None
            for name in dynamic.difference({"databaseOpened", "status"})
        ):
            return False
        if constraint.get("databaseOpened") is not False:
            return False
        ready_socket = _socket_value(
            actual.get("privateReadyChannel"),
            "CANDIDATE_READY_SOCKET_INVALID",
        )
        if (
            ready_socket.get("path") != constraint.get("privateReadyChannelPath")
            or not _positive_integer(actual.get("pid"))
            or type(actual.get("processStartMarker")) is not str
            or not actual["processStartMarker"]
            or not _positive_integer(actual.get("processGroupId"))
            or type(actual.get("registrationFingerprint")) is not str
            or _SHA256.fullmatch(str(actual["registrationFingerprint"])) is None
            or type(actual.get("databaseLeaseProofFingerprint")) is not str
            or _SHA256.fullmatch(str(actual["databaseLeaseProofFingerprint"])) is None
            or actual.get("databaseOpened") is not True
            or actual.get("workingSocketPublished") is not False
            or actual.get("acceptingNewRoutes") is not False
            or actual.get("exitProofFingerprint") is not None
        ):
            return False
        return all(
            actual.get(name) == value
            for name, value in constraint.items()
            if name not in dynamic
        )
    except (KeyError, TypeError, ValueError, InstallerUpdateControllerPortsV2Error):
        return False


def _matches_quiescence_after(
    observed: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    return _same_projection_value(observed, definition.expected_after)


def _matches_shutdown_after(
    observed: ProjectionV2,
    definition: StepDefinitionV2,
) -> bool:
    return matches_shutdown_constraint_v2(
        observed,
        definition.expected_after,
        require_orphan_proof=True,
    )


def _same_projection_value(left: ProjectionV2, right: ProjectionV2) -> bool:
    return (
        isinstance(left, ProjectionV2)
        and isinstance(right, ProjectionV2)
        and left.schema_id == right.schema_id
        and left.schema_sha256 == right.schema_sha256
        and dict(left.value) == dict(right.value)
    )


def _same_projection_header(
    observed: ProjectionV2,
    expected: ProjectionV2,
    schema_id: str,
) -> bool:
    return (
        isinstance(observed, ProjectionV2)
        and isinstance(expected, ProjectionV2)
        and observed.schema_id == schema_id
        and expected.schema_id == schema_id
        and observed.schema_sha256 == expected.schema_sha256
    )


def _validate_definition_shape(
    definition: StepDefinitionV2,
    *,
    kind: str,
    operation_id: str,
) -> None:
    if not isinstance(definition, StepDefinitionV2) or definition.kind != kind:
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            f"определение {kind} отсутствует или имеет иной тип",
        )
    expected_projection_schemas = {
        "maintenance_begin": ("controller-state-v2", "controller-state-v2"),
        "wait_runtime_quiescent": (
            "controller-state-v2",
            "quiescence-proof-v2",
        ),
        "maintenance_strengthen": (
            "controller-state-v2",
            "controller-state-v2",
        ),
        "controller_shutdown": (
            "controller-state-v2",
            "shutdown-intent-v2",
        ),
        "controller_accept": (
            "controller-candidate-v2",
            "controller-state-v2",
        ),
        "maintenance_resume": (
            "controller-state-v2",
            "controller-state-v2",
        ),
    }
    before_schema, after_schema = expected_projection_schemas[kind]
    if (
        not isinstance(definition.before, ProjectionV2)
        or not isinstance(definition.expected_after, ProjectionV2)
        or definition.before.schema_id != before_schema
        or definition.expected_after.schema_id != after_schema
        or definition.before.schema_sha256 != definition.expected_after.schema_sha256
        or _SHA256.fullmatch(definition.before.schema_sha256) is None
        or _SHA256.fullmatch(definition.before.value_fingerprint) is None
        or _SHA256.fullmatch(definition.expected_after.value_fingerprint) is None
    ):
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            f"проекции {kind} не соответствуют договору шага",
        )
    if kind == "wait_runtime_quiescent":
        if (
            definition.command_id is not None
            or set(definition.action) != {"actionKind", "predicate", "timeoutMs"}
            or definition.action.get("actionKind") != "verify"
            or definition.action.get("predicate") != "runtime-quiescent"
            or type(definition.action.get("timeoutMs")) is not int
            or not 1 <= int(definition.action["timeoutMs"]) <= 60_000
        ):
            _fail(
                "CONTROLLER_STEP_DEFINITIONS_INVALID",
                "wait_runtime_quiescent имеет неверное действие",
            )
        return
    method = _METHOD_BY_KIND[kind]
    if (
        type(definition.command_id) is not str
        or _COMMAND_ID.fullmatch(definition.command_id) is None
        or set(definition.action)
        != {"actionKind", "method", "operationId", "expectedControlEpoch"}
        or definition.action.get("actionKind") != "controller-command"
        or definition.action.get("method") != method
        or definition.action.get("operationId") != operation_id
        or type(definition.action.get("expectedControlEpoch")) is not int
        or not 1
        <= int(definition.action["expectedControlEpoch"])
        <= 9_007_199_254_740_990
    ):
        _fail(
            "CONTROLLER_STEP_DEFINITIONS_INVALID",
            f"действие {kind} не связано с долговечной командой",
        )


def _require_definition(
    received: StepDefinitionV2,
    expected: StepDefinitionV2,
) -> None:
    if not isinstance(received, StepDefinitionV2) or received != expected:
        _fail(
            "CONTROLLER_STEP_DEFINITION_CHANGED",
            "исполнитель получил другое определение шага",
        )


def _projection(
    schema_id: str,
    value: Mapping[str, Any],
    domain: str,
    *,
    schema_sha256: str,
) -> ProjectionV2:
    copied = copy.deepcopy(dict(value))
    envelope = {
        "schemaId": schema_id,
        "schemaSha256": schema_sha256,
        "value": copied,
    }
    return ProjectionV2(
        schema_id=schema_id,
        schema_sha256=schema_sha256,
        value=copied,
        value_fingerprint=domain_fingerprint(domain, envelope),
    )


def _private_database(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise InstallerUpdateControllerPortsV2Error(
            "CONTROLLER_DATABASE_UNAVAILABLE", str(error)
        ) from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        _fail(
            "CONTROLLER_DATABASE_UNSAFE",
            "файл базы не является частным одиночным обычным файлом",
        )
    return info


def _socket_value(value: Any, code: str) -> dict[str, Any]:
    keys = {"path", "device", "inode", "ownerUid", "ownerGid", "mode"}
    if type(value) is not dict or set(value) != keys:
        _fail(code, "идентичность сокета имеет неверные поля")
    path = value.get("path")
    if (
        type(path) is not str
        or not Path(path).is_absolute()
        or any(
            type(value.get(name)) is not int or int(value[name]) < 0
            for name in (
                "device",
                "inode",
                "ownerUid",
                "ownerGid",
            )
        )
        or type(value.get("mode")) is not str
        or re.fullmatch(r"0[0-7]{3}", str(value["mode"])) is None
    ):
        _fail(code, "идентичность сокета имеет неверные значения")
    return copy.deepcopy(value)


def _command_id(definition: StepDefinitionV2) -> str:
    value = definition.command_id
    if type(value) is not str or _COMMAND_ID.fullmatch(value) is None:
        _fail("CONTROLLER_COMMAND_ID_INVALID", "шаг не содержит долговечный commandId")
    return value


def _absolute_path(value: Any, code: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or "\0" in str(value):
        _fail(code, "требуется абсолютный Path")
    return value.absolute()


def _positive_integer(value: Any) -> bool:
    return type(value) is int and 1 <= value <= 2_147_483_647


def _identifier(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор имеет неверную форму")
    return value


def _fail(code: str, message: str) -> None:
    raise InstallerUpdateControllerPortsV2Error(code, message)


__all__ = [
    "InstallerUpdateControllerPortsV2Error",
    "build_shutdown_controller_step_ports_v2",
    "build_update_controller_step_ports_v2",
    "observe_controller_database_v2",
    "observe_stopped_controller_database_v2",
    "observe_runtime_quiescence_database_v2",
]
