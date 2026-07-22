"""Строгий исполнитель ветви ``apply/update-matched-active`` версии 2.

Модуль не строит частично известный журнал. Вызывающая сторона обязана передать
полный :class:`OperationDefinitionV2`, а этот слой проверяет его по нормативному
реестру, повторно подтверждает отдельную квитанцию подготовки и только затем
передаёт все эффекты долговечному :class:`OperationExecutorV2`.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Mapping

from .canonical_json import canonical_json_bytes, domain_fingerprint
from .lifecycle_operation_v2 import (
    ActivationCommitPayloadIntentV2,
    OperationDefinitionV2,
    OperationExecutorV2,
    ProjectionV2,
    StepCallbacksV2,
    StepDefinitionV2,
    TerminalCallbacksV2,
)
from .lifecycle_plan_v2 import LifecyclePlanRegistryV2
from . import operation_deadline_v2

if TYPE_CHECKING:
    from .activation_preparation_v2 import ActivationPreparationReceiptV2
    from .activation_materializer_v2 import StagedActivationV2
    from .activation_transition_v2 import (
        ActivationLinkPlanV2,
        ActivationTransitionProofV2,
        CandidateAcceptanceProofV2,
        ControllerShutdownProofV2,
        ManifestCommitPlanV2,
    )
    from .installer_upgrade_v2 import UpgradePreparationV2


UPDATE_MATCHED_ACTIVE_STEPS_V2 = (
    "gate_close",
    "maintenance_begin",
    "wait_runtime_quiescent",
    "maintenance_strengthen",
    "controller_shutdown",
    "shutdown_socket_cleanup",
    "database_prepare",
    "activation_link",
    "recovery_forward_only",
    "marketplace_registry",
    "plugin_registry",
    "launchers",
    "controller_candidate_spawn",
    "controller_accept",
    "verify_candidate",
    "manifest_commit",
    "maintenance_resume",
    "terminal_journal_freeze",
    "commit_receipt_publish",
    "gate_open",
)
_INTERNAL_MUTABLE_STEPS = {"recovery_forward_only"}
_PORT_STEP_KINDS = frozenset(UPDATE_MATCHED_ACTIVE_STEPS_V2[1:17]).difference(
    _INTERNAL_MUTABLE_STEPS
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STEP_ID = re.compile(r"^st2_[0-9a-f]{32}$")
_COMMAND_ID = re.compile(r"^cc2_[0-9a-f]{32}$")
_RECEIPT_DOMAIN = "codex-smart/activation-commit-receipt/v2"
_MAX_RECEIPT_BYTES = 1024 * 1024


def _checkpoint_operation_deadline_if_scoped_v2() -> None:
    """Проверить общий срок, не создавая вложенный."""

    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is not None:
        deadline.checkpoint()


@dataclass
class UpdateOperationV2Error(RuntimeError):
    """Закрытый отказ сборки либо исполнения обновления."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class PreparationReceiptObservationV2:
    """Минимальная неизменяемая проекция проверенной квитанции подготовки."""

    installation_id: str
    operation_id: str
    receipt_fingerprint: str
    activation_tree: ProjectionV2
    database_empty_file: ProjectionV2
    manifest_expected_after: ProjectionV2

    def __post_init__(self) -> None:
        if not isinstance(self.installation_id, str) or not self.installation_id:
            _fail("PREPARATION_RECEIPT_INVALID", "installationId отсутствует")
        if not isinstance(self.operation_id, str) or not self.operation_id:
            _fail("PREPARATION_RECEIPT_INVALID", "operationId отсутствует")
        if (
            not isinstance(self.receipt_fingerprint, str)
            or _SHA256.fullmatch(self.receipt_fingerprint) is None
        ):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "receiptFingerprint квитанции подготовки неверен",
            )
        if not isinstance(self.activation_tree, ProjectionV2):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "квитанция не содержит типизированное дерево активации",
            )
        if not isinstance(self.database_empty_file, ProjectionV2):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "квитанция не содержит закреплённый пустой файл базы",
            )
        if not isinstance(self.manifest_expected_after, ProjectionV2):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "подготовленный манифест не содержит expectedAfter",
            )


@dataclass(frozen=True)
class PreparationReceiptGateV2:
    """Повторно проверяет одну и ту же подготовительную квитанцию."""

    expected: PreparationReceiptObservationV2
    verify_before_journal: Callable[[], PreparationReceiptObservationV2]
    verify_resume: Callable[[Mapping[str, object]], PreparationReceiptObservationV2]

    def __post_init__(self) -> None:
        if not isinstance(self.expected, PreparationReceiptObservationV2):
            raise TypeError("expected must be PreparationReceiptObservationV2")
        if not callable(self.verify_before_journal):
            raise TypeError("verify_before_journal must be callable")
        if not callable(self.verify_resume):
            raise TypeError("verify_resume must be callable")

    def verify_before_journal_exact(self) -> PreparationReceiptObservationV2:
        return self._verify_result(self.verify_before_journal())

    def verify_resume_exact(
        self, journal: Mapping[str, object]
    ) -> PreparationReceiptObservationV2:
        return self._verify_result(self.verify_resume(journal))

    def _verify_result(
        self, observed: PreparationReceiptObservationV2
    ) -> PreparationReceiptObservationV2:
        if not isinstance(observed, PreparationReceiptObservationV2):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "проверяющий объект вернул иной тип",
            )
        if observed != self.expected:
            _fail(
                "PREPARATION_RECEIPT_CHANGED",
                "подготовительная квитанция или её физическое дерево изменились",
            )
        return observed


def _matches_before_exact_v2(
    observed: ProjectionV2, definition: StepDefinitionV2
) -> bool:
    return observed == definition.before


def _matches_after_exact_v2(
    observed: ProjectionV2, definition: StepDefinitionV2
) -> bool:
    return observed == definition.expected_after


def _never_replay_indistinguishable_v2(
    _observed: ProjectionV2, _definition: StepDefinitionV2
) -> bool:
    return False


def _never_match_intent_resume_v2(
    _observed: ProjectionV2, _definition: StepDefinitionV2
) -> bool:
    return False


def _completed_current_matches_exact_v2(
    persisted_after: ProjectionV2,
    current_observed: ProjectionV2,
    _definition: StepDefinitionV2,
) -> bool:
    return persisted_after == current_observed


@dataclass(frozen=True)
class UpdateStepPortV2:
    """Физическое наблюдение и один идемпотентный эффект шага."""

    observe: Callable[[StepDefinitionV2], ProjectionV2]
    apply: Callable[[StepDefinitionV2], None]
    matches_before: Callable[[ProjectionV2, StepDefinitionV2], bool] = (
        _matches_before_exact_v2
    )
    matches_after: Callable[[ProjectionV2, StepDefinitionV2], bool] = (
        _matches_after_exact_v2
    )
    matches_intent_resume: Callable[
        [ProjectionV2, StepDefinitionV2], bool
    ] = _never_match_intent_resume_v2
    replay_safe_when_indistinguishable: Callable[
        [ProjectionV2, StepDefinitionV2], bool
    ] = _never_replay_indistinguishable_v2
    completed_current_matches: Callable[
        [ProjectionV2, ProjectionV2, StepDefinitionV2], bool
    ] = _completed_current_matches_exact_v2

    def __post_init__(self) -> None:
        if (
            not callable(self.observe)
            or not callable(self.apply)
            or not callable(self.matches_before)
            or not callable(self.matches_after)
            or not callable(self.matches_intent_resume)
            or not callable(self.replay_safe_when_indistinguishable)
            or not callable(self.completed_current_matches)
        ):
            raise TypeError("update step port callbacks must be callable")


class UpdateStepPortsV2:
    """Закрытый набор портов всех внешних изменяемых шагов обновления."""

    def __init__(self, ports: Mapping[str, UpdateStepPortV2]) -> None:
        copied = dict(ports)
        if set(copied) != _PORT_STEP_KINDS:
            missing = sorted(_PORT_STEP_KINDS.difference(copied))
            extra = sorted(set(copied).difference(_PORT_STEP_KINDS))
            _fail(
                "UPDATE_PORTS_INVALID",
                f"неверный набор портов: missing={missing}, extra={extra}",
            )
        if any(not isinstance(port, UpdateStepPortV2) for port in copied.values()):
            raise TypeError("every update port must be UpdateStepPortV2")
        self._ports = copied

    def require(self, kind: str) -> UpdateStepPortV2:
        try:
            return self._ports[kind]
        except KeyError as error:  # pragma: no cover - защищено конструктором
            raise UpdateOperationV2Error(
                "UPDATE_PORT_MISSING", f"нет порта шага {kind}"
            ) from error


def build_upgrade_database_step_port_v2(
    receipt: ActivationPreparationReceiptV2,
) -> UpdateStepPortV2:
    """Построить реальный идемпотентный порт шага ``database_prepare``.

    Порт связан с точной подготовительной квитанцией. Он принимает только
    определение с тем же пустым inode в ``before`` и с полной вычисленной
    привязкой базы в ``expectedAfter``. Наблюдение не изменяет файл базы.
    """

    from .activation_preparation_v2 import ActivationPreparationReceiptV2
    from .installer_upgrade_v2 import (
        build_upgrade_database_binding_v2,
        observe_upgrade_database_v2,
        prepare_upgrade_database_v2,
    )
    from .prepared_database_v2 import PreparedDatabaseStateV2

    if not isinstance(receipt, ActivationPreparationReceiptV2):
        raise TypeError("receipt must be ActivationPreparationReceiptV2")
    intent = receipt.activation_intent
    expected_before = receipt.database_empty_file
    expected_after = build_upgrade_database_binding_v2(receipt)
    expected_action = {
        "actionKind": "database-mutation",
        "method": "prepare",
        "databaseId": intent.database_id,
        "path": str(intent.database_path),
        "expectedSchemaFingerprint": intent.schema_fingerprint,
    }

    def validate_definition(definition: StepDefinitionV2) -> None:
        if not isinstance(definition, StepDefinitionV2):
            raise TypeError("definition must be StepDefinitionV2")
        if (
            definition.kind != "database_prepare"
            or canonical_json_bytes(definition.action)
            != canonical_json_bytes(expected_action)
            or definition.before != expected_before
            or definition.expected_after != expected_after
        ):
            _fail(
                "DATABASE_STEP_DEFINITION_INVALID",
                "database_prepare не связан с точной prep receipt",
            )

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        validate_definition(definition)
        state, observed = observe_upgrade_database_v2(receipt)
        if state is PreparedDatabaseStateV2.EMPTY and observed == expected_before:
            return observed
        if state is PreparedDatabaseStateV2.PREPARED and observed == expected_after:
            return observed
        if state is PreparedDatabaseStateV2.RECOVERABLE:
            return observed
        _fail(
            "DATABASE_STEP_OBSERVATION_INVALID",
            "состояние базы не совпадает с проекцией prep receipt",
        )

    def apply(definition: StepDefinitionV2) -> None:
        validate_definition(definition)
        observed_after = prepare_upgrade_database_v2(receipt)
        if observed_after != expected_after:
            _fail(
                "DATABASE_STEP_APPLY_INVALID",
                "инициализация вернула иную привязку базы",
            )

    def matches_intent_resume(
        observed: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        validate_definition(definition)
        value = observed.value
        before = expected_before.value
        return (
            observed.schema_id == "file-object-v2"
            and type(value) is dict
            and value.get("path") == before.get("path")
            and value.get("device") == before.get("device")
            and value.get("inode") == before.get("inode")
            and value.get("ownerUid") == before.get("ownerUid")
            and value.get("ownerGid") == before.get("ownerGid")
            and value.get("mode") == before.get("mode")
            and value.get("linkCount") == before.get("linkCount")
            and type(value.get("size")) is int
            and value["size"] > 0
        )

    return UpdateStepPortV2(
        observe=observe,
        apply=apply,
        matches_intent_resume=matches_intent_resume,
    )


@dataclass(frozen=True)
class UpdateOperationRunV2:
    status: str
    operation_id: str
    attempt_id: str | None


@dataclass(frozen=True)
class UpdateControllerProofProvidersV2:
    """Долговечные поставщики авторизации без внутрипроцессного кэша."""

    shutdown: Callable[[], ControllerShutdownProofV2]
    acceptance: Callable[[], CandidateAcceptanceProofV2]

    def __post_init__(self) -> None:
        if not callable(self.shutdown) or not callable(self.acceptance):
            raise TypeError("controller proof providers must be callable")


def build_rehydrating_controller_proof_providers_v2(
    *,
    definition: OperationDefinitionV2,
    proof: ActivationTransitionProofV2,
    preparation_receipt: ActivationPreparationReceiptV2,
    shutdown_loader: Callable[..., object] | None = None,
    acceptance_loader: Callable[..., object] | None = None,
) -> UpdateControllerProofProvidersV2:
    """Каждый раз восстановить proof из точных квитанций старой/новой БД."""

    from .activation_preparation_v2 import ActivationPreparationReceiptV2
    from .activation_transition_v2 import ActivationTransitionProofV2
    from .controller_transition_rehydration_v2 import (
        ControllerShutdownCommandIdsV2,
        rehydrate_candidate_acceptance_proof_v2,
        rehydrate_controller_shutdown_proof_v2,
    )

    if not isinstance(definition, OperationDefinitionV2):
        raise TypeError("definition must be OperationDefinitionV2")
    if not isinstance(proof, ActivationTransitionProofV2):
        raise TypeError("proof must be ActivationTransitionProofV2")
    if not isinstance(preparation_receipt, ActivationPreparationReceiptV2):
        raise TypeError("preparation_receipt must be ActivationPreparationReceiptV2")
    if shutdown_loader is not None and not callable(shutdown_loader):
        raise TypeError("shutdown_loader must be callable")
    if acceptance_loader is not None and not callable(acceptance_loader):
        raise TypeError("acceptance_loader must be callable")
    if (
        not proof.complete
        or definition.installation_id != proof.installation_id
        or definition.installation_id != preparation_receipt.installation_id
        or definition.operation_id != preparation_receipt.operation_id
        or preparation_receipt.activation_intent.codex_home != proof.codex_home
    ):
        _fail(
            "UPDATE_PROOF_BINDING_INVALID",
            "definition, transition proof и prep receipt относятся к разным операциям",
        )

    by_kind = {step.kind: step for step in definition.mutable_steps}
    required = {
        "maintenance_begin",
        "maintenance_strengthen",
        "controller_shutdown",
        "controller_accept",
    }
    if not required.issubset(by_kind):
        _fail(
            "UPDATE_PROOF_BINDING_INVALID",
            "definition не содержит все управляющие шаги",
        )

    def command_id(kind: str) -> str:
        value = by_kind[kind].command_id
        if not isinstance(value, str) or _COMMAND_ID.fullmatch(value) is None:
            _fail(
                "UPDATE_PROOF_BINDING_INVALID",
                f"шаг {kind} не содержит долговечный commandId",
            )
        return value

    shutdown_ids = ControllerShutdownCommandIdsV2(
        maintenance_begin=command_id("maintenance_begin"),
        maintenance_strengthen=command_id("maintenance_strengthen"),
        shutdown=command_id("controller_shutdown"),
    )
    accept_id = command_id("controller_accept")
    load_shutdown = shutdown_loader or rehydrate_controller_shutdown_proof_v2
    load_acceptance = acceptance_loader or rehydrate_candidate_acceptance_proof_v2

    def shutdown() -> ControllerShutdownProofV2:
        return load_shutdown(
            database_path=proof.database_path,
            activation_proof_fingerprint=proof.proof_fingerprint,
            operation_id=definition.operation_id,
            command_ids=shutdown_ids,
        )

    def acceptance() -> CandidateAcceptanceProofV2:
        shutdown_proof = shutdown()
        shutdown_fingerprint = getattr(shutdown_proof, "proof_fingerprint", None)
        if (
            not isinstance(shutdown_fingerprint, str)
            or _SHA256.fullmatch(shutdown_fingerprint) is None
        ):
            _fail(
                "UPDATE_PROOF_REHYDRATION_INVALID",
                "loader остановки вернул proof без отпечатка",
            )
        intent = preparation_receipt.activation_intent
        return load_acceptance(
            database_path=intent.database_path,
            activation_proof_fingerprint=proof.proof_fingerprint,
            shutdown_proof_fingerprint=shutdown_fingerprint,
            operation_id=definition.operation_id,
            activation_id=intent.activation_id,
            database_id=intent.database_id,
            command_id=accept_id,
        )

    return UpdateControllerProofProvidersV2(
        shutdown=shutdown,
        acceptance=acceptance,
    )


def build_activation_link_step_port_v2(
    *,
    plan: ActivationLinkPlanV2,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    proof_providers: UpdateControllerProofProvidersV2,
) -> UpdateStepPortV2:
    """Связать чистый план ссылки с восстановимым shutdown proof."""

    from .activation_materializer_v2 import StagedActivationV2
    from .activation_transition_v2 import (
        ActivationLinkPlanV2,
        ActivationTransitionProofV2,
        apply_activation_link_primitive_v2,
        authorize_activation_link_plan_v2,
        build_activation_link_plan_v2,
        observe_activation_link_plan_v2,
    )

    if not isinstance(plan, ActivationLinkPlanV2):
        raise TypeError("plan must be ActivationLinkPlanV2")
    if not isinstance(proof, ActivationTransitionProofV2):
        raise TypeError("proof must be ActivationTransitionProofV2")
    if not isinstance(staged, StagedActivationV2):
        raise TypeError("staged must be StagedActivationV2")
    if not isinstance(proof_providers, UpdateControllerProofProvidersV2):
        raise TypeError("proof_providers must be UpdateControllerProofProvidersV2")
    expected_plan = build_activation_link_plan_v2(
        proof=proof,
        staged=staged,
    )
    if not plan.complete or plan != expected_plan:
        _fail(
            "ACTIVATION_LINK_STEP_PLAN_INVALID",
            "план activation_link не совпадает с proof и кандидатом",
        )

    def validate_definition(definition: StepDefinitionV2) -> None:
        _validate_plan_step_definition_v2(
            definition,
            kind="activation_link",
            action=plan.action,
            before=plan.before,
            expected_after=plan.expected_after,
            code="ACTIVATION_LINK_STEP_DEFINITION_INVALID",
        )

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        validate_definition(definition)
        return observe_activation_link_plan_v2(plan)

    def apply(definition: StepDefinitionV2) -> None:
        validate_definition(definition)
        shutdown = proof_providers.shutdown()
        primitive = authorize_activation_link_plan_v2(
            plan=plan,
            proof=proof,
            staged=staged,
            shutdown=shutdown,
        )
        _validate_authorized_primitive_v2(
            primitive,
            definition=definition,
            code="ACTIVATION_LINK_AUTHORIZATION_INVALID",
        )
        result = apply_activation_link_primitive_v2(
            primitive,
            shutdown=shutdown,
        )
        _validate_mutation_result_v2(
            result,
            definition=definition,
            code="ACTIVATION_LINK_APPLY_INVALID",
        )

    return UpdateStepPortV2(observe=observe, apply=apply)


def build_manifest_commit_step_port_v2(
    *,
    plan: ManifestCommitPlanV2,
    proof: ActivationTransitionProofV2,
    staged: StagedActivationV2,
    proof_providers: UpdateControllerProofProvidersV2,
) -> UpdateStepPortV2:
    """Связать чистый план манифеста с восстановимым acceptance proof."""

    from .activation_materializer_v2 import StagedActivationV2
    from .activation_transition_v2 import (
        ActivationTransitionProofV2,
        ManifestCommitPlanV2,
        PreparedManifestTransitionStateV2,
        apply_manifest_commit_primitive_v2,
        authorize_manifest_commit_plan_v2,
        build_manifest_commit_plan_v2,
        observe_prepared_manifest_transition_v2,
    )

    if not isinstance(plan, ManifestCommitPlanV2):
        raise TypeError("plan must be ManifestCommitPlanV2")
    if not isinstance(proof, ActivationTransitionProofV2):
        raise TypeError("proof must be ActivationTransitionProofV2")
    if not isinstance(staged, StagedActivationV2):
        raise TypeError("staged must be StagedActivationV2")
    if not isinstance(proof_providers, UpdateControllerProofProvidersV2):
        raise TypeError("proof_providers must be UpdateControllerProofProvidersV2")
    expected_plan = build_manifest_commit_plan_v2(
        proof=proof,
        staged=staged,
        prepared=plan.prepared,
    )
    if not plan.complete or plan != expected_plan:
        _fail(
            "MANIFEST_COMMIT_STEP_PLAN_INVALID",
            "план manifest_commit не совпадает с proof и кандидатом",
        )

    def validate_definition(definition: StepDefinitionV2) -> None:
        _validate_plan_step_definition_v2(
            definition,
            kind="manifest_commit",
            action=plan.action,
            before=plan.before,
            expected_after=plan.expected_after,
            code="MANIFEST_COMMIT_STEP_DEFINITION_INVALID",
        )

    def observe(definition: StepDefinitionV2) -> ProjectionV2:
        validate_definition(definition)
        transition = observe_prepared_manifest_transition_v2(
            proof=proof,
            staged=staged,
            prepared=plan.prepared,
        )
        if transition is PreparedManifestTransitionStateV2.BEFORE:
            return plan.before
        if transition is PreparedManifestTransitionStateV2.AFTER:
            return plan.expected_after
        _fail(
            "MANIFEST_COMMIT_OBSERVATION_INVALID",
            "наблюдатель вернул состояние вне BEFORE/AFTER",
        )

    def apply(definition: StepDefinitionV2) -> None:
        validate_definition(definition)
        acceptance = proof_providers.acceptance()
        primitive = authorize_manifest_commit_plan_v2(
            plan=plan,
            proof=proof,
            staged=staged,
            acceptance=acceptance,
        )
        _validate_authorized_primitive_v2(
            primitive,
            definition=definition,
            code="MANIFEST_COMMIT_AUTHORIZATION_INVALID",
        )
        result = apply_manifest_commit_primitive_v2(
            primitive,
            acceptance=acceptance,
        )
        _validate_mutation_result_v2(
            result,
            definition=definition,
            code="MANIFEST_COMMIT_APPLY_INVALID",
        )

    return UpdateStepPortV2(observe=observe, apply=apply)


def _validate_plan_step_definition_v2(
    definition: StepDefinitionV2,
    *,
    kind: str,
    action: Mapping[str, object],
    before: ProjectionV2,
    expected_after: ProjectionV2,
    code: str,
) -> None:
    if not isinstance(definition, StepDefinitionV2):
        raise TypeError("definition must be StepDefinitionV2")
    if (
        definition.kind != kind
        or canonical_json_bytes(definition.action) != canonical_json_bytes(action)
        or definition.before != before
        or definition.expected_after != expected_after
    ):
        _fail(code, f"шаг {kind} не совпадает с чистым планом")


def _validate_authorized_primitive_v2(
    primitive: object,
    *,
    definition: StepDefinitionV2,
    code: str,
) -> None:
    if (
        getattr(primitive, "kind", None) != definition.kind
        or canonical_json_bytes(getattr(primitive, "action", None))
        != canonical_json_bytes(definition.action)
        or getattr(primitive, "before", None) != definition.before
        or getattr(primitive, "expected_after", None) != definition.expected_after
    ):
        _fail(code, "авторизованный примитив изменил долговечное намерение")


def _validate_mutation_result_v2(
    result: object,
    *,
    definition: StepDefinitionV2,
    code: str,
) -> None:
    if (
        getattr(result, "before", None) != definition.before
        or getattr(result, "expected_after", None) != definition.expected_after
        or getattr(result, "observed_after", None) != definition.expected_after
    ):
        _fail(code, "результат мутации не совпадает с долговечным намерением")


class ActivationCommitReceiptStoreV2:
    """Неизменяемая публикация и строгая проверка commit-квитанции."""

    def __init__(self, *, definition: OperationDefinitionV2) -> None:
        if not isinstance(definition, OperationDefinitionV2):
            raise TypeError("definition must be OperationDefinitionV2")
        terminal = definition.terminal
        if (
            terminal is None
            or terminal.terminal_kind != "COMMIT"
            or terminal.receipt_kind != "activation-commit"
            or not isinstance(terminal.receipt_payload, ActivationCommitPayloadIntentV2)
        ):
            _fail(
                "UPDATE_TERMINAL_INVALID",
                "обновление требует терминальную activation-commit квитанцию",
            )
        self.definition = definition
        self.path = terminal.receipt_path
        _require_private_directory(self.path.parent)

    def callbacks(self) -> TerminalCallbacksV2:
        return TerminalCallbacksV2(
            receipt_matches=self.matches_frozen_journal,
            publish_receipt=self.publish_for_frozen_journal,
        )

    def matches_frozen_journal(self, journal: dict[str, object]) -> bool:
        try:
            actual = self._read()
            expected = self._receipt_for_frozen_journal(journal)
        except (OSError, ValueError, UpdateOperationV2Error):
            return False
        return canonical_json_bytes(actual) == canonical_json_bytes(expected)

    def publish_for_frozen_journal(self, journal: dict[str, object]) -> None:
        expected = self._receipt_for_frozen_journal(journal)
        payload = canonical_json_bytes(expected)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            if self.matches_frozen_journal(journal):
                return
            _fail(
                "COMMIT_RECEIPT_CONFLICT",
                "путь commit-квитанции занят другим содержимым",
            )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        except BaseException:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            raise
        finally:
            os.close(descriptor)
        _fsync_directory(self.path.parent)
        if not self.matches_frozen_journal(journal):
            _fail(
                "COMMIT_RECEIPT_PUBLISH_FAILED",
                "опубликованная commit-квитанция не совпала с намерением",
            )

    def completed_matches_definition(self) -> bool:
        """Доказать завершённый повтор после удаления основного журнала."""

        if not os.path.lexists(self.path):
            return False
        try:
            receipt = self._read()
        except (OSError, ValueError, UpdateOperationV2Error):
            return False
        terminal = self.definition.terminal
        assert terminal is not None
        payload = terminal.receipt_payload
        assert isinstance(payload, ActivationCommitPayloadIntentV2)
        static_expected = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": self.definition.installation_id,
            "operationId": self.definition.operation_id,
            "manifest": payload.manifest.to_document(),
            "manifestDocument": copy.deepcopy(dict(payload.manifest_document)),
            "transitionLineage": payload.transition_lineage.to_document(),
            "activation": payload.activation.to_document(),
            "databaseBinding": payload.database_binding.to_document(),
            "journalAbsenceTarget": payload.journal_absence_target.to_document(),
            "controllerIdentity": payload.controller_identity,
        }
        if any(receipt.get(name) != value for name, value in static_expected.items()):
            return False
        completed = receipt.get("completedStepIds")
        expected_completed_count = 1 + len(self.definition.mutable_steps) + 1
        return bool(
            isinstance(completed, list)
            and len(completed) == expected_completed_count
            and len(set(completed)) == len(completed)
            and all(
                isinstance(item, str) and _STEP_ID.fullmatch(item) is not None
                for item in completed
            )
        )

    def _receipt_for_frozen_journal(
        self, journal: Mapping[str, object]
    ) -> dict[str, object]:
        if (
            journal.get("phase") != "TERMINAL_FROZEN"
            or journal.get("installationId") != self.definition.installation_id
            or journal.get("operationId") != self.definition.operation_id
        ):
            _fail(
                "FROZEN_JOURNAL_INVALID",
                "commit-квитанция требует точный замороженный журнал",
            )
        intent = journal.get("terminalDeleteIntent")
        if not isinstance(intent, Mapping):
            _fail("FROZEN_JOURNAL_INVALID", "нет terminalDeleteIntent")
        payload = intent.get("receiptPayloadIntent")
        if not isinstance(payload, Mapping) or payload.get("payloadKind") != (
            "activation-commit"
        ):
            _fail("FROZEN_JOURNAL_INVALID", "нет activation-commit намерения")
        projection: dict[str, object] = {
            "schemaVersion": 2,
            "receiptKind": "activation-commit",
            "installationId": journal["installationId"],
            "operationId": journal["operationId"],
            "frozenJournalFingerprint": journal["journalFingerprint"],
            "manifest": copy.deepcopy(payload["manifest"]),
            "manifestDocument": copy.deepcopy(payload["manifestDocument"]),
            "transitionLineage": copy.deepcopy(payload["transitionLineage"]),
            "activation": copy.deepcopy(payload["activation"]),
            "databaseBinding": copy.deepcopy(payload["databaseBinding"]),
            "journalAbsenceTarget": copy.deepcopy(payload["journalAbsenceTarget"]),
            "controllerIdentity": payload["controllerIdentity"],
            "completedStepIds": copy.deepcopy(payload["completedStepIds"]),
            "completedAt": payload["completedAt"],
        }
        return {
            **projection,
            "receiptFingerprint": domain_fingerprint(_RECEIPT_DOMAIN, projection),
        }

    def _read(self) -> dict[str, object]:
        information = self.path.lstat()
        if (
            not stat.S_ISREG(information.st_mode)
            or stat.S_ISLNK(information.st_mode)
            or information.st_uid != os.getuid()
            or stat.S_IMODE(information.st_mode) != 0o600
            or information.st_nlink != 1
            or information.st_size > _MAX_RECEIPT_BYTES
        ):
            _fail("COMMIT_RECEIPT_INVALID", "небезопасный файл commit-квитанции")
        raw = self.path.read_bytes()
        if len(raw) > _MAX_RECEIPT_BYTES:
            _fail("COMMIT_RECEIPT_INVALID", "commit-квитанция слишком велика")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid receipt JSON") from error
        if not isinstance(document, dict) or canonical_json_bytes(document) != raw:
            _fail(
                "COMMIT_RECEIPT_INVALID",
                "commit-квитанция не является canonical-json-v1",
            )
        expected_keys = {
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
            "receiptFingerprint",
            "completedAt",
        }
        if set(document) != expected_keys:
            _fail("COMMIT_RECEIPT_INVALID", "поля commit-квитанции отличаются")
        unsigned = {
            name: copy.deepcopy(value)
            for name, value in document.items()
            if name != "receiptFingerprint"
        }
        if document.get("receiptFingerprint") != domain_fingerprint(
            _RECEIPT_DOMAIN, unsigned
        ):
            _fail("COMMIT_RECEIPT_INVALID", "receiptFingerprint не совпал")
        return document


class UpdateMatchedActiveOperationV2:
    """Выполняет или возобновляет ровно одну нормативную ветвь обновления."""

    def __init__(
        self,
        *,
        registry: LifecyclePlanRegistryV2,
        executor: OperationExecutorV2,
        definition: OperationDefinitionV2,
        preparation: PreparationReceiptGateV2,
        ports: UpdateStepPortsV2,
        receipt_store: ActivationCommitReceiptStoreV2,
    ) -> None:
        if not isinstance(registry, LifecyclePlanRegistryV2):
            raise TypeError("registry must be LifecyclePlanRegistryV2")
        if not isinstance(executor, OperationExecutorV2):
            raise TypeError("executor must be OperationExecutorV2")
        if not isinstance(definition, OperationDefinitionV2):
            raise TypeError("definition must be OperationDefinitionV2")
        if not isinstance(preparation, PreparationReceiptGateV2):
            raise TypeError("preparation must be PreparationReceiptGateV2")
        if not isinstance(ports, UpdateStepPortsV2):
            raise TypeError("ports must be UpdateStepPortsV2")
        if not isinstance(receipt_store, ActivationCommitReceiptStoreV2):
            raise TypeError("receipt_store must be ActivationCommitReceiptStoreV2")
        self.registry = registry
        self.executor = executor
        self.definition = definition
        self.preparation = preparation
        self.ports = ports
        self.receipt_store = receipt_store
        self._validate_contract()

    def execute(self, *, failure_injector=None) -> UpdateOperationRunV2:
        _checkpoint_operation_deadline_if_scoped_v2()
        journal_exists = os.path.lexists(self.executor.store.journal_path)
        if not journal_exists:
            completed = self.receipt_store.completed_matches_definition()
            _checkpoint_operation_deadline_if_scoped_v2()
        else:
            completed = False
        if completed:
            return UpdateOperationRunV2(
                status="ALREADY_COMPLETED",
                operation_id=self.definition.operation_id,
                attempt_id=None,
            )

        if journal_exists:
            journal = self.executor.store.read()
            _checkpoint_operation_deadline_if_scoped_v2()
            self.preparation.verify_resume_exact(journal)
            _checkpoint_operation_deadline_if_scoped_v2()
            self._verify_resume_effects(journal)
        else:
            self.preparation.verify_before_journal_exact()
        _checkpoint_operation_deadline_if_scoped_v2()
        run = self.executor.execute(
            self.definition,
            callbacks=StepCallbacksV2(
                observe=self._observe_step,
                apply=self._apply_step,
                matches_before=self._matches_before_step,
                matches_after=self._matches_after_step,
                matches_intent_resume=self._matches_intent_resume_step,
                replay_safe_when_indistinguishable=(
                    self._replay_safe_when_indistinguishable_step
                ),
                completed_current_matches=self._completed_current_matches_step,
            ),
            terminal_callbacks=self.receipt_store.callbacks(),
            failure_injector=failure_injector,
        )
        return UpdateOperationRunV2(
            status=run.status,
            operation_id=run.operation_id,
            attempt_id=run.attempt_id,
        )

    def _validate_contract(self) -> None:
        definition = self.definition
        expected_plan = self.registry.select(
            machine_id="apply",
            branch_id="update-matched-active",
            plan_id=definition.execution_plan.plan_id,
        )
        if (
            definition.kind != "activation"
            or definition.operation != "apply"
            or definition.execution_plan != expected_plan
            or definition.execution_plan.composed_step_kinds
            != UPDATE_MATCHED_ACTIVE_STEPS_V2
        ):
            _fail(
                "UPDATE_PLAN_INVALID",
                "definition не равен apply/update-matched-active из реестра",
            )
        actual_kinds = (definition.gate_close.kind,) + tuple(
            step.kind for step in definition.mutable_steps
        )
        terminal = definition.terminal
        if terminal is not None:
            actual_kinds += (terminal.freeze.kind,) + terminal.post_freeze_action_kinds
        if actual_kinds != UPDATE_MATCHED_ACTIVE_STEPS_V2:
            _fail("UPDATE_PLAN_INVALID", "определения шагов не покрывают 20 шагов")
        if (
            definition.installation_id != self.preparation.expected.installation_id
            or definition.operation_id != self.preparation.expected.operation_id
        ):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "подготовительная квитанция принадлежит другой операции",
            )
        steps = {step.kind: step for step in definition.mutable_steps}
        database = steps["database_prepare"]
        manifest = steps["manifest_commit"]
        prepared = self.preparation.expected
        terminal = definition.terminal
        assert terminal is not None
        payload = terminal.receipt_payload
        assert isinstance(payload, ActivationCommitPayloadIntentV2)
        if (
            database.before != prepared.database_empty_file
            or manifest.expected_after != prepared.manifest_expected_after
            or payload.manifest != prepared.manifest_expected_after
        ):
            _fail(
                "PREPARATION_RECEIPT_INVALID",
                "шаги базы и манифеста не связаны с квитанцией подготовки",
            )
        if self.receipt_store.definition != definition:
            _fail(
                "UPDATE_TERMINAL_INVALID",
                "хранилище квитанции связано с другим определением",
            )

    def _observe_step(self, definition: StepDefinitionV2) -> ProjectionV2:
        return self.ports.require(definition.kind).observe(definition)

    def _apply_step(self, definition: StepDefinitionV2) -> None:
        self.ports.require(definition.kind).apply(definition)

    def _matches_before_step(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        return self.ports.require(definition.kind).matches_before(observed, definition)

    def _matches_after_step(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        return self.ports.require(definition.kind).matches_after(observed, definition)

    def _matches_intent_resume_step(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        return self.ports.require(definition.kind).matches_intent_resume(
            observed, definition
        )

    def _replay_safe_when_indistinguishable_step(
        self, observed: ProjectionV2, definition: StepDefinitionV2
    ) -> bool:
        return self.ports.require(definition.kind).replay_safe_when_indistinguishable(
            observed, definition
        )

    def _completed_current_matches_step(
        self,
        persisted_after: ProjectionV2,
        current_observed: ProjectionV2,
        definition: StepDefinitionV2,
    ) -> bool:
        return self.ports.require(definition.kind).completed_current_matches(
            persisted_after,
            current_observed,
            definition,
        )

    def _verify_resume_effects(self, journal: Mapping[str, object]) -> None:
        """До возобновления заново доказать каждый сохранённый внешний эффект."""

        self._verify_resume_journal_identity(journal)
        persisted_steps = journal.get("steps")
        if not isinstance(persisted_steps, list):
            _fail("UPDATE_RESUME_JOURNAL_INVALID", "в журнале нет списка шагов")
        persisted_plan = journal.get("executionPlan")
        first_incomplete = (
            persisted_plan.get("firstIncompleteOrdinal")
            if isinstance(persisted_plan, Mapping)
            else None
        )
        if not isinstance(first_incomplete, int) or not 0 <= first_incomplete <= 20:
            _fail(
                "UPDATE_RESUME_JOURNAL_INVALID",
                "в журнале нет допустимого курсора исполнения",
            )
        definitions = {
            ordinal: definition
            for ordinal, definition in enumerate(self.definition.mutable_steps, start=1)
        }
        for persisted in persisted_steps:
            _checkpoint_operation_deadline_if_scoped_v2()
            if not isinstance(persisted, Mapping):
                _fail(
                    "UPDATE_RESUME_JOURNAL_INVALID",
                    "сохранённый шаг имеет неверный тип",
                )
            plan_ordinal = persisted.get("planOrdinal")
            if not isinstance(plan_ordinal, int) or plan_ordinal not in definitions:
                continue
            definition = definitions[plan_ordinal]
            self._verify_persisted_step(persisted, definition)
            if plan_ordinal > first_incomplete:
                if persisted.get("state") != "PLANNED":
                    _fail(
                        "UPDATE_RESUME_JOURNAL_INVALID",
                        f"будущий шаг {definition.kind} уже имеет эффект",
                    )
                continue
            if definition.kind in _INTERNAL_MUTABLE_STEPS:
                continue
            state = persisted.get("state")
            if state not in {"PLANNED", "INTENT_DURABLE", "COMPLETED"}:
                _fail(
                    "UPDATE_RESUME_JOURNAL_INVALID",
                    f"неизвестное состояние шага {definition.kind}",
                )
            _checkpoint_operation_deadline_if_scoped_v2()
            observed = self.ports.require(definition.kind).observe(definition)
            _checkpoint_operation_deadline_if_scoped_v2()
            port = self.ports.require(definition.kind)
            if state == "PLANNED":
                accepted = port.matches_before(observed, definition)
            elif state == "INTENT_DURABLE":
                accepted = port.matches_before(
                    observed, definition
                ) or port.matches_after(
                    observed, definition
                ) or port.matches_intent_resume(observed, definition)
            else:
                try:
                    persisted_after = ProjectionV2.from_document(
                        persisted["observedAfter"]
                    )
                except (KeyError, TypeError, ValueError) as error:
                    raise UpdateOperationV2Error(
                        "UPDATE_RESUME_JOURNAL_INVALID",
                        f"нет observedAfter шага {definition.kind}",
                    ) from error
                accepted = port.matches_after(
                    persisted_after, definition
                ) and port.completed_current_matches(
                    persisted_after,
                    observed,
                    definition,
                )
            if not accepted:
                _fail(
                    "UPDATE_RESUME_EFFECT_CHANGED",
                    f"внешний эффект шага {definition.kind} изменился",
                )

    def _verify_resume_journal_identity(self, journal: Mapping[str, object]) -> None:
        plan = journal.get("executionPlan")
        if not isinstance(plan, Mapping):
            _fail("UPDATE_RESUME_JOURNAL_INVALID", "в журнале нет плана")
        expected_plan = self.definition.execution_plan
        expected = {
            "planId": expected_plan.plan_id,
            "machineId": expected_plan.machine_id,
            "selectedBranchId": expected_plan.selected_branch_id,
            "selectionSource": expected_plan.selection_source,
            "composedStepKinds": list(expected_plan.composed_step_kinds),
            "planDefinitionFingerprint": expected_plan.plan_definition_fingerprint,
        }
        if (
            journal.get("installationId") != self.definition.installation_id
            or journal.get("operationId") != self.definition.operation_id
            or any(plan.get(name) != value for name, value in expected.items())
        ):
            _fail(
                "UPDATE_RESUME_JOURNAL_INVALID",
                "основной журнал принадлежит другому определению",
            )

    @staticmethod
    def _verify_persisted_step(
        persisted: Mapping[str, object], definition: StepDefinitionV2
    ) -> None:
        expected = {
            "kind": definition.kind,
            "commandId": definition.command_id,
            "action": copy.deepcopy(dict(definition.action)),
            "actionFingerprint": definition.action_fingerprint,
            "before": definition.before.to_document(),
            "expectedAfter": definition.expected_after.to_document(),
        }
        if any(
            canonical_json_bytes(persisted.get(name)) != canonical_json_bytes(value)
            for name, value in expected.items()
        ):
            _fail(
                "UPDATE_RESUME_JOURNAL_INVALID",
                f"сохранённое определение шага {definition.kind} изменилось",
            )


def build_upgrade_preparation_gate_v2(
    *,
    proof: ActivationTransitionProofV2,
    preparation: UpgradePreparationV2,
    expected_receipt: ActivationPreparationReceiptV2,
) -> PreparationReceiptGateV2:
    """Связать подготовительную квитанцию с новой и возобновляемой операцией.

    До появления основного журнала штатный исполнитель подготовки повторно
    доказывает в том числе пустой файл базы. После появления журнала этот
    исполнитель намеренно не запускается: база могла быть уже заполнена шагом
    ``database_prepare``, а prepared-manifest мог быть атомарно перенесён.
    """

    from .activation_preparation_v2 import (
        ActivationPreparationExecutorV2,
        ActivationPreparationReceiptV2,
        ActivationPreparationV2Error,
        capture_file_projection_v2,
        capture_tree_projection_v2,
        prepared_receipt_to_staged_activation_v2,
    )
    from .activation_transition_v2 import (
        ActivationTransitionV2Error,
        ActivationTransitionProofV2,
        PreparedManifestTransitionStateV2,
        observe_prepared_manifest_transition_v2,
        verify_prepared_manifest_file_v2,
    )
    from .installer_upgrade_v2 import (
        UpgradePreparationV2,
        prepared_manifest_from_upgrade_receipt_v2,
    )

    if not isinstance(proof, ActivationTransitionProofV2):
        raise TypeError("proof must be ActivationTransitionProofV2")
    if not isinstance(preparation, UpgradePreparationV2):
        raise TypeError("preparation must be UpgradePreparationV2")
    if not isinstance(expected_receipt, ActivationPreparationReceiptV2):
        raise TypeError("expected_receipt must be ActivationPreparationReceiptV2")
    if (
        preparation.definition.activation_intent != expected_receipt.activation_intent
        or preparation.definition.receipt_path
        != proof.layout.receipts_root
        / expected_receipt.installation_id
        / f"{expected_receipt.operation_id}.preparation.json"
    ):
        _fail(
            "PREPARATION_RECEIPT_INVALID",
            "квитанция не связана с подготовкой, манифестом и установкой",
        )
    try:
        prepared_manifest = prepared_manifest_from_upgrade_receipt_v2(
            proof=proof,
            preparation=preparation,
            receipt=expected_receipt,
        )
    except (OSError, ValueError, ActivationTransitionV2Error) as error:
        raise UpdateOperationV2Error(
            "PREPARATION_RECEIPT_INVALID",
            "квитанция не восстанавливает подготовленный source манифеста",
        ) from error

    expected_document = expected_receipt.to_document()
    staged = prepared_receipt_to_staged_activation_v2(expected_receipt)
    observation = PreparationReceiptObservationV2(
        installation_id=expected_receipt.installation_id,
        operation_id=expected_receipt.operation_id,
        receipt_fingerprint=expected_receipt.receipt_fingerprint,
        activation_tree=expected_receipt.activation_tree,
        database_empty_file=expected_receipt.database_empty_file,
        manifest_expected_after=prepared_manifest.expected_after,
    )

    def read_exact_receipt() -> ActivationPreparationReceiptV2:
        try:
            observed = ActivationPreparationReceiptV2.from_path(
                preparation.definition.receipt_path
            )
        except (OSError, ValueError, ActivationPreparationV2Error) as error:
            raise UpdateOperationV2Error(
                "PREPARATION_RECEIPT_CHANGED",
                "подготовительная квитанция недоступна или повреждена",
            ) from error
        if observed.to_document() != expected_document:
            _fail(
                "PREPARATION_RECEIPT_CHANGED",
                "подготовительная квитанция отличается от принятой",
            )
        return observed

    def verify_static_objects(receipt: ActivationPreparationReceiptV2) -> None:
        expected_files = (
            receipt.snapshot_file,
            receipt.activation_file,
        )
        try:
            for expected in expected_files:
                observed = capture_file_projection_v2(
                    Path(str(expected.value["path"])),
                    schema_sha256=expected.schema_sha256,
                )
                if observed != expected:
                    _fail(
                        "PREPARATION_RECEIPT_CHANGED",
                        "закреплённый файл подготовки изменился",
                    )
            observed_tree = capture_tree_projection_v2(
                Path(str(receipt.activation_tree.value["path"])),
                schema_sha256=receipt.activation_tree.schema_sha256,
            )
        except (
            KeyError,
            OSError,
            ValueError,
            ActivationPreparationV2Error,
        ) as error:
            raise UpdateOperationV2Error(
                "PREPARATION_RECEIPT_CHANGED",
                "физические объекты подготовки недоступны",
            ) from error
        if observed_tree != receipt.activation_tree:
            _fail(
                "PREPARATION_RECEIPT_CHANGED",
                "дерево подготовленной активации изменилось",
            )

    def verify_before_journal() -> PreparationReceiptObservationV2:
        if os.path.lexists(proof.layout.journal_path):
            _fail(
                "PREPARATION_HANDOFF_CONFLICT",
                "основной журнал уже существует до полной проверки подготовки",
            )
        try:
            verified = ActivationPreparationExecutorV2(
                definition=preparation.definition,
                callbacks=preparation.callbacks,
            ).execute()
        except (OSError, ValueError, ActivationPreparationV2Error) as error:
            raise UpdateOperationV2Error(
                "PREPARATION_RECEIPT_CHANGED",
                "штатная проверка подготовки завершилась отказом",
            ) from error
        if verified.to_document() != expected_document:
            _fail(
                "PREPARATION_RECEIPT_CHANGED",
                "штатная проверка вернула другую квитанцию",
            )
        try:
            verify_prepared_manifest_file_v2(
                proof=proof,
                staged=staged,
                prepared=prepared_manifest,
            )
        except (OSError, ValueError, ActivationTransitionV2Error) as error:
            raise UpdateOperationV2Error(
                "PREPARATION_RECEIPT_CHANGED",
                "подготовленный источник манифеста изменился",
            ) from error
        if os.path.lexists(proof.layout.journal_path):
            _fail(
                "PREPARATION_HANDOFF_CONFLICT",
                "основной журнал появился во время проверки подготовки",
            )
        return observation

    def verify_resume(
        journal: Mapping[str, object],
    ) -> PreparationReceiptObservationV2:
        receipt = read_exact_receipt()
        verify_static_objects(receipt)
        manifest_step = _persisted_kind(journal, "manifest_commit")
        state = None if manifest_step is None else manifest_step.get("state")
        if state not in {None, "PLANNED", "INTENT_DURABLE", "COMPLETED"}:
            _fail(
                "UPDATE_RESUME_JOURNAL_INVALID",
                "состояние шага manifest_commit недопустимо",
            )
        try:
            transition = observe_prepared_manifest_transition_v2(
                proof=proof,
                staged=staged,
                prepared=prepared_manifest,
            )
        except (OSError, ValueError, ActivationTransitionV2Error) as error:
            raise UpdateOperationV2Error(
                "PREPARATION_RECEIPT_CHANGED",
                "пара source/target подготовленного манифеста неоднозначна",
            ) from error
        accepted = (
            transition is PreparedManifestTransitionStateV2.BEFORE
            if state in {None, "PLANNED"}
            else (
                transition
                in {
                    PreparedManifestTransitionStateV2.BEFORE,
                    PreparedManifestTransitionStateV2.AFTER,
                }
                if state == "INTENT_DURABLE"
                else transition is PreparedManifestTransitionStateV2.AFTER
            )
        )
        if not accepted:
            _fail(
                "PREPARATION_RECEIPT_CHANGED",
                "состояние prepared-manifest не соответствует журналу",
            )
        return observation

    return PreparationReceiptGateV2(
        expected=observation,
        verify_before_journal=verify_before_journal,
        verify_resume=verify_resume,
    )


def _persisted_kind(
    journal: Mapping[str, object], kind: str
) -> Mapping[str, object] | None:
    steps = journal.get("steps")
    if not isinstance(steps, list):
        _fail("UPDATE_RESUME_JOURNAL_INVALID", "в журнале нет списка шагов")
    matches = [
        item for item in steps if isinstance(item, Mapping) and item.get("kind") == kind
    ]
    if len(matches) > 1:
        _fail(
            "UPDATE_RESUME_JOURNAL_INVALID",
            f"шаг {kind} повторяется в журнале",
        )
    return matches[0] if matches else None


def _require_private_directory(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("COMMIT_RECEIPT_PATH_INVALID", "каталог квитанций не абсолютный")
    information = path.lstat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or stat.S_ISLNK(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        _fail("COMMIT_RECEIPT_PATH_INVALID", "каталог квитанций небезопасен")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fail(code: str, message: str) -> None:
    raise UpdateOperationV2Error(code, message)


__all__ = [
    "UPDATE_MATCHED_ACTIVE_STEPS_V2",
    "ActivationCommitReceiptStoreV2",
    "PreparationReceiptGateV2",
    "PreparationReceiptObservationV2",
    "UpdateMatchedActiveOperationV2",
    "UpdateControllerProofProvidersV2",
    "UpdateOperationRunV2",
    "UpdateOperationV2Error",
    "UpdateStepPortV2",
    "UpdateStepPortsV2",
    "build_activation_link_step_port_v2",
    "build_manifest_commit_step_port_v2",
    "build_rehydrating_controller_proof_providers_v2",
    "build_upgrade_database_step_port_v2",
    "build_upgrade_preparation_gate_v2",
]
