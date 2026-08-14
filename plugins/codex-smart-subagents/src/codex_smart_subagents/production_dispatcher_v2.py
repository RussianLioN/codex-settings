"""Строгая производственная композиция дочерних запусков версии 2.

Модуль намеренно не подменяет отсутствующие доказательства локальными
сравнениями. Барьер запуска, проверка разрешений, дескрипторная проверка
снимка Codex и независимая проверка процесса являются обязательными
зависимостями точки композиции.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from .activation_gateway_v2 import GatewayRuntimeBindingV2
from .child_execution_v2 import ChildExecutionV2
from .child_guard_v2 import (
    GuardExecConfirmationV2,
    PosixSpawnGuardFactoryV2,
)
from .child_launch_coordinator_v2 import (
    ChildLaunchCoordinatorV2,
    OTelAttemptResourceV2,
    ProcessObservationV2,
    SnapshotObservationV2,
)
from .child_launch_v2 import (
    ChildAttemptResourceV2,
    PreparedChildLaunchV2,
    prepare_child_launch_v2,
)
from .child_profile_runtime_v1 import ChildProfileDomainsV1
from .child_runner import ChildRuntimeLayout
from .execution_dispatcher_v2 import ExecutionDispatcherV2
from .launcher import parse_codex_version
from .policy_bundle_v2 import PolicyBundleV2
from .plan_projection_v2 import PlanProjectionV2Error, node_routing_input_v2
from .production_runtime_v2 import (
    ActivationProviderV2,
    DispatcherFactoryV2,
)
from .runtime_recovery_v2 import write_attempt_marker_v2
from .snapshot import (
    SnapshotLimits,
    SnapshotResult,
)
from .state_store_v2 import (
    NodePlanV2,
    RequestContextV2,
    SmartStoreV2,
    StartRequestV2,
)
from .writer_publication_v2 import (
    WriterPublicationCoordinatorV2,
    WriterPublicationRequestV2,
    WriterPublicationResultV2,
    WriterPublicationSessionV2,
)


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BASE_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_ATTEMPT_ID = re.compile(r"^att2_[0-9a-f]{32}$")
_SCHEMA_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CLEAN_WORKTREE_FINGERPRINT = hashlib.sha256(b"").hexdigest()


@dataclass
class ProductionDispatcherV2Error(RuntimeError):
    """Ошибка строгой производственной композиции версии 2."""

    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ProductionDispatcherDependenciesV2:
    """Доказательные зависимости, которые нельзя честно вывести локально.

    У доказательных поставщиков нет значений по умолчанию: отсутствие
    производственного барьера, независимого доказательства, связанного
    разрешения схем либо ограниченного по сроку построителя снимков должно
    останавливать сборку, а не незаметно ослаблять её.
    """

    launch_barrier: Callable[[], Any]
    fresh_permission_probe: Callable[[PreparedChildLaunchV2], str]
    codex_snapshot_probe: Callable[[Path, str], SnapshotObservationV2]
    fresh_process_probe: Callable[
        [PreparedChildLaunchV2, GuardExecConfirmationV2],
        ProcessObservationV2,
    ]
    result_schema_resolution_provider: Callable[
        [GatewayRuntimeBindingV2, PolicyBundleV2],
        Mapping[str, str],
    ]
    bounded_snapshot_builder_factory: Callable[[SnapshotLimits], Any]
    guard_factory: Any = field(default_factory=PosixSpawnGuardFactoryV2)
    attempt_resource_factory: Callable[[], ChildAttemptResourceV2] = (
        OTelAttemptResourceV2.start
    )
    writer_publication_coordinator_factory: Callable[..., Any] | None = None
    writer_validation_commands_provider: Callable[..., Any] | None = None
    clock: Callable[[], datetime] = _utc_now
    error_sink: Callable[[str, BaseException], None] | None = None
    max_workers: int = 2
    max_pending: int = 32

    def __post_init__(self) -> None:
        for name in (
            "launch_barrier",
            "fresh_permission_probe",
            "codex_snapshot_probe",
            "fresh_process_probe",
            "result_schema_resolution_provider",
            "bounded_snapshot_builder_factory",
            "attempt_resource_factory",
            "clock",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"{name} must be callable")
        if not callable(getattr(self.guard_factory, "start", None)):
            raise TypeError("guard_factory must provide start()")
        if self.error_sink is not None and not callable(self.error_sink):
            raise TypeError("error_sink must be callable")
        for name in (
            "writer_publication_coordinator_factory",
            "writer_validation_commands_provider",
        ):
            value = getattr(self, name)
            if value is not None and not callable(value):
                raise TypeError(f"{name} must be callable")
        if type(self.max_workers) is not int or not 1 <= self.max_workers <= 2:
            raise ValueError("max_workers must be between one and two")
        if (
            type(self.max_pending) is not int
            or not self.max_workers <= self.max_pending <= 32
        ):
            raise ValueError("max_pending must contain all workers and be at most 32")


class _OwnedAttemptResourceV2:
    """Закрывает телеметрию и ровно один созданный адаптером каталог."""

    def __init__(
        self,
        *,
        delegate: ChildAttemptResourceV2,
        attempt_root: Path,
        attempts_root: Path,
        store: SmartStoreV2,
        artifact_id: str,
    ) -> None:
        for method in ("attest", "close"):
            if not callable(getattr(delegate, method, None)):
                raise TypeError(f"attempt resource must provide {method}()")
        self._delegate = delegate
        self._attempt_root = attempt_root
        self._attempts_root = attempts_root
        self._store = store
        self._artifact_id = artifact_id
        self._cleanup_started = False
        self._delegate_closed = False
        self._tree_removed = False
        self._artifact_closed = False
        self._lock = threading.Lock()

    @property
    def telemetry_config(self) -> Any:
        with self._lock:
            if self._cleanup_started:
                raise RuntimeError("attempt resource is closed")
        return self._delegate.telemetry_config

    def attest(
        self,
        prepared: PreparedChildLaunchV2,
        jsonl_events: list[dict[str, Any]],
        permission_probe_id: str,
    ) -> Any:
        with self._lock:
            if self._cleanup_started:
                raise RuntimeError("attempt resource is closed")
        return self._delegate.attest(
            prepared,
            jsonl_events,
            permission_probe_id,
        )

    def close(self) -> None:
        with self._lock:
            if (
                self._delegate_closed
                and self._tree_removed
                and self._artifact_closed
            ):
                return
            self._cleanup_started = True
            failures: list[str] = []
            if not self._delegate_closed:
                try:
                    self._delegate.close()
                except Exception as exc:
                    failures.append(str(exc) or type(exc).__name__)
                else:
                    self._delegate_closed = True
            if not self._tree_removed:
                try:
                    _remove_owned_attempt(self._attempt_root, self._attempts_root)
                except Exception as exc:
                    failures.append(str(exc) or type(exc).__name__)
                else:
                    self._tree_removed = True
            if self._tree_removed and not self._artifact_closed:
                try:
                    sealed = self._store.seal_runtime_artifact(
                        self._artifact_id,
                        terminal=True,
                    )
                    if sealed.get("state") != "MISSING":
                        raise ProductionDispatcherV2Error(
                            "ATTEMPT_ARTIFACT_SEAL_MISMATCH",
                            "removed attempt runtime did not become MISSING",
                        )
                except Exception as exc:
                    failures.append(str(exc) or type(exc).__name__)
                else:
                    self._artifact_closed = True
        if failures:
            raise ProductionDispatcherV2Error(
                "ATTEMPT_CLEANUP_FAILED",
                "; ".join(failures),
            )


class _WriterCompletionV2:
    """Преобразует ровно одно завершение автора в каноническую проекцию."""

    def __init__(
        self,
        *,
        coordinator: WriterPublicationCoordinatorV2,
        session: WriterPublicationSessionV2,
    ) -> None:
        self._coordinator = coordinator
        self._session = session
        self._lock = threading.Lock()
        self._completed = False

    def complete(self, child_result: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(child_result, Mapping):
            raise TypeError("child_result must be a mapping")
        with self._lock:
            if self._completed:
                raise ProductionDispatcherV2Error(
                    "WRITER_COMPLETION_REPLAY",
                    "writer completion is single-use",
                )
            self._completed = True
        result = self._coordinator.complete(
            self._session,
            cancellation=threading.Event(),
        )
        if not isinstance(result, WriterPublicationResultV2):
            raise ProductionDispatcherV2Error(
                "WRITER_COMPLETION_INVALID",
                "writer coordinator returned another result type",
            )
        return _writer_publication_result_value(result)


class ProductionLaunchPreparerV2:
    """Материализует один запуск только из плана и свежей READY-привязки."""

    def __init__(
        self,
        *,
        store: SmartStoreV2,
        provider: ActivationProviderV2,
        policy_bundle: PolicyBundleV2,
        binding: GatewayRuntimeBindingV2,
        environment: Mapping[str, str],
        dependencies: ProductionDispatcherDependenciesV2,
    ) -> None:
        if not isinstance(policy_bundle, PolicyBundleV2):
            raise TypeError("policy_bundle must be PolicyBundleV2")
        if not isinstance(binding, GatewayRuntimeBindingV2):
            raise TypeError("binding must be GatewayRuntimeBindingV2")
        if not isinstance(dependencies, ProductionDispatcherDependenciesV2):
            raise TypeError("dependencies must be ProductionDispatcherDependenciesV2")
        for name in ("runtime_binding", "activation_gate"):
            if not callable(getattr(provider, name, None)):
                raise TypeError(f"provider must provide {name}()")
        for name in ("reserve_runtime_artifact", "seal_runtime_artifact"):
            if not callable(getattr(store, name, None)):
                raise TypeError(f"store must provide {name}()")
        self.store = store
        self.provider = provider
        self.policy_bundle = policy_bundle
        self.binding = binding
        self.dependencies = dependencies
        self.environment = _closed_environment(environment)
        self._require_current_binding()
        self._codex_home = _configured_codex_home(self.environment)
        self._executable, self._snapshot_sha256, self._cli_version = (
            _codex_snapshot_contract(binding)
        )
        self._attempts_root = _prepare_attempts_root(binding.state_home)
        self._role_templates, self._profiles = _policy_profiles(policy_bundle)
        self._schema_resolution = self._read_schema_resolution()
        limits = _snapshot_limits(policy_bundle)
        try:
            self._snapshot_builder = dependencies.bounded_snapshot_builder_factory(
                limits
            )
        except Exception as exc:
            self._fail("SNAPSHOT_BUILDER_UNAVAILABLE", str(exc))
        if not callable(getattr(self._snapshot_builder, "build", None)):
            raise TypeError("snapshot builder must provide build()")
        self._writer_coordinator_lock = threading.Lock()
        self._writer_coordinator: WriterPublicationCoordinatorV2 | None = None

    def __call__(
        self,
        plan: NodePlanV2,
        prompt: str,
        request_context: RequestContextV2,
        start_request: StartRequestV2,
    ) -> PreparedChildLaunchV2:
        self._require_current_binding()
        self._validate_start_request(plan, start_request)
        self._require_before_deadline(start_request.deadline_at)
        repository = self._validate_request_context(request_context)
        profile, expected_profile_fingerprint = self._select_profile(plan)
        writer_coordinator: WriterPublicationCoordinatorV2 | None = None
        if profile["role"] == "writer":
            writer_coordinator = self._require_writer_coordinator()
        pair = {
            "model": plan.node.selected_model,
            "reasoningEffort": plan.node.reasoning_effort,
        }
        output_schema = self._output_schema(profile)
        attempt_root, artifact_id = self._create_attempt_root(
            plan,
            start_request.attempt_id,
        )
        resource: _OwnedAttemptResourceV2 | None = None
        try:
            writer_completion: _WriterCompletionV2 | None = None
            workspace_root: Path | None = None
            if profile["role"] == "writer":
                assert writer_coordinator is not None
                commands = self._writer_validation_commands(plan)
                writer_request = WriterPublicationRequestV2(
                    route_id=plan.route_id,
                    node_id=plan.node_id,
                    attempt_id=start_request.attempt_id,
                    repository=repository,
                    base_sha=request_context.base_sha,
                    attempt_root=attempt_root / "writer-publication",
                    quarantine_state_root=self.binding.state_home / "quarantine-v2",
                    validation_commands=commands,
                    source_date_epoch=int(start_request.deadline_at.timestamp()),
                    max_files=self.policy_bundle.catalog_limits[
                        "snapshot_max_files"
                    ],
                    max_file_bytes=self.policy_bundle.catalog_limits[
                        "snapshot_max_file_bytes"
                    ],
                    max_total_bytes=self.policy_bundle.catalog_limits[
                        "snapshot_max_total_bytes"
                    ],
                    max_diff_bytes=self.policy_bundle.catalog_limits[
                        "snapshot_max_total_bytes"
                    ],
                    deadline_at=start_request.deadline_at,
                )
                writer_session = writer_coordinator.prepare(writer_request)
                snapshot = writer_session.snapshot
                snapshot_destination = writer_request.attempt_root / "snapshot"
                workspace_root = writer_session.workspace.root
                writer_completion = _WriterCompletionV2(
                    coordinator=writer_coordinator,
                    session=writer_session,
                )
            else:
                snapshot_destination = attempt_root / "repository"
                snapshot = self._snapshot_builder.build(
                    repository=repository,
                    base_sha=request_context.base_sha,
                    destination=snapshot_destination,
                    deadline_at=start_request.deadline_at,
                )
            self._validate_repository_snapshot(
                snapshot,
                destination=snapshot_destination,
                request_context=request_context,
            )
            self._require_before_deadline(start_request.deadline_at)
            self._require_current_binding()
            observation = self._observe_codex_snapshot()
            runtime = ChildRuntimeLayout.create(attempt_root / "runtime")
            delegate = self.dependencies.attempt_resource_factory()
            try:
                resource = _OwnedAttemptResourceV2(
                    delegate=delegate,
                    attempt_root=attempt_root,
                    attempts_root=self._attempts_root,
                    store=self.store,
                    artifact_id=artifact_id,
                )
            except BaseException:
                close = getattr(delegate, "close", None)
                if callable(close):
                    close()
                raise
            return prepare_child_launch_v2(
                executable=self._executable,
                snapshot_sha256=observation.snapshot_sha256,
                snapshot_identity_fingerprint=(
                    observation.snapshot_identity_fingerprint
                ),
                pair=pair,
                allowed_pairs=self.policy_bundle.policy_pairs,
                runtime=runtime,
                snapshot_root=snapshot.root,
                output_schema=output_schema,
                profile=profile,
                profile_domain=self.policy_bundle.child_profile_domain,
                expected_profile_fingerprint=expected_profile_fingerprint,
                domains=ChildProfileDomainsV1(
                    argv=self.policy_bundle.child_argv_domain,
                    environment=self.policy_bundle.child_environment_domain,
                    secret=self.policy_bundle.child_secret_domain,
                ),
                compatibility_fingerprint=self.binding.compatibility_fingerprint,
                account_context_fingerprint=plan.account_context_fingerprint,
                expected_cli_version=self._cli_version,
                attempt_resource=resource,
                auth_file=self._codex_home / "auth.json",
                prompt=prompt,
                workspace_root=workspace_root,
                completion=writer_completion,
            )
        except BaseException as exc:
            try:
                if resource is not None:
                    resource.close()
                else:
                    _remove_owned_attempt(attempt_root, self._attempts_root)
                    sealed = self.store.seal_runtime_artifact(
                        artifact_id,
                        terminal=True,
                    )
                    if sealed.get("state") != "MISSING":
                        self._fail(
                            "ATTEMPT_ARTIFACT_SEAL_MISMATCH",
                            "removed attempt runtime did not become MISSING",
                        )
            except Exception as cleanup_error:
                raise ProductionDispatcherV2Error(
                    "ATTEMPT_CLEANUP_FAILED",
                    f"{cleanup_error}; preceding error: {exc}",
                ) from cleanup_error
            raise

    def fresh_snapshot_probe(
        self,
        prepared: PreparedChildLaunchV2,
    ) -> SnapshotObservationV2:
        """Повторяет независимую проверку закреплённого снимка Codex."""

        self._require_current_binding()
        if (
            not isinstance(prepared, PreparedChildLaunchV2)
            or prepared.executable != self._executable
            or prepared.snapshot_sha256 != self._snapshot_sha256
        ):
            self._fail(
                "CODEX_SNAPSHOT_CHANGED",
                "подготовленный запуск относится к другому снимку Codex",
            )
        return self._observe_codex_snapshot()

    def _writer_validation_commands(
        self,
        plan: NodePlanV2,
    ) -> tuple[tuple[str, ...], ...]:
        provider = self.dependencies.writer_validation_commands_provider
        if provider is None:
            self._fail(
                "WRITER_PUBLICATION_UNAVAILABLE",
                "writer validation provider is absent",
            )
        try:
            raw = provider(plan, self.policy_bundle)
            commands = tuple(tuple(command) for command in raw)
        except Exception as exc:
            raise ProductionDispatcherV2Error(
                "WRITER_VALIDATION_PROFILE_INVALID",
                str(exc),
            ) from exc
        if not commands or any(
            not command
            or any(
                not isinstance(argument, str)
                or not argument
                or "\0" in argument
                for argument in command
            )
            for command in commands
        ):
            self._fail(
                "WRITER_VALIDATION_PROFILE_INVALID",
                "writer validation profile is empty or malformed",
            )
        return commands

    def _require_writer_coordinator(self) -> WriterPublicationCoordinatorV2:
        factory = self.dependencies.writer_publication_coordinator_factory
        if (
            factory is None
            or self.dependencies.writer_validation_commands_provider is None
        ):
            self._fail(
                "WRITER_PUBLICATION_UNAVAILABLE",
                "версия 2 не получила владельца публикации и профиля проверки",
            )
        with self._writer_coordinator_lock:
            coordinator = self._writer_coordinator
            if coordinator is not None:
                return coordinator
            try:
                coordinator = factory(
                    store=self.store,
                    binding=self.binding,
                    policy_bundle=self.policy_bundle,
                    environment=self.environment,
                    snapshot_builder=self._snapshot_builder,
                )
            except Exception as exc:
                self._fail("WRITER_PUBLICATION_UNAVAILABLE", str(exc))
            if not isinstance(coordinator, WriterPublicationCoordinatorV2):
                self._fail(
                    "WRITER_PUBLICATION_UNAVAILABLE",
                    "writer factory returned another coordinator type",
                )
            self._writer_coordinator = coordinator
            return coordinator

    def require_current_binding(self) -> GatewayRuntimeBindingV2:
        """Даёт свежую привязку только при точном равенстве закреплённой."""

        return self._require_current_binding()

    def _require_current_binding(self) -> GatewayRuntimeBindingV2:
        try:
            fresh = self.provider.runtime_binding()
        except Exception as exc:
            raise ProductionDispatcherV2Error(
                "ACTIVATION_BINDING_UNAVAILABLE",
                str(exc),
            ) from exc
        if not isinstance(fresh, GatewayRuntimeBindingV2):
            self._fail(
                "ACTIVATION_BINDING_INVALID",
                "поставщик вернул не GatewayRuntimeBindingV2",
            )
        if fresh != self.binding:
            self._fail(
                "ACTIVATION_BINDING_CHANGED",
                "READY-привязка изменилась после сборки рабочего контура",
            )
        return fresh

    def _validate_start_request(
        self,
        plan: NodePlanV2,
        start_request: StartRequestV2,
    ) -> None:
        if not isinstance(plan, NodePlanV2):
            raise TypeError("plan must be NodePlanV2")
        if not isinstance(start_request, StartRequestV2):
            raise TypeError("start_request must be StartRequestV2")
        if (
            start_request.route_id != plan.route_id
            or start_request.node_id != plan.node_id
            or start_request.state != "ATTESTING"
            or _ATTEMPT_ID.fullmatch(start_request.attempt_id) is None
        ):
            self._fail(
                "START_REQUEST_BINDING_MISMATCH",
                "заявка запуска не совпала с подготовляемым планом",
            )

    def _require_before_deadline(self, deadline_at: datetime) -> None:
        if not isinstance(deadline_at, datetime) or deadline_at.tzinfo is None:
            self._fail(
                "REQUEST_DEADLINE_INVALID", "срок заявки не имеет часового пояса"
            )
        try:
            now = self.dependencies.clock()
        except Exception as exc:
            raise ProductionDispatcherV2Error("CLOCK_INVALID", str(exc)) from exc
        if not isinstance(now, datetime) or now.tzinfo is None:
            self._fail("CLOCK_INVALID", "часы вернули время без часового пояса")
        if now.astimezone(timezone.utc) >= deadline_at.astimezone(timezone.utc):
            self._fail(
                "REQUEST_DEADLINE_EXCEEDED",
                "срок заявки истёк во время подготовки",
            )

    def _validate_request_context(self, value: RequestContextV2) -> Path:
        if not isinstance(value, RequestContextV2):
            raise TypeError("request_context must be RequestContextV2")
        if (
            value.activation_fingerprint != self.binding.activation_fingerprint
            or value.compatibility_fingerprint != self.binding.compatibility_fingerprint
        ):
            self._fail(
                "REQUEST_BINDING_MISMATCH",
                "контекст запроса относится к другой активации",
            )
        try:
            context_home = Path(value.codex_home).resolve(strict=True)
        except OSError as exc:
            raise ProductionDispatcherV2Error(
                "CODEX_HOME_INVALID",
                str(exc),
            ) from exc
        if context_home != self._codex_home:
            self._fail(
                "CODEX_HOME_MISMATCH",
                "контекст запроса относится к другому CODEX_HOME",
            )
        if value.worktree_fingerprint != _CLEAN_WORKTREE_FINGERPRINT:
            self._fail(
                "WORKTREE_NOT_CLEAN",
                "производственный снимок поддерживает только чистый рабочий каталог",
            )
        if _BASE_SHA.fullmatch(value.base_sha) is None:
            self._fail("BASE_SHA_INVALID", "контекст содержит неверный base SHA")
        try:
            repository = Path(value.repo_root).resolve(strict=True)
        except OSError as exc:
            raise ProductionDispatcherV2Error(
                "REPOSITORY_INVALID",
                str(exc),
            ) from exc
        if not repository.is_dir():
            self._fail("REPOSITORY_INVALID", "корень репозитория не является каталогом")
        return repository

    def _select_profile(
        self,
        plan: NodePlanV2,
    ) -> tuple[dict[str, Any], str]:
        if not isinstance(plan, NodePlanV2):
            raise TypeError("plan must be NodePlanV2")
        if (
            plan.node_id != plan.node.node_id
            or plan.node_state != "PLANNED"
            or plan.catalog_generation != self.policy_bundle.bundle_fingerprint
            or plan.compatibility_fingerprint != self.binding.compatibility_fingerprint
            or plan.algorithm_version != self.policy_bundle.algorithm_version
            or _SHA256.fullmatch(plan.account_context_fingerprint) is None
        ):
            self._fail(
                "NODE_PLAN_BINDING_MISMATCH",
                "план узла не связан с текущим договором запуска",
            )
        try:
            routing_input = node_routing_input_v2(plan.plan_output, plan.node_id)
            template_id = routing_input["roleTemplateId"]
        except (KeyError, TypeError, PlanProjectionV2Error) as exc:
            raise ProductionDispatcherV2Error(
                "ROLE_TEMPLATE_MISSING",
                str(exc),
            ) from exc
        if type(template_id) is not str or template_id not in self._role_templates:
            self._fail("ROLE_TEMPLATE_MISSING", str(template_id))
        template = self._role_templates[template_id]
        if plan.node.role != template["semanticRole"]:
            self._fail(
                "ROLE_TEMPLATE_MISMATCH",
                "смысловая роль плана отличается от шаблона",
            )
        profile_role = template["executionProfile"]
        profile, fingerprint = self._profiles[profile_role]
        self._require_interface_profile(profile_role, fingerprint)
        if plan.node.permission_profile_id != profile["permissionProfileId"]:
            self._fail(
                "PERMISSION_PROFILE_MISMATCH",
                "профиль разрешений плана отличается от дочернего профиля",
            )
        selected = (
            plan.node.selected_model,
            plan.node.reasoning_effort,
        )
        allowed = {
            (item["model"], item["reasoningEffort"])
            for item in self.policy_bundle.policy_pairs
        }
        if selected not in allowed:
            self._fail(
                "PAIR_NOT_ALLOWED",
                "пара модели и уровня рассуждения отсутствует в политике",
            )
        return profile, fingerprint

    def _output_schema(self, profile: Mapping[str, Any]) -> Path:
        schema_id = profile.get("resultSchemaId")
        if type(schema_id) is not str or _SCHEMA_ID.fullmatch(schema_id) is None:
            self._fail("RESULT_SCHEMA_INVALID", "профиль содержит неверную схему")
        resolution = self._read_schema_resolution()
        if resolution != self._schema_resolution:
            self._fail(
                "RESULT_SCHEMA_RESOLUTION_CHANGED",
                "разрешение машинной схемы изменилось после сборки",
            )
        relative_root = PurePosixPath(resolution["repositoryRoot"])
        schema_root = self.binding.marketplace_path.joinpath(*relative_root.parts)
        target = schema_root / f"{schema_id}.schema.json"
        expected_sha256 = self._interface_schema_sha256(schema_id)
        observed_sha256 = _private_file_sha256(target)
        if observed_sha256 != expected_sha256:
            self._fail(
                "RESULT_SCHEMA_FINGERPRINT_MISMATCH",
                "байты схемы результата отличаются от InterfaceEvidence",
            )
        return target

    def _read_schema_resolution(self) -> dict[str, str]:
        try:
            raw = self.dependencies.result_schema_resolution_provider(
                self.binding,
                self.policy_bundle,
            )
        except Exception as exc:
            raise ProductionDispatcherV2Error(
                "RESULT_SCHEMA_RESOLUTION_UNAVAILABLE",
                str(exc),
            ) from exc
        return _validated_schema_resolution(raw)

    def _require_interface_profile(self, role: str, fingerprint: str) -> None:
        try:
            profiles = self.binding.interface_evidence["semantic"]["childProfiles"]
            observed = profiles[role]
        except (KeyError, TypeError) as exc:
            raise ProductionDispatcherV2Error(
                "INTERFACE_CHILD_PROFILE_INVALID",
                str(exc),
            ) from exc
        if observed != fingerprint:
            self._fail(
                "INTERFACE_CHILD_PROFILE_MISMATCH",
                "отпечаток дочернего профиля отличается от InterfaceEvidence",
            )

    def _interface_schema_sha256(self, schema_id: str) -> str:
        try:
            machine_schemas = self.binding.interface_evidence["semantic"][
                "machineSchemas"
            ]
            record = machine_schemas[schema_id]
        except (KeyError, TypeError) as exc:
            raise ProductionDispatcherV2Error(
                "INTERFACE_MACHINE_SCHEMA_INVALID",
                str(exc),
            ) from exc
        if (
            type(record) is not dict
            or set(record) != {"schemaId", "schemaSha256"}
            or record["schemaId"] != schema_id
            or not isinstance(record["schemaSha256"], str)
            or _SHA256.fullmatch(record["schemaSha256"]) is None
        ):
            self._fail(
                "INTERFACE_MACHINE_SCHEMA_INVALID",
                "машинная запись схемы не является закрытым точным объектом",
            )
        return record["schemaSha256"]

    def _observe_codex_snapshot(self) -> SnapshotObservationV2:
        try:
            observation = self.dependencies.codex_snapshot_probe(
                self._executable,
                self._snapshot_sha256,
            )
        except Exception as exc:
            raise ProductionDispatcherV2Error(
                "CODEX_SNAPSHOT_PROBE_FAILED",
                str(exc),
            ) from exc
        if not isinstance(observation, SnapshotObservationV2):
            self._fail(
                "CODEX_SNAPSHOT_PROBE_INVALID",
                "поставщик вернул не SnapshotObservationV2",
            )
        if observation.snapshot_sha256 != self._snapshot_sha256:
            self._fail(
                "CODEX_SNAPSHOT_CHANGED",
                "дескрипторная проверка увидела другой снимок Codex",
            )
        return observation

    def _create_attempt_root(
        self,
        plan: NodePlanV2,
        attempt_id: str,
    ) -> tuple[Path, str]:
        if not isinstance(attempt_id, str) or _ATTEMPT_ID.fullmatch(attempt_id) is None:
            self._fail("ATTEMPT_ID_INVALID", "неверный идентификатор попытки")
        target = self._attempts_root / f"attempt-{attempt_id}"
        try:
            artifact_id = self.store.reserve_runtime_artifact(
                route_id=plan.route_id,
                node_id=plan.node_id,
                kind="attempt_runtime_v2",
                path=target,
                allowed_root=self._attempts_root,
            )
        except Exception as exc:
            raise ProductionDispatcherV2Error(
                "ATTEMPT_ARTIFACT_RESERVATION_FAILED",
                str(exc),
            ) from exc
        created = False
        try:
            target.mkdir(mode=0o700)
            created = True
            _require_private_directory(target, "ATTEMPT_ROOT_UNSAFE")
            write_attempt_marker_v2(
                target,
                artifact_id=artifact_id,
                attempt_id=attempt_id,
            )
            sealed = self.store.seal_runtime_artifact(
                artifact_id,
                terminal=False,
            )
            metadata = target.lstat()
            if (
                sealed.get("state") != "ACTIVE"
                or sealed.get("device") != metadata.st_dev
                or sealed.get("inode") != metadata.st_ino
            ):
                self._fail(
                    "ATTEMPT_ARTIFACT_SEAL_MISMATCH",
                    "attempt runtime was not bound to its exact directory",
                )
        except Exception as exc:
            cleanup_error: Exception | None = None
            if created:
                try:
                    _remove_owned_attempt(target, self._attempts_root)
                    self.store.seal_runtime_artifact(
                        artifact_id,
                        terminal=True,
                    )
                except Exception as error:
                    cleanup_error = error
            elif not os.path.lexists(target):
                try:
                    self.store.seal_runtime_artifact(
                        artifact_id,
                        terminal=True,
                    )
                except Exception as error:
                    cleanup_error = error
            if cleanup_error is not None:
                raise ProductionDispatcherV2Error(
                    "ATTEMPT_CLEANUP_FAILED",
                    f"{cleanup_error}; preceding error: {exc}",
                ) from cleanup_error
            raise ProductionDispatcherV2Error(
                "ATTEMPT_ROOT_UNAVAILABLE",
                str(exc),
            ) from exc
        return target, artifact_id

    @staticmethod
    def _validate_repository_snapshot(
        value: Any,
        *,
        destination: Path,
        request_context: RequestContextV2,
    ) -> None:
        if not isinstance(value, SnapshotResult):
            ProductionLaunchPreparerV2._fail(
                "REPOSITORY_SNAPSHOT_INVALID",
                "построитель вернул не SnapshotResult",
            )
        if (
            value.root != destination
            or value.base_sha != request_context.base_sha
            or value.source_before != value.source_after
            or value.source_before.head_sha != request_context.base_sha
            or value.source_before.status_sha256 != _CLEAN_WORKTREE_FINGERPRINT
            or _SHA256.fullmatch(value.manifest_sha256) is None
        ):
            ProductionLaunchPreparerV2._fail(
                "REPOSITORY_SNAPSHOT_MISMATCH",
                "снимок не совпал с закреплённым чистым контекстом запроса",
            )

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise ProductionDispatcherV2Error(code, message)


def build_production_dispatcher_factory_v2(
    dependencies: ProductionDispatcherDependenciesV2,
) -> DispatcherFactoryV2:
    """Возвращает точную фабрику для ``build_production_runtime_v2``."""

    if not isinstance(dependencies, ProductionDispatcherDependenciesV2):
        raise TypeError("dependencies must be ProductionDispatcherDependenciesV2")

    def factory(
        service: Any,
        store: SmartStoreV2,
        provider: ActivationProviderV2,
        policy_bundle: PolicyBundleV2,
        binding: GatewayRuntimeBindingV2,
        environment: Mapping[str, str],
    ) -> ExecutionDispatcherV2:
        preparer = ProductionLaunchPreparerV2(
            store=store,
            provider=provider,
            policy_bundle=policy_bundle,
            binding=binding,
            environment=environment,
            dependencies=dependencies,
        )

        def current_gate() -> Mapping[str, Any]:
            preparer.require_current_binding()
            return provider.activation_gate()

        def permission_probe(prepared: PreparedChildLaunchV2) -> str:
            preparer.require_current_binding()
            return dependencies.fresh_permission_probe(prepared)

        def process_probe(
            prepared: PreparedChildLaunchV2,
            confirmation: GuardExecConfirmationV2,
        ) -> ProcessObservationV2:
            preparer.require_current_binding()
            return dependencies.fresh_process_probe(prepared, confirmation)

        coordinator = ChildLaunchCoordinatorV2(
            store=store,
            guard_factory=dependencies.guard_factory,
            launch_barrier=dependencies.launch_barrier,
            allowed_pairs=policy_bundle.policy_pairs,
            argv_domain=policy_bundle.child_argv_domain,
            environment_domain=policy_bundle.child_environment_domain,
            secret_domain=policy_bundle.child_secret_domain,
            activation_gate_provider=current_gate,
            fresh_permission_probe=permission_probe,
            fresh_snapshot_probe=preparer.fresh_snapshot_probe,
            fresh_process_probe=process_probe,
            expected_control_epoch=binding.control_epoch,
        )
        owner_id, pid, process_start_marker = _controller_worker_identity(binding)
        child_timeout_seconds, max_output_bytes = _child_limits(policy_bundle)
        execution = ChildExecutionV2(
            service=service,
            store=store,
            launch_coordinator=coordinator,
            launch_preparer=preparer,
            activation_gate_provider=current_gate,
            role_templates=tuple(policy_bundle.role_templates),
            owner_id=owner_id,
            pid=pid,
            process_start_marker=process_start_marker,
            child_timeout_seconds=child_timeout_seconds,
            max_output_bytes=max_output_bytes,
            launch_barrier=dependencies.launch_barrier,
        )
        return ExecutionDispatcherV2(
            store=store,
            execution=execution,
            max_workers=dependencies.max_workers,
            max_pending=dependencies.max_pending,
            error_sink=dependencies.error_sink,
        )

    return factory


def _closed_environment(value: Mapping[str, str]) -> dict[str, str]:
    try:
        environment = dict(value)
    except (TypeError, ValueError) as exc:
        raise ProductionDispatcherV2Error(
            "ENVIRONMENT_INVALID",
            str(exc),
        ) from exc
    if any(
        not isinstance(name, str)
        or not name
        or "=" in name
        or "\0" in name
        or not isinstance(item, str)
        or "\0" in item
        for name, item in environment.items()
    ):
        raise ProductionDispatcherV2Error(
            "ENVIRONMENT_INVALID",
            "среда должна быть отображением безопасных строк",
        )
    return environment


def _writer_publication_result_value(
    result: WriterPublicationResultV2,
) -> dict[str, Any]:
    validation = result.validation
    return {
        "contractVersion": "writer-publication-v2",
        "state": result.state,
        "validationState": result.validation_state,
        "errorCode": result.error_code,
        "artifactId": result.artifact_id,
        "ref": result.ref,
        "commitSha": result.commit_sha,
        "treeSha": result.tree_sha,
        "baseCommitSha": result.base_commit_sha,
        "refPublished": result.ref_published,
        "proofHash": result.proof_hash,
        "validation": [
            {
                "argv": list(command.catalog_argv),
                "exitCode": command.exit_code,
                "stdoutSha256": command.stdout_sha256,
                "stderrSha256": command.stderr_sha256,
            }
            for command in (validation.commands if validation is not None else ())
        ],
    }


def _configured_codex_home(environment: Mapping[str, str]) -> Path:
    raw = environment.get("CODEX_HOME")
    if not isinstance(raw, str) or not raw or not Path(raw).is_absolute():
        raise ProductionDispatcherV2Error(
            "CODEX_HOME_REQUIRED",
            "производственная фабрика требует абсолютный CODEX_HOME",
        )
    try:
        path = Path(raw).resolve(strict=True)
    except OSError as exc:
        raise ProductionDispatcherV2Error("CODEX_HOME_INVALID", str(exc)) from exc
    if path != Path(raw):
        raise ProductionDispatcherV2Error(
            "CODEX_HOME_INVALID",
            "CODEX_HOME должен быть каноническим путём",
        )
    _require_owned_directory(path, "CODEX_HOME_UNSAFE")
    return path


def _validated_schema_resolution(value: Mapping[str, str]) -> dict[str, str]:
    try:
        resolution = dict(value)
    except (TypeError, ValueError) as exc:
        raise ProductionDispatcherV2Error(
            "RESULT_SCHEMA_RESOLUTION_INVALID",
            str(exc),
        ) from exc
    if set(resolution) != {"virtualRoot", "repositoryRoot"} or any(
        not isinstance(item, str) or not item or "\0" in item
        for item in resolution.values()
    ):
        raise ProductionDispatcherV2Error(
            "RESULT_SCHEMA_RESOLUTION_INVALID",
            "разрешение должно быть закрытым объектом двух безопасных строк",
        )
    virtual_root = PurePosixPath(resolution["virtualRoot"])
    repository_root = PurePosixPath(resolution["repositoryRoot"])
    if (
        not virtual_root.is_absolute()
        or ".." in virtual_root.parts
        or repository_root.is_absolute()
        or repository_root in {PurePosixPath("."), PurePosixPath("")}
        or ".." in repository_root.parts
        or str(virtual_root) != resolution["virtualRoot"]
        or str(repository_root) != resolution["repositoryRoot"]
    ):
        raise ProductionDispatcherV2Error(
            "RESULT_SCHEMA_RESOLUTION_INVALID",
            "корни разрешения должны быть каноническими и не допускать выход",
        )
    return resolution


def _private_file_sha256(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise ProductionDispatcherV2Error(
            "RESULT_SCHEMA_UNSAFE",
            "схема должна быть абсолютным обычным файлом",
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProductionDispatcherV2Error(
            "RESULT_SCHEMA_UNSAFE",
            str(exc),
        ) from exc
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            or not 0 < metadata.st_size <= 1024 * 1024
        ):
            raise ProductionDispatcherV2Error(
                "RESULT_SCHEMA_UNSAFE",
                "схема должна быть частным ограниченным файлом",
            )
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise ProductionDispatcherV2Error(
                    "RESULT_SCHEMA_CHANGED",
                    "схема укоротилась во время чтения",
                )
            digest.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ProductionDispatcherV2Error(
                "RESULT_SCHEMA_CHANGED",
                "схема выросла во время чтения",
            )
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _codex_snapshot_contract(
    binding: GatewayRuntimeBindingV2,
) -> tuple[Path, str, str]:
    try:
        snapshot = binding.activation_identity["codexSnapshot"]
        subject = binding.interface_evidence["subject"]
        raw_path = snapshot["absolutePath"]
        snapshot_sha256 = snapshot["sha256"]
        subject_path = subject["snapshotPath"]
        subject_sha256 = subject["snapshotSha256"]
        raw_version = subject["version"]
    except (KeyError, TypeError) as exc:
        raise ProductionDispatcherV2Error(
            "CODEX_SNAPSHOT_CONTRACT_INVALID",
            str(exc),
        ) from exc
    if (
        not isinstance(raw_path, str)
        or not Path(raw_path).is_absolute()
        or raw_path != subject_path
        or not isinstance(snapshot_sha256, str)
        or _SHA256.fullmatch(snapshot_sha256) is None
        or snapshot_sha256 != subject_sha256
        or not isinstance(raw_version, str)
    ):
        raise ProductionDispatcherV2Error(
            "CODEX_SNAPSHOT_CONTRACT_INVALID",
            "активация и InterfaceEvidence описывают разные снимки Codex",
        )
    try:
        version = parse_codex_version(raw_version)
    except Exception as exc:
        raise ProductionDispatcherV2Error(
            "CODEX_VERSION_INVALID",
            str(exc),
        ) from exc
    return Path(raw_path), snapshot_sha256, version


def _policy_profiles(
    bundle: PolicyBundleV2,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, tuple[dict[str, Any], str]],
]:
    roles: dict[str, dict[str, Any]] = {}
    for raw in bundle.role_templates:
        template = dict(raw)
        try:
            template_id = template["templateId"]
            semantic_role = template["semanticRole"]
            execution_profile = template["executionProfile"]
        except KeyError as exc:
            raise ProductionDispatcherV2Error(
                "ROLE_TEMPLATE_INVALID",
                str(exc),
            ) from exc
        if (
            not all(
                isinstance(item, str) and item
                for item in (template_id, semantic_role, execution_profile)
            )
            or template_id in roles
        ):
            raise ProductionDispatcherV2Error(
                "ROLE_TEMPLATE_INVALID",
                "шаблоны ролей неоднозначны",
            )
        roles[template_id] = template
    profiles: dict[str, tuple[dict[str, Any], str]] = {}
    for raw in bundle.child_profiles:
        profile = dict(raw)
        role = profile.get("role")
        if type(role) is not str or role in profiles:
            raise ProductionDispatcherV2Error(
                "CHILD_PROFILE_INVALID",
                "дочерние профили неоднозначны",
            )
        fingerprint = bundle.child_profile_fingerprints.get(role)
        if not isinstance(fingerprint, str) or _SHA256.fullmatch(fingerprint) is None:
            raise ProductionDispatcherV2Error(
                "CHILD_PROFILE_INVALID",
                "профиль не связан с отпечатком политики",
            )
        profiles[role] = (profile, fingerprint)
    for template in roles.values():
        if template["executionProfile"] not in profiles:
            raise ProductionDispatcherV2Error(
                "ROLE_CHILD_PROFILE_MISMATCH",
                "шаблон роли не имеет дочернего профиля",
            )
    return roles, profiles


def _snapshot_limits(bundle: PolicyBundleV2) -> SnapshotLimits:
    try:
        return SnapshotLimits(
            max_files=bundle.catalog_limits["snapshot_max_files"],
            max_file_bytes=bundle.catalog_limits["snapshot_max_file_bytes"],
            max_total_bytes=bundle.catalog_limits["snapshot_max_total_bytes"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProductionDispatcherV2Error(
            "SNAPSHOT_LIMITS_INVALID",
            str(exc),
        ) from exc


def _child_limits(bundle: PolicyBundleV2) -> tuple[float, int]:
    try:
        timeout = bundle.catalog_limits["child_timeout_seconds"]
        maximum = bundle.catalog_limits["child_max_output_bytes"]
    except KeyError as exc:
        raise ProductionDispatcherV2Error(
            "CHILD_LIMITS_INVALID",
            str(exc),
        ) from exc
    if (
        type(timeout) is not int
        or not 0 < timeout <= 1800
        or type(maximum) is not int
        or not 1024 <= maximum <= 16 * 1024 * 1024
    ):
        raise ProductionDispatcherV2Error(
            "CHILD_LIMITS_INVALID",
            "пределы дочернего запуска выходят за допустимый диапазон",
        )
    return float(timeout), maximum


def _controller_worker_identity(
    binding: GatewayRuntimeBindingV2,
) -> tuple[str, int, str]:
    row = binding.controller_row
    try:
        owner_id = row["controller_identity"]
        pid = row["controller_pid"]
        marker = row["controller_process_start_marker"]
    except KeyError as exc:
        raise ProductionDispatcherV2Error(
            "CONTROLLER_IDENTITY_INVALID",
            str(exc),
        ) from exc
    if (
        not isinstance(owner_id, str)
        or not owner_id
        or len(owner_id.encode("utf-8")) > 256
        or any(character in owner_id for character in "\0\r\n")
        or type(pid) is not int
        or pid <= 0
        or not isinstance(marker, str)
        or not marker
        or len(marker.encode("utf-8")) > 256
        or any(character in marker for character in "\0\r\n")
    ):
        raise ProductionDispatcherV2Error(
            "CONTROLLER_IDENTITY_INVALID",
            "привязка контроллера не содержит допустимую личность работника",
        )
    return owner_id, pid, marker


def _prepare_attempts_root(state_home: Path) -> Path:
    _require_private_directory(state_home, "STATE_HOME_UNSAFE")
    target = state_home / "attempt-runtimes-v2"
    try:
        target.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise ProductionDispatcherV2Error(
            "ATTEMPTS_ROOT_UNAVAILABLE",
            str(exc),
        ) from exc
    _require_private_directory(target, "ATTEMPTS_ROOT_UNSAFE")
    try:
        leftovers = sorted(item.name for item in target.iterdir())
    except OSError as exc:
        raise ProductionDispatcherV2Error(
            "ATTEMPTS_ROOT_UNAVAILABLE",
            str(exc),
        ) from exc
    if leftovers:
        raise ProductionDispatcherV2Error(
            "ATTEMPT_RECOVERY_REQUIRED",
            "каталог содержит незарегистрированные остатки прошлой попытки",
        )
    return target


def _require_private_directory(path: Path, code: str) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ProductionDispatcherV2Error(
            code,
            "каталог должен быть абсолютным и не ссылкой",
        )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProductionDispatcherV2Error(code, str(exc)) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProductionDispatcherV2Error(
            code,
            "каталог должен быть частным и принадлежать текущему пользователю",
        )


def _require_owned_directory(path: Path, code: str) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ProductionDispatcherV2Error(
            code,
            "каталог должен быть абсолютным и не ссылкой",
        )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProductionDispatcherV2Error(code, str(exc)) from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or mode & 0o022
    ):
        raise ProductionDispatcherV2Error(
            code,
            "каталог должен принадлежать пользователю и запрещать чужую запись",
        )


def _remove_owned_attempt(path: Path, attempts_root: Path) -> None:
    attempt_id = path.name.removeprefix("attempt-")
    if path.parent != attempts_root or _ATTEMPT_ID.fullmatch(attempt_id) is None:
        raise ProductionDispatcherV2Error(
            "ATTEMPT_CLEANUP_PATH_MISMATCH",
            "путь не принадлежит каталогу попыток фабрики",
        )
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ProductionDispatcherV2Error(
            "ATTEMPT_CLEANUP_FAILED",
            str(exc),
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
    ):
        raise ProductionDispatcherV2Error(
            "ATTEMPT_CLEANUP_PATH_MISMATCH",
            "каталог попытки был подменён",
        )
    try:
        for current, directories, filenames in os.walk(
            path,
            topdown=False,
            followlinks=False,
        ):
            current_path = Path(current)
            current_path.chmod(0o700)
            for name in filenames:
                item = current_path / name
                item.unlink()
            for name in directories:
                item = current_path / name
                if item.is_symlink():
                    item.unlink()
                else:
                    item.chmod(0o700)
                    item.rmdir()
        path.chmod(0o700)
        path.rmdir()
    except OSError as exc:
        raise ProductionDispatcherV2Error(
            "ATTEMPT_CLEANUP_FAILED",
            str(exc),
        ) from exc


__all__ = [
    "ProductionDispatcherDependenciesV2",
    "ProductionDispatcherV2Error",
    "ProductionLaunchPreparerV2",
    "build_production_dispatcher_factory_v2",
]
