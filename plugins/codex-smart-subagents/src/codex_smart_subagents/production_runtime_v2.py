"""Сборка доказанного рабочего контура умного хода версии 2."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .account_evidence_executor_v2 import AppServerAccountEvidenceExecutorV2
from .activation_gateway_v2 import GatewayRuntimeBindingV2
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .mcp_server_v2 import MCPServerV2
from .policy_bundle_v2 import PolicyBundleV2, load_policy_bundle_v2
from .recovery_suite_v2 import RecoverySuiteV2
from .runtime_recovery_v2 import prepare_attempts_root_v2
from .smart_service_v2 import SmartServiceV2, SmartServiceV2Error
from .smart_turn_runtime_v2 import SmartTurnRuntimeV2
from .state_store_v2 import (
    AcceptingControllerV2,
    DatabaseIdentityV2,
    QueuedStartDispatchV2,
    RequestContextV2,
    SmartStoreV2,
)
from .resume_session_v2 import (
    ProjectIdentityV2,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    route_is_terminal_v2,
    system_process_marker_reader_v2,
)


_MAX_CATALOG_BYTES = 1024 * 1024


class ProductionRuntimeV2Error(RuntimeError):
    """Ошибка замыкания производственного контура версии 2."""


class ActivationProviderV2(Protocol):
    def request_context(self) -> RequestContextV2: ...

    def activation_gate(self) -> dict[str, Any]: ...

    def runtime_binding(self) -> GatewayRuntimeBindingV2: ...


class StartDispatcherV2(Protocol):
    def submit(
        self, start_request_id: str, request_context: RequestContextV2
    ) -> bool: ...

    def close(self) -> None: ...


DispatcherFactoryV2 = Callable[
    [
        SmartServiceV2,
        SmartStoreV2,
        ActivationProviderV2,
        PolicyBundleV2,
        GatewayRuntimeBindingV2,
        Mapping[str, str],
    ],
    StartDispatcherV2,
]


@dataclass
class ProductionRuntimeV2:
    provider: ActivationProviderV2
    binding: GatewayRuntimeBindingV2
    policy_bundle: PolicyBundleV2
    store: SmartStoreV2
    service: SmartServiceV2
    runtime: SmartTurnRuntimeV2
    server: MCPServerV2
    dispatcher: StartDispatcherV2 | None
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        cleanup_errors = _close_runtime_components_v2(
            dispatcher=self.dispatcher,
            store=self.store,
        )
        if cleanup_errors:
            primary = cleanup_errors[0]
            for secondary in cleanup_errors[1:]:
                primary.add_note(
                    "Дополнительная ошибка очистки: "
                    f"{type(secondary).__name__}: {secondary}"
                )
            raise primary


def build_production_runtime_v2(
    *,
    provider: ActivationProviderV2,
    environment: Mapping[str, str],
    dispatcher_factory: DispatcherFactoryV2 | None = None,
    account_evidence_executor: Any | None = None,
) -> ProductionRuntimeV2:
    """Собирает только компоненты, связанные одной свежей READY-привязкой."""

    binding = provider.runtime_binding()
    plugin_root = binding.marketplace_path / "plugins" / "codex-smart-subagents"
    config_root = plugin_root / "config"
    contract_root = config_root / "contracts"
    policy_bundle = load_policy_bundle_v2(
        catalog_path=config_root / "adaptive-subagents.toml",
        routing_vector_path=contract_root / "routing-policy-v2.json",
        delegation_vector_path=contract_root / "delegation-policy-v2.json",
        role_vector_path=contract_root / "role-template-v1.json",
        child_profile_vector_path=contract_root / "child-profile-v1.json",
    )
    bundled_catalog = _read_bundled_catalog(
        config_root / "bundled-catalog-v1.json",
        expected_fingerprint=str(
            binding.activation_identity["bundledCatalogFingerprint"]
        ),
    )
    database_identity = database_identity_from_binding_v2(binding)
    controller = accepting_controller_from_binding_v2(binding)
    resume_store: RootSessionLeaseStoreV2 | None = None
    resume_root: RootIdentityV2 | None = None
    launch_kind = environment.get("CODEX_SMART_LAUNCH_KIND")
    try:
        if launch_kind in {"startup", "resume"}:
            resume_root = RootIdentityV2(
                pid=int(environment["CODEX_SMART_ROOT_PID"]),
                process_start_marker=environment["CODEX_SMART_ROOT_START_MARKER"],
            )
            resume_store = RootSessionLeaseStoreV2(
                binding.state_home,
                process_marker_reader=system_process_marker_reader_v2,
            )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise ProductionRuntimeV2Error(
            "MANAGED_ROOT_IDENTITY_UNAVAILABLE"
        ) from exc

    def project_for_context(context: RequestContextV2) -> ProjectIdentityV2:
        return ProjectIdentityV2(
            repo_root=context.repo_root,
            base_sha=context.base_sha,
            worktree_fingerprint=context.worktree_fingerprint,
            compatibility_fingerprint=context.compatibility_fingerprint,
        )

    def authorize_resumed_route(
        route_id: str,
        current: RequestContextV2,
        original: RequestContextV2,
    ) -> bool:
        if resume_store is None or resume_root is None:
            return False
        lease = resume_store.load(current.session_id)
        attachment = None if lease is None else lease.attachment
        if (
            attachment is None
            or attachment.candidate.original_shell_session_id
            != original.shell_session_id
            or attachment.candidate.original_session_id != original.session_id
            or attachment.candidate.original_turn_id != original.turn_id
        ):
            return False
        return resume_store.authorize_route(
            route_id=route_id,
            session_id=current.session_id,
            shell_session_id=current.shell_session_id,
            turn_id=current.turn_id,
            root=resume_root,
            project=project_for_context(current),
        )

    store = SmartStoreV2(
        binding.database_path,
        database_identity=database_identity,
        controller=controller,
        resume_authorizer=(
            authorize_resumed_route if resume_store is not None else None
        ),
    )
    dispatcher: StartDispatcherV2 | None = None
    try:
        attempts_root = prepare_attempts_root_v2(binding.state_home)
        recovery = RecoverySuiteV2(
            store=store,
            attempts_root=attempts_root,
        ).run(apply=True)
        if not recovery.ok:
            raise ProductionRuntimeV2Error(
                "RUNTIME_RECOVERY_BLOCKED: " + ",".join(recovery.blockers)
            )
        home = _runtime_directory(
            environment.get("HOME", str(Path.home())),
            "HOME",
        )
        tmpdir = _runtime_directory(
            environment.get("TMPDIR", tempfile.gettempdir()),
            "TMPDIR",
        )

        def verify_activation_gate(value: Mapping[str, Any]) -> dict[str, Any]:
            fresh = provider.activation_gate()
            if type(value) is not dict or dict(value) != fresh:
                raise ProductionRuntimeV2Error("ACTIVATION_GATE_CHANGED")
            return fresh

        def verify_snapshot_subject(value: dict[str, Any]) -> None:
            fresh = provider.runtime_binding()
            expected = dict(fresh.interface_evidence["subject"])
            if value != expected:
                raise ProductionRuntimeV2Error("SNAPSHOT_SUBJECT_CHANGED")

        def live_control_epoch() -> int:
            fresh = provider.runtime_binding()
            if fresh != binding:
                raise ProductionRuntimeV2Error("ACTIVATION_BINDING_CHANGED")
            return fresh.control_epoch

        def guard_resumed_plan(context: RequestContextV2) -> None:
            if resume_store is None or resume_root is None:
                return
            lease = resume_store.load(context.session_id)
            if lease is None or lease.attachment is None:
                return
            attachment = lease.attachment
            if attachment.state == "ACKNOWLEDGED":
                return
            if not resume_store.authorize_route(
                route_id=attachment.candidate.route_id,
                session_id=context.session_id,
                shell_session_id=context.shell_session_id,
                turn_id=context.turn_id,
                root=resume_root,
                project=project_for_context(context),
            ):
                raise SmartServiceV2Error(
                    "RESUME_ATTACHMENT_CHANGED",
                    "присоединение умного маршрута изменилось",
                )
            if not route_is_terminal_v2(
                binding.database_path,
                attachment.candidate.route_id,
            ):
                raise SmartServiceV2Error(
                    "RESUME_ROUTE_PENDING",
                    "прежний маршрут должен завершиться до нового smart_plan",
                )

        service = SmartServiceV2(
            store=store,
            policy_bundle=policy_bundle,
            bundled_catalog_projection=bundled_catalog,
            activation_gate_verifier=verify_activation_gate,
            live_control_epoch_provider=live_control_epoch,
            interface_evidence=binding.interface_evidence,
            account_evidence_executor=(
                account_evidence_executor or AppServerAccountEvidenceExecutorV2()
            ),
            verify_snapshot_subject=verify_snapshot_subject,
            account_home=str(home),
            account_tmpdir=str(tmpdir),
            resume_plan_guard=guard_resumed_plan,
        )
        runtime = SmartTurnRuntimeV2(service=service, store=store)
        dispatcher = (
            dispatcher_factory(
                service,
                store,
                provider,
                policy_bundle,
                binding,
                environment,
            )
            if dispatcher_factory is not None
            else None
        )
        if dispatcher is not None:
            restore_queued_start_requests_v2(
                store=store,
                dispatcher=dispatcher,
                now=datetime.now(timezone.utc),
            )

        server = MCPServerV2(
            runtime=runtime,
            request_context_provider=provider.request_context,
            activation_gate_provider=provider.activation_gate,
            start_dispatcher=(dispatcher.submit if dispatcher is not None else None),
        )
        return ProductionRuntimeV2(
            provider=provider,
            binding=binding,
            policy_bundle=policy_bundle,
            store=store,
            service=service,
            runtime=runtime,
            server=server,
            dispatcher=dispatcher,
        )
    except BaseException as original_error:
        for cleanup_error in _close_runtime_components_v2(
            dispatcher=dispatcher,
            store=store,
        ):
            original_error.add_note(
                "Ошибка очистки после сбоя сборки: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
        raise


def _close_runtime_components_v2(
    *,
    dispatcher: StartDispatcherV2 | None,
    store: SmartStoreV2,
) -> tuple[BaseException, ...]:
    """Закрывает все построенные части и не прерывает каскад первой ошибкой."""

    errors: list[BaseException] = []
    if dispatcher is not None:
        try:
            dispatcher.close()
        except BaseException as error:
            errors.append(error)
    try:
        store.close()
    except BaseException as error:
        errors.append(error)
    return tuple(errors)


def restore_queued_start_requests_v2(
    *,
    store: Any,
    dispatcher: StartDispatcherV2,
    now: datetime,
) -> int:
    """Переподаёт ограниченную долговечную очередь до готовности сервера."""

    list_queued = getattr(store, "queued_start_dispatches", None)
    terminalize = getattr(store, "record_account_evidence_terminal", None)
    if not callable(list_queued) or not callable(terminalize):
        raise TypeError("store must provide durable queued-start operations")
    if not callable(getattr(dispatcher, "submit", None)):
        raise TypeError("dispatcher must provide submit()")
    current = _aware_utc(now)
    queued = list_queued()
    if type(queued) is not tuple or len(queued) > 32:
        raise ProductionRuntimeV2Error("DURABLE_START_QUEUE_INVALID")
    restored = 0
    seen: set[str] = set()
    for item in queued:
        if not isinstance(item, QueuedStartDispatchV2):
            raise ProductionRuntimeV2Error("DURABLE_START_QUEUE_INVALID")
        if item.start_request_id in seen:
            raise ProductionRuntimeV2Error("DURABLE_START_QUEUE_CONFLICT")
        seen.add(item.start_request_id)
        if item.deadline_at <= current:
            terminalize(
                item.evidence_job_id,
                item.request_context,
                state="FAILED",
                failure_code="REQUEST_DEADLINE_EXCEEDED",
                problem={
                    "category": "UNAVAILABLE",
                    "code": "REQUEST_DEADLINE_EXCEEDED",
                    "message": "Истёк общий срок запуска дочерней задачи.",
                    "retryable": True,
                },
                now=current,
            )
            continue
        submitted = dispatcher.submit(
            item.start_request_id,
            item.request_context,
        )
        if submitted is not False:
            restored += 1
    return restored


def database_identity_from_binding_v2(
    binding: GatewayRuntimeBindingV2,
) -> DatabaseIdentityV2:
    row = binding.database_identity_row
    try:
        return DatabaseIdentityV2(
            database_id=str(row["database_id"]),
            activation_binding_nonce=str(row["activation_binding_nonce"]),
            activation_id=str(row["activation_id"]),
            activation_fingerprint=str(row["activation_fingerprint"]),
            created_operation_id=str(row["created_operation_id"]),
            created_at=_parse_time(row["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProductionRuntimeV2Error("неверная привязка идентичности базы") from exc


def accepting_controller_from_binding_v2(
    binding: GatewayRuntimeBindingV2,
) -> AcceptingControllerV2:
    row = binding.controller_row
    try:
        return AcceptingControllerV2(
            controller_identity=str(row["controller_identity"]),
            instance_id=str(row["instance_id"]),
            controller_start_id=str(row["controller_start_id"]),
            controller_pid=int(row["controller_pid"]),
            controller_process_start_marker=str(row["controller_process_start_marker"]),
            controller_process_group_id=int(row["controller_process_group_id"]),
            control_epoch=int(row["control_epoch"]),
            activation_id=str(row["activation_id"]),
            activation_fingerprint=str(row["activation_fingerprint"]),
            compatibility_fingerprint=str(row["compatibility_fingerprint"]),
            routing_policy_fingerprint=str(row["routing_policy_fingerprint"]),
            bundled_catalog_fingerprint=str(row["bundled_catalog_fingerprint"]),
            socket_path=str(row["socket_path"]),
            socket_device=int(row["socket_device"]),
            socket_inode=int(row["socket_inode"]),
            socket_owner_uid=int(row["socket_owner_uid"]),
            socket_owner_gid=int(row["socket_owner_gid"]),
            socket_mode=str(row["socket_mode"]),
            updated_at=_parse_time(row["updated_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProductionRuntimeV2Error("неверная привязка живого контроллера") from exc


def _read_bundled_catalog(
    path: Path,
    *,
    expected_fingerprint: str,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > _MAX_CATALOG_BYTES:
            raise ValueError("неверный размер")
        value = json.loads(raw.decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProductionRuntimeV2Error("встроенный каталог недоступен") from exc
    if type(value) is not dict or raw != canonical_json_bytes(value):
        raise ProductionRuntimeV2Error("встроенный каталог неканоничен")
    observed = domain_fingerprint("codex-smart/bundled-catalog/v1", value)
    if observed != expected_fingerprint:
        raise ProductionRuntimeV2Error("отпечаток встроенного каталога не совпал")
    return value


def _runtime_directory(raw: str, name: str) -> Path:
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise ProductionRuntimeV2Error(f"{name} не задан")
    path = Path(raw)
    if not path.is_absolute():
        raise ProductionRuntimeV2Error(f"{name} не является абсолютным путём")
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise ProductionRuntimeV2Error(f"{name} недоступен") from exc
    if canonical != path or not canonical.is_dir():
        raise ProductionRuntimeV2Error(f"{name} не является каноническим каталогом")
    return canonical


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("time is not a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("time has no offset")
    return parsed.astimezone(timezone.utc)


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("time must include an offset")
    return value.astimezone(timezone.utc)


__all__ = [
    "ProductionRuntimeV2",
    "ProductionRuntimeV2Error",
    "accepting_controller_from_binding_v2",
    "build_production_runtime_v2",
    "database_identity_from_binding_v2",
    "restore_queued_start_requests_v2",
]
