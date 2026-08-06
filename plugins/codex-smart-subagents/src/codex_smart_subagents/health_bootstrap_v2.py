"""Ограниченный двухфазный запуск контроллера здоровья версии 2.

Этот слой доказывает только настоящий метод ``health`` и поэтому возвращает
явное состояние ``HEALTH_ONLY_READY``. Он не изображает планирование, запуск
субагентов или команды управления полноценного контроллера.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import sqlite3
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from .activation_gateway_v2 import (
    ActivationResolver,
    GatewayDecision,
    GatewayLayout,
    GatewayRuntimeBindingV2,
    GatewayState,
    _unix_controller_probe,
)
from .activation_materializer_v2 import (
    ActivationFinalizationV2,
    ActivationMaterializationV2,
    StagedActivationV2,
    activate_materialized_v2,
    discard_staged_activation_v2,
    finalize_staged_activation_v2,
    normalize_state_home_v2,
    stage_activation_identity_v2,
)
from .canonical_json import domain_fingerprint
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .codex_binary_snapshot import SnapshotCommandExecutor
from .controller_health_v2 import (
    ControllerHealthServerV2,
    ControllerRegistrationReceiptV2,
)
from .coordinator_selection_v2 import (
    CoordinatorSelectionRefreshLoopV2,
    inspect_coordinator_selection_v2,
)
from .model_catalog import AppServerModelCatalogInspector
from .policy_bundle_v2 import PolicyBundleV2
from .installer_upgrade_v2 import (
    build_initial_activation_preparation_v2,
    execute_initial_activation_preparation_v2,
)
from .schema_projection import APPLICATION_ID
from .state_store_v2 import _QUIESCENCE_QUERIES, AcceptingControllerV2


@dataclass
class HealthBootstrapV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class HealthBootstrapRuntimeV2:
    """Живой владеющий handle либо read-only наблюдение чужого процесса."""

    def __init__(
        self,
        *,
        gateway_decision: GatewayDecision,
        owns_runtime: bool,
        request_fingerprint: str | None = None,
        materialization: ActivationMaterializationV2 | None = None,
        controller: AcceptingControllerV2 | None = None,
        server: ControllerHealthServerV2 | None = None,
        thread: threading.Thread | None = None,
        catalog_refresh: CoordinatorSelectionRefreshLoopV2 | None = None,
        registry_key: str | None = None,
    ) -> None:
        if gateway_decision.state is not GatewayState.READY:
            raise ValueError("health bootstrap runtime requires READY gateway")
        if owns_runtime and (
            materialization is None
            or controller is None
            or server is None
            or thread is None
            or registry_key is None
            or request_fingerprint is None
        ):
            raise ValueError("owner runtime requires complete local ownership")
        self.readiness = "HEALTH_ONLY_READY"
        self.gateway_decision = gateway_decision
        self.owns_runtime = owns_runtime
        self.request_fingerprint = request_fingerprint
        self.materialization = materialization
        self.controller = controller
        self._server = server
        self._thread = thread
        self._catalog_refresh = catalog_refresh
        self._registry_key = registry_key
        self._close_lock = threading.Lock()
        self._closed = False

    @property
    def thread_alive(self) -> bool:
        return bool(self._thread is not None and self._thread.is_alive())

    @property
    def catalog_refresh_alive(self) -> bool:
        return bool(
            self._catalog_refresh is not None
            and self._catalog_refresh.thread_alive
        )

    def bind_lifecycle_handler(
        self,
        handler: Callable[[Mapping[str, object]], Mapping[str, object]],
        *,
        response_observer: Callable[[Mapping[str, object], Mapping[str, object]], None]
        | None = None,
    ) -> None:
        """Подключает управляющий протокол только к локально занятому сокету."""

        if not self.owns_runtime or self._server is None:
            raise HealthBootstrapV2Error(
                "CONTROLLER_OWNERSHIP_REQUIRED",
                "чужое наблюдение не может подключить управляющий протокол",
            )
        self._server.bind_lifecycle_handler(
            handler,
            response_observer=response_observer,
        )

    def close(self) -> None:
        """Освобождает только runtime-владение, сохраняя принятую активацию."""

        if not self.owns_runtime:
            return
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            error: BaseException | None = None
            try:
                if self._catalog_refresh is not None:
                    try:
                        self._catalog_refresh.close()
                    except BaseException as exc:
                        error = exc
                try:
                    assert self._server is not None
                    self._server.close()
                except BaseException as exc:
                    if error is None:
                        error = exc
            finally:
                if self._thread is not None:
                    self._thread.join(timeout=2.0)
                _unregister_owner(self)
            if self.thread_alive:
                raise HealthBootstrapV2Error(
                    "HEALTH_THREAD_DID_NOT_STOP",
                    "поток health-сервера не завершился после close",
                )
            if error is not None:
                raise error


_OWNER_LOCK = threading.RLock()
_OWNER_RUNTIMES: dict[str, HealthBootstrapRuntimeV2] = {}


@dataclass(frozen=True)
class _RecoveryRegistrationV2:
    database_path: Path
    database_identity: Mapping[str, object]
    previous_controller: Mapping[str, object]
    recovered_controller: Mapping[str, object]

    def cleanup(self) -> None:
        """Успешный runtime сохраняет новую привязку для следующего запуска."""

    def rollback(self) -> None:
        _restore_controller_row_v2(
            database_path=self.database_path,
            expected_database_identity=self.database_identity,
            expected_current=self.recovered_controller,
            replacement=self.previous_controller,
        )


def bootstrap_health_activation_v2(
    *,
    source_root: Path,
    codex_home: Path,
    state_home: Path,
    codex_binary: Path,
    wrapper: Path,
    policy_bundle: PolicyBundleV2,
    snapshotter=None,
    interface_executor: SnapshotCommandExecutor | None = None,
    snapshot_verifier: Callable[[object], None],
    completed_at: datetime | None = None,
    control_epoch: int = 1,
    first_install_operation_id: str | None = None,
    first_installation_id: str | None = None,
    coordinator_inspector_factory: Callable[..., object] = (
        AppServerModelCatalogInspector
    ),
) -> HealthBootstrapRuntimeV2:
    """Выполняет stage → bind/register → serve → настоящий gateway READY."""

    source_root = source_root.expanduser().resolve()
    codex_home = codex_home.expanduser().absolute()
    state_home = normalize_state_home_v2(state_home)
    codex_binary = codex_binary.expanduser().absolute()
    wrapper = wrapper.expanduser().absolute()
    if (first_install_operation_id is None) != (first_installation_id is None):
        raise HealthBootstrapV2Error(
            "FIRST_INSTALL_IDENTITY_INVALID",
            "идентификаторы первой установки должны передаваться вместе",
        )
    if first_install_operation_id is not None and (
        len(first_install_operation_id) != len("op2_") + 32
        or not first_install_operation_id.startswith("op2_")
        or any(
            character not in "0123456789abcdef"
            for character in first_install_operation_id[4:]
        )
        or len(first_installation_id or "") != len("ins2_") + 32
        or not (first_installation_id or "").startswith("ins2_")
        or any(
            character not in "0123456789abcdef"
            for character in (first_installation_id or "")[5:]
        )
    ):
        raise HealthBootstrapV2Error(
            "FIRST_INSTALL_IDENTITY_INVALID",
            "идентификаторы первой установки имеют неверный формат",
        )
    registry_key = str(codex_home.resolve())
    request_fingerprint = _bootstrap_request_fingerprint(
        source_root=source_root,
        codex_home=codex_home,
        state_home=state_home,
        codex_binary=codex_binary,
        wrapper=wrapper,
        policy_bundle=policy_bundle,
        control_epoch=control_epoch,
        first_install_operation_id=first_install_operation_id,
        first_installation_id=first_installation_id,
    )

    with _OWNER_LOCK:
        existing = _OWNER_RUNTIMES.get(registry_key)
        if existing is not None:
            if existing.thread_alive:
                if existing.request_fingerprint != request_fingerprint:
                    raise HealthBootstrapV2Error(
                        "OWNER_CONFIGURATION_CONFLICT",
                        "живой владелец запущен с другим смыслом конфигурации",
                    )
                return existing
            _OWNER_RUNTIMES.pop(registry_key, None)

        layout = GatewayLayout.for_codex_home(codex_home)
        incomplete_initial_finalization = bool(
            first_install_operation_id is not None
            and layout.manifest_path.exists()
            and not (
                layout.marketplace_link.exists()
                or layout.marketplace_link.is_symlink()
            )
        )
        if (
            layout.manifest_path.exists()
            or layout.marketplace_link.exists()
            or layout.marketplace_link.is_symlink()
        ) and not incomplete_initial_finalization:
            observed = ActivationResolver(
                layout=layout,
                wrapper=wrapper,
                snapshot_verifier=snapshot_verifier,
                controller_probe=_unix_controller_probe,
            ).resolve()
            if observed.state is GatewayState.READY:
                binding = observed.runtime_binding
                if binding is None or binding.state_home != state_home:
                    raise HealthBootstrapV2Error(
                        "RECOVERY_CONFIGURATION_CONFLICT",
                        "state_home отличается от принятой активации",
                    )
                return HealthBootstrapRuntimeV2(
                    gateway_decision=observed,
                    owns_runtime=False,
                )
            return _recover_persisted_activation_v2(
                layout=layout,
                codex_binary=codex_binary,
                state_home=state_home,
                wrapper=wrapper,
                policy_bundle=policy_bundle,
                snapshot_verifier=snapshot_verifier,
                request_fingerprint=request_fingerprint,
                registry_key=registry_key,
                coordinator_inspector_factory=coordinator_inspector_factory,
            )

        staged: StagedActivationV2 | None = None
        finalization: ActivationFinalizationV2 | None = None
        server: ControllerHealthServerV2 | None = None
        thread: threading.Thread | None = None
        catalog_refresh: CoordinatorSelectionRefreshLoopV2 | None = None
        initial_registration: _RecoveryRegistrationV2 | None = None
        initial_database: tuple[
            dict[str, object], dict[str, object]
        ] | None = None
        try:
            if first_install_operation_id is None:
                staged = stage_activation_identity_v2(
                    source_root=source_root,
                    codex_home=codex_home,
                    state_home=state_home,
                    codex_binary=codex_binary,
                    policy_bundle=policy_bundle,
                    snapshotter=snapshotter,
                    interface_executor=interface_executor,
                    completed_at=completed_at,
                )
            else:
                assert first_installation_id is not None
                staged = execute_initial_activation_preparation_v2(
                    build_initial_activation_preparation_v2(
                        source_root=source_root,
                        codex_home=codex_home,
                        state_home=state_home,
                        codex_binary=codex_binary,
                        policy_bundle=policy_bundle,
                        installation_id=first_installation_id,
                        operation_id=first_install_operation_id,
                        snapshotter=snapshotter,
                        interface_executor=interface_executor,
                        completed_at=completed_at,
                    )
                )

            initial_database = (
                None
                if first_install_operation_id is None
                else _inspect_initial_finalization_database_v2(staged)
            )
            coordinator_selection = inspect_coordinator_selection_v2(
                codex_executable=staged.snapshot_path,
                codex_home=staged.codex_home,
                runtime_parent=staged.state_home,
                selection=policy_bundle.coordinator_selection,
                candidates=policy_bundle.coordinator_candidates,
                active_context_fingerprint=staged.activation_fingerprint,
                inspector_factory=coordinator_inspector_factory,
                timeout_seconds=1.0,
            )

            def registrar(
                accepting_controller: AcceptingControllerV2,
            ) -> ControllerRegistrationReceiptV2:
                nonlocal finalization, initial_registration
                if initial_database is not None:
                    database_identity, previous_controller = initial_database
                    initial_registration = _replace_initial_controller_row_v2(
                        staged=staged,
                        controller=accepting_controller,
                        database_identity=database_identity,
                        previous_controller=previous_controller,
                    )
                finalization = finalize_staged_activation_v2(
                    staged=staged,
                    controller=accepting_controller,
                    coordinator_selection=coordinator_selection,
                    allow_initialized_database_recovery=(
                        initial_database is not None
                    ),
                )
                return ControllerRegistrationReceiptV2(
                    database_path=finalization.database_path,
                    cleanup=finalization.cleanup,
                )

            clock = (lambda: completed_at) if completed_at is not None else None
            server = ControllerHealthServerV2(
                socket_path=staged.socket_path,
                lock_path=staged.controller_lock_path,
                codex_home=staged.codex_home,
                state_home=staged.state_home,
                database_id=staged.database_id,
                activation_id=staged.activation_id,
                activation_fingerprint=staged.activation_fingerprint,
                compatibility_fingerprint=staged.compatibility_fingerprint,
                routing_policy_fingerprint=staged.routing_policy_fingerprint,
                bundled_catalog_fingerprint=staged.bundled_catalog_fingerprint,
                coordinator_selection=coordinator_selection,
                instance_id="ci2_" + secrets.token_hex(16),
                controller_start_id="cs2_" + secrets.token_hex(16),
                control_epoch=(
                    control_epoch
                    if initial_database is None
                    else int(initial_database[1]["control_epoch"]) + 1
                ),
                registrar=registrar,
                clock=clock,
            )
            controller = server.start()
            if finalization is None:
                raise HealthBootstrapV2Error(
                    "REGISTRATION_MISSING",
                    "health-сервер не вернул результат регистратора",
                )
            thread = threading.Thread(
                target=server.serve_forever,
                name=(
                    "codex-smart-health-bootstrap-v2-"
                    + staged.activation_id.removeprefix("act2_")[:12]
                ),
                daemon=True,
            )
            thread.start()
            decision = activate_materialized_v2(
                materialization=finalization.materialization,
                wrapper=wrapper,
                snapshot_verifier=snapshot_verifier,
                controller_probe=_unix_controller_probe,
            )
            catalog_refresh = _start_catalog_refresh_v2(
                initial_selection=coordinator_selection,
                server=server,
                codex_executable=staged.snapshot_path,
                codex_home=staged.codex_home,
                runtime_parent=staged.state_home,
                policy_bundle=policy_bundle,
                active_context_fingerprint=staged.activation_fingerprint,
                inspector_factory=coordinator_inspector_factory,
            )
            runtime = HealthBootstrapRuntimeV2(
                gateway_decision=decision,
                owns_runtime=True,
                request_fingerprint=request_fingerprint,
                materialization=finalization.materialization,
                controller=controller,
                server=server,
                thread=thread,
                catalog_refresh=catalog_refresh,
                registry_key=registry_key,
            )
            _OWNER_RUNTIMES[registry_key] = runtime
            return runtime
        except BaseException as primary_error:
            cleanup_errors: list[str] = []
            if catalog_refresh is not None:
                try:
                    catalog_refresh.close()
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"catalog refresh close: {cleanup_error}")
            if server is not None:
                try:
                    server.close()
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"server close: {cleanup_error}")
                try:
                    server.discard_created_lock()
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"controller lock discard: {cleanup_error}")
            elif finalization is not None:
                try:
                    finalization.cleanup()
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"registration close: {cleanup_error}")
            if thread is not None:
                thread.join(timeout=2.0)
                if thread.is_alive():
                    cleanup_errors.append("health thread is still alive")
            if (
                initial_registration is not None
                and initial_registration.database_path.exists()
            ):
                try:
                    initial_registration.rollback()
                except BaseException as cleanup_error:
                    cleanup_errors.append(
                        f"initial database rollback: {cleanup_error}"
                    )
            if staged is not None and initial_database is None:
                try:
                    discard_staged_activation_v2(
                        staged,
                        finalization=finalization,
                    )
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"candidate discard: {cleanup_error}")
            if cleanup_errors:
                raise HealthBootstrapV2Error(
                    "BOOTSTRAP_ROLLBACK_FAILED",
                    "; ".join(cleanup_errors),
                ) from primary_error
            raise


def _start_catalog_refresh_v2(
    *,
    initial_selection,
    server: ControllerHealthServerV2,
    codex_executable: Path,
    codex_home: Path,
    runtime_parent: Path,
    policy_bundle: PolicyBundleV2,
    active_context_fingerprint: str,
    inspector_factory: Callable[..., object],
) -> CoordinatorSelectionRefreshLoopV2:
    def probe(timeout_seconds: float):
        return inspect_coordinator_selection_v2(
            codex_executable=codex_executable,
            codex_home=codex_home,
            runtime_parent=runtime_parent,
            selection=policy_bundle.coordinator_selection,
            candidates=policy_bundle.coordinator_candidates,
            active_context_fingerprint=active_context_fingerprint,
            inspector_factory=inspector_factory,
            timeout_seconds=timeout_seconds,
        )

    refresh = CoordinatorSelectionRefreshLoopV2(
        initial_selection=initial_selection,
        probe=probe,
        publish=server.publish_coordinator_selection,
    )
    refresh.start()
    return refresh


def _inspect_initial_finalization_database_v2(
    staged: StagedActivationV2,
) -> tuple[dict[str, object], dict[str, object]] | None:
    """Доказать точную базу, пережившую остановку после preparation receipt."""

    info = _private_database_file_v2(staged.database_path)
    if info.st_size == 0:
        return None
    connection = sqlite3.connect(
        f"file:{staged.database_path}?mode=ro",
        uri=True,
        timeout=1.0,
    )
    connection.row_factory = sqlite3.Row
    try:
        if int(connection.execute("pragma application_id").fetchone()[0]) != APPLICATION_ID:
            raise HealthBootstrapV2Error(
                "INITIAL_FINALIZATION_DATABASE_INVALID",
                "application_id незавершённой первой базы изменён",
            )
        if int(connection.execute("pragma user_version").fetchone()[0]) != 2:
            raise HealthBootstrapV2Error(
                "INITIAL_FINALIZATION_DATABASE_INVALID",
                "user_version незавершённой первой базы изменён",
            )
        identity_rows = connection.execute(
            "select * from database_identity"
        ).fetchall()
        controller_rows = connection.execute(
            "select * from controller_state"
        ).fetchall()
    finally:
        connection.close()
    if len(identity_rows) != 1 or len(controller_rows) != 1:
        raise HealthBootstrapV2Error(
            "INITIAL_FINALIZATION_DATABASE_INVALID",
            "singleton-строки незавершённой первой базы отсутствуют",
        )
    identity = dict(identity_rows[0])
    expected_identity = {
        "singleton": 1,
        "database_id": staged.database_id,
        "schema_version": 2,
        "schema_fingerprint": staged.schema_fingerprint,
        "schema_artifact_sha256": staged.schema_artifact_sha256,
        "activation_binding_nonce": staged.activation_binding_nonce,
        "activation_id": staged.activation_id,
        "activation_fingerprint": staged.activation_fingerprint,
        "source_shape": "fresh-v2",
        "source_schema_fingerprint": None,
        "source_backup_sha256": None,
        "created_operation_id": staged.operation_id,
        "created_at": _iso(staged.completed_at),
    }
    if identity != expected_identity:
        raise HealthBootstrapV2Error(
            "INITIAL_FINALIZATION_DATABASE_CHANGED",
            "database_identity не совпадает с preparation receipt",
        )
    controller = dict(controller_rows[0])
    expected_immutable = {
        "database_id": staged.database_id,
        "controller_identity": staged.controller_identity,
        "activation_id": staged.activation_id,
        "activation_fingerprint": staged.activation_fingerprint,
        "compatibility_fingerprint": staged.compatibility_fingerprint,
        "routing_policy_fingerprint": staged.routing_policy_fingerprint,
        "bundled_catalog_fingerprint": staged.bundled_catalog_fingerprint,
    }
    if any(controller.get(name) != value for name, value in expected_immutable.items()):
        raise HealthBootstrapV2Error(
            "INITIAL_FINALIZATION_DATABASE_CHANGED",
            "controller_state не совпадает с preparation receipt",
        )
    epoch = controller.get("control_epoch")
    if type(epoch) is not int or epoch < 1 or epoch >= 9_007_199_254_740_991:
        raise HealthBootstrapV2Error(
            "CONTROL_EPOCH_EXHAUSTED",
            "эпоха незавершённого первого контроллера недопустима",
        )
    _assert_previous_controller_dead_v2(controller)
    return identity, controller


def _replace_initial_controller_row_v2(
    *,
    staged: StagedActivationV2,
    controller: AcceptingControllerV2,
    database_identity: Mapping[str, object],
    previous_controller: Mapping[str, object],
) -> _RecoveryRegistrationV2:
    expected_immutable = {
        "database_id": staged.database_id,
        "controller_identity": staged.controller_identity,
        "activation_id": staged.activation_id,
        "activation_fingerprint": staged.activation_fingerprint,
        "compatibility_fingerprint": staged.compatibility_fingerprint,
        "routing_policy_fingerprint": staged.routing_policy_fingerprint,
        "bundled_catalog_fingerprint": staged.bundled_catalog_fingerprint,
    }
    observed_immutable = {
        "database_id": staged.database_id,
        "controller_identity": controller.controller_identity,
        "activation_id": controller.activation_id,
        "activation_fingerprint": controller.activation_fingerprint,
        "compatibility_fingerprint": controller.compatibility_fingerprint,
        "routing_policy_fingerprint": controller.routing_policy_fingerprint,
        "bundled_catalog_fingerprint": controller.bundled_catalog_fingerprint,
    }
    previous_epoch = previous_controller.get("control_epoch")
    if observed_immutable != expected_immutable:
        raise HealthBootstrapV2Error(
            "RECOVERY_BINDING_MISMATCH",
            "новый контроллер меняет preparation identity",
        )
    if type(previous_epoch) is not int or controller.control_epoch != previous_epoch + 1:
        raise HealthBootstrapV2Error(
            "CONTROL_EPOCH_MISMATCH",
            "восстановление первой финализации обязано повысить controlEpoch",
        )
    recovered = copy.deepcopy(dict(previous_controller))
    recovered.update(
        {
            "instance_id": controller.instance_id,
            "controller_start_id": controller.controller_start_id,
            "controller_pid": controller.controller_pid,
            "controller_process_start_marker": (
                controller.controller_process_start_marker
            ),
            "controller_process_group_id": controller.controller_process_group_id,
            "control_epoch": controller.control_epoch,
            "state": "ACCEPTING",
            "maintenance_mode": "NONE",
            "reason_code": "NONE",
            "operation_id": None,
            "socket_path": controller.socket_path,
            "socket_device": controller.socket_device,
            "socket_inode": controller.socket_inode,
            "socket_owner_uid": controller.socket_owner_uid,
            "socket_owner_gid": controller.socket_owner_gid,
            "socket_mode": controller.socket_mode,
            "lock_held": 1,
            "accepting_new_routes": 1,
            "quiescent": 0,
            "updated_at": _iso(controller.updated_at),
        }
    )
    _replace_exact_controller_row_v2(
        database_path=staged.database_path,
        expected_database_identity=database_identity,
        expected_current=previous_controller,
        replacement=recovered,
        require_previous_dead=True,
    )
    return _RecoveryRegistrationV2(
        database_path=staged.database_path,
        database_identity=copy.deepcopy(dict(database_identity)),
        previous_controller=copy.deepcopy(dict(previous_controller)),
        recovered_controller=recovered,
    )


def _recover_persisted_activation_v2(
    *,
    layout: GatewayLayout,
    codex_binary: Path,
    state_home: Path,
    wrapper: Path,
    policy_bundle: PolicyBundleV2,
    snapshot_verifier: Callable[[object], None],
    request_fingerprint: str,
    registry_key: str,
    coordinator_inspector_factory: Callable[..., object],
) -> HealthBootstrapRuntimeV2:
    resolver = ActivationResolver(
        layout=layout,
        wrapper=wrapper,
        snapshot_verifier=snapshot_verifier,
        controller_probe=_unix_controller_probe,
    )
    try:
        persisted = resolver.resolve_persisted_activation()
    except Exception as exc:
        raise HealthBootstrapV2Error(
            "PERSISTED_ACTIVATION_INVALID",
            f"статическое доказательство активации не прошло: {exc}",
        ) from exc
    binding = persisted.runtime_binding
    if binding is None:
        raise HealthBootstrapV2Error(
            "PERSISTED_ACTIVATION_INVALID",
            "статическое доказательство не вернуло runtime binding",
        )
    if binding.state_home != state_home:
        raise HealthBootstrapV2Error(
            "RECOVERY_CONFIGURATION_CONFLICT",
            "state_home отличается от принятой активации",
        )
    if persisted.executable.expanduser().absolute() != codex_binary:
        raise HealthBootstrapV2Error(
            "RECOVERY_CONFIGURATION_CONFLICT",
            "переданный Codex отличается от источника принятой активации",
        )
    if (
        binding.activation_identity.get("routingPolicyFingerprint")
        != policy_bundle.router.policy_fingerprint
    ):
        raise HealthBootstrapV2Error(
            "RECOVERY_CONFIGURATION_CONFLICT",
            "политика маршрутизации отличается от принятой активации",
        )

    previous_controller = dict(binding.controller_row)
    _assert_previous_controller_dead_v2(previous_controller)
    previous_epoch = previous_controller.get("control_epoch")
    if (
        type(previous_epoch) is not int
        or previous_epoch < 1
        or previous_epoch >= 9_007_199_254_740_991
    ):
        raise HealthBootstrapV2Error(
            "CONTROL_EPOCH_EXHAUSTED",
            "предыдущая эпоха не допускает безопасного повышения",
        )

    registration: _RecoveryRegistrationV2 | None = None
    server: ControllerHealthServerV2 | None = None
    thread: threading.Thread | None = None
    catalog_refresh: CoordinatorSelectionRefreshLoopV2 | None = None
    try:
        coordinator_selection = inspect_coordinator_selection_v2(
            codex_executable=Path(
                str(binding.activation_identity["codexSnapshot"]["absolutePath"])
            ),
            codex_home=layout.codex_home,
            runtime_parent=binding.state_home,
            selection=policy_bundle.coordinator_selection,
            candidates=policy_bundle.coordinator_candidates,
            active_context_fingerprint=binding.activation_fingerprint,
            inspector_factory=coordinator_inspector_factory,
            timeout_seconds=1.0,
        )

        def registrar(
            accepting_controller: AcceptingControllerV2,
        ) -> ControllerRegistrationReceiptV2:
            nonlocal registration
            registration = _replace_controller_row_v2(
                binding=binding,
                controller=accepting_controller,
            )
            return ControllerRegistrationReceiptV2(
                database_path=registration.database_path,
                cleanup=registration.cleanup,
            )

        database_id = str(binding.database_identity_row["database_id"])
        server = ControllerHealthServerV2(
            socket_path=binding.state_home / "controller.sock",
            lock_path=binding.state_home / "controller.lock",
            codex_home=layout.codex_home,
            state_home=binding.state_home,
            database_id=database_id,
            activation_id=binding.activation_id,
            activation_fingerprint=binding.activation_fingerprint,
            compatibility_fingerprint=binding.compatibility_fingerprint,
            routing_policy_fingerprint=str(
                binding.activation_identity["routingPolicyFingerprint"]
            ),
            bundled_catalog_fingerprint=str(
                binding.activation_identity["bundledCatalogFingerprint"]
            ),
            coordinator_selection=coordinator_selection,
            instance_id="ci2_" + secrets.token_hex(16),
            controller_start_id="cs2_" + secrets.token_hex(16),
            control_epoch=previous_epoch + 1,
            registrar=registrar,
        )
        controller = server.start()
        if registration is None:
            raise HealthBootstrapV2Error(
                "RECOVERY_REGISTRATION_MISSING",
                "health-сервер не зарегистрировал восстановленный контроллер",
            )
        thread = threading.Thread(
            target=server.serve_forever,
            name=(
                "codex-smart-health-bootstrap-v2-"
                + binding.activation_id.removeprefix("act2_")[:12]
            ),
            daemon=True,
        )
        thread.start()
        decision = ActivationResolver(
            layout=layout,
            wrapper=wrapper,
            snapshot_verifier=snapshot_verifier,
            controller_probe=_unix_controller_probe,
        ).resolve()
        if decision.state is not GatewayState.READY:
            raise HealthBootstrapV2Error(
                "RECOVERY_HEALTH_NOT_READY",
                f"восстановленный контроллер отклонён: {decision.reason_code}",
            )
        materialization = _recovered_materialization_v2(
            layout=layout,
            decision=decision,
            controller=controller,
        )
        catalog_refresh = _start_catalog_refresh_v2(
            initial_selection=coordinator_selection,
            server=server,
            codex_executable=Path(
                str(binding.activation_identity["codexSnapshot"]["absolutePath"])
            ),
            codex_home=layout.codex_home,
            runtime_parent=binding.state_home,
            policy_bundle=policy_bundle,
            active_context_fingerprint=binding.activation_fingerprint,
            inspector_factory=coordinator_inspector_factory,
        )
        runtime = HealthBootstrapRuntimeV2(
            gateway_decision=decision,
            owns_runtime=True,
            request_fingerprint=request_fingerprint,
            materialization=materialization,
            controller=controller,
            server=server,
            thread=thread,
            catalog_refresh=catalog_refresh,
            registry_key=registry_key,
        )
        _OWNER_RUNTIMES[registry_key] = runtime
        return runtime
    except BaseException as exc:
        cleanup_errors: list[str] = []
        if catalog_refresh is not None:
            try:
                catalog_refresh.close()
            except BaseException as cleanup_exc:
                cleanup_errors.append(f"catalog refresh close: {cleanup_exc}")
        if server is not None:
            try:
                server.close()
            except BaseException as cleanup_exc:
                cleanup_errors.append(f"server close: {cleanup_exc}")
        if thread is not None:
            thread.join(timeout=2.0)
            if thread.is_alive():
                cleanup_errors.append("health thread is still alive")
        if registration is not None:
            try:
                registration.rollback()
            except BaseException as cleanup_exc:
                cleanup_errors.append(f"database rollback: {cleanup_exc}")
        if cleanup_errors:
            raise HealthBootstrapV2Error(
                "RECOVERY_ROLLBACK_FAILED",
                "; ".join(cleanup_errors),
            ) from exc
        raise


def _replace_controller_row_v2(
    *,
    binding: GatewayRuntimeBindingV2,
    controller: AcceptingControllerV2,
) -> _RecoveryRegistrationV2:
    previous = dict(binding.controller_row)
    _assert_previous_controller_dead_v2(previous)
    previous_epoch = previous.get("control_epoch")
    if (
        type(previous_epoch) is not int
        or controller.control_epoch != previous_epoch + 1
    ):
        raise HealthBootstrapV2Error(
            "CONTROL_EPOCH_MISMATCH",
            "восстановление обязано повысить controlEpoch ровно на один",
        )
    expected_immutable = {
        "database_id": binding.database_identity_row["database_id"],
        "controller_identity": previous["controller_identity"],
        "activation_id": binding.activation_id,
        "activation_fingerprint": binding.activation_fingerprint,
        "compatibility_fingerprint": binding.compatibility_fingerprint,
        "routing_policy_fingerprint": binding.activation_identity[
            "routingPolicyFingerprint"
        ],
        "bundled_catalog_fingerprint": binding.activation_identity[
            "bundledCatalogFingerprint"
        ],
    }
    observed_immutable = {
        "database_id": binding.database_identity_row["database_id"],
        "controller_identity": controller.controller_identity,
        "activation_id": controller.activation_id,
        "activation_fingerprint": controller.activation_fingerprint,
        "compatibility_fingerprint": controller.compatibility_fingerprint,
        "routing_policy_fingerprint": controller.routing_policy_fingerprint,
        "bundled_catalog_fingerprint": controller.bundled_catalog_fingerprint,
    }
    if observed_immutable != expected_immutable:
        raise HealthBootstrapV2Error(
            "RECOVERY_BINDING_MISMATCH",
            "новый контроллер меняет неизменяемую идентичность активации",
        )

    recovered = copy.deepcopy(previous)
    recovered.update(
        {
            "instance_id": controller.instance_id,
            "controller_start_id": controller.controller_start_id,
            "controller_pid": controller.controller_pid,
            "controller_process_start_marker": (
                controller.controller_process_start_marker
            ),
            "controller_process_group_id": controller.controller_process_group_id,
            "control_epoch": controller.control_epoch,
            "state": "ACCEPTING",
            "maintenance_mode": "NONE",
            "reason_code": "NONE",
            "operation_id": None,
            "socket_path": controller.socket_path,
            "socket_device": controller.socket_device,
            "socket_inode": controller.socket_inode,
            "socket_owner_uid": controller.socket_owner_uid,
            "socket_owner_gid": controller.socket_owner_gid,
            "socket_mode": controller.socket_mode,
            "lock_held": 1,
            "accepting_new_routes": 1,
            "updated_at": _iso(controller.updated_at),
        }
    )
    _replace_exact_controller_row_v2(
        database_path=binding.database_path,
        expected_database_identity=binding.database_identity_row,
        expected_current=previous,
        replacement=recovered,
        require_previous_dead=True,
    )
    return _RecoveryRegistrationV2(
        database_path=binding.database_path,
        database_identity=copy.deepcopy(dict(binding.database_identity_row)),
        previous_controller=previous,
        recovered_controller=recovered,
    )


def _restore_controller_row_v2(
    *,
    database_path: Path,
    expected_database_identity: Mapping[str, object],
    expected_current: Mapping[str, object],
    replacement: Mapping[str, object],
) -> None:
    _replace_exact_controller_row_v2(
        database_path=database_path,
        expected_database_identity=expected_database_identity,
        expected_current=expected_current,
        replacement=replacement,
        require_previous_dead=False,
    )


def _replace_exact_controller_row_v2(
    *,
    database_path: Path,
    expected_database_identity: Mapping[str, object] | None,
    expected_current: Mapping[str, object],
    replacement: Mapping[str, object],
    require_previous_dead: bool,
) -> None:
    before = _private_database_file_v2(database_path)
    connection = sqlite3.connect(
        database_path,
        timeout=1.0,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("pragma foreign_keys=on")
        connection.execute("pragma trusted_schema=off")
        connection.execute("pragma busy_timeout=1000")
        if (
            int(connection.execute("pragma application_id").fetchone()[0])
            != APPLICATION_ID
        ):
            raise HealthBootstrapV2Error(
                "RECOVERY_DATABASE_INVALID",
                "application_id базы изменён",
            )
        if int(connection.execute("pragma user_version").fetchone()[0]) != 2:
            raise HealthBootstrapV2Error(
                "RECOVERY_DATABASE_INVALID",
                "user_version базы изменён",
            )
        connection.execute("begin immediate")
        identity_rows = connection.execute("select * from database_identity").fetchall()
        controller_rows = connection.execute(
            "select * from controller_state"
        ).fetchall()
        if len(identity_rows) != 1 or len(controller_rows) != 1:
            raise HealthBootstrapV2Error(
                "RECOVERY_DATABASE_INVALID",
                "singleton-строки базы отсутствуют",
            )
        identity = dict(identity_rows[0])
        current = dict(controller_rows[0])
        if expected_database_identity is not None and identity != dict(
            expected_database_identity
        ):
            raise HealthBootstrapV2Error(
                "RECOVERY_DATABASE_CHANGED",
                "database_identity изменилась после статического доказательства",
            )
        if current != dict(expected_current):
            raise HealthBootstrapV2Error(
                "RECOVERY_CONTROLLER_CHANGED",
                "controller_state изменилась до атомарной замены",
            )
        if require_previous_dead:
            _assert_previous_controller_dead_v2(current)
        columns = [name for name in replacement if name != "singleton"]
        values = [replacement[name] for name in columns]
        cursor = connection.execute(
            "update controller_state set "
            + ",".join(f"{name}=?" for name in columns)
            + " where singleton=1",
            values,
        )
        if cursor.rowcount != 1:
            raise HealthBootstrapV2Error(
                "RECOVERY_CONTROLLER_CHANGED",
                "controller_state не была заменена ровно один раз",
            )
        observed = dict(connection.execute("select * from controller_state").fetchone())
        if observed != dict(replacement):
            raise HealthBootstrapV2Error(
                "RECOVERY_CONTROLLER_CHANGED",
                "прочитанная controller_state отличается от записанной",
            )
        connection.execute("commit")
    except BaseException:
        if connection.in_transaction:
            connection.execute("rollback")
        raise
    finally:
        connection.close()
    after = _private_database_file_v2(database_path)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise HealthBootstrapV2Error(
            "RECOVERY_DATABASE_CHANGED",
            "inode базы изменился во время атомарной замены",
        )


def _assert_previous_controller_dead_v2(
    controller_row: Mapping[str, object],
) -> None:
    pid = controller_row.get("controller_pid")
    marker = controller_row.get("controller_process_start_marker")
    if type(pid) is not int or pid <= 0 or type(marker) is not str or not marker:
        raise HealthBootstrapV2Error(
            "PREVIOUS_CONTROLLER_IDENTITY_INVALID",
            "PID или системный маркер прежнего контроллера неверен",
        )
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise HealthBootstrapV2Error(
            "PREVIOUS_CONTROLLER_LIVENESS_UNKNOWN",
            "нет права доказать завершение прежнего процесса",
        ) from exc
    try:
        observed_marker = system_process_start_marker_v2(pid)
    except ChildGuardV2Error as exc:
        raise HealthBootstrapV2Error(
            "PREVIOUS_CONTROLLER_LIVENESS_UNKNOWN",
            "не удалось доказать системный маркер прежнего процесса",
        ) from exc
    if observed_marker == marker:
        raise HealthBootstrapV2Error(
            "PREVIOUS_CONTROLLER_STILL_LIVE",
            "прежний PID и системный маркер всё ещё принадлежат живому процессу",
        )


def _private_database_file_v2(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise HealthBootstrapV2Error("RECOVERY_DATABASE_INVALID", str(exc)) from exc
    if (
        not path.is_absolute()
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise HealthBootstrapV2Error(
            "RECOVERY_DATABASE_INVALID",
            "файл базы имеет небезопасные метаданные",
        )
    return info


def _recovered_materialization_v2(
    *,
    layout: GatewayLayout,
    decision: GatewayDecision,
    controller: AcceptingControllerV2,
) -> ActivationMaterializationV2:
    binding = decision.runtime_binding
    if binding is None:
        raise HealthBootstrapV2Error(
            "RECOVERY_BINDING_MISSING",
            "READY не содержит runtime binding",
        )
    manifest = _read_json_v2(layout.manifest_path)
    activation_dir = layout.managed_root / "activations" / binding.activation_id
    bundled_catalog_path = (
        activation_dir
        / "marketplace"
        / "plugins"
        / "codex-smart-subagents"
        / "config"
        / "bundled-catalog-v1.json"
    )
    receipt_path = (
        layout.receipts_root
        / str(manifest["installationId"])
        / f"{manifest['lastCommittedOperation']}.commit.json"
    )
    health = {
        "namespace": "codex-smart-subagents-v2",
        "controllerIdentity": controller.controller_identity,
        "instanceId": controller.instance_id,
        "controllerStartId": controller.controller_start_id,
        "pid": controller.controller_pid,
        "processStartMarker": controller.controller_process_start_marker,
        "processGroupId": controller.controller_process_group_id,
        "state": "ACCEPTING",
        "maintenanceMode": None,
        "operationId": None,
        "acceptingNewRoutes": True,
        "quiescent": bool(binding.controller_row["quiescent"]),
        "activationFingerprint": binding.activation_fingerprint,
        "compatibilityFingerprint": binding.compatibility_fingerprint,
        "routingPolicyFingerprint": binding.activation_identity[
            "routingPolicyFingerprint"
        ],
        "bundledCatalogFingerprint": binding.activation_identity[
            "bundledCatalogFingerprint"
        ],
        "databaseId": binding.database_identity_row["database_id"],
        "databaseSchemaVersion": 2,
        "workCounts": _read_work_counts_v2(binding.database_path),
    }
    if decision.coordinator_selection is not None:
        health["coordinatorSelection"] = copy.deepcopy(
            dict(decision.coordinator_selection)
        )
    return ActivationMaterializationV2(
        status="CONTROLLER_RECOVERED",
        readiness="HEALTH_ONLY_READY",
        codex_home=layout.codex_home,
        state_home=binding.state_home,
        activation_id=binding.activation_id,
        activation_fingerprint=binding.activation_fingerprint,
        installation_id=str(manifest["installationId"]),
        operation_id=str(manifest["lastCommittedOperation"]),
        controller_identity=controller.controller_identity,
        activation_dir=activation_dir,
        snapshot_path=Path(str(manifest["codexSnapshot"]["absolutePath"])),
        bundled_catalog_path=bundled_catalog_path,
        bundled_catalog=_read_json_v2(bundled_catalog_path),
        interface_evidence=copy.deepcopy(dict(binding.interface_evidence)),
        receipt_path=receipt_path,
        expected_health_payload=health,
    )


def _read_json_v2(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HealthBootstrapV2Error("RECOVERY_JSON_INVALID", str(exc)) from exc
    if type(value) is not dict:
        raise HealthBootstrapV2Error(
            "RECOVERY_JSON_INVALID",
            f"корень JSON не является объектом: {path}",
        )
    return value


def _read_work_counts_v2(database_path: Path) -> dict[str, int]:
    connection = sqlite3.connect(database_path, timeout=0.5)
    try:
        connection.execute("pragma query_only=on")
        return {
            name: int(connection.execute(statement).fetchone()[0])
            for name, statement in _QUIESCENCE_QUERIES.items()
        }
    finally:
        connection.close()


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HealthBootstrapV2Error(
            "RECOVERY_TIME_INVALID",
            "время контроллера не содержит часовой пояс",
        )
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def observe_health_activation_v2(
    *,
    codex_home: Path,
    wrapper: Path,
    snapshot_verifier: Callable[[object], None],
) -> HealthBootstrapRuntimeV2:
    """Проверяет чужую живую активацию без присвоения сокета и блокировки."""

    codex_home = codex_home.expanduser().absolute()
    decision = ActivationResolver(
        layout=GatewayLayout.for_codex_home(codex_home),
        wrapper=wrapper.expanduser().absolute(),
        snapshot_verifier=snapshot_verifier,
        controller_probe=_unix_controller_probe,
    ).resolve()
    if decision.state is not GatewayState.READY:
        raise HealthBootstrapV2Error(
            "FOREIGN_ACTIVATION_NOT_READY",
            f"существующая активация не прошла health: {decision.reason_code}",
        )
    return HealthBootstrapRuntimeV2(
        gateway_decision=decision,
        owns_runtime=False,
    )


def _bootstrap_request_fingerprint(
    *,
    source_root: Path,
    codex_home: Path,
    state_home: Path,
    codex_binary: Path,
    wrapper: Path,
    policy_bundle: PolicyBundleV2,
    control_epoch: int,
    first_install_operation_id: str | None,
    first_installation_id: str | None,
) -> str:
    return domain_fingerprint(
        "codex-smart/health-bootstrap-request/v2",
        {
            "sourceRoot": str(source_root),
            "codexHome": str(codex_home.resolve()),
            "stateHome": str(state_home),
            "codexBinary": str(codex_binary),
            "wrapper": str(wrapper),
            "routingPolicyFingerprint": policy_bundle.router.policy_fingerprint,
            "policyBundleFingerprint": policy_bundle.bundle_fingerprint,
            "controlEpoch": control_epoch,
            "firstInstallOperationId": first_install_operation_id,
            "firstInstallationId": first_installation_id,
        },
    )


def _unregister_owner(runtime: HealthBootstrapRuntimeV2) -> None:
    registry_key = runtime._registry_key
    if registry_key is None:
        return
    with _OWNER_LOCK:
        if _OWNER_RUNTIMES.get(registry_key) is runtime:
            _OWNER_RUNTIMES.pop(registry_key, None)
