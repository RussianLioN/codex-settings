"""Связывает строгий диспетчер с фактическими производственными проверками."""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path
from typing import Any, Callable

from .activation_gateway_v2 import GatewayRuntimeBindingV2
from .controller_entrypoint_v2 import ControllerEntrypointConfigV2
from .policy_bundle_v2 import PolicyBundleV2
from .production_dispatcher_v2 import ProductionDispatcherDependenciesV2
from .production_proofs_v2 import (
    CodexSnapshotDescriptorProbeV2,
    LivePreparedPermissionProbeV2,
    PermissionProbeContextV2,
    PreparedProcessProbeV2,
    SharedLaunchBarrierV2,
    build_managed_config_inspector_v2,
)
from .snapshot import SnapshotBuilder, SnapshotLimits
from .state_candidate_publisher_v2 import StateCandidateRefPublisherV2
from .state_store_v2 import NodePlanV2, SmartStoreV2
from .validation import (
    ValidationLimits,
    ValidationRunner,
    ValidationSandbox,
)
from .writer_publication_v2 import WriterPublicationCoordinatorV2


class ProductionCompositionV2Error(RuntimeError):
    """Ошибка соединения доказательств с одной живой активацией."""


_BARRIERS_LOCK = threading.Lock()
_BARRIERS: dict[str, SharedLaunchBarrierV2] = {}


def build_default_production_dispatcher_dependencies_v2(
    *,
    config: ControllerEntrypointConfigV2,
    policy_bundle: PolicyBundleV2,
    launch_decision: Any,
    managed_config_inspector_factory: Callable[..., Any] = (
        build_managed_config_inspector_v2
    ),
) -> ProductionDispatcherDependenciesV2:
    """Создаёт обязательные поставщики только из одной READY-привязки."""

    if not isinstance(config, ControllerEntrypointConfigV2):
        raise TypeError("config must be ControllerEntrypointConfigV2")
    if not isinstance(policy_bundle, PolicyBundleV2):
        raise TypeError("policy_bundle must be PolicyBundleV2")
    if not callable(managed_config_inspector_factory):
        raise TypeError("managed_config_inspector_factory must be callable")
    try:
        state = getattr(launch_decision.state, "value", launch_decision.state)
        binding = launch_decision.runtime_binding
    except AttributeError as exc:
        raise ProductionCompositionV2Error("launch decision is incomplete") from exc
    if state != "READY" or not isinstance(binding, GatewayRuntimeBindingV2):
        raise ProductionCompositionV2Error("launch decision is not READY")
    if binding.state_home != config.state_home:
        raise ProductionCompositionV2Error("state home differs from controller config")

    canary_root = binding.state_home / "permission-canary-v2"
    _private_directory(canary_root)
    try:
        executable = Path(binding.interface_evidence["subject"]["snapshotPath"])
    except (KeyError, TypeError) as exc:
        raise ProductionCompositionV2Error("snapshot subject is incomplete") from exc
    inspector = managed_config_inspector_factory(
        codex_executable=executable,
        codex_home=config.codex_home,
        runtime_parent=canary_root,
    )
    protected_source = _protected_source_file(config.source_root)
    context = PermissionProbeContextV2(
        codex_home=config.codex_home,
        runtime_parent=canary_root,
        managed_config_inspector=inspector,
        secret_read_file=config.codex_home / "auth.json",
        source_git_read_file=protected_source,
        controller_database_read_file=binding.database_path,
        source_worktree_write_file=protected_source,
        controller_socket=binding.state_home / "controller.sock",
    )
    snapshot_probe = CodexSnapshotDescriptorProbeV2()

    def result_schema_resolution_provider(
        current_binding: GatewayRuntimeBindingV2,
        current_bundle: PolicyBundleV2,
    ) -> dict[str, str]:
        if (
            _binding_identity(current_binding) != _binding_identity(binding)
            or current_bundle.bundle_fingerprint != policy_bundle.bundle_fingerprint
            or dict(current_bundle.result_schema_resolution)
            != dict(policy_bundle.result_schema_resolution)
        ):
            raise ProductionCompositionV2Error(
                "result schema resolution belongs to another activation"
            )
        return dict(current_bundle.result_schema_resolution)

    def bounded_snapshot_builder_factory(
        limits: SnapshotLimits,
    ) -> SnapshotBuilder:
        return SnapshotBuilder(limits)

    def writer_validation_commands_provider(
        plan: NodePlanV2,
        current_bundle: PolicyBundleV2,
    ) -> tuple[tuple[str, ...], ...]:
        if (
            not isinstance(current_bundle, PolicyBundleV2)
            or current_bundle.bundle_fingerprint
            != policy_bundle.bundle_fingerprint
        ):
            raise ProductionCompositionV2Error(
                "writer validation belongs to another activation"
            )
        try:
            profile_id = plan.node.validation_profile_id
            commands = current_bundle.validation_commands[profile_id]
        except (AttributeError, KeyError, TypeError) as exc:
            raise ProductionCompositionV2Error(
                "writer validation profile is unavailable"
            ) from exc
        if profile_id != "writer-validation-v2" or not commands:
            raise ProductionCompositionV2Error(
                "writer validation profile is not allowed"
            )
        return tuple(tuple(command) for command in commands)

    def writer_publication_coordinator_factory(
        *,
        store: SmartStoreV2,
        binding: GatewayRuntimeBindingV2,
        policy_bundle: PolicyBundleV2,
        environment: Any,
        snapshot_builder: SnapshotBuilder,
    ) -> WriterPublicationCoordinatorV2:
        del environment
        if (
            _binding_identity(binding)
            != _binding_identity(launch_decision.runtime_binding)
            or policy_bundle.bundle_fingerprint
            != current_policy_fingerprint
        ):
            raise ProductionCompositionV2Error(
                "writer publication belongs to another activation"
            )
        try:
            managed_state = inspector.inspect()
        except Exception as exc:
            raise ProductionCompositionV2Error(
                "managed configuration is unavailable for writer validation"
            ) from exc
        helper = config.plugin_root / "bin" / "codex-smart-subagents-validate"
        limits = policy_bundle.catalog_limits
        return WriterPublicationCoordinatorV2(
            snapshot_builder=snapshot_builder,
            validation_runner=ValidationRunner(
                sandbox=ValidationSandbox(
                    codex_executable=executable,
                    helper_executable=helper,
                    permission_profile_name="adaptive_validator",
                ),
                limits=ValidationLimits(
                    timeout_seconds=limits["validation_timeout_seconds"],
                    max_output_bytes=limits["validation_max_output_bytes"],
                    max_address_space_bytes=limits[
                        "validation_max_address_space_bytes"
                    ],
                    max_processes=limits["validation_max_processes"],
                    max_file_bytes=limits["validation_max_file_bytes"],
                    max_open_files=limits["validation_max_open_files"],
                    max_growth_bytes=limits["validation_max_growth_bytes"],
                ),
                managed_config_inspector=inspector,
                expected_managed_config_sha256=managed_state.sha256,
            ),
            ref_publisher=StateCandidateRefPublisherV2(store=store),
        )

    current_policy_fingerprint = policy_bundle.bundle_fingerprint

    return ProductionDispatcherDependenciesV2(
        launch_barrier=_shared_barrier(binding.state_home),
        fresh_permission_probe=LivePreparedPermissionProbeV2(context),
        codex_snapshot_probe=snapshot_probe,
        fresh_process_probe=PreparedProcessProbeV2(
            snapshot_probe=snapshot_probe,
        ),
        result_schema_resolution_provider=result_schema_resolution_provider,
        bounded_snapshot_builder_factory=bounded_snapshot_builder_factory,
        writer_publication_coordinator_factory=(
            writer_publication_coordinator_factory
        ),
        writer_validation_commands_provider=writer_validation_commands_provider,
    )


def _shared_barrier(state_home: Path) -> SharedLaunchBarrierV2:
    key = str(state_home)
    with _BARRIERS_LOCK:
        barrier = _BARRIERS.get(key)
        if barrier is None:
            barrier = SharedLaunchBarrierV2()
            _BARRIERS[key] = barrier
        return barrier


def _binding_identity(binding: GatewayRuntimeBindingV2) -> tuple[object, ...]:
    if not isinstance(binding, GatewayRuntimeBindingV2):
        raise ProductionCompositionV2Error("runtime binding has another type")
    try:
        return (
            binding.activation_id,
            binding.activation_fingerprint,
            binding.compatibility_fingerprint,
            binding.control_epoch,
            str(binding.state_home),
            str(binding.marketplace_path),
            str(binding.database_path),
        )
    except TypeError as exc:
        raise ProductionCompositionV2Error("runtime binding is incomplete") from exc


def _private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
    except OSError as exc:
        raise ProductionCompositionV2Error(str(exc)) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ProductionCompositionV2Error("canary root is not private")


def _protected_source_file(source_root: Path) -> Path:
    preferred = (source_root / ".git" / "HEAD", source_root / "README.md")
    for candidate in preferred:
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.lstat()
        except OSError:
            continue
        if (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
        ):
            return resolved
    for candidate in sorted(source_root.rglob("*"), key=lambda item: item.as_posix()):
        try:
            info = candidate.lstat()
        except OSError:
            continue
        if (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.getuid()
            and info.st_nlink == 1
        ):
            return candidate.resolve(strict=True)
    raise ProductionCompositionV2Error("source tree has no protected regular file")


__all__ = [
    "ProductionCompositionV2Error",
    "build_default_production_dispatcher_dependencies_v2",
]
