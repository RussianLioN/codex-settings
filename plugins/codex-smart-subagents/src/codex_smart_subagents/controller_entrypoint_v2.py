"""Сборка полного контроллера версии 2 из одного доказанного владельца."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .activation_gateway_v2 import (
    ActivationResolver,
    GatewayLayout,
    _default_snapshot_verifier,
    _unix_controller_probe,
)
from .controller_application_v2 import ControllerApplicationV2
from .controller_command_v2 import ControllerCommandServerV2
from .controller_provider_v2 import PinnedControllerProviderV2
from .health_bootstrap_v2 import bootstrap_health_activation_v2
from .lifecycle_controller_protocol_v2 import LifecycleControllerProtocolV2
from .policy_bundle_v2 import PolicyBundleV2, load_policy_bundle_v2
from .production_runtime_v2 import build_production_runtime_v2


_SAFE_RUNTIME_ENVIRONMENT = (
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
_BOOTSTRAP_ENVIRONMENT = (
    "CODEX_V2_SOURCE_ROOT",
    "CODEX_V2_CODEX_BIN",
    "CODEX_V2_WRAPPER_PATH",
)
_STATE_HOME_ENVIRONMENT = "CODEX_V2_STATE_HOME"
_FIRST_INSTALL_OPERATION_ENVIRONMENT = "CODEX_V2_FIRST_INSTALL_OPERATION_ID"
_FIRST_INSTALLATION_ENVIRONMENT = "CODEX_V2_FIRST_INSTALLATION_ID"
_OPERATION_ID_PATTERN = re.compile(r"^op2_[0-9a-f]{32}$")
_INSTALLATION_ID_PATTERN = re.compile(r"^ins2_[0-9a-f]{32}$")


@dataclass
class ControllerEntrypointV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ControllerEntrypointConfigV2:
    """Неизменяемые пути и закрытая среда одного процесса контроллера."""

    source_root: Path
    plugin_root: Path
    codex_home: Path
    state_home: Path
    codex_binary: Path
    wrapper: Path
    environment: Mapping[str, str]
    first_install_operation_id: str | None = None
    first_installation_id: str | None = None

    def __post_init__(self) -> None:
        for value, name, expected_directory in (
            (self.source_root, "source_root", True),
            (self.plugin_root, "plugin_root", True),
            (self.codex_home, "codex_home", True),
            (self.codex_binary, "codex_binary", False),
            (self.wrapper, "wrapper", False),
        ):
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute path")
            if not value.exists():
                raise ValueError(f"{name} does not exist")
            if expected_directory != value.is_dir():
                expected = "directory" if expected_directory else "file"
                raise ValueError(f"{name} must be a {expected}")
        if not isinstance(self.state_home, Path) or not self.state_home.is_absolute():
            raise ValueError("state_home must be an absolute path")
        if not os.access(self.codex_binary, os.X_OK):
            raise ValueError("codex_binary must be executable")
        if not os.access(self.wrapper, os.X_OK):
            raise ValueError("wrapper must be executable")
        if not isinstance(self.environment, Mapping):
            raise TypeError("environment must be a mapping")
        copied: dict[str, str] = {}
        for key, value in self.environment.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or "\0" in key
                or "=" in key
                or "\0" in value
            ):
                raise ValueError("environment contains an invalid entry")
            copied[key] = value
        object.__setattr__(self, "environment", copied)
        if (self.first_install_operation_id is None) != (
            self.first_installation_id is None
        ):
            raise ValueError("first-install identities must be paired")
        if self.first_install_operation_id is not None and (
            _OPERATION_ID_PATTERN.fullmatch(self.first_install_operation_id) is None
            or _INSTALLATION_ID_PATTERN.fullmatch(self.first_installation_id or "")
            is None
        ):
            raise ValueError("first-install identities are invalid")


def load_controller_entrypoint_config_v2(
    *,
    plugin_root: Path,
    environment: Mapping[str, str],
    recovery_decision_provider: Callable[..., Any] | None = None,
) -> ControllerEntrypointConfigV2:
    """Читает либо полный первичный bootstrap, либо принятую активацию.

    Три первичных значения образуют единый набор: частичный набор не может
    незаметно перейти в восстановление. В рабочую среду эти значения и другие
    произвольные переменные не переносятся.
    """

    if not isinstance(plugin_root, Path) or not plugin_root.is_absolute():
        raise ValueError("plugin_root must be an absolute Path")
    if not isinstance(environment, Mapping) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in environment.items()
    ):
        raise TypeError("environment must contain strings")
    raw_home = environment.get("CODEX_HOME", "")
    if not raw_home or not Path(raw_home).is_absolute():
        raise ControllerEntrypointV2Error(
            "CODEX_HOME_INVALID",
            "CODEX_HOME не задан абсолютным путём",
        )
    codex_home = Path(raw_home).resolve(strict=True)
    present = [bool(environment.get(name)) for name in _BOOTSTRAP_ENVIRONMENT]
    if any(present) and not all(present):
        raise ControllerEntrypointV2Error(
            "BOOTSTRAP_ENVIRONMENT_INCOMPLETE",
            "первичный запуск требует все три CODEX_V2 пути",
        )

    if all(present):
        if not environment.get(_STATE_HOME_ENVIRONMENT):
            raise ControllerEntrypointV2Error(
                "BOOTSTRAP_ENVIRONMENT_INCOMPLETE",
                "первичный запуск требует CODEX_V2_STATE_HOME",
            )
        source_root = Path(environment[_BOOTSTRAP_ENVIRONMENT[0]]).resolve(strict=True)
        raw_codex_binary = Path(environment[_BOOTSTRAP_ENVIRONMENT[1]]).expanduser()
        if not raw_codex_binary.is_absolute():
            raise ControllerEntrypointV2Error(
                "CODEX_BINARY_INVALID",
                "CODEX_V2_CODEX_BIN должен быть абсолютным путём",
            )
        # Лексический путь является частью договора sourceLocator и argv[0].
        # Проверка существования ниже следует по ссылке, но сама ссылка должна
        # сохраниться в манифесте, квитанции установщика и при откате.
        codex_binary = raw_codex_binary.absolute()
        wrapper = Path(environment[_BOOTSTRAP_ENVIRONMENT[2]]).resolve(strict=True)
        raw_state_home = Path(environment[_STATE_HOME_ENVIRONMENT]).expanduser()
        if not raw_state_home.is_absolute():
            raise ControllerEntrypointV2Error(
                "STATE_HOME_INVALID",
                "CODEX_V2_STATE_HOME должен быть абсолютным путём",
            )
        state_home = raw_state_home.absolute()
        first_install_operation_id = environment.get(
            _FIRST_INSTALL_OPERATION_ENVIRONMENT
        )
        first_installation_id = environment.get(_FIRST_INSTALLATION_ENVIRONMENT)
        if bool(first_install_operation_id) != bool(first_installation_id):
            raise ControllerEntrypointV2Error(
                "BOOTSTRAP_ENVIRONMENT_INCOMPLETE",
                "первичный запуск требует оба идентификатора первой установки",
            )
    else:
        source_root = plugin_root.resolve(strict=True)
        wrapper = (plugin_root / "bin" / "codex-smart").resolve(strict=True)
        layout = GatewayLayout.for_codex_home(codex_home)
        if recovery_decision_provider is None:
            decision = ActivationResolver(
                layout=layout,
                wrapper=wrapper,
                snapshot_verifier=_default_snapshot_verifier,
            ).resolve_persisted_activation()
        else:
            if not callable(recovery_decision_provider):
                raise TypeError("recovery_decision_provider must be callable")
            decision = recovery_decision_provider(layout=layout, wrapper=wrapper)
        try:
            # sourceLocator связывает argv[0] лексически. Раскрытие управляемой
            # ссылки заставляет восстановление сравнить физическую цель с
            # сохранённым путём и отвергнуть тот же исполняемый файл Codex.
            codex_binary = Path(decision.executable).expanduser().absolute()
            state_home = Path(decision.runtime_binding.state_home)
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise ControllerEntrypointV2Error(
                "RECOVERY_EXECUTABLE_UNAVAILABLE",
                "принятая активация не дала обычный исполняемый файл",
            ) from exc
        expected_state_home = environment.get(_STATE_HOME_ENVIRONMENT)
        if expected_state_home:
            supplied = Path(expected_state_home).expanduser()
            if not supplied.is_absolute() or supplied.absolute() != state_home:
                raise ControllerEntrypointV2Error(
                    "RECOVERY_CONFIGURATION_CONFLICT",
                    "переданный state_home отличается от принятой активации",
                )
        first_install_operation_id = None
        first_installation_id = None
        if environment.get(_FIRST_INSTALL_OPERATION_ENVIRONMENT) or environment.get(
            _FIRST_INSTALLATION_ENVIRONMENT
        ):
            raise ControllerEntrypointV2Error(
                "RECOVERY_CONFIGURATION_CONFLICT",
                "идентификаторы первой установки недопустимы при восстановлении",
            )

    runtime_environment = {
        name: environment[name]
        for name in _SAFE_RUNTIME_ENVIRONMENT
        if environment.get(name) and "\0" not in environment[name]
    }
    for name in ("HOME", "TMPDIR"):
        value = runtime_environment.get(name)
        if value is None:
            continue
        path = Path(value).expanduser()
        try:
            canonical = path.resolve(strict=True)
        except OSError as exc:
            raise ControllerEntrypointV2Error(
                "RUNTIME_DIRECTORY_INVALID",
                f"{name} недоступен",
            ) from exc
        if not path.is_absolute() or not canonical.is_dir():
            raise ControllerEntrypointV2Error(
                "RUNTIME_DIRECTORY_INVALID",
                f"{name} должен быть абсолютным каталогом",
            )
        runtime_environment[name] = str(canonical)
    runtime_environment["CODEX_HOME"] = str(codex_home)
    runtime_environment["PATH"] = os.defpath
    return ControllerEntrypointConfigV2(
        source_root=source_root,
        plugin_root=plugin_root.resolve(strict=True),
        codex_home=codex_home,
        state_home=state_home,
        codex_binary=codex_binary,
        wrapper=wrapper,
        environment=runtime_environment,
        first_install_operation_id=first_install_operation_id,
        first_installation_id=first_installation_id,
    )


def load_controller_policy_bundle_v2(
    *,
    source_root: Path,
    plugin_root: Path,
) -> PolicyBundleV2:
    """Выбирает один и тот же договор из исходного или принятого дерева."""

    installed_contracts = plugin_root / "config" / "contracts"
    if installed_contracts.is_dir():
        catalog = plugin_root / "config" / "adaptive-subagents.toml"
        contracts = installed_contracts
    else:
        catalog = source_root / ".codex" / "adaptive-subagents.toml"
        contracts = source_root / "docs" / "contracts" / "vectors"
    return load_policy_bundle_v2(
        catalog_path=catalog,
        routing_vector_path=contracts / "routing-policy-v2.json",
        delegation_vector_path=contracts / "delegation-policy-v2.json",
        role_vector_path=contracts / "role-template-v1.json",
        child_profile_vector_path=contracts / "child-profile-v1.json",
    )


def build_controller_turn_context_loader_v2(
    *,
    config: ControllerEntrypointConfigV2,
    launch_decision: Any,
) -> Callable[[str], Any]:
    """Строит доверенное чтение записи хода для произвольного shell-сеанса."""

    try:
        binding = launch_decision.runtime_binding
        activation_id = str(launch_decision.activation_id)
        gate_fingerprint = str(launch_decision.gate_fingerprint)
        catalog_path = Path(launch_decision.catalog_path)
        state_home = Path(binding.state_home)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ControllerEntrypointV2Error(
            "LAUNCH_DECISION_INCOMPLETE",
            "решение запуска не содержит путей контекста хода",
        ) from exc
    scripts = config.plugin_root / "scripts"
    if not scripts.is_dir():
        raise ControllerEntrypointV2Error(
            "INTEGRATION_RUNTIME_UNAVAILABLE",
            "каталог скриптов принятого расширения отсутствует",
        )
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    try:
        from integration_runtime_v2 import IntegrationConfigV2, TurnContextStoreV2
    except ImportError as exc:
        raise ControllerEntrypointV2Error(
            "INTEGRATION_RUNTIME_UNAVAILABLE",
            "не удалось загрузить хранилище контекста хода",
        ) from exc

    def load(shell_session_id: str) -> Any:
        integration_config = IntegrationConfigV2(
            shell_session_id=shell_session_id,
            codex_home=config.codex_home,
            state_home=state_home,
            gateway_path=config.wrapper,
            launch_activation_id=activation_id,
            launch_gate_fingerprint=gate_fingerprint,
            catalog_path=catalog_path,
        )
        return TurnContextStoreV2(integration_config).load()

    return load


def start_full_controller_v2(
    config: ControllerEntrypointConfigV2,
    *,
    policy_bundle: Any,
    dispatcher_factory: Any,
    dispatcher_factory_builder: Callable[..., Any] | None = None,
    bootstrapper: Callable[..., Any] = bootstrap_health_activation_v2,
    decision_provider: Callable[[], Any] | None = None,
    turn_context_loader: Callable[[str], Any] | None = None,
    production_builder: Callable[..., Any] = build_production_runtime_v2,
    command_server_factory: Callable[..., Any] | None = None,
    snapshot_verifier: Callable[[object], None] = _default_snapshot_verifier,
) -> ControllerApplicationV2:
    """Поднимает health, рабочий контур и командный сокет одной активации.

    Если health уже принадлежит другому процессу, вызывающая сторона ничего у
    него не закрывает и не пытается открыть второй рабочий контур.
    """

    if not isinstance(config, ControllerEntrypointConfigV2):
        raise TypeError("config must be ControllerEntrypointConfigV2")
    if (dispatcher_factory is None) == (dispatcher_factory_builder is None):
        raise ControllerEntrypointV2Error(
            "DISPATCHER_COMPOSITION_INVALID",
            "нужна ровно одна готовая фабрика или её производственный построитель",
        )
    for value, name in (
        (bootstrapper, "bootstrapper"),
        (production_builder, "production_builder"),
        (snapshot_verifier, "snapshot_verifier"),
    ):
        if not callable(value):
            raise TypeError(f"{name} must be callable")

    health = bootstrapper(
        source_root=config.source_root,
        codex_home=config.codex_home,
        state_home=config.state_home,
        codex_binary=config.codex_binary,
        wrapper=config.wrapper,
        policy_bundle=policy_bundle,
        snapshot_verifier=snapshot_verifier,
        first_install_operation_id=config.first_install_operation_id,
        first_installation_id=config.first_installation_id,
    )
    if getattr(health, "owns_runtime", None) is not True:
        raise ControllerEntrypointV2Error(
            "CONTROLLER_ALREADY_RUNNING",
            "health уже принадлежит другому процессу",
        )
    binding = getattr(health.gateway_decision, "runtime_binding", None)
    if binding is None or Path(binding.state_home) != config.state_home:
        health.close()
        raise ControllerEntrypointV2Error(
            "STATE_HOME_BINDING_MISMATCH",
            "контроллер и принятая активация используют разные state_home",
        )

    try:
        try:
            lifecycle_database_path = Path(binding.database_path)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ControllerEntrypointV2Error(
                "LIFECYCLE_BINDING_INCOMPLETE",
                "принятая активация не содержит путь рабочей базы",
            ) from exc
        lifecycle_protocol = LifecycleControllerProtocolV2(
            database_path=lifecycle_database_path,
            codex_home=config.codex_home,
            controller_lock_path=config.state_home / "controller.lock",
        )
        effective_dispatcher_factory = dispatcher_factory
        if dispatcher_factory_builder is not None:
            if not callable(dispatcher_factory_builder):
                raise TypeError("dispatcher_factory_builder must be callable")
            effective_dispatcher_factory = dispatcher_factory_builder(
                config=config,
                policy_bundle=policy_bundle,
                launch_decision=health.gateway_decision,
            )
        if not callable(effective_dispatcher_factory):
            raise ControllerEntrypointV2Error(
                "DISPATCHER_COMPOSITION_INVALID",
                "производственный построитель не вернул фабрику диспетчера",
            )
        resolver = ActivationResolver(
            layout=GatewayLayout.for_codex_home(config.codex_home),
            wrapper=config.wrapper,
            snapshot_verifier=snapshot_verifier,
            controller_probe=_unix_controller_probe,
        )
        fresh_decision = decision_provider or resolver.resolve
        if not callable(fresh_decision):
            raise TypeError("decision_provider must be callable")
        context_loader = turn_context_loader or build_controller_turn_context_loader_v2(
            config=config,
            launch_decision=health.gateway_decision,
        )
        if not callable(context_loader):
            raise TypeError("turn_context_loader must be callable")

        provider = PinnedControllerProviderV2(
            launch_decision=health.gateway_decision,
            decision_provider=fresh_decision,
            turn_context_loader=context_loader,
        )

        def build_production(scoped_provider: Any) -> Any:
            return production_builder(
                provider=scoped_provider,
                environment=dict(config.environment),
                dispatcher_factory=effective_dispatcher_factory,
            )

        def build_command_server(handler: Any) -> Any:
            if command_server_factory is not None:
                return command_server_factory(handler=handler)
            return ControllerCommandServerV2(
                socket_path=config.state_home / "command.sock",
                lock_path=config.state_home / "command.lock",
                handler=handler,
            )

        return ControllerApplicationV2.start(
            health_runtime=health,
            provider=provider,
            production_factory=build_production,
            command_server_factory=build_command_server,
            lifecycle_handler=lifecycle_protocol.handle,
        )
    except BaseException:
        # ControllerApplicationV2 закрывает health при ошибках после начала
        # сборки. Повторный close обязан быть идемпотентным и закрывает также
        # ошибки, возникшие до передачи владения приложению.
        health.close()
        raise


__all__ = [
    "ControllerEntrypointConfigV2",
    "ControllerEntrypointV2Error",
    "build_controller_turn_context_loader_v2",
    "load_controller_entrypoint_config_v2",
    "load_controller_policy_bundle_v2",
    "start_full_controller_v2",
]
