"""Непрерывный переход контроллера-кандидата к полному рабочему контуру."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .activation_gateway_v2 import (
    ActivationResolver,
    GatewayLayout,
    GatewayState,
    _default_snapshot_verifier,
    _unix_controller_probe,
)
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .candidate_ready_channel_v2 import (
    CandidateReadyBootstrapV2,
    start_candidate_ready_channel_v2,
)
from .controller_entrypoint_v2 import (
    ControllerEntrypointConfigV2,
    load_controller_policy_bundle_v2,
    start_full_controller_v2,
)
from .controller_health_v2 import ControllerHealthServerV2
from .lifecycle_controller_protocol_v2 import LifecycleControllerProtocolV2


_RELEASE = "0.2.0"
_NAMESPACE = "codex-smart-subagents-v2"
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_ACTIVATION_ID = re.compile(r"^act2_[0-9a-f]{64}$")
_DATABASE_ID = re.compile(r"^db2_[0-9a-f]{32}$")
_CONTROLLER_START_ID = re.compile(r"^cs2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_RUNTIME_ENVIRONMENT = (
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


@dataclass
class CandidateControllerV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class CandidateControllerConfigV2:
    plugin_root: Path
    activation_dir: Path
    activation_document: Mapping[str, Any]
    codex_home: Path
    state_home: Path
    database_path: Path
    codex_binary: Path
    wrapper: Path
    operation_id: str
    activation_id: str
    activation_fingerprint: str
    database_id: str
    controller_identity: str
    controller_start_id: str
    compatibility_fingerprint: str
    routing_policy_fingerprint: str
    bundled_catalog_fingerprint: str
    entrypoint_config: ControllerEntrypointConfigV2


class _LifecycleHandlerProxyV2:
    """Сохраняет один и тот же объект обработчика до и после приёмки."""

    def __init__(self, handler: Callable[[Mapping[str, object]], Mapping[str, object]]):
        self._handler = handler

    def __call__(self, request: Mapping[str, object]) -> Mapping[str, object]:
        return self._handler(request)


class _AdoptedCandidateHealthV2:
    """Совместимый handle уже занятого кандидатом health-сокета."""

    def __init__(self, *, decision: Any, server: Any, thread: threading.Thread, proxy: Any):
        self.gateway_decision = decision
        self.owns_runtime = True
        self._server = server
        self._thread = thread
        self._proxy = proxy
        self._closed = False
        self._lock = threading.Lock()

    def bind_lifecycle_handler(
        self,
        handler: Callable[[Mapping[str, object]], Mapping[str, object]],
        *,
        response_observer: Callable[
            [Mapping[str, object], Mapping[str, object]], None
        ]
        | None = None,
    ) -> None:
        if not callable(handler):
            _fail("LIFECYCLE_HANDLER_INVALID", "обработчик должен быть вызываемым")
        self._server.bind_lifecycle_handler(
            self._proxy,
            response_observer=response_observer,
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._server.close()
            if self._thread is not threading.current_thread():
                self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                _fail(
                    "CANDIDATE_HEALTH_DID_NOT_STOP",
                    "поток health кандидата не завершился",
                )


def load_candidate_controller_config_v2(
    *,
    plugin_root: Path,
    environment: Mapping[str, str],
) -> CandidateControllerConfigV2:
    """Связать закрытое окружение с самим деревом активации кандидата."""

    if not isinstance(environment, Mapping) or not all(
        type(name) is str and type(value) is str
        for name, value in environment.items()
    ):
        _fail("CANDIDATE_ENVIRONMENT_INVALID", "окружение должно содержать строки")
    if "CODEX_V2_CANDIDATE_DATABASE" in environment:
        _fail(
            "CANDIDATE_ENVIRONMENT_FORBIDDEN",
            "путь базы берётся только из неизменяемой активации",
        )
    plugin_root = _private_directory(plugin_root, "CANDIDATE_PLUGIN_ROOT_INVALID")
    try:
        activation_dir = plugin_root.parents[2]
    except IndexError as error:
        raise CandidateControllerV2Error(
            "CANDIDATE_PLUGIN_ROOT_INVALID",
            "корень расширения не вложен в активацию",
        ) from error
    if _ACTIVATION_ID.fullmatch(activation_dir.name) is None:
        _fail(
            "CANDIDATE_PLUGIN_ROOT_INVALID",
            "родитель расширения не является активацией версии 2",
        )
    expected_suffix = Path("marketplace") / "plugins" / "codex-smart-subagents"
    if plugin_root != activation_dir / expected_suffix:
        _fail(
            "CANDIDATE_PLUGIN_ROOT_INVALID",
            "расширение находится вне нормативного дерева активации",
        )

    activation_path = activation_dir / "activation.json"
    activation_document = _read_private_canonical_json(
        activation_path,
        "CANDIDATE_ACTIVATION_INVALID",
    )
    identity = activation_document.get("identity")
    activation_id = activation_document.get("activationId")
    activation_fingerprint = activation_document.get("activationFingerprint")
    if (
        type(identity) is not dict
        or type(activation_id) is not str
        or _ACTIVATION_ID.fullmatch(activation_id) is None
        or type(activation_fingerprint) is not str
        or _SHA256.fullmatch(activation_fingerprint) is None
        or activation_id != activation_dir.name
        or activation_id != "act2_" + activation_fingerprint
        or activation_fingerprint
        != domain_fingerprint("codex-smart/activation/v2", identity)
        or identity.get("release") != _RELEASE
    ):
        _fail(
            "CANDIDATE_ACTIVATION_INVALID",
            "activation.json не связан со своим каталогом и идентичностью",
        )

    codex_home = _owned_codex_home_from_environment(
        environment, "CODEX_HOME", "CODEX_HOME_INVALID"
    )
    state_home = _private_directory_from_environment(
        environment, "CODEX_V2_STATE_HOME", "STATE_HOME_INVALID"
    )
    wrapper = _executable_from_environment(
        environment, "CODEX_V2_WRAPPER_PATH", "WRAPPER_INVALID"
    )
    operation_id = _environment_identifier(
        environment,
        "CODEX_V2_CANDIDATE_OPERATION_ID",
        _OPERATION_ID,
        "CANDIDATE_OPERATION_INVALID",
    )
    controller_start_id = _environment_identifier(
        environment,
        "CODEX_V2_CANDIDATE_CONTROLLER_START_ID",
        _CONTROLLER_START_ID,
        "CANDIDATE_CONTROLLER_START_INVALID",
    )

    database = identity.get("database")
    snapshot = identity.get("codexSnapshot")
    if type(database) is not dict or type(snapshot) is not dict:
        _fail(
            "CANDIDATE_ACTIVATION_INVALID",
            "идентичность не содержит базу или снимок Codex",
        )
    database_id = database.get("databaseId")
    raw_database_path = database.get("absolutePath")
    if (
        type(database_id) is not str
        or _DATABASE_ID.fullmatch(database_id) is None
        or type(raw_database_path) is not str
    ):
        _fail("CANDIDATE_DATABASE_INVALID", "идентичность базы неполна")
    database_path = _private_regular_file(
        Path(raw_database_path), "CANDIDATE_DATABASE_INVALID", executable=False
    )
    expected_database = (
        state_home / "databases" / database_id / "smart-subagents.sqlite3"
    )
    if database_path != expected_database:
        _fail(
            "CANDIDATE_DATABASE_INVALID",
            "база находится вне нормативного каталога состояния",
        )
    raw_snapshot_path = snapshot.get("absolutePath")
    snapshot_sha256 = snapshot.get("sha256")
    if type(raw_snapshot_path) is not str or type(snapshot_sha256) is not str:
        _fail("CANDIDATE_SNAPSHOT_INVALID", "идентичность снимка неполна")
    codex_binary = _private_regular_file(
        Path(raw_snapshot_path), "CANDIDATE_SNAPSHOT_INVALID", executable=True
    )
    if (
        _SHA256.fullmatch(snapshot_sha256) is None
        or _sha256_file(codex_binary) != snapshot_sha256
    ):
        _fail("CANDIDATE_SNAPSHOT_INVALID", "снимок Codex изменён")

    compatibility = _identity_sha256(identity, "compatibilityFingerprint")
    routing = _identity_sha256(identity, "routingPolicyFingerprint")
    catalog = _identity_sha256(identity, "bundledCatalogFingerprint")
    controller_identity = domain_fingerprint(
        "codex-smart/controller-identity/v2",
        {
            "protocolVersion": 2,
            "release": _RELEASE,
            "namespace": _NAMESPACE,
            "codexHomeHash": hashlib.sha256(
                str(codex_home.resolve()).encode("utf-8")
            ).hexdigest(),
            "stateHome": str(state_home),
            "activationFingerprint": activation_fingerprint,
            "compatibilityFingerprint": compatibility,
            "routingPolicyFingerprint": routing,
            "bundledCatalogFingerprint": catalog,
            "databaseId": database_id,
            "databaseSchemaVersion": 2,
        },
    )
    runtime_environment = {
        name: environment[name]
        for name in _SAFE_RUNTIME_ENVIRONMENT
        if environment.get(name) and "\0" not in environment[name]
    }
    runtime_environment.update(
        {"CODEX_HOME": str(codex_home), "PATH": os.defpath}
    )
    entrypoint_config = ControllerEntrypointConfigV2(
        source_root=plugin_root,
        plugin_root=plugin_root,
        codex_home=codex_home,
        state_home=state_home,
        codex_binary=codex_binary,
        wrapper=wrapper,
        environment=runtime_environment,
    )
    return CandidateControllerConfigV2(
        plugin_root=plugin_root,
        activation_dir=activation_dir,
        activation_document=activation_document,
        codex_home=codex_home,
        state_home=state_home,
        database_path=database_path,
        codex_binary=codex_binary,
        wrapper=wrapper,
        operation_id=operation_id,
        activation_id=activation_id,
        activation_fingerprint=activation_fingerprint,
        database_id=database_id,
        controller_identity=controller_identity,
        controller_start_id=controller_start_id,
        compatibility_fingerprint=compatibility,
        routing_policy_fingerprint=routing,
        bundled_catalog_fingerprint=catalog,
        entrypoint_config=entrypoint_config,
    )


def serve_candidate_controller_v2(
    config: CandidateControllerConfigV2,
    *,
    ready_bootstrap: CandidateReadyBootstrapV2 | None = None,
    ready_channel_starter: Callable[..., Any] = start_candidate_ready_channel_v2,
    policy_loader: Callable[..., Any] = load_controller_policy_bundle_v2,
    server_factory: Callable[..., Any] = ControllerHealthServerV2,
    protocol_factory: Callable[..., Any] = LifecycleControllerProtocolV2,
    decision_provider: Callable[[], Any] | None = None,
    full_controller_starter: Callable[..., Any] = start_full_controller_v2,
    dispatcher_factory_builder: Callable[..., Any] | None = None,
    signal_installer: Callable[[Any], None] = lambda _application: None,
    ready_timeout_seconds: float = 30.0,
    gateway_timeout_seconds: float = 30.0,
) -> Any:
    """Принять кандидата и без смены процесса открыть полный контроллер."""

    if not isinstance(config, CandidateControllerConfigV2):
        raise TypeError("config must be CandidateControllerConfigV2")
    if not 0 < float(ready_timeout_seconds) <= 60:
        raise ValueError("ready_timeout_seconds must be in (0, 60]")
    if not 0 < float(gateway_timeout_seconds) <= 60:
        raise ValueError("gateway_timeout_seconds must be in (0, 60]")
    policy_bundle = policy_loader(
        source_root=config.entrypoint_config.source_root,
        plugin_root=config.plugin_root,
    )
    protocol = protocol_factory(
        database_path=config.database_path,
        codex_home=config.codex_home,
        controller_lock_path=config.state_home / "controller.lock",
    )
    proxy = _LifecycleHandlerProxyV2(protocol.handle)
    server = server_factory(
        socket_path=config.state_home / "controller.sock",
        lock_path=config.state_home / "controller.lock",
        codex_home=config.codex_home,
        state_home=config.state_home,
        database_id=config.database_id,
        activation_id=config.activation_id,
        activation_fingerprint=config.activation_fingerprint,
        compatibility_fingerprint=config.compatibility_fingerprint,
        routing_policy_fingerprint=config.routing_policy_fingerprint,
        bundled_catalog_fingerprint=config.bundled_catalog_fingerprint,
        instance_id="ci2_" + secrets.token_hex(16),
        controller_start_id=config.controller_start_id,
        control_epoch=1,
        registrar=lambda _controller: None,
    )
    thread: threading.Thread | None = None
    health: _AdoptedCandidateHealthV2 | None = None
    application: Any | None = None
    ready_channel: Any | None = None
    try:
        if ready_bootstrap is not None:
            _validate_ready_bootstrap_v2(config, ready_bootstrap)
            if not callable(ready_channel_starter):
                raise TypeError("ready_channel_starter must be callable")
        server.bind_lifecycle_handler(proxy)
        candidate = server.start_candidate(database_path=config.database_path)
        if ready_bootstrap is not None:
            ready_action, readiness_token = ready_bootstrap.consume()
            ready_channel = ready_channel_starter(
                action=ready_action,
                readiness_token=readiness_token,
                database_path=config.database_path,
                controller=candidate,
            )
        thread = threading.Thread(
            target=server.serve_forever,
            name=(
                "codex-smart-candidate-v2-"
                + config.activation_id.removeprefix("act2_")[:12]
            ),
            daemon=True,
        )
        thread.start()
        accept_timeout = float(ready_timeout_seconds)
        if ready_channel is not None:
            registration_timeout = min(
                float(ready_timeout_seconds),
                float(ready_channel.remaining_seconds()),
            )
            if (
                registration_timeout <= 0
                or not ready_channel.wait_until_registered(registration_timeout)
            ):
                _fail(
                    "CANDIDATE_REGISTRATION_TIMEOUT",
                    "родитель не получил точную регистрацию кандидата до срока",
                )
            accept_timeout = min(
                float(ready_timeout_seconds),
                float(ready_channel.remaining_seconds()),
            )
        accepted = (
            server.wait_until_ready(accept_timeout)
            if ready_channel is None and accept_timeout > 0
            else _wait_for_candidate_accept_v2(
                server=server,
                ready_channel=ready_channel,
                timeout_seconds=accept_timeout,
            )
        )
        if not accepted:
            _fail(
                "CANDIDATE_ACCEPT_TIMEOUT",
                "кандидат не получил долговечную команду controller_accept",
            )
        if ready_channel is not None:
            ready_channel.mark_accepted()
        decision = _wait_for_gateway_ready_v2(
            config,
            decision_provider=decision_provider,
            timeout_seconds=float(gateway_timeout_seconds),
        )
        health = _AdoptedCandidateHealthV2(
            decision=decision,
            server=server,
            thread=thread,
            proxy=proxy,
        )
        application = full_controller_starter(
            config.entrypoint_config,
            policy_bundle=policy_bundle,
            dispatcher_factory=None,
            dispatcher_factory_builder=dispatcher_factory_builder,
            bootstrapper=lambda **_arguments: health,
            decision_provider=decision_provider,
        )
        signal_installer(application)
        application.wait()
        return application
    finally:
        if ready_channel is not None:
            ready_channel.close()
        if application is not None:
            application.close()
        elif health is not None:
            health.close()
        else:
            server.close()
            if thread is not None:
                thread.join(timeout=2.0)


def _validate_ready_bootstrap_v2(
    config: CandidateControllerConfigV2,
    bootstrap: CandidateReadyBootstrapV2,
) -> None:
    if not isinstance(bootstrap, CandidateReadyBootstrapV2):
        raise TypeError("ready_bootstrap must be CandidateReadyBootstrapV2")
    action = bootstrap.action
    if (
        action.operation_id != config.operation_id
        or action.controller_start_id != config.controller_start_id
        or action.controller_identity != config.controller_identity
        or action.activation_id != config.activation_id
        or action.activation_fingerprint != config.activation_fingerprint
        or action.database_id != config.database_id
        or action.argv[1]
        != str((config.plugin_root / "controller" / "server.py").absolute())
        or action.argv[2] != "--serve-candidate-v2"
        or action.snapshot_fingerprint
        != config.activation_document["identity"]["codexSnapshot"]["sha256"]
        or action.private_ready_channel_path.parent != config.state_home
    ):
        _fail(
            "CANDIDATE_READY_ACTION_MISMATCH",
            "долговечное действие ready-канала отличается от конфигурации кандидата",
        )


def _wait_for_candidate_accept_v2(
    *,
    server: Any,
    ready_channel: Any,
    timeout_seconds: float,
) -> bool:
    if timeout_seconds <= 0:
        return False
    deadline = time.monotonic() + timeout_seconds
    while True:
        state = getattr(ready_channel, "state", None)
        if state in {"FAILED", "EXPIRED", "CLOSED"}:
            _fail(
                "CANDIDATE_READY_CHANNEL_FAILED",
                f"ready-канал завершился до controller_accept: {state}",
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if server.wait_until_ready(min(0.05, remaining)):
            return True


def _wait_for_gateway_ready_v2(
    config: CandidateControllerConfigV2,
    *,
    decision_provider: Callable[[], Any] | None,
    timeout_seconds: float,
) -> Any:
    provider = decision_provider
    if provider is None:
        resolver = ActivationResolver(
            layout=GatewayLayout.for_codex_home(config.codex_home),
            wrapper=config.wrapper,
            snapshot_verifier=_default_snapshot_verifier,
            controller_probe=_unix_controller_probe,
        )
        provider = resolver.resolve
    if not callable(provider):
        raise TypeError("decision_provider must be callable")
    deadline = time.monotonic() + timeout_seconds
    last_reason = "GATEWAY_NOT_READY"
    while True:
        decision = provider()
        binding = getattr(decision, "runtime_binding", None)
        state = getattr(decision, "state", GatewayState.READY if binding else None)
        if (
            binding is not None
            and state in {GatewayState.READY, "READY", None}
            and Path(binding.state_home) == config.state_home
            and Path(binding.database_path) == config.database_path
        ):
            return decision
        last_reason = str(getattr(decision, "reason_code", last_reason))
        if time.monotonic() >= deadline:
            _fail(
                "CANDIDATE_GATEWAY_TIMEOUT",
                f"шлюз не принял кандидата: {last_reason}",
            )
        time.sleep(0.05)


def _private_directory(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "путь должен быть абсолютным Path")
    try:
        info = os.lstat(path)
    except OSError as error:
        raise CandidateControllerV2Error(code, f"каталог недоступен: {path}") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail(code, f"каталог не является частным: {path}")
    return path.absolute()


def _private_directory_from_environment(
    environment: Mapping[str, str], name: str, code: str
) -> Path:
    raw = environment.get(name)
    if type(raw) is not str or not raw or not Path(raw).is_absolute():
        _fail(code, f"{name} должен быть абсолютным путём")
    return _private_directory(Path(raw), code)


def _owned_codex_home_from_environment(
    environment: Mapping[str, str], name: str, code: str
) -> Path:
    raw = environment.get(name)
    if type(raw) is not str or not raw or not Path(raw).is_absolute():
        _fail(code, f"{name} должен быть абсолютным путём")
    path = Path(raw)
    try:
        info = os.lstat(path)
    except OSError as error:
        raise CandidateControllerV2Error(
            code, f"каталог недоступен: {path}"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) not in {0o700, 0o755}
    ):
        _fail(code, f"CODEX_HOME имеет недопустимую идентичность: {path}")
    return path.absolute()


def _executable_from_environment(
    environment: Mapping[str, str], name: str, code: str
) -> Path:
    raw = environment.get(name)
    if type(raw) is not str or not raw or not Path(raw).is_absolute():
        _fail(code, f"{name} должен быть абсолютным путём")
    return _private_regular_file(Path(raw), code, executable=True)


def _private_regular_file(path: Path, code: str, *, executable: bool) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code, "путь должен быть абсолютным Path")
    try:
        info = os.lstat(path)
    except OSError as error:
        raise CandidateControllerV2Error(code, f"файл недоступен: {path}") from error
    allowed_modes = {0o500, 0o700} if executable else {0o600}
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in allowed_modes
        or (executable and not os.access(path, os.X_OK))
    ):
        _fail(code, f"файл имеет небезопасную идентичность: {path}")
    return path.absolute()


def _read_private_canonical_json(path: Path, code: str) -> dict[str, Any]:
    path = _private_regular_file(path, code, executable=False)
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateControllerV2Error(code, f"неверный JSON: {path}") from error
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        _fail(code, "управляющий документ должен быть каноническим объектом JSON")
    return value


def _environment_identifier(
    environment: Mapping[str, str],
    name: str,
    pattern: re.Pattern[str],
    code: str,
) -> str:
    value = environment.get(name)
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, f"{name} имеет неверную форму")
    return value


def _identity_sha256(identity: Mapping[str, Any], name: str) -> str:
    value = identity.get(name)
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail("CANDIDATE_ACTIVATION_INVALID", f"identity.{name} не является SHA-256")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _fail(code: str, message: str) -> None:
    raise CandidateControllerV2Error(code, message)


__all__ = [
    "CandidateControllerConfigV2",
    "CandidateControllerV2Error",
    "load_candidate_controller_config_v2",
    "serve_candidate_controller_v2",
]
