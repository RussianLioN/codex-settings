"""Ограниченный запуск полноценного контроллера перед корневым Codex v2."""

from __future__ import annotations

import ctypes
import math
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Protocol

from .activation_gateway_v2 import GatewayDecision, GatewayState
from . import operation_deadline_v2
from . import operation_process_group_supervisor_v2


_MAX_WAIT_SECONDS = 120.0
_MAX_POLL_SECONDS = 0.5
_SAFE_INHERITED_ENVIRONMENT = (
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


@dataclass
class ControllerSupervisorV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class SupervisorStateV2(str, Enum):
    READY = "READY"
    ORDINARY = "ORDINARY"


@dataclass(frozen=True)
class ControllerSpawnSpecV2:
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    nonblocking: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.argv) is not tuple
            or len(self.argv) != 3
            or not all(type(item) is str and item for item in self.argv)
            or self.argv[2] != "--serve-v2"
        ):
            _fail("INVALID_SPAWN_SPEC", "controller argv differs")
        if not isinstance(self.cwd, Path) or not self.cwd.is_absolute():
            _fail("INVALID_SPAWN_SPEC", "controller cwd must be absolute")
        if self.nonblocking is not True:
            _fail("INVALID_SPAWN_SPEC", "controller spawn must be nonblocking")
        if not isinstance(self.environment, Mapping) or not all(
            type(name) is str
            and type(value) is str
            and name
            and "\0" not in name
            and "\0" not in value
            for name, value in self.environment.items()
        ):
            _fail("INVALID_SPAWN_SPEC", "controller environment is invalid")
        forbidden = [
            name
            for name in self.environment
            if name.startswith(
                ("CODEX_SMART_", "CODEX_ADAPTIVE_", "CODEX_COORDINATOR_")
            )
            or name == "CODEX_REAL_BIN"
        ]
        if forbidden:
            _fail("INVALID_SPAWN_SPEC", "controller environment contains smart secrets")
        for name in ("CODEX_HOME", "CODEX_V2_STATE_HOME"):
            value = self.environment.get(name)
            if type(value) is not str or not Path(value).is_absolute():
                _fail(
                    "INVALID_SPAWN_SPEC",
                    f"controller environment requires absolute {name}",
                )


@dataclass(frozen=True)
class ControllerSupervisorResultV2:
    state: SupervisorStateV2
    reason_code: str
    executable: Path
    gateway_decision: GatewayDecision
    command_socket: Path
    spawn_attempted: bool
    spawn_succeeded: bool
    observation_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.gateway_decision, GatewayDecision):
            raise TypeError("gateway_decision must be GatewayDecision")
        if not self.executable.is_absolute() or not self.command_socket.is_absolute():
            raise ValueError("supervisor result paths must be absolute")
        if self.state is SupervisorStateV2.READY:
            if self.gateway_decision.state is not GatewayState.READY:
                raise ValueError("READY supervisor requires READY activation")
            if self.reason_code != "READY":
                raise ValueError("READY supervisor reason differs")
        if self.spawn_succeeded and not self.spawn_attempted:
            raise ValueError("successful spawn requires an attempt")
        if type(self.observation_count) is not int or self.observation_count < 1:
            raise ValueError("observation_count must be positive")

    @property
    def smart_enabled(self) -> bool:
        return self.state is SupervisorStateV2.READY


class ResolverV2(Protocol):
    def resolve(self) -> GatewayDecision: ...


CommandProbeV2 = Callable[[Path], bool]
SpawnControllerV2 = Callable[[ControllerSpawnSpecV2], object]


class ControllerSupervisorV2:
    """Делает не более одной попытки запуска и ждёт два доказательства готовности."""

    def __init__(
        self,
        *,
        resolver: ResolverV2,
        manifest_path: Path,
        state_home: Path,
        codex_home: Path,
        plugin_root: Path,
        command_probe: CommandProbeV2 | None = None,
        spawn: SpawnControllerV2 | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        source_environment: Mapping[str, str] | None = None,
        python_executable: Path = Path(sys.executable),
        wait_timeout_seconds: float = 3.0,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if not callable(getattr(resolver, "resolve", None)):
            _fail("INVALID_CONFIGURATION", "resolver must provide resolve()")
        if command_probe is not None and not callable(command_probe):
            _fail("INVALID_CONFIGURATION", "command_probe must be callable")
        if spawn is not None and not callable(spawn):
            _fail("INVALID_CONFIGURATION", "spawn must be callable")
        if not callable(clock) or not callable(sleep):
            _fail("INVALID_CONFIGURATION", "clock and sleep must be callable")
        self.manifest_path = _absolute_path(manifest_path, "manifest_path")
        self.state_home = _private_directory(state_home, "state_home")
        self.codex_home = _owned_directory(codex_home, "codex_home")
        self.plugin_root = _owned_directory(plugin_root, "plugin_root").resolve()
        self.python_executable = _owned_executable(
            python_executable,
            "python_executable",
        ).resolve()
        controller_entrypoint = self.plugin_root / "controller" / "server.py"
        _owned_regular_file(controller_entrypoint, "controller entrypoint")
        _bounded_number(
            wait_timeout_seconds,
            minimum=0.01,
            maximum=_MAX_WAIT_SECONDS,
            name="wait_timeout_seconds",
        )
        _bounded_number(
            poll_interval_seconds,
            minimum=0.001,
            maximum=min(_MAX_POLL_SECONDS, float(wait_timeout_seconds)),
            name="poll_interval_seconds",
        )
        source = dict(os.environ if source_environment is None else source_environment)
        if not all(
            type(name) is str and type(value) is str for name, value in source.items()
        ):
            _fail("INVALID_CONFIGURATION", "source environment must contain strings")

        self.resolver = resolver
        self.command_probe = command_probe or probe_controller_command_socket_v2
        self.spawn = spawn or spawn_controller_process_v2
        self.clock = clock
        self.sleep = sleep
        self.source_environment = source
        self.wait_timeout_seconds = float(wait_timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.command_socket = self.state_home / "command.sock"

    def ensure(self) -> ControllerSupervisorResultV2:
        """Возвращает READY только после активации и доступности частного сокета."""

        initial = self._resolve_required()
        observations = 1
        if self._is_ready(initial):
            return self._result(
                SupervisorStateV2.READY,
                "READY",
                initial,
                spawn_attempted=False,
                spawn_succeeded=False,
                observations=observations,
            )
        if not _owned_manifest_exists(self.manifest_path):
            reason_code = (
                initial.reason_code
                if initial.state is GatewayState.ORDINARY
                else "COMMAND_UNAVAILABLE"
            )
            return self._result(
                SupervisorStateV2.ORDINARY,
                reason_code,
                initial,
                spawn_attempted=False,
                spawn_succeeded=False,
                observations=observations,
            )

        spawn_attempted = True
        spawn_succeeded = False
        spawned_process: object | None = None
        try:
            spawned_process = self.spawn(self.spawn_spec())
            spawn_succeeded = True
        except Exception:
            # Другой процесс оболочки мог одновременно запустить владельца.
            pass

        with _reject_supervised_spawn_on_error_v2(spawned_process):
            operation_deadline = (
                operation_deadline_v2.current_operation_deadline_v2()
            )
            wait_timeout_seconds = self.wait_timeout_seconds
            if operation_deadline is not None:
                wait_timeout_seconds = (
                    operation_deadline.bounded_timeout_seconds(
                        local_cap_seconds=self.wait_timeout_seconds
                    )
                )
            started_at = self._now()
            deadline = started_at + wait_timeout_seconds
            maximum_observations = (
                math.ceil(wait_timeout_seconds / self.poll_interval_seconds)
                + 2
            )
            last = initial
            for _index in range(maximum_observations):
                if operation_deadline is not None:
                    operation_deadline.checkpoint()
                candidate = self._resolve_optional(last)
                last = candidate
                observations += 1
                if self._is_ready(candidate):
                    _finish_supervised_spawn_v2(
                        spawned_process,
                        accepted=True,
                    )
                    return self._result(
                        SupervisorStateV2.READY,
                        "READY",
                        candidate,
                        spawn_attempted=spawn_attempted,
                        spawn_succeeded=spawn_succeeded,
                        observations=observations,
                    )
                now = self._now()
                remaining = deadline - now
                if remaining <= 0:
                    break
                self.sleep(min(self.poll_interval_seconds, remaining))

            _finish_supervised_spawn_v2(spawned_process, accepted=False)
            return self._result(
                SupervisorStateV2.ORDINARY,
                "CONTROLLER_NOT_READY",
                last,
                spawn_attempted=spawn_attempted,
                spawn_succeeded=spawn_succeeded,
                observations=observations,
            )

    def spawn_spec(self) -> ControllerSpawnSpecV2:
        entrypoint = (self.plugin_root / "controller" / "server.py").resolve()
        environment = _closed_controller_environment(
            self.source_environment,
            codex_home=self.codex_home,
            state_home=self.state_home,
        )
        return ControllerSpawnSpecV2(
            argv=(
                str(self.python_executable),
                str(entrypoint),
                "--serve-v2",
            ),
            cwd=self.plugin_root,
            environment=MappingProxyType(environment),
        )

    def _resolve_required(self) -> GatewayDecision:
        try:
            decision = self.resolver.resolve()
        except Exception as exc:
            raise ControllerSupervisorV2Error(
                "RESOLVER_UNAVAILABLE",
                "activation resolver did not return a fallback decision",
            ) from exc
        return _gateway_decision(decision)

    def _resolve_optional(self, fallback: GatewayDecision) -> GatewayDecision:
        try:
            return _gateway_decision(self.resolver.resolve())
        except Exception:
            return fallback

    def _is_ready(self, decision: GatewayDecision) -> bool:
        if decision.state is not GatewayState.READY:
            return False
        try:
            return self.command_probe(self.command_socket) is True
        except Exception:
            return False

    def _now(self) -> float:
        value = self.clock()
        if (
            type(value) not in {int, float}
            or type(value) is bool
            or not math.isfinite(float(value))
        ):
            _fail("INVALID_CLOCK", "clock must return a finite number")
        return float(value)

    def _result(
        self,
        state: SupervisorStateV2,
        reason_code: str,
        decision: GatewayDecision,
        *,
        spawn_attempted: bool,
        spawn_succeeded: bool,
        observations: int,
    ) -> ControllerSupervisorResultV2:
        return ControllerSupervisorResultV2(
            state=state,
            reason_code=reason_code,
            executable=decision.executable,
            gateway_decision=decision,
            command_socket=self.command_socket,
            spawn_attempted=spawn_attempted,
            spawn_succeeded=spawn_succeeded,
            observation_count=observations,
        )


def spawn_controller_process_v2(spec: ControllerSpawnSpecV2) -> subprocess.Popen:
    """Запускает владельца без ожидания и без унаследованных файловых дескрипторов."""

    if not isinstance(spec, ControllerSpawnSpecV2):
        raise TypeError("spec must be ControllerSpawnSpecV2")
    supervisor = (
        operation_process_group_supervisor_v2.
        current_process_group_supervisor_v2()
    )
    if supervisor is None:
        return subprocess.Popen(
            spec.argv,
            cwd=spec.cwd,
            env=dict(spec.environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    lease = supervisor.spawn_transient(
        label="controller-supervisor",
        argv=spec.argv,
        cwd=spec.cwd,
        env=dict(spec.environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    process = lease.process
    setattr(process, "_codex_process_supervisor_v2", supervisor)
    setattr(process, "_codex_process_lease_v2", lease)
    return process


@contextmanager
def _reject_supervised_spawn_on_error_v2(
    process: object | None,
) -> Iterator[None]:
    try:
        yield
    except BaseException:
        if not bool(getattr(process, "_codex_process_finishing_v2", False)):
            _finish_supervised_spawn_v2(process, accepted=False)
        raise


def _finish_supervised_spawn_v2(
    process: object | None,
    *,
    accepted: bool,
) -> None:
    if process is None:
        return
    supervisor = getattr(process, "_codex_process_supervisor_v2", None)
    lease = getattr(process, "_codex_process_lease_v2", None)
    if supervisor is None and lease is None:
        return
    if not isinstance(
        supervisor,
        operation_process_group_supervisor_v2.
        OperationProcessGroupSupervisorV2,
    ) or not isinstance(
        lease,
        operation_process_group_supervisor_v2.TransientProcessLeaseV2,
    ):
        _fail("INVALID_PROCESS_OWNERSHIP", "spawn ownership is malformed")
    setattr(process, "_codex_process_finishing_v2", True)
    poll = getattr(process, "poll", None)
    return_code = poll() if callable(poll) else None
    deadline = operation_deadline_v2.current_operation_deadline_v2()
    if deadline is None:
        deadline = operation_deadline_v2.OperationDeadlineV2.start(
            operation="controller-supervisor-cleanup",
            timeout_seconds=6,
            timeout_code="CONTROLLER_SUPERVISOR_CLEANUP_TIMEOUT",
        )
    if accepted and return_code is None:
        supervisor.release_after_acceptance(lease)
    elif return_code is not None:
        released = supervisor.release_after_verified_exit(
            lease,
            deadline=deadline,
            reason_code="CONTROLLER_SPAWN_EXITED",
        )
        if isinstance(
            released,
            operation_process_group_supervisor_v2.
            ProcessGroupTerminationResultV2,
        ):
            _fail(
                "PROCESS_CLEANUP_REQUIRED",
                "controller spawn left a live descendant",
            )
    else:
        result = supervisor.terminate_transient(
            lease,
            deadline=deadline,
            max_wait_seconds=5,
            reason_code="CONTROLLER_NOT_READY",
        )
        if not result.continuation_allowed:
            _fail(
                "PROCESS_CLEANUP_REQUIRED",
                "controller process cleanup remains pending",
            )
    delattr(process, "_codex_process_supervisor_v2")
    delattr(process, "_codex_process_lease_v2")
    delattr(process, "_codex_process_finishing_v2")


def probe_controller_command_socket_v2(socket_path: Path) -> bool:
    """Проверяет частный сокет и идентификатор пользователя без смысловой команды."""

    try:
        path = _absolute_path(socket_path, "command socket")
        info = os.lstat(path)
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.25)
            connection.connect(str(path))
            return _peer_uid(connection) == os.getuid()
    except (ControllerSupervisorV2Error, OSError, ValueError):
        return False


def _closed_controller_environment(
    source: Mapping[str, str],
    *,
    codex_home: Path,
    state_home: Path,
) -> dict[str, str]:
    result = {
        "PATH": os.defpath,
        "CODEX_HOME": str(codex_home),
        "CODEX_V2_STATE_HOME": str(state_home),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1",
    }
    for name in _SAFE_INHERITED_ENVIRONMENT:
        value = source.get(name)
        if type(value) is str and value and "\0" not in value:
            result[name] = value
    return result


def _owned_manifest_exists(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return bool(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.getuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
    )


def _gateway_decision(value: Any) -> GatewayDecision:
    if not isinstance(value, GatewayDecision):
        _fail("INVALID_RESOLVER_RESULT", "resolver returned another type")
    return value


def _absolute_path(path: Path, name: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("INVALID_CONFIGURATION", f"{name} must be an absolute Path")
    return path


def _owned_directory(path: Path, name: str) -> Path:
    absolute = _absolute_path(path, name)
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        raise ControllerSupervisorV2Error(
            "INVALID_CONFIGURATION", f"{name} is unavailable"
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        _fail("INVALID_CONFIGURATION", f"{name} must be an owned directory")
    return absolute


def _private_directory(path: Path, name: str) -> Path:
    absolute = _owned_directory(path, name)
    info = os.lstat(absolute)
    if stat.S_IMODE(info.st_mode) != 0o700:
        _fail("INVALID_CONFIGURATION", f"{name} must have mode 0700")
    return absolute


def _owned_regular_file(path: Path, name: str) -> Path:
    absolute = _absolute_path(path, name)
    try:
        info = os.lstat(absolute)
    except OSError as exc:
        raise ControllerSupervisorV2Error(
            "INVALID_CONFIGURATION", f"{name} is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
    ):
        _fail("INVALID_CONFIGURATION", f"{name} must be an owned regular file")
    return absolute


def _owned_executable(path: Path, name: str) -> Path:
    absolute = _owned_regular_file(path.resolve(strict=True), name)
    if not os.access(absolute, os.X_OK):
        _fail("INVALID_CONFIGURATION", f"{name} must be executable")
    return absolute


def _bounded_number(
    value: Any,
    *,
    minimum: float,
    maximum: float,
    name: str,
) -> None:
    if (
        type(value) not in {int, float}
        or type(value) is bool
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        _fail(
            "INVALID_CONFIGURATION",
            f"{name} must be between {minimum} and {maximum}",
        )


def _peer_uid(connection: socket.socket) -> int:
    if hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    library = ctypes.CDLL(None, use_errno=True)
    getpeereid = getattr(library, "getpeereid", None)
    if getpeereid is None:
        _fail("PEER_CREDENTIALS_UNAVAILABLE", "getpeereid is unavailable")
    uid = ctypes.c_uint()
    gid = ctypes.c_uint()
    result = getpeereid(
        connection.fileno(),
        ctypes.byref(uid),
        ctypes.byref(gid),
    )
    if result != 0:
        _fail("PEER_CREDENTIALS_FAILED", "getpeereid failed")
    return int(uid.value)


def _fail(code: str, message: str) -> None:
    raise ControllerSupervisorV2Error(code, message)


__all__ = [
    "CommandProbeV2",
    "ControllerSpawnSpecV2",
    "ControllerSupervisorResultV2",
    "ControllerSupervisorV2",
    "ControllerSupervisorV2Error",
    "SpawnControllerV2",
    "SupervisorStateV2",
    "probe_controller_command_socket_v2",
    "spawn_controller_process_v2",
]
