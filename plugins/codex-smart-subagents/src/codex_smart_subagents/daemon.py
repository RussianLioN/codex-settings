"""Controller process lifecycle and production composition entrypoint."""

from __future__ import annotations

import os
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .controller import (
    ControllerClient,
    RELEASE,
    PROTOCOL_VERSION,
    RuntimePaths,
    WireProtocolError,
)
from .identity import sha256_text


@dataclass
class ControllerStartError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ControllerProcessConfig:
    codex_home: Path
    state_home: Path
    catalog_path: Path
    controller_executable: Path
    real_codex: Path

    def __post_init__(self) -> None:
        for name in (
            "codex_home",
            "state_home",
            "catalog_path",
            "controller_executable",
            "real_codex",
        ):
            value = getattr(self, name)
            if not value.is_absolute():
                raise ValueError(f"{name} must be absolute")
        if not self.codex_home.is_dir():
            raise ValueError("codex_home must exist")
        if not self.catalog_path.is_file():
            raise ValueError("catalog_path must exist")
        for name in ("controller_executable", "real_codex"):
            value = getattr(self, name)
            if not value.is_file() or not os.access(value, os.X_OK):
                raise ValueError(f"{name} must be executable")

    @property
    def paths(self) -> RuntimePaths:
        return RuntimePaths.for_codex_home(
            str(self.codex_home.resolve()),
            state_home=self.state_home.resolve(),
        )

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
        *,
        plugin_root: Path,
    ) -> "ControllerProcessConfig":
        codex_home = Path(
            environ.get("CODEX_HOME", str(Path.home() / ".codex"))
        ).expanduser().resolve()
        state_home = Path(
            environ.get(
                "XDG_STATE_HOME",
                str(Path.home() / ".local" / "state"),
            )
        ).expanduser().resolve()
        catalog = Path(
            environ.get(
                "CODEX_ADAPTIVE_CATALOG",
                str(plugin_root / "config" / "adaptive-subagents.toml"),
            )
        ).expanduser().resolve()
        controller = Path(
            environ.get(
                "CODEX_SMART_CONTROLLER_BIN",
                str(plugin_root / "bin" / "codex-smart-subagents-controller"),
            )
        ).expanduser().resolve()
        real_codex = Path(
            environ.get("CODEX_REAL_BIN", "/opt/homebrew/bin/codex")
        ).expanduser().resolve()
        return cls(
            codex_home=codex_home,
            state_home=state_home,
            catalog_path=catalog,
            controller_executable=controller,
            real_codex=real_codex,
        )


class Process(Protocol):
    def poll(self) -> int | None:
        ...


def controller_environment(
    source: Mapping[str, str],
    config: ControllerProcessConfig,
) -> dict[str, str]:
    del source
    return {
        "CODEX_HOME": str(config.codex_home.resolve()),
        "XDG_STATE_HOME": str(config.state_home.resolve()),
        "CODEX_ADAPTIVE_CATALOG": str(config.catalog_path.resolve()),
        "CODEX_REAL_BIN": str(config.real_codex.resolve()),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        "PYTHONUNBUFFERED": "1",
    }


def spawn_controller(
    config: ControllerProcessConfig,
    environ: Mapping[str, str],
) -> Process:
    paths = config.paths
    log_dir = paths.namespace_dir / "logs"
    _prepare_private_directory(paths.base_dir)
    _prepare_private_directory(paths.namespace_dir)
    _prepare_private_directory(log_dir)
    log_path = log_dir / "controller.log"
    descriptor = os.open(
        log_path,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT,
        0o600,
    )
    os.fchmod(descriptor, 0o600)
    log_stream = os.fdopen(descriptor, "ab", buffering=0)
    try:
        process = subprocess.Popen(
            [str(config.controller_executable.resolve()), "--serve"],
            stdin=subprocess.DEVNULL,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            cwd=config.paths.namespace_dir,
            env=controller_environment(environ, config),
            shell=False,
            close_fds=True,
            start_new_session=True,
            restore_signals=True,
            umask=0o077,
        )
    except BaseException:
        log_stream.close()
        raise
    log_stream.close()
    return process


def ensure_controller_running(
    config: ControllerProcessConfig,
    *,
    shell_session_id: str,
    environ: Mapping[str, str],
    timeout_seconds: float = 5,
    client_factory: Callable[..., ControllerClient] = ControllerClient,
    spawn: Callable[
        [ControllerProcessConfig, Mapping[str, str]],
        Process,
    ] = spawn_controller,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    if not shell_session_id:
        raise ControllerStartError(
            "INVALID_SESSION",
            "adaptive shell session identifier is missing",
        )
    client = client_factory(
        socket_path=config.paths.socket_path,
        codex_home_hash=sha256_text(str(config.codex_home.resolve())),
        shell_session_id=shell_session_id,
        timeout=min(1.0, timeout_seconds),
    )
    try:
        _verify_health(client.call("health", {}), config)
        return
    except WireProtocolError as exc:
        if exc.code != "CONTROLLER_UNAVAILABLE":
            raise ControllerStartError(exc.code, exc.message) from exc

    process = spawn(config, environ)
    deadline = time.monotonic() + timeout_seconds
    last_error = "controller did not become ready"
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            raise ControllerStartError(
                "CONTROLLER_START_FAILED",
                f"controller exited with status {returncode}",
            )
        try:
            _verify_health(client.call("health", {}), config)
            return
        except WireProtocolError as exc:
            last_error = exc.message
            if exc.code != "CONTROLLER_UNAVAILABLE":
                raise ControllerStartError(exc.code, exc.message) from exc
        sleep(0.05)
    raise ControllerStartError("CONTROLLER_START_TIMEOUT", last_error)


def _verify_health(
    result: dict[str, object],
    config: ControllerProcessConfig,
) -> None:
    expected = {
        "protocolVersion": PROTOCOL_VERSION,
        "release": RELEASE,
        "namespace": config.paths.namespace,
    }
    if result != expected:
        raise ControllerStartError(
            "CONTROLLER_HEALTH_MISMATCH",
            "controller health identity does not match this installation",
        )


def _prepare_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ControllerStartError(
            "UNSAFE_STATE_DIRECTORY",
            f"state directory is a symlink: {path}",
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    metadata = path.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ControllerStartError(
            "UNSAFE_STATE_DIRECTORY",
            f"state directory is not private: {path}",
        )
