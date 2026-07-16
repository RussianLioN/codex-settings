"""Live, fail-closed verification of Codex permission profiles."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import tempfile
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence

from .permissions import (
    REQUIRED_CANARY_CHECKS,
    CanaryEvidence,
    CanaryRequest,
)


FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
SANDBOX_RESULT_PREFIX = "CODEX_PERMISSION_CANARY_V1:"
EXEC_RESULT_PREFIX = "CODEX_EXEC_PERMISSION_CANARY_V1:"
SANDBOX_CHECKS = (
    "snapshot_read_allowed",
    "snapshot_write_denied",
    "secret_read_denied",
    "source_git_read_denied",
    "controller_database_read_denied",
    "source_worktree_write_denied",
    "external_network_denied",
    "dns_denied",
    "udp_denied",
    "loopback_denied",
    "controller_socket_denied",
)
FEATURES_DISABLED_FOR_CANARY = (
    "apps",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "enable_fanout",
    "enable_mcp_apps",
    "hooks",
    "in_app_browser",
    "memories",
    "multi_agent",
    "multi_agent_v2",
    "plugins",
    "remote_plugin",
    "shell_snapshot",
    "skill_mcp_dependency_install",
    "workspace_dependencies",
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"(?:codex(?:-cli)?\s+)?([0-9]+\.[0-9]+\.[0-9]+)\s*")
_PROFILE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_NONCE = re.compile(r"ce1_[A-Za-z0-9_-]{43}")
_DENIED_ERRNOS = frozenset((errno.EACCES, errno.EPERM))
_ALLOWED_AUTH_ENVIRONMENT = frozenset(("OPENAI_API_KEY",))


@dataclass
class LiveCanaryError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ManagedConfigState:
    sha256: str
    legacy_sandbox_mode: bool

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("managed configuration hash must be a SHA-256")
        if type(self.legacy_sandbox_mode) is not bool:
            raise ValueError("legacy_sandbox_mode must be boolean")


class ManagedConfigInspector(Protocol):
    def inspect(self) -> ManagedConfigState:
        """Return the fingerprint and legacy-mode status of the loaded policy."""


class FileManagedConfigInspector:
    """Re-read an explicit active config stack and detect legacy sandbox keys."""

    def __init__(self, paths: Sequence[Path]) -> None:
        try:
            candidates = tuple(paths)
        except TypeError as exc:
            raise ValueError("managed config paths must be a sequence") from exc
        if len(candidates) > 32:
            raise ValueError("managed config path count exceeds the limit")
        resolved = tuple(_safe_config_file(path) for path in candidates)
        if len(set(resolved)) != len(resolved):
            raise ValueError("managed config paths must be unique")
        self._paths = tuple(sorted(resolved, key=os.fspath))

    def inspect(self) -> ManagedConfigState:
        digest = hashlib.sha256(b"codex-managed-config-v1\0")
        legacy = False
        for path in self._paths:
            contents = _read_stable_file(path, maximum=1024 * 1024)
            try:
                parsed = tomllib.loads(contents.decode("utf-8", errors="strict"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                raise LiveCanaryError(
                    "MANAGED_CONFIG_INVALID",
                    f"managed configuration is invalid: {path.name}",
                ) from exc
            encoded_path = os.fsencode(path)
            digest.update(len(encoded_path).to_bytes(4, "big"))
            digest.update(encoded_path)
            digest.update(len(contents).to_bytes(8, "big"))
            digest.update(contents)
            legacy = legacy or (
                "sandbox_mode" in parsed
                or "sandbox_workspace_write" in parsed
            )
        return ManagedConfigState(
            sha256=digest.hexdigest(),
            legacy_sandbox_mode=legacy,
        )


class PermissionProfile(Protocol):
    name: str
    config_overrides: Sequence[str]
    sha256: str


@dataclass(frozen=True)
class CanaryProbeTargets:
    snapshot_root: Path
    snapshot_read_file: Path
    snapshot_write_file: Path
    secret_read_file: Path
    source_git_read_file: Path
    controller_database_read_file: Path
    source_worktree_write_file: Path
    controller_socket: Path

    def __post_init__(self) -> None:
        snapshot_root = _safe_probe_root(self.snapshot_root)
        object.__setattr__(self, "snapshot_root", snapshot_root)
        regular = (
            "snapshot_read_file",
            "snapshot_write_file",
            "secret_read_file",
            "source_git_read_file",
            "controller_database_read_file",
            "source_worktree_write_file",
        )
        for field in regular:
            path = _safe_probe_file(getattr(self, field), field)
            object.__setattr__(self, field, path)
        for field in ("snapshot_read_file", "snapshot_write_file"):
            if not getattr(self, field).is_relative_to(snapshot_root):
                raise ValueError(f"{field} must be inside snapshot_root")
        controller = _safe_controller_socket(self.controller_socket)
        object.__setattr__(self, "controller_socket", controller)


@dataclass(frozen=True)
class CanaryTimeouts:
    version_seconds: float = 5.0
    sandbox_seconds: float = 15.0
    exec_seconds: float = 90.0

    def __post_init__(self) -> None:
        for name in ("version_seconds", "sandbox_seconds", "exec_seconds"):
            value = getattr(self, name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not 0 < float(value) <= 300
            ):
                raise ValueError(f"{name} must be in (0, 300]")


@dataclass(frozen=True)
class CanaryCommand:
    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    stdin: bytes
    timeout_seconds: float
    max_output_bytes: int = MAX_COMMAND_OUTPUT

    def __post_init__(self) -> None:
        if (
            not self.argv
            or not all(isinstance(value, str) and value for value in self.argv)
            or any("\0" in value for value in self.argv)
        ):
            raise ValueError("argv must be a non-empty tuple of safe strings")
        if not Path(self.argv[0]).is_absolute():
            raise ValueError("the executable in argv must be absolute")
        cwd = _safe_private_directory(self.cwd, "command cwd")
        object.__setattr__(self, "cwd", cwd)
        try:
            environment = dict(self.environment)
        except (TypeError, ValueError) as exc:
            raise ValueError("environment must be a string mapping") from exc
        if not all(
            isinstance(name, str)
            and name
            and "=" not in name
            and "\0" not in name
            and isinstance(value, str)
            and "\0" not in value
            for name, value in environment.items()
        ):
            raise ValueError("environment must be a safe string mapping")
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(environment),
        )
        if not isinstance(self.stdin, bytes):
            raise ValueError("stdin must be bytes")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0 < float(self.timeout_seconds) <= 300
        ):
            raise ValueError("timeout_seconds must be in (0, 300]")
        if (
            type(self.max_output_bytes) is not int
            or not 1024 <= self.max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if type(self.exit_code) is not int:
            raise ValueError("exit_code must be an integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("command output must be bytes")


class CommandExecutor(Protocol):
    def run(self, command: CanaryCommand) -> CommandResult:
        """Execute one shell-free, bounded command."""


class SubprocessExecutor:
    """Bounded process-group executor that never invokes a shell."""

    def run(self, command: CanaryCommand) -> CommandResult:
        try:
            process = subprocess.Popen(
                command.argv,
                cwd=command.cwd,
                env=dict(command.environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                restore_signals=True,
                umask=0o077,
            )
        except OSError as exc:
            raise LiveCanaryError("CANARY_SPAWN_FAILED", str(exc)) from exc

        stdout, stderr, reason = _collect_output(process, command)
        if reason is not None:
            raise LiveCanaryError(reason, _terminal_message(reason))
        return CommandResult(int(process.returncode), stdout, stderr)


class LivePermissionCanary:
    """Verify one immutable profile with live sandbox and Codex exec probes."""

    def __init__(
        self,
        *,
        codex_executable: Path,
        ruby_executable: Path,
        codex_home: Path,
        runtime_parent: Path,
        profile: PermissionProfile,
        managed_config_inspector: ManagedConfigInspector,
        targets: CanaryProbeTargets,
        model: str,
        reasoning_effort: str,
        executor: CommandExecutor | None = None,
        clock: Callable[[], datetime] | None = None,
        timeouts: CanaryTimeouts | None = None,
        auth_environment: Mapping[str, str] | None = None,
    ) -> None:
        self._codex = _safe_executable(codex_executable, "Codex")
        self._ruby = _safe_executable(ruby_executable, "Ruby")
        self._codex_home = _safe_owned_directory(codex_home, "CODEX_HOME")
        self._runtime_parent = _safe_private_directory(
            runtime_parent,
            "runtime parent",
        )
        self._profile_name = _profile_name(profile.name)
        self._profile_overrides = _profile_overrides(
            self._profile_name,
            profile.config_overrides,
        )
        _validate_profile_policy(
            self._profile_name,
            self._profile_overrides,
            targets.snapshot_root,
        )
        calculated = _profile_sha256(
            self._profile_name,
            self._profile_overrides,
        )
        if profile.sha256 != calculated:
            raise ValueError("profile hash does not match its exact overrides")
        self._profile_sha256 = calculated
        self._managed_config_inspector = managed_config_inspector
        self._targets = targets
        if not isinstance(model, str) or not model or len(model) > 128:
            raise ValueError("model must be a non-empty bounded string")
        if (
            not isinstance(reasoning_effort, str)
            or not reasoning_effort
            or len(reasoning_effort) > 32
        ):
            raise ValueError("reasoning_effort must be a non-empty bounded string")
        self._model = model
        self._reasoning_effort = reasoning_effort
        self._executor = executor or SubprocessExecutor()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._timeouts = timeouts or CanaryTimeouts()
        self._auth_environment = _auth_environment(auth_environment or {})

    def verify(self, request: CanaryRequest) -> CanaryEvidence:
        verified_at = _utc_now(self._clock())
        probe_id = _probe_id()
        state = self._inspect_managed_config()
        if (
            request.permission_profile != self._profile_name
            or request.profile_sha256 != self._profile_sha256
            or request.managed_config_sha256 != state.sha256
            or state.legacy_sandbox_mode
        ):
            return _failed_evidence(
                request,
                probe_id=probe_id,
                verified_at=verified_at,
                legacy_sandbox_mode=state.legacy_sandbox_mode,
            )

        with tempfile.TemporaryDirectory(
            prefix="permission-canary-",
            dir=self._runtime_parent,
        ) as raw_root:
            runtime = _Runtime.create(Path(raw_root))
            environment = self._environment(runtime)

            version = self._executor.run(
                CanaryCommand(
                    argv=(os.fspath(self._codex), "--version"),
                    cwd=runtime.work,
                    environment=environment,
                    stdin=b"",
                    timeout_seconds=self._timeouts.version_seconds,
                )
            )
            if not _version_matches(version, request.codex_version):
                return _failed_evidence(
                    request,
                    probe_id=probe_id,
                    verified_at=verified_at,
                    legacy_sandbox_mode=False,
                )

            with _NetworkFixtures() as network:
                sandbox = self._executor.run(
                    self._sandbox_command(runtime, environment, network)
                )
            sandbox_checks = _parse_sandbox_result(sandbox)
            if sandbox_checks is None:
                return _failed_evidence(
                    request,
                    probe_id=probe_id,
                    verified_at=verified_at,
                    legacy_sandbox_mode=False,
                )

            checks = {name: False for name in REQUIRED_CANARY_CHECKS}
            checks["catalog_syntax_loaded"] = True
            for name in SANDBOX_CHECKS:
                checks[name] = sandbox_checks[name]
            checks["sandbox_negative_probe"] = all(
                sandbox_checks[name] for name in SANDBOX_CHECKS
            )
            if not checks["sandbox_negative_probe"]:
                return _evidence(
                    request,
                    probe_id=probe_id,
                    verified_at=verified_at,
                    legacy_sandbox_mode=False,
                    checks=checks,
                )

            nonce = _nonce("ce1_")
            exec_command, expected_probe_command = self._exec_command(
                runtime,
                environment,
                nonce,
            )
            codex_exec = self._executor.run(exec_command)
            checks["exec_negative_probe"] = _parse_exec_result(
                codex_exec,
                nonce,
                expected_probe_command,
            )
            return _evidence(
                request,
                probe_id=probe_id,
                verified_at=verified_at,
                legacy_sandbox_mode=False,
                checks=checks,
            )

    def _inspect_managed_config(self) -> ManagedConfigState:
        try:
            state = self._managed_config_inspector.inspect()
        except Exception as exc:
            raise LiveCanaryError(
                "MANAGED_CONFIG_UNAVAILABLE",
                "managed configuration could not be inspected",
            ) from exc
        if not isinstance(state, ManagedConfigState):
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "managed configuration inspector returned malformed state",
            )
        return state

    def _environment(self, runtime: "_Runtime") -> Mapping[str, str]:
        environment = {
            "CODEX_ADAPTIVE_CHILD": "1",
            "CODEX_HOME": os.fspath(self._codex_home),
            "HOME": os.fspath(runtime.home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": FIXED_PATH,
            "TMPDIR": os.fspath(runtime.tmp),
        }
        environment.update(self._auth_environment)
        return environment

    def _sandbox_command(
        self,
        runtime: "_Runtime",
        environment: Mapping[str, str],
        network: "_NetworkFixtures",
    ) -> CanaryCommand:
        payload = {
            "controller_database_read": os.fspath(
                self._targets.controller_database_read_file
            ),
            "controller_socket": os.fspath(self._targets.controller_socket),
            "dns_address": "192.0.2.53",
            "external_address": "192.0.2.1",
            "loopback_port": network.tcp_port,
            "secret_read": os.fspath(self._targets.secret_read_file),
            "snapshot_read": os.fspath(self._targets.snapshot_read_file),
            "snapshot_write": os.fspath(self._targets.snapshot_write_file),
            "source_git_read": os.fspath(self._targets.source_git_read_file),
            "source_write": os.fspath(
                self._targets.source_worktree_write_file
            ),
            "udp_port": network.udp_port,
        }
        argv = [
            os.fspath(self._codex),
            "sandbox",
            "-P",
            self._profile_name,
            "--include-managed-config",
            "-C",
            os.fspath(runtime.work),
        ]
        for override in self._profile_overrides:
            argv.extend(("-c", override))
        argv.extend(
            (
                "--",
                os.fspath(self._ruby),
                "--disable-gems",
                "-rjson",
                "-rsocket",
                "-e",
                _SANDBOX_PROBE,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
            )
        )
        return CanaryCommand(
            argv=tuple(argv),
            cwd=runtime.work,
            environment=environment,
            stdin=b"",
            timeout_seconds=self._timeouts.sandbox_seconds,
        )

    def _exec_command(
        self,
        runtime: "_Runtime",
        environment: Mapping[str, str],
        nonce: str,
    ) -> tuple[CanaryCommand, str]:
        probe_argv = (
            os.fspath(self._ruby),
            "--disable-gems",
            "-e",
            _EXEC_PROBE,
            os.fspath(self._targets.secret_read_file),
            nonce,
        )
        exact_command = shlex.join(probe_argv)
        prompt = (
            "Выполни ровно одну команду через средство запуска команд и не "
            "добавляй других действий. Команда:\n"
            f"{exact_command}\n"
            "После завершения кратко закончи ответ."
        ).encode("utf-8")
        argv: list[str] = [
            os.fspath(self._codex),
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--ephemeral",
            "--json",
            "--skip-git-repo-check",
            "--model",
            self._model,
            "-C",
            os.fspath(runtime.work),
            "-c",
            f"model_reasoning_effort={json.dumps(self._reasoning_effort)}",
            "-c",
            'approval_policy="never"',
            "-c",
            f"default_permissions={json.dumps(self._profile_name)}",
            "-c",
            "project_root_markers=[]",
            "-c",
            "project_doc_max_bytes=0",
            "-c",
            'shell_environment_policy.inherit="none"',
            "-c",
            _shell_environment_override(runtime),
            "-c",
            "allow_login_shell=false",
            "-c",
            "agents.max_threads=1",
            "-c",
            "agents.max_depth=1",
            "-c",
            'web_search="disabled"',
        ]
        for override in self._profile_overrides:
            argv.extend(("-c", override))
        for feature in FEATURES_DISABLED_FOR_CANARY:
            argv.extend(("--disable", feature))
        return (
            CanaryCommand(
                argv=tuple(argv),
                cwd=runtime.work,
                environment=environment,
                stdin=prompt,
                timeout_seconds=self._timeouts.exec_seconds,
            ),
            exact_command,
        )


@dataclass(frozen=True)
class _Runtime:
    root: Path
    home: Path
    tmp: Path
    work: Path

    @classmethod
    def create(cls, root: Path) -> "_Runtime":
        root.chmod(0o700)
        children = []
        for name in ("home", "tmp", "work"):
            path = root / name
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            children.append(path.resolve(strict=True))
        return cls(
            root=root.resolve(strict=True),
            home=children[0],
            tmp=children[1],
            work=children[2],
        )


class _NetworkFixtures:
    def __init__(self) -> None:
        self._tcp: socket.socket | None = None
        self._udp: socket.socket | None = None
        self.tcp_port = 0
        self.udp_port = 0

    def __enter__(self) -> "_NetworkFixtures":
        try:
            self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp.bind(("127.0.0.1", 0))
            self._tcp.listen(1)
            self.tcp_port = int(self._tcp.getsockname()[1])
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.bind(("127.0.0.1", 0))
            self.udp_port = int(self._udp.getsockname()[1])
        except OSError as exc:
            self.__exit__(None, None, None)
            raise LiveCanaryError(
                "CANARY_FIXTURE_FAILED",
                "local network fixtures could not be created",
            ) from exc
        return self

    def __exit__(self, *_: object) -> None:
        if self._tcp is not None:
            self._tcp.close()
        if self._udp is not None:
            self._udp.close()


def _profile_name(value: str) -> str:
    if not isinstance(value, str) or _PROFILE.fullmatch(value) is None:
        raise ValueError("permission profile name is unsafe")
    return value


def _profile_overrides(
    name: str,
    values: Sequence[str],
) -> tuple[str, ...]:
    try:
        overrides = tuple(values)
    except TypeError as exc:
        raise ValueError("profile overrides must be a sequence") from exc
    prefix = f"permissions.{name}."
    if (
        not overrides
        or len(overrides) > 32
        or not all(
            isinstance(value, str)
            and value.startswith(prefix)
            and "\0" not in value
            and "\n" not in value
            and len(value.encode("utf-8")) <= 16 * 1024
            for value in overrides
        )
    ):
        raise ValueError("profile overrides are incomplete or unsafe")
    return overrides


def _profile_sha256(name: str, overrides: Sequence[str]) -> str:
    return hashlib.sha256(
        json.dumps(
            {"name": name, "overrides": tuple(overrides)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _validate_profile_policy(
    name: str,
    overrides: Sequence[str],
    snapshot_root: Path,
) -> None:
    try:
        parsed = tomllib.loads("\n".join(overrides))
        selected = parsed["permissions"][name]
        filesystem = selected["filesystem"]
        network = selected["network"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("permission profile overrides are not valid TOML") from exc
    expected_filesystem = {
        ":root": "deny",
        ":minimal": "read",
        ":tmpdir": "write",
        ":workspace_roots": {".": "write"},
        os.fspath(snapshot_root): "read",
    }
    if (
        not isinstance(selected, dict)
        or set(selected) != {"description", "filesystem", "network"}
        or not isinstance(selected["description"], str)
        or not selected["description"]
        or filesystem != expected_filesystem
        or network != {"enabled": False}
    ):
        raise ValueError(
            "permission profile must match the exact reader policy"
        )


def _auth_environment(values: Mapping[str, str]) -> Mapping[str, str]:
    copied = dict(values)
    if not set(copied).issubset(_ALLOWED_AUTH_ENVIRONMENT):
        raise ValueError("auth environment contains a forbidden variable")
    if not all(
        isinstance(value, str) and value and "\0" not in value
        for value in copied.values()
    ):
        raise ValueError("auth environment values must be non-empty strings")
    return MappingProxyType(copied)


def _safe_executable(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} executable must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} executable is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in (0, os.getuid())
        or metadata.st_mode & 0o111 == 0
        or metadata.st_mode & 0o022
    ):
        raise ValueError(f"{label} executable is unsafe")
    return resolved


def _safe_private_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError(f"{label} must be an owned private directory")
    return resolved


def _safe_owned_directory(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022
    ):
        raise ValueError(f"{label} must be an owned non-writable directory")
    return resolved


def _safe_probe_root(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("snapshot_root must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("snapshot_root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("snapshot_root must be an owned directory")
    return resolved


def _safe_config_file(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("managed config path must be absolute and non-symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("managed config file is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in (0, os.getuid())
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or metadata.st_size > 1024 * 1024
    ):
        raise ValueError("managed config file is unsafe")
    return resolved


def _read_stable_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LiveCanaryError(
            "MANAGED_CONFIG_UNAVAILABLE",
            f"managed configuration could not be opened: {path.name}",
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                f"managed configuration is unsafe: {path.name}",
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise LiveCanaryError(
                    "MANAGED_CONFIG_INVALID",
                    f"managed configuration is too large: {path.name}",
                )
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after:
            raise LiveCanaryError(
                "MANAGED_CONFIG_CHANGED",
                f"managed configuration changed during inspection: {path.name}",
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _safe_probe_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink file")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise ValueError(f"{label} must be an owned regular file")
    return resolved


def _safe_controller_socket(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("controller_socket must be an absolute socket path")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("controller_socket is unavailable") from exc
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("controller_socket must be an owned Unix socket")
    return resolved


def _utc_now(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LiveCanaryError(
            "CANARY_CLOCK_INVALID",
            "canary clock must be timezone-aware",
        )
    return value.astimezone(timezone.utc)


def _nonce(prefix: str) -> str:
    encoded = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
    return prefix + encoded.decode("ascii")


def _probe_id() -> str:
    return _nonce("pc1_")


def _version_matches(result: CommandResult, expected: str) -> bool:
    if result.exit_code != 0 or result.stderr:
        return False
    try:
        output = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    match = _VERSION.fullmatch(output)
    return match is not None and match.group(1) == expected


def _parse_sandbox_result(
    result: CommandResult,
) -> dict[str, bool] | None:
    if result.exit_code != 0 or result.stderr:
        return None
    try:
        text = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith(SANDBOX_RESULT_PREFIX):
        return None
    try:
        payload = json.loads(lines[0][len(SANDBOX_RESULT_PREFIX) :])
    except json.JSONDecodeError:
        return None
    if (
        not isinstance(payload, dict)
        or set(payload) != set(SANDBOX_CHECKS)
        or not all(type(payload[name]) is bool for name in SANDBOX_CHECKS)
    ):
        return None
    return {name: payload[name] for name in SANDBOX_CHECKS}


def _parse_exec_result(
    result: CommandResult,
    nonce: str,
    expected_command: str,
) -> bool:
    if result.exit_code != 0 or result.stderr or _NONCE.fullmatch(nonce) is None:
        return False
    try:
        text = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    events = []
    for line in text.splitlines():
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(event, dict):
            return False
        events.append(event)
        if len(events) > 4096:
            return False
    if not events or events[-1].get("type") != "turn.completed":
        return False
    marker = f"{EXEC_RESULT_PREFIX}{nonce}:DENIED\n"
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item")
        if not isinstance(item, dict) or item.get("type") != "command_execution":
            continue
        if (
            item.get("exit_code") == 0
            and item.get("status") == "completed"
            and isinstance(item.get("command"), str)
            and nonce in item["command"]
            and expected_command in item["command"]
            and item.get("aggregated_output") == marker
        ):
            return True
    return False


def _evidence(
    request: CanaryRequest,
    *,
    probe_id: str,
    verified_at: datetime,
    legacy_sandbox_mode: bool,
    checks: Mapping[str, bool],
) -> CanaryEvidence:
    return CanaryEvidence(
        probe_id=probe_id,
        codex_version=request.codex_version,
        permission_profile=request.permission_profile,
        profile_sha256=request.profile_sha256,
        managed_config_sha256=request.managed_config_sha256,
        verified_at=verified_at,
        legacy_sandbox_mode=legacy_sandbox_mode,
        checks=checks,
    )


def _failed_evidence(
    request: CanaryRequest,
    *,
    probe_id: str,
    verified_at: datetime,
    legacy_sandbox_mode: bool,
) -> CanaryEvidence:
    return _evidence(
        request,
        probe_id=probe_id,
        verified_at=verified_at,
        legacy_sandbox_mode=legacy_sandbox_mode,
        checks={name: False for name in REQUIRED_CANARY_CHECKS},
    )


def _shell_environment_override(runtime: _Runtime) -> str:
    values = (
        ("HOME", os.fspath(runtime.home)),
        ("TMPDIR", os.fspath(runtime.tmp)),
        ("PATH", FIXED_PATH),
    )
    encoded = ",".join(
        f"{name}={json.dumps(value)}" for name, value in values
    )
    return f"shell_environment_policy.set={{{encoded}}}"


def _collect_output(
    process: subprocess.Popen[bytes],
    command: CanaryCommand,
) -> tuple[bytes, bytes, str | None]:
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    stdin_fd = process.stdin.fileno()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    outputs = {
        stdout_fd: bytearray(),
        stderr_fd: bytearray(),
    }
    for descriptor in outputs:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    os.set_blocking(stdin_fd, False)
    if command.stdin:
        selector.register(stdin_fd, selectors.EVENT_WRITE)
    else:
        process.stdin.close()
    deadline = time.monotonic() + float(command.timeout_seconds)
    stdin_offset = 0
    total = 0
    reason: str | None = None
    while selector.get_map() or process.poll() is None:
        if reason is None and time.monotonic() >= deadline:
            reason = "CANARY_TIMEOUT"
            _close_stdin(selector, process, stdin_fd)
            _terminate_process_group(process)
        for key, _ in selector.select(timeout=0.05):
            descriptor = int(key.fd)
            if descriptor == stdin_fd:
                try:
                    written = os.write(
                        stdin_fd,
                        command.stdin[stdin_offset:],
                    )
                except (BrokenPipeError, OSError):
                    _close_stdin(selector, process, stdin_fd)
                    continue
                stdin_offset += written
                if stdin_offset == len(command.stdin):
                    _close_stdin(selector, process, stdin_fd)
                continue
            try:
                chunk = os.read(descriptor, 64 * 1024)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(descriptor)
                continue
            total += len(chunk)
            remaining = max(
                0,
                command.max_output_bytes - sum(len(value) for value in outputs.values()),
            )
            outputs[descriptor].extend(chunk[:remaining])
            if reason is None and total > command.max_output_bytes:
                reason = "CANARY_OUTPUT_LIMIT"
                _close_stdin(selector, process, stdin_fd)
                _terminate_process_group(process)
        if process.poll() is not None and stdin_fd in selector.get_map():
            _close_stdin(selector, process, stdin_fd)
        if process.poll() is not None and not selector.get_map():
            break
    selector.close()
    if process.poll() is None:
        _terminate_process_group(process)
    process.wait()
    stdout = bytes(outputs[stdout_fd])
    stderr = bytes(outputs[stderr_fd])
    process.stdout.close()
    process.stderr.close()
    if not process.stdin.closed:
        process.stdin.close()
    return stdout, stderr, reason


def _close_stdin(
    selector: selectors.BaseSelector,
    process: subprocess.Popen[bytes],
    descriptor: int,
) -> None:
    try:
        selector.unregister(descriptor)
    except KeyError:
        pass
    if process.stdin is not None and not process.stdin.closed:
        process.stdin.close()


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    group = process.pid
    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(group):
            return
        time.sleep(0.01)
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminal_message(code: str) -> str:
    if code == "CANARY_TIMEOUT":
        return "permission canary command exceeded its timeout"
    return "permission canary command exceeded its output limit"


_SANDBOX_PROBE = r"""
p=JSON.parse(ARGV[0])
denied=[Errno::EACCES,Errno::EPERM]
read_allowed=lambda do |path|
  begin
    File.open(path,"rb"){|file| file.read(1)}
    true
  rescue SystemCallError
    false
  end
end
open_denied=lambda do |path,flags|
  begin
    File.open(path,flags){|_|}
    false
  rescue SystemCallError => error
    denied.include?(error.class)
  end
end
network_denied=lambda do |&operation|
  begin
    operation.call
    false
  rescue SystemCallError => error
    denied.include?(error.class)
  end
end
r={
"snapshot_read_allowed"=>read_allowed.call(p["snapshot_read"]),
"snapshot_write_denied"=>open_denied.call(p["snapshot_write"],File::WRONLY),
"secret_read_denied"=>open_denied.call(p["secret_read"],File::RDONLY),
"source_git_read_denied"=>open_denied.call(p["source_git_read"],File::RDONLY),
"controller_database_read_denied"=>open_denied.call(p["controller_database_read"],File::RDONLY),
"source_worktree_write_denied"=>open_denied.call(p["source_write"],File::WRONLY),
"external_network_denied"=>network_denied.call{Socket.tcp(p["external_address"],9,connect_timeout:0.4).close},
"dns_denied"=>network_denied.call{socket=UDPSocket.new;begin socket.send("\0"*12,0,p["dns_address"],53);ensure socket.close;end},
"udp_denied"=>network_denied.call{socket=UDPSocket.new;begin socket.send("x",0,"127.0.0.1",p["udp_port"]);ensure socket.close;end},
"loopback_denied"=>network_denied.call{Socket.tcp("127.0.0.1",p["loopback_port"],connect_timeout:0.4).close},
"controller_socket_denied"=>network_denied.call{UNIXSocket.new(p["controller_socket"]).close},
}
puts "CODEX_PERMISSION_CANARY_V1:"+JSON.generate(r.sort.to_h)
""".strip()


_EXEC_PROBE = r"""
path,nonce=ARGV
begin
  File.open(path,"rb"){|file| file.read(1)}
  denied=false
rescue SystemCallError => error
  denied=[Errno::EACCES,Errno::EPERM].include?(error.class)
end
status=denied ? "DENIED" : "NOT_DENIED"
puts "CODEX_EXEC_PERMISSION_CANARY_V1:"+nonce+":"+status
""".strip()
