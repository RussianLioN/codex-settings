"""Live, fail-closed verification of Codex permission profiles."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import math
import os
import re
import selectors
import shlex
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
from typing import Callable, Mapping, Protocol, Sequence, TypeVar

from .operation_deadline_v2 import (
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    current_operation_deadline_v2,
)
from .operation_process_group_supervisor_v2 import (
    OperationProcessGroupSupervisorV2,
    ProcessGroupTerminationResultV2,
    TransientProcessIdentityErrorV2,
    TransientProcessLeaseV2,
    current_process_group_supervisor_v2,
)
from .permissions import (
    REQUIRED_CANARY_CHECKS,
    CanaryEvidence,
    CanaryRequest,
)
from .supervised_subprocess_v2 import (
    SupervisedCommandCleanupRequiredV2,
    SupervisedCommandOutputLimitExceededV2,
    SupervisedCommandV2Error,
    run_supervised_command_v2,
)


FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
MAX_APP_SERVER_REQUEST = 64 * 1024
MAX_APP_SERVER_SESSION_REQUESTS = 128
SANDBOX_RESULT_PREFIX = "CODEX_PERMISSION_CANARY_V1:"
EXEC_RESULT_PREFIX = "CODEX_EXEC_PERMISSION_CANARY_V1:"
EXEC_STDIN_NOTICE = b"Reading prompt from stdin...\n"
_MODEL_REFRESH_TIMEOUT_NOTICE = re.compile(
    rb"\d{4}-\d{2}-\d{2}T"
    rb"\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z ERROR "
    rb"codex_models_manager::manager: failed to refresh available models: "
    rb"timeout waiting for child process to exit\n"
)
_MAX_MODEL_REFRESH_TIMEOUT_NOTICES = 4
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
_APP_SERVER_METHOD = re.compile(
    r"[A-Za-z][A-Za-z0-9_-]*(?:/[A-Za-z][A-Za-z0-9_-]*)+"
)
_DENIED_ERRNOS = frozenset((errno.EACCES, errno.EPERM))
_ALLOWED_AUTH_ENVIRONMENT = frozenset(("OPENAI_API_KEY",))
_MAX_AUTH_BYTES = 1024 * 1024
_SessionResult = TypeVar("_SessionResult")


@dataclass
class LiveCanaryError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass
class AppServerError(RuntimeError):
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


class StrictAppServerClient:
    """Run one bounded, strict app-server JSON-RPC session over stdio."""

    def __init__(
        self,
        *,
        codex_executable: Path,
        codex_home: Path,
        home: Path,
        tmpdir: Path,
        cwd: Path,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 1024 * 1024,
        client_name: str = "codex_smart_subagents",
        client_title: str = "Codex Smart Subagents",
        client_version: str = "0.1.0",
        use_temporary_sqlite_home: bool = True,
        cancel_check: Callable[[], bool] | None = None,
        accepted_stderr: Callable[[bytes], bool] | None = None,
    ) -> None:
        self._codex = _safe_executable(codex_executable, "Codex")
        self._codex_home = _safe_owned_directory(codex_home, "CODEX_HOME")
        self._home = _safe_owned_directory(home, "app-server HOME")
        self._tmpdir = _safe_private_directory(tmpdir, "app-server TMPDIR")
        self._cwd = _safe_owned_directory(cwd, "app-server cwd")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 180
        ):
            raise ValueError("timeout_seconds must be in (0, 180]")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        for label, value, maximum in (
            ("client_name", client_name, 64),
            ("client_title", client_title, 128),
            ("client_version", client_version, 32),
        ):
            if (
                not isinstance(value, str)
                or not value
                or "\0" in value
                or "\n" in value
                or len(value.encode("utf-8")) > maximum
            ):
                raise ValueError(f"{label} is invalid")
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes
        self._client_info = {
            "name": client_name,
            "title": client_title,
            "version": client_version,
        }
        if type(use_temporary_sqlite_home) is not bool:
            raise TypeError("use_temporary_sqlite_home must be boolean")
        self._use_temporary_sqlite_home = use_temporary_sqlite_home
        if cancel_check is not None and not callable(cancel_check):
            raise TypeError("cancel_check must be callable")
        self._cancel_check = cancel_check
        if accepted_stderr is not None and not callable(accepted_stderr):
            raise TypeError("accepted_stderr must be callable")
        self._accepted_stderr = (
            _empty_stderr if accepted_stderr is None else accepted_stderr
        )

    def call(self, method: str, params: Mapping[str, object]) -> object:
        return self.run_session(lambda session_call: session_call(method, params))

    def run_session(
        self,
        operation: Callable[
            [Callable[[str, Mapping[str, object]], object]], _SessionResult
        ],
    ) -> _SessionResult:
        """Execute bounded sequential calls in one initialized process."""

        if not callable(operation):
            raise TypeError("app-server session operation must be callable")
        if not self._use_temporary_sqlite_home:
            return self._run_session_with_sqlite_home(
                operation,
                sqlite_home=None,
            )
        with tempfile.TemporaryDirectory(
            prefix="app-server-sqlite-",
            dir=self._tmpdir,
        ) as raw_sqlite_home:
            sqlite_home = Path(raw_sqlite_home)
            os.chmod(sqlite_home, 0o700)
            return self._run_session_with_sqlite_home(
                operation,
                sqlite_home=sqlite_home,
            )

    def _run_session_with_sqlite_home(
        self,
        operation: Callable[
            [Callable[[str, Mapping[str, object]], object]], _SessionResult
        ],
        *,
        sqlite_home: Path | None,
    ) -> _SessionResult:
        environment: dict[str, str] = {
            "CODEX_HOME": os.fspath(self._codex_home),
            "HOME": os.fspath(self._home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": FIXED_PATH,
            "TMPDIR": os.fspath(self._tmpdir),
        }
        if sqlite_home is not None:
            environment["CODEX_SQLITE_HOME"] = os.fspath(sqlite_home)
        operation_deadline, process_supervisor = _process_runtime_v2(
            operation="strict-app-server-session",
            standalone_timeout_seconds=self._timeout_seconds + 1.0,
        )
        session_deadline = operation_deadline.child(
            phase="strict-app-server-session",
            max_seconds=self._timeout_seconds,
            timeout_code="APP_SERVER_TIMEOUT",
        )
        try:
            process_lease = process_supervisor.spawn_transient(
                label="strict-app-server",
                argv=(
                    os.fspath(self._codex),
                    "app-server",
                    "--strict-config",
                    "--listen",
                    "stdio://",
                ),
                cwd=self._cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                restore_signals=True,
                umask=0o077,
            )
        except (OSError, TransientProcessIdentityErrorV2) as exc:
            raise AppServerError("APP_SERVER_SPAWN_FAILED", str(exc)) from exc

        process = process_lease.process
        reader: _StrictJsonLineReader | None = None
        root_deadline_error: OperationDeadlineExceededV2 | None = None
        try:
            reader = _StrictJsonLineReader(
                process,
                maximum=self._max_output_bytes,
                cancel_check=self._cancel_check,
            )
            initialize = {
                "method": "initialize",
                "id": 1,
                "params": {
                    "clientInfo": self._client_info,
                    "capabilities": {
                        "optOutNotificationMethods": [
                            "remoteControl/status/changed"
                        ]
                    },
                },
            }
            _write_app_server_message(
                process,
                _encode_json_line(initialize),
                deadline=session_deadline,
            )
            notification_count = [0]
            initialized = _read_app_server_response(
                reader,
                expected_id=1,
                deadline=session_deadline,
                notification_count=notification_count,
            )
            _validate_initialize_result(
                initialized,
                expected_codex_home=self._codex_home,
            )
            _write_app_server_message(
                process,
                _encode_json_line(
                    {"method": "initialized", "params": {}}
                ),
                deadline=session_deadline,
            )
            next_request_id = 2

            def session_call(
                method: str, params: Mapping[str, object]
            ) -> object:
                nonlocal next_request_id
                if (
                    not isinstance(method, str)
                    or _APP_SERVER_METHOD.fullmatch(method) is None
                ):
                    raise ValueError("app-server method is invalid")
                if next_request_id >= 2 + MAX_APP_SERVER_SESSION_REQUESTS:
                    raise AppServerError(
                        "APP_SERVER_REQUEST_LIMIT",
                        "app-server session request limit exceeded",
                    )
                try:
                    copied_params = dict(params)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        "app-server params must be a mapping"
                    ) from exc
                request_id = next_request_id
                encoded_request = _encode_json_line(
                    {
                        "method": method,
                        "id": request_id,
                        "params": copied_params,
                    }
                )
                if len(encoded_request) > MAX_APP_SERVER_REQUEST:
                    raise ValueError(
                        "app-server request exceeds the byte limit"
                    )
                next_request_id += 1
                _write_app_server_message(
                    process,
                    encoded_request,
                    deadline=session_deadline,
                )
                return _read_app_server_response(
                    reader,
                    expected_id=request_id,
                    deadline=session_deadline,
                    notification_count=notification_count,
                )

            result = operation(session_call)
            trailing_deadline = session_deadline.child(
                phase="strict-app-server-trailing-message-check",
                max_seconds=0.05,
                timeout_code="APP_SERVER_TRAILING_WAIT_COMPLETE",
            )
            _assert_no_app_server_message(
                reader,
                process=process,
                deadline=trailing_deadline,
            )
            reader.require_accepted_stderr(self._accepted_stderr)
            return result
        except OperationDeadlineExceededV2 as exc:
            try:
                operation_deadline.checkpoint()
            except OperationDeadlineExceededV2 as root_exc:
                root_deadline_error = root_exc
                raise
            if exc.code == "APP_SERVER_TIMEOUT":
                raise AppServerError(
                    "APP_SERVER_TIMEOUT",
                    "app-server request exceeded its timeout",
                ) from exc
            raise
        finally:
            if reader is not None:
                reader.close()
            try:
                _close_app_server_process(
                    process,
                    supervisor=process_supervisor,
                    lease=process_lease,
                    deadline=operation_deadline,
                )
            except AppServerError as cleanup_error:
                if root_deadline_error is not None:
                    raise root_deadline_error from cleanup_error
                raise


class AppServerManagedConfigInspector:
    """Fingerprint effective managed requirements reported by Codex itself."""

    def __init__(
        self,
        *,
        codex_executable: Path,
        codex_home: Path,
        runtime_parent: Path,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 1024 * 1024,
    ) -> None:
        self._codex = _safe_executable(codex_executable, "Codex")
        self._codex_home = _safe_owned_directory(
            codex_home,
            "managed requirements CODEX_HOME",
        )
        self._runtime_parent = _safe_private_directory(
            runtime_parent,
            "managed requirements runtime parent",
        )
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 60
        ):
            raise ValueError("timeout_seconds must be in (0, 60]")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 16 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes

    def inspect(self) -> ManagedConfigState:
        with tempfile.TemporaryDirectory(
            prefix="managed-requirements-",
            dir=self._runtime_parent,
        ) as raw_root:
            runtime = _Runtime.create(Path(raw_root))
            # The real CODEX_HOME is required for cloud-managed requirements;
            # only the typed requirements result is retained or fingerprinted.
            client = StrictAppServerClient(
                codex_executable=self._codex,
                codex_home=self._codex_home,
                home=runtime.home,
                tmpdir=runtime.tmp,
                cwd=runtime.work,
                timeout_seconds=self._timeout_seconds,
                max_output_bytes=self._max_output_bytes,
                use_temporary_sqlite_home=False,
            )
            try:
                result = client.call("configRequirements/read", {})
            except AppServerError as exc:
                raise _managed_config_app_server_error(exc) from exc

        if (
            not isinstance(result, dict)
            or set(result) != {"requirements"}
        ):
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "configRequirements/read returned a malformed result",
            )
        requirements = result["requirements"]
        if requirements is not None and not isinstance(requirements, dict):
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "managed requirements must be an object or null",
            )
        try:
            _validate_json_tree(requirements)
        except ValueError as exc:
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "managed requirements exceed strict JSON limits",
            ) from exc
        allowed_sandbox_modes = (
            None
            if requirements is None
            else requirements.get("allowedSandboxModes")
        )
        if allowed_sandbox_modes is not None and (
            not isinstance(allowed_sandbox_modes, list)
            or not all(
                isinstance(value, str) and value
                for value in allowed_sandbox_modes
            )
        ):
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "allowedSandboxModes must be an array of non-empty strings",
            )
        feature_requirements = (
            None
            if requirements is None
            else requirements.get("featureRequirements")
        )
        if feature_requirements is not None and (
            not isinstance(feature_requirements, dict)
            or not all(
                isinstance(name, str)
                and name
                and type(required) is bool
                for name, required in feature_requirements.items()
            )
        ):
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "featureRequirements must map feature names to booleans",
            )
        required_forbidden = (
            set()
            if feature_requirements is None
            else {
                name
                for name, required in feature_requirements.items()
                if required is True and name in FEATURES_DISABLED_FOR_CANARY
            }
        )
        if required_forbidden:
            raise LiveCanaryError(
                "MANAGED_FEATURE_CONFLICT",
                "managed requirements force a disabled child capability",
            )
        try:
            canonical = json.dumps(
                requirements,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise LiveCanaryError(
                "MANAGED_CONFIG_INVALID",
                "managed requirements cannot be canonicalized",
            ) from exc
        digest = hashlib.sha256(
            b"codex-config-requirements-v1\0" + canonical
        ).hexdigest()
        return ManagedConfigState(
            sha256=digest,
            legacy_sandbox_mode=bool(allowed_sandbox_modes),
        )


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
    writable_root: Path | None
    workspace_access: str


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
        for field in ("snapshot_read_file", "snapshot_write_file"):
            path = _safe_snapshot_probe_target(
                getattr(self, field),
                snapshot_root,
                field,
            )
            object.__setattr__(self, field, path)
        regular = (
            "secret_read_file",
            "source_git_read_file",
            "controller_database_read_file",
            "source_worktree_write_file",
        )
        for field in regular:
            path = _safe_probe_file(getattr(self, field), field)
            object.__setattr__(self, field, path)
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
        deadline, supervisor = _process_runtime_v2(
            operation="permission-canary-command",
            standalone_timeout_seconds=float(command.timeout_seconds) + 1.0,
        )
        try:
            result = run_supervised_command_v2(
                argv=command.argv,
                label="permission-canary",
                local_timeout_seconds=command.timeout_seconds,
                cleanup_wait_seconds=0.5,
                stdin=command.stdin,
                max_output_bytes=command.max_output_bytes,
                cwd=command.cwd,
                env=dict(command.environment),
                deadline=deadline,
                supervisor=supervisor,
            )
        except SupervisedCommandOutputLimitExceededV2 as exc:
            raise LiveCanaryError(
                "CANARY_OUTPUT_LIMIT", _terminal_message("CANARY_OUTPUT_LIMIT")
            ) from exc
        except OperationDeadlineExceededV2 as exc:
            raise LiveCanaryError(
                "CANARY_TIMEOUT", _terminal_message("CANARY_TIMEOUT")
            ) from exc
        except SupervisedCommandCleanupRequiredV2 as exc:
            raise LiveCanaryError(
                "CANARY_PROCESS_CLEANUP_REQUIRED",
                "permission canary process group cleanup remains pending",
            ) from exc
        except (OSError, TransientProcessIdentityErrorV2) as exc:
            raise LiveCanaryError("CANARY_SPAWN_FAILED", str(exc)) from exc
        except SupervisedCommandV2Error as exc:
            raise LiveCanaryError("CANARY_PROCESS_FAILED", str(exc)) from exc
        return CommandResult(result.returncode, result.stdout, result.stderr)


class _StrictJsonLineReader:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        maximum: int,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        if process.stdout is None or process.stderr is None:
            raise AppServerError(
                "APP_SERVER_INVALID",
                "app-server pipes are unavailable",
            )
        self._process = process
        self._maximum = maximum
        self._total = 0
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._selector = selectors.DefaultSelector()
        for stream in (process.stdout, process.stderr):
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            self._selector.register(descriptor, selectors.EVENT_READ)
        self._stdout_fd = process.stdout.fileno()
        self._stderr_fd = process.stderr.fileno()
        self._cancel_check = cancel_check

    def read(self, *, deadline: OperationDeadlineV2) -> object:
        while True:
            deadline.checkpoint()
            if self._cancel_check is not None and self._cancel_check():
                raise AppServerError(
                    "APP_SERVER_CANCELLED",
                    "app-server operation was cancelled",
                )
            newline = self._stdout.find(b"\n")
            if newline >= 0:
                raw = bytes(self._stdout[:newline])
                del self._stdout[: newline + 1]
                if not raw:
                    raise AppServerError(
                        "APP_SERVER_INVALID",
                        "app-server emitted an empty message",
                    )
                try:
                    text = raw.decode("utf-8", errors="strict")
                    value = _strict_json_loads(text)
                    _validate_json_tree(value)
                    return value
                except (UnicodeDecodeError, ValueError, RecursionError) as exc:
                    raise AppServerError(
                        "APP_SERVER_INVALID",
                        "app-server emitted invalid JSON",
                    ) from exc

            select_timeout = deadline.bounded_timeout_seconds(
                local_cap_seconds=0.05,
            )
            events = self._selector.select(timeout=select_timeout)
            deadline.checkpoint()
            for key, _ in events:
                descriptor = int(key.fd)
                try:
                    chunk = os.read(descriptor, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    try:
                        self._selector.unregister(descriptor)
                    except KeyError:
                        pass
                    continue
                self._total += len(chunk)
                if self._total > self._maximum:
                    raise AppServerError(
                        "APP_SERVER_OUTPUT_LIMIT",
                        "app-server output exceeded its byte limit",
                    )
                if descriptor == self._stderr_fd:
                    self._stderr.extend(chunk)
                elif descriptor == self._stdout_fd:
                    self._stdout.extend(chunk)
            if (
                self._process.poll() is not None
                and not self._selector.get_map()
            ):
                if self._stdout:
                    raise AppServerError(
                        "APP_SERVER_INVALID",
                        "app-server exited with an incomplete response",
                    )
                raise AppServerError(
                    "APP_SERVER_INVALID",
                    "app-server exited before returning a complete response",
                )

    def close(self) -> None:
        self._selector.close()

    def require_accepted_stderr(
        self,
        accepted_stderr: Callable[[bytes], bool],
    ) -> None:
        payload = bytes(self._stderr)
        if not accepted_stderr(payload):
            raise AppServerError(
                "APP_SERVER_INVALID",
                "app-server wrote unexpected diagnostic output",
            )

    def require_complete_stdout(self) -> None:
        if self._stdout:
            raise AppServerError(
                "APP_SERVER_INVALID",
                "app-server emitted an incomplete response",
            )


def _read_app_server_response(
    reader: _StrictJsonLineReader,
    *,
    expected_id: int,
    deadline: OperationDeadlineV2,
    notification_count: list[int] | None = None,
) -> object:
    while True:
        message = reader.read(deadline=deadline)
        if not isinstance(message, dict):
            raise AppServerError(
                "APP_SERVER_INVALID",
                "app-server message must be an object",
            )
        if "id" not in message:
            if (
                set(message) != {"method", "params"}
                or not isinstance(message["method"], str)
                or not 1 <= len(message["method"].encode("utf-8")) <= 256
                or not isinstance(message["params"], dict)
            ):
                raise AppServerError(
                    "APP_SERVER_INVALID",
                    "app-server notification is malformed",
                )
            if notification_count is not None:
                notification_count[0] += 1
                if notification_count[0] > 128:
                    raise AppServerError(
                        "APP_SERVER_NOTIFICATION_LIMIT",
                        "app-server emitted too many unanswered messages",
                    )
            continue
        if type(message["id"]) is not int or message["id"] != expected_id:
            raise AppServerError(
                "APP_SERVER_INVALID",
                "app-server response id is invalid",
            )
        if set(message) == {"id", "error"}:
            error = message["error"]
            if (
                not isinstance(error, dict)
                or "message" not in error
                or "code" not in error
                or not isinstance(error["message"], str)
                or not error["message"]
                or type(error["code"]) not in {str, int}
            ):
                raise AppServerError(
                    "APP_SERVER_INVALID",
                    "app-server error envelope is malformed",
                )
            raise AppServerError(
                "APP_SERVER_REMOTE_ERROR",
                "app-server rejected the request",
            )
        if set(message) != {"id", "result"}:
            raise AppServerError(
                "APP_SERVER_INVALID",
                "app-server response envelope is malformed",
            )
        return message["result"]


def _validate_initialize_result(
    result: object,
    *,
    expected_codex_home: Path,
) -> None:
    expected_fields = {
        "userAgent",
        "codexHome",
        "platformFamily",
        "platformOs",
    }
    if (
        not isinstance(result, dict)
        or not expected_fields.issubset(result)
        or not all(isinstance(result[name], str) for name in expected_fields)
        or not result["userAgent"]
        or not result["platformFamily"]
        or not result["platformOs"]
    ):
        raise AppServerError(
            "APP_SERVER_INVALID",
            "app-server initialize result is malformed",
        )
    if result["codexHome"] != os.fspath(expected_codex_home):
        raise AppServerError(
            "APP_SERVER_CODEX_HOME_MISMATCH",
            "app-server initialized with an unexpected CODEX_HOME",
        )


def _assert_no_app_server_message(
    reader: _StrictJsonLineReader,
    *,
    process: subprocess.Popen[bytes],
    deadline: OperationDeadlineV2,
) -> None:
    """Запрещает ответ, запрос или уведомление после итогового ответа."""

    try:
        reader.read(deadline=deadline)
    except OperationDeadlineExceededV2 as exc:
        if exc.code == "APP_SERVER_TRAILING_WAIT_COMPLETE":
            reader.require_complete_stdout()
            return
        raise
    except AppServerError as exc:
        if process.poll() is not None and "exited before" in exc.message:
            return
        raise
    raise AppServerError(
        "APP_SERVER_TRAILING_MESSAGE",
        "app-server emitted a message after the final response",
    )


def _write_app_server_message(
    process: subprocess.Popen[bytes],
    payload: bytes,
    *,
    deadline: OperationDeadlineV2,
) -> None:
    if process.stdin is None:
        raise AppServerError(
            "APP_SERVER_INVALID",
            "app-server stdin is unavailable",
        )
    try:
        descriptor = process.stdin.fileno()
        os.set_blocking(descriptor, False)
    except (AttributeError, OSError, ValueError) as exc:
        raise AppServerError(
            "APP_SERVER_INVALID",
            "app-server stdin is unavailable",
        ) from exc
    selector = selectors.DefaultSelector()
    try:
        selector.register(descriptor, selectors.EVENT_WRITE)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            deadline.checkpoint()
            wait_seconds = deadline.bounded_timeout_seconds(
                local_cap_seconds=0.05,
            )
            if not selector.select(timeout=wait_seconds):
                continue
            deadline.checkpoint()
            try:
                count = os.write(
                    descriptor,
                    view[written : written + 64 * 1024],
                )
            except (BlockingIOError, InterruptedError):
                continue
            if count <= 0:
                raise AppServerError(
                    "APP_SERVER_INVALID",
                    "app-server closed its input unexpectedly",
                )
            written += count
    except (BrokenPipeError, OSError) as exc:
        raise AppServerError(
            "APP_SERVER_INVALID",
            "app-server closed its input unexpectedly",
        ) from exc
    finally:
        selector.close()


def _encode_json_line(value: object) -> bytes:
    _validate_json_tree(value)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("value is not strict bounded JSON") from exc
    return encoded + b"\n"


def _strict_json_loads(value: str) -> object:
    def object_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = item
        return result

    return json.loads(
        value,
        object_pairs_hook=object_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("non-finite JSON number")
        ),
    )


def _validate_json_tree(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 100_000 or depth > 32:
            raise ValueError("JSON value exceeds structural limits")
        if current is None or type(current) in (bool, int, str):
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise ValueError("JSON number must be finite")
            continue
        if isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise ValueError("JSON object keys must be strings")
            pending.extend((item, depth + 1) for item in current.values())
            continue
        raise ValueError("value contains a non-JSON type")


def _close_app_server_process(
    process: subprocess.Popen[bytes],
    *,
    supervisor: OperationProcessGroupSupervisorV2,
    lease: TransientProcessLeaseV2,
    deadline: OperationDeadlineV2,
) -> None:
    if process.stdin is not None and not process.stdin.closed:
        process.stdin.close()
    try:
        if process.poll() is None:
            termination = supervisor.terminate_transient(
                lease,
                deadline=deadline,
                max_wait_seconds=0.5,
                reason_code="STRICT_APP_SERVER_SESSION_FINISHED",
            )
            if not termination.continuation_allowed:
                assert termination.cleanup_obligation is not None
                raise AppServerError(
                    "APP_SERVER_PROCESS_CLEANUP_REQUIRED",
                    "app-server process group cleanup remains pending",
                )
        else:
            released = supervisor.release_after_verified_exit(
                lease,
                deadline=deadline,
                reason_code="APP_SERVER_GROUP_REMAINS_AFTER_EXIT",
            )
            if isinstance(released, ProcessGroupTerminationResultV2):
                raise AppServerError(
                    "APP_SERVER_PROCESS_CLEANUP_REQUIRED",
                    "app-server descendant remained after leader exit",
                )
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _process_runtime_v2(
    *,
    operation: str,
    standalone_timeout_seconds: float,
) -> tuple[OperationDeadlineV2, OperationProcessGroupSupervisorV2]:
    deadline = current_operation_deadline_v2()
    if deadline is None:
        deadline = OperationDeadlineV2.start(
            operation=operation,
            timeout_seconds=standalone_timeout_seconds,
            timeout_code=f"{operation.upper().replace('-', '_')}_TIMEOUT",
        )
    supervisor = current_process_group_supervisor_v2()
    if supervisor is None:
        supervisor = OperationProcessGroupSupervisorV2(
            popen_factory=subprocess.Popen
        )
    return deadline, supervisor


def _managed_config_app_server_error(
    error: AppServerError,
) -> LiveCanaryError:
    codes = {
        "APP_SERVER_TIMEOUT": "MANAGED_CONFIG_TIMEOUT",
        "APP_SERVER_OUTPUT_LIMIT": "MANAGED_CONFIG_OUTPUT_LIMIT",
        "APP_SERVER_CODEX_HOME_MISMATCH": (
            "MANAGED_CONFIG_CODEX_HOME_MISMATCH"
        ),
        "APP_SERVER_SPAWN_FAILED": "MANAGED_CONFIG_UNAVAILABLE",
    }
    return LiveCanaryError(
        codes.get(error.code, "MANAGED_CONFIG_INVALID"),
        "effective managed requirements could not be verified",
    )


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
            getattr(profile, "writable_root", None),
            getattr(profile, "workspace_access", "write"),
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
            staged_auth: Path | None = None
            if not self._auth_environment:
                # Sandbox and exec see only this bounded copy, never the user's
                # config.toml or the rest of the real CODEX_HOME.
                staged_auth = _stage_canary_auth(
                    self._codex_home / "auth.json",
                    runtime.codex_home,
                )
            try:
                return self._verify_in_runtime(
                    request,
                    runtime=runtime,
                    probe_id=probe_id,
                    verified_at=verified_at,
                )
            finally:
                if staged_auth is not None:
                    _remove_canary_auth(staged_auth)

    def _verify_in_runtime(
        self,
        request: CanaryRequest,
        *,
        runtime: "_Runtime",
        probe_id: str,
        verified_at: datetime,
    ) -> CanaryEvidence:
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
        except OperationDeadlineExceededV2:
            raise
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
            "CODEX_HOME": os.fspath(runtime.codex_home),
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
    codex_home: Path
    work: Path

    @classmethod
    def create(cls, root: Path) -> "_Runtime":
        root.chmod(0o700)
        children = []
        for name in ("home", "tmp", "codex-home", "work"):
            path = root / name
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            children.append(path.resolve(strict=True))
        return cls(
            root=root.resolve(strict=True),
            home=children[0],
            tmp=children[1],
            codex_home=children[2],
            work=children[3],
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
    writable_root: Path | None,
    workspace_access: str,
) -> None:
    try:
        parsed = tomllib.loads("\n".join(overrides))
        selected = parsed["permissions"][name]
        filesystem = selected["filesystem"]
        network = selected["network"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("permission profile overrides are not valid TOML") from exc
    if workspace_access not in {"read", "write"}:
        raise ValueError("workspace access must be read or write")
    if writable_root is not None and workspace_access != "write":
        raise ValueError("writer profile requires writable control workspace")
    expected_filesystem = {
        ":root": "deny",
        ":minimal": "read",
        ":tmpdir": "write",
        ":workspace_roots": {".": workspace_access},
        os.fspath(snapshot_root): "read",
    }
    if writable_root is not None:
        writable = _safe_private_directory(
            writable_root,
            "writer candidate root",
        )
        if writable == snapshot_root:
            raise ValueError(
                "writer candidate root must differ from the snapshot"
            )
        expected_filesystem[os.fspath(writable)] = "write"
    if (
        not isinstance(selected, dict)
        or set(selected) != {"description", "filesystem", "network"}
        or not isinstance(selected["description"], str)
        or not selected["description"]
        or filesystem != expected_filesystem
        or network != {"enabled": False}
    ):
        raise ValueError(
            "permission profile must match the exact child policy"
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


def _stage_canary_auth(source: Path, codex_home: Path) -> Path:
    if not source.is_absolute() or source.is_symlink():
        raise LiveCanaryError(
            "CANARY_AUTH_UNAVAILABLE",
            "authentication source is unsafe",
        )
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_fd = os.open(source, source_flags)
    except OSError as exc:
        raise LiveCanaryError(
            "CANARY_AUTH_UNAVAILABLE",
            "authentication source is unavailable",
        ) from exc
    destination = codex_home / "auth.json"
    try:
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= _MAX_AUTH_BYTES
        ):
            raise LiveCanaryError(
                "CANARY_AUTH_UNAVAILABLE",
                "authentication source is not a private bounded file",
            )
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_fd = os.open(destination, destination_flags, 0o600)
        try:
            remaining = before.st_size
            while remaining:
                chunk = os.read(source_fd, min(remaining, 64 * 1024))
                if not chunk:
                    raise LiveCanaryError(
                        "CANARY_AUTH_UNAVAILABLE",
                        "authentication source changed during staging",
                    )
                view = memoryview(chunk)
                while view:
                    view = view[os.write(destination_fd, view) :]
                remaining -= len(chunk)
            if os.read(source_fd, 1):
                raise LiveCanaryError(
                    "CANARY_AUTH_UNAVAILABLE",
                    "authentication source changed during staging",
                )
            after = os.fstat(source_fd)
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
                    "CANARY_AUTH_UNAVAILABLE",
                    "authentication source changed during staging",
                )
            os.fsync(destination_fd)
        except BaseException:
            os.close(destination_fd)
            destination.unlink(missing_ok=True)
            raise
        else:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    return destination


def _remove_canary_auth(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise LiveCanaryError(
            "CANARY_AUTH_CLEANUP_FAILED",
            "staged authentication path changed during verification",
        )
    path.unlink()


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


def _safe_snapshot_probe_target(path: Path, root: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if resolved == root:
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError(f"{label} must be the owned snapshot root")
        return resolved
    if (
        not resolved.is_relative_to(root)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise ValueError(f"{label} must be an owned snapshot file")
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
    if (
        result.exit_code != 0
        or not _expected_exec_stderr(result.stderr)
        or _NONCE.fullmatch(nonce) is None
    ):
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
            and _exec_command_matches(item["command"], expected_command)
            and item.get("aggregated_output") == marker
        ):
            return True
    return False


def _empty_stderr(stderr: bytes) -> bool:
    return stderr == b""


def expected_model_refresh_timeout_stderr(stderr: bytes) -> bool:
    if stderr == b"":
        return True
    lines = stderr.splitlines(keepends=True)
    return (
        1 <= len(lines) <= _MAX_MODEL_REFRESH_TIMEOUT_NOTICES
        and all(
            _MODEL_REFRESH_TIMEOUT_NOTICE.fullmatch(line) is not None
            for line in lines
        )
    )


def _expected_exec_stderr(stderr: bytes) -> bool:
    if stderr == EXEC_STDIN_NOTICE:
        return True
    if stderr.startswith(EXEC_STDIN_NOTICE):
        stderr = stderr[len(EXEC_STDIN_NOTICE) :]
    return expected_model_refresh_timeout_stderr(stderr)


def _exec_command_matches(observed: str, expected: str) -> bool:
    if observed == expected:
        return True
    try:
        arguments = shlex.split(observed, posix=True)
    except ValueError:
        return False
    return arguments == ["/bin/zsh", "-c", expected]


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


def _terminal_message(code: str) -> str:
    if code == "CANARY_TIMEOUT":
        return "permission canary command exceeded its timeout"
    return "permission canary command exceeded its output limit"


_SANDBOX_PROBE = r"""
p=JSON.parse(ARGV[0])
denied=[Errno::EACCES,Errno::EPERM]
read_allowed=lambda do |path|
  begin
    if File.directory?(path)
      Dir.children(path)
    else
      File.open(path,"rb"){|file| file.read(1)}
    end
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
snapshot_write_denied=lambda do |path|
  unless File.directory?(path)
    next open_denied.call(path,File::WRONLY)
  end
  target=File.join(path,".codex-permission-canary-#{Process.pid}")
  begin
    File.open(target,File::WRONLY|File::CREAT|File::EXCL,0600){|_|}
    false
  rescue SystemCallError => error
    denied.include?(error.class)
  ensure
    begin
      File.unlink(target) if File.exist?(target)
    rescue SystemCallError
    end
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
"snapshot_write_denied"=>snapshot_write_denied.call(p["snapshot_write"]),
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
