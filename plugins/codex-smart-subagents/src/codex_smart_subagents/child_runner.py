"""Least-privilege, shell-free launcher for one external ``codex exec``."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any
from urllib.parse import quote
from urllib.parse import urlsplit

from .compatibility import codex_version_supported
from .permissions import CanaryRequest, PermissionGate


FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_PROMPT_BYTES = 64 * 1024
MAX_SCHEMA_BYTES = 1024 * 1024
READ_CHUNK = 64 * 1024
FEATURES_DISABLED_FOR_CHILDREN = (
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
MODEL_EFFORTS = {
    "gpt-5.6-luna": frozenset({"low", "medium"}),
    "gpt-5.6-terra": frozenset({"medium", "high", "xhigh"}),
    "gpt-5.6-sol": frozenset({"high", "xhigh", "max"}),
}

_PROFILE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ARG0_SESSION = re.compile(r"codex-arg0[A-Za-z0-9]{6}")
_ARG0_ALIASES = frozenset(
    ("apply_patch", "applypatch", "codex-execve-wrapper")
)
_HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
_OTEL_TOKEN = re.compile(r"[\x21-\x7e]{8,256}")
_MAX_AUTH_BYTES = 1024 * 1024


@dataclass
class ChildLaunchError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ChildRuntimeLayout:
    root: Path
    home: Path
    tmpdir: Path
    codex_home: Path
    sqlite_home: Path
    work_dir: Path

    @classmethod
    def create(cls, root: Path) -> "ChildRuntimeLayout":
        expanded = root.expanduser()
        try:
            parent = expanded.parent.resolve(strict=True)
        except OSError as exc:
            raise ChildLaunchError("UNSAFE_RUNTIME_ROOT", str(exc)) from exc
        target = parent / expanded.name
        if os.path.lexists(target):
            raise ChildLaunchError(
                "UNSAFE_RUNTIME_ROOT",
                "child runtime root must be fresh",
            )
        target.mkdir(mode=0o700)
        target.chmod(0o700)
        children = {}
        try:
            for name in (
                "home",
                "tmp",
                "codex-home",
                "sqlite-home",
                "work",
            ):
                path = target / name
                path.mkdir(mode=0o700)
                path.chmod(0o700)
                children[name] = path
        except BaseException:
            _remove_private_runtime(target)
            raise
        return cls(
            root=target,
            home=children["home"],
            tmpdir=children["tmp"],
            codex_home=children["codex-home"],
            sqlite_home=children["sqlite-home"],
            work_dir=children["work"],
        )


@dataclass(frozen=True)
class ChildTelemetryConfig:
    endpoint: str
    header_name: str
    token: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or not 0 < parsed.port <= 65535
            or not parsed.path.startswith("/")
            or parsed.path == "/"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "telemetry endpoint must be a private loopback HTTP URL"
            )
        if _HEADER_NAME.fullmatch(self.header_name) is None:
            raise ValueError("telemetry header name is unsafe")
        if (
            not isinstance(self.token, str)
            or _OTEL_TOKEN.fullmatch(self.token) is None
        ):
            raise ValueError("telemetry token is not bounded printable ASCII")


@dataclass(frozen=True)
class ChildResourceLimits:
    max_memory_bytes: int = 2 * 1024 * 1024 * 1024
    max_processes: int = 64
    max_growth_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_memory_bytes",
            "max_processes",
            "max_growth_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class PermissionProfileDefinition:
    name: str
    description: str
    snapshot_root: Path
    writable_root: Path | None = None

    def __post_init__(self) -> None:
        if _PROFILE_NAME.fullmatch(self.name) is None:
            raise ValueError("permission profile name is unsafe")
        if not self.description or len(self.description) > 120:
            raise ValueError("permission profile description is invalid")
        snapshot = _plain_directory(
            self.snapshot_root,
            code="UNSAFE_SNAPSHOT_ROOT",
            require_read_only=True,
        )
        _validate_read_only_tree(snapshot)
        object.__setattr__(self, "snapshot_root", snapshot)
        writable = self.writable_root
        if writable is not None:
            writable = _plain_directory(
                writable,
                code="UNSAFE_WRITABLE_ROOT",
            )
            _validate_workdir(writable, allow_populated=True)
            if writable == snapshot:
                raise ValueError(
                    "writable root must be separate from the snapshot"
                )
            object.__setattr__(self, "writable_root", writable)

    @classmethod
    def reader(
        cls,
        *,
        name: str,
        snapshot_root: Path,
    ) -> "PermissionProfileDefinition":
        return cls(
            name=name,
            description="Adaptive child reader",
            snapshot_root=snapshot_root,
        )

    @classmethod
    def writer(
        cls,
        *,
        name: str,
        snapshot_root: Path,
        writable_root: Path,
    ) -> "PermissionProfileDefinition":
        return cls(
            name=name,
            description="Adaptive child writer",
            snapshot_root=snapshot_root,
            writable_root=writable_root,
        )

    @property
    def config_overrides(self) -> tuple[str, ...]:
        quoted_path = json.dumps(os.fspath(self.snapshot_root))
        writable = (
            ""
            if self.writable_root is None
            else (
                ","
                f"{json.dumps(os.fspath(self.writable_root))}=\"write\""
            )
        )
        filesystem = (
            f"permissions.{self.name}.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="write"},'
            f"{quoted_path}=\"read\"{writable}}}"
        )
        return (
            f"permissions.{self.name}.description={json.dumps(self.description)}",
            filesystem,
            f"permissions.{self.name}.network.enabled=false",
        )

    @property
    def sha256(self) -> str:
        encoded = json.dumps(
            {
                "name": self.name,
                "overrides": self.config_overrides,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ChildRunRequest:
    codex_executable: Path
    codex_version: str
    model: str
    reasoning_effort: str
    permission_profile: PermissionProfileDefinition
    managed_config_sha256: str
    runtime: ChildRuntimeLayout
    output_schema: Path
    prompt: str
    timeout_seconds: float
    max_output_bytes: int
    resource_limits: ChildResourceLimits = ChildResourceLimits()
    auth_file: Path | None = None
    telemetry: ChildTelemetryConfig | None = None

    def __post_init__(self) -> None:
        if not codex_version_supported(self.codex_version):
            raise ValueError("unsupported Codex CLI version")
        efforts = MODEL_EFFORTS.get(self.model)
        if efforts is None:
            raise ValueError("unsupported child model")
        if self.reasoning_effort not in efforts:
            raise ValueError("reasoning effort is invalid for the selected model")
        if _SHA256.fullmatch(self.managed_config_sha256) is None:
            raise ValueError("managed_config_sha256 must be a lowercase SHA-256")
        writable = self.permission_profile.writable_root
        if writable is not None and (
            writable == self.runtime.work_dir
            or writable.parent != self.runtime.root
        ):
            raise ValueError(
                "writer root must be a separate direct child of the runtime"
            )
        if not isinstance(self.prompt, str) or not self.prompt:
            raise ValueError("child prompt must be non-empty")
        if len(self.prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ValueError("child prompt exceeds the byte limit")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0 < float(self.timeout_seconds) <= 3600
        ):
            raise ValueError("timeout_seconds must be in (0, 3600]")
        if (
            type(self.max_output_bytes) is not int
            or not 1024 <= self.max_output_bytes <= 64 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")


@dataclass(frozen=True)
class ChildRunResult:
    exit_code: int
    events: tuple[dict[str, Any], ...]
    stderr: str
    stdout_sha256: str
    probe_id: str
    argv_fingerprint: str

    @property
    def succeeded(self) -> bool:
        return (
            self.exit_code == 0
            and bool(self.events)
            and self.events[-1].get("type") == "turn.completed"
        )


def build_codex_exec_argv(request: ChildRunRequest) -> tuple[str, ...]:
    executable = _safe_executable(request.codex_executable)
    schema = _safe_schema(request.output_schema)
    _validate_runtime(request.runtime)
    _validate_workdir(
        request.runtime.work_dir,
        allow_populated=False,
    )
    if request.permission_profile.writable_root is not None:
        _validate_workdir(
            request.permission_profile.writable_root,
            allow_populated=True,
        )
    profile = request.permission_profile
    arguments: list[str] = [
        os.fspath(executable),
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--ephemeral",
        "--json",
        "--skip-git-repo-check",
        "--model",
        request.model,
        "-C",
        os.fspath(request.runtime.work_dir),
        "--output-schema",
        os.fspath(schema),
        "-c",
        f"model_reasoning_effort={json.dumps(request.reasoning_effort)}",
        "-c",
        'approval_policy="never"',
        "-c",
        f"default_permissions={json.dumps(profile.name)}",
        "-c",
        "project_root_markers=[]",
        "-c",
        "project_doc_max_bytes=0",
        "-c",
        'shell_environment_policy.inherit="none"',
        "-c",
        _shell_environment_override(request),
        "-c",
        "allow_login_shell=false",
        "-c",
        "agents.max_threads=1",
        "-c",
        "agents.max_depth=1",
        "-c",
        'web_search="disabled"',
    ]
    for override in profile.config_overrides:
        arguments.extend(("-c", override))
    for feature in FEATURES_DISABLED_FOR_CHILDREN:
        arguments.extend(("--disable", feature))
    if request.telemetry is not None:
        arguments.extend(
            (
                "-c",
                'otel.environment="adaptive-child"',
                "-c",
                "otel.log_user_prompt=false",
                "-c",
                'otel.metrics_exporter="none"',
                "-c",
                'otel.trace_exporter="none"',
                "-c",
                _otel_exporter_override(request.telemetry),
            )
        )
    return tuple(arguments)


class ChildRunner:
    def __init__(self, permission_gate: PermissionGate) -> None:
        self._permission_gate = permission_gate

    def run(
        self,
        request: ChildRunRequest,
        *,
        cancellation: Event | None = None,
    ) -> ChildRunResult:
        cancellation = cancellation or Event()
        if cancellation.is_set():
            raise ChildLaunchError(
                "CHILD_CANCELLED",
                "child launch was cancelled before admission",
            )
        argv = build_codex_exec_argv(request)
        evidence = self._permission_gate.require_verified(
            CanaryRequest(
                codex_version=request.codex_version,
                permission_profile=request.permission_profile.name,
                profile_sha256=request.permission_profile.sha256,
                managed_config_sha256=request.managed_config_sha256,
            )
        )
        if cancellation.is_set():
            raise ChildLaunchError(
                "CHILD_CANCELLED",
                "child launch was cancelled after permission verification",
            )
        _validate_workdir(
            request.runtime.work_dir,
            allow_populated=False,
        )
        if request.permission_profile.writable_root is not None:
            _validate_workdir(
                request.permission_profile.writable_root,
                allow_populated=True,
            )

        staged_auth = (
            stage_auth_file(request.auth_file, request.runtime.codex_home)
            if request.auth_file is not None
            else None
        )
        try:
            environment = _child_environment(
                request.runtime,
                request.permission_profile.snapshot_root,
                request.telemetry,
                request.permission_profile.writable_root,
            )
            codex_target = Path(argv[0])
            baseline_bytes = _runtime_tree_usage(
                request.runtime.root,
                allowed_arg0_target=codex_target,
            )
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=request.runtime.work_dir,
                    env=environment,
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
                raise ChildLaunchError("CHILD_SPAWN_FAILED", str(exc)) from exc

            stdout, stderr, terminal_reason = _collect_bounded_output(
                process,
                prompt=request.prompt.encode("utf-8"),
                timeout_seconds=float(request.timeout_seconds),
                max_output_bytes=request.max_output_bytes,
                max_memory_bytes=request.resource_limits.max_memory_bytes,
                max_processes=request.resource_limits.max_processes,
                max_growth_bytes=request.resource_limits.max_growth_bytes,
                growth_root=request.runtime.root,
                baseline_bytes=baseline_bytes,
                allowed_arg0_target=codex_target,
                cancellation=cancellation,
            )
            if terminal_reason is not None:
                raise ChildLaunchError(
                    terminal_reason,
                    _reason_message(terminal_reason),
                )

            events = _parse_jsonl(stdout)
            return ChildRunResult(
                exit_code=int(process.returncode),
                events=events,
                stderr=stderr.decode("utf-8", errors="replace"),
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                probe_id=evidence.probe_id,
                argv_fingerprint=hashlib.sha256(
                    "\0".join(argv).encode("utf-8")
                ).hexdigest(),
            )
        finally:
            if staged_auth is not None:
                remove_staged_auth(staged_auth)


def _collect_bounded_output(
    process: subprocess.Popen[bytes],
    *,
    prompt: bytes,
    timeout_seconds: float,
    max_output_bytes: int,
    max_memory_bytes: int,
    max_processes: int,
    max_growth_bytes: int,
    growth_root: Path,
    baseline_bytes: int,
    allowed_arg0_target: Path,
    cancellation: Event,
) -> tuple[bytes, bytes, str | None]:
    assert process.stdout is not None
    assert process.stderr is not None
    assert process.stdin is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): ("stdout", bytearray()),
        process.stderr.fileno(): ("stderr", bytearray()),
    }
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    stdin_fd = process.stdin.fileno()
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    os.set_blocking(stdin_fd, False)
    selector.register(stdin_fd, selectors.EVENT_WRITE)

    deadline = time.monotonic() + timeout_seconds
    reason: str | None = None
    total_seen = 0
    total_stored = 0
    prompt_offset = 0
    stdin_open = True
    next_resource_check = 0.0
    while selector.get_map() or process.poll() is None:
        if reason is None and cancellation.is_set():
            reason = "CHILD_CANCELLED"
            _close_stdin(selector, process, stdin_fd)
            stdin_open = False
            _terminate_process_group(process)
        now = time.monotonic()
        if reason is None and now >= next_resource_check:
            next_resource_check = now + 0.2
            try:
                growth = (
                    _runtime_tree_usage(
                        growth_root,
                        allowed_arg0_target=allowed_arg0_target,
                    )
                    - baseline_bytes
                )
                process_count, memory_bytes = _process_group_usage(
                    process.pid
                )
            except ChildLaunchError as exc:
                reason = (
                    exc.code
                    if exc.code
                    in {"CHILD_DISK_LIMIT", "CHILD_RESOURCE_PROBE_FAILED"}
                    else "CHILD_RESOURCE_PROBE_FAILED"
                )
                _close_stdin(selector, process, stdin_fd)
                stdin_open = False
                _terminate_process_group(process)
            else:
                if growth > max_growth_bytes:
                    reason = "CHILD_DISK_LIMIT"
                elif process_count > max_processes:
                    reason = "CHILD_PROCESS_LIMIT"
                elif memory_bytes > max_memory_bytes:
                    reason = "CHILD_MEMORY_LIMIT"
                if reason is not None:
                    _close_stdin(selector, process, stdin_fd)
                    stdin_open = False
                    _terminate_process_group(process)
        if reason is None and time.monotonic() >= deadline:
            reason = "CHILD_TIMEOUT"
            _close_stdin(selector, process, stdin_fd)
            stdin_open = False
            _terminate_process_group(process)
        for key, _ in selector.select(timeout=0.05):
            descriptor = int(key.fd)
            if descriptor == stdin_fd:
                try:
                    written = os.write(stdin_fd, prompt[prompt_offset:])
                except (BlockingIOError, InterruptedError):
                    continue
                except (BrokenPipeError, OSError):
                    _close_stdin(selector, process, stdin_fd)
                    stdin_open = False
                    continue
                prompt_offset += written
                if prompt_offset == len(prompt):
                    _close_stdin(selector, process, stdin_fd)
                    stdin_open = False
                continue
            try:
                chunk = os.read(descriptor, READ_CHUNK)
            except BlockingIOError:
                continue
            if not chunk:
                selector.unregister(descriptor)
                continue
            total_seen += len(chunk)
            _, target = streams[descriptor]
            remaining = max(0, max_output_bytes - total_stored)
            if remaining:
                stored = chunk[:remaining]
                target.extend(stored)
                total_stored += len(stored)
            if reason is None and total_seen > max_output_bytes:
                reason = "OUTPUT_LIMIT_EXCEEDED"
                _close_stdin(selector, process, stdin_fd)
                stdin_open = False
                _terminate_process_group(process)
        if process.poll() is not None and stdin_open:
            _close_stdin(selector, process, stdin_fd)
            stdin_open = False
        if process.poll() is not None and not selector.get_map():
            break
    selector.close()
    if process.poll() is None:
        _terminate_process_group(process)
    process.wait()
    stdout = bytes(streams[stdout_fd][1])
    stderr = bytes(streams[stderr_fd][1])
    process.stdout.close()
    process.stderr.close()
    if not process.stdin.closed:
        process.stdin.close()
    return stdout, stderr, reason


def _process_group_usage(process_group: int) -> tuple[int, int]:
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pgid=,rss="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": FIXED_PATH,
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ChildLaunchError(
            "CHILD_RESOURCE_PROBE_FAILED",
            "child process resources could not be measured",
        ) from exc
    if result.returncode != 0:
        raise ChildLaunchError(
            "CHILD_RESOURCE_PROBE_FAILED",
            "child process resources could not be measured",
        )
    process_count = 0
    total_kib = 0
    try:
        for raw_line in result.stdout.splitlines():
            raw_group, raw_rss = raw_line.split()
            if int(raw_group) == process_group:
                process_count += 1
                total_kib += int(raw_rss)
    except (IndexError, ValueError) as exc:
        raise ChildLaunchError(
            "CHILD_RESOURCE_PROBE_FAILED",
            "child process resource output is malformed",
        ) from exc
    return process_count, total_kib * 1024


def _runtime_tree_usage(
    root: Path,
    *,
    allowed_arg0_target: Path | None = None,
) -> int:
    total = 0
    entries = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            entries += 1
            try:
                metadata = (current_path / name).lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(
                metadata.st_mode
            ):
                raise ChildLaunchError(
                    "CHILD_RESOURCE_PROBE_FAILED",
                    "child runtime contains an unsafe directory entry",
                )
        for name in files:
            entries += 1
            path = current_path / name
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                if not _is_allowed_arg0_alias(
                    root,
                    path,
                    metadata,
                    allowed_target=allowed_arg0_target,
                ):
                    raise ChildLaunchError(
                        "CHILD_RESOURCE_PROBE_FAILED",
                        "child runtime contains an unsafe symbolic link",
                    )
                total += metadata.st_size
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ChildLaunchError(
                    "CHILD_RESOURCE_PROBE_FAILED",
                    "child runtime contains an unsafe file entry",
                )
            total += metadata.st_size
        if entries > 200_000:
            raise ChildLaunchError(
                "CHILD_DISK_LIMIT",
                "child runtime contains too many entries",
            )
    return total


def _is_allowed_arg0_alias(
    root: Path,
    path: Path,
    metadata: os.stat_result,
    *,
    allowed_target: Path | None,
) -> bool:
    if (
        allowed_target is None
        or not allowed_target.is_absolute()
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        return False
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    parts = relative.parts
    if (
        len(parts) != 5
        or parts[:3] != ("codex-home", "tmp", "arg0")
        or _ARG0_SESSION.fullmatch(parts[3]) is None
        or parts[4] not in _ARG0_ALIASES
    ):
        return False
    session = root.joinpath(*parts[:4])
    for parent in (
        root,
        root / "codex-home",
        root / "codex-home" / "tmp",
        root / "codex-home" / "tmp" / "arg0",
        session,
    ):
        try:
            parent_metadata = parent.lstat()
        except OSError:
            return False
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        ):
            return False
    lock = session / ".lock"
    try:
        lock_metadata = lock.lstat()
        raw_target = os.readlink(path)
        target_metadata = allowed_target.lstat()
        observed_target_metadata = path.stat()
    except OSError:
        return False
    if (
        not stat.S_ISREG(lock_metadata.st_mode)
        or lock_metadata.st_uid != os.getuid()
        or lock_metadata.st_nlink != 1
        or stat.S_IMODE(lock_metadata.st_mode) & 0o077
        or not stat.S_ISREG(target_metadata.st_mode)
        or target_metadata.st_uid != os.getuid()
        or not Path(raw_target).is_absolute()
        or Path(raw_target) != allowed_target
        or (
            observed_target_metadata.st_dev,
            observed_target_metadata.st_ino,
        )
        != (target_metadata.st_dev, target_metadata.st_ino)
    ):
        return False
    return True


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        process.poll()
        return
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        process.poll()
        if not _process_group_exists(process_group):
            return
        time.sleep(0.01)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass


def _parse_jsonl(output: bytes) -> tuple[dict[str, Any], ...]:
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ChildLaunchError(
            "CHILD_PROTOCOL_ERROR",
            "Codex JSONL output is not valid UTF-8",
        ) from exc
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ChildLaunchError(
                "CHILD_PROTOCOL_ERROR",
                "Codex emitted an invalid JSONL record",
            ) from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ChildLaunchError(
                "CHILD_PROTOCOL_ERROR",
                "Codex emitted a JSONL record without a string type",
            )
        events.append(event)
        if len(events) > 4096:
            raise ChildLaunchError(
                "CHILD_PROTOCOL_ERROR",
                "Codex emitted too many JSONL records",
            )
    if not events:
        raise ChildLaunchError(
            "CHILD_PROTOCOL_ERROR",
            "Codex emitted no JSONL events",
        )
    return tuple(events)


def _child_environment(
    runtime: ChildRuntimeLayout,
    snapshot_root: Path,
    telemetry: ChildTelemetryConfig | None,
    writable_root: Path | None,
) -> dict[str, str]:
    environment = {
        "CODEX_ADAPTIVE_CHILD": "1",
        "CODEX_ADAPTIVE_SNAPSHOT_ROOT": os.fspath(snapshot_root),
        "CODEX_HOME": os.fspath(runtime.codex_home),
        "CODEX_SQLITE_HOME": os.fspath(runtime.sqlite_home),
        "HOME": os.fspath(runtime.home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": FIXED_PATH,
        "TMPDIR": os.fspath(runtime.tmpdir),
    }
    if writable_root is not None:
        environment["CODEX_ADAPTIVE_WORKSPACE_ROOT"] = os.fspath(
            writable_root
        )
    if telemetry is not None:
        environment["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = (
            f"{telemetry.header_name}={quote(telemetry.token, safe='')}"
        )
    return environment


def _otel_exporter_override(telemetry: ChildTelemetryConfig) -> str:
    return (
        "otel.exporter={ otlp-http = { endpoint="
        f"{json.dumps(telemetry.endpoint)}, protocol=\"json\", "
        "headers={} } }"
    )


def stage_auth_file(source: Path, codex_home: Path) -> Path:
    """Копирует частный файл аутентификации в изолированный CODEX_HOME."""
    if not source.is_absolute() or source.is_symlink():
        raise ChildLaunchError(
            "UNSAFE_AUTH_FILE",
            "authentication file must be an absolute non-symlink path",
        )
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(source, source_flags)
    except OSError as exc:
        raise ChildLaunchError("UNSAFE_AUTH_FILE", str(exc)) from exc
    destination = codex_home / "auth.json"
    try:
        metadata = os.fstat(source_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 0 < metadata.st_size <= _MAX_AUTH_BYTES
        ):
            raise ChildLaunchError(
                "UNSAFE_AUTH_FILE",
                "authentication file must be private, owned, and bounded",
            )
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            destination_flags |= os.O_NOFOLLOW
        destination_fd = os.open(destination, destination_flags, 0o600)
        try:
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(source_fd, min(remaining, READ_CHUNK))
                if not chunk:
                    raise ChildLaunchError(
                        "UNSAFE_AUTH_FILE",
                        "authentication file changed while being staged",
                    )
                view = memoryview(chunk)
                while view:
                    view = view[os.write(destination_fd, view) :]
                remaining -= len(chunk)
            if os.read(source_fd, 1):
                raise ChildLaunchError(
                    "UNSAFE_AUTH_FILE",
                    "authentication file grew while being staged",
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


def remove_staged_auth(path: Path) -> None:
    """Удаляет ранее подготовленный файл, отклоняя подмену пути."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise ChildLaunchError(
            "AUTH_CLEANUP_FAILED",
            "staged authentication path changed during execution",
        )
    path.unlink()


def _shell_environment_override(request: ChildRunRequest) -> str:
    values = [
        ("HOME", os.fspath(request.runtime.home)),
        ("TMPDIR", os.fspath(request.runtime.tmpdir)),
        ("PATH", FIXED_PATH),
        (
            "CODEX_SQLITE_HOME",
            os.fspath(request.runtime.sqlite_home),
        ),
        (
            "CODEX_ADAPTIVE_SNAPSHOT_ROOT",
            os.fspath(request.permission_profile.snapshot_root),
        ),
    ]
    if request.permission_profile.writable_root is not None:
        values.append(
            (
                "CODEX_ADAPTIVE_WORKSPACE_ROOT",
                os.fspath(request.permission_profile.writable_root),
            )
        )
    encoded = ",".join(
        f"{name}={json.dumps(value)}" for name, value in values
    )
    return f"shell_environment_policy.set={{{encoded}}}"


def _safe_executable(path: Path) -> Path:
    if not path.is_absolute():
        raise ChildLaunchError(
            "UNSAFE_EXECUTABLE",
            "Codex executable must be an absolute path",
        )
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ChildLaunchError("UNSAFE_EXECUTABLE", str(exc)) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o111 == 0
    ):
        raise ChildLaunchError(
            "UNSAFE_EXECUTABLE",
            "Codex executable must be an owned executable regular file",
        )
    return resolved


def _safe_schema(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ChildLaunchError(
            "UNSAFE_OUTPUT_SCHEMA",
            "output schema must be an absolute non-symlink path",
        )
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ChildLaunchError("UNSAFE_OUTPUT_SCHEMA", str(exc)) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_SCHEMA_BYTES
        or metadata.st_mode & 0o022
    ):
        raise ChildLaunchError(
            "UNSAFE_OUTPUT_SCHEMA",
            "output schema is not a private immutable regular file",
        )
    return resolved


def _validate_runtime(runtime: ChildRuntimeLayout) -> None:
    root = _plain_directory(runtime.root, code="UNSAFE_RUNTIME_ROOT")
    expected = (
        runtime.home,
        runtime.tmpdir,
        runtime.codex_home,
        runtime.sqlite_home,
        runtime.work_dir,
    )
    resolved = tuple(
        _plain_directory(path, code="UNSAFE_RUNTIME_ROOT") for path in expected
    )
    if len(set(resolved)) != len(resolved):
        raise ChildLaunchError(
            "UNSAFE_RUNTIME_ROOT",
            "runtime directories must be distinct",
        )
    for path in resolved:
        if path.parent != root:
            raise ChildLaunchError(
                "UNSAFE_RUNTIME_ROOT",
                "runtime directories must be direct children of the runtime root",
            )


def _validate_workdir(work_dir: Path, *, allow_populated: bool) -> None:
    try:
        next(work_dir.iterdir())
    except StopIteration:
        return
    except OSError as exc:
        raise ChildLaunchError("UNSAFE_RUNTIME_ROOT", str(exc)) from exc
    if not allow_populated:
        raise ChildLaunchError(
            "WORKDIR_NOT_EMPTY",
            "reader Codex must start from an empty working directory",
        )
    count = 0
    for current, directories, files in os.walk(
        work_dir,
        followlinks=False,
    ):
        current_path = Path(current)
        for name in directories:
            count += 1
            path = current_path / name
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or name.casefold() == ".git"
            ):
                raise ChildLaunchError(
                    "WORKDIR_UNSAFE",
                    "writer workspace contains an unsafe directory",
                )
        for name in files:
            count += 1
            path = current_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o700}
                or name.casefold() == ".git"
            ):
                raise ChildLaunchError(
                    "WORKDIR_UNSAFE",
                    "writer workspace contains an unsafe file",
                )
        if count > 100_000:
            raise ChildLaunchError(
                "WORKDIR_UNSAFE",
                "writer workspace exceeds the validation entry limit",
            )


def _plain_directory(
    path: Path,
    *,
    code: str,
    require_read_only: bool = False,
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ChildLaunchError(code, "path must be an absolute non-symlink directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ChildLaunchError(code, str(exc)) from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ChildLaunchError(code, "directory must be owned by the current user")
    if require_read_only:
        if metadata.st_mode & 0o222:
            raise ChildLaunchError(code, "snapshot root must be read-only")
    elif stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ChildLaunchError(code, "runtime directory mode must be 0700")
    return resolved


def _validate_read_only_tree(root: Path) -> None:
    count = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            count += 1
            path = current_path / name
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o222
            ):
                raise ChildLaunchError(
                    "UNSAFE_SNAPSHOT_ROOT",
                    "snapshot contains an unsafe directory",
                )
        for name in files:
            count += 1
            path = current_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o222
            ):
                raise ChildLaunchError(
                    "UNSAFE_SNAPSHOT_ROOT",
                    "snapshot contains an unsafe file",
                )
        if count > 100_000:
            raise ChildLaunchError(
                "UNSAFE_SNAPSHOT_ROOT",
                "snapshot tree exceeds the validation entry limit",
            )


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


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False
    return True


def _remove_private_runtime(root: Path) -> None:
    for current, directories, files in os.walk(root, topdown=False):
        current_path = Path(current)
        for name in files:
            (current_path / name).unlink()
        for name in directories:
            (current_path / name).rmdir()
    root.rmdir()


def _reason_message(code: str) -> str:
    return {
        "CHILD_CANCELLED": "child process group was cancelled",
        "CHILD_TIMEOUT": "child process exceeded its time limit",
        "OUTPUT_LIMIT_EXCEEDED": "child output exceeded its byte limit",
        "CHILD_DISK_LIMIT": "child runtime exceeded its growth limit",
        "CHILD_PROCESS_LIMIT": "child process group exceeded its process limit",
        "CHILD_MEMORY_LIMIT": "child process group exceeded its memory limit",
        "CHILD_RESOURCE_PROBE_FAILED": (
            "child process resources could not be measured safely"
        ),
    }[code]
