"""Shell-free, bounded validation of materialized quarantine candidates."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Iterable

from .child_runner import FEATURES_DISABLED_FOR_CHILDREN
from .live_canary import ManagedConfigInspector, ManagedConfigState


FIXED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
READ_CHUNK = 64 * 1024


@dataclass
class ValidationError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ValidationCommandResult:
    catalog_argv: tuple[str, ...]
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str


@dataclass(frozen=True)
class ValidationResult:
    validation_state: str
    commands: tuple[ValidationCommandResult, ...]


@dataclass(frozen=True)
class ValidationLimits:
    timeout_seconds: float
    max_output_bytes: int
    max_address_space_bytes: int
    max_processes: int
    max_file_bytes: int
    max_open_files: int
    max_growth_bytes: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not 0 < float(self.timeout_seconds) <= 3600
        ):
            raise ValueError("validation timeout is outside the supported range")
        for name in (
            "max_output_bytes",
            "max_address_space_bytes",
            "max_processes",
            "max_file_bytes",
            "max_open_files",
            "max_growth_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not 1024 <= self.max_output_bytes <= 64 * 1024 * 1024:
            raise ValueError("validation output limit is outside the supported range")


@dataclass(frozen=True)
class ValidationSandbox:
    codex_executable: Path
    helper_executable: Path
    permission_profile_name: str

    def __post_init__(self) -> None:
        executable = _safe_executable(
            self.codex_executable,
            "validation Codex executable",
            allow_symlink=True,
        )
        helper = _safe_executable(
            self.helper_executable,
            "validation limit helper",
            allow_symlink=False,
        )
        name = self.permission_profile_name
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 64
            or not name[0].isalpha()
            or not all(character.isalnum() or character in "_-" for character in name)
        ):
            raise ValueError("validation permission profile name is unsafe")
        object.__setattr__(self, "codex_executable", executable)
        object.__setattr__(self, "helper_executable", helper)

    def wrap(
        self,
        workspace: Path,
        control_cwd: Path,
        command: tuple[str, ...],
        limits: ValidationLimits,
    ) -> tuple[str, ...]:
        quoted_name = json.dumps(self.permission_profile_name)
        profile = f"permissions.{self.permission_profile_name}"
        quoted_workspace = json.dumps(os.fspath(workspace))
        filesystem = (
            f"{profile}.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="write"},'
            f"{quoted_workspace}=\"write\","
            f"{json.dumps(os.fspath(self.helper_executable))}=\"read\"}}"
        )
        arguments = [
            os.fspath(self.codex_executable),
            "sandbox",
            "-P",
            self.permission_profile_name,
            "--include-managed-config",
            "-C",
            os.fspath(control_cwd),
            "-c",
            f"{profile}.description={json.dumps('Adaptive candidate validator')}",
            "-c",
            filesystem,
            "-c",
            f"{profile}.network.enabled=false",
            "-c",
            f"default_permissions={quoted_name}",
            "-c",
            "project_root_markers=[]",
            "-c",
            "project_doc_max_bytes=0",
            "-c",
            "agents.max_threads=1",
            "-c",
            "agents.max_depth=1",
            "-c",
            'web_search="disabled"',
        ]
        for feature in FEATURES_DISABLED_FOR_CHILDREN:
            arguments.extend(("--disable", feature))
        arguments.extend(
            (
            "--",
            os.fspath(self.helper_executable),
            "--address-space",
            str(limits.max_address_space_bytes),
            "--processes",
            str(limits.max_processes),
            "--file-size",
            str(limits.max_file_bytes),
            "--open-files",
            str(limits.max_open_files),
            "--cwd",
            os.fspath(workspace),
            "--",
            *command,
            )
        )
        return tuple(arguments)


class ValidationRunner:
    def __init__(
        self,
        *,
        sandbox: ValidationSandbox,
        limits: ValidationLimits,
        managed_config_inspector: ManagedConfigInspector | None = None,
        expected_managed_config_sha256: str | None = None,
    ) -> None:
        if (managed_config_inspector is None) != (
            expected_managed_config_sha256 is None
        ):
            raise ValueError(
                "managed configuration inspector and hash must be configured together"
            )
        if expected_managed_config_sha256 is not None and (
            len(expected_managed_config_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_managed_config_sha256
            )
        ):
            raise ValueError(
                "expected managed configuration hash must be a SHA-256"
            )
        self.sandbox = sandbox
        self.limits = limits
        self.managed_config_inspector = managed_config_inspector
        self.expected_managed_config_sha256 = (
            expected_managed_config_sha256
        )

    def run(
        self,
        *,
        workspace: Path,
        commands: Iterable[Iterable[str]],
        cancellation: Event,
    ) -> ValidationResult:
        root = _safe_workspace(workspace)
        catalog_commands = tuple(_safe_argv(command) for command in commands)
        results: list[ValidationCommandResult] = []
        with tempfile.TemporaryDirectory(
            prefix=".adaptive-validation-",
            dir=root.parent,
        ) as raw_runtime:
            runtime = Path(raw_runtime)
            runtime.chmod(0o700)
            home = _new_private_directory(runtime / "home")
            codex_home = _new_private_directory(runtime / "codex-home")
            tmpdir = _new_private_directory(runtime / "tmp")
            control_cwd = _new_private_directory(runtime / "control")
            growth_roots = (root, runtime)
            baseline_bytes = _tree_usage_many(growth_roots)
            for command in catalog_commands:
                if cancellation.is_set():
                    raise ValidationError(
                        "VALIDATION_CANCELLED",
                        "candidate validation was cancelled",
                    )
                self._verify_managed_config()
                argv = self.sandbox.wrap(
                    root,
                    control_cwd,
                    command,
                    self.limits,
                )
                exit_code, stdout, stderr = _run_bounded(
                    argv=argv,
                    cwd=control_cwd,
                    home=home,
                    codex_home=codex_home,
                    tmpdir=tmpdir,
                    growth_roots=growth_roots,
                    timeout_seconds=float(self.limits.timeout_seconds),
                    max_output_bytes=self.limits.max_output_bytes,
                    max_memory_bytes=self.limits.max_address_space_bytes,
                    max_processes=self.limits.max_processes,
                    max_growth_bytes=self.limits.max_growth_bytes,
                    baseline_bytes=baseline_bytes,
                    cancellation=cancellation,
                )
                results.append(
                    ValidationCommandResult(
                        catalog_argv=command,
                        exit_code=exit_code,
                        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
                    )
                )
                if exit_code != 0:
                    return ValidationResult("failed", tuple(results))
        return ValidationResult(
            "passed" if results else "not_applicable",
            tuple(results),
        )

    def _verify_managed_config(self) -> None:
        inspector = self.managed_config_inspector
        expected = self.expected_managed_config_sha256
        if inspector is None or expected is None:
            return
        try:
            state = inspector.inspect()
        except Exception as exc:
            raise ValidationError(
                "MANAGED_CONFIG_UNAVAILABLE",
                "managed configuration could not be rechecked",
            ) from exc
        if not isinstance(state, ManagedConfigState):
            raise ValidationError(
                "MANAGED_CONFIG_INVALID",
                "managed configuration state is malformed",
            )
        if state.legacy_sandbox_mode:
            raise ValidationError(
                "LEGACY_SANDBOX_MODE",
                "legacy sandbox mode is forbidden for candidate validation",
            )
        if state.sha256 != expected:
            raise ValidationError(
                "MANAGED_CONFIG_CHANGED",
                "managed configuration changed before candidate validation",
            )


def _safe_workspace(path: Path) -> Path:
    if path.is_symlink():
        raise ValidationError(
            "VALIDATION_WORKSPACE_UNSAFE",
            "validation workspace must not be a symbolic link",
        )
    try:
        root = path.expanduser().resolve(strict=True)
        metadata = root.stat()
    except OSError as exc:
        raise ValidationError(
            "VALIDATION_WORKSPACE_UNSAFE",
            "validation workspace is unavailable",
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValidationError(
            "VALIDATION_WORKSPACE_UNSAFE",
            "validation workspace must be a private owned directory",
        )
    return root


def _safe_executable(
    path: Path,
    label: str,
    *,
    allow_symlink: bool,
) -> Path:
    if not path.is_absolute() or (path.is_symlink() and not allow_symlink):
        raise ValueError(f"{label} is unsafe")
    try:
        executable = path.expanduser().resolve(strict=True)
        metadata = executable.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or (not allow_symlink and metadata.st_nlink != 1)
        or metadata.st_mode & 0o111 == 0
        or metadata.st_mode & 0o022
    ):
        raise ValueError(f"{label} is unsafe")
    return executable


def _safe_argv(values: Iterable[str]) -> tuple[str, ...]:
    try:
        command = tuple(values)
    except TypeError as exc:
        raise ValidationError(
            "VALIDATION_ARGV_UNSAFE",
            "validation command must be an argv sequence",
        ) from exc
    if (
        not command
        or len(command) > 256
        or not all(
            isinstance(value, str)
            and value
            and "\0" not in value
            and len(value.encode("utf-8")) <= 64 * 1024
            for value in command
        )
        or not Path(command[0]).is_absolute()
    ):
        raise ValidationError(
            "VALIDATION_ARGV_UNSAFE",
            "validation command must use a bounded absolute argv",
        )
    return command


def _run_bounded(
    *,
    argv: tuple[str, ...],
    cwd: Path,
    home: Path,
    codex_home: Path,
    tmpdir: Path,
    growth_roots: tuple[Path, ...],
    timeout_seconds: float,
    max_output_bytes: int,
    max_memory_bytes: int,
    max_processes: int,
    max_growth_bytes: int,
    baseline_bytes: int,
    cancellation: Event,
) -> tuple[int, bytes, bytes]:
    environment = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "CODEX_HOME": os.fspath(codex_home),
        "HOME": os.fspath(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": FIXED_PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": os.fspath(tmpdir),
    }
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            restore_signals=True,
            umask=0o077,
        )
    except OSError as exc:
        raise ValidationError(
            "VALIDATION_SPAWN_FAILED",
            "validation command could not be started",
        ) from exc
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): bytearray(),
        process.stderr.fileno(): bytearray(),
    }
    for descriptor in streams:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    reason: str | None = None
    total = 0
    stored = 0
    next_resource_check = 0.0
    try:
        while selector.get_map() or process.poll() is None:
            if reason is None and cancellation.is_set():
                reason = "VALIDATION_CANCELLED"
                _terminate(process)
            if reason is None and time.monotonic() >= deadline:
                reason = "VALIDATION_TIMEOUT"
                _terminate(process)
            now = time.monotonic()
            if reason is None and now >= next_resource_check:
                next_resource_check = now + 0.2
                if (
                    _tree_usage_many(growth_roots) - baseline_bytes
                    > max_growth_bytes
                ):
                    reason = "VALIDATION_DISK_LIMIT"
                    _terminate(process)
                else:
                    process_count, memory_bytes = _process_group_usage(
                        process.pid
                    )
                    if process_count > max_processes:
                        reason = "VALIDATION_PROCESS_LIMIT"
                        _terminate(process)
                    elif memory_bytes > max_memory_bytes:
                        reason = "VALIDATION_MEMORY_LIMIT"
                        _terminate(process)
            for key, _events in selector.select(timeout=0.05):
                descriptor = int(key.fd)
                try:
                    chunk = os.read(descriptor, READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                total += len(chunk)
                remaining = max(0, max_output_bytes - stored)
                selected = chunk[:remaining]
                streams[descriptor].extend(selected)
                stored += len(selected)
                if reason is None and total > max_output_bytes:
                    reason = "VALIDATION_OUTPUT_LIMIT"
                    _terminate(process)
            if process.poll() is not None and not selector.get_map():
                break
    except BaseException:
        if process.poll() is None:
            _terminate(process)
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
        raise
    selector.close()
    if process.poll() is None:
        _terminate(process)
    process.wait()
    stdout = bytes(streams[process.stdout.fileno()])
    stderr = bytes(streams[process.stderr.fileno()])
    process.stdout.close()
    process.stderr.close()
    if reason is not None:
        raise ValidationError(reason, "candidate validation did not complete safely")
    if _tree_usage_many(growth_roots) - baseline_bytes > max_growth_bytes:
        raise ValidationError(
            "VALIDATION_DISK_LIMIT",
            "candidate validation exceeded its disk-growth limit",
        )
    return int(process.returncode), stdout, stderr


def _tree_usage(root: Path) -> int:
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
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValidationError(
                    "VALIDATION_WORKSPACE_TAINTED",
                    "validation created an unsafe directory entry",
                )
        for name in files:
            entries += 1
            try:
                metadata = (current_path / name).lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValidationError(
                    "VALIDATION_WORKSPACE_TAINTED",
                    "validation created an unsafe file entry",
                )
            total += metadata.st_size
        if entries > 200_000:
            raise ValidationError(
                "VALIDATION_DISK_LIMIT",
                "validation workspace contains too many entries",
            )
    return total


def _tree_usage_many(roots: tuple[Path, ...]) -> int:
    return sum(_tree_usage(root) for root in roots)


def _new_private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path.resolve(strict=True)


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
        raise ValidationError(
            "VALIDATION_MEMORY_UNAVAILABLE",
            "validation memory usage could not be measured",
        ) from exc
    if result.returncode != 0:
        raise ValidationError(
            "VALIDATION_MEMORY_UNAVAILABLE",
            "validation memory usage could not be measured",
        )
    total_kib = 0
    process_count = 0
    try:
        for raw_line in result.stdout.splitlines():
            raw_group, raw_rss = raw_line.split()
            if int(raw_group) == process_group:
                process_count += 1
                total_kib += int(raw_rss)
    except (ValueError, IndexError) as exc:
        raise ValidationError(
            "VALIDATION_MEMORY_UNAVAILABLE",
            "validation memory output is malformed",
        ) from exc
    return process_count, total_kib * 1024




def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.poll()
        return
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
