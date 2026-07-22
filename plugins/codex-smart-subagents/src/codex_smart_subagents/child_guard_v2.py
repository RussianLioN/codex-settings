"""Отдельный сторож: HELLO, долговечный COMMIT и только затем ``execve``."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import json
import os
import select
import selectors
import signal
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .canonical_json import canonical_json_v1
from .child_launch_v2 import (
    PreparedChildLaunchV2,
    child_argv_fingerprint_v2,
    require_child_environment_integrity_v2,
)


_MAX_FRAME_BYTES = 16 * 1024
_MAX_CONFIG_FRAME_BYTES = 512 * 1024
_READ_CHUNK = 64 * 1024
_PROC_PIDTBSDINFO = 3


class _DarwinProcBSDInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


@dataclass
class ChildGuardV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class GuardHelloV2:
    protocol_version: int
    permit_id: str
    one_time_token: str
    pid: int
    process_start_marker: str
    argv_fingerprint: str
    snapshot_identity_fingerprint: str


@dataclass(frozen=True)
class GuardExecConfirmationV2:
    pid: int
    process_start_marker: str


@dataclass(frozen=True)
class GuardExecutionResultV2:
    exit_code: int
    stdout: bytes
    stderr: bytes


class SnapshotProbeV2(Protocol):
    def __call__(self, prepared: PreparedChildLaunchV2) -> Any: ...


class ProcessStartMarkerProviderV2(Protocol):
    def __call__(self, pid: int) -> str: ...


class GuardHandleV2(Protocol):
    def receive_hello(self, timeout_seconds: float) -> GuardHelloV2: ...

    def authorize_commit(
        self, one_time_token: str, timeout_seconds: float
    ) -> GuardExecConfirmationV2: ...

    def collect(
        self,
        stdin: bytes,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> GuardExecutionResultV2: ...

    def abort(self) -> None: ...


class GuardFactoryV2(Protocol):
    def start(
        self,
        prepared: PreparedChildLaunchV2,
        *,
        permit_id: str,
        one_time_token: str,
        snapshot_probe: SnapshotProbeV2,
    ) -> GuardHandleV2: ...


class PosixSpawnGuardFactoryV2:
    """Создаёт свежий процесс сторожа без ``fork`` многопоточного Python."""

    def __init__(
        self,
        process_start_marker_provider: ProcessStartMarkerProviderV2 | None = None,
    ) -> None:
        self.process_start_marker_provider = (
            process_start_marker_provider or system_process_start_marker_v2
        )
        if not callable(self.process_start_marker_provider):
            raise TypeError("process_start_marker_provider must be callable")

    def start(
        self,
        prepared: PreparedChildLaunchV2,
        *,
        permit_id: str,
        one_time_token: str,
        snapshot_probe: SnapshotProbeV2,
    ) -> GuardHandleV2:
        if not callable(snapshot_probe):
            raise TypeError("snapshot_probe must be callable")
        _require_argv_fingerprint(prepared)
        pipes = [_pipe() for _ in range(6)]
        (
            (control_r, control_w),
            (hello_r, hello_w),
            (error_r, error_w),
            (
                stdin_r,
                stdin_w,
            ),
            (stdout_r, stdout_w),
            (stderr_r, stderr_w),
        ) = pipes
        all_descriptors = tuple(
            descriptor for pair in pipes for descriptor in pair
        )
        first_protocol_fd = max(all_descriptors) + 8
        child_control_fd = first_protocol_fd
        child_hello_fd = first_protocol_fd + 1
        child_error_fd = first_protocol_fd + 2
        file_actions: list[tuple[int, ...]] = [
            (os.POSIX_SPAWN_DUP2, control_r, child_control_fd),
            (os.POSIX_SPAWN_DUP2, hello_w, child_hello_fd),
            (os.POSIX_SPAWN_DUP2, error_w, child_error_fd),
            (os.POSIX_SPAWN_DUP2, stdin_r, 0),
            (os.POSIX_SPAWN_DUP2, stdout_w, 1),
            (os.POSIX_SPAWN_DUP2, stderr_w, 2),
        ]
        file_actions.extend(
            (os.POSIX_SPAWN_CLOSE, descriptor)
            for descriptor in all_descriptors
        )
        helper = Path(__file__).with_name("child_guard_process_v2.py").absolute()
        helper_environment = {
            "PATH": os.defpath,
            "LC_CTYPE": "UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "CODEX_GUARD_CONTROL_FD": str(child_control_fd),
            "CODEX_GUARD_HELLO_FD": str(child_hello_fd),
            "CODEX_GUARD_ERROR_FD": str(child_error_fd),
        }
        try:
            pid = os.posix_spawn(
                sys.executable,
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(helper),
                ),
                helper_environment,
                file_actions=file_actions,
                setsid=True,
                setsigmask=(),
            )
        except BaseException:
            for pair in pipes:
                _close_many(pair)
            raise
        _close_many((control_r, hello_w, error_w, stdin_r, stdout_w, stderr_w))
        try:
            _write_frame(
                control_w,
                _guard_config_document_v2(
                    prepared,
                    permit_id=permit_id,
                    one_time_token=one_time_token,
                ),
                max_frame_bytes=_MAX_CONFIG_FRAME_BYTES,
            )
        except BaseException:
            _close_many((control_w, hello_r, error_r, stdin_w, stdout_r, stderr_r))
            _terminate_and_reap(pid, timeout_seconds=1.0)
            raise
        return _ForkExecGuardHandleV2(
            pid=pid,
            permit_id=permit_id,
            one_time_token=one_time_token,
            argv_fingerprint=prepared.argv_fingerprint,
            snapshot_identity_fingerprint=prepared.snapshot_identity_fingerprint,
            process_start_marker_provider=self.process_start_marker_provider,
            control_fd=control_w,
            hello_fd=hello_r,
            error_fd=error_r,
            stdin_fd=stdin_w,
            stdout_fd=stdout_r,
            stderr_fd=stderr_r,
        )


# Совместимое имя публичного контракта сохраняется для уже собранных портов.
ForkExecGuardFactoryV2 = PosixSpawnGuardFactoryV2


@dataclass(frozen=True)
class _GuardPreparedLaunchV2:
    executable: Path
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    argv_fingerprint: str
    snapshot_sha256: str
    snapshot_identity_fingerprint: str
    argv_domain: str
    environment_domain: str
    secret_domain: str
    non_secret_environment: Mapping[str, str]
    environment_fingerprint: str
    secret_sha256: str


def _guard_config_document_v2(
    prepared: PreparedChildLaunchV2,
    *,
    permit_id: str,
    one_time_token: str,
) -> dict[str, Any]:
    return {
        "frame": "CONFIG",
        "protocolVersion": 2,
        "permitId": permit_id,
        "oneTimeToken": one_time_token,
        "executable": str(prepared.executable),
        "argv": list(prepared.argv),
        "environment": dict(prepared.environment),
        "argvFingerprint": prepared.argv_fingerprint,
        "snapshotSha256": prepared.snapshot_sha256,
        "snapshotIdentityFingerprint": prepared.snapshot_identity_fingerprint,
        "argvDomain": prepared.argv_domain,
        "environmentDomain": prepared.environment_domain,
        "secretDomain": prepared.secret_domain,
        "nonSecretEnvironment": dict(prepared.non_secret_environment),
        "environmentFingerprint": prepared.environment_fingerprint,
        "secretSha256": prepared.secret_sha256,
    }


def _prepared_from_guard_config_v2(
    value: Mapping[str, Any],
) -> tuple[_GuardPreparedLaunchV2, str, str]:
    expected = {
        "frame",
        "protocolVersion",
        "permitId",
        "oneTimeToken",
        "executable",
        "argv",
        "environment",
        "argvFingerprint",
        "snapshotSha256",
        "snapshotIdentityFingerprint",
        "argvDomain",
        "environmentDomain",
        "secretDomain",
        "nonSecretEnvironment",
        "environmentFingerprint",
        "secretSha256",
    }
    if set(value) != expected or value.get("frame") != "CONFIG":
        raise ChildGuardV2Error("GUARD_CONFIG_INVALID", "invalid CONFIG frame")
    if value.get("protocolVersion") != 2:
        raise ChildGuardV2Error(
            "GUARD_CONFIG_INVALID", "CONFIG protocol version differs"
        )
    permit_id = value.get("permitId")
    one_time_token = value.get("oneTimeToken")
    executable = value.get("executable")
    argv = value.get("argv")
    environment = value.get("environment")
    non_secret = value.get("nonSecretEnvironment")
    string_fields = (
        permit_id,
        one_time_token,
        executable,
        value.get("argvFingerprint"),
        value.get("snapshotSha256"),
        value.get("snapshotIdentityFingerprint"),
        value.get("argvDomain"),
        value.get("environmentDomain"),
        value.get("secretDomain"),
        value.get("environmentFingerprint"),
        value.get("secretSha256"),
    )
    if any(
        type(item) is not str
        or not item
        or "\0" in item
        or len(item.encode("utf-8")) > 64 * 1024
        for item in string_fields
    ):
        raise ChildGuardV2Error(
            "GUARD_CONFIG_INVALID", "CONFIG contains invalid string fields"
        )
    if not Path(str(executable)).is_absolute():
        raise ChildGuardV2Error(
            "GUARD_CONFIG_INVALID", "CONFIG executable is not absolute"
        )
    if (
        type(argv) is not list
        or not argv
        or any(type(item) is not str or not item or "\0" in item for item in argv)
        or type(environment) is not dict
        or type(non_secret) is not dict
        or any(
            type(name) is not str
            or type(item) is not str
            or not name
            or "\0" in name
            or "\0" in item
            for mapping in (environment, non_secret)
            for name, item in mapping.items()
        )
    ):
        raise ChildGuardV2Error(
            "GUARD_CONFIG_INVALID", "CONFIG argv or environment is invalid"
        )
    prepared = _GuardPreparedLaunchV2(
        executable=Path(str(executable)),
        argv=tuple(argv),
        environment=dict(environment),
        argv_fingerprint=str(value["argvFingerprint"]),
        snapshot_sha256=str(value["snapshotSha256"]),
        snapshot_identity_fingerprint=str(value["snapshotIdentityFingerprint"]),
        argv_domain=str(value["argvDomain"]),
        environment_domain=str(value["environmentDomain"]),
        secret_domain=str(value["secretDomain"]),
        non_secret_environment=dict(non_secret),
        environment_fingerprint=str(value["environmentFingerprint"]),
        secret_sha256=str(value["secretSha256"]),
    )
    _require_argv_fingerprint(prepared)
    return prepared, str(permit_id), str(one_time_token)


def _fresh_guard_snapshot_probe_v2(prepared: _GuardPreparedLaunchV2) -> Any:
    # Ленивый импорт избегает цикла: production_proofs использует системный
    # маркер процесса из этого модуля.
    from .production_proofs_v2 import CodexSnapshotDescriptorProbeV2

    return CodexSnapshotDescriptorProbeV2()(
        prepared.executable,
        prepared.snapshot_sha256,
    )


def _child_guard_process_entrypoint_v2() -> int:
    descriptors: list[int] = []
    try:
        for name in (
            "CODEX_GUARD_CONTROL_FD",
            "CODEX_GUARD_HELLO_FD",
            "CODEX_GUARD_ERROR_FD",
        ):
            raw = os.environ.get(name)
            if raw is None or not raw.isascii() or not raw.isdigit():
                raise ChildGuardV2Error(
                    "GUARD_CONFIG_INVALID", "guard descriptor environment is invalid"
                )
            descriptor = int(raw)
            if not 3 <= descriptor < 4096:
                raise ChildGuardV2Error(
                    "GUARD_CONFIG_INVALID", "guard descriptor is outside bounds"
                )
            descriptors.append(descriptor)
        control_fd, hello_fd, error_fd = descriptors
        if len(set(descriptors)) != 3:
            raise ChildGuardV2Error(
                "GUARD_CONFIG_INVALID", "guard descriptors are not distinct"
            )
        fcntl.fcntl(error_fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        config = _read_frame(
            control_fd,
            8.0,
            max_frame_bytes=_MAX_CONFIG_FRAME_BYTES,
        )
        prepared, permit_id, one_time_token = _prepared_from_guard_config_v2(config)
        _child_guard_main(
            prepared=prepared,
            permit_id=permit_id,
            one_time_token=one_time_token,
            snapshot_probe=_fresh_guard_snapshot_probe_v2,
            process_start_marker_provider=system_process_start_marker_v2,
            control_fd=control_fd,
            hello_fd=hello_fd,
            error_fd=error_fd,
            stdin_fd=0,
            stdout_fd=1,
            stderr_fd=2,
            establish_session=False,
        )
    except BaseException as exc:
        error_fd = descriptors[2] if len(descriptors) == 3 else -1
        try:
            _write_frame(
                error_fd,
                {
                    "frame": "EXEC_ERROR",
                    "code": getattr(exc, "code", "GUARD_CONFIG_INVALID"),
                    "message": str(exc)[:1024] or type(exc).__name__,
                },
            )
        except BaseException:
            pass
        _close_many(tuple(descriptors))
        return 126
    return 127


class _ForkExecGuardHandleV2:
    def __init__(
        self,
        *,
        pid: int,
        permit_id: str,
        one_time_token: str,
        argv_fingerprint: str,
        snapshot_identity_fingerprint: str,
        process_start_marker_provider: ProcessStartMarkerProviderV2,
        control_fd: int,
        hello_fd: int,
        error_fd: int,
        stdin_fd: int,
        stdout_fd: int,
        stderr_fd: int,
    ) -> None:
        self.pid = pid
        self.permit_id = permit_id
        self.one_time_token = one_time_token
        self.argv_fingerprint = argv_fingerprint
        self.snapshot_identity_fingerprint = snapshot_identity_fingerprint
        self.process_start_marker_provider = process_start_marker_provider
        self.control_fd = control_fd
        self.hello_fd = hello_fd
        self.error_fd = error_fd
        self.stdin_fd = stdin_fd
        self.stdout_fd = stdout_fd
        self.stderr_fd = stderr_fd
        self._hello: GuardHelloV2 | None = None
        self._exec_confirmed = False
        self._reaped = False

    def receive_hello(self, timeout_seconds: float) -> GuardHelloV2:
        if self._hello is not None:
            return self._hello
        value = _read_frame(self.hello_fd, timeout_seconds)
        _close_fd(self.hello_fd)
        self.hello_fd = -1
        expected = {
            "frame",
            "protocolVersion",
            "permitId",
            "oneTimeToken",
            "pid",
            "processStartMarker",
            "argvFingerprint",
            "snapshotIdentityFingerprint",
        }
        if set(value) != expected or value["frame"] != "HELLO":
            raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "invalid HELLO frame")
        if (
            type(value["protocolVersion"]) is not int
            or type(value["pid"]) is not int
            or any(
                type(value[name]) is not str
                for name in (
                    "permitId",
                    "oneTimeToken",
                    "processStartMarker",
                    "argvFingerprint",
                    "snapshotIdentityFingerprint",
                )
            )
        ):
            raise ChildGuardV2Error(
                "GUARD_PROTOCOL_ERROR", "HELLO field types are invalid"
            )
        try:
            hello = GuardHelloV2(
                protocol_version=int(value["protocolVersion"]),
                permit_id=str(value["permitId"]),
                one_time_token=str(value["oneTimeToken"]),
                pid=int(value["pid"]),
                process_start_marker=str(value["processStartMarker"]),
                argv_fingerprint=str(value["argvFingerprint"]),
                snapshot_identity_fingerprint=str(value["snapshotIdentityFingerprint"]),
            )
        except (TypeError, ValueError) as exc:
            raise ChildGuardV2Error(
                "GUARD_PROTOCOL_ERROR", "malformed HELLO values"
            ) from exc
        if hello.pid != self.pid or hello.pid <= 0 or not hello.process_start_marker:
            raise ChildGuardV2Error(
                "GUARD_PROTOCOL_ERROR", "HELLO process identity differs"
            )
        try:
            observed_marker = self.process_start_marker_provider(hello.pid)
        except Exception as exc:
            raise ChildGuardV2Error(
                "PROCESS_MARKER_UNAVAILABLE",
                "could not observe the guard process start marker",
            ) from exc
        if observed_marker != hello.process_start_marker:
            raise ChildGuardV2Error(
                "PROCESS_MARKER_MISMATCH",
                "HELLO process start marker differs from the operating system",
            )
        self._hello = hello
        return hello

    def authorize_commit(
        self, one_time_token: str, timeout_seconds: float
    ) -> GuardExecConfirmationV2:
        hello = self.receive_hello(timeout_seconds)
        if one_time_token != self.one_time_token:
            raise ChildGuardV2Error("GUARD_TOKEN_MISMATCH", "commit token differs")
        _write_frame(
            self.control_fd,
            {
                "frame": "COMMIT",
                "protocolVersion": 2,
                "permitId": self.permit_id,
                "oneTimeToken": one_time_token,
                "argvFingerprint": self.argv_fingerprint,
                "snapshotIdentityFingerprint": self.snapshot_identity_fingerprint,
            },
        )
        _close_fd(self.control_fd)
        self.control_fd = -1
        error = _read_frame_or_eof(self.error_fd, timeout_seconds)
        _close_fd(self.error_fd)
        self.error_fd = -1
        if error is not None:
            code = str(error.get("code", "CHILD_EXEC_FAILED"))
            message = str(error.get("message", "guard could not exec child"))
            raise ChildGuardV2Error(code, message)
        self._exec_confirmed = True
        return GuardExecConfirmationV2(
            pid=hello.pid,
            process_start_marker=hello.process_start_marker,
        )

    def collect(
        self,
        stdin: bytes,
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> GuardExecutionResultV2:
        if not self._exec_confirmed:
            raise ChildGuardV2Error(
                "COMMIT_REQUIRED", "mission cannot be sent before exec confirmation"
            )
        if not isinstance(stdin, bytes):
            raise TypeError("stdin must be bytes")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 3600
        ):
            raise ValueError("timeout_seconds must be in (0, 3600]")
        if (
            type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 64 * 1024 * 1024
        ):
            raise ValueError("max_output_bytes is outside the supported range")
        stdout, stderr, status = _collect_process(
            self.pid,
            stdin_fd=self.stdin_fd,
            stdout_fd=self.stdout_fd,
            stderr_fd=self.stderr_fd,
            stdin=stdin,
            timeout_seconds=float(timeout_seconds),
            max_output_bytes=max_output_bytes,
        )
        self.stdin_fd = self.stdout_fd = self.stderr_fd = -1
        self._reaped = True
        return GuardExecutionResultV2(
            exit_code=os.waitstatus_to_exitcode(status),
            stdout=stdout,
            stderr=stderr,
        )

    def abort(self) -> None:
        _close_many(
            (
                self.control_fd,
                self.hello_fd,
                self.error_fd,
                self.stdin_fd,
                self.stdout_fd,
                self.stderr_fd,
            )
        )
        self.control_fd = self.hello_fd = self.error_fd = -1
        self.stdin_fd = self.stdout_fd = self.stderr_fd = -1
        if self._reaped:
            return
        try:
            waited, _ = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self._reaped = True
            return
        if waited == 0:
            self._reaped = _terminate_and_reap(self.pid, timeout_seconds=1.0)
        else:
            self._reaped = True


def _child_guard_main(
    *,
    prepared: PreparedChildLaunchV2,
    permit_id: str,
    one_time_token: str,
    snapshot_probe: SnapshotProbeV2,
    process_start_marker_provider: ProcessStartMarkerProviderV2,
    control_fd: int,
    hello_fd: int,
    error_fd: int,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    establish_session: bool = True,
) -> None:
    if establish_session:
        os.setsid()
    try:
        fcntl.fcntl(error_fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        marker = process_start_marker_provider(os.getpid())
        if (
            not isinstance(marker, str)
            or not marker
            or len(marker.encode("utf-8")) > 256
        ):
            raise ChildGuardV2Error(
                "PROCESS_MARKER_UNAVAILABLE",
                "system process start marker is invalid",
            )
        _require_argv_fingerprint(prepared)
        _require_snapshot_observation(snapshot_probe(prepared), prepared)
        _write_frame(
            hello_fd,
            {
                "frame": "HELLO",
                "protocolVersion": 2,
                "permitId": permit_id,
                "oneTimeToken": one_time_token,
                "pid": os.getpid(),
                "processStartMarker": marker,
                "argvFingerprint": prepared.argv_fingerprint,
                "snapshotIdentityFingerprint": prepared.snapshot_identity_fingerprint,
            },
        )
        _close_fd(hello_fd)
        hello_fd = -1
        commit = _read_frame(control_fd, 8.0)
        expected = {
            "frame": "COMMIT",
            "protocolVersion": 2,
            "permitId": permit_id,
            "oneTimeToken": one_time_token,
            "argvFingerprint": prepared.argv_fingerprint,
            "snapshotIdentityFingerprint": prepared.snapshot_identity_fingerprint,
        }
        if commit != expected:
            raise ChildGuardV2Error(
                "GUARD_COMMIT_MISMATCH", "commit frame differs from HELLO"
            )
        _require_argv_fingerprint(prepared)
        _require_snapshot_observation(snapshot_probe(prepared), prepared)
        _close_fd(control_fd)
        control_fd = -1
        for descriptor, target in (
            (stdin_fd, 0),
            (stdout_fd, 1),
            (stderr_fd, 2),
        ):
            if descriptor != target:
                os.dup2(descriptor, target)
        _close_many(
            tuple(
                descriptor
                for descriptor, target in (
                    (stdin_fd, 0),
                    (stdout_fd, 1),
                    (stderr_fd, 2),
                )
                if descriptor != target
            )
        )
        os.umask(0o077)
        _reset_signals()
        cwd = _argv_working_directory(prepared.argv)
        if cwd is not None:
            os.chdir(cwd)
        os.execve(
            os.fspath(prepared.executable),
            list(prepared.argv),
            dict(prepared.environment),
        )
    except BaseException as exc:
        try:
            _write_frame(
                error_fd,
                {
                    "frame": "EXEC_ERROR",
                    "code": getattr(exc, "code", "CHILD_EXEC_FAILED"),
                    "message": str(exc)[:1024] or type(exc).__name__,
                },
            )
        except BaseException:
            pass
        _close_many(
            (
                control_fd,
                hello_fd,
                error_fd,
                stdin_fd,
                stdout_fd,
                stderr_fd,
            )
        )
        os._exit(126)


def _require_snapshot_observation(value: Any, prepared: PreparedChildLaunchV2) -> None:
    if (
        getattr(value, "snapshot_sha256", None) != prepared.snapshot_sha256
        or getattr(value, "snapshot_identity_fingerprint", None)
        != prepared.snapshot_identity_fingerprint
    ):
        raise ChildGuardV2Error(
            "SNAPSHOT_IDENTITY_MISMATCH",
            "fresh guard snapshot observation differs",
        )


def _require_argv_fingerprint(prepared: PreparedChildLaunchV2) -> None:
    try:
        require_child_environment_integrity_v2(prepared)
    except Exception as exc:
        raise ChildGuardV2Error(
            getattr(exc, "code", "ENVIRONMENT_FINGERPRINT_MISMATCH"),
            str(exc),
        ) from exc
    observed = child_argv_fingerprint_v2(
        argv=prepared.argv,
        argv_domain=prepared.argv_domain,
    )
    if observed != prepared.argv_fingerprint:
        raise ChildGuardV2Error(
            "ARGV_FINGERPRINT_MISMATCH",
            "guard launch differs from its argv fingerprint",
        )


def system_process_start_marker_v2(pid: int) -> str:
    """Читает системный маркер старта, устойчивый к повторному использованию PID."""

    if type(pid) is not int or pid <= 0:
        raise ChildGuardV2Error("PROCESS_MARKER_INVALID_PID", "pid must be positive")
    if sys.platform == "darwin":
        return _darwin_process_start_marker(pid)
    if sys.platform.startswith("linux"):
        return _linux_process_start_marker(pid)
    raise ChildGuardV2Error(
        "PROCESS_MARKER_UNAVAILABLE",
        f"unsupported process marker platform: {sys.platform}",
    )


def _darwin_process_start_marker(pid: int) -> str:
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError as exc:
        raise ChildGuardV2Error(
            "PROCESS_MARKER_UNAVAILABLE",
            "libproc is unavailable",
        ) from exc
    library.proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    library.proc_pidinfo.restype = ctypes.c_int
    info = _DarwinProcBSDInfo()
    observed = library.proc_pidinfo(
        pid,
        _PROC_PIDTBSDINFO,
        0,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if (
        observed == 0
        and ctypes.get_errno() == errno.ESRCH
    ) or info.pbi_status == 5:
        raise ChildGuardV2Error(
            "PROCESS_NOT_RUNNING",
            "process is absent or awaiting collection",
        )
    if observed != ctypes.sizeof(info) or info.pbi_pid != pid:
        raise ChildGuardV2Error(
            "PROCESS_MARKER_UNAVAILABLE",
            "proc_pidinfo did not return the requested process",
        )
    return f"darwin:{info.pbi_start_tvsec}:{info.pbi_start_tvusec}"


def _linux_process_start_marker(pid: int) -> str:
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = stat_line[stat_line.rindex(")") + 2 :].split()
        process_state = fields[0]
        start_ticks = fields[19]
        boot_id = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
    except (OSError, UnicodeError, ValueError, IndexError) as exc:
        raise ChildGuardV2Error(
            "PROCESS_MARKER_UNAVAILABLE",
            "procfs did not return the requested process",
        ) from exc
    if process_state == "Z":
        raise ChildGuardV2Error(
            "PROCESS_NOT_RUNNING",
            "process is awaiting collection",
        )
    if not start_ticks.isdecimal() or not boot_id:
        raise ChildGuardV2Error(
            "PROCESS_MARKER_UNAVAILABLE",
            "procfs process marker is malformed",
        )
    return f"linux:{boot_id}:{start_ticks}"


def _terminate_and_reap(pid: int, *, timeout_seconds: float) -> bool:
    """Посылает SIGKILL группе и PID, затем ждёт только до заданного срока."""

    try:
        waited, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    if waited == pid:
        return True
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if waited == pid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _collect_process(
    pid: int,
    *,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    stdin: bytes,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[bytes, bytes, int]:
    selector = selectors.DefaultSelector()
    outputs = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    for descriptor in outputs:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
    os.set_blocking(stdin_fd, False)
    selector.register(stdin_fd, selectors.EVENT_WRITE)
    offset = 0
    total = 0
    deadline = time.monotonic() + timeout_seconds
    status: int | None = None
    try:
        while selector.get_map() or status is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChildGuardV2Error(
                    "CHILD_TIMEOUT", "child execution exceeded its deadline"
                )
            for key, mask in selector.select(min(remaining, 0.1)):
                descriptor = key.fd
                if descriptor == stdin_fd and mask & selectors.EVENT_WRITE:
                    if offset < len(stdin):
                        try:
                            written = os.write(
                                stdin_fd, stdin[offset : offset + _READ_CHUNK]
                            )
                        except BrokenPipeError:
                            written = 0
                            offset = len(stdin)
                        offset += written
                    if offset >= len(stdin):
                        selector.unregister(stdin_fd)
                        _close_fd(stdin_fd)
                        stdin_fd = -1
                elif mask & selectors.EVENT_READ:
                    chunk = os.read(descriptor, _READ_CHUNK)
                    if not chunk:
                        selector.unregister(descriptor)
                        _close_fd(descriptor)
                        if descriptor == stdout_fd:
                            stdout_fd = -1
                        else:
                            stderr_fd = -1
                        continue
                    total += len(chunk)
                    if total > max_output_bytes:
                        raise ChildGuardV2Error(
                            "CHILD_OUTPUT_LIMIT", "child output exceeded its limit"
                        )
                    outputs[descriptor].extend(chunk)
            if status is None:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = candidate
        return (
            bytes(outputs[next(iter(outputs))]),
            bytes(outputs[list(outputs)[1]]),
            status,
        )
    except BaseException:
        _terminate_and_reap(pid, timeout_seconds=1.0)
        raise
    finally:
        selector.close()
        _close_many((stdin_fd, stdout_fd, stderr_fd))


def _read_frame(
    descriptor: int,
    timeout_seconds: float,
    *,
    max_frame_bytes: int = _MAX_FRAME_BYTES,
) -> dict[str, Any]:
    header = _read_exact(descriptor, 4, timeout_seconds)
    size = struct.unpack(">I", header)[0]
    if size <= 0 or size > max_frame_bytes:
        raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "frame length is invalid")
    payload = _read_exact(descriptor, size, timeout_seconds)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "frame is not JSON") from exc
    if type(value) is not dict or canonical_json_v1(value).encode("utf-8") != payload:
        raise ChildGuardV2Error(
            "GUARD_PROTOCOL_ERROR", "frame is not canonical JSON object"
        )
    return value


def _read_frame_or_eof(
    descriptor: int, timeout_seconds: float
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    ready, _, _ = select.select([descriptor], [], [], timeout_seconds)
    if not ready:
        raise ChildGuardV2Error("GUARD_DEADLINE", "guard exec deadline expired")
    first = os.read(descriptor, 4)
    if first == b"":
        return None
    while len(first) < 4:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChildGuardV2Error("GUARD_DEADLINE", "partial error frame")
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            raise ChildGuardV2Error("GUARD_DEADLINE", "partial error frame")
        chunk = os.read(descriptor, 4 - len(first))
        if not chunk:
            raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "partial error frame")
        first += chunk
    size = struct.unpack(">I", first)[0]
    if size <= 0 or size > _MAX_FRAME_BYTES:
        raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "error frame length is invalid")
    payload = _read_exact(descriptor, size, max(0.001, deadline - time.monotonic()))
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChildGuardV2Error(
            "GUARD_PROTOCOL_ERROR", "error frame is not JSON"
        ) from exc
    if type(value) is not dict or canonical_json_v1(value).encode("utf-8") != payload:
        raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "error frame is invalid")
    return value


def _read_exact(descriptor: int, size: int, timeout_seconds: float) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChildGuardV2Error("GUARD_DEADLINE", "guard frame deadline expired")
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            raise ChildGuardV2Error("GUARD_DEADLINE", "guard frame deadline expired")
        chunk = os.read(descriptor, size - len(result))
        if not chunk:
            raise ChildGuardV2Error("GUARD_CHANNEL_CLOSED", "guard channel closed")
        result.extend(chunk)
    return bytes(result)


def _write_frame(
    descriptor: int,
    value: Mapping[str, Any],
    *,
    max_frame_bytes: int = _MAX_FRAME_BYTES,
) -> None:
    payload = canonical_json_v1(dict(value)).encode("utf-8")
    if not payload or len(payload) > max_frame_bytes:
        raise ChildGuardV2Error("GUARD_PROTOCOL_ERROR", "frame is too large")
    data = struct.pack(">I", len(payload)) + payload
    offset = 0
    while offset < len(data):
        offset += os.write(descriptor, data[offset:])


def _argv_working_directory(argv: tuple[str, ...]) -> str | None:
    positions = [index for index, value in enumerate(argv) if value == "-C"]
    if len(positions) != 1:
        return None
    index = positions[0]
    if index + 1 >= len(argv) or not os.path.isabs(argv[index + 1]):
        raise ChildGuardV2Error("GUARD_ARGV_INVALID", "working directory is invalid")
    return argv[index + 1]


def _reset_signals() -> None:
    for selected in (signal.SIGPIPE, signal.SIGINT, signal.SIGTERM):
        signal.signal(selected, signal.SIG_DFL)


def _pipe() -> tuple[int, int]:
    return os.pipe()


def _close_fd(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _close_many(descriptors: tuple[int, ...]) -> None:
    for descriptor in descriptors:
        _close_fd(descriptor)
