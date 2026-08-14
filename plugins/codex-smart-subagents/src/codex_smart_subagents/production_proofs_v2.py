"""Фактические поставщики доказательств производственного дочернего запуска."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import stat
import sys
import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .canonical_json import domain_fingerprint
from .child_guard_v2 import GuardExecConfirmationV2, system_process_start_marker_v2
from .child_launch_coordinator_v2 import (
    ProcessObservationV2,
    SnapshotObservationV2,
)
from .child_runner import PermissionProfileDefinition
from .live_canary import (
    AppServerManagedConfigInspector,
    CanaryProbeTargets,
    LivePermissionCanary,
    ManagedConfigInspector,
)
from .permissions import CanaryEvidence, CanaryRequest, PermissionGate


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROBE_ID = re.compile(r"^pc1_[A-Za-z0-9_-]{43}$")
_MAX_BINARY_BYTES = 2 * 1024 * 1024 * 1024
_IDENTITY_DOMAIN = "codex-smart/codex-snapshot-descriptor/v2"


@dataclass
class ProductionProofV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class SharedLaunchBarrierV2:
    """Один повторно входимый барьер для всех запусков данного контроллера."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._local = threading.local()

    def __call__(self) -> AbstractContextManager[None]:
        return _BarrierLeaseV2(self)

    @property
    def held_by_current_thread(self) -> bool:
        return bool(getattr(self._local, "depth", 0))

    def _enter(self) -> None:
        self._lock.acquire()
        self._local.depth = int(getattr(self._local, "depth", 0)) + 1

    def _exit(self) -> None:
        depth = int(getattr(self._local, "depth", 0))
        if depth <= 0:
            raise RuntimeError("launch barrier ownership is inconsistent")
        self._local.depth = depth - 1
        self._lock.release()


class _BarrierLeaseV2(AbstractContextManager[None]):
    def __init__(self, owner: SharedLaunchBarrierV2) -> None:
        self._owner = owner
        self._entered = False

    def __enter__(self) -> None:
        if self._entered:
            raise RuntimeError("barrier lease is already entered")
        self._owner._enter()
        self._entered = True

    def __exit__(self, *_args: object) -> None:
        if self._entered:
            self._entered = False
            self._owner._exit()


class CodexSnapshotDescriptorProbeV2:
    """Хеширует открытый без следования ссылке снимок и его файловую личность."""

    def __call__(self, path: Path, expected_sha256: str) -> SnapshotObservationV2:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or not isinstance(expected_sha256, str)
            or _SHA256.fullmatch(expected_sha256) is None
        ):
            _fail("CODEX_SNAPSHOT_INVALID", "неверные входы проверки снимка")
        try:
            lexical = path.absolute()
            before = os.lstat(lexical)
        except OSError as exc:
            raise ProductionProofV2Error(
                "CODEX_SNAPSHOT_UNAVAILABLE", str(exc)
            ) from exc
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o500
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > _MAX_BINARY_BYTES
        ):
            _fail(
                "CODEX_SNAPSHOT_UNSAFE",
                "снимок Codex имеет недопустимые метаданные",
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lexical, flags)
        except OSError as exc:
            raise ProductionProofV2Error(
                "CODEX_SNAPSHOT_UNAVAILABLE", str(exc)
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if _file_identity(opened) != _file_identity(before):
                _fail("CODEX_SNAPSHOT_CHANGED", "снимок изменился при открытии")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_BINARY_BYTES:
                    _fail("CODEX_SNAPSHOT_UNSAFE", "снимок превышает предел")
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        observed_sha256 = digest.hexdigest()
        if (
            total != before.st_size
            or _file_identity(after) != _file_identity(opened)
            or observed_sha256 != expected_sha256
        ):
            _fail("CODEX_SNAPSHOT_CHANGED", "содержимое снимка Codex изменилось")
        identity = domain_fingerprint(
            _IDENTITY_DOMAIN,
            {
                "path": str(lexical),
                "device": str(opened.st_dev),
                "inode": str(opened.st_ino),
                "ownerUid": opened.st_uid,
                "ownerGid": opened.st_gid,
                "mode": f"0{stat.S_IMODE(opened.st_mode):03o}",
                "linkCount": opened.st_nlink,
                "size": opened.st_size,
                "mtimeNs": str(opened.st_mtime_ns),
                "sha256": observed_sha256,
            },
        )
        return SnapshotObservationV2(
            snapshot_sha256=observed_sha256,
            snapshot_identity_fingerprint=identity,
        )


class PreparedProcessProbeV2:
    """Сверяет живой процесс с подготовленным образом и точными аргументами."""

    def __init__(
        self,
        *,
        snapshot_probe: Callable[[Path, str], Any] | None = None,
        process_start_marker_provider: Callable[[int], str] = (
            system_process_start_marker_v2
        ),
        process_executable_provider: Callable[[int], Path] | None = None,
        process_argv_provider: Callable[[int], tuple[str, ...]] | None = None,
    ) -> None:
        self.snapshot_probe = snapshot_probe or CodexSnapshotDescriptorProbeV2()
        self.process_start_marker_provider = process_start_marker_provider
        self.process_executable_provider = (
            process_executable_provider or _system_process_executable
        )
        self.process_argv_provider = process_argv_provider or _system_process_argv
        for value, name in (
            (self.snapshot_probe, "snapshot_probe"),
            (self.process_start_marker_provider, "process_start_marker_provider"),
            (self.process_executable_provider, "process_executable_provider"),
            (self.process_argv_provider, "process_argv_provider"),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")

    def __call__(
        self,
        prepared: Any,
        confirmation: GuardExecConfirmationV2,
    ) -> ProcessObservationV2:
        if not isinstance(confirmation, GuardExecConfirmationV2):
            raise TypeError("confirmation must be GuardExecConfirmationV2")
        try:
            marker_before = self.process_start_marker_provider(confirmation.pid)
            executable = self.process_executable_provider(confirmation.pid)
            argv = self.process_argv_provider(confirmation.pid)
            observation = self.snapshot_probe(
                prepared.executable,
                prepared.snapshot_sha256,
            )
            marker_after = self.process_start_marker_provider(confirmation.pid)
        except ProductionProofV2Error:
            raise
        except Exception as exc:
            raise ProductionProofV2Error("PROCESS_PROBE_FAILED", str(exc)) from exc
        if (
            marker_before != confirmation.process_start_marker
            or marker_after != marker_before
        ):
            _fail("PROCESS_MARKER_MISMATCH", "PID или маркер процесса изменился")
        if Path(executable).resolve(strict=True) != Path(prepared.executable).resolve(
            strict=True
        ):
            _fail("PROCESS_EXECUTABLE_MISMATCH", "процесс исполняет другой образ")
        if tuple(argv) != tuple(prepared.argv):
            _fail("PROCESS_ARGV_MISMATCH", "аргументы живого процесса отличаются")
        if not isinstance(observation, SnapshotObservationV2):
            _fail("PROCESS_SNAPSHOT_INVALID", "проверка снимка вернула другой тип")
        if (
            observation.snapshot_sha256 != prepared.snapshot_sha256
            or observation.snapshot_identity_fingerprint
            != prepared.snapshot_identity_fingerprint
        ):
            _fail("PROCESS_SNAPSHOT_MISMATCH", "процесс связан с другим снимком")
        return ProcessObservationV2(
            model=prepared.model,
            reasoning_effort=prepared.reasoning_effort,
            permission_profile_id=prepared.permission_profile_id,
            argv_fingerprint=prepared.argv_fingerprint,
            snapshot_identity_fingerprint=prepared.snapshot_identity_fingerprint,
            compatibility_fingerprint=prepared.compatibility_fingerprint,
            account_context_fingerprint=prepared.account_context_fingerprint,
            pid=confirmation.pid,
            process_start_marker=confirmation.process_start_marker,
            codex_binary_sha256=observation.snapshot_sha256,
        )


@dataclass(frozen=True)
class PermissionProbeContextV2:
    codex_home: Path
    runtime_parent: Path
    managed_config_inspector: ManagedConfigInspector
    secret_read_file: Path
    source_git_read_file: Path
    controller_database_read_file: Path
    source_worktree_write_file: Path
    controller_socket: Path
    ruby_executable: Path = Path("/usr/bin/ruby")

    def __post_init__(self) -> None:
        if not callable(getattr(self.managed_config_inspector, "inspect", None)):
            raise TypeError("managed_config_inspector must provide inspect()")
        for value, name in (
            (self.codex_home, "codex_home"),
            (self.runtime_parent, "runtime_parent"),
            (self.ruby_executable, "ruby_executable"),
        ):
            if (
                not isinstance(value, Path)
                or not value.is_absolute()
                or not value.exists()
            ):
                raise ValueError(f"{name} must be an existing absolute path")
        for value, name in (
            (self.secret_read_file, "secret_read_file"),
            (self.source_git_read_file, "source_git_read_file"),
            (self.controller_database_read_file, "controller_database_read_file"),
            (self.source_worktree_write_file, "source_worktree_write_file"),
            (self.controller_socket, "controller_socket"),
        ):
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{name} must be an absolute Path")


class LivePreparedPermissionProbeV2:
    """Запускает полный canary по тому же профилю, что и дочерний процесс."""

    def __init__(
        self,
        context: PermissionProbeContextV2,
        *,
        canary_factory: Callable[..., Any] = LivePermissionCanary,
        gate_factory: Callable[[Any], Any] = PermissionGate,
    ) -> None:
        if not isinstance(context, PermissionProbeContextV2):
            raise TypeError("context must be PermissionProbeContextV2")
        if not callable(canary_factory) or not callable(gate_factory):
            raise TypeError("permission factories must be callable")
        self.context = context
        self.canary_factory = canary_factory
        self.gate_factory = gate_factory

    def __call__(self, prepared: Any) -> str:
        try:
            snapshot_root = Path(
                prepared.non_secret_environment["CODEX_ADAPTIVE_SNAPSHOT_ROOT"]
            ).resolve(strict=True)
            writable_raw = prepared.non_secret_environment.get(
                "CODEX_ADAPTIVE_WORKSPACE_ROOT"
            )
            writable_root = (
                Path(writable_raw).resolve(strict=True)
                if writable_raw is not None
                else None
            )
            description = {
                "classifier": "Adaptive child classifier",
                "reader": "Adaptive child reader",
                "writer": "Adaptive child writer",
            }[prepared.role]
            profile = PermissionProfileDefinition(
                name=prepared.permission_profile_id,
                description=description,
                snapshot_root=snapshot_root,
                writable_root=writable_root,
            )
        except Exception as exc:
            raise ProductionProofV2Error(
                "PERMISSION_PROFILE_INVALID", str(exc)
            ) from exc
        observed_overrides = _permission_overrides(
            prepared.argv,
            prepared.permission_profile_id,
        )
        if observed_overrides != profile.config_overrides:
            _fail(
                "PERMISSION_PROFILE_MISMATCH",
                "аргументы запуска содержат другой профиль разрешений",
            )
        read_probe = _snapshot_probe_target(snapshot_root)
        targets = CanaryProbeTargets(
            snapshot_root=snapshot_root,
            snapshot_read_file=read_probe,
            snapshot_write_file=read_probe,
            secret_read_file=self.context.secret_read_file,
            source_git_read_file=self.context.source_git_read_file,
            controller_database_read_file=self.context.controller_database_read_file,
            source_worktree_write_file=self.context.source_worktree_write_file,
            controller_socket=self.context.controller_socket,
        )
        state = self.context.managed_config_inspector.inspect()
        request = CanaryRequest(
            codex_version=prepared.expected_cli_version,
            permission_profile=profile.name,
            profile_sha256=profile.sha256,
            managed_config_sha256=state.sha256,
        )
        canary = self.canary_factory(
            codex_executable=prepared.executable,
            ruby_executable=self.context.ruby_executable,
            codex_home=self.context.codex_home,
            runtime_parent=self.context.runtime_parent,
            profile=profile,
            managed_config_inspector=self.context.managed_config_inspector,
            targets=targets,
            model=prepared.model,
            reasoning_effort=prepared.reasoning_effort,
        )
        evidence = self.gate_factory(canary).require_verified(request)
        if (
            not isinstance(evidence, CanaryEvidence)
            or _PROBE_ID.fullmatch(evidence.probe_id) is None
        ):
            _fail("PERMISSION_PROBE_INVALID", "canary вернул неверное свидетельство")
        return evidence.probe_id


def build_managed_config_inspector_v2(
    *,
    codex_executable: Path,
    codex_home: Path,
    runtime_parent: Path,
) -> AppServerManagedConfigInspector:
    """Явная производственная фабрика эффективных управляемых требований."""

    return AppServerManagedConfigInspector(
        codex_executable=codex_executable,
        codex_home=codex_home,
        runtime_parent=runtime_parent,
    )


def _permission_overrides(argv: tuple[str, ...], profile: str) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    prefix = f"permissions.{profile}."
    while index < len(argv):
        if argv[index] == "-c" and index + 1 < len(argv):
            candidate = argv[index + 1]
            if candidate.startswith(prefix):
                values.append(candidate)
            index += 2
            continue
        index += 1
    if len(values) != 3:
        _fail("PERMISSION_PROFILE_INVALID", "профиль не содержит три настройки")
    return tuple(values)


def _snapshot_probe_target(root: Path) -> Path:
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        try:
            info = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            return candidate
    return root


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _system_process_executable(pid: int) -> Path:
    if sys.platform.startswith("linux"):
        return Path(os.readlink(f"/proc/{pid}/exe")).resolve(strict=True)
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        buffer = ctypes.create_string_buffer(4096)
        size = library.proc_pidpath(pid, buffer, len(buffer))
        if size <= 0:
            code = ctypes.get_errno() or errno.ESRCH
            raise OSError(code, os.strerror(code))
        return Path(os.fsdecode(buffer.value)).resolve(strict=True)
    raise OSError(errno.ENOTSUP, "process executable probe is unsupported")


def _system_process_argv(pid: int) -> tuple[str, ...]:
    if sys.platform.startswith("linux"):
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return tuple(os.fsdecode(item) for item in raw.rstrip(b"\0").split(b"\0"))
    if sys.platform == "darwin":
        return _darwin_process_argv(pid)
    raise OSError(errno.ENOTSUP, "process argv probe is unsupported")


def _darwin_process_argv(pid: int) -> tuple[str, ...]:
    libc = ctypes.CDLL(None, use_errno=True)
    argmax = ctypes.c_int()
    argmax_size = ctypes.c_size_t(ctypes.sizeof(argmax))
    if (
        libc.sysctlbyname(
            b"kern.argmax", ctypes.byref(argmax), ctypes.byref(argmax_size), None, 0
        )
        != 0
    ):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    buffer = ctypes.create_string_buffer(argmax.value)
    size = ctypes.c_size_t(argmax.value)
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2, pid
    if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    raw = bytes(buffer.raw[: size.value])
    if len(raw) < ctypes.sizeof(ctypes.c_int):
        raise OSError(errno.EIO, "process argv response is truncated")
    argc = int.from_bytes(raw[:4], byteorder=sys.byteorder, signed=True)
    if argc <= 0 or argc > 65536:
        raise OSError(errno.EIO, "process argc is invalid")
    position = 4
    executable_end = raw.find(b"\0", position)
    if executable_end < 0:
        raise OSError(errno.EIO, "process executable is unterminated")
    position = executable_end
    while position < len(raw) and raw[position] == 0:
        position += 1
    result: list[str] = []
    for _index in range(argc):
        end = raw.find(b"\0", position)
        if end < 0:
            raise OSError(errno.EIO, "process argv is unterminated")
        result.append(os.fsdecode(raw[position:end]))
        position = end + 1
    return tuple(result)


def _fail(code: str, message: str) -> None:
    raise ProductionProofV2Error(code, message)


__all__ = [
    "CodexSnapshotDescriptorProbeV2",
    "LivePreparedPermissionProbeV2",
    "PermissionProbeContextV2",
    "PreparedProcessProbeV2",
    "ProductionProofV2Error",
    "SharedLaunchBarrierV2",
    "build_managed_config_inspector_v2",
]
