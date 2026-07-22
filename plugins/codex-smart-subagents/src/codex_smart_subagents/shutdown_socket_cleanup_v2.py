"""Доказуемое удаление сокета уже остановленного контроллера версии 2."""

from __future__ import annotations

import copy
import fcntl
import os
import re
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .activation_gateway_v2 import _LIFECYCLE_SCHEMA_SHA256
from .activation_transition_v2 import ControllerShutdownProofV2
from .canonical_json import domain_fingerprint
from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .lifecycle_operation_v2 import ProjectionV2
from . import operation_deadline_v2


_INSTALLATION_ID = re.compile(r"^ins2_[0-9a-f]{32}$")
_OPERATION_ID = re.compile(r"^op2_[0-9a-f]{32}$")
_COMMAND_ID = re.compile(r"^cc2_[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PID = 2_147_483_647


@dataclass
class ShutdownSocketCleanupV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ShutdownSocketCleanupPlanV2:
    installation_id: str
    activation_proof_fingerprint: str
    operation_id: str
    shutdown_command_id: str
    socket_path: Path
    socket_device: int
    socket_inode: int
    socket_owner_uid: int
    socket_owner_gid: int
    socket_mode: str
    socket_parent_device: int
    socket_parent_inode: int
    target_pid: int
    target_start_marker: str
    target_process_group_id: int
    lock_path: Path
    action: Mapping[str, Any]
    plan_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", copy.deepcopy(dict(self.action)))

    @property
    def complete(self) -> bool:
        try:
            return self.plan_fingerprint == _plan_fingerprint(self)
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class ShutdownSocketOrphanProofV2:
    plan_fingerprint: str
    shutdown_proof_fingerprint: str
    process_exit_proof_fingerprint: str
    exclusive_lock_proof_fingerprint: str
    proof_fingerprint: str

    @property
    def complete(self) -> bool:
        try:
            return self.proof_fingerprint == _orphan_fingerprint(self)
        except (AttributeError, TypeError, ValueError):
            return False


@dataclass(frozen=True)
class ShutdownSocketCleanupResultV2:
    plan_fingerprint: str
    orphan_proof_fingerprint: str
    absence_projection: ProjectionV2


class ShutdownSocketCleanupStateV2(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"


@dataclass(frozen=True)
class ShutdownSocketCleanupObservationV2:
    state: ShutdownSocketCleanupStateV2
    orphan: ShutdownSocketOrphanProofV2
    absence_projection: ProjectionV2 | None


def build_shutdown_socket_cleanup_plan_v2(
    *,
    installation_id: str,
    activation_proof_fingerprint: str,
    operation_id: str,
    shutdown_command_id: str,
    state_home: Path,
    controller_state: Mapping[str, Any],
) -> ShutdownSocketCleanupPlanV2:
    """До основного журнала связать только заранее известные входы очистки."""

    _identifier(installation_id, _INSTALLATION_ID, "INSTALLATION_ID_INVALID")
    _identifier(operation_id, _OPERATION_ID, "OPERATION_ID_INVALID")
    _identifier(shutdown_command_id, _COMMAND_ID, "COMMAND_ID_INVALID")
    _identifier(
        activation_proof_fingerprint,
        _SHA256,
        "ACTIVATION_PROOF_FINGERPRINT_INVALID",
    )
    if not isinstance(state_home, Path) or not state_home.is_absolute():
        _fail("SHUTDOWN_STATE_HOME_INVALID", "state_home должен быть абсолютным Path")
    if not isinstance(controller_state, Mapping):
        _fail("SHUTDOWN_CONTROLLER_STATE_INVALID", "controller_state отсутствует")
    socket_path = _absolute_path(
        controller_state.get("socket_path"), "SHUTDOWN_SOCKET_INTENT_INVALID"
    )
    lock_path = state_home / "controller.lock"
    if (
        socket_path != state_home / "controller.sock"
        or lock_path.parent != socket_path.parent
    ):
        _fail(
            "SHUTDOWN_SOCKET_INTENT_INVALID",
            "socket и lock не принадлежат точному state_home",
        )
    parent = _private_parent(socket_path.parent)
    socket_info = _socket_info(socket_path, "SHUTDOWN_SOCKET_CHANGED")
    expected_socket = _socket_tuple_from_controller(controller_state)
    observed_socket = _socket_tuple(socket_info)
    if observed_socket != expected_socket:
        _fail("SHUTDOWN_SOCKET_CHANGED", "живой socket не совпадает с controller_state")
    _validate_lock_file(lock_path, parent_device=parent.st_dev, parent_inode=parent.st_ino)
    target_pid = _positive_integer(
        controller_state.get("controller_pid"), "SHUTDOWN_PROCESS_IDENTITY_INVALID"
    )
    target_group = _positive_integer(
        controller_state.get("controller_process_group_id"),
        "SHUTDOWN_PROCESS_IDENTITY_INVALID",
    )
    marker = controller_state.get("controller_process_start_marker")
    if type(marker) is not str or not marker or len(marker) > 256:
        _fail("SHUTDOWN_PROCESS_IDENTITY_INVALID", "маркер процесса неверен")
    action = {
        "actionKind": "socket-cleanup",
        "method": "unlink-proven-orphan",
        "proofSource": "CONTROLLER_SHUTDOWN_INTENT",
        "proofSourceId": shutdown_command_id,
        "socketPath": str(socket_path),
        "socketDevice": socket_info.st_dev,
        "socketInode": socket_info.st_ino,
        "socketOwnerUid": socket_info.st_uid,
        "socketOwnerGid": socket_info.st_gid,
        "socketMode": _mode(socket_info),
        "socketParentDevice": parent.st_dev,
        "socketParentInode": parent.st_ino,
        "targetPid": target_pid,
        "targetStartMarker": marker,
        "targetProcessGroupId": target_group,
        "lockPath": str(lock_path),
        "durability": "UNLINKAT_FSYNC_PARENT",
    }
    plan = ShutdownSocketCleanupPlanV2(
        installation_id=installation_id,
        activation_proof_fingerprint=activation_proof_fingerprint,
        operation_id=operation_id,
        shutdown_command_id=shutdown_command_id,
        socket_path=socket_path,
        socket_device=socket_info.st_dev,
        socket_inode=socket_info.st_ino,
        socket_owner_uid=socket_info.st_uid,
        socket_owner_gid=socket_info.st_gid,
        socket_mode=_mode(socket_info),
        socket_parent_device=parent.st_dev,
        socket_parent_inode=parent.st_ino,
        target_pid=target_pid,
        target_start_marker=marker,
        target_process_group_id=target_group,
        lock_path=lock_path,
        action=action,
        plan_fingerprint="0" * 64,
    )
    return ShutdownSocketCleanupPlanV2(
        **{
            name: getattr(plan, name)
            for name in plan.__dataclass_fields__
            if name != "plan_fingerprint"
        },
        plan_fingerprint=_plan_fingerprint(plan),
    )


def prove_shutdown_socket_orphan_v2(
    *,
    plan: ShutdownSocketCleanupPlanV2,
    shutdown: ControllerShutdownProofV2,
    process_start_marker_provider: Callable[[int], str] = system_process_start_marker_v2,
) -> ShutdownSocketOrphanProofV2:
    """Доказать exit/PID-reuse и эксклюзивную блокировку без удаления socket."""

    _authorize(plan, shutdown)
    with _proven_environment(
        plan,
        process_start_marker_provider=process_start_marker_provider,
    ) as evidence:
        process_fingerprint, lock_fingerprint, _parent_descriptor = evidence
        proof = ShutdownSocketOrphanProofV2(
            plan_fingerprint=plan.plan_fingerprint,
            shutdown_proof_fingerprint=shutdown.proof_fingerprint,
            process_exit_proof_fingerprint=process_fingerprint,
            exclusive_lock_proof_fingerprint=lock_fingerprint,
            proof_fingerprint="0" * 64,
        )
        return ShutdownSocketOrphanProofV2(
            plan_fingerprint=proof.plan_fingerprint,
            shutdown_proof_fingerprint=proof.shutdown_proof_fingerprint,
            process_exit_proof_fingerprint=proof.process_exit_proof_fingerprint,
            exclusive_lock_proof_fingerprint=proof.exclusive_lock_proof_fingerprint,
            proof_fingerprint=_orphan_fingerprint(proof),
        )


def wait_for_shutdown_socket_orphan_v2(
    *,
    plan: ShutdownSocketCleanupPlanV2,
    shutdown: ControllerShutdownProofV2,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 0.02,
    process_start_marker_provider: Callable[[int], str] = (
        system_process_start_marker_v2
    ),
    orphan_prover: Callable[..., Any] = prove_shutdown_socket_orphan_v2,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> ShutdownSocketOrphanProofV2:
    """Дождаться только штатного завершения процесса и освобождения lock."""

    for value, name, upper in (
        (timeout_seconds, "timeout_seconds", 120.0),
        (poll_interval_seconds, "poll_interval_seconds", 1.0),
    ):
        if (
            type(value) not in {int, float}
            or type(value) is bool
            or not 0 < float(value) <= upper
        ):
            raise TypeError(f"{name} is outside its supported range")
    for value, name in (
        (process_start_marker_provider, "process_start_marker_provider"),
        (orphan_prover, "orphan_prover"),
        (monotonic, "monotonic"),
        (sleeper, "sleeper"),
    ):
        if not callable(value):
            raise TypeError(f"{name} must be callable")
    operation_deadline = operation_deadline_v2.current_operation_deadline_v2()
    bounded_timeout = float(timeout_seconds)
    if operation_deadline is not None:
        bounded_timeout = operation_deadline.bounded_timeout_seconds(
            local_cap_seconds=bounded_timeout
        )
    deadline = float(monotonic()) + bounded_timeout
    transient = {
        "SHUTDOWN_PROCESS_STILL_ACTIVE",
        "SHUTDOWN_LOCK_NOT_EXCLUSIVE",
    }
    while True:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        try:
            return orphan_prover(
                plan=plan,
                shutdown=shutdown,
                process_start_marker_provider=process_start_marker_provider,
            )
        except ShutdownSocketCleanupV2Error as error:
            if error.code not in transient:
                raise
            if float(monotonic()) >= deadline:
                raise ShutdownSocketCleanupV2Error(
                    "SHUTDOWN_COMPLETION_TIMEOUT",
                    "контроллер не завершился и не освободил блокировку в срок",
                ) from error
            sleep_seconds = float(poll_interval_seconds)
            if operation_deadline is not None:
                operation_deadline.checkpoint()
                sleep_seconds = min(
                    sleep_seconds, operation_deadline.remaining_seconds()
                )
            sleeper(sleep_seconds)


def apply_shutdown_socket_cleanup_v2(
    *,
    plan: ShutdownSocketCleanupPlanV2,
    shutdown: ControllerShutdownProofV2,
    orphan: ShutdownSocketOrphanProofV2,
    process_start_marker_provider: Callable[[int], str] = system_process_start_marker_v2,
) -> ShutdownSocketCleanupResultV2:
    """Удалить exact socket через open parent и синхронизировать каталог."""

    _authorize(plan, shutdown)
    if (
        not isinstance(orphan, ShutdownSocketOrphanProofV2)
        or not orphan.complete
        or orphan.plan_fingerprint != plan.plan_fingerprint
        or orphan.shutdown_proof_fingerprint != shutdown.proof_fingerprint
    ):
        _fail("SHUTDOWN_ORPHAN_PROOF_INVALID", "orphan proof не связан с планом")
    with _proven_environment(
        plan,
        process_start_marker_provider=process_start_marker_provider,
    ) as evidence:
        process_fingerprint, lock_fingerprint, parent_descriptor = evidence
        if (
            process_fingerprint != orphan.process_exit_proof_fingerprint
            or lock_fingerprint != orphan.exclusive_lock_proof_fingerprint
        ):
            _fail("SHUTDOWN_ORPHAN_PROOF_CHANGED", "exit/lock proof изменился")
        observed = _entry_info(parent_descriptor, plan.socket_path.name)
        if observed is not None:
            if _socket_tuple(observed) != (
                plan.socket_device,
                plan.socket_inode,
                plan.socket_owner_uid,
                plan.socket_owner_gid,
                plan.socket_mode,
            ):
                _fail("SHUTDOWN_SOCKET_CHANGED", "socket inode был заменён")
            os.unlink(plan.socket_path.name, dir_fd=parent_descriptor)
        _require_absent(parent_descriptor, plan.socket_path.name)
        os.fsync(parent_descriptor)
        _require_absent(parent_descriptor, plan.socket_path.name)
        absence = _absence_projection(plan)
    return ShutdownSocketCleanupResultV2(
        plan_fingerprint=plan.plan_fingerprint,
        orphan_proof_fingerprint=orphan.proof_fingerprint,
        absence_projection=absence,
    )


def observe_shutdown_socket_cleanup_v2(
    *,
    plan: ShutdownSocketCleanupPlanV2,
    shutdown: ControllerShutdownProofV2,
    process_start_marker_provider: Callable[[int], str] = system_process_start_marker_v2,
) -> ShutdownSocketCleanupObservationV2:
    """Различить exact socket и durable absence; третье состояние закрыть."""

    orphan = prove_shutdown_socket_orphan_v2(
        plan=plan,
        shutdown=shutdown,
        process_start_marker_provider=process_start_marker_provider,
    )
    try:
        info = plan.socket_path.lstat()
    except FileNotFoundError:
        # Повторный idempotent apply не меняет namespace, но доводит fsync
        # после сбоя между unlinkat и подтверждением directory durability.
        result = apply_shutdown_socket_cleanup_v2(
            plan=plan,
            shutdown=shutdown,
            orphan=orphan,
            process_start_marker_provider=process_start_marker_provider,
        )
        return ShutdownSocketCleanupObservationV2(
            state=ShutdownSocketCleanupStateV2.AFTER,
            orphan=orphan,
            absence_projection=result.absence_projection,
        )
    except OSError as error:
        raise ShutdownSocketCleanupV2Error(
            "SHUTDOWN_SOCKET_CHANGED", str(error)
        ) from error
    if _socket_tuple(info) != (
        plan.socket_device,
        plan.socket_inode,
        plan.socket_owner_uid,
        plan.socket_owner_gid,
        plan.socket_mode,
    ):
        _fail("SHUTDOWN_SOCKET_CHANGED", "socket inode был заменён")
    return ShutdownSocketCleanupObservationV2(
        state=ShutdownSocketCleanupStateV2.BEFORE,
        orphan=orphan,
        absence_projection=None,
    )


@contextmanager
def _proven_environment(
    plan: ShutdownSocketCleanupPlanV2,
    *,
    process_start_marker_provider: Callable[[int], str],
) -> Iterator[tuple[str, str, int]]:
    if not callable(process_start_marker_provider):
        _fail("SHUTDOWN_PROCESS_PROBE_INVALID", "поставщик маркера не вызывается")
    process_fingerprint = _process_exit_fingerprint(
        plan, process_start_marker_provider=process_start_marker_provider
    )
    parent_descriptor = _open_bound_parent(plan)
    lock_descriptor = -1
    try:
        lock_descriptor, lock_fingerprint = _claim_bound_lock(
            plan, parent_descriptor=parent_descriptor
        )
        yield process_fingerprint, lock_fingerprint, parent_descriptor
    finally:
        if lock_descriptor >= 0:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
        os.close(parent_descriptor)


def _authorize(
    plan: ShutdownSocketCleanupPlanV2,
    shutdown: ControllerShutdownProofV2,
) -> None:
    if not isinstance(plan, ShutdownSocketCleanupPlanV2) or not plan.complete:
        _fail("SHUTDOWN_CLEANUP_PLAN_INVALID", "план очистки неполон")
    if (
        not isinstance(shutdown, ControllerShutdownProofV2)
        or not shutdown.complete
        or shutdown.activation_proof_fingerprint
        != plan.activation_proof_fingerprint
        or shutdown.operation_id != plan.operation_id
        or shutdown.shutdown.command_id != plan.shutdown_command_id
    ):
        _fail("SHUTDOWN_PROOF_INVALID", "shutdown proof не авторизует план")
    intent = shutdown.shutdown.payload.get("socketIntent")
    expected = {
        "path": str(plan.socket_path),
        "device": plan.socket_device,
        "inode": plan.socket_inode,
        "ownerUid": plan.socket_owner_uid,
        "ownerGid": plan.socket_owner_gid,
        "mode": plan.socket_mode,
        "controllerPid": plan.target_pid,
        "controllerStartMarker": plan.target_start_marker,
        "controllerProcessGroupId": plan.target_process_group_id,
        "lockPath": str(plan.lock_path),
        "processExitRequired": True,
        "exclusiveLockRequired": True,
    }
    if intent != expected:
        _fail("SHUTDOWN_SOCKET_INTENT_CHANGED", "socketIntent не совпадает с планом")


def _process_exit_fingerprint(
    plan: ShutdownSocketCleanupPlanV2,
    *,
    process_start_marker_provider: Callable[[int], str],
) -> str:
    disposition = "PID_ABSENT"
    observed_marker: str | None = None
    try:
        os.kill(plan.target_pid, 0)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        raise ShutdownSocketCleanupV2Error(
            "SHUTDOWN_PROCESS_LIVENESS_UNKNOWN",
            "нет права проверить старый PID",
        ) from error
    else:
        try:
            observed_marker = process_start_marker_provider(plan.target_pid)
        except ChildGuardV2Error as error:
            if error.code == "PROCESS_NOT_RUNNING":
                disposition = "PID_ABSENT"
            else:
                raise ShutdownSocketCleanupV2Error(
                    "SHUTDOWN_PROCESS_LIVENESS_UNKNOWN",
                    "не удалось получить системный маркер PID",
                ) from error
        else:
            if observed_marker == plan.target_start_marker:
                _fail(
                    "SHUTDOWN_PROCESS_STILL_ACTIVE",
                    "исходный процесс контроллера всё ещё существует",
                )
            disposition = "PID_REUSED"
    return domain_fingerprint(
        "codex-smart/process-exit-proof/v2",
        {
            "pid": plan.target_pid,
            "expectedProcessStartMarker": plan.target_start_marker,
            "expectedProcessGroupId": plan.target_process_group_id,
            # PID_ABSENT and PID_REUSED are two observations of the same
            # monotonic fact: the exact original incarnation is gone.  The
            # fingerprint must survive the reused process exiting later.
            "originalProcessIncarnationAbsent": disposition
            in {"PID_ABSENT", "PID_REUSED"},
        },
    )


def _open_bound_parent(plan: ShutdownSocketCleanupPlanV2) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(plan.socket_path.parent, flags)
    except OSError as error:
        raise ShutdownSocketCleanupV2Error(
            "SHUTDOWN_SOCKET_PARENT_CHANGED", str(error)
        ) from error
    info = os.fstat(descriptor)
    if (
        not _private_directory_info(info)
        or info.st_dev != plan.socket_parent_device
        or info.st_ino != plan.socket_parent_inode
    ):
        os.close(descriptor)
        _fail("SHUTDOWN_SOCKET_PARENT_CHANGED", "родитель socket был заменён")
    return descriptor


def _claim_bound_lock(
    plan: ShutdownSocketCleanupPlanV2,
    *,
    parent_descriptor: int,
) -> tuple[int, str]:
    try:
        descriptor = os.open(
            plan.lock_path.name,
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise ShutdownSocketCleanupV2Error(
            "SHUTDOWN_LOCK_CHANGED", str(error)
        ) from error
    try:
        info = os.fstat(descriptor)
        path_info = os.stat(
            plan.lock_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not _private_lock_info(info) or (info.st_dev, info.st_ino) != (
            path_info.st_dev,
            path_info.st_ino,
        ):
            _fail("SHUTDOWN_LOCK_CHANGED", "lock inode небезопасен или заменён")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ShutdownSocketCleanupV2Error(
                "SHUTDOWN_LOCK_NOT_EXCLUSIVE", "lock всё ещё удерживается"
            ) from error
        fingerprint = domain_fingerprint(
            "codex-smart/exclusive-lock-proof/v2",
            {
                "path": str(plan.lock_path),
                "device": info.st_dev,
                "inode": info.st_ino,
                "ownerUid": info.st_uid,
                "ownerGid": info.st_gid,
                "mode": _mode(info),
                "linkCount": info.st_nlink,
                "parentDevice": plan.socket_parent_device,
                "parentInode": plan.socket_parent_inode,
                "exclusive": True,
            },
        )
        return descriptor, fingerprint
    except BaseException:
        os.close(descriptor)
        raise


def _absence_projection(plan: ShutdownSocketCleanupPlanV2) -> ProjectionV2:
    seed = {
        "installationId": plan.installation_id,
        "operationId": plan.operation_id,
        "entries": [
            {
                "path": str(plan.socket_path),
                "basename": plan.socket_path.name,
                "parentDevice": plan.socket_parent_device,
                "parentInode": plan.socket_parent_inode,
                "absent": True,
            }
        ],
    }
    value = {
        "proofId": "ap2_"
        + domain_fingerprint("codex-smart/absence-proof-id/v2", seed)[:32],
        **seed,
        "directorySyncCompleted": True,
    }
    value["proofFingerprint"] = domain_fingerprint(
        "codex-smart/absence-proof/v2", value
    )
    envelope = {
        "schemaId": "absence-proof-v2",
        "schemaSha256": _LIFECYCLE_SCHEMA_SHA256,
        "value": value,
    }
    return ProjectionV2(
        schema_id="absence-proof-v2",
        schema_sha256=_LIFECYCLE_SCHEMA_SHA256,
        value=value,
        value_fingerprint=domain_fingerprint(
            "codex-smart/absence-proof-projection/v2", envelope
        ),
    )


def _plan_fingerprint(plan: ShutdownSocketCleanupPlanV2) -> str:
    return domain_fingerprint(
        "codex-smart/shutdown-socket-cleanup-plan/v2",
        {
            "installationId": plan.installation_id,
            "activationProofFingerprint": plan.activation_proof_fingerprint,
            "operationId": plan.operation_id,
            "shutdownCommandId": plan.shutdown_command_id,
            "action": copy.deepcopy(dict(plan.action)),
        },
    )


def _orphan_fingerprint(proof: ShutdownSocketOrphanProofV2) -> str:
    return domain_fingerprint(
        "codex-smart/shutdown-socket-orphan-proof/v2",
        {
            "planFingerprint": proof.plan_fingerprint,
            "shutdownProofFingerprint": proof.shutdown_proof_fingerprint,
            "processExitProofFingerprint": proof.process_exit_proof_fingerprint,
            "exclusiveLockProofFingerprint": proof.exclusive_lock_proof_fingerprint,
        },
    )


def _private_parent(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise ShutdownSocketCleanupV2Error(
            "SHUTDOWN_SOCKET_PARENT_CHANGED", str(error)
        ) from error
    if not _private_directory_info(info):
        _fail("SHUTDOWN_SOCKET_PARENT_CHANGED", "родитель socket небезопасен")
    return info


def _private_directory_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _validate_lock_file(path: Path, *, parent_device: int, parent_inode: int) -> None:
    parent = _private_parent(path.parent)
    if (parent.st_dev, parent.st_ino) != (parent_device, parent_inode):
        _fail("SHUTDOWN_LOCK_CHANGED", "lock принадлежит другому parent")
    try:
        info = path.lstat()
    except OSError as error:
        raise ShutdownSocketCleanupV2Error("SHUTDOWN_LOCK_CHANGED", str(error)) from error
    if not _private_lock_info(info):
        _fail("SHUTDOWN_LOCK_CHANGED", "lock file небезопасен")


def _private_lock_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
    )


def _socket_info(path: Path, code: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise ShutdownSocketCleanupV2Error(code, str(error)) from error
    if not stat.S_ISSOCK(info.st_mode):
        _fail(code, "объект не является Unix socket")
    return info


def _socket_tuple_from_controller(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        value.get("socket_device"),
        value.get("socket_inode"),
        value.get("socket_owner_uid"),
        value.get("socket_owner_gid"),
        value.get("socket_mode"),
    )


def _socket_tuple(info: os.stat_result) -> tuple[int, int, int, int, str]:
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, _mode(info)


def _entry_info(parent_descriptor: int, basename: str) -> os.stat_result | None:
    try:
        return os.stat(basename, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ShutdownSocketCleanupV2Error(
            "SHUTDOWN_SOCKET_CHANGED", str(error)
        ) from error


def _require_absent(parent_descriptor: int, basename: str) -> None:
    if _entry_info(parent_descriptor, basename) is not None:
        _fail("SHUTDOWN_SOCKET_DELETE_FAILED", "socket остался после unlinkat")


def _absolute_path(value: Any, code: str) -> Path:
    if type(value) is not str or not value:
        _fail(code, "абсолютный путь отсутствует")
    path = Path(value)
    if not path.is_absolute():
        _fail(code, "ожидался абсолютный путь")
    return path


def _positive_integer(value: Any, code: str) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_PID:
        _fail(code, "ожидалось положительное системное число")
    return value


def _mode(info: os.stat_result) -> str:
    return f"0{stat.S_IMODE(info.st_mode):03o}"


def _identifier(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _fail(code, "идентификатор имеет неверную форму")
    return value


def _fail(code: str, message: str) -> None:
    raise ShutdownSocketCleanupV2Error(code, message)


__all__ = [
    "ShutdownSocketCleanupObservationV2",
    "ShutdownSocketCleanupPlanV2",
    "ShutdownSocketCleanupResultV2",
    "ShutdownSocketCleanupStateV2",
    "ShutdownSocketCleanupV2Error",
    "ShutdownSocketOrphanProofV2",
    "apply_shutdown_socket_cleanup_v2",
    "build_shutdown_socket_cleanup_plan_v2",
    "observe_shutdown_socket_cleanup_v2",
    "prove_shutdown_socket_orphan_v2",
]
