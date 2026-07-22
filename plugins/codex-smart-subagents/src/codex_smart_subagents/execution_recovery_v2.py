"""Восстановление дочерних запусков, переживших контроллер версии 2."""

from __future__ import annotations

import os
import re
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol

from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2


_ATTEMPT_ID = re.compile(r"^att2_[0-9a-f]{32}$")
_PERMIT_ID = re.compile(r"^lp2_[0-9a-f]{32}$")
_ROUTE_ID = re.compile(r"^route2_[0-9a-f]{32}$")
_NODE_ID = re.compile(r"^node2_[0-9a-f]{32}$")
_OBSERVATIONS = frozenset({"EXACT", "ABSENT", "REUSED", "UNVERIFIABLE"})


@dataclass
class ExecutionRecoveryV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class ExecutionRecoveryActionV2:
    kind: str
    attempt_id: str
    route_id: str
    node_id: str
    pid: int
    process_start_marker: str


@dataclass(frozen=True)
class ExecutionRecoveryReportV2:
    ok: bool
    applied: bool
    actions: tuple[ExecutionRecoveryActionV2, ...]
    blockers: tuple[str, ...]


class ExecutionRecoveryStoreV2(Protocol):
    def stranded_attempts(self) -> list[dict[str, Any]]: ...

    def begin_stranded_attempt_recovery(
        self,
        attempt_id: str,
        *,
        pid: int,
        process_start_marker: str,
        now: datetime,
    ) -> Mapping[str, Any]: ...

    def complete_stranded_attempt_recovery(
        self,
        attempt_id: str,
        *,
        pid: int,
        process_start_marker: str,
        now: datetime,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class LaunchPermitRecoveryActionV2:
    kind: str
    permit_id: str
    route_id: str
    node_id: str
    guard_pid: int | None
    guard_start_marker: str | None


@dataclass(frozen=True)
class LaunchPermitRecoveryReportV2:
    ok: bool
    applied: bool
    actions: tuple[LaunchPermitRecoveryActionV2, ...]
    blockers: tuple[str, ...]


class LaunchPermitRecoveryStoreV2(Protocol):
    def stranded_launch_permits(self) -> list[dict[str, Any]]: ...

    def begin_stranded_permit_recovery(
        self,
        permit_id: str,
        *,
        guard_pid: int | None,
        guard_start_marker: str | None,
        now: datetime,
    ) -> Mapping[str, Any]: ...

    def complete_stranded_permit_recovery(
        self,
        permit_id: str,
        *,
        guard_pid: int | None,
        guard_start_marker: str | None,
        now: datetime,
    ) -> Mapping[str, Any]: ...

ProcessObserverV2 = Callable[[int, str], str]
ProcessTerminatorV2 = Callable[[int, str], None]


class ExecutionRecoveryV2:
    """Сначала доказывает полный план, затем закрывает только точные попытки."""

    def __init__(
        self,
        *,
        store: ExecutionRecoveryStoreV2,
        process_observer: ProcessObserverV2 | None = None,
        process_terminator: ProcessTerminatorV2 | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        required = (
            "stranded_attempts",
            "begin_stranded_attempt_recovery",
            "complete_stranded_attempt_recovery",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise TypeError("store не предоставляет операции восстановления запуска")
        observer = process_observer or observe_process_identity_v2
        terminator = process_terminator or terminate_process_identity_v2
        if not callable(observer) or not callable(terminator):
            raise TypeError("process observer and terminator must be callable")
        self.store = store
        self.process_observer = observer
        self.process_terminator = terminator
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, *, apply: bool) -> ExecutionRecoveryReportV2:
        if type(apply) is not bool:
            raise TypeError("apply должен быть bool")
        actions, blockers = self._plan()
        if blockers or not apply:
            return ExecutionRecoveryReportV2(
                ok=not blockers,
                applied=False,
                actions=tuple(actions),
                blockers=tuple(blockers),
            )

        confirmed_actions, confirmed_blockers = self._plan()
        if confirmed_blockers or confirmed_actions != actions:
            changed = list(confirmed_blockers)
            changed.append("EXECUTION_RECOVERY_PLAN_CHANGED")
            return ExecutionRecoveryReportV2(
                ok=False,
                applied=False,
                actions=tuple(confirmed_actions),
                blockers=tuple(dict.fromkeys(changed)),
            )
        for action in actions:
            self._apply(action)
        return ExecutionRecoveryReportV2(
            ok=True,
            applied=bool(actions),
            actions=tuple(actions),
            blockers=(),
        )

    def _plan(
        self,
    ) -> tuple[list[ExecutionRecoveryActionV2], list[str]]:
        try:
            raw_records = self.store.stranded_attempts()
        except Exception as exc:
            raise ExecutionRecoveryV2Error(
                "EXECUTION_RECOVERY_STORE_UNAVAILABLE",
                str(exc),
            ) from exc
        if type(raw_records) is not list:
            raise ExecutionRecoveryV2Error(
                "EXECUTION_RECOVERY_STORE_INVALID",
                "stranded attempt list must be an exact list",
            )
        actions: list[ExecutionRecoveryActionV2] = []
        blockers: list[str] = []
        seen: set[str] = set()
        for raw in raw_records:
            parsed = _parse_record(raw)
            if parsed is None:
                blockers.append("STRANDED_ATTEMPT_RECORD_INVALID")
                continue
            attempt_id, route_id, node_id, pid, marker = parsed
            if attempt_id in seen:
                blockers.append("STRANDED_ATTEMPT_RECORD_CONFLICT")
                continue
            seen.add(attempt_id)
            observation = self.process_observer(pid, marker)
            if observation not in _OBSERVATIONS:
                raise ExecutionRecoveryV2Error(
                    "PROCESS_OBSERVATION_INVALID",
                    "process observer returned an unknown state",
                )
            if observation == "UNVERIFIABLE":
                blockers.append("PROCESS_IDENTITY_UNVERIFIABLE")
                continue
            actions.append(
                ExecutionRecoveryActionV2(
                    kind=(
                        "TERMINATE_AND_FAIL"
                        if observation == "EXACT"
                        else "FAIL_ABSENT"
                    ),
                    attempt_id=attempt_id,
                    route_id=route_id,
                    node_id=node_id,
                    pid=pid,
                    process_start_marker=marker,
                )
            )
        actions.sort(key=lambda item: item.attempt_id)
        return actions, list(dict.fromkeys(blockers))

    def _apply(self, action: ExecutionRecoveryActionV2) -> None:
        begun = self.store.begin_stranded_attempt_recovery(
            action.attempt_id,
            pid=action.pid,
            process_start_marker=action.process_start_marker,
            now=self.clock(),
        )
        if begun.get("state") != "PENDING":
            raise ExecutionRecoveryV2Error(
                "EXECUTION_RECOVERY_INTENT_MISMATCH",
                "recovery intent did not become PENDING",
            )
        observation = self.process_observer(
            action.pid,
            action.process_start_marker,
        )
        if observation == "EXACT":
            self.process_terminator(
                action.pid,
                action.process_start_marker,
            )
            observation = self.process_observer(
                action.pid,
                action.process_start_marker,
            )
        if observation not in {"ABSENT", "REUSED"}:
            raise ExecutionRecoveryV2Error(
                "PROCESS_TERMINATION_UNPROVEN",
                "the original child process is still present or unverifiable",
            )
        completed = self.store.complete_stranded_attempt_recovery(
            action.attempt_id,
            pid=action.pid,
            process_start_marker=action.process_start_marker,
            now=self.clock(),
        )
        if (
            completed.get("state") != "FAILED"
            or completed.get("errorCode") != "CONTROLLER_RESTARTED"
        ):
            raise ExecutionRecoveryV2Error(
                "EXECUTION_RECOVERY_TERMINAL_MISMATCH",
                "stranded attempt did not become the expected terminal state",
            )


class LaunchPermitRecoveryV2:
    """Закрывает резервы и сторожей, не дошедших до создания попытки."""

    def __init__(
        self,
        *,
        store: LaunchPermitRecoveryStoreV2,
        process_observer: ProcessObserverV2 | None = None,
        process_terminator: ProcessTerminatorV2 | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        required = (
            "stranded_launch_permits",
            "begin_stranded_permit_recovery",
            "complete_stranded_permit_recovery",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise TypeError("store не предоставляет операции восстановления разрешения")
        observer = process_observer or observe_process_identity_v2
        terminator = process_terminator or terminate_process_identity_v2
        if not callable(observer) or not callable(terminator):
            raise TypeError("process observer and terminator must be callable")
        self.store = store
        self.process_observer = observer
        self.process_terminator = terminator
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, *, apply: bool) -> LaunchPermitRecoveryReportV2:
        if type(apply) is not bool:
            raise TypeError("apply должен быть bool")
        actions, blockers = self._plan()
        if blockers or not apply:
            return LaunchPermitRecoveryReportV2(
                ok=not blockers,
                applied=False,
                actions=tuple(actions),
                blockers=tuple(blockers),
            )
        confirmed_actions, confirmed_blockers = self._plan()
        if confirmed_blockers or confirmed_actions != actions:
            changed = list(confirmed_blockers)
            changed.append("LAUNCH_PERMIT_RECOVERY_PLAN_CHANGED")
            return LaunchPermitRecoveryReportV2(
                ok=False,
                applied=False,
                actions=tuple(confirmed_actions),
                blockers=tuple(dict.fromkeys(changed)),
            )
        for action in actions:
            self._apply(action)
        return LaunchPermitRecoveryReportV2(
            ok=True,
            applied=bool(actions),
            actions=tuple(actions),
            blockers=(),
        )

    def _plan(
        self,
    ) -> tuple[list[LaunchPermitRecoveryActionV2], list[str]]:
        try:
            raw_records = self.store.stranded_launch_permits()
        except Exception as exc:
            raise ExecutionRecoveryV2Error(
                "LAUNCH_PERMIT_RECOVERY_STORE_UNAVAILABLE",
                str(exc),
            ) from exc
        if type(raw_records) is not list:
            raise ExecutionRecoveryV2Error(
                "LAUNCH_PERMIT_RECOVERY_STORE_INVALID",
                "stranded launch permit list must be an exact list",
            )
        actions: list[LaunchPermitRecoveryActionV2] = []
        blockers: list[str] = []
        seen: set[str] = set()
        for raw in raw_records:
            parsed = _parse_permit_record(raw)
            if parsed is None:
                blockers.append("STRANDED_LAUNCH_PERMIT_RECORD_INVALID")
                continue
            permit_id, route_id, node_id, state, guard_pid, marker = parsed
            if permit_id in seen:
                blockers.append("STRANDED_LAUNCH_PERMIT_RECORD_CONFLICT")
                continue
            seen.add(permit_id)
            if state == "RESERVED":
                kind = "ABORT_RESERVED"
            else:
                assert guard_pid is not None and marker is not None
                observation = self.process_observer(guard_pid, marker)
                if observation not in _OBSERVATIONS:
                    raise ExecutionRecoveryV2Error(
                        "PROCESS_OBSERVATION_INVALID",
                        "process observer returned an unknown state",
                    )
                if observation == "UNVERIFIABLE":
                    blockers.append("PROCESS_IDENTITY_UNVERIFIABLE")
                    continue
                kind = (
                    "TERMINATE_GUARD_AND_ABORT"
                    if observation == "EXACT"
                    else "ABORT_GUARD_ABSENT"
                )
            actions.append(
                LaunchPermitRecoveryActionV2(
                    kind=kind,
                    permit_id=permit_id,
                    route_id=route_id,
                    node_id=node_id,
                    guard_pid=guard_pid,
                    guard_start_marker=marker,
                )
            )
        actions.sort(key=lambda item: item.permit_id)
        return actions, list(dict.fromkeys(blockers))

    def _apply(self, action: LaunchPermitRecoveryActionV2) -> None:
        begun = self.store.begin_stranded_permit_recovery(
            action.permit_id,
            guard_pid=action.guard_pid,
            guard_start_marker=action.guard_start_marker,
            now=self.clock(),
        )
        if begun.get("state") != "PENDING":
            raise ExecutionRecoveryV2Error(
                "LAUNCH_PERMIT_RECOVERY_INTENT_MISMATCH",
                "permit recovery intent did not become PENDING",
            )
        if action.guard_pid is not None and action.guard_start_marker is not None:
            observation = self.process_observer(
                action.guard_pid,
                action.guard_start_marker,
            )
            if observation == "EXACT":
                self.process_terminator(
                    action.guard_pid,
                    action.guard_start_marker,
                )
                observation = self.process_observer(
                    action.guard_pid,
                    action.guard_start_marker,
                )
            if observation not in {"ABSENT", "REUSED"}:
                raise ExecutionRecoveryV2Error(
                    "PROCESS_TERMINATION_UNPROVEN",
                    "the original guard process is still present or unverifiable",
                )
        completed = self.store.complete_stranded_permit_recovery(
            action.permit_id,
            guard_pid=action.guard_pid,
            guard_start_marker=action.guard_start_marker,
            now=self.clock(),
        )
        if (
            completed.get("state") != "FAILED_BEFORE_START"
            or completed.get("errorCode") != "CONTROLLER_RESTARTED"
        ):
            raise ExecutionRecoveryV2Error(
                "LAUNCH_PERMIT_RECOVERY_TERMINAL_MISMATCH",
                "stranded permit did not become the expected terminal state",
            )


def observe_process_identity_v2(pid: int, expected_marker: str) -> str:
    """Различает точный процесс, отсутствие, повтор PID и неизвестность."""

    if type(pid) is not int or pid <= 0 or not isinstance(expected_marker, str) or not expected_marker:
        raise ExecutionRecoveryV2Error(
            "PROCESS_IDENTITY_INVALID",
            "process identity is incomplete",
        )
    try:
        marker = system_process_start_marker_v2(pid)
    except ChildGuardV2Error as exc:
        if exc.code == "PROCESS_NOT_RUNNING":
            return "ABSENT"
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "ABSENT"
        except (PermissionError, OSError):
            return "UNVERIFIABLE"
        return "UNVERIFIABLE"
    return "EXACT" if marker == expected_marker else "REUSED"


def terminate_process_identity_v2(
    pid: int,
    expected_marker: str,
    *,
    graceful_seconds: float = 1.0,
    force_seconds: float = 1.0,
) -> None:
    """Останавливает только подтверждённую отдельную группу дочернего процесса."""

    if observe_process_identity_v2(pid, expected_marker) != "EXACT":
        return
    try:
        process_group = os.getpgid(pid)
    except OSError as exc:
        if observe_process_identity_v2(pid, expected_marker) in {"ABSENT", "REUSED"}:
            return
        raise ExecutionRecoveryV2Error(
            "PROCESS_GROUP_UNVERIFIABLE",
            str(exc),
        ) from exc
    if process_group != pid:
        raise ExecutionRecoveryV2Error(
            "PROCESS_GROUP_UNVERIFIABLE",
            "child process does not lead its recorded process group",
        )
    _signal_exact_group(pid, expected_marker, signal.SIGTERM)
    if _wait_until_original_absent(pid, expected_marker, graceful_seconds):
        return
    _signal_exact_group(pid, expected_marker, signal.SIGKILL)
    if not _wait_until_original_absent(pid, expected_marker, force_seconds):
        raise ExecutionRecoveryV2Error(
            "PROCESS_TERMINATION_UNPROVEN",
            "child process survived SIGKILL deadline",
        )


def _signal_exact_group(pid: int, marker: str, signum: int) -> None:
    if observe_process_identity_v2(pid, marker) != "EXACT":
        return
    try:
        if os.getpgid(pid) != pid:
            raise ExecutionRecoveryV2Error(
                "PROCESS_GROUP_UNVERIFIABLE",
                "child process group changed before signal",
            )
        os.killpg(pid, signum)
    except ProcessLookupError:
        return
    except ExecutionRecoveryV2Error:
        raise
    except OSError as exc:
        raise ExecutionRecoveryV2Error(
            "PROCESS_SIGNAL_FAILED",
            str(exc),
        ) from exc


def _wait_until_original_absent(pid: int, marker: str, seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, float(seconds))
    while True:
        if observe_process_identity_v2(pid, marker) in {"ABSENT", "REUSED"}:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def _parse_record(
    raw: object,
) -> tuple[str, str, str, int, str] | None:
    if not isinstance(raw, Mapping) or set(raw) != {
        "attemptId",
        "routeId",
        "nodeId",
        "state",
        "pid",
        "processStartMarker",
    }:
        return None
    attempt_id = raw["attemptId"]
    route_id = raw["routeId"]
    node_id = raw["nodeId"]
    state = raw["state"]
    pid = raw["pid"]
    marker = raw["processStartMarker"]
    if (
        type(attempt_id) is not str
        or _ATTEMPT_ID.fullmatch(attempt_id) is None
        or type(route_id) is not str
        or _ROUTE_ID.fullmatch(route_id) is None
        or type(node_id) is not str
        or _NODE_ID.fullmatch(node_id) is None
        or state not in {"STARTING", "RUNNING"}
        or type(pid) is not int
        or pid <= 0
        or type(marker) is not str
        or not marker
        or len(marker.encode("utf-8")) > 256
    ):
        return None
    return attempt_id, route_id, node_id, pid, marker


def _parse_permit_record(
    raw: object,
) -> tuple[str, str, str, str, int | None, str | None] | None:
    if not isinstance(raw, Mapping) or set(raw) != {
        "permitId",
        "routeId",
        "nodeId",
        "state",
        "guardPid",
        "guardStartMarker",
    }:
        return None
    permit_id = raw["permitId"]
    route_id = raw["routeId"]
    node_id = raw["nodeId"]
    state = raw["state"]
    guard_pid = raw["guardPid"]
    marker = raw["guardStartMarker"]
    if (
        type(permit_id) is not str
        or _PERMIT_ID.fullmatch(permit_id) is None
        or type(route_id) is not str
        or _ROUTE_ID.fullmatch(route_id) is None
        or type(node_id) is not str
        or _NODE_ID.fullmatch(node_id) is None
        or state not in {"RESERVED", "GUARDED"}
    ):
        return None
    if state == "RESERVED":
        if guard_pid is not None or marker is not None:
            return None
    elif (
        type(guard_pid) is not int
        or guard_pid <= 0
        or type(marker) is not str
        or not marker
        or len(marker.encode("utf-8")) > 256
    ):
        return None
    return permit_id, route_id, node_id, state, guard_pid, marker


__all__ = [
    "ExecutionRecoveryActionV2",
    "ExecutionRecoveryReportV2",
    "ExecutionRecoveryV2",
    "ExecutionRecoveryV2Error",
    "LaunchPermitRecoveryActionV2",
    "LaunchPermitRecoveryReportV2",
    "LaunchPermitRecoveryV2",
    "observe_process_identity_v2",
    "terminate_process_identity_v2",
]
