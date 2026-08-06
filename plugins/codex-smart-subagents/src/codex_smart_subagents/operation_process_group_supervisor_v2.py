"""Конечный надзор за непринятыми временными группами процессов версии 2.

Новый процесс всегда получает отдельный сеанс и немедленно регистрируется как
принадлежащий надзору. Надзор умеет только мягко завершать всю группу. Если
группа не исчезла в пределах переданного общего срока, владение сохраняется,
возвращается долговечная обязанность очистки и шлюз продолжения закрывается.
"""

from __future__ import annotations

import copy
import errno
import math
import os
import secrets
import signal
import subprocess
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Sequence

from .child_guard_v2 import ChildGuardV2Error, system_process_start_marker_v2
from .operation_deadline_v2 import (
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    deadline_proof_v2,
    validate_deadline_proof_v2,
)


_CLEANUP_OBLIGATION_KEYS = frozenset(
    {
        "schemaVersion",
        "obligationType",
        "obligationId",
        "status",
        "operation",
        "phase",
        "processLabel",
        "pid",
        "processGroupId",
        "reasonCode",
        "attempt",
        "termSent",
        "contSent",
        "preContSent",
        "postContSent",
        "termErrorErrno",
        "contErrorErrno",
        "preContErrorErrno",
        "postContErrorErrno",
        "observedAlive",
        "nextAction",
        "automaticSignalAuthorized",
        "continuationAllowed",
        "expectedProcessIdentity",
        "observedProcessIdentity",
        "identityFailureCode",
        "deadlineProof",
    }
)


class ProcessGroupSupervisorV2Error(RuntimeError):
    """Базовая ошибка надзора за временными группами."""


class TransientProcessOwnershipErrorV2(ProcessGroupSupervisorV2Error):
    """Дескриптор не принадлежит этому надзору либо уже принят."""


class TransientProcessIdentityErrorV2(ProcessGroupSupervisorV2Error):
    """Запущенный процесс нельзя безопасно связать с новой группой."""

    def __init__(self, code: str, launch_id: str) -> None:
        super().__init__(f"{code}: transient process identity is unverified")
        self.code = code
        self.launch_id = launch_id


class OutstandingProcessCleanupObligationV2(ProcessGroupSupervisorV2Error):
    """Продолжение запрещено, пока известная группа остаётся живой."""

    def __init__(self, obligation_ids: Sequence[str]) -> None:
        ids = tuple(obligation_ids)
        super().__init__(
            "outstanding transient process cleanup obligations: "
            + ", ".join(ids)
        )
        self.obligation_ids = ids


class CleanupObligationValidationErrorV2(ValueError):
    """Обязанность очистки не соответствует закрытому контракту."""


class CurrentProcessGroupSupervisorUnavailableV2(RuntimeError):
    """Запуск вызван вне области единого надзора операции."""


class CurrentProcessGroupSupervisorConflictV2(RuntimeError):
    """Вложенная область попыталась заменить надзор текущей операции."""


class DurableProcessOwnershipCallbackErrorV2(
    ProcessGroupSupervisorV2Error
):
    """Долговечная публикация либо смена состояния владения не удалась."""

    def __init__(
        self,
        *,
        lease_id: str,
        outcome: str,
        cleanup_obligation: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(
            "DURABLE_PROCESS_OWNERSHIP_CALLBACK_FAILED: "
            f"{lease_id}/{outcome}"
        )
        self.lease_id = lease_id
        self.outcome = outcome
        self.cleanup_obligation = (
            None
            if cleanup_obligation is None
            else copy.deepcopy(dict(cleanup_obligation))
        )


@dataclass(frozen=True, slots=True)
class ProcessIdentityV2:
    """Повторно наблюдаемая системная личность лидера новой группы."""

    pid: int
    process_group_id: int
    session_id: int
    start_marker: str

    def __post_init__(self) -> None:
        for name in ("pid", "process_group_id", "session_id"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.start_marker) is not str or not self.start_marker:
            raise ValueError("start_marker must be a non-empty string")


@dataclass(frozen=True, slots=True)
class TransientProcessLeaseV2:
    """Владение одним ещё не принятым временным процессом."""

    lease_id: str
    label: str
    pid: int
    process_group_id: int
    session_id: int
    process_start_marker: str
    process: Any = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ProcessGroupTerminationResultV2:
    """Конечный результат одной попытки мягкой очистки группы."""

    lease_id: str
    pid: int
    process_group_id: int
    state: str
    term_sent: bool
    cont_sent: bool
    term_error_errno: int | None
    cont_error_errno: int | None
    observed_group_alive: bool
    identity_failure_code: str | None
    continuation_allowed: bool
    cleanup_obligation: Mapping[str, object] | None

    def __post_init__(self) -> None:
        if self.cleanup_obligation is not None:
            object.__setattr__(
                self,
                "cleanup_obligation",
                copy.deepcopy(dict(self.cleanup_obligation)),
            )


@dataclass(slots=True)
class _OwnedTransientProcessV2:
    lease: TransientProcessLeaseV2
    ownership_context: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType({})
    )
    ownership_published: bool = False
    ownership_callback_failed: bool = False
    attempt: int = 0
    cleanup_obligation: dict[str, object] | None = None


@dataclass(slots=True)
class _UnverifiedTransientProcessV2:
    process: Any
    pid: int | None
    process_group_id: int | None


class OperationProcessGroupSupervisorV2:
    """Владелец только временных процессов до явного принятия результата."""

    def __init__(
        self,
        *,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        killpg: Callable[[int, int], None] = os.killpg,
        group_exists: Callable[[int], bool] | None = None,
        identity_reader: Callable[[int], ProcessIdentityV2 | None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_seconds: float = 0.01,
        ownership_publisher: Callable[
            [TransientProcessLeaseV2, Mapping[str, object]], None
        ]
        | None = None,
        ownership_transition: Callable[
            [
                TransientProcessLeaseV2,
                Mapping[str, object],
                str,
                Mapping[str, object] | None,
            ],
            None,
        ]
        | None = None,
    ) -> None:
        if not callable(popen_factory):
            raise TypeError("popen_factory must be callable")
        if not callable(killpg):
            raise TypeError("killpg must be callable")
        if group_exists is not None and not callable(group_exists):
            raise TypeError("group_exists must be callable")
        if identity_reader is not None and not callable(identity_reader):
            raise TypeError("identity_reader must be callable")
        if not callable(sleep):
            raise TypeError("sleep must be callable")
        if ownership_publisher is not None and not callable(
            ownership_publisher
        ):
            raise TypeError("ownership_publisher must be callable or null")
        if ownership_transition is not None and not callable(
            ownership_transition
        ):
            raise TypeError("ownership_transition must be callable or null")
        if (ownership_publisher is None) != (ownership_transition is None):
            raise ValueError(
                "durable ownership callbacks must be configured together"
            )
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not math.isfinite(float(poll_interval_seconds))
            or float(poll_interval_seconds) <= 0
        ):
            raise ValueError(
                "poll_interval_seconds must be a positive finite number"
            )
        self._popen_factory = popen_factory
        self._killpg = killpg
        self._group_exists = (
            _default_group_exists if group_exists is None else group_exists
        )
        self._identity_reader = (
            _default_process_identity_v2
            if identity_reader is None
            else identity_reader
        )
        self._sleep = sleep
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._ownership_publisher = ownership_publisher
        self._ownership_transition = ownership_transition
        self._owned: dict[str, _OwnedTransientProcessV2] = {}
        self._unverified: dict[str, _UnverifiedTransientProcessV2] = {}

    def spawn_transient(
        self,
        *,
        label: str,
        argv: Sequence[str],
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        pass_fds: Sequence[int] = (),
        restore_signals: bool = True,
        umask: int = -1,
        text: bool = False,
        encoding: str | None = None,
        errors: str | None = None,
        ownership_context: Mapping[str, object] | None = None,
    ) -> TransientProcessLeaseV2:
        """Запустить новую группу и сразу зарегистрировать владение ею."""

        self.assert_continuation_allowed()
        checked_label = _required_string(label, "label")
        checked_argv = _checked_argv(argv)
        checked_pass_fds = _checked_pass_fds(pass_fds)
        checked_ownership_context = _checked_ownership_context(
            ownership_context,
            label=checked_label,
        )
        if type(restore_signals) is not bool:
            raise TypeError("restore_signals must be a bool")
        if type(text) is not bool:
            raise TypeError("text must be a bool")
        if encoding is not None and (type(encoding) is not str or not encoding):
            raise ValueError("encoding must be null or a non-empty string")
        if errors is not None and (type(errors) is not str or not errors):
            raise ValueError("errors must be null or a non-empty string")
        if type(umask) is not int or umask < -1 or umask > 0o777:
            raise ValueError("umask must be -1 or an integer in [0, 0o777]")
        lease_id = "transient-" + secrets.token_hex(16)
        process = self._popen_factory(
            checked_argv,
            cwd=cwd,
            env=None if env is None else dict(env),
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            start_new_session=True,
            close_fds=True,
            pass_fds=checked_pass_fds,
            restore_signals=restore_signals,
            umask=umask,
            text=text,
            encoding=encoding,
            errors=errors,
        )
        pid = getattr(process, "pid", None)
        if type(pid) is not int or pid <= 0:
            self._unverified[lease_id] = _UnverifiedTransientProcessV2(
                process=process,
                pid=None,
                process_group_id=None,
            )
            self._softly_terminate_unverified(lease_id)
            raise TransientProcessIdentityErrorV2(
                "SPAWNED_PROCESS_PID_INVALID", lease_id
            )
        provisional_lease = TransientProcessLeaseV2(
            lease_id=lease_id,
            label=checked_label,
            pid=pid,
            process_group_id=pid,
            session_id=pid,
            process_start_marker="identity-pending",
            process=process,
        )
        # Никаких вызовов процесса или системы между Popen и этой записью нет.
        record = _OwnedTransientProcessV2(
            lease=provisional_lease,
            ownership_context=checked_ownership_context,
        )
        self._owned[lease_id] = record
        identity = self._read_identity(pid)
        if not _is_new_session_identity(identity, pid):
            del self._owned[lease_id]
            self._unverified[lease_id] = _UnverifiedTransientProcessV2(
                process=process,
                pid=pid,
                process_group_id=pid,
            )
            self._softly_terminate_unverified(lease_id)
            raise TransientProcessIdentityErrorV2(
                "SPAWNED_PROCESS_IDENTITY_UNVERIFIED", lease_id
            )
        assert identity is not None
        lease = TransientProcessLeaseV2(
            lease_id=lease_id,
            label=checked_label,
            pid=identity.pid,
            process_group_id=identity.process_group_id,
            session_id=identity.session_id,
            process_start_marker=identity.start_marker,
            process=process,
        )
        record.lease = lease
        if self._ownership_publisher is not None:
            try:
                self._ownership_publisher(
                    lease,
                    record.ownership_context,
                )
            except BaseException as error:
                record.ownership_callback_failed = True
                raise DurableProcessOwnershipCallbackErrorV2(
                    lease_id=lease.lease_id,
                    outcome="publish",
                ) from error
            record.ownership_published = True
        return lease

    def owned_lease_ids(self) -> tuple[str, ...]:
        return tuple(self._owned)

    def unverified_launch_ids(self) -> tuple[str, ...]:
        return tuple(self._unverified)

    def reconcile_unverified_launches(self) -> tuple[str, ...]:
        """Снять из шлюза лишь уже завершившиеся непроверенные запуски."""

        removed: list[str] = []
        for launch_id, record in tuple(self._unverified.items()):
            try:
                return_code = record.process.poll()
            except (AttributeError, OSError):
                continue
            if return_code is not None and not self._unverified_group_alive(
                record
            ):
                _close_process_streams(record.process)
                del self._unverified[launch_id]
                removed.append(launch_id)
        return tuple(removed)

    def reconcile_completed_transients(self) -> tuple[str, ...]:
        """Снять владение только с доказанно исчезнувших завершённых групп."""

        removed: list[str] = []
        for lease_id, record in tuple(self._owned.items()):
            try:
                return_code = record.lease.process.poll()
            except (AttributeError, OSError):
                continue
            if return_code is None or self._observe_group_alive(record):
                continue
            self._transition_durable_ownership(
                record,
                outcome="verified-exit",
                cleanup_obligation=None,
            )
            _close_process_streams(record.lease.process)
            del self._owned[lease_id]
            removed.append(lease_id)
        return tuple(removed)

    def outstanding_cleanup_obligations(
        self,
    ) -> tuple[dict[str, object], ...]:
        return tuple(
            copy.deepcopy(record.cleanup_obligation)
            for record in self._owned.values()
            if record.cleanup_obligation is not None
        )

    def assert_continuation_allowed(self) -> None:
        """Закрыть последующие действия при незавершённой очистке."""

        obligation_ids = tuple(
            record.lease.lease_id
            for record in self._owned.values()
            if record.cleanup_obligation is not None
            or record.ownership_callback_failed
        )
        obligation_ids += tuple(self._unverified)
        if obligation_ids:
            raise OutstandingProcessCleanupObligationV2(obligation_ids)

    def assert_operation_quiescent(self) -> None:
        """Доказать отсутствие любого оставшегося временного владения."""

        self.reconcile_unverified_launches()
        self.reconcile_completed_transients()
        self.assert_continuation_allowed()
        if self._owned:
            raise TransientProcessOwnershipErrorV2(
                "operation returned with transient process ownership: "
                + ", ".join(self._owned)
            )

    def release_after_acceptance(self, lease: TransientProcessLeaseV2) -> Any:
        """Передать уже принятый процесс вызывающей стороне и прекратить надзор."""

        record = self._require_owned(lease)
        self.assert_continuation_allowed()
        self._transition_durable_ownership(
            record,
            outcome="accepted",
            cleanup_obligation=None,
        )
        del self._owned[lease.lease_id]
        return record.lease.process

    def release_after_acceptance_identity(
        self,
        *,
        pid: int,
        process_group_id: int,
        process_start_marker: str,
    ) -> Any | None:
        """Передать принятый процесс по полной сохранённой личности."""

        if type(pid) is not int or pid <= 0:
            raise ValueError("pid must be a positive integer")
        if type(process_group_id) is not int or process_group_id <= 0:
            raise ValueError("process_group_id must be a positive integer")
        marker = _required_string(
            process_start_marker, "process_start_marker"
        )
        matches = [
            record
            for record in self._owned.values()
            if record.lease.pid == pid
            and record.lease.process_group_id == process_group_id
            and record.lease.process_start_marker == marker
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise TransientProcessOwnershipErrorV2(
                "accepted process identity is not unique"
            )
        return self.release_after_acceptance(matches[0].lease)

    def release_after_verified_exit(
        self,
        lease: TransientProcessLeaseV2,
        *,
        deadline: OperationDeadlineV2,
        reason_code: str,
    ) -> Any | ProcessGroupTerminationResultV2:
        """Снять завершённую короткую команду лишь после исчезновения группы."""

        record = self._require_owned(lease)
        if not isinstance(deadline, OperationDeadlineV2):
            raise TypeError("deadline must be OperationDeadlineV2")
        checked_reason = _required_string(reason_code, "reason_code")
        try:
            return_code = record.lease.process.poll()
        except (AttributeError, OSError) as error:
            raise TransientProcessOwnershipErrorV2(
                "transient process completion cannot be observed"
            ) from error
        if return_code is None:
            raise TransientProcessOwnershipErrorV2(
                "transient process has not exited"
            )
        if not self._observe_group_alive(record):
            self._transition_durable_ownership(
                record,
                outcome="verified-exit",
                cleanup_obligation=None,
            )
            del self._owned[lease.lease_id]
            return record.lease.process
        record.attempt += 1
        observed_identity = self._read_identity(lease.pid)
        if observed_identity is None:
            identity_failure_code = "PROCESS_IDENTITY_UNAVAILABLE"
        elif observed_identity == _lease_identity(lease):
            identity_failure_code = "PROCESS_IDENTITY_PRESENT_AFTER_EXIT"
        else:
            identity_failure_code = "PROCESS_IDENTITY_MISMATCH"
        return self._finish_cleanup_required(
            record,
            operation=deadline.operation,
            phase="completed-process-group-reconciliation",
            reason_code=checked_reason,
            term_sent=False,
            cont_sent=False,
            term_errno=None,
            cont_errno=None,
            observed_alive=True,
            observed_identity=observed_identity,
            identity_failure_code=identity_failure_code,
            deadline_error=None,
        )

    def terminate_transient(
        self,
        lease: TransientProcessLeaseV2,
        *,
        deadline: OperationDeadlineV2,
        max_wait_seconds: object,
        reason_code: str,
    ) -> ProcessGroupTerminationResultV2:
        """Разбудить группу, отправить TERM и условный CONT в пределах срока."""

        record = self._require_owned(lease)
        if not isinstance(deadline, OperationDeadlineV2):
            raise TypeError("deadline must be OperationDeadlineV2")
        checked_reason = _required_string(reason_code, "reason_code")

        wait_deadline: OperationDeadlineV2 | None
        deadline_error: OperationDeadlineExceededV2 | None = None
        try:
            wait_deadline = deadline.child(
                phase="process-group-cleanup",
                max_seconds=max_wait_seconds,
                timeout_code="PROCESS_GROUP_CLEANUP_DEADLINE_EXCEEDED",
            )
        except OperationDeadlineExceededV2 as error:
            wait_deadline = None
            deadline_error = error
        record.attempt += 1

        observed_identity = self._read_identity(lease.pid)
        if observed_identity != _lease_identity(lease):
            return self._finish_cleanup_required(
                record,
                operation=deadline.operation,
                phase="process-group-identity-check",
                reason_code=checked_reason,
                term_sent=False,
                cont_sent=False,
                term_errno=None,
                cont_errno=None,
                observed_alive=self._observe_group_alive(record),
                observed_identity=observed_identity,
                identity_failure_code=(
                    "PROCESS_IDENTITY_UNAVAILABLE"
                    if observed_identity is None
                    else "PROCESS_IDENTITY_MISMATCH"
                ),
                deadline_error=None,
            )

        # Сначала будим точно опознанную группу. Иначе лидер может исчезнуть
        # после TERM, а остановленные потомки уже не смогут безопасно получить
        # CONT: повторно доказать личность по исчезнувшему лидеру невозможно.
        pre_cont_sent, pre_cont_errno = self._send_group_signal(
            lease.process_group_id, signal.SIGCONT
        )
        if not pre_cont_sent:
            observed_alive = self._observe_group_alive(record)
            if not observed_alive:
                return self._finish_terminated(
                    record,
                    term_sent=False,
                    cont_sent=False,
                    term_errno=None,
                    cont_errno=pre_cont_errno,
                )
            return self._finish_cleanup_required(
                record,
                operation=deadline.operation,
                phase="process-group-pre-cont",
                reason_code=checked_reason,
                term_sent=False,
                cont_sent=False,
                term_errno=None,
                cont_errno=pre_cont_errno,
                observed_alive=True,
                observed_identity=observed_identity,
                identity_failure_code=None,
                deadline_error=None,
                pre_cont_sent=False,
                pre_cont_errno=pre_cont_errno,
            )
        before_term_identity = self._read_identity(lease.pid)
        if before_term_identity != _lease_identity(lease):
            return self._finish_cleanup_required(
                record,
                operation=deadline.operation,
                phase="process-group-identity-check",
                reason_code=checked_reason,
                term_sent=False,
                cont_sent=True,
                term_errno=None,
                cont_errno=None,
                observed_alive=self._observe_group_alive(record),
                observed_identity=before_term_identity,
                identity_failure_code=(
                    "PROCESS_IDENTITY_UNAVAILABLE"
                    if before_term_identity is None
                    else "PROCESS_IDENTITY_MISMATCH"
                ),
                deadline_error=None,
                pre_cont_sent=True,
            )

        term_sent, term_errno = self._send_group_signal(
            lease.process_group_id, signal.SIGTERM
        )
        cont_sent = True
        cont_errno: int | None = None
        post_cont_sent = False
        post_cont_errno: int | None = None
        identity_failure_after_term: str | None = None
        if term_sent:
            after_term_identity = self._read_identity(lease.pid)
            if after_term_identity is None:
                identity_failure_after_term = (
                    "PROCESS_IDENTITY_UNAVAILABLE_AFTER_TERM"
                )
            elif after_term_identity != _lease_identity(lease):
                return self._finish_cleanup_required(
                    record,
                    operation=deadline.operation,
                    phase="process-group-identity-check",
                    reason_code=checked_reason,
                    term_sent=True,
                    cont_sent=True,
                    term_errno=term_errno,
                    cont_errno=None,
                    observed_alive=self._observe_group_alive(record),
                    observed_identity=after_term_identity,
                    identity_failure_code=(
                        "PROCESS_IDENTITY_CHANGED_AFTER_TERM"
                    ),
                    deadline_error=None,
                    pre_cont_sent=True,
                )
            else:
                post_cont_sent, post_cont_errno = self._send_group_signal(
                    lease.process_group_id, signal.SIGCONT
                )
                if post_cont_sent:
                    cont_sent = True
                    cont_errno = None
                elif not cont_sent:
                    cont_errno = post_cont_errno

        observed_alive = self._observe_group_alive(record)
        if not observed_alive:
            return self._finish_terminated(
                record,
                term_sent=term_sent,
                cont_sent=cont_sent,
                term_errno=term_errno,
                cont_errno=cont_errno,
            )

        if wait_deadline is not None:
            while observed_alive:
                remaining_ns = wait_deadline.remaining_nanoseconds()
                if remaining_ns <= 0:
                    try:
                        wait_deadline.checkpoint()
                    except OperationDeadlineExceededV2 as error:
                        deadline_error = error
                    break
                sleep_seconds = min(
                    self._poll_interval_seconds,
                    remaining_ns / 1_000_000_000,
                )
                self._sleep(sleep_seconds)
                observed_alive = self._observe_group_alive(record)
            if not observed_alive:
                return self._finish_terminated(
                    record,
                    term_sent=term_sent,
                    cont_sent=cont_sent,
                    term_errno=term_errno,
                    cont_errno=cont_errno,
                )

        if deadline_error is None:
            raise ProcessGroupSupervisorV2Error(
                "cleanup wait ended without a deadline proof"
            )
        if identity_failure_after_term is not None:
            return self._finish_cleanup_required(
                record,
                operation=deadline.operation,
                phase="process-group-identity-check",
                reason_code=checked_reason,
                term_sent=term_sent,
                cont_sent=cont_sent,
                term_errno=term_errno,
                cont_errno=cont_errno,
                observed_alive=True,
                observed_identity=None,
                identity_failure_code=identity_failure_after_term,
                deadline_error=None,
                pre_cont_sent=True,
                post_cont_sent=post_cont_sent,
                post_cont_errno=post_cont_errno,
            )
        return self._finish_cleanup_required(
            record,
            operation=deadline_error.operation,
            phase=deadline_error.phase,
            reason_code=checked_reason,
            term_sent=term_sent,
            cont_sent=cont_sent,
            term_errno=term_errno,
            cont_errno=cont_errno,
            observed_alive=True,
            observed_identity=observed_identity,
            identity_failure_code=None,
            deadline_error=deadline_error,
            pre_cont_sent=True,
            post_cont_sent=post_cont_sent,
            post_cont_errno=post_cont_errno,
        )

    def _require_owned(
        self, lease: TransientProcessLeaseV2
    ) -> _OwnedTransientProcessV2:
        if not isinstance(lease, TransientProcessLeaseV2):
            raise TransientProcessOwnershipErrorV2(
                "lease has the wrong type"
            )
        record = self._owned.get(lease.lease_id)
        if record is None or record.lease is not lease:
            raise TransientProcessOwnershipErrorV2(
                "transient process is not owned by this supervisor"
            )
        return record

    def _read_identity(self, pid: int) -> ProcessIdentityV2 | None:
        try:
            identity = self._identity_reader(pid)
        except OSError:
            return None
        if identity is not None and not isinstance(identity, ProcessIdentityV2):
            raise ProcessGroupSupervisorV2Error(
                "identity_reader must return ProcessIdentityV2 or None"
            )
        return identity

    def _softly_terminate_unverified(self, launch_id: str) -> None:
        record = self._unverified[launch_id]
        try:
            record.process.terminate()
        except (AttributeError, OSError):
            pass
        try:
            return_code = record.process.poll()
        except (AttributeError, OSError):
            return_code = None
        if return_code is not None and not self._unverified_group_alive(record):
            _close_process_streams(record.process)
            del self._unverified[launch_id]

    def _unverified_group_alive(
        self,
        record: _UnverifiedTransientProcessV2,
    ) -> bool:
        if record.process_group_id is None:
            return False
        try:
            observed = self._group_exists(record.process_group_id)
        except OSError:
            return True
        if type(observed) is not bool:
            raise ProcessGroupSupervisorV2Error(
                "group_exists must return a bool"
            )
        return observed

    def _send_group_signal(
        self, process_group_id: int, signum: int
    ) -> tuple[bool, int | None]:
        try:
            self._killpg(process_group_id, signum)
        except OSError as error:
            error_number = error.errno if type(error.errno) is int else None
            return False, error_number
        return True, None

    def _observe_group_alive(self, record: _OwnedTransientProcessV2) -> bool:
        try:
            record.lease.process.poll()
        except OSError:
            pass
        try:
            observed = self._group_exists(record.lease.process_group_id)
        except OSError:
            return True
        if type(observed) is not bool:
            raise ProcessGroupSupervisorV2Error(
                "group_exists must return a bool"
            )
        return observed

    def _finish_cleanup_required(
        self,
        record: _OwnedTransientProcessV2,
        *,
        operation: str,
        phase: str,
        reason_code: str,
        term_sent: bool,
        cont_sent: bool,
        term_errno: int | None,
        cont_errno: int | None,
        observed_alive: bool,
        observed_identity: ProcessIdentityV2 | None,
        identity_failure_code: str | None,
        deadline_error: OperationDeadlineExceededV2 | None,
        pre_cont_sent: bool = False,
        pre_cont_errno: int | None = None,
        post_cont_sent: bool = False,
        post_cont_errno: int | None = None,
    ) -> ProcessGroupTerminationResultV2:
        lease = record.lease
        obligation = validate_cleanup_obligation_v2(
            {
                "schemaVersion": 2,
                "obligationType": "transient-process-group-cleanup-v2",
                "obligationId": lease.lease_id,
                "status": "pending",
                "operation": operation,
                "phase": phase,
                "processLabel": lease.label,
                "pid": lease.pid,
                "processGroupId": lease.process_group_id,
                "reasonCode": reason_code,
                "attempt": record.attempt,
                "termSent": term_sent,
                "contSent": cont_sent,
                "preContSent": pre_cont_sent,
                "postContSent": post_cont_sent,
                "termErrorErrno": term_errno,
                "contErrorErrno": cont_errno,
                "preContErrorErrno": pre_cont_errno,
                "postContErrorErrno": post_cont_errno,
                "observedAlive": observed_alive,
                "nextAction": "reconcile-identity-and-retry-term-cont",
                "automaticSignalAuthorized": False,
                "continuationAllowed": False,
                "expectedProcessIdentity": _identity_document(
                    _lease_identity(lease)
                ),
                "observedProcessIdentity": (
                    None
                    if observed_identity is None
                    else _identity_document(observed_identity)
                ),
                "identityFailureCode": identity_failure_code,
                "deadlineProof": (
                    None
                    if deadline_error is None
                    else deadline_proof_v2(deadline_error)
                ),
            }
        )
        record.cleanup_obligation = copy.deepcopy(obligation)
        self._transition_durable_ownership(
            record,
            outcome="cleanup-required",
            cleanup_obligation=obligation,
        )
        return ProcessGroupTerminationResultV2(
            lease_id=lease.lease_id,
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            state="cleanup-required",
            term_sent=term_sent,
            cont_sent=cont_sent,
            term_error_errno=term_errno,
            cont_error_errno=cont_errno,
            observed_group_alive=observed_alive,
            identity_failure_code=identity_failure_code,
            continuation_allowed=False,
            cleanup_obligation=obligation,
        )

    def _finish_terminated(
        self,
        record: _OwnedTransientProcessV2,
        *,
        term_sent: bool,
        cont_sent: bool,
        term_errno: int | None,
        cont_errno: int | None,
    ) -> ProcessGroupTerminationResultV2:
        lease = record.lease
        self._transition_durable_ownership(
            record,
            outcome="soft-terminated",
            cleanup_obligation=None,
        )
        _close_process_streams(record.lease.process)
        del self._owned[lease.lease_id]
        return ProcessGroupTerminationResultV2(
            lease_id=lease.lease_id,
            pid=lease.pid,
            process_group_id=lease.process_group_id,
            state="terminated",
            term_sent=term_sent,
            cont_sent=cont_sent,
            term_error_errno=term_errno,
            cont_error_errno=cont_errno,
            observed_group_alive=False,
            identity_failure_code=None,
            continuation_allowed=True,
            cleanup_obligation=None,
        )

    def _transition_durable_ownership(
        self,
        record: _OwnedTransientProcessV2,
        *,
        outcome: str,
        cleanup_obligation: Mapping[str, object] | None,
    ) -> None:
        if not record.ownership_published:
            return
        if self._ownership_transition is None:
            raise AssertionError(
                "published durable ownership has no transition callback"
            )
        try:
            self._ownership_transition(
                record.lease,
                record.ownership_context,
                outcome,
                cleanup_obligation,
            )
        except BaseException as error:
            record.ownership_callback_failed = True
            raise DurableProcessOwnershipCallbackErrorV2(
                lease_id=record.lease.lease_id,
                outcome=outcome,
                cleanup_obligation=cleanup_obligation,
            ) from error
        record.ownership_callback_failed = False


_CURRENT_PROCESS_GROUP_SUPERVISOR_V2: ContextVar[
    OperationProcessGroupSupervisorV2 | None
] = ContextVar("codex_smart_current_process_group_supervisor_v2", default=None)


@contextmanager
def scoped_current_process_group_supervisor_v2(
    supervisor: OperationProcessGroupSupervisorV2,
) -> Iterator[OperationProcessGroupSupervisorV2]:
    """Распространить ровно один надзор на всю текущую операцию."""

    if not isinstance(supervisor, OperationProcessGroupSupervisorV2):
        raise TypeError("supervisor must be OperationProcessGroupSupervisorV2")
    current = _CURRENT_PROCESS_GROUP_SUPERVISOR_V2.get()
    if current is not None and current is not supervisor:
        raise CurrentProcessGroupSupervisorConflictV2(
            "nested scope must reuse the current process group supervisor"
        )
    token = _CURRENT_PROCESS_GROUP_SUPERVISOR_V2.set(supervisor)
    try:
        yield supervisor
    finally:
        _CURRENT_PROCESS_GROUP_SUPERVISOR_V2.reset(token)


def current_process_group_supervisor_v2(
) -> OperationProcessGroupSupervisorV2 | None:
    """Вернуть текущий надзор без неявного создания запасного объекта."""

    return _CURRENT_PROCESS_GROUP_SUPERVISOR_V2.get()


def validate_cleanup_obligation_v2(
    document: Mapping[str, object],
) -> dict[str, object]:
    """Проверить закрытый долговечный документ обязанности очистки."""

    if type(document) is not dict:
        raise CleanupObligationValidationErrorV2(
            "cleanup obligation must be a plain object"
        )
    if set(document) != _CLEANUP_OBLIGATION_KEYS:
        raise CleanupObligationValidationErrorV2(
            "cleanup obligation fields must match the closed contract"
        )
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 2:
        raise CleanupObligationValidationErrorV2(
            "schemaVersion must be integer 2"
        )
    if document["obligationType"] != "transient-process-group-cleanup-v2":
        raise CleanupObligationValidationErrorV2(
            "obligationType has an unsupported value"
        )
    if document["status"] != "pending":
        raise CleanupObligationValidationErrorV2("status must be pending")
    for key in (
        "obligationId",
        "operation",
        "phase",
        "processLabel",
        "reasonCode",
    ):
        if type(document[key]) is not str or not document[key]:
            raise CleanupObligationValidationErrorV2(
                f"{key} must be a non-empty string"
            )
    for key in ("pid", "processGroupId", "attempt"):
        if type(document[key]) is not int or document[key] <= 0:
            raise CleanupObligationValidationErrorV2(
                f"{key} must be a positive integer"
            )
    if document["pid"] != document["processGroupId"]:
        raise CleanupObligationValidationErrorV2(
            "pid and processGroupId must identify the new-session leader"
        )
    for key in (
        "termSent",
        "contSent",
        "preContSent",
        "postContSent",
        "observedAlive",
    ):
        if type(document[key]) is not bool:
            raise CleanupObligationValidationErrorV2(
                f"{key} must be a bool"
            )
    for key in (
        "termErrorErrno",
        "contErrorErrno",
        "preContErrorErrno",
        "postContErrorErrno",
    ):
        value = document[key]
        if value is not None and (type(value) is not int or value <= 0):
            raise CleanupObligationValidationErrorV2(
                f"{key} must be null or a positive integer"
            )
    if document["termSent"] is True and document["termErrorErrno"] is not None:
        raise CleanupObligationValidationErrorV2(
            "termErrorErrno must be null when TERM was sent"
        )
    if document["preContSent"] is True and (
        document["preContErrorErrno"] is not None
    ):
        raise CleanupObligationValidationErrorV2(
            "preContErrorErrno must be null when pre-CONT was sent"
        )
    if document["postContSent"] is True and (
        document["termSent"] is not True
        or document["postContErrorErrno"] is not None
    ):
        raise CleanupObligationValidationErrorV2(
            "post-CONT requires a successful TERM and no post-CONT error"
        )
    if document["termSent"] is True and document["preContSent"] is not True:
        raise CleanupObligationValidationErrorV2(
            "TERM requires a successful pre-CONT"
        )
    expected_cont_sent = bool(
        document["preContSent"] or document["postContSent"]
    )
    expected_cont_errno = (
        None
        if expected_cont_sent
        else (
            document["postContErrorErrno"]
            if document["postContErrorErrno"] is not None
            else document["preContErrorErrno"]
        )
    )
    if (
        document["contSent"] is not expected_cont_sent
        or document["contErrorErrno"] != expected_cont_errno
    ):
        raise CleanupObligationValidationErrorV2(
            "aggregate CONT outcome must match pre/post CONT outcomes"
        )
    next_action = document["nextAction"]
    retry_action = "reconcile-identity-and-retry-term-cont"
    observe_only_action = "reconcile-identity-without-repeat-signals"
    if next_action not in {retry_action, observe_only_action}:
        raise CleanupObligationValidationErrorV2(
            "nextAction has an unsupported value"
        )
    signal_sequence_sent = bool(
        document["preContSent"]
        and document["termSent"]
        and document["postContSent"]
    )
    if next_action == observe_only_action and not signal_sequence_sent:
        raise CleanupObligationValidationErrorV2(
            "observe-only reconciliation requires the complete signal sequence"
        )
    if next_action == observe_only_action and (
        document["operation"] != "recover"
        or document["phase"] != "durable-process-ownership"
    ):
        raise CleanupObligationValidationErrorV2(
            "observe-only reconciliation belongs to durable recovery"
        )
    if document["automaticSignalAuthorized"] is not False:
        raise CleanupObligationValidationErrorV2(
            "automaticSignalAuthorized must be false"
        )
    if document["continuationAllowed"] is not False:
        raise CleanupObligationValidationErrorV2(
            "continuationAllowed must be false"
        )
    expected_identity = _validate_identity_document(
        document["expectedProcessIdentity"], "expectedProcessIdentity"
    )
    if (
        expected_identity["pid"] != document["pid"]
        or expected_identity["processGroupId"]
        != document["processGroupId"]
        or expected_identity["sessionId"] != document["pid"]
    ):
        raise CleanupObligationValidationErrorV2(
            "expectedProcessIdentity must match the obligation leader"
        )
    observed_document = document["observedProcessIdentity"]
    checked_observed_identity = (
        None
        if observed_document is None
        else _validate_identity_document(
            observed_document, "observedProcessIdentity"
        )
    )
    identity_failure_code = document["identityFailureCode"]
    if identity_failure_code is not None and (
        type(identity_failure_code) is not str or not identity_failure_code
    ):
        raise CleanupObligationValidationErrorV2(
            "identityFailureCode must be null or a non-empty string"
        )
    unavailable_codes = {
        "PROCESS_IDENTITY_UNAVAILABLE",
        "PROCESS_IDENTITY_UNAVAILABLE_AFTER_TERM",
    }
    mismatch_codes = {
        "PROCESS_IDENTITY_MISMATCH",
        "PROCESS_IDENTITY_CHANGED_AFTER_TERM",
    }
    present_after_exit_codes = {"PROCESS_IDENTITY_PRESENT_AFTER_EXIT"}
    if identity_failure_code is None and (
        checked_observed_identity != expected_identity
    ):
        raise CleanupObligationValidationErrorV2(
            "a timeout obligation requires the exact expected identity"
        )
    if identity_failure_code in unavailable_codes and (
        checked_observed_identity is not None
    ):
        raise CleanupObligationValidationErrorV2(
            "an unavailable identity must not include an observation"
        )
    if identity_failure_code in mismatch_codes and (
        checked_observed_identity is None
        or checked_observed_identity == expected_identity
    ):
        raise CleanupObligationValidationErrorV2(
            "an identity mismatch requires a different observation"
        )
    if identity_failure_code in present_after_exit_codes and (
        checked_observed_identity != expected_identity
    ):
        raise CleanupObligationValidationErrorV2(
            "an identity-present-after-exit failure requires the exact identity"
        )
    if identity_failure_code is not None and identity_failure_code not in (
        unavailable_codes | mismatch_codes | present_after_exit_codes
    ):
        raise CleanupObligationValidationErrorV2(
            "identityFailureCode has an unsupported value"
        )
    proof = document["deadlineProof"]
    signal_checkpoint_reason = (
        "DURABLE_PROCESS_OWNERSHIP_SIGNAL_SEQUENCE_SENT"
    )
    is_signal_checkpoint = bool(
        document["reasonCode"] == signal_checkpoint_reason
        and next_action == observe_only_action
        and signal_sequence_sent
        and checked_observed_identity == expected_identity
        and document["observedAlive"] is True
        and identity_failure_code is None
        and proof is None
    )
    if document["reasonCode"] == signal_checkpoint_reason and not (
        is_signal_checkpoint
    ):
        raise CleanupObligationValidationErrorV2(
            "signal-sequence checkpoint must be exact and failure-free"
        )
    if proof is None:
        has_signal_failure = any(
            document[key] is not None
            for key in (
                "termErrorErrno",
                "preContErrorErrno",
                "postContErrorErrno",
            )
        )
        if (
            identity_failure_code is None
            and not has_signal_failure
            and not is_signal_checkpoint
        ):
            raise CleanupObligationValidationErrorV2(
                "an identity, signal, or deadline failure is required"
            )
        checked_proof = None
    else:
        try:
            checked_proof = validate_deadline_proof_v2(
                proof  # type: ignore[arg-type]
            )
        except (TypeError, ValueError) as error:
            raise CleanupObligationValidationErrorV2(
                "deadlineProof is invalid"
            ) from error
        if (
            checked_proof["operation"] != document["operation"]
            or checked_proof["phase"] != document["phase"]
        ):
            raise CleanupObligationValidationErrorV2(
                "deadlineProof operation and phase must match the obligation"
            )
        if identity_failure_code is not None:
            raise CleanupObligationValidationErrorV2(
                "identityFailureCode and deadlineProof are mutually exclusive"
            )
    result = copy.deepcopy(dict(document))
    result["expectedProcessIdentity"] = expected_identity
    result["observedProcessIdentity"] = checked_observed_identity
    result["deadlineProof"] = checked_proof
    return result


_IDENTITY_DOCUMENT_KEYS = frozenset(
    {"pid", "processGroupId", "sessionId", "startMarker"}
)


def _lease_identity(lease: TransientProcessLeaseV2) -> ProcessIdentityV2:
    return ProcessIdentityV2(
        pid=lease.pid,
        process_group_id=lease.process_group_id,
        session_id=lease.session_id,
        start_marker=lease.process_start_marker,
    )


def _identity_document(identity: ProcessIdentityV2) -> dict[str, object]:
    return {
        "pid": identity.pid,
        "processGroupId": identity.process_group_id,
        "sessionId": identity.session_id,
        "startMarker": identity.start_marker,
    }


def _validate_identity_document(
    value: object, name: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != _IDENTITY_DOCUMENT_KEYS:
        raise CleanupObligationValidationErrorV2(
            f"{name} must match the closed process identity contract"
        )
    for key in ("pid", "processGroupId", "sessionId"):
        if type(value[key]) is not int or value[key] <= 0:
            raise CleanupObligationValidationErrorV2(
                f"{name}.{key} must be a positive integer"
            )
    if type(value["startMarker"]) is not str or not value["startMarker"]:
        raise CleanupObligationValidationErrorV2(
            f"{name}.startMarker must be a non-empty string"
        )
    return copy.deepcopy(value)


def _is_new_session_identity(
    identity: ProcessIdentityV2 | None, expected_pid: int
) -> bool:
    return (
        identity is not None
        and identity.pid == expected_pid
        and identity.process_group_id == expected_pid
        and identity.session_id == expected_pid
    )


def _default_process_identity_v2(pid: int) -> ProcessIdentityV2 | None:
    """Снять согласованный системный маркер без доверия к одному только PID."""

    if type(pid) is not int or pid <= 0:
        return None
    try:
        first_pgid = os.getpgid(pid)
        first_session = os.getsid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        return None
    try:
        start_marker = system_process_start_marker_v2(pid)
    except ChildGuardV2Error:
        return None
    try:
        second_pgid = os.getpgid(pid)
        second_session = os.getsid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        return None
    if (first_pgid, first_session) != (second_pgid, second_session):
        return None
    return ProcessIdentityV2(
        pid=pid,
        process_group_id=second_pgid,
        session_id=second_session,
        start_marker=start_marker,
    )


def _close_process_streams(process: Any) -> None:
    """Закрыть каналы процесса, который уже нельзя вернуть вызывающей стороне."""

    for name in ("stdin", "stdout", "stderr"):
        stream = getattr(process, name, None)
        if stream is None:
            continue
        try:
            if stream.closed:
                continue
        except (AttributeError, OSError, ValueError):
            pass
        descriptor: int | None = None
        try:
            candidate = stream.fileno()
            if type(candidate) is int and candidate >= 0:
                descriptor = candidate
        except (AttributeError, OSError, ValueError):
            pass
        try:
            stream.close()
        except (BrokenPipeError, OSError, ValueError):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _default_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        return True
    return True


def _checked_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        raise TypeError("argv must be a sequence of strings")
    result = tuple(argv)
    if not result:
        raise ValueError("argv must not be empty")
    if any(type(item) is not str or not item or "\0" in item for item in result):
        raise ValueError("argv items must be non-empty strings without NUL")
    return result


def _checked_pass_fds(pass_fds: Sequence[int]) -> tuple[int, ...]:
    if isinstance(pass_fds, (str, bytes)) or not isinstance(
        pass_fds, Sequence
    ):
        raise TypeError("pass_fds must be a sequence of integers")
    result = tuple(pass_fds)
    if any(type(item) is not int or item < 0 for item in result):
        raise ValueError("pass_fds items must be non-negative integers")
    if len(set(result)) != len(result):
        raise ValueError("pass_fds items must be unique")
    return result


def _checked_ownership_context(
    value: Mapping[str, object] | None,
    *,
    label: str,
) -> Mapping[str, object]:
    if value is None:
        document: dict[str, object] = {
            "schemaVersion": 2,
            "contextKind": "installer-transient-v2",
            "processLabel": label,
        }
    else:
        if type(value) is not dict:
            raise TypeError("ownership_context must be a plain mapping or null")
        document = copy.deepcopy(dict(value))
    if not document or len(document) > 32:
        raise ValueError("ownership_context has an invalid field count")
    for key, item in document.items():
        if type(key) is not str or not key or len(key) > 128 or "\0" in key:
            raise ValueError("ownership_context keys must be bounded strings")
        if type(item) is str:
            if not item or len(item.encode("utf-8")) > 4096 or "\0" in item:
                raise ValueError(
                    "ownership_context strings must be non-empty and bounded"
                )
        elif type(item) is int:
            if item < 0:
                raise ValueError(
                    "ownership_context integers must be non-negative"
                )
        else:
            raise TypeError(
                "ownership_context values must be strings or integers"
            )
    return MappingProxyType(document)


def _required_string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


__all__ = [
    "CleanupObligationValidationErrorV2",
    "CurrentProcessGroupSupervisorConflictV2",
    "CurrentProcessGroupSupervisorUnavailableV2",
    "DurableProcessOwnershipCallbackErrorV2",
    "OperationProcessGroupSupervisorV2",
    "OutstandingProcessCleanupObligationV2",
    "ProcessIdentityV2",
    "ProcessGroupSupervisorV2Error",
    "ProcessGroupTerminationResultV2",
    "TransientProcessLeaseV2",
    "TransientProcessIdentityErrorV2",
    "TransientProcessOwnershipErrorV2",
    "current_process_group_supervisor_v2",
    "scoped_current_process_group_supervisor_v2",
    "validate_cleanup_obligation_v2",
]
