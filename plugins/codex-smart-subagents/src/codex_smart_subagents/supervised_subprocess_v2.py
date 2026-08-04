"""Конечный запуск коротких команд под единым сроком операции версии 2."""

from __future__ import annotations

import os
import select
import selectors
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .operation_deadline_v2 import (
    CurrentOperationDeadlineConflictV2,
    CurrentOperationDeadlineUnavailableV2,
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    current_operation_deadline_v2,
)
from .operation_process_group_supervisor_v2 import (
    CurrentProcessGroupSupervisorConflictV2,
    CurrentProcessGroupSupervisorUnavailableV2,
    OperationProcessGroupSupervisorV2,
    ProcessGroupTerminationResultV2,
    TransientProcessLeaseV2,
    current_process_group_supervisor_v2,
)


_BOOTSTRAP_SOURCE = """
import os
import sys

ready_fd = int(sys.argv[1])
gate_fd = int(sys.argv[2])
target = sys.argv[3:]
try:
    try:
        os.write(ready_fd, b"R")
    except BrokenPipeError:
        raise SystemExit(125)
finally:
    os.close(ready_fd)
try:
    token = os.read(gate_fd, 1)
finally:
    os.close(gate_fd)
if token != b"G":
    raise SystemExit(125)
os.execvpe(target[0], target, os.environ)
""".strip()


class SupervisedCommandV2Error(RuntimeError):
    """Базовая ошибка конечного запуска команды."""


class SupervisedCommandBootstrapErrorV2(SupervisedCommandV2Error):
    """Защитная обёртка не подтвердила готовность к точному запуску."""


class SupervisedCommandOutputLimitExceededV2(SupervisedCommandV2Error):
    """Совокупный вывод команды превысил заданную границу."""

    def __init__(self, *, stdout: bytes, stderr: bytes, maximum: int) -> None:
        super().__init__(
            f"SUPERVISED_COMMAND_OUTPUT_LIMIT_EXCEEDED: limit is {maximum} bytes"
        )
        self.stdout = bytes(stdout)
        self.stderr = bytes(stderr)
        self.maximum = maximum


class SupervisedCommandCleanupRequiredV2(SupervisedCommandV2Error):
    """Мягкое завершение не доказало исчезновение точной группы."""

    def __init__(
        self,
        *,
        cleanup_obligation: Mapping[str, object],
        supervisor: OperationProcessGroupSupervisorV2,
    ) -> None:
        obligation = dict(cleanup_obligation)
        super().__init__(
            "SUPERVISED_COMMAND_CLEANUP_REQUIRED: "
            + str(obligation.get("obligationId", "unknown"))
        )
        self.cleanup_obligation = obligation
        self.supervisor = supervisor


@dataclass(frozen=True, slots=True)
class SupervisedCommandResultV2:
    """Ограниченный результат доказанно завершившейся группы."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if not self.argv or any(type(item) is not str for item in self.argv):
            raise ValueError("argv must be a non-empty tuple of strings")
        if type(self.returncode) is not int:
            raise ValueError("returncode must be an integer")
        if not isinstance(self.stdout, bytes) or not isinstance(
            self.stderr, bytes
        ):
            raise ValueError("stdout and stderr must be bytes")


def spawn_gated_transient_v2(
    *,
    argv: Sequence[str],
    label: str,
    gate_deadline: OperationDeadlineV2,
    cleanup_deadline: OperationDeadlineV2,
    cleanup_wait_seconds: object,
    supervisor: OperationProcessGroupSupervisorV2,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    stdin: object = None,
    stdout: object = None,
    stderr: object = None,
    text: bool = False,
    encoding: str | None = None,
    errors: str | None = None,
    ownership_context: Mapping[str, object] | None = None,
) -> TransientProcessLeaseV2:
    """Открыть целевой запуск лишь после публикации владения процессом."""

    checked_argv = _checked_argv(argv)
    checked_label = _required_string(label, "label")
    if not isinstance(gate_deadline, OperationDeadlineV2):
        raise TypeError("gate_deadline must be OperationDeadlineV2")
    if not isinstance(cleanup_deadline, OperationDeadlineV2):
        raise TypeError("cleanup_deadline must be OperationDeadlineV2")
    owner = _resolve_supervisor(supervisor)
    owner.assert_continuation_allowed()

    ready_read, ready_write = os.pipe()
    gate_read, gate_write = os.pipe()
    lease: TransientProcessLeaseV2 | None = None
    try:
        lease = owner.spawn_transient(
            label=checked_label,
            argv=(
                sys.executable,
                "-c",
                _BOOTSTRAP_SOURCE,
                str(ready_write),
                str(gate_read),
                *checked_argv,
            ),
            cwd=cwd,
            env=env,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            pass_fds=(ready_write, gate_read),
            text=text,
            encoding=encoding,
            errors=errors,
            ownership_context=ownership_context,
        )
    except BaseException:
        _close_descriptor(ready_read)
        _close_descriptor(ready_write)
        _close_descriptor(gate_read)
        _close_descriptor(gate_write)
        raise
    else:
        os.close(ready_write)
        os.close(gate_read)

    assert lease is not None
    try:
        _await_bootstrap_ready(
            lease=lease,
            ready_descriptor=ready_read,
            deadline=gate_deadline,
        )
        os.write(gate_write, b"G")
    except BaseException as error:
        _close_descriptor(ready_read)
        _close_descriptor(gate_write)
        _terminate_after_failure(
            owner=owner,
            lease=lease,
            deadline=cleanup_deadline,
            cleanup_wait_seconds=cleanup_wait_seconds,
            reason_code="SUPERVISED_COMMAND_BOOTSTRAP_FAILED",
            error=error,
        )
        raise AssertionError("unreachable")
    finally:
        _close_descriptor(ready_read)
        _close_descriptor(gate_write)
    return lease


def run_supervised_command_v2(
    *,
    argv: Sequence[str],
    label: str,
    local_timeout_seconds: object,
    cleanup_wait_seconds: object,
    stdin: bytes = b"",
    max_output_bytes: int = 1024 * 1024,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    deadline: OperationDeadlineV2 | None = None,
    supervisor: OperationProcessGroupSupervisorV2 | None = None,
) -> SupervisedCommandResultV2:
    """Выполнить одну команду без оболочки и без скрытого жёсткого завершения."""

    checked_argv = _checked_argv(argv)
    checked_label = _required_string(label, "label")
    if not isinstance(stdin, bytes):
        raise TypeError("stdin must be bytes")
    if (
        type(max_output_bytes) is not int
        or max_output_bytes <= 0
        or max_output_bytes > 16 * 1024 * 1024
    ):
        raise ValueError("max_output_bytes is outside the supported range")
    root_deadline = _resolve_deadline(deadline)
    execution_deadline = root_deadline.child(
        phase=f"supervised-command:{checked_label}",
        max_seconds=local_timeout_seconds,
        timeout_code="SUPERVISED_COMMAND_DEADLINE_EXCEEDED",
    )
    owner = _resolve_supervisor(supervisor)
    owner.assert_continuation_allowed()

    lease = spawn_gated_transient_v2(
        argv=checked_argv,
        label=checked_label,
        gate_deadline=execution_deadline,
        cleanup_deadline=root_deadline,
        cleanup_wait_seconds=cleanup_wait_seconds,
        supervisor=owner,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        stdout, stderr = _collect_bounded_output(
            lease=lease,
            stdin=stdin,
            deadline=execution_deadline,
            maximum=max_output_bytes,
        )
    except BaseException as error:
        reason_code = (
            "SUPERVISED_COMMAND_OUTPUT_LIMIT_EXCEEDED"
            if isinstance(error, SupervisedCommandOutputLimitExceededV2)
            else "SUPERVISED_COMMAND_DEADLINE_EXCEEDED"
        )
        _terminate_after_failure(
            owner=owner,
            lease=lease,
            deadline=root_deadline,
            cleanup_wait_seconds=cleanup_wait_seconds,
            reason_code=reason_code,
            error=error,
        )
        raise AssertionError("unreachable")

    released = owner.release_after_verified_exit(
        lease,
        deadline=root_deadline,
        reason_code="SUPERVISED_COMMAND_GROUP_REMAINS_AFTER_EXIT",
    )
    if isinstance(released, ProcessGroupTerminationResultV2):
        assert released.cleanup_obligation is not None
        raise SupervisedCommandCleanupRequiredV2(
            cleanup_obligation=released.cleanup_obligation,
            supervisor=owner,
        )
    process = released
    return_code = process.returncode
    if type(return_code) is not int:
        raise SupervisedCommandV2Error(
            "SUPERVISED_COMMAND_RETURN_CODE_UNAVAILABLE"
        )
    return SupervisedCommandResultV2(
        argv=checked_argv,
        returncode=return_code,
        stdout=stdout,
        stderr=stderr,
    )


def _await_bootstrap_ready(
    *,
    lease: TransientProcessLeaseV2,
    ready_descriptor: int,
    deadline: OperationDeadlineV2,
) -> None:
    while True:
        deadline.checkpoint()
        timeout = min(0.05, deadline.remaining_seconds())
        readable, _, _ = select.select((ready_descriptor,), (), (), timeout)
        if readable:
            token = os.read(ready_descriptor, 1)
            if token == b"R":
                return
            raise SupervisedCommandBootstrapErrorV2(
                "SUPERVISED_COMMAND_BOOTSTRAP_INVALID"
            )
        if lease.process.poll() is not None:
            raise SupervisedCommandBootstrapErrorV2(
                "SUPERVISED_COMMAND_BOOTSTRAP_EXITED"
            )


def _collect_bounded_output(
    *,
    lease: TransientProcessLeaseV2,
    stdin: bytes,
    deadline: OperationDeadlineV2,
    maximum: int,
) -> tuple[bytes, bytes]:
    process = lease.process
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise SupervisedCommandV2Error(
            "SUPERVISED_COMMAND_PIPES_UNAVAILABLE"
        )
    selector = selectors.DefaultSelector()
    stdin_fd = process.stdin.fileno()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    outputs = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    total_received = 0
    stdin_offset = 0
    try:
        for descriptor in outputs:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        os.set_blocking(stdin_fd, False)
        if stdin:
            selector.register(stdin_fd, selectors.EVENT_WRITE)
        else:
            process.stdin.close()

        while selector.get_map() or process.poll() is None:
            deadline.checkpoint()
            timeout = min(0.05, deadline.remaining_seconds())
            try:
                events = selector.select(timeout=timeout)
            except InterruptedError:
                continue
            for key, _ in events:
                descriptor = int(key.fd)
                if descriptor == stdin_fd:
                    try:
                        written = os.write(
                            stdin_fd, stdin[stdin_offset : stdin_offset + 65536]
                        )
                    except (BlockingIOError, InterruptedError):
                        continue
                    except (BrokenPipeError, OSError):
                        _close_stdin(selector, process, stdin_fd)
                        continue
                    stdin_offset += written
                    if stdin_offset == len(stdin):
                        _close_stdin(selector, process, stdin_fd)
                    continue
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                remaining = max(0, maximum - total_received)
                outputs[descriptor].extend(chunk[:remaining])
                total_received += len(chunk)
                if total_received > maximum:
                    raise SupervisedCommandOutputLimitExceededV2(
                        stdout=bytes(outputs[stdout_fd]),
                        stderr=bytes(outputs[stderr_fd]),
                        maximum=maximum,
                    )
            if process.poll() is not None and stdin_fd in selector.get_map():
                _close_stdin(selector, process, stdin_fd)
            if process.poll() is not None and not selector.get_map():
                break
        if process.poll() is None:
            raise SupervisedCommandV2Error(
                "SUPERVISED_COMMAND_EXIT_UNOBSERVED"
            )
        return bytes(outputs[stdout_fd]), bytes(outputs[stderr_fd])
    finally:
        selector.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        if process.stderr is not None and not process.stderr.closed:
            process.stderr.close()


def _terminate_after_failure(
    *,
    owner: OperationProcessGroupSupervisorV2,
    lease: TransientProcessLeaseV2,
    deadline: OperationDeadlineV2,
    cleanup_wait_seconds: object,
    reason_code: str,
    error: BaseException,
) -> None:
    result = owner.terminate_transient(
        lease,
        deadline=deadline,
        max_wait_seconds=cleanup_wait_seconds,
        reason_code=reason_code,
    )
    if not result.continuation_allowed:
        assert result.cleanup_obligation is not None
        raise SupervisedCommandCleanupRequiredV2(
            cleanup_obligation=result.cleanup_obligation,
            supervisor=owner,
        ) from error
    raise error


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


def _resolve_deadline(
    explicit: OperationDeadlineV2 | None,
) -> OperationDeadlineV2:
    current = current_operation_deadline_v2()
    if explicit is None:
        if current is None:
            raise CurrentOperationDeadlineUnavailableV2(
                "no current operation deadline is scoped"
            )
        return current
    if not isinstance(explicit, OperationDeadlineV2):
        raise TypeError("deadline must be OperationDeadlineV2 or None")
    if current is not None and current is not explicit:
        raise CurrentOperationDeadlineConflictV2(
            "explicit deadline must reuse the current operation deadline"
        )
    return explicit


def _resolve_supervisor(
    explicit: OperationProcessGroupSupervisorV2 | None,
) -> OperationProcessGroupSupervisorV2:
    current = current_process_group_supervisor_v2()
    if explicit is None:
        if current is None:
            raise CurrentProcessGroupSupervisorUnavailableV2(
                "no current process group supervisor is scoped"
            )
        return current
    if not isinstance(explicit, OperationProcessGroupSupervisorV2):
        raise TypeError(
            "supervisor must be OperationProcessGroupSupervisorV2 or None"
        )
    if current is not None and current is not explicit:
        raise CurrentProcessGroupSupervisorConflictV2(
            "explicit supervisor must reuse the current operation supervisor"
        )
    return explicit


def _checked_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        raise TypeError("argv must be a sequence of strings")
    checked = tuple(argv)
    if not checked:
        raise ValueError("argv must not be empty")
    if any(type(item) is not str or not item or "\0" in item for item in checked):
        raise ValueError("argv items must be non-empty strings without NUL")
    return checked


def _required_string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


__all__ = [
    "SupervisedCommandBootstrapErrorV2",
    "SupervisedCommandCleanupRequiredV2",
    "SupervisedCommandOutputLimitExceededV2",
    "SupervisedCommandResultV2",
    "SupervisedCommandV2Error",
    "run_supervised_command_v2",
    "spawn_gated_transient_v2",
]
