"""Конечное ожидание файловой блокировки для переходов версии 2."""

from __future__ import annotations

import errno
import fcntl
import math
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable, Iterator

from . import operation_deadline_v2


INSTALLATION_LOCK_TIMEOUT_SECONDS = 30.0
LOCAL_FILE_LOCK_TIMEOUT_SECONDS = 30.0
MUTATING_LOCK_BUDGET_SECONDS = 600.0
RECOVERY_LOCK_BUDGET_SECONDS = 120.0
DEFAULT_LOCK_POLL_INTERVAL_SECONDS = 0.05


@dataclass
class FileLockTimeoutV2(TimeoutError):
    """Ожидаемая занятость блокировки дольше закреплённого срока."""

    code: str
    timeout_seconds: float

    def __str__(self) -> str:
        return (
            f"{self.code}: file lock remained busy for "
            f"{self.timeout_seconds:g} seconds"
        )


@dataclass(frozen=True)
class _AbsoluteLockBudgetV2:
    deadline: float
    timeout_code: str
    timeout_seconds: float


_LOCK_BUDGET_V2: ContextVar[_AbsoluteLockBudgetV2 | None] = ContextVar(
    "codex_smart_subagents_lock_budget_v2",
    default=None,
)


@contextmanager
def lock_budget_v2(
    *,
    timeout_seconds: float,
    timeout_code: str,
    monotonic: Callable[[], float] = time.monotonic,
) -> Iterator[None]:
    """Установить один абсолютный срок для всех вложенных ожиданий lock."""

    timeout = _positive_finite(timeout_seconds, "timeout_seconds")
    if type(timeout_code) is not str or not timeout_code:
        raise ValueError("timeout_code must be a non-empty string")
    if not callable(monotonic):
        raise TypeError("monotonic must be callable")
    started_at = float(monotonic())
    if not math.isfinite(started_at):
        raise ValueError("monotonic clock returned a non-finite value")
    requested = _AbsoluteLockBudgetV2(
        deadline=started_at + timeout,
        timeout_code=timeout_code,
        timeout_seconds=timeout,
    )
    inherited = _LOCK_BUDGET_V2.get()
    effective = (
        inherited
        if inherited is not None and inherited.deadline <= requested.deadline
        else requested
    )
    token = _LOCK_BUDGET_V2.set(effective)
    try:
        yield
    finally:
        _LOCK_BUDGET_V2.reset(token)


def acquire_flock_v2(
    descriptor: int,
    *,
    exclusive: bool,
    timeout_seconds: float,
    timeout_code: str,
    poll_interval_seconds: float = DEFAULT_LOCK_POLL_INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    flock: Callable[[int, int], None] = fcntl.flock,
) -> None:
    """Получить ``flock`` опросом ``LOCK_NB`` без продления срока."""

    if type(descriptor) is not int or descriptor < 0:
        raise ValueError("descriptor must be a non-negative integer")
    if type(exclusive) is not bool:
        raise TypeError("exclusive must be a bool")
    timeout = _positive_finite(timeout_seconds, "timeout_seconds")
    interval = _positive_finite(
        poll_interval_seconds, "poll_interval_seconds"
    )
    if type(timeout_code) is not str or not timeout_code:
        raise ValueError("timeout_code must be a non-empty string")
    if not callable(monotonic) or not callable(sleep) or not callable(flock):
        raise TypeError("clock, sleep and flock must be callable")

    operation_deadline = (
        operation_deadline_v2.current_operation_deadline_v2()
    )
    if operation_deadline is not None:
        operation_deadline.checkpoint()

    started_at = float(monotonic())
    if not math.isfinite(started_at):
        raise ValueError("monotonic clock returned a non-finite value")
    deadline = started_at + timeout
    effective_timeout_code = timeout_code
    effective_timeout_seconds = timeout
    budget = _LOCK_BUDGET_V2.get()
    if budget is not None and budget.deadline < deadline:
        deadline = budget.deadline
        effective_timeout_code = budget.timeout_code
        effective_timeout_seconds = budget.timeout_seconds
    operation = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
    busy_errors = {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}
    first_attempt = True

    while True:
        if operation_deadline is not None:
            operation_deadline.checkpoint()
        if first_attempt and started_at >= deadline:
            raise FileLockTimeoutV2(
                effective_timeout_code, effective_timeout_seconds
            ) from None
        if not first_attempt:
            observed_at = float(monotonic())
            if not math.isfinite(observed_at):
                raise ValueError("monotonic clock returned a non-finite value")
            if observed_at >= deadline:
                raise FileLockTimeoutV2(
                    effective_timeout_code, effective_timeout_seconds
                ) from None
        first_attempt = False
        try:
            flock(descriptor, operation)
            return
        except OSError as error:
            if error.errno not in busy_errors:
                raise

        if operation_deadline is not None:
            operation_deadline.checkpoint()
        observed_at = float(monotonic())
        if not math.isfinite(observed_at):
            raise ValueError("monotonic clock returned a non-finite value")
        remaining = deadline - observed_at
        if remaining <= 0:
            raise FileLockTimeoutV2(
                effective_timeout_code, effective_timeout_seconds
            ) from None
        sleep_seconds = min(interval, remaining)
        if operation_deadline is not None:
            operation_deadline.checkpoint()
            sleep_seconds = min(
                sleep_seconds,
                operation_deadline.remaining_seconds(),
            )
        sleep(sleep_seconds)


def _positive_finite(value: object, name: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError(f"{name} must be a positive finite number")
    return float(value)
