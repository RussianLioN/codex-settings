"""Единый непродлеваемый срок операции версии 2.

Модуль хранит абсолютные показания монотонных часов только в памяти. Наружу
выдаётся закрытое доказательство с длительностями, но без значений часов,
которые бессмысленны после перезапуска процесса.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR
from typing import Callable, Iterator, Mapping


NANOSECONDS_PER_SECOND = 1_000_000_000
_DEADLINE_PROOF_KEYS = frozenset(
    {
        "schemaVersion",
        "proofType",
        "operation",
        "phase",
        "timeoutCode",
        "deadlineKind",
        "configuredTimeoutNanoseconds",
        "elapsedMonotonicNanoseconds",
        "deadlineExceeded",
    }
)


class DeadlineProofValidationErrorV2(ValueError):
    """Документ доказательства срока не соответствует закрытому контракту."""


class CurrentOperationDeadlineUnavailableV2(RuntimeError):
    """Низкоуровневая проверка вызвана вне области общего срока."""


class CurrentOperationDeadlineConflictV2(RuntimeError):
    """Вложенная область попыталась заменить единый объект срока."""


class OperationDeadlineExceededV2(TimeoutError):
    """Общий либо локальный срок операции исчерпан."""

    def __init__(
        self,
        *,
        code: str,
        operation: str,
        phase: str,
        deadline_kind: str,
        configured_timeout_nanoseconds: int,
        elapsed_monotonic_nanoseconds: int,
    ) -> None:
        super().__init__(
            f"{code}: {deadline_kind} deadline exceeded during "
            f"{operation}/{phase} after {elapsed_monotonic_nanoseconds} ns"
        )
        self.code = code
        self.operation = operation
        self.phase = phase
        self.deadline_kind = deadline_kind
        self.configured_timeout_nanoseconds = configured_timeout_nanoseconds
        self.elapsed_monotonic_nanoseconds = elapsed_monotonic_nanoseconds


@dataclass(frozen=True, slots=True)
class OperationDeadlineV2:
    """Неизменяемый контекст общего срока и вложенного этапа.

    Вложенный контекст выбирает более ранний из своего локального предела и
    уже действующего предела родителя. При равенстве родитель имеет приоритет,
    поэтому локальный этап не может подменить код общего срока.
    """

    operation: str
    phase: str
    _root_started_monotonic_ns: int
    _operation_deadline_monotonic_ns: int
    _effective_deadline_monotonic_ns: int
    _effective_timeout_code: str
    _effective_configured_timeout_ns: int
    _deadline_kind: str
    _monotonic_ns: Callable[[], int] = field(repr=False, compare=False)

    @classmethod
    def start(
        cls,
        *,
        operation: str,
        timeout_seconds: object,
        timeout_code: str,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> OperationDeadlineV2:
        """Создать корневой срок, единожды считав монотонные часы."""

        checked_operation = _required_string(operation, "operation")
        checked_code = _required_string(timeout_code, "timeout_code")
        if not callable(monotonic_ns):
            raise TypeError("monotonic_ns must be callable")
        timeout_ns = _seconds_to_nanoseconds(
            timeout_seconds,
            "timeout_seconds",
            allow_zero=False,
            rounding=ROUND_FLOOR,
        )
        started_ns = _read_clock(monotonic_ns)
        deadline_ns = started_ns + timeout_ns
        return cls(
            operation=checked_operation,
            phase="operation",
            _root_started_monotonic_ns=started_ns,
            _operation_deadline_monotonic_ns=deadline_ns,
            _effective_deadline_monotonic_ns=deadline_ns,
            _effective_timeout_code=checked_code,
            _effective_configured_timeout_ns=timeout_ns,
            _deadline_kind="operation",
            _monotonic_ns=monotonic_ns,
        )

    @property
    def timeout_code(self) -> str:
        return self._effective_timeout_code

    @property
    def deadline_kind(self) -> str:
        return self._deadline_kind

    @property
    def configured_timeout_nanoseconds(self) -> int:
        return self._effective_configured_timeout_ns

    def child(
        self,
        *,
        phase: str,
        max_seconds: object,
        timeout_code: str,
    ) -> OperationDeadlineV2:
        """Создать этап, не способный продлить действующий предел."""

        checked_phase = _required_string(phase, "phase")
        checked_code = _required_string(timeout_code, "timeout_code")
        local_timeout_ns = _seconds_to_nanoseconds(
            max_seconds,
            "max_seconds",
            allow_zero=False,
            rounding=ROUND_FLOOR,
        )
        observed_ns = _read_clock(self._monotonic_ns)
        if observed_ns >= self._effective_deadline_monotonic_ns:
            self._raise_exceeded(observed_ns, phase=checked_phase)

        local_deadline_ns = observed_ns + local_timeout_ns
        if local_deadline_ns < self._effective_deadline_monotonic_ns:
            effective_deadline_ns = local_deadline_ns
            effective_code = checked_code
            effective_timeout_ns = local_timeout_ns
            deadline_kind = "phase"
        else:
            effective_deadline_ns = self._effective_deadline_monotonic_ns
            effective_code = self._effective_timeout_code
            effective_timeout_ns = self._effective_configured_timeout_ns
            deadline_kind = self._deadline_kind

        return OperationDeadlineV2(
            operation=self.operation,
            phase=checked_phase,
            _root_started_monotonic_ns=self._root_started_monotonic_ns,
            _operation_deadline_monotonic_ns=(
                self._operation_deadline_monotonic_ns
            ),
            _effective_deadline_monotonic_ns=effective_deadline_ns,
            _effective_timeout_code=effective_code,
            _effective_configured_timeout_ns=effective_timeout_ns,
            _deadline_kind=deadline_kind,
            _monotonic_ns=self._monotonic_ns,
        )

    def remaining_nanoseconds(self) -> int:
        """Вернуть остаток действующего срока, не меньше нуля."""

        observed_ns = _read_clock(self._monotonic_ns)
        return max(0, self._effective_deadline_monotonic_ns - observed_ns)

    def hard_remaining_nanoseconds(self) -> int:
        """Вернуть остаток корневого срока независимо от локального этапа."""

        observed_ns = _read_clock(self._monotonic_ns)
        return max(0, self._operation_deadline_monotonic_ns - observed_ns)

    def remaining_seconds(self) -> float:
        return self.remaining_nanoseconds() / NANOSECONDS_PER_SECOND

    def hard_remaining_seconds(self) -> float:
        return self.hard_remaining_nanoseconds() / NANOSECONDS_PER_SECOND

    def checkpoint(self) -> None:
        """Остановить выполнение на точной границе действующего срока."""

        observed_ns = _read_clock(self._monotonic_ns)
        if observed_ns >= self._effective_deadline_monotonic_ns:
            self._raise_exceeded(observed_ns)

    def require_remaining(self, *, reserve_seconds: object = 0) -> None:
        """Потребовать положительный остаток сверх заданного резерва."""

        reserve_ns = _seconds_to_nanoseconds(
            reserve_seconds,
            "reserve_seconds",
            allow_zero=True,
            rounding=ROUND_CEILING,
        )
        self._available_after_reserve(reserve_ns)

    def bounded_timeout_nanoseconds(
        self,
        *,
        local_cap_nanoseconds: int,
        reserve_nanoseconds: int = 0,
    ) -> int:
        """Получить положительный предел, не выходящий за общий остаток."""

        local_cap_ns = _positive_integer(
            local_cap_nanoseconds, "local_cap_nanoseconds"
        )
        reserve_ns = _nonnegative_integer(
            reserve_nanoseconds, "reserve_nanoseconds"
        )
        available_ns = self._available_after_reserve(reserve_ns)
        return min(local_cap_ns, available_ns)

    def bounded_timeout_seconds(
        self,
        *,
        local_cap_seconds: object,
        reserve_seconds: object = 0,
    ) -> float:
        """Версия ограничителя для интерфейсов, принимающих секунды."""

        local_cap_ns = _seconds_to_nanoseconds(
            local_cap_seconds,
            "local_cap_seconds",
            allow_zero=False,
            rounding=ROUND_FLOOR,
        )
        reserve_ns = _seconds_to_nanoseconds(
            reserve_seconds,
            "reserve_seconds",
            allow_zero=True,
            rounding=ROUND_CEILING,
        )
        bounded_ns = self.bounded_timeout_nanoseconds(
            local_cap_nanoseconds=local_cap_ns,
            reserve_nanoseconds=reserve_ns,
        )
        return bounded_ns / NANOSECONDS_PER_SECOND

    def bounded_timeout_ms(
        self,
        *,
        local_cap_ms: int,
        reserve_ms: int = 0,
    ) -> int:
        """Вернуть целое число миллисекунд без округления вверх."""

        cap_ms = _positive_integer(local_cap_ms, "local_cap_ms")
        checked_reserve_ms = _nonnegative_integer(reserve_ms, "reserve_ms")
        bounded_ns = self.bounded_timeout_nanoseconds(
            local_cap_nanoseconds=cap_ms * 1_000_000,
            reserve_nanoseconds=checked_reserve_ms * 1_000_000,
        )
        bounded_ms = bounded_ns // 1_000_000
        if bounded_ms <= 0:
            observed_ns = _read_clock(self._monotonic_ns)
            self._raise_exceeded(observed_ns)
        return bounded_ms

    def _available_after_reserve(self, reserve_ns: int) -> int:
        observed_ns = _read_clock(self._monotonic_ns)
        available_ns = (
            self._effective_deadline_monotonic_ns
            - observed_ns
            - reserve_ns
        )
        if available_ns <= 0:
            self._raise_exceeded(observed_ns)
        return available_ns

    def _raise_exceeded(
        self, observed_ns: int, *, phase: str | None = None
    ) -> None:
        elapsed_ns = max(0, observed_ns - self._root_started_monotonic_ns)
        raise OperationDeadlineExceededV2(
            code=self._effective_timeout_code,
            operation=self.operation,
            phase=self.phase if phase is None else phase,
            deadline_kind=self._deadline_kind,
            configured_timeout_nanoseconds=(
                self._effective_configured_timeout_ns
            ),
            elapsed_monotonic_nanoseconds=elapsed_ns,
        ) from None


_CURRENT_OPERATION_DEADLINE_V2: ContextVar[OperationDeadlineV2 | None] = (
    ContextVar("codex_smart_current_operation_deadline_v2", default=None)
)


@contextmanager
def scoped_current_deadline_v2(
    deadline: OperationDeadlineV2,
) -> Iterator[OperationDeadlineV2]:
    """Временно распространить ровно тот же объект общего срока."""

    if not isinstance(deadline, OperationDeadlineV2):
        raise TypeError("deadline must be OperationDeadlineV2")
    current = _CURRENT_OPERATION_DEADLINE_V2.get()
    if current is not None and deadline is not current:
        raise CurrentOperationDeadlineConflictV2(
            "nested scope must reuse the current operation deadline object"
        )
    token = _CURRENT_OPERATION_DEADLINE_V2.set(deadline)
    try:
        yield deadline
    finally:
        _CURRENT_OPERATION_DEADLINE_V2.reset(token)


def current_operation_deadline_v2() -> OperationDeadlineV2 | None:
    """Вернуть текущий общий срок без создания запасного значения."""

    return _CURRENT_OPERATION_DEADLINE_V2.get()


def checkpoint_current_operation_deadline_v2() -> OperationDeadlineV2:
    """Проверить текущий срок или закрыто отклонить отсутствие области."""

    deadline = current_operation_deadline_v2()
    if deadline is None:
        raise CurrentOperationDeadlineUnavailableV2(
            "no current operation deadline is scoped"
        )
    deadline.checkpoint()
    return deadline


def checkpoint_current_operation_deadline_if_scoped_v2(
) -> OperationDeadlineV2 | None:
    """Проверить общий срок, сохранив автономные низкоуровневые вызовы.

    Файловые и SQLite-примитивы используются как внутри публичной операции,
    так и отдельными диагностическими инструментами. В первом случае они
    обязаны участвовать в едином сроке; во втором новый срок здесь создавать
    нельзя, иначе вложенный вызов смог бы незаметно продлить операцию.
    """

    deadline = current_operation_deadline_v2()
    if deadline is not None:
        deadline.checkpoint()
    return deadline


def deadline_proof_v2(error: OperationDeadlineExceededV2) -> dict[str, object]:
    """Построить закрытое долговечное доказательство исчерпания срока."""

    if not isinstance(error, OperationDeadlineExceededV2):
        raise TypeError("error must be OperationDeadlineExceededV2")
    return validate_deadline_proof_v2(
        {
            "schemaVersion": 2,
            "proofType": "operation-deadline-v2",
            "operation": error.operation,
            "phase": error.phase,
            "timeoutCode": error.code,
            "deadlineKind": error.deadline_kind,
            "configuredTimeoutNanoseconds": (
                error.configured_timeout_nanoseconds
            ),
            "elapsedMonotonicNanoseconds": (
                error.elapsed_monotonic_nanoseconds
            ),
            "deadlineExceeded": True,
        }
    )


def validate_deadline_proof_v2(
    document: Mapping[str, object],
) -> dict[str, object]:
    """Проверить закрытый документ и вернуть отдельную обычную копию."""

    if type(document) is not dict:
        raise DeadlineProofValidationErrorV2(
            "deadline proof must be a plain object"
        )
    if set(document) != _DEADLINE_PROOF_KEYS:
        raise DeadlineProofValidationErrorV2(
            "deadline proof fields must match the closed contract"
        )
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 2:
        raise DeadlineProofValidationErrorV2("schemaVersion must be integer 2")
    if document["proofType"] != "operation-deadline-v2":
        raise DeadlineProofValidationErrorV2(
            "proofType must be operation-deadline-v2"
        )
    for key in ("operation", "phase", "timeoutCode"):
        value = document[key]
        if type(value) is not str or not value:
            raise DeadlineProofValidationErrorV2(
                f"{key} must be a non-empty string"
            )
    deadline_kind = document["deadlineKind"]
    if type(deadline_kind) is not str or deadline_kind not in {
        "operation",
        "phase",
    }:
        raise DeadlineProofValidationErrorV2(
            "deadlineKind must be operation or phase"
        )
    if (
        type(document["configuredTimeoutNanoseconds"]) is not int
        or document["configuredTimeoutNanoseconds"] <= 0
    ):
        raise DeadlineProofValidationErrorV2(
            "configuredTimeoutNanoseconds must be a positive integer"
        )
    if (
        type(document["elapsedMonotonicNanoseconds"]) is not int
        or document["elapsedMonotonicNanoseconds"] < 0
    ):
        raise DeadlineProofValidationErrorV2(
            "elapsedMonotonicNanoseconds must be a non-negative integer"
        )
    if document["deadlineExceeded"] is not True:
        raise DeadlineProofValidationErrorV2(
            "deadlineExceeded must be true"
        )
    return dict(document)


def _seconds_to_nanoseconds(
    value: object,
    name: str,
    *,
    allow_zero: bool,
    rounding: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise TypeError(f"{name} must be a finite number")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"{name} must be a finite number") from error
    if not decimal_value.is_finite():
        raise ValueError(f"{name} must be a finite number")
    if decimal_value < 0 or (not allow_zero and decimal_value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{name} must be {qualifier}")
    nanoseconds = int(
        (decimal_value * NANOSECONDS_PER_SECOND).to_integral_value(
            rounding=rounding
        )
    )
    if nanoseconds == 0 and decimal_value != 0:
        raise ValueError(f"{name} must be at least one nanosecond")
    return nanoseconds


def _read_clock(monotonic_ns: Callable[[], int]) -> int:
    observed_ns = monotonic_ns()
    if type(observed_ns) is not int:
        raise TypeError("monotonic_ns must return an integer")
    if observed_ns < 0:
        raise ValueError("monotonic_ns must not return a negative value")
    return observed_ns


def _required_string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _positive_integer(value: object, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nonnegative_integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


__all__ = [
    "CurrentOperationDeadlineConflictV2",
    "CurrentOperationDeadlineUnavailableV2",
    "DeadlineProofValidationErrorV2",
    "NANOSECONDS_PER_SECOND",
    "OperationDeadlineExceededV2",
    "OperationDeadlineV2",
    "checkpoint_current_operation_deadline_if_scoped_v2",
    "checkpoint_current_operation_deadline_v2",
    "current_operation_deadline_v2",
    "deadline_proof_v2",
    "scoped_current_deadline_v2",
    "validate_deadline_proof_v2",
]
