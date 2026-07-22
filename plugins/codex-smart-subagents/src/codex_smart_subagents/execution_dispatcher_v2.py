"""Ограниченный внутрипроцессный диспетчер долговечных заявок запуска v2."""

from __future__ import annotations

import logging
import re
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .state_store_v2 import RequestContextV2


_START_REQUEST_ID = re.compile(r"^sr2_[0-9a-f]{32}$")
_COMPLETED_START_STATES = {
    "SUCCEEDED",
    "QUARANTINED",
    "STALE",
    "FAILED",
    "CANCELLED",
}
_NON_DISPATCHABLE_START_STATES = _COMPLETED_START_STATES | {"STARTED"}
_LOGGER = logging.getLogger(__name__)


@dataclass
class ExecutionDispatcherV2Error(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ExecutionDispatcherV2:
    """Передаёт не более двух долговечных заявок единому исполнителю.

    База остаётся источником истины: рабочий поток повторно читает заявку по
    идентификатору, а диспетчер хранит только ограниченный набор текущих работ.
    """

    def __init__(
        self,
        *,
        store: Any,
        execution: Any,
        max_workers: int = 2,
        max_pending: int = 32,
        error_sink: Callable[[str, BaseException], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(store, "read_start_request", None)):
            raise TypeError("store must provide read_start_request()")
        if not callable(getattr(execution, "run", None)):
            raise TypeError("execution must provide run()")
        if type(max_workers) is not int or not 1 <= max_workers <= 2:
            raise ValueError("max_workers must be between one and two")
        if (
            type(max_pending) is not int
            or not max_workers <= max_pending <= 32
        ):
            raise ValueError("max_pending must contain all workers and be at most 32")
        if error_sink is not None and not callable(error_sink):
            raise TypeError("error_sink must be callable")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._store = store
        self._execution = execution
        self._maximum_pending = max_pending
        self._error_sink = error_sink or self._log_error
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._condition = threading.Condition(threading.RLock())
        self._futures: dict[str, Future[Any]] = {}
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="codex-smart-v2",
        )

    def submit(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
    ) -> bool:
        """Ставит заявку один раз; повтор текущей заявки не создаёт работу."""

        if (
            not isinstance(start_request_id, str)
            or _START_REQUEST_ID.fullmatch(start_request_id) is None
        ):
            self._fail("START_REQUEST_ID_INVALID", "неверный идентификатор заявки")
        if not isinstance(request_context, RequestContextV2):
            raise TypeError("request_context must be RequestContextV2")
        with self._condition:
            if self._closed:
                self._fail("CLOSED", "диспетчер уже закрыт")
            if start_request_id in self._futures:
                return False
            if len(self._futures) >= self._maximum_pending:
                self._fail("QUEUE_FULL", "внутренняя очередь достигла предела")
            try:
                future = self._executor.submit(
                    self._run_one,
                    start_request_id,
                    request_context,
                )
            except RuntimeError as exc:
                self._fail("CLOSED", str(exc))
            self._futures[start_request_id] = future
            future.add_done_callback(
                lambda completed, identifier=start_request_id: self._completed(
                    identifier,
                    completed,
                )
            )
            return True

    def wait_idle(self, timeout_seconds: float) -> bool:
        """Ожидает пустой текущий набор в заданном ограниченном интервале."""

        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 <= float(timeout_seconds) <= 1800
        ):
            raise ValueError("timeout_seconds is outside the supported range")
        deadline = time.monotonic() + float(timeout_seconds)
        with self._condition:
            while self._futures:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def close(self) -> None:
        """Перестаёт принимать заявки и дожидается уже принятых работ."""

        with self._condition:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=False)
        with self._condition:
            self._condition.notify_all()

    def _run_one(
        self,
        start_request_id: str,
        request_context: RequestContextV2,
    ) -> Any:
        start_request = self._store.read_start_request(
            start_request_id,
            request_context,
        )
        state = getattr(start_request, "state", None)
        # STARTED уже принадлежит действующему дочернему процессу. Оно теперь
        # промежуточное для smart_wait, но повторная постановка не должна
        # запускать вторую копию после потери внутрипроцессного Future.
        if state in _NON_DISPATCHABLE_START_STATES:
            return None
        if state != "ATTESTING":
            self._fail(
                "START_STATE_UNRECOVERABLE",
                f"заявка находится в неподдерживаемом состоянии {state!r}",
            )
        deadline_at = getattr(start_request, "deadline_at", None)
        if not isinstance(deadline_at, datetime) or deadline_at.tzinfo is None:
            self._fail(
                "START_DEADLINE_INVALID",
                "долговечная заявка не содержит корректный срок",
            )
        try:
            now = self._now()
        except ExecutionDispatcherV2Error as error:
            self._terminalize_start_request(
                start_request,
                request_context,
                failure_code=error.code,
                public_message="Внутренние часы запуска недоступны.",
                now=self._terminalization_now(),
            )
            raise
        if deadline_at.astimezone(timezone.utc) <= now:
            self._terminalize_start_request(
                start_request,
                request_context,
                failure_code="REQUEST_DEADLINE_EXCEEDED",
                public_message="Истёк общий срок запуска дочерней задачи.",
                now=now,
            )
            return None
        return self._execution.run(start_request, request_context)

    def _terminalize_start_request(
        self,
        start_request: Any,
        request_context: RequestContextV2,
        *,
        failure_code: str,
        public_message: str,
        now: datetime,
    ) -> None:
        terminalize = getattr(
            self._store,
            "record_account_evidence_terminal",
            None,
        )
        if not callable(terminalize):
            self._fail(
                "START_TERMINALIZER_MISSING",
                "хранилище не умеет терминализировать заявку",
            )
        terminal = terminalize(
            start_request.evidence_job_id,
            request_context,
            state="FAILED",
            failure_code=failure_code,
            problem=(
                {
                    "category": "UNAVAILABLE",
                    "code": "REQUEST_DEADLINE_EXCEEDED",
                    "message": public_message,
                    "retryable": True,
                }
                if failure_code == "REQUEST_DEADLINE_EXCEEDED"
                else {
                    "category": "INTERNAL",
                    "code": "INTERNAL_ERROR",
                    "message": public_message,
                    "retryable": False,
                }
            ),
            now=now,
        )
        if (
            getattr(terminal, "state", None) != "FAILED"
            or getattr(terminal, "terminal", None) is not True
        ):
            self._fail(
                "START_TERMINALIZATION_INVALID",
                "хранилище не подтвердило терминализацию заявки",
            )

    def _completed(self, start_request_id: str, future: Future[Any]) -> None:
        error: BaseException | None
        try:
            error = future.exception()
        except BaseException as exc:  # pragma: no cover - защитная граница Future
            error = exc
        with self._condition:
            self._futures.pop(start_request_id, None)
            self._condition.notify_all()
        if error is not None:
            try:
                self._error_sink(start_request_id, error)
            except BaseException:
                _LOGGER.exception("обработчик ошибки диспетчера сам завершился ошибкой")

    @staticmethod
    def _log_error(start_request_id: str, error: BaseException) -> None:
        _LOGGER.error(
            "заявка %s завершилась ошибкой",
            start_request_id,
            exc_info=(type(error), error, error.__traceback__),
        )

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as error:
            self._fail("CLOCK_INVALID", str(error) or type(error).__name__)
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            self._fail("CLOCK_INVALID", "часы диспетчера вернули неверное время")
        return value.astimezone(timezone.utc)

    def _terminalization_now(self) -> datetime:
        try:
            return self._now()
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _fail(code: str, message: str) -> None:
        raise ExecutionDispatcherV2Error(code, message)


__all__ = ["ExecutionDispatcherV2", "ExecutionDispatcherV2Error"]
