"""SQLite-соединение, кооперативно подчинённое сроку операции версии 2."""

from __future__ import annotations

import sqlite3
import math
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .operation_deadline_v2 import (
    OperationDeadlineExceededV2,
    checkpoint_current_operation_deadline_if_scoped_v2,
    current_operation_deadline_v2,
)


_DEFAULT_BUSY_TIMEOUT_MS = 5_000
_DEFAULT_PROGRESS_STEPS = 1_000
_DEADLINE_SCHEDULING_RESERVE_MS = 100


class DeadlineAwareCursorV2(sqlite3.Cursor):
    """Курсор, возвращающий исходную ошибку срока вместо `interrupted`."""

    @property
    def _deadline_connection(self) -> DeadlineAwareConnectionV2:
        connection = self.connection
        if not isinstance(connection, DeadlineAwareConnectionV2):
            raise TypeError("deadline cursor requires a deadline connection")
        return connection

    def execute(
        self,
        sql: str,
        parameters: Sequence[Any] | Mapping[str, Any] = (),
    ) -> DeadlineAwareCursorV2:
        connection = self._deadline_connection
        connection._before_sqlite_call()
        try:
            result = super().execute(sql, parameters)
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        connection._after_sqlite_call()
        return result

    def executemany(
        self,
        sql: str,
        seq_of_parameters: Iterable[Sequence[Any] | Mapping[str, Any]],
    ) -> DeadlineAwareCursorV2:
        connection = self._deadline_connection
        connection._before_sqlite_call()
        try:
            if current_operation_deadline_v2() is None:
                return super().executemany(sql, seq_of_parameters)

            def checked_parameters():
                for parameters in seq_of_parameters:
                    # Получение элемента может быть ленивым и долгим. Проверка
                    # после него запрещает запись с устаревшим остатком.
                    connection._before_sqlite_call()
                    yield parameters

            result = super().executemany(sql, checked_parameters())
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        connection._after_sqlite_call()
        return result

    def executescript(self, sql_script: str) -> DeadlineAwareCursorV2:
        if not isinstance(sql_script, str):
            raise TypeError("sql_script must be str")
        connection = self._deadline_connection
        connection._before_sqlite_call()
        previous_isolation_level: str | None = None
        restore_isolation_level = False
        try:
            if current_operation_deadline_v2() is None:
                return super().executescript(sql_script)
            if connection.in_transaction:
                connection.commit()
                connection._before_sqlite_call()
            previous_isolation_level = connection.isolation_level
            if previous_isolation_level is not None:
                connection.isolation_level = None
                restore_isolation_level = True
            statements = iter(_iter_sqlite_script_statements(sql_script))
            first_statement = next(statements, None)
            if first_statement is None:
                super().executescript(sql_script)
            else:
                # Один нативный statement безопасен при progress_steps=1 и
                # одновременно сохраняет обычные cursor observables.
                super().executescript(first_statement)
                connection._after_sqlite_call()
                worker = connection.cursor()
                try:
                    for statement in statements:
                        worker.execute(statement)
                finally:
                    worker.close()
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        finally:
            if restore_isolation_level:
                connection.isolation_level = previous_isolation_level
        connection._after_sqlite_call()
        return self

    def fetchone(self) -> Any:
        connection = self._deadline_connection
        connection._before_sqlite_call()
        try:
            result = super().fetchone()
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        connection._after_sqlite_call()
        return result

    def fetchmany(self, size: int | None = None) -> list[Any]:
        connection = self._deadline_connection
        connection._before_sqlite_call()
        try:
            if size is None:
                result = super().fetchmany()
            else:
                result = super().fetchmany(size)
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        connection._after_sqlite_call()
        return result

    def fetchall(self) -> list[Any]:
        connection = self._deadline_connection
        connection._before_sqlite_call()
        try:
            result = super().fetchall()
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        connection._after_sqlite_call()
        return result

    def __next__(self) -> Any:
        connection = self._deadline_connection
        connection._before_sqlite_call()
        try:
            result = super().__next__()
        except sqlite3.OperationalError as error:
            connection._reraise_deadline_or(error)
        except BaseException as error:
            connection._restore_policy_preserving_v2(error)
            raise
        connection._after_sqlite_call()
        return result


class DeadlineAwareConnectionV2(sqlite3.Connection):
    """Соединение с динамическим busy timeout и progress handler."""

    _codex_default_busy_timeout_ms: int
    _codex_deadline_error: OperationDeadlineExceededV2 | None
    _codex_progress_steps: int
    _codex_active_progress_steps: int

    def configure_operation_deadline_v2(
        self,
        *,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
        progress_steps: int = _DEFAULT_PROGRESS_STEPS,
    ) -> None:
        if type(busy_timeout_ms) is not int or busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be a nonnegative integer")
        if type(progress_steps) is not int or progress_steps <= 0:
            raise ValueError("progress_steps must be a positive integer")
        self._codex_default_busy_timeout_ms = busy_timeout_ms
        self._codex_deadline_error = None
        self._codex_progress_steps = progress_steps
        self._codex_active_progress_steps = progress_steps
        self.set_progress_handler(self._deadline_progress, progress_steps)
        self._before_sqlite_call()

    def cursor(
        self,
        factory: type[sqlite3.Cursor] | None = None,
    ) -> sqlite3.Cursor:
        selected_factory = DeadlineAwareCursorV2 if factory is None else factory
        if not (
            isinstance(selected_factory, type)
            and issubclass(selected_factory, DeadlineAwareCursorV2)
        ):
            raise TypeError(
                "custom cursor factory must inherit DeadlineAwareCursorV2"
            )
        return super().cursor(selected_factory)

    def execute(
        self,
        sql: str,
        parameters: Sequence[Any] | Mapping[str, Any] = (),
    ) -> DeadlineAwareCursorV2:
        cursor = self.cursor()
        assert isinstance(cursor, DeadlineAwareCursorV2)
        return cursor.execute(sql, parameters)

    def executemany(
        self,
        sql: str,
        seq_of_parameters: Iterable[Sequence[Any] | Mapping[str, Any]],
    ) -> DeadlineAwareCursorV2:
        cursor = self.cursor()
        assert isinstance(cursor, DeadlineAwareCursorV2)
        return cursor.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> DeadlineAwareCursorV2:
        cursor = self.cursor()
        assert isinstance(cursor, DeadlineAwareCursorV2)
        return cursor.executescript(sql_script)

    def commit(self) -> None:
        self._before_sqlite_call()
        try:
            super().commit()
        except sqlite3.OperationalError as error:
            self._reraise_deadline_or(error)
        except BaseException as error:
            self._restore_policy_preserving_v2(error)
            raise
        self._after_sqlite_call()

    def __enter__(self) -> DeadlineAwareConnectionV2:
        entered = super().__enter__()
        if entered is not self:  # pragma: no cover - гарантия sqlite3 API
            raise TypeError("sqlite connection context returned another object")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, traceback
        if exc is not None:
            try:
                self.rollback_for_cleanup_v2()
            except BaseException as cleanup_error:
                exc.add_note(
                    "SQLite context cleanup rollback also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            return False
        try:
            self.commit()
        except BaseException as primary:
            try:
                self.rollback_for_cleanup_v2()
            except BaseException as cleanup_error:
                primary.add_note(
                    "SQLite context rollback after failed commit also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise
        return False

    def backup(
        self,
        target: sqlite3.Connection,
        *,
        pages: int = -1,
        progress: Callable[[int, int, int], None] | None = None,
        name: str = "main",
        sleep: float = 0.250,
    ) -> None:
        deadline_target = (
            target if isinstance(target, DeadlineAwareConnectionV2) else None
        )
        target_prepared = False

        def guarded_progress(status: int, remaining: int, total: int) -> None:
            checkpoint_current_operation_deadline_if_scoped_v2()
            if progress is not None:
                progress(status, remaining, total)
            checkpoint_current_operation_deadline_if_scoped_v2()

        guarded_sleep = sleep
        if current_operation_deadline_v2() is not None:
            guarded_sleep = min(sleep, 0.01)
        try:
            self._before_sqlite_call()
            if deadline_target is not None:
                target_prepared = True
                deadline_target._before_sqlite_call()
            try:
                super().backup(
                    target,
                    pages=pages,
                    progress=guarded_progress,
                    name=name,
                    sleep=guarded_sleep,
                )
            except sqlite3.OperationalError as error:
                self._reraise_deadline_or(error)
            self._after_sqlite_call()
        except BaseException as primary:
            self._restore_policy_preserving_v2(primary)
            if target_prepared:
                assert deadline_target is not None
                deadline_target._restore_policy_preserving_v2(primary)
            raise
        else:
            if target_prepared:
                assert deadline_target is not None
                deadline_target._restore_default_sqlite_policy_v2()

    def rollback(self) -> None:
        self._before_sqlite_call()
        try:
            super().rollback()
        except sqlite3.OperationalError as error:
            self._reraise_deadline_or(error)
        except BaseException as error:
            self._restore_policy_preserving_v2(error)
            raise
        self._after_sqlite_call()

    def rollback_for_cleanup_v2(self) -> None:
        """Откатить начатую транзакцию, даже если общий срок уже истёк.

        Метод предназначен только для обработки уже возникшей ошибки. Он не
        ждёт блокировок, временно отключает обработчик срока и восстанавливает
        обычный режим соединения до возврата вызывающему коду.
        """

        self._codex_deadline_error = None
        self.set_progress_handler(None, 0)
        try:
            sqlite3.Connection.execute(self, "pragma busy_timeout=0")
            sqlite3.Connection.rollback(self)
        finally:
            self._codex_deadline_error = None
            sqlite3.Connection.execute(
                self,
                f"pragma busy_timeout={self._codex_default_busy_timeout_ms}",
            )
            self.set_progress_handler(
                self._deadline_progress,
                self._codex_progress_steps,
            )
            self._codex_active_progress_steps = self._codex_progress_steps

    def _deadline_progress(self) -> int:
        deadline = current_operation_deadline_v2()
        if deadline is None:
            self._codex_deadline_error = None
            return 0
        try:
            deadline.checkpoint()
        except OperationDeadlineExceededV2 as error:
            self._codex_deadline_error = error
            return 1
        return 0

    def _before_sqlite_call(self) -> None:
        # Ошибка progress handler относится только к SQL-вызову, во время
        # которого она возникла. Новый вызов не вправе унаследовать её.
        self._codex_deadline_error = None
        deadline = checkpoint_current_operation_deadline_if_scoped_v2()
        selected_progress_steps = (
            1 if deadline is not None else self._codex_progress_steps
        )
        if selected_progress_steps != self._codex_active_progress_steps:
            self.set_progress_handler(
                self._deadline_progress,
                selected_progress_steps,
            )
            self._codex_active_progress_steps = selected_progress_steps
        timeout_ms = self._codex_default_busy_timeout_ms
        if deadline is not None and timeout_ms > 0:
            remaining_ms = deadline.remaining_nanoseconds() // 1_000_000
            timeout_ms = min(
                timeout_ms,
                max(0, remaining_ms - _DEADLINE_SCHEDULING_RESERVE_MS),
            )
        try:
            sqlite3.Connection.execute(
                self,
                f"pragma busy_timeout={timeout_ms}",
            )
        except sqlite3.OperationalError as error:
            self._reraise_deadline_or(error)

    def _after_sqlite_call(self) -> None:
        try:
            checkpoint_current_operation_deadline_if_scoped_v2()
        except BaseException as primary:
            try:
                self._restore_default_sqlite_policy_v2()
            except BaseException as cleanup_error:
                primary.add_note(
                    "SQLite policy restoration also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise
        self._restore_default_sqlite_policy_v2()

    def _restore_default_sqlite_policy_v2(self) -> None:
        self._codex_deadline_error = None
        self.set_progress_handler(
            self._deadline_progress,
            self._codex_progress_steps,
        )
        self._codex_active_progress_steps = self._codex_progress_steps
        sqlite3.Connection.execute(
            self,
            f"pragma busy_timeout={self._codex_default_busy_timeout_ms}",
        )

    def _reraise_deadline_or(self, error: sqlite3.OperationalError) -> Any:
        deadline_error = self._codex_deadline_error
        self._codex_deadline_error = None
        if deadline_error is not None:
            self._restore_policy_preserving_v2(deadline_error)
            raise deadline_error from error
        try:
            checkpoint_current_operation_deadline_if_scoped_v2()
        except BaseException as deadline_error:
            self._restore_policy_preserving_v2(deadline_error)
            raise
        self._restore_policy_preserving_v2(error)
        raise error

    def _restore_policy_preserving_v2(self, primary: BaseException) -> None:
        try:
            self._restore_default_sqlite_policy_v2()
        except BaseException as cleanup_error:
            primary.add_note(
                "SQLite policy restoration also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )


def connect_sqlite_with_deadline_v2(
    database: str | bytes | Path,
    *,
    timeout: float = 5.0,
    busy_timeout_ms: int | None = None,
    progress_steps: int = _DEFAULT_PROGRESS_STEPS,
    **kwargs: Any,
) -> DeadlineAwareConnectionV2:
    """Открыть SQLite, не позволяя локальному ожиданию продлить общий срок."""

    if "factory" in kwargs:
        raise ValueError("factory is owned by connect_sqlite_with_deadline_v2")
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError) as error:
        raise ValueError("timeout must be a finite nonnegative number") from error
    if not math.isfinite(timeout_value) or timeout_value < 0:
        raise ValueError("timeout must be a finite nonnegative number")
    if busy_timeout_ms is None:
        selected_busy_timeout_ms = min(
            _DEFAULT_BUSY_TIMEOUT_MS,
            int(timeout_value * 1_000),
        )
    else:
        selected_busy_timeout_ms = busy_timeout_ms

    deadline = checkpoint_current_operation_deadline_if_scoped_v2()
    bounded_timeout = timeout_value
    if deadline is not None and timeout_value > 0:
        available_seconds = max(
            0.0,
            deadline.remaining_seconds()
            - (_DEADLINE_SCHEDULING_RESERVE_MS / 1_000),
        )
        bounded_timeout = min(timeout_value, available_seconds)
    try:
        connection = sqlite3.connect(
            database,
            timeout=bounded_timeout,
            factory=DeadlineAwareConnectionV2,
            **kwargs,
        )
    except sqlite3.OperationalError as error:
        checkpoint_current_operation_deadline_if_scoped_v2()
        raise error
    try:
        connection.configure_operation_deadline_v2(
            busy_timeout_ms=selected_busy_timeout_ms,
            progress_steps=progress_steps,
        )
        checkpoint_current_operation_deadline_if_scoped_v2()
    except BaseException:
        connection.close()
        raise
    return connection


def _iter_sqlite_script_statements(sql_script: str) -> Iterable[str]:
    if not isinstance(sql_script, str):
        raise TypeError("sql_script must be str")
    buffer: list[str] = []
    for character in sql_script:
        buffer.append(character)
        if character != ";":
            continue
        candidate = "".join(buffer)
        if sqlite3.complete_statement(candidate):
            if candidate.strip():
                yield candidate
            buffer.clear()
    tail = "".join(buffer)
    if tail.strip():
        yield tail


__all__ = [
    "DeadlineAwareConnectionV2",
    "DeadlineAwareCursorV2",
    "connect_sqlite_with_deadline_v2",
]
