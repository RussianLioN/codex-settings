from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)
from codex_smart_subagents.sqlite_deadline_v2 import (  # noqa: E402
    connect_sqlite_with_deadline_v2,
)
from codex_smart_subagents import sqlite_deadline_v2  # noqa: E402


class _SteppingClock:
    def __init__(self, *, step: int = 1) -> None:
        self.value = 1_000_000_000
        self.step = step

    def __call__(self) -> int:
        observed = self.value
        self.value += self.step
        return observed


class SqliteDeadlineV2Tests(unittest.TestCase):
    def test_standalone_connection_preserves_normal_sqlite_behavior(self) -> None:
        connection = connect_sqlite_with_deadline_v2(":memory:")
        try:
            connection.execute("create table sample(value integer)")
            connection.execute("insert into sample values(1)")
            self.assertEqual(
                1,
                connection.execute("select value from sample").fetchone()[0],
            )
            self.assertEqual(
                5_000,
                connection.execute("pragma busy_timeout").fetchone()[0],
            )
        finally:
            connection.close()

    def test_progress_interrupt_reraises_the_exact_root_deadline(self) -> None:
        clock = _SteppingClock(step=1_000)
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.005,
            timeout_code="MUTATING_OPERATION_DEADLINE_TIMEOUT",
            monotonic_ns=clock,
        )
        with scoped_current_deadline_v2(deadline):
            connection = connect_sqlite_with_deadline_v2(
                ":memory:",
                progress_steps=1,
            )
            try:
                with self.assertRaises(OperationDeadlineExceededV2) as caught:
                    connection.execute(
                        "with recursive n(x) as (values(1) union all "
                        "select x+1 from n where x<100000) select sum(x) from n"
                    ).fetchone()
            finally:
                connection.close()

        self.assertEqual(
            "MUTATING_OPERATION_DEADLINE_TIMEOUT",
            caught.exception.code,
        )

    def test_unrelated_operational_error_is_not_reclassified(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        with scoped_current_deadline_v2(deadline):
            connection = connect_sqlite_with_deadline_v2(":memory:")
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("select * from absent_table").fetchall()
            finally:
                connection.close()

    def test_stale_progress_error_cannot_poison_the_next_sql_call(self) -> None:
        clock = _SteppingClock(step=1_000)
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.005,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        connection = connect_sqlite_with_deadline_v2(
            ":memory:",
            progress_steps=1,
        )
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(sqlite3.OperationalError):
                    sqlite3.Connection.execute(
                        connection,
                        "with recursive n(x) as (values(1) union all "
                        "select x+1 from n where x<100000) select sum(x) from n",
                    ).fetchone()

            with self.assertRaises(sqlite3.OperationalError) as caught:
                connection.execute("select * from absent_table").fetchall()
            self.assertIn("absent_table", str(caught.exception))
        finally:
            connection.close()

    def test_custom_cursor_factory_cannot_bypass_deadline_contract(self) -> None:
        class RawCursor(sqlite3.Cursor):
            pass

        connection = connect_sqlite_with_deadline_v2(":memory:")
        try:
            with self.assertRaisesRegex(
                TypeError,
                "DeadlineAwareCursorV2",
            ):
                connection.cursor(RawCursor)
        finally:
            connection.close()

    def test_zero_lock_timeout_remains_a_valid_nonblocking_mode(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        with scoped_current_deadline_v2(deadline):
            connection = connect_sqlite_with_deadline_v2(
                ":memory:",
                timeout=0,
            )
        try:
            self.assertEqual(
                0,
                connection.execute("pragma busy_timeout").fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute("select 1").fetchone()[0],
            )
        finally:
            connection.close()

    def test_default_busy_timeout_does_not_exceed_connect_timeout(self) -> None:
        connection = connect_sqlite_with_deadline_v2(
            ":memory:",
            timeout=1,
        )
        try:
            self.assertEqual(
                1_000,
                connection.execute("pragma busy_timeout").fetchone()[0],
            )
        finally:
            connection.close()

    def test_busy_timeout_is_recomputed_before_each_sqlite_step(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        with scoped_current_deadline_v2(deadline):
            connection = connect_sqlite_with_deadline_v2(":memory:")
            try:
                self.assertEqual(
                    5_000,
                    connection.execute("pragma busy_timeout").fetchone()[0],
                )
                clock.value += 9_750_000_000
                self.assertEqual(
                    150,
                    connection.execute("pragma busy_timeout").fetchone()[0],
                )
            finally:
                connection.close()

    def test_short_remaining_deadline_forces_nonblocking_sqlite(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.05,
            timeout_code="ROOT_EXPIRED",
        )
        with scoped_current_deadline_v2(deadline):
            connection = connect_sqlite_with_deadline_v2(":memory:")
            try:
                self.assertEqual(
                    0,
                    sqlite3.Connection.execute(
                        connection,
                        "pragma busy_timeout",
                    ).fetchone()[0],
                )
            finally:
                connection.close()

    def test_configuration_failure_closes_new_connection(self) -> None:
        class FakeConnection:
            def __init__(self) -> None:
                self.closed = False

            def configure_operation_deadline_v2(self, **_kwargs: object) -> None:
                raise RuntimeError("configuration failed")

            def close(self) -> None:
                self.closed = True

        connection = FakeConnection()
        with mock.patch.object(
            sqlite_deadline_v2.sqlite3,
            "connect",
            return_value=connection,
        ):
            with self.assertRaisesRegex(RuntimeError, "configuration failed"):
                connect_sqlite_with_deadline_v2(":memory:")

        self.assertTrue(connection.closed)

    def test_executemany_rechecks_deadline_after_each_parameter_pull(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")

        def delayed_parameters():
            clock.value += 200_000_000
            yield (1,)

        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    connection.executemany(
                        "insert into sample values(?)",
                        delayed_parameters(),
                    )
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_executescript_rechecks_deadline_between_statements(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")

        def expire() -> int:
            clock.value += 200_000_000
            return 1

        connection.create_function("expire_deadline", 0, expire)
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    connection.executescript(
                        "select expire_deadline();\n"
                        "insert into sample values(1);\n"
                    )
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_slow_udf_cannot_commit_a_short_statement_after_deadline(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        connection = connect_sqlite_with_deadline_v2(
            ":memory:",
            isolation_level=None,
        )
        connection.execute("create table sample(value integer)")

        def expire() -> int:
            clock.value += 200_000_000
            return 1

        connection.create_function("expire_deadline", 0, expire)
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    connection.execute(
                        "insert into sample select expire_deadline()"
                    )
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_slow_row_factory_is_checked_before_fetch_returns(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        connection.execute("insert into sample values(1)")

        def slow_factory(_cursor: sqlite3.Cursor, row: tuple[object, ...]):
            clock.value += 200_000_000
            return row

        connection.row_factory = slow_factory
        try:
            with scoped_current_deadline_v2(deadline):
                cursor = connection.execute("select value from sample")
                with self.assertRaises(OperationDeadlineExceededV2):
                    cursor.fetchone()
        finally:
            connection.close()

    def test_backup_checks_deadline_after_user_progress_callback(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=0.1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        source = connect_sqlite_with_deadline_v2(":memory:")
        destination = connect_sqlite_with_deadline_v2(":memory:")
        source.execute("create table sample(value integer)")

        def expire(_status: int, _remaining: int, _total: int) -> None:
            clock.value += 200_000_000

        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    source.backup(destination, pages=1, progress=expire)
        finally:
            destination.close()
            source.close()

    def test_invalid_executescript_never_commits_pending_transaction(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        connection.execute("insert into sample values(1)")
        self.assertTrue(connection.in_transaction)
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(TypeError):
                    connection.executescript(123)  # type: ignore[arg-type]
            self.assertTrue(connection.in_transaction)
            connection.rollback()
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_scoped_composite_calls_preserve_cursor_observables(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        cursor = connection.cursor()
        try:
            with scoped_current_deadline_v2(deadline):
                returned = cursor.executemany(
                    "insert into sample values(?)",
                    ((1,), (2,), (3,)),
                )
                self.assertIs(cursor, returned)
                self.assertEqual(3, cursor.rowcount)
                lastrowid_before_script = cursor.lastrowid
                returned = cursor.executescript(
                    "select value from sample; insert into sample values(4);"
                )
                self.assertIs(cursor, returned)

            self.assertEqual(lastrowid_before_script, cursor.lastrowid)
            self.assertIsNone(cursor.description)
            self.assertEqual([], cursor.fetchall())
            self.assertEqual(
                4,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            cursor.close()
            connection.close()

    def test_scoped_executescript_preserves_prior_cursor_metadata(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        cursor = connection.cursor()
        try:
            cursor.execute("insert into sample values(1)")
            insertion_metadata = (
                cursor.lastrowid,
                cursor.rowcount,
                cursor.description,
            )
            with scoped_current_deadline_v2(deadline):
                cursor.executescript("insert into sample values(2);")
            self.assertEqual(
                insertion_metadata,
                (cursor.lastrowid, cursor.rowcount, cursor.description),
            )

            cursor.execute("select value from sample order by value")
            selection_metadata = (
                cursor.lastrowid,
                cursor.rowcount,
                cursor.description,
            )
            with scoped_current_deadline_v2(deadline):
                cursor.executescript("insert into sample values(3);")
            self.assertEqual(
                selection_metadata,
                (cursor.lastrowid, cursor.rowcount, cursor.description),
            )
            self.assertEqual([(1,), (2,)], cursor.fetchall())
        finally:
            cursor.close()
            connection.close()

    def test_scoped_executescript_preserves_native_autocommit_semantics(
        self,
    ) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        try:
            with scoped_current_deadline_v2(deadline):
                connection.executescript(
                    "select 1; insert into sample values(1);"
                )

            self.assertFalse(connection.in_transaction)
            connection.rollback()
            self.assertEqual(
                1,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_closed_connection_context_fails_before_entering_body(self) -> None:
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.close()
        entered = False

        with self.assertRaises(sqlite3.ProgrammingError):
            with connection:
                entered = True

        self.assertFalse(entered)

    def test_scoped_call_restores_default_sqlite_policy_on_return(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        try:
            with scoped_current_deadline_v2(deadline):
                connection.execute("select 1")

            self.assertEqual(
                5_000,
                sqlite3.Connection.execute(
                    connection,
                    "pragma busy_timeout",
                ).fetchone()[0],
            )
            self.assertEqual(
                1_000,
                connection._codex_active_progress_steps,
            )
        finally:
            connection.close()

    def test_scoped_error_restores_default_sqlite_policy(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer unique)")
        connection.execute("insert into sample values(1)")
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("insert into sample values(1)")

            self.assertEqual(
                5_000,
                sqlite3.Connection.execute(
                    connection,
                    "pragma busy_timeout",
                ).fetchone()[0],
            )
            self.assertEqual(
                1_000,
                connection._codex_active_progress_steps,
            )
        finally:
            connection.close()

    def test_scoped_backup_restores_target_sqlite_policy(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
        )
        source = connect_sqlite_with_deadline_v2(":memory:")
        target = connect_sqlite_with_deadline_v2(":memory:")
        source.execute("create table sample(value integer)")
        try:
            with scoped_current_deadline_v2(deadline):
                source.backup(target)

            self.assertEqual(
                5_000,
                sqlite3.Connection.execute(
                    target,
                    "pragma busy_timeout",
                ).fetchone()[0],
            )
            self.assertEqual(1_000, target._codex_active_progress_steps)
        finally:
            target.close()
            source.close()

    def test_scoped_executescript_preserves_explicit_transaction(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        try:
            with scoped_current_deadline_v2(deadline):
                connection.executescript(
                    "begin; insert into sample values(1);"
                )

            self.assertTrue(connection.in_transaction)
            connection.rollback()
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_scoped_executescript_keeps_explicit_autocommit_transaction_open(
        self,
    ) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(
            ":memory:",
            isolation_level=None,
        )
        connection.execute("create table sample(value integer)")
        try:
            with scoped_current_deadline_v2(deadline):
                connection.executescript(
                    "begin; insert into sample values(1);"
                )

            self.assertTrue(connection.in_transaction)
            connection.rollback()
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_failed_scoped_executescript_keeps_explicit_transaction_open(
        self,
    ) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=10,
            timeout_code="ROOT_EXPIRED",
        )
        connection = connect_sqlite_with_deadline_v2(
            ":memory:",
            isolation_level=None,
        )
        connection.execute("create table sample(value integer)")
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(sqlite3.OperationalError):
                    connection.executescript(
                        "begin; insert into sample values(1); "
                        "select * from absent_table;"
                    )

            self.assertTrue(connection.in_transaction)
            connection.rollback()
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_connection_context_rolls_back_when_deadline_blocks_commit(self) -> None:
        class Clock:
            def __init__(self) -> None:
                self.value = 1_000_000_000

            def __call__(self) -> int:
                return self.value

        clock = Clock()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=1,
            timeout_code="ROOT_EXPIRED",
            monotonic_ns=clock,
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        try:
            with scoped_current_deadline_v2(deadline):
                with self.assertRaises(OperationDeadlineExceededV2):
                    with connection:
                        connection.execute("insert into sample values(1)")
                        clock.value += 2_000_000_000

            self.assertFalse(connection.in_transaction)
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()

    def test_connection_context_preserves_original_exception_during_cleanup(
        self,
    ) -> None:
        original = OperationDeadlineExceededV2(
            code="ROOT_EXPIRED",
            operation="apply",
            phase="body",
            deadline_kind="operation",
            configured_timeout_nanoseconds=1,
            elapsed_monotonic_nanoseconds=2,
        )
        connection = connect_sqlite_with_deadline_v2(":memory:")
        connection.execute("create table sample(value integer)")
        try:
            with self.assertRaises(OperationDeadlineExceededV2) as caught:
                with connection:
                    connection.execute("insert into sample values(1)")
                    raise original

            self.assertIs(original, caught.exception)
            self.assertFalse(connection.in_transaction)
            self.assertEqual(
                0,
                connection.execute("select count(*) from sample").fetchone()[0],
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
