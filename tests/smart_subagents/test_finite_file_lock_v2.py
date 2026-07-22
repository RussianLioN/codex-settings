from __future__ import annotations

import ast
import errno
import fcntl
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.finite_file_lock_v2 import (  # noqa: E402
    FileLockTimeoutV2,
    acquire_flock_v2,
    lock_budget_v2,
)


def _load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _MonotonicClock:
    def __init__(self) -> None:
        self.value = 10.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class FiniteFileLockV2Tests(unittest.TestCase):
    def test_busy_lock_stops_at_monotonic_deadline_with_exact_code(self) -> None:
        clock = _MonotonicClock()
        operations: list[int] = []

        def busy(_descriptor: int, operation: int) -> None:
            operations.append(operation)
            raise BlockingIOError(errno.EAGAIN, "busy")

        with self.assertRaises(FileLockTimeoutV2) as captured:
            acquire_flock_v2(
                7,
                exclusive=True,
                timeout_seconds=0.12,
                timeout_code="INSTALLATION_LOCK_TIMEOUT",
                poll_interval_seconds=0.05,
                monotonic=clock,
                sleep=clock.sleep,
                flock=busy,
            )

        self.assertEqual("INSTALLATION_LOCK_TIMEOUT", captured.exception.code)
        self.assertEqual(0.12, captured.exception.timeout_seconds)
        self.assertAlmostEqual(0.12, sum(clock.sleeps))
        self.assertGreaterEqual(len(operations), 2)
        self.assertTrue(all(operation & fcntl.LOCK_NB for operation in operations))
        self.assertTrue(all(operation & fcntl.LOCK_EX for operation in operations))

    def test_busy_lock_can_be_acquired_before_deadline(self) -> None:
        clock = _MonotonicClock()
        attempts = 0

        def eventually_available(_descriptor: int, _operation: int) -> None:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise BlockingIOError(errno.EWOULDBLOCK, "busy")

        acquire_flock_v2(
            8,
            exclusive=False,
            timeout_seconds=1.0,
            timeout_code="OPERATION_JOURNAL_LOCK_TIMEOUT",
            poll_interval_seconds=0.1,
            monotonic=clock,
            sleep=clock.sleep,
            flock=eventually_available,
        )

        self.assertEqual(3, attempts)
        self.assertEqual([0.1, 0.1], clock.sleeps)

    def test_lock_is_not_acquired_on_an_attempt_after_deadline(self) -> None:
        clock = _MonotonicClock()
        attempts = 0

        def available_only_after_sleep(_descriptor: int, _operation: int) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise BlockingIOError(errno.EAGAIN, "busy")

        with self.assertRaises(FileLockTimeoutV2) as captured:
            acquire_flock_v2(
                8,
                exclusive=True,
                timeout_seconds=0.1,
                timeout_code="EXACT_DEADLINE_TIMEOUT",
                poll_interval_seconds=0.1,
                monotonic=clock,
                sleep=clock.sleep,
                flock=available_only_after_sleep,
            )

        self.assertEqual("EXACT_DEADLINE_TIMEOUT", captured.exception.code)
        self.assertEqual(1, attempts)

    def test_absolute_budget_is_shared_by_sequential_lock_waits(self) -> None:
        clock = _MonotonicClock()
        first_attempts = 0

        def first_lock(_descriptor: int, _operation: int) -> None:
            nonlocal first_attempts
            first_attempts += 1
            if first_attempts == 1:
                raise BlockingIOError(errno.EAGAIN, "busy")

        def second_lock(_descriptor: int, _operation: int) -> None:
            raise BlockingIOError(errno.EAGAIN, "busy")

        with lock_budget_v2(
            timeout_seconds=0.15,
            timeout_code="MUTATING_LOCK_BUDGET_TIMEOUT",
            monotonic=clock,
        ):
            acquire_flock_v2(
                10,
                exclusive=True,
                timeout_seconds=30.0,
                timeout_code="FIRST_LOCK_TIMEOUT",
                poll_interval_seconds=0.1,
                monotonic=clock,
                sleep=clock.sleep,
                flock=first_lock,
            )
            with self.assertRaises(FileLockTimeoutV2) as captured:
                acquire_flock_v2(
                    11,
                    exclusive=True,
                    timeout_seconds=30.0,
                    timeout_code="SECOND_LOCK_TIMEOUT",
                    poll_interval_seconds=0.1,
                    monotonic=clock,
                    sleep=clock.sleep,
                    flock=second_lock,
                )

        self.assertEqual(
            "MUTATING_LOCK_BUDGET_TIMEOUT", captured.exception.code
        )
        self.assertAlmostEqual(0.15, sum(clock.sleeps))

    def test_unexpected_lock_error_is_not_hidden_as_timeout(self) -> None:
        def broken(_descriptor: int, _operation: int) -> None:
            raise OSError(errno.EBADF, "bad descriptor")

        with self.assertRaises(OSError) as captured:
            acquire_flock_v2(
                9,
                exclusive=True,
                timeout_seconds=1.0,
                timeout_code="FILE_LOCK_TIMEOUT",
                flock=broken,
            )

        self.assertEqual(errno.EBADF, captured.exception.errno)

    def test_operation_journal_timeout_preserves_existing_bytes(self) -> None:
        from codex_smart_subagents.lifecycle_operation_v2 import (
            OperationJournalLockTimeoutV2,
            OperationJournalStoreV2,
        )

        with tempfile.TemporaryDirectory(dir="/tmp", prefix="lock-v2-") as raw:
            root = Path(raw)
            root.chmod(0o700)
            journal = root / "operation.json"
            lock = root / "operation.lock"
            original = b"journal-must-remain-byte-identical"
            journal.write_bytes(original)
            journal.chmod(0o600)
            store = OperationJournalStoreV2(
                journal_path=journal,
                lock_path=lock,
                validate_document=lambda _document: None,
            )
            timeout = FileLockTimeoutV2("OPERATION_JOURNAL_LOCK_TIMEOUT", 30.0)

            with mock.patch(
                "codex_smart_subagents.lifecycle_operation_v2."
                "finite_file_lock_v2.acquire_flock_v2",
                side_effect=timeout,
            ) as acquire:
                with self.assertRaises(OperationJournalLockTimeoutV2) as captured:
                    store.read()

            self.assertEqual(
                "OPERATION_JOURNAL_LOCK_TIMEOUT", captured.exception.code
            )
            self.assertEqual(30.0, acquire.call_args.kwargs["timeout_seconds"])
            self.assertEqual(original, journal.read_bytes())

    def test_installation_lock_timeout_has_public_exact_code(self) -> None:
        installer = _load_script(
            "install_adaptive_subagents_finite_lock_under_test",
            ROOT / "scripts" / "install_adaptive_subagents.py",
        )
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="install-lock-v2-") as raw:
            path = Path(raw) / "installer.lock"
            path.write_bytes(b"")
            path.chmod(0o600)
            timeout = FileLockTimeoutV2("INSTALLATION_LOCK_TIMEOUT", 30.0)

            with mock.patch.object(
                installer.finite_file_lock_v2,
                "acquire_flock_v2",
                side_effect=timeout,
            ) as acquire:
                with self.assertRaises(installer.InstallError) as captured:
                    with installer.installation_lock(path):
                        self.fail("busy lock must not enter its protected region")

            self.assertEqual("INSTALLATION_LOCK_TIMEOUT", captured.exception.code)
            self.assertEqual(30.0, acquire.call_args.kwargs["timeout_seconds"])

    def test_maintenance_lock_timeout_has_public_exact_code(self) -> None:
        from codex_smart_subagents.installer_maintenance_v2 import (
            InstallerMaintenanceV2Error,
            _installation_lock,
        )

        with tempfile.TemporaryDirectory(dir="/tmp", prefix="maint-lock-v2-") as raw:
            path = Path(raw) / "installer.lock"
            path.write_bytes(b"")
            path.chmod(0o600)
            timeout = FileLockTimeoutV2("INSTALLATION_LOCK_TIMEOUT", 30.0)

            with mock.patch(
                "codex_smart_subagents.installer_maintenance_v2."
                "finite_file_lock_v2.acquire_flock_v2",
                side_effect=timeout,
            ):
                with self.assertRaises(InstallerMaintenanceV2Error) as captured:
                    with _installation_lock(path):
                        self.fail("busy lock must not enter its protected region")

            self.assertEqual("INSTALLATION_LOCK_TIMEOUT", captured.exception.code)

    def test_nested_lock_preserves_absolute_budget_timeout_code(self) -> None:
        from codex_smart_subagents.activation_preparation_v2 import (
            ActivationPreparationLockTimeoutV2,
            _exclusive_lock,
        )

        with tempfile.TemporaryDirectory(dir="/tmp", prefix="prep-lock-v2-") as raw:
            path = Path(raw) / "preparation.lock"
            path.write_bytes(b"")
            path.chmod(0o600)
            timeout = FileLockTimeoutV2("RECOVERY_LOCK_BUDGET_TIMEOUT", 120.0)

            with mock.patch(
                "codex_smart_subagents.activation_preparation_v2."
                "finite_file_lock_v2.acquire_flock_v2",
                side_effect=timeout,
            ):
                with self.assertRaises(
                    ActivationPreparationLockTimeoutV2
                ) as captured:
                    with _exclusive_lock(path):
                        self.fail("busy lock must not enter its protected region")

            self.assertEqual(
                "RECOVERY_LOCK_BUDGET_TIMEOUT", captured.exception.code
            )

    def test_public_mutations_establish_one_absolute_lock_budget(self) -> None:
        installer = _load_script(
            "install_adaptive_subagents_lock_budget_under_test",
            ROOT / "scripts" / "install_adaptive_subagents.py",
        )
        observations: list[tuple[float, str]] = []

        @contextmanager
        def observe_budget(*, timeout_seconds: float, timeout_code: str):
            observations.append((timeout_seconds, timeout_code))
            yield

        layout = object()
        cases = (
            (
                "cleanup",
                600.0,
                "MUTATING_LOCK_BUDGET_TIMEOUT",
                "cleanup_installation_v2",
            ),
            (
                "recover",
                120.0,
                "RECOVERY_LOCK_BUDGET_TIMEOUT",
                "recover_installation_v2",
            ),
        )
        for command, seconds, code, target in cases:
            with self.subTest(command=command), mock.patch.object(
                installer, "default_layout", return_value=layout
            ), mock.patch.object(
                installer.finite_file_lock_v2,
                "lock_budget_v2",
                side_effect=observe_budget,
            ), mock.patch.object(
                installer,
                target,
                return_value={"status": "ok"},
            ):
                result = installer.execute_installer_invocation_v2(
                    SimpleNamespace(command=command, execute=True, retain_data=True)
                )
                self.assertEqual("ok", result["status"])
                self.assertEqual((seconds, code), observations[-1])

    def test_public_lock_timeout_is_proven_busy_with_exit_75(self) -> None:
        from codex_smart_subagents.installer_maintenance_v2 import (
            InstallerMaintenanceV2Error,
        )

        installer = _load_script(
            "install_adaptive_subagents_lock_busy_under_test",
            ROOT / "scripts" / "install_adaptive_subagents.py",
        )
        invocation = SimpleNamespace(
            command="cleanup",
            execute=True,
            retain_data=True,
            json=True,
        )
        published: list[dict[str, object]] = []

        def busy_cleanup(*_args, **_kwargs):
            try:
                raise FileLockTimeoutV2("INSTALLATION_LOCK_TIMEOUT", 30.0)
            except FileLockTimeoutV2 as cause:
                raise InstallerMaintenanceV2Error(
                    cause.code,
                    "установочная блокировка занята",
                ) from cause

        with mock.patch.object(
            installer, "parse_installer_argv_v2", return_value=invocation
        ), mock.patch.object(
            installer, "default_layout", return_value=object()
        ), mock.patch.object(
            installer,
            "cleanup_installation_v2",
            side_effect=busy_cleanup,
        ), mock.patch.object(
            installer,
            "_print_result",
            side_effect=lambda result, **_kwargs: published.append(result),
        ):
            exit_code = installer.main([])

        self.assertEqual(75, exit_code)
        self.assertEqual(1, len(published))
        self.assertEqual(
            "INSTALLATION_LOCK_TIMEOUT", published[0]["problems"][0]["code"]
        )
        self.assertEqual(
            "finite-file-lock-timeout-v2",
            published[0]["extensions"]["busyProof"]["proofKind"],
        )
        busy_proof = published[0]["extensions"]["busyProof"]
        self.assertIs(False, busy_proof.get("timedOutLockAcquired"))
        self.assertNotIn("protectedRegionEntered", busy_proof)
        encoded = json.dumps(
            published[0],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        self.assertEqual(published[0], json.loads(encoded))

    def test_public_busy_classifier_accepts_explicit_lock_timeout_cause(self) -> None:
        installer = _load_script(
            "install_adaptive_subagents_explicit_lock_cause_under_test",
            ROOT / "scripts" / "install_adaptive_subagents.py",
        )
        invocation = SimpleNamespace(command="cleanup", execute=True)

        def explicitly_caused_failure(*_args, **_kwargs):
            try:
                raise FileLockTimeoutV2("INSTALLATION_LOCK_TIMEOUT", 30.0)
            except FileLockTimeoutV2 as cause:
                raise RuntimeError("обёртка блокировки") from cause

        with mock.patch.object(
            installer,
            "_execute_installer_invocation_with_lock_budget_v2",
            side_effect=explicitly_caused_failure,
        ):
            with self.assertRaises(installer.ProvenTemporaryBusyV2) as captured:
                installer.execute_installer_invocation_v2(invocation)

        self.assertEqual(75, installer.exit_code_v2(captured.exception))
        self.assertEqual("INSTALLATION_LOCK_TIMEOUT", captured.exception.code)

    def test_suppressed_lock_context_is_not_proven_busy(self) -> None:
        installer = _load_script(
            "install_adaptive_subagents_suppressed_lock_context_under_test",
            ROOT / "scripts" / "install_adaptive_subagents.py",
        )
        invocation = SimpleNamespace(command="cleanup", execute=True)

        def independently_suppressed_failure(*_args, **_kwargs):
            try:
                raise FileLockTimeoutV2("INSTALLATION_LOCK_TIMEOUT", 30.0)
            except FileLockTimeoutV2:
                raise RuntimeError("независимая ошибка") from None

        with mock.patch.object(
            installer,
            "_execute_installer_invocation_with_lock_budget_v2",
            side_effect=independently_suppressed_failure,
        ):
            with self.assertRaises(RuntimeError) as captured:
                installer.execute_installer_invocation_v2(invocation)

        self.assertNotIsInstance(
            captured.exception, installer.ProvenTemporaryBusyV2
        )
        self.assertEqual(70, installer.exit_code_v2(captured.exception))

    def test_implicit_lock_context_is_not_proven_busy(self) -> None:
        installer = _load_script(
            "install_adaptive_subagents_implicit_lock_context_under_test",
            ROOT / "scripts" / "install_adaptive_subagents.py",
        )
        invocation = SimpleNamespace(command="cleanup", execute=True)

        def independently_implicit_failure(*_args, **_kwargs):
            try:
                raise FileLockTimeoutV2("INSTALLATION_LOCK_TIMEOUT", 30.0)
            except FileLockTimeoutV2:
                raise RuntimeError("независимая ошибка")

        with mock.patch.object(
            installer,
            "_execute_installer_invocation_with_lock_budget_v2",
            side_effect=independently_implicit_failure,
        ):
            with self.assertRaises(RuntimeError) as captured:
                installer.execute_installer_invocation_v2(invocation)

        self.assertNotIsInstance(
            captured.exception, installer.ProvenTemporaryBusyV2
        )
        self.assertEqual(70, installer.exit_code_v2(captured.exception))

    def test_reachable_v2_paths_do_not_use_blocking_flock(self) -> None:
        package = PLUGIN_SRC / "codex_smart_subagents"
        paths = tuple(sorted(package.glob("*_v2.py"))) + (
            ROOT / "scripts" / "install_adaptive_subagents.py",
            package / "codex_binary_snapshot.py",
            package / "installation_rollback.py",
            ROOT
            / "plugins"
            / "codex-smart-subagents"
            / "scripts"
            / "integration_runtime_v2.py",
            ROOT
            / "plugins"
            / "codex-smart-subagents"
            / "scripts"
            / "integration_runtime.py",
        )
        failures: list[str] = []
        for path in paths:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=os.fspath(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(
                    node.func, ast.Attribute
                ):
                    continue
                if node.func.attr != "flock" or not node.args:
                    continue
                operation = ast.unparse(node.args[-1])
                if "LOCK_UN" in operation or "LOCK_NB" in operation:
                    continue
                failures.append(
                    f"{path.relative_to(ROOT)}:{node.lineno}: {operation}"
                )

        self.assertEqual(
            [],
            failures,
            "blocking flock calls remain: " + "; ".join(failures),
        )


if __name__ == "__main__":
    unittest.main()
