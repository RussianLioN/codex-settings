from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import SourceDriftV1  # noqa: E402
from codex_smart_subagents.canonical_json import canonical_json_bytes  # noqa: E402
from codex_smart_subagents.installer_command_v2 import (  # noqa: E402
    build_lifecycle_command_result_v2,
)
from codex_smart_subagents.finite_file_lock_v2 import (  # noqa: E402
    FileLockTimeoutV2,
)
from codex_smart_subagents.source_reconciliation_v1 import (  # noqa: E402
    SourceReconciliationAcceptanceV1,
    SourceReconciliationRequestV1,
    reconcile_source_drift_v1,
)
import codex_smart_subagents.source_reconciliation_v1 as reconciliation  # noqa: E402


INCOMPATIBILITY_CODES = (
    "CODEX_VERSION_INCOMPATIBLE",
    "MODEL_CATALOG_INVALID",
    "MODEL_UNAVAILABLE",
    "MODEL_EFFORT_UNAVAILABLE",
    "INTERFACE_EVIDENCE_INVALID",
)


class SourceReconciliationV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="source-reconciliation-v1-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.updater_activation_id = "act2_" + "1" * 64
        self.new_activation_id = "act2_" + "2" * 64
        self.source_root = (
            self.root
            / "managed"
            / "activations"
            / self.updater_activation_id
            / "marketplace"
        )
        self.installer_path = (
            self.source_root / "scripts" / "install_adaptive_subagents.py"
        )
        self.installer_path.parent.mkdir(parents=True, mode=0o700)
        self.installer_path.write_text("# fixture\n", encoding="utf-8")
        self.installer_path.chmod(0o500)
        self.state_home = self.root / "state"
        self.state_home.mkdir(mode=0o700)
        self.codex_home = self.root / "codex-home"
        self.bin_dir = self.root / "bin"
        self.python_executable = self.root / "python"
        self.live_codex = self.root / "live" / "codex"
        self.resolved_codex = self.root / "resolved" / "codex"
        self.process_calls = 0
        self.process_lock = threading.Lock()
        self.observed_sha256 = "3" * 64
        self.drift = SourceDriftV1(
            lexical_path=self.live_codex,
            resolved_path=self.resolved_codex,
            observed_sha256=self.observed_sha256,
            expected_sha256="4" * 64,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self) -> SourceReconciliationRequestV1:
        return SourceReconciliationRequestV1(
            drift=self.drift,
            updater_activation_id=self.updater_activation_id,
            updater_release="0.2.0",
            updater_source_digest="5" * 64,
            source_root=self.source_root,
            installer_path=self.installer_path,
            python_executable=self.python_executable,
            codex_home=self.codex_home,
            bin_dir=self.bin_dir,
            state_home=self.state_home,
        )

    def acceptance(self, **changes: object) -> SourceReconciliationAcceptanceV1:
        values: dict[str, object] = {
            "activation_id": self.new_activation_id,
            "source_lexical_path": self.live_codex,
            "source_resolved_path": self.resolved_codex,
            "source_sha256": self.observed_sha256,
            "snapshot_sha256": self.observed_sha256,
            "installer_receipt_activation_id": self.new_activation_id,
        }
        values.update(changes)
        return SourceReconciliationAcceptanceV1(**values)  # type: ignore[arg-type]

    def accepted_activation(self) -> SourceReconciliationAcceptanceV1:
        return self.acceptance()

    @staticmethod
    def no_accepted_activation() -> None:
        return None

    def lifecycle_result(
        self,
        *,
        status: str = "upgraded",
        readiness: str = "READY",
        problems: tuple[dict[str, str], ...] = (),
    ) -> dict[str, object]:
        return build_lifecycle_command_result_v2(
            command="apply",
            status=status,
            readiness=readiness,
            operation_id="op2_" + "6" * 32,
            attempt_id="opa2_" + "7" * 32,
            problems=problems,
            extensions={"activeActivationId": self.new_activation_id},
        )

    def completed(
        self, result: dict[str, object], *, returncode: int = 0
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=["installer"],
            returncode=returncode,
            stdout=canonical_json_bytes(result) + b"\n",
            stderr=b"",
        )

    def accepted_process(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> subprocess.CompletedProcess[bytes]:
        del argv, timeout_seconds, max_output_bytes
        with self.process_lock:
            self.process_calls += 1
        return self.completed(self.lifecycle_result())

    def incompatible_process(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        code: str = "CODEX_VERSION_INCOMPATIBLE",
    ) -> subprocess.CompletedProcess[bytes]:
        del argv, timeout_seconds, max_output_bytes
        with self.process_lock:
            self.process_calls += 1
        result = self.lifecycle_result(
            status="failed",
            readiness="BROKEN",
            problems=(
                {
                    "code": code,
                    "severity": "error",
                    "component": "compatibility",
                    "message": "candidate is incompatible",
                    "remediation": "keep the verified snapshot",
                },
            ),
        )
        return self.completed(result, returncode=2)

    def temporary_failure(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> subprocess.CompletedProcess[bytes]:
        del argv, timeout_seconds, max_output_bytes
        with self.process_lock:
            self.process_calls += 1
        return subprocess.CompletedProcess(
            args=["installer"], returncode=70, stdout=b"", stderr=b"failure"
        )

    def must_not_run(self, *_args: object, **_kwargs: object) -> object:
        self.fail("installer process must not run")

    def reconcile_accepted(self):
        return reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.accepted_activation,
            run_process=self.accepted_process,
        )

    def test_request_and_acceptance_are_closed_and_path_bound(self) -> None:
        request = self.request()
        self.assertEqual(request.source_root, request.installer_path.parents[1])
        self.assertEqual("marketplace", request.source_root.name)
        self.assertEqual(
            request.updater_activation_id, request.source_root.parent.name
        )

        for name in (
            "source_root",
            "installer_path",
            "python_executable",
            "codex_home",
            "bin_dir",
            "state_home",
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    replace(request, **{name: Path("relative")})

        with self.assertRaises(ValueError):
            replace(request, installer_path=request.source_root / "wrong.py")
        with self.assertRaises(ValueError):
            replace(request, installer_path=Path("/installer.py"))
        with self.assertRaises(ValueError):
            replace(request, updater_activation_id="foreign")
        with self.assertRaises(ValueError):
            replace(
                request,
                source_root=(
                    self.root / "managed" / "activations" / "foreign" / "marketplace"
                ),
            )
        with self.assertRaises(ValueError):
            replace(self.acceptance(), source_lexical_path=Path("relative"))
        with self.assertRaises(ValueError):
            replace(self.acceptance(), activation_id="act2_malformed")
        with self.assertRaises(ValueError):
            replace(
                self.acceptance(),
                installer_receipt_activation_id="act2_malformed",
            )

    def test_incompatible_receipt_suppresses_same_binary_and_updater(self) -> None:
        first = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.incompatible_process,
        )
        second = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.must_not_run,
        )

        self.assertEqual("INCOMPATIBLE", first.outcome)
        self.assertEqual("CODEX_VERSION_INCOMPATIBLE", first.reason_code)
        self.assertEqual(first, second)
        self.assertFalse(first.restart)
        self.assertIsNone(first.retry_after_epoch_seconds)
        self.assertEqual(1, self.process_calls)

    def test_every_exact_incompatibility_code_is_terminal(self) -> None:
        for code in INCOMPATIBILITY_CODES:
            with self.subTest(code=code):
                receipt = self.state_home / "source-reconciliation-v1.json"
                receipt.unlink(missing_ok=True)
                result = reconcile_source_drift_v1(
                    self.request(),
                    verify_accepted=self.no_accepted_activation,
                    run_process=lambda argv, **kwargs: self.incompatible_process(
                        argv, code=code, **kwargs
                    ),
                )
                self.assertEqual("INCOMPATIBLE", result.outcome)
                self.assertEqual(code, result.reason_code)

    def test_changed_binary_or_updater_release_reopens_reconciliation(self) -> None:
        reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.incompatible_process,
        )
        changed = replace(self.request(), updater_release="0.2.1")
        accepted = reconcile_source_drift_v1(
            changed,
            verify_accepted=self.accepted_activation,
            run_process=self.accepted_process,
        )

        self.assertEqual("ACCEPTED", accepted.outcome)
        self.assertEqual(2, self.process_calls)

    def test_changed_observed_binary_identity_reopens_reconciliation(self) -> None:
        reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.incompatible_process,
        )
        changed_sha256 = "a" * 64
        changed_request = replace(
            self.request(),
            drift=replace(self.drift, observed_sha256=changed_sha256),
        )
        changed_acceptance = self.acceptance(
            source_sha256=changed_sha256,
            snapshot_sha256=changed_sha256,
        )

        accepted = reconcile_source_drift_v1(
            changed_request,
            verify_accepted=lambda: changed_acceptance,
            run_process=self.accepted_process,
        )

        self.assertEqual("ACCEPTED", accepted.outcome)
        self.assertEqual(2, self.process_calls)

    def test_retry_after_uses_exact_300_second_window(self) -> None:
        first = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.temporary_failure,
            now_epoch_seconds=lambda: 1000,
        )
        self.assertEqual(1300, first.retry_after_epoch_seconds)
        paused = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.must_not_run,
            now_epoch_seconds=lambda: 1299,
        )
        accepted = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.accepted_activation,
            run_process=self.accepted_process,
            now_epoch_seconds=lambda: 1300,
        )

        self.assertEqual(first, paused)
        self.assertEqual("ACCEPTED", accepted.outcome)
        self.assertEqual(2, self.process_calls)

    def test_retry_window_starts_after_the_failed_process_finishes(self) -> None:
        observed_time = [1000]

        def process(*args: object, **kwargs: object) -> object:
            observed_time[0] = 1180
            return self.temporary_failure(*args, **kwargs)  # type: ignore[arg-type]

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=process,
            now_epoch_seconds=lambda: observed_time[0],
        )

        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertEqual(1480, result.retry_after_epoch_seconds)

    def test_busy_reconciliation_lock_is_retryable_without_a_process(self) -> None:
        timeout = FileLockTimeoutV2(
            "SOURCE_RECONCILIATION_LOCK_TIMEOUT", 30.0
        )
        with mock.patch(
            "codex_smart_subagents.source_reconciliation_v1.acquire_flock_v2",
            side_effect=timeout,
        ):
            result = reconcile_source_drift_v1(
                self.request(),
                verify_accepted=self.accepted_activation,
                run_process=self.must_not_run,
                now_epoch_seconds=lambda: 1000,
            )

        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertEqual("SOURCE_RECONCILIATION_LOCK_TIMEOUT", result.reason_code)
        self.assertEqual(1300, result.retry_after_epoch_seconds)
        self.assertFalse(result.restart)
        self.assertEqual(0, self.process_calls)

    def test_first_lock_creation_race_does_not_lose_reconciliation(self) -> None:
        real_open = os.open
        real_close = os.close
        injected = False

        def open_with_creation_race(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal injected
            if (
                path == "source-reconciliation-v1.lock"
                and flags & os.O_CREAT
                and not injected
            ):
                injected = True
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                real_close(descriptor)
                if flags & os.O_EXCL:
                    raise FileExistsError(errno.EEXIST, "created concurrently")
                raise FileNotFoundError(errno.ENOENT, "created concurrently")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(reconciliation.os, "open", open_with_creation_race):
            result = reconcile_source_drift_v1(
                self.request(),
                verify_accepted=self.accepted_activation,
                run_process=self.accepted_process,
            )

        self.assertTrue(injected)
        self.assertEqual("ACCEPTED", result.outcome)
        self.assertEqual(1, self.process_calls)

    def test_tampered_receipt_closes_path_and_never_authorizes_restart(self) -> None:
        receipt = {
            "schemaVersion": 1,
            "source": {
                "lexicalPath": str(self.live_codex),
                "resolvedPath": str(self.resolved_codex),
                "sha256": self.observed_sha256,
            },
            "updater": {
                "activationId": self.updater_activation_id,
                "release": "0.2.0",
                "sourceDigest": "5" * 64,
            },
            "outcome": "ACCEPTED",
            "reasonCode": "SOURCE_RECONCILIATION_ACCEPTED",
            "retryAfterEpochSeconds": None,
            "acceptedActivationId": self.new_activation_id,
            "receiptFingerprint": "f" * 64,
        }
        path = self.state_home / "source-reconciliation-v1.json"
        path.write_bytes(canonical_json_bytes(receipt))
        path.chmod(0o600)

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.accepted_activation,
            run_process=self.must_not_run,
            now_epoch_seconds=lambda: 1000,
        )

        self.assertFalse(result.restart)
        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertEqual(1300, result.retry_after_epoch_seconds)
        self.assertEqual("SOURCE_RECONCILIATION_RECEIPT_INVALID", result.reason_code)

    def test_noncanonical_or_public_receipt_closes_path(self) -> None:
        first = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.temporary_failure,
            now_epoch_seconds=lambda: 1000,
        )
        self.assertEqual("RETRY_AFTER", first.outcome)
        path = self.state_home / "source-reconciliation-v1.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        path.chmod(0o644)

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.must_not_run,
            now_epoch_seconds=lambda: 1001,
        )

        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertEqual("SOURCE_RECONCILIATION_RECEIPT_INVALID", result.reason_code)

    def test_parallel_calls_execute_installer_once(self) -> None:
        def delayed_process(*args: object, **kwargs: object) -> object:
            time.sleep(0.05)
            return self.accepted_process(*args, **kwargs)  # type: ignore[arg-type]

        def reconcile():
            return reconcile_source_drift_v1(
                self.request(),
                verify_accepted=self.accepted_activation,
                run_process=delayed_process,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _item: reconcile(), range(2)))

        self.assertEqual(1, self.process_calls)
        self.assertEqual([True, True], [result.restart for result in results])
        self.assertTrue(all(result.outcome == "ACCEPTED" for result in results))

    def test_old_or_foreign_activation_cannot_be_accepted(self) -> None:
        acceptances = (
            self.acceptance(activation_id=self.updater_activation_id),
            self.acceptance(source_lexical_path=self.root / "other-codex"),
            self.acceptance(source_resolved_path=self.root / "other-resolved"),
            self.acceptance(source_sha256="e" * 64),
            self.acceptance(snapshot_sha256="e" * 64),
            self.acceptance(installer_receipt_activation_id="act2_" + "e" * 64),
        )
        for acceptance in acceptances:
            with self.subTest(acceptance=acceptance):
                (self.state_home / "source-reconciliation-v1.json").unlink(
                    missing_ok=True
                )
                result = reconcile_source_drift_v1(
                    self.request(),
                    verify_accepted=lambda: acceptance,
                    run_process=self.accepted_process,
                    now_epoch_seconds=lambda: 1000,
                )
                self.assertFalse(result.restart)
                self.assertEqual("RETRY_AFTER", result.outcome)
                self.assertEqual(
                    "SOURCE_RECONCILIATION_ACCEPTANCE_UNVERIFIED",
                    result.reason_code,
                )

    def test_cached_accepted_receipt_is_rechecked_against_active_manifest(self) -> None:
        first = self.reconcile_accepted()
        self.assertTrue(first.restart)
        calls_before = self.process_calls

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=lambda: self.acceptance(
                activation_id="act2_" + "9" * 64,
                installer_receipt_activation_id="act2_" + "9" * 64,
            ),
            run_process=self.must_not_run,
            now_epoch_seconds=lambda: 1000,
        )

        self.assertFalse(result.restart)
        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertEqual(calls_before, self.process_calls)

    def test_temporary_manifest_failure_preserves_accepted_suppression(self) -> None:
        first = self.reconcile_accepted()
        self.assertTrue(first.restart)
        calls_before = self.process_calls

        unavailable = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=self.must_not_run,
            now_epoch_seconds=lambda: 1000,
        )
        recovered = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.accepted_activation,
            run_process=self.must_not_run,
            now_epoch_seconds=lambda: 2000,
        )

        self.assertEqual("RETRY_AFTER", unavailable.outcome)
        self.assertFalse(unavailable.restart)
        self.assertEqual("ACCEPTED", recovered.outcome)
        self.assertTrue(recovered.restart)
        self.assertEqual(calls_before, self.process_calls)

    def test_success_uses_exact_argv_deadline_output_limit_and_private_receipt(
        self,
    ) -> None:
        observed: dict[str, object] = {}

        def process(
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            max_output_bytes: int,
        ) -> subprocess.CompletedProcess[bytes]:
            observed.update(
                argv=argv,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
            return self.accepted_process(
                argv,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.accepted_activation,
            run_process=process,
        )

        self.assertTrue(result.restart)
        self.assertEqual(
            (
                str(self.python_executable),
                "-B",
                str(self.installer_path),
                "--source-root",
                str(self.source_root),
                "--codex-home",
                str(self.codex_home),
                "--bin-dir",
                str(self.bin_dir),
                "--state-home",
                str(self.state_home),
                "--codex-binary",
                str(self.live_codex),
                "--apply",
                "--json",
            ),
            observed["argv"],
        )
        self.assertEqual(180.0, observed["timeout_seconds"])
        self.assertEqual(1024 * 1024, observed["max_output_bytes"])
        receipt = self.state_home / "source-reconciliation-v1.json"
        self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))
        raw = receipt.read_bytes()
        self.assertEqual(raw, canonical_json_bytes(json.loads(raw)))

    def test_exit_zero_with_invalid_v2_result_is_retryable(self) -> None:
        def invalid(
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            max_output_bytes: int,
        ) -> subprocess.CompletedProcess[bytes]:
            del argv, timeout_seconds, max_output_bytes
            self.process_calls += 1
            return subprocess.CompletedProcess(
                args=["installer"],
                returncode=0,
                stdout=b'{"schemaVersion":2,"readiness":"READY"}\n',
                stderr=b"",
            )

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.accepted_activation,
            run_process=invalid,
            now_epoch_seconds=lambda: 1000,
        )

        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertFalse(result.restart)
        self.assertEqual("SOURCE_RECONCILIATION_RESULT_INVALID", result.reason_code)

    def test_incompatibility_from_non_apply_result_is_only_retryable(self) -> None:
        doctor = build_lifecycle_command_result_v2(
            command="doctor",
            status="BROKEN",
            readiness="BROKEN",
            problems=(
                {
                    "code": "CODEX_VERSION_INCOMPATIBLE",
                    "severity": "error",
                    "component": "compatibility",
                    "message": "unrelated doctor result",
                    "remediation": "run the apply command",
                },
            ),
        )

        def wrong_command(
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            max_output_bytes: int,
        ) -> subprocess.CompletedProcess[bytes]:
            del argv, timeout_seconds, max_output_bytes
            self.process_calls += 1
            return self.completed(doctor, returncode=2)

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=wrong_command,
            now_epoch_seconds=lambda: 1000,
        )

        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertFalse(result.restart)

    def test_incompatibility_with_inconsistent_zero_exit_is_only_retryable(
        self,
    ) -> None:
        incompatible = self.lifecycle_result(
            status="failed",
            readiness="BROKEN",
            problems=(
                {
                    "code": "CODEX_VERSION_INCOMPATIBLE",
                    "severity": "error",
                    "component": "compatibility",
                    "message": "candidate is incompatible",
                    "remediation": "keep the verified snapshot",
                },
            ),
        )

        def inconsistent_exit(
            argv: tuple[str, ...],
            *,
            timeout_seconds: float,
            max_output_bytes: int,
        ) -> subprocess.CompletedProcess[bytes]:
            del argv, timeout_seconds, max_output_bytes
            self.process_calls += 1
            return self.completed(incompatible, returncode=0)

        result = reconcile_source_drift_v1(
            self.request(),
            verify_accepted=self.no_accepted_activation,
            run_process=inconsistent_exit,
            now_epoch_seconds=lambda: 1000,
        )

        self.assertEqual("RETRY_AFTER", result.outcome)
        self.assertFalse(result.restart)


if __name__ == "__main__":
    unittest.main()
