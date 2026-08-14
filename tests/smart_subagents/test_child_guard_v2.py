from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    ChildGuardV2Error,
    ForkExecGuardFactoryV2,
    _child_guard_main,
    _terminate_and_reap,
    system_process_start_marker_v2,
)
from codex_smart_subagents.child_launch_v2 import (  # noqa: E402
    PreparedChildLaunchV2,
    child_argv_fingerprint_v2,
    child_environment_fingerprints_v1,
)
from codex_smart_subagents.production_proofs_v2 import (  # noqa: E402
    CodexSnapshotDescriptorProbeV2,
)


@dataclass(frozen=True)
class SnapshotObservationV2:
    snapshot_sha256: str
    snapshot_identity_fingerprint: str


class _AttemptResource:
    def attest(self, *_arguments: object):
        raise AssertionError("guard test must not attest")

    def close(self) -> None:
        return None


class ForkExecGuardV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.marker = self.root / "executed"
        self.executable = self.root / "codex"
        self.executable.write_text(
            "#!/bin/sh\n"
            'printf executed > "$GUARD_TEST_MARKER"\n'
            "IFS= read -r mission\n"
            "printf '%s\\n' "
            '\'{"type":"thread.started","thread_id":"guard-test"}\'\n'
            "printf '%s\\n' "
            '\'{"type":"turn.completed","usage":{}}\'\n'
            'printf "%s" "$mission" >&2\n',
            encoding="utf-8",
        )
        self.executable.chmod(0o500)
        self.snapshot_sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        self.identity = CodexSnapshotDescriptorProbeV2()(
            self.executable,
            self.snapshot_sha,
        ).snapshot_identity_fingerprint
        argv = (str(self.executable), "exec", "--json")
        non_secret_environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "GUARD_TEST_MARKER": str(self.marker),
        }
        raw_headers = "X-Test=bounded-guard-fixture"
        environment = MappingProxyType(
            {
                **non_secret_environment,
                "OTEL_EXPORTER_OTLP_HEADERS": raw_headers,
            }
        )
        environment_fingerprint, secret_sha256 = child_environment_fingerprints_v1(
            non_secret_environment=non_secret_environment,
            raw_otel_headers=raw_headers,
            environment_domain="codex-smart/environment/v1",
            secret_domain="codex-smart/launch-secret/v1",
        )
        self.prepared = PreparedChildLaunchV2(
            executable=self.executable,
            argv=argv,
            environment=environment,
            stdin=b"mission-v2\n",
            argv_fingerprint=child_argv_fingerprint_v2(
                argv=argv,
            ),
            snapshot_sha256=self.snapshot_sha,
            snapshot_identity_fingerprint=self.identity,
            model="catalog-model",
            reasoning_effort="catalog-effort",
            permission_profile_id="reader-v2",
            argv_domain="codex-smart/argv/v2",
            environment_domain="codex-smart/environment/v1",
            secret_domain="codex-smart/launch-secret/v1",
            non_secret_environment=MappingProxyType(non_secret_environment),
            environment_fingerprint=environment_fingerprint,
            secret_sha256=secret_sha256,
            compatibility_fingerprint="b" * 64,
            account_context_fingerprint="c" * 64,
            expected_cli_version="0.107.0-test",
            role="reader",
            attempt_resource=_AttemptResource(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_separate_guard_does_not_exec_until_exact_commit(self) -> None:
        def snapshot_probe(_prepared):
            return SnapshotObservationV2(
                snapshot_sha256=self.snapshot_sha,
                snapshot_identity_fingerprint=self.identity,
            )

        handle = ForkExecGuardFactoryV2().start(
            self.prepared,
            permit_id="lp2_" + "c" * 32,
            one_time_token="guard-token-abcdefghijklmnopqrstuvwxyz-123456",
            snapshot_probe=snapshot_probe,
        )
        try:
            hello = handle.receive_hello(timeout_seconds=2)
            self.assertNotEqual(os.getpid(), hello.pid)
            self.assertFalse(self.marker.exists())
            self.assertEqual(self.identity, hello.snapshot_identity_fingerprint)

            confirmation = handle.authorize_commit(
                "guard-token-abcdefghijklmnopqrstuvwxyz-123456",
                timeout_seconds=2,
            )
            self.assertEqual(hello.pid, confirmation.pid)
            result = handle.collect(
                self.prepared.stdin,
                timeout_seconds=5,
                max_output_bytes=64 * 1024,
            )
        finally:
            handle.abort()

        self.assertEqual(0, result.exit_code)
        self.assertTrue(self.marker.is_file())
        self.assertIn(b'"turn.completed"', result.stdout)
        self.assertEqual(b"mission-v2", result.stderr)

    def test_start_never_calls_fork(self) -> None:
        with patch(
            "codex_smart_subagents.child_guard_v2.os.fork",
            side_effect=AssertionError("fork is forbidden"),
        ):
            handle = ForkExecGuardFactoryV2().start(
                self.prepared,
                permit_id="lp2_" + "e" * 32,
                one_time_token="guard-token-abcdefghijklmnopqrstuvwxyz-000001",
                snapshot_probe=lambda _prepared: SnapshotObservationV2(
                    snapshot_sha256=self.snapshot_sha,
                    snapshot_identity_fingerprint=self.identity,
                ),
            )
            try:
                hello = handle.receive_hello(timeout_seconds=2)
                handle.authorize_commit(
                    "guard-token-abcdefghijklmnopqrstuvwxyz-000001",
                    timeout_seconds=2,
                )
                result = handle.collect(
                    self.prepared.stdin,
                    timeout_seconds=5,
                    max_output_bytes=64 * 1024,
                )
            finally:
                handle.abort()

        self.assertGreater(hello.pid, 0)
        self.assertEqual(0, result.exit_code)

    def test_lock_held_by_another_thread_cannot_stall_fresh_guard(self) -> None:
        inherited_lock = threading.Lock()
        acquired = threading.Event()
        release = threading.Event()

        def holder() -> None:
            with inherited_lock:
                acquired.set()
                release.wait(timeout=5)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(acquired.wait(timeout=2))

        def blocked_in_a_forked_child(_prepared):
            with inherited_lock:
                return SnapshotObservationV2(
                    snapshot_sha256=self.snapshot_sha,
                    snapshot_identity_fingerprint=self.identity,
                )

        handle = ForkExecGuardFactoryV2().start(
            self.prepared,
            permit_id="lp2_" + "f" * 32,
            one_time_token="guard-token-abcdefghijklmnopqrstuvwxyz-000002",
            snapshot_probe=blocked_in_a_forked_child,
        )
        try:
            hello = handle.receive_hello(timeout_seconds=2)
        finally:
            handle.abort()
            release.set()
            thread.join(timeout=2)

        self.assertGreater(hello.pid, 0)
        self.assertFalse(thread.is_alive())

    def test_hello_contains_fresh_system_process_start_marker(self) -> None:
        handle = ForkExecGuardFactoryV2().start(
            self.prepared,
            permit_id="lp2_" + "d" * 32,
            one_time_token="guard-token-abcdefghijklmnopqrstuvwxyz-654321",
            snapshot_probe=lambda _prepared: SnapshotObservationV2(
                snapshot_sha256=self.snapshot_sha,
                snapshot_identity_fingerprint=self.identity,
            ),
        )
        try:
            hello = handle.receive_hello(timeout_seconds=2)
            self.assertEqual(
                system_process_start_marker_v2(hello.pid),
                hello.process_start_marker,
            )
        finally:
            handle.abort()

    def test_spawned_guard_is_its_own_session_and_process_group_leader(self) -> None:
        handle = ForkExecGuardFactoryV2().start(
            self.prepared,
            permit_id="lp2_" + "1" * 32,
            one_time_token="guard-token-abcdefghijklmnopqrstuvwxyz-000003",
            snapshot_probe=lambda _prepared: SnapshotObservationV2(
                snapshot_sha256=self.snapshot_sha,
                snapshot_identity_fingerprint=self.identity,
            ),
        )
        try:
            hello = handle.receive_hello(timeout_seconds=2)
            self.assertEqual(hello.pid, os.getsid(hello.pid))
            self.assertEqual(hello.pid, os.getpgid(hello.pid))
        finally:
            handle.abort()

    def test_two_parallel_real_guards_keep_protocol_frames_separate(self) -> None:
        handles = [
            ForkExecGuardFactoryV2().start(
                self.prepared,
                permit_id="lp2_" + digit * 32,
                one_time_token=(
                    "guard-token-abcdefghijklmnopqrstuvwxyz-00000" + digit
                ),
                snapshot_probe=lambda _prepared: SnapshotObservationV2(
                    snapshot_sha256=self.snapshot_sha,
                    snapshot_identity_fingerprint=self.identity,
                ),
            )
            for digit in ("4", "5")
        ]
        try:
            hellos = [handle.receive_hello(timeout_seconds=2) for handle in handles]
            for handle, digit in zip(handles, ("4", "5"), strict=True):
                handle.authorize_commit(
                    "guard-token-abcdefghijklmnopqrstuvwxyz-00000" + digit,
                    timeout_seconds=2,
                )
            results = [
                handle.collect(
                    self.prepared.stdin,
                    timeout_seconds=5,
                    max_output_bytes=64 * 1024,
                )
                for handle in handles
            ]
        finally:
            for handle in handles:
                handle.abort()

        self.assertEqual(2, len({hello.pid for hello in hellos}))
        self.assertEqual([0, 0], [result.exit_code for result in results])

    def test_wrong_commit_token_never_executes_mission(self) -> None:
        handle = ForkExecGuardFactoryV2().start(
            self.prepared,
            permit_id="lp2_" + "6" * 32,
            one_time_token="guard-token-abcdefghijklmnopqrstuvwxyz-000006",
            snapshot_probe=lambda _prepared: SnapshotObservationV2(
                snapshot_sha256=self.snapshot_sha,
                snapshot_identity_fingerprint=self.identity,
            ),
        )
        try:
            handle.receive_hello(timeout_seconds=2)
            with self.assertRaises(ChildGuardV2Error) as captured:
                handle.authorize_commit(
                    "guard-token-abcdefghijklmnopqrstuvwxyz-wrong6",
                    timeout_seconds=2,
                )
            self.assertEqual("GUARD_TOKEN_MISMATCH", captured.exception.code)
        finally:
            handle.abort()

        self.assertFalse(self.marker.exists())

    def test_guard_waits_long_enough_for_verified_commit_without_unbounded_wait(
        self,
    ) -> None:
        permit_id = "lp2_" + "7" * 32
        one_time_token = "guard-token-abcdefghijklmnopqrstuvwxyz-000007"
        simulated_coordinator_seconds = 120.0
        observed_timeouts: list[float] = []
        expected_commit = {
            "frame": "COMMIT",
            "protocolVersion": 2,
            "permitId": permit_id,
            "oneTimeToken": one_time_token,
            "argvFingerprint": self.prepared.argv_fingerprint,
            "snapshotIdentityFingerprint": self.prepared.snapshot_identity_fingerprint,
        }

        def delayed_commit(_descriptor: int, timeout_seconds: float, **_kwargs):
            observed_timeouts.append(timeout_seconds)
            if timeout_seconds < simulated_coordinator_seconds:
                raise ChildGuardV2Error(
                    "GUARD_DEADLINE",
                    "simulated coordinator verification delay exceeded guard wait",
                )
            return expected_commit

        with (
            patch("codex_smart_subagents.child_guard_v2.os.setsid"),
            patch("codex_smart_subagents.child_guard_v2.fcntl.fcntl"),
            patch("codex_smart_subagents.child_guard_v2._write_frame"),
            patch("codex_smart_subagents.child_guard_v2._read_frame", delayed_commit),
            patch("codex_smart_subagents.child_guard_v2._close_fd"),
            patch("codex_smart_subagents.child_guard_v2._close_many"),
            patch("codex_smart_subagents.child_guard_v2.os.dup2"),
            patch("codex_smart_subagents.child_guard_v2.os.umask"),
            patch("codex_smart_subagents.child_guard_v2._reset_signals"),
            patch(
                "codex_smart_subagents.child_guard_v2.os.execve",
            ) as execve,
            patch(
                "codex_smart_subagents.child_guard_v2.os._exit",
                side_effect=AssertionError("guard exited before COMMIT"),
            ),
        ):
            _child_guard_main(
                prepared=self.prepared,
                permit_id=permit_id,
                one_time_token=one_time_token,
                snapshot_probe=lambda _prepared: SnapshotObservationV2(
                    snapshot_sha256=self.snapshot_sha,
                    snapshot_identity_fingerprint=self.identity,
                ),
                process_start_marker_provider=lambda _pid: "marker",
                control_fd=10,
                hello_fd=11,
                error_fd=12,
                stdin_fd=0,
                stdout_fd=1,
                stderr_fd=2,
            )

        self.assertEqual(1, len(observed_timeouts))
        self.assertGreaterEqual(observed_timeouts[0], simulated_coordinator_seconds)
        self.assertLessEqual(observed_timeouts[0], 180.0)
        execve.assert_called_once()

    def test_system_marker_distinguishes_a_process_awaiting_collection(self) -> None:
        process = subprocess.Popen(["/bin/sleep", "30"])
        observed_code = None
        try:
            self.assertTrue(system_process_start_marker_v2(process.pid))
            process.terminate()
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                try:
                    system_process_start_marker_v2(process.pid)
                except ChildGuardV2Error as exc:
                    observed_code = exc.code
                    break
                time.sleep(0.01)
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=2.0)

        self.assertEqual("PROCESS_NOT_RUNNING", observed_code)

    def test_termination_falls_back_to_pid_and_never_blocks_on_waitpid(self) -> None:
        with (
            patch(
                "codex_smart_subagents.child_guard_v2.os.waitpid",
                side_effect=[(0, 0), (7001, 9)],
            ),
            patch(
                "codex_smart_subagents.child_guard_v2.os.killpg",
                side_effect=ProcessLookupError,
            ),
            patch("codex_smart_subagents.child_guard_v2.os.kill") as kill,
        ):
            self.assertTrue(_terminate_and_reap(7001, timeout_seconds=0.1))

        kill.assert_called_once_with(7001, 9)


if __name__ == "__main__":
    unittest.main()
