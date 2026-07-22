from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.operation_deadline_v2 import (  # noqa: E402
    OperationDeadlineExceededV2,
    OperationDeadlineV2,
    scoped_current_deadline_v2,
)
from codex_smart_subagents.operation_process_group_supervisor_v2 import (  # noqa: E402
    DurableProcessOwnershipCallbackErrorV2,
    OperationProcessGroupSupervisorV2,
)
from codex_smart_subagents import supervised_subprocess_v2  # noqa: E402
from codex_smart_subagents.supervised_subprocess_v2 import (  # noqa: E402
    SupervisedCommandCleanupRequiredV2,
    SupervisedCommandOutputLimitExceededV2,
    run_supervised_command_v2,
)


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "killpg"),
    "requires POSIX process groups",
)
class SupervisedSubprocessV2Tests(unittest.TestCase):
    def test_durable_publication_failure_closes_gate_before_target_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="supervised-gated-spawn-v2-"
        ) as raw:
            marker = Path(raw) / "target-opened"
            captured: list[object] = []

            def fail_publication(lease, _context):
                captured.append(lease)
                raise RuntimeError("forced durable publication failure")

            supervisor = OperationProcessGroupSupervisorV2(
                ownership_publisher=fail_publication,
                ownership_transition=lambda *_args: None,
            )
            deadline = OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=3,
                timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
            )

            with self.assertRaises(
                DurableProcessOwnershipCallbackErrorV2
            ) as caught:
                supervised_subprocess_v2.spawn_gated_transient_v2(
                    argv=(
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; "
                        "Path(sys.argv[1]).write_text('opened')",
                        str(marker),
                    ),
                    label="initial-controller",
                    gate_deadline=deadline,
                    cleanup_deadline=deadline,
                    cleanup_wait_seconds=1,
                    supervisor=supervisor,
                )

            self.assertIsInstance(caught.exception.__cause__, RuntimeError)
            self.assertEqual(1, len(captured))
            lease = captured[0]
            process = lease.process
            self.assertEqual(125, process.wait(timeout=2))
            self.assertFalse(marker.exists())
            self.assertEqual(
                (lease.lease_id,), supervisor.owned_lease_ids()
            )
            self.assertEqual(
                (lease.lease_id,), supervisor.reconcile_completed_transients()
            )
            self.assertEqual((), supervisor.owned_lease_ids())

    def test_fast_commands_are_registered_before_the_target_can_exit(self) -> None:
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=5,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
        )
        supervisor = OperationProcessGroupSupervisorV2()

        with scoped_current_deadline_v2(deadline):
            for _ in range(20):
                result = run_supervised_command_v2(
                    argv=("/usr/bin/printf", "hello"),
                    label="fast-command",
                    local_timeout_seconds=1,
                    cleanup_wait_seconds=0.5,
                    supervisor=supervisor,
                )

        self.assertEqual(0, result.returncode)
        self.assertEqual(b"hello", result.stdout)
        self.assertEqual(b"", result.stderr)
        self.assertEqual((), supervisor.owned_lease_ids())
        self.assertEqual((), supervisor.unverified_launch_ids())

    def test_nonzero_exit_and_bounded_stdin_stdout_stderr_are_returned(self) -> None:
        code = (
            "import sys;"
            "data=sys.stdin.buffer.read();"
            "sys.stdout.buffer.write(data.upper());"
            "sys.stderr.buffer.write(b'problem');"
            "raise SystemExit(7)"
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=3,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
        )

        result = run_supervised_command_v2(
            argv=(sys.executable, "-c", code),
            label="io-command",
            stdin=b"payload",
            local_timeout_seconds=1,
            cleanup_wait_seconds=0.5,
            max_output_bytes=1024,
            deadline=deadline,
            supervisor=OperationProcessGroupSupervisorV2(),
        )

        self.assertEqual(7, result.returncode)
        self.assertEqual(b"PAYLOAD", result.stdout)
        self.assertEqual(b"problem", result.stderr)

    def test_output_limit_softly_terminates_the_exact_group(self) -> None:
        supervisor = OperationProcessGroupSupervisorV2()
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=3,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
        )

        with self.assertRaises(SupervisedCommandOutputLimitExceededV2) as caught:
            run_supervised_command_v2(
                argv=(
                    sys.executable,
                    "-c",
                    "import sys,time;sys.stdout.write('x'*8192);"
                    "sys.stdout.flush();time.sleep(30)",
                ),
                label="noisy-command",
                local_timeout_seconds=2,
                cleanup_wait_seconds=1,
                max_output_bytes=1024,
                deadline=deadline,
                supervisor=supervisor,
            )

        self.assertEqual(1024, len(caught.exception.stdout))
        self.assertEqual((), supervisor.owned_lease_ids())
        supervisor.assert_continuation_allowed()

    def test_timeout_terminates_parent_and_descendant_without_sigkill(self) -> None:
        with tempfile.TemporaryDirectory(
            dir="/tmp", prefix="supervised-command-v2-"
        ) as raw:
            marker = Path(raw) / "child.pid"
            code = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import time;time.sleep(30)']);"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
                "time.sleep(30)"
            )
            supervisor = OperationProcessGroupSupervisorV2()
            deadline = OperationDeadlineV2.start(
                operation="apply",
                timeout_seconds=3,
                timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
            )

            with self.assertRaises(OperationDeadlineExceededV2):
                run_supervised_command_v2(
                    argv=(sys.executable, "-c", code, str(marker)),
                    label="tree-command",
                    local_timeout_seconds=0.2,
                    cleanup_wait_seconds=1,
                    deadline=deadline,
                    supervisor=supervisor,
                )

            self.assertTrue(marker.is_file())
            child_pid = int(marker.read_text(encoding="utf-8"))
            self.assertTrue(_wait_until_not_live(child_pid, 2))
            self.assertEqual((), supervisor.owned_lease_ids())

    def test_stubborn_group_closes_continuation_until_it_disappears(self) -> None:
        supervisor = OperationProcessGroupSupervisorV2(
            poll_interval_seconds=0.005
        )
        deadline = OperationDeadlineV2.start(
            operation="apply",
            timeout_seconds=2,
            timeout_code="APPLY_OPERATION_DEADLINE_EXCEEDED",
        )
        code = (
            "import signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(0.35)"
        )

        with self.assertRaises(SupervisedCommandCleanupRequiredV2) as caught:
            run_supervised_command_v2(
                argv=(sys.executable, "-c", code),
                label="stubborn-command",
                local_timeout_seconds=0.1,
                cleanup_wait_seconds=0.02,
                deadline=deadline,
                supervisor=supervisor,
            )

        obligation = caught.exception.cleanup_obligation
        self.assertIs(False, obligation["continuationAllowed"])
        self.assertIs(False, obligation["automaticSignalAuthorized"])
        time.sleep(0.4)
        self.assertEqual(
            1, len(supervisor.reconcile_completed_transients())
        )
        supervisor.assert_continuation_allowed()

    def test_module_contains_no_hard_kill_escalation(self) -> None:
        module = (
            PLUGIN_SRC
            / "codex_smart_subagents"
            / "supervised_subprocess_v2.py"
        )
        self.assertNotIn("SIGKILL", module.read_text(encoding="utf-8"))


def _wait_until_not_live(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = subprocess.run(
            ("/bin/ps", "-o", "stat=", "-p", str(pid)),
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
        state = completed.stdout.strip()
        if not state or state.startswith("Z"):
            return True
        time.sleep(0.01)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    return False


if __name__ == "__main__":
    unittest.main()
