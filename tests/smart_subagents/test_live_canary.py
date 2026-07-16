from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.live_canary import (  # noqa: E402
    CanaryCommand,
    CanaryProbeTargets,
    CanaryTimeouts,
    CommandResult,
    FileManagedConfigInspector,
    LiveCanaryError,
    LivePermissionCanary,
    ManagedConfigState,
    SubprocessExecutor,
)
from codex_smart_subagents.permissions import (  # noqa: E402
    REQUIRED_CANARY_CHECKS,
    CanaryRequest,
)


NOW = datetime(2026, 7, 16, 15, 0, tzinfo=timezone.utc)
SANDBOX_RESULT_PREFIX = "CODEX_PERMISSION_CANARY_V1:"
EXEC_RESULT_PREFIX = "CODEX_EXEC_PERMISSION_CANARY_V1:"


@dataclass(frozen=True)
class Profile:
    name: str
    config_overrides: tuple[str, ...]
    sha256: str


def profile(snapshot_root: Path, name: str = "adaptive_reader") -> Profile:
    overrides = (
        f'permissions.{name}.description="Adaptive child reader"',
        (
            f"permissions.{name}.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="write"},'
            f'{json.dumps(str(snapshot_root.resolve()))}="read"}}'
        ),
        f"permissions.{name}.network.enabled=false",
    )
    digest = hashlib.sha256(
        json.dumps(
            {"name": name, "overrides": overrides},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return Profile(name=name, config_overrides=overrides, sha256=digest)


def request(selected: Profile, **overrides: object) -> CanaryRequest:
    values: dict[str, object] = {
        "codex_version": "0.144.4",
        "permission_profile": selected.name,
        "profile_sha256": selected.sha256,
        "managed_config_sha256": "b" * 64,
    }
    values.update(overrides)
    return CanaryRequest(**values)


class MutableInspector:
    def __init__(
        self,
        *,
        sha256: str = "b" * 64,
        legacy_sandbox_mode: bool = False,
    ) -> None:
        self.state = ManagedConfigState(
            sha256=sha256,
            legacy_sandbox_mode=legacy_sandbox_mode,
        )
        self.calls = 0

    def inspect(self) -> ManagedConfigState:
        self.calls += 1
        return self.state


class RecordingExecutor:
    def __init__(self) -> None:
        self.commands: list[CanaryCommand] = []
        self.version = "codex-cli 0.144.4\n"
        self.sandbox_payload: dict[str, bool] | None = {
            "snapshot_read_allowed": True,
            "snapshot_write_denied": True,
            "secret_read_denied": True,
            "source_git_read_denied": True,
            "controller_database_read_denied": True,
            "source_worktree_write_denied": True,
            "external_network_denied": True,
            "dns_denied": True,
            "udp_denied": True,
            "loopback_denied": True,
            "controller_socket_denied": True,
        }
        self.sandbox_stdout: bytes | None = None
        self.exec_mode = "pass"
        self.raise_on_kind: str | None = None

    def run(self, command: CanaryCommand) -> CommandResult:
        self.commands.append(command)
        kind = self._kind(command)
        if kind == self.raise_on_kind:
            raise LiveCanaryError("CANARY_TIMEOUT", "synthetic timeout")
        if kind == "version":
            return CommandResult(0, self.version.encode("utf-8"), b"")
        if kind == "sandbox":
            if self.sandbox_stdout is not None:
                return CommandResult(0, self.sandbox_stdout, b"")
            assert self.sandbox_payload is not None
            return CommandResult(
                0,
                (
                    SANDBOX_RESULT_PREFIX
                    + json.dumps(
                        self.sandbox_payload,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8"),
                b"",
            )
        nonce_match = re.search(rb"\bce1_[A-Za-z0-9_-]{43}\b", command.stdin)
        assert nonce_match is not None
        nonce = nonce_match.group().decode("ascii")
        prompt = command.stdin.decode("utf-8")
        exact_probe_command = prompt.split("Команда:\n", 1)[1].split(
            "\nПосле завершения",
            1,
        )[0]
        marker = f"{EXEC_RESULT_PREFIX}{nonce}:DENIED\n"
        if self.exec_mode == "agent_message_only":
            events = (
                {"type": "thread.started"},
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": marker},
                },
                {"type": "turn.completed"},
            )
        elif self.exec_mode == "wrong_command":
            events = (
                {"type": "thread.started"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": "/usr/bin/true",
                        "aggregated_output": marker,
                        "exit_code": 0,
                        "status": "completed",
                    },
                },
                {"type": "turn.completed"},
            )
        else:
            events = (
                {"type": "thread.started"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": exact_probe_command,
                        "aggregated_output": marker,
                        "exit_code": 0,
                        "status": "completed",
                    },
                },
                {"type": "turn.completed"},
            )
        return CommandResult(
            0,
            b"".join(
                json.dumps(event, separators=(",", ":")).encode("utf-8")
                + b"\n"
                for event in events
            ),
            b"",
        )

    @staticmethod
    def _kind(command: CanaryCommand) -> str:
        if command.argv[1:] == ("--version",):
            return "version"
        if command.argv[1] == "sandbox":
            return "sandbox"
        return "exec"


class LivePermissionCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.executable = self.base / "codex"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o700)
        self.ruby = self.base / "ruby"
        self.ruby.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.ruby.chmod(0o700)
        self.codex_home = self.base / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.runtime_parent = self.base / "runtime"
        self.runtime_parent.mkdir(mode=0o700)
        self.snapshot_root = self.base / "snapshot"
        self.snapshot_root.mkdir(mode=0o700)
        self.snapshot = self._file(
            "snapshot/snapshot.txt",
            b"snapshot\n",
            0o400,
        )
        self.snapshot_root.chmod(0o500)
        self.secret = self._file("secret.txt", b"secret\n", 0o600)
        self.source_git = self._file("git-head", b"ref: refs/heads/main\n", 0o600)
        self.database = self._file("controller.sqlite3", b"sqlite\n", 0o600)
        self.source = self._file("source.py", b"print('safe')\n", 0o600)
        self.controller_listener = socket.socket(socket.AF_UNIX)
        self.controller_socket = self.base / "controller.sock"
        self.controller_listener.bind(os.fspath(self.controller_socket))
        self.controller_listener.listen(1)
        self.targets = CanaryProbeTargets(
            snapshot_root=self.snapshot_root,
            snapshot_read_file=self.snapshot,
            snapshot_write_file=self.snapshot,
            secret_read_file=self.secret,
            source_git_read_file=self.source_git,
            controller_database_read_file=self.database,
            source_worktree_write_file=self.source,
            controller_socket=self.controller_socket,
        )
        self.profile = profile(self.snapshot_root)
        self.inspector = MutableInspector()
        self.executor = RecordingExecutor()
        self.timeouts = CanaryTimeouts(
            version_seconds=3.0,
            sandbox_seconds=11.0,
            exec_seconds=37.0,
        )

    def tearDown(self) -> None:
        self.controller_listener.close()
        self.directory.cleanup()

    def _file(self, name: str, contents: bytes, mode: int) -> Path:
        path = self.base / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(mode)
        return path

    def canary(self, **overrides: object) -> LivePermissionCanary:
        values: dict[str, object] = {
            "codex_executable": self.executable,
            "ruby_executable": self.ruby,
            "codex_home": self.codex_home,
            "runtime_parent": self.runtime_parent,
            "profile": self.profile,
            "managed_config_inspector": self.inspector,
            "targets": self.targets,
            "model": "gpt-5.6-luna",
            "reasoning_effort": "low",
            "executor": self.executor,
            "clock": lambda: NOW,
            "timeouts": self.timeouts,
        }
        values.update(overrides)
        return LivePermissionCanary(**values)

    def test_success_returns_complete_evidence_and_exact_shell_free_commands(
        self,
    ) -> None:
        evidence = self.canary().verify(request(self.profile))

        self.assertEqual(set(REQUIRED_CANARY_CHECKS), set(evidence.checks))
        self.assertTrue(all(evidence.checks.values()))
        self.assertFalse(evidence.legacy_sandbox_mode)
        self.assertEqual(NOW, evidence.verified_at)
        self.assertRegex(evidence.probe_id, r"^pc1_[A-Za-z0-9_-]{43}$")
        self.assertEqual(3, len(self.executor.commands))

        version, sandbox, codex_exec = self.executor.commands
        self.assertEqual(
            (str(self.executable.resolve()), "--version"),
            version.argv,
        )
        self.assertEqual(3.0, version.timeout_seconds)
        self.assertEqual(
            (
                str(self.executable.resolve()),
                "sandbox",
                "-P",
                "adaptive_reader",
                "--include-managed-config",
                "-C",
                str(sandbox.cwd),
            ),
            sandbox.argv[:7],
        )
        for override in self.profile.config_overrides:
            self.assertIn(override, sandbox.argv)
        separator = sandbox.argv.index("--")
        self.assertEqual(
            (
                str(self.ruby.resolve()),
                "--disable-gems",
                "-rjson",
                "-rsocket",
                "-e",
            ),
            sandbox.argv[separator + 1 : separator + 6],
        )
        self.assertEqual(11.0, sandbox.timeout_seconds)
        payload = json.loads(sandbox.argv[-1])
        self.assertEqual(str(self.snapshot.resolve()), payload["snapshot_read"])
        self.assertEqual(str(self.source.resolve()), payload["source_write"])
        self.assertNotIn("/bin/sh", sandbox.argv)
        self.assertNotIn("-s", sandbox.argv)
        self.assertNotIn("--sandbox", sandbox.argv)

        self.assertEqual(
            (
                str(self.executable.resolve()),
                "exec",
                "--ignore-user-config",
                "--ignore-rules",
                "--strict-config",
                "--ephemeral",
                "--json",
                "--skip-git-repo-check",
                "--model",
                "gpt-5.6-luna",
                "-C",
                str(codex_exec.cwd),
            ),
            codex_exec.argv[:12],
        )
        self.assertIn('model_reasoning_effort="low"', codex_exec.argv)
        self.assertIn('approval_policy="never"', codex_exec.argv)
        self.assertIn(
            'default_permissions="adaptive_reader"',
            codex_exec.argv,
        )
        self.assertNotIn("--sandbox", codex_exec.argv)
        self.assertNotIn("--profile", codex_exec.argv)
        self.assertEqual(37.0, codex_exec.timeout_seconds)
        self.assertRegex(
            codex_exec.stdin.decode("utf-8"),
            r"\bce1_[A-Za-z0-9_-]{43}\b",
        )
        self.assertEqual(
            {
                "CODEX_ADAPTIVE_CHILD",
                "CODEX_HOME",
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "PATH",
                "TMPDIR",
            },
            set(codex_exec.environment),
        )

    def test_legacy_sandbox_or_managed_hash_mismatch_fails_before_processes(
        self,
    ) -> None:
        scenarios = (
            ManagedConfigState(
                sha256="b" * 64,
                legacy_sandbox_mode=True,
            ),
            ManagedConfigState(
                sha256="c" * 64,
                legacy_sandbox_mode=False,
            ),
        )
        for state in scenarios:
            with self.subTest(state=state):
                self.executor.commands.clear()
                self.inspector.state = state
                evidence = self.canary().verify(request(self.profile))
                self.assertEqual(set(REQUIRED_CANARY_CHECKS), set(evidence.checks))
                self.assertFalse(any(evidence.checks.values()))
                self.assertEqual(
                    state.legacy_sandbox_mode,
                    evidence.legacy_sandbox_mode,
                )
                self.assertEqual([], self.executor.commands)

    def test_version_mismatch_returns_complete_failed_evidence(self) -> None:
        self.executor.version = "codex-cli 0.144.3\n"

        evidence = self.canary().verify(request(self.profile))

        self.assertFalse(any(evidence.checks.values()))
        self.assertEqual(1, len(self.executor.commands))

    def test_malformed_or_incomplete_sandbox_output_fails_closed(self) -> None:
        outputs = (
            b"",
            b"not-json\n",
            SANDBOX_RESULT_PREFIX.encode("ascii") + b'{"snapshot_read_allowed":true}\n',
            (
                SANDBOX_RESULT_PREFIX.encode("ascii")
                + json.dumps(
                    {
                        **self.executor.sandbox_payload,
                        "snapshot_read_allowed": "yes",
                    }
                ).encode("utf-8")
                + b"\n"
            ),
        )
        for output in outputs:
            with self.subTest(output=output):
                self.executor.commands.clear()
                self.executor.sandbox_stdout = output
                evidence = self.canary().verify(request(self.profile))
                self.assertFalse(any(evidence.checks.values()))
                self.assertEqual(2, len(self.executor.commands))

    def test_failed_negative_probe_is_preserved_and_exec_is_not_run(self) -> None:
        assert self.executor.sandbox_payload is not None
        self.executor.sandbox_payload["source_worktree_write_denied"] = False

        evidence = self.canary().verify(request(self.profile))

        self.assertTrue(evidence.checks["snapshot_read_allowed"])
        self.assertFalse(evidence.checks["source_worktree_write_denied"])
        self.assertFalse(evidence.checks["sandbox_negative_probe"])
        self.assertFalse(evidence.checks["exec_negative_probe"])
        self.assertEqual(2, len(self.executor.commands))

    def test_exec_marker_must_come_from_matching_completed_command(self) -> None:
        for mode in ("agent_message_only", "wrong_command"):
            with self.subTest(mode=mode):
                self.executor.commands.clear()
                self.executor.exec_mode = mode
                evidence = self.canary().verify(request(self.profile))
                self.assertFalse(evidence.checks["exec_negative_probe"])
                self.assertTrue(evidence.checks["sandbox_negative_probe"])
                self.assertEqual(3, len(self.executor.commands))

    def test_timeout_is_fail_closed_and_each_stage_gets_its_exact_budget(
        self,
    ) -> None:
        for kind, expected_calls, expected_timeouts in (
            ("version", 1, (3.0,)),
            ("sandbox", 2, (3.0, 11.0)),
            ("exec", 3, (3.0, 11.0, 37.0)),
        ):
            with self.subTest(kind=kind):
                self.executor.commands.clear()
                self.executor.raise_on_kind = kind
                with self.assertRaisesRegex(LiveCanaryError, "CANARY_TIMEOUT"):
                    self.canary().verify(request(self.profile))
                self.assertEqual(expected_calls, len(self.executor.commands))
                self.assertEqual(
                    expected_timeouts,
                    tuple(
                        command.timeout_seconds
                        for command in self.executor.commands
                    ),
                )
                self.executor.raise_on_kind = None

    def test_profile_identity_mismatch_fails_before_processes(self) -> None:
        wrong = request(self.profile, profile_sha256="d" * 64)
        evidence = self.canary().verify(wrong)
        self.assertFalse(any(evidence.checks.values()))
        self.assertEqual([], self.executor.commands)

    def test_subprocess_executor_always_spawns_without_a_shell(self) -> None:
        command = CanaryCommand(
            argv=(
                str(self.executable.resolve()),
                "$(touch should-not-run)",
            ),
            cwd=self.base,
            environment={"PATH": "/usr/bin:/bin"},
            stdin=b"",
            timeout_seconds=1.0,
            max_output_bytes=1024,
        )
        with patch(
            "codex_smart_subagents.live_canary.subprocess.Popen",
            side_effect=OSError("synthetic"),
        ) as popen:
            with self.assertRaisesRegex(LiveCanaryError, "CANARY_SPAWN_FAILED"):
                SubprocessExecutor().run(command)

        _, kwargs = popen.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["close_fds"], True)
        self.assertIs(kwargs["start_new_session"], True)
        self.assertEqual(command.argv, popen.call_args.args[0])
        self.assertFalse((self.base / "should-not-run").exists())

    def test_file_inspector_detects_legacy_keys_and_configuration_drift(
        self,
    ) -> None:
        first = self._file(
            "requirements.toml",
            b'default_permissions = ":read-only"\n',
            0o600,
        )
        second = self._file(
            "managed.toml",
            b'[allowed_permission_profiles]\n":read-only" = true\n',
            0o600,
        )
        inspector = FileManagedConfigInspector((second, first))

        safe = inspector.inspect()
        self.assertFalse(safe.legacy_sandbox_mode)
        self.assertRegex(safe.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(safe, inspector.inspect())

        second.write_text(
            'sandbox_mode = "read-only"\n',
            encoding="utf-8",
        )
        second.chmod(0o600)
        legacy = inspector.inspect()
        self.assertTrue(legacy.legacy_sandbox_mode)
        self.assertNotEqual(safe.sha256, legacy.sha256)

    def test_owned_read_only_codex_home_need_not_be_mode_0700(self) -> None:
        self.codex_home.chmod(0o755)
        constructed = self.canary()
        self.assertIsInstance(constructed, LivePermissionCanary)


if __name__ == "__main__":
    unittest.main()
