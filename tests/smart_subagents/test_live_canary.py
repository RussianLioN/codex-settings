from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import socket
import stat
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
    AppServerManagedConfigInspector,
    CanaryCommand,
    CanaryProbeTargets,
    CanaryTimeouts,
    CommandResult,
    FileManagedConfigInspector,
    LiveCanaryError,
    LivePermissionCanary,
    ManagedConfigState,
    StrictAppServerClient,
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
    writable_root: Path | None = None


def profile(
    snapshot_root: Path,
    name: str = "adaptive_reader",
    writable_root: Path | None = None,
) -> Profile:
    writable = (
        ""
        if writable_root is None
        else f',{json.dumps(str(writable_root.resolve()))}="write"'
    )
    overrides = (
        f'permissions.{name}.description="Adaptive child reader"',
        (
            f"permissions.{name}.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="write"},'
            f'{json.dumps(str(snapshot_root.resolve()))}="read"{writable}}}'
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
    return Profile(
        name=name,
        config_overrides=overrides,
        sha256=digest,
        writable_root=writable_root,
    )


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
        self.codex_home_snapshots: list[
            tuple[Path, tuple[str, ...], tuple[int, ...]]
        ] = []
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
        self.exec_stderr = b""
        self.raise_on_kind: str | None = None

    def run(self, command: CanaryCommand) -> CommandResult:
        self.commands.append(command)
        codex_home = Path(command.environment["CODEX_HOME"])
        entries = tuple(sorted(path.name for path in codex_home.iterdir()))
        modes = tuple(
            stat.S_IMODE((codex_home / name).stat().st_mode)
            for name in entries
        )
        self.codex_home_snapshots.append((codex_home, entries, modes))
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
            observed_command = exact_probe_command
            if self.exec_mode == "shell_wrapper":
                observed_command = shlex.join(
                    ("/bin/zsh", "-c", exact_probe_command)
                )
            elif self.exec_mode == "shell_wrapper_extra":
                observed_command = shlex.join(
                    (
                        "/bin/zsh",
                        "-c",
                        exact_probe_command,
                        "unexpected",
                    )
                )
            events = (
                {"type": "thread.started"},
                {
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "command": observed_command,
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
            self.exec_stderr,
        )

    @staticmethod
    def _kind(command: CanaryCommand) -> str:
        if command.argv[1:] == ("--version",):
            return "version"
        if command.argv[1] == "sandbox":
            return "sandbox"
        return "exec"


class StrictAppServerClientTests(unittest.TestCase):
    def test_sqlite_runtime_is_private_temporary_and_outside_codex_home(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "codex"
            executable.write_text(
                """#!/usr/bin/env python3
import json
import os
import stat
import sys
from pathlib import Path

sqlite_home = Path(os.environ["CODEX_SQLITE_HOME"])
sqlite_home.joinpath("state_5.sqlite").write_bytes(b"temporary")
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        response = {
            "id": request["id"],
            "result": {
                "userAgent": "fake-codex",
                "codexHome": os.environ["CODEX_HOME"],
                "platformFamily": "unix",
                "platformOs": "test",
            },
        }
        print(json.dumps(response), flush=True)
    elif request.get("method") == "initialized":
        continue
    else:
        response = {
            "id": request["id"],
            "result": {
                "sqliteHome": str(sqlite_home),
                "sqliteMode": stat.S_IMODE(sqlite_home.stat().st_mode),
            },
        }
        print(json.dumps(response), flush=True)
""",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            codex_home = root / "codex-home"
            home = root / "home"
            tmpdir = root / "tmp"
            cwd = root / "cwd"
            for path in (codex_home, home, tmpdir, cwd):
                path.mkdir(mode=0o700)
            marker = codex_home / "keep"
            marker.write_text("unchanged\n", encoding="utf-8")

            client = StrictAppServerClient(
                codex_executable=executable,
                codex_home=codex_home,
                home=home,
                tmpdir=tmpdir,
                cwd=cwd,
            )
            result = client.call("hooks/list", {"cwds": [str(cwd)]})

            self.assertIsInstance(result, dict)
            assert isinstance(result, dict)
            sqlite_home = Path(result["sqliteHome"])
            self.assertEqual(tmpdir.resolve(), sqlite_home.parent)
            self.assertTrue(
                sqlite_home.name.startswith("app-server-sqlite-")
            )
            self.assertEqual(0o700, result["sqliteMode"])
            self.assertFalse(sqlite_home.exists())
            self.assertEqual(
                ["keep"],
                sorted(path.name for path in codex_home.iterdir()),
            )
            self.assertEqual(
                "unchanged\n",
                marker.read_text(encoding="utf-8"),
            )


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
        self.auth = self._file(
            "codex-home/auth.json",
            b'{"synthetic":"credential"}\n',
            0o600,
        )
        self.user_config = self._file(
            "codex-home/config.toml",
            b'sandbox_mode = "danger-full-access"\n',
            0o600,
        )
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
        private_codex_homes = {
            snapshot[0] for snapshot in self.executor.codex_home_snapshots
        }
        self.assertEqual(1, len(private_codex_homes))
        private_codex_home = next(iter(private_codex_homes))
        self.assertNotEqual(self.codex_home.resolve(), private_codex_home)
        self.assertEqual(
            {
                ("auth.json",),
            },
            {
                snapshot[1]
                for snapshot in self.executor.codex_home_snapshots
            },
        )
        self.assertEqual(
            {(0o600,)},
            {
                snapshot[2]
                for snapshot in self.executor.codex_home_snapshots
            },
        )
        self.assertFalse(private_codex_home.exists())

    def test_exact_writer_policy_accepts_one_separate_writable_root(
        self,
    ) -> None:
        writable = self.base / "writer-candidate"
        writable.mkdir(mode=0o700)
        selected = profile(
            self.snapshot_root,
            name="adaptive_writer",
            writable_root=writable,
        )

        evidence = self.canary(profile=selected).verify(request(selected))

        self.assertTrue(all(evidence.checks.values()))
        sandbox = self.executor.commands[1]
        self.assertTrue(
            any(
                str(writable.resolve()) in argument
                for argument in sandbox.argv
            )
        )

    def test_api_key_auth_uses_empty_private_codex_home(self) -> None:
        self.auth.unlink()

        evidence = self.canary(
            auth_environment={"OPENAI_API_KEY": "synthetic-key"}
        ).verify(request(self.profile))

        self.assertTrue(all(evidence.checks.values()))
        self.assertEqual(
            {()},
            {
                snapshot[1]
                for snapshot in self.executor.codex_home_snapshots
            },
        )
        self.assertTrue(
            all(
                command.environment["OPENAI_API_KEY"] == "synthetic-key"
                for command in self.executor.commands
            )
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

    def test_exec_accepts_the_official_stdin_notice_only(self) -> None:
        self.executor.exec_stderr = b"Reading prompt from stdin...\n"

        evidence = self.canary().verify(request(self.profile))

        self.assertTrue(all(evidence.checks.values()))

        self.executor.exec_stderr = (
            b"Reading prompt from stdin...\nunexpected diagnostic\n"
        )
        evidence = self.canary().verify(request(self.profile))
        self.assertFalse(evidence.checks["exec_negative_probe"])

    def test_exec_accepts_only_the_exact_codex_zsh_wrapper(self) -> None:
        self.executor.exec_mode = "shell_wrapper"

        evidence = self.canary().verify(request(self.profile))

        self.assertTrue(all(evidence.checks.values()))

        self.executor.exec_mode = "shell_wrapper_extra"
        evidence = self.canary().verify(request(self.profile))
        self.assertFalse(evidence.checks["exec_negative_probe"])

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


class AppServerManagedConfigInspectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.runtime_parent = self.base / "runtime"
        self.runtime_parent.mkdir(mode=0o700)
        self.codex_home = self.base / "codex-home"
        self.codex_home.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def fake_app_server(
        self,
        *,
        mode: str = "success",
        requirements: object = None,
    ) -> tuple[Path, Path]:
        executable = self.base / f"codex-{mode}"
        requirements_file = executable.with_suffix(".requirements.json")
        requirements_file.write_text(
            json.dumps(requirements, separators=(",", ":")),
            encoding="utf-8",
        )
        executable.write_text(
            """#!/usr/bin/python3
import json
import os
import sys
import time
from pathlib import Path

MODE = %r
REQUIREMENTS = Path(__file__).with_suffix(".requirements.json")

def emit(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\\n")
    sys.stdout.flush()

if MODE == "timeout":
    time.sleep(10)
    raise SystemExit(0)
if MODE == "oversized":
    sys.stdout.write("x" * 8192)
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)
if MODE == "broken_initialize":
    sys.stdout.write("{broken\\n")
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)

initialize = json.loads(sys.stdin.readline())
if initialize.get("method") != "initialize":
    raise SystemExit(3)
codex_home = (
    "/unexpected/codex-home"
    if MODE == "wrong_codex_home"
    else os.environ["CODEX_HOME"]
)
emit({
    "id": initialize["id"],
    "result": {
        "userAgent": "codex_smart_subagents/0.144.4",
        "codexHome": codex_home,
        "platformFamily": "unix",
        "platformOs": "macos",
    },
})
initialized = json.loads(sys.stdin.readline())
request = json.loads(sys.stdin.readline())
if initialized.get("method") != "initialized":
    raise SystemExit(4)
if request.get("method") != "configRequirements/read":
    raise SystemExit(5)
if MODE == "broken_requirements":
    sys.stdout.write('{"id":2,"result":\\n')
    sys.stdout.flush()
    time.sleep(10)
    raise SystemExit(0)
emit({
    "id": request["id"],
    "result": {
        "requirements": json.loads(REQUIREMENTS.read_text(encoding="utf-8")),
    },
})
""" % mode,
            encoding="utf-8",
        )
        executable.chmod(0o700)
        requirements_file.chmod(0o600)
        return executable, requirements_file

    def inspector(
        self,
        executable: Path,
        *,
        timeout_seconds: float = 5.0,
        max_output_bytes: int = 4096,
    ) -> AppServerManagedConfigInspector:
        return AppServerManagedConfigInspector(
            codex_executable=executable,
            codex_home=self.codex_home,
            runtime_parent=self.runtime_parent,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def test_null_requirements_have_stable_canonical_identity(self) -> None:
        executable, _ = self.fake_app_server(requirements=None)

        first = self.inspector(executable).inspect()
        second = self.inspector(executable).inspect()

        self.assertEqual(first, second)
        self.assertFalse(first.legacy_sandbox_mode)
        self.assertRegex(first.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual([], list(self.runtime_parent.iterdir()))

    def test_canonical_hash_ignores_object_key_order_and_tracks_content(self) -> None:
        executable, requirements_file = self.fake_app_server(
            requirements={
                "featureRequirements": {"plugins": False},
                "allowedSandboxModes": [],
            }
        )
        inspector = self.inspector(executable)

        first = inspector.inspect()
        requirements_file.write_text(
            (
                '{"allowedSandboxModes":[],'
                '"featureRequirements":{"plugins":false}}'
            ),
            encoding="utf-8",
        )
        same = inspector.inspect()
        requirements_file.write_text(
            (
                '{"allowedSandboxModes":[],'
                '"featureRequirements":{"multi_agent":false,"plugins":false}}'
            ),
            encoding="utf-8",
        )
        changed = inspector.inspect()

        self.assertEqual(first.sha256, same.sha256)
        self.assertNotEqual(first.sha256, changed.sha256)

    def test_required_child_capability_conflict_fails_closed(self) -> None:
        executable, _ = self.fake_app_server(
            requirements={
                "allowedSandboxModes": [],
                "featureRequirements": {"multi_agent": True},
            }
        )

        with self.assertRaisesRegex(
            LiveCanaryError,
            "MANAGED_FEATURE_CONFLICT",
        ):
            self.inspector(executable).inspect()

    def test_nonempty_allowed_sandbox_modes_activate_legacy_adapter(self) -> None:
        executable, _ = self.fake_app_server(
            requirements={"allowedSandboxModes": ["read-only"]}
        )

        state = self.inspector(executable).inspect()

        self.assertTrue(state.legacy_sandbox_mode)

    def test_user_config_sandbox_mode_is_not_a_managed_requirement(self) -> None:
        (self.codex_home / "config.toml").write_text(
            'sandbox_mode = "danger-full-access"\n',
            encoding="utf-8",
        )
        executable, _ = self.fake_app_server(requirements=None)

        state = self.inspector(executable).inspect()

        self.assertFalse(state.legacy_sandbox_mode)

    def test_invalid_app_server_protocol_fails_closed(self) -> None:
        scenarios = (
            ("wrong_codex_home", "MANAGED_CONFIG_CODEX_HOME_MISMATCH", 5.0, 4096),
            ("timeout", "MANAGED_CONFIG_TIMEOUT", 0.1, 4096),
            ("broken_initialize", "MANAGED_CONFIG_INVALID", 5.0, 4096),
            ("broken_requirements", "MANAGED_CONFIG_INVALID", 5.0, 4096),
            ("oversized", "MANAGED_CONFIG_OUTPUT_LIMIT", 5.0, 1024),
        )
        for mode, code, timeout, output_limit in scenarios:
            with self.subTest(mode=mode):
                executable, _ = self.fake_app_server(mode=mode)
                with self.assertRaisesRegex(LiveCanaryError, code):
                    self.inspector(
                        executable,
                        timeout_seconds=timeout,
                        max_output_bytes=output_limit,
                    ).inspect()

    def test_app_server_client_spawns_with_minimal_environment_and_no_shell(
        self,
    ) -> None:
        executable, _ = self.fake_app_server()
        inspector = self.inspector(executable)
        with patch(
            "codex_smart_subagents.live_canary.subprocess.Popen",
            side_effect=OSError("synthetic"),
        ) as popen:
            with self.assertRaisesRegex(
                LiveCanaryError,
                "MANAGED_CONFIG_UNAVAILABLE",
            ):
                inspector.inspect()

        _, kwargs = popen.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["close_fds"], True)
        self.assertIs(kwargs["start_new_session"], True)
        self.assertEqual(
            {
                "CODEX_HOME",
                "CODEX_SQLITE_HOME",
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "PATH",
                "TMPDIR",
            },
            set(kwargs["env"]),
        )
        sqlite_home = Path(kwargs["env"]["CODEX_SQLITE_HOME"])
        self.assertEqual(
            Path(kwargs["env"]["TMPDIR"]),
            sqlite_home.parent,
        )
        self.assertTrue(
            sqlite_home.name.startswith("app-server-sqlite-")
        )
        self.assertFalse(sqlite_home.exists())
        self.assertEqual(
            (
                str(executable.resolve()),
                "app-server",
                "--strict-config",
                "--listen",
                "stdio://",
            ),
            popen.call_args.args[0],
        )

    def test_changed_app_server_requirements_reject_old_request(self) -> None:
        executable, requirements_file = self.fake_app_server(requirements=None)
        inspector = self.inspector(executable)
        initial = inspector.inspect()

        requirements_file.write_text(
            '{"allowedSandboxModes":["workspace-write"]}',
            encoding="utf-8",
        )

        with tempfile.TemporaryDirectory(dir=self.base) as canary_root:
            root = Path(canary_root)
            codex_home = root / "source-codex-home"
            codex_home.mkdir(mode=0o700)
            auth = codex_home / "auth.json"
            auth.write_text('{"synthetic":"credential"}\n', encoding="utf-8")
            auth.chmod(0o600)
            runtime_parent = root / "canary-runtime"
            runtime_parent.mkdir(mode=0o700)
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir(mode=0o700)
            snapshot = snapshot_root / "source.txt"
            snapshot.write_text("source\n", encoding="utf-8")
            snapshot.chmod(0o400)
            snapshot_root.chmod(0o500)
            secret = root / "secret.txt"
            secret.write_text("secret\n", encoding="utf-8")
            secret.chmod(0o600)
            git_head = root / "HEAD"
            git_head.write_text("ref: refs/heads/main\n", encoding="utf-8")
            git_head.chmod(0o600)
            database = root / "controller.sqlite3"
            database.write_text("sqlite\n", encoding="utf-8")
            database.chmod(0o600)
            source = root / "source.py"
            source.write_text("pass\n", encoding="utf-8")
            source.chmod(0o600)
            listener = socket.socket(socket.AF_UNIX)
            socket_path = root / "controller.sock"
            listener.bind(os.fspath(socket_path))
            listener.listen(1)
            try:
                selected = profile(snapshot_root)
                executor = RecordingExecutor()
                canary = LivePermissionCanary(
                    codex_executable=executable,
                    ruby_executable=executable,
                    codex_home=codex_home,
                    runtime_parent=runtime_parent,
                    profile=selected,
                    managed_config_inspector=inspector,
                    targets=CanaryProbeTargets(
                        snapshot_root=snapshot_root,
                        snapshot_read_file=snapshot,
                        snapshot_write_file=snapshot,
                        secret_read_file=secret,
                        source_git_read_file=git_head,
                        controller_database_read_file=database,
                        source_worktree_write_file=source,
                        controller_socket=socket_path,
                    ),
                    model="gpt-5.6-luna",
                    reasoning_effort="low",
                    executor=executor,
                    clock=lambda: NOW,
                )

                evidence = canary.verify(
                    request(
                        selected,
                        managed_config_sha256=initial.sha256,
                    )
                )
            finally:
                listener.close()

        self.assertTrue(evidence.legacy_sandbox_mode)
        self.assertFalse(any(evidence.checks.values()))
        self.assertEqual([], executor.commands)


if __name__ == "__main__":
    unittest.main()
