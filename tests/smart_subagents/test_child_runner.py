from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
FAKE_CODEX = Path(__file__).with_name("test_child_fake_codex.py")
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.child_runner import (  # noqa: E402
    ChildLaunchError,
    ChildRunRequest,
    ChildRunner,
    ChildRuntimeLayout,
    ChildTelemetryConfig,
    PermissionProfileDefinition,
    build_codex_exec_argv,
)
from codex_smart_subagents.permissions import (  # noqa: E402
    REQUIRED_CANARY_CHECKS,
    CanaryEvidence,
    PermissionGate,
)


class PassingCanary:
    def __init__(self) -> None:
        self.calls = []

    def verify(self, request):
        self.calls.append(request)
        return CanaryEvidence(
            probe_id="pc1_" + "A" * 43,
            codex_version=request.codex_version,
            permission_profile=request.permission_profile,
            profile_sha256=request.profile_sha256,
            managed_config_sha256=request.managed_config_sha256,
            verified_at=datetime.now(timezone.utc),
            legacy_sandbox_mode=False,
            checks={name: True for name in REQUIRED_CANARY_CHECKS},
        )


class ChildRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.snapshot = self.base / "snapshot"
        self.snapshot.mkdir(mode=0o700)
        (self.snapshot / "source.txt").write_text("source\n", encoding="utf-8")
        (self.snapshot / "source.txt").chmod(0o444)
        self.snapshot.chmod(0o555)
        self.layout = ChildRuntimeLayout.create(self.base / "runtime")
        self.schema = self.base / "output.schema.json"
        self.schema.write_text(
            '{"type":"object","additionalProperties":false}',
            encoding="utf-8",
        )
        self.profile = PermissionProfileDefinition.reader(
            name="adaptive_reader",
            snapshot_root=self.snapshot,
        )
        self.canary = PassingCanary()
        self.runner = ChildRunner(PermissionGate(self.canary))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def request(self, **overrides: object) -> ChildRunRequest:
        values: dict[str, object] = {
            "codex_executable": FAKE_CODEX,
            "codex_version": "0.144.4",
            "model": "gpt-5.6-terra",
            "reasoning_effort": "high",
            "permission_profile": self.profile,
            "managed_config_sha256": "b" * 64,
            "runtime": self.layout,
            "output_schema": self.schema,
            "prompt": "Проверь снимок.",
            "timeout_seconds": 5.0,
            "max_output_bytes": 1024 * 1024,
        }
        values.update(overrides)
        return ChildRunRequest(**values)

    def test_builds_exact_shell_free_codex_exec_argv(self) -> None:
        request = self.request()
        snapshot = self.snapshot.resolve()
        expected_profile = (
            "permissions.adaptive_reader.filesystem="
            '{":root"="deny",":minimal"="read",":tmpdir"="write",'
            '":workspace_roots"={"."="write"},'
            f'{json.dumps(str(snapshot))}="read"}}'
        )
        expected = (
            str(FAKE_CODEX.resolve()),
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--ephemeral",
            "--json",
            "--skip-git-repo-check",
            "--model",
            "gpt-5.6-terra",
            "-C",
            str(self.layout.work_dir),
            "--output-schema",
            str(self.schema.resolve()),
            "-c",
            'model_reasoning_effort="high"',
            "-c",
            'approval_policy="never"',
            "-c",
            'default_permissions="adaptive_reader"',
            "-c",
            'project_root_markers=[]',
            "-c",
            "project_doc_max_bytes=0",
            "-c",
            'shell_environment_policy.inherit="none"',
            "-c",
            (
                "shell_environment_policy.set="
                f'{{HOME={json.dumps(str(self.layout.home))},'
                f'TMPDIR={json.dumps(str(self.layout.tmpdir))},'
                'PATH="/usr/bin:/bin:/usr/sbin:/sbin",'
                "CODEX_ADAPTIVE_SNAPSHOT_ROOT="
                f"{json.dumps(str(snapshot))}}}"
            ),
            "-c",
            "allow_login_shell=false",
            "-c",
            "agents.max_threads=1",
            "-c",
            "agents.max_depth=1",
            "-c",
            'web_search="disabled"',
            "-c",
            'permissions.adaptive_reader.description="Adaptive child reader"',
            "-c",
            expected_profile,
            "-c",
            "permissions.adaptive_reader.network.enabled=false",
            "--disable",
            "apps",
            "--disable",
            "browser_use",
            "--disable",
            "browser_use_external",
            "--disable",
            "browser_use_full_cdp_access",
            "--disable",
            "computer_use",
            "--disable",
            "enable_fanout",
            "--disable",
            "enable_mcp_apps",
            "--disable",
            "hooks",
            "--disable",
            "in_app_browser",
            "--disable",
            "memories",
            "--disable",
            "multi_agent",
            "--disable",
            "multi_agent_v2",
            "--disable",
            "plugins",
            "--disable",
            "remote_plugin",
            "--disable",
            "shell_snapshot",
            "--disable",
            "skill_mcp_dependency_install",
            "--disable",
            "workspace_dependencies",
        )
        self.assertEqual(expected, build_codex_exec_argv(request))
        self.assertNotIn("--add-dir", expected)
        self.assertNotIn("--sandbox", expected)
        self.assertNotIn("--profile", expected)
        self.assertNotIn("--output-last-message", expected)

    def test_runs_fake_codex_with_isolated_environment_stdin_and_umask(self) -> None:
        marker = self.base / "must-not-exist"
        prompt = f"literal $(/usr/bin/touch {marker})"
        expected_argv = list(build_codex_exec_argv(self.request()))[1:]
        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "must-not-leak",
                "HTTPS_PROXY": "http://user:password@example.invalid",
                "SSH_AUTH_SOCK": "/tmp/private-agent.sock",
                "BASH_FUNC_attack%%": "() { :; }",
            },
            clear=False,
        ):
            result = self.runner.run(self.request(prompt=prompt))

        self.assertTrue(result.succeeded)
        self.assertEqual(0, result.exit_code)
        self.assertEqual(
            ("thread.started", "turn.completed"),
            tuple(event["type"] for event in result.events),
        )
        invocation = json.loads(
            (self.layout.work_dir / "fake-codex-invocation.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(prompt, invocation["prompt"])
        self.assertEqual(expected_argv, invocation["argv"])
        expected_environment = {
            "CODEX_ADAPTIVE_CHILD": "1",
            "CODEX_ADAPTIVE_SNAPSHOT_ROOT": str(self.snapshot.resolve()),
            "CODEX_HOME": str(self.layout.codex_home),
            "HOME": str(self.layout.home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": str(self.layout.tmpdir),
        }
        for name, value in expected_environment.items():
            self.assertEqual(value, invocation["environment"][name])
        for forbidden in (
            "OPENAI_API_KEY",
            "HTTPS_PROXY",
            "SSH_AUTH_SOCK",
            "BASH_FUNC_attack%%",
        ):
            self.assertNotIn(forbidden, invocation["environment"])
        self.assertEqual(0o600, invocation["umaskProbeMode"])
        self.assertEqual(invocation["pid"], invocation["processGroup"])
        self.assertEqual(invocation["pid"], invocation["session"])
        self.assertFalse(marker.exists())
        self.assertEqual(1, len(self.canary.calls))
        self.assertEqual(self.profile.sha256, self.canary.calls[0].profile_sha256)

    def test_stages_auth_and_otel_without_exposing_token_in_argv(self) -> None:
        source_auth = self.base / "source-auth.json"
        source_auth.write_text('{"token":"test-only"}\n', encoding="utf-8")
        source_auth.chmod(0o600)
        telemetry = ChildTelemetryConfig(
            endpoint="http://127.0.0.1:4318/random/v1/logs",
            header_name="X-Codex-Attestation-Token",
            token="test-otel-token",
        )
        request = self.request(
            auth_file=source_auth,
            telemetry=telemetry,
        )

        argv = build_codex_exec_argv(request)
        self.assertNotIn(telemetry.token, "\0".join(argv))
        self.assertIn(
            (
                'otel.exporter={ otlp-http = { endpoint='
                '"http://127.0.0.1:4318/random/v1/logs", protocol="json", '
                'headers={ "X-Codex-Attestation-Token"='
                '"${CODEX_ADAPTIVE_OTEL_TOKEN}" } } }'
            ),
            argv,
        )

        result = self.runner.run(request)

        self.assertTrue(result.succeeded)
        self.assertEqual(
            hashlib.sha256("\0".join(argv).encode("utf-8")).hexdigest(),
            result.argv_fingerprint,
        )
        invocation = json.loads(
            (self.layout.work_dir / "fake-codex-invocation.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            telemetry.token,
            invocation["environment"]["CODEX_ADAPTIVE_OTEL_TOKEN"],
        )
        self.assertEqual(
            '{"token":"test-only"}\n',
            invocation["authContents"],
        )
        self.assertEqual(0o600, invocation["authMode"])
        self.assertFalse((self.layout.codex_home / "auth.json").exists())

    def test_rejects_unsafe_auth_and_non_loopback_telemetry(self) -> None:
        source_auth = self.base / "source-auth.json"
        source_auth.write_text("{}\n", encoding="utf-8")
        source_auth.chmod(0o644)
        with self.assertRaisesRegex(ChildLaunchError, "UNSAFE_AUTH_FILE"):
            self.runner.run(self.request(auth_file=source_auth))

        with self.assertRaises(ValueError):
            ChildTelemetryConfig(
                endpoint="https://collector.example.com/v1/logs",
                header_name="X-Codex-Attestation-Token",
                token="token",
            )

    def test_runtime_directories_are_private_and_separate(self) -> None:
        paths = (
            self.layout.root,
            self.layout.home,
            self.layout.tmpdir,
            self.layout.codex_home,
            self.layout.work_dir,
        )
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(0o700, stat.S_IMODE(path.stat().st_mode))

    def test_rejects_invalid_model_effort_schema_and_executable(self) -> None:
        with self.assertRaises(ValueError):
            self.request(model="gpt-5.6-terra;touch /tmp/pwned")
        with self.assertRaises(ValueError):
            self.request(reasoning_effort="ultra")

        schema_link = self.base / "schema-link"
        schema_link.symlink_to(self.schema)
        with self.assertRaisesRegex(ChildLaunchError, "UNSAFE_OUTPUT_SCHEMA"):
            build_codex_exec_argv(self.request(output_schema=schema_link))

        executable_link = self.base / "codex-link"
        executable_link.symlink_to(FAKE_CODEX)
        self.assertEqual(
            str(FAKE_CODEX.resolve()),
            build_codex_exec_argv(
                self.request(codex_executable=executable_link)
            )[0],
        )

        writable_snapshot = self.base / "writable-snapshot"
        writable_snapshot.mkdir(mode=0o700)
        (writable_snapshot / "writable.txt").write_text(
            "writable\n",
            encoding="utf-8",
        )
        writable_snapshot.chmod(0o555)
        with self.assertRaisesRegex(ChildLaunchError, "UNSAFE_SNAPSHOT_ROOT"):
            PermissionProfileDefinition.reader(
                name="adaptive_reader",
                snapshot_root=writable_snapshot,
            )

    def test_work_directory_must_still_be_empty_at_launch(self) -> None:
        (self.layout.work_dir / "unexpected").write_text(
            "not empty\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ChildLaunchError, "WORKDIR_NOT_EMPTY"):
            self.runner.run(self.request())
        self.assertEqual([], self.canary.calls)

    def test_invalid_json_output_and_output_flood_fail_closed(self) -> None:
        with self.assertRaisesRegex(ChildLaunchError, "CHILD_PROTOCOL_ERROR"):
            self.runner.run(self.request(prompt="FAKE_INVALID_JSON"))

        fresh_layout = ChildRuntimeLayout.create(self.base / "runtime-flood")
        with self.assertRaisesRegex(ChildLaunchError, "OUTPUT_LIMIT_EXCEEDED"):
            self.runner.run(
                self.request(
                    runtime=fresh_layout,
                    prompt="FAKE_FLOOD",
                    max_output_bytes=32 * 1024,
                )
            )

    def test_timeout_and_cancellation_terminate_the_process_group(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(ChildLaunchError, "CHILD_TIMEOUT"):
            self.runner.run(
                self.request(
                    prompt="FAKE_SLEEP_IGNORE_TERM",
                    timeout_seconds=1.0,
                )
            )
        self.assertLess(time.monotonic() - started, 3.0)
        grandchild = int(
            (self.layout.work_dir / "fake-grandchild.pid").read_text(
                encoding="ascii"
            )
        )
        try:
            for _ in range(50):
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("grandchild survived process-group termination")
        finally:
            try:
                os.kill(grandchild, signal.SIGKILL)
            except ProcessLookupError:
                pass

        cancellation = threading.Event()
        cancellation.set()
        fresh_layout = ChildRuntimeLayout.create(self.base / "runtime-cancelled")
        with self.assertRaisesRegex(ChildLaunchError, "CHILD_CANCELLED"):
            self.runner.run(
                self.request(runtime=fresh_layout),
                cancellation=cancellation,
            )
        self.assertFalse(
            (fresh_layout.work_dir / "fake-codex-invocation.json").exists()
        )

    def test_nonzero_exit_is_reported_without_trusting_model_output(self) -> None:
        result = self.runner.run(self.request(prompt="FAKE_EXIT_7"))
        self.assertFalse(result.succeeded)
        self.assertEqual(7, result.exit_code)
        self.assertEqual("turn.failed", result.events[-1]["type"])

    def test_timeout_applies_even_when_executable_never_reads_stdin(self) -> None:
        executable = self.base / "codex-no-stdin"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import time\n"
            "time.sleep(2)\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        layout = ChildRuntimeLayout.create(self.base / "runtime-no-stdin")

        started = time.monotonic()
        with self.assertRaisesRegex(ChildLaunchError, "CHILD_TIMEOUT"):
            self.runner.run(
                self.request(
                    codex_executable=executable,
                    runtime=layout,
                    prompt="x" * (60 * 1024),
                    timeout_seconds=0.2,
                )
            )
        self.assertLess(time.monotonic() - started, 1.5)


if __name__ == "__main__":
    unittest.main()
