from __future__ import annotations

import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from typing import Mapping, Sequence
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.launcher import (  # noqa: E402
    LauncherError,
    apply_coordinator_defaults,
    build_adaptive_environment,
    classify_invocation,
    classify_managed_invocation,
    parse_codex_version,
    run_launcher,
    validate_real_binary,
)


class InvocationClassificationTests(unittest.TestCase):
    def test_supported_interactive_forms_enable_adaptive_mode(self) -> None:
        cases = [
            [],
            ["fix the failing test"],
            ["-C", "/tmp/project"],
            ["-C/tmp/project", "--search", "review this"],
            ["--cd=/tmp/project", "--no-alt-screen"],
            ["-i", "screen.png", "explain"],
            ["--image=screen.png", "--strict-config=true"],
            ["--", "exec is prompt text"],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                decision = classify_invocation(arguments)
                self.assertTrue(decision.adaptive, decision.reason)

    def test_subcommands_explicit_controls_and_unknown_flags_bypass(self) -> None:
        cases = [
            ["exec", "task"],
            ["e", "task"],
            ["review"],
            ["resume"],
            ["fork"],
            ["app"],
            ["cloud"],
            ["mcp-server"],
            ["--model", "gpt-5.6-sol"],
            ["-mgpt-5.6-sol"],
            ["--profile=fast"],
            ["--sandbox", "read-only"],
            ["--ask-for-approval=never"],
            ["--oss"],
            ["--local-provider", "ollama"],
            ["--remote=ws://127.0.0.1:1234"],
            ["--ignore-user-config"],
            ["--add-dir", "/tmp/extra"],
            ["--dangerously-bypass-approvals-and-sandbox"],
            ["-c", "model_reasoning_effort=high"],
            ["--enable", "multi_agent"],
            ["--unknown"],
            ["one", "two"],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                decision = classify_invocation(arguments)
                self.assertFalse(decision.adaptive)

    def test_missing_supported_flag_value_bypasses_without_rewriting_error(self) -> None:
        for arguments in (["-C"], ["--cd"], ["-i"], ["--image"]):
            with self.subTest(arguments=arguments):
                self.assertFalse(classify_invocation(arguments).adaptive)

    def test_managed_classifier_bypasses_service_subcommands(self) -> None:
        for arguments in (
            ["help"],
            ["update"],
            ["update", "--help"],
            ["help", "--"],
            ["update", "--"],
        ):
            with self.subTest(arguments=arguments):
                self.assertFalse(classify_managed_invocation(arguments).adaptive)

    def test_managed_classifier_preserves_explicit_coordinator_controls(self) -> None:
        for arguments in (
            ["--model", "gpt-user"],
            ["-m", "gpt-user"],
            ["-c", 'model="gpt-user"'],
            ["-c", 'model_reasoning_effort="high"'],
        ):
            with self.subTest(arguments=arguments):
                self.assertTrue(classify_managed_invocation(arguments).adaptive)

    def test_separator_keeps_service_words_as_managed_prompt_text(self) -> None:
        self.assertTrue(classify_managed_invocation(["--", "help"]).adaptive)
        self.assertTrue(classify_managed_invocation(["--", "update"]).adaptive)
        self.assertTrue(classify_managed_invocation(["--", "--model"]).adaptive)
        self.assertTrue(
            classify_managed_invocation(
                ["--", "-c", 'model="prompt text"']
            ).adaptive
        )


class LauncherSafetyTests(unittest.TestCase):
    def test_coordinator_defaults_are_added_as_one_validated_pair(self) -> None:
        original = ["-C", "/tmp/project", "проверь задачу"]
        rewritten = apply_coordinator_defaults(
            original,
            {
                "model": "gpt-5.6-terra",
                "reasoning_effort": "medium",
            },
        )
        self.assertEqual(
            [
                *original,
                "--model",
                "gpt-5.6-terra",
                "-c",
                'model_reasoning_effort="medium"',
            ],
            rewritten,
        )
        self.assertEqual(["-C", "/tmp/project", "проверь задачу"], original)

        separated = ["--", "help"]
        self.assertEqual(
            [
                "--model",
                "gpt-5.6-terra",
                "-c",
                'model_reasoning_effort="medium"',
                "--",
                "help",
            ],
            apply_coordinator_defaults(
                separated,
                {
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "medium",
                },
            ),
        )
        self.assertEqual(["--", "help"], separated)

        for invalid in (
            {"model": "gpt-5.6-terra"},
            {"model": "", "reasoning_effort": "medium"},
            {"model": "gpt-5.6-terra", "reasoning_effort": "medium\nmax"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(LauncherError):
                apply_coordinator_defaults([], invalid)

    def test_version_parser_is_exact(self) -> None:
        self.assertEqual("0.144.6", parse_codex_version("codex-cli 0.144.6\n"))
        for value in (
            "0.144.6",
            "codex 0.144.6",
            "codex-cli latest",
            "codex-cli 00.144.6\n",
        ):
            with self.subTest(value=value), self.assertRaises(LauncherError):
                parse_codex_version(value)

    def test_newer_stable_version_enables_adaptive_launch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wrapper = root / "codex-smart"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            real = root / "codex"
            real.write_text("#!/bin/sh\n", encoding="utf-8")
            real.chmod(0o700)
            controller_environments: list[dict[str, str]] = []
            executions: list[tuple[str, tuple[str, ...], dict[str, str]]] = []

            def expected_exec(
                path: str,
                arguments: Sequence[str],
                environment: Mapping[str, str],
            ) -> object:
                executions.append(
                    (
                        path,
                        tuple(arguments),
                        dict(environment),
                    )
                )
                raise RuntimeError("expected exec")

            with mock.patch(
                "codex_smart_subagents.launcher.probe_codex_version",
                return_value="0.144.6",
            ), self.assertRaisesRegex(RuntimeError, "expected exec"):
                run_launcher(
                    [],
                    real_binary=real,
                    wrapper=wrapper,
                    environment={"PATH": "/usr/bin"},
                    ensure_controller=lambda environment: (
                        controller_environments.append(dict(environment))
                    ),
                    execve=expected_exec,
                )

            self.assertEqual(1, len(controller_environments))
            self.assertEqual(1, len(executions))
            self.assertEqual(
                "1",
                executions[0][2]["CODEX_SMART_LAUNCHER_ACTIVE"],
            )

    def test_controller_failure_preserves_ordinary_codex_launch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wrapper = root / "codex-smart"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            real = root / "codex"
            real.write_text("#!/bin/sh\n", encoding="utf-8")
            real.chmod(0o700)
            executions: list[tuple[tuple[str, ...], dict[str, str]]] = []

            def unavailable(_environment: Mapping[str, str]) -> None:
                raise RuntimeError("controller offline")

            def expected_exec(
                _path: str,
                arguments: Sequence[str],
                environment: Mapping[str, str],
            ) -> object:
                executions.append((tuple(arguments), dict(environment)))
                raise RuntimeError("expected exec")

            error = StringIO()
            with (
                mock.patch(
                    "codex_smart_subagents.launcher.probe_codex_version",
                    return_value="0.144.6",
                ),
                self.assertRaisesRegex(RuntimeError, "expected exec"),
                redirect_stderr(error),
            ):
                run_launcher(
                    ["проверь"],
                    real_binary=real,
                    wrapper=wrapper,
                    environment={"PATH": "/usr/bin"},
                    coordinator={"model": "unused", "reasoning_effort": "low"},
                    ensure_controller=unavailable,
                    execve=expected_exec,
                )

            self.assertEqual((str(real.resolve()), "проверь"), executions[0][0])
            self.assertEqual({"PATH": "/usr/bin"}, executions[0][1])
            self.assertIn("контроллер недоступен", error.getvalue())

    def test_every_intentional_ordinary_launch_cleans_smart_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wrapper = root / "codex-smart"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            real = root / "codex"
            real.write_text("#!/bin/sh\n", encoding="utf-8")
            real.chmod(0o700)
            dirty_environment = {
                "PATH": "/usr/bin",
                "CODEX_SMART_REQUIRED": "invalid",
                "CODEX_SMART_GATE_FINGERPRINT": "stale",
                "CODEX_ADAPTIVE_SESSION_ID": "stale",
                "CODEX_ADAPTIVE_CATALOG": "/stale/catalog.toml",
                "CODEX_COORDINATOR_MODEL": "stale",
                "CODEX_REAL_BIN": "/stale/codex",
            }

            def unavailable(_environment: Mapping[str, str]) -> None:
                raise RuntimeError("controller offline")

            cases = (
                (
                    "version probe failure",
                    ["help"],
                    LauncherError("VERSION_PROBE_FAILED", "private"),
                    None,
                ),
                ("unsupported version", [], "0.143.0", None),
                ("service invocation", ["help"], "0.145.0", None),
                (
                    "controller failure",
                    ["проверь"],
                    "0.145.0",
                    unavailable,
                ),
            )
            for name, arguments, probe_result, ensure in cases:
                with self.subTest(name=name):
                    executions: list[dict[str, str]] = []

                    def expected_exec(
                        _path: str,
                        _arguments: Sequence[str],
                        environment: Mapping[str, str],
                    ) -> object:
                        executions.append(dict(environment))
                        raise RuntimeError("expected exec")

                    probe_patch = (
                        mock.patch(
                            "codex_smart_subagents.launcher.probe_codex_version",
                            side_effect=probe_result,
                        )
                        if isinstance(probe_result, Exception)
                        else mock.patch(
                            "codex_smart_subagents.launcher.probe_codex_version",
                            return_value=probe_result,
                        )
                    )
                    with (
                        probe_patch,
                        self.assertRaisesRegex(RuntimeError, "expected exec"),
                        redirect_stderr(StringIO()),
                    ):
                        run_launcher(
                            arguments,
                            real_binary=real,
                            wrapper=wrapper,
                            environment=dirty_environment,
                            ensure_controller=ensure,
                            execve=expected_exec,
                        )

                    self.assertEqual(1, len(executions))
                    self.assertEqual("/usr/bin", executions[0]["PATH"])
                    self.assertFalse(
                        any(
                            key.startswith("CODEX_SMART_")
                            or key.startswith("CODEX_ADAPTIVE_")
                            or key.startswith("CODEX_COORDINATOR_")
                            or key == "CODEX_REAL_BIN"
                            for key in executions[0]
                        )
                    )

    def test_ready_launch_uses_catalog_coordinator_pair(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wrapper = root / "codex-smart"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            real = root / "codex"
            real.write_text("#!/bin/sh\n", encoding="utf-8")
            real.chmod(0o700)
            executions: list[tuple[str, ...]] = []

            def expected_exec(
                _path: str,
                arguments: Sequence[str],
                _environment: Mapping[str, str],
            ) -> object:
                executions.append(tuple(arguments))
                raise RuntimeError("expected exec")

            with mock.patch(
                "codex_smart_subagents.launcher.probe_codex_version",
                return_value="0.144.6",
            ), self.assertRaisesRegex(RuntimeError, "expected exec"):
                run_launcher(
                    ["проверь задачу"],
                    real_binary=real,
                    wrapper=wrapper,
                    environment={"PATH": "/usr/bin"},
                    coordinator={
                        "model": "gpt-5.6-terra",
                        "reasoning_effort": "medium",
                    },
                    execve=expected_exec,
                )

            self.assertEqual(
                (
                    str(real.resolve()),
                    "проверь задачу",
                    "--model",
                    "gpt-5.6-terra",
                    "-c",
                    'model_reasoning_effort="medium"',
                ),
                executions[0],
            )

    def test_environment_adds_fresh_session_without_mutating_input(self) -> None:
        original = {"PATH": "/usr/bin", "CODEX_HOME": "/tmp/codex"}
        result = build_adaptive_environment(original)
        self.assertNotIn("CODEX_ADAPTIVE_SESSION_ID", original)
        self.assertRegex(
            result["CODEX_ADAPTIVE_SESSION_ID"],
            r"^cas1_[A-Za-z0-9_-]{43}$",
        )
        self.assertEqual("1", result["CODEX_SMART_LAUNCHER_ACTIVE"])

    def test_real_binary_must_be_absolute_executable_and_not_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wrapper = root / "codex"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o700)
            real = root / "real-codex"
            real.write_text("#!/bin/sh\n", encoding="utf-8")
            real.chmod(0o700)
            self.assertEqual(real.resolve(), validate_real_binary(real, wrapper))
            with self.assertRaises(LauncherError):
                validate_real_binary(wrapper, wrapper)
            with self.assertRaises(LauncherError):
                validate_real_binary(Path("relative"), wrapper)
            real.chmod(0o600)
            with self.assertRaises(LauncherError):
                validate_real_binary(real, wrapper)


if __name__ == "__main__":
    unittest.main()
