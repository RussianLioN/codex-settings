from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.launcher import (  # noqa: E402
    LauncherError,
    build_adaptive_environment,
    classify_invocation,
    parse_codex_version,
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


class LauncherSafetyTests(unittest.TestCase):
    def test_version_parser_is_exact(self) -> None:
        self.assertEqual("0.144.4", parse_codex_version("codex-cli 0.144.4\n"))
        for value in ("0.144.4", "codex 0.144.4", "codex-cli latest"):
            with self.subTest(value=value), self.assertRaises(LauncherError):
                parse_codex_version(value)

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
