from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.controller import WireProtocolError  # noqa: E402
from codex_smart_subagents.daemon import (  # noqa: E402
    ControllerProcessConfig,
    controller_environment,
    ensure_controller_running,
    spawn_controller,
)


class SequenceClient:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def call(self, method: str, params: dict[str, object]):
        self.calls += 1
        self.assertion = (method, params)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeProcess:
    def __init__(self, returncode: int | None = None) -> None:
        self._returncode = returncode

    def poll(self) -> int | None:
        return self._returncode


class ControllerProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.root / "state"
        self.catalog = PLUGIN_ROOT / "config" / "adaptive-subagents.toml"
        self.controller = self.root / "controller"
        self.controller.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.controller.chmod(0o700)
        self.real_codex = self.root / "codex"
        self.real_codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.real_codex.chmod(0o700)
        self.config = ControllerProcessConfig(
            codex_home=self.codex_home,
            state_home=self.state_home,
            catalog_path=self.catalog,
            controller_executable=self.controller,
            real_codex=self.real_codex,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_controller_environment_is_minimal_and_absolute(self) -> None:
        source = {
            "CODEX_HOME": str(self.codex_home),
            "XDG_STATE_HOME": str(self.state_home),
            "CODEX_ADAPTIVE_CATALOG": str(self.catalog),
            "CODEX_REAL_BIN": str(self.real_codex),
            "OPENAI_API_KEY": "must-not-leak",
            "HTTPS_PROXY": "http://secret@example.invalid",
            "SSH_AUTH_SOCK": "/tmp/agent.sock",
        }

        result = controller_environment(source, self.config)

        self.assertEqual(str(self.codex_home.resolve()), result["CODEX_HOME"])
        self.assertEqual(str(self.state_home.resolve()), result["XDG_STATE_HOME"])
        self.assertEqual(str(self.catalog.resolve()), result["CODEX_ADAPTIVE_CATALOG"])
        self.assertEqual(str(self.real_codex.resolve()), result["CODEX_REAL_BIN"])
        self.assertNotIn("OPENAI_API_KEY", result)
        self.assertNotIn("HTTPS_PROXY", result)
        self.assertNotIn("SSH_AUTH_SOCK", result)

    def test_existing_healthy_controller_is_not_spawned(self) -> None:
        client = SequenceClient(
            [
                {
                    "protocolVersion": 1,
                    "release": "0.1.0",
                    "namespace": self.config.paths.namespace,
                }
            ]
        )
        spawned: list[ControllerProcessConfig] = []

        ensure_controller_running(
            self.config,
            shell_session_id="cas1_" + "A" * 43,
            environ={},
            client_factory=lambda *_args, **_kwargs: client,
            spawn=lambda config, _environ: spawned.append(config),
            timeout_seconds=0.1,
            sleep=lambda _seconds: None,
        )

        self.assertEqual([], spawned)
        self.assertEqual(("health", {}), client.assertion)

    def test_unavailable_controller_is_spawned_and_polled_until_healthy(self) -> None:
        client = SequenceClient(
            [
                WireProtocolError("CONTROLLER_UNAVAILABLE", "missing"),
                WireProtocolError("CONTROLLER_UNAVAILABLE", "starting"),
                {
                    "protocolVersion": 1,
                    "release": "0.1.0",
                    "namespace": self.config.paths.namespace,
                },
            ]
        )
        spawned: list[ControllerProcessConfig] = []

        ensure_controller_running(
            self.config,
            shell_session_id="cas1_" + "A" * 43,
            environ={},
            client_factory=lambda *_args, **_kwargs: client,
            spawn=lambda config, _environ: (
                spawned.append(config) or FakeProcess()
            ),
            timeout_seconds=1,
            sleep=lambda _seconds: None,
        )

        self.assertEqual([self.config], spawned)
        self.assertEqual(3, client.calls)

    def test_early_controller_exit_fails_closed(self) -> None:
        client = SequenceClient(
            [
                WireProtocolError("CONTROLLER_UNAVAILABLE", "missing"),
                WireProtocolError("CONTROLLER_UNAVAILABLE", "failed"),
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "CONTROLLER_START_FAILED"):
            ensure_controller_running(
                self.config,
                shell_session_id="cas1_" + "A" * 43,
                environ={},
                client_factory=lambda *_args, **_kwargs: client,
                spawn=lambda _config, _environ: FakeProcess(7),
                timeout_seconds=1,
                sleep=lambda _seconds: None,
            )

    def test_spawn_uses_no_shell_and_private_log(self) -> None:
        captured: dict[str, object] = {}

        def fake_popen(argv, **kwargs):
            captured["argv"] = argv
            captured.update(kwargs)
            return FakeProcess()

        with patch("codex_smart_subagents.daemon.subprocess.Popen", fake_popen):
            process = spawn_controller(self.config, {})

        self.assertIsInstance(process, FakeProcess)
        self.assertEqual(
            [str(self.controller.resolve()), "--serve"],
            captured["argv"],
        )
        self.assertFalse(captured["shell"])
        self.assertTrue(captured["close_fds"])
        self.assertTrue(captured["start_new_session"])
        log_path = self.state_home / "codex-as"
        logs = list(log_path.rglob("controller.log"))
        self.assertEqual(1, len(logs))
        self.assertEqual(0o600, logs[0].stat().st_mode & 0o777)
        self.assertTrue(captured["stdout"].closed)


if __name__ == "__main__":
    unittest.main()
