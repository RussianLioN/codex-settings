from __future__ import annotations

import threading
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.controller_entrypoint_v2 import (  # noqa: E402
    ControllerEntrypointConfigV2,
    ControllerEntrypointV2Error,
    load_controller_entrypoint_config_v2,
    load_controller_policy_bundle_v2,
    start_full_controller_v2,
)


def _decision(state_home: Path):
    gate = {
        "manifestSemanticFingerprint": "1" * 64,
        "activationReceiptFingerprint": "2" * 64,
        "journalAbsenceProof": {"proof": "stable"},
        "gateFingerprint": "3" * 64,
    }
    binding = SimpleNamespace(
        activation_id="act2_" + "a" * 64,
        activation_fingerprint="a" * 64,
        compatibility_fingerprint="b" * 64,
        control_epoch=1,
        state_home=state_home,
        database_path=state_home / "databases" / "current.sqlite3",
        controller_row={"controller_start_id": "cs2_" + "c" * 32},
    )
    return SimpleNamespace(
        state="READY",
        executable=Path("/private/codex"),
        activation_id=binding.activation_id,
        gate_fingerprint="3" * 64,
        activation_gate=gate,
        catalog_path=Path("/private/catalog.toml"),
        runtime_binding=binding,
    )


class _Health:
    def __init__(self, decision, *, owns_runtime: bool = True) -> None:
        self.gateway_decision = decision
        self.owns_runtime = owns_runtime
        self.closed = False
        self.lifecycle_handler = None
        self.lifecycle_response_observer = None

    def bind_lifecycle_handler(self, handler, *, response_observer=None) -> None:
        self.lifecycle_handler = handler
        self.lifecycle_response_observer = response_observer

    def close(self) -> None:
        self.closed = True


class _Production:
    def __init__(self) -> None:
        self.closed = False
        self.server = SimpleNamespace(
            call_tool=lambda method, arguments: {
                "method": method,
                "arguments": arguments,
            }
        )

    def close(self) -> None:
        self.closed = True


class _Command:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.ready = threading.Event()
        self.stop = threading.Event()

    def start(self) -> None:
        self.ready.set()

    def wait_until_ready(self, timeout: float) -> bool:
        return self.ready.wait(timeout)

    def serve_forever(self) -> None:
        self.stop.wait(2)

    def close(self) -> None:
        self.stop.set()


class ControllerEntrypointV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="cev2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.codex = self.root / "codex"
        self.codex.write_text("#!/bin/sh\n", encoding="utf-8")
        self.codex.chmod(0o500)
        self.wrapper = self.root / "codex-smart"
        self.wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.wrapper.chmod(0o500)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _config(self) -> ControllerEntrypointConfigV2:
        return ControllerEntrypointConfigV2(
            source_root=ROOT,
            plugin_root=PLUGIN_ROOT,
            codex_home=self.codex_home,
            state_home=self.state_home,
            codex_binary=self.codex,
            wrapper=self.wrapper,
            environment={"HOME": str(self.root), "TMPDIR": "/tmp"},
        )

    def test_start_composes_health_provider_production_and_command_socket(self) -> None:
        decision = _decision(self.state_home)
        health = _Health(decision)
        production = _Production()
        resolver_calls: list[str] = []
        loaded_shells: list[str] = []

        def dispatcher(*_args: object) -> None:
            return None

        application = start_full_controller_v2(
            self._config(),
            policy_bundle=object(),
            dispatcher_factory=dispatcher,
            bootstrapper=lambda **_kwargs: health,
            decision_provider=lambda: resolver_calls.append("resolve") or decision,
            turn_context_loader=lambda shell: (
                loaded_shells.append(shell)
                or SimpleNamespace(
                    shell_session_id=shell,
                    session_id="session",
                    turn_id="turn",
                    codex_home=str(self.codex_home),
                    repo_root=str(self.root),
                    base_sha="4" * 64,
                    worktree_fingerprint="5" * 64,
                )
            ),
            production_builder=lambda **kwargs: (
                self.assertIs(dispatcher, kwargs["dispatcher_factory"]) or production
            ),
            command_server_factory=lambda **kwargs: _Command(kwargs["handler"]),
        )
        try:
            shell = "cas2_" + "A" * 32
            command = application.command_server
            result = command.handler(shell, "smart_wait", {"startRequestId": "x"})
            self.assertEqual("smart_wait", result["method"])
            self.assertEqual([shell], loaded_shells)
            self.assertGreaterEqual(len(resolver_calls), 1)
            self.assertTrue(application.ready)
            self.assertTrue(callable(health.lifecycle_handler))
            self.assertTrue(callable(health.lifecycle_response_observer))
        finally:
            application.close()
        self.assertTrue(production.closed)
        self.assertTrue(health.closed)

    def test_foreign_health_owner_never_opens_production(self) -> None:
        decision = _decision(self.state_home)
        health = _Health(decision, owns_runtime=False)
        with self.assertRaisesRegex(
            ControllerEntrypointV2Error,
            "CONTROLLER_ALREADY_RUNNING",
        ):
            start_full_controller_v2(
                self._config(),
                policy_bundle=object(),
                dispatcher_factory=object(),
                bootstrapper=lambda **_kwargs: health,
                decision_provider=lambda: decision,
                turn_context_loader=lambda _shell: None,
                production_builder=lambda **_kwargs: self.fail(
                    "foreign process built production"
                ),
                command_server_factory=lambda **_kwargs: self.fail(
                    "foreign process built command server"
                ),
            )
        self.assertFalse(health.closed)

    def test_dispatcher_dependencies_are_built_only_after_health_ownership(
        self,
    ) -> None:
        decision = _decision(self.state_home)
        health = _Health(decision)
        production = _Production()
        built: list[object] = []

        def dispatcher(*_args: object) -> None:
            return None

        application = start_full_controller_v2(
            self._config(),
            policy_bundle="policy",
            dispatcher_factory=None,
            dispatcher_factory_builder=lambda **kwargs: (
                self.assertIs(decision, kwargs["launch_decision"])
                or self.assertEqual("policy", kwargs["policy_bundle"])
                or built.append(kwargs["config"])
                or dispatcher
            ),
            bootstrapper=lambda **_kwargs: health,
            decision_provider=lambda: decision,
            turn_context_loader=lambda shell: SimpleNamespace(
                shell_session_id=shell,
                session_id="session",
                turn_id="turn",
                codex_home=str(self.codex_home),
                repo_root=str(self.root),
                base_sha="4" * 64,
                worktree_fingerprint="5" * 64,
            ),
            production_builder=lambda **kwargs: (
                self.assertIs(dispatcher, kwargs["dispatcher_factory"]) or production
            ),
            command_server_factory=lambda **kwargs: _Command(kwargs["handler"]),
        )
        application.close()
        self.assertEqual([self._config()], built)

    def test_config_rejects_relative_or_missing_runtime_paths(self) -> None:
        with self.assertRaises(ValueError):
            ControllerEntrypointConfigV2(
                source_root=Path("relative"),
                plugin_root=PLUGIN_ROOT,
                codex_home=self.codex_home,
                state_home=self.state_home,
                codex_binary=self.codex,
                wrapper=self.wrapper,
                environment={},
            )

    def test_initial_environment_requires_all_bootstrap_paths_and_strips_them(
        self,
    ) -> None:
        environment = {
            "CODEX_HOME": str(self.codex_home),
            "CODEX_V2_SOURCE_ROOT": str(ROOT),
            "CODEX_V2_CODEX_BIN": str(self.codex),
            "CODEX_V2_WRAPPER_PATH": str(self.wrapper),
            "CODEX_V2_STATE_HOME": str(self.state_home),
            "HOME": str(self.root),
            "TMPDIR": "/tmp",
            "UNRELATED_SECRET": "never inherit",
        }
        config = load_controller_entrypoint_config_v2(
            plugin_root=PLUGIN_ROOT,
            environment=environment,
        )
        self.assertEqual(ROOT, config.source_root)
        self.assertEqual(self.codex, config.codex_binary)
        self.assertEqual(self.wrapper, config.wrapper)
        self.assertEqual(str(self.root), config.environment["HOME"])
        self.assertNotIn("UNRELATED_SECRET", config.environment)
        self.assertFalse(
            any(name.startswith("CODEX_V2_") for name in config.environment)
        )

        for missing in (
            "CODEX_V2_SOURCE_ROOT",
            "CODEX_V2_CODEX_BIN",
            "CODEX_V2_WRAPPER_PATH",
            "CODEX_V2_STATE_HOME",
        ):
            incomplete = dict(environment)
            incomplete.pop(missing)
            with (
                self.subTest(missing=missing),
                self.assertRaisesRegex(
                    ControllerEntrypointV2Error,
                    "BOOTSTRAP_ENVIRONMENT_INCOMPLETE",
                ),
            ):
                load_controller_entrypoint_config_v2(
                    plugin_root=PLUGIN_ROOT,
                    environment=incomplete,
                )

    def test_initial_environment_accepts_an_explicit_state_home(self) -> None:
        state_home = self.root / "s"
        environment = {
            "CODEX_HOME": str(self.codex_home),
            "CODEX_V2_SOURCE_ROOT": str(ROOT),
            "CODEX_V2_CODEX_BIN": str(self.codex),
            "CODEX_V2_WRAPPER_PATH": str(self.wrapper),
            "CODEX_V2_STATE_HOME": str(state_home),
        }

        config = load_controller_entrypoint_config_v2(
            plugin_root=PLUGIN_ROOT,
            environment=environment,
        )

        self.assertEqual(state_home, config.state_home)
        self.assertNotIn("CODEX_V2_STATE_HOME", config.environment)

    def test_initial_environment_preserves_the_lexical_codex_path(self) -> None:
        selected_codex = self.root / "selected-codex"
        selected_codex.symlink_to(self.codex.name)
        environment = {
            "CODEX_HOME": str(self.codex_home),
            "CODEX_V2_SOURCE_ROOT": str(ROOT),
            "CODEX_V2_CODEX_BIN": str(selected_codex),
            "CODEX_V2_WRAPPER_PATH": str(self.wrapper),
            "CODEX_V2_STATE_HOME": str(self.state_home),
        }

        config = load_controller_entrypoint_config_v2(
            plugin_root=PLUGIN_ROOT,
            environment=environment,
        )

        self.assertEqual(selected_codex.absolute(), config.codex_binary)
        self.assertNotEqual(self.codex, config.codex_binary)

    def test_runtime_directories_are_canonicalized_at_the_environment_boundary(
        self,
    ) -> None:
        real_tmp = self.root / "real-tmp"
        real_tmp.mkdir(mode=0o700)
        alias = self.root / "tmp-alias"
        alias.symlink_to(real_tmp, target_is_directory=True)
        environment = {
            "CODEX_HOME": str(self.codex_home),
            "CODEX_V2_SOURCE_ROOT": str(ROOT),
            "CODEX_V2_CODEX_BIN": str(self.codex),
            "CODEX_V2_WRAPPER_PATH": str(self.wrapper),
            "CODEX_V2_STATE_HOME": str(self.state_home),
            "HOME": str(self.root),
            "TMPDIR": str(alias),
        }

        config = load_controller_entrypoint_config_v2(
            plugin_root=PLUGIN_ROOT,
            environment=environment,
        )

        self.assertEqual(str(real_tmp), config.environment["TMPDIR"])

    def test_recovery_config_uses_persisted_ordinary_executable(self) -> None:
        config = load_controller_entrypoint_config_v2(
            plugin_root=PLUGIN_ROOT,
            environment={"CODEX_HOME": str(self.codex_home)},
            recovery_decision_provider=lambda **_kwargs: SimpleNamespace(
                executable=self.codex,
                runtime_binding=SimpleNamespace(state_home=self.state_home),
            ),
        )
        self.assertEqual(PLUGIN_ROOT, config.source_root)
        self.assertEqual(self.codex, config.codex_binary)
        self.assertEqual(
            (PLUGIN_ROOT / "bin" / "codex-smart").resolve(), config.wrapper
        )

    def test_recovery_config_preserves_persisted_lexical_codex_path(self) -> None:
        selected_codex = self.root / "selected-recovery-codex"
        selected_codex.symlink_to(self.codex.name)

        config = load_controller_entrypoint_config_v2(
            plugin_root=PLUGIN_ROOT,
            environment={"CODEX_HOME": str(self.codex_home)},
            recovery_decision_provider=lambda **_kwargs: SimpleNamespace(
                executable=selected_codex,
                runtime_binding=SimpleNamespace(state_home=self.state_home),
            ),
        )

        self.assertEqual(selected_codex.absolute(), config.codex_binary)
        self.assertNotEqual(self.codex, config.codex_binary)

    def test_source_policy_bundle_is_loadable_for_initial_activation(self) -> None:
        bundle = load_controller_policy_bundle_v2(
            source_root=ROOT,
            plugin_root=PLUGIN_ROOT,
        )
        self.assertEqual(2, bundle.schema_version)
        self.assertIn("child_timeout_seconds", bundle.catalog_limits)


if __name__ == "__main__":
    unittest.main()
