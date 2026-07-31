from __future__ import annotations

import os
import runpy
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "plugins" / "codex-smart-subagents" / "bin" / "codex-smart"
PLUGIN_SRC = WRAPPER.parents[1] / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayDecision,
    GatewayState,
    SourceDriftV1,
)
from codex_smart_subagents.launcher import (  # noqa: E402
    classify_managed_invocation,
    run_launcher,
)


def _ordinary(executable: Path, reason: str = "HEALTH_UNAVAILABLE") -> GatewayDecision:
    return GatewayDecision(
        state=GatewayState.ORDINARY,
        reason_code=reason,
        executable=executable,
    )


class WrapperSupervisorV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = runpy.run_path(str(WRAPPER), run_name="codex_smart_wrapper_test")
        self.globals = self.module["main"].__globals__
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp", prefix="wsv2-")
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.fallback = self.root / "codex"
        self.fallback.write_text("#!/bin/sh\n", encoding="utf-8")
        self.fallback.chmod(0o500)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_v2_path_passes_exact_supervisor_decision_to_gateway(self) -> None:
        snapshot = self.root / "snapshot-codex"
        snapshot.write_text("#!/bin/sh\n", encoding="utf-8")
        snapshot.chmod(0o500)
        live_codex = self.root / "live-codex"
        live_codex.write_text("#!/bin/sh\n", encoding="utf-8")
        live_codex.chmod(0o500)
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=snapshot,
            coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
            catalog_schema_version=1,
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.root / "adaptive-subagents.toml",
            source_drift=SourceDriftV1(
                lexical_path=live_codex,
                resolved_path=live_codex,
                observed_sha256="c" * 64,
                expected_sha256="d" * 64,
            ),
        )
        result = SimpleNamespace(gateway_decision=decision)
        supervisor_arguments: dict[str, object] = {}
        gateway_arguments: dict[str, object] = {}

        class Resolver:
            def __init__(self, **kwargs) -> None:
                self.kwargs = kwargs

            def resolve(self):
                return decision

            def resolve_persisted_activation(self):
                return SimpleNamespace(
                    runtime_binding=SimpleNamespace(state_home=self_state_home)
                )

        class Supervisor:
            def __init__(self, **kwargs) -> None:
                supervisor_arguments.update(kwargs)

            def ensure(self):
                return result

        def gateway(arguments, **kwargs):
            gateway_arguments.update(kwargs)
            self.assertIs(decision, kwargs["resolver"].resolve())
            self.assertIs(
                decision.source_drift,
                kwargs["resolver"].resolve().source_drift,
            )
            return 17

        globals_ = self.globals
        self_state_home = self.root / "external-state"
        self_state_home.mkdir(mode=0o700)
        with (
            mock.patch.dict(
                os.environ, {"CODEX_HOME": str(self.codex_home)}, clear=True
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "task"]),
            mock.patch.dict(
                globals_,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "ActivationResolver": Resolver,
                    "ControllerSupervisorV2": Supervisor,
                    "run_permanent_gateway": gateway,
                },
            ),
        ):
            self.assertEqual(17, globals_["main"]())

        self.assertEqual(self.codex_home, supervisor_arguments["codex_home"])
        self.assertEqual(
            self_state_home,
            supervisor_arguments["state_home"],
        )

    def test_service_and_explicit_native_calls_bypass_supervisor(self) -> None:
        for arguments in (
            ["help"],
            ["update"],
            ["update", "--help"],
            ["help", "--"],
            ["update", "--"],
            ["--profile", "custom"],
            ["-c", 'approval_policy="never"'],
        ):
            with self.subTest(arguments=arguments):
                decision = _ordinary(self.fallback)
                supervisor_calls: list[object] = []
                gateway_arguments: dict[str, object] = {}

                class Resolver:
                    def __init__(self, **_kwargs) -> None:
                        pass

                    def resolve(self):
                        return decision

                    def resolve_persisted_activation(self):
                        return SimpleNamespace(
                            runtime_binding=SimpleNamespace(
                                state_home=self_state_home
                            )
                        )

                class Supervisor:
                    def __init__(self, **_kwargs) -> None:
                        supervisor_calls.append(object())

                    def ensure(self):
                        raise AssertionError("service call started supervisor")

                def gateway(raw_arguments, **kwargs):
                    self.assertEqual(arguments, raw_arguments)
                    gateway_arguments.update(kwargs)
                    return 17

                self_state_home = self.root / "external-state"
                self_state_home.mkdir(mode=0o700, exist_ok=True)
                with (
                    mock.patch.dict(
                        os.environ,
                        {
                            "CODEX_HOME": str(self.codex_home),
                            "CODEX_SMART_REQUIRED": "1",
                        },
                        clear=True,
                    ),
                    mock.patch.object(sys, "argv", [str(WRAPPER), *arguments]),
                    mock.patch.dict(
                        self.globals,
                        {
                            "classify_managed_invocation": classify_managed_invocation,
                            "v2_gateway_state_present": lambda _layout: True,
                            "ActivationResolver": Resolver,
                            "ControllerSupervisorV2": Supervisor,
                            "run_permanent_gateway": gateway,
                        },
                    ),
                ):
                    self.assertEqual(17, self.globals["main"]())

                self.assertEqual([], supervisor_calls)
                self.assertFalse(gateway_arguments["managed_required"])

    def test_ultra_bypasses_resolver_preparation_supervisor_and_controller(self) -> None:
        arguments = [
            "-c",
            "model_reasoning_effort='ultra'",
            "проверь",
        ]
        calls: list[str] = []
        gateway_arguments: dict[str, object] = {}
        error = StringIO()

        def unexpected(name: str):
            def fail(*_arguments, **_kwargs):
                calls.append(name)
                self.fail(f"ultra вызвал {name}")

            return fail

        def gateway(raw_arguments, **kwargs):
            self.assertEqual(arguments, raw_arguments)
            gateway_arguments.update(kwargs)
            return 17

        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_REQUIRED": "1",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), *arguments]),
            mock.patch.dict(
                self.globals,
                {
                    "ActivationResolver": unexpected("resolver"),
                    "_prepare_v2_decision": unexpected("preparation"),
                    "ControllerSupervisorV2": unexpected("supervisor"),
                    "ControllerProcessConfig": unexpected("controller"),
                    "run_permanent_gateway": gateway,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual([], calls)
        self.assertIsNone(gateway_arguments["resolver"])
        self.assertFalse(gateway_arguments["managed_required"])
        self.assertEqual("", error.getvalue())

    def test_legacy_service_path_cleans_added_catalog_and_smart_environment(
        self,
    ) -> None:
        executions: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def expected_exec(
            _path: str,
            arguments,
            environment,
        ) -> object:
            executions.append((tuple(arguments), dict(environment)))
            raise RuntimeError("expected exec")

        def legacy_launcher(arguments, **kwargs):
            return run_launcher(
                arguments,
                **kwargs,
                execve=expected_exec,
            )

        config_factory = SimpleNamespace(
            from_environ=lambda _environment, **_kwargs: SimpleNamespace(
                real_codex=self.fallback
            )
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "PATH": "/usr/bin",
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_REQUIRED": "invalid",
                    "CODEX_SMART_GATE_FINGERPRINT": "stale",
                    "CODEX_ADAPTIVE_SESSION_ID": "stale",
                    "CODEX_COORDINATOR_MODEL": "stale",
                    "CODEX_REAL_BIN": "/stale/codex",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "help"]),
            mock.patch(
                "codex_smart_subagents.launcher.probe_codex_version",
                return_value="0.145.0",
            ),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: False,
                    "ControllerProcessConfig": config_factory,
                    "run_launcher": legacy_launcher,
                },
            ),
            self.assertRaisesRegex(RuntimeError, "expected exec"),
        ):
            self.globals["main"]()

        self.assertEqual(
            (str(self.fallback.resolve()), "help"),
            executions[0][0],
        )
        self.assertEqual("/usr/bin", executions[0][1]["PATH"])
        self.assertEqual(str(self.codex_home), executions[0][1]["CODEX_HOME"])
        self.assertFalse(
            any(
                key.startswith("CODEX_SMART_")
                or key.startswith("CODEX_ADAPTIVE_")
                or key.startswith("CODEX_COORDINATOR_")
                or key == "CODEX_REAL_BIN"
                for key in executions[0][1]
            )
        )

    def test_required_managed_failure_returns_69_with_safe_escape_hint(self) -> None:
        decision = _ordinary(self.fallback, reason="MANIFEST_INVALID")
        gateway_arguments: dict[str, object] = {}

        class StrictFailure(RuntimeError):
            def __init__(self, code: str, message: str) -> None:
                super().__init__(f"{code}: {message}")
                self.code = code
                self.message = message

        def gateway(_arguments, **kwargs):
            gateway_arguments.update(kwargs)
            raise StrictFailure("MANIFEST_INVALID", "private resolver details")

        error = StringIO()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_REQUIRED": "1",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "проверь"]),
            mock.patch.dict(
                self.globals,
                {
                    "ManagedLaunchUnavailable": StrictFailure,
                    "classify_managed_invocation": classify_managed_invocation,
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: decision,
                    "run_permanent_gateway": gateway,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(69, self.globals["main"]())

        self.assertTrue(gateway_arguments["managed_required"])
        self.assertIn("MANIFEST_INVALID", error.getvalue())
        self.assertIn("codex-native", error.getvalue())
        self.assertNotIn("private resolver details", error.getvalue())

    def test_automatic_coordinator_unavailable_returns_69_without_marker(
        self,
    ) -> None:
        decision = GatewayDecision(
            state=GatewayState.READY,
            reason_code="READY",
            executable=self.fallback,
            coordinator=None,
            coordinator_selection={
                "selection": "first-verified-available",
                "status": "UNAVAILABLE",
                "reasonCode": "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
                "selectedPair": None,
                "candidateIndex": None,
                "accountCatalogFingerprint": None,
                "accountContextFingerprint": "6" * 64,
            },
            catalog_schema_version=2,
            activation_id="act2_" + "a" * 64,
            gate_fingerprint="b" * 64,
            activation_gate={"gateFingerprint": "b" * 64},
            catalog_path=self.root / "adaptive-subagents.toml",
        )

        error = StringIO()
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "проверь"]),
            mock.patch.dict(
                self.globals,
                {
                    "classify_managed_invocation": classify_managed_invocation,
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: decision,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(69, self.globals["main"]())

        self.assertIn(
            "COORDINATOR_ACCOUNT_CATALOG_UNAVAILABLE",
            error.getvalue(),
        )
        self.assertIn("codex-native", error.getvalue())
        self.assertNotIn("model/list", error.getvalue())

    def test_required_preparation_exception_returns_69_without_details(self) -> None:
        def unavailable(**_kwargs):
            raise RuntimeError("private preparation details")

        error = StringIO()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_REQUIRED": "1",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "проверь"]),
            mock.patch.dict(
                self.globals,
                {
                    "classify_managed_invocation": classify_managed_invocation,
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": unavailable,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(69, self.globals["main"]())

        self.assertIn("MANAGED_PREPARATION_FAILED", error.getvalue())
        self.assertIn("codex-native", error.getvalue())
        self.assertNotIn("private preparation details", error.getvalue())

    def test_required_marker_rejects_values_other_than_zero_or_one(self) -> None:
        error = StringIO()
        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_REQUIRED": "yes",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "проверь"]),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: (
                        self.fail("invalid marker reached gateway selection")
                    ),
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(69, self.globals["main"]())

        self.assertIn("CODEX_SMART_REQUIRED_INVALID", error.getvalue())
        self.assertIn("codex-native", error.getvalue())

    def test_invalid_required_marker_does_not_block_service_bypass(self) -> None:
        decision = _ordinary(self.fallback)
        gateway_arguments: dict[str, object] = {}

        class Resolver:
            def __init__(self, **_kwargs) -> None:
                pass

            def resolve(self):
                return decision

        def gateway(arguments, **kwargs):
            self.assertEqual(["help"], arguments)
            gateway_arguments.update(kwargs)
            return 17

        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_REQUIRED": "yes",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "help"]),
            mock.patch.dict(
                self.globals,
                {
                    "classify_managed_invocation": classify_managed_invocation,
                    "v2_gateway_state_present": lambda _layout: True,
                    "ActivationResolver": Resolver,
                    "run_permanent_gateway": gateway,
                },
            ),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertFalse(gateway_arguments["managed_required"])

    def test_supervisor_failure_downgrades_ready_claim_to_ordinary(self) -> None:
        ready = SimpleNamespace(
            state=GatewayState.READY,
            executable=self.fallback,
        )
        observed: list[GatewayDecision] = []
        gateway_arguments: dict[str, object] = {}

        class Resolver:
            def __init__(self, **_kwargs) -> None:
                pass

            def resolve(self):
                return ready

            def resolve_persisted_activation(self):
                return SimpleNamespace(
                    runtime_binding=SimpleNamespace(state_home=self_state_home)
                )

        class Supervisor:
            def __init__(self, **_kwargs) -> None:
                raise RuntimeError("private details")

        def gateway(_arguments, **kwargs):
            gateway_arguments.update(kwargs)
            observed.append(kwargs["resolver"].resolve())
            return 0

        globals_ = self.globals
        self_state_home = self.root / "external-state"
        self_state_home.mkdir(mode=0o700)
        with (
            mock.patch.dict(
                os.environ, {"CODEX_HOME": str(self.codex_home)}, clear=True
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER)]),
            mock.patch.dict(
                globals_,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "ActivationResolver": Resolver,
                    "ControllerSupervisorV2": Supervisor,
                    "run_permanent_gateway": gateway,
                },
            ),
        ):
            self.assertEqual(0, globals_["main"]())

        self.assertEqual(1, len(observed))
        self.assertIs(GatewayState.ORDINARY, observed[0].state)
        self.assertEqual(self.fallback, observed[0].executable)
        self.assertEqual("CONTROLLER_SUPERVISOR_FAILED", observed[0].reason_code)
        self.assertFalse(gateway_arguments["managed_required"])


if __name__ == "__main__":
    unittest.main()
