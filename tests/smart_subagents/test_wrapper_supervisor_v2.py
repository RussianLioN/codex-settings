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
from codex_smart_subagents.source_reconciliation_v1 import (  # noqa: E402
    SourceReconciliationContinuationProhibitedV1,
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

    def _ready_snapshot_decision(self) -> GatewayDecision:
        snapshot = self.root / "snapshot-codex"
        snapshot.write_text("#!/bin/sh\n", encoding="utf-8")
        snapshot.chmod(0o500)
        live_codex = self.root / "live-codex"
        live_codex.write_text("#!/bin/sh\n", encoding="utf-8")
        live_codex.chmod(0o500)
        return GatewayDecision(
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

    def test_source_drift_reconciles_and_restarts_stable_wrapper_once(self) -> None:
        decision = self._ready_snapshot_decision()
        stable_wrapper = self.root / "bin" / "codex-smart"
        stable_wrapper.parent.mkdir(mode=0o700)
        stable_wrapper.symlink_to(WRAPPER)
        reconcile_calls: list[tuple[GatewayDecision, object]] = []

        class ExecCalled(RuntimeError):
            def __init__(self, executable, arguments, environment) -> None:
                self.executable = executable
                self.arguments = tuple(arguments)
                self.environment = dict(environment)

        def reconcile(**kwargs):
            reconcile_calls.append((kwargs["decision"], kwargs["gateway_layout"]))
            return (
                SimpleNamespace(outcome="ACCEPTED", restart=True),
                stable_wrapper,
            )

        def execve(executable, arguments, environment):
            raise ExecCalled(executable, arguments, environment)

        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_STALE": "remove-me",
                    "PATH": "/usr/bin",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "исправь задачу"]),
            mock.patch.object(os, "execve", side_effect=execve),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: decision,
                    "_reconcile_source_drift": reconcile,
                    "run_permanent_gateway": lambda *_args, **_kwargs: self.fail(
                        "accepted reconciliation reached the old gateway"
                    ),
                },
            ),
            self.assertRaises(ExecCalled) as caught,
        ):
            self.globals["main"]()

        self.assertEqual(1, len(reconcile_calls))
        self.assertIs(decision, reconcile_calls[0][0])
        self.assertEqual(str(stable_wrapper), caught.exception.executable)
        self.assertEqual(
            (str(stable_wrapper), "исправь задачу"),
            caught.exception.arguments,
        )
        self.assertEqual(
            "1",
            caught.exception.environment["CODEX_SMART_RECONCILED_V1"],
        )
        self.assertNotIn("CODEX_SMART_STALE", caught.exception.environment)
        self.assertEqual("/usr/bin", caught.exception.environment["PATH"])

    def test_update_failure_warns_once_and_continues_exact_snapshot(self) -> None:
        decision = self._ready_snapshot_decision()
        gateway_decisions: list[GatewayDecision] = []
        error = StringIO()

        def gateway(_arguments, **kwargs):
            gateway_decisions.append(kwargs["resolver"].resolve())
            return 17

        for result in (
            SimpleNamespace(outcome="INCOMPATIBLE", restart=False),
            SimpleNamespace(outcome="RETRY_AFTER", restart=False),
        ):
            with self.subTest(outcome=result.outcome):
                error.seek(0)
                error.truncate(0)
                gateway_decisions.clear()
                with (
                    mock.patch.dict(
                        os.environ,
                        {"CODEX_HOME": str(self.codex_home)},
                        clear=True,
                    ),
                    mock.patch.object(sys, "argv", [str(WRAPPER), "задача"]),
                    mock.patch.dict(
                        self.globals,
                        {
                            "v2_gateway_state_present": lambda _layout: True,
                            "_prepare_v2_decision": lambda **_kwargs: decision,
                            "_reconcile_source_drift": lambda **_kwargs: (
                                result,
                                self.root / "bin" / "codex-smart",
                            ),
                            "run_permanent_gateway": gateway,
                        },
                    ),
                    redirect_stderr(error),
                ):
                    self.assertEqual(17, self.globals["main"]())

                self.assertEqual([decision], gateway_decisions)
                self.assertEqual(
                    "codex-smart: "
                    f"SOURCE_UPDATE_{result.outcome}; "
                    "используется последний проверенный снимок\n",
                    error.getvalue(),
                )

    def test_reconciliation_error_warns_once_and_continues_snapshot(self) -> None:
        decision = self._ready_snapshot_decision()
        gateway_decisions: list[GatewayDecision] = []
        error = StringIO()

        def fail(**_kwargs):
            raise OSError("private updater failure")

        def gateway(_arguments, **kwargs):
            gateway_decisions.append(kwargs["resolver"].resolve())
            return 17

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "задача"]),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: decision,
                    "_reconcile_source_drift": fail,
                    "run_permanent_gateway": gateway,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual([decision], gateway_decisions)
        self.assertEqual(
            "codex-smart: SOURCE_UPDATE_RETRY_AFTER; "
            "используется последний проверенный снимок\n",
            error.getvalue(),
        )
        self.assertNotIn("private updater failure", error.getvalue())

    def test_cleanup_prohibition_warns_and_continues_verified_snapshot(self) -> None:
        decision = self._ready_snapshot_decision()
        error = StringIO()
        decisions: list[GatewayDecision] = []

        def prohibited(**_kwargs):
            raise SourceReconciliationContinuationProhibitedV1()

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(self.codex_home)},
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "задача"]),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: decision,
                    "_reconcile_source_drift": prohibited,
                    "run_permanent_gateway": lambda *_args, **kwargs: (
                        decisions.append(kwargs["resolver"].resolve()) or 17
                    ),
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual(
            "codex-smart: SOURCE_UPDATE_CLEANUP_REQUIRED; "
            "используется последний проверенный снимок\n",
            error.getvalue(),
        )
        self.assertEqual([decision], decisions)
        self.assertNotIn("CONTINUATION_PROHIBITED", error.getvalue())

    def test_restart_guard_never_runs_reconciler_twice(self) -> None:
        decision = self._ready_snapshot_decision()
        gateway_decisions: list[GatewayDecision] = []
        error = StringIO()

        def gateway(_arguments, **kwargs):
            gateway_decisions.append(kwargs["resolver"].resolve())
            return 17

        with (
            mock.patch.dict(
                os.environ,
                {
                    "CODEX_HOME": str(self.codex_home),
                    "CODEX_SMART_RECONCILED_V1": "1",
                },
                clear=True,
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "задача"]),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: decision,
                    "_reconcile_source_drift": lambda **_kwargs: self.fail(
                        "restart guard invoked reconciliation"
                    ),
                    "run_permanent_gateway": gateway,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual([decision], gateway_decisions)
        self.assertEqual(
            "codex-smart: SOURCE_UPDATE_RESTART_GUARD; "
            "используется последний проверенный снимок\n",
            error.getvalue(),
        )

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
        error = StringIO()
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
                    "_reconcile_source_drift": lambda **_kwargs: (
                        SimpleNamespace(outcome="RETRY_AFTER", restart=False),
                        self.root / "bin/codex-smart",
                    ),
                    "run_permanent_gateway": gateway,
                },
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(17, globals_["main"]())

        self.assertEqual(self.codex_home, supervisor_arguments["codex_home"])
        self.assertEqual(
            self_state_home,
            supervisor_arguments["state_home"],
        )
        self.assertIn("SOURCE_UPDATE_RETRY_AFTER", error.getvalue())

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
                            "_reconcile_source_drift": lambda **_kwargs: self.fail(
                                "native invocation started reconciliation"
                            ),
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
                    "_reconcile_source_drift": unexpected("reconciliation"),
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

    def test_stale_required_marker_cannot_turn_interactive_launch_strict(self) -> None:
        decision = _ordinary(self.fallback, reason="MANIFEST_INVALID")
        gateway_arguments: dict[str, object] = {}

        class StrictFailure(RuntimeError):
            def __init__(self, code: str, message: str) -> None:
                super().__init__(f"{code}: {message}")
                self.code = code
                self.message = message

        gateway_calls: list[dict[str, object]] = []

        def gateway(_arguments, **kwargs):
            gateway_calls.append(dict(kwargs))
            gateway_arguments.update(kwargs)
            if len(gateway_calls) == 1:
                raise StrictFailure("MANIFEST_INVALID", "private resolver details")
            return 17

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
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual(2, len(gateway_calls))
        self.assertFalse(gateway_calls[0]["managed_required"])
        self.assertFalse(gateway_calls[1]["managed_required"])
        self.assertIsNone(gateway_calls[1]["resolver"])
        self.assertEqual("", error.getvalue())

    def test_automatic_coordinator_unavailable_starts_limited_managed_root(
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

        decisions: list[GatewayDecision] = []

        def gateway(_arguments, **kwargs):
            decisions.append(kwargs["resolver"].resolve())
            self.assertFalse(kwargs["managed_required"])
            return 17

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
                    "run_permanent_gateway": gateway,
                },
            ),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual([decision], decisions)

    def test_preparation_exception_automatically_uses_real_codex_path(self) -> None:
        def unavailable(**_kwargs):
            raise RuntimeError("private preparation details")

        gateway_calls: list[dict[str, object]] = []

        def gateway(_arguments, **kwargs):
            gateway_calls.append(dict(kwargs))
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
            mock.patch.object(sys, "argv", [str(WRAPPER), "проверь"]),
            mock.patch.dict(
                self.globals,
                {
                    "classify_managed_invocation": classify_managed_invocation,
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": unavailable,
                    "run_permanent_gateway": gateway,
                },
            ),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual(1, len(gateway_calls))
        self.assertIsNone(gateway_calls[0]["resolver"])
        self.assertFalse(gateway_calls[0]["managed_required"])

    def test_invalid_required_marker_is_ignored_for_interactive_launch(self) -> None:
        gateway_calls: list[dict[str, object]] = []

        def gateway(_arguments, **kwargs):
            gateway_calls.append(dict(kwargs))
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
            mock.patch.object(sys, "argv", [str(WRAPPER), "проверь"]),
            mock.patch.dict(
                self.globals,
                {
                    "v2_gateway_state_present": lambda _layout: True,
                    "_prepare_v2_decision": lambda **_kwargs: _ordinary(
                        self.fallback
                    ),
                    "run_permanent_gateway": gateway,
                },
            ),
        ):
            self.assertEqual(17, self.globals["main"]())

        self.assertEqual(1, len(gateway_calls))
        self.assertFalse(gateway_calls[0]["managed_required"])

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
