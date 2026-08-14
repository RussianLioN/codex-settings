from __future__ import annotations

import importlib.util
import io
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "plugins" / "codex-smart-subagents"
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SRC))


def _load_server() -> ModuleType:
    path = PLUGIN_ROOT / "controller" / "server.py"
    spec = importlib.util.spec_from_file_location("controller_server_v2_test", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ControllerServerV2Tests(unittest.TestCase):
    def test_main_dispatches_exact_v2_mode(self) -> None:
        module = _load_server()
        with mock.patch.object(module, "serve_v2", return_value=None) as serve:
            self.assertEqual(0, module.main(["--serve-v2"]))
        serve.assert_called_once_with(os.environ)

    def test_main_dispatches_exact_candidate_v2_mode(self) -> None:
        module = _load_server()
        with mock.patch.object(
            module, "serve_candidate_v2", return_value=None
        ) as serve:
            self.assertEqual(0, module.main(["--serve-candidate-v2"]))
        serve.assert_called_once_with(os.environ)

    def test_serve_candidate_v2_uses_closed_candidate_loader_and_runtime(self) -> None:
        module = _load_server()
        config = SimpleNamespace(
            codex_home=Path("/tmp/codex-home"),
            operation_id="op2_" + "1" * 32,
            controller_start_id="cs2_" + "2" * 32,
        )
        ready_bootstrap = object()
        captured = {}
        environment = {"CODEX_HOME": "/tmp/codex-home"}
        events: list[str] = []

        module.serve_candidate_v2(
            environment,
            config_loader=lambda **arguments: (
                captured.update(loader=arguments) or config
            ),
            ready_bootstrap_loader=lambda **arguments: (
                events.append("bootstrap")
                or captured.update(ready_loader=arguments)
                or ready_bootstrap
            ),
            ownership_gate_waiter=lambda loaded_environment: (
                self.assertIs(environment, loaded_environment)
                or events.append("ownership-gate")
            ),
            server=lambda loaded, **arguments: (
                self.assertIs(config, loaded)
                or events.append("server")
                or captured.update(server=arguments)
                or None
            ),
        )

        self.assertEqual(PLUGIN_ROOT, captured["loader"]["plugin_root"])
        self.assertEqual(
            {
                "codex_home": config.codex_home,
                "environment": environment,
                "operation_id": config.operation_id,
                "controller_start_id": config.controller_start_id,
            },
            captured["ready_loader"],
        )
        self.assertIs(ready_bootstrap, captured["server"]["ready_bootstrap"])
        self.assertEqual(
            module._build_dispatcher_factory_v2,
            captured["server"]["dispatcher_factory_builder"],
        )
        self.assertEqual(
            module.install_v2_signal_handlers,
            captured["server"]["signal_installer"],
        )
        self.assertEqual(["bootstrap", "ownership-gate", "server"], events)

    def test_serve_v2_composes_config_policy_dispatcher_and_closes(self) -> None:
        module = _load_server()
        config = SimpleNamespace(source_root=ROOT, plugin_root=PLUGIN_ROOT)
        policy = object()
        events: list[str] = []

        class Application:
            def wait(self) -> None:
                events.append("wait")

            def close(self) -> None:
                events.append("close")

        module.serve_v2(
            {"CODEX_HOME": "/tmp/codex-home"},
            config_loader=lambda **kwargs: (
                self.assertEqual(PLUGIN_ROOT, kwargs["plugin_root"]) or config
            ),
            policy_loader=lambda **kwargs: (
                self.assertEqual(ROOT, kwargs["source_root"])
                or self.assertEqual(PLUGIN_ROOT, kwargs["plugin_root"])
                or policy
            ),
            starter=lambda loaded, **kwargs: (
                self.assertIs(config, loaded)
                or self.assertIs(policy, kwargs["policy_bundle"])
                or self.assertIs(
                    module._build_dispatcher_factory_v2,
                    kwargs["dispatcher_factory_builder"],
                )
                or Application()
            ),
            signal_installer=lambda _application: events.append("signals"),
        )

        self.assertEqual(["signals", "wait", "close"], events)

    def test_unknown_mode_remains_rejected(self) -> None:
        module = _load_server()
        self.assertEqual(2, module.main(["--unknown"]))

    def test_v2_start_error_is_bounded_for_the_installer_pipe(self) -> None:
        module = _load_server()

        class StartupFailure(RuntimeError):
            code = "STARTUP_FAILED"
            message = "x" * 10000

        output = io.StringIO()
        with (
            mock.patch.object(module, "serve_v2", side_effect=StartupFailure()),
            mock.patch.object(module.sys, "stderr", output),
        ):
            self.assertEqual(1, module.main(["--serve-v2"]))

        rendered = output.getvalue()
        self.assertIn("STARTUP_FAILED", rendered)
        self.assertLessEqual(len(rendered.encode("utf-8")), 4096)


if __name__ == "__main__":
    unittest.main()
