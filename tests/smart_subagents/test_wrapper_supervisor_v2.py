from __future__ import annotations

import os
import runpy
import sys
import tempfile
import unittest
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
        decision = _ordinary(self.fallback)
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
            return 17

        globals_ = self.globals
        self_state_home = self.root / "external-state"
        self_state_home.mkdir(mode=0o700)
        with (
            mock.patch.dict(
                os.environ, {"CODEX_HOME": str(self.codex_home)}, clear=True
            ),
            mock.patch.object(sys, "argv", [str(WRAPPER), "exec", "task"]),
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

    def test_supervisor_failure_downgrades_ready_claim_to_ordinary(self) -> None:
        ready = SimpleNamespace(
            state=GatewayState.READY,
            executable=self.fallback,
        )
        observed: list[GatewayDecision] = []

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


if __name__ == "__main__":
    unittest.main()
