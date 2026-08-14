from __future__ import annotations

import inspect
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "plugins" / "codex-smart-subagents"
PLUGIN_SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.activation_gateway_v2 import (  # noqa: E402
    GatewayDecision,
    GatewayState,
)
from codex_smart_subagents.controller_supervisor_v2 import (  # noqa: E402
    ControllerSpawnSpecV2,
    ControllerSupervisorV2,
    SupervisorStateV2,
    probe_controller_command_socket_v2,
    spawn_controller_process_v2,
)
from codex_smart_subagents.controller_command_v2 import (  # noqa: E402
    ControllerCommandServerV2,
)
from codex_smart_subagents.model_catalog import (  # noqa: E402
    AppServerModelCatalogInspector,
)


class _Resolver:
    def __init__(self, decisions: list[GatewayDecision]) -> None:
        self.decisions = decisions
        self.calls = 0

    def resolve(self) -> GatewayDecision:
        index = min(self.calls, len(self.decisions) - 1)
        self.calls += 1
        return self.decisions[index]


class _Clock:
    def __init__(self) -> None:
        self.value = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class _Probe:
    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.calls: list[Path] = []

    def __call__(self, path: Path) -> bool:
        self.calls.append(path)
        index = min(len(self.calls) - 1, len(self.values) - 1)
        value = self.values[index]
        if isinstance(value, BaseException):
            raise value
        return bool(value)


def _ordinary(executable: Path, reason: str = "CONTROLLER_UNAVAILABLE"):
    return GatewayDecision(
        state=GatewayState.ORDINARY,
        reason_code=reason,
        executable=executable,
    )


def _ready(executable: Path):
    gate = {"gateFingerprint": "c" * 64}
    return GatewayDecision(
        state=GatewayState.READY,
        reason_code="READY",
        executable=executable,
        coordinator={"model": "gpt-5.6-terra", "reasoning_effort": "medium"},
        activation_id="act2_" + "a" * 64,
        gate_fingerprint="c" * 64,
        activation_gate=gate,
        catalog_path=ROOT / ".codex" / "adaptive-subagents.toml",
    )


class ControllerSupervisorV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            dir="/tmp",
            prefix="csv2-",
        )
        self.root = Path(self.temporary.name).resolve()
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        self.state_home = self.codex_home / "state" / "codex-smart-subagents-v2"
        self.state_home.mkdir(parents=True, mode=0o700)
        self.manifest = self.codex_home / "install-manifests" / "active.json"
        self.manifest.parent.mkdir(mode=0o700)
        self.manifest.write_text("{}", encoding="utf-8")
        self.manifest.chmod(0o600)
        self.fallback = self.root / "codex"
        self.fallback.write_text("#!/bin/sh\n", encoding="utf-8")
        self.fallback.chmod(0o500)
        self.clock = _Clock()
        self.spawn_specs: list[ControllerSpawnSpecV2] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _supervisor(
        self,
        *,
        resolver: _Resolver,
        probe: _Probe,
        spawn=None,
        wait_timeout_seconds: float = 0.3,
        source_environment: dict[str, str] | None = None,
    ) -> ControllerSupervisorV2:
        def record_spawn(spec: ControllerSpawnSpecV2) -> object:
            self.spawn_specs.append(spec)
            return object()

        return ControllerSupervisorV2(
            resolver=resolver,
            command_probe=probe,
            spawn=spawn or record_spawn,
            clock=self.clock.monotonic,
            sleep=self.clock.sleep,
            manifest_path=self.manifest,
            state_home=self.state_home,
            codex_home=self.codex_home,
            plugin_root=PLUGIN_ROOT,
            python_executable=Path(sys.executable),
            source_environment=(
                source_environment
                if source_environment is not None
                else {"HOME": str(self.root), "PATH": "/untrusted/bin"}
            ),
            wait_timeout_seconds=wait_timeout_seconds,
            poll_interval_seconds=0.1,
        )

    def test_already_ready_requires_both_proofs_and_never_spawns(self) -> None:
        resolver = _Resolver([_ready(self.fallback)])
        probe = _Probe([True])
        supervisor = self._supervisor(resolver=resolver, probe=probe)

        result = supervisor.ensure()

        self.assertIs(SupervisorStateV2.READY, result.state)
        self.assertTrue(result.smart_enabled)
        self.assertFalse(result.spawn_attempted)
        self.assertEqual(self.fallback, result.executable)
        self.assertEqual([], self.spawn_specs)
        self.assertEqual([self.state_home / "command.sock"], probe.calls)
        self.assertEqual(1, resolver.calls)

    def test_ready_health_without_command_socket_spawns_once_then_converges(
        self,
    ) -> None:
        resolver = _Resolver([_ready(self.fallback)])
        probe = _Probe([False, False, True])
        supervisor = self._supervisor(resolver=resolver, probe=probe)

        result = supervisor.ensure()

        self.assertIs(SupervisorStateV2.READY, result.state)
        self.assertTrue(result.spawn_attempted)
        self.assertTrue(result.spawn_succeeded)
        self.assertEqual(1, len(self.spawn_specs))
        self.assertEqual(3, len(probe.calls))

    def test_dead_health_with_manifest_spawns_once_and_accepts_later_readiness(
        self,
    ) -> None:
        resolver = _Resolver(
            [_ordinary(self.fallback), _ordinary(self.fallback), _ready(self.fallback)]
        )
        probe = _Probe([True])
        supervisor = self._supervisor(resolver=resolver, probe=probe)

        result = supervisor.ensure()

        self.assertIs(SupervisorStateV2.READY, result.state)
        self.assertEqual(1, len(self.spawn_specs))
        self.assertGreaterEqual(resolver.calls, 3)
        self.assertEqual([self.state_home / "command.sock"], probe.calls)

    def test_losing_spawn_race_still_accepts_the_winner(self) -> None:
        attempts: list[ControllerSpawnSpecV2] = []

        def losing_spawn(spec: ControllerSpawnSpecV2) -> object:
            attempts.append(spec)
            raise FileExistsError("controller lock is held")

        resolver = _Resolver([_ordinary(self.fallback), _ready(self.fallback)])
        supervisor = self._supervisor(
            resolver=resolver,
            probe=_Probe([True]),
            spawn=losing_spawn,
        )

        result = supervisor.ensure()

        self.assertIs(SupervisorStateV2.READY, result.state)
        self.assertTrue(result.spawn_attempted)
        self.assertFalse(result.spawn_succeeded)
        self.assertEqual(1, len(attempts))

    def test_timeout_closes_smart_path_but_preserves_ordinary_executable(self) -> None:
        resolver = _Resolver([_ordinary(self.fallback)])
        supervisor = self._supervisor(
            resolver=resolver,
            probe=_Probe([False]),
            wait_timeout_seconds=0.25,
        )

        result = supervisor.ensure()

        self.assertIs(SupervisorStateV2.ORDINARY, result.state)
        self.assertFalse(result.smart_enabled)
        self.assertEqual("CONTROLLER_NOT_READY", result.reason_code)
        self.assertEqual(self.fallback, result.executable)
        self.assertEqual(1, len(self.spawn_specs))
        self.assertLessEqual(sum(self.clock.sleeps), 0.250001)
        self.assertGreaterEqual(resolver.calls, 2)

    def test_installer_can_request_the_full_readiness_wait_budget(self) -> None:
        supervisor = self._supervisor(
            resolver=_Resolver([_ready(self.fallback)]),
            probe=_Probe([True]),
            wait_timeout_seconds=120.0,
        )

        result = supervisor.ensure()

        self.assertIs(SupervisorStateV2.READY, result.state)

    def test_default_wait_exceeds_the_five_second_catalog_inspection(self) -> None:
        supervisor_default = inspect.signature(
            ControllerSupervisorV2.__init__
        ).parameters["wait_timeout_seconds"].default
        inspector_default = inspect.signature(
            AppServerModelCatalogInspector.__init__
        ).parameters["timeout_seconds"].default

        self.assertEqual(5.0, inspector_default)
        self.assertGreater(supervisor_default, inspector_default)

    def test_absent_or_unsafe_manifest_never_spawns(self) -> None:
        for mutation in ("absent", "unsafe-mode"):
            with self.subTest(mutation=mutation):
                if self.manifest.exists():
                    self.manifest.unlink()
                if mutation == "unsafe-mode":
                    self.manifest.write_text("{}", encoding="utf-8")
                    self.manifest.chmod(0o644)
                self.spawn_specs.clear()
                result = self._supervisor(
                    resolver=_Resolver(
                        [_ordinary(self.fallback, "MANIFEST_UNAVAILABLE")]
                    ),
                    probe=_Probe([True]),
                ).ensure()
                self.assertIs(SupervisorStateV2.ORDINARY, result.state)
                self.assertEqual(self.fallback, result.executable)
                self.assertEqual([], self.spawn_specs)

    def test_ready_claim_without_manifest_closes_with_command_reason(self) -> None:
        self.manifest.unlink()
        result = self._supervisor(
            resolver=_Resolver([_ready(self.fallback)]),
            probe=_Probe([False]),
        ).ensure()

        self.assertIs(SupervisorStateV2.ORDINARY, result.state)
        self.assertEqual("COMMAND_UNAVAILABLE", result.reason_code)
        self.assertEqual([], self.spawn_specs)

    def test_spawn_spec_is_nonblocking_and_has_closed_environment(self) -> None:
        environment = {
            "HOME": str(self.root),
            "TMPDIR": str(self.root / "tmp"),
            "PATH": "/attacker/bin",
            "LANG": "ru_RU.UTF-8",
            "CODEX_SMART_ACTIVATION_GATE": "секрет",
            "CODEX_ADAPTIVE_SESSION_ID": "cas2_" + "Z" * 32,
            "CODEX_COORDINATOR_TOKEN": "секрет",
            "CODEX_REAL_BIN": "/private/codex",
            "CODEX_V2_STATE_HOME": "/private/attacker-state",
            "PYTHONPATH": "/tmp/injection",
            "WIFI_PASSWORD": "секрет",
        }
        supervisor = self._supervisor(
            resolver=_Resolver([_ordinary(self.fallback)]),
            probe=_Probe([False]),
            source_environment=environment,
            wait_timeout_seconds=0.1,
        )

        supervisor.ensure()

        self.assertEqual(1, len(self.spawn_specs))
        spec = self.spawn_specs[0]
        self.assertEqual(
            (
                str(Path(sys.executable).resolve()),
                str((PLUGIN_ROOT / "controller" / "server.py").resolve()),
                "--serve-v2",
            ),
            spec.argv,
        )
        self.assertEqual(PLUGIN_ROOT.resolve(), spec.cwd)
        self.assertTrue(spec.nonblocking)
        self.assertEqual(str(self.codex_home), spec.environment["CODEX_HOME"])
        self.assertEqual(str(self.state_home), spec.environment["CODEX_V2_STATE_HOME"])
        self.assertEqual("1", spec.environment["PYTHONDONTWRITEBYTECODE"])
        self.assertEqual(os.defpath, spec.environment["PATH"])
        self.assertNotIn("PYTHONPATH", spec.environment)
        self.assertNotIn("WIFI_PASSWORD", spec.environment)
        self.assertFalse(
            any(
                name.startswith(
                    ("CODEX_SMART_", "CODEX_ADAPTIVE_", "CODEX_COORDINATOR_")
                )
                or name == "CODEX_REAL_BIN"
                for name in spec.environment
            )
        )

    def test_supervisor_does_not_open_sqlite_and_never_retries_spawn(self) -> None:
        resolver = _Resolver([_ordinary(self.fallback)])
        supervisor = self._supervisor(
            resolver=resolver,
            probe=_Probe([RuntimeError("socket unavailable")]),
            wait_timeout_seconds=0.3,
        )

        with mock.patch.object(
            sqlite3,
            "connect",
            side_effect=AssertionError("supervisor opened SQLite"),
        ):
            first = supervisor.ensure()

        self.assertIs(SupervisorStateV2.ORDINARY, first.state)
        self.assertEqual(1, len(self.spawn_specs))

        resolver.decisions[:] = [_ready(self.fallback)]
        supervisor.command_probe = _Probe([True])
        second = supervisor.ensure()
        self.assertIs(SupervisorStateV2.READY, second.state)
        self.assertEqual(1, len(self.spawn_specs))

    def test_default_spawn_is_nonblocking_and_closes_process_streams(self) -> None:
        spec = self._supervisor(
            resolver=_Resolver([_ordinary(self.fallback)]),
            probe=_Probe([False]),
        ).spawn_spec()
        sentinel = object()
        with mock.patch(
            "codex_smart_subagents.controller_supervisor_v2.subprocess.Popen",
            return_value=sentinel,
        ) as popen:
            self.assertIs(sentinel, spawn_controller_process_v2(spec))

        popen.assert_called_once_with(
            spec.argv,
            cwd=spec.cwd,
            env=dict(spec.environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )

    def test_default_command_probe_accepts_only_live_private_owned_socket(self) -> None:
        server = ControllerCommandServerV2(
            socket_path=self.state_home / "command.sock",
            lock_path=self.state_home / "command.lock",
            handler=lambda _shell, _method, _arguments: {},
        )
        server.start()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            self.assertTrue(
                probe_controller_command_socket_v2(self.state_home / "command.sock")
            )
        finally:
            server.close()
            thread.join(timeout=2)

        replacement = self.state_home / "command.sock"
        replacement.write_text("не сокет", encoding="utf-8")
        replacement.chmod(0o600)
        self.assertFalse(probe_controller_command_socket_v2(replacement))


if __name__ == "__main__":
    unittest.main()
