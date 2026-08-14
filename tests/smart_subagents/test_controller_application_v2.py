from __future__ import annotations

import threading
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.controller_application_v2 import (  # noqa: E402
    ControllerApplicationV2,
    ControllerApplicationV2Error,
)


class _HealthRuntime:
    def __init__(self, *, owns_runtime: bool = True) -> None:
        self.owns_runtime = owns_runtime
        self.closed = False
        self.lifecycle_handler = None
        self.lifecycle_response_observer = None

    def bind_lifecycle_handler(self, handler, *, response_observer=None) -> None:
        self.lifecycle_handler = handler
        self.lifecycle_response_observer = response_observer

    def close(self) -> None:
        self.closed = True


class _Provider:
    def __init__(self) -> None:
        self.entered: list[str] = []
        self.exited: list[str] = []

    class _Scope:
        def __init__(self, owner: "_Provider", shell: str) -> None:
            self.owner = owner
            self.shell = shell

        def __enter__(self) -> None:
            self.owner.entered.append(self.shell)

        def __exit__(self, *_args: object) -> None:
            self.owner.exited.append(self.shell)

    def bind(self, shell_session_id: str) -> "_Provider._Scope":
        return self._Scope(self, shell_session_id)


class _ToolServer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call_tool(self, method: str, arguments: dict[str, object]) -> dict[str, object]:
        self.calls.append((method, arguments))
        return {"method": method, "arguments": arguments}


class _Production:
    def __init__(self, events: list[str]) -> None:
        self.server = _ToolServer()
        self.closed = False
        self.events = events

    def close(self) -> None:
        self.closed = True
        self.events.append("production.close")


class _CommandServer:
    def __init__(
        self,
        handler,
        events: list[str],
        *,
        fail_start: bool = False,
        fail_serve: bool = False,
    ) -> None:
        self.handler = handler
        self.events = events
        self.fail_start = fail_start
        self.fail_serve = fail_serve
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.closed = False

    def start(self) -> None:
        self.events.append("command.start")
        if self.fail_start:
            raise RuntimeError("bind failed")
        self.ready.set()

    def wait_until_ready(self, timeout: float) -> bool:
        return self.ready.wait(timeout)

    def serve_forever(self) -> None:
        self.events.append("command.serve")
        if self.fail_serve:
            raise RuntimeError("serve failed")
        self.stop.wait(2.0)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.events.append("command.close")
        self.stop.set()


class ControllerApplicationV2Tests(unittest.TestCase):
    def test_lifecycle_shutdown_response_requests_process_stop_after_reply(self) -> None:
        events: list[str] = []
        health = _HealthRuntime()
        command = _CommandServer(lambda *_args: {}, events)

        application = ControllerApplicationV2.start(
            health_runtime=health,
            provider=_Provider(),
            production_factory=lambda _provider: _Production(events),
            command_server_factory=lambda _handler: command,
            lifecycle_handler=lambda request: {"request": request},
        )
        try:
            self.assertIsNotNone(health.lifecycle_handler)
            self.assertTrue(callable(health.lifecycle_response_observer))
            health.lifecycle_response_observer(
                {"method": "shutdown"},
                {
                    "responseKind": "SUCCESS",
                    "payload": {"status": "SHUTDOWN_COMMITTED"},
                },
            )

            self.assertTrue(application.wait(timeout_seconds=0.2))
            self.assertTrue(command.closed)
        finally:
            application.close()

    def test_binds_each_private_call_to_exact_shell_scope(self) -> None:
        events: list[str] = []
        health = _HealthRuntime()
        provider = _Provider()
        production = _Production(events)
        command_holder: list[_CommandServer] = []

        application = ControllerApplicationV2.start(
            health_runtime=health,
            provider=provider,
            production_factory=lambda _provider: production,
            command_server_factory=lambda handler: command_holder.append(
                _CommandServer(handler, events)
            )
            or command_holder[-1],
        )
        try:
            command = command_holder[0]
            result = command.handler(
                "cas2_" + "a" * 32,
                "smart_plan",
                {
                    "nodes": [
                        {
                            "clientNodeId": "reader_a",
                            "dependencyIds": [],
                            "routingInput": {},
                        }
                    ]
                },
            )
            self.assertEqual(
                {
                    "method": "smart_plan",
                    "arguments": {
                        "nodes": [
                            {
                                "clientNodeId": "reader_a",
                                "dependencyIds": [],
                                "routingInput": {},
                            }
                        ]
                    },
                },
                result,
            )
            self.assertEqual(["cas2_" + "a" * 32], provider.entered)
            self.assertEqual(provider.entered, provider.exited)
            self.assertEqual(
                [
                    (
                        "smart_plan",
                        {
                            "nodes": [
                                {
                                    "clientNodeId": "reader_a",
                                    "dependencyIds": [],
                                    "routingInput": {},
                                }
                            ]
                        },
                    )
                ],
                production.server.calls,
            )
            self.assertTrue(application.ready)
        finally:
            application.close()
        self.assertTrue(health.closed)
        self.assertTrue(production.closed)
        self.assertTrue(command_holder[0].closed)

    def test_refuses_to_serve_when_health_runtime_is_foreign(self) -> None:
        health = _HealthRuntime(owns_runtime=False)
        built: list[str] = []
        with self.assertRaisesRegex(
            ControllerApplicationV2Error,
            "CONTROLLER_OWNERSHIP_REQUIRED",
        ):
            ControllerApplicationV2.start(
                health_runtime=health,
                provider=_Provider(),
                production_factory=lambda _provider: built.append("production"),
                command_server_factory=lambda _handler: built.append("command"),
            )
        self.assertEqual([], built)
        self.assertFalse(health.closed)

    def test_command_start_failure_rolls_back_production_and_health(self) -> None:
        events: list[str] = []
        health = _HealthRuntime()
        production = _Production(events)
        command = _CommandServer(lambda *_args: {}, events, fail_start=True)
        with self.assertRaisesRegex(RuntimeError, "bind failed"):
            ControllerApplicationV2.start(
                health_runtime=health,
                provider=_Provider(),
                production_factory=lambda _provider: production,
                command_server_factory=lambda _handler: command,
            )
        self.assertTrue(command.closed)
        self.assertTrue(production.closed)
        self.assertTrue(health.closed)
        self.assertEqual(
            ["command.start", "command.close", "production.close"],
            events,
        )

    def test_background_failure_is_reported_and_closes_all_components(self) -> None:
        events: list[str] = []
        health = _HealthRuntime()
        production = _Production(events)
        command = _CommandServer(lambda *_args: {}, events, fail_serve=True)
        application = ControllerApplicationV2.start(
            health_runtime=health,
            provider=_Provider(),
            production_factory=lambda _provider: production,
            command_server_factory=lambda _handler: command,
        )
        with self.assertRaisesRegex(
            ControllerApplicationV2Error,
            "COMMAND_SERVER_FAILED",
        ):
            application.wait(timeout_seconds=1.0)
        application.close()
        self.assertTrue(command.closed)
        self.assertTrue(production.closed)
        self.assertTrue(health.closed)

    def test_close_is_idempotent_and_uses_dependency_order(self) -> None:
        events: list[str] = []
        health = _HealthRuntime()
        original_health_close = health.close

        def close_health() -> None:
            events.append("health.close")
            original_health_close()

        health.close = close_health  # type: ignore[method-assign]
        production = _Production(events)
        command = _CommandServer(lambda *_args: {}, events)
        application = ControllerApplicationV2.start(
            health_runtime=health,
            provider=_Provider(),
            production_factory=lambda _provider: production,
            command_server_factory=lambda _handler: command,
        )
        application.close()
        application.close()
        self.assertEqual(
            [
                "command.start",
                "command.serve",
                "command.close",
                "production.close",
                "health.close",
            ],
            events,
        )


if __name__ == "__main__":
    unittest.main()
