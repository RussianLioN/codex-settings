from __future__ import annotations

import errno
import importlib.util
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
SCRIPTS = PLUGIN_ROOT / "scripts"
SRC = PLUGIN_ROOT / "src"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SRC))


def load_module(name: str, relative_path: str) -> ModuleType:
    path = PLUGIN_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def hook_payload(event: str, *, turn_id: str = "turn-1") -> dict[str, Any]:
    return {
        "session_id": "codex-session-1",
        "turn_id": turn_id,
        "transcript_path": None,
        "cwd": str(REPO),
        "hook_event_name": event,
        "model": "root-model",
        "permission_mode": "default",
    }


def environment(state_home: Path) -> dict[str, str]:
    return {
        "CODEX_ADAPTIVE_SESSION_ID": "adaptive-session-1",
        "CODEX_HOME": str((state_home / "codex-home").resolve()),
        "CODEX_ADAPTIVE_CATALOG": str(
            (REPO / ".codex" / "adaptive-subagents.toml").resolve()
        ),
        "XDG_STATE_HOME": str(state_home.resolve()),
    }


class SessionStartHookTests(unittest.TestCase):
    def test_session_start_reserves_a_cold_start_budget(self) -> None:
        module = load_module("session_start_cold_budget", "hooks/session_start.py")
        with tempfile.TemporaryDirectory() as tmp:
            state_home = Path(tmp)
            config = SimpleNamespace(
                state_home=state_home,
                shell_session_id="shell-session-1",
            )
            binding = SimpleNamespace(
                database_path=state_home / "smart-subagents.sqlite3",
                compatibility_fingerprint="a" * 64,
            )
            store = mock.Mock()
            environ = {
                "CODEX_SMART_LAUNCH_KIND": "startup",
                "CODEX_SMART_ROOT_PID": "1234",
                "CODEX_SMART_ROOT_START_MARKER": "darwin:1:2",
            }
            payload = {
                "session_id": "codex-session-1",
                "cwd": str(REPO),
                "hook_event_name": "SessionStart",
                "source": "startup",
            }

            with (
                mock.patch.object(module, "environment_is_active", return_value=True),
                mock.patch.object(module.time, "monotonic", return_value=100.0),
                mock.patch.object(
                    module.IntegrationConfigV2,
                    "from_environ",
                    return_value=config,
                ),
                mock.patch.object(module, "require_current_user_mcp_policy_v2"),
                mock.patch.object(
                    module,
                    "pinned_resume_binding_v2",
                    return_value=binding,
                ) as pinned_binding,
                mock.patch.object(
                    module,
                    "_git_identity",
                    return_value=(str(REPO), "b" * 40, "c" * 64),
                ),
                mock.patch.object(
                    module,
                    "RootSessionLeaseStoreV2",
                    return_value=store,
                ),
            ):
                result = module.handle(payload, environ)

            self.assertIsNone(result)
            deadline = pinned_binding.call_args.kwargs["deadline"]
            self.assertGreaterEqual(deadline - 100.0, 7.5)

    def test_startup_uses_bounded_pinned_binding_instead_of_full_resolver(
        self,
    ) -> None:
        module = load_module("session_start_bounded_binding", "hooks/session_start.py")
        with tempfile.TemporaryDirectory() as tmp:
            state_home = Path(tmp)
            config = SimpleNamespace(
                state_home=state_home,
                shell_session_id="shell-session-1",
            )
            binding = SimpleNamespace(
                database_path=state_home / "smart-subagents.sqlite3",
                compatibility_fingerprint="a" * 64,
            )
            store = mock.Mock()
            environ = {
                "CODEX_SMART_LAUNCH_KIND": "startup",
                "CODEX_SMART_ROOT_PID": "1234",
                "CODEX_SMART_ROOT_START_MARKER": "darwin:1:2",
            }
            payload = {
                "session_id": "codex-session-1",
                "cwd": str(REPO),
                "hook_event_name": "SessionStart",
                "source": "startup",
            }

            with (
                mock.patch.object(module, "environment_is_active", return_value=True),
                mock.patch.object(
                    module.IntegrationConfigV2,
                    "from_environ",
                    return_value=config,
                ),
                mock.patch.object(module, "require_current_user_mcp_policy_v2"),
                mock.patch.object(
                    module,
                    "pinned_resume_binding_v2",
                    return_value=binding,
                    create=True,
                ) as pinned_binding,
                mock.patch.object(
                    module,
                    "FreshActivationProviderV2",
                    side_effect=AssertionError("full resolver must not run"),
                    create=True,
                ) as full_resolver,
                mock.patch.object(
                    module,
                    "_git_identity",
                    return_value=(str(REPO), "b" * 40, "c" * 64),
                ),
                mock.patch.object(
                    module,
                    "RootSessionLeaseStoreV2",
                    return_value=store,
                ),
            ):
                result = module.handle(payload, environ)

            self.assertIsNone(result)
            pinned_binding.assert_called_once()
            full_resolver.assert_not_called()
            store.register_startup.assert_called_once()


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.binding_index = 0

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        if method == "issue_turn_binding":
            self.binding_index += 1
            return {"turnBinding": "tb1_" + chr(64 + self.binding_index) * 43}
        if method == "smart_cancel":
            return {
                "schemaVersion": "1",
                "ok": True,
                "code": "CANCEL_ACCEPTED",
                "message": "",
                "routeId": params["routeId"],
                "previousState": "RUNNING",
                "newState": "CANCELLED",
                "accepted": True,
            }
        raise AssertionError(method)


class PluginMetadataTests(unittest.TestCase):
    def test_manifest_declares_real_components_without_placeholders(self) -> None:
        manifest = json.loads(
            (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("codex-smart-subagents", manifest["name"])
        self.assertEqual("0.2.0", manifest["version"])
        self.assertEqual("./skills/", manifest["skills"])
        self.assertNotIn("hooks", manifest)
        self.assertTrue((PLUGIN_ROOT / "hooks" / "hooks.json").is_file())
        self.assertEqual("./.mcp.json", manifest["mcpServers"])
        self.assertIsInstance(manifest["interface"]["defaultPrompt"], list)
        self.assertEqual(
            ["Interactive", "Read", "Write"],
            manifest["interface"]["capabilities"],
        )
        self.assertNotIn("[TODO:", json.dumps(manifest))

    def test_mcp_config_uses_bundled_entrypoint_and_exact_tool_allowlist(self) -> None:
        config = json.loads(
            (PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8")
        )
        self.assertEqual({"mcpServers"}, set(config))
        self.assertEqual(
            {"codex-smart-subagents"},
            set(config["mcpServers"]),
        )
        server = config["mcpServers"]["codex-smart-subagents"]
        self.assertEqual("./bin/codex-smart-subagents-mcp", server["command"])
        self.assertEqual(["--stdio"], server["args"])
        self.assertEqual(".", server["cwd"])
        self.assertTrue(server["required"])
        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            server["enabled_tools"],
        )
        self.assertGreaterEqual(server["tool_timeout_sec"], 420)
        self.assertEqual("approve", server["default_tools_approval_mode"])
        self.assertIn("CODEX_ADAPTIVE_CATALOG", server["env_vars"])
        for name in (
            "CODEX_SMART_LAUNCHER_ACTIVE",
            "CODEX_SMART_STATE_HOME",
            "CODEX_SMART_GATEWAY_PATH",
            "CODEX_SMART_ACTIVATION_ID",
            "CODEX_SMART_GATE_FINGERPRINT",
            "CODEX_SMART_LAUNCH_KIND",
            "CODEX_SMART_ROOT_PID",
            "CODEX_SMART_ROOT_START_MARKER",
            "CODEX_SMART_MCP_SESSION_NONCE",
            "CODEX_SMART_USER_MCP_POLICY_PROOF",
        ):
            self.assertIn(name, server["env_vars"])

    def test_hook_config_has_smart_turn_and_session_lifecycle_events(self) -> None:
        hooks = json.loads(
            (PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            {"SessionStart", "UserPromptSubmit", "Stop", "SessionEnd"},
            set(hooks["hooks"]),
        )
        session_start = hooks["hooks"]["SessionStart"][0]
        self.assertEqual("startup|resume|clear|compact", session_start["matcher"])
        start_command = session_start["hooks"][0]
        prompt = hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        stop = hooks["hooks"]["Stop"][0]["hooks"][0]
        session_end = hooks["hooks"]["SessionEnd"][0]["hooks"][0]
        self.assertIn("session-start", start_command["command"])
        self.assertGreaterEqual(start_command["timeout"], 9)
        self.assertEqual("command", prompt["type"])
        self.assertIn("$PLUGIN_ROOT", prompt["command"])
        self.assertEqual(5, prompt["timeout"])
        self.assertEqual("command", stop["type"])
        self.assertIn("$PLUGIN_ROOT", stop["command"])
        self.assertEqual(5, stop["timeout"])
        self.assertIn("session-end", session_end["command"])
        self.assertEqual(5, session_end["timeout"])

    def test_stop_launcher_overwrites_deadline_before_runpy(self) -> None:
        launcher_source = (
            PLUGIN_ROOT / "bin" / "codex-smart-subagents-hook"
        ).read_text(encoding="utf-8")
        self.assertLess(
            launcher_source.index("os.environ[STOP_HOOK_DEADLINE_MONOTONIC_NS_ENV]"),
            launcher_source.index("import runpy"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            fake_pathlib = Path(tmp) / "pathlib.py"
            fake_pathlib.write_text(
                "\n".join(
                    [
                        "import json",
                        "import os",
                        "import sys",
                        "started = os.environ.get('CODEX_SMART_HOOK_STARTED_MONOTONIC_NS')",
                        "deadline = os.environ.get('CODEX_SMART_HOOK_DEADLINE_MONOTONIC_NS')",
                        "with open(os.environ['SMART_TEST_MARKER'], 'w', encoding='utf-8') as stream:",
                        "    json.dump({'started': started, 'deadline': deadline}, stream)",
                        "raise SystemExit(0)",
                    ]
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update(
                {
                    "PYTHONPATH": tmp,
                    "SMART_TEST_MARKER": str(marker),
                    "CODEX_SMART_HOOK_STARTED_MONOTONIC_NS": "user-start",
                    "CODEX_SMART_HOOK_DEADLINE_MONOTONIC_NS": "user-deadline",
                }
            )

            result = subprocess.run(
                [str(PLUGIN_ROOT / "bin" / "codex-smart-subagents-hook"), "stop"],
                input=b'{"hook_event_name":"Stop"}',
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
            observed = json.loads(marker.read_text(encoding="utf-8"))
            self.assertNotEqual("user-start", observed["started"])
            self.assertNotEqual("user-deadline", observed["deadline"])
            started = int(observed["started"])
            deadline = int(observed["deadline"])
            self.assertGreater(started, 0)
            self.assertEqual(1_500_000_000, deadline - started)

    def test_stop_subprocess_returns_fail_open_json_when_deadline_elapsed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_pathlib = Path(tmp) / "pathlib.py"
            fake_pathlib.write_text(
                "\n".join(
                    [
                        "import importlib",
                        "import os",
                        "import sys",
                        "import time",
                        "time.sleep(1.55)",
                        "sys.path = [p for p in sys.path if p != os.path.dirname(__file__)]",
                        "sys.modules.pop(__name__, None)",
                        "module = importlib.import_module(__name__)",
                        "globals().update(module.__dict__)",
                    ]
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = tmp
            payload = {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "hook_event_name": "Stop",
            }

            result = subprocess.run(
                [str(PLUGIN_ROOT / "bin" / "codex-smart-subagents-hook"), "stop"],
                input=json.dumps(payload).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8"))
            response = json.loads(result.stdout.decode("utf-8"))
            self.assertTrue(response["continue"])
            self.assertEqual("SMART_HOOK_DEFERRED", response["code"])
            self.assertIn("срок", response["reason"].lower())

    def test_bundled_entrypoints_are_executable_regular_files(self) -> None:
        for relative in (
            "bin/codex-smart",
            "bin/codex-smart-subagents-controller",
            "bin/codex-smart-subagents-mcp",
            "bin/codex-smart-subagents-hook",
        ):
            path = PLUGIN_ROOT / relative
            info = path.stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertTrue(info.st_mode & stat.S_IXUSR)


class HookIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prompt_hook = load_module(
            "smart_prompt_hook",
            "hooks/user_prompt_submit.py",
        )
        cls.stop_hook = load_module(
            "smart_stop_hook",
            "hooks/stop.py",
        )
        cls.session_end_hook = load_module(
            "smart_session_end_hook",
            "hooks/session_end.py",
        )
        cls.runtime = load_module(
            "smart_integration_runtime",
            "scripts/integration_runtime.py",
        )

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.state_home = Path(self.directory.name)
        self.env = environment(self.state_home)
        self.client = FakeClient()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_inactive_and_child_sessions_are_ignored(self) -> None:
        inactive = dict(self.env)
        inactive.pop("CODEX_ADAPTIVE_SESSION_ID")
        self.assertIsNone(
            self.prompt_hook.handle(
                hook_payload("UserPromptSubmit"),
                inactive,
                client_factory=lambda _config: self.client,
            )
        )

        child = dict(self.env)
        child["CODEX_ADAPTIVE_CHILD"] = "1"
        self.assertIsNone(
            self.prompt_hook.handle(
                hook_payload("UserPromptSubmit"),
                child,
                client_factory=lambda _config: self.client,
            )
        )
        built_in_child = hook_payload("UserPromptSubmit")
        built_in_child["agent_id"] = "agent-1"
        built_in_child["agent_type"] = "worker"
        self.assertIsNone(
            self.prompt_hook.handle(
                built_in_child,
                self.env,
                client_factory=lambda _config: self.client,
            )
        )
        self.assertEqual([], self.client.calls)

    def test_user_prompt_issues_binding_and_injects_bounded_opaque_context(self) -> None:
        response = self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=lambda _config: self.client,
        )

        self.assertTrue(response["continue"])
        context = response["hookSpecificOutput"]["additionalContext"]
        self.assertEqual(
            "UserPromptSubmit",
            response["hookSpecificOutput"]["hookEventName"],
        )
        self.assertLessEqual(len(context.encode("utf-8")), 2048)
        self.assertIn("tb1_" + "A" * 43, context)
        self.assertIn("cg1_", context)
        self.assertIn("scope_", context)
        self.assertIn("artifact_", context)
        self.assertIn("validation_", context)
        self.assertIn("по определениям и правилам схемы smart_plan", context)
        self.assertNotIn(str(REPO), context)
        self.assertNotIn("gpt-5.6", context)
        self.assertEqual("issue_turn_binding", self.client.calls[0][0])
        wire_context = self.client.calls[0][1]["context"]
        self.assertEqual(
            {
                "shellSessionId",
                "sessionId",
                "turnId",
                "codexHome",
                "repoRoot",
                "baseSha",
                "worktreeFingerprint",
            },
            set(wire_context),
        )

        config = self.runtime.IntegrationConfig.from_environ(
            self.env,
            require_catalog=True,
        )
        state = self.runtime.CoordinationStore(config).load()
        self.assertEqual("turn-1", state["turnId"])
        self.assertFalse(state["planCalled"])

    def test_controller_failure_falls_back_to_ordinary_turn(self) -> None:
        def unavailable(_config: Any) -> Any:
            raise RuntimeError("socket unavailable")

        response = self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=unavailable,
        )
        self.assertTrue(response["continue"])
        self.assertNotIn("stopReason", response)
        self.assertIn("обычном режиме", response["systemMessage"].lower())
        self.assertNotIn("socket unavailable", json.dumps(response))

    def test_slow_controller_still_respects_the_hook_budget(self) -> None:
        config = self.runtime.IntegrationConfig.from_environ(
            self.env,
            require_catalog=True,
        )
        socket_path = config.paths.socket_path
        socket_path.parent.mkdir(parents=True, mode=0o700)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)

        def serve() -> None:
            connection, _address = listener.accept()
            with connection:
                connection.recv(64 * 1024)
                time.sleep(1)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started = time.monotonic()
        try:
            response = self.prompt_hook.handle(
                hook_payload("UserPromptSubmit"),
                self.env,
            )
        finally:
            listener.close()
            thread.join(timeout=2)
            if os.path.lexists(socket_path):
                socket_path.unlink()

        self.assertTrue(response["continue"])
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(thread.is_alive())

    def test_stop_requests_at_most_two_planning_continuations(self) -> None:
        self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=lambda _config: self.client,
        )

        first = self.stop_hook.handle(hook_payload("Stop"), self.env)
        second = self.stop_hook.handle(hook_payload("Stop"), self.env)
        third = self.stop_hook.handle(hook_payload("Stop"), self.env)

        for response in (first, second):
            self.assertEqual("block", response["decision"])
            self.assertIn("smart_plan", response["reason"])
            self.assertNotIn("continue", response)
            self.assertNotIn("hookSpecificOutput", response)
        self.assertTrue(third["continue"])
        self.assertIn("двух", third["systemMessage"].lower())

    def test_session_end_error_returns_fail_open_json(self) -> None:
        payload = hook_payload("SessionEnd")
        with (
            mock.patch.object(
                self.session_end_hook,
                "environment_is_active",
                return_value=True,
            ),
            mock.patch.object(
                self.session_end_hook.IntegrationConfigV2,
                "from_environ",
                side_effect=RuntimeError("broken runtime"),
            ),
        ):
            response = self.session_end_hook.handle(payload, self.env)

        self.assertTrue(response["continue"])
        self.assertEqual("SMART_HOOK_DEFERRED", response["code"])
        self.assertIn("SessionEnd", response["reason"])

    def test_new_turn_best_effort_cancels_superseded_active_route(self) -> None:
        self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=lambda _config: self.client,
        )
        config = self.runtime.IntegrationConfig.from_environ(
            self.env,
            require_catalog=True,
        )
        store = self.runtime.CoordinationStore(config)
        state = store.load()
        state.update(
            {
                "planCalled": True,
                "routeId": "rt1_" + "R" * 43,
                "disposition": "delegate",
                "routeState": "RUNNING",
            }
        )
        store.save(state)

        response = self.prompt_hook.handle(
            hook_payload("UserPromptSubmit", turn_id="turn-2"),
            self.env,
            client_factory=lambda _config: self.client,
        )

        self.assertTrue(response["continue"])
        self.assertEqual(
            (
                "smart_cancel",
                {
                    "schemaVersion": "1",
                    "routeId": "rt1_" + "R" * 43,
                    "reasonCode": "superseded",
                },
            ),
            self.client.calls[-2],
        )
        self.assertEqual("issue_turn_binding", self.client.calls[-1][0])

    def test_invalid_new_event_cannot_cancel_an_existing_route(self) -> None:
        self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=lambda _config: self.client,
        )
        config = self.runtime.IntegrationConfig.from_environ(
            self.env,
            require_catalog=True,
        )
        store = self.runtime.CoordinationStore(config)
        state = store.load()
        state.update(
            {
                "planCalled": True,
                "routeId": "rt1_" + "R" * 43,
                "disposition": "delegate",
                "routeState": "RUNNING",
            }
        )
        store.save(state)
        self.client.calls.clear()
        malformed = hook_payload("UserPromptSubmit", turn_id="turn-2")
        malformed.pop("turn_id")

        response = self.prompt_hook.handle(
            malformed,
            self.env,
            client_factory=lambda _config: self.client,
        )

        self.assertTrue(response["continue"])
        self.assertEqual([], self.client.calls)


class MCPEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server_entry = load_module(
            "smart_mcp_entry",
            "mcp/server.py",
        )
        cls.runtime = sys.modules["smart_integration_runtime"]

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.state_home = Path(self.directory.name)
        self.env = environment(self.state_home)
        self.client = FakeClient()
        config = self.runtime.IntegrationConfig.from_environ(
            self.env,
            require_catalog=False,
        )
        self.store = self.runtime.CoordinationStore(config)
        self.store.save(
            {
                "schemaVersion": 1,
                "shellSessionId": "adaptive-session-1",
                "sessionId": "codex-session-1",
                "turnId": "turn-1",
                "turnBinding": "tb1_" + "A" * 43,
                "catalogGeneration": "cg1_" + "a" * 16,
                "planCalled": False,
                "routeId": "",
                "disposition": "",
                "routeState": "",
                "afterSequence": 0,
                "continuationCount": 0,
            }
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_tracking_backend_records_route_state_without_tool_payloads(self) -> None:
        class PlanClient:
            def call(
                self,
                method: str,
                params: dict[str, Any],
            ) -> dict[str, Any]:
                if method != "smart_plan":
                    raise AssertionError(method)
                return {
                    "schemaVersion": "1",
                    "ok": True,
                    "code": "PLAN_READY",
                    "message": "",
                    "routeId": "rt1_" + "R" * 43,
                    "routeGeneration": 1,
                    "expiresAt": "2026-07-16T00:00:00+00:00",
                    "startable": True,
                    "overallDisposition": "delegate",
                    "nodeDecisions": [],
                    "clarificationQuestions": [],
                    "catalogGeneration": "cg1_" + "a" * 16,
                }

        backend = self.server_entry.TrackingBackend(PlanClient(), self.store)
        result = backend.call(
            "smart_plan",
            {
                "schemaVersion": "1",
                "turnBinding": "tb1_" + "A" * 43,
                "requestKey": "secret-request-key",
                "catalogGeneration": "cg1_" + "a" * 16,
                "nodes": [],
            },
        )

        self.assertEqual("rt1_" + "R" * 43, result["routeId"])
        state = self.store.load()
        self.assertTrue(state["planCalled"])
        self.assertEqual("delegate", state["disposition"])
        self.assertEqual("PLANNED", state["routeState"])
        self.assertNotIn("secret-request-key", json.dumps(state))

    def test_coordination_update_stops_at_one_monotonic_lock_deadline(self) -> None:
        clock = [10.0]
        sleeps: list[float] = []
        operations: list[int] = []

        def monotonic() -> float:
            return clock[0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock[0] += seconds

        def always_busy(_descriptor: int, operation: int) -> None:
            operations.append(operation)
            if operation == self.runtime.fcntl.LOCK_UN:
                return
            raise BlockingIOError(errno.EAGAIN, "busy")

        with (
            mock.patch.object(
                self.runtime,
                "COORDINATION_LOCK_TIMEOUT_SECONDS",
                0.12,
                create=True,
            ),
            mock.patch.object(
                self.runtime,
                "COORDINATION_LOCK_POLL_INTERVAL_SECONDS",
                0.05,
                create=True,
            ),
            mock.patch.object(self.runtime.time, "monotonic", side_effect=monotonic),
            mock.patch.object(self.runtime.time, "sleep", side_effect=sleep),
            mock.patch.object(self.runtime.fcntl, "flock", side_effect=always_busy),
        ):
            with self.assertRaises(BaseException) as captured:
                self.store.update(lambda state: state)

        self.assertIsInstance(captured.exception, self.runtime.IntegrationError)
        self.assertAlmostEqual(0.12, sum(sleeps))
        self.assertGreaterEqual(len(operations), 2)
        self.assertTrue(
            all(operation & self.runtime.fcntl.LOCK_NB for operation in operations)
        )
        self.assertNotIn(self.runtime.fcntl.LOCK_UN, operations)

    def test_coordination_update_retries_nonblocking_lock_before_deadline(self) -> None:
        clock = [20.0]
        attempts = 0
        operations: list[int] = []

        def sleep(seconds: float) -> None:
            clock[0] += seconds

        def eventually_available(_descriptor: int, operation: int) -> None:
            nonlocal attempts
            operations.append(operation)
            if operation == self.runtime.fcntl.LOCK_UN:
                return
            attempts += 1
            if attempts < 3:
                raise BlockingIOError(errno.EWOULDBLOCK, "busy")

        try:
            with (
                mock.patch.object(
                    self.runtime,
                    "COORDINATION_LOCK_TIMEOUT_SECONDS",
                    0.2,
                    create=True,
                ),
                mock.patch.object(
                    self.runtime,
                    "COORDINATION_LOCK_POLL_INTERVAL_SECONDS",
                    0.05,
                    create=True,
                ),
                mock.patch.object(
                    self.runtime.time, "monotonic", side_effect=lambda: clock[0]
                ),
                mock.patch.object(self.runtime.time, "sleep", side_effect=sleep),
                mock.patch.object(
                    self.runtime.fcntl,
                    "flock",
                    side_effect=eventually_available,
                ),
            ):
                updated = self.store.update(
                    lambda state: {
                        **state,
                        "continuationCount": state["continuationCount"] + 1,
                    }
                )
        except BaseException as error:
            self.fail(f"coordination lock did not retry: {error!r}")

        self.assertEqual(3, attempts)
        self.assertEqual(1, updated["continuationCount"])
        self.assertTrue(
            all(
                operation == self.runtime.fcntl.LOCK_UN
                or operation & self.runtime.fcntl.LOCK_NB
                for operation in operations
            )
        )

    def test_coordination_update_closes_descriptor_when_unlock_fails(self) -> None:
        lock_descriptor: list[int] = []
        closed_descriptors: list[int] = []
        real_close = self.runtime.os.close

        def flock(descriptor: int, operation: int) -> None:
            if operation == self.runtime.fcntl.LOCK_UN:
                raise OSError(errno.EIO, "unlock failed")
            lock_descriptor.append(descriptor)

        def close(descriptor: int) -> None:
            closed_descriptors.append(descriptor)
            real_close(descriptor)

        with (
            mock.patch.object(self.runtime.fcntl, "flock", side_effect=flock),
            mock.patch.object(self.runtime.os, "close", side_effect=close),
        ):
            with self.assertRaises(OSError):
                self.store.update(lambda state: state)

        self.assertEqual(1, len(lock_descriptor))
        self.assertIn(lock_descriptor[0], closed_descriptors)

    def test_entrypoint_without_adaptive_session_is_inactive(self) -> None:
        ordinary = dict(self.env)
        ordinary.pop("CODEX_ADAPTIVE_SESSION_ID")

        server = self.server_entry.build_server(
            ordinary,
            client_factory=lambda _config: self.fail("выбран путь v1"),
        )

        self.assertIsInstance(server, self.server_entry.InactiveMCPServer)

    def test_entrypoint_requires_codex_home_for_adaptive_session(self) -> None:
        invalid = dict(self.env)
        invalid.pop("CODEX_HOME")
        with self.assertRaises(RuntimeError):
            self.server_entry.build_server(
                invalid,
                client_factory=lambda _config: self.client,
            )

    def test_tools_list_explains_assessment_scale_and_graph_invariants(
        self,
    ) -> None:
        server = self.server_entry.build_server(
            self.env,
            client_factory=lambda _config: self.client,
        )
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
        )
        tools = {
            tool["name"]: tool
            for tool in response["result"]["tools"]
        }
        plan = tools["smart_plan"]
        self.assertIn("implementer", plan["description"])
        self.assertIn("глубины 4", plan["description"])
        node = plan["inputSchema"]["properties"]["nodes"]["items"]
        assessment = node["properties"]["assessment"]["properties"]
        delegation = assessment["delegation"]["properties"]
        for factor in ("q", "p", "v", "o"):
            description = delegation[factor]["description"]
            self.assertIn("0 — низко", description)
            self.assertIn("min", description)
        for group in ("complexity", "reasoning"):
            for field in assessment[group]["properties"].values():
                self.assertIn("0 — низко", field["description"])


class RuntimeHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = sys.modules.get("smart_integration_runtime") or load_module(
            "smart_integration_runtime",
            "scripts/integration_runtime.py",
        )

    def test_git_probe_disables_project_hooks_and_file_monitor_commands(self) -> None:
        completed = mock.Mock(stdout=b"")
        with mock.patch.object(
            self.runtime.subprocess,
            "run",
            return_value=completed,
        ) as run:
            self.runtime._run_git(
                "/usr/bin/git",
                str(REPO),
                "status",
                "--porcelain=v2",
            )

        argv = run.call_args.args[0]
        self.assertIn("core.fsmonitor=false", argv)
        self.assertIn("core.hooksPath=/dev/null", argv)
        environment = run.call_args.kwargs["env"]
        self.assertEqual("/dev/null", environment["GIT_CONFIG_GLOBAL"])
        self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])

    def test_git_identity_uses_two_calls_with_budgeted_timeouts(self) -> None:
        results = (
            mock.Mock(
                stdout=(
                    f"{REPO}\n"
                    + "a" * 40
                    + "\n"
                ).encode("utf-8")
            ),
            mock.Mock(stdout=b""),
        )
        with mock.patch.object(
            self.runtime.subprocess,
            "run",
            side_effect=results,
        ) as run:
            identity = self.runtime._git_identity(str(REPO))

        self.assertEqual(str(REPO.resolve()), identity[0])
        self.assertEqual("a" * 40, identity[1])
        self.assertEqual(2, run.call_count)
        first, second = run.call_args_list
        self.assertIn("--show-toplevel", first.args[0])
        self.assertIn("HEAD", first.args[0])
        self.assertIn("--porcelain=v2", second.args[0])
        self.assertGreater(first.kwargs["timeout"], 0.05)
        self.assertLessEqual(first.kwargs["timeout"], 0.4)
        self.assertGreater(second.kwargs["timeout"], 0.05)
        self.assertLessEqual(second.kwargs["timeout"], 0.65)

    def test_mcp_client_allows_delayed_plan_and_wait(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            config = self.runtime.IntegrationConfig.from_environ(
                environment(Path(raw)),
                require_catalog=False,
            )
            socket_path = config.paths.socket_path
            socket_path.parent.mkdir(parents=True, mode=0o700)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen(2)
            failures: list[BaseException] = []

            def serve() -> None:
                try:
                    for _ in range(2):
                        connection, _address = listener.accept()
                        with connection:
                            with connection.makefile(
                                "rwb",
                                buffering=0,
                            ) as stream:
                                request = json.loads(stream.readline())
                                time.sleep(1.7)
                                stream.write(
                                    json.dumps(
                                        {
                                            "ok": True,
                                            "result": {
                                                "method": request["method"]
                                            },
                                        },
                                        separators=(",", ":"),
                                    ).encode("utf-8")
                                    + b"\n"
                                )
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            client = self.runtime.mcp_controller_client(config)
            try:
                self.assertEqual(
                    "smart_plan",
                    client.call("smart_plan", {})["method"],
                )
                self.assertEqual(
                    "smart_wait",
                    client.call(
                        "smart_wait",
                        {"timeoutSeconds": 2},
                    )["method"],
                )
            finally:
                listener.close()
                thread.join(timeout=5)
                if os.path.lexists(socket_path):
                    socket_path.unlink()
            self.assertFalse(thread.is_alive())
            self.assertEqual([], failures)


class SkillContractTests(unittest.TestCase):
    def test_skill_explains_direct_delegate_wait_and_hook_limits(self) -> None:
        text = (
            PLUGIN_ROOT
            / "skills"
            / "using-smart-subagents"
            / "SKILL.md"
        ).read_text(encoding="utf-8")
        normalized_text = " ".join(text.split())
        self.assertIn("name: using-smart-subagents", text)
        self.assertIn("Use when", text)
        for tool in ("smart_plan", "route_start", "smart_wait", "smart_cancel"):
            self.assertIn(tool, text)
            self.assertIn(f"mcp__codex_smart_subagents__{tool}", text)
        self.assertIn("direct", text)
        self.assertIn("не применяют", text.lower())
        self.assertIn("JSON.parse", text)
        self.assertIn("baseInput", text)
        self.assertIn("factorClaims", text)
        self.assertIn("не перепечатывай нормативный объект", text.lower())
        self.assertIn("researcher-v1", text)
        self.assertIn("implementer-v1", text)
        self.assertIn("byteLength", text)
        self.assertIn("UTF-8", text)
        self.assertIn("до единственного вызова", text.lower())
        self.assertIn("clientNodeId", text)
        self.assertIn("dependencyIds", text)
        self.assertIn("nodes: [", text)
        self.assertIn("const planInput", text)
        self.assertIn("smart_plan(planInput)", text)
        self.assertIn("При умном возобновлении", text)
        self.assertIn("не вызывай новый `smart_plan`", text)
        self.assertIn(
            "никогда не присваивай его переменной `routinginput`",
            normalized_text.lower(),
        )
        self.assertIn(
            "не оборачивай повторно в новый `nodes`",
            normalized_text.lower(),
        )
        self.assertIn("первый `smart_wait`", normalized_text.lower())
        self.assertIn("`cursor: null`", normalized_text)
        self.assertIn("непустой `nextCursor`", normalized_text)
        self.assertIn("pageSize: 100", text)
        self.assertIn("waitSeconds: 60", text)
        self.assertIn("independentWorkUnits: 0", text)
        self.assertIn("не проверяй повторно структуру", normalized_text.lower())
        self.assertNotIn("lastCursor", text)
        self.assertNotIn("smart_integrate", text)
        self.assertIn("prepare_smart_plan.py", text)
        self.assertIn("--spec-json", text)
        self.assertIn("shellQuote", text)
        self.assertIn("готовый `planInput`", text)
        self.assertNotIn("new TextEncoder", text)
        self.assertNotIn("crypto.subtle", text)


if __name__ == "__main__":
    unittest.main()
