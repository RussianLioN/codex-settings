from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
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
        self.assertFalse(server["required"])
        self.assertEqual(
            ["smart_plan", "smart_start", "smart_wait", "smart_cancel"],
            server["enabled_tools"],
        )
        self.assertGreaterEqual(server["tool_timeout_sec"], 60)
        self.assertIn("CODEX_ADAPTIVE_CATALOG", server["env_vars"])

    def test_hook_config_has_only_supported_turn_events(self) -> None:
        hooks = json.loads(
            (PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8")
        )
        self.assertEqual({"UserPromptSubmit", "Stop"}, set(hooks["hooks"]))
        prompt = hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        stop = hooks["hooks"]["Stop"][0]["hooks"][0]
        self.assertEqual("command", prompt["type"])
        self.assertIn("$PLUGIN_ROOT", prompt["command"])
        self.assertEqual(2, prompt["timeout"])
        self.assertEqual("command", stop["type"])
        self.assertIn("$PLUGIN_ROOT", stop["command"])
        self.assertLessEqual(stop["timeout"], 2)

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

    def test_controller_failure_stops_only_the_smart_turn(self) -> None:
        def unavailable(_config: Any) -> Any:
            raise RuntimeError("socket unavailable")

        response = self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=unavailable,
        )
        self.assertFalse(response["continue"])
        self.assertIn("контроллер", response["stopReason"].lower())
        self.assertNotIn("socket unavailable", json.dumps(response))

    def test_stop_requests_at_most_two_planning_continuations(self) -> None:
        self.prompt_hook.handle(
            hook_payload("UserPromptSubmit"),
            self.env,
            client_factory=lambda _config: self.client,
        )

        first = self.stop_hook.handle(hook_payload("Stop"), self.env)
        second = self.stop_hook.handle(hook_payload("Stop"), self.env)
        third = self.stop_hook.handle(hook_payload("Stop"), self.env)

        self.assertFalse(first["continue"])
        self.assertFalse(second["continue"])
        self.assertIn("smart_plan", json.dumps(first))
        self.assertTrue(third["continue"])
        self.assertIn("двух", third["systemMessage"].lower())

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

        self.assertFalse(response["continue"])
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

    def test_entrypoint_requires_explicit_session_and_codex_home(self) -> None:
        for missing in ("CODEX_ADAPTIVE_SESSION_ID", "CODEX_HOME"):
            invalid = dict(self.env)
            invalid.pop(missing)
            with self.assertRaises(RuntimeError):
                self.server_entry.build_server(
                    invalid,
                    client_factory=lambda _config: self.client,
                )


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


class SkillContractTests(unittest.TestCase):
    def test_skill_explains_direct_delegate_wait_and_hook_limits(self) -> None:
        text = (
            PLUGIN_ROOT
            / "skills"
            / "using-smart-subagents"
            / "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("name: using-smart-subagents", text)
        self.assertIn("Use when", text)
        for tool in ("smart_plan", "smart_start", "smart_wait", "smart_cancel"):
            self.assertIn(tool, text)
        self.assertIn("direct", text)
        self.assertIn("не гарантируют", text.lower())
        self.assertNotIn("smart_integrate", text)


if __name__ == "__main__":
    unittest.main()
