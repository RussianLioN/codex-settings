from __future__ import annotations

import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = ROOT / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

from codex_smart_subagents.mcp_runtime_proof_v2 import (  # noqa: E402
    MCP_SESSION_NONCE_ENV_V2,
    USER_MCP_POLICY_PROOF_ENV_V2,
    build_user_mcp_policy_proof_v2,
    mcp_runtime_attestation_path_v2,
    verify_mcp_runtime_attestation_v2,
)
from integration_runtime_v2 import (  # noqa: E402
    IntegrationConfigV2,
    TurnContextStoreV2,
)


def _load_entrypoint() -> ModuleType:
    path = PLUGIN_ROOT / "mcp" / "server.py"
    name = "smart_mcp_entry_v2_tests"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _Client:
    def call(self, _method: str, _arguments: dict[str, object]):
        raise AssertionError("tools/list не должен вызывать транспорт")


class MCPEntrypointV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entry = _load_entrypoint()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state_home = self.root / "state-v2"
        self.state_home.mkdir(mode=0o700)
        self.codex_home = self.root / "codex-home"
        self.codex_home.mkdir(mode=0o700)
        config_path = self.codex_home / "config.toml"
        config_path.write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = true\n",
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        self.environment = {
            "CODEX_SMART_LAUNCHER_ACTIVE": "1",
            "CODEX_ADAPTIVE_SESSION_ID": "cas2_" + "A" * 32,
            "CODEX_HOME": str(self.codex_home),
            "CODEX_SMART_STATE_HOME": str(self.state_home),
            "CODEX_SMART_GATEWAY_PATH": str(
                (PLUGIN_ROOT / "bin" / "codex-smart").resolve()
            ),
            "CODEX_SMART_ACTIVATION_ID": "act2_" + "b" * 64,
            "CODEX_SMART_GATE_FINGERPRINT": "c" * 64,
            MCP_SESSION_NONCE_ENV_V2: "mcpn2_" + "d" * 64,
            "CODEX_ADAPTIVE_CATALOG": str(
                (ROOT / ".codex" / "adaptive-subagents.toml").resolve()
            ),
        }
        self.environment[USER_MCP_POLICY_PROOF_ENV_V2] = (
            build_user_mcp_policy_proof_v2(self.codex_home)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_full_v2_environment_builds_thin_proxy_with_exact_client_binding(
        self,
    ) -> None:
        calls: list[dict[str, object]] = []

        def v2_factory(**kwargs: object) -> _Client:
            calls.append(kwargs)
            return _Client()

        with (
            mock.patch.object(
                sqlite3,
                "connect",
                side_effect=AssertionError("MCP открыл SQLite"),
            ),
            mock.patch.object(
                subprocess,
                "Popen",
                side_effect=AssertionError("MCP запустил дочерний процесс"),
            ),
        ):
            server = self.entry.build_server(
                self.environment,
                client_factory=lambda _config: self.fail("выбран путь v1"),
                v2_client_factory=v2_factory,
            )

        self.assertIsInstance(server, self.entry.MCPProxyServerV2)
        self.assertEqual(
            [
                {
                    "socket_path": self.state_home.resolve() / "command.sock",
                    "shell_session_id": "cas2_" + "A" * 32,
                }
            ],
            calls,
        )
        listed = server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            [tool["name"] for tool in listed["result"]["tools"]],
        )

        default_server = self.entry.build_server(self.environment)
        self.assertIsInstance(
            default_server.client,
            self.entry.ControllerCommandClientV2,
        )
        self.assertEqual(
            self.state_home.resolve() / "command.sock",
            default_server.client.socket_path,
        )
        self.assertEqual(
            "cas2_" + "A" * 32,
            default_server.client.shell_session_id,
        )

    def test_any_partial_v2_environment_uses_inactive_server_without_v1_fallback(
        self,
    ) -> None:
        required = (
            "CODEX_SMART_LAUNCHER_ACTIVE",
            "CODEX_ADAPTIVE_SESSION_ID",
            "CODEX_HOME",
            "CODEX_SMART_STATE_HOME",
            "CODEX_SMART_GATEWAY_PATH",
            "CODEX_SMART_ACTIVATION_ID",
            "CODEX_SMART_GATE_FINGERPRINT",
            MCP_SESSION_NONCE_ENV_V2,
            USER_MCP_POLICY_PROOF_ENV_V2,
            "CODEX_ADAPTIVE_CATALOG",
        )
        for missing in required:
            with self.subTest(missing=missing):
                partial = dict(self.environment)
                partial.pop(missing)
                v1_calls: list[object] = []
                v2_calls: list[object] = []
                server = self.entry.build_server(
                    partial,
                    client_factory=lambda config: v1_calls.append(config),
                    v2_client_factory=lambda **kwargs: v2_calls.append(kwargs),
                )
                self.assertIsInstance(server, self.entry.InactiveMCPServer)
                listed = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {},
                    }
                )
                self.assertEqual([], listed["result"]["tools"])
                self.assertEqual([], v1_calls)
                self.assertEqual([], v2_calls)

    def test_v1_environment_keeps_existing_builder_and_never_uses_v2_factory(
        self,
    ) -> None:
        v1_state = self.root / "state-v1"
        v1_state.mkdir(mode=0o700)
        v1_environment = {
            "CODEX_ADAPTIVE_SESSION_ID": "adaptive-session-1",
            "CODEX_HOME": str(self.codex_home),
            "CODEX_ADAPTIVE_CATALOG": self.environment["CODEX_ADAPTIVE_CATALOG"],
            "XDG_STATE_HOME": str(v1_state),
        }
        client = _Client()
        server = self.entry.build_server(
            v1_environment,
            client_factory=lambda _config: client,
            v2_client_factory=lambda **_kwargs: self.fail("v1 ушёл в v2"),
        )

        self.assertIsInstance(server, self.entry.MCPServer)
        self.assertIs(server.backend.client, client)

    def test_ordinary_environment_initializes_required_server_without_tools(
        self,
    ) -> None:
        try:
            server = self.entry.build_server(
                {"CODEX_HOME": str(self.codex_home)},
                client_factory=lambda _config: self.fail("выбран путь v1"),
                v2_client_factory=lambda **_kwargs: self.fail("выбран путь v2"),
            )
        except Exception as error:
            self.fail(f"обычный Codex не инициализировал пустой MCP: {error!r}")

        self.assertIsInstance(server, self.entry.InactiveMCPServer)
        initialized = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        )
        self.assertEqual(
            "codex-smart-subagents-inactive",
            initialized["result"]["serverInfo"]["name"],
        )
        listed = server.handle(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        self.assertEqual([], listed["result"]["tools"])

    def test_main_selects_v2_stdio_runner(self) -> None:
        proxy = self.entry.MCPProxyServerV2(client=_Client())
        with (
            mock.patch.object(self.entry, "build_server", return_value=proxy),
            mock.patch.object(
                self.entry,
                "run_stdio_proxy_v2",
                return_value=41,
            ) as run_v2,
            mock.patch.object(
                self.entry,
                "run_stdio",
                side_effect=AssertionError("для v2 выбран старый цикл"),
            ),
        ):
            self.assertEqual(41, self.entry.main(["--stdio"]))
        run_v2.assert_called_once_with(proxy)

    def test_main_runs_inactive_server_through_json_rpc_loop(self) -> None:
        inactive = self.entry.InactiveMCPServer()
        with (
            mock.patch.object(self.entry, "build_server", return_value=inactive),
            mock.patch.object(
                self.entry,
                "run_stdio_proxy_v2",
                return_value=43,
            ) as run_v2,
            mock.patch.object(
                self.entry,
                "run_stdio",
                side_effect=AssertionError("пустой сервер ушёл в v1"),
            ),
        ):
            self.assertEqual(43, self.entry.main(["--stdio"]))
        run_v2.assert_called_once_with(inactive)

    def test_main_serves_incomplete_v2_environment_as_successful_inactive_mcp(
        self,
    ) -> None:
        partial = dict(self.environment)
        partial.pop("CODEX_SMART_STATE_HOME")
        error = io.StringIO()
        output = io.StringIO()
        requests = (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": self.entry.MCP_PROTOCOL_V2},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        with (
            mock.patch.object(self.entry.os, "environ", partial),
            mock.patch.object(self.entry.sys, "stderr", error),
            mock.patch.object(
                self.entry.sys,
                "stdin",
                io.StringIO("".join(json.dumps(value) + "\n" for value in requests)),
            ),
            mock.patch.object(self.entry.sys, "stdout", output),
        ):
            self.assertEqual(0, self.entry.main(["--stdio"]))

        self.assertEqual("", error.getvalue())
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(
            "codex-smart-subagents-inactive",
            responses[0]["result"]["serverInfo"]["name"],
        )
        self.assertEqual([], responses[1]["result"]["tools"])

    def test_runtime_attestation_is_published_for_exact_tools_list_before_flush(
        self,
    ) -> None:
        server = self.entry.build_server(
            self.environment,
            v2_client_factory=lambda **_kwargs: _Client(),
        )
        path = mcp_runtime_attestation_path_v2(self.environment)
        self.assertFalse(path.exists())
        requests = (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": self.entry.MCP_PROTOCOL_V2},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

        class ObservingOutput(io.StringIO):
            def __init__(nested_self) -> None:
                super().__init__()
                nested_self.flush_count = 0

            def flush(nested_self) -> None:
                nested_self.flush_count += 1
                if nested_self.flush_count == 1:
                    self.assertFalse(path.exists())
                if nested_self.flush_count == 2:
                    self.assertTrue(path.exists())
                    verify_mcp_runtime_attestation_v2(self.environment)
                super().flush()

        source = io.StringIO(
            "".join(json.dumps(request) + "\n" for request in requests)
        )
        output = ObservingOutput()
        with (
            mock.patch.object(self.entry.sys, "stdin", source),
            mock.patch.object(self.entry.sys, "stdout", output),
        ):
            self.assertEqual(0, self.entry.run_stdio_proxy_v2(server))

        self.assertEqual(2, output.flush_count)
        self.assertFalse(path.exists())

    def test_failed_tools_list_write_removes_prepared_attestation(self) -> None:
        server = self.entry.build_server(
            self.environment,
            v2_client_factory=lambda **_kwargs: _Client(),
        )
        path = mcp_runtime_attestation_path_v2(self.environment)
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }

        class FailingOutput(io.StringIO):
            def write(nested_self, value: str) -> int:
                self.assertTrue(path.exists())
                raise BrokenPipeError("expected write failure")

        with (
            mock.patch.object(
                self.entry.sys,
                "stdin",
                io.StringIO(json.dumps(request) + "\n"),
            ),
            mock.patch.object(self.entry.sys, "stdout", FailingOutput()),
        ):
            self.assertNotEqual(0, self.entry.run_stdio_proxy_v2(server))

        self.assertFalse(path.exists())

    def test_policy_mismatch_uses_successful_inactive_server(self) -> None:
        attestation_path = mcp_runtime_attestation_path_v2(self.environment)
        self.codex_home.joinpath("config.toml").write_text(
            '[plugins."codex-smart-subagents@codex-settings-adaptive"]\n'
            "enabled = false\n",
            encoding="utf-8",
        )
        self.codex_home.joinpath("config.toml").chmod(0o600)

        server = self.entry.build_server(
            self.environment,
            client_factory=lambda _config: self.fail("выбран путь v1"),
            v2_client_factory=lambda **_kwargs: self.fail(
                "контроллер не должен открываться"
            ),
        )

        self.assertIsInstance(server, self.entry.InactiveMCPServer)
        listed = server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        self.assertEqual([], listed["result"]["tools"])
        self.assertFalse(attestation_path.exists())

    def test_initialize_tools_list_then_user_prompt_activates_exact_v2_turn(
        self,
    ) -> None:
        hook_path = PLUGIN_ROOT / "hooks" / "user_prompt_submit.py"
        spec = importlib.util.spec_from_file_location(
            "smart_prompt_after_tools_list_test",
            hook_path,
        )
        assert spec is not None and spec.loader is not None
        hook = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = hook
        spec.loader.exec_module(hook)
        server = self.entry.build_server(
            self.environment,
            v2_client_factory=lambda **_kwargs: _Client(),
        )
        path = mcp_runtime_attestation_path_v2(self.environment)
        responses: list[dict[str, object]] = []

        class HookOutput(io.StringIO):
            def __init__(nested_self) -> None:
                super().__init__()
                nested_self.flush_count = 0

            def flush(nested_self) -> None:
                nested_self.flush_count += 1
                if nested_self.flush_count == 2:
                    self.assertTrue(path.exists())
                    responses.append(
                        hook.handle(
                            {
                                "session_id": "codex-01446-session",
                                "turn_id": "turn-after-tools-list",
                                "cwd": str(ROOT),
                                "hook_event_name": "UserPromptSubmit",
                            },
                            self.environment,
                            v2_mcp_contract_checker=lambda _plugin_root: None,
                            v2_controller_checker=(
                                lambda _config, *, deadline: None
                            ),
                        )
                    )
                super().flush()

        requests = (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": self.entry.MCP_PROTOCOL_V2},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        with (
            mock.patch.object(
                self.entry.sys,
                "stdin",
                io.StringIO(
                    "".join(json.dumps(request) + "\n" for request in requests)
                ),
            ),
            mock.patch.object(self.entry.sys, "stdout", HookOutput()),
        ):
            self.assertEqual(0, self.entry.run_stdio_proxy_v2(server))

        self.assertEqual(1, len(responses))
        self.assertIn("hookSpecificOutput", responses[0])
        saved = TurnContextStoreV2(
            IntegrationConfigV2.from_environ(self.environment)
        ).load()
        self.assertEqual("turn-after-tools-list", saved.turn_id)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
