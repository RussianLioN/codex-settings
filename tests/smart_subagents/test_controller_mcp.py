from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = REPO / "plugins" / "codex-smart-subagents"
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.catalog import Catalog  # noqa: E402
from codex_smart_subagents.controller import (  # noqa: E402
    ControllerAlreadyRunning,
    ControllerClient,
    ControllerServer,
    RuntimePaths,
    WireProtocolError,
)
from codex_smart_subagents.identity import RequestContext, sha256_text  # noqa: E402
from codex_smart_subagents.mcp_server import MCPServer  # noqa: E402
from codex_smart_subagents.service import SmartService  # noqa: E402
from codex_smart_subagents.store import SmartStore  # noqa: E402

from tests.smart_subagents.fixtures import valid_plan


def context() -> RequestContext:
    return RequestContext(
        shell_session_id="shell-1",
        session_id="session-1",
        turn_id="turn-1",
        codex_home="/Users/test/.codex",
        repo_root=str(REPO),
        base_sha="a" * 40,
        worktree_fingerprint="b" * 64,
    )


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name) / "state"
        self.paths = RuntimePaths.for_codex_home(
            "/Users/test/.codex",
            state_home=base,
        )
        self.store = SmartStore(self.paths.namespace_dir)
        self.catalog = Catalog.load(REPO / ".codex" / "adaptive-subagents.toml")
        self.service = SmartService(self.store, self.catalog)
        self.server = ControllerServer(
            paths=self.paths,
            service=self.service,
            codex_home_hash=sha256_text("/Users/test/.codex"),
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        self.assertTrue(self.server.wait_until_ready(2))
        self.client = ControllerClient(
            socket_path=self.paths.socket_path,
            codex_home_hash=sha256_text("/Users/test/.codex"),
            shell_session_id="shell-1",
        )

    def tearDown(self) -> None:
        self.server.close()
        self.thread.join(timeout=2)
        self.store.close()
        self.directory.cleanup()

    def test_runtime_paths_and_socket_permissions_are_safe(self) -> None:
        self.assertLess(len(os.fsencode(self.paths.socket_path)), 100)
        self.assertEqual(0o700, stat.S_IMODE(self.paths.run_dir.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.paths.socket_path.stat().st_mode))
        self.assertTrue(stat.S_ISSOCK(self.paths.socket_path.stat().st_mode))

        other = RuntimePaths.for_codex_home(
            "/Users/test/other-codex",
            state_home=self.paths.base_dir.parent,
        )
        self.assertNotEqual(self.paths.namespace, other.namespace)
        self.assertNotEqual(self.paths.socket_path, other.socket_path)

    def test_second_controller_and_wrong_namespace_are_rejected(self) -> None:
        with self.assertRaises(ControllerAlreadyRunning):
            ControllerServer(
                paths=self.paths,
                service=self.service,
                codex_home_hash=sha256_text("/Users/test/.codex"),
            )

        wrong = ControllerClient(
            socket_path=self.paths.socket_path,
            codex_home_hash=sha256_text("/Users/test/other"),
            shell_session_id="shell-1",
        )
        with self.assertRaises(WireProtocolError):
            wrong.call("health", {})

    def test_controller_roundtrip_for_four_operations(self) -> None:
        binding = self.client.call(
            "issue_turn_binding",
            {"context": context().to_wire()},
        )["turnBinding"]
        payload = valid_plan(self.catalog)
        payload["turnBinding"] = binding
        payload["catalogGeneration"] = self.catalog.generation

        plan = self.client.call("smart_plan", payload)
        start = self.client.call(
            "smart_start",
            {"schemaVersion": "1", "routeId": plan["routeId"]},
        )
        waited = self.client.call(
            "smart_wait",
            {
                "schemaVersion": "1",
                "routeId": plan["routeId"],
                "afterSequence": 0,
                "timeoutSeconds": 0,
            },
        )
        cancelled = self.client.call(
            "smart_cancel",
            {
                "schemaVersion": "1",
                "routeId": plan["routeId"],
                "reasonCode": "user_requested",
            },
        )

        self.assertEqual("delegate", plan["overallDisposition"])
        self.assertEqual("QUEUED", start["state"])
        self.assertGreaterEqual(waited["sequence"], 1)
        self.assertEqual("CANCELLED", cancelled["newState"])


class MCPServerTests(unittest.TestCase):
    def setUp(self) -> None:
        class Backend:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def call(self, method: str, params: dict[str, object]) -> dict[str, object]:
                self.calls.append((method, params))
                if method == "smart_start":
                    return {
                        "schemaVersion": "1",
                        "ok": True,
                        "code": "STARTED",
                        "message": "",
                        "routeId": params["routeId"],
                        "runId": "run1_" + "A" * 43,
                        "state": "QUEUED",
                        "acceptedAt": "2026-07-16T00:00:00+00:00",
                    }
                raise AssertionError(method)

        self.backend = Backend()
        self.server = MCPServer(self.backend)

    def test_initialize_advertises_tools_only(self) -> None:
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            }
        )
        result = response["result"]
        self.assertEqual({"tools": {"listChanged": False}}, result["capabilities"])
        self.assertEqual("2025-06-18", result["protocolVersion"])

    def test_tools_list_contains_exactly_four_tools(self) -> None:
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            }
        )
        self.assertEqual(
            ["smart_plan", "smart_start", "smart_wait", "smart_cancel"],
            [tool["name"] for tool in response["result"]["tools"]],
        )

    def test_tool_call_returns_equivalent_structured_and_text_json(self) -> None:
        arguments = {
            "schemaVersion": "1",
            "routeId": "rt1_" + "A" * 43,
        }
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "smart_start", "arguments": arguments},
            }
        )
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], json.loads(result["content"][0]["text"]))
        self.assertEqual([("smart_start", arguments)], self.backend.calls)

    def test_unknown_method_uses_json_rpc_error(self) -> None:
        response = self.server.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "resources/list",
                "params": {},
            }
        )
        self.assertEqual(-32601, response["error"]["code"])


if __name__ == "__main__":
    unittest.main()
