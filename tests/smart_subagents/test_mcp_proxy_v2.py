from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.controller_command_v2 import (  # noqa: E402
    ControllerCommandV2Error,
)
from codex_smart_subagents.mcp_proxy_v2 import MCPProxyServerV2  # noqa: E402
from codex_smart_subagents.smart_turn_runtime_v2 import (  # noqa: E402
    _response,
    owner_for_context_v2,
)
from codex_smart_subagents.state_store_v2 import RequestContextV2  # noqa: E402


class _Client:
    def __init__(self, *, error: BaseException | None = None) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.error = error

    def call(self, method: str, arguments: dict[str, object]):
        self.calls.append((method, arguments))
        if self.error is not None:
            raise self.error
        owner = owner_for_context_v2(
            RequestContextV2(
                shell_session_id="cas2_" + "A" * 32,
                session_id="session",
                turn_id="turn",
                codex_home="/private/codex-home",
                repo_root="/private/repo",
                base_sha="1" * 64,
                worktree_fingerprint="2" * 64,
                activation_fingerprint="3" * 64,
                compatibility_fingerprint="4" * 64,
                issued_control_epoch=1,
            )
        )
        return _response(
            {
                "requestId": "strq2_" + "1" * 32,
                "owner": owner,
                "method": method,
                "requestFingerprint": "3" * 64,
            },
            "ORDINARY",
            {
                "status": "ORDINARY",
                "reasonCode": "DIRECT_SELECTED",
                "ordinaryCommand": "codex",
                "preserveUserRequest": True,
                "message": "Выполнить задачу в обычном Codex.",
                "effect": {
                    "operation": "READ",
                    "transactionMode": "READ_ONLY",
                    "transitions": [],
                    "completedAt": "2026-07-19T12:00:00Z",
                    "result": {
                        "resultKind": "ORDINARY_DECISION",
                        "resultId": "route2_" + "4" * 32,
                        "resultFingerprint": "5" * 64,
                    },
                },
            },
        )


def _call(name: str, arguments: dict[str, object]):
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _plan_arguments() -> dict[str, object]:
    return {
        "nodes": [
            {
                "clientNodeId": "reader_a",
                "dependencyIds": [],
                "routingInput": _public_routing_input(),
            }
        ]
    }


def _public_routing_input() -> dict[str, object]:
    internal = json.loads(
        (ROOT / "docs/contracts/vectors/routing-input-v2.json").read_text(
            encoding="utf-8"
        )
    )["baseInput"]
    facts = internal["taskFacts"]
    return {
        "taskFacts": {
            "taskText": facts["taskText"],
            "evidence": facts["evidence"],
            "workShape": facts["workShape"],
            "factorClaims": facts["factorClaims"],
            "delegation": {
                "objectivelyVerifiable": facts["delegation"]["objectivelyVerifiable"],
                "independentWorkUnits": facts["delegation"]["independentWorkUnits"],
            },
            "hardFloorReasons": facts["hardFloorReasons"],
            "hardBanReasons": facts["hardBanReasons"],
        },
        "contextBundle": internal["contextBundle"],
        "roleTemplateId": internal["roleTemplateId"],
    }


class MCPProxyServerV2Tests(unittest.TestCase):
    def test_lists_exactly_four_v2_tools(self) -> None:
        server = MCPProxyServerV2(client=_Client())
        response = server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        self.assertEqual(
            ["smart_plan", "route_start", "smart_wait", "smart_cancel"],
            [tool["name"] for tool in response["result"]["tools"]],
        )

    def test_forwards_only_valid_tool_arguments_and_returns_equal_text_json(
        self,
    ) -> None:
        client = _Client()
        server = MCPProxyServerV2(client=client)
        response = server.handle(_call("smart_plan", _plan_arguments()))
        self.assertEqual(
            [("smart_plan", _plan_arguments())],
            client.calls,
        )
        result = response["result"]
        self.assertEqual(
            result["structuredContent"],
            __import__("json").loads(result["content"][0]["text"]),
        )
        self.assertFalse(result["isError"])

    def test_rejects_extra_call_fields_before_transport(self) -> None:
        client = _Client()
        server = MCPProxyServerV2(client=client)
        message = _call(
            "route_start",
            {"routeId": "route2_" + "1" * 32, "nodeId": "node2_" + "2" * 32},
        )
        message["params"]["path"] = "/tmp/injection"
        response = server.handle(message)
        self.assertEqual(-32602, response["error"]["code"])
        self.assertEqual([], client.calls)

    def test_transport_failure_is_sanitized_as_internal_mcp_error(self) -> None:
        client = _Client(
            error=ControllerCommandV2Error("TRANSPORT_FAILURE", "/private/secret")
        )
        server = MCPProxyServerV2(client=client)
        response = server.handle(_call("smart_plan", _plan_arguments()))
        self.assertEqual(-32603, response["error"]["code"])
        self.assertNotIn("secret", str(response))


if __name__ == "__main__":
    unittest.main()
