"""Тонкий MCP-переходник к единственному процессу контроллера v2."""

from __future__ import annotations

import copy
import json
import sys
from typing import Any, Mapping

from .mcp_contracts_v2 import (
    MCPContractV2Error,
    get_tool_definitions_v2,
    validate_tool_input_v2,
    validate_tool_output_v2,
)
from .mcp_server_v2 import MCP_PROTOCOL, SERVER_NAME, SERVER_VERSION


class MCPProxyServerV2:
    """Обрабатывает MCP-оболочку, а смысловые команды передаёт контроллеру."""

    def __init__(
        self,
        *,
        client: Any,
        routing_input_schema: Mapping[str, Any] | None = None,
        routing_input_validator=None,
    ) -> None:
        if not callable(getattr(client, "call", None)):
            raise TypeError("client must provide call()")
        if routing_input_validator is not None and not callable(
            routing_input_validator
        ):
            raise TypeError("routing_input_validator must be callable")
        self.client = client
        self.routing_input_validator = routing_input_validator
        self.tool_definitions = get_tool_definitions_v2(
            routing_input_schema=routing_input_schema
        )

    def handle(self, message: Any) -> dict[str, Any] | None:
        if type(message) is not dict or message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if type(method) is not str or type(params) is not dict:
            return self._error(request_id, -32600, "Invalid Request")
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            requested = params.get("protocolVersion")
            protocol = requested if type(requested) is str else MCP_PROTOCOL
            return self._result(
                request_id,
                {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                },
            )
        if method == "ping":
            return self._result(request_id, {})
        if method == "tools/list":
            return self._result(
                request_id,
                {"tools": copy.deepcopy(self.tool_definitions)},
            )
        if method == "tools/call":
            return self._call_tool(request_id, params)
        if method == "shutdown":
            return self._result(request_id, {})
        return self._error(request_id, -32601, "Method not found")

    def _call_tool(
        self,
        request_id: Any,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        if set(params) not in (
            {"name", "arguments"},
            {"name", "arguments", "_meta"},
        ) or ("_meta" in params and type(params["_meta"]) is not dict):
            return self._error(request_id, -32602, "Invalid params")
        name = params["name"]
        if type(name) is not str:
            return self._error(request_id, -32602, "Invalid params")
        try:
            arguments = validate_tool_input_v2(
                name,
                params["arguments"],
                routing_input_validator=self.routing_input_validator,
            )
        except MCPContractV2Error:
            return self._error(request_id, -32602, "Invalid params")
        try:
            output = self.client.call(name, arguments)
            output = validate_tool_output_v2(name, output)
        except Exception:
            return self._error(request_id, -32603, "Internal error")
        text = json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return self._result(
            request_id,
            {
                "content": [{"type": "text", "text": text}],
                "structuredContent": output,
                "isError": output["responseKind"]
                in {"STALE", "UNAVAILABLE", "ERROR"},
            },
        )

    @staticmethod
    def _result(request_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def run_stdio_proxy_v2(server: MCPProxyServerV2) -> int:
    cleanup = getattr(server, "cleanup_runtime_attestation", None)
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            message: Any = None
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                response = MCPProxyServerV2._error(None, -32700, "Parse error")
            else:
                response = server.handle(message)
            if response is not None:
                prepare = getattr(server, "prepare_response_for_write", None)
                if callable(prepare):
                    response = prepare(message, response)
                try:
                    sys.stdout.write(
                        json.dumps(
                            response,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    sys.stdout.flush()
                except (BrokenPipeError, OSError):
                    return 1
        return 0
    finally:
        if callable(cleanup):
            cleanup()


__all__ = ["MCPProxyServerV2", "run_stdio_proxy_v2"]
