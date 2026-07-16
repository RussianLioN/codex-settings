"""Minimal MCP stdio server exposing only the four smart-subagent tools."""

from __future__ import annotations

import json
import sys
from typing import Any, Protocol

from .contracts import (
    ContractError,
    SCHEMA_VERSION,
    get_tool_definitions,
    validate_tool_input,
    validate_tool_output,
)
from .controller import WireProtocolError


MCP_PROTOCOL = "2025-06-18"
SERVER_NAME = "codex-smart-subagents"
SERVER_VERSION = "0.1.0"


class Backend(Protocol):
    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        ...


class MCPServer:
    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return self._error(request_id, -32600, "Invalid Request")

        if method == "notifications/initialized":
            return None
        if method == "initialize":
            requested = params.get("protocolVersion")
            protocol = requested if isinstance(requested, str) else MCP_PROTOCOL
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
                {"tools": get_tool_definitions()},
            )
        if method == "tools/call":
            return self._call_tool(request_id, params)
        if method == "shutdown":
            return self._result(request_id, {})
        return self._error(request_id, -32601, "Method not found")

    def _call_tool(
        self,
        request_id: Any,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return self._error(request_id, -32602, "Invalid params")
        try:
            validated = validate_tool_input(name, arguments)
            output = validate_tool_output(
                name,
                self.backend.call(name, validated),
            )
            is_error = False
        except (ContractError, WireProtocolError) as exc:
            output = _tool_error_output(
                name,
                arguments,
                getattr(exc, "code", "TOOL_ERROR"),
                getattr(exc, "message", str(exc)),
            )
            is_error = True
        except Exception:
            output = _tool_error_output(
                name,
                arguments,
                "INTERNAL_ERROR",
                "internal smart-subagent error",
            )
            is_error = True

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
                "isError": is_error,
            },
        )

    @staticmethod
    def _result(request_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(
        request_id: Any,
        code: int,
        message: str,
    ) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def run_stdio(server: MCPServer) -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = MCPServer._error(None, -32700, "Parse error")
        else:
            response = server.handle(message)
        if response is not None:
            sys.stdout.write(
                json.dumps(
                    response,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            sys.stdout.flush()
    return 0


def _tool_error_output(
    name: str,
    arguments: dict[str, Any],
    code: str,
    message: str,
) -> dict[str, Any]:
    message = message[:1000]
    route_id = arguments.get("routeId")
    if not isinstance(route_id, str):
        route_id = ""
    if name == "smart_plan":
        output = {
            "schemaVersion": SCHEMA_VERSION,
            "ok": False,
            "code": code[:64] or "TOOL_ERROR",
            "message": message,
            "routeId": "",
            "routeGeneration": 0,
            "expiresAt": "",
            "startable": False,
            "overallDisposition": "error",
            "nodeDecisions": [],
            "clarificationQuestions": [],
            "catalogGeneration": "",
        }
    elif name == "smart_start":
        output = {
            "schemaVersion": SCHEMA_VERSION,
            "ok": False,
            "code": code[:64] or "TOOL_ERROR",
            "message": message,
            "routeId": route_id,
            "runId": "",
            "state": "FAILED",
            "acceptedAt": "",
        }
    elif name == "smart_wait":
        after = arguments.get("afterSequence", 0)
        output = {
            "schemaVersion": SCHEMA_VERSION,
            "ok": False,
            "code": code[:64] or "TOOL_ERROR",
            "message": message,
            "routeId": route_id,
            "state": "FAILED",
            "sequence": after if type(after) is int and after >= 0 else 0,
            "events": [],
            "truncated": False,
        }
    elif name == "smart_cancel":
        output = {
            "schemaVersion": SCHEMA_VERSION,
            "ok": False,
            "code": code[:64] or "TOOL_ERROR",
            "message": message,
            "routeId": route_id,
            "previousState": "FAILED",
            "newState": "FAILED",
            "accepted": False,
        }
    else:
        raise ContractError("UNKNOWN_TOOL", f"unknown tool: {name}")
    return validate_tool_output(name, output)

