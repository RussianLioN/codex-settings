"""Тонкий MCP-сервер с четырьмя инструментами умного хода версии 2."""

from __future__ import annotations

import copy
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .canonical_json import domain_fingerprint
from .mcp_contracts_v2 import (
    MCPContractV2Error,
    get_tool_definitions_v2,
    validate_tool_input_v2,
    validate_tool_output_v2,
)
from .smart_turn_runtime_v2 import (
    SmartTurnRuntimeV2,
    build_public_request_v2,
    owner_for_context_v2,
)
from .state_store_v2 import RequestContextV2


MCP_PROTOCOL = "2025-06-18"
SERVER_NAME = "codex-smart-subagents"
SERVER_VERSION = "0.2.0"
_LOGGER = logging.getLogger(__name__)


class MCPServerV2:
    """Не позволяет модели задавать контекст владельца или шлюз активации."""

    def __init__(
        self,
        *,
        runtime: SmartTurnRuntimeV2,
        request_context_provider: Callable[[], RequestContextV2],
        activation_gate_provider: Callable[[], Mapping[str, Any]],
        clock: Callable[[], datetime] | None = None,
        routing_input_validator: Callable[[Mapping[str, Any]], Any] | None = None,
        routing_input_schema: Mapping[str, Any] | None = None,
        start_dispatcher: Callable[[str, RequestContextV2], None] | None = None,
    ) -> None:
        if not isinstance(runtime, SmartTurnRuntimeV2):
            raise TypeError("runtime must be SmartTurnRuntimeV2")
        for value, name in (
            (request_context_provider, "request_context_provider"),
            (activation_gate_provider, "activation_gate_provider"),
        ):
            if not callable(value):
                raise TypeError(f"{name} must be callable")
        self.runtime = runtime
        self.request_context_provider = request_context_provider
        self.activation_gate_provider = activation_gate_provider
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.routing_input_validator = routing_input_validator
        if start_dispatcher is not None and not callable(start_dispatcher):
            raise TypeError("start_dispatcher must be callable")
        self.start_dispatcher = start_dispatcher
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
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
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

    def _call_tool(self, request_id: Any, params: Mapping[str, Any]) -> dict[str, Any]:
        if set(params) != {"name", "arguments"}:
            return self._error(request_id, -32602, "Invalid params")
        name = params["name"]
        arguments = params["arguments"]
        if type(name) is not str:
            return self._error(request_id, -32602, "Invalid params")
        try:
            output = self.call_tool(name, arguments)
        except MCPContractV2Error:
            return self._error(request_id, -32602, "Invalid params")
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
                "isError": output["responseKind"] in {"STALE", "UNAVAILABLE", "ERROR"},
            },
        )

    def call_tool(self, name: str, arguments: Any) -> dict[str, Any]:
        """Выполняет один проверенный вызов без внешней оболочки JSON-RPC."""

        validated = validate_tool_input_v2(
            name,
            arguments,
            routing_input_validator=self.routing_input_validator,
        )
        context = self.request_context_provider()
        if not isinstance(context, RequestContextV2):
            raise TypeError("request context provider returned another type")
        output = self._execute(name, validated, context)
        return validate_tool_output_v2(name, output)

    def _execute(
        self,
        name: str,
        arguments: Mapping[str, Any],
        context: RequestContextV2,
    ) -> dict[str, Any]:
        owner = owner_for_context_v2(context)
        if name == "smart_plan":
            binding_request = self._request(
                "issue_turn_binding",
                owner=owner,
                params={
                    "requestContext": context.contract_value(),
                    "ttlSeconds": 120,
                },
                purpose="binding",
                arguments=arguments,
                idempotent=True,
            )
            binding_response = self.runtime.issue_turn_binding(
                binding_request,
                request_context=context,
            )
            if binding_response["responseKind"] != "SUCCESS":
                return self._ordinary_before_request(
                    "smart_plan",
                    owner=owner,
                    arguments=arguments,
                    result_id=binding_request["requestId"],
                )
            plan_request = self._request(
                "smart_plan",
                owner=owner,
                params={"nodes": copy.deepcopy(arguments["nodes"])},
                purpose="plan",
                arguments=arguments,
                turn_binding=binding_response["payload"]["turnBinding"],
                idempotent=True,
            )
            response = self.runtime.smart_plan(
                plan_request,
                request_context=context,
            )
            if response["responseKind"] == "UNAVAILABLE":
                return self.runtime.ordinary_unavailable(plan_request)
            return response

        if name == "route_start":
            try:
                gate = self.activation_gate_provider()
                if type(gate) is not dict:
                    raise TypeError("activation gate provider returned another type")
            except Exception:
                return self._ordinary_before_request(
                    "route_start",
                    owner=owner,
                    arguments=arguments,
                    result_id=str(arguments["routeId"]),
                )
            start_request = self._request(
                "route_start",
                owner=owner,
                params={
                    "routeId": arguments["routeId"],
                    "nodeId": arguments["nodeId"],
                    "activationGate": copy.deepcopy(gate),
                },
                purpose="start",
                arguments=arguments,
                idempotent=True,
            )
            response = self.runtime.route_start(
                start_request,
                request_context=context,
                activation_gate=gate,
            )
            if response["responseKind"] == "UNAVAILABLE":
                return self.runtime.ordinary_unavailable(start_request)
            if response["responseKind"] == "SUCCESS":
                self._dispatch_start_best_effort(
                    response["payload"]["startRequestId"],
                    context,
                )
            return response

        if name == "smart_wait":
            self._dispatch_start_best_effort(arguments["startRequestId"], context)
            now = self._now()
            wait_deadline = now + timedelta(seconds=arguments["waitSeconds"])
            wait_request = self._request(
                "smart_wait",
                owner=owner,
                params={
                    "startRequestId": arguments["startRequestId"],
                    "cursor": arguments["cursor"],
                    "pageSize": arguments["pageSize"],
                    "waitDeadlineAt": _iso(wait_deadline),
                },
                purpose="wait",
                arguments=arguments,
                request_deadline_at=wait_deadline + timedelta(seconds=5),
                idempotent=False,
            )
            return self.runtime.smart_wait(wait_request, request_context=context)

        cancel_request = self._request(
            "smart_cancel",
            owner=owner,
            params={
                "startRequestId": arguments["startRequestId"],
                "reasonCode": arguments["reasonCode"],
            },
            purpose="cancel",
            arguments=arguments,
            idempotent=True,
        )
        return self.runtime.smart_cancel(cancel_request, request_context=context)

    def _dispatch_start_best_effort(
        self,
        start_request_id: str,
        context: RequestContextV2,
    ) -> None:
        if self.start_dispatcher is None:
            return
        try:
            self.start_dispatcher(start_request_id, context)
        except Exception:
            _LOGGER.exception("не удалось подать долговечную заявку запуска")

    def _request(
        self,
        method: str,
        *,
        owner: Mapping[str, Any],
        params: Mapping[str, Any],
        purpose: str,
        arguments: Mapping[str, Any],
        idempotent: bool,
        turn_binding: Mapping[str, Any] | None = None,
        request_deadline_at: datetime | None = None,
    ) -> dict[str, Any]:
        identity = {
            "method": method,
            "purpose": purpose,
            "owner": copy.deepcopy(dict(owner)),
            "arguments": copy.deepcopy(dict(arguments)),
        }
        request_id = (
            "strq2_"
            + domain_fingerprint(
                "codex-smart/mcp-request-id/v2",
                identity,
            )[:32]
        )
        idempotency_key = (
            "idem2_"
            + domain_fingerprint(
                "codex-smart/mcp-idempotency-key/v2",
                identity,
            )[:32]
            if idempotent
            else None
        )
        return build_public_request_v2(
            method,
            request_id=request_id,
            owner=owner,
            turn_binding=turn_binding,
            idempotency_key=idempotency_key,
            request_deadline_at=request_deadline_at
            or (self._now() + timedelta(seconds=5)),
            params=params,
        )

    def _ordinary_before_request(
        self,
        method: str,
        *,
        owner: Mapping[str, Any],
        arguments: Mapping[str, Any],
        result_id: str,
    ) -> dict[str, Any]:
        request_id = (
            "strq2_"
            + domain_fingerprint(
                "codex-smart/mcp-fallback-request-id/v2",
                {
                    "method": method,
                    "owner": copy.deepcopy(dict(owner)),
                    "arguments": copy.deepcopy(dict(arguments)),
                },
            )[:32]
        )
        return self.runtime.ordinary_unavailable_call(
            method=method,
            request_id=request_id,
            owner=owner,
            call_arguments=arguments,
            result_id=result_id,
        )

    def _now(self) -> datetime:
        value = self.clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError("clock must return an aware datetime")
        return value.astimezone(timezone.utc)

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


def run_stdio_v2(server: MCPServerV2) -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = MCPServerV2._error(None, -32700, "Parse error")
        else:
            response = server.handle(message)
        if response is not None:
            sys.stdout.write(
                json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
            sys.stdout.flush()
    return 0


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must include an offset")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


__all__ = ["MCPServerV2", "run_stdio_v2"]
