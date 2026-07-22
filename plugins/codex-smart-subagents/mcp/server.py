"""Bundled MCP stdio entrypoint backed by the local controller."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Mapping


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for component in ("scripts", "src"):
    path = str(PLUGIN_ROOT / component)
    if path not in sys.path:
        sys.path.insert(0, path)

from codex_smart_subagents.mcp_server import MCPServer, run_stdio  # noqa: E402
from codex_smart_subagents.controller_command_v2 import (  # noqa: E402
    ControllerCommandClientV2,
)
from codex_smart_subagents.mcp_proxy_v2 import (  # noqa: E402
    MCPProxyServerV2,
    run_stdio_proxy_v2,
)
from codex_smart_subagents.mcp_server_v2 import (  # noqa: E402
    MCP_PROTOCOL as MCP_PROTOCOL_V2,
    SERVER_NAME as SERVER_NAME_V2,
    SERVER_VERSION as SERVER_VERSION_V2,
)
from codex_smart_subagents.mcp_runtime_proof_v2 import (  # noqa: E402
    MCPRuntimeAttestationPublisherV2,
    MCP_SESSION_NONCE_ENV_V2,
    USER_MCP_POLICY_PROOF_ENV_V2,
)
from integration_runtime import (  # noqa: E402
    CoordinationStore,
    IntegrationConfig,
    mcp_controller_client,
)
from integration_runtime_v2 import IntegrationConfigV2  # noqa: E402


ClientFactory = Callable[[IntegrationConfig], Any]
V2ClientFactory = Callable[..., Any]
_V2_ENVIRONMENT_MARKERS = frozenset(
    {
        "CODEX_SMART_LAUNCHER_ACTIVE",
        "CODEX_SMART_STATE_HOME",
        "CODEX_SMART_GATEWAY_PATH",
        "CODEX_SMART_ACTIVATION_ID",
        "CODEX_SMART_GATE_FINGERPRINT",
        "CODEX_SMART_ACTIVATION_GATE",
        MCP_SESSION_NONCE_ENV_V2,
        USER_MCP_POLICY_PROOF_ENV_V2,
    }
)


class TrackingBackend:
    """Records only bounded route coordination, never missions or tool inputs."""

    def __init__(self, client: Any, store: CoordinationStore) -> None:
        self.client = client
        self.store = store

    def call(
        self,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        result = self.client.call(method, params)

        def update(state: dict[str, Any] | None) -> dict[str, Any] | None:
            if state is None:
                return None
            if method == "smart_plan":
                state["planCalled"] = True
                state["routeId"] = str(result.get("routeId", ""))
                state["disposition"] = str(
                    result.get("overallDisposition", "")
                )
                state["routeState"] = "PLANNED"
            elif (
                method == "smart_start"
                and state["routeId"] == params.get("routeId")
            ):
                state["routeState"] = str(result.get("state", ""))
            elif (
                method == "smart_wait"
                and state["routeId"] == params.get("routeId")
            ):
                state["routeState"] = str(result.get("state", ""))
                sequence = result.get("sequence")
                if type(sequence) is int and sequence >= 0:
                    state["afterSequence"] = sequence
            elif (
                method == "smart_cancel"
                and state["routeId"] == params.get("routeId")
            ):
                state["routeState"] = str(result.get("newState", ""))
            return state

        self.store.update(update)
        return result


class InactiveMCPServer:
    """Пустой сервер для обычного Codex без ложного умного режима."""

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
            protocol = requested if type(requested) is str else MCP_PROTOCOL_V2
            return self._result(
                request_id,
                {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "codex-smart-subagents-inactive",
                        "version": SERVER_VERSION_V2,
                    },
                },
            )
        if method == "ping":
            return self._result(request_id, {})
        if method == "tools/list":
            return self._result(request_id, {"tools": []})
        if method == "shutdown":
            return self._result(request_id, {})
        return self._error(request_id, -32601, "Method not found")

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


class AttestedMCPProxyServerV2(MCPProxyServerV2):
    """Публикует proof из точного tools/list непосредственно перед записью."""

    def __init__(
        self,
        *,
        client: Any,
        publisher: MCPRuntimeAttestationPublisherV2,
    ) -> None:
        super().__init__(client=client)
        self.publisher = publisher

    def prepare_response_for_write(
        self,
        message: Any,
        response: dict[str, Any],
    ) -> dict[str, Any]:
        if type(message) is not dict or message.get("method") != "tools/list":
            return response
        try:
            result = response["result"]
            tools = result["tools"]
            if type(result) is not dict or type(tools) is not list:
                raise TypeError("tools/list response is malformed")
            self.publisher.publish(
                tools,
                server_name=SERVER_NAME_V2,
                server_version=SERVER_VERSION_V2,
                protocol_version=MCP_PROTOCOL_V2,
            )
            return response
        except Exception:
            self.publisher.cleanup()
            return self._result(message.get("id"), {"tools": []})

    def cleanup_runtime_attestation(self) -> None:
        self.publisher.cleanup()


def build_server(
    environ: Mapping[str, str],
    *,
    client_factory: ClientFactory = mcp_controller_client,
    v2_client_factory: V2ClientFactory = ControllerCommandClientV2,
) -> MCPServer | MCPProxyServerV2 | InactiveMCPServer:
    if _has_v2_environment(environ):
        try:
            config_v2 = IntegrationConfigV2.from_environ(environ)
            publisher = MCPRuntimeAttestationPublisherV2.from_environ(environ)
            client_v2 = v2_client_factory(
                socket_path=config_v2.state_home / "command.sock",
                shell_session_id=config_v2.shell_session_id,
            )
        except Exception:
            # Сервер объявлен обязательным в bundled-конфигурации. Поэтому
            # неполное или устаревшее окружение должно сохранить успешный
            # протокол MCP без инструментов, а не сорвать запуск обычного
            # Codex и не провалиться в старый путь версии 1.
            return InactiveMCPServer()
        return AttestedMCPProxyServerV2(
            client=client_v2,
            publisher=publisher,
        )

    if not environ.get("CODEX_ADAPTIVE_SESSION_ID"):
        return InactiveMCPServer()

    config = IntegrationConfig.from_environ(
        environ,
        require_catalog=False,
    )
    client = client_factory(config)
    return MCPServer(
        TrackingBackend(
            client,
            CoordinationStore(config),
        )
    )


def _has_v2_environment(environ: Mapping[str, str]) -> bool:
    shell_session_id = environ.get("CODEX_ADAPTIVE_SESSION_ID", "")
    return shell_session_id.startswith("cas2_") or any(
        name in environ for name in _V2_ENVIRONMENT_MARKERS
    )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments != ["--stdio"]:
        sys.stderr.write(
            "codex-smart-subagents: поддерживается только --stdio\n"
        )
        return 2
    try:
        server = build_server(os.environ)
    except Exception:
        sys.stderr.write(
            "codex-smart-subagents: неполное окружение умного сеанса\n"
        )
        return 2
    if isinstance(server, (MCPProxyServerV2, InactiveMCPServer)):
        return run_stdio_proxy_v2(server)
    return run_stdio(server)


if __name__ == "__main__":
    raise SystemExit(main())
