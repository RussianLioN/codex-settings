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
from integration_runtime import (  # noqa: E402
    CoordinationStore,
    IntegrationConfig,
    controller_client,
)


ClientFactory = Callable[[IntegrationConfig], Any]


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


def build_server(
    environ: Mapping[str, str],
    *,
    client_factory: ClientFactory = controller_client,
) -> MCPServer:
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
    return run_stdio(server)


if __name__ == "__main__":
    raise SystemExit(main())
