"""SessionEnd: освобождает активность аренды, сохраняя её происхождение."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Mapping


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for component in ("scripts", "src"):
    path = str(PLUGIN_ROOT / component)
    if path not in sys.path:
        sys.path.insert(0, path)

from integration_runtime import (  # noqa: E402
    environment_is_active,
    read_hook_input,
    write_hook_output,
)
from integration_runtime_v2 import IntegrationConfigV2  # noqa: E402
from hook_deadline import fail_open_response  # noqa: E402
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    system_process_marker_reader_v2,
)


def handle(payload: dict[str, Any], environ: Mapping[str, str]) -> dict[str, Any] | None:
    if not environment_is_active(environ) or payload.get("agent_id"):
        return None
    if payload.get("hook_event_name") != "SessionEnd":
        return None
    try:
        config = IntegrationConfigV2.from_environ(environ)
        root = RootIdentityV2(
            pid=int(environ.get("CODEX_SMART_ROOT_PID", "")),
            process_start_marker=environ.get("CODEX_SMART_ROOT_START_MARKER", ""),
        )
        RootSessionLeaseStoreV2(
            config.state_home,
            process_marker_reader=system_process_marker_reader_v2,
        ).release(
            session_id=payload["session_id"],
            shell_session_id=config.shell_session_id,
            root=root,
        )
    except Exception:
        return fail_open_response(
            "SessionEnd не освободил умный сеанс; состояние останется проверяемым"
        )
    return None


def main() -> int:
    try:
        payload = read_hook_input(sys.stdin)
        response = handle(payload, os.environ)
        write_hook_output(sys.stdout, response)
    except Exception:
        write_hook_output(
            sys.stdout,
            fail_open_response("SessionEnd завершился ошибкой чтения события"),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
