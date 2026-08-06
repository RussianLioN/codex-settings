"""SessionStart: регистрирует корень и готовит умное возобновление."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Mapping


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for component in ("scripts", "src"):
    path = str(PLUGIN_ROOT / component)
    if path not in sys.path:
        sys.path.insert(0, path)

from integration_runtime import (  # noqa: E402
    _git_identity,
    environment_is_active,
    read_hook_input,
    write_hook_output,
)
from integration_runtime_v2 import (  # noqa: E402
    IntegrationConfigV2,
    pinned_resume_binding_v2,
    require_current_user_mcp_policy_v2,
)
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    ProjectIdentityV2,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    discover_resume_candidate_v2,
    system_process_marker_reader_v2,
)


SESSION_START_TOTAL_BUDGET_SECONDS = 8.0


def handle(payload: dict[str, Any], environ: Mapping[str, str]) -> dict[str, Any] | None:
    if not environment_is_active(environ) or payload.get("agent_id"):
        return None
    if payload.get("hook_event_name") != "SessionStart":
        return None
    source = payload.get("source")
    if source not in {"startup", "resume", "clear", "compact"}:
        return {
            "continue": True,
            "systemMessage": (
                "Источник SessionStart не распознан; основной запрос продолжится "
                "без умного присоединения."
            ),
        }
    # Первый запуск после сна или обновления может читать активацию, базу и
    # состояние Git с холодного диска. Короткий срок остальных хуков здесь
    # создавал ложный отказ ровно на границе 1,75 секунды.
    deadline = time.monotonic() + SESSION_START_TOTAL_BUDGET_SECONDS
    try:
        config = IntegrationConfigV2.from_environ(environ)
        require_current_user_mcp_policy_v2(config, environ)
        binding = pinned_resume_binding_v2(config, environ, deadline=deadline)
        repo_root, base_sha, worktree_fingerprint = _git_identity(
            payload["cwd"], deadline=deadline
        )
        project = ProjectIdentityV2(
            repo_root=repo_root,
            base_sha=base_sha,
            worktree_fingerprint=worktree_fingerprint,
            compatibility_fingerprint=binding.compatibility_fingerprint,
        )
        root = _root_identity(environ)
        store = RootSessionLeaseStoreV2(
            config.state_home,
            process_marker_reader=system_process_marker_reader_v2,
        )
        if source == "resume":
            if environ.get("CODEX_SMART_LAUNCH_KIND") != "resume":
                raise RuntimeError("режим загрузчика и событие resume расходятся")
            candidate = discover_resume_candidate_v2(
                binding.database_path,
                session_id=payload["session_id"],
            )
            prepared = store.prepare_resume(
                session_id=payload["session_id"],
                shell_session_id=config.shell_session_id,
                root=root,
                project=project,
                candidate=candidate,
            )
            return _resume_output(prepared.status, prepared.route_id)
        store.register_startup(
            session_id=payload["session_id"],
            shell_session_id=config.shell_session_id,
            root=root,
            project=project,
        )
        return None
    except Exception:
        return {
            "continue": True,
            "systemMessage": (
                "Не удалось доказать аренду умного сеанса; основной запрос "
                "продолжится без старого маршрута."
            ),
        }


def _root_identity(environ: Mapping[str, str]) -> RootIdentityV2:
    try:
        pid = int(environ.get("CODEX_SMART_ROOT_PID", ""))
    except ValueError as exc:
        raise RuntimeError("pid корневого процесса отсутствует") from exc
    return RootIdentityV2(
        pid=pid,
        process_start_marker=environ.get("CODEX_SMART_ROOT_START_MARKER", ""),
    )


def _resume_output(status: str, route_id: str | None) -> dict[str, Any] | None:
    if status == "RESUME_PREPARED":
        return {
            "continue": True,
            "systemMessage": (
                "Подготовлено безопасное присоединение незавершённого умного "
                f"маршрута {route_id}."
            ),
        }
    if status == "RESUME_OWNER_ACTIVE":
        return {
            "continue": True,
            "systemMessage": (
                "RESUME_OWNER_ACTIVE: старый маршрут принадлежит другому "
                "живому процессу; текущий диалог продолжится как новый умный ход."
            ),
        }
    if status in {
        "RESUME_CONTEXT_MISMATCH",
        "RESUME_COMPATIBILITY_MISMATCH",
        "RESUME_OWNER_UNPROVED",
        "RESUME_ATTACHMENT_CHANGED",
        "RESUME_SNAPSHOT_MISMATCH",
        "RESUME_LEASE_INVALID",
    }:
        return {
            "continue": True,
            "systemMessage": (
                f"{status}: старый маршрут не присоединён; диалог продолжится "
                "как новый умный ход."
            ),
        }
    return None


def main() -> int:
    payload = read_hook_input(sys.stdin)
    response = handle(payload, os.environ)
    write_hook_output(sys.stdout, response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
