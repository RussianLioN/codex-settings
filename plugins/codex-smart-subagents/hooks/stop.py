"""Stop hook that bounds coordination continuations without guessing shutdown."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Protocol


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for component in ("scripts", "src"):
    path = str(PLUGIN_ROOT / component)
    if path not in sys.path:
        sys.path.insert(0, path)

from integration_runtime import (  # noqa: E402
    CoordinationStore,
    IntegrationConfig,
    TERMINAL_ROUTE_STATES,
    environment_is_active,
    read_hook_input,
    write_hook_output,
)
from integration_runtime_v2 import (  # noqa: E402
    HookTurnContextV2,
    IntegrationConfigV2,
    TurnContextStoreV2,
    durable_stop_smart_turn_state_v2,
    pinned_resume_binding_v2,
    require_current_user_mcp_policy_v2,
)
from hook_deadline import (  # noqa: E402
    STOP_HOOK_BUDGET_SECONDS,
    HookDeadlineExceeded,
    fail_open_response,
    require_time_remaining,
    stop_deadline_from_environ,
)
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    ProjectIdentityV2,
    ResumeSessionV2Error,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    route_is_terminal_v2,
    system_process_marker_reader_v2,
)


_RESUME_LEASE_OPERATION_BUDGET_SECONDS = 0.30
HOOK_TOTAL_BUDGET_SECONDS_V2 = STOP_HOOK_BUDGET_SECONDS


class V2PlanStateProvider(Protocol):
    def __call__(
        self,
        config: IntegrationConfigV2,
        record: HookTurnContextV2,
        *,
        environ: Mapping[str, str],
        deadline: float,
    ) -> str: ...


def handle(
    payload: dict[str, Any],
    environ: Mapping[str, str],
    *,
    v2_plan_state_provider: V2PlanStateProvider = durable_stop_smart_turn_state_v2,
) -> dict[str, Any] | None:
    deadline = stop_deadline_from_environ(
        environ,
        fallback_budget_seconds=HOOK_TOTAL_BUDGET_SECONDS_V2,
    )
    if not environment_is_active(environ):
        return None
    try:
        require_time_remaining(deadline, "истёк общий срок Stop")
        if payload.get("hook_event_name") != "Stop":
            return None
        if environ.get("CODEX_SMART_STATE_HOME") and environ.get(
            "CODEX_SMART_GATEWAY_PATH"
        ):
            config_v2 = IntegrationConfigV2.from_environ(environ)
            try:
                require_current_user_mcp_policy_v2(config_v2, environ)
            except Exception:
                return None
            require_time_remaining(deadline, "истёк общий срок Stop")
            store_v2 = TurnContextStoreV2(config_v2)
            outcome = "unknown"

            def inspect_and_increment(
                current: HookTurnContextV2,
            ) -> HookTurnContextV2:
                nonlocal outcome
                if (
                    current.session_id != payload.get("session_id")
                    or current.turn_id != payload.get("turn_id")
                ):
                    outcome = "different-turn"
                    return current
                route_state = v2_plan_state_provider(
                    config_v2,
                    current,
                    environ=environ,
                    deadline=deadline,
                )
                require_time_remaining(deadline, "истёк общий срок Stop")
                if route_state in {"DIRECT", "CLARIFY", "DELEGATE_TERMINAL"}:
                    outcome = "complete"
                    return current
                if route_state not in {"MISSING", "DELEGATE_PENDING"}:
                    raise RuntimeError("состояние умного хода неизвестно")
                if current.continuation_count >= 2:
                    outcome = (
                        "bounded-plan"
                        if route_state == "MISSING"
                        else "bounded-route"
                    )
                    return current
                outcome = (
                    "block-plan" if route_state == "MISSING" else "block-route"
                )
                return replace(
                    current,
                    continuation_count=current.continuation_count + 1,
                )

            updated_record = store_v2.update(
                inspect_and_increment,
                deadline=deadline,
            )
            require_time_remaining(deadline, "истёк общий срок Stop")
            if outcome in {"different-turn", "complete"}:
                if outcome == "complete":
                    _acknowledge_resume_result_v2(
                        config_v2,
                        updated_record,
                        environ,
                        deadline=deadline,
                    )
                return None
            if outcome in {"bounded-plan", "bounded-route"}:
                if outcome == "bounded-route":
                    _defer_resume_to_next_turn_v2(
                        config_v2,
                        updated_record,
                        environ,
                        deadline=deadline,
                    )
                message = (
                    "После двух попыток завершение разрешено, хотя "
                    "долговечная запись smart_plan не найдена."
                    if outcome == "bounded-plan"
                    else "После двух попыток завершение разрешено, хотя "
                    "делегированный маршрут не достиг конечного состояния."
                )
                return {
                    "continue": True,
                    "systemMessage": message,
                }
            if outcome == "block-plan":
                reason = (
                    "Перед завершением хода вызови smart_plan. "
                    "Если решение предписывает обычное выполнение, "
                    "заверши задачу в корневом диалоге."
                )
            elif outcome == "block-route":
                reason = (
                    "Делегированный маршрут ещё не завершён. Вызови "
                    "route_start для готовых узлов и продолжи smart_wait. "
                    "Если маршрут больше не нужен, вызови smart_cancel."
                )
            else:
                raise RuntimeError("состояние Stop не определено")
            return {
                "decision": "block",
                "reason": reason,
            }
        require_time_remaining(deadline, "истёк общий срок Stop")
        config = IntegrationConfig.from_environ(
            environ,
            require_catalog=False,
        )
        store = CoordinationStore(config)
        state = store.load()
        if (
            state is None
            or state["sessionId"] != payload.get("session_id")
            or state["turnId"] != payload.get("turn_id")
        ):
            return None

        if state["planCalled"] and state["disposition"] in {
            "direct",
            "clarify",
        }:
            store.clear()
            return None
        if state["routeState"] in TERMINAL_ROUTE_STATES:
            store.clear()
            return None

        if state["continuationCount"] >= 2:
            if not state["planCalled"]:
                store.clear()
            return {
                "continue": True,
                "systemMessage": (
                    "После двух попыток координации завершение разрешено. "
                    "Событие Stop не подтверждает автоматическую отмену "
                    "маршрута."
                ),
            }

        state["continuationCount"] += 1
        store.save(state)
        require_time_remaining(deadline, "истёк общий срок Stop")
        if not state["planCalled"]:
            instruction = (
                "Перед завершением хода вызови smart_plan с выданной "
                "привязкой. Если результат direct, выполни задачу в корневом "
                "диалоге; если clarify, задай вопрос пользователю."
            )
            reason = "Умный ход ещё не прошёл обязательное планирование."
        elif state["routeState"] in {"", "PLANNED"}:
            instruction = (
                "Маршрут делегирования ещё не запущен. Вызови smart_start, "
                "затем smart_wait. Если маршрут больше не нужен, явно вызови "
                "smart_cancel с причиной superseded."
            )
            reason = "Маршрут делегирования ещё не запущен."
        else:
            instruction = (
                "Маршрут ещё не завершён. Продолжи smart_wait с последним "
                "номером события. Если маршрут больше не нужен, явно вызови "
                "smart_cancel."
            )
            reason = "Маршрут делегирования ещё не завершён."
        return {
            "decision": "block",
            "reason": f"{reason} {instruction}",
        }
    except ResumeSessionV2Error as exc:
        if exc.code == "RESUME_DEADLINE_EXCEEDED":
            return fail_open_response(exc.message)
        if environ.get("CODEX_SMART_LAUNCH_KIND") == "resume":
            return fail_open_response(
                "ошибка resume-подтверждения Stop; состояние будет сохранено для следующего хода"
            )
        return fail_open_response(
            "ошибка проверки Stop; состояние будет сохранено для следующего хода"
        )
    except HookDeadlineExceeded as exc:
        return fail_open_response(str(exc))
    except Exception:
        if environ.get("CODEX_SMART_LAUNCH_KIND") == "resume":
            return fail_open_response(
                "ошибка resume-подтверждения Stop; состояние будет сохранено для следующего хода"
            )
        return fail_open_response(
            "ошибка проверки Stop; состояние будет сохранено для следующего хода"
        )


def _acknowledge_resume_result_v2(
    config: IntegrationConfigV2,
    record: HookTurnContextV2,
    environ: Mapping[str, str],
    *,
    deadline: float,
) -> None:
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    if not environ.get("CODEX_SMART_ROOT_PID") or not environ.get(
        "CODEX_SMART_ROOT_START_MARKER"
    ):
        return
    root = RootIdentityV2(
        pid=int(environ.get("CODEX_SMART_ROOT_PID", "")),
        process_start_marker=environ.get("CODEX_SMART_ROOT_START_MARKER", ""),
    )
    store = RootSessionLeaseStoreV2(
        config.state_home,
        process_marker_reader=system_process_marker_reader_v2,
    )
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    lease = store.load(record.session_id, deadline=deadline)
    if lease is None or lease.attachment is None:
        return
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    binding = pinned_resume_binding_v2(
        config,
        environ,
        deadline=deadline,
    )
    route_id = lease.attachment.candidate.route_id
    if not route_is_terminal_v2(binding.database_path, route_id, deadline=deadline):
        return
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    project = ProjectIdentityV2(
        repo_root=record.repo_root,
        base_sha=record.base_sha,
        worktree_fingerprint=record.worktree_fingerprint,
        compatibility_fingerprint=binding.compatibility_fingerprint,
    )
    if not store.authorize_route(
        route_id=route_id,
        session_id=record.session_id,
        shell_session_id=record.shell_session_id,
        turn_id=record.turn_id,
        root=root,
        project=project,
        deadline=deadline,
    ):
        return
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    store.acknowledge_result(
        session_id=record.session_id,
        shell_session_id=record.shell_session_id,
        turn_id=record.turn_id,
        root=root,
        route_id=route_id,
        deadline=deadline,
    )


def _defer_resume_to_next_turn_v2(
    config: IntegrationConfigV2,
    record: HookTurnContextV2,
    environ: Mapping[str, str],
    *,
    deadline: float,
) -> None:
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    if not environ.get("CODEX_SMART_ROOT_PID") or not environ.get(
        "CODEX_SMART_ROOT_START_MARKER"
    ):
        return
    root = RootIdentityV2(
        pid=int(environ.get("CODEX_SMART_ROOT_PID", "")),
        process_start_marker=environ.get("CODEX_SMART_ROOT_START_MARKER", ""),
    )
    store = RootSessionLeaseStoreV2(
        config.state_home,
        process_marker_reader=system_process_marker_reader_v2,
    )
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    lease = store.load(record.session_id, deadline=deadline)
    if lease is None or lease.attachment is None:
        return
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    project = lease.project
    if (
        project.repo_root != record.repo_root
        or project.base_sha != record.base_sha
        or project.worktree_fingerprint != record.worktree_fingerprint
    ):
        return
    route_id = lease.attachment.candidate.route_id
    if lease.attachment.state == "PENDING_NEXT_TURN":
        return
    if not _resume_lease_operation_has_budget_v2(deadline):
        return
    store.defer_resume_to_next_turn(
        session_id=record.session_id,
        shell_session_id=record.shell_session_id,
        turn_id=record.turn_id,
        root=root,
        project=project,
        route_id=route_id,
        deadline=deadline,
    )


def _resume_lease_operation_has_budget_v2(deadline: float) -> bool:
    return deadline - time.monotonic() > _RESUME_LEASE_OPERATION_BUDGET_SECONDS


def main() -> int:
    try:
        payload = read_hook_input(sys.stdin)
        deadline = stop_deadline_from_environ(os.environ)
        require_time_remaining(deadline, "истёк общий срок Stop")
        response = handle(payload, os.environ)
        write_hook_output(sys.stdout, response)
        return 0
    except HookDeadlineExceeded as exc:
        write_hook_output(sys.stdout, fail_open_response(str(exc)))
        return 0
    except Exception:
        write_hook_output(
            sys.stdout,
            fail_open_response(
                "ошибка Stop; состояние будет сохранено для следующего хода"
            ),
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
