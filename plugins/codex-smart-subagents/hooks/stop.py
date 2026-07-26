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
    HOOK_TOTAL_BUDGET_SECONDS as HOOK_TOTAL_BUDGET_SECONDS_V2,
    HookTurnContextV2,
    IntegrationConfigV2,
    TurnContextStoreV2,
    durable_stop_smart_turn_state_v2,
    require_current_user_mcp_policy_v2,
)


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
    if not environment_is_active(environ):
        return None
    try:
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
            deadline = time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS_V2
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

            store_v2.update(
                inspect_and_increment,
                deadline=deadline,
            )
            if outcome in {"different-turn", "complete"}:
                return None
            if outcome in {"bounded-plan", "bounded-route"}:
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
    except Exception:
        return {
            "continue": True,
            "systemMessage": (
                "Не удалось проверить состояние умного маршрута; событие "
                "Stop не считает это доказательством отмены."
            ),
        }


def main() -> int:
    try:
        payload = read_hook_input(sys.stdin)
        response = handle(payload, os.environ)
        write_hook_output(sys.stdout, response)
        return 0
    except Exception:
        write_hook_output(
            sys.stdout,
            {
                "continue": True,
                "systemMessage": (
                    "Событие Stop завершилось ошибкой и не подтверждает "
                    "отмену маршрута."
                ),
            },
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
