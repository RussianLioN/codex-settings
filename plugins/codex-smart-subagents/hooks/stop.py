"""Stop hook that bounds coordination continuations without guessing shutdown."""

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
    CoordinationStore,
    IntegrationConfig,
    TERMINAL_ROUTE_STATES,
    environment_is_active,
    read_hook_input,
    write_hook_output,
)


def handle(
    payload: dict[str, Any],
    environ: Mapping[str, str],
) -> dict[str, Any] | None:
    if not environment_is_active(environ):
        return None
    try:
        if payload.get("hook_event_name") != "Stop":
            return None
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
            "continue": False,
            "stopReason": reason,
            "systemMessage": reason,
            "hookSpecificOutput": {
                "hookEventName": "Stop",
                "additionalContext": instruction,
            },
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
