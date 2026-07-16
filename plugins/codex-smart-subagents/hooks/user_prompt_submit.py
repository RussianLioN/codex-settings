"""UserPromptSubmit hook for issuing an opaque, one-use turn binding."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for component in ("scripts", "src"):
    path = str(PLUGIN_ROOT / component)
    if path not in sys.path:
        sys.path.insert(0, path)

from integration_runtime import (  # noqa: E402
    CoordinationStore,
    HOOK_CONTROLLER_TIMEOUT_SECONDS,
    HOOK_TOTAL_BUDGET_SECONDS,
    IntegrationConfig,
    catalog_routing_context,
    controller_client,
    environment_is_active,
    hook_context,
    read_hook_input,
    request_context,
    write_hook_output,
)


ClientFactory = Callable[[IntegrationConfig], Any]


def handle(
    payload: dict[str, Any],
    environ: Mapping[str, str],
    *,
    client_factory: ClientFactory = controller_client,
) -> dict[str, Any] | None:
    if not environment_is_active(environ) or payload.get("agent_id"):
        return None
    deadline = time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS
    try:
        config = IntegrationConfig.from_environ(
            environ,
            require_catalog=True,
        )
        context = request_context(
            payload,
            config,
            deadline=deadline,
        )
        generation, identifiers = catalog_routing_context(config)
        client = client_factory(config)
        store = CoordinationStore(config)
        previous = store.load()
        if (
            previous is not None
            and previous["turnId"] != payload.get("turn_id")
            and previous["planCalled"]
            and previous["disposition"] == "delegate"
            and previous["routeId"]
            and previous["routeState"] not in {
                "SUCCEEDED",
                "CANDIDATE_READY",
                "QUARANTINED",
                "CANCELLED",
                "FAILED",
                "STALE",
                "SKIPPED",
            }
        ):
            if (
                deadline - time.monotonic()
                > 2 * HOOK_CONTROLLER_TIMEOUT_SECONDS
            ):
                try:
                    client.call(
                        "smart_cancel",
                        {
                            "schemaVersion": "1",
                            "routeId": previous["routeId"],
                            "reasonCode": "superseded",
                        },
                    )
                except Exception:
                    pass

        if (
            deadline - time.monotonic()
            <= HOOK_CONTROLLER_TIMEOUT_SECONDS
        ):
            raise RuntimeError("hook time budget exhausted")
        binding = client.call(
            "issue_turn_binding",
            {"context": context.to_wire()},
        )["turnBinding"]
        store.save(
            {
                "schemaVersion": 1,
                "shellSessionId": config.shell_session_id,
                "sessionId": payload["session_id"],
                "turnId": payload["turn_id"],
                "turnBinding": binding,
                "catalogGeneration": generation,
                "planCalled": False,
                "routeId": "",
                "disposition": "",
                "routeState": "",
                "afterSequence": 0,
                "continuationCount": 0,
            }
        )
    except Exception:
        return {
            "continue": False,
            "stopReason": (
                "Умный ход остановлен: локальный контроллер или его "
                "проверенная конфигурация недоступны."
            ),
            "systemMessage": (
                "Умный режим не запущен. Повторите запрос после проверки "
                "локального контроллера."
            ),
        }

    opaque_context = ", ".join(
        f"{name}={value}" for name, value in identifiers.items()
    )
    text = (
        "Умный режим активен для этого хода. Сначала вызови smart_plan ровно "
        "один раз: schemaVersion=1, turnBinding="
        f"{binding}, catalogGeneration={generation}. "
        f"Допустимые непрозрачные идентификаторы: {opaque_context}. "
        "Оценки и граф формируй строго по определениям и правилам схемы "
        "smart_plan. Передавай только миссии, зависимости, оценки и выданные "
        "непрозрачные идентификаторы; не передавай пути, команды или "
        "переменные окружения. "
        "Решение direct выполняй в корневом диалоге. Для delegate вызови "
        "smart_start и затем smart_wait до конечного состояния. Если маршрут "
        "больше не нужен, вызови smart_cancel. Модель, уровень рассуждения и "
        "права выбирает контроллер. События лишь координируют ход и не "
        "гарантируют автоматический перехват или отмену."
    )
    return hook_context("UserPromptSubmit", text)


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
                "continue": False,
                "stopReason": "Умный ход остановлен из-за ошибки события.",
                "systemMessage": "Проверьте установку расширения и контроллер.",
            },
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
