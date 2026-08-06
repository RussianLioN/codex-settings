"""UserPromptSubmit hook for issuing an opaque, one-use turn binding."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


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
from integration_runtime_v2 import (  # noqa: E402
    HOOK_TOTAL_BUDGET_SECONDS as HOOK_TOTAL_BUDGET_SECONDS_V2,
    IntegrationConfigV2,
    IntegrationV2Error,
    TurnContextStoreV2,
    capture_hook_turn_context_v2,
    require_current_user_mcp_policy_v2,
    require_live_controller_v2,
    require_mcp_contract_v2,
)
from codex_smart_subagents.resume_session_v2 import (  # noqa: E402
    ProjectIdentityV2,
    ResumeSessionV2Error,
    RootIdentityV2,
    RootSessionLeaseStoreV2,
    system_process_marker_reader_v2,
)


ClientFactory = Callable[[IntegrationConfig], Any]
V2MCPContractChecker = Callable[[Path], None]


class V2ControllerChecker(Protocol):
    def __call__(
        self,
        config: IntegrationConfigV2,
        environ: Mapping[str, str],
        *,
        deadline: float,
    ) -> None: ...


def handle(
    payload: dict[str, Any],
    environ: Mapping[str, str],
    *,
    client_factory: ClientFactory = controller_client,
    v2_mcp_contract_checker: V2MCPContractChecker = require_mcp_contract_v2,
    v2_controller_checker: V2ControllerChecker = require_live_controller_v2,
) -> dict[str, Any] | None:
    if not environment_is_active(environ) or payload.get("agent_id"):
        return None
    if environ.get("CODEX_SMART_STATE_HOME") and environ.get(
        "CODEX_SMART_GATEWAY_PATH"
    ):
        return _handle_v2(
            payload,
            environ,
            mcp_contract_checker=v2_mcp_contract_checker,
            controller_checker=v2_controller_checker,
        )
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
            "continue": True,
            "systemMessage": (
                "Умное делегирование недоступно; запрос продолжается в "
                "обычном режиме Codex без субагентов."
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


def _handle_v2(
    payload: dict[str, Any],
    environ: Mapping[str, str],
    *,
    mcp_contract_checker: V2MCPContractChecker,
    controller_checker: V2ControllerChecker,
) -> dict[str, Any]:
    deadline = time.monotonic() + HOOK_TOTAL_BUDGET_SECONDS_V2
    try:
        config = IntegrationConfigV2.from_environ(environ)
        # Codex запускает MCP лениво и может выполнить UserPromptSubmit раньше
        # первого tools/list. Здесь доказываем неизменную пользовательскую
        # политику и bundled-договор; сам процесс MCP подтверждает себя при
        # фактическом обращении к инструментам.
        require_current_user_mcp_policy_v2(config, environ)
        mcp_contract_checker(PLUGIN_ROOT)
        controller_checker(config, environ, deadline=deadline)
    except Exception:
        return {
            "continue": True,
            "systemMessage": (
                "Умное делегирование версии 2 недоступно для этого хода; "
                "запрос продолжается в обычном режиме Codex без субагентов."
            ),
        }
    try:
        record = capture_hook_turn_context_v2(
            payload,
            config,
            deadline=deadline,
        )
        resume_instruction = _bind_resume_instruction_v2(
            config,
            record,
            environ,
        )
    except Exception:
        return {
            "continue": True,
            "systemMessage": (
                "Умное делегирование версии 2 недоступно для этого хода; "
                "запрос продолжается в обычном режиме Codex без субагентов."
            ),
        }

    text = resume_instruction or (
        "Умный режим версии 2 активен для этого хода. До вызова smart_plan "
        "прочитай навык codex-smart-subagents:using-smart-subagents, подготовь "
        "нормативный planInput по его образцу и программно проверь поля. Затем "
        "вызови smart_plan ровно один раз через его прямое имя. Если ответ "
        "предписывает обычное "
        "выполнение, реши задачу в корневом диалоге. Для делегированного узла "
        "вызови route_start, затем smart_wait до конечного состояния; ненужный "
        "запуск отмени через smart_cancel. Модель, уровень рассуждения, права и "
        "фактический дочерний процесс выбирает и проверяет контроллер. Не передавай "
        "инструментам пути, команды, переменные окружения или сведения доступа."
    )
    return hook_context("UserPromptSubmit", text)


def _bind_resume_instruction_v2(
    config: IntegrationConfigV2,
    record: Any,
    environ: Mapping[str, str],
) -> str | None:
    store = RootSessionLeaseStoreV2(
        config.state_home,
        process_marker_reader=system_process_marker_reader_v2,
    )
    turn_store = TurnContextStoreV2(config)
    current = store.load(record.session_id)
    if current is None:
        turn_store.save(record)
        return None
    root = RootIdentityV2(
        pid=int(environ.get("CODEX_SMART_ROOT_PID", "")),
        process_start_marker=environ.get("CODEX_SMART_ROOT_START_MARKER", ""),
    )
    project = ProjectIdentityV2(
        repo_root=record.repo_root,
        base_sha=record.base_sha,
        worktree_fingerprint=record.worktree_fingerprint,
        compatibility_fingerprint=current.project.compatibility_fingerprint,
    )
    attachment = current.attachment
    if attachment is not None and attachment.state == "CLAIMING":
        previous_record = None
        try:
            previous_record = turn_store.load()
        except IntegrationV2Error as exc:
            if "LOCK_TIMEOUT" in str(exc):
                raise
        except (FileNotFoundError, OSError, ValueError):
            pass
        if (
            previous_record is not None
            and previous_record.session_id == record.session_id
            and previous_record.turn_id == attachment.bound_turn_id
            and previous_record.resume_claim_nonce == attachment.claim_nonce
        ):
            store.finalize_resume_claim(
                session_id=record.session_id,
                shell_session_id=record.shell_session_id,
                turn_id=previous_record.turn_id,
                root=root,
                project=current.project,
                claim_nonce=attachment.claim_nonce,
                context_claim_nonce=previous_record.resume_claim_nonce,
            )
    try:
        claim = store.begin_resume_claim(
            session_id=record.session_id,
            shell_session_id=record.shell_session_id,
            turn_id=record.turn_id,
            root=root,
            project=project,
        )
    except ResumeSessionV2Error as exc:
        # Чужой живой владелец или недоказанная старая аренда не должны
        # блокировать свежий умный ход текущего корня.
        if exc.code != "RESUME_ATTACHMENT_CHANGED":
            raise
        turn_store.save(record)
        return None
    if claim.claim_nonce is None:
        turn_store.save(record)
        return None
    claimed_record = replace(record, resume_claim_nonce=claim.claim_nonce)
    turn_store.save(claimed_record)
    lease = store.finalize_resume_claim(
        session_id=record.session_id,
        shell_session_id=record.shell_session_id,
        turn_id=record.turn_id,
        root=root,
        project=project,
        claim_nonce=claim.claim_nonce,
        context_claim_nonce=claimed_record.resume_claim_nonce,
    )
    attachment = lease.attachment
    if attachment is None or attachment.state in {"ACKNOWLEDGED", "DETACHED"}:
        return None
    candidate = attachment.candidate
    if candidate.start_request_id is None:
        continuation = (
            "Сначала вызови route_start для routeId="
            f"{candidate.route_id} и nodeId={candidate.node_id}, затем smart_wait "
            "до конечного состояния."
        )
    else:
        continuation = (
            "Сначала вызови smart_wait для startRequestId="
            f"{candidate.start_request_id} до конечного состояния."
        )
    return (
        "Возобновлён умный маршрут предыдущего хода. "
        + continuation
        + " До его конечного состояния smart_plan запрещён. После получения "
        "и проверки старого результата вызови smart_plan ровно один раз для нового "
        "запроса пользователя; модель и уровень рассуждений выберет контроллер."
    )


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
                    "Событие умного делегирования завершилось ошибкой; "
                    "запрос продолжается в обычном режиме Codex."
                ),
            },
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
