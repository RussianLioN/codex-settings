# Отчёт по Task 1: доступный запуск и самовосстанавливающийся каталог

## Статус

DONE

Обычные интерактивные `codex` и `codex resume` больше не завершаются кодом
69 из-за недоступности умной подсистемы и не требуют ручного
`codex-native`. Внутренний параметр `managed_required=True` сохранён для
служебных административных вызовов, но пользовательская обёртка его больше
не выводит из `CODEX_SMART_REQUIRED`.

## RED

Первый пакет проверок был запущен до производственных изменений:

```text
uv run --locked python -m unittest tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_automatic_unavailable_pair_starts_managed_root_without_defaults tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_unsupported_resume_executes_real_codex_with_original_arguments tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_managed_invocation_without_resolver_executes_real_codex tests.smart_subagents.test_coordinator_selection_v2 tests.smart_subagents.test_controller_health_v2.ControllerHealthServerV2Tests.test_catalog_recovery_atomically_replaces_health_selection tests.smart_subagents.test_autonomous_workflow.AutonomousWorkflowEntrypointContractTests.test_exact_managed_entrypoint_contract_is_healthy -v
```

Результат: `FAILED (failures=4, errors=2)`. Подтверждены старые
`COORDINATOR_PAIR_UNAVAILABLE`, `MANAGED_RESUME_UNSUPPORTED`,
`MANAGED_RESOLVER_UNAVAILABLE`, старый псевдоним с
`CODEX_SMART_REQUIRED=1`, отсутствие фонового цикла и отсутствие атомарной
публикации выбора в health.

Дополнительные отдельные RED-проверки:

```text
uv run --locked python -m unittest tests.smart_subagents.test_health_bootstrap_v2.HealthBootstrapV2Tests.test_temporary_catalog_failure_recovers_in_one_joined_background_loop -v
# FAIL: recovered.wait(1.0) == False

uv run --locked python -m unittest tests.smart_subagents.test_wrapper_supervisor_v2.WrapperSupervisorV2Tests.test_cleanup_prohibition_warns_and_continues_verified_snapshot -v
# FAIL: получен 69 вместо продолжения на проверенном снимке

uv run --locked python -m unittest tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_interactive_resolver_failure_executes_verified_real_codex -v
# FAIL: наружу вышел FALLBACK_UNAVAILABLE вместо exec настоящего Codex

uv run --locked python -m unittest tests.smart_subagents.test_health_bootstrap_v2.HealthBootstrapV2Tests.test_initial_controller_collects_coordinator_selection_once tests.smart_subagents.test_health_bootstrap_v2.HealthBootstrapV2Tests.test_temporary_catalog_failure_recovers_in_one_joined_background_loop -v
# FAIL: начальный срок был 5.0 вместо 1.0 секунды
```

## Реализация

- Стандартный псевдоним теперь задаёт только `CODEX_SMART_ENABLED=1`.
- Пользовательская обёртка игнорирует устаревший строгий маркер и не содержит
  пути `return 69`.
- Ошибка подготовки, отсутствие разрешателя, ошибка разрешателя и
  неподдержанный умный вариант `resume` выполняют проверенный настоящий Codex
  с исходными аргументами и очищенным умным окружением.
- Недоступный выбор координатора сохраняет управляемый ограниченный корень,
  но не добавляет `--model` и `model_reasoning_effort`.
- Начальная проверка каталога ограничена одной секундой.
- Один процессный фоновый цикл делает немедленную повторную проверку со
  сроком 20 секунд, затем использует интервалы 5, 30, 120 и не более 300
  секунд; после успеха проверяет каталог раз в 300 секунд.
- Повторно доказанный выбор атомарно заменяется в живом health под отдельной
  блокировкой, без изменения закрытой схемы и без перезапуска процесса.
- Закрытие владельца сначала останавливает и присоединяет фоновый цикл, затем
  закрывает health; максимальное ожидание присоединения больше срока одной
  проверки каталога.
- Согласователь псевдонимов получил новую точную версию и сохранил предыдущую
  пару в явном реестре управляемых версий.

## GREEN

```text
uv run --locked python -m unittest tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_automatic_unavailable_pair_starts_managed_root_without_defaults tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_unsupported_resume_executes_real_codex_with_original_arguments tests.smart_subagents.test_activation_gateway_v2.PermanentGatewayExecutionTests.test_managed_invocation_without_resolver_executes_real_codex tests.smart_subagents.test_coordinator_selection_v2 tests.smart_subagents.test_controller_health_v2.ControllerHealthServerV2Tests.test_catalog_recovery_atomically_replaces_health_selection tests.smart_subagents.test_health_bootstrap_v2.HealthBootstrapV2Tests.test_temporary_catalog_failure_recovers_in_one_joined_background_loop tests.smart_subagents.test_autonomous_workflow.AutonomousWorkflowEntrypointContractTests.test_exact_managed_entrypoint_contract_is_healthy -v
# Ran 19 tests: OK

uv run --locked python -m unittest tests.smart_subagents.test_wrapper_supervisor_v2 -v
# Ran 15 tests: OK

uv run --locked python -m unittest tests.smart_subagents.test_install_adaptive_subagents -v
# Ran 57 tests: OK

uv run --locked python -m unittest tests.smart_subagents.test_activation_gateway_v2 tests.smart_subagents.test_wrapper_supervisor_v2 tests.smart_subagents.test_coordinator_selection_v2 tests.smart_subagents.test_controller_health_v2 tests.smart_subagents.test_health_bootstrap_v2 tests.smart_subagents.test_controller_application_v2 tests.smart_subagents.test_controller_entrypoint_v2 tests.smart_subagents.test_candidate_controller_v2 tests.smart_subagents.test_autonomous_workflow tests.smart_subagents.test_codex_entrypoint_reconciler tests.smart_subagents.test_installer_entrypoint_v2 -v
# Ran 270 tests: OK

uv run --locked python -m py_compile plugins/codex-smart-subagents/src/codex_smart_subagents/activation_gateway_v2.py plugins/codex-smart-subagents/src/codex_smart_subagents/coordinator_selection_v2.py plugins/codex-smart-subagents/src/codex_smart_subagents/controller_health_v2.py plugins/codex-smart-subagents/src/codex_smart_subagents/health_bootstrap_v2.py plugins/codex-smart-subagents/bin/codex-smart scripts/reconcile_codex_entrypoint.py scripts/validate_autonomous_workflow.py
# exit 0

git diff --check
# exit 0
```

## Изменённые файлы

Производственный код:

- `plugins/codex-smart-subagents/bin/codex-smart`
- `plugins/codex-smart-subagents/src/codex_smart_subagents/activation_gateway_v2.py`
- `plugins/codex-smart-subagents/src/codex_smart_subagents/controller_health_v2.py`
- `plugins/codex-smart-subagents/src/codex_smart_subagents/coordinator_selection_v2.py`
- `plugins/codex-smart-subagents/src/codex_smart_subagents/health_bootstrap_v2.py`
- `scripts/reconcile_codex_entrypoint.py`
- `scripts/validate_autonomous_workflow.py`

Проверки:

- `tests/smart_subagents/test_activation_gateway_v2.py`
- `tests/smart_subagents/test_autonomous_workflow.py`
- `tests/smart_subagents/test_codex_entrypoint_reconciler.py`
- `tests/smart_subagents/test_controller_health_v2.py`
- `tests/smart_subagents/test_coordinator_selection_v2.py`
- `tests/smart_subagents/test_health_bootstrap_v2.py`
- `tests/smart_subagents/test_wrapper_supervisor_v2.py`

`resume_session_v2.py` и обработчики возобновления не изменялись.
Старый `.superpowers/sdd/task-1-report.md` не изменялся.

## Коммит

- `743d717` — `fix(runtime): keep interactive Codex fail-open`

## Сомнения и границы проверки

- Полный проектный набор из примерно двух тысяч проверок не запускался в
  этой подзадаче; выполнены все непосредственно затронутые и соседние наборы
  (270 + отдельные 57 проверок установщика). Полный прогон относится к общей
  приёмке ветки.
- Живая глобальная установка и десять ручных циклов `codex`/`codex resume`
  здесь не выполнялись; это отдельная общая приёмка и публикация.
- Документация всё ещё может описывать старый строгий отказ; её обновление
  выделено в следующую документационную задачу плана.
