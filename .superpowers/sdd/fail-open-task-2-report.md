# Отчёт Task 2: согласование возобновления без остановки

Дата: 2026-08-06
База: `fe236000238bbbe3586fdfb783075391ab2bada2`

## Результат

Аренда корневого сеанса переведена на схему 3. Ошибки Git, SQLite,
блокировки, активации, контроллера и аренды больше не останавливают основной
запрос. Старый маршрут доступен только после доказанной двухфазной привязки;
во всех недоказанных случаях текущий запрос продолжает обычный либо свежий
умный ход без доступа к старому маршруту.

## RED-доказательства

Проверки были добавлены и запущены до реализации в коммите `6d8d82e`.

1. `python -m unittest tests.smart_subagents.test_resume_session_v2`
   завершился с кодом 1: отсутствовал `ResumeClaimV2`.
2. Проверки `SessionStart` завершились двумя ожидаемыми падениями:
   `test_session_start_failures_never_stop_the_root_request` и
   `test_live_owner_resume_is_fail_open_without_replacing_owner` получили
   `continue: false`.
3. Проверки `UserPromptSubmit` завершились двумя ожидаемыми падениями:
   `test_resume_user_prompt_classifies_runtime_errors_without_exception_details`
   и `test_second_resumed_prompt_without_attachment_is_a_fresh_smart_turn`
   получили остановку вместо продолжения.
4. После ревью добавлен отдельный RED-коммит `b5d7ea3`: при совместимости
   аренды A и доказанной живой совместимости B обработчик ошибочно выдавал
   старый `smart_wait` и оставлял присоединение `BOUND`. Точный случай A=A
   в том же прогоне оставался успешным.

## Реализация

- Схема аренды 3 отдельно хранит стабильную личность
  (`repoRoot`, `compatibilityFingerprint`) и снимок хода (`baseSha`,
  `worktreeFingerprint`).
- Состояния `CLAIMING` и `DETACHED` дополнили существующий автомат состояний.
- `begin_resume_claim` атомарно выдаёт `claimNonce`, контекст хода сохраняет
  тот же nonce, `finalize_resume_claim` идемпотентно публикует `BOUND`.
- Незавершённый claim после записанного контекста восстанавливается; claim без
  доказанного контекста при следующем ходе безопасно отсоединяется.
- Новый запрос является последовательной границей: точный `BOUND` того же
  живого корня перепривязывается без зависимости от `Stop`.
- `CODEX_SMART_LAUNCH_KIND=resume` читается только в `SessionStart`.
- `UserPromptSubmit` получает `compatibilityFingerprint` из полного
  доказательства живой закреплённой привязки контроллера в пределах единого
  абсолютного срока события. Значение из самой аренды больше не используется
  как доказательство текущей совместимости.
- Если живую совместимость доказать нельзя, обработчик возвращает
  `continue: true` без `stopReason`, контекста умных инструментов и инструкции
  `smart_plan`.
- `DETACHED` изменяет только документ аренды. Код согласования не отменяет
  маршрут, не завершает дочерний процесс и не пишет состояние маршрута в
  SQLite; чтение маршрутов открывает базу в режиме `mode=ro`.
- Валидная аренда версии 2 при полном совпадении лениво переписывается в
  версию 3. Несовпадение либо повреждение создаёт безопасную аренду версии 3
  с `DETACHED` и без старого доступа.

## GREEN-доказательства

После коммитов реализации `bfcee3f` и `8aeec9c` выполнены:

```text
python -m unittest tests.smart_subagents.test_resume_session_v2 tests.smart_subagents.test_integration_runtime_v2 tests.smart_subagents.test_plugin_integration tests.smart_subagents.test_production_runtime_v2 tests.smart_subagents.test_smart_service_v2

Ran 112 tests in 8.395s
OK
```

Дополнительно успешно выполнены:

- `python -m py_compile` для всех изменённых производственных модулей,
  обработчиков и непосредственно затронутых проверок;
- `git diff --check`;
- поиск подтвердил отсутствие `stopReason` и `continue: false` в
  `SessionStart`, `UserPromptSubmit` и `Stop`;
- поиск подтвердил, что `CODEX_SMART_LAUNCH_KIND` в затронутом пути читает
  только `SessionStart`.

Проверки охватывают второй запрос без attachment, изменение снимка,
несовпадение проекта и совместимости, прерывание при `BOUND`, обе стороны
незавершённого `CLAIMING`, занятую блокировку, медленный Git, чужого живого
владельца, повреждённую версию 2, исчерпание нитей, отказ доступа после
`DETACHED`, а также точные продолжения через `route_start` и `smart_wait`.
Дополнительная регрессия доказывает, что после обрыва между `CLAIMING` и
финализацией ручной `smart_plan` создаёт только свежий `routeId`, а
`resume_authorizer` продолжает запрещать доступ к старому маршруту.

## Изменённые файлы

- `plugins/codex-smart-subagents/src/codex_smart_subagents/resume_session_v2.py`
- `plugins/codex-smart-subagents/hooks/session_start.py`
- `plugins/codex-smart-subagents/hooks/user_prompt_submit.py`
- `plugins/codex-smart-subagents/hooks/stop.py`
- `plugins/codex-smart-subagents/src/codex_smart_subagents/production_runtime_v2.py`
- `plugins/codex-smart-subagents/scripts/integration_runtime_v2.py`
- `tests/smart_subagents/test_resume_session_v2.py`
- `tests/smart_subagents/test_integration_runtime_v2.py`
- `tests/smart_subagents/test_plugin_integration.py`
- `tests/smart_subagents/test_smart_service_v2.py`

## Коммиты

- `6d8d82e` — RED-проверки договора fail-open и аренды версии 3.
- `bfcee3f` — минимальная реализация и GREEN-проверки.
- `f07ddd6` — исходный отчёт Task 2.
- `b5d7ea3` — RED-проверка живой совместимости после ревью.
- `8aeec9c` — доказательство живой совместимости и регрессия незавершённого
  `CLAIMING`.
- Обновление отчёта фиксируется отдельным атомарным коммитом после повторной
  проверки.

## Остаточные риски

- В рамках Task 2 не выполнялась живая многоцикловая приёмка настоящего
  интерактивного Codex; она относится к Task 4 общего плана.
- Набор проверок выводит неблокирующее `ResourceWarning` о соединении SQLite
  из существующего `schema_projection.py`; все 112 проверок завершаются
  успешно. Предупреждение не связано с записью либо отменой маршрута.
- Пакетной миграции аренды версии 2 намеренно нет: миграция выполняется только
  при обращении к конкретному сеансу.
