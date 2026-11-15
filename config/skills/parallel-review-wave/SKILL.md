---
name: parallel-review-wave
description: Coordinate bounded Codex subagent review waves. Use when the user asks for parallel exploration, read-heavy review, triage, or independent reviewers and the work can be split into disjoint evidence-gathering tasks.
---

# Parallel Review Wave

Use this skill for interactive subagent waves.

Исторический план организации обычного ревью (текущий договор допуска приведён ниже):
`$HOME/coding/projects/codex-settings/docs/plans/codex-autonomous-subagents-profiles-workers-plan.md`

Обычное ревью: выбирай минимальный достаточный состав от 1 до 19.
`default wave size: 6` обозначает резервную границу, а не обязательный обычный состав.
Доверенный договор: `skill-id=parallel-review-wave`, `execution_kind=flat-trusted-wide-wave`,
`fallback=chunks<=6`, `max_live_wave=19`.

Полный консилиум на 19 ролей выполняй через установленный `consilium`.
Не заменяй его на `consilium-lean` из 7 ролей без явного выбора владельца.
Общий подбор команды и обычное ревью не уменьшают число ролей или размер волны
консилиума. Их определяет договор выбранного навыка и его предварительная
проверка: `OK/19/ALLOW` разрешает 19, `WARN` допускает волны только по договору
навыка с сохранением общего числа ролей, `BLOCK` останавливает запуск.
Неизвестный результат не является допуском. Сохраняй реальные ресурсные проверки,
доверенный пакет Consilium и его хэши.

Успешная проверка `--wave-size 6` подтверждает допуск запрошенной волны из шести;
она не устанавливает общий предел сессии и не проверяет волну из 19.
Не сообщай «среда разрешила только шесть» на основании такого вызова.
Перед полным консилиумом сначала выполни проверку на 19 по его договору.
Это относится и к повторному поручению 19 существующим ролевым потокам:
повторное использование не является основанием выбрать резервные волны.
Переходи к ним только после результата полной проверки, который этого требует.
Для нового каталога без Git укажи в манифесте `base_commit: null` и назначь
всех участников только на чтение с `owned_write_scope: []`. Валидатор проверяет
отсутствие Git в каталоге и его родителях. В проекте с Git укажи настоящий коммит;
не создавай фиктивный репозиторий и не подставляй чужой хэш ради допуска.

`agents.max_concurrent_threads_per_session = 19` относится к одной сессии,
без корневого агента. Другие вкладки не вычитаются. Свободную вместимость
определяет среда текущей сессии. Завершение потока не означает его закрытие
или освобождение места.

## Wait Cadence

- Do available coordinator work before waiting: integrate received results, read evidence, or run safe state checks (`useful work before waiting`).
- For an ordinary wait, call `wait_agent` with `timeout_ms = 60000`; it returns early on a mailbox message or completion (`wait_agent returns early on message or completion`).
- After two consecutive empty waits, call `list_agents` once (`two empty waits -> list_agents once`).
- After the third consecutive empty wait, inspect real progress through available logs, processes, and Git state (`third empty wait -> real progress check`).
- Reset the empty-wait counter on any agent message or completion (`reset empty-wait counter on message or completion`).
- Never call `interrupt_agent` only because a wait expired (`no interrupt_agent on timeout alone`).
- For long-running tasks, require milestone reports or a report every 2–3 minutes (`progress checkpoint every 2-3 minutes`).

## Workflow

1. Keep the main thread as coordinator for intent, decisions, integration, and final judgment.
2. Для полного консилиума сначала выполни проверку выбранного навыка на 19 с доверенными аргументами, включая повторное использование потоков. Перед обычной волной выполни обязательный FD preflight с её фактическим размером: `$HOME/.local/bin/codex-highfd --fd-doctor --wave-size N`; для 7–19 добавь `--skill-id parallel-review-wave --skill-file PATH --manifest PATH`.
   Применяй зарегистрированный глобальный `admission_backend`: на macOS Air/Pro `fd-doctor`, на Linux/Windows `native`.
   Ошибка обязательного doctor не разрешает переход на native. Применяй `close_agent` только при наличии этого инструмента и только к собственным потокам; без него не объявляй потоки закрытыми.
3. Для обычного ревью используй минимальный достаточный состав до 19 агентов в пределах фактического допуска сессии. Для полного консилиума следуй разрешённой волне его навыка. Для обычного ревью предпочитай читающие роли: `repo-reader`, `docs-reader`, `reviewer`, `risk-auditor`, or `test-runner`.
4. Give each subagent a bounded task, expected output shape, and explicit instruction to cite paths and uncertainty.
5. Wait for the wave, collect each available result, и закрой собственные завершённые потоки, если `close_agent` доступен; иначе сообщи, что закрытие недоступно.
6. Summarize findings by evidence, risk, and required next action; check `/agent`, `/status`, and `/usage` before another wave.
7. On `Too many open files`, `EMFILE`, or an unresolvable tool process, stop spawning, close all open threads, and report each missing read as an environment limitation rather than content evidence.
8. On `agent thread limit reached`, wait for completed work, close it when `close_agent` exists, and continue only the remaining assignments at the smaller observed capacity; report the capacity limit separately from expert evidence.
9. Для отдельного terminal `codex exec` завершение принадлежащего тебе процесса после его задания обеспечивает session-exit cleanup. Не завершай интерактивную сессию пользователя или другую вкладку. При отсутствии `close_agent` продолжение зависит от фактического допуска среды, а не предположения об освобождённых местах.

Do not delegate tiny tasks, unclear product decisions, merge/release decisions, or write-heavy tasks without disjoint write scopes.
