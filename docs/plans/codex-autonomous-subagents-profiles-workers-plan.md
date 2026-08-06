# План организации автономной работы Codex со сложными проектами

## Summary

- Считать глобальный `agents.max_concurrent_threads_per_session = 20` только потолком открытых agent threads, а не безопасным размером одной волны; `agents.max_threads` является legacy-ключом.
- Использовать default wave size `6`; повышать его только после FD preflight и отдельного canary.
- Использовать интерактивные subagents для read-heavy exploration, review, triage и параллельного анализа.
- Использовать `codex exec --json` плюс внешнюю очередь и worktree-per-task для настоящей автономной batch-работы.
- Использовать custom agents для ролей, profiles для режимов доступа, модели и concurrency, skills для повторяемых workflows, plugins для распространения skills, MCP и hooks.
- Держать `agents.max_depth = 1` во всех профилях. Recursive delegation запрещен по умолчанию.

## Профили Codex

Создать отдельные файлы `~/.codex/<profile>.config.toml`; не использовать legacy `[profiles.*]`.

- `small.config.toml`: легкие локальные задачи.
  - `model = "gpt-5.4-mini"`
  - `model_reasoning_effort = "medium"`
  - `sandbox_mode = "workspace-write"`
  - `approval_policy = "on-request"`
  - `agents.max_concurrent_threads_per_session = 2`
  - `agents.max_depth = 1`

- `standard.config.toml`: ежедневная инженерная работа.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "high"`
  - `sandbox_mode = "workspace-write"`
  - `approval_policy = "on-request"`
  - `agents.max_concurrent_threads_per_session = 4`
  - `agents.max_depth = 1`

- `deep-review.config.toml`: глубокие code, design и security reviews.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "xhigh"`
  - `sandbox_mode = "read-only"`
  - `approval_policy = "on-request"`
  - `agents.max_concurrent_threads_per_session = 4`
  - `agents.max_depth = 1`

- `safe-readonly.config.toml`: строгий read-only режим для исследования без side effects.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "high"`
  - `sandbox_mode = "read-only"`
  - `approval_policy = "never"`
  - `agents.max_concurrent_threads_per_session = 2`
  - `agents.max_depth = 1`

- `wide-readers.config.toml`: controlled parallel read/review waves.
  - `model = "gpt-5.4-mini"`
  - `model_reasoning_effort = "medium"`
  - `sandbox_mode = "read-only"`
  - `approval_policy = "never"`
  - `agents.max_concurrent_threads_per_session = 8`
  - `agents.max_depth = 1`
  - `agents.job_max_runtime_seconds = 1800`

- `wide-readers-16.config.toml`: canary-only профиль для 16 read-only subagents.
  - те же настройки, что `wide-readers`
  - `agents.max_concurrent_threads_per_session = 16`
  - использовать только после успешных прогонов 8 и 12 без stale threads, rate-limit storms и resource pressure.

- `batch-workers.config.toml`: headless workers через `codex exec`.
  - `model = "gpt-5.4-mini"`
  - `model_reasoning_effort = "medium"`
  - `sandbox_mode = "workspace-write"`
  - `approval_policy = "never"`
  - `agents.max_concurrent_threads_per_session = 1`
  - `agents.max_depth = 1`
  - `agents.job_max_runtime_seconds = 1800`

- `full-access.config.toml`: аварийный ручной режим, не для subagent fan-out.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "xhigh"`
  - `sandbox_mode = "danger-full-access"`
  - `approval_policy = "never"`
  - `agents.max_concurrent_threads_per_session = 4`
  - `agents.max_depth = 1`

## Custom Agents

Создать `~/.codex/agents/` с узкими ролями. Каждый файл должен задавать `name`, `description`, `developer_instructions`; при необходимости также `model`, `model_reasoning_effort`, `sandbox_mode`, `nickname_candidates`.

- `repo-reader`: read-only explorer, возвращает только paths, evidence, risks, uncertainty.
- `docs-reader`: читает `AGENTS.md`, README, plans, architecture docs, validator docs; не делает выводов без ссылок на источники.
- `reviewer`: correctness, regressions, missing tests, maintainability; read-only, `gpt-5.5`, high/xhigh.
- `risk-auditor`: secrets, destructive commands, generated-file ownership, policy violations.
- `test-runner`: запускает проверки и объясняет failures; не чинит без явного назначения.
- `implementation-worker`: scoped writer для одного bounded task и disjoint write set.
- `batch-worker`: worker для внешней очереди; один task, один worktree, один artifact set.

Каждый writer prompt должен включать:
`mission`, `owned write scope`, `allowed read scope`, `do not touch`, `validation commands`, `done criteria`, `expected artifact`, `stop condition`.

## Интерактивный Workflow

- Main thread всегда остается coordinator: intent, план, решения, интеграция, финальный judgement.
- Subagents используются волнами:
  - wave 1: repo/docs readers;
  - wave 2: focused reviewers/test runners;
  - wave 3: один или несколько writers только при disjoint write scopes;
  - wave 4: independent reviewers.
- Для read-heavy waves использовать `wide-readers`, но запускать не более 6 live agents одновременно; canary ladder `8 -> 12 -> 16` разрешен только при soft limit не ниже `4096` и успешном FD preflight.
- Перед каждой wave закрыть completed/stale agents и запустить `$HOME/.local/bin/codex-highfd --fd-doctor --wave-size N`; agent shells не должны зависеть от interactive aliases.
- После каждой wave: wait for all, collect results, немедленно вызвать `close_agent` для каждого завершенного thread, затем summarize и проверить `/agent`, `/status`, `/usage`.
- Обычное ожидание выполнять через `wait_agent` с `timeout_ms = 60000`; вызов возвращается раньше при сообщении или завершении (`wait_agent returns early on message or completion`).
- Перед каждым ожиданием координатор выполняет доступную полезную работу: интеграцию уже полученных результатов, чтение доказательств или безопасную проверку состояния (`useful work before waiting`).
- Пустым считается ожидание, завершившееся без сообщения или завершения агента. После двух последовательных пустых ожиданий один раз вызвать `list_agents` (`two empty waits -> list_agents once`).
- После третьего последовательного пустого ожидания проверить реальный прогресс по доступным журналам, процессам и состоянию Git (`third empty wait -> real progress check`).
- При сообщении или завершении агента сбросить счётчик пустых ожиданий (`reset empty-wait counter on message or completion`).
- Не вызывать `interrupt_agent` только из-за истечения срока ожидания (`no interrupt_agent on timeout alone`).
- Для длительной задачи требовать этапный отчёт либо отчёт каждые 2–3 минуты (`progress checkpoint every 2-3 minutes`).
- Эта политика ожидания не требует изменения `agents.job_max_runtime_seconds`, `agents.max_concurrent_threads_per_session` или `agents.max_depth`; `agents.max_threads` не используется в новых профилях.
- При `Too many open files` / `EMFILE` прекратить новые spawn, собрать доступные ответы, закрыть открытые threads и отметить пропуски как environment limitation, а не как предметное доказательство.
- При `agent thread limit reached` уменьшить live batch до фактической capacity и продолжить только оставшиеся assignments после освобождения завершенных threads.
- Если terminal `codex exec` не предоставляет `close_agent`, разрешена только одна terminal operation; выход процесса после synthesis является session-exit cleanup.
- Не делегировать tiny tasks, serial tasks, unclear product decisions, merge/release decisions.
- Не поднимать `max_depth` выше 1.

## Автономный Batch Workflow

- Для production-like автономии не использовать интерактивный TUI как scheduler.
- Построить внешний control plane:
  - immutable task spec: repo, base SHA, goal, constraints, validation profile, risk level, output schema;
  - durable queue: SQLite/Postgres/Redis/SQS;
  - lease manager: `queued -> leased -> succeeded/failed/retryable`;
  - workspace manager: один clean git worktree на task attempt;
  - runner: `codex exec --profile batch-workers --json --cd "$WORKTREE" -o "$ARTIFACT/result.md" "$PROMPT"`;
  - artifact collector: `events.jsonl`, `stderr`, final result, `git diff --binary`, status, validator logs, usage;
  - supervisor: запускает tests/build/lint/security/diff policy и только потом публикует patch/PR.
- Workers не пушат, не мержат, не открывают PR напрямую. Publish job отделен и требует human или explicit supervisor gate.
- Retries запускать в новом clean worktree; `codex exec resume` использовать только для продолжения того же attempt.

## Worktrees

- Read-only subagents могут работать в primary checkout.
- Write-heavy задачи выполнять в отдельных Git worktrees или Codex App worktrees.
- Один worktree = один task/branch/attempt.
- Не checkout одну branch в двух worktrees.
- Для Codex App managed worktrees добавить `.worktreeinclude` только для реально нужных ignored setup files.
- Permanent worktrees использовать для долгоживущих направлений работы, disposable worktrees для batch attempts.
- Cleanup должен проверять exact absolute path, owner label/task id, collected artifacts и git status перед удалением.

## Skills, Plugins, MCP, Hooks

- Создать repo/user skills для повторяемых процедур:
  - `project-intake`
  - `parallel-review-wave`
  - `batch-task-authoring`
  - `worktree-worker-handoff`
  - `quality-gate`
  - `safe-cleanup`
- Skills держать focused; scripts добавлять только для deterministic checks.
- Plugins использовать только когда workflow нужно распространять между проектами или вместе с MCP/hooks.
- Установить и использовать Codex Security plugin для security scans, но не заменять им diff-focused review и acceptance tests.
- MCP включать минимально; heavy/write-capable tools не наследовать в массовые read-only agents.
- `node_repl` и bundled browser runtime должны ссылаться на один установленный desktop bundle. Для текущего macOS runtime это `/Applications/ChatGPT.app/Contents/Resources`; version и trusted browser-client SHA должны соответствовать установленному browser plugin.
- Обычный интерактивный `codex` запускается через `~/.local/bin/codex-highfd`, который поднимает inherited soft FD limit до `4096` без изменения системного `launchctl` limit.
- `scripts/codex_fd_doctor.sh` является обязательным preflight для subagent waves; `WARN` допускает только default wave size 6, `BLOCK` запрещает новые spawn.
- Hooks добавить fail-closed для `PreToolUse`, `PermissionRequest`, `PostToolUse`, `SubagentStart`, `SubagentStop`, `Stop`, `SessionEnd`.
- `SubagentStart` должен принимать фактические поля `agent_type`/`agentType` и разрешать только роли из утверждённого набора.
- Hooks должны блокировать или логировать: writes вне worktree, `.git`, `~/.codex`, `~/.ssh`, secrets, destructive shell, `curl | sh`, `sudo`, `ssh/scp/rsync`, side-effect MCP/app tools. `git push` блокируется для автономных агентов, но разрешён supervisor только при явном запросе на публикацию; `gh pr merge` остаётся заблокированным для всех сессий.

## Rollout

1. Inventory: проверить `CODEX_HOME`, текущий config, `/etc/codex/requirements.toml`, enabled plugins/MCP, доступные hooks, disk/RAM/FD limits.
2. Создать config backup.
3. Добавить профили без изменения base config.
4. Добавить custom agents.
5. Прогнать TOML parse и `codex --profile <name> --strict-config --version`.
6. Прогнать `codex debug prompt-input -c agents.max_concurrent_threads_per_session=16 -c agents.max_depth=1 "smoke"`.
7. Прогнать negative tests для read-only agents.
8. Canary: сначала 6 read-only agents; затем отдельно 8 -> 12 -> 16 только при `status=OK`. Остановиться при stale threads, limit errors, rate-limit pressure или orphan processes.
9. Включить aliases только после smoke:
   - `codexs='codex --profile standard'`
   - `codexro='codex --profile safe-readonly'`
   - `codexwide='codex --profile wide-readers'`
   - `codexfa='codex --profile full-access'`
10. Для batch workflow сначала запустить один disposable repo, затем один реальный trusted repo, затем параллель 2/4/8 workers.

## Acceptance Criteria

- Unlimited не используется; `0`, `-1`, `"unlimited"` не допускаются.
- Base config допускает `agents.max_concurrent_threads_per_session <= 20`, но default live wave всегда равен 6; `agents.max_threads` считается legacy и не допускается.
- Все профили явно задают `sandbox_mode`, `approval_policy`, `agents.max_concurrent_threads_per_session`, `agents.max_depth`.
- `max_depth = 1` везде.
- `wide-readers-16` используется только для read-only canary.
- Completed agents явно закрываются после каждой wave.
- `node_repl` проходит MCP initialize/tools smoke, а `codex doctor` не сообщает unresolvable MCP command.
- `codex-highfd --self-test` показывает soft limit `4096`; FD doctor блокирует wide wave при soft limit `256`.
- Write tasks не редактируют primary checkout параллельно.
- Batch workers работают только через isolated worktrees и artifacts.
- Supervisor, а не worker, публикует результат.
- Hooks блокируют опасные команды и пишут audit log.
- Rollback отключает high-concurrency profile usage, возвращает runtime config/skills/aliases из timestamped backup и закрывает active agents/worktrees. Значение `agents.max_concurrent_threads_per_session` не меняется без отдельного решения; `agents.max_threads` остаётся только legacy-термином для разбора старых конфигураций.

## Rollback

- Вернуть запуск на `standard` или `safe-readonly`.
- Остановить активные subagent waves.
- Закрыть completed/stale agents; при необходимости начать новую session.
- Отключить aliases на `wide-readers-16`.
- Восстановить config, plugin cache, aliases и runtime skills из одного timestamped backup set.
- Удалить только проверенные task-owned worktrees после artifact collection.
- Проверить новый session через `/status`, `/usage`, `/agent`.
