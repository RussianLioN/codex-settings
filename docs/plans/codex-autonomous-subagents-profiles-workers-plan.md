# План организации автономной работы Codex со сложными проектами

## Summary

- Не менять глобальный `~/.codex/config.toml` на высокий fan-out. Оставить high-concurrency только в явных профилях.
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
  - `agents.max_threads = 2`
  - `agents.max_depth = 1`

- `standard.config.toml`: ежедневная инженерная работа.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "high"`
  - `sandbox_mode = "workspace-write"`
  - `approval_policy = "on-request"`
  - `agents.max_threads = 4`
  - `agents.max_depth = 1`

- `deep-review.config.toml`: глубокие code, design и security reviews.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "xhigh"`
  - `sandbox_mode = "read-only"`
  - `approval_policy = "on-request"`
  - `agents.max_threads = 4`
  - `agents.max_depth = 1`

- `safe-readonly.config.toml`: строгий read-only режим для исследования без side effects.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "high"`
  - `sandbox_mode = "read-only"`
  - `approval_policy = "never"`
  - `agents.max_threads = 2`
  - `agents.max_depth = 1`

- `wide-readers.config.toml`: controlled parallel read/review waves.
  - `model = "gpt-5.4-mini"`
  - `model_reasoning_effort = "medium"`
  - `sandbox_mode = "read-only"`
  - `approval_policy = "never"`
  - `agents.max_threads = 8`
  - `agents.max_depth = 1`
  - `agents.job_max_runtime_seconds = 1800`

- `wide-readers-16.config.toml`: canary-only профиль для 16 read-only subagents.
  - те же настройки, что `wide-readers`
  - `agents.max_threads = 16`
  - использовать только после успешных прогонов 8 и 12 без stale threads, rate-limit storms и resource pressure.

- `batch-workers.config.toml`: headless workers через `codex exec`.
  - `model = "gpt-5.4-mini"`
  - `model_reasoning_effort = "medium"`
  - `sandbox_mode = "workspace-write"`
  - `approval_policy = "never"`
  - `agents.max_threads = 1`
  - `agents.max_depth = 1`
  - `agents.job_max_runtime_seconds = 1800`

- `full-access.config.toml`: аварийный ручной режим, не для subagent fan-out.
  - `model = "gpt-5.5"`
  - `model_reasoning_effort = "xhigh"`
  - `sandbox_mode = "danger-full-access"`
  - `approval_policy = "never"`
  - `agents.max_threads = 4`
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
- Для read-heavy waves использовать `wide-readers`; начинать с 8, затем 12, затем 16 только после canary.
- После каждой wave: wait for all, summarize, close completed agents, проверить `/agent`, `/status`, `/usage`.
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
- Hooks добавить fail-closed для `PreToolUse`, `PermissionRequest`, `PostToolUse`, `SubagentStart`, `SubagentStop`, `Stop`.
- Hooks должны блокировать или логировать: writes вне worktree, `.git`, `~/.codex`, `~/.ssh`, secrets, `git push`, `gh pr merge`, destructive shell, `curl | sh`, `sudo`, `ssh/scp/rsync`, side-effect MCP/app tools.

## Rollout

1. Inventory: проверить `CODEX_HOME`, текущий config, `/etc/codex/requirements.toml`, enabled plugins/MCP, доступные hooks, disk/RAM/FD limits.
2. Создать config backup.
3. Добавить профили без изменения base config.
4. Добавить custom agents.
5. Прогнать TOML parse и `codex --profile <name> --strict-config --version`.
6. Прогнать `codex debug prompt-input -c agents.max_threads=16 -c agents.max_depth=1 "smoke"`.
7. Прогнать negative tests для read-only agents.
8. Canary: 6 -> 8 -> 12 -> 16 read-only agents; остановиться при stale threads, limit errors, rate-limit pressure, orphan processes.
9. Включить aliases только после smoke:
   - `codexs='codex --profile standard'`
   - `codexro='codex --profile safe-readonly'`
   - `codexwide='codex --profile wide-readers'`
   - `codexfa='codex --profile full-access'`
10. Для batch workflow сначала запустить один disposable repo, затем один реальный trusted repo, затем параллель 2/4/8 workers.

## Acceptance Criteria

- Unlimited не используется; `0`, `-1`, `"unlimited"` не допускаются.
- Все профили явно задают `sandbox_mode`, `approval_policy`, `agents.max_threads`, `agents.max_depth`.
- `max_depth = 1` везде.
- `wide-readers-16` используется только для read-only canary.
- Completed agents явно закрываются после каждой wave.
- Write tasks не редактируют primary checkout параллельно.
- Batch workers работают только через isolated worktrees и artifacts.
- Supervisor, а не worker, публикует результат.
- Hooks блокируют опасные команды и пишут audit log.
- Rollback возвращает `max_threads <= 6`, отключает high-concurrency profile usage и закрывает active agents/worktrees.

## Rollback

- Вернуть запуск на `standard` или `safe-readonly`.
- Остановить активные subagent waves.
- Закрыть completed/stale agents; при необходимости начать новую session.
- Отключить aliases на `wide-readers-16`.
- Восстановить config backup.
- Удалить только проверенные task-owned worktrees после artifact collection.
- Проверить новый session через `/status`, `/usage`, `/agent`.
