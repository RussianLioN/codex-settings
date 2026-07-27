# Smart Codex Entrypoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Сделать обычную интерактивную команду `codex` строгим входом в уже существующий управляемый контур адаптивных субагентов версии 2, сохранив `codex-native` как независимый нативный обход.

**Architecture:** Пользовательский псевдоним включает два локальных признака и вызывает `codex-highfd`; оболочка поднимает предел файловых дескрипторов и передаёт запуск в `codex-smart`. Общий классификатор отделяет служебные и явно нативные вызовы до подготовки контроллера. Отдельный узкий согласователь атомарно владеет только установленным `codex-highfd` и файлом псевдонимов; установщик расширения версии 2 не расширяет свою область ответственности.

**Tech Stack:** Python 3.11+, zsh, `unittest`, существующие SQLite/MCP/жизненный цикл версии 2, `uv`, `make`.

## Global Constraints

- Не создавать исполняемый файл `~/.local/bin/codex` и не менять `PATH`.
- Настоящий Codex передавать только абсолютным путём `/opt/homebrew/bin/codex`.
- `codex` включает `CODEX_SMART_ENABLED=1` и `CODEX_SMART_REQUIRED=1`.
- `codex-native` и существующие профильные псевдонимы явно используют `CODEX_SMART_ENABLED=0` и `CODEX_SMART_REQUIRED=0`.
- Строгий отказ действует только для поддержанного интерактивного управляемого запуска; служебные и явно нативные вызовы всегда передаются настоящему Codex без контроллера.
- `codex help` и `codex update` являются служебными подкомандами; `codex -- help` и `codex -- update` являются пользовательскими запросами.
- Явные корневые `--model`, `-m`, `-c model=...` и `-c model_reasoning_effort=...` сохраняются побайтно и не отключают управляемый выбор дочерних пар.
- Плагин сохраняет ровно четыре MCP-инструмента: `smart_plan`, `route_start`, `smart_wait`, `smart_cancel`.
- В обычной сессии `tools/list` остаётся пустым; управляемая сессия публикует точный аттестованный договор.
- `codex-smart` остаётся установленной диагностической командой.
- Не изменять исторический отчёт живой проверки от 2026-07-20.
- Все изменения поведения выполняются через TDD: новый тест должен сначала упасть по ожидаемой причине.

---

### Task 1: Ранняя классификация и строгий управляемый запуск

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/launcher.py`
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/activation_gateway_v2.py`
- Modify: `plugins/codex-smart-subagents/bin/codex-smart`
- Modify: `tests/smart_subagents/test_launcher.py`
- Modify: `tests/smart_subagents/test_wrapper_supervisor_v2.py`
- Modify: `tests/smart_subagents/test_activation_gateway_v2.py`

**Interfaces:**
- Produces: `classify_managed_invocation(arguments: Sequence[str]) -> InvocationDecision`.
- Produces: `ManagedLaunchUnavailable(code: str, message: str)`.
- Consumes: `CODEX_SMART_REQUIRED`, допускающий только `0` или `1`.
- Preserves: `run_permanent_gateway(..., managed_required=False)` for direct `codex-smart` diagnostics.

- [ ] **Step 1: Write failing classifier tests**

Add table cases proving:

```python
for argv in (["help"], ["update"], ["update", "--help"]):
    self.assertFalse(classify_managed_invocation(argv).adaptive)

for argv in (
    ["--model", "gpt-user"],
    ["-m", "gpt-user"],
    ["-c", 'model="gpt-user"'],
    ["-c", 'model_reasoning_effort="high"'],
):
    self.assertTrue(classify_managed_invocation(argv).adaptive)

self.assertTrue(classify_managed_invocation(["--", "help"]).adaptive)
self.assertTrue(classify_managed_invocation(["--", "update"]).adaptive)
```

- [ ] **Step 2: Verify the classifier tests are RED**

Run:

```bash
uv run --locked python -m unittest tests.smart_subagents.test_launcher -v
```

Expected: failures for missing `help`/`update` and missing `classify_managed_invocation`.

- [ ] **Step 3: Implement the shared managed classifier**

Keep the primitive argument parser in `launcher.py`, add `help` and `update` to the closed subcommand set, and move the existing coordinator-control normalization from `activation_gateway_v2.py` into `classify_managed_invocation`. The function may remove only model/reasoning controls from its temporary classification copy; it must never mutate the actual argument sequence.

- [ ] **Step 4: Verify classifier GREEN**

Run the same focused command and require all launcher tests to pass.

- [ ] **Step 5: Write failing early-bypass and strict-failure tests**

Add tests that:

```python
# help/update must not construct or call ControllerSupervisorV2
# managed interactive failure with CODEX_SMART_REQUIRED=1 returns 69
# the same failure without CODEX_SMART_REQUIRED preserves diagnostic fallback
# profile/arbitrary non-model config passes through byte-for-byte
# explicit root model/reasoning remains in the final managed argv exactly once
```

Use fake resolvers and `execve` recorders; never invoke the real Codex.

- [ ] **Step 6: Verify wrapper/gateway tests are RED**

Run:

```bash
uv run --locked python -m unittest \
  tests.smart_subagents.test_wrapper_supervisor_v2 \
  tests.smart_subagents.test_activation_gateway_v2 -v
```

Expected: service calls still prepare the controller and required managed failures still execute ordinary Codex.

- [ ] **Step 7: Implement early bypass and strict failure**

In `bin/codex-smart`:

1. classify raw arguments before `v2_gateway_state_present()` and `_prepare_v2_decision()`;
2. for a non-managed decision, resolve and execute the ordinary path without constructing the supervisor;
3. for a managed decision, prepare the controller;
4. when `CODEX_SMART_REQUIRED=1`, translate an ordinary gateway decision, supervisor failure, manifest failure, or policy-proof failure into `ManagedLaunchUnavailable`;
5. print one safe diagnostic with the stable reason and `codex-native`, then return exit code `69`.

In `run_permanent_gateway`, replace the local `_adaptive_invocation` with `classify_managed_invocation` and add the `managed_required` parameter. Clean `CODEX_SMART_REQUIRED` together with the existing smart environment before an intentional ordinary execution.

- [ ] **Step 8: Verify Task 1**

Run:

```bash
uv run --locked python -m unittest \
  tests.smart_subagents.test_launcher \
  tests.smart_subagents.test_wrapper_supervisor_v2 \
  tests.smart_subagents.test_activation_gateway_v2
```

Expected: all focused tests pass with no unexpected output.

- [ ] **Step 9: Commit Task 1**

```bash
git add \
  plugins/codex-smart-subagents/src/codex_smart_subagents/launcher.py \
  plugins/codex-smart-subagents/src/codex_smart_subagents/activation_gateway_v2.py \
  plugins/codex-smart-subagents/bin/codex-smart \
  tests/smart_subagents/test_launcher.py \
  tests/smart_subagents/test_wrapper_supervisor_v2.py \
  tests/smart_subagents/test_activation_gateway_v2.py
git commit -m "feat(subagents): make managed launch strict"
```

### Task 2: Идемпотентная точка входа и откат

**Files:**
- Modify: `scripts/codex-highfd`
- Create: `scripts/reconcile_codex_entrypoint.py`
- Create: `tests/smart_subagents/test_codex_entrypoint_reconciler.py`
- Modify: `scripts/validate_autonomous_workflow.py`
- Create: `tests/smart_subagents/test_autonomous_workflow.py`

**Interfaces:**
- Produces commands:
  - `python3 scripts/reconcile_codex_entrypoint.py --preview --json`
  - `python3 scripts/reconcile_codex_entrypoint.py --apply --json`
  - `python3 scripts/reconcile_codex_entrypoint.py --doctor --json`
  - `python3 scripts/reconcile_codex_entrypoint.py --rollback --json`
- Test-only path injection: `--home ABSOLUTE_PATH` and `--source-root ABSOLUTE_PATH`.
- Owns only:
  - `$HOME/.local/bin/codex-highfd`
  - `$HOME/.codex/codex-autonomous-aliases.zsh`
  - `$HOME/.codex/install-manifests/codex-entrypoint-v1.json`
  - `$HOME/.codex/install-manifests/codex-entrypoint-v1.journal.json`
  - `$HOME/.codex/install-manifests/codex-entrypoint-v1.lock`

- [ ] **Step 1: Write failing `codex-highfd` tests**

Cover:

```text
CODEX_SMART_ENABLED=1 + CODEX_SMART_REQUIRED=1 -> codex-smart
CODEX_SMART_ENABLED=0 + CODEX_SMART_REQUIRED=0 -> native Codex
required=1 + enabled=0 -> exit 2
values outside 0/1 -> exit 2
all arguments are preserved
--fd-doctor and --self-test never reach codex-smart
```

- [ ] **Step 2: Verify highfd RED, then implement minimal validation**

Add `smart_required=${CODEX_SMART_REQUIRED:-0}`, validate the pair, and export it only into the smart branch. Preserve the existing default `0`.

- [ ] **Step 3: Write failing reconciler tests**

Tests in a temporary home must prove:

1. preview performs no writes;
2. apply migrates the known legacy `codex-highfd` and current known alias file;
3. target aliases are exactly:

```zsh
alias codex='CODEX_SMART_ENABLED=1 CODEX_SMART_REQUIRED=1 $HOME/.local/bin/codex-highfd'
alias codex-native='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 $HOME/.local/bin/codex-highfd'
alias codexs='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 $HOME/.local/bin/codex-highfd --profile standard'
alias codexro='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 $HOME/.local/bin/codex-highfd --profile safe-readonly'
alias codexwide='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 $HOME/.local/bin/codex-highfd --profile wide-readers'
alias codexfa='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 $HOME/.local/bin/codex-highfd --profile full-access'
alias codexfd='CODEX_SMART_ENABLED=0 CODEX_SMART_REQUIRED=0 $HOME/.local/bin/codex-highfd --fd-doctor'
```

4. apply twice returns `applied`, then `unchanged`, without changing bytes;
5. foreign target contents return a conflict and remain byte-for-byte unchanged;
6. rollback restores exact previous bytes/modes or absence;
7. rollback twice returns `rolled_back`, then `unchanged`;
8. a journal left after the first replacement is recovered deterministically;
9. an existing `$HOME/.local/bin/codex` and the supplied `PATH` remain unchanged;
10. doctor reports `READY`, `DRIFT`, or `RECOVERY_REQUIRED` without writes.

`preview` and `doctor` must not create even a parent directory or lock file.

- [ ] **Step 4: Verify reconciler RED**

Run:

```bash
uv run --locked python -m unittest \
  tests.smart_subagents.test_codex_entrypoint_reconciler -v
```

Expected: import or behavior failures because the reconciler does not exist.

- [ ] **Step 5: Implement the narrow reconciler**

Use:

- `fcntl.flock` on a user-owned `0600` lock file;
- regular-file, owner, mode, link-count and size validation;
- same-directory temporary files, `fsync`, `os.replace`, and directory `fsync`;
- a journal written before the first replacement and updated after each phase;
- a receipt containing schema version, before projections, desired SHA-256 values and modes;
- exact known legacy recognition using the existing highfd fixture and the current seven-line alias form;
- conflict codes for unknown contents;
- sorted, compact JSON output without prompts.

The script must not import or mutate the version-2 installer lifecycle.

- [ ] **Step 6: Update the autonomous validator**

Require exact smart/native alias semantics, the current tracked highfd hash, and absence of a reconciler journal in a healthy state. Do not require deletion of an external `~/.local/bin/codex`; only prove the reconciler never owns or changes it.

- [ ] **Step 7: Verify Task 2**

Run:

```bash
uv run --locked python -m unittest \
  tests.smart_subagents.test_codex_entrypoint_reconciler \
  tests.smart_subagents.test_autonomous_workflow
uv run --locked python scripts/validate_autonomous_workflow.py
```

Expected: all focused tests and the validator pass.

- [ ] **Step 8: Commit Task 2**

```bash
git add \
  scripts/codex-highfd \
  scripts/reconcile_codex_entrypoint.py \
  scripts/validate_autonomous_workflow.py \
  tests/smart_subagents/test_codex_entrypoint_reconciler.py \
  tests/smart_subagents/test_autonomous_workflow.py
git commit -m "feat(subagents): reconcile the default Codex entrypoint"
```

### Task 3: Документация, установка и сквозная проверка

**Files:**
- Modify: `README.md`
- Modify: `plugins/codex-smart-subagents/README.md`
- Modify: `docs/runbooks/adaptive-subagents-v2-operations.md`
- Modify: `docs/analysis/adaptive-subagents-v2-flow.md`
- Modify: `docs/migrations/adaptive-subagents-v2.md`
- Modify: `docs/guides/autonomous-workflow.md`

**Interfaces:**
- Public entrypoint: `codex`.
- Native escape hatch: `codex-native`.
- Diagnostic entrypoint retained: `codex-smart`.

- [ ] **Step 1: Update operator documentation**

Document:

- exact `--preview`, `--apply`, `--doctor`, and `--rollback` commands;
- the chain `codex → codex-highfd → codex-smart → native Codex`;
- service-command early bypass;
- strict managed failure with `codex-native`;
- native status of the four profile aliases;
- retained diagnostic role of `codex-smart`;
- the fact that an already running conversation cannot be retrofitted.

Keep historical reports unchanged and preserve required Markdown anchors and Mermaid diagram kinds.

- [ ] **Step 2: Validate documentation**

Run:

```bash
make docs
git diff --check
```

Expected: navigation validation and whitespace check pass.

- [ ] **Step 3: Run repository quality gates**

Run focused compilation first:

```bash
make compile
```

Then run the full gate once:

```bash
make quality
```

If the known timing-sensitive supervised-subprocess test fails, rerun that exact test in isolation five times and record the full-suite failure separately; do not change unrelated process supervision in this task.

- [ ] **Step 4: Reinstall the plugin with an absolute native binary**

Run:

```bash
python3 scripts/install_adaptive_subagents.py --apply --codex-binary /opt/homebrew/bin/codex --json
python3 scripts/install_adaptive_subagents.py --apply --codex-binary /opt/homebrew/bin/codex --json
python3 scripts/install_adaptive_subagents.py --doctor --codex-binary /opt/homebrew/bin/codex --json
python3 scripts/install_adaptive_subagents.py --smoke --codex-binary /opt/homebrew/bin/codex --json
```

Require `applied` or an update on the first call, `unchanged` on the second, and `READY` for doctor/smoke.

- [ ] **Step 5: Apply the entrypoint last**

Run:

```bash
python3 scripts/reconcile_codex_entrypoint.py --preview --json
python3 scripts/reconcile_codex_entrypoint.py --apply --json
python3 scripts/reconcile_codex_entrypoint.py --apply --json
python3 scripts/reconcile_codex_entrypoint.py --doctor --json
```

Require no foreign conflict, then `applied`, `unchanged`, and `READY`.

- [ ] **Step 6: Verify a fresh shell**

Run non-mutating service checks:

```bash
zsh -lic 'alias codex; alias codex-native; codex --version; codex help >/dev/null; codex update --help >/dev/null; codex-native --version'
```

Require both aliases, native version output, and no controller preparation for service commands.

Verify `codex-highfd --self-test` for both modes and use the existing admin `status`/`inspect` evidence for an attested route. Do not claim an already-open conversation became managed.

- [ ] **Step 7: Commit Task 3**

```bash
git add \
  README.md \
  plugins/codex-smart-subagents/README.md \
  docs/runbooks/adaptive-subagents-v2-operations.md \
  docs/analysis/adaptive-subagents-v2-flow.md \
  docs/migrations/adaptive-subagents-v2.md \
  docs/guides/autonomous-workflow.md \
  docs/superpowers/plans/2026-07-27-smart-codex-entrypoint.md
git commit -m "docs(subagents): make codex the managed entrypoint"
```

### Task 4: Final review and publication

**Files:**
- Review the complete branch diff from the commit before Task 1 through Task 3.

**Interfaces:**
- No new implementation interface.

- [ ] **Step 1: Run a whole-branch review**

Generate one review package from the recorded implementation base through `HEAD`. Dispatch a fresh high-reasoning reviewer against this plan and the package. Fix all Critical and Important findings with focused tests, then re-review.

- [ ] **Step 2: Run final fresh verification**

Run:

```bash
make quality
python3 scripts/reconcile_codex_entrypoint.py --doctor --json
python3 scripts/install_adaptive_subagents.py --doctor --codex-binary /opt/homebrew/bin/codex --json
python3 scripts/install_adaptive_subagents.py --smoke --codex-binary /opt/homebrew/bin/codex --json
git diff --check
git status --short --branch
```

Read every exit code and output before claiming completion.

- [ ] **Step 3: Push the existing feature branch**

Push `codex/implement-adaptive-subagents-v2` without force. Confirm the remote head equals local `HEAD`.
