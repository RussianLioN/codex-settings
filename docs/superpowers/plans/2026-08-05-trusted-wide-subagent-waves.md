> **Статус на 2026-08-14:** это исторический план от 2026-08-05, не текущий договор и не доказательство текущего живого состояния.
>
> Текущий публичный ключ — `agents.max_concurrent_threads_per_session`; `agents.max_threads` здесь только исторический термин. Текущий `consilium` допускается ровно на 19 ролей. Хуки и смарт-запуск отключены. Нормативные текущие материалы: [спецификация наблюдателя](../../plans/2026-08-14-codex-capacity-observer-specification.md) и [действующий план общего ограничителя](../../plans/2026-08-13-consilium-19-wide-preflight-recovery.md).

# План доверенных широких волн субагентов

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Разрешить проверенным навыкам запускать до 20 субагентов без снятия обычного ограничения 6 и без повторения истощения файловых дескрипторов или процессов.

**Architecture:** Публичный предел Codex задаётся одним каноническим ключом на 20 субагентов. Обычная волна остаётся не больше 6; волна 7–20 допускается только после проверки ресурсов, имени и SHA-256 навыка и непересекающихся областей записи. Consilium получает широкий режим в отслеживаемом пакете 0.2.0, а умный маршрутизатор сохраняет граф до 20 узлов и собственный предел 6 одновременно работающих узлов маршрута.

**Tech Stack:** Python 3.12+, zsh, TOML, JSON Schema, unittest, Codex plugin marketplace.

**Status (2026-08-05):** реализация, живое применение, широкая волна 20,
запасной режим `6 + 1`, восстановление целевой вкладки и устранение остаточного
тестового повреждения навыка и хуков подтверждены. Ветки оставлены локальными
без публикации и слияния. Строгий валидатор
`agents-skills` проходит все функциональные ворота, но остаётся красным на
ранее существовавшем внешнем блокаторе: `gitleaks` отсутствует, послабление
истекло.

## Global Constraints

- Не изменять вручную `~/.codex/plugins/cache` и сгенерированные поверхности `agents-skills`.
- Не затрагивать грязные рабочие копии `codex-settings`, `agents-skills` и `session-termination-command-gate`.
- Обычная живая волна: максимум 6; доверенная широкая волна: 7–20.
- Широкий режим использует инструкцию и обязательный preflight, но не hook-принуждение; это операционный ограничитель, а не граница безопасности.
- Публичный `[agents].max_concurrent_threads_per_session = 20`; устаревший `max_threads` и внутренний `features.multi_agent_v2.max_concurrent_threads_per_session` должны отсутствовать.
- Для волны `N` требуется запас процессов `128 + 20 * N`; неизвестный запас блокирует любые новые запуски.
- Пишущие роли получают относительные непересекающиеся области; общий генератор и интеграционные файлы принадлежат одному интегратору.
- Машинная матрица едина: `OK/0` разрешает точный `N`, `WARN/1` разрешает только заново построенную волну до 6, `BLOCK/2` запрещает новые запуски.

---

### Task 1: Канонический предел Codex и ресурсный preflight

**Files:**
- Modify: `scripts/apply_runtime_fd_guardrails.py`
- Modify: `scripts/codex_fd_doctor.sh`
- Create: `config/trusted-wide-wave-skills.json`
- Create: `schemas/codex-wide-wave-manifest.schema.json`
- Create: `scripts/validate_wide_wave_manifest.py`
- Test: `tests/smart_subagents/test_runtime_fd_guardrail_installer.py`
- Test: `tests/smart_subagents/test_autonomous_workflow.py`
- Test: `tests/smart_subagents/test_wide_wave_manifest.py`

**Interfaces:**
- Установщик владеет живыми `config.toml`, `AGENTS.md`, doctor, валидатором манифеста и доверенным списком.
- `codex_fd_doctor.sh --wave-size N [--skill-id ID --skill-file PATH --manifest PATH]` возвращает `OK=0`, `WARN=1`, `BLOCK=2`.
- Для `N <= 6` параметры навыка необязательны; для `N >= 7` обязательны все три.
- Доверенная запись: `skill_id`, `sha256`, `max_live_wave`, `execution_kind`, `fallback`.
- Манифест: `schema_version`, `skill_id`, `wave_size`, `repository_root`, `base_commit`, `participants[]`; участник содержит `id`, `access`, `owned_write_scope[]`.
- Валидатор выводит `protocol_version=1`, `status`, `allowed_wave_size` и фиксированные причины; doctor закрыто проверяет соответствие статуса коду `0/1/2`.

- [x] **Step 1: Write failing config migration tests**

Ожидать публичное значение 20, удаление устаревшего псевдонима и внутреннего V2-предела, сохранение `features.multi_agent_v2.enabled = true`.

- [x] **Step 2: Run config tests and confirm RED**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.smart_subagents.test_runtime_fd_guardrail_installer`

Expected: FAIL на старом `max_threads` и оставшемся внутреннем ключе.

- [x] **Step 3: Implement canonical TOML migration**

Добавить безопасное удаление одного ключа внутри таблицы; дубликаты таблиц или ключей завершают применение ошибкой. Проверка состояния различает устаревший псевдоним, отсутствующий публичный предел и присутствующий внутренний предел.

- [x] **Step 4: Write failing resource-headroom tests**

Покрыть достаточные 4096 дескрипторов и `maxproc`; `WARN`, когда запаса хватает для 6, но не для широкого `N`; `BLOCK`, когда запаса не хватает даже для 6 или process limit неизвестен; различение `maxfiles=256` и `maxproc=2666`.

- [x] **Step 5: Run doctor tests and confirm RED**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.smart_subagents.test_autonomous_workflow`

Expected: FAIL из-за отсутствующих `user_process_count`, `process_headroom` и причин.

- [x] **Step 6: Implement process and FD checks**

Читать `ulimit -Su`, `launchctl limit maxproc`, считать процессы текущего uid и выбирать минимальный известный предел. Для запроса `N` вычислять `128 + 20*N` и отдельный безопасный порог 248 для волны 6. Между порогами выдавать `WARN`, ниже 248 либо при неизвестном запасе — `BLOCK`. Выводить отдельные `launchd_fd_soft_limit`, `user_process_soft_limit`, `user_process_count`, `process_headroom`, `required_process_headroom`.

- [x] **Step 7: Write failing trust and scope tests**

Покрыть неизвестный навык, неверный хэш, превышение контрактного максимума, абсолютный путь, `..`, одинаковые и вложенные области записи, корректные read-only роли и корректные раздельные области.

- [x] **Step 8: Run manifest tests and confirm RED**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.smart_subagents.test_wide_wave_manifest`

Expected: FAIL, потому что валидатор и схема отсутствуют.

- [x] **Step 9: Implement trust and manifest validation**

Нормализовать пути относительно `repository_root`, запрещать абсолютные пути и выход через `..`, считать пересечением равенство и отношение предок/потомок. Хэш вычислять по байтам окончательного `SKILL.md`. Недоказанное широкое доверие даёт `WARN` и требует отбросить широкий манифест; ошибки структуры, свежести, прав или областей дают `BLOCK`.

- [x] **Step 10: Update managed policy and installer tests**

Политика различает обычную волну, доверенную широкую волну и 20 узлов умного графа; запрещает вложенное делегирование экспертам широкой волны; требует одного интегратора для общих файлов. Установщик резервирует и восстанавливает все принадлежащие ему файлы.

- [x] **Step 11: Verify Task 1 and commit**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.smart_subagents.test_runtime_fd_guardrail_installer tests.smart_subagents.test_autonomous_workflow tests.smart_subagents.test_wide_wave_manifest`

Run: `/bin/zsh -n scripts/codex-highfd scripts/codex_fd_doctor.sh`

Expected: PASS.

Commit: `fix: разрешить доверенные широкие волны субагентов`

### Task 2: Отслеживаемый пакет Consilium 0.2.0

**Files:**
- Create: `.codex/skills/consilium/SKILL.md`
- Create: `.codex/skills/expert-consilium/SKILL.md`
- Create: `.codex/skills/consilium-lean/SKILL.md`
- Modify: `scripts/build-local-vault.py`
- Modify: `scripts/validate-vault.py`
- Modify: `scripts/codex_install_smoke.py`
- Modify: `.github/workflows/validate.yml`
- Test: `tests/test_unified_vault.py`

**Interfaces:**
- `consilium`: доверенная волна 19; fallback `6+6+6+1`.
- `expert-consilium`: доверенная волна 13; fallback `6+6+1`.
- `consilium-lean`: доверенная волна `R`, `7 <= R <= 20`; fallback волнами до 6.
- Плагин `consilium` версии `0.2.0` содержит только эти три канонических навыка.
- `codex_install_smoke.py --plugin consilium` проверяет доступность, установку и список трёх навыков в изолированном Codex home.

- [x] **Step 1: Write failing generator and contract tests**

Требовать три канонических источника, пакет 0.2.0, максимумы 19/13/20, обязательный preflight, fallback, запрет вложенного spawn и правила областей записи. Отрицательный тест удаляет один маркер и ожидает ошибку валидатора.

- [x] **Step 2: Run tests and confirm RED**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests`

Expected: FAIL из-за отсутствующего пакета и новых источников.

- [x] **Step 3: Add canonical skill sources**

Перенести смысл проверенных контрактов без превращения ручного кэша в источник. Все роли по умолчанию read-only; писатели требуют отдельную рабочую копию и непересекающийся `owned_write_scope`. При `BLOCK` новые роли не запускаются; при `WARN` широкий манифест отбрасывается и заново создаются читающие запасные задачи волнами до 6.

- [x] **Step 4: Add curated package generation**

Добавить явные продвижения локальных `.codex/skills`, `PLUGIN_SPECS` для `consilium` 0.2.0 и генерацию без усечения обязательного контракта. Не переносить старый коммит `c5dab87` целиком.

- [x] **Step 5: Harden validation and install smoke**

Валидатор проверяет поведение структурно, а не один устаревающий фрагмент. Дымовая проверка принимает имя плагина и ожидаемый набор навыков; CI отдельно проверяет Consilium.

- [x] **Step 6: Regenerate owned surfaces**

Run: `python3 scripts/build-local-vault.py --config 90_Audit/Config/local-runtime.json --vault-root . --write --clean --run-gitleaks`

Expected: сгенерированы экспортные навыки, `plugins/consilium`, marketplace, каталоги, манифесты и отчёты без ручных правок.

- [x] **Step 7: Verify Task 2 and commit**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests`

Run: `python3 scripts/validate-vault.py --vault-root . --offline --strict`

Run: `python3 scripts/codex_install_smoke.py --mode local --repo-root . --plugin consilium --require-codex`

Run: `git diff --check`

Expected: PASS.

Фактический результат: 44 модульные проверки, изолированная установка и все
функциональные ворота прошли; строгий режим остановился только на отсутствии
`gitleaks` и истёкшем прежнем послаблении.

Commit: `feat: добавить доверенный широкий режим Consilium`

### Task 3: Согласование умных субагентов и документации

**Files:**
- Modify: `plugins/codex-smart-subagents/skills/using-smart-subagents/SKILL.md`
- Modify: `docs/guides/autonomous-workflow.md`
- Modify: `docs/plans/codex-autonomous-subagents-profiles-workers-plan.md`
- Modify: `scripts/validate_autonomous_workflow.py`
- Test: `tests/smart_subagents/test_plugin_integration.py`

**Interfaces:**
- `smart_plan` по-прежнему принимает 1–20 узлов.
- `root_processes=6`, `global_processes=20`, `sol_processes=2` остаются без изменения: 20 — размер графа, 6 — одновременно работающие узлы одного маршрута.
- Сам умный навык не входит в доверенный широкий список. План из 20 узлов разрешён как граф, но исполняется маршрутами и живыми волнами не больше 6, пока отдельный доверенный навык не докажет широкий допуск.

- [x] **Step 1: Write failing wording tests**

Требовать явного различения `20 graph nodes` и `6 live route processes`, а также запрета трактовать обычный live cap как размер графа.

- [x] **Step 2: Run test and confirm RED**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.smart_subagents.test_plugin_integration`

Expected: FAIL на отсутствующем контрактном тексте.

- [x] **Step 3: Update source skill, validators, and docs**

Добавить обязательный resource preflight перед графом больше 6 узлов и сохранить внутренний ограничитель маршрута. Не добавлять недоказанный публичный признак wide-route в V2 API.

- [x] **Step 4: Verify Task 3 and commit**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.smart_subagents.test_plugin_integration tests.smart_subagents.test_catalog tests.smart_subagents.test_process_limiter tests.smart_subagents.test_production tests.smart_subagents.test_execution_engine`

Expected: PASS.

Commit: `docs: согласовать графы умных субагентов с ресурсной политикой`

### Task 4: Живое применение, установка и доказательство восстановления

**Runtime targets:**
- `~/.codex/config.toml`, `~/.codex/AGENTS.md`, `~/.codex/config/trusted-wide-wave-skills.json`
- `~/.local/libexec/codex_fd_doctor.sh`, `~/.local/libexec/validate_wide_wave_manifest.py`
- `~/.codex/plugins/cache/agents-skills/consilium/0.2.0` только через установщик Codex.

**Interfaces:**
- Проверка без `--apply` не пишет файлы и сообщает точное расхождение до установки.
- Применение создаёт закрытый резервный снимок и атомарно устанавливает полный набор.
- Уже открытый сеанс не является доказательством нового потолка; 20-й слот проверяется в новом сеансе.

- [x] **Step 1: Run both repository quality gates**

Запустить целевые и полные тесты, `git diff --check`, строгий validator `agents-skills` и безопасную проверку состояния `codex-settings`.

- [x] **Step 2: Bind final skill hashes and verify rollback**

Вычислить SHA-256 окончательных файлов трёх навыков, записать доверенный список и выполнить изолированные проверки установщика, целостности резерва, компенсации и повторного отката. Полный валидатор пользовательского профиля не запускать как проверку только на чтение.

- [x] **Step 3: Apply guardrails and install tracked Consilium**

Выполнить проверку без записи, затем `scripts/apply_runtime_fd_guardrails.py --apply` и повторную проверку. Зафиксировать резерв и доказать публичный предел 20 при отсутствии устаревшего и внутреннего пределов. Штатной командой Codex переключить локальную площадку на отслеживаемую рабочую копию, заново установить `codex-quality-tools` и установить `consilium@agents-skills` 0.2.0; кэш вручную не менять.

- [x] **Step 4: Run preflight scenarios**

Проверить обычную волну 6, доверенные 19 и 13, корректный read-only манифест 20, неверный хэш, пересечение областей и искусственно низкий process headroom. Неверный хэш и нехватка только широкого запаса дают `WARN/allowed_wave_size=6`; пересечение и небезопасный даже для 6 запас дают `BLOCK/allowed_wave_size=0`.

- [x] **Step 5: Verify fresh-session capacity and fallback**

В новом сеансе подтвердить, что публичная настройка допускает 20 дочерних нитей и что доступный внешний потолок среды честно отражён в результате. Доказать запасной режим Consilium при `WARN`, полный запрет при `BLOCK` и отсутствие лишних `node_repl` или дочерних процессов после завершения.

- [x] **Step 6: Record local result and hand off**

Показать разницы обеих веток, проверки, живые хэши и RCA. Не сливать и не удалять рабочие копии без отдельного запроса владельца.
