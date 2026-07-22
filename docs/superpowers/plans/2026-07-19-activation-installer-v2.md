# Activation Installer v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Заменить применяемый путь установщика schema 1 на идемпотентную установку принятой активации версии 2 с двойной готовностью, восстановлением через супервизор и точным откатом.

**Architecture:** Первый `--apply` создаёт стабильные ссылки, напрямую запускает исходный `controller/server.py --serve-v2` с закрытым окружением, ждёт `ActivationResolver.READY` и `command.sock`, затем регистрирует `marketplace-current` и расширение. Отдельная закрытая квитанция schema 2 доказывает `sourceDigest` и внешнее владение; повторы идут только через `ControllerSupervisorV2`.

**Tech Stack:** Python 3, `unittest`, Unix-сокеты, `subprocess`, атомарные файлы JSON, штатный интерфейс расширений Codex.

## Global Constraints

- Не изменять `plugins/codex-smart-subagents/controller/server.py` и `plugins/codex-smart-subagents/bin/codex-smart`.
- Не создавать старое изменяемое дерево рынка, lifecycle-манифест schema 1, резервную копию `config.toml` или `codex-highfd`.
- Сохранить интерфейсы просмотра, `--apply`, `--doctor`, `--smoke` и `--json`.
- Не обновлять Codex и не изменять сеть операционной системы.
- Любое несовпадение принятой установки закрывает повторное применение.
- `HEALTH_ONLY` никогда не является готовой установкой.

---

### Task 0: Полный набор схем неизменяемого рынка

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/activation_materializer_v2.py`
- Modify: `tests/smart_subagents/test_activation_materializer_v2.py`

**Interfaces:**
- Consumes: схемы результатов boundary, reader и writer из `docs/contracts/schemas`.
- Produces: точный runtime-набор схем, который учитывает digest установщика.

- [ ] **Step 1: Extend the exact-set test and confirm RED**

Добавить `boundary-result-v1.schema.json`, `reader-result-v1.schema.json` и
`writer-result-v1.schema.json` в ожидаемый набор и запустить один тест.

- [ ] **Step 2: Add the three source schema names**

Расширить `_RUNTIME_SCHEMA_FILES`, не меняя алгоритм безопасного копирования.

- [ ] **Step 3: Run the exact-set test and confirm GREEN**

Run: `python3 -m unittest tests.smart_subagents.test_activation_materializer_v2.ActivationMaterializerV2Tests.test_runtime_schemas_are_exact_and_installed_mcp_is_self_contained -v`

Expected: PASS.

### Task 1: Узкий cleanup принятой активации

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/activation_materializer_v2.py`
- Modify: `tests/smart_subagents/test_activation_materializer_v2.py`

**Interfaces:**
- Consumes: `GatewayLayout`, lifecycle manifest schema 2 и commit receipt.
- Produces: `cleanup_accepted_activation_v2(*, codex_home: Path, installation_id: str, activation_id: str) -> ActivationCleanupV2`.

- [ ] **Step 1: Write failing tests for exact cleanup ownership**

Добавить проверки, что cleanup отказывает при живом контроллере, неверном
`installationId`/`activationId` и изменённом объекте, а после остановки
удаляет только точные manifest, receipt, activation, database, fallback,
snapshot и `marketplace-current`.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `python3 -m unittest tests.smart_subagents.test_activation_materializer_v2 -v`

Expected: FAIL because `cleanup_accepted_activation_v2` is absent.

- [ ] **Step 3: Implement the narrow cleanup API**

Под lifecycle-lock перечитать закрытые документы, сверить точные
идентификаторы и метаданные, доказать остановку PID/marker и свободу lock,
после чего удалять только совпавшие объекты и пустые каталоги. Возвращать
неизменяемый результат с точным перечнем удалённых путей.

- [ ] **Step 4: Run the focused tests and confirm GREEN**

Run: `python3 -m unittest tests.smart_subagents.test_activation_materializer_v2 -v`

Expected: PASS.

### Task 2: Новый договор layout, квитанции и закрытого запуска

**Files:**
- Modify: `scripts/install_adaptive_subagents.py`
- Replace relevant installer cases: `tests/smart_subagents/test_install_adaptive_subagents.py`

**Interfaces:**
- Consumes: `GatewayLayout.for_codex_home`, `ControllerSupervisorV2`,
  `probe_controller_command_socket_v2`.
- Produces: `InstallLayout.gateway_layout`, `installer_receipt_path`,
  `initial_controller_environment()` и строгую schema-2 квитанцию.

- [ ] **Step 1: Write failing layout and environment tests**

Проверить цели обеих стабильных ссылок через `marketplace-current`, отдельный
путь квитанции, отсутствие schema 1/highfd/backup в dry-run и ровно четыре
обязательных параметра bootstrap в закрытом окружении.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents.InstallerV2ContractTests -v`

Expected: FAIL on old layout and actions.

- [ ] **Step 3: Implement minimal layout, digest, receipt and environment**

Перевести свойства на `GatewayLayout`, добавить строгую загрузку/атомарную
запись квитанции mode `0600`, новый digest только по входам materializer и
формирование закрытой среды без наследования произвольных переменных.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents.InstallerV2ContractTests -v`

Expected: PASS.

### Task 3: Первый apply и компенсация

**Files:**
- Modify: `scripts/install_adaptive_subagents.py`
- Modify: `tests/smart_subagents/test_install_adaptive_subagents.py`
- Modify: `tests/smart_subagents/test_install_fake_codex.py`

**Interfaces:**
- Consumes: Task 1 cleanup API and Task 2 receipt/layout helpers.
- Produces: transactional `install(layout, apply=True)` status `installed`.

- [ ] **Step 1: Write failing first-apply tests**

Доказать порядок links → direct spawn → dual readiness → marketplace add →
plugin add → receipt, точный путь рынка, отсутствие старого дерева schema 1,
отказ без каждого из трёх `CODEX_V2_*` и отсутствие их значений в результате
и квитанции.

- [ ] **Step 2: Run focused first-apply tests and confirm RED**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents.InstallerV2ApplyTests -v`

Expected: FAIL on old schema-1 apply.

- [ ] **Step 3: Implement first apply**

Под отдельной installer-lock безопасно создать точные ссылки, запустить один
процесс с `--serve-v2`, ограниченно дождаться resolver/socket, выполнить две
штатные регистрации, проверить их и атомарно записать квитанцию.

- [ ] **Step 4: Implement reverse compensation**

На любом сбое удалить только добавленные попыткой plugin/marketplace/links,
остановить только сохранённый process handle и вызвать точный cleanup API.
Сохранить исходную ошибку и добавить ограниченную диагностику сбоя отката.

- [ ] **Step 5: Run first-apply and failure tests and confirm GREEN**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents.InstallerV2ApplyTests -v`

Expected: PASS.

### Task 4: Повтор, восстановление и закрытые несовпадения

**Files:**
- Modify: `scripts/install_adaptive_subagents.py`
- Modify: `tests/smart_subagents/test_install_adaptive_subagents.py`

**Interfaces:**
- Consumes: exact installer receipt and `ControllerSupervisorV2.ensure()`.
- Produces: repeat status `unchanged` only for exact `FULL_READY` state.

- [ ] **Step 1: Write failing repeat tests**

Проверить отсутствие direct spawn и команд add при полном повторе, один вызов
супервизора после остановки, успешное восстановление, а также закрытые ветви
для другого digest, отсутствующей квитанции, другой ссылки и другой
регистрации.

- [ ] **Step 2: Run repeat tests and confirm RED**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents.InstallerV2RepeatTests -v`

Expected: FAIL because old repeat reads schema 1.

- [ ] **Step 3: Implement exact repeat path**

Сверить квитанцию до любых изменений, вызвать супервизор установленного
plugin root, затем повторно сверить двойную готовность и внешние артефакты.
Ничего не чинить при несовпадении.

- [ ] **Step 4: Run repeat tests and confirm GREEN**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents.InstallerV2RepeatTests -v`

Expected: PASS.

### Task 5: Трёхсостояний doctor, smoke и запрет утечки bootstrap-параметров

**Files:**
- Modify: `scripts/install_adaptive_subagents.py`
- Modify: `tests/smart_subagents/test_install_adaptive_subagents.py`
- Modify: `tests/smart_subagents/test_child_runner.py`

**Interfaces:**
- Consumes: public resolver, command socket probe and exact receipt checks.
- Produces: `doctor()` statuses `ORDINARY`, `HEALTH_ONLY`, `FULL_READY` and
  `ok=True` only for exact `FULL_READY`.

- [ ] **Step 1: Write failing doctor and leak tests**

Проверить все три состояния, `ok=False` для health-only, блокировку smoke вне
полной готовности и отсутствие `CODEX_V2_SOURCE_ROOT`, `CODEX_V2_CODEX_BIN`,
`CODEX_V2_WRAPPER_PATH` в окружении дочерней модели и наблюдаемой телеметрии.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents tests.smart_subagents.test_child_runner -v`

Expected: FAIL on old doctor status and missing bootstrap sentinels.

- [ ] **Step 3: Implement three-state diagnosis and guarded smoke**

Классифицировать сначала фактическую готовность, отдельно собрать проблемы
квитанции, ссылок и регистраций и разрешить smoke только при полном `ok`.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents tests.smart_subagents.test_child_runner -v`

Expected: PASS.

### Task 6: Интеграция с супервизором и общий шлюз качества

**Files:**
- Modify only if required by agreed public API: `scripts/install_adaptive_subagents.py`
- Test: `tests/smart_subagents/test_controller_supervisor_v2.py`
- Test: `tests/smart_subagents/test_health_bootstrap_v2.py`

**Interfaces:**
- Consumes: final supervisor contract from the root worker.
- Produces: verified end-to-end installer slice without changes to root-owned entrypoints.

- [ ] **Step 1: Re-read the supervisor public signature and align the adapter**

Использовать его только при существующей принятой schema-2 активации; первый
запуск остаётся прямым.

- [ ] **Step 2: Run narrow integration validation**

Run: `python3 -m unittest tests.smart_subagents.test_install_adaptive_subagents tests.smart_subagents.test_controller_supervisor_v2 tests.smart_subagents.test_health_bootstrap_v2 -v`

Expected: PASS.

- [ ] **Step 3: Run compile and diff checks**

Run: `python3 -m compileall -q scripts plugins/codex-smart-subagents/src tests/smart_subagents`

Expected: exit 0.

Run: `git diff --check`

Expected: exit 0.

- [ ] **Step 4: Report exact changed files and validation evidence to root**

Не создавать коммит самостоятельно в общем грязном дереве; передать корню
границы изменений, результаты проверок и известные внешние зависимости.
