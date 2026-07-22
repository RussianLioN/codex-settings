# Health Bootstrap V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Создать единый двухфазный bootstrap, который связывает staged activation с настоящим health-сервером и публикует шлюз только после доказанного `READY`.

**Architecture:** Материализатор разделяется на подготовку неизменяемой идентичности и финализацию по фактическому `AcceptingControllerV2`. Новый orchestration-модуль запускает `ControllerHealthServerV2`, финализирует активацию через registrar, запускает `serve_forever`, проверяет её обычным `ActivationResolver` и возвращает владеющий runtime handle со статусом `HEALTH_ONLY_READY`.

**Tech Stack:** Python 3.13, Unix domain sockets, SQLite, `threading`, `unittest`.

## Global Constraints

- Не подключать `scripts/install_adaptive_subagents.py`.
- Не реализовывать никакие методы контроллера кроме `health`.
- Не закрывать и не перепривязывать сокет между регистрацией и проверкой.
- Ошибка до READY удаляет все принадлежащие кандидату артефакты.
- Повтор владельца возвращает тот же живой handle.

---

### Task 1: Staged immutable identity

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/activation_materializer_v2.py`
- Test: `tests/smart_subagents/test_health_bootstrap_v2.py`

**Interfaces:**
- Produces: `StagedActivationV2`, `stage_activation_identity_v2(...)`, `finalize_staged_activation_v2(staged, controller)`.

- [x] **Step 1: Write the failing test**

Проверить, что staging возвращает `database_id`, `activation_id`, отпечатки и каталог активации, но не создаёт сокет, БД, манифест, квитанцию или активную ссылку.

- [x] **Step 2: Run test to verify it fails**

Run: `uv run --locked python -m unittest tests.smart_subagents.test_health_bootstrap_v2.HealthBootstrapV2Tests.test_stage_has_identity_without_controller_artifacts -v`

Expected: import failure for `stage_activation_identity_v2`.

- [x] **Step 3: Write minimal implementation**

Вынести существующую подготовку snapshot/interface/marketplace/identity в
`stage_activation_identity_v2`; сохранить полный набор данных, необходимый
для финализации, в frozen dataclass `StagedActivationV2`.

- [x] **Step 4: Run test to verify it passes**

Run: команда шага 2. Expected: PASS.

### Task 2: Registrar finalization

**Files:** те же.

**Interfaces:**
- Consumes: `StagedActivationV2`, фактический `AcceptingControllerV2`.
- Produces: `ActivationMaterializationV2` и `ControllerRegistrationReceiptV2` через orchestration closure.

- [x] **Step 1: Write the failing test**

Проверить, что один заранее связанный socket inode попадает в
`AcceptingControllerV2`, `controller_state`, health response и последующую
проверку gateway без повторного bind.

- [x] **Step 2: Run test to verify it fails**

Run: `uv run --locked python -m unittest tests.smart_subagents.test_health_bootstrap_v2.HealthBootstrapV2Tests.test_real_two_phase_bootstrap_uses_one_socket_inode -v`

Expected: orchestration API отсутствует.

- [x] **Step 3: Write minimal implementation**

Добавить финализацию, которая создаёт `SmartStoreV2`, fallback, manifest,
receipt и absence proof только из принятого controller; registrar cleanup
закрывает store ровно один раз.

- [x] **Step 4: Run test to verify it passes**

Run: команда шага 2. Expected: PASS.

### Task 3: Live orchestration and rollback

**Files:**
- Create: `plugins/codex-smart-subagents/src/codex_smart_subagents/health_bootstrap_v2.py`
- Test: `tests/smart_subagents/test_health_bootstrap_v2.py`

**Interfaces:**
- Produces: `HealthBootstrapRuntimeV2`, `bootstrap_health_activation_v2(...)`, `observe_health_activation_v2(...)`.

- [x] **Step 1: Write failing owner-repeat and rollback tests**

Проверить один и тот же handle при повторе владельца; при принудительном
отказе gateway проверить отсутствие link/manifest/receipt/activation/database
и остановленный поток.

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run --locked python -m unittest tests.smart_subagents.test_health_bootstrap_v2 -v`

Expected: отсутствует `health_bootstrap_v2`.

- [x] **Step 3: Write minimal implementation**

Собрать stage → server.start/registrar → serve thread → resolver → link в
одну функцию. Реестр хранит только владеющие живые handle. Внешняя активация
возвращается отдельным невладеющим наблюдаемым handle.

- [x] **Step 4: Run focused and adjacent tests**

Run:
`uv run --locked python -m unittest tests.smart_subagents.test_health_bootstrap_v2 tests.smart_subagents.test_activation_materializer_v2 tests.smart_subagents.test_controller_health_v2 tests.smart_subagents.test_activation_gateway_v2 -q`

Expected: PASS.

- [x] **Step 5: Final validation**

Run: `git diff --check` and compile both new modules. Parent agent performs the logical commit after shared-tree integration.

### Task 4: Idempotent recovery after owner-process exit

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/activation_gateway_v2.py`
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/health_bootstrap_v2.py`
- Test: `tests/smart_subagents/test_health_bootstrap_v2.py`

**Interfaces:**
- Reuses the immutable activation and database identity.
- Replaces only `controller_state` under the real controller lock and an
  immediate SQLite transaction.

- [x] **Step 1: Write the failing inter-process recovery test**

Первый процесс принимает activation и завершается без cleanup. Второй вызов
должен сохранить manifest/activation/receipt/database identity, создать новые
instance/start/PID/socket и получить `controlEpoch + 1`.

- [x] **Step 2: Prove the test fails before recovery exists**

Expected initial result: `FOREIGN_ACTIVATION_NOT_READY` with
`CONTROLLER_UNAVAILABLE`.

- [x] **Step 3: Implement static proof and atomic controller replacement**

Исключить только live-controller часть внутреннего доказательства, проверить
прежний PID+marker, получить controller-lock, повторно сверить rows под
`BEGIN IMMEDIATE`, заменить controller row и затем выполнить обычный live
resolver.

- [x] **Step 4: Cover takeover prohibitions and rollback**

Проверить отказ при живой прежней паре PID+marker, занятой файловой
блокировке и восстановление старой controller row при отказе нового READY.

- [x] **Step 5: Run focused recovery tests**

Expected: PASS with `ResourceWarning` promoted to errors.
