# Durable Transient Process Ownership v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Сохранить владение временными процессами через сбой установщика и безопасно завершать либо принимать их после точной повторной проверки личности.

**Architecture:** Отдельный закрытый каталог содержит по одному атомарному каноническому документу на аренду. Адаптеры публикации и перехода подключаются к единому надзору операции; кандидат удерживается стартовым каналом до записи полной личности. Восстановление сначала доказывает принятие, иначе требует точного совпадения PID, PGID, SID и маркера старта перед мягкими сигналами.

**Tech Stack:** Python 3.11+, `pytest`, канонический JSON v1, JSON Schema draft 2020-12, POSIX process groups on macOS.

## Global Constraints

- Не изменять Git index и не создавать коммиты в этой задаче.
- Не изменять `operation_process_group_supervisor_v2.py` и его тесты.
- Не изменять `schema_projection.py`, `state_migration*`, `activation_materializer_v2.py`, `installer_maintenance_v2.py`.
- Не посылать сигнал без точного совпадения PID, PGID, SID и системного маркера старта; не использовать `SIGKILL`.
- Обязанность очистки имеет приоритет над обычной ошибкой срока.
- Успешная обычная установка или обновление не оставляет новый файл владения.

---

### Task 1: Закрытый документ и атомарное хранилище

**Files:**
- Create: `plugins/codex-smart-subagents/src/codex_smart_subagents/durable_process_ownership_v2.py`
- Create: `tests/smart_subagents/test_durable_process_ownership_v2.py`

**Interfaces:**
- Consumes: `TransientProcessLeaseV2`, `validate_cleanup_obligation_v2`, `canonical_json_bytes`, `domain_fingerprint`.
- Produces: `DurableProcessOwnershipStoreV2.publish(lease, context)`, `transition(lease, outcome, cleanup_obligation)`, `load_all()`, `recover(...)`, `build_durable_ownership_callbacks_v2(codex_home)`.

- [ ] **Step 1: Write the failing contract tests**

Проверить закрытые контексты `candidate-dispatch-v2` и
`installer-transient-v2`, отпечаток записи, режимы каталогов и файлов,
повторную точную публикацию, отказ при конфликте, переход
`OWNED -> CLEANUP_REQUIRED`, точное удаление и удаление пустого каталога.

- [ ] **Step 2: Run the focused tests and prove RED**

Run: `pytest -q tests/smart_subagents/test_durable_process_ownership_v2.py`

Expected: collection fails because `durable_process_ownership_v2` does not exist.

- [ ] **Step 3: Implement the minimal closed store**

Реализовать закрытый документ с полями `schemaVersion`, `recordKind`,
`leaseId`, `processLabel`, `pid`, `processGroupId`, `sessionId`,
`processStartMarker`, `context`, `state`, `cleanupObligation` и
`recordFingerprint`. Публикация использует частный временный файл, `fsync`,
атомарный `link`, `fsync` каталога и чтение после публикации. Переход создаёт
новый канонический файл и атомарно заменяет только запись с точным отпечатком.

- [ ] **Step 4: Run focused tests and prove GREEN**

Run: `pytest -q tests/smart_subagents/test_durable_process_ownership_v2.py`

Expected: all tests pass.

### Task 2: Безопасное восстановление

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/durable_process_ownership_v2.py`
- Modify: `tests/smart_subagents/test_durable_process_ownership_v2.py`

**Interfaces:**
- Consumes: `identity_reader(pid) -> ProcessIdentityV2 | None`, `group_exists(pgid) -> bool`, `killpg(pgid, signal)`, `accepted_candidate_proof(record) -> bool`, отдельное положительное `candidate_termination_authorized(record) -> bool`.
- Produces: `DurableOwnershipRecoveryResultV2` and `OutstandingDurableProcessOwnershipV2`.

- [ ] **Step 1: Write failing recovery tests**

Проверить: принятый кандидат удаляется без сигналов; исчезнувший процесс
удаляется после доказанного отсутствия; несовпадение любого поля не сигналит и
сохраняет запись; точное совпадение допускает только `SIGCONT`/`SIGTERM`;
живая после срока группа остаётся `CLEANUP_REQUIRED`; `SIGKILL` отсутствует;
неизвестное состояние принятия не читает личность и не посылает сигнал;
занятая файловая блокировка и локальное ожидание процесса не переживают более
ранний общий срок и сохраняют его точный код.

- [ ] **Step 2: Run the focused recovery tests and prove RED**

Run: `pytest -q tests/smart_subagents/test_durable_process_ownership_v2.py -k recover`

Expected: failures report missing recovery behavior.

- [ ] **Step 3: Implement exact-identity recovery**

Сначала вызвать доказательство принятия только для candidate context. Если оно
не положительно, не считать это доказательством непринятия: без отдельного
положительного разрешения на завершение сохранить запись без чтения процесса.
Для разрешённого завершения заново получить личность, сравнить четыре поля,
перед каждым сигналом повторить сравнение и ограниченно ждать исчезновения
группы. Блокировку каталога брать конечным `LOCK_NB`-опросом. Перед каждым
чтением личности, сигналом и сном проверять общий непродлеваемый срок, а сон
ограничивать его остатком. Любая неоднозначность возвращает блокирующий
результат и сохраняет каноническую запись.

- [ ] **Step 4: Run focused tests and prove GREEN**

Run: `pytest -q tests/smart_subagents/test_durable_process_ownership_v2.py`

Expected: all tests pass.

### Task 3: Стартовый канал кандидата

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/candidate_ready_channel_v2.py`
- Modify: `plugins/codex-smart-subagents/controller/server.py`
- Modify: `tests/smart_subagents/test_candidate_ready_channel_v2.py`
- Modify: `tests/smart_subagents/test_controller_server_v2.py`

**Interfaces:**
- Consumes: supervisor `spawn_transient(..., ownership_context=...)` and callback publication before return.
- Produces: закрытая переменная `CODEX_V2_CANDIDATE_OWNERSHIP_GATE_FD`; `await_candidate_ownership_gate_v2(environment)`.

- [ ] **Step 1: Write failing gate tests**

Проверить передачу read FD через `pass_fds`, закрытый candidate context,
отправку одного разрешающего байта только после возврата аренды, закрытие всех
дескрипторов на каждой ошибке, отказ ребёнка на EOF/неверный байт и удаление
переменной среды до дальнейшего запуска.

- [ ] **Step 2: Run gate tests and prove RED**

Run: `pytest -q tests/smart_subagents/test_candidate_ready_channel_v2.py -k ownership_gate tests/smart_subagents/test_controller_server_v2.py -k ownership_gate`

Expected: failures report absent gate/context behavior.

- [ ] **Step 3: Implement the pipe handshake**

Создать pipe до запуска, сделать write FD закрываемым при `exec`, передать read
FD через `pass_fds`, включить номер FD в безопасную среду, передать candidate
context надзору, закрыть parent read FD и после долговечной публикации записать
ровно `b"1"`. Ребёнок после загрузки bootstrap читает ровно один байт;
`b""`, иной байт или лишние данные завершают запуск до SQLite/ready.

- [ ] **Step 4: Run candidate tests and prove GREEN**

Run: `pytest -q tests/smart_subagents/test_candidate_ready_channel_v2.py tests/smart_subagents/test_controller_server_v2.py`

Expected: all tests pass.

### Task 4: Принятие и публичная операция

**Files:**
- Modify: `plugins/codex-smart-subagents/src/codex_smart_subagents/installer_update_controller_ports_v2.py`
- Modify: `scripts/install_adaptive_subagents.py`
- Modify: `tests/smart_subagents/test_installer_update_controller_ports_v2.py`
- Modify: `tests/smart_subagents/test_operation_deadline_integration_v2.py`

**Interfaces:**
- Consumes: callback factory from Task 1, proven `controller_accept`, supervisor transition callbacks.
- Produces: блокирующая публичная ошибка с долговечной записью; приоритет cleanup над deadline; отсутствие записей после успеха.

- [ ] **Step 1: Write failing integration tests**

Проверить удаление точной candidate-записи только после валидной квитанции
`controller_accept`, сохранение при несовпадении, сохранение cleanup через
исключение/выход `ContextVar`, приоритет cleanup над вложенной deadline error и
отсутствие каталога после обычного успеха. Отдельно воспроизвести сбой после
долговечного `controller_accept`, но до удаления ownership-записи, когда
основной журнал уже снят: восстановление обязано безопасно заблокироваться без
сигнала.

- [ ] **Step 2: Run integration tests and prove RED**

Run: `pytest -q tests/smart_subagents/test_installer_update_controller_ports_v2.py -k ownership tests/smart_subagents/test_operation_deadline_integration_v2.py -k ownership`

Expected: failures report missing durable callback and wrong error priority.

- [ ] **Step 3: Wire callbacks and error precedence**

Создать store после определения `codex_home`, передать callbacks конструктору
надзора, заблокировать обычный запуск при существующей записи, а в обработчике
ошибок сначала извлечь/проверить долговечную обязанность и лишь затем ошибку
срока. После доказанного принятия вызвать переход `accepted` с точной арендой.

- [ ] **Step 4: Run integration tests and prove GREEN**

Run: `pytest -q tests/smart_subagents/test_installer_update_controller_ports_v2.py tests/smart_subagents/test_operation_deadline_integration_v2.py`

Expected: all tests pass.

### Task 5: Схема, векторы и итоговая проверка

**Files:**
- Create: `docs/contracts/schemas/transient-process-ownership-v2.schema.json`
- Create: `docs/contracts/vectors/transient-process-ownership-v2.json`
- Create: `scripts/validate_transient_process_ownership_vectors.py`
- Modify: `docs/contracts/schemas/README.md`
- Modify: `scripts/validate_contracts.py`

**Interfaces:**
- Consumes: точный документ из Task 1.
- Produces: закрытая схема и положительные/отрицательные векторы для всех состояний и контекстов.

- [ ] **Step 1: Add schema vectors that fail validation**

Положительные векторы покрывают оба контекста и два состояния. Отрицательные
покрывают лишнее поле, неверный отпечаток, неполную личность, cleanup в
`OWNED`, отсутствие cleanup в `CLEANUP_REQUIRED` и неизвестный исход.

- [ ] **Step 2: Run validators and prove RED**

Run: `python3 scripts/validate_transient_process_ownership_vectors.py`

Expected: validation fails until schema/runtime validator is wired.

- [ ] **Step 3: Implement the closed schema and validator**

Схема запрещает дополнительные свойства на каждом уровне, различает context
через `oneOf`, связывает `state` и `cleanupObligation` условными правилами и
проверяет идентификаторы/отпечатки. Валидатор сравнивает JSON Schema и runtime
accept/reject behavior для каждого вектора.

- [ ] **Step 4: Run narrow and full gates**

Run: `python3 scripts/validate_transient_process_ownership_vectors.py`

Run: `python3 scripts/validate_contracts.py`

Run: `pytest -q tests/smart_subagents/test_durable_process_ownership_v2.py tests/smart_subagents/test_candidate_ready_channel_v2.py tests/smart_subagents/test_controller_server_v2.py tests/smart_subagents/test_installer_update_controller_ports_v2.py tests/smart_subagents/test_operation_deadline_integration_v2.py`

Run: `python3 -m compileall -q plugins/codex-smart-subagents/src scripts tests/smart_subagents`

Run: `git diff --check`

Expected: every command exits 0; successful-path tests prove the ownership directory is absent.
