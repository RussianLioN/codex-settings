# Договор состояния адаптивных субагентов версии 2

Статус: нормативная часть проекта решения от 17 июля 2026 года.

[Назад к проекту решения](../plans/2026-07-17-codex-capability-compatibility-idempotent-lifecycle-design.md)

## Назначение и главный инвариант

Этот документ задаёт единственный допустимый способ распознать старую базу
версии 1, создать базу версии 2, перенести данные и доказать отсутствие
работы перед переключением активации.

База версии 2 принадлежит ровно одной неизменяемой активации. Её нельзя
открыть рабочим контроллером, пока одновременно не совпали:

- абсолютный путь из `activation.json`;
- `databaseId` из активации и строки `database_identity`;
- `application_id`, `user_version` и отпечаток нормативной схемы;
- отпечатки активации, совместимости, политики маршрутизации и встроенного
  каталога;
- идентичность контроллера и его состояние допуска;
- полный закрытый `activationGate` из
  [договора жизненного цикла](adaptive-subagents-lifecycle-v2.md): смысловой
  отпечаток фактического манифеста, отпечаток неизменяемой положительной
  квитанции активации и свежая полная проекция `absence-proof-v2`, которая
  доказывает синхронизированное отсутствие основного установочного журнала;
- производный `gateFingerprint` того же шлюза, проверенный по единственной
  нормативной области реестра отпечатков жизненного цикла.

Одного совпадения имени файла, `user_version`, набора таблиц,
`controller_state=ACCEPTING` или итогового `gateFingerprint` недостаточно.
Каждый потребитель проверяет все составляющие шлюза по фактическому состоянию.
Неизвестная либо частично похожая форма базы не исправляется на месте и
получает ошибку `UNKNOWN_V1_SCHEMA` или `UNSUPPORTED_DATABASE`.

## Термины, значения и форматы

Все строки времени имеют форму UTC RFC 3339 с шестью цифрами долей секунды и
суффиксом `Z`. Все отпечатки SHA-256 — 64 строчных шестнадцатеричных знака.
Идентификаторы операций и попыток имеют формы, заданные договором жизненного
цикла. `permitId` имеет единственную форму `lp2_` плюс 32 строчных
шестнадцатеричных знака. Для нового запуска это 16 криптографически случайных
байт. Для перенесённой попытки вычисляется

```text
SHA256(UTF8("codex-smart/legacy-launch-permit/v2") || 0x00 ||
       canonical-json-v1({sourceBackupSha256,attemptId}))
```

и берутся первые 16 байт 32-байтового результата в сетевом порядке. Они
кодируются 32 строчными шестнадцатеричными знаками после `lp2_`. Если такой
идентификатор уже принадлежит иному каноническому объекту, перенос закрыто
останавливается с `LEGACY_PERMIT_ID_COLLISION`: исторический идентификатор не
перегенерируется и не замещается.
`databaseId` имеет форму `db2_` плюс 32 строчных шестнадцатеричных
знака, полученных из криптографически случайных 16 байт; совпадение вызывает
новую генерацию до создания каталога.

Значения SQLite:

- `application_id = 1129529650` (`0x43534132`);
- старая база: `user_version = 1`;
- новая база: `user_version = 2`;
- `foreign_keys = ON`, `trusted_schema = OFF`, `synchronous = FULL`,
  `secure_delete = FAST`, `busy_timeout = 5000`;
- рабочий контроллер версии 2 после принятия базы использует `journal_mode =
  WAL`;
- распознавание и перенос не переводят исходную базу в WAL и не применяют
  `immutable=1`, пока рядом могут существовать действующие `-wal` и `-shm`.

Перечисления ниже закрыты. Новое значение требует новой версии договора.
Регистр, дефисы и подчёркивания значимы.

## Единственная нормативная схема

После реализации единственным источником схемы служит файл:

```text
plugins/codex-smart-subagents/src/codex_smart_subagents/schema/state-v2.sql
```

Это один файл UTF-8 без сигнатуры, с переводами строк LF и завершающим
переводом строки. Он не содержит комментариев, `IF NOT EXISTS`, триггеров,
динамических подстановок, `ATTACH`, `VACUUM`, `PRAGMA journal_mode` или
пользовательских функций. Создание новой базы и миграция исполняют одни и те
же байты этого файла. Копии выражений `CREATE TABLE` и `CREATE INDEX` в
`store.py`, установщике или тестах запрещены.

Рядом хранится машинный манифест схемы с:

- `schemaVersion=2`;
- SHA-256 самого `state-v2.sql`;
- итоговым отпечатком схемы версии 2;
- 19 разрешёнными отпечатками рабочих и аварийных форм `user_version=1` и
  19 отпечатками пустых незавершённых форм `user_version=0`;
- полными исходными коммитами для воспроизводимых эталонов;
- версией алгоритма проекции и нормализации.

Сборка создаёт пустую базу из нормативного файла, повторно вычисляет её
проекцию и сравнивает с манифестом. Любое расхождение останавливает сборку и
установку.

## Проекция и отпечаток схемы

### Безопасное открытие

Проверяющий процесс сначала открывает путь и каждый родительский каталог без
перехода по символическим ссылкам, проверяет владельца и режимы, затем
удерживает файловый дескриптор. Исходная база версии 1 открывается только для
чтения штатным режимом SQLite. Если существуют `-wal` или `-shm`, SQLite
должен видеть их по исходному имени; запрет записи обеспечивается правами и
режимом подключения, а не ложным обещанием `immutable=1`.

До чтения пользовательских строк обязательно выполняются:

```text
PRAGMA quick_check;          -> ровно одна строка "ok"
PRAGMA foreign_key_check;    -> ноль строк
PRAGMA application_id;       -> 1129529650
PRAGMA user_version;         -> 1 или 2 согласно ожидаемой версии
```

Ошибка, занятость, лишняя строка или неизвестный внутренний объект закрывают
проверку.

### Каноническая проекция

Корень содержит только следующие поля и JSON-типы. Числовые признаки остаются
целыми `0` или `1`, а не превращаются в логические значения:

```text
{
  "applicationId": integer,
  "userVersion": integer,
  "sqliteSchema": [
    {"type": string, "name": string, "table": string,
     "sql": string | null}
  ],
  "tableXinfo": [
    {"table": string, "cid": integer, "name": string, "type": string,
     "notNull": integer, "defaultValue": string | null,
     "primaryKey": integer, "hidden": integer}
  ],
  "foreignKeyList": [
    {"table": string, "id": integer, "sequence": integer,
     "referencedTable": string, "from": string, "to": string | null,
     "onUpdate": string, "onDelete": string, "match": string}
  ],
  "indexList": [
    {"table": string, "name": string, "unique": integer,
     "origin": string, "partial": integer}
  ],
  "indexXinfo": [
    {"table": string, "index": string, "sequence": integer,
     "columnId": integer, "columnName": string | null,
     "descending": integer, "collation": string | null, "key": integer}
  ],
  "sqliteSequencePresent": boolean
}
```

Проекция строится так:

1. `sqliteSchema` включает все строки `sqlite_schema`, в том числе
   автоматические индексы и `sqlite_sequence`, и сортируется по байтам UTF-8
   `(type,name,table)`. Исходный SQL-нуль автоматического индекса остаётся
   JSON `null`.
2. `tableXinfo` включает `PRAGMA table_xinfo` для каждой строки
   `sqlite_schema` с `type='table'`, в том числе `sqlite_sequence`, и
   сортируется по `(table UTF-8,cid)`.
3. `foreignKeyList` включает полный `PRAGMA foreign_key_list` каждой таблицы
   и сортируется по `(table UTF-8,id,sequence)`.
4. `indexList` включает `PRAGMA index_list` каждой таблицы, отбрасывает только
   нестабильное поле `seq` и сортируется по `(table UTF-8,name UTF-8)`.
5. `indexXinfo` включает полный `PRAGMA index_xinfo` каждого индекса и
   сортируется по `(table UTF-8,index UTF-8,sequence)`.
6. Значения `dflt_value`, имена столбцов, действия внешних ключей, правила
   сопоставления, сортировки и параметры индексов не преобразуются; SQL-нуль
   становится JSON `null`.
7. `sqliteSequencePresent` фиксирует наличие таблицы `sqlite_sequence`, но
   содержимое её строк в отпечаток не входит. Виды и триггеры не разрешены ни
   одной входной формой.

Поле `sql` нормализуется единственным конечным автоматом:

- CRLF заменяется LF; одиночный CR далее обрабатывается как ASCII-пробел;
- вне строк в одинарных кавычках, двойных кавычках, обратных кавычках и
  квадратных идентификаторов последовательность ASCII-пробелов `0x09–0x0D`
  и `0x20` заменяется одним пробелом;
- пробелы в начале и конце удаляются;
- экранирование удвоением закрывающего знака сохраняется побайтно;
- содержимое, регистр, порядок лексем и пробелы внутри кавычек не меняются;
- `--` и `/* ... */` вне кавычек запрещены, а не удаляются.

К объекту применяется `canonical-json-v1` из
[договора интерфейса](codex-interface-v1.md), затем:

```text
SHA256(UTF8("codex-smart/database-schema/v1") || 0x00 || canonical-json-v1(projection))
```

Для схемы 2 домен равен `codex-smart/database-schema/v2`, а
`userVersion=2`. Реализации нормализации на Python и в проверочном генераторе
должны проходить один общий набор положительных и отрицательных векторов.

## Допустимые законченные и аварийные формы

Старый код открывал соединение с `isolation_level=None`. Его `executescript()`
снимал внешний `BEGIN IMMEDIATE`, поэтому потеря питания могла долговечно
оставить любой префикс группы `CREATE TABLE`/`CREATE INDEX`. Разрешать только
шесть удобных конечных снимков было бы потерей настоящих баз. Мигратор знает
ровно 38 воспроизведённых форм: 19 с `user_version=1` и 19 с
`user_version=0`. Пустой файл с `application_id=0` неразличим с чужой базой и
не принимается.

Базовая последовательность объектов обозначена так:

```text
B1 turn_bindings
B2 routes
B3 nodes
B4 events + неявная sqlite_sequence
B5 events_route_sequence
B6 intents
B7 leases
B8 attempts
B9 attempts_route_started
```

Форма `pN` содержит `B1…BN` и не содержит оставшийся суффикс. Все 19 форм
`user_version=0` являются только незавершённой пустой установкой:

| Имя | Отпечаток |
|---|---|
| `v0-empty` | `88f3b204cadff521675bebf66beb1878456608602fa4ad35f2b593f82a16d55e` |
| `v0-old-base-p1` | `f9c0f11d0540549378fc7068ce06fa5cd545fda49893e13ca21682f3a5ca16f7` |
| `v0-old-base-p2` | `79c03c108fd832f6c102a455f6a9be9211baeea557d79db0c81a033f3ecc5d4a` |
| `v0-old-base-p3` | `416d7051caf3f3529e5f5148870bbc2291949b4166a543e480a7f123997970b1` |
| `v0-old-base-p4` | `743e520cdf49f709400627aacbf16dfb996241cb996eb8d6ba13bc8f28ffc3fd` |
| `v0-old-base-p5` | `cb627ee60b26dcded25aa30e8664b8a74b491358cb7798f5e8483b82b383eb45` |
| `v0-old-base-p6` | `bc0fe1e8e09bd0cbe41d6e5b105532515695500556c5ea78bd7f18df5b5922a8` |
| `v0-old-base-p7` | `0affc5b3eb92812d8f79aad379aaefa7b6a7bd703f4416883f303bcb26bc37fc` |
| `v0-old-base-p8` | `0c33208df6ded0d62cbde48a72fa6ae9b4b761df2b1a0b0821cf395218872e3a` |
| `v0-old-base-p9` | `056368aea93b1062c5b9fe651f7d859030def080f2c40a3b1cf469d1120a4ada` |
| `v0-new-base-p1` | `9f8a4f58e2e2e440a128560c4a5930bb58b09d197f08dd1c2e822f4126baed7c` |
| `v0-new-base-p2` | `f4155808281e7b13e30a0d065dd127326292f89792f5f2f88b1afd6b65156819` |
| `v0-new-base-p3` | `7cdc0f3d8741fb2516c72efc6906246fb2044058ae984f2ddb7444eba2f4de45` |
| `v0-new-base-p4` | `132ef6f7978caff66dad8c23bb9ae3597d7264e66be52727a3916cb91fda3896` |
| `v0-new-base-p5` | `84cc55d4379fa3f070555fdd53308c2d39eb83579b146f925ae114ed03a1fb29` |
| `v0-new-base-p6` | `7b61bef97ef0f49d69bc97d60c7d20c1504afd6843072a955f42133a772da99b` |
| `v0-new-base-p7` | `6283a055f0e9e0ce4dc8f7cce9eae14f580d4acd7fd3aafb4e691ce2e2b31c17` |
| `v0-new-base-p8` | `091202ea7e98e90b47991c83a4e230cdd343394f99fe7421da354307bd145de9` |
| `v0-new-base-p9` | `0e6554319aa3d3c882e825713b5a03a61683471fd3f2bb00fd54a4c3b5af60a1` |

Каждая существующая прикладная таблица и `sqlite_sequence` такой формы
обязана быть пустой; путь, владелец, старый корень и происхождение обязаны
совпасть с журналом; посторонний объект запрещён. Иная строка даёт
`LEGACY_PARTIAL_SCHEMA_HAS_DATA`. Исходник не дополняется: создаётся чистая
база 2, а пустой старый файл архивируется.

После базовой группы код добавлял:

```text
R1 runtime_artifacts
R2 runtime_artifacts_route
C1 quarantine_repositories
C2 candidate_publication_intents
C3 candidate_intents_state
C4 candidate_registry
C5 candidate_registry_route
```

Ровно 19 мигрируемых форм `user_version=1`:

| Имя | Отпечаток | Условие данных |
|---|---|---|
| `execution-v1` | `ddd502469ab1c0ec513cd6e3d0673cd7ab30ea6071a7daf29432d2f7c3042b35` | данные допустимы; нет binding, R, C |
| `execution-alter-binding-v1` | `f54a699f426ca4fbec314feee4765950dbd3b933a1eb8c9d0557ae675653c637` | данные допустимы; нет R, C |
| `artifacts-table-only-v1` | `af55b0279ffd185a33683305ea6f249cf2a626849043732b804ead8a44fea11b` | R1 обязана быть пуста; нет R2, C |
| `artifacts-v1` | `660f25fea873615b3ac507fffa969761d7bd1080579127e411aaaf0d2f650904` | данные допустимы; есть R1–R2, нет C |
| `artifacts-table-only-alter-binding-v1` | `7c8a6dd4c92f3ac7b2332301031d4fd2b2607a4953bb09daab5f74323afbc1b4` | R1 обязана быть пуста; нет R2, C |
| `artifacts-alter-binding-v1` | `fa1fdf8a1a0f54c2018fbef4762570bda6f1c72757d2719b259866367f89882d` | данные допустимы; есть R1–R2, нет C |
| `new-base-embedded-binding-v1` | `12a47fe9c577f89f9c95d7f8722977b8fd3540f93ef3f2c1044ef99ef1036a06` | вся прикладная база пуста |
| `new-runtime-table-only-embedded-binding-v1` | `44015016f581105606faa13c4a385b9e3dcf9d8799c93f4d1cfa85236e1898cb` | вся прикладная база пуста |
| `new-runtime-embedded-binding-v1` | `e7c00704c21420e10066ea28bf8ca42146bb4f46c45eeb62d71d0c5de61b26c0` | вся прикладная база пуста |
| `candidate-alter-p1` | `a31c9181b4d9045c06d988c89988ba92f4e6e511059aabf9e0baf58c6405d936` | существующая группа C пуста |
| `candidate-alter-p2` | `4e2eaa53062aace794be8f5e87796193d654284793cace02cfc00cf83ec60dcb` | существующая группа C пуста |
| `candidate-alter-p3` | `81e3b2b864b4363587db07f3330a57bc9b9efd8059f0096090edfd06b7c6a122` | существующая группа C пуста |
| `candidate-alter-p4` | `e8f58eac2e7383afa4c381b84a36982fedf804d59cee2d204e4f0aeda07df4f5` | существующая группа C пуста |
| `candidate-alter-p5` | `bdacdbc4ce27b98edbbd3bb3c035e1927a081c00990093888373db630717f498` | полноценная форма; данные допустимы при покое |
| `candidate-embedded-p1` | `1d72cb917d18a83d6c994e196ee92dd6d2cb500db92e4e55bed3c47d51d5cd52` | вся прикладная база пуста |
| `candidate-embedded-p2` | `54d6abc9bab55c9f822a0dc8877886e23b33587d19b460cb598ebc5cf1a2b129` | вся прикладная база пуста |
| `candidate-embedded-p3` | `ecc8d5237dccfc1baa740238d07db4ce45f430ebf9c14a4d477477e1f1886c96` | вся прикладная база пуста |
| `candidate-embedded-p4` | `3fdd5eae038ddb977485e332b465bc941eba1e0091a9bab1b4e7eb0036e82000` | вся прикладная база пуста |
| `candidate-embedded-p5` | `a65cc307783faf71a9e0eaabd12889c129c1be5ee8c4de4947149ad8bab7b36c` | полноценная форма; данные допустимы при покое |

Формы с `ALTER` и встроенными полями различаются текстом SQL намеренно.
`execution-alter-binding-v1` и `artifacts-alter-binding-v1` происходят из
аварийных промежуточных состояний цепочки `45bab…`, а не являются законченным
результатом ранних коммитов. Шесть ранее опубликованных отпечатков и их
канонические размеры `20762`, `21054`, `24595`, `24887`, `41648`, `41648`
байт остаются подтверждёнными; машинный манифест дополнительно хранит размер,
происхождение, отсутствующие объекты и предикат пустоты всех 38 форм.

Имя формы выбирается только по полному отпечатку. Непустая незавершённая
группа, недостающий неразрешённый объект, дополнительный индекс, изменённый
`CHECK`, пользовательский триггер или вид дают
`LEGACY_PARTIAL_SCHEMA_HAS_DATA` либо `UNKNOWN_V1_SCHEMA`; эвристическое
достраивание на месте запрещено.

## Изменения существующих таблиц

Схема 2 сохраняет смысловые поля формы `rollout-v1` и добавляет следующие
обязательные столбцы. Все ссылки проверяются при каждой записи внутри одной
`BEGIN IMMEDIATE`.

### `turn_bindings`

Добавляются:

- `activation_fingerprint TEXT NOT NULL`;
- `compatibility_fingerprint TEXT NOT NULL`;
- `account_context_fingerprint TEXT NOT NULL`;
- `issued_control_epoch INTEGER NOT NULL
  CHECK(issued_control_epoch BETWEEN 0 AND 9007199254740991)`.

Эти значения входят в канонический `context_json` и `context_hash`. Токен,
созданный при другой активации, совместимости, учётной среде или эпохе, не
потребляется.

Строгий `request-context-v2` имеет ровно поля `schemaVersion=2`,
`shellSessionId`, `sessionId`, `turnId`, `codexHome`, `repoRoot`, `baseSha`,
`worktreeFingerprint`, `activationFingerprint`,
`compatibilityFingerprint`, `accountContextFingerprint`,
`issuedControlEpoch`. Все строки непусты и ограничены 4096 байт; отпечатки —
64 hex, эпоха — целое от 0 до 9007199254740991. Ноль допустим только в
перенесённой уже потреблённой привязке версии 1 и никогда не принимается
живым контроллером версии 2. `context_json` является
`canonical-json-v1` этого объекта. `context_hash` использует домен
`codex-smart/request-context/v2` и проекцию, где `codexHome` и `repoRoot`
заменены их SHA-256, а остальные поля сохранены. `routes.context_json` и
`turn_bindings.context_json` одного запроса перестраиваются одновременно и
обязаны иметь одинаковые байты и хеш.

### `routes`

Добавляются:

- `activation_fingerprint TEXT NOT NULL`;
- `compatibility_fingerprint TEXT NOT NULL`;
- `account_catalog_fingerprint TEXT NOT NULL`;
- `account_context_fingerprint TEXT NOT NULL`;
- `UNIQUE(route_id,activation_fingerprint,account_context_fingerprint)`.

Маршрут не хранит отдельную текущую контрольную эпоху: исторический
`issuedControlEpoch` внутри контекста доказывает момент выдачи привязки, но
последующие `drain/resume` не делают поставленный маршрут структурно
устаревшим. Действующая эпоха заново фиксируется на границе запуска узла.

### Единый `activationGate`

Закрытый объект шлюза имеет поля ровно в таком порядке:

```text
{
  manifestSemanticFingerprint,
  activationReceiptFingerprint,
  journalAbsenceProof,
  gateFingerprint
}
```

`journalAbsenceProof` является полной проекцией
`lifecycle-projection-v2` со `schemaId=absence-proof-v2`, включая
`schemaSha256`, весь `value` и `valueFingerprint`. Его
`directorySyncCompleted` равен `true`; наблюдение отсутствия до синхронизации
не принимается. `gateFingerprint` вычисляется единственной нормативной
областью реестра жизненного цикла:

```text
projection = {
  manifestSemanticFingerprint,
  activationReceiptFingerprint,
  journalAbsenceProof
}
gateFingerprint =
  SHA256(UTF8("codex-smart/activation-gate/v2") || 0x00 ||
         canonical-json-v1(projection))
```

Из проекции исключён только собственный `gateFingerprint`. Сокращённая копия
с одним `proofFingerprint`, иной порядок полей, иной домен или добавочное
поле запрещены. `smart_start`, `reserve_launch_permit` и
`commit_launch_permit` принимают побайтно одинаковый после
`canonical-json-v1` объект целиком и на каждом рубеже независимо перестраивают
его из фактического манифеста, неизменяемой квитанции и нового
синхронизированного доказательства отсутствия основного журнала.

Свежесть означает новую дескрипторную проверку тех же путей и повторную
синхронизационную сверку, а не выдачу нового `proofId`. Шлюз использует
устойчивую идентичность доказательства, связанную с последней положительной
квитанцией активации, повторно строит все `entries` и проверяет, что
канонические байты остались прежними. Поэтому свежая проверка совместима с
обязательным побайтным равенством трёх запросов; изменение пути, родительского
inode, операции или любого другого поля закрывает допуск.

### `nodes`

Добавляются:

- `activation_fingerprint TEXT NOT NULL`;
- `account_context_fingerprint TEXT NOT NULL`;
- `account_catalog_fingerprint TEXT NOT NULL`;
- `admission_id TEXT`, уникальный `adm2_` плюс 32 строчных hex только в состояниях
  `ATTESTING` и последующих состояниях запуска;
- `admission_state TEXT`, одно из `ATTESTING`, `RESERVED`, `GUARDED`,
  `COMMIT_AUTHORIZED`, `STARTED`, `STALE`, `ABORTED`, либо `NULL` до допуска;
- `admission_manifest_semantic_fingerprint TEXT`;
- `admission_activation_receipt_fingerprint TEXT`;
- `admission_journal_absence_proof_json TEXT`;
- `admission_gate_fingerprint TEXT`;
- составной внешний ключ
  `(route_id,activation_fingerprint,account_context_fingerprint)` на
  одноимённую уникальную тройку `routes`.

Выбранные `selected_model`, `reasoning_effort` и `permission_profile_id`
остаются обязательными и неизменяемыми после допуска узла.
`admission_journal_absence_proof_json` является каноническим JSON полной
проекции `lifecycle-projection-v2` со `schemaId=absence-proof-v2`, а не
одиночным отпечатком. Четыре поля шлюза одновременно равны `NULL` до допуска
и одновременно ненулевые начиная с `ATTESTING`. Вместе они побайтно
восстанавливают `activationGate`, принятый `smart_start`; один
`admission_gate_fingerprint` не считается доказательством. Закрытая ссылка
из разрешения запуска и попытки обязана приводить к тем же компонентам.

### `leases`

Добавляются:

- `activation_fingerprint TEXT NOT NULL`;
- `acquired_control_epoch INTEGER NOT NULL
  CHECK(acquired_control_epoch BETWEEN 1 AND 9007199254740991)`.

Новая аренда возможна только при совпавшей активации и состоянии контроллера
`ACCEPTING`. Смена эпохи не завершает уже запущенный процесс, но запрещает
продление аренды без успешной сверки с текущим контроллером.

### `attempts`

Добавляются:

- `launch_permit_id TEXT NOT NULL UNIQUE`;
- `activation_fingerprint TEXT NOT NULL`;
- `account_context_fingerprint TEXT NOT NULL`;
- `account_catalog_fingerprint TEXT NOT NULL`;
- `launch_control_epoch INTEGER NOT NULL
  CHECK(launch_control_epoch BETWEEN 0 AND 9007199254740991)`;
- `controller_identity TEXT NOT NULL`, `controller_instance_id TEXT NOT NULL`;
- `evidence_kind TEXT NOT NULL` из `V2_ATTESTED`, `V1_LEGACY`;
- `codex_binary_sha256 TEXT`;
- `codex_snapshot_sha256 TEXT`;
- `compatibility_fingerprint TEXT NOT NULL`;
- `model TEXT NOT NULL`, `reasoning_effort TEXT NOT NULL`;
- `permission_profile_id TEXT NOT NULL`, `argv_fingerprint TEXT NOT NULL`;
- `snapshot_identity_fingerprint TEXT`;
- `permit_evidence_fingerprint TEXT NOT NULL`;
- `admission_id TEXT`;
- `manifest_semantic_fingerprint TEXT`;
- `activation_receipt_fingerprint TEXT`;
- `journal_absence_proof_json TEXT`;
- `activation_gate_fingerprint TEXT`;
- `process_start_marker TEXT`.

Для `V2_ATTESTED` `compatibility_fingerprint` обязан равняться
`compatibilityFingerprint` из `InterfaceEvidence`, а
`permit_evidence_fingerprint` вычисляется доменом
`codex-smart/permit-evidence/v2` от точного объекта
`{permitId,routeId,nodeId,admissionId,activationFingerprint,
accountContextFingerprint,accountCatalogFingerprint,
controllerIdentity,controllerInstanceId,reservedControlEpoch,model,
reasoningEffort,permissionProfileId,argvFingerprint,
compatibilityFingerprint,codexSnapshotSha256,snapshotIdentityFingerprint,
manifestSemanticFingerprint,activationReceiptFingerprint,
journalAbsenceProof,activationGateFingerprint}`. `journalAbsenceProof` здесь
является полной канонической проекцией, а не одним `proofFingerprint`. Этот
объект записывается в разрешение и попытку уже с точным
`snapshotIdentityFingerprint` из того же снимка, который подтверждает сторож
и передаёт `commit_launch_permit`. Разрешение имеет
`UNIQUE(permit_id,permit_evidence_fingerprint,snapshot_identity_fingerprint)`,
а попытка — составной внешний ключ из своих `launch_permit_id`,
`permit_evidence_fingerprint` и `snapshot_identity_fingerprint` на эту тройку.
Отдельный точный внешний ключ
`attempts(launch_permit_id,pid,process_start_marker)` ссылается на
`node_launch_permits(permit_id,pid,start_marker)` и связывает процесс попытки
с процессом разрешения, а не только с его идентификатором.
Дополнительный полный составной внешний ключ связывает попытку с теми же
`admission_id`, маршрутом, узлом, активацией, учётной средой, эпохой, моделью,
уровнем рассуждения, профилем, аргументами, `codex_snapshot_sha256`,
`snapshot_identity_fingerprint` и всеми компонентами шлюза разрешения.
`doctor` независимо пересчитывает отпечаток, сравнивает снимок разрешения с
кадром `HELLO`, запросом `commit_launch_permit` и попыткой и побайтно сравнивает
канонические проекции из трёх строк. Он также повторно проверяет точное
равенство `attempts.pid`, `node_launch_permits.pid` и `guard_pid`, а также
равенство `attempts.process_start_marker`,
`node_launch_permits.start_marker` и `guard_start_marker`. Поэтому замена Luna
на Sol, уровня, профиля, аргументов, совместимости, содержимого или
идентичности снимка, PID, маркера либо одного доказательства шлюза не проходит
даже при том же маршруте.

Для `V2_ATTESTED` все перечисленные поля, включая
`snapshot_identity_fingerprint`, обязательны. Для `V1_LEGACY`
`admission_id` и четыре поля шлюза равны `NULL`: поддельное доказательство
активации для исторического запуска не создаётся, а неизвестная историческая
эпоха представляется единственным значением `launch_control_epoch=0`.
`permit_evidence_fingerprint` такой строки равен полному 32-байтовому
результату той же формулы `codex-smart/legacy-launch-permit/v2`, первые 16
байт которой образуют `permit_id`; это аудиторская связь с исходной резервной
копией и попыткой, а не аттестация запуска версии 2. В состоянии попытки
`STARTING` её `pid` и маркер равны данным сторожа и разрешение находится в
`COMMIT_AUTHORIZED`; после успешного `exec` попытка становится `RUNNING`, а
разрешение — `STARTED`. Локальные формы каждой строки ограничиваются SQL
`CHECK`, а равенство данных разных строк проверяется кодом внутри той же
`BEGIN IMMEDIATE`, составными внешними ключами там, где SQLite позволяет их
выразить, и независимо `doctor`. Для `V1_LEGACY`
попытка обязана быть терминальной; неизвестные новые отпечатки получают
исторический маркер, фактические старые модель и уровень сохраняются,
`codex_binary_sha256`, `codex_snapshot_sha256`,
`snapshot_identity_fingerprint` и
`process_start_marker` равны `NULL`. Историческая строка связывается с
разрешением отдельной парой исходной резервной копии и прежней попытки, а не
составным ключом аттестованного снимка версии 2. Такая строка доступна только
для аудита и не является аттестацией запуска версии 2.

Остальные таблицы версии 1 сохраняют поля и ограничения без ослабления.
Никакой столбец версии 1 не удаляется и не меняет смысл скрыто.

## Новые таблицы версии 2

### `database_identity`

Ровно одна строка:

| Поле | Ограничение |
|---|---|
| `singleton` | `INTEGER PRIMARY KEY CHECK(singleton=1)` |
| `database_id` | `TEXT NOT NULL UNIQUE`, форма `db2_` + 32 hex |
| `schema_version` | `INTEGER NOT NULL CHECK(schema_version=2)` |
| `schema_fingerprint` | `TEXT NOT NULL`, 64 hex |
| `schema_artifact_sha256` | `TEXT NOT NULL`, 64 hex |
| `activation_binding_nonce` | `TEXT NOT NULL`, 64 hex случайных 32 байт |
| `activation_id` | `TEXT NOT NULL UNIQUE`, `act2_` + 64 hex |
| `activation_fingerprint` | `TEXT NOT NULL UNIQUE`, 64 hex |
| `source_shape` | одно из 38 имён формы либо `fresh-v2` |
| `source_schema_fingerprint` | `TEXT`, 64 hex либо `NULL` |
| `source_backup_sha256` | `TEXT`, 64 hex либо `NULL` |
| `created_operation_id` | `TEXT NOT NULL` |
| `created_at` | `TEXT NOT NULL` |

Для `fresh-v2` оба поля источника равны `NULL`; для миграции оба обязательны.
`schema_fingerprint` равен отпечатку уже созданной базы, а
`schema_artifact_sha256` — байтам нормативного SQL. Строка вставляется уже с
вычисленными `activation_id` и `activation_fingerprint`, до публикации базы;
пути её изменения в рабочем коде нет. Открытие требует точного совпадения
этих трёх полей и `activation_binding_nonce` с активацией. Повторное связывание
существующего `database_id` с другой активацией запрещено.

### Полные проекции базы и покоя

Любой журнал, квитанция или долговечный объект жизненного цикла, который
утверждает состояние базы версии 2, хранит полную закрытую проекцию
`lifecycle-projection-v2` со `schemaId=database-object-v2`. Её `value`
содержит ровно:

- путь, устройство, inode, владельца, группу, режим, `linkCount=1`, размер и
  SHA-256 файла;
- `databaseId`, полный объект `databaseIdentity` и его отпечаток;
- полную привязку `activationIdentity`;
- `databaseVersion=0.2.0`, `schemaVersion=2`, `userVersion=2`, отпечатки
  схемы и нормативного SQL;
- именованные `sidecars.wal` и `sidecars.shm`, каждый как полный файл либо
  доказанное отсутствие;
- резервную копию как полный файл либо доказанное отсутствие.

Голый `databaseId`, SHA-256 файла, `valueFingerprint` или путь не заменяет эту
проекцию. Полная проекция не хранится внутри того же файла SQLite, чей SHA-256
она содержит: это создало бы саморекурсивный отпечаток. Нельзя хранить в этой
базе и производный от внешней проекции отпечаток либо полную файловую
идентичность её носителя: внешний объект содержит SHA-256 базы, поэтому такая
обратная зависимость создала бы взаимный цикл двух объектов. Внешний журнал, а
после принятия неизменяемая квитанция активации, хранит проекцию целиком и
связывает её с теми же `operationId` и `databaseId`. Строка базы сохраняет
только логический указатель, вычисляемый из этих двух независимых от содержимого
идентификаторов, и постоянный `schemaId=database-object-v2`. Указатель сам не
доказывает целостность: исполнитель разрешает его во внешнем носителе,
проверяет его операцию и базу, затем сверяет полную проекцию с фактической
базой.

Доказательство покоя, напротив, может храниться в базе как канонический JSON
полной проекции `lifecycle-projection-v2` со
`schemaId=quiescence-proof-v2`, включая `schemaSha256`, `value` и
`valueFingerprint`. Вариант `runtime-v2` содержит
`controllerIdentity`, `instanceId`, `controlEpoch`, точные восемь нулевых
счётчиков `workCounts`, `databasePredicatesFingerprint`,
`barrierHeld=true`, `quiescent=true`. Вариант `legacy-migration` содержит
`legacyStateHome`, отпечаток полного множества старых процессов, точный
целевой процесс, вооружённого сторожа, доказательства ограждений шлюза и
моста, полный неизменяемый снимок файла базы, отпечатки идентичности базы и
снимка, доказательства исключительной аренды и внешнего барьера, те же восемь
нулевых счётчиков и `quiescent=true`. Удаление любого поля или замена всей
проекции её итоговым отпечатком закрывает операцию.

### `controller_state`

Ровно одна строка:

| Поле | Ограничение |
|---|---|
| `singleton` | `INTEGER PRIMARY KEY CHECK(singleton=1)` |
| `database_id` | внешний ключ на `database_identity(database_id)` |
| `protocol_version` | `INTEGER NOT NULL CHECK(protocol_version=2)` |
| `release` | `TEXT NOT NULL CHECK(release='0.2.0')` |
| `controller_identity` | `TEXT NOT NULL`, 64 hex |
| `instance_id` | `TEXT`, `ci2_` + 32 hex; `NULL` только в служебной форме до принятия |
| `controller_start_id` | `TEXT`, `cs2_` + 32 hex; `NULL` только в служебной форме до принятия |
| `controller_pid` | положительный `INTEGER`; `NULL` только в служебной форме до принятия |
| `controller_process_start_marker` | непустой `TEXT`; `NULL` только в служебной форме до принятия |
| `controller_process_group_id` | положительный `INTEGER`; `NULL` только в служебной форме до принятия |
| `control_epoch` | `INTEGER NOT NULL CHECK(control_epoch BETWEEN 1 AND 9007199254740991)` |
| `state` | `ACCEPTING`, `DRAINING`, `MAINTENANCE` или `STOPPED` |
| `maintenance_mode` | `TEXT NOT NULL`: `NONE`, `DRAIN` или `FREEZE` |
| `reason_code` | `TEXT NOT NULL` |
| `operation_id` | `TEXT`, `op2_` + 32 hex либо `NULL` |
| `activation_id` | `TEXT NOT NULL` |
| `activation_fingerprint` | `TEXT NOT NULL`, 64 hex |
| `compatibility_fingerprint` | `TEXT NOT NULL`, 64 hex |
| `routing_policy_fingerprint` | `TEXT NOT NULL`, 64 hex |
| `bundled_catalog_fingerprint` | `TEXT NOT NULL`, 64 hex |
| `socket_path` | абсолютный путь либо `NULL` |
| `socket_device`, `socket_inode` | неотрицательные целые либо `NULL` |
| `socket_owner_uid`, `socket_owner_gid` | неотрицательные целые либо `NULL` |
| `socket_mode` | строка `0[0-7]{3}` либо `NULL` |
| `lock_held` | `INTEGER NOT NULL CHECK(lock_held IN (0,1))` |
| `accepting_new_routes` | `INTEGER NOT NULL CHECK(accepting_new_routes IN (0,1))` |
| `quiescent` | `INTEGER NOT NULL CHECK(quiescent IN (0,1))` |
| `updated_at` | `TEXT NOT NULL` |

Отдельная служебная форма ещё не опубликованной базы использует
`state=MAINTENANCE`, `maintenance_mode=FREEZE`, непустой установочный
`operation_id`, `control_epoch=1`, пустые идентификаторы процесса и сокета,
`lock_held=0`, `accepting_new_routes=0`, `quiescent=1` и
`reason_code=AWAITING_CONTROLLER_ACCEPT`. Она не является
`controller-state-v2`, не публикуется в манифесте, не отвечает на рабочий
`health` и может перейти только через `controller_accept` той же операции в
живую `MAINTENANCE`. Поэтому защищённый перенос может вставить строку
`controller_state` в `MAINTENANCE`, а живая форма и запросы протокола никогда
не ослабляются до эпохи ноль.

Остальные строки образуют точную проекцию `controller-state-v2`. Их закрытые
сочетания:

- `ACCEPTING` означает `maintenance_mode=NONE`, `operation_id IS NULL`,
  непустые поля экземпляра, процесса и сокета, `lock_held=1`,
  `accepting_new_routes=1` и `reason_code=NONE`;
- `DRAINING` означает `maintenance_mode=DRAIN`, непустой `operation_id`,
  живые поля процесса и сокета, `lock_held=1` и
  `accepting_new_routes=0`;
- живая `MAINTENANCE` означает `maintenance_mode IN (DRAIN,FREEZE)`,
  непустой `operation_id`, живые поля процесса и сокета, `lock_held=1` и
  `accepting_new_routes=0`; единственное исключение — описанная выше
  непубликуемая служебная форма до `controller_accept`;
- `STOPPED` означает `maintenance_mode=NONE`, `operation_id IS NULL`, все
  поля сокета равны `NULL`, `lock_held=0`, `accepting_new_routes=0`,
  `quiescent=1`; прежние `instance_id`, `controller_start_id`, PID, маркер и
  группа процесса сохраняются для аудита и сверки с неизменяемым намерением
  остановки;
- ровно `maintenance_begin`, `maintenance_strengthen`, `shutdown`,
  `controller_accept`, `controller_recover` и `maintenance_resume` всегда
  повышают `control_epoch` ровно на один и в той же `BEGIN IMMEDIATE` пишут
  связанную долговечную квитанцию команды; исходная эпоха такой команды не
  превышает 9007199254740990, а при достигнутом пределе 9007199254740991
  команда закрывается без изменения и без квитанции;
- `maintenance_status`, `smart_start`, `smart_status`,
  `reserve_launch_permit` и `commit_launch_permit` эпоху не меняют и
  квитанцию управляющей команды не создают;
- строка живой формы не доказывает живость сама по себе: сокет и маркер
  процесса должны совпасть с `controller_identity` и `instance_id`;
  `STOPPED` проверяется как историческая форма и не объявляется живым.

При построении `controller-state-v2` и ответа здоровья база отображает
`NONE → null`, `DRAIN → drain`, `FREEZE → freeze`. Это единственное
преобразование регистра и пустого режима; служебная форма до принятия в
проекцию не попадает.

Простые `CHECK` ограничивают значения и локальные сочетания одной строки.
Равенство с активацией, фактическим сокетом, процессом, квитанцией и строками
других таблиц проверяется кодом в той же транзакции, затем независимо
`doctor` и проверочными векторами; обычный SQLite `CHECK` не выдаётся за
межстрочное или файловое доказательство.

### `controller_command_receipts`

Таблица содержит:

- `command_id TEXT PRIMARY KEY`, форма `cc2_` + 32 hex;
- `operation_id TEXT NOT NULL`;
- `method TEXT NOT NULL` из `maintenance_begin`, `maintenance_strengthen`,
  `shutdown`, `controller_accept`, `controller_recover`,
  `maintenance_resume`;
- `request_fingerprint TEXT NOT NULL`;
- `result_fingerprint TEXT NOT NULL`;
- `response_json TEXT NOT NULL`;
- `response_fingerprint TEXT NOT NULL`;
- `controller_identity TEXT NOT NULL`;
- `before_instance_id TEXT`;
- `resulting_instance_id TEXT`;
- `quiescence_proof_json TEXT`;
- `socket_intent_json TEXT`;
- `before_epoch INTEGER NOT NULL
  CHECK(before_epoch BETWEEN 1 AND 9007199254740990)`;
- `after_epoch INTEGER NOT NULL
  CHECK(after_epoch BETWEEN 2 AND 9007199254740991
  AND after_epoch=before_epoch+1)`;
- `created_at TEXT NOT NULL`.

`response_json` — канонический строгий ответ протокола, а
`result_fingerprint` использует единственную область
`controllerCommandResult` реестра жизненного цикла и не включает собственную
квитанцию или отпечаток ответа; возникающего рекурсивного хеша нет. Для
`shutdown` `quiescence_proof_json` обязателен и
является полной проекцией `quiescence-proof-v2` варианта `runtime-v2` той же
идентичности контроллера, экземпляра и `before_epoch`, снятой при удерживаемой
исключительной стороне барьера запуска. `operation_id` квитанции и запроса
совпадает с операцией живой формы `MAINTENANCE/FREEZE`. Для него же
`socket_intent_json` является каноническим неизменяемым `socketIntent` из
смыслового результата и строгого ответа. Он содержит путь, устройство,
inode, владельца, группу, режим, прежние PID, маркер запуска и группу
процесса, путь блокировки, `processExitRequired=true` и
`exclusiveLockRequired=true`. Для остальных пяти методов обе эти колонки
равны `NULL`.

Для `maintenance_begin`, `maintenance_strengthen` и `maintenance_resume`
`before_instance_id=resulting_instance_id` и оба равны живому экземпляру.
Для `shutdown` первый равен прежнему живому экземпляру, а второй — `NULL`.
Для `controller_accept` исходный экземпляр равен `NULL`, для
`controller_recover` он отражает фактическую закрытую исходную форму, а
`resulting_instance_id` в обоих случаях является новым и никогда не
переиспользуется.

`maintenance_status` является чистым чтением и квитанцию не создаёт.
Повтор `command_id` с тем же отпечатком возвращает сохранённый канонический
ответ; с другим отпечатком получает `COMMAND_REPLAY_CONFLICT`. Разные
`command_id` позволяют законную последовательность
`maintenance_begin → maintenance_resume → maintenance_begin` внутри одной
операции и новый запуск контроллера после доказанной смерти старого.

#### Остановка и файловая очистка сокета

`shutdown` допустим только из живой формы `state=MAINTENANCE`,
`maintenance_mode=FREEZE`, при точном совпадении `operation_id` с операцией
запроса и под исключительной стороной барьера запуска. Ограждение запроса
обязано одновременно совпасть по `controllerIdentity`, `instanceId`,
`controllerStartId` и ожидаемой живой эпохе. Под тем же исключительным
барьером одна `BEGIN IMMEDIATE` получает полную свежую проекцию `runtime-v2`
покоя с теми же идентичностью контроллера, экземпляром и `controlEpoch`;
`barrierHeld=true` не заменяет требование именно исключительной стороны.
Несовпадение любого условия закрывает команду без изменения эпохи и без
квитанции. Успешная транзакция:

1. переводит `controller_state` из `MAINTENANCE` в `STOPPED`, сохраняет
   прежние идентификаторы экземпляра и процесса, очищает поля сокета,
   устанавливает `maintenance_mode=NONE`,
   `operation_id IS NULL`, `lock_held=0`, `accepting_new_routes=0`,
   `quiescent=1`;
2. сохраняет прежний экземпляр в `before_instance_id`, а PID, маркер, группу
   процесса, сокет и путь блокировки — в неизменяемом `socketIntent`
   квитанции;
3. повышает эпоху ровно на один;
4. пишет связанную строку `controller_command_receipts` и только затем
   возвращает канонический ответ `SHUTDOWN_COMMITTED`.

База не удаляет файловый сокет. После фиксации процесс перестаёт принимать
соединения, закрывает потоки и базу и освобождает блокировку. Внешний
исполнитель по точным квитанции и `socketIntent` доказывает смерть PID с тем
же маркером и группой и захватывает исключительную блокировку. Только после
этого он создаёт внешний конечный `lifecycle-projection-v2` со
`schemaId=shutdown-intent-v2` и закрытым состоянием
`SHUTDOWN_COMMITTED_EXIT_AND_LOCK_PROVEN`. Конечная проекция содержит
`controllerAfter=STOPPED`, связь с операцией, командой, запросом и квитанцией,
обе эпохи, прежний процесс, полный сокет, путь блокировки и отдельные
доказательства выхода и исключительной блокировки. Она не создаётся в
транзакции `shutdown` и не хранится внутри базы.

Лишь отдельный файловый шаг `shutdown_socket_cleanup` принимает эту конечную
проекцию, повторно сверяет путь, устройство, inode, владельца, группу и режим
сокета, удерживая исключительную блокировку, выполняет `unlinkat`,
синхронизирует родительский каталог и сохраняет полную проекцию
`absence-proof-v2`. Чужой или изменившийся сокет не удаляется.

При потере ответа повтор того же `command_id` сначала находит точную
квитанцию и возвращает `REPLAY_RECEIPT`. Восстановитель считает остановку
доказанной только при совпавших квитанции, `socketIntent`, повышенной эпохе,
полной форме `STOPPED`, смерти процесса и исключительной блокировке. Одного
отсутствия процесса или сокета недостаточно; точный оставшийся сокет требует
`shutdown_socket_cleanup`, а несовпадение закрывает восстановление.

### `node_launch_permits`

Разрешение запуска содержит:

- `permit_id TEXT PRIMARY KEY`, форма `lp2_` плюс ровно 32 строчных hex;
- `admission_id TEXT UNIQUE`, ссылка на допуск узла; `NULL` только для
  `LEGACY_IMPORTED`;
- `route_id TEXT NOT NULL`, `node_id TEXT NOT NULL` и составной внешний ключ
  `ON UPDATE RESTRICT ON DELETE RESTRICT` на `nodes`;
- `activation_fingerprint TEXT NOT NULL`;
- `account_context_fingerprint TEXT`, допускающий `NULL` только для
  `ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE`;
- `account_catalog_fingerprint TEXT` с тем же правилом;
- `manifest_semantic_fingerprint TEXT`;
- `activation_receipt_fingerprint TEXT`;
- `journal_absence_proof_json TEXT`;
- `activation_gate_fingerprint TEXT`;
- `controller_identity TEXT NOT NULL`,
  `controller_instance_id TEXT NOT NULL`;
- `reserved_control_epoch INTEGER NOT NULL
  CHECK(reserved_control_epoch BETWEEN 0 AND 9007199254740991)`;
- `model TEXT NOT NULL`, `reasoning_effort TEXT NOT NULL`,
  `permission_profile_id TEXT NOT NULL`;
- `argv_fingerprint TEXT NOT NULL`;
- `compatibility_fingerprint TEXT NOT NULL`;
- `codex_snapshot_sha256 TEXT NOT NULL`;
- `permit_evidence_fingerprint TEXT NOT NULL`;
- `state TEXT NOT NULL`;
- `guard_pid INTEGER`, `guard_start_marker TEXT`, `pid INTEGER`,
  `start_marker TEXT`;
- `one_time_token_hash TEXT`;
- `snapshot_identity_fingerprint TEXT`, допускающий `NULL` только для
  `LEGACY_IMPORTED`;
- `legacy_source_backup_sha256 TEXT`, `legacy_attempt_id TEXT`;
- `reserved_at TEXT NOT NULL`, `resolved_at TEXT`, `failure_code TEXT`.

`argv_fingerprint` вычисляется доменом `codex-smart/argv/v2` от точного
массива строк, передаваемого в `execve`, уже после добавления всех строгих
настроек, модели, уровня и профиля, но без окружения. Массив не сортируется.

`journal_absence_proof_json` является побайтно каноническим полным
`absence-proof-v2`; остальные три поля вместе с ним являются полной копией
`activationGate`, сохранённого узлом. Таблица имеет уникальные составные ключи
для
`(permit_id,permit_evidence_fingerprint,snapshot_identity_fingerprint)` и
`(permit_id,pid,start_marker)`, а также для
полного набора
`(permit_id,admission_id,route_id,node_id,activation_fingerprint,
account_context_fingerprint,account_catalog_fingerprint,
reserved_control_epoch,model,reasoning_effort,permission_profile_id,
argv_fingerprint,compatibility_fingerprint,codex_snapshot_sha256,
snapshot_identity_fingerprint,
manifest_semantic_fingerprint,activation_receipt_fingerprint,
activation_gate_fingerprint)`. Полная проекция доказательства отсутствия
сравнивается побайтно кодом, поскольку SQLite не позволяет использовать
канонический JSON как надёжное межтабличное ограничение.

`admission_id` и четыре поля шлюза одновременно равны `NULL` только для
`LEGACY_IMPORTED`; для него не создаётся фиктивная активационная
аттестация, а неизвестная историческая эпоха представляется
`reserved_control_epoch=0`. Для этой формы обязательны
`legacy_source_backup_sha256`, `legacy_attempt_id` и их уникальная пара: по
ней повторно проверяется детерминированный `permit_id` и закрыто
обнаруживается совпадение с иным объектом; полный результат SHA-256 служит
тем же `permit_evidence_fingerprint`, что и у связанной исторической попытки.
`snapshot_identity_fingerprint` исторического разрешения и попытки равен
`NULL`: неизвестную идентичность старого снимка нельзя подменять новым
доказательством. Во всех остальных состояниях оба исторических поля равны
`NULL`, поля шлюза и `snapshot_identity_fingerprint` одновременно ненулевые,
форматно проверены и эпоха находится в диапазоне от 1 до
9007199254740991.

`nodes` имеет соответствующий уникальный ключ допуска с `admission_id`,
маршрутом, узлом, активацией, учётной средой и всеми компонентами шлюза.
Составной внешний ключ разрешения подтверждает этот ключ; отдельные внешние
ключи не считаются доказательством равенства всего допуска.

Закрытые состояния:

```text
RESERVED
GUARDED
COMMIT_AUTHORIZED
STARTED
ABORTED_FREEZE
ABORTED_RECOVERY
ABORTED_ACCOUNT_CONTEXT_CHANGED
ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE
ABORTED_ACTIVATION_GATE_CHANGED
FAILED_BEFORE_START
LEGACY_IMPORTED
```

Точные инварианты:

- `RESERVED`: поля сторожа, процесса, `resolved_at`, `failure_code` равны
  `NULL`; `snapshot_identity_fingerprint` уже получен свежей дескрипторной
  проверкой выбранного снимка и входит в `permit_evidence_fingerprint`, но
  одноразовый знак ещё не передан сторожу;
- `GUARDED`: обязательны положительный `guard_pid` и его маркер, но поля
  подтверждённого процесса `pid` и `start_marker` ещё `NULL`; обязательны также
  `one_time_token_hash` и `snapshot_identity_fingerprint`;
- `COMMIT_AUTHORIZED`: сторож и попытка долговечно известны, кадр `COMMIT`
  разрешён, но успешный `exec` ещё не доказан; `permit_id`, положительный
  `pid` и непустой `start_marker` обязательны, локальный `CHECK` требует
  `pid=guard_pid` и `start_marker=guard_start_marker`, а точный составной
  внешний ключ связывает их с попыткой `STARTING`;
- `STARTED`: те же обязательные `permit_id`, положительный `pid` и непустой
  `start_marker` остаются равны `guard_pid` и `guard_start_marker`, связанная
  попытка подтверждена, `resolved_at` обязателен, `failure_code IS NULL`;
- `ABORTED_*` и `FAILED_BEFORE_START`: процесс не подтверждён, поэтому `pid`
  и `start_marker` равны `NULL`, а `resolved_at` и `failure_code` обязательны;
- `ABORTED_ACTIVATION_GATE_CHANGED`: фактический канонический
  `activationGate` перестал совпадать с объектом, сохранённым при
  `smart_start`; `failure_code` равен ровно
  `ABORTED_ACTIVATION_GATE_CHANGED`, связанный допуск узла имеет
  `admission_state=ABORTED`, а попытка не создаётся;
- `LEGACY_IMPORTED`: применяется только к терминальной исторической попытке,
  сохраняет её положительный `pid`, имеет `start_marker IS NULL`, обязательный
  `resolved_at`, а `failure_code` равен `LEGACY_V1`; это факт переноса строки,
  а не подтверждение идентичности старого процесса;
- для пары `(route_id,node_id)` допускается не более одной строки
  в `RESERVED`, `GUARDED` или `COMMIT_AUTHORIZED`;
- `attempts.launch_permit_id` ссылается на разрешение и составным внешним
  ключом подтверждает те же маршрут, узел, отпечатки, эпоху,
  `snapshot_identity_fingerprint`; отдельный точный внешний ключ
  `attempts(launch_permit_id,pid,process_start_marker)` →
  `node_launch_permits(permit_id,pid,start_marker)` подтверждает PID и маркер.
  Для `V1_LEGACY`, где `start_marker IS NULL`, составной внешний ключ SQLite
  не является доказательством и вместо него действует отдельная историческая
  пара исходной резервной копии и прежней попытки.

Для всех нормальных состояний все поля доказательства допуска ненулевые и
форматно проверены; `permit_evidence_fingerprint` пересчитывается. Для
`ABORTED_ACCOUNT_EVIDENCE_UNAVAILABLE` контекст и каталог учётной среды равны
`NULL`, процесса и попытки нет, а `failure_code` совпадает с состоянием.
Для `ABORTED_ACTIVATION_GATE_CHANGED` сохраняется последний принятый полный
шлюз без подстановки нового доказательства, а `failure_code` совпадает с этим
состоянием.

Переход допуска закрыт и атомарен на каждом рубеже:

1. `smart_start` под общей стороной барьера и одной `BEGIN IMMEDIATE` заново
   проверяет фактический манифест, неизменяемую квитанцию активации, свежую
   синхронизированную проекцию отсутствия журнала, производный отпечаток,
   живой экземпляр и ожидаемую эпоху. Он записывает в узел `admission_id`,
   полный канонический `activationGate` и `admission_state=ATTESTING`.
2. После свежего `AccountEvidence` отдельный `reserve_launch_permit` снова
   получает общую сторону барьера и новую `BEGIN IMMEDIATE`, проверяет
   `ACCEPTING`, ту же эпоху, маршрут, учётную среду, модель, уровень,
   профиль, аргументы, снимок и побайтно тот же после канонизации шлюз. Свежая
   дескрипторная проверка сохраняет `snapshot_identity_fingerprint`; он входит
   в `permit_evidence_fingerprint`. Транзакция создаёт единственный `RESERVED`
   и переводит допуск узла в `RESERVED`.
3. Проверенный `HELLO` сторожа отдельной транзакцией записывает его PID,
   маркер и одноразовый знак, требует точного равенства переданного
   `snapshotIdentityFingerprint` уже сохранённому разрешением значению и
   переводит обе связанные формы в `GUARDED`; процесса Codex ещё нет.
4. `commit_launch_permit` под общей стороной барьера и новой
   `BEGIN IMMEDIATE` в третий раз проверяет фактические три доказательства
   шлюза, их каноническое равенство первым двум рубежам, текущую эпоху, всю
   идентичность запуска и равенство `snapshotIdentityFingerprint` запроса
   разрешению и сторожу. Он атомарно создаёт попытку `STARTING` с тем же
   `snapshot_identity_fingerprint`, связывает её полным составным внешним
   ключом и переводит разрешение и допуск в `COMMIT_AUTHORIZED`; только после
   фиксации посылается `COMMIT`.
5. Доказанное закрытие канала ошибки с `CLOEXEC`, тот же PID, маркер и образ
   процесса одной транзакцией переводят попытку в `RUNNING`, а разрешение и
   допуск — в `STARTED`.

Резервирование и фиксация допуска всегда являются разными транзакциями.
Одного `controller_state=ACCEPTING`, совпавшего итогового хеша либо прежнего
доказательства отсутствия журнала недостаточно ни на одном из трёх рубежей.
Если после долговечного `admission_id` фактический шлюз изменился, транзакция
`reserve_launch_permit` создаёт единственное терминальное разрешение, а
`commit_launch_permit` переводит уже существующее разрешение в
`ABORTED_ACTIVATION_GATE_CHANGED`; в обоих случаях узел становится `ABORTED`,
`failure_code=ABORTED_ACTIVATION_GATE_CHANGED`, сторож закрывается до `exec`,
попытка не создаётся и новый шлюз в старый допуск не записывается.
Сбой до `COMMIT_AUTHORIZED` получает один из закрытых `ABORTED_*` или
`FAILED_BEFORE_START` без попытки; сбой после него восстанавливает известную
пару разрешения и попытки. Ни один закрытый исход не создаёт скрытый новый
`permit_id`, `admission_id` или повторный процесс.

### `schema_migrations`

Таблица содержит:

- `operation_id TEXT PRIMARY KEY`;
- `database_id TEXT NOT NULL` с внешним ключом на `database_identity`;
- `from_version INTEGER NOT NULL CHECK(from_version IN (0,1))`;
- `to_version INTEGER NOT NULL CHECK(to_version=2)`;
- `source_shape TEXT NOT NULL`;
- `source_schema_fingerprint TEXT NOT NULL`;
- `source_backup_sha256 TEXT NOT NULL`;
- `target_schema_fingerprint TEXT NOT NULL`;
- `target_database_projection_schema_id TEXT NOT NULL
  CHECK(target_database_projection_schema_id='database-object-v2')`;
- `target_database_projection_locator TEXT NOT NULL`;
- `legacy_quiescence_proof_json TEXT NOT NULL`;
- `applied_at TEXT NOT NULL`;
- `UNIQUE(source_backup_sha256,to_version)`.

`target_database_projection_locator` является каноническим логическим
указателем, полученным только из постоянного пространства имён,
`operation_id` и `database_id`. Он не содержит `schemaSha256`,
`valueFingerprint`, SHA-256, размер, устройство, inode или иную файловую
идентичность внешней проекции. Во время операции указатель разрешается через
точный внешний журнал, после принятия — через неизменяемую квитанцию активации;
оба носителя содержат полную `database-object-v2`. Проверка требует равенства
`operationId` носителя значению `operation_id`, равенства вложенного
`databaseId` значению `database_id`, нормативного `schemaId` и полной сверки
`schemaSha256`, `value`, `valueFingerprint` с фактической базой. Целостность
закрепляет внешний носитель, а не обратная ссылка из SQLite.

`legacy_quiescence_proof_json` является канонической полной проекцией
`quiescence-proof-v2` варианта `legacy-migration`, снятой под всеми
ограждениями непосредственно для `source_backup_sha256`. Её нельзя заменить
`valueFingerprint`, отдельными счётчиками или ссылкой на диагностический
отчёт. Вставка строки `schema_migrations` и всех перенесённых данных
фиксируется одной транзакцией; публикация внешней проекции базы завершается
долговечным файловым шагом жизненного цикла до квитанции активации.

## Индексы и отсутствие триггеров

Помимо индексов и автоиндексов формы `rollout-v1` нормативный файл создаёт:

```text
routes_state_created(state,created_at)
controller_command_receipts_created(created_at)
node_launch_permits_state(state,reserved_at)
node_launch_permits_route(route_id,node_id,reserved_at)
node_launch_permits_one_inflight(route_id,node_id)
  WHERE state IN ('RESERVED','GUARDED','COMMIT_AUTHORIZED')
schema_migrations_applied(applied_at)
```

Все имена, порядок столбцов, направление сортировки и условие частичного
индекса входят в отпечаток. Триггеры запрещены. Межтабличные инварианты
проверяются кодом под `BEGIN IMMEDIATE`, а затем независимо командами
`doctor` и `maintenance_status`; это исключает скрытую логику, которая могла
бы различаться между SQLite разных поставок.

## Точный критерий покоя

Для `routes` и `nodes` разрешён один закрытый набор:

```text
PLANNED BLOCKED QUEUED LEASED PREPARING RUNNING COLLECTING ATTESTING
VALIDATING CANDIDATE_BUILDING SUCCEEDED CANDIDATE_READY QUARANTINED
RETRYABLE RECOVERING CANCELLING CANCELLED FAILED STALE SKIPPED SPLIT
```

Терминальны ровно `SUCCEEDED`, `CANDIDATE_READY`, `QUARANTINED`, `CANCELLED`,
`FAILED`, `STALE`, `SKIPPED`; остальные нетерминальны. Для `attempts`
разрешены `STARTING`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`,
`QUARANTINED`, и `STARTING`/`RUNNING` нетерминальны. `STARTING` допустим
только при связанном разрешении `COMMIT_AUTHORIZED`. Для `intents` разрешены `PENDING`, `COMPLETED`;
для `runtime_artifacts` — `RESERVED`, `ACTIVE`, `TERMINAL`, `MISSING`; для
`candidate_publication_intents` — `PENDING`, `COMPLETED`, `RECOVERED`,
`ABORTED`, `QUARANTINED`. Неизвестное значение является повреждением, а не
новым терминальным состоянием.

`runtimeQuiescentV2` разрешает переключение действующей активации только как
полная проекция `lifecycle-projection-v2` со
`schemaId=quiescence-proof-v2` и `proofKind=runtime-v2`. Один снимок под
`BEGIN IMMEDIATE` и удерживаемой общей либо исключительной стороной барьера
запуска связывает точные `controllerIdentity`, `instanceId`, живую
`controlEpoch`, `barrierHeld=true`, `quiescent=true`,
`databasePredicatesFingerprint` закрытых запросов ниже и ноль по всем восьми
полям `workCounts`:

1. маршруты в нетерминальном состоянии;
2. узлы в нетерминальном состоянии;
3. попытки в `STARTING` или `RUNNING`;
4. любые строки `leases`;
5. намерения `intents` в `PENDING`;
6. разрешения запуска `node_launch_permits` в `RESERVED`, `GUARDED` или
   `COMMIT_AUTHORIZED`;
7. `runtime_artifacts` в `RESERVED` или `ACTIVE`;
8. `candidate_publication_intents` в `PENDING`.

Эти закрытые наборы закрепляются в нормативных проверочных запросах рядом со
схемой и используются без копирования в контроллере, миграторе и `doctor`.
Полный `databasePredicatesFingerprint` связывает точные тексты восьми
запросов, их параметры, закрытые перечисления и результат одного снимка. Он
не заменяет `workCounts`, идентичность экземпляра, эпоху или признак
удержания барьера.

Для неизменяемого снимка версии 1 применяется отдельная полная проекция
`quiescence-proof-v2` с `proofKind=legacy-migration`. Под остановленным старым
контроллером и эксклюзивной арендой она хранит все поля окончательной схемы
жизненного цикла: `legacyStateHome`, отпечаток закрытого множества старых
процессов, полный целевой процесс, точного вооружённого сторожа,
`gatewayFenceProofFingerprint`, `bridgeFenceProofFingerprint`, полный
`databaseFile`, `databaseIdentityFingerprint`,
`databaseSnapshotFingerprint`, доказательства исключительной аренды базы и
внешнего барьера, восемь нулевых счётчиков и `quiescent=true`.

Закрытый запрос сначала выделяет маршрут как виртуально переносимый, только
если маршрут и все его узлы находятся в `PLANNED` или `BLOCKED` и у него нет
попыток, аренд, намерений, активных рабочих артефактов или незакрытых
публикаций. Только эти маршруты и узлы исключаются из первых двух
проецируемых счётчиков; остальные шесть счётчиков и вся прочая
нетерминальная работа обязаны быть нулевыми. Исходная база не изменяется. Уже
в новой базе версии 2 копии выделенных узлов, затем маршрута получают
`STALE` и события переноса. Иное сочетание даёт `ACTIVE_WORK_REMAINS`.

Двойное чтение счётчиков без барьера не является доказательством: между
чтениями мог появиться запуск. Сначала шлюз закрывает новые команды, затем
контроллер устанавливает барьер в памяти и подтверждает идентичность и эпоху,
после чего одна транзакция читает все восемь значений и сохраняет всю
проекцию. Голый хеш, отдельная строка `quiescent=1` или повторное чтение после
освобождения барьера отвергаются.

## Перенос версии 1 в версию 2

### Предварительные условия

Миграция начинается только после установочной блокировки, закрытия шлюза,
установки загрузочного ограждения, остановки старого контроллера и доказанного
покоя. Путь старого `STATE_HOME` задаётся явно либо извлекается из строгого
манифеста версии 1. Если старый процесс открыл базу из другого корня,
сканирование `KERN_PROCARGS2` обнаруживает путь и блокирует перенос.

Исходная база никогда не меняется, не заменяется и не удаляется. Перед
созданием кандидата SQLite Backup API формирует частную копию по пути
`STATE_HOME/backups/OPERATION_ID/source-v1.sqlite3`, созданному в новом
каталоге и через `O_EXCL`. Журнал хранит путь, устройство, номер файла, число
связей, размер, SHA-256 и отпечаток схемы. На самой копии выполняется
`PRAGMA journal_mode=DELETE`; затем соединение закрывается, доказывается
отсутствие `-wal`, `-shm` и `-journal`, файл и каталог синхронизируются и
только после этого вычисляется SHA-256. Полные `integrity_check`,
`foreign_key_check`, структурная проверка и проверка данных выполняются на
копии. Все переносимые строки далее читаются только из неё; повтор операции
переиспользует ровно записанную копию и не снимает новый снимок молча.

### Алгоритм

1. Под закрытым шлюзом повторно проверить путь, владельца, права,
   `integrity_check`, внешние ключи, `application_id`, `user_version`, точный
   отпечаток одной из 38 форм и её предикат пустоты; стабилизировать частную
   копию и с этого момента читать только её.
2. Создать новый уникальный каталог `databases/db2_...` режимом `0700` и
   временный файл базы режимом `0600` с `O_EXCL`; существующий путь никогда
   не переиспользовать.
3. Исполнить единственный `state-v2.sql` в новой базе с `foreign_keys=ON`,
   `trusted_schema=OFF`, `synchronous=FULL`, но без WAL.
4. В одной `BEGIN IMMEDIATE` копировать данные параметризованными запросами в
   порядке родителей до потомков. `SELECT *`, `INSERT ... SELECT *`,
   `executescript` с данными и интерполяция значений запрещены.
5. Присвоить историческим маршрутам, узлам, привязкам, разрешениям и всем
   новым обязательным полям попыток отпечаток
   `1aa3a175a176dc3eda64ddf7edcdd71757bb40e34847dae975d341daf1482ebc`
   (`SHA256("codex-smart-subagents-db-v1-legacy")`) там, где версия 1 не
   хранила доказательство. Он является явным значением `UNKNOWN_LEGACY_V1`, а
   не поддельной совместимостью. Все старые привязки хода пометить
   потреблёнными выражением
   `consumed_at = COALESCE(consumed_at,migration_time)`. Существующие
   `request_key`, `request_hash` и старое время потребления сохраняются;
   `request-context-v2` для маршрутов и привязок перестраивается одновременно.
   Такие строки остаются только для аудита и не могут запускаться.
6. Перевести виртуально допустимые незапущенные `PLANNED/BLOCKED` в `STALE`,
   создать события только для реально изменённых маршрутов и узлов и
   `LEGACY_IMPORTED` только для терминальных исторических попыток. Для них
   записать `evidence_kind=V1_LEGACY`, сохранить PID и оставить
   `codex_binary_sha256` и `process_start_marker` равными `NULL`.
7. Точно перенести `sqlite_sequence`. Глобальное доказательство миграции
   хранить только в `schema_migrations`; в пустой или полностью терминальной
   базе искусственный маршрут и событие не создаются.
8. Вставить `database_identity`, `controller_state` в `MAINTENANCE` и одну
   строку `schema_migrations`.
9. Установить `application_id=1129529650`, `user_version=2`, зафиксировать
   транзакцию и выполнить полный набор проверок схемы, данных, покоя и
   отрицательных проб.
10. Синхронизировать файл и каталог, атомарно заменить временное имя внутри
    нового уникального каталога, снова открыть конечный путь и повторить
    проверки.
11. Только после успешного переключения активации принятый контроллер может
    перевести новую базу в WAL.

Повтор операции с тем же журналом сверяет резервную копию и уже созданный
`databaseId`. Совпавший законченный кандидат используется повторно; частичный
кандидат удаляется только по точному пути, файловому идентификатору и
отпечаткам из журнала, после чего шаг выполняется заново. Новый `databaseId`
не подставляется в старый журнал.

### Сохранение `sqlite_sequence`

В версии 1 допустима только таблица `sqlite_sequence` с нулём или одной
строкой для `events`. Значение `seq` — целое не меньше максимального
`events.sequence`; иная форма блокирует миграцию.

События копируются с явным `sequence`. Затем в кандидате удаляется строка
`sqlite_sequence` для `events` и, если она была в источнике, вставляется её
точное старое значение. Только после этого события реально переведённых в
`STALE` маршрутов и узлов вставляются без явного `sequence`, чтобы SQLite
продолжил последовательность штатно. Если таких событий нет, значение
остаётся точно перенесённым. Если в источнике строки не было, мигратор не
создаёт искусственный ноль.

## Аварийные окна и восстановление

До переключения `marketplace-current` авария оставляет исходную активацию и
базу единственной опубликованной парой. После переключения, но до квитанции,
шлюз остаётся закрыт из-за журнала; восстановление либо завершает принятие
точно записанной пары, либо возвращает прежнюю ссылку и прежний манифест.

Новая база никогда не публикуется по постоянному имени старой. Откат
переключает всю активацию вместе с её собственным `databaseId`; программа
старого поколения не открывает базу версии 2. Неопубликованный кандидат может
быть убран лишь по журналу. Опубликованная или предыдущая база не удаляется
обычной уборкой.

Если сбой случился после `RESERVED`, но до подтверждения процесса, восстановление
сверяет сторож, PID и маркер старта:

- доказанно неисполненный процесс получает `FAILED_BEFORE_START`;
- живой, но не принятый сторож получает `ABORTED_RECOVERY` и завершает работу
  до `exec`;
- доказанный дочерний процесс должен иметь `STARTED` и связанную попытку;
- неоднозначность закрывает контроллер и требует `recover`, а не создаёт
  вторую попытку.

На каждом из рубежей `smart_start`, `reserve_launch_permit` и
`commit_launch_permit` восстановитель заново строит фактический
`activationGate`. Несовпадение любого компонента, канонических байтов или
`gateFingerprint` завершает известный допуск состоянием
`ABORTED_ACTIVATION_GATE_CHANGED` и одноимённым `failure_code`;
восстановление не подставляет новое доказательство в старый `admission_id` и
не создаёт скрытый повтор.

Потеря ответа `shutdown` разбирается отдельно от очистки сокета. Совпавшая
квитанция и повышенная эпоха доказывают транзакцию базы, но не смерть процесса
и не удаление сокета. После доказанных смерти и исключительной блокировки
внешняя конечная проекция `shutdown-intent-v2` разрешает ровно один
`shutdown_socket_cleanup`; синхронизированная проекция `absence-proof-v2`
доказывает его завершение. Неизвестный сокет, PID с другим маркером,
несовпавшая квитанция или неполное доказательство покоя дают закрытую ошибку.

## Проверка данных и приёмка

После создания, миграции, восстановления и перед открытием шлюза выполняются:

- точный отпечаток схемы 2 и SHA-256 нормативного файла;
- `quick_check`, `integrity_check`, `foreign_key_check`;
- ровно одна строка `database_identity` и `controller_state`;
- соответствие всех строк формам идентификаторов и закрытым перечислениям;
- отсутствие осиротевших маршрутов, узлов, разрешений, попыток, артефактов,
  кандидатов и квитанций;
- точный `release=0.2.0`, `protocol_version=2`, живые эпохи не ниже единицы и
  закрытые сочетания служебной, живых и `STOPPED` форм контроллера;
- равенство связанных отпечатков и эпох, включая квитанции ровно шести
  изменяющих управляющих методов, границы `before_epoch` от 1 до
  9007199254740990, `after_epoch` от 2 до 9007199254740991 и закрытый отказ
  от повышения достигнутого предела;
- допуск `shutdown` только из совпавшей `MAINTENANCE/FREEZE` той же операции,
  под исключительной стороной барьера и с полной `runtime-v2` той же
  идентичности, экземпляра и эпохи;
- побайтное равенство полного `activationGate` узла, разрешения и попытки,
  пересчёт его нормативного домена и повторную проверку фактического
  манифеста, квитанции и синхронизированного отсутствия журнала;
- точную связь `snapshot_identity_fingerprint` разрешения, кадра `HELLO`,
  `commit_launch_permit`, `permit_evidence_fingerprint` и попытки, отдельную
  историческую форму с `NULL` и однозначный
  `ABORTED_ACTIVATION_GATE_CHANGED` с одноимённым `failure_code`;
- родительский `UNIQUE(permit_id,pid,start_marker)`, точный внешний ключ
  процесса попытки, обязательные PID и маркер в `COMMIT_AUTHORIZED` и
  `STARTED`, их равенство сторожу и отдельную историческую проверку при
  `start_marker IS NULL`;
- полные внешние `database-object-v2`, полные `runtime-v2` и
  `legacy-migration` проекции покоя и закрытые ссылки
  `schema_migrations` на неизменяемые внешние объекты;
- инварианты `sqlite_sequence`;
- восемь счётчиков покоя для установочной операции;
- совпадение базы, активации, манифеста и контроллера;
- отрицательные пробы неизвестной формы, чужой базы, подменённого SQL,
  дополнительного триггера, незавершённого WAL, подмены каждого компонента
  шлюза, столкновения исторического `permit_id`, неполной остановки и аварии
  на каждом шаге.

Обязательные испытания создают каждую из 38 настоящих форм на указанном
коммите и каждом префиксе `executescript`, проверяют разрешённую пустоту или
наполняют законные законченные формы граничными данными, переносят их и
сравнивают смысловые строки. Отдельные испытания обрывают процесс перед и
после каждого постоянного действия, в том числе каждого перехода
`ATTESTING → RESERVED → GUARDED → COMMIT_AUTHORIZED → STARTED`, транзакции
`shutdown`, выхода процесса, построения конечного `shutdown-intent-v2`,
`unlinkat` и синхронизации каталога. Они повторяют `recover` не менее двух раз
и доказывают один и тот же итоговый `resultFingerprint` без второго запуска.

Минимальный набор свойств:

1. свежая версия 2 создаётся из единственного SQL и повторно открывается;
2. каждая из 19 форм v1 переносится по своему предикату, 19 форм v0
   восстанавливаются только пустыми, а непустая частичная и неизвестная формы
   отвергаются;
3. активная работа блокирует перенос, а безопасные `PLANNED/BLOCKED` становятся
   `STALE`;
4. `sqlite_sequence` не откатывается и не создаёт повторов;
5. разрешение запуска нельзя повторно использовать, создать во время
   осушения, связать с другой учётной средой или провести с изменившимся
   шлюзом между тремя проверками; изменение шлюза после допуска даёт ровно
   `ABORTED_ACTIVATION_GATE_CHANGED` без попытки и скрытого повтора;
6. исторический `permit_id` воспроизводим, имеет ровно 32 hex после `lp2_` и
   закрыто отвергает совпадение с иным источником;
7. ровно шесть управляющих методов повышают эпоху и имеют квитанцию, а
   остановка допускается только из `MAINTENANCE/FREEZE` той же операции под
   исключительным барьером и не удаляет сокет из транзакции базы; предельная
   эпоха не переполняется и не создаёт квитанцию;
8. авария не соединяет код и базу разных активаций;
9. откат не открывает базу версии 2 кодом версии 1;
10. `doctor` независимо обнаруживает каждое нарушение, которое проверяет
   рабочий контроллер.

## Порядок реализации

До изменения `SmartStore` создаются и проверяются:

1. общая библиотека `canonical-json-v1` и нормализатор SQL с векторами;
2. генератор 38 эталонных форм из закреплённых коммитов, цепочек и префиксов;
3. манифест их полных отпечатков;
4. `state-v2.sql` и его машинный манифест;
5. закрытые машинные проекции `database-object-v2`, обоих вариантов
   `quiescence-proof-v2`, `activationGate`, `shutdown-intent-v2` и
   `absence-proof-v2` с положительными и отрицательными векторами;
6. независимая команда проверки пустой базы и `doctor`, который не вызывает
   рабочий код записи;
7. аварийные векторы каждого постоянного рубежа допуска и остановки;
8. только затем мигратор, контроллер и рабочее хранилище.

Так схема становится входом реализации, а не побочным результатом её первого
запуска.
